import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    path = ROOT / "tools/platform-cli/server-cloudflare-acceptance.py"
    spec = importlib.util.spec_from_file_location("server_cloudflare_acceptance", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CloudflareAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    @staticmethod
    def app_config(*app_ids):
        return {
            "spec": {
                "cloudflare": {"additionalApps": []},
                "components": [
                    {"id": app_id, "exposure": {"declarative": True}}
                    for app_id in app_ids
                ],
            }
        }

    def test_external_observer_requires_ssh_and_blocks_direct_origins(self):
        class Connection:
            def close(self):
                return None

        def connect(target, timeout):
            self.assertEqual(target[0], "198.51.100.10")
            self.assertGreater(timeout, 0)
            if target[1] == 22:
                return Connection()
            raise TimeoutError("blocked")

        with mock.patch.object(
            self.module.socket, "create_connection", side_effect=connect
        ):
            value = self.module.socket_observation("root@198.51.100.10", 0.1)
        self.assertTrue(value["ok"])
        self.assertTrue(value["ports"]["22"]["open"])
        self.assertTrue(
            all(not value["ports"][str(port)]["open"] for port in (80, 443, 3000))
        )
        self.assertEqual(
            value["producerSha256"],
            hashlib.sha256(
                (ROOT / "tools/platform-cli/server-cloudflare-acceptance.py").read_bytes()
            ).hexdigest(),
        )

    def test_external_observation_is_fresh_hash_bound_and_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "observer.json"
            payload = {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "CloudflareExternalPortObservation",
                "generatedAt": self.module.utcnow(),
                "freshnessMaxAgeSeconds": 300,
                "futureSkewSeconds": 30,
                "targetHost": "198.51.100.10",
                "producerSha256": "a" * 64,
                "ports": {
                    "22": {"open": True},
                    "80": {"open": False},
                    "443": {"open": False},
                    "3000": {"open": False},
                },
                "ok": True,
            }
            path.write_text(json.dumps(payload))
            path.chmod(0o600)
            values = {
                "MTE_SSH_TARGET": "root@198.51.100.10",
                "MTE_EXCLUDED_HOST_1": "192.0.2.1",
                "MTE_EXCLUDED_HOST_2": "192.0.2.2",
            }
            with (
                mock.patch.object(self.module, "exact_mode"),
                mock.patch.object(
                    self.module,
                    "current_host_identity",
                    return_value={
                        "expectedAddressMatched": True,
                        "excludedAddressMatched": False,
                    },
                ),
            ):
                result = self.module.validate_observation(path, values, "a" * 64)
            self.assertTrue(result["sshReachable"])
            self.assertEqual(
                result["externalPortsBlocked"], {"80": True, "443": True, "3000": True}
            )
            payload["ports"]["443"]["open"] = True
            path.write_text(json.dumps(payload))
            with (
                mock.patch.object(self.module, "exact_mode"),
                mock.patch.object(
                    self.module,
                    "current_host_identity",
                    return_value={
                        "expectedAddressMatched": True,
                        "excludedAddressMatched": False,
                    },
                ),
                self.assertRaises(self.module.AcceptanceError),
            ):
                self.module.validate_observation(path, values, "a" * 64)

    def test_apps_projection_requires_exact_profile_count_and_canonical_children(self):
        rows = {
            f"app-{index}": {
                "hostname": f"app-{index}.example.test",
                "origin": f"http://127.0.0.1:{10000 + index}",
                "accessClass": "human" if index < 9 else "service",
            }
            for index in range(12)
        }
        result = self.module.app_rows(
            {
                "apps": rows,
                "dataContent": {"profile": "baserow-wikijs"},
            },
            {"PLATFORM_BASE_DOMAIN": "example.test"},
            self.app_config(*rows),
        )
        self.assertEqual(len(result), 12)
        del rows["app-0"]
        with self.assertRaises(self.module.AcceptanceError):
            self.module.app_rows(
                {
                    "apps": rows,
                    "dataContent": {"profile": "baserow-wikijs"},
                },
                {"PLATFORM_BASE_DOMAIN": "example.test"},
                self.app_config(*result),
            )

    def test_postgres_notion_apps_projection_uses_exact_declared_app_set(self):
        rows = {
            f"app-{index}": {
                "hostname": f"app-{index}.example.test",
                "origin": f"http://127.0.0.1:{10000 + index}",
                "accessClass": "human" if index < 8 else "service",
            }
            for index in range(10)
        }
        config = self.app_config(*rows)
        result = self.module.app_rows(
            {
                "apps": rows,
                "dataContent": {"profile": "postgres-notion"},
            },
            {"PLATFORM_BASE_DOMAIN": "example.test"},
            config,
        )
        self.assertEqual(len(result), 10)
        rows["notion"] = {
            "hostname": "notion.example.test",
            "origin": "http://127.0.0.1:19999",
            "accessClass": "human",
        }
        with self.assertRaises(self.module.AcceptanceError) as raised:
            self.module.app_rows(
                {
                    "apps": rows,
                    "dataContent": {"profile": "postgres-notion"},
                },
                {"PLATFORM_BASE_DOMAIN": "example.test"},
                config,
            )
        self.assertEqual(raised.exception.code, "managed_app_declaration_mismatch")

    def test_postgres_notion_real_declarations_resolve_ten_edge_apps(self):
        contract_path = ROOT / "tools/platform-cli/data_content_plane.py"
        spec = importlib.util.spec_from_file_location(
            "test_cloudflare_data_content_contract", contract_path
        )
        assert spec is not None and spec.loader is not None
        contract = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(contract)
        active = contract.filter_platform_config(
            yaml.safe_load((ROOT / "config/platform.yaml").read_text()),
            yaml.safe_load((ROOT / "config/platform.lock.yaml").read_text()),
            {"DATA_CONTENT_PROFILE": "postgres-notion"},
        )
        self.assertEqual(
            self.module.declared_managed_app_ids(active),
            {
                "9router",
                "activepieces",
                "dokploy",
                "firecrawl",
                "kestra",
                "mattermost",
                "observability",
                "paperclip",
                "searxng",
                "toolhive",
            },
        )

    def test_cloudflare_inventory_requires_exact_dns_access_routes_and_foreign_records(
        self,
    ):
        apps = {
            f"app-{index}": {
                "hostname": f"app-{index}.example.test",
                "origin": f"http://127.0.0.1:{10000 + index}",
                "accessClass": "human" if index < 9 else "service",
            }
            for index in range(12)
        }
        tunnel_id = "00000000-0000-0000-0000-000000000001"

        class FakeApi:
            def __init__(self, _token):
                pass

            def pages(self, path):
                if path.endswith("/cfd_tunnel"):
                    return [
                        {
                            "id": tunnel_id,
                            "name": "mte-test",
                            "status": "healthy",
                            "connections": [{"is_pending_reconnect": False}],
                        }
                    ]
                if path.endswith("/dns_records"):
                    records = [
                        {
                            "id": f"dns-{index}",
                            "name": row["hostname"],
                            "type": "CNAME",
                            "content": tunnel_id + ".cfargotunnel.com",
                            "proxied": True,
                            "comment": "Managed by MTE platform IaC for " + app_id,
                        }
                        for index, (app_id, row) in enumerate(apps.items())
                    ]
                    records.extend(
                        [
                            {
                                "id": "foreign-1",
                                "name": "paperclip.example.test",
                                "type": "A",
                                "content": "192.0.2.10",
                            },
                            {
                                "id": "foreign-2",
                                "name": "chat.example.test",
                                "type": "A",
                                "content": "192.0.2.11",
                            },
                        ]
                    )
                    return records
                if path.endswith("/access/apps"):
                    return [
                        {
                            "id": f"access-{index}",
                            "domain": row["hostname"],
                            "type": "self_hosted",
                            "policies": [
                                {
                                    "id": (
                                        "policy-human"
                                        if row["accessClass"] == "human"
                                        else "policy-service"
                                    )
                                }
                            ],
                            "app_launcher_visible": row["accessClass"] == "human",
                            "service_auth_401_redirect": row["accessClass"]
                            == "service",
                        }
                        for index, row in enumerate(apps.values())
                    ]
                raise AssertionError(path)

            def get(self, path):
                if not path:
                    raise AssertionError("missing path")
                if path.endswith("/policies/policy-human"):
                    return {
                        "decision": "allow",
                        "include": [{"email": {"email": "operator@example.test"}}],
                        "exclude": [],
                        "require": [],
                    }
                if path.endswith("/policies/policy-service"):
                    return {
                        "decision": "non_identity",
                        "include": [
                            {"service_token": {"token_id": "service-token-id-1234"}}
                        ],
                        "exclude": [],
                        "require": [],
                    }
                return {
                    "config": {
                        "ingress": [
                            *[
                                {"hostname": row["hostname"], "service": row["origin"]}
                                for row in apps.values()
                            ],
                            {"service": "http_status:404"},
                        ]
                    }
                }

        values = {
            "CLOUDFLARE_API_TOKEN": "not-a-real-token",
            "CLOUDFLARE_ACCOUNT_ID": "a" * 32,
            "CLOUDFLARE_ZONE_ID": "b" * 32,
            "CLOUDFLARE_TUNNEL_NAME": "mte-test",
            "PLATFORM_BASE_DOMAIN": "example.test",
            "CLOUDFLARE_ACCESS_ALLOWED_EMAILS": "operator@example.test",
            "CLOUDFLARE_ACCESS_SERVICE_TOKEN_ID": "service-token-id-1234",
        }
        with mock.patch.object(self.module, "CloudflareApi", FakeApi):
            result = self.module.cloudflare_inventory(values, apps)
        self.assertEqual(result["dnsRecordCount"], 12)
        self.assertEqual(result["accessApplicationCount"], 12)
        self.assertEqual(result["accessPolicyCount"], 2)
        self.assertTrue(result["humanAccessPolicyScoped"])
        self.assertTrue(result["serviceAccessTokenScoped"])
        self.assertEqual(len(result["foreign"]), 2)
        values["CLOUDFLARE_ACCESS_ALLOWED_EMAILS"] = "someone-else@example.test"
        with mock.patch.object(self.module, "CloudflareApi", FakeApi):
            with self.assertRaises(self.module.AcceptanceError) as raised:
                self.module.cloudflare_inventory(values, apps)
        self.assertEqual(raised.exception.code, "managed_access_policy_scope_drift")

    def test_human_rows_are_redirect_and_direct_semantic_bound(self):
        apps = {
            app_id: {
                "hostname": app_id + ".example.test",
                "origin": "http://127.0.0.1:1234",
                "accessClass": "human",
            }
            for app_id in self.module.human_connections.values()
        }
        apps["wikijs"] = {
            "hostname": "docs.example.test",
            "origin": "http://127.0.0.1:1235",
            "accessClass": "human",
        }
        apps["baserow"] = {
            "hostname": "tables.example.test",
            "origin": "http://127.0.0.1:1236",
            "accessClass": "human",
        }
        data_content = {
            "profile": "provider-a",
            "projectionSha256": "f" * 64,
            "edgeManaged": True,
            "roles": {
                "tablesUi": {
                    "applicationId": "baserow",
                    "hostname": "tables.example.test",
                    "accessClass": "human",
                },
                "documentsUi": {
                    "applicationId": "wikijs",
                    "hostname": "docs.example.test",
                    "accessClass": "human",
                },
            },
            "roleBindings": {},
            "applicationIds": ["baserow", "wikijs"],
        }
        semantic = {
            app_id: (
                lambda _values, _origin, app_id=app_id: {
                    "semantic": app_id,
                    "originAuthenticationRequired": app_id != "searxng",
                    "originAuthenticationVerified": True,
                }
            )
            for app_id in apps
        }
        with (
            mock.patch.object(
                self.module,
                "edge_redirect",
                return_value={
                    "anonymousStatus": 302,
                    "accessLocationVerified": True,
                },
            ),
            mock.patch.object(self.module, "semantic_checks", semantic),
        ):
            rows = self.module.human_rows(
                {},
                apps,
                self.module.human_connection_contract(data_content),
                data_content,
            )
        self.assertEqual(set(rows), {*self.module.human_connections, "C029"})
        for row in rows.values():
            self.assertTrue(row["edgeGateVerified"])
            self.assertTrue(row["serviceSemanticVerified"])
            self.assertTrue(row["originAuthenticationVerified"])
            self.assertFalse(row["authenticatedCloudflareSessionTested"])
        self.assertEqual(rows["C029"]["dataContentApplications"], ["baserow", "wikijs"])
        self.assertEqual(rows["C029"]["dataContentProfile"], "provider-a")
        self.assertEqual(len(rows["C029"]["edgeApplications"]), 2)

    def test_data_content_edge_contract_is_projection_driven(self):
        with tempfile.TemporaryDirectory() as directory:
            plane = Path(directory) / "data-content-plane.json"
            plane.write_text('{"kind":"DataContentPlane"}\n')
            apps = {
                "table-app": {
                    "hostname": "tables.example.test",
                    "origin": "http://127.0.0.1:1",
                    "accessClass": "human",
                },
                "docs-app": {
                    "hostname": "docs.example.test",
                    "origin": "http://127.0.0.1:2",
                    "accessClass": "human",
                },
            }
            projection = {
                "dataContent": {
                    "profile": "provider-a",
                    "projectionSha256": hashlib.sha256(plane.read_bytes()).hexdigest(),
                    "roles": {
                        "tablesUi": {
                            "applicationId": "table-app",
                            "hostname": "tables.example.test",
                            "accessClass": "human",
                        },
                        "documentsUi": {
                            "applicationId": "docs-app",
                            "hostname": "docs.example.test",
                            "accessClass": "human",
                        },
                    },
                }
            }
            with mock.patch.object(self.module, "data_content_path", plane):
                value = self.module.data_content_edge_contract(projection, apps)
            self.assertEqual(value["applicationIds"], ["table-app", "docs-app"])
            projection["dataContent"]["roles"]["tablesUi"]["applicationId"] = "baserow"
            with (
                mock.patch.object(self.module, "data_content_path", plane),
                self.assertRaises(self.module.AcceptanceError),
            ):
                self.module.data_content_edge_contract(projection, apps)

    def test_postgres_notion_data_content_contract_has_no_cloudflare_apps(self):
        with tempfile.TemporaryDirectory() as directory:
            plane = Path(directory) / "data-content-plane.json"
            plane.write_text(
                json.dumps(
                    {
                        "kind": "DataContentPlane",
                        "profile": "postgres-notion",
                        "providers": {
                            "notion": {
                                "kind": "external-workspace",
                                "deployment": "external",
                                "componentId": None,
                            }
                        },
                        "roles": {
                            "tablesUi": {
                                "providerId": "notion",
                                "capability": "tables",
                                "interface": "ui",
                                "adapterId": "notion",
                            },
                            "tablesApi": {
                                "providerId": "notion",
                                "capability": "tables",
                                "interface": "api",
                                "adapterId": "notion",
                            },
                            "documentsUi": {
                                "providerId": "notion",
                                "capability": "documents",
                                "interface": "ui",
                                "adapterId": "notion",
                            },
                            "documentsApi": {
                                "providerId": "notion",
                                "capability": "documents",
                                "interface": "api",
                                "adapterId": "notion",
                            },
                        },
                    }
                )
            )
            projection = {
                "dataContent": {
                    "profile": "postgres-notion",
                    "projectionSha256": hashlib.sha256(plane.read_bytes()).hexdigest(),
                    "roles": {},
                }
            }
            with mock.patch.object(self.module, "data_content_path", plane):
                value = self.module.data_content_edge_contract(projection, {})
            self.assertFalse(value["edgeManaged"])
            self.assertEqual(value["providerId"], "notion")
            self.assertEqual(value["applicationIds"], [])
            self.assertEqual(value["roles"], {})
            self.assertEqual(
                set(value["roleBindings"]),
                {"tablesUi", "tablesApi", "documentsUi", "documentsApi"},
            )
            self.assertNotIn("notion", value["applicationIds"])

    def test_external_notion_human_rows_skip_dns_access_and_origin_checks(self):
        apps = {
            app_id: {
                "hostname": app_id + ".example.test",
                "origin": "http://127.0.0.1:1234",
                "accessClass": "human",
            }
            for app_id in self.module.human_connections.values()
        }
        role_bindings = {
            "tablesUi": {
                "providerId": "notion",
                "capability": "tables",
                "interface": "ui",
                "adapterId": "notion",
            },
            "tablesApi": {
                "providerId": "notion",
                "capability": "tables",
                "interface": "api",
                "adapterId": "notion",
            },
            "documentsUi": {
                "providerId": "notion",
                "capability": "documents",
                "interface": "ui",
                "adapterId": "notion",
            },
            "documentsApi": {
                "providerId": "notion",
                "capability": "documents",
                "interface": "api",
                "adapterId": "notion",
            },
        }
        data_content = {
            "profile": "postgres-notion",
            "projectionSha256": "f" * 64,
            "edgeManaged": False,
            "providerId": "notion",
            "roles": {},
            "roleBindings": role_bindings,
            "applicationIds": [],
        }
        semantic = {
            app_id: (
                lambda _values, _origin, app_id=app_id: {
                    "semantic": app_id,
                    "originAuthenticationRequired": True,
                    "originAuthenticationVerified": True,
                }
            )
            for app_id in apps
        }
        with (
            mock.patch.object(
                self.module,
                "edge_redirect",
                return_value={"anonymousStatus": 302, "accessLocationVerified": True},
            ) as edge,
            mock.patch.object(self.module, "semantic_checks", semantic),
        ):
            rows = self.module.human_rows(
                {},
                apps,
                self.module.human_connection_contract(data_content),
                data_content,
            )
        self.assertEqual(set(rows), {*self.module.human_connections, "C029"})
        self.assertEqual(edge.call_count, len(self.module.human_connections))
        c029 = rows["C029"]
        self.assertFalse(c029["cloudflareManaged"])
        self.assertFalse(c029["edgeGateApplicable"])
        self.assertFalse(c029["edgeGateVerified"])
        self.assertEqual(c029["edgeApplications"], [])
        self.assertEqual(c029["dataContentApplications"], [])
        self.assertEqual(c029["externalProvider"], "notion")

    def test_split_connection_evidence_is_hash_bound_utc_and_root_only_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config = base / "platform.json"
            manifest = base / "manifest.json"
            apps_projection = base / "apps.json"
            data_content_projection = base / "data-content-plane.json"
            config.write_text('{"kind":"PlatformDeployment"}\n')
            manifest.write_text('{"projections":[]}\n')
            apps_projection.write_text('{"apps":{}}\n')
            data_content_projection.write_text('{"kind":"DataContentPlane"}\n')
            rows = {
                connection_id: {
                    "id": connection_id,
                    "ok": True,
                    "state": "passed",
                    "canonicalHostname": connection_id.lower() + ".example.test",
                    "expectedAccessClass": (
                        "service" if connection_id == "C026" else "human"
                    ),
                    "dependencyEvidence": [],
                }
                for connection_id in self.module.connection_evidence_ids
            }
            source_hash = "6" * 64
            producer_hash = hashlib.sha256(
                (ROOT / "tools/platform-cli/server-cloudflare-acceptance.py").read_bytes()
            ).hexdigest()
            with (
                mock.patch.object(self.module, "root", base),
                mock.patch.object(self.module, "config_path", config),
                mock.patch.object(self.module, "manifest_path", manifest),
                mock.patch.object(self.module, "apps_path", apps_projection),
                mock.patch.object(
                    self.module, "data_content_path", data_content_projection
                ),
                mock.patch.object(self.module, "exact_mode"),
            ):
                refs = self.module.write_connection_evidence(
                    {
                        "sourceSha256": source_hash,
                        "generatorVersion": self.module.generator_contract,
                    },
                    producer_hash,
                    rows,
                )
            self.assertEqual(set(refs), set(self.module.connection_evidence_ids))
            for connection_id, reference in refs.items():
                path = Path(reference["path"])
                document = json.loads(path.read_text())
                self.assertEqual(document["connectionId"], connection_id)
                self.assertEqual(document["canonicalSourceSha256"], source_hash)
                self.assertEqual(document["producerSha256"], producer_hash)
                self.assertEqual(
                    document["appsProjectionSha256"],
                    hashlib.sha256(apps_projection.read_bytes()).hexdigest(),
                )
                self.assertEqual(
                    document["dataContentProjectionSha256"],
                    hashlib.sha256(data_content_projection.read_bytes()).hexdigest(),
                )
                self.assertRegex(
                    document["generatedAt"],
                    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$",
                )
                self.assertEqual(document["fileSecurity"]["evidence"]["mode"], "0600")
                self.assertEqual(document["fileSecurity"]["evidence"]["ownerUid"], 0)
                self.assertEqual(
                    document["subjectSha256"],
                    self.module.canonical_json_sha256(document["connection"]),
                )
                self.assertEqual(
                    document["upstreamEvidenceSha256"],
                    self.module.canonical_json_sha256(document["upstreamEvidence"]),
                )
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_ose_storage_semantics_use_authenticated_baserow_and_wikijs_apis(self):
        calls = []

        def request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            if "/api/database/rows/table/" in url:
                self.assertEqual(
                    kwargs["headers"]["Authorization"], "Token baserow-token"
                )
                return 200, {"count": 1, "results": [{"id": 1}]}, {}
            self.assertTrue(url.endswith("/graphql"))
            self.assertEqual(kwargs["headers"]["Authorization"], "Bearer wikijs-token")
            return (
                200,
                {
                    "data": {
                        "system": {
                            "info": {
                                "currentVersion": "2.5.314",
                                "dbType": "postgres",
                                "dbHost": "mte-postgres",
                            }
                        }
                    }
                },
                {},
            )

        with mock.patch.object(self.module, "request", side_effect=request):
            baserow = self.module.semantic_baserow(
                {
                    "BASEROW_PAPERCLIP_TOKEN": "baserow-token",
                    "BASEROW_TABLE_ID": "42",
                },
                "http://127.0.0.1:18085",
            )
            wikijs = self.module.semantic_wikijs(
                {"WIKIJS_API_TOKEN": "wikijs-token"},
                "http://127.0.0.1:18086",
            )
        self.assertEqual(baserow["rowCount"], 1)
        self.assertEqual(wikijs["version"], "2.5.314")
        self.assertEqual(len(calls), 2)

    def test_dependency_evidence_requires_current_source_producer_and_c029_semantics(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "bin").mkdir()
            producer = base / "bin/server-integration-canaries.py"
            producer.write_text("producer-v1")
            baserow_producer = base / "bin/server-baserow.py"
            baserow_producer.write_text("baserow-producer-v1")
            wikijs_producer = base / "bin/server-wikijs.py"
            wikijs_producer.write_text("wikijs-producer-v1")
            evidence = base / "integration-canary-C029.json"
            baserow_evidence = base / "baserow-verify.json"
            wikijs_evidence = base / "wikijs-verify.json"
            source = "7" * 64
            baserow_persistence = {
                "databaseId": 1,
                "tableId": 2,
                "rowId": 3,
                "markerSha256": "4" * 64,
                "restartObserved": True,
                "persistenceVerified": True,
                "postDeleteStatus": 404,
                "cleanupCompleted": True,
            }
            wikijs_persistence = {
                "pageId": 4,
                "pathHashSha256": "3" * 64,
                "markerSha256": "5" * 64,
                "restartObserved": True,
                "persistenceVerified": True,
                "postDeleteStatus": 404,
                "cleanupCompleted": True,
            }
            evidence.write_text(
                json.dumps(
                    {
                        "apiVersion": "micro-task-engine/v1alpha1",
                        "kind": "IntegrationCanaryEvidence",
                        "status": "passed",
                        "generatedAt": self.module.utcnow(),
                        "canonicalSourceSha256": source,
                        "producerSha256": hashlib.sha256(
                            producer.read_bytes()
                        ).hexdigest(),
                        "selected": ["C029"],
                        "canaries": [
                            {
                                "id": "C029",
                                "ok": True,
                                "state": "passed",
                                "source": "controlled_ose_application_restarts",
                                "dataContentProfile": "baserow-wikijs",
                                "roles": {
                                    "tablesUi": "baserow",
                                    "tablesApi": "baserow",
                                    "documentsUi": "wikijs",
                                    "documentsApi": "wikijs",
                                },
                                "tablesPersistence": {
                                    "markerSha256": "4" * 64,
                                    "restartObserved": True,
                                    "persistenceVerified": True,
                                    "postDeleteAbsent": True,
                                    "cleanupCompleted": True,
                                },
                                "documentsPersistence": {
                                    "markerSha256": "5" * 64,
                                    "restartObserved": True,
                                    "persistenceVerified": True,
                                    "postDeleteAbsent": True,
                                    "cleanupCompleted": True,
                                },
                                "baserowPersistence": baserow_persistence,
                                "wikijsPersistence": wikijs_persistence,
                                "osiLicenses": [
                                    {
                                        "component": "baserow",
                                        "version": "2.3.1",
                                        "spdx": "MIT",
                                        "imageDigest": "sha256:496889c4fe22ee6b632698c3c74f7ccaee734c8002b5ebc8d194c5fcacffc98a",
                                        "verified": True,
                                    },
                                    {
                                        "component": "wikijs",
                                        "version": "2.5.314",
                                        "spdx": "AGPL-3.0-only",
                                        "imageDigest": "sha256:68f0d1848261ae76492ba358e30a96a76fed5d97a3fff381656082bf90f70d7e",
                                        "verified": True,
                                    },
                                ],
                                "tablePersistenceVerified": True,
                                "documentPersistenceVerified": True,
                                "applicationRestartObserved": True,
                                "cleanupCompleted": True,
                                "dependencyEvidence": {},
                            }
                        ],
                    }
                )
            )
            evidence.chmod(0o600)
            baserow_evidence.write_text(
                json.dumps(
                    {
                        "apiVersion": "mte.example.test/v1",
                        "kind": "BaserowAcceptance",
                        "status": "passed",
                        "ok": True,
                        "generatedAt": self.module.utcnow(),
                        "canonicalSourceSha256": source,
                        "producerSha256": hashlib.sha256(
                            baserow_producer.read_bytes()
                        ).hexdigest(),
                        "distribution": {
                            "name": "Baserow OSE",
                            "version": "2.3.1",
                            "image": "baserow/baserow:2.3.1@sha256:496889c4fe22ee6b632698c3c74f7ccaee734c8002b5ebc8d194c5fcacffc98a",
                            "platformDigest": "sha256:16d9dd21b3f282c9300d876da66c8036e217143cae0af8f1dd2da5b45af0e30b",
                            "license": "MIT",
                            "licenseSource": "https://github.com/baserow/baserow/blob/2.3.1/LICENSE",
                            "licenseSourceSha256": "1c1fa26d7bb6fddee61c4120803a7190ee3199ac29062bcc1ff0f00a0de08e2b",
                            "enterpriseLicenseConfigured": False,
                            "premiumFeaturesUsed": False,
                        },
                        "restApi": {
                            "ok": True,
                            "tokenCheckStatus": 200,
                            "rowsStatus": 200,
                        },
                        "mcp": {
                            "ok": True,
                            "initializeOk": True,
                            "toolsListOk": True,
                            "toolNames": ["list_rows"],
                        },
                        "baserowPersistence": baserow_persistence,
                    }
                )
            )
            baserow_evidence.chmod(0o600)
            wikijs_evidence.write_text(
                json.dumps(
                    {
                        "apiVersion": "micro-task-engine/v1alpha1",
                        "kind": "WikiJsVerification",
                        "status": "passed",
                        "ok": True,
                        "generatedAt": self.module.utcnow(),
                        "canonicalSourceSha256": source,
                        "producerSha256": hashlib.sha256(
                            wikijs_producer.read_bytes()
                        ).hexdigest(),
                        "image": {
                            "ref": "ghcr.io/requarks/wiki:2.5.314@sha256:68f0d1848261ae76492ba358e30a96a76fed5d97a3fff381656082bf90f70d7e",
                            "version": "2.5.314",
                            "digest": "sha256:68f0d1848261ae76492ba358e30a96a76fed5d97a3fff381656082bf90f70d7e",
                            "upstreamCommit": "6f042e97cc2d3acda6b6ff611de8e0faacce91c1",
                            "license": {
                                "spdx": "AGPL-3.0-only",
                                "source": "https://github.com/requarks/wiki/blob/v2.5.314/LICENSE",
                            },
                        },
                        "graphql": {
                            "pageId": 4,
                            "bearerAuthenticated": True,
                            "restartObserved": True,
                            "persistenceVerified": True,
                            "cleanupCompleted": True,
                            "postDeleteGraphqlMissing": True,
                            "postDeleteStatus404": 404,
                            "pathHashSha256": "3" * 64,
                            "markerSha256": "5" * 64,
                        },
                        "secretAudit": {
                            "rawSecretsPresent": False,
                            "contentMarkerPresent": False,
                        },
                    }
                )
            )
            wikijs_evidence.chmod(0o600)
            document = json.loads(evidence.read_text())
            document["canaries"][0]["dependencyEvidence"] = {
                "baserow": {
                    "path": str(baserow_evidence),
                    "sha256": hashlib.sha256(baserow_evidence.read_bytes()).hexdigest(),
                    "kind": "BaserowAcceptance",
                    "producerSha256": hashlib.sha256(
                        baserow_producer.read_bytes()
                    ).hexdigest(),
                },
                "wikijs": {
                    "path": str(wikijs_evidence),
                    "sha256": hashlib.sha256(wikijs_evidence.read_bytes()).hexdigest(),
                    "kind": "WikiJsVerification",
                    "producerSha256": hashlib.sha256(
                        wikijs_producer.read_bytes()
                    ).hexdigest(),
                },
            }
            evidence.write_text(json.dumps(document))
            with (
                mock.patch.object(
                    self.module, "c029_integration_evidence_path", evidence
                ),
                mock.patch.object(
                    self.module, "baserow_evidence_path", baserow_evidence
                ),
                mock.patch.object(self.module, "wikijs_evidence_path", wikijs_evidence),
                mock.patch.object(self.module, "root", base),
                mock.patch.object(self.module, "exact_mode"),
            ):
                dependencies = self.module.c029_persistence_dependencies(
                    {
                        "sourceSha256": source,
                        "generatorVersion": self.module.generator_contract,
                    },
                    "example.test",
                )
            self.assertEqual(len(dependencies), 3)
            self.assertEqual(
                dependencies[0]["sha256"],
                hashlib.sha256(evidence.read_bytes()).hexdigest(),
            )
            document = json.loads(evidence.read_text())
            document["canaries"][0]["applicationRestartObserved"] = False
            evidence.write_text(json.dumps(document))
            with (
                mock.patch.object(
                    self.module, "c029_integration_evidence_path", evidence
                ),
                mock.patch.object(
                    self.module, "baserow_evidence_path", baserow_evidence
                ),
                mock.patch.object(self.module, "wikijs_evidence_path", wikijs_evidence),
                mock.patch.object(self.module, "root", base),
                mock.patch.object(self.module, "exact_mode"),
                self.assertRaises(self.module.AcceptanceError),
            ):
                self.module.c029_persistence_dependencies(
                    {
                        "sourceSha256": source,
                        "generatorVersion": self.module.generator_contract,
                    },
                    "example.test",
                )

    def test_postgres_notion_c029_binds_fresh_canary_and_connector_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "bin").mkdir()
            integration_producer = base / "bin/server-integration-canaries.py"
            notion_producer = base / "bin/server-notion.py"
            integration_producer.write_text("integration-producer-v1")
            notion_producer.write_text("notion-producer-v1")
            integration = base / "integration-canary-C029.json"
            notion_evidence = base / "notion-connector-verify.json"
            source = "7" * 64

            def postgres_item(seed):
                return {
                    "objectIdSha256": seed * 64,
                    "initialRevision": 1,
                    "finalRevision": 2,
                    "initialContentSha256": "2" * 64,
                    "finalContentSha256": "3" * 64,
                    "created": True,
                    "readBackVerified": True,
                    "updated": True,
                    "projectionIntentVerified": True,
                    "postDeleteAbsent": True,
                    "cleanupVerified": True,
                }

            table = {
                "pageIdSha256": hashlib.sha256(b"page-table").hexdigest(),
                "created": True,
                "queryVerified": True,
                "updated": True,
                "archived": True,
                "cleanupVerified": True,
                "linkageVerified": True,
            }
            document = {
                "pageIdSha256": hashlib.sha256(b"page-document").hexdigest(),
                "created": True,
                "appendVerified": True,
                "readBackVerified": True,
                "archived": True,
                "cleanupVerified": True,
                "linkageVerified": True,
            }
            cleanup = {
                "postgresRecordDeleted": True,
                "postgresDocumentDeleted": True,
                "postgresProjectionRowsDeleted": True,
                "notionTableRowArchived": True,
                "notionDocumentArchived": True,
                "verified": True,
            }
            dependency = {
                "path": str(notion_evidence),
                "sha256": "0" * 64,
                "kind": "NotionConnectorVerification",
                "producerSha256": hashlib.sha256(
                    notion_producer.read_bytes()
                ).hexdigest(),
            }
            row = {
                "id": "C029",
                "ok": True,
                "state": "passed",
                "source": "server_notion_connector_canary",
                "dataContentProfile": "postgres-notion",
                "roles": {
                    "tablesUi": "notion",
                    "tablesApi": "notion",
                    "documentsUi": "notion",
                    "documentsApi": "notion",
                },
                "postgresSsot": {
                    "record": postgres_item("a"),
                    "document": postgres_item("b"),
                },
                "notion": {"table": table, "document": document},
                "tablePersistenceVerified": True,
                "documentPersistenceVerified": True,
                "crossProviderLinkageVerified": True,
                "cleanupCompleted": True,
                "cleanup": cleanup,
                "redacted": True,
                "dependencyEvidence": dependency,
            }
            integration.write_text(
                json.dumps(
                    {
                        "apiVersion": "micro-task-engine/v1alpha1",
                        "kind": "IntegrationCanaryEvidence",
                        "status": "passed",
                        "generatedAt": self.module.utcnow(),
                        "canonicalSourceSha256": source,
                        "producerSha256": hashlib.sha256(
                            integration_producer.read_bytes()
                        ).hexdigest(),
                        "selected": ["C029"],
                        "canaries": [row],
                    }
                )
            )
            notion_evidence.write_text(
                json.dumps(
                    {
                        "apiVersion": "micro-task-engine/v1alpha1",
                        "kind": "NotionConnectorVerification",
                        "status": "passed",
                        "ok": True,
                        "generatedAt": self.module.utcnow(),
                        "canonicalSourceSha256": source,
                        "producerSha256": hashlib.sha256(
                            notion_producer.read_bytes()
                        ).hexdigest(),
                        "dataContentProfile": "postgres-notion",
                        "notionApiVersion": "2025-09-03",
                        "identity": {
                            "botId": "bot-id",
                            "workspaceId": "workspace-id",
                            "botExact": True,
                            "workspaceExact": True,
                        },
                        "resources": {
                            "root": {"exact": True},
                            "documents": {"exact": True},
                            "database": {"exact": True},
                            "dataSource": {"exact": True},
                        },
                        "schema": {
                            "exact": True,
                            "properties": {"Name": {"type": "title"}},
                        },
                        "canary": {
                            "kind": "NotionConnectorCanary",
                            "status": "passed",
                            "ok": True,
                            "dataContentProfile": "postgres-notion",
                            "canonicalSourceSha256": source,
                            "producerSha256": hashlib.sha256(
                                notion_producer.read_bytes()
                            ).hexdigest(),
                            "linkage": {
                                kind: {
                                    key: value
                                    for key, value in row["postgresSsot"][kind].items()
                                    if key
                                    in {
                                        "objectIdSha256",
                                        "initialRevision",
                                        "finalRevision",
                                        "initialContentSha256",
                                        "finalContentSha256",
                                    }
                                }
                                for kind in ("record", "document")
                            },
                            "notion": {
                                "table": {**table, "pageId": "page-table"},
                                "document": {
                                    **document,
                                    "pageId": "page-document",
                                },
                            },
                            "redacted": True,
                        },
                        "cleanup": {"verified": True},
                        "redacted": True,
                        "secretAudit": {
                            "tokenPresent": False,
                            "rawMarkerPresent": False,
                        },
                    }
                )
            )
            integration_document = json.loads(integration.read_text())
            integration_document["canaries"][0]["dependencyEvidence"]["sha256"] = (
                hashlib.sha256(notion_evidence.read_bytes()).hexdigest()
            )
            integration.write_text(json.dumps(integration_document))
            integration.chmod(0o600)
            notion_evidence.chmod(0o600)
            with (
                mock.patch.object(
                    self.module, "c029_integration_evidence_path", integration
                ),
                mock.patch.object(self.module, "notion_evidence_path", notion_evidence),
                mock.patch.object(self.module, "root", base),
                mock.patch.object(self.module, "exact_mode"),
            ):
                dependencies = self.module.c029_persistence_dependencies(
                    {
                        "sourceSha256": source,
                        "generatorVersion": self.module.generator_contract,
                    },
                    "example.test",
                )
            self.assertEqual(len(dependencies), 2)
            self.assertEqual(dependencies[0]["kind"], "IntegrationCanaryEvidence")
            self.assertEqual(dependencies[1]["kind"], "NotionConnectorVerification")
            self.assertEqual(dependencies[1]["path"], str(notion_evidence))

            notion_document = json.loads(notion_evidence.read_text())
            notion_document["secretAudit"]["tokenPresent"] = True
            notion_evidence.write_text(json.dumps(notion_document))
            with (
                mock.patch.object(
                    self.module, "c029_integration_evidence_path", integration
                ),
                mock.patch.object(self.module, "notion_evidence_path", notion_evidence),
                mock.patch.object(self.module, "root", base),
                mock.patch.object(self.module, "exact_mode"),
                self.assertRaises(self.module.AcceptanceError) as raised,
            ):
                self.module.c029_persistence_dependencies(
                    {
                        "sourceSha256": source,
                        "generatorVersion": self.module.generator_contract,
                    },
                    "example.test",
                )
            self.assertEqual(
                raised.exception.code, "notion_connector_canary_dependency_invalid"
            )

    def test_observability_dependency_requires_all_three_real_datasource_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "bin").mkdir()
            producer = base / "bin/server-observability-canary.py"
            producer.write_text("producer-v1")
            evidence = base / "observability-data-canary.json"
            source = "8" * 64
            evidence.write_text(
                json.dumps(
                    {
                        "apiVersion": "micro-task-engine/v1alpha1",
                        "kind": "ObservabilityDataCanaryEvidence",
                        "status": "passed",
                        "completedAt": self.module.utcnow(),
                        "sourceGate": {
                            "sourceSha256": source,
                            "generatorVersion": self.module.generator_contract,
                        },
                        "producerSha256": hashlib.sha256(
                            producer.read_bytes()
                        ).hexdigest(),
                        "checks": {
                            "C045": {
                                "status": "pass",
                                "health": {
                                    "victoriametrics": 200,
                                    "victorialogs": 200,
                                    "victoriatraces": 200,
                                },
                                "metricSeries": 1,
                                "logsFound": True,
                                "traceFound": True,
                            }
                        },
                    }
                )
            )
            evidence.chmod(0o600)
            with (
                mock.patch.object(self.module, "observability_evidence_path", evidence),
                mock.patch.object(self.module, "root", base),
                mock.patch.object(self.module, "exact_mode"),
            ):
                dependency = self.module.c046_datasource_dependency(
                    {
                        "sourceSha256": source,
                        "generatorVersion": self.module.generator_contract,
                    }
                )
            self.assertEqual(
                dependency["sha256"], hashlib.sha256(evidence.read_bytes()).hexdigest()
            )

    def test_firecrawl_requires_unauthorized_anonymous_and_controlled_marker(self):
        marker = "MTE-C026-" + "ab" * 12
        get_urls = []

        def fake_request(method, url, **kwargs):
            if method == "GET":
                get_urls.append(url)
                if not kwargs.get("headers"):
                    return 401, None, {}
                return 200, {"status": "ok"}, {}
            self.assertIn("/v1/scrape", url)
            self.assertTrue(kwargs["body"]["url"].startswith("http://mte-cf-marker-"))
            return 200, {"data": {"markdown": marker}}, {}

        completed = subprocess.CompletedProcess([], 0, "removed", "")
        values = {
            "CLOUDFLARE_ACCESS_CLIENT_ID": "cf-client-id-value-7f4a9c21",
            "CLOUDFLARE_ACCESS_CLIENT_SECRET": "cf-client-secret-value-a83bd695",
            "CLOUDFLARE_ACCESS_SERVICE_TOKEN_ID": "cf-service-token-value-31c6e2d8",
            "CLOUDFLARE_ACCESS_EXPIRES_AT": "2099-01-01T00:00:00.000000+00:00",
            "FIRECRAWL_API_KEY": "firecrawl-key-value-d40b8e17",
            "FIRECRAWL_HEALTH_URL": "http://127.0.0.1:13002/",
        }
        with (
            mock.patch.object(self.module, "request", side_effect=fake_request),
            mock.patch.object(self.module, "docker_run", return_value=completed),
            mock.patch.object(self.module.secrets, "token_hex", return_value="ab" * 12),
            mock.patch.object(self.module.time, "sleep"),
        ):
            row = self.module.firecrawl_row(
                values,
                {
                    "hostname": "firecrawl.example.test",
                    "accessClass": "service",
                },
            )
        self.assertTrue(row["anonymousDenied"])
        self.assertEqual(row["serviceTokenStatus"], 200)
        self.assertEqual(row["healthPath"], "/")
        self.assertEqual(
            get_urls,
            ["https://firecrawl.example.test/", "https://firecrawl.example.test/"],
        )
        self.assertTrue(all(not url.endswith("/health") for url in get_urls))
        self.assertTrue(row["serviceTokenExpiryVerified"])
        self.assertFalse(row["serviceTokenCredentialValuesEmitted"])
        self.assertTrue(row["controlledScrapeMarkerObserved"])
        self.assertTrue(row["markerContainerRemoved"])
        encoded = json.dumps(row, sort_keys=True)
        self.assertTrue(all(values[key] not in encoded for key in values))

    def test_grafana_semantic_validates_exact_declarative_dashboard(self):
        calls = []

        def fake_request(method, url, **kwargs):
            calls.append((method, url))
            if url.endswith("/api/datasources"):
                return (
                    200,
                    [
                        {"uid": "victoriametrics"},
                        {"uid": "victorialogs"},
                        {"uid": "victoriatraces"},
                    ],
                    {},
                )
            return (
                200,
                {
                    "dashboard": {
                        "uid": "mte-platform-overview",
                        "title": "MTE Platform: Agents and Services",
                        "tags": ["mte", "agents", "task_id", "run_id"],
                        "editable": False,
                        "panels": [
                            {
                                "title": "Platform endpoints up",
                                "type": "stat",
                                "datasource": {"uid": "victoriametrics"},
                            },
                            {
                                "title": "Endpoint availability",
                                "type": "timeseries",
                                "datasource": {"uid": "victoriametrics"},
                            },
                            {
                                "title": "Task and run log search",
                                "type": "logs",
                                "datasource": {"uid": "victorialogs"},
                            },
                        ],
                    },
                    "meta": {"folderUid": "mte-platform"},
                },
                {},
            )

        with mock.patch.object(self.module, "request", side_effect=fake_request):
            value = self.module.semantic_grafana(
                {"GRAFANA_ADMIN_USER": "admin", "GRAFANA_ADMIN_PASSWORD": "password"},
                "http://127.0.0.1:13000",
            )
        self.assertTrue(value["dashboardProvisioned"])
        self.assertEqual(value["requiredPanels"], 3)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(method == "GET" for method, _url in calls))

    def test_tofu_gate_requires_zero_exit_safe_modes_and_no_token_in_tfvars(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            iac = base / "iac"
            iac.mkdir()
            (iac / "terraform.tfstate").write_text("{}")
            (iac / "terraform.tfvars.json").write_text(
                json.dumps({"base_domain": "example.test"})
            )
            api_env = base / "api.env"
            api_env.write_text("CLOUDFLARE_API_TOKEN=not-a-real-token\n")
            lock = base / "platform.lock.yaml"
            lock.write_text(
                "spec:\n  images:\n    openTofu: example/tofu@sha256:" + "1" * 64 + "\n"
            )

            def run(command, **_kwargs):
                if "plan" in command:
                    output = next(
                        value.split("/workspace/", 1)[1]
                        for value in command
                        if value.startswith("-out=/workspace/")
                    )
                    (iac / output).write_bytes(b"fresh-empty-plan")
                    return subprocess.CompletedProcess(command, 0, "", "")
                self.assertIn("show", command)
                return subprocess.CompletedProcess(
                    command,
                    0,
                    json.dumps(
                        {
                            "timestamp": self.module.utcnow(),
                            "applyable": False,
                            "complete": True,
                            "errored": False,
                            "resource_changes": [{"change": {"actions": ["no-op"]}}],
                            "resource_drift": [],
                            "output_changes": {},
                        }
                    ),
                    "",
                )

            with (
                mock.patch.object(self.module, "iac_root", iac),
                mock.patch.object(self.module, "api_env_path", api_env),
                mock.patch.object(self.module, "lock_path", lock),
                mock.patch.object(self.module, "exact_mode"),
                mock.patch.object(self.module.subprocess, "run", side_effect=run),
            ):
                value = self.module.tofu_status(
                    {"CLOUDFLARE_API_TOKEN": "not-a-real-token"}
                )
        self.assertEqual(value["tofuDetailedExitCode"], 0)
        self.assertEqual(value["changes"], {"create": 0, "update": 0, "delete": 0})
        self.assertEqual((value["create"], value["update"], value["delete"]), (0, 0, 0))
        self.assertFalse(value["savedPlanApplyable"])
        self.assertEqual(value["savedPlanActionCounts"]["create"], 0)
        self.assertTrue(value["savedPlanPath"].endswith("/acceptance-empty.tfplan"))
        self.assertRegex(value["savedPlanSha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(value["tfvarsContainsApiToken"])

    def test_tofu_gate_rejects_saved_plan_with_twenty_nine_creates(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            iac = base / "iac"
            iac.mkdir()
            (iac / "terraform.tfstate").write_text("{}")
            (iac / "terraform.tfvars.json").write_text('{"base_domain":"example.test"}')
            api_env = base / "api.env"
            api_env.write_text("CLOUDFLARE_API_TOKEN=hidden\n")
            lock = base / "platform.lock.yaml"
            lock.write_text(
                "spec:\n  images:\n    openTofu: example/tofu@sha256:" + "1" * 64 + "\n"
            )

            def run(command, **_kwargs):
                if "plan" in command:
                    output = next(
                        value.split("/workspace/", 1)[1]
                        for value in command
                        if value.startswith("-out=/workspace/")
                    )
                    (iac / output).write_bytes(b"old-29-create-plan")
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(
                    command,
                    0,
                    json.dumps(
                        {
                            "timestamp": self.module.utcnow(),
                            "applyable": False,
                            "complete": True,
                            "errored": False,
                            "resource_changes": [
                                {"change": {"actions": ["create"]}} for _ in range(29)
                            ],
                            "resource_drift": [],
                            "output_changes": {},
                        }
                    ),
                    "",
                )

            with (
                mock.patch.object(self.module, "iac_root", iac),
                mock.patch.object(self.module, "api_env_path", api_env),
                mock.patch.object(self.module, "lock_path", lock),
                mock.patch.object(self.module, "exact_mode"),
                mock.patch.object(self.module.subprocess, "run", side_effect=run),
                self.assertRaisesRegex(
                    self.module.AcceptanceError, "opentofu_saved_plan_not_empty"
                ),
            ):
                self.module.tofu_status({"CLOUDFLARE_API_TOKEN": "not-a-real-token"})
            self.assertFalse((iac / "acceptance-empty.tfplan").exists())

    def test_run_acceptance_emits_exact_connection_contract_and_hash_fields(self):
        source_hash = "1" * 64
        apps = {
            **{
                app_id: {
                    "hostname": app_id + ".example.test",
                    "origin": "http://127.0.0.1:1000",
                    "accessClass": "human",
                }
                for app_id in self.module.human_connections.values()
            },
            "firecrawl": {
                "hostname": "firecrawl.example.test",
                "origin": "http://127.0.0.1:1001",
                "accessClass": "service",
            },
            "service-a": {
                "hostname": "a.example.test",
                "origin": "http://127.0.0.1:1002",
                "accessClass": "service",
            },
            "service-b": {
                "hostname": "b.example.test",
                "origin": "http://127.0.0.1:1003",
                "accessClass": "service",
            },
            "human-a": {
                "hostname": "c.example.test",
                "origin": "http://127.0.0.1:1004",
                "accessClass": "human",
            },
        }
        # Notion is external; the active Platform declarations govern the ten
        # locally deployed edge applications without a parallel magic count.
        self.assertEqual(len(apps), 10)
        app_config = self.app_config(*apps)
        human = {
            cid: {
                "id": cid,
                "ok": True,
                "state": "passed",
                "canonicalHostname": app + ".example.test",
                "expectedAccessClass": "human",
                "edgeGateVerified": True,
                "serviceSemanticVerified": True,
                "dependencyEvidence": [],
                "anonymousStatus": 302,
                "accessLocationVerified": True,
            }
            for cid, app in self.module.human_connections.items()
        }
        human["C029"] = {
            "id": "C029",
            "ok": True,
            "state": "passed",
            "canonicalHostname": "api.notion.com",
            "canonicalHostnames": [],
            "expectedAccessClass": "external-saas",
            "cloudflareManaged": False,
            "edgeGateApplicable": False,
            "edgeGateVerified": False,
            "serviceSemanticVerified": False,
            "originSemanticVerified": False,
            "originAuthenticationVerified": False,
            "dependencyEvidence": [],
            "edgeApplications": [],
            "externalProvider": "notion",
            "dataContentProfile": "postgres-notion",
            "dataContentProjectionSha256": "9" * 64,
            "dataContentApplications": [],
            "dataContentRoles": {
                "tablesUi": {
                    "providerId": "notion",
                    "capability": "tables",
                    "interface": "ui",
                    "adapterId": "notion",
                },
                "tablesApi": {
                    "providerId": "notion",
                    "capability": "tables",
                    "interface": "api",
                    "adapterId": "notion",
                },
                "documentsUi": {
                    "providerId": "notion",
                    "capability": "documents",
                    "interface": "ui",
                    "adapterId": "notion",
                },
                "documentsApi": {
                    "providerId": "notion",
                    "capability": "documents",
                    "interface": "api",
                    "adapterId": "notion",
                },
            },
        }
        data_content = {
            "profile": "postgres-notion",
            "projectionSha256": "9" * 64,
            "edgeManaged": False,
            "providerId": "notion",
            "roles": {},
            "roleBindings": human["C029"]["dataContentRoles"],
            "applicationIds": [],
        }
        firecrawl = {
            "id": "C026",
            "ok": True,
            "state": "passed",
            "canonicalHostname": "firecrawl.example.test",
            "expectedAccessClass": "service",
            "edgeGateVerified": True,
            "serviceSemanticVerified": True,
            "dependencyEvidence": [],
            "anonymousDenied": True,
            "serviceTokenStatus": 200,
            "controlledScrapeMarkerObserved": True,
        }
        inventory = {
            "tunnelName": "mte-test",
            "tunnelHealthy": True,
            "connectorCount": 4,
            "routes": {str(index): str(index) for index in range(10)},
            "dnsRecordCount": 10,
            "accessApplicationCount": 10,
            "accessPolicyCount": 2,
            "humanAccessPolicyScoped": True,
            "serviceAccessTokenScoped": True,
            "foreign": [{}, {}],
        }
        external = {
            "expectedHost": "198.51.100.10",
            "evidenceSha256": "2" * 64,
            "externalPortsBlocked": {"80": True, "443": True, "3000": True},
        }
        firewall = {
            "firewallV4Input": True,
            "firewallV4Docker": True,
            "firewallV6Input": True,
            "firewallV6Docker": True,
        }
        tofu = {
            "tofuDetailedExitCode": 0,
            "create": 0,
            "update": 0,
            "delete": 0,
            "changes": {"create": 0, "update": 0, "delete": 0},
            "iacDirMode": "0700",
            "stateMode": "0600",
            "tfvarsContainsApiToken": False,
            "savedPlanPath": "/root/.config/mte-secrets/cloudflare/iac/acceptance-empty.tfplan",
            "savedPlanSha256": "c" * 64,
            "savedPlanGeneratedAt": self.module.utcnow(),
            "savedPlanAgeSeconds": 0.1,
            "savedPlanMode": "0600",
            "savedPlanOwner": "root:root",
            "savedPlanApplyable": False,
            "savedPlanComplete": True,
            "savedPlanErrored": False,
            "savedPlanActionCounts": {
                "create": 0,
                "update": 0,
                "delete": 0,
                "forget": 0,
                "import": 0,
                "read": 0,
                "no-op": 10,
            },
        }
        installed = Path(self.module.__file__).resolve()
        with (
            mock.patch.object(self.module.os, "geteuid", return_value=0),
            mock.patch.object(self.module, "producer_path_expected", installed),
            mock.patch.object(self.module, "exact_mode"),
            mock.patch.object(
                self.module,
                "exact_hash_gate",
                return_value=(
                    {
                        "sourceSha256": source_hash,
                        "generatorVersion": self.module.generator_contract,
                    },
                    {"kind": "Platform", **app_config},
                    {"apps": apps},
                ),
            ),
            mock.patch.object(
                self.module,
                "read_env",
                return_value={
                    "PLATFORM_BASE_DOMAIN": "example.test",
                    "MTE_SSH_TARGET": "root@198.51.100.10",
                },
            ),
            mock.patch.object(self.module, "app_rows", return_value=apps),
            mock.patch.object(
                self.module,
                "data_content_edge_contract",
                return_value=data_content,
            ),
            mock.patch.object(
                self.module, "cloudflare_inventory", return_value=inventory
            ),
            mock.patch.object(self.module, "human_rows", return_value=human),
            mock.patch.object(self.module, "firecrawl_row", return_value=firecrawl),
            mock.patch.object(
                self.module,
                "write_semantic_evidence",
                return_value={
                    "path": "/opt/mte-platform/evidence/cloudflare-app-semantics.json",
                    "sha256": "4" * 64,
                },
            ),
            mock.patch.object(
                self.module,
                "write_connection_evidence",
                return_value={
                    connection_id: {
                        "path": f"/opt/mte-platform/evidence/cloudflare-connection-{connection_id}.json",
                        "sha256": "a" * 64,
                        "kind": "CloudflareConnectionEvidence",
                        "producerSha256": "b" * 64,
                    }
                    for connection_id in self.module.connection_evidence_ids
                },
            ),
            mock.patch.object(
                self.module,
                "c029_persistence_dependencies",
                return_value=[
                    {
                        "path": "/opt/mte-platform/evidence/integration-canary-C029.json",
                        "sha256": "5" * 64,
                        "kind": "IntegrationCanaryEvidence",
                        "producerSha256": "d" * 64,
                    },
                    {
                        "path": "/opt/mte-platform/evidence/notion-connector-verify.json",
                        "sha256": "7" * 64,
                        "kind": "NotionConnectorVerification",
                        "producerSha256": "e" * 64,
                    },
                ],
            ),
            mock.patch.object(
                self.module,
                "c046_datasource_dependency",
                return_value={
                    "path": "/opt/mte-platform/evidence/observability-data-canary.json",
                    "sha256": "6" * 64,
                },
            ),
            mock.patch.object(
                self.module, "validate_observation", return_value=external
            ),
            mock.patch.object(self.module, "firewall_status", return_value=firewall),
            mock.patch.object(
                self.module,
                "cloudflared_status",
                return_value={"cloudflaredRunning": True, "restartCount": 0},
            ),
            mock.patch.object(self.module, "tofu_status", return_value=tofu),
            mock.patch.object(
                self.module,
                "sha256_file",
                side_effect=lambda path: (
                    hashlib.sha256(installed.read_bytes()).hexdigest()
                    if path == installed
                    else "3" * 64
                ),
            ),
            mock.patch.object(self.module, "atomic_json") as write,
        ):
            payload = self.module.run_acceptance(Path("/tmp/observer.json"))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["canonicalSourceSha256"], source_hash)
        self.assertEqual(payload["sourceGate"]["sourceSha256"], source_hash)
        self.assertEqual(set(payload["connections"]), set(self.module.connection_ids))
        self.assertEqual(
            set(payload["connectionEvidence"]),
            set(self.module.connection_evidence_ids),
        )
        self.assertTrue(all(row["ok"] for row in payload["connections"].values()))
        self.assertTrue(payload["connections"]["C029"]["tablePersistenceVerified"])
        self.assertEqual(
            payload["connections"]["C029"]["dataContentProfile"], "postgres-notion"
        )
        self.assertEqual(
            payload["connections"]["C029"]["dataContentApplications"],
            [],
        )
        self.assertFalse(payload["connections"]["C029"]["cloudflareManaged"])
        self.assertFalse(payload["connections"]["C029"]["edgeGateApplicable"])
        self.assertTrue(payload["connections"]["C029"]["notionConnectorVerified"])
        self.assertEqual(len(payload["connections"]["C029"]["dependencyEvidence"]), 2)
        self.assertTrue(payload["connections"]["C046"]["dashboardProvisioned"])
        self.assertEqual(payload["connections"]["C067"]["savedPlanSha256"], "c" * 64)
        for connection_id in ("C029", "C046", "C065", "C066", "C067"):
            self.assertEqual(
                payload["connections"][connection_id]["connectionEvidence"],
                payload["connectionEvidence"][connection_id],
            )
        self.assertEqual(
            payload["connections"]["C067"]["changes"],
            {
                "create": 0,
                "update": 0,
                "delete": 0,
            },
        )
        write.assert_called_once()


if __name__ == "__main__":
    unittest.main()

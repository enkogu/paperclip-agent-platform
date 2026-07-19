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
    def origin_firewall_status_payload() -> dict[str, object]:
        return {
            "firewallPolicyVersion": "mte-origin-firewall/v2",
            "firewallServiceActive": True,
            "firewallServiceEnabled": True,
            "firewallRecoveryTimerActive": True,
            "firewallRecoveryTimerEnabled": True,
            "publicInterface": "eth0",
            "publicInterfaceV4": "eth0",
            "publicInterfaceV6": "eth0",
            "operatorSshCidrsSha256": "a" * 64,
            "firewallSshCidrCount": 2,
            "firewallSshIpv4CidrCount": 1,
            "firewallSshIpv6CidrCount": 1,
            "firewallSshCidrsEnforced": True,
            "firewallV4Established": True,
            "firewallV6Established": True,
            "firewallV4InputTcpDrop": True,
            "firewallV4InputUdpDrop": True,
            "firewallV4DockerTcpDrop": True,
            "firewallV4DockerUdpDrop": True,
            "firewallV6InputTcpDrop": True,
            "firewallV6InputUdpDrop": True,
            "firewallV6DockerTcpDrop": True,
            "firewallV6DockerUdpDrop": True,
            "firewallV4Input": True,
            "firewallV4Docker": True,
            "firewallV6Input": True,
            "firewallV6Docker": True,
            "udp443Blocked": True,
            "publicTcpDefaultDenied": True,
            "publicUdpDefaultDenied": True,
        }

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
            all(
                not value["ports"][str(port)]["open"]
                for port in (80, 443, 2377, 3000, 7946, 20241)
            )
        )
        self.assertEqual(
            value["producerSha256"],
            hashlib.sha256(
                (
                    ROOT / "tools/platform-cli/server-cloudflare-acceptance.py"
                ).read_bytes()
            ).hexdigest(),
        )

    def test_exact_mode_rejects_a_symlink_even_when_the_target_mode_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            link = root / "link.json"
            target.write_text("{}")
            target.chmod(0o600)
            link.symlink_to(target)
            with self.assertRaises(self.module.AcceptanceError) as raised:
                self.module.exact_mode(link, 0o600, root_owned=False)
        self.assertEqual(raised.exception.code, "unsafe_file_symlink")

    def test_firewall_status_consumes_the_v2_status_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            step = Path(directory) / "origin-firewall.sh"
            step.write_text("#!/usr/bin/env bash\n")
            step.chmod(0o755)
            completed = subprocess.CompletedProcess(
                [str(step), "status"],
                0,
                json.dumps(self.origin_firewall_status_payload()),
                "",
            )
            with (
                mock.patch.object(self.module, "origin_firewall_step_path", step),
                mock.patch.object(self.module, "exact_mode") as exact_mode,
                mock.patch.object(self.module, "docker_run", return_value=completed),
            ):
                result = self.module.firewall_status()
        exact_mode.assert_called_once_with(step, 0o700)
        self.assertEqual(result["firewallPolicyVersion"], "mte-origin-firewall/v2")
        self.assertTrue(result["firewallV4DockerTcpDrop"])
        self.assertTrue(result["firewallV6InputUdpDrop"])

    def test_firewall_status_fails_closed_for_the_obsolete_rule_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            step = Path(directory) / "origin-firewall.sh"
            step.write_text("#!/usr/bin/env bash\n")
            step.chmod(0o755)
            payload = self.origin_firewall_status_payload()
            payload["firewallPolicyVersion"] = "mte-origin-firewall/v1"
            completed = subprocess.CompletedProcess(
                [str(step), "status"], 0, json.dumps(payload), ""
            )
            with (
                mock.patch.object(self.module, "origin_firewall_step_path", step),
                mock.patch.object(self.module, "exact_mode"),
                mock.patch.object(self.module, "docker_run", return_value=completed),
                self.assertRaises(self.module.AcceptanceError) as raised,
            ):
                self.module.firewall_status()
        self.assertEqual(raised.exception.code, "origin_firewall_contract_failed")

    def test_cloudflared_status_runs_the_canonical_runtime_verifier_first(self):
        with tempfile.TemporaryDirectory() as directory:
            step = Path(directory) / "cloudflare-tunnel.sh"
            step.write_text("#!/usr/bin/env bash\n")
            step.chmod(0o755)
            calls: list[list[str]] = []

            def run(args, **_kwargs):
                calls.append(args)
                if args == [str(step), "verify"]:
                    return subprocess.CompletedProcess(args, 0, "", "")
                if args[3] == "{{json .State}}":
                    return subprocess.CompletedProcess(args, 0, '{"Running": true}', "")
                if args[3] == "{{.RestartCount}}":
                    return subprocess.CompletedProcess(args, 0, "0\n", "")
                raise AssertionError(args)

            with (
                mock.patch.object(self.module, "cloudflared_step_path", step),
                mock.patch.object(self.module, "exact_mode") as exact_mode,
                mock.patch.object(self.module, "docker_run", side_effect=run),
            ):
                result = self.module.cloudflared_status(
                    {"CLOUDFLARED_CONTAINER_NAME": "mte-cloudflared"}
                )
        exact_mode.assert_called_once_with(step, 0o700)
        self.assertEqual(calls[0], [str(step), "verify"])
        self.assertTrue(result["cloudflaredRunning"])
        self.assertTrue(result["cloudflaredRuntimeConfigVerified"])

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
                    "2377": {"open": False},
                    "3000": {"open": False},
                    "7946": {"open": False},
                    "20241": {"open": False},
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
                result["externalPortsBlocked"],
                {
                    "80": True,
                    "443": True,
                    "2377": True,
                    "3000": True,
                    "7946": True,
                    "20241": True,
                },
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

    def test_postgres_notion_real_declarations_resolve_nine_edge_apps(self):
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
                "firecrawl",
                "kestra",
                "mattermost",
                "observability",
                "paperclip",
                "postgrest",
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
                            "ttl": 1,
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
                                "ttl": 1,
                                "proxied": False,
                                "comment": "",
                            },
                            {
                                "id": "foreign-2",
                                "name": "chat.example.test",
                                "type": "A",
                                "content": "192.0.2.11",
                                "ttl": 1,
                                "proxied": False,
                                "comment": "",
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
                                        else "policy-service-" + app_id
                                    )
                                }
                            ],
                            "app_launcher_visible": row["accessClass"] == "human",
                            "service_auth_401_redirect": row["accessClass"]
                            == "service",
                        }
                        for index, (app_id, row) in enumerate(apps.items())
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
                if "/policies/policy-service-" in path:
                    app_id = path.rsplit("policy-service-", 1)[-1]
                    return {
                        "decision": "non_identity",
                        "include": [
                            {
                                "service_token": {
                                    "token_id": "service-token-id-" + app_id
                                }
                            }
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
        }
        for app_id, row in apps.items():
            if row["accessClass"] != "service":
                continue
            prefix = "CLOUDFLARE_ACCESS_ROUTE_" + app_id.upper().replace("-", "_")
            values.update(
                {
                    prefix + "_ID": "service-token-id-" + app_id,
                    prefix + "_CLIENT_ID": "client-id-123456-" + app_id,
                    prefix + "_CLIENT_SECRET": "s" * 48,
                    prefix + "_EXPIRES_AT": "2099-01-01T00:00:00+00:00",
                }
            )
        with mock.patch.object(self.module, "CloudflareApi", FakeApi):
            result = self.module.cloudflare_inventory(values, apps)
        self.assertEqual(result["dnsRecordCount"], 12)
        self.assertEqual(result["accessApplicationCount"], 12)
        self.assertEqual(result["accessPolicyCount"], 4)
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
        apps["documents-ui"] = {
            "hostname": "docs.example.test",
            "origin": "http://127.0.0.1:1235",
            "accessClass": "human",
        }
        apps["tables-ui"] = {
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
                    "applicationId": "tables-ui",
                    "hostname": "tables.example.test",
                    "accessClass": "human",
                },
                "documentsUi": {
                    "applicationId": "documents-ui",
                    "hostname": "docs.example.test",
                    "accessClass": "human",
                },
            },
            "roleBindings": {},
            "applicationIds": ["documents-ui", "tables-ui"],
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
        self.assertEqual(
            rows["C029"]["dataContentApplications"],
            ["tables-ui", "documents-ui"],
        )
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
            projection["dataContent"]["roles"]["tablesUi"]["applicationId"] = (
                "missing-app"
            )
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
                (
                    ROOT / "tools/platform-cli/server-cloudflare-acceptance.py"
                ).read_bytes()
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

    def test_postgres_notion_c029_requires_consumer_canary_and_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "bin").mkdir()
            integration_producer = base / "bin/server-integration-canaries.py"
            notion_producer = base / "bin/server-notion-sync.py"
            integration_producer.write_text("integration-producer-v1")
            notion_producer.write_text("notion-consumer-producer-v1")
            integration = base / "integration-canary-C029.json"
            canary_evidence = base / "notion-projection-live-canary.json"
            verification_evidence = base / "notion-projection-consumer-verify.json"
            source = "7" * 64
            producer_sha = hashlib.sha256(notion_producer.read_bytes()).hexdigest()

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

            postgres = {
                "record": postgres_item("a"),
                "document": postgres_item("b"),
            }
            table = {
                "pageIdSha256": "c" * 64,
                "created": True,
                "queryVerified": True,
                "updated": True,
                "archived": True,
                "cleanupVerified": True,
                "linkageVerified": True,
            }
            notion_document = {
                "pageIdSha256": "d" * 64,
                "created": True,
                "appendVerified": True,
                "readBackVerified": True,
                "archived": True,
                "cleanupVerified": True,
                "linkageVerified": True,
            }
            canary = {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "NotionProjectionLiveCanary",
                "status": "passed",
                "ok": True,
                "generatedAt": self.module.utcnow(),
                "canonicalSourceSha256": source,
                "producerSha256": producer_sha,
                "dataContentProfile": "postgres-notion",
                "provider": "notion",
                "linkage": {
                    "entity": {
                        "canonicalObjectIdSha256": postgres["record"]["objectIdSha256"],
                        "providerObjectIdSha256": table["pageIdSha256"],
                        "initialRevision": 1,
                        "finalRevision": 2,
                        "initialContentSha256": "2" * 64,
                        "finalContentSha256": "3" * 64,
                    },
                    "document": {
                        "canonicalObjectIdSha256": postgres["document"][
                            "objectIdSha256"
                        ],
                        "providerObjectIdSha256": notion_document["pageIdSha256"],
                        "initialRevision": 1,
                        "finalRevision": 2,
                        "initialContentSha256": "2" * 64,
                        "finalContentSha256": "3" * 64,
                    },
                },
                "cleanup": {"verified": True},
                "evidence": {"path": str(canary_evidence), "mode": "0600"},
                "redacted": True,
            }
            verification = {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "NotionProjectionConsumerVerification",
                "status": "passed",
                "ok": True,
                "generatedAt": self.module.utcnow(),
                "canonicalSourceSha256": source,
                "producerSha256": producer_sha,
                "dataContentProfile": "postgres-notion",
                "provider": "notion",
                "delivery": {
                    "pending": 0,
                    "processing": 0,
                    "failed": 0,
                    "eligible": 0,
                    "exhausted": 0,
                    "expiredLeases": 0,
                    "schemaReady": True,
                },
                "systemd": {"serviceActive": True, "timerActive": True},
                "evidence": {"path": str(verification_evidence), "mode": "0600"},
                "redacted": True,
            }
            canary_evidence.write_text(json.dumps(canary))
            verification_evidence.write_text(json.dumps(verification))
            canary_reference = {
                "path": str(canary_evidence),
                "sha256": hashlib.sha256(canary_evidence.read_bytes()).hexdigest(),
                "kind": "NotionProjectionLiveCanary",
                "producerSha256": producer_sha,
            }
            verification_reference = {
                "path": str(verification_evidence),
                "sha256": hashlib.sha256(
                    verification_evidence.read_bytes()
                ).hexdigest(),
                "kind": "NotionProjectionConsumerVerification",
                "producerSha256": producer_sha,
            }
            row = {
                "id": "C029",
                "ok": True,
                "state": "passed",
                "source": "server_notion_projection_consumer_canary",
                "dataContentProfile": "postgres-notion",
                "roles": {
                    "tablesUi": "notion",
                    "tablesApi": "notion",
                    "documentsUi": "notion",
                    "documentsApi": "notion",
                },
                "postgresSsot": postgres,
                "notion": {"table": table, "document": notion_document},
                "tablePersistenceVerified": True,
                "documentPersistenceVerified": True,
                "crossProviderLinkageVerified": True,
                "cleanupCompleted": True,
                "cleanup": {
                    "postgresRecordDeleted": True,
                    "postgresDocumentDeleted": True,
                    "postgresProjectionRowsDeleted": True,
                    "notionTableRowArchived": True,
                    "notionDocumentArchived": True,
                    "verified": True,
                },
                "redacted": True,
                "dependencyEvidence": canary_reference,
                "consumerVerificationEvidence": verification_reference,
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
            for path in (integration, canary_evidence, verification_evidence):
                path.chmod(0o600)

            with (
                mock.patch.object(
                    self.module, "c029_integration_evidence_path", integration
                ),
                mock.patch.object(
                    self.module,
                    "notion_projection_canary_evidence_path",
                    canary_evidence,
                ),
                mock.patch.object(
                    self.module,
                    "notion_consumer_verification_evidence_path",
                    verification_evidence,
                ),
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
            self.assertEqual(
                [row["kind"] for row in dependencies],
                [
                    "IntegrationCanaryEvidence",
                    "NotionProjectionLiveCanary",
                    "NotionProjectionConsumerVerification",
                ],
            )
            self.assertTrue(
                all(row["producerSha256"] == producer_sha for row in dependencies[1:])
            )

            integration_document = json.loads(integration.read_text())
            integration_document["canaries"][0]["source"] = (
                "server_notion_connector_canary"
            )
            integration.write_text(json.dumps(integration_document))
            with (
                mock.patch.object(
                    self.module, "c029_integration_evidence_path", integration
                ),
                mock.patch.object(
                    self.module,
                    "notion_projection_canary_evidence_path",
                    canary_evidence,
                ),
                mock.patch.object(
                    self.module,
                    "notion_consumer_verification_evidence_path",
                    verification_evidence,
                ),
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
                raised.exception.code,
                "notion_projection_canary_dependency_invalid",
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

    def test_firecrawl_requires_unauthorized_anonymous_and_live_scrape(self):
        get_urls = []

        def fake_request(method, url, **kwargs):
            if method == "GET":
                get_urls.append(url)
                if not kwargs.get("headers"):
                    return 401, None, {}
                return 200, {"status": "ok"}, {}
            self.assertIn("/v1/scrape", url)
            self.assertEqual(kwargs["body"]["url"], "https://example.com/")
            self.assertEqual(kwargs["body"]["maxAge"], 0)
            return (
                200,
                {
                    "success": True,
                    "data": {
                        "markdown": "# Example Domain",
                        "metadata": {"statusCode": 200},
                    },
                },
                {},
            )

        values = {
            "CLOUDFLARE_ACCESS_ROUTE_FIRECRAWL_CLIENT_ID": "cf-client-id-value-7f4a9c21",
            "CLOUDFLARE_ACCESS_ROUTE_FIRECRAWL_CLIENT_SECRET": "cf-client-secret-value-a83bd695",
            "CLOUDFLARE_ACCESS_ROUTE_FIRECRAWL_ID": "cf-service-token-value-31c6e2d8",
            "CLOUDFLARE_ACCESS_ROUTE_FIRECRAWL_EXPIRES_AT": "2099-01-01T00:00:00.000000+00:00",
            "FIRECRAWL_API_KEY": "firecrawl-key-value-d40b8e17",
            "FIRECRAWL_HEALTH_URL": "http://127.0.0.1:13002/",
        }
        with (
            mock.patch.object(self.module, "request", side_effect=fake_request),
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
        self.assertTrue(row["liveScrapeKnownDocumentObserved"])
        self.assertEqual(row["liveScrapeMetadataStatus"], 200)
        self.assertTrue(row["liveScrapeCacheBypassed"])
        encoded = json.dumps(row, sort_keys=True)
        self.assertTrue(all(values[key] not in encoded for key in values))

    def test_every_service_route_denies_anonymous_and_cross_route_tokens(self):
        apps = {
            "9router": {
                "hostname": "router.example.test",
                "origin": "http://127.0.0.1:12080",
                "accessClass": "service",
            },
            "toolhive": {
                "hostname": "tools.example.test",
                "origin": "http://127.0.0.1:12081",
                "accessClass": "service",
            },
        }
        config = {
            "spec": {
                "components": [
                    {
                        "id": "9router",
                        "health": {"url": "http://127.0.0.1:12080/health"},
                    },
                    {
                        "id": "toolhive",
                        "health": {"url": "http://127.0.0.1:12081/ready"},
                    },
                ]
            }
        }
        values = {}
        clients = {"router-client": "router-secret", "tools-client": "tools-secret"}
        for app_id, (client_id, secret) in zip(apps, clients.items(), strict=True):
            prefix = "CLOUDFLARE_ACCESS_ROUTE_" + app_id.upper().replace("-", "_")
            values.update(
                {
                    prefix + "_ID": "service-token-id-" + app_id,
                    prefix + "_CLIENT_ID": client_id,
                    prefix + "_CLIENT_SECRET": secret * 4,
                    prefix + "_EXPIRES_AT": "2099-01-01T00:00:00+00:00",
                }
            )

        def fake_request(_method, url, **kwargs):
            headers = kwargs.get("headers", {})
            if not headers:
                return 401, None, {}
            expected_client = "router-client" if "router." in url else "tools-client"
            return (
                (200 if headers["CF-Access-Client-Id"] == expected_client else 401),
                None,
                {},
            )

        with mock.patch.object(self.module, "request", side_effect=fake_request):
            checks = self.module.service_edge_checks(values, apps, config)
        self.assertEqual(set(checks), set(apps))
        self.assertTrue(all(row["anonymousDenied"] for row in checks.values()))
        self.assertTrue(
            all(row["intendedTokenStatus"] == 200 for row in checks.values())
        )
        self.assertTrue(all(row["crossTokenDenied"] for row in checks.values()))
        encoded = json.dumps(checks, sort_keys=True)
        self.assertTrue(all(secret not in encoded for secret in clients.values()))

    def test_searxng_semantic_retries_empty_results_then_validates_json_result(self):
        calls = []
        responses = [
            (200, {"query": "OpenAI", "results": []}, {}),
            (200, {"query": "OpenAI", "results": []}, {}),
            (
                200,
                {
                    "query": "OpenAI",
                    "results": [{"title": "OpenAI", "url": "https://openai.com/"}],
                },
                {},
            ),
        ]

        def fake_request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return responses.pop(0)

        with (
            mock.patch.object(self.module, "request", side_effect=fake_request),
            mock.patch.object(self.module.time, "sleep") as sleep,
        ):
            value = self.module.semantic_searxng({}, "http://127.0.0.1:13004")
        self.assertEqual(value["attemptCount"], 3)
        self.assertEqual(value["validResultCount"], 1)
        self.assertRegex(value["canaryQuerySha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(call[0] == "GET" for call in calls))
        self.assertEqual(len({call[1] for call in calls}), 1)
        self.assertIn("q=OpenAI", calls[0][1])
        self.assertIn("format=json", calls[0][1])
        self.assertIn("language=en", calls[0][1])
        self.assertTrue(all(call[2]["timeout"] == 60 for call in calls))
        self.assertEqual(sleep.call_count, 2)

    def test_searxng_semantic_rejects_nonempty_malformed_search_results(self):
        with (
            mock.patch.object(
                self.module,
                "request",
                return_value=(
                    200,
                    {"query": "OpenAI", "results": [{"title": "missing url"}]},
                    {},
                ),
            ),
            mock.patch.object(self.module.time, "sleep") as sleep,
            self.assertRaisesRegex(
                self.module.AcceptanceError,
                "searxng_live_search_contract_invalid",
            ),
        ):
            self.module.semantic_searxng({}, "http://127.0.0.1:13004")
        sleep.assert_not_called()

    def test_searxng_semantic_fails_closed_after_bounded_empty_retries(self):
        with (
            mock.patch.object(
                self.module,
                "request",
                return_value=(200, {"query": "OpenAI", "results": []}, {}),
            ) as request,
            mock.patch.object(self.module.time, "sleep") as sleep,
            self.assertRaisesRegex(
                self.module.AcceptanceError, "searxng_live_search_empty"
            ),
        ):
            self.module.semantic_searxng({}, "http://127.0.0.1:13004")
        self.assertEqual(request.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

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
                            "applyable": None,
                            "complete": None,
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

    def test_tofu_gate_accepts_opentofu_null_metadata_only_for_empty_plan(self):
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
                    (iac / output).write_bytes(b"fresh-opentofu-empty-plan")
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(
                    command,
                    0,
                    json.dumps(
                        {
                            "format_version": "1.2",
                            "terraform_version": "1.12.1",
                            "timestamp": self.module.utcnow(),
                            "applyable": None,
                            "complete": None,
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
        self.assertIsNone(value["savedPlanApplyable"])
        self.assertIsNone(value["savedPlanComplete"])
        self.assertFalse(value["savedPlanErrored"])
        self.assertEqual(value["savedPlanMetadataMode"], "opentofu-null-empty")
        self.assertEqual(value["savedPlanActionCounts"]["no-op"], 1)

    def test_saved_plan_metadata_rejects_ambiguous_mixed_null_state(self):
        counts = {
            "create": 0,
            "update": 0,
            "delete": 0,
            "forget": 0,
            "import": 0,
            "read": 0,
            "no-op": 0,
        }
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "opentofu_saved_plan_metadata_invalid"
        ):
            self.module.saved_plan_metadata(
                {"applyable": None, "complete": True, "errored": False}, counts
            )

    def test_saved_plan_metadata_rejects_null_state_without_action_sections(self):
        counts = {
            "create": 0,
            "update": 0,
            "delete": 0,
            "forget": 0,
            "import": 0,
            "read": 0,
            "no-op": 0,
        }
        with self.assertRaisesRegex(
            self.module.AcceptanceError, "opentofu_saved_plan_metadata_invalid"
        ):
            self.module.saved_plan_metadata(
                {
                    "format_version": "1.2",
                    "terraform_version": "1.12.1",
                    "applyable": None,
                    "complete": None,
                    "errored": False,
                },
                counts,
            )

    def test_saved_plan_metadata_rejects_missing_or_true_error_flag(self):
        counts = {
            "create": 0,
            "update": 0,
            "delete": 0,
            "forget": 0,
            "import": 0,
            "read": 0,
            "no-op": 0,
        }
        for errored in (None, True):
            with (
                self.subTest(errored=errored),
                self.assertRaisesRegex(
                    self.module.AcceptanceError,
                    "opentofu_saved_plan_metadata_invalid",
                ),
            ):
                self.module.saved_plan_metadata(
                    {"applyable": None, "complete": None, "errored": errored},
                    counts,
                )

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
        # Notion is external; the active Platform declarations govern the nine
        # locally deployed edge applications without a parallel magic count.
        self.assertEqual(len(apps), 9)
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
            "liveScrapeKnownDocumentObserved": True,
            "liveScrapeMetadataStatus": 200,
            "liveScrapeCacheBypassed": True,
        }
        inventory = {
            "tunnelId": "00000000-0000-0000-0000-000000000001",
            "tunnelName": "mte-test",
            "tunnelHealthy": True,
            "connectorCount": 4,
            "routes": {str(index): str(index) for index in range(9)},
            "dnsRecordCount": 9,
            "accessApplicationCount": 9,
            "accessPolicyCount": 2,
            "humanAccessPolicyScoped": True,
            "serviceAccessTokenScoped": True,
            "desiredHostnamesReserved": True,
            "dnsTargetTunnelBound": True,
            "proxiedDnsOnly": True,
            "originAddressRecordCount": 0,
            "foreign": [{}, {}],
            "foreignRecordSetSha256": "8" * 64,
        }
        dns_reconcile = {
            "dependencyEvidence": {
                "path": "/opt/mte-platform/evidence/cloudflare-dns-reconcile.json",
                "sha256": "8" * 64,
            },
            "batchApplied": True,
            "batchDatabaseTransactionAtomic": True,
            "edgePropagationAtomic": False,
            "desiredHostnamesReserved": True,
            "desiredRecordsExact": True,
            "proxiedDnsOnly": True,
            "originAddressRecordCount": 0,
            "foreignRecordCount": 2,
            "foreignRecordsPreserved": True,
            "foreignRecordSetSha256": "8" * 64,
        }
        external = {
            "expectedHost": "198.51.100.10",
            "evidenceSha256": "2" * 64,
            "externalPortsBlocked": {
                "80": True,
                "443": True,
                "2377": True,
                "3000": True,
                "7946": True,
                "20241": True,
            },
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
            mock.patch.multiple(
                self.module,
                data_content_edge_contract=mock.Mock(return_value=data_content),
                cloudflare_inventory=mock.Mock(return_value=inventory),
                service_edge_checks=mock.Mock(
                    return_value={
                        "firecrawl": {
                            "hostname": "firecrawl.example.test",
                            "healthPath": "/",
                            "anonymousDenied": True,
                            "intendedTokenStatus": 200,
                            "crossTokenDenied": True,
                            "crossTokenRoute": "9router",
                            "credentialValuesEmitted": False,
                        }
                    }
                ),
            ),
            mock.patch.object(
                self.module, "dns_reconcile_status", return_value=dns_reconcile
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
                        "path": "/opt/mte-platform/evidence/notion-projection-live-canary.json",
                        "sha256": "7" * 64,
                        "kind": "NotionProjectionLiveCanary",
                        "producerSha256": "e" * 64,
                    },
                    {
                        "path": "/opt/mte-platform/evidence/notion-projection-consumer-verify.json",
                        "sha256": "8" * 64,
                        "kind": "NotionProjectionConsumerVerification",
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
        self.assertTrue(
            payload["connections"]["C029"]["notionProjectionConsumerVerified"]
        )
        self.assertEqual(len(payload["connections"]["C029"]["dependencyEvidence"]), 3)
        self.assertTrue(payload["connections"]["C046"]["dashboardProvisioned"])
        self.assertTrue(payload["connections"]["C066"]["desiredRecordsExact"])
        self.assertTrue(payload["connections"]["C066"]["foreignDnsPreserved"])
        self.assertFalse(payload["connections"]["C066"]["edgePropagationAtomic"])
        self.assertEqual(
            payload["connections"]["C066"]["dependencyEvidence"],
            [dns_reconcile["dependencyEvidence"]],
        )
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

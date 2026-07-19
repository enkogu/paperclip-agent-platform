import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "mte_server_postgrest", ROOT / "tools/platform-cli/server-postgrest.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def values(module, *, generated: bool = False) -> dict[str, str]:
    result = {key: "unit" for key in module.REQUIRED_REFS}
    result.update(
        {
            "DATA_CONTENT_PROFILE": module.PROFILE,
            "POSTGRES_ADMIN_DB": "postgres",
            "POSTGRES_ADMIN_USER": "postgres",
            "POSTGREST_DB_HOST": "mte-postgres",
            "POSTGREST_DB_PORT": "5432",
            "POSTGREST_DB_SSLMODE": "disable",
            "POSTGREST_DATA_DB_NAME": "mte_data",
            "POSTGREST_DATA_DB_USER": "mte_data_owner",
            "POSTGREST_DATA_DB_PASSWORD": "data-secret",
            "POSTGREST_DB_LOGIN_ROLE": "mte_authenticator",
            "POSTGREST_AUTHENTICATOR_PASSWORD": "auth-secret",
            "POSTGREST_ANON_ROLE": "mte_anon",
            "POSTGREST_READER_ROLE": "mte_reader",
            "POSTGREST_WRITER_ROLE": "mte_writer",
            "POSTGREST_PAPERCLIP_ROLE": "mte_paperclip",
            "POSTGREST_JWT_SECRET": "s" * 64,
            "POSTGREST_API_AUDIENCE": "mte-api",
            "POSTGREST_HEALTH_URL": "http://127.0.0.1:18095/ready",
            "POSTGREST_ORIGIN_PORT": "18093",
        }
    )
    if generated:
        for key, (token_id, role_ref) in module.SCOPED_TOKEN_SPECS.items():
            result[key] = module.jwt(
                result,
                result[role_ref],
                lifetime=31_536_000,
                token_id=token_id,
            )
    return result


class PostgrestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_unique_container_uses_exact_direct_compose_project_and_service(self):
        calls: list[list[str]] = []

        def fake_run(argv, **_kwargs):
            calls.append(argv)
            return SimpleNamespace(stdout="container-one\n")

        with mock.patch.object(self.module, "run", side_effect=fake_run):
            observed = self.module.unique_container("postgres", "postgres")

        self.assertEqual(observed, "container-one")
        self.assertIn("label=com.docker.compose.project=mte-platform", calls[0])
        self.assertIn("label=com.docker.compose.service=postgres", calls[0])
        self.assertIn("status=running", calls[0])

    def test_unique_container_rejects_noncanonical_direct_compose_identity(self):
        with self.assertRaisesRegex(
            self.module.PostgrestError,
            "direct_compose_identity_invalid:postgres:postgres-copy",
        ):
            self.module.unique_container("postgres", "postgres-copy")

    def test_unique_container_missing_and_duplicate_fail_closed(self):
        for output in ("", "container-one\ncontainer-two\n"):
            with (
                self.subTest(output=output),
                mock.patch.object(
                    self.module,
                    "run",
                    return_value=SimpleNamespace(stdout=output),
                ),
                self.assertRaisesRegex(
                    self.module.PostgrestError,
                    "container_not_unique:postgres:postgres",
                ),
            ):
                self.module.unique_container("postgres", "postgres")

    def test_release_is_exact_pinned_mit_contract(self):
        contract = {
            "spec": {
                "images": {"postgrest": self.module.IMAGE},
                "dataContentProfiles": {
                    profile: {
                        "selectable": True,
                        "contractComplete": True,
                        "componentIds": ["postgrest"],
                        "images": {"postgrest": self.module.IMAGE},
                        "licenses": {"postgrest": "MIT"},
                        "adapters": {
                            "postgrest": {
                                "script": "server-postgrest.py",
                                "componentId": "postgrest",
                                "actions": ["database", "provision", "verify"],
                            }
                        },
                    }
                    for profile in self.module.SUPPORTED_PROFILES
                },
            }
        }
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "platform.lock.yaml"
            lock.write_text(yaml.safe_dump(contract))
            with mock.patch.object(self.module, "LOCK", lock):
                releases = {
                    profile: self.module.release_contract(profile)
                    for profile in self.module.SUPPORTED_PROFILES
                }
        self.assertEqual(set(releases), self.module.SUPPORTED_PROFILES)
        for profile, release in releases.items():
            self.assertEqual(release["profile"], profile)
            self.assertEqual(release["license"], "MIT")
            self.assertRegex(release["image"], r"@sha256:[0-9a-f]{64}$")

    def test_default_profile_selects_projection_provider(self):
        current = values(self.module)
        self.module.require_values(current)
        self.assertEqual(
            self.module.projection_provider(self.module.DEFAULT_PROFILE), "notion"
        )
        current["DATA_CONTENT_PROFILE"] = "unsupported"
        with self.assertRaisesRegex(
            self.module.PostgrestError, "provider_profile_not_selected"
        ):
            self.module.require_values(current)

    def test_compose_uses_only_canonical_runtime_projections(self):
        document = yaml.safe_load(
            (ROOT / "deployment/services/postgrest/compose.yaml").read_text()
        )
        service = document["services"]["postgrest"]
        self.assertEqual(service["image"], "${MTE_POSTGREST_POSTGREST_IMAGE:?required}")
        self.assertEqual(
            service["ports"],
            [
                "${MTE_POSTGREST_POSTGREST_PORT_1_MAPPING:?required}",
                "${MTE_POSTGREST_POSTGREST_PORT_2_MAPPING:?required}",
            ],
        )
        environment = service["environment"]
        for key in (
            "PGRST_DB_URI",
            "PGRST_OPENAPI_MODE",
            "PGRST_SERVER_PORT",
            "PGRST_ADMIN_SERVER_PORT",
        ):
            self.assertRegex(
                environment[key], r"^\$\{MTE_POSTGREST_[A-Z0-9_]+:\?required\}$"
            )

    def test_role_refs_are_exact_and_all_database_roles_are_distinct(self):
        current = values(self.module)
        self.module.require_values(current)
        current["POSTGREST_PAPERCLIP_ROLE"] = current["POSTGREST_READER_ROLE"]
        with self.assertRaisesRegex(
            self.module.PostgrestError, "postgrest_database_roles_not_distinct"
        ):
            self.module.require_values(current)

    def test_scoped_token_has_exact_role_audience_and_identity(self):
        current = values(self.module)
        paperclip = self.module.jwt(
            current,
            current["POSTGREST_PAPERCLIP_ROLE"],
            lifetime=31_536_000,
            token_id="mte-paperclip",
        )
        paperclip_claims = self.module.token_claims(current, paperclip)
        self.assertEqual(paperclip_claims["role"], current["POSTGREST_PAPERCLIP_ROLE"])
        self.assertEqual(paperclip_claims["aud"], current["POSTGREST_API_AUDIENCE"])
        self.assertTrue(
            self.module.scoped_token_valid(
                current,
                paperclip,
                "mte-paperclip",
                current["POSTGREST_PAPERCLIP_ROLE"],
            )
        )
        self.assertFalse(
            self.module.scoped_token_valid(
                current,
                paperclip,
                "mte-paperclip",
                current["POSTGREST_READER_ROLE"],
            )
        )


class PostgrestDatabaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_database_installs_distinct_grants_and_prefix_bound_rls_policies(self):
        calls: list[tuple[str, str]] = []

        def fake_psql(current: dict[str, str], database: str, sql: str) -> str:
            calls.append((database, sql))
            if "SELECT 1 FROM pg_database" in sql:
                return "1"
            if "bool_and(c.relrowsecurity" in sql:
                return "t|5|5|5|5"
            if "has_table_privilege" in sql:
                return "t|t|t|t|f|t|f|t|t|t|f"
            if "information_schema.tables" in sql:
                return "2|6|2|0|2|1|1"
            return ""

        with (
            mock.patch.object(self.module, "dotenv", return_value=values(self.module)),
            mock.patch.object(self.module, "release_contract"),
            mock.patch.object(self.module, "psql", side_effect=fake_psql),
        ):
            result = self.module.database()

        all_sql = "\n".join(sql for _, sql in calls)
        self.assertEqual(result["roles"], 6)
        self.assertTrue(result["authorization"]["paperclipRoleScoped"])
        self.assertIn(
            'GRANT "mte_anon", "mte_reader", "mte_writer", "mte_paperclip" TO "mte_authenticator"',
            all_sql,
        )
        for table in (
            "prototype_items",
            "canonical_entities",
            "canonical_documents",
            "provider_sync_state",
            "provider_outbox",
        ):
            self.assertIn(f"ALTER TABLE api.{table} FORCE ROW LEVEL SECURITY", all_sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS api.canonical_entities", all_sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS api.canonical_documents", all_sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS api.provider_sync_state", all_sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS api.provider_outbox", all_sql)
        self.assertIn(
            'GRANT USAGE ON SCHEMA api TO "mte_reader", "mte_writer", "mte_paperclip"',
            all_sql,
        )
        self.assertIn("mte_entities_projection_outbox", all_sql)
        self.assertIn("mte_documents_projection_outbox", all_sql)
        self.assertIn("'notion', TG_ARGV[0]", all_sql)
        self.assertNotIn("payload jsonb", all_sql)
        self.assertIn("CREATE POLICY mte_paperclip_canary_rows", all_sql)
        self.assertIn("external_object_id LIKE 'MTE-C027-%'", all_sql)
        self.assertEqual(result["authorization"]["canonicalSystem"], "postgresql")
        self.assertFalse(
            result["authorization"]["projectionTablesContainCanonicalPayload"]
        )

    def test_database_authorization_verification_fails_closed(self):
        with mock.patch.object(self.module, "psql", return_value="f|0|0|0|0"):
            with self.assertRaisesRegex(
                self.module.PostgrestError, "postgrest_rls_policy_contract_invalid"
            ):
                self.module.verify_database_authorization(values(self.module))

        responses = iter(
            (
                "t|5|5|5|5",
                "t|t|t|t|f|t|f|t|t|t|f",
                "2|5|2|0|2|1|1",
            )
        )
        with mock.patch.object(
            self.module, "psql", side_effect=lambda *_args: next(responses)
        ):
            with self.assertRaisesRegex(
                self.module.PostgrestError,
                "postgres_canonical_ownership_contract_invalid",
            ):
                self.module.verify_database_authorization(values(self.module))


class PostgrestProvisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_scoped_token_provision_is_idempotent_and_secret_free(self):
        with tempfile.TemporaryDirectory() as temporary:
            secret_root = Path(temporary)
            canonical = secret_root / "platform.env"
            canonical_lock = secret_root / ".platform-env.lock"
            initial = values(self.module)
            canonical.write_text(
                "".join(f"{key}={initial[key]}\n" for key in sorted(initial))
            )
            canonical.chmod(0o600)

            def parse_canonical() -> dict[str, str]:
                parsed: dict[str, str] = {}
                for line in canonical.read_text().splitlines():
                    key, value = line.split("=", 1)
                    parsed[key] = value
                return parsed

            with (
                mock.patch.object(self.module, "SECRET_ROOT", secret_root),
                mock.patch.object(self.module, "CANONICAL", canonical),
                mock.patch.object(self.module, "CANONICAL_LOCK", canonical_lock),
                mock.patch.object(self.module, "dotenv", side_effect=parse_canonical),
            ):
                first = self.module.provision_scoped_tokens(initial)
                first_stat = canonical.stat()
                current = parse_canonical()
                second = self.module.provision_scoped_tokens(current)
                second_stat = canonical.stat()

            self.assertEqual(first["changedKeys"], sorted(self.module.GENERATED_REFS))
            self.assertEqual(second["changedKeys"], [])
            self.assertEqual(first_stat.st_ino, second_stat.st_ino)
            self.assertEqual(first_stat.st_mtime_ns, second_stat.st_mtime_ns)
            paperclip = current["POSTGREST_PAPERCLIP_TOKEN"]
            self.assertEqual(
                self.module.token_claims(current, paperclip)["role"],
                current["POSTGREST_PAPERCLIP_ROLE"],
            )
            serialized = json.dumps({"first": first, "second": second})
            self.assertNotIn(paperclip, serialized)

    def test_rls_canary_proves_paperclip_scope_and_cleanup(self):
        current = values(self.module, generated=True)
        rows: dict[int, dict[str, object]] = {}
        next_id = 1

        def fake_request(method: str, url: str, **kwargs: object):
            nonlocal next_id
            token = kwargs.get("token")
            if method == "POST":
                body = kwargs["body"]
                if not str(body["title"]).startswith("MTE-C027-"):
                    return 403, {"message": "row-level security"}
                row_id = next_id
                next_id += 1
                rows[row_id] = {
                    "id": row_id,
                    "title": body["title"],
                    "ownerToken": token,
                }
                return 201, [{"id": row_id, "title": body["title"]}]
            row_id = int(url.rsplit("eq.", 1)[1])
            row = rows.get(row_id)
            visible = row is not None and row["ownerToken"] == token
            if method == "GET":
                return 200, ([{"id": row_id, "title": row["title"]}] if visible else [])
            if method == "DELETE":
                if visible:
                    rows.pop(row_id)
                return 204, None
            raise AssertionError((method, url))

        with mock.patch.object(self.module, "request", side_effect=fake_request):
            result = self.module.paperclip_scope_canary(
                current, "http://postgrest/prototype_items"
            )
        self.assertTrue(result["paperclipRoleScoped"])
        self.assertTrue(result["outOfScopeWriteDenied"])
        self.assertEqual(rows, {})

    def test_verify_evidence_includes_live_database_authorization(self):
        current = values(self.module, generated=True)
        captured: dict[str, object] = {}
        request_results = iter(
            (
                (403, None),
                (403, None),
                (201, [{"id": 1}]),
                (200, [{"id": 1, "title": mock.ANY}]),
                (200, [{"id": 1, "title": mock.ANY}]),
                (204, None),
                (200, []),
            )
        )

        def fake_request(_method, _url, **_kwargs):
            return next(request_results)

        database_authorization = {
            "rlsEnabled": True,
            "paperclipRoleScoped": True,
            "anonymousDenied": True,
            "canonicalTables": ["canonical_entities", "canonical_documents"],
        }
        role_isolation = {
            "paperclipRoleScoped": True,
            "outOfScopeWriteDenied": True,
            "cleanupCompleted": True,
        }
        ownership = {
            "canonicalSystem": "postgresql",
            "projectionProvider": "notion",
        }
        with (
            mock.patch.object(self.module, "dotenv", return_value=current),
            mock.patch.object(self.module, "release_contract", return_value={}),
            mock.patch.object(
                self.module,
                "verify_database_authorization",
                return_value=database_authorization,
            ) as database_check,
            mock.patch.object(
                self.module, "paperclip_scope_canary", return_value=role_isolation
            ),
            mock.patch.object(
                self.module, "canonical_ssot_canary", return_value=ownership
            ),
            mock.patch.object(self.module, "jwt", return_value="unit-token"),
            mock.patch.object(self.module, "request", side_effect=fake_request),
            mock.patch.object(self.module, "run"),
            mock.patch.object(self.module, "unique_container", return_value="container"),
            mock.patch.object(self.module, "wait_ready"),
            mock.patch.object(self.module, "sha256_path", return_value="a" * 64),
            mock.patch.object(
                self.module,
                "atomic_json",
                side_effect=lambda _path, payload: captured.update(payload),
            ),
        ):
            result = self.module.verify()

        database_check.assert_called_once_with(current)
        self.assertTrue(result["authorization"]["rlsEnabled"])
        self.assertEqual(result["authorization"], captured["authorization"])
        self.assertTrue(result["authorization"]["paperclipRoleScoped"])

    def test_canonical_ssot_canary_proves_content_is_postgres_owned(self):
        current = values(self.module)
        entity_hashes: list[str] = []
        document_hash = ""
        deleted: set[str] = set()

        def fake_request(method: str, url: str, **kwargs: object):
            nonlocal document_hash
            body = kwargs.get("body", {})
            if method == "POST" and url.endswith("/canonical_entities"):
                assert isinstance(body, dict)
                entity_hashes.append(str(body["content_hash"]))
                return 201, [{"id": "11111111-1111-4111-8111-111111111111"}]
            if method == "POST" and url.endswith("/canonical_documents"):
                assert isinstance(body, dict)
                document_hash = str(body["content_hash"])
                return 201, [{"id": "22222222-2222-4222-8222-222222222222"}]
            if method == "PATCH" and "/canonical_entities?" in url:
                assert isinstance(body, dict)
                entity_hashes.append(str(body["content_hash"]))
                return 204, None
            if method == "GET" and "/provider_sync_state?" in url:
                is_entity = "-entity" in url
                return 200, [
                    {
                        "provider": "notion",
                        "object_kind": "entity" if is_entity else "document",
                        "canonical_revision": len(entity_hashes) if is_entity else 1,
                        "canonical_content_hash": (
                            entity_hashes[-1] if is_entity else document_hash
                        ),
                        "sync_status": "pending",
                    }
                ]
            if method == "GET" and "/provider_outbox?" in url:
                is_entity = "-entity" in url
                if "operation=eq.delete" in url:
                    return 200, [{"operation": "delete"}]
                if "order=canonical_revision.asc" in url:
                    return 200, [
                        {"operation": "upsert", "canonical_revision": 1},
                        {"operation": "upsert", "canonical_revision": 2},
                    ]
                return 200, [
                    {
                        "operation": "upsert",
                        "canonical_content_hash": (
                            entity_hashes[0] if is_entity else document_hash
                        ),
                    }
                ]
            if method == "GET" and "/canonical_entities?" in url:
                return 200, [
                    {
                        "revision": 2,
                        "content_hash": entity_hashes[-1],
                    }
                ]
            if method == "GET" and "/canonical_documents?" in url:
                return 200, [
                    {
                        "body": "Canonical body owned by PostgreSQL.",
                        "content_hash": document_hash,
                    }
                ]
            if method == "DELETE":
                deleted.add(url.split("/", 3)[-1])
                return 204, None
            raise AssertionError((method, url, kwargs))

        with (
            mock.patch.object(self.module, "request", side_effect=fake_request),
            mock.patch.object(self.module, "run"),
            mock.patch.object(
                self.module, "unique_container", return_value="container"
            ),
            mock.patch.object(self.module, "wait_ready"),
        ):
            result = self.module.canonical_ssot_canary(
                current, "http://postgrest", "reader", "writer"
            )

        self.assertEqual(result["canonicalSystem"], "postgresql")
        self.assertEqual(result["projectionProvider"], "notion")
        self.assertEqual(result["canonicalEntityRevision"], 2)
        self.assertTrue(result["outboxGeneratedByDatabaseTriggers"])
        self.assertFalse(result["projectionTablesContainCanonicalPayload"])
        self.assertTrue(result["restartPersistenceVerified"])
        self.assertTrue(any("provider_outbox" in url for url in deleted))
        self.assertTrue(any("provider_sync_state" in url for url in deleted))


if __name__ == "__main__":
    unittest.main()

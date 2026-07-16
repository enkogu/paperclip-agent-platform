import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "mte_server_nocodb", ROOT / "tools/platform-cli/server-nocodb.py"
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
            "POSTGREST_DATA_DB_NAME": "mte_data",
            "POSTGREST_DATA_DB_USER": "mte_data_owner",
            "POSTGREST_WRITER_ROLE": "mte_writer",
            "POSTGREST_PAPERCLIP_ROLE": "mte_paperclip",
            "POSTGREST_ACTIVEPIECES_ROLE": "mte_activepieces",
            "POSTGREST_JWT_SECRET": "jwt-secret",
            "POSTGREST_API_AUDIENCE": "mte-postgrest",
            "POSTGREST_ORIGIN_PORT": "18093",
            "NOCODB_DB_HOST": "mte-postgres",
            "NOCODB_DB_PORT": "5432",
            "NOCODB_DB_SSLMODE": "disable",
            "NOCODB_META_DB_NAME": "nocodb_meta",
            "NOCODB_META_DB_USER": "nocodb_meta_role",
            "NOCODB_META_DB_PASSWORD": "metadata-secret",
            "NOCODB_DATA_DB_USER": "nocodb_data_role",
            "NOCODB_DATA_DB_PASSWORD": "external-source-secret",
            "NOCODB_ADMIN_EMAIL": "admin@mte.local",
            "NOCODB_ADMIN_PASSWORD": "admin-secret",
            "NOCODB_BASE_TITLE": "MTE Data",
            "NOCODB_TABLE_TITLE": "prototype_items",
            "NOCODB_HEALTH_URL": "http://127.0.0.1:18096/api/v1/health",
            "NOCODB_ORIGIN_PORT": "18096",
        }
    )
    if generated:
        result.update(
            {
                "NOCODB_API_TOKEN": "T" * 40,
                "NOCODB_API_TOKEN_ID": "token-1",
                "NOCODB_API_TOKEN_SHA256": hashlib.sha256(
                    ("T" * 40).encode()
                ).hexdigest(),
                "NOCODB_BASE_ID": "base-1",
                "NOCODB_SOURCE_ID": "source-1",
                "NOCODB_TABLE_ID": "table-1",
            }
        )
    return result


class NocoDbContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_release_is_exact_reviewed_sustainable_use_exception(self):
        with mock.patch.object(self.module, "LOCK", ROOT / "config/platform.lock.yaml"):
            release = self.module.release_contract()
        self.assertEqual(release["status"], "reviewed-inactive")
        self.assertFalse(release["selectable"])
        self.assertFalse(release["contractComplete"])
        self.assertEqual(
            release["activationBlockers"], self.module.INACTIVE_ACTIVATION_BLOCKERS
        )
        self.assertEqual(release["license"], "LicenseRef-NocoDB-Sustainable-Use-1.0")
        self.assertEqual(release["exception"]["approval"], "user-approved-2026-07-15")

    def test_release_contract_fails_closed_on_activation_or_contract_drift(self):
        original = yaml.safe_load((ROOT / "config/platform.lock.yaml").read_text())
        cases = (
            ("selected", ("selectable",), True),
            ("complete", ("contractComplete",), True),
            (
                "license approval",
                ("licenseExceptions", "nocodb", "approval"),
                "unreviewed",
            ),
            (
                "adapter action",
                ("adapters", "nocodb", "actions"),
                ["provision"],
            ),
        )
        for label, path, replacement in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                lock = json.loads(json.dumps(original))
                current = lock["spec"]["dataContentProfiles"][self.module.PROFILE]
                for key in path[:-1]:
                    current = current[key]
                current[path[-1]] = replacement
                lock_path = Path(temporary) / "platform.lock.yaml"
                lock_path.write_text(yaml.safe_dump(lock, sort_keys=False))
                with mock.patch.object(self.module, "LOCK", lock_path):
                    with self.assertRaisesRegex(
                        self.module.NocoError, "nocodb_release_contract_drift"
                    ):
                        self.module.release_contract()

    def test_explicit_selection_cannot_activate_reviewed_inactive_provider(self):
        current = values(self.module)
        with (
            mock.patch.object(self.module, "dotenv", return_value=current),
            mock.patch.object(self.module, "psql") as psql,
            mock.patch.object(self.module, "LOCK", ROOT / "config/platform.lock.yaml"),
        ):
            with self.assertRaisesRegex(
                self.module.NocoError, "provider_profile_inactive"
            ):
                self.module.database()
        psql.assert_not_called()

    def test_rendered_compose_omits_truthy_external_database_disable_flag(self):
        document = yaml.safe_load(
            (ROOT / "deployment/services/nocodb/compose.yaml").read_text()
        )
        service = document["services"]["nocodb"]
        environment = service["environment"]
        self.assertEqual(service["image"], "${MTE_NOCODB_NOCODB_IMAGE:?required}")
        self.assertEqual(
            service["ports"], ["${MTE_NOCODB_NOCODB_PORT_1_MAPPING:?required}"]
        )
        self.assertNotIn("NC_CONNECT_TO_EXTERNAL_DB_DISABLED", environment)
        self.assertEqual(environment["NC_ALLOW_LOCAL_EXTERNAL_DBS"], "true")

    def test_docs_403_and_404_fail_closed_as_business_license_required(self):
        for status in (403, 404):
            with self.subTest(status=status):
                error = urllib.error.HTTPError(
                    "http://nocodb/api/v3/docs/base",
                    status,
                    "denied",
                    {},
                    io.BytesIO(b"{}"),
                )
                with mock.patch.object(
                    self.module.urllib.request, "urlopen", side_effect=error
                ):
                    with self.assertRaises(self.module.NocoError) as raised:
                        self.module.request(
                            "POST",
                            "http://nocodb/api/v3/docs/base",
                            body={"title": "canary"},
                            license_gate=True,
                        )
                self.assertEqual(raised.exception.code, "business_license_required")
                self.assertEqual(raised.exception.status, status)

    def test_wrong_profile_and_nonshared_database_fail_closed(self):
        current = values(self.module)
        current["DATA_CONTENT_PROFILE"] = "postgres-notion"
        with self.assertRaisesRegex(
            self.module.NocoError, "provider_profile_not_selected"
        ):
            self.module.require_values(current)


class NocoDbDatabaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_database_revokes_public_connect_and_proves_role_isolation(self):
        calls: list[tuple[str, str]] = []

        def fake_psql(current: dict[str, str], database: str, sql: str) -> str:
            calls.append((database, sql))
            if "SELECT 1 FROM pg_database" in sql:
                return "1"
            if "has_database_privilege" in sql:
                return "t|f|f|t"
            if "has_schema_privilege" in sql:
                return "f|t|f|t|1"
            return ""

        with (
            mock.patch.object(self.module, "dotenv", return_value=values(self.module)),
            mock.patch.object(self.module, "release_contract"),
            mock.patch.object(self.module, "psql", side_effect=fake_psql),
        ):
            result = self.module.database()

        all_sql = "\n".join(sql for _, sql in calls)
        self.assertIn('REVOKE CONNECT ON DATABASE "nocodb_meta" FROM PUBLIC', all_sql)
        self.assertIn('REVOKE CONNECT ON DATABASE "mte_data" FROM PUBLIC', all_sql)
        self.assertIn(
            'REVOKE CONNECT ON DATABASE "nocodb_meta" FROM "nocodb_data_role"', all_sql
        )
        self.assertIn(
            'REVOKE CONNECT ON DATABASE "mte_data" FROM "nocodb_meta_role"', all_sql
        )
        self.assertIn(
            'REVOKE ALL PRIVILEGES ON SCHEMA api FROM "nocodb_meta_role"', all_sql
        )
        self.assertIn("CREATE POLICY mte_nocodb_external_source_all", all_sql)
        self.assertTrue(result["isolation"]["externalSourceRoleDeniedMetadata"])
        self.assertTrue(result["isolation"]["metadataRoleDeniedData"])
        self.assertTrue(result["isolation"]["metadataRoleDeniedDataSchema"])

    def test_database_isolation_verification_fails_closed(self):
        with mock.patch.object(self.module, "psql", return_value="t|t|t|t"):
            with self.assertRaisesRegex(
                self.module.NocoError, "nocodb_database_connect_isolation_invalid"
            ):
                self.module.verify_database_isolation(values(self.module))

        responses = iter(("t|f|f|t", "f|t|f|t|0"))
        with mock.patch.object(
            self.module, "psql", side_effect=lambda *_args: next(responses)
        ):
            with self.assertRaisesRegex(
                self.module.NocoError, "nocodb_data_schema_isolation_invalid"
            ):
                self.module.verify_database_isolation(values(self.module))


class NocoDbProvisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_external_source_provision_is_happy_and_idempotent(self):
        current = values(self.module)
        state = {"created": False, "createCalls": 0}

        def fake_request(method: str, url: str, **kwargs: object):
            if url.endswith("/api/v2/meta/bases") and method == "GET":
                listing = (
                    [{"id": "base-1", "title": current["NOCODB_BASE_TITLE"]}]
                    if state["created"]
                    else []
                )
                return 200, {"list": listing}
            if url.endswith("/api/v2/meta/bases") and method == "POST":
                body = kwargs["body"]
                source = body["sources"][0]
                self.assertFalse(source["is_meta"])
                self.assertFalse(source["is_local"])
                self.assertEqual(source["config"]["connection"]["host"], "mte-postgres")
                self.assertEqual(source["config"]["searchPath"], ["api"])
                state["created"] = True
                state["createCalls"] += 1
                return 200, {"id": "base-1", "title": current["NOCODB_BASE_TITLE"]}
            if url.endswith("/sources"):
                return 200, {
                    "list": [{"id": "source-1", "alias": self.module.SOURCE_ALIAS}]
                }
            if url.endswith("/tables"):
                return 200, {
                    "list": [{"id": "table-1", "title": current["NOCODB_TABLE_TITLE"]}]
                }
            raise AssertionError((method, url))

        with mock.patch.object(self.module, "request", side_effect=fake_request):
            first = self.module.ensure_base(current, "http://nocodb", "admin-session")
            second = self.module.ensure_base(current, "http://nocodb", "admin-session")

        self.assertEqual(first, second)
        self.assertEqual(state["createCalls"], 1)

    def test_provision_twice_persists_token_then_is_exact_noop_and_secret_free(self):
        token = "unit-only-nocodb-token-material-1234567890"
        state = {"created": False, "createCalls": 0, "listFixture": None}

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

            def fake_request(method: str, url: str, **kwargs: object):
                if url.endswith("/api-tokens") and method == "GET":
                    if not state["created"]:
                        return 200, {"list": []}
                    row = {
                        "id": "token-1",
                        "description": self.module.TOKEN_DESCRIPTION,
                        "token_prefix": token[:12],
                    }
                    self.assertNotIn("token", row)
                    state["listFixture"] = row
                    return 200, {"list": [row]}
                if url.endswith("/api-tokens") and method == "POST":
                    self.assertEqual(
                        kwargs["body"], {"description": self.module.TOKEN_DESCRIPTION}
                    )
                    state["created"] = True
                    state["createCalls"] += 1
                    return 200, {
                        "id": "token-1",
                        "description": self.module.TOKEN_DESCRIPTION,
                        "token": token,
                    }
                if "/api/v2/tables/table-1/records?limit=1" in url:
                    self.assertEqual(kwargs.get("api_token"), token)
                    return 200, {"list": []}
                raise AssertionError((method, url))

            with (
                mock.patch.object(self.module, "SECRET_ROOT", secret_root),
                mock.patch.object(self.module, "CANONICAL", canonical),
                mock.patch.object(self.module, "CANONICAL_LOCK", canonical_lock),
                mock.patch.object(self.module, "dotenv", side_effect=parse_canonical),
                mock.patch.object(self.module, "release_contract"),
                mock.patch.object(self.module, "database"),
                mock.patch.object(self.module, "wait_ready"),
                mock.patch.object(
                    self.module,
                    "session",
                    return_value=("http://127.0.0.1:18096", "admin-session"),
                ),
                mock.patch.object(
                    self.module,
                    "ensure_base",
                    return_value={
                        "baseId": "base-1",
                        "sourceId": "source-1",
                        "tableId": "table-1",
                    },
                ),
                mock.patch.object(self.module, "request", side_effect=fake_request),
            ):
                first = self.module.provision()
                first_stat = canonical.stat()
                first_body = canonical.read_bytes()
                second = self.module.provision()
                second_stat = canonical.stat()

            self.assertEqual(state["createCalls"], 1)
            self.assertIsNotNone(state["listFixture"])
            self.assertTrue(first["apiToken"]["created"])
            self.assertFalse(second["apiToken"]["created"])
            self.assertEqual(
                first["canonical"]["changedKeys"], sorted(self.module.GENERATED_REFS)
            )
            self.assertEqual(second["canonical"]["changedKeys"], [])
            self.assertEqual(first_body, canonical.read_bytes())
            self.assertEqual(first_stat.st_ino, second_stat.st_ino)
            self.assertEqual(first_stat.st_mtime_ns, second_stat.st_mtime_ns)
            self.assertEqual(
                first["apiToken"]["fingerprintSha256"],
                hashlib.sha256(token.encode()).hexdigest(),
            )
            serialized = json.dumps({"first": first, "second": second})
            self.assertNotIn(token, serialized)
            self.assertIn(f"NOCODB_API_TOKEN={token}\n", canonical.read_text())

    def test_existing_token_failures_are_closed_without_rotation(self):
        token = "T" * 40
        current = values(self.module, generated=True)
        bad_stored_fingerprint = dict(current)
        bad_stored_fingerprint["NOCODB_API_TOKEN_SHA256"] = "0" * 64
        cases = (
            (
                "duplicate",
                [
                    {"id": "token-1", "description": self.module.TOKEN_DESCRIPTION},
                    {"id": "token-2", "description": self.module.TOKEN_DESCRIPTION},
                ],
                current,
                "nocodb_api_token_ambiguous",
            ),
            (
                "missing material",
                [{"id": "token-1", "description": self.module.TOKEN_DESCRIPTION}],
                values(self.module),
                "nocodb_api_token_material_missing",
            ),
            (
                "identity mismatch",
                [{"id": "token-2", "description": self.module.TOKEN_DESCRIPTION}],
                current,
                "nocodb_api_token_identity_mismatch",
            ),
            (
                "description mismatch",
                [{"id": "token-1", "description": "other"}],
                current,
                "nocodb_api_token_description_mismatch",
            ),
            (
                "fingerprint mismatch",
                [
                    {
                        "id": "token-1",
                        "description": self.module.TOKEN_DESCRIPTION,
                        "token_prefix": "wrong-prefix",
                    }
                ],
                current,
                "nocodb_api_token_fingerprint_mismatch",
            ),
            (
                "stored fingerprint mismatch",
                [
                    {
                        "id": "token-1",
                        "description": self.module.TOKEN_DESCRIPTION,
                    }
                ],
                bad_stored_fingerprint,
                "nocodb_api_token_fingerprint_mismatch",
            ),
            (
                "raw listing exposure",
                [
                    {
                        "id": "token-1",
                        "description": self.module.TOKEN_DESCRIPTION,
                        "token": token,
                    }
                ],
                current,
                "nocodb_api_token_list_exposed_material",
            ),
        )
        for label, listing, case_values, error_code in cases:
            with self.subTest(label=label):
                with mock.patch.object(
                    self.module, "request", return_value=(200, {"list": listing})
                ) as request:
                    with self.assertRaises(self.module.NocoError) as raised:
                        self.module.ensure_api_token(
                            case_values, "http://nocodb", "admin-session", "base-1"
                        )
                self.assertEqual(raised.exception.code, error_code)
                self.assertNotIn(token, str(raised.exception))
                self.assertEqual(request.call_count, 1)

    def test_binding_failure_redacts_stored_token(self):
        token = "unit-only-nocodb-token-material-1234567890"
        with mock.patch.object(
            self.module,
            "request",
            side_effect=self.module.NocoError("nocodb_http_status:401", status=401),
        ):
            with self.assertRaises(self.module.NocoError) as raised:
                self.module.verify_api_token_binding(
                    "http://nocodb",
                    "table-1",
                    token,
                    hashlib.sha256(token.encode()).hexdigest(),
                )
        self.assertEqual(raised.exception.code, "nocodb_api_token_fingerprint_mismatch")
        self.assertNotIn(token, str(raised.exception))


if __name__ == "__main__":
    unittest.main()

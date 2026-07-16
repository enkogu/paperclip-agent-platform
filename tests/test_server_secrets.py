import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(platform_root: Path, secret_root: Path):
    old_platform = os.environ.get("MTE_PLATFORM_ROOT")
    old_secret = os.environ.get("MTE_SECRET_ROOT")
    os.environ["MTE_PLATFORM_ROOT"] = str(platform_root)
    os.environ["MTE_SECRET_ROOT"] = str(secret_root)
    try:
        spec = importlib.util.spec_from_file_location(
            f"server_secrets_{id(platform_root)}", ROOT / "tools/platform-cli/server-secrets.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if old_platform is None:
            os.environ.pop("MTE_PLATFORM_ROOT", None)
        else:
            os.environ["MTE_PLATFORM_ROOT"] = old_platform
        if old_secret is None:
            os.environ.pop("MTE_SECRET_ROOT", None)
        else:
            os.environ["MTE_SECRET_ROOT"] = old_secret


class SecretAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mte-secret-audit-")
        self.root = Path(self.temp.name)
        self.secret_root = self.root / "secrets"
        self.secret_root.mkdir()
        self.manifests = self.root / "manifests"
        self.manifests.mkdir()
        self.module = load_module(self.root, self.secret_root)

    def tearDown(self):
        self.temp.cleanup()

    def run_audit(self):
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            self.module.audit()
        return json.loads(output.getvalue())

    def test_public_config_match_is_not_a_secret_leak(self):
        public_url = "https://data.example.test/long-public-path"
        (self.secret_root / "platform.env").write_text(
            f"BASEROW_PUBLIC_URL={public_url}\nPOSTGRES_ADMIN_PASSWORD=very-sensitive-password\n"
        )
        (self.manifests / "public.txt").write_text(public_url)
        result = self.run_audit()
        self.assertTrue(result["ok"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["publicKeysExcluded"], 1)

    def test_sensitive_value_match_fails_without_printing_value(self):
        secret = "very-sensitive-password"
        (self.secret_root / "platform.env").write_text(
            f"POSTGRES_ADMIN_PASSWORD={secret}\n"
        )
        (self.manifests / "leak.txt").write_text(secret)
        output = io.StringIO()
        with mock.patch("sys.stdout", output), self.assertRaises(SystemExit):
            self.module.audit()
        rendered = output.getvalue()
        self.assertNotIn(secret, rendered)
        result = json.loads(rendered)
        self.assertFalse(result["ok"])
        self.assertEqual(result["findings"][0]["key"], "POSTGRES_ADMIN_PASSWORD")

    def test_init_updates_only_canonical_and_removes_legacy_admin_sidecar(self):
        canonical = self.secret_root / "platform.env"
        canonical.write_text(
            "DOKPLOY_ADMIN_NAME=Existing Owner\n"
            "DOKPLOY_ADMIN_EMAIL=owner@example.test\n"
            "DOKPLOY_ADMIN_PASSWORD=preserved-owner-password\n"
        )
        legacy = self.secret_root / "dokploy-admin.env"
        legacy.write_text("DOKPLOY_ADMIN_PASSWORD=must-not-be-imported\n")
        result = self.module.init()
        values = self.module.dotenv(canonical)
        self.assertEqual(
            values["DOKPLOY_ADMIN_PASSWORD"],
            "preserved-owner-password",
        )
        self.assertFalse(legacy.exists())
        self.assertFalse((self.secret_root / "services").exists())
        self.assertTrue(result["projectionRenderRequired"])
        self.assertEqual(
            result["canonicalSourceSha256"],
            self.module.hashlib.sha256(canonical.read_bytes()).hexdigest(),
        )

    def test_reconcile_renders_and_audits_after_canonical_write(self):
        calls = []
        with (
            mock.patch.object(
                self.module,
                "init",
                return_value={"initialized": True, "projectionRenderRequired": True},
            ),
            mock.patch.object(
                self.module.subprocess,
                "run",
                side_effect=lambda argv, **_kwargs: calls.append(argv),
            ),
        ):
            result = self.module.reconcile()
        self.assertEqual([row[-1] for row in calls], ["render", "audit"])
        self.assertFalse(result["projectionRenderRequired"])
        self.assertTrue(result["projectionAuditPassed"])

    def test_profile_gateway_identities_are_generated_only_as_secrets(self):
        values = self.module.generated_defaults()
        keys = {
            "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN",
            "TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_BEARER_TOKEN",
            "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN",
        }
        self.assertEqual(len({values[key] for key in keys}), 3)
        self.assertTrue(all(len(values[key]) >= 36 for key in keys))

    def test_postgres_notion_profile_generates_only_internal_database_secrets(self):
        values = self.module.generated_defaults("postgres-notion")
        self.assertIn("POSTGREST_DATA_DB_PASSWORD", values)
        self.assertIn("POSTGREST_AUTHENTICATOR_PASSWORD", values)
        self.assertIn("POSTGREST_JWT_SECRET", values)
        self.assertNotIn("NOTION_TOKEN", values)
        self.assertFalse(any(key.startswith("NOCODB_") for key in values))


if __name__ == "__main__":
    unittest.main()

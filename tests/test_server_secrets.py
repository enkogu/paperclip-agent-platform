import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import yaml


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
            f"POSTGREST_PUBLIC_URL={public_url}\nPOSTGRES_ADMIN_PASSWORD=very-sensitive-password\n"
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

    def test_short_sensitive_value_match_also_fails_without_printing_value(self):
        secret = "short"
        (self.secret_root / "platform.env").write_text(
            f"POSTGRES_ADMIN_PASSWORD={secret}\n"
        )
        (self.manifests / "leak.txt").write_text(secret)
        output = io.StringIO()
        with mock.patch("sys.stdout", output), self.assertRaises(SystemExit):
            self.module.audit()
        rendered = output.getvalue()
        self.assertNotIn(secret, rendered)
        self.assertFalse(json.loads(rendered)["ok"])

    def test_secret_named_metadata_is_excluded_but_raw_secret_is_scanned(self):
        cases = (
            ("PAPERCLIP_SECRET_MTE_CONTEXT7_API_KEY_ENABLED", False),
            ("PAPERCLIP_SECRET_MTE_CONTEXT7_API_KEY_MODE", False),
            ("PAPERCLIP_SECRET_MTE_CONTEXT7_API_KEY_ROOT", False),
            ("PAPERCLIP_SECRET_MTE_CONTEXT7_API_KEY_DURATION", False),
            ("PAPERCLIP_SECRET_MTE_CONTEXT7_API_KEY_ID", False),
            (
                "PAPERCLIP_SECRET_MTE_CONTEXT7_API_KEY_SOURCE_FINGERPRINT",
                False,
            ),
            ("PAPERCLIP_SECRET_MTE_CONTEXT7_API_KEY", True),
        )

        for index, (key, should_fail) in enumerate(cases):
            with self.subTest(key=key):
                value = f"audit-regression-value-{index}"
                (self.secret_root / "platform.env").write_text(f"{key}={value}\n")
                (self.manifests / "leak.txt").write_text(value)
                if should_fail:
                    with self.assertRaises(SystemExit):
                        result = self.run_audit()
                else:
                    result = self.run_audit()
                    self.assertTrue(result["ok"])
                    self.assertEqual(result["sensitiveKeysScanned"], 0)
                    self.assertEqual(result["publicKeysExcluded"], 1)

    def test_init_preserves_existing_canonical_values(self):
        canonical = self.secret_root / "platform.env"
        canonical.write_text("POSTGRES_ADMIN_PASSWORD=preserved-password\n")
        result = self.module.init()
        values = self.module.dotenv(canonical)
        self.assertEqual(values["POSTGRES_ADMIN_PASSWORD"], "preserved-password")
        self.assertFalse((self.secret_root / "services").exists())
        self.assertTrue(result["projectionRenderRequired"])
        self.assertEqual(
            result["canonicalSourceSha256"],
            self.module.hashlib.sha256(canonical.read_bytes()).hexdigest(),
        )

    def test_init_creates_only_root_private_canonical_artifacts(self):
        self.module.init()
        for path, expected_mode in (
            (self.secret_root, 0o700),
            (self.secret_root / "integrations", 0o700),
            (self.secret_root / "platform.env", 0o600),
            (self.secret_root / "generated-manifest.json", 0o600),
        ):
            with self.subTest(path=path):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected_mode)
        self.assertEqual(
            list(self.secret_root.glob("platform.env.tmp")),
            [],
        )

    def test_canonical_symlink_is_rejected_without_reading_or_replacing_target(self):
        target = self.root / "outside.env"
        target.write_text("POSTGRES_ADMIN_PASSWORD=preserved\n")
        canonical = self.secret_root / "platform.env"
        canonical.symlink_to(target)
        with self.assertRaisesRegex(
            self.module.SecretConfigurationError,
            "not a regular file",
        ):
            self.module.init()
        self.assertEqual(target.read_text(), "POSTGRES_ADMIN_PASSWORD=preserved\n")
        self.assertTrue(canonical.is_symlink())

    def test_secret_root_symlink_is_rejected_before_canonical_read(self):
        target_root = self.root / "target-secrets"
        target_root.mkdir()
        target_env = target_root / "platform.env"
        target_env.write_text("POSTGRES_ADMIN_PASSWORD=preserved\n")
        linked_root = self.root / "linked-secrets"
        linked_root.symlink_to(target_root, target_is_directory=True)
        module = load_module(self.root, linked_root)
        with self.assertRaisesRegex(
            module.SecretConfigurationError,
            "not a directory",
        ):
            module.init()
        self.assertEqual(target_env.read_text(), "POSTGRES_ADMIN_PASSWORD=preserved\n")

    def test_lock_symlink_is_rejected_before_locking(self):
        target = self.root / "outside.lock"
        target.write_text("preserved\n")
        lock = self.secret_root / ".platform-env.lock"
        lock.symlink_to(target)
        with self.assertRaisesRegex(
            self.module.SecretConfigurationError,
            "cannot open secret configuration lock",
        ):
            with self.module.config_lock():
                self.fail("must not acquire a symlinked lock")
        self.assertEqual(target.read_text(), "preserved\n")

    def test_env_writer_rejects_line_injection(self):
        canonical = self.secret_root / "platform.env"
        with self.assertRaisesRegex(
            self.module.SecretConfigurationError,
            "must be single-line",
        ):
            self.module.write_env(canonical, {"SAFE_KEY": "value\nINJECTED_KEY=bad"})
        self.assertFalse(canonical.exists())

    def test_dotenv_rejects_duplicate_canonical_keys(self):
        canonical = self.secret_root / "platform.env"
        canonical.write_text("POSTGRES_ADMIN_PASSWORD=one\nPOSTGRES_ADMIN_PASSWORD=two\n")
        with self.assertRaisesRegex(
            self.module.SecretConfigurationError,
            "canonical key is duplicated",
        ):
            self.module.dotenv(canonical)

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

    def test_hermes_api_server_identity_is_generated_as_a_secret(self):
        value = self.module.generated_defaults()["HERMES_API_SERVER_KEY"]
        self.assertGreaterEqual(len(value), 36)

    def test_postgres_notion_profile_generates_only_internal_database_secrets(self):
        values = self.module.generated_defaults("postgres-notion")
        self.assertIn("POSTGREST_DATA_DB_PASSWORD", values)
        self.assertIn("POSTGREST_AUTHENTICATOR_PASSWORD", values)
        self.assertIn("POSTGREST_JWT_SECRET", values)
        self.assertNotIn("NOTION_TOKEN", values)

    def test_daytona_declared_secrets_are_generated_with_strong_types(self):
        expected = {
            "DAYTONA_ADMIN_API_KEY",
            "DAYTONA_DB_PASSWORD",
            "DAYTONA_ENCRYPTION_KEY",
            "DAYTONA_ENCRYPTION_SALT",
            "DAYTONA_HEALTH_CHECK_API_KEY",
            "DAYTONA_MINIO_PASSWORD",
            "DAYTONA_OTEL_COLLECTOR_API_KEY",
            "DAYTONA_PROXY_API_KEY",
            "DAYTONA_REGISTRY_PASSWORD",
            "DAYTONA_RUNNER_API_KEY",
            "DAYTONA_SSH_GATEWAY_API_KEY",
        }
        config = yaml.safe_load((ROOT / "config/platform.yaml").read_text())
        component = next(
            row for row in config["spec"]["components"] if row["id"] == "daytona"
        )
        declared = {
            key for key in component["secrets"] if key.startswith("DAYTONA_")
        }
        self.assertEqual(declared, expected)

        values = self.module.daytona_generated_defaults()
        self.assertEqual(set(values), expected)
        self.assertEqual(len(set(values.values())), len(expected))
        self.assertRegex(values["DAYTONA_ADMIN_API_KEY"], r"^dtn_[0-9a-f]{64}$")
        for key in {
            "DAYTONA_ENCRYPTION_KEY",
            "DAYTONA_ENCRYPTION_SALT",
        }:
            self.assertRegex(values[key], r"^[0-9a-f]{32}$")
        for key in expected - {
            "DAYTONA_ADMIN_API_KEY",
            "DAYTONA_ENCRYPTION_KEY",
            "DAYTONA_ENCRYPTION_SALT",
        }:
            self.assertRegex(values[key], r"^[0-9a-f]{48}$")

    def test_init_creates_and_then_preserves_all_daytona_secrets(self):
        expected = set(self.module.daytona_generated_defaults())
        first = self.module.init()
        canonical = self.secret_root / "platform.env"
        first_values = self.module.dotenv(canonical)
        self.assertTrue(expected <= set(first_values))
        self.assertTrue(expected <= set(first["createdKeys"]))
        public_result = json.dumps(first)
        manifest = (self.secret_root / "generated-manifest.json").read_text()
        for key in expected:
            self.assertNotIn(first_values[key], public_result)
            self.assertNotIn(first_values[key], manifest)

        second = self.module.init()
        second_values = self.module.dotenv(canonical)
        self.assertEqual(
            {key: first_values[key] for key in expected},
            {key: second_values[key] for key in expected},
        )
        self.assertTrue(expected.isdisjoint(second["createdKeys"]))
        self.assertEqual(stat.S_IMODE(canonical.stat().st_mode), 0o600)

    def test_daytona_secret_leak_is_detected_without_emitting_its_value(self):
        secret = self.module.daytona_generated_defaults()["DAYTONA_PROXY_API_KEY"]
        (self.secret_root / "platform.env").write_text(
            f"DAYTONA_PROXY_API_KEY={secret}\n"
        )
        (self.manifests / "leak.txt").write_text(secret)
        output = io.StringIO()
        with mock.patch("sys.stdout", output), self.assertRaises(SystemExit):
            self.module.audit()
        self.assertNotIn(secret, output.getvalue())
        result = json.loads(output.getvalue())
        self.assertEqual(result["findings"][0]["key"], "DAYTONA_PROXY_API_KEY")


if __name__ == "__main__":
    unittest.main()

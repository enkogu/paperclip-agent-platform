from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class HermesSecurityDefaultsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.installer = load("security_server_hermes", "tools/platform-cli/server-hermes.py")

    def test_service_is_hardened_unless_admin_mode_is_explicit(self):
        safe = self.installer.render_service_unit(grant_platform_admin=False)
        privileged = self.installer.render_service_unit(grant_platform_admin=True)

        self.assertIn("NoNewPrivileges=true", safe)
        self.assertIn("ProtectSystem=strict", safe)
        self.assertIn("ReadWritePaths=/var/lib/mte-hermes", safe)
        self.assertNotIn("@@HERMES_PRIVILEGE_HARDENING@@", safe)
        self.assertNotIn("NoNewPrivileges=true", privileged)
        self.assertIn("Explicit host-admin mode", privileged)

        self.assertFalse(
            self.installer.parser().parse_args(["install"]).grant_platform_admin
        )
        self.assertTrue(
            self.installer.parser()
            .parse_args(["install", "--grant-platform-admin"])
            .grant_platform_admin
        )

    def test_default_policy_reconcile_removes_stale_unrestricted_sudo(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "mte-hermes"
            policy.write_text("mte-hermes ALL=(ALL) NOPASSWD: ALL\n")
            with mock.patch.object(self.installer, "SUDOERS_PATH", policy):
                self.installer.reconcile_admin_policy(False)
            self.assertFalse(policy.exists())

    def test_runtime_projection_excludes_unrelated_platform_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = root / "platform.env"
            runtime = root / "hermes-runtime.env"
            digest = root / "hermes-runtime.env.sha256"
            lock = root / ".platform-env.lock"
            values = {
                key: f"unit-{index}"
                for index, key in enumerate(self.installer.REQUIRED_KEYS)
            }
            values.update(
                {
                    "MATTERMOST_URL": "http://127.0.0.1:18065",
                    "MATTERMOST_TOKEN": "unit-mattermost-token",
                    "MATTERMOST_ALLOWED_USERS": "a" * 26,
                    "UNRELATED_ROOT_SECRET": "must-not-be-projected",
                }
            )
            canonical.write_text(
                "".join(f"{key}={value}\n" for key, value in values.items())
            )
            source_sha = hashlib.sha256(canonical.read_bytes()).hexdigest()
            with (
                mock.patch.object(self.installer, "DEFAULT_ENV_FILE", canonical),
                mock.patch.object(self.installer, "PLATFORM_ENV_LOCK", lock),
                mock.patch.object(self.installer, "HERMES_RUNTIME_ENV_FILE", runtime),
                mock.patch.object(
                    self.installer, "HERMES_RUNTIME_ENV_HASH_PATH", digest
                ),
                mock.patch.object(self.installer.os, "chown"),
            ):
                evidence = self.installer.render_runtime_credential_projection(
                    canonical, source_sha
                )
                self.assertTrue(
                    self.installer.runtime_credential_projection_matches(canonical)
                )

            projected = runtime.read_text()
            self.assertNotIn("UNRELATED_ROOT_SECRET", projected)
            self.assertNotIn("must-not-be-projected", projected)
            self.assertIn("HERMES_PAPERCLIP_API_KEY", projected)
            self.assertIn("OPENAI_API_KEY=", projected)
            self.assertIn("OPENAI_BASE_URL=", projected)
            self.assertNotIn("HERMES_LLM_API_KEY=", projected)
            self.assertEqual(stat.S_IMODE(runtime.stat().st_mode), 0o600)
            self.assertEqual(
                digest.read_text().strip(),
                hashlib.sha256(runtime.read_bytes()).hexdigest(),
            )
            self.assertLess(evidence["keyCount"], len(values))


class MattermostSecretTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bootstrap = load(
            "security_bootstrap_mattermost", "deployment/services/hermes/bootstrap-mattermost.py"
        )
        cls.provision = load("security_server_provision", "tools/platform-cli/server-provision.py")

    def test_bootstrap_password_is_sent_in_api_body(self):
        existing = mock.Mock(returncode=0, stdout="[]", stderr="")
        calls = []

        def api(path, **kwargs):
            calls.append((path, kwargs))
            if path == "/api/v4/users":
                return {"id": "operator-id", "username": "mte-operator"}, {}
            return {}, {}

        with (
            mock.patch.object(self.bootstrap, "mmctl", return_value=existing),
            mock.patch.object(self.bootstrap, "api_request", side_effect=api),
            mock.patch.object(
                self.bootstrap.secrets,
                "token_urlsafe",
                return_value="unit-password-never-in-argv",
            ),
        ):
            user, password = self.bootstrap.ensure_user(
                "mattermost", "admin-token", None
            )
        self.assertEqual(user["id"], "operator-id")
        self.assertEqual(password, "unit-password-never-in-argv")
        create = next(row for row in calls if row[0] == "/api/v4/users")
        self.assertEqual(create[1]["body"]["password"], password)
        self.assertEqual(create[1]["bearer"], "admin-token")

    def test_provision_mattermost_source_has_no_password_cli_flag(self):
        for relative in (
            "deployment/services/hermes/bootstrap-mattermost.py",
            "tools/platform-cli/server-provision.py",
        ):
            with self.subTest(relative=relative):
                source = (ROOT / relative).read_text()
                self.assertNotIn(
                    '"--password"',
                    source,
                    "Mattermost passwords must travel in JSON API bodies",
                )

    def test_provision_admin_creation_uses_json_request(self):
        source = (ROOT / "tools/platform-cli/server-provision.py").read_text()
        self.assertIn(
            'f"{ctx.url(component)}/api/v4/users"',
            source,
        )
        self.assertIn(
            '"password": saved["MATTERMOST_ADMIN_PASSWORD"]',
            source,
        )
        self.assertNotIn(
            "mmctl_password(",
            source,
        )


class PaperclipAuthenticationContractTests(unittest.TestCase):
    def test_runtime_supports_authenticated_public_without_secret_in_container_env(
        self,
    ):
        runtime_step = (ROOT / "deployment/steps/50-paperclip.sh").read_text()
        self.assertIn("PAPERCLIP_DEPLOYMENT_MODE", runtime_step)
        self.assertIn("PAPERCLIP_DEPLOYMENT_EXPOSURE", runtime_step)
        self.assertIn("authenticated public mode requires HTTPS", runtime_step)
        self.assertIn("/run/secrets/paperclip-agent-jwt-secret", runtime_step)
        self.assertIn("scripts/profile_catalog.py", runtime_step)
        self.assertIn('"$RUNTIME_ROOT/profiles"', runtime_step)
        self.assertIn("profile instructions ref missing", runtime_step)
        self.assertNotIn("-e PAPERCLIP_AGENT_JWT_SECRET=", runtime_step)
        self.assertNotIn('deploymentMode: "local_trusted"', runtime_step)
        self.assertIn('source: "configure"', runtime_step)
        self.assertNotIn('source: "mte-runtime-reconcile"', runtime_step)


if __name__ == "__main__":
    unittest.main()

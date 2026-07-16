from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class HermesAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.acceptance = load("test_hermes_acceptance", "deployment/services/hermes/acceptance-canary.py")

    def test_router_delta_requires_hermes_key_model_and_total_growth(self):
        result = self.acceptance.usage_delta(
            {"hermesKeyRequests": 4, "modelRequests": 10, "totalRequests": 20},
            {"hermesKeyRequests": 5, "modelRequests": 11, "totalRequests": 21},
        )
        self.assertEqual(result["hermesKeyRequests"], 1)
        with self.assertRaises(self.acceptance.CanaryError):
            self.acceptance.usage_delta(
                {"hermesKeyRequests": 4, "modelRequests": 10, "totalRequests": 20},
                {"hermesKeyRequests": 4, "modelRequests": 11, "totalRequests": 21},
            )

    def test_router_usage_matches_exact_provider_qualified_model(self):
        key = "unit-hermes-key"
        provider = "openai-compatible-chat-unit-node"
        values = {
            "HERMES_LLM_BASE_URL": "http://127.0.0.1:20128/v1",
            "HERMES_LLM_API_KEY": key,
            "HERMES_LLM_MODEL": "mte-minimax/MiniMax-M2.7-highspeed",
            "NINEROUTER_INITIAL_PASSWORD": "unit-password",
            "NINEROUTER_MINIMAX_PROVIDER_NODE_ID": provider,
        }
        usage = {
            "byApiKey": {f"mte-client-hermes ({key})": {"requests": 4}},
            "byModel": {
                f"MiniMax-M2.7-highspeed ({provider})": {"requests": 7},
                "MiniMax-M2.7-highspeed (another-node)": {"requests": 99},
            },
            "totalRequests": 11,
        }

        def request(url, **_kwargs):
            if url.endswith("/api/auth/login"):
                return {"ok": True}
            if url.endswith("/api/usage/history"):
                return usage
            raise AssertionError(url)

        with mock.patch.object(self.acceptance, "request_json", side_effect=request):
            self.assertEqual(
                self.acceptance.router_usage(values),
                {
                    "hermesKeyRequests": 4,
                    "modelRequests": 7,
                    "totalRequests": 11,
                },
            )

    def test_installer_requires_and_finds_acceptance_asset(self):
        installer = load("test_hermes_installer", "tools/platform-cli/server-hermes.py")
        assets = installer.hermes_asset_paths()
        self.assertEqual(
            assets,
            {
                "acceptance": ROOT / "deployment/services/hermes/acceptance-canary.py",
                "mattermostBootstrap": ROOT / "deployment/services/hermes/bootstrap-mattermost.py",
                "configTemplate": ROOT
                / "deployment/services/hermes/config.yaml.template",
                "soul": ROOT / "deployment/services/hermes/soul.txt",
                "platformSkill": ROOT
                / "deployment/services/hermes/platform-skill.txt",
                "serviceUnit": ROOT / "deployment/services/hermes/service.unit",
            },
        )
        self.assertTrue(all(path.is_file() for path in assets.values()))

    def test_producer_metadata_hashes_exact_installed_files(self):
        with tempfile.TemporaryDirectory() as directory:
            producer = Path(directory) / "acceptance-canary"
            native_cli = Path(directory) / "hermes"
            producer.write_bytes(b"producer-v1")
            native_cli.write_bytes(b"native-cli-v1")
            with (
                mock.patch.object(self.acceptance, "PRODUCER", producer),
                mock.patch.object(self.acceptance, "HERMES_CLI", native_cli),
            ):
                value = self.acceptance.producer_metadata()
        self.assertEqual(
            value["producerSha256"], hashlib.sha256(b"producer-v1").hexdigest()
        )
        self.assertEqual(
            value["nativeHermesCliSha256"],
            hashlib.sha256(b"native-cli-v1").hexdigest(),
        )

    def test_native_acceptance_uses_upstream_api_and_terminal(self):
        source = (ROOT / "deployment/services/hermes/acceptance-canary.py").read_text()
        self.assertIn("/v1/runs", source)
        self.assertIn("X-Hermes-Session-Key", source)
        self.assertIn("run_native_terminal_check", source)

    def test_telegram_absent_is_conditional_not_passed(self):
        self.assertEqual(
            self.acceptance.telegram_connection({}),
            {
                "ok": None,
                "state": "conditional_disabled",
                "notFabricated": True,
            },
        )
        with self.assertRaises(self.acceptance.CanaryError):
            self.acceptance.telegram_connection(
                {"HERMES_TELEGRAM_BOT_TOKEN": "partial-only"}
            )

    def test_platform_declares_only_the_native_hermes_runtime_contract(self):
        document = yaml.safe_load((ROOT / "config/platform.yaml").read_text())
        hermes = next(
            row for row in document["spec"]["components"] if row.get("id") == "hermes"
        )
        self.assertEqual(
            hermes["runtime"],
            {
                "command": "/opt/mte-hermes/current/venv/bin/hermes gateway run --replace",
                "apiExposure": "loopback",
                "llmRoute": "9router",
                "messaging": ["telegram", "mattermost"],
                "operatorMode": "unrestricted_host_repair",
            },
        )
        self.assertTrue(
            {
                "HERMES_LLM_API_KEY",
                "HERMES_TELEGRAM_BOT_TOKEN",
                "HERMES_TELEGRAM_ALLOWED_USERS",
            }
            <= set(hermes["secrets"])
        )


class HermesInstallerTests(unittest.TestCase):
    def setUp(self):
        self.installer = load("test_hermes_installer_wait", "tools/platform-cli/server-hermes.py")

    def test_api_wait_retries_authenticated_health_until_ready(self):
        values = {
            "HERMES_API_SERVER_HOST": "127.0.0.1",
            "HERMES_API_SERVER_PORT": "8642",
            "HERMES_API_SERVER_KEY": "unit-secret",
        }
        ticks = iter((0.0, 0.1, 0.2, 0.3))
        with (
            mock.patch.object(
                self.installer,
                "json_request",
                side_effect=(OSError("not-ready"), {"status": "ok"}),
            ) as request,
            mock.patch.object(self.installer.time, "monotonic", side_effect=ticks),
            mock.patch.object(self.installer.time, "sleep") as sleep,
        ):
            self.assertTrue(
                self.installer.wait_hermes_api_server(values, timeout_seconds=30)
            )
        self.assertEqual(request.call_count, 2)
        self.assertEqual(
            request.call_args.kwargs["bearer"],
            "unit-secret",
        )
        sleep.assert_called_once_with(1)

    def test_service_runs_upstream_hermes_directly(self):
        unit = self.installer.render_service_unit(grant_platform_admin=True)
        self.assertIn(
            "ExecStart=/opt/mte-hermes/current/venv/bin/hermes gateway run --replace",
            unit,
        )
        self.assertIn(
            "EnvironmentFile=/root/.config/mte-secrets/hermes-runtime.env", unit
        )

    def test_projection_reconcile_requires_render_audit_and_exact_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = root / "platform.env"
            renderer = root / "server-config.py"
            manifest = root / "projections-manifest.json"
            projection = root / "mattermost.env"
            env.write_text("SAFE_REF=value\n")
            renderer.write_text("# unit renderer\n")
            projection.write_text("SAFE_REF=value\n")
            source_sha = hashlib.sha256(env.read_bytes()).hexdigest()
            projection_sha = hashlib.sha256(projection.read_bytes()).hexdigest()
            generator = "unit-renderer/v1"
            manifest.write_text(
                json.dumps(
                    {
                        "sourceSha256": source_sha,
                        "generatorVersion": generator,
                        "projections": [
                            {
                                "path": str(projection),
                                "sourceSha256": source_sha,
                                "contentSha256": projection_sha,
                                "generatorVersion": generator,
                            }
                        ],
                    }
                )
            )
            manifest.chmod(0o600)
            responses = [
                mock.Mock(
                    returncode=0,
                    stdout=json.dumps(
                        {
                            "rendered": True,
                            "sourceSha256": source_sha,
                            "generatorVersion": generator,
                            "projectionCount": 1,
                            "manifest": str(manifest),
                        }
                    ),
                ),
                mock.Mock(
                    returncode=0,
                    stdout=json.dumps(
                        {"ok": True, "sourceSha256": source_sha, "findings": []}
                    ),
                ),
            ]
            with (
                mock.patch.object(self.installer, "CONFIG_RENDERER", renderer),
                mock.patch.object(self.installer, "PROJECTIONS_MANIFEST", manifest),
                mock.patch.object(
                    self.installer, "command", side_effect=responses
                ) as run,
            ):
                evidence = self.installer.reconcile_platform_projections(env)
        self.assertEqual(evidence["sourceSha256"], source_sha)
        self.assertEqual(evidence["projectionCount"], 1)
        self.assertEqual(
            [call.args[0][-1] for call in run.call_args_list], ["render", "audit"]
        )

    def test_projection_hash_is_written_under_shared_lock_for_expected_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = root / "platform.env"
            digest = root / "platform.env.sha256"
            lock = root / ".platform-env.lock"
            env.write_text("SAFE_REF=value\n")
            expected = hashlib.sha256(env.read_bytes()).hexdigest()
            locks: list[int] = []

            def record_lock(_descriptor, operation):
                locks.append(operation)

            with (
                mock.patch.object(self.installer, "DEFAULT_ENV_FILE", env),
                mock.patch.object(self.installer, "PROJECTION_HASH_PATH", digest),
                mock.patch.object(self.installer, "PLATFORM_ENV_LOCK", lock),
                mock.patch.object(self.installer.os, "chown"),
                mock.patch.object(
                    self.installer.fcntl, "flock", side_effect=record_lock
                ),
            ):
                self.installer.write_projection_hash(env, expected)

            self.assertEqual(digest.read_text().strip(), expected)
            self.assertEqual(stat.S_IMODE(digest.stat().st_mode), 0o600)
            self.assertEqual(
                locks,
                [self.installer.fcntl.LOCK_EX, self.installer.fcntl.LOCK_UN],
            )

    def test_install_stops_before_runtime_changes_when_projection_reconcile_fails(self):
        args = mock.Mock(
            env_file=self.installer.DEFAULT_ENV_FILE,
            grant_platform_admin=True,
            no_start=True,
        )
        with (
            mock.patch.object(self.installer, "require_root"),
            mock.patch.object(self.installer, "bootstrap_mattermost") as bootstrap,
            mock.patch.object(
                self.installer,
                "reconcile_platform_projections",
                side_effect=self.installer.HermesInstallError("audit failed"),
            ) as reconcile,
            mock.patch.object(self.installer, "ensure_packages") as packages,
        ):
            with self.assertRaises(self.installer.HermesInstallError):
                self.installer.install(args)

        bootstrap.assert_called_once_with()
        reconcile.assert_called_once_with(self.installer.DEFAULT_ENV_FILE)
        packages.assert_not_called()


class HermesMattermostBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.bootstrap = load(
            "test_hermes_mattermost_bootstrap", "deployment/services/hermes/bootstrap-mattermost.py"
        )

    def test_canonical_update_uses_shared_lock_and_atomic_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / "platform.env"
            lock = Path(directory) / ".platform-env.lock"
            env.write_text("EXISTING=preserved\nMATTERMOST_TOKEN=old\n")
            env.chmod(0o600)
            locks: list[int] = []

            def record_lock(_descriptor, operation):
                locks.append(operation)

            with (
                mock.patch.object(self.bootstrap, "ENV_FILE", env),
                mock.patch.object(self.bootstrap, "ENV_LOCK", lock),
                mock.patch.object(
                    self.bootstrap,
                    "read_env",
                    return_value=(
                        ["EXISTING=preserved", "MATTERMOST_TOKEN=old"],
                        {"EXISTING": "preserved", "MATTERMOST_TOKEN": "old"},
                    ),
                ),
                mock.patch.object(self.bootstrap.os, "chown"),
                mock.patch.object(
                    self.bootstrap.fcntl, "flock", side_effect=record_lock
                ),
            ):
                self.bootstrap.update_env(
                    {"MATTERMOST_TOKEN": "new", "MATTERMOST_ALLOWED_USERS": "user"}
                )

            self.assertEqual(stat.S_IMODE(env.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
            self.assertIn("EXISTING=preserved", env.read_text())
            self.assertIn("MATTERMOST_TOKEN=new", env.read_text())
            self.assertIn("MATTERMOST_ALLOWED_USERS=user", env.read_text())
            self.assertEqual(
                locks,
                [self.bootstrap.fcntl.LOCK_EX, self.bootstrap.fcntl.LOCK_UN],
            )

    def test_canonical_update_rereads_source_after_lock_acquisition(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / "platform.env"
            env.write_text("EXISTING=before-lock\nMATTERMOST_TOKEN=old\n")
            env.chmod(0o600)
            reads: list[str] = []

            @contextmanager
            def concurrent_writer_then_lock():
                env.write_text("EXISTING=concurrent\nMATTERMOST_TOKEN=old\n")
                yield

            def read_current():
                text = env.read_text()
                reads.append(text)
                lines = text.splitlines()
                values = dict(line.split("=", 1) for line in lines if "=" in line)
                return lines, values

            with (
                mock.patch.object(self.bootstrap, "ENV_FILE", env),
                mock.patch.object(
                    self.bootstrap,
                    "platform_env_lock",
                    side_effect=concurrent_writer_then_lock,
                ),
                mock.patch.object(self.bootstrap, "read_env", side_effect=read_current),
                mock.patch.object(self.bootstrap.os, "chown"),
            ):
                self.bootstrap.update_env({"MATTERMOST_TOKEN": "new"})

            self.assertEqual(len(reads), 1)
            self.assertIn("EXISTING=concurrent", reads[0])
            self.assertIn("EXISTING=concurrent", env.read_text())
            self.assertIn("MATTERMOST_TOKEN=new", env.read_text())


if __name__ == "__main__":
    unittest.main()

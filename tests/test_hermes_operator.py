from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
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


def mattermost_bootstrap_values(bootstrap):
    values = {key: "configured" for key in bootstrap.CANONICAL_RUNTIME_KEYS}
    values.update(
        {
            "HERMES_PAPERCLIP_URL": "http://127.0.0.1:43100/api",
            "HERMES_KESTRA_URL": "http://127.0.0.1:48082",
            "HERMES_LLM_BASE_URL": "http://127.0.0.1:40128/v1",
            "MATTERMOST_URL": "http://127.0.0.1:48065",
            "MATTERMOST_BOOTSTRAP_HTTP_TIMEOUT_SECONDS": "17",
            "MATTERMOST_BOOTSTRAP_COMMAND_TIMEOUT_SECONDS": "71",
            "MATTERMOST_CONTAINER_NAME_SUFFIX": "mattermost-unit-1",
            "MATTERMOST_HERMES_BOT_USERNAME": "unit-hermes",
            "MATTERMOST_OPERATOR_USERNAME": "unit-operator",
            "MATTERMOST_OPERATOR_EMAIL": "operator@unit.invalid",
            "MATTERMOST_PLATFORM_TEAM_NAME": "unit-platform",
            "MATTERMOST_OPERATOR_CHANNEL_NAME": "unit-operator-channel",
            "MATTERMOST_ADMIN_USERNAME": "unit-admin",
            "MATTERMOST_ADMIN_PASSWORD": "unit-admin-password",
        }
    )
    return values


class HermesAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.acceptance = load(
            "test_hermes_acceptance", "deployment/services/hermes/acceptance-canary.py"
        )

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

    def test_acceptance_default_http_client_uses_urlopen(self):
        response = mock.MagicMock()
        response.read.return_value = b'{"ok":true}'
        response.__enter__.return_value = response
        with mock.patch.object(
            self.acceptance.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            self.assertEqual(
                self.acceptance.request_json("http://127.0.0.1:8642/health"),
                {"ok": True},
            )
        urlopen.assert_called_once()
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 30)

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
                "mattermostBootstrap": ROOT
                / "deployment/services/hermes/bootstrap-mattermost.py",
                "configTemplate": ROOT
                / "deployment/services/hermes/config.yaml.template",
                "soul": ROOT / "deployment/services/hermes/soul.txt",
                "platformSkill": ROOT / "skills/system-platform",
                "requirementsLock": ROOT
                / "deployment/services/hermes/requirements-messaging.lock",
                "serviceUnit": ROOT / "deployment/services/hermes/service.unit",
                "supplyChainLock": ROOT
                / "deployment/services/hermes/supply-chain.lock.json",
            },
        )
        self.assertTrue(assets["platformSkill"].is_dir())
        self.assertTrue(
            all(
                path.is_file()
                for name, path in assets.items()
                if name != "platformSkill"
            )
        )

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

    def test_acceptance_reads_canonical_env_without_a_second_hash_sidecar(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / "platform.env"
            env.write_text("SAFE_REF=value\n")
            with mock.patch.object(self.acceptance, "ENV_FILE", env):
                self.assertEqual(self.acceptance.env_values(), {"SAFE_REF": "value"})

    def test_native_acceptance_uses_upstream_api_and_terminal(self):
        source = (ROOT / "deployment/services/hermes/acceptance-canary.py").read_text()
        self.assertIn("/v1/runs", source)
        self.assertIn("X-Hermes-Session-Key", source)
        self.assertIn("run_native_terminal_check", source)

    def test_native_acceptance_accepts_only_private_api_bindings(self):
        values = {
            "HERMES_API_SERVER_HOST": "172.30.0.1",
            "HERMES_API_SERVER_PORT": "8642",
            "HERMES_API_SERVER_KEY": "unit-key",
        }
        self.assertEqual(
            self.acceptance.api_server(values),
            ("http://172.30.0.1:8642", "unit-key"),
        )
        for host in ("0.0.0.0", "8.8.8.8", "not-an-ip"):
            with self.subTest(host=host):
                with self.assertRaises(self.acceptance.CanaryError):
                    self.acceptance.api_server({**values, "HERMES_API_SERVER_HOST": host})

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

    def test_mattermost_requires_and_proves_the_native_operator_channel(self):
        values = {
            "MATTERMOST_URL": "http://127.0.0.1:48065",
            "MATTERMOST_TOKEN": "unit-token",
            "MATTERMOST_ALLOWED_USERS": "a" * 26,
            "MATTERMOST_HOME_CHANNEL": "b" * 26,
        }

        def request(url, **_kwargs):
            if url.endswith("/users/me"):
                return {"id": "c" * 26, "is_bot": True}
            self.assertTrue(url.endswith("/channels/" + "b" * 26))
            return {"id": "b" * 26}

        with mock.patch.object(self.acceptance, "request_json", side_effect=request):
            result = self.acceptance.mattermost_connection(values)
        self.assertEqual(
            result,
            {
                "ok": True,
                "state": "ready",
                "nativeHermesIntegration": True,
                "operatorChannelAccessible": True,
            },
        )

        with self.assertRaises(self.acceptance.CanaryError):
            self.acceptance.mattermost_connection(
                {key: value for key, value in values.items() if key != "MATTERMOST_HOME_CHANNEL"}
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
                "apiExposure": "private-docker-bridge",
                "llmRoute": "9router",
                "messaging": ["telegram", "mattermost"],
                "operatorMode": "${HERMES_OPERATOR_MODE:?required}",
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
        self.installer = load(
            "test_hermes_installer_wait", "tools/platform-cli/server-hermes.py"
        )

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

    def test_private_docker_bridge_is_a_valid_gateway_bind(self):
        self.assertEqual(
            self.installer.validate_api_server_host("172.30.0.1"),
            "172.30.0.1",
        )
        self.assertEqual(
            self.installer.validate_api_server_host("127.0.0.1"),
            "127.0.0.1",
        )
        for value in ("0.0.0.0", "8.8.8.8", "not-an-ip"):
            with self.subTest(value=value):
                with self.assertRaises(self.installer.HermesInstallError):
                    self.installer.validate_api_server_host(value)

    def test_service_runs_upstream_hermes_directly(self):
        unit = self.installer.render_service_unit(grant_platform_admin=True)
        self.assertIn(
            "ExecStart=/opt/mte-hermes/current/venv/bin/hermes gateway run --replace",
            unit,
        )
        self.assertIn(
            "EnvironmentFile=/root/.config/mte-secrets/services/hermes.env", unit
        )
        self.assertIn("WorkingDirectory=/var/lib/mte-hermes", unit)
        self.assertNotIn("WorkingDirectory=/opt/mte-platform", unit)

    def test_operator_mode_requires_matching_explicit_admin_flag(self):
        self.assertEqual(
            self.installer.authorize_operator_mode("unprivileged_service", False),
            "unprivileged_service",
        )
        self.assertEqual(
            self.installer.authorize_operator_mode(
                "unrestricted_host_repair", True
            ),
            "unrestricted_host_repair",
        )
        for mode, flag in (
            ("unprivileged_service", True),
            ("unrestricted_host_repair", False),
            ("unknown", False),
        ):
            with self.subTest(mode=mode, flag=flag):
                with self.assertRaises(self.installer.HermesInstallError):
                    self.installer.authorize_operator_mode(mode, flag)

    def test_supply_chain_assets_bind_official_wheel_and_mcp_closure(self):
        evidence = self.installer.validate_supply_chain_assets()
        self.assertEqual(
            evidence["manifestSha256"], self.installer.SUPPLY_CHAIN_MANIFEST_SHA256
        )
        self.assertEqual(len(evidence["pythonPackages"]), 89)
        self.assertEqual(evidence["pythonPackages"]["setuptools"], "82.0.1")
        self.assertEqual(evidence["pythonPackages"]["pip"], "26.0.1")
        self.assertEqual(evidence["pythonPackages"]["hermes-agent"], "0.18.2")
        self.assertEqual(evidence["pythonPackages"]["mcp"], "1.26.0")
        self.assertEqual(evidence["wheelSha256"], self.installer.HERMES_WHEEL_SHA256)
        self.assertEqual(evidence["wheelSize"], 9569078)
        source = (ROOT / "tools/platform-cli/server-hermes.py").read_text()
        self.assertIn('"--require-hashes"', source)
        self.assertIn('"--only-binary=:all:"', source)
        self.assertNotIn('"git",\n                    "clone"', source)
        self.assertNotIn('"--no-build-isolation"', source)
        self.assertNotIn("install_source", source)

    def test_supply_chain_rejects_manifest_and_requirement_tampering(self):
        assets = self.installer.hermes_asset_paths()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "supply-chain.lock.json"
            requirements = root / "requirements-messaging.lock"
            manifest.write_bytes(assets["supplyChainLock"].read_bytes())
            requirements.write_bytes(assets["requirementsLock"].read_bytes())
            projected = {
                **assets,
                "supplyChainLock": manifest,
                "requirementsLock": requirements,
            }
            manifest.write_text(manifest.read_text() + "\n")
            with mock.patch.object(
                self.installer, "hermes_asset_paths", return_value=projected
            ):
                with self.assertRaisesRegex(
                    self.installer.HermesInstallError, "manifest hash drifted"
                ):
                    self.installer.validate_supply_chain_assets()

            manifest.write_bytes(assets["supplyChainLock"].read_bytes())
            requirements.write_text(
                requirements.read_text().replace("pip==26.0.1", "pip==26.0.2")
            )
            with mock.patch.object(
                self.installer, "hermes_asset_paths", return_value=projected
            ):
                with self.assertRaisesRegex(
                    self.installer.HermesInstallError, "Python dependency lock"
                ):
                    self.installer.validate_supply_chain_assets()

    def test_venv_verifier_rejects_installed_and_receipt_drift(self):
        supply = {
            "manifestSha256": "a" * 64,
            "requirementsSha256": "b" * 64,
            "pythonPackages": {
                "pip": "26.0.1",
                "hermes-agent": self.installer.VERSION,
            },
        }
        expected = supply["pythonPackages"]
        with (
            mock.patch.object(
                self.installer, "validate_supply_chain_assets", return_value=supply
            ),
            mock.patch.object(
                self.installer,
                "python_distribution_versions",
                return_value={**expected, "unlocked": "1.0"},
            ),
        ):
            with self.assertRaisesRegex(
                self.installer.HermesInstallError, "dependency closure drifted"
            ):
                self.installer.venv_supply_chain_evidence()

        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_text(
                json.dumps(
                    {
                        "hermesVersion": self.installer.VERSION,
                        "manifestSha256": supply["manifestSha256"],
                        "pythonPackages": expected,
                        "requirementsSha256": supply["requirementsSha256"],
                        "wheelSha256": "0" * 64,
                        "wheelUrl": self.installer.HERMES_WHEEL_URL,
                    }
                )
            )
            with (
                mock.patch.object(
                    self.installer, "validate_supply_chain_assets", return_value=supply
                ),
                mock.patch.object(
                    self.installer,
                    "python_distribution_versions",
                    return_value=expected,
                ),
                mock.patch.object(self.installer, "SUPPLY_CHAIN_RECEIPT", receipt),
                mock.patch.object(
                    self.installer,
                    "command",
                    return_value=mock.Mock(returncode=0, stdout="", stderr=""),
                ),
            ):
                with self.assertRaisesRegex(
                    self.installer.HermesInstallError, "receipt drifted"
                ):
                    self.installer.venv_supply_chain_evidence()

    def test_apt_package_pins_are_complete_exact_and_used_verbatim(self):
        expected = {
            "ca-certificates": "20260601~24.04.1",
            "curl": "8.5.0-2ubuntu10.11",
            "ffmpeg": "7:6.1.1-3ubuntu5",
            "python3": "3.12.3-0ubuntu2.1",
            "python3-venv": "3.12.3-0ubuntu2.1",
            "ripgrep": "14.1.0-1",
            "sudo": "1.9.15p5-3ubuntu5.24.04.2",
        }
        raw = ",".join(f"{name}={version}" for name, version in expected.items())
        self.assertEqual(
            self.installer.parse_pinned_apt_packages({"HERMES_APT_PACKAGES": raw}),
            expected,
        )
        with self.assertRaises(self.installer.HermesInstallError):
            self.installer.parse_pinned_apt_packages(
                {"HERMES_APT_PACKAGES": raw.replace("curl=", "curl>=")}
            )

        env = Path("/unit/platform.env")
        with (
            mock.patch.object(
                self.installer,
                "parse_dotenv",
                return_value={"HERMES_OPERATOR_MODE": "unprivileged_service"},
            ),
            mock.patch.object(
                self.installer, "parse_pinned_apt_packages", return_value=expected
            ),
            mock.patch.object(
                self.installer,
                "installed_apt_versions",
                side_effect=({}, expected),
            ),
            mock.patch.object(
                self.installer.shutil, "which", return_value="/bin/unit"
            ) as which,
            mock.patch.object(self.installer, "command") as command,
        ):
            self.assertEqual(self.installer.ensure_packages(env), expected)
        install = next(
            call.args[0]
            for call in command.call_args_list
            if call.args[0][:2] == ["apt-get", "install"]
        )
        self.assertTrue(
            {f"{name}={version}" for name, version in expected.items()} <= set(install)
        )
        self.assertNotIn("curl", install)
        checked_binaries = {
            call.args[0]
            for call in which.call_args_list
        }
        self.assertEqual(
            checked_binaries,
            {
                "apt-get",
                "curl",
                "ffmpeg",
                "openssl",
                "python3",
                "rg",
                "sudo",
                "visudo",
            },
        )

    def test_locked_artifacts_are_private_and_verified_without_test_network(self):
        wheel_bytes = b"unit hermes wheel"
        wheel_hash = hashlib.sha256(wheel_bytes).hexdigest()
        fixture_bytes = {
            self.installer.HERMES_WHEEL_URL: wheel_bytes,
            self.installer.HERMES_PYPI_PROVENANCE_URL: b'{"version":1}',
            self.installer.HERMES_SIGSTORE_BUNDLE_URL: b'{"mediaType":"unit"}',
        }

        def fixture_download(url, destination, *, limit):
            self.assertGreater(limit, len(fixture_bytes[url]))
            descriptor = os.open(
                destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(descriptor, "wb") as output:
                output.write(fixture_bytes[url])

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "supply-chain"
            workspace.mkdir()
            with (
                mock.patch.object(
                    self.installer,
                    "HERMES_WHEEL_SHA256",
                    wheel_hash,
                ),
                mock.patch.object(
                    self.installer,
                    "download_private_artifact",
                    side_effect=fixture_download,
                ) as download,
                mock.patch.object(self.installer, "verify_sigstore_bundle") as sigstore,
                mock.patch.object(self.installer, "verify_pypi_provenance") as pypi,
            ):
                wheel = self.installer.fetch_and_verify_hermes_artifacts(
                    {"wheelSize": len(wheel_bytes)},
                    workspace,
                    {
                        "HERMES_SIGSTORE_VERIFIER_IMAGE": "node:22-bookworm@sha256:"
                        + "0" * 64,
                        "HERMES_SIGSTORE_PACKAGE_VERSION": "3.0.0",
                    },
                )

            self.assertEqual(wheel.read_bytes(), wheel_bytes)
            self.assertEqual(download.call_count, 3)
            self.assertEqual(
                [call.args[0] for call in download.call_args_list],
                [
                    self.installer.HERMES_WHEEL_URL,
                    self.installer.HERMES_PYPI_PROVENANCE_URL,
                    self.installer.HERMES_SIGSTORE_BUNDLE_URL,
                ],
            )
            self.assertTrue(
                all(
                    stat.S_IMODE(path.stat().st_mode) == 0o600
                    for path in workspace.iterdir()
                )
            )
            sigstore.assert_called_once()
            pypi.assert_called_once()

    def test_offline_provenance_contract_binds_digest_signatures_and_identity(self):
        wheel_bytes = b"unit signed wheel"
        wheel_hash = hashlib.sha256(wheel_bytes).hexdigest()
        statement = json.dumps(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {
                        "name": self.installer.HERMES_WHEEL_FILENAME,
                        "digest": {"sha256": wheel_hash},
                    }
                ],
                "predicateType": self.installer.PYPI_PUBLISH_ATTESTATION_TYPE,
                "predicate": None,
            },
            separators=(",", ":"),
        ).encode()
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            wheel = workspace / self.installer.HERMES_WHEEL_FILENAME
            wheel.write_bytes(wheel_bytes)
            sigstore = workspace / "wheel.sigstore.json"
            sigstore.write_text(
                json.dumps(
                    {
                        "mediaType": self.installer.SIGSTORE_BUNDLE_MEDIA_TYPE,
                        "verificationMaterial": {
                            "certificate": {"rawBytes": base64.b64encode(b"cert").decode()},
                            "tlogEntries": [{"logIndex": "1"}],
                        },
                        "messageSignature": {
                            "messageDigest": {
                                "algorithm": "SHA2_256",
                                "digest": base64.b64encode(
                                    bytes.fromhex(wheel_hash)
                                ).decode(),
                            },
                            "signature": base64.b64encode(b"signature").decode(),
                        },
                    }
                )
            )
            provenance = workspace / "provenance.json"
            provenance.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "attestation_bundles": [
                            {
                                "publisher": {
                                    "kind": "GitHub",
                                    "repository": self.installer.HERMES_SIGNER_REPOSITORY,
                                    "workflow": "release.yml",
                                },
                                "attestations": [
                                    {
                                        "version": 1,
                                        "envelope": {
                                            "statement": base64.b64encode(
                                                statement
                                            ).decode(),
                                            "signature": base64.b64encode(
                                                b"attestation"
                                            ).decode(),
                                        },
                                        "verification_material": {
                                            "certificate": base64.b64encode(
                                                b"pypi-cert"
                                            ).decode(),
                                            "transparency_entries": [
                                                {"logIndex": "2"}
                                            ],
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                )
            )
            bundle_hash = hashlib.sha256(sigstore.read_bytes()).hexdigest()
            with (
                mock.patch.object(
                    self.installer, "HERMES_WHEEL_SHA256", wheel_hash
                ),
                mock.patch.object(
                    self.installer,
                    "HERMES_SIGSTORE_BUNDLE_SHA256",
                    bundle_hash,
                ),
                mock.patch.object(self.installer, "run_sigstore_verifier") as verify,
            ):
                self.installer.verify_sigstore_bundle(
                    wheel,
                    sigstore,
                    workspace,
                    {
                        "HERMES_SIGSTORE_VERIFIER_IMAGE": "node:22-bookworm@sha256:"
                        + "0" * 64,
                        "HERMES_SIGSTORE_PACKAGE_VERSION": "3.0.0",
                    },
                )
                self.installer.verify_pypi_provenance(
                    wheel, provenance, workspace
                )

            verify.assert_called_once_with(
                wheel,
                sigstore,
                workspace,
                {
                    "HERMES_SIGSTORE_VERIFIER_IMAGE": "node:22-bookworm@sha256:"
                    + "0" * 64,
                    "HERMES_SIGSTORE_PACKAGE_VERSION": "3.0.0",
                },
            )

    def test_sigstore_verifier_enforces_fulcio_rekor_and_exact_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            wheel = workspace / self.installer.HERMES_WHEEL_FILENAME
            bundle = workspace / "wheel.sigstore.json"
            wheel.write_bytes(b"wheel")
            bundle.write_text("{}")
            completed = mock.Mock(returncode=0, stdout="", stderr="")
            with (
                mock.patch.object(self.installer.shutil, "which", return_value="/docker"),
                mock.patch.object(
                    self.installer, "command", return_value=completed
                ) as command,
            ):
                self.installer.run_sigstore_verifier(
                    wheel,
                    bundle,
                    workspace,
                    {
                        "HERMES_SIGSTORE_VERIFIER_IMAGE": "node:22-bookworm@sha256:"
                        + "0" * 64,
                        "HERMES_SIGSTORE_PACKAGE_VERSION": "3.0.0",
                    },
                )

        argv = command.call_args.args[0]
        self.assertIn("node:22-bookworm@sha256:" + "0" * 64, argv)
        self.assertIn(self.installer.HERMES_SIGNER_IDENTITY, argv)
        self.assertIn(self.installer.HERMES_SIGNER_ISSUER, argv)
        self.assertIn("3.0.0", argv)
        self.assertIn("ctLogThreshold: 1", self.installer.SIGSTORE_VERIFY_PROGRAM)
        self.assertIn("tlogThreshold: 1", self.installer.SIGSTORE_VERIFY_PROGRAM)

    def test_sigstore_rejects_self_signed_opaque_tlog_and_wrong_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            wheel = workspace / self.installer.HERMES_WHEEL_FILENAME
            bundle = workspace / "wheel.sigstore.json"
            wheel.write_bytes(b"wheel")
            bundle.write_text("{}")
            for failure in (
                "self-signed certificate",
                "opaque transparency entry",
                "wrong workflow identity",
            ):
                with self.subTest(failure=failure), mock.patch.object(
                    self.installer.shutil, "which", return_value="/docker"
                ), mock.patch.object(
                    self.installer,
                    "command",
                    return_value=mock.Mock(
                        returncode=1, stdout="", stderr=failure
                    ),
                ):
                    with self.assertRaisesRegex(
                        self.installer.HermesInstallError,
                        "Sigstore verification failed",
                    ):
                        self.installer.run_sigstore_verifier(
                            wheel,
                            bundle,
                            workspace,
                            {
                                "HERMES_SIGSTORE_VERIFIER_IMAGE": "node:22-bookworm@sha256:"
                                + "0" * 64,
                                "HERMES_SIGSTORE_PACKAGE_VERSION": "3.0.0",
                            },
                        )

    def test_install_uses_verified_local_wheel_under_hash_locked_binary_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            venv = release / "venv"
            requirements = root / "requirements.lock"
            requirements.write_text(
                "dependency==1 --hash=sha256:" + "1" * 64 + "\n"
                f"hermes-agent[messaging,mcp]=={self.installer.VERSION} "
                f"--hash=sha256:{self.installer.HERMES_WHEEL_SHA256}\n"
            )
            observed_requirements = []

            def fetch(_supply, workspace, _values):
                wheel = workspace / self.installer.HERMES_WHEEL_FILENAME
                wheel.write_bytes(b"verified wheel")
                wheel.chmod(0o600)
                return wheel

            def command(argv, **_kwargs):
                if argv[:4] == [str(venv / "bin/python"), "-m", "pip", "install"]:
                    lock_path = Path(argv[argv.index("-r") + 1])
                    observed_requirements.append(lock_path.read_text())
                    self.assertIn("--require-hashes", argv)
                    self.assertIn("--only-binary=:all:", argv)
                return mock.Mock(returncode=0, stdout="", stderr="")

            supply = {
                "requirementsPath": requirements,
                "pythonPackages": {"hermes-agent": self.installer.VERSION},
            }
            with (
                mock.patch.object(self.installer, "RELEASE", release),
                mock.patch.object(self.installer, "VENV", venv),
                mock.patch.object(self.installer, "LEGACY_SOURCE", release / "source"),
                mock.patch.object(
                    self.installer, "validate_supply_chain_assets", return_value=supply
                ),
                mock.patch.object(
                    self.installer,
                    "venv_supply_chain_evidence",
                    side_effect=(self.installer.HermesInstallError("missing"), {}),
                ),
                mock.patch.object(
                    self.installer,
                    "installed_version",
                    side_effect=(None, self.installer.VERSION),
                ),
                mock.patch.object(
                    self.installer,
                    "fetch_and_verify_hermes_artifacts",
                    side_effect=fetch,
                ),
                mock.patch.object(self.installer, "write_supply_chain_receipt"),
                mock.patch.object(self.installer, "command", side_effect=command),
            ):
                self.installer.install_venv(
                    {
                        "HERMES_SIGSTORE_VERIFIER_IMAGE": "node:22-bookworm@sha256:"
                        + "0" * 64,
                        "HERMES_SIGSTORE_PACKAGE_VERSION": "3.0.0",
                    }
                )

            self.assertEqual(len(observed_requirements), 1)
            self.assertIn(
                "hermes-agent[messaging,mcp] @ file://", observed_requirements[0]
            )
            self.assertNotIn(
                f"hermes-agent[messaging,mcp]=={self.installer.VERSION}",
                observed_requirements[0],
            )

    def test_wheel_install_removes_legacy_source_checkout_when_already_current(self):
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release"
            legacy_source = release / "source"
            legacy_source.mkdir(parents=True)
            (legacy_source / ".git").mkdir()
            supply = {"pythonPackages": {"hermes-agent": self.installer.VERSION}}
            with (
                mock.patch.object(self.installer, "RELEASE", release),
                mock.patch.object(self.installer, "LEGACY_SOURCE", legacy_source),
                mock.patch.object(
                    self.installer, "validate_supply_chain_assets", return_value=supply
                ),
                mock.patch.object(
                    self.installer,
                    "venv_supply_chain_evidence",
                    return_value={"packageCount": 1},
                ),
                mock.patch.object(
                    self.installer,
                    "installed_version",
                    return_value=self.installer.VERSION,
                ),
                mock.patch.object(self.installer, "command") as command,
            ):
                self.installer.install_venv(
                    {
                        "HERMES_SIGSTORE_VERIFIER_IMAGE": "node:22-bookworm@sha256:"
                        + "0" * 64,
                        "HERMES_SIGSTORE_PACKAGE_VERSION": "3.0.0",
                    }
                )

            self.assertFalse(legacy_source.exists())
            command.assert_not_called()

    def test_hermes_has_no_runtime_projection_writer(self):
        verifier = load(
            "test_hermes_projection_writer_audit",
            "tools/platform-cli/server-verify.py",
        )
        findings = [
            row
            for row in verifier.configuration_writer_findings(ROOT)
            if row.get("path") == "tools/platform-cli/server-hermes.py"
        ]
        self.assertEqual(findings, [])
        self.assertFalse(
            hasattr(self.installer, "render_runtime_credential_projection")
        )
        self.assertEqual(
            self.installer.HERMES_RUNTIME_ENV_FILE,
            Path("/root/.config/mte-secrets/services/hermes.env"),
        )

    def test_dependency_health_endpoints_use_exact_canonical_loopback_routes(self):
        values = {
            "HERMES_PAPERCLIP_URL": "http://127.0.0.1:3100/api",
            "HERMES_KESTRA_URL": "http://127.0.0.1:18082",
            "KESTRA_HEALTH_URL": "http://127.0.0.1:18081/health",
        }
        self.assertEqual(
            self.installer.dependency_health_endpoints(values),
            {
                "paperclipApi": "http://127.0.0.1:3100/api/health",
                "kestraApi": "http://127.0.0.1:18081/health",
            },
        )

        mutations = (
            ("HERMES_PAPERCLIP_URL", "http://127.0.0.1:3100/api/health"),
            ("HERMES_KESTRA_URL", "http://127.0.0.1:18082/health"),
            ("KESTRA_HEALTH_URL", "http://kestra:8081/health"),
            ("KESTRA_HEALTH_URL", "https://127.0.0.1:18081/health"),
            ("KESTRA_HEALTH_URL", "http://127.0.0.1:18081/api/v1/health"),
        )
        for name, value in mutations:
            with self.subTest(name=name, value=value):
                mutated = {**values, name: value}
                with self.assertRaises(self.installer.HermesInstallError):
                    self.installer.dependency_health_endpoints(mutated)

    def test_external_readiness_probes_paperclip_and_kestra_health_exactly_once(self):
        values = {
            "HERMES_API_SERVER_HOST": "127.0.0.1",
            "HERMES_API_SERVER_PORT": "8642",
            "HERMES_API_SERVER_KEY": "unit-hermes-api-key",
            "HERMES_PAPERCLIP_URL": "http://127.0.0.1:3100/api",
            "HERMES_PAPERCLIP_API_KEY": "unit-paperclip-key",
            "HERMES_KESTRA_URL": "http://127.0.0.1:18082",
            "KESTRA_HEALTH_URL": "http://127.0.0.1:18081/health",
            "HERMES_LLM_BASE_URL": "http://127.0.0.1:20128/v1",
            "HERMES_LLM_API_KEY": "unit-llm-key",
            "HERMES_LLM_MODEL": "unit-model",
        }

        def response(url, **_kwargs):
            if url.endswith("/models"):
                return {"data": [{"id": "unit-model"}]}
            if url.endswith("/chat/completions"):
                return {"choices": [{"message": {"content": "OK"}}]}
            return {"status": "UP"}

        with (
            mock.patch.object(self.installer, "parse_dotenv", return_value=values),
            mock.patch.object(
                self.installer, "hermes_api_server_ready", return_value=True
            ),
            mock.patch.object(
                self.installer, "json_request", side_effect=response
            ) as request,
        ):
            checks, _states = self.installer.external_readiness(Path("/unit.env"))

        requested_urls = [call.args[0] for call in request.call_args_list]
        self.assertTrue(checks["paperclipApi"])
        self.assertTrue(checks["kestraApi"])
        self.assertEqual(requested_urls.count("http://127.0.0.1:3100/api/health"), 1)
        self.assertEqual(requested_urls.count("http://127.0.0.1:18081/health"), 1)
        self.assertNotIn("http://127.0.0.1:18082/health", requested_urls)
        self.assertNotIn("http://127.0.0.1:3100/api/api/health", requested_urls)

    def test_context7_native_config_is_anonymous_by_default_and_never_embeds_key(self):
        anonymous = yaml.safe_load(self.installer.render_context7_mcp_config({}))
        self.assertEqual(
            anonymous,
            {
                "mcp_servers": {
                    "context7": {
                        "url": "https://mcp.context7.com/mcp",
                        "tools": {
                            "include": ["resolve-library-id", "query-docs"],
                            "resources": False,
                            "prompts": False,
                        },
                    }
                }
            },
        )
        keyed = self.installer.render_context7_mcp_config(
            {"CONTEXT7_API_KEY": "unit-context7-secret"}
        )
        self.assertIn('Authorization: "Bearer ${CONTEXT7_API_KEY}"', keyed)
        self.assertNotIn("unit-context7-secret", keyed)
        self.assertIn("CONTEXT7_API_KEY", self.installer.HERMES_RUNTIME_KEYS)

        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            config = state / ".hermes/config.yaml"
            config.parent.mkdir(parents=True)
            config.write_text(keyed + "\n")
            with mock.patch.object(self.installer, "STATE_ROOT", state):
                self.assertTrue(
                    self.installer.context7_mcp_config_ready(
                        {"CONTEXT7_API_KEY": "unit-context7-secret"}
                    )
                )
                config.write_text(keyed + "\n# unit-context7-secret\n")
                self.assertFalse(
                    self.installer.context7_mcp_config_ready(
                        {"CONTEXT7_API_KEY": "unit-context7-secret"}
                    )
                )

    def test_native_config_renders_context7_reference_as_valid_yaml(self):
        values = {
            "HERMES_LLM_MODEL": "unit-model",
            "HERMES_LLM_PROVIDER": "custom:mte9router",
            "HERMES_LLM_BASE_URL": "http://127.0.0.1:20128/v1",
            "HERMES_LLM_API_MODE": "chat_completions",
            "HERMES_TERMINAL_BACKEND": "local",
            "HERMES_TERMINAL_CWD": "/opt/mte-platform",
            "HERMES_TERMINAL_TIMEOUT": "600",
            "HERMES_TERMINAL_LIFETIME_SECONDS": "1800",
            "HERMES_TERMINAL_HOME_MODE": "real",
            "HERMES_APPROVALS_MODE": "manual",
            "HERMES_APPROVALS_TIMEOUT": "600",
            "HERMES_APPROVALS_CRON_MODE": "deny",
            "HERMES_APPROVALS_MCP_RELOAD_CONFIRM": "true",
            "HERMES_APPROVALS_DESTRUCTIVE_SLASH_CONFIRM": "true",
            "HERMES_GATEWAY_STREAMING_ENABLED": "true",
            "HERMES_GATEWAY_STREAMING_TRANSPORT": "edit",
            "HERMES_TELEGRAM_REQUIRE_MENTION": "true",
            "HERMES_TELEGRAM_EXCLUSIVE_BOT_MENTIONS": "true",
            "HERMES_TELEGRAM_GUEST_MODE": "false",
            "HERMES_DISPLAY_TOOL_PROGRESS": "new",
            "HERMES_TELEGRAM_NOTIFICATIONS": "important",
            "CONTEXT7_API_KEY": "unit-context7-secret",
        }
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            (state / ".hermes").mkdir(parents=True)
            account = mock.Mock(pw_uid=os.getuid(), pw_gid=os.getgid())
            with (
                mock.patch.object(self.installer, "STATE_ROOT", state),
                mock.patch.object(
                    self.installer,
                    "hermes_asset_paths",
                    return_value={
                        "configTemplate": ROOT
                        / "deployment/services/hermes/config.yaml.template",
                        "soul": ROOT / "deployment/services/hermes/soul.txt",
                    },
                ),
                mock.patch.object(self.installer.pwd, "getpwnam", return_value=account),
                mock.patch.object(self.installer.os, "chown"),
            ):
                evidence = self.installer.render_native_config(values)

            config_path = state / ".hermes/config.yaml"
            config = yaml.safe_load(config_path.read_text())
            self.assertEqual(config["model"]["provider"], "custom:mte9router")
            self.assertEqual(
                config["custom_providers"],
                [
                    {
                        "name": "mte9router",
                        "base_url": "http://127.0.0.1:20128/v1",
                        "key_env": "OPENAI_API_KEY",
                        "api_mode": "chat_completions",
                    }
                ],
            )
            self.assertEqual(
                config["mcp_servers"]["context7"],
                {
                    "url": "https://mcp.context7.com/mcp",
                    "tools": {
                        "include": ["resolve-library-id", "query-docs"],
                        "resources": False,
                        "prompts": False,
                    },
                    "headers": {"Authorization": "Bearer ${CONTEXT7_API_KEY}"},
                },
            )
            self.assertNotIn("unit-context7-secret", config_path.read_text())
            self.assertEqual(stat.S_IMODE(config_path.stat().st_mode), 0o600)
            self.assertRegex(evidence["configSha256"], r"^[0-9a-f]{64}$")

    def test_native_config_scopes_mattermost_to_the_bootstrapped_home_channel(self):
        values = {
            "HERMES_LLM_MODEL": "unit-model",
            "HERMES_LLM_PROVIDER": "custom:mte9router",
            "HERMES_LLM_BASE_URL": "http://127.0.0.1:20128/v1",
            "HERMES_LLM_API_MODE": "chat_completions",
            "HERMES_TERMINAL_BACKEND": "local",
            "HERMES_TERMINAL_CWD": "/opt/mte-platform",
            "HERMES_TERMINAL_TIMEOUT": "600",
            "HERMES_TERMINAL_LIFETIME_SECONDS": "1800",
            "HERMES_TERMINAL_HOME_MODE": "real",
            "HERMES_APPROVALS_MODE": "manual",
            "HERMES_APPROVALS_TIMEOUT": "600",
            "HERMES_APPROVALS_CRON_MODE": "deny",
            "HERMES_APPROVALS_MCP_RELOAD_CONFIRM": "true",
            "HERMES_APPROVALS_DESTRUCTIVE_SLASH_CONFIRM": "true",
            "HERMES_GATEWAY_STREAMING_ENABLED": "true",
            "HERMES_GATEWAY_STREAMING_TRANSPORT": "edit",
            "HERMES_TELEGRAM_REQUIRE_MENTION": "true",
            "HERMES_TELEGRAM_EXCLUSIVE_BOT_MENTIONS": "true",
            "HERMES_TELEGRAM_GUEST_MODE": "false",
            "HERMES_DISPLAY_TOOL_PROGRESS": "new",
            "HERMES_TELEGRAM_NOTIFICATIONS": "important",
            "MATTERMOST_URL": "http://127.0.0.1:48065",
            "MATTERMOST_HOME_CHANNEL": "a" * 26,
        }
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            (state / ".hermes").mkdir(parents=True)
            account = mock.Mock(pw_uid=os.getuid(), pw_gid=os.getgid())
            with (
                mock.patch.object(self.installer, "STATE_ROOT", state),
                mock.patch.object(
                    self.installer,
                    "hermes_asset_paths",
                    return_value={
                        "configTemplate": ROOT
                        / "deployment/services/hermes/config.yaml.template",
                        "soul": ROOT / "deployment/services/hermes/soul.txt",
                    },
                ),
                mock.patch.object(self.installer.pwd, "getpwnam", return_value=account),
                mock.patch.object(self.installer.os, "chown"),
            ):
                self.installer.render_native_config(values)
                config = yaml.safe_load((state / ".hermes/config.yaml").read_text())
                self.assertEqual(
                    config["mattermost"]["allowed_channels"], ["a" * 26]
                )
                self.assertTrue(self.installer.mattermost_native_config_ready(values))

    def test_mattermost_config_is_omitted_when_native_messaging_is_disabled(self):
        self.assertEqual(self.installer.render_mattermost_native_config({}), "")

    def test_context7_http_auth_uses_bearer_header_only(self):
        response = mock.MagicMock()
        response.status = 200
        response.headers = {"MCP-Session-ID": "unit-session"}
        response.read.return_value = (
            b'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n'
        )
        response.__enter__.return_value = response
        with mock.patch.object(
            self.installer.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            message, session_id = self.installer.context7_mcp_request(
                "initialize",
                {},
                request_id=1,
                session_id=None,
                api_key="unit-context7-secret",
            )

        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.get_header("Authorization"),
            "Bearer unit-context7-secret",
        )
        self.assertIsNone(request.get_header("CONTEXT7_API_KEY"))
        self.assertNotIn(b"unit-context7-secret", request.data)
        self.assertEqual(message, {"jsonrpc": "2.0", "id": 1, "result": {}})
        self.assertEqual(session_id, "unit-session")

    def test_context7_endpoint_and_protocol_are_declared_immutable(self):
        verifier = load(
            "test_hermes_context7_config_source", "tools/platform-cli/server-verify.py"
        )
        self.assertTrue(
            {
                "CONTEXT7_MCP_PROTOCOL_VERSION",
                "CONTEXT7_MCP_URL",
            }
            <= verifier.IMMUTABLE_GLOBAL_CONSTANTS[
                "tools/platform-cli/server-hermes.py"
            ]
        )

    def test_context7_readiness_discovers_required_surface_and_runs_resolve_query(self):
        calls = [
            ({"result": {"protocolVersion": "2025-03-26"}}, "unit-session"),
            ({}, "unit-session"),
            (
                {
                    "result": {
                        "tools": [
                            {"name": "resolve-library-id"},
                            {"name": "query-docs"},
                        ]
                    }
                },
                "unit-session",
            ),
            (
                {
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": "Context7-compatible library ID: /upstash/context7",
                            }
                        ]
                    }
                },
                "unit-session",
            ),
            (
                {"result": {"content": [{"type": "text", "text": "Current docs"}]}},
                "unit-session",
            ),
        ]
        with (
            mock.patch.object(
                self.installer, "context7_mcp_request", side_effect=calls
            ) as request,
            mock.patch.object(self.installer, "close_context7_mcp_session") as close,
        ):
            checks, states = self.installer.context7_readiness(
                {"CONTEXT7_API_KEY": "unit-context7-secret"}
            )

        self.assertEqual(
            checks,
            {"context7Discovery": True, "context7Query": True},
        )
        self.assertEqual(states["context7AuthMode"], "api-key")
        self.assertNotIn("unit-context7-secret", json.dumps(states))
        self.assertEqual(
            [call.args[0] for call in request.call_args_list],
            [
                "initialize",
                "notifications/initialized",
                "tools/list",
                "tools/call",
                "tools/call",
            ],
        )
        self.assertEqual(
            request.call_args_list[3].args[1]["name"], "resolve-library-id"
        )
        self.assertEqual(request.call_args_list[4].args[1]["name"], "query-docs")
        close.assert_called_once_with("unit-session", api_key="unit-context7-secret")

    def test_ordinary_status_checks_config_without_live_context7_request(self):
        account = mock.Mock(pw_dir=str(self.installer.STATE_ROOT))
        service = mock.Mock(stdout="active\n")
        with (
            mock.patch.object(self.installer.pwd, "getpwnam", return_value=account),
            mock.patch.object(self.installer, "validate_env_file", return_value={}),
            mock.patch.object(
                self.installer,
                "parse_dotenv",
                return_value={"HERMES_OPERATOR_MODE": "unprivileged_service"},
            ),
            mock.patch.object(self.installer, "systemctl", return_value=service),
            mock.patch.object(
                self.installer, "installed_version", return_value=self.installer.VERSION
            ),
            mock.patch.object(self.installer, "sudoers_valid", return_value=True),
            mock.patch.object(
                self.installer, "operator_mode_ready", return_value=True
            ),
            mock.patch.object(
                self.installer, "native_runtime_files_ready", return_value=True
            ),
            mock.patch.object(
                self.installer,
                "runtime_credential_projection_matches",
                return_value=True,
            ),
            mock.patch.object(
                self.installer,
                "platform_skill_status",
                return_value={"ready": True},
            ),
            mock.patch.object(
                self.installer,
                "venv_supply_chain_evidence",
                return_value={"packageCount": 81},
            ),
            mock.patch.object(
                self.installer,
                "parse_pinned_apt_packages",
                return_value={"curl": "unit"},
            ),
            mock.patch.object(
                self.installer,
                "installed_apt_versions",
                return_value={"curl": "unit"},
            ),
            mock.patch.object(
                self.installer, "context7_mcp_config_ready", return_value=True
            ),
            mock.patch.object(
                self.installer,
                "context7_readiness",
                side_effect=AssertionError("ordinary status must stay offline"),
            ),
        ):
            status = self.installer.status_payload(Path("/unit/platform.env"))

        self.assertTrue(status["checks"]["context7McpConfig"])
        self.assertNotIn("context7Discovery", status["checks"])
        self.assertEqual(
            status["externalReadiness"]["context7Discovery"], "not-requested"
        )

    def test_platform_skill_install_replaces_full_tree_and_removes_legacy_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source/system-platform"
            for relative, content in {
                "SKILL.md": "---\nname: system-platform\ndescription: unit\n---\n",
                "agents/openai.yaml": "interface: {}\n",
                "assets/architecture.html": "<html>unit</html>\n",
                "references/operations.md": "# Operations\n",
                "references/security.md": "# Security\n",
            }.items():
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            state = root / "state"
            legacy = state / ".hermes/skills/mte-platform"
            legacy.mkdir(parents=True)
            (legacy / "SKILL.md").write_text("legacy\n")
            account = mock.Mock(pw_uid=os.getuid(), pw_gid=os.getgid())
            with (
                mock.patch.object(
                    self.installer,
                    "hermes_asset_paths",
                    return_value={"platformSkill": source},
                ),
                mock.patch.object(self.installer, "STATE_ROOT", state),
                mock.patch.object(self.installer.pwd, "getpwnam", return_value=account),
                mock.patch.object(self.installer.os, "chown"),
            ):
                installed = self.installer.install_platform_skill()
                skill_status = self.installer.platform_skill_status()

            destination = state / ".hermes/skills/system-platform"
            self.assertFalse(legacy.exists())
            self.assertEqual(
                {
                    path.relative_to(destination).as_posix()
                    for path in destination.rglob("*")
                    if path.is_file()
                },
                {
                    path.relative_to(source).as_posix()
                    for path in source.rglob("*")
                    if path.is_file()
                },
            )
            self.assertEqual(
                installed["treeSha256"],
                self.installer.skill_tree_evidence(source)["treeSha256"],
            )
            self.assertTrue(skill_status["ready"])
            self.assertTrue(skill_status["hashesMatch"])
            self.assertTrue(skill_status["legacySkillAbsent"])

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

    def test_atomic_secret_write_is_private_before_content_and_ignores_legacy_tmp(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "rendered-secret.env"
            legacy_temporary = destination.with_name(destination.name + ".tmp")
            legacy_temporary.write_text("attacker-controlled\n")
            observed: list[tuple[int, int]] = []
            real_fchmod = os.fchmod

            def record_mode_before_write(descriptor: int, mode: int) -> None:
                observed.append((mode, os.fstat(descriptor).st_size))
                real_fchmod(descriptor, mode)

            with (
                mock.patch.object(
                    self.installer.os, "fchmod", side_effect=record_mode_before_write
                ),
                mock.patch.object(
                    self.installer.tempfile, "mkstemp", wraps=tempfile.mkstemp
                ) as create_temporary,
            ):
                self.installer.atomic_write_text(
                    destination, "HERMES_TOKEN=secret-reference\n", mode=0o600
                )

            self.assertEqual(
                destination.read_text(), "HERMES_TOKEN=secret-reference\n"
            )
            self.assertEqual(legacy_temporary.read_text(), "attacker-controlled\n")
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertEqual(observed, [(0o600, 0)])
            self.assertEqual(
                create_temporary.call_args.kwargs,
                {
                    "prefix": ".rendered-secret.env.",
                    "suffix": ".new",
                    "dir": str(root),
                },
            )

    def test_atomic_secret_write_rejects_symlink_destination_and_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside.env"
            outside.write_text("preserved\n")

            destination = root / "rendered-secret.env"
            destination.symlink_to(outside)
            with self.assertRaisesRegex(
                self.installer.HermesInstallError, "unsafe atomic-write path"
            ):
                self.installer.atomic_write_text(destination, "secret\n", mode=0o600)
            self.assertEqual(outside.read_text(), "preserved\n")

            destination.unlink()
            linked_parent = root / "linked"
            linked_parent.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(
                self.installer.HermesInstallError,
                "unsafe atomic-write path",
            ):
                self.installer.atomic_write_text(
                    linked_parent / "secret.env", "secret\n", mode=0o600
                )
            self.assertFalse((root / "secret.env").exists())

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

    def test_public_install_revokes_stale_admin_policy_before_package_work(self):
        args = mock.Mock(
            env_file=self.installer.DEFAULT_ENV_FILE,
            grant_platform_admin=False,
            no_start=True,
        )
        with (
            mock.patch.object(self.installer, "require_root"),
            mock.patch.object(self.installer, "bootstrap_mattermost"),
            mock.patch.object(
                self.installer,
                "reconcile_platform_projections",
                return_value={"sourceSha256": "a" * 64},
            ),
            mock.patch.object(
                self.installer,
                "validate_env_file",
                return_value={"operatorMode": "unprivileged_service"},
            ),
            mock.patch.object(
                self.installer, "source_hash", return_value="a" * 64
            ),
            mock.patch.object(self.installer, "reconcile_admin_policy") as policy,
            mock.patch.object(
                self.installer,
                "ensure_packages",
                side_effect=self.installer.HermesInstallError("package failure"),
            ),
        ):
            with self.assertRaisesRegex(
                self.installer.HermesInstallError, "package failure"
            ):
                self.installer.install(args)

        policy.assert_called_once_with(False)

    def test_public_install_revokes_stale_admin_before_validation_failure(self):
        args = mock.Mock(
            env_file=self.installer.DEFAULT_ENV_FILE,
            grant_platform_admin=False,
            no_start=True,
        )
        ordering = []

        def invalid(_env_file):
            ordering.append(("validate", None))
            raise self.installer.HermesInstallError("invalid env")

        with (
            mock.patch.object(self.installer, "require_root"),
            mock.patch.object(
                self.installer,
                "reconcile_admin_policy",
                side_effect=lambda enabled: ordering.append(("revoke", enabled)),
            ),
            mock.patch.object(
                self.installer,
                "bootstrap_mattermost",
                side_effect=lambda: ordering.append(("bootstrap", None)),
            ),
            mock.patch.object(
                self.installer,
                "reconcile_platform_projections",
                return_value={"sourceSha256": "a" * 64},
            ),
            mock.patch.object(
                self.installer,
                "validate_env_file",
                side_effect=invalid,
            ),
        ):
            with self.assertRaisesRegex(
                self.installer.HermesInstallError, "invalid env"
            ):
                self.installer.install(args)

        self.assertEqual(
            ordering,
            [("revoke", False), ("bootstrap", None), ("validate", None)],
        )

    def test_public_reconcile_revokes_stale_admin_before_any_renderer_failure(self):
        args = mock.Mock(env_file=self.installer.DEFAULT_ENV_FILE, no_restart=True)
        ordering = []

        def revoke(enabled):
            self.assertFalse(enabled)
            ordering.append("revoke")

        def fail_projection(_env_file):
            ordering.append("render")
            raise self.installer.HermesInstallError("render failed")

        with (
            mock.patch.object(self.installer, "require_root"),
            mock.patch.object(
                self.installer,
                "validate_env_file",
                return_value={"operatorMode": "unprivileged_service"},
            ) as validate,
            mock.patch.object(
                self.installer, "reconcile_admin_policy", side_effect=revoke
            ) as policy,
            mock.patch.object(
                self.installer,
                "reconcile_platform_projections",
                side_effect=fail_projection,
            ) as render,
            mock.patch.object(self.installer, "render_native_config") as native,
            mock.patch.object(self.installer, "install_platform_skill") as skill,
        ):
            with self.assertRaisesRegex(
                self.installer.HermesInstallError, "render failed"
            ):
                self.installer.reconcile(args)

        validate.assert_called_once_with(self.installer.DEFAULT_ENV_FILE)
        policy.assert_called_once_with(False)
        render.assert_called_once_with(self.installer.DEFAULT_ENV_FILE)
        self.assertEqual(ordering, ["revoke", "render"])
        native.assert_not_called()
        skill.assert_not_called()

    def test_public_reconcile_revokes_stale_admin_before_validation_failure(self):
        args = mock.Mock(env_file=self.installer.DEFAULT_ENV_FILE, no_restart=True)
        ordering = []

        def revoke(enabled):
            ordering.append(("revoke", enabled))

        def invalid(_env_file):
            ordering.append(("validate", None))
            raise self.installer.HermesInstallError("invalid env")

        with (
            mock.patch.object(self.installer, "require_root"),
            mock.patch.object(
                self.installer, "public_mode_requested", return_value=True
            ),
            mock.patch.object(
                self.installer, "reconcile_admin_policy", side_effect=revoke
            ),
            mock.patch.object(
                self.installer, "validate_env_file", side_effect=invalid
            ),
            mock.patch.object(
                self.installer, "reconcile_platform_projections"
            ) as render,
        ):
            with self.assertRaisesRegex(
                self.installer.HermesInstallError, "invalid env"
            ):
                self.installer.reconcile(args)

        self.assertEqual(ordering, [("revoke", False), ("validate", None)])
        render.assert_not_called()

    def test_malformed_or_unreadable_env_revokes_stale_admin_before_validation(self):
        cases = (
            ("malformed", b"HERMES_OPERATOR_MODE unrestricted_host_repair\n", None),
            ("invalid-utf8", b"HERMES_OPERATOR_MODE=\xff\n", None),
            (
                "unreadable",
                b"HERMES_OPERATOR_MODE=unrestricted_host_repair\n",
                0o000,
            ),
        )
        for name, contents, mode in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                env_file = Path(directory) / "platform.env"
                sudoers = Path(directory) / "mte-hermes-platform-admin"
                env_file.write_bytes(contents)
                sudoers.write_text("stale unrestricted policy\n", encoding="utf-8")
                if mode is not None:
                    env_file.chmod(mode)

                self.assertTrue(self.installer.public_mode_requested(env_file))
                args = mock.Mock(env_file=env_file, no_restart=True)
                ordering = []

                def validation_sentinel(_env_file):
                    ordering.append("validate")
                    self.assertFalse(sudoers.exists())
                    raise self.installer.HermesInstallError("validation sentinel")

                with (
                    mock.patch.object(self.installer, "require_root"),
                    mock.patch.object(self.installer, "DEFAULT_ENV_FILE", env_file),
                    mock.patch.object(self.installer, "SUDOERS_PATH", sudoers),
                    mock.patch.object(
                        self.installer,
                        "validate_env_file",
                        side_effect=validation_sentinel,
                    ),
                    mock.patch.object(
                        self.installer, "reconcile_platform_projections"
                    ) as render,
                    mock.patch.object(self.installer, "render_native_config") as native,
                ):
                    with self.assertRaisesRegex(
                        self.installer.HermesInstallError, "validation sentinel"
                    ):
                        self.installer.reconcile(args)

                self.assertEqual(ordering, ["validate"])
                self.assertFalse(sudoers.exists())
                render.assert_not_called()
                native.assert_not_called()
                if mode is not None:
                    env_file.chmod(0o600)


class HermesMattermostBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.bootstrap = load(
            "test_hermes_mattermost_bootstrap",
            "deployment/services/hermes/bootstrap-mattermost.py",
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

    def test_settings_consume_canonical_urls_timeouts_and_identities(self):
        values = mattermost_bootstrap_values(self.bootstrap)

        settings = self.bootstrap.bootstrap_settings(values)

        self.assertEqual(settings.mattermost_url, "http://127.0.0.1:48065")
        self.assertEqual(settings.http_timeout_seconds, 17)
        self.assertEqual(settings.command_timeout_seconds, 71)
        self.assertEqual(settings.container_name_suffix, "mattermost-unit-1")
        self.assertEqual(settings.bot_name, "unit-hermes")
        self.assertEqual(settings.operator_name, "unit-operator")
        self.assertEqual(settings.operator_email, "operator@unit.invalid")
        self.assertEqual(settings.team_name, "unit-platform")
        self.assertEqual(settings.channel_name, "unit-operator-channel")

    def test_configured_command_timeout_is_enforced(self):
        settings = self.bootstrap.bootstrap_settings(
            mattermost_bootstrap_values(self.bootstrap)
        )
        result = mock.Mock(
            returncode=0,
            stdout="mte-platform-mattermost-unit-1\n",
            stderr="",
        )

        with mock.patch.object(
            self.bootstrap.subprocess, "run", return_value=result
        ) as run:
            self.assertEqual(
                self.bootstrap.mattermost_container(settings),
                "mte-platform-mattermost-unit-1",
            )

        self.assertEqual(run.call_args.kwargs["timeout"], 71)

    def test_configured_api_url_and_timeout_are_enforced(self):
        settings = self.bootstrap.bootstrap_settings(
            mattermost_bootstrap_values(self.bootstrap)
        )
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"ok":true}'
        response.__enter__.return_value.headers.items.return_value = []

        with mock.patch.object(
            self.bootstrap.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            payload, _ = self.bootstrap.api_request(settings, "/api/v4/test")

        self.assertEqual(payload, {"ok": True})
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:48065/api/v4/test")
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 17)

    def test_main_validates_complete_canonical_contract_before_mutation(self):
        values = mattermost_bootstrap_values(self.bootstrap)
        del values["HERMES_KESTRA_URL"]

        with (
            mock.patch.object(self.bootstrap.os, "geteuid", return_value=0),
            mock.patch.object(self.bootstrap, "read_env", return_value=([], values)),
            mock.patch.object(self.bootstrap, "mattermost_container") as container,
            self.assertRaisesRegex(
                self.bootstrap.BootstrapError,
                "canonical HERMES_KESTRA_URL is required",
            ),
        ):
            self.bootstrap.main()

        container.assert_not_called()

    def test_main_only_persists_server_generated_mattermost_values(self):
        values = mattermost_bootstrap_values(self.bootstrap)
        settings = self.bootstrap.bootstrap_settings(values)
        command_result = mock.Mock(returncode=1, stdout="", stderr="")

        with (
            mock.patch.object(self.bootstrap.os, "geteuid", return_value=0),
            mock.patch.object(self.bootstrap, "read_env", return_value=([], values)),
            mock.patch.object(
                self.bootstrap,
                "bootstrap_settings",
                return_value=settings,
            ),
            mock.patch.object(
                self.bootstrap, "mattermost_container", return_value="unit-mm"
            ),
            mock.patch.object(self.bootstrap, "mmctl", return_value=command_result),
            mock.patch.object(
                self.bootstrap,
                "admin_login",
                side_effect=["admin-session", "operator-session"],
            ),
            mock.patch.object(
                self.bootstrap,
                "ensure_user",
                return_value=({"id": "operator-id"}, "operator-password"),
            ),
            mock.patch.object(
                self.bootstrap,
                "ensure_bot",
                return_value=({"id": "bot-id"}, "bot-token"),
            ),
            mock.patch.object(
                self.bootstrap, "ensure_team", return_value={"id": "team-id"}
            ),
            mock.patch.object(
                self.bootstrap,
                "ensure_channel",
                return_value={"id": "channel-id"},
            ),
            mock.patch.object(self.bootstrap, "update_env") as update,
            mock.patch("builtins.print"),
        ):
            self.assertEqual(self.bootstrap.main(), 0)

        update.assert_called_once_with(
            {
                "MATTERMOST_ALLOWED_USERS": "operator-id",
                "MATTERMOST_HOME_CHANNEL": "channel-id",
                "MATTERMOST_OPERATOR_PASSWORD": "operator-password",
                "MATTERMOST_TOKEN": "bot-token",
            }
        )


if __name__ == "__main__":
    unittest.main()

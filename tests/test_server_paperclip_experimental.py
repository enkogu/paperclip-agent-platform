import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools/platform-cli/server-paperclip-experimental.py"
spec = importlib.util.spec_from_file_location(
    "server_paperclip_experimental", MODULE_PATH
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def canonical_values() -> dict[str, str]:
    return {
        "PAPERCLIP_API_BASE": "http://127.0.0.1:3100",
        "DAYTONA_API_URL": "http://127.0.0.1:3310/api",
        "MTE_DAYTONA_API_URL": "http://127.0.0.1:3310/api",
        "MTE_DAYTONA_API_INTERNAL_PORT": "3000",
        "PAPERCLIP_DAYTONA_UPSTREAM_URL": "http://mte-daytona-api:3000/api",
        "DAYTONA_TARGET": "us",
        "MTE_DAYTONA_SANDBOX_IMAGE": "ghcr.io/example/daytona-harness@sha256:"
        + "9" * 64,
        "MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL": "https://github.com/example/platform",
        "MTE_DAYTONA_SANDBOX_IMAGE_REVISION": "8" * 40,
        "MTE_DAYTONA_CONTROL_PLANE_VERSION": "0.187.0",
        "MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT": "7" * 40,
        "MTE_DAYTONA_SANDBOX_VERSION": "0.190.0",
        "MTE_CODEX_VERSION": "0.144.4",
        "MTE_CLAUDE_CODE_VERSION": "2.1.209",
        "MTE_PI_VERSION": "0.80.7",
        "MTE_CODEX_NPM_INTEGRITY": "sha512-" + "a" * 88,
        "MTE_CLAUDE_CODE_NPM_INTEGRITY": "sha512-" + "b" * 88,
        "MTE_PI_NPM_INTEGRITY": "sha512-" + "c" * 88,
        "MTE_CONTEXT7_MCP_URL": "https://mcp.context7.com/mcp",
        "MTE_CONTEXT7_PI_PACKAGE": "@upstash/context7-pi",
        "MTE_CONTEXT7_PI_VERSION": "0.1.1",
        "MTE_CONTEXT7_PI_NPM_INTEGRITY": "sha512-" + "d" * 88,
        "MTE_PI_TOOLHIVE_EXTENSION_SHA256": "e" * 64,
        "MTE_TOOLHIVE_VERSION": "0.36.0",
        "MTE_TOOLHIVE_ARCHIVE_SHA256": "a" * 64,
        "MTE_GITHUB_CLI_VERSION": "2.96.0",
        "MTE_GITHUB_CLI_ARCHIVE_SHA256": "b" * 64,
        "MTE_DOCKER_LOG_DRIVER": "json-file",
        "MTE_DOCKER_LOG_MAX_SIZE": "10m",
        "MTE_DOCKER_LOG_MAX_FILES": "3",
        "MTE_JQ_VERSION": "1.8.1",
        "MTE_JQ_LINUX_AMD64_SHA256": "3" * 64,
        "MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL": "http://172.20.0.1:22080/v1",
        "HERMES_LLM_MODEL": "mte-minimax/unit-model",
        "MTE_PI_CODING_AGENT_DIR": "/home/daytona/.pi/mte-profile",
        "MTE_DAYTONA_CODING_SNAPSHOT": "mte-coding-harness-v1",
        "MTE_DAYTONA_GENERAL_SNAPSHOT": "mte-general-harness-v1",
        "MTE_DAYTONA_CODING_CPU": "1",
        "MTE_DAYTONA_CODING_MEMORY_GIB": "2",
        "MTE_DAYTONA_GENERAL_CPU": "1",
        "MTE_DAYTONA_GENERAL_MEMORY_GIB": "1",
        "MTE_DAYTONA_DISK_GIB": "20",
        "MTE_AGENT_GATEWAY_HOST": "172.20.0.1",
        "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_PORT": "22081",
        "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_PORT": "22082",
        "MTE_AGENT_GATEWAY_TOOLHIVE_PI_PORT": "22083",
        "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL": "http://172.20.0.1:22081/mcp",
        "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_URL": "http://172.20.0.1:22082/mcp",
        "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL": "http://172.20.0.1:22083/mcp",
        "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_PROXY_PORT": "19011",
        "TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_PROXY_PORT": "19012",
        "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_PROXY_PORT": "19013",
        "PROFILE_CODING_DAYTONA_CODEX_PACKAGE_CODEX_VERSION": "0.144.4",
        "PROFILE_CODING_DAYTONA_CODEX_MODEL": "mte-minimax/MiniMax-M2.7-highspeed",
        "PROFILE_CODING_DAYTONA_CLAUDE_PACKAGE_CLAUDECODE_VERSION": "2.1.209",
        "PROFILE_CODING_DAYTONA_CLAUDE_MODEL": "mte-minimax/MiniMax-M2.7-highspeed",
        "PROFILE_CODING_DAYTONA_PI_PACKAGE_PI_VERSION": "0.80.7",
        "PROFILE_CODING_DAYTONA_PI_PROVIDER": "mte9router",
        "PROFILE_CODING_DAYTONA_PI_MODEL": (
            "mte9router/mte-minimax/MiniMax-M2.7-highspeed"
        ),
    }


class PaperclipExperimentalEvidenceTests(unittest.TestCase):
    def test_harness_version_matching_rejects_substring_collisions(self):
        self.assertEqual(
            module.normalized_harness_version("codex", "codex-cli 0.144.4"),
            "0.144.4",
        )
        self.assertNotEqual(
            module.normalized_harness_version("codex", "codex-cli 0.144.40"),
            "0.144.4",
        )

    def test_all_daytona_harnesses_are_minimax_through_9router(self):
        values = canonical_values()
        profiles = {
            profile_ref: copy.deepcopy(
                module.DEFAULT_PROFILE_CATALOG.require(profile_ref)
            )
            for profile_ref in module.DAYTONA_PROFILE_REFS
        }
        catalog = mock.Mock()
        catalog.refs = module.DAYTONA_PROFILE_REFS
        catalog.require.side_effect = profiles.__getitem__

        self.assertEqual(
            module.required_daytona_profile_refs(catalog, values),
            module.DAYTONA_PROFILE_REFS,
        )
        self.assertEqual(
            module.DAYTONA_PROFILE_REFS,
            (
                "coding-daytona-codex",
                "coding-daytona-claude",
                "coding-daytona-pi",
            ),
        )
        self.assertEqual(
            module.expected_profile_skill()["installedProfiles"],
            list(module.DAYTONA_PROFILE_REFS),
        )
        self.assertEqual(
            set(module.expected_profile_skill()["nativeDestinations"]),
            {"codex", "claude", "pi"},
        )
        self.assertEqual(
            module.expected_snapshot_harness_versions(values),
            {"codex": "0.144.4", "claudeCode": "2.1.209", "pi": "0.80.7"},
        )

        for profile_ref, field, value in (
            ("coding-daytona-codex", "harnessKind", "pi"),
            ("coding-daytona-claude", "runtimeSecretEnv", "OPENAI_API_KEY"),
        ):
            with self.subTest(profile=profile_ref, field=field):
                drifted = copy.deepcopy(profiles[profile_ref])
                drifted["runtimeContract"][field] = value
                catalog.require.side_effect = lambda ref, drifted=drifted: (
                    drifted if ref == profile_ref else profiles[ref]
                )
                with self.assertRaises(module.ControlError):
                    module.required_daytona_profile_refs(catalog, values)
                catalog.require.side_effect = profiles.__getitem__

        for profile_ref, drifted_values, drifted_profile in (
            (
                "coding-daytona-pi",
                {**values, "PROFILE_CODING_DAYTONA_PI_MODEL": "other/model"},
                profiles["coding-daytona-pi"],
            ),
            (
                "coding-daytona-claude",
                values,
                {
                    **profiles["coding-daytona-claude"],
                    "llmRouting": {
                        **profiles["coding-daytona-claude"]["llmRouting"],
                        "provider": "direct",
                    },
                },
            ),
            (
                "coding-daytona-codex",
                values,
                {
                    **profiles["coding-daytona-codex"],
                    "nativeAdapterConfig": {
                        **profiles["coding-daytona-codex"]["nativeAdapterConfig"],
                        "extraArgs": [],
                    },
                },
            ),
            (
                "coding-daytona-claude",
                values,
                {
                    **profiles["coding-daytona-claude"],
                    "authPolicy": {
                        **profiles["coding-daytona-claude"]["authPolicy"],
                        "oauthInImage": True,
                    },
                },
            ),
        ):
            with self.subTest(profile=profile_ref, values=drifted_values):
                catalog.require.side_effect = lambda ref, drifted=drifted_profile: (
                    drifted if ref == profile_ref else profiles[ref]
                )
                with self.assertRaises(module.ControlError):
                    module.required_daytona_profile_refs(catalog, drifted_values)
                catalog.require.side_effect = profiles.__getitem__

        source = MODULE_PATH.read_text()
        self.assertIn(
            "required_profiles = required_daytona_profile_refs(profile_catalog, values)",
            source,
        )
        self.assertIn("DAYTONA_HARNESS_CONTRACTS", source)

    def test_rendered_codex_profile_keeps_exact_canonical_router_contract(self):
        values = canonical_values()
        profiles = {
            profile_ref: copy.deepcopy(
                module.DEFAULT_PROFILE_CATALOG.require(profile_ref)
            )
            for profile_ref in module.DAYTONA_PROFILE_REFS
        }
        codex = profiles["coding-daytona-codex"]
        placeholder = (
            "${MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL:?required}"
        )
        codex["nativeAdapterConfig"]["extraArgs"] = [
            str(item).replace(
                placeholder,
                values["MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL"],
            )
            for item in codex["nativeAdapterConfig"]["extraArgs"]
        ]
        catalog = mock.Mock()
        catalog.refs = module.DAYTONA_PROFILE_REFS
        catalog.require.side_effect = profiles.__getitem__

        self.assertEqual(
            module.required_daytona_profile_refs(catalog, values),
            module.DAYTONA_PROFILE_REFS,
        )

        codex["nativeAdapterConfig"]["extraArgs"] = [
            str(item).replace(
                values["MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL"],
                "http://wrong-router.internal:9999/v1",
            )
            for item in codex["nativeAdapterConfig"]["extraArgs"]
        ]
        with self.assertRaisesRegex(
            module.ControlError, "Codex must use its 9Router"
        ):
            module.required_daytona_profile_refs(catalog, values)

    def test_operator_api_base_requires_explicit_valid_scheme_host_port_and_path(self):
        self.assertEqual(
            module.validated_operator_api_base(
                "http://127.0.0.1:3100",
                setting="PAPERCLIP_API_BASE",
                expected_path="",
            ),
            "http://127.0.0.1:3100",
        )
        self.assertEqual(
            module.validated_operator_api_base(
                "https://paperclip.example.com:443",
                setting="PAPERCLIP_API_BASE",
                expected_path="",
            ),
            "https://paperclip.example.com:443",
        )
        invalid = (
            None,
            "",
            " http://127.0.0.1:3100",
            "ftp://127.0.0.1:3100",
            "http://:3100",
            "http://127.0.0.1",
            "http://127.0.0.1:70000",
            "http://user:secret@127.0.0.1:3100",
            "http://bad_host:3100",
            "http://127.0.0.1:3100/api",
            "http://127.0.0.1:3100?mode=unsafe",
            "http://127.0.0.1:3100#fragment",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(module.ControlError):
                    module.validated_operator_api_base(
                        value,
                        setting="PAPERCLIP_API_BASE",
                        expected_path="",
                    )

    def test_paperclip_context_requires_exact_rendered_canonical_api_base(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = root / "platform.env"
            bootstrap = root / "paperclip-bootstrap.json"
            canonical.write_text("PAPERCLIP_API_BASE=http://127.0.0.1:3100\n")
            bootstrap.write_text(json.dumps({"companyId": "company-unit"}))
            experimental = {"apiBase": "http://127.0.0.1:3100"}

            with (
                mock.patch.object(module, "PLATFORM_ENV", canonical),
                mock.patch.object(module, "BOOTSTRAP", bootstrap),
                mock.patch.object(module, "settings", return_value=({}, experimental)),
                mock.patch.object(
                    module,
                    "json_request",
                    return_value=[{"id": "company-unit"}],
                ) as request,
            ):
                self.assertEqual(
                    module.paperclip_context(),
                    ("http://127.0.0.1:3100", "company-unit"),
                )
                request.assert_called_once_with(
                    "http://127.0.0.1:3100", "GET", "/api/companies"
                )

                canonical.write_text("PAPERCLIP_API_BASE=http://127.0.0.1:3199\n")
                with self.assertRaisesRegex(module.ControlError, "differs"):
                    module.paperclip_context()

    def test_paperclip_api_base_missing_invalid_or_mutated_fails_before_request(self):
        cases = (
            ({}, "PAPERCLIP_API_BASE=http://127.0.0.1:3100\n"),
            ({"apiBase": "http://127.0.0.1:3100"}, "UNIT=value\n"),
            (
                {"apiBase": "http://127.0.0.1:3100"},
                "PAPERCLIP_API_BASE=http://127.0.0.1:3199\n",
            ),
            (
                {"apiBase": "http://127.0.0.1/api"},
                "PAPERCLIP_API_BASE=http://127.0.0.1/api\n",
            ),
        )
        for experimental, canonical_text in cases:
            with self.subTest(experimental=experimental, canonical=canonical_text):
                with tempfile.TemporaryDirectory() as directory:
                    canonical = Path(directory) / "platform.env"
                    canonical.write_text(canonical_text)
                    with (
                        mock.patch.object(module, "PLATFORM_ENV", canonical),
                        mock.patch.object(
                            module, "settings", return_value=({}, experimental)
                        ),
                        mock.patch.object(module, "json_request") as request,
                        self.assertRaises(module.ControlError),
                    ):
                        module.paperclip_context()
                    request.assert_not_called()

    def test_paperclip_admin_request_uses_canonical_board_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            canonical = Path(directory) / "platform.env"
            canonical.write_text("PAPERCLIP_BOARD_API_KEY=unit-board-key\n")
            response = mock.MagicMock()
            response.read.return_value = b'{"ok":true}'
            response.__enter__.return_value = response
            with (
                mock.patch.object(module, "PLATFORM_ENV", canonical),
                mock.patch.object(
                    module.urllib.request, "urlopen", return_value=response
                ) as urlopen,
            ):
                value = module.json_request(
                    "http://127.0.0.1:3100", "GET", "/api/companies"
                )

            self.assertEqual(value, {"ok": True})
            request = urlopen.call_args.args[0]
            self.assertEqual(
                request.get_header("Authorization"), "Bearer unit-board-key"
            )

    def test_paperclip_admin_request_fails_closed_without_board_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            canonical = Path(directory) / "platform.env"
            canonical.write_text("PAPERCLIP_API_BASE=http://127.0.0.1:3100\n")
            with (
                mock.patch.object(module, "PLATFORM_ENV", canonical),
                mock.patch.object(module.urllib.request, "urlopen") as urlopen,
                self.assertRaisesRegex(
                    module.ControlError, "PAPERCLIP_BOARD_API_KEY is required"
                ),
            ):
                module.json_request(
                    "http://127.0.0.1:3100", "GET", "/api/companies"
                )
            urlopen.assert_not_called()

    def test_daytona_api_base_strictly_separates_operator_and_container_routes(self):
        values = canonical_values()
        spec = {"apiUrlRef": "PAPERCLIP_DAYTONA_UPSTREAM_URL"}
        self.assertEqual(
            module.canonical_daytona_api_base(values, spec),
            "http://mte-daytona-api:3000/api",
        )
        self.assertEqual(
            module.canonical_daytona_api_base(values),
            "http://127.0.0.1:3310/api",
        )

        drifted = dict(
            values,
            PAPERCLIP_DAYTONA_UPSTREAM_URL="http://mte-daytona-api:3399/api",
        )
        with self.assertRaisesRegex(module.ControlError, "separated"):
            module.canonical_daytona_api_base(drifted, spec)

        for changed_values, changed_spec in (
            (
                {
                    key: value
                    for key, value in values.items()
                    if key != "MTE_DAYTONA_API_URL"
                },
                spec,
            ),
            (values, {}),
            (values, {"apiUrlRef": "missing-ref"}),
            (values, {"apiUrlRef": "DAYTONA_API_URL"}),
            (
                {
                    **values,
                    "PAPERCLIP_DAYTONA_UPSTREAM_URL": "http://127.0.0.1:3310/api",
                },
                spec,
            ),
            ({**values, "MTE_DAYTONA_API_URL": "http://127.0.0.1/api"}, spec),
        ):
            with self.subTest(values=changed_values, spec=changed_spec):
                with self.assertRaises(module.ControlError):
                    module.canonical_daytona_api_base(changed_values, changed_spec)

    def test_daytona_request_rejects_invalid_api_base_before_network(self):
        values = canonical_values()
        values["MTE_DAYTONA_API_URL"] = "http://127.0.0.1/api"
        with (
            mock.patch.object(module.urllib.request, "urlopen") as request,
            self.assertRaises(module.ControlError),
        ):
            module.daytona_json_request(values, "GET", "/sandbox")
        request.assert_not_called()

    def test_probe_cleanup_accepts_already_deleted_sandbox(self):
        values = canonical_values()
        with mock.patch.object(
            module, "daytona_json_request", side_effect=[None, None]
        ) as request:
            module.destroy_daytona_probe_sandbox(values, "sandbox-unit")

        self.assertEqual(request.call_count, 2)
        delete = request.call_args_list[0]
        self.assertEqual(delete.args[1:3], ("DELETE", "/sandbox/sandbox-unit"))
        self.assertTrue(delete.kwargs["allow_not_found"])
        get = request.call_args_list[1]
        self.assertEqual(get.args[1:3], ("GET", "/sandbox/sandbox-unit"))
        self.assertTrue(get.kwargs["allow_not_found"])

    def test_environment_probe_optionalizes_only_user_secret_bindings(self):
        adapter_config = {
            "cwd": "/workspace",
            "env": {
                "GITHUB_TOKEN": {
                    "type": "user_secret_ref",
                    "key": "mte.github.personal_access_token",
                    "required": True,
                },
                "OPENAI_API_KEY": {
                    "type": "secret_ref",
                    "secretId": "router-unit",
                    "required": True,
                },
                "OPENAI_BASE_URL": {
                    "type": "plain",
                    "value": "http://router/v1",
                },
            },
        }
        original = copy.deepcopy(adapter_config)

        probe_config, count = module.adapter_environment_probe_config(adapter_config)

        self.assertEqual(count, 1)
        self.assertEqual(adapter_config, original)
        self.assertIsNot(probe_config, adapter_config)
        self.assertEqual(
            probe_config["env"]["GITHUB_TOKEN"],
            {
                "type": "user_secret_ref",
                "key": "mte.github.personal_access_token",
                "required": False,
                "allowMissingOverride": True,
            },
        )
        self.assertEqual(
            probe_config["env"]["OPENAI_API_KEY"],
            original["env"]["OPENAI_API_KEY"],
        )
        self.assertEqual(
            probe_config["env"]["OPENAI_BASE_URL"],
            original["env"]["OPENAI_BASE_URL"],
        )

    def test_environment_probe_optionalizes_both_github_aliases_without_values(self):
        user_ref = {
            "type": "user_secret_ref",
            "key": "mte.github.personal_access_token",
            "required": True,
        }
        adapter_config = {
            "env": {"GH_TOKEN": copy.deepcopy(user_ref), "GITHUB_TOKEN": user_ref}
        }
        original = copy.deepcopy(adapter_config)

        probe_config, count = module.adapter_environment_probe_config(adapter_config)

        self.assertEqual(count, 2)
        self.assertEqual(adapter_config, original)
        self.assertEqual(
            probe_config["env"]["GH_TOKEN"],
            probe_config["env"]["GITHUB_TOKEN"],
        )
        self.assertEqual(
            set(probe_config["env"]["GH_TOKEN"]),
            {"type", "key", "required", "allowMissingOverride"},
        )
        self.assertFalse(probe_config["env"]["GH_TOKEN"]["required"])

    def test_environment_probe_rejects_non_object_env(self):
        with self.assertRaisesRegex(module.ControlError, "must be an object"):
            module.adapter_environment_probe_config({"env": ["invalid"]})

    def test_environment_probe_accepts_only_expected_claude_router_warning(self):
        payload = {
            "status": "warn",
            "checks": [
                {
                    "code": "claude_anthropic_api_key_overrides_subscription",
                    "level": "warn",
                },
                {"code": "claude_hello_probe_passed", "level": "info"},
            ],
        }
        accepted, warning_codes = module.accepted_environment_probe(
            "coding-daytona-claude", payload
        )
        self.assertTrue(accepted)
        self.assertEqual(
            warning_codes, ["claude_anthropic_api_key_overrides_subscription"]
        )

        rejected_payloads = (
            {**payload, "status": "fail"},
            {**payload, "checks": payload["checks"][:1]},
            {
                **payload,
                "checks": [
                    *payload["checks"],
                    {"code": "unexpected_warning", "level": "warn"},
                ],
            },
            {
                **payload,
                "checks": [
                    *payload["checks"],
                    {"code": "runtime_error", "level": "error"},
                ],
            },
        )
        for drifted in rejected_payloads:
            with self.subTest(drifted=drifted):
                self.assertFalse(
                    module.accepted_environment_probe("coding-daytona-claude", drifted)[
                        0
                    ]
                )

    def test_environment_probe_pass_requires_native_harness_hello(self):
        self.assertEqual(
            module.accepted_environment_probe(
                "coding-daytona-codex",
                {
                    "status": "pass",
                    "checks": [{"code": "codex_hello_probe_passed", "level": "info"}],
                },
            ),
            (True, []),
        )
        rejected_payloads = (
            {"status": "pass"},
            {
                "status": "pass",
                "checks": [{"code": "other_check", "level": "info"}],
            },
            {
                "status": "pass",
                "checks": [
                    {"code": "codex_hello_probe_passed", "level": "info"},
                    {"code": "unexpected_warning", "level": "warn"},
                ],
            },
        )
        for payload in rejected_payloads:
            with self.subTest(payload=payload):
                self.assertFalse(
                    module.accepted_environment_probe("coding-daytona-codex", payload)[
                        0
                    ]
                )

    def test_environment_probe_observation_keeps_only_safe_check_fields(self):
        observation = module.environment_probe_observation(
            {
                "status": "fail",
                "checks": [
                    {
                        "code": "codex_hello_probe_failed",
                        "level": "error",
                        "message": "must never enter evidence",
                        "stdout": "sensitive provider output",
                    }
                ],
                "connection": {"token": "not-for-evidence"},
            },
            attempt=1,
            accepted=False,
            warning_codes=[],
            request_error=None,
            deleted_sandbox_count=1,
        )

        self.assertEqual(
            observation,
            {
                "attempt": 1,
                "status": "fail",
                "accepted": False,
                "warningCodes": [],
                "requestError": None,
                "checks": [{"code": "codex_hello_probe_failed", "level": "error"}],
                "probeSandboxesDeleted": 1,
            },
        )
        self.assertNotIn("message", json.dumps(observation))
        self.assertNotIn("sensitive provider output", json.dumps(observation))

    def test_environment_probe_retry_policy_is_small_and_bounded(self):
        self.assertEqual(module.ENVIRONMENT_PROBE_ATTEMPTS, 3)
        self.assertGreaterEqual(module.ENVIRONMENT_PROBE_RETRY_SECONDS, 1)
        self.assertLessEqual(module.ENVIRONMENT_PROBE_RETRY_SECONDS, 5)

    def test_codex_env_contract_accepts_only_paperclip_managed_home(self):
        required = {"OPENAI_API_KEY", "GITHUB_TOKEN"}
        managed_home = (
            "/data/instances/default/companies/company-unit/"
            "agents/agent-unit/codex-home"
        )
        env = {
            "OPENAI_API_KEY": {"type": "secret_ref", "secretId": "router-unit"},
            "GITHUB_TOKEN": {
                "type": "user_secret_ref",
                "key": "mte.github.personal_access_token",
            },
            "CODEX_HOME": {"type": "plain", "value": managed_home},
        }
        module.validate_profile_env_contract(
            profile_ref="coding-daytona-codex",
            company_id="company-unit",
            agent_id="agent-unit",
            env=env,
            required_keys=required,
        )

        for drifted in (
            {key: value for key, value in env.items() if key != "CODEX_HOME"},
            {**env, "UNMANAGED": {"type": "plain", "value": "unit"}},
            {
                **env,
                "CODEX_HOME": {"type": "plain", "value": "/tmp/operator"},
            },
            {**env, "CODEX_HOME": managed_home},
        ):
            with self.subTest(keys=sorted(drifted)):
                with self.assertRaises(module.ControlError):
                    module.validate_profile_env_contract(
                        profile_ref="coding-daytona-codex",
                        company_id="company-unit",
                        agent_id="agent-unit",
                        env=drifted,
                        required_keys=required,
                    )

    def test_non_codex_env_contract_rejects_provider_owned_codex_home(self):
        env = {"ANTHROPIC_API_KEY": {"type": "secret_ref", "secretId": "unit"}}
        module.validate_profile_env_contract(
            profile_ref="coding-daytona-claude",
            company_id="company-unit",
            agent_id="agent-unit",
            env=env,
            required_keys=set(env),
        )
        with self.assertRaises(module.ControlError):
            module.validate_profile_env_contract(
                profile_ref="coding-daytona-claude",
                company_id="company-unit",
                agent_id="agent-unit",
                env={
                    **env,
                    "CODEX_HOME": {"type": "plain", "value": "/tmp/operator"},
                },
                required_keys=set(env),
            )

    def test_optional_extension_credential_may_be_absent_but_never_allows_extras(self):
        env = {"OPENAI_API_KEY": {"type": "secret_ref", "secretId": "unit"}}
        module.validate_profile_env_contract(
            profile_ref="coding-daytona-pi",
            company_id="company-unit",
            agent_id="agent-unit",
            env=env,
            required_keys={"OPENAI_API_KEY", "CONTEXT7_API_KEY"},
            provider_managed_env={},
            optional_keys={"CONTEXT7_API_KEY"},
        )
        module.validate_profile_env_contract(
            profile_ref="coding-daytona-pi",
            company_id="company-unit",
            agent_id="agent-unit",
            env={
                **env,
                "CONTEXT7_API_KEY": {
                    "type": "secret_ref",
                    "secretId": "context7-unit",
                },
            },
            required_keys={"OPENAI_API_KEY", "CONTEXT7_API_KEY"},
            provider_managed_env={},
            optional_keys={"CONTEXT7_API_KEY"},
        )
        with self.assertRaises(module.ControlError):
            module.validate_profile_env_contract(
                profile_ref="coding-daytona-pi",
                company_id="company-unit",
                agent_id="agent-unit",
                env={**env, "UNMANAGED": {"type": "plain", "value": "unit"}},
                required_keys={"OPENAI_API_KEY", "CONTEXT7_API_KEY"},
                provider_managed_env={},
                optional_keys={"CONTEXT7_API_KEY"},
            )

    def test_plugin_install_uses_image_bundled_package_path(self):
        requests = []

        def json_response(_base, method, path, body=None, **_kwargs):
            requests.append((method, path, body))
            if method == "GET" and path == "/api/plugins":
                return []
            if method == "POST" and path == "/api/plugins/install":
                return {"status": "ready"}
            self.fail(f"unexpected Paperclip request: {method} {path}")

        ready_plugin = {
            "packageName": "@paperclipai/plugin-daytona",
            "packagePath": "/app/plugins/daytona",
            "pluginKey": "paperclip.daytona-sandbox-provider",
            "version": "0.1.0",
            "status": "ready",
        }
        with (
            mock.patch.object(module, "json_request", side_effect=json_response),
            mock.patch.object(
                module,
                "plugin_rows",
                side_effect=[[], [ready_plugin]],
            ),
        ):
            plugin = module.ensure_daytona_plugin(
                "http://paperclip.test",
                "@paperclipai/plugin-daytona",
                "0.1.0",
                {
                    "version": "0.1.0",
                    "packagePath": "/app/plugins/daytona",
                },
            )

        self.assertEqual(plugin, ready_plugin)
        self.assertIn(
            (
                "POST",
                "/api/plugins/install",
                {
                    "packageName": "/app/plugins/daytona",
                    "isLocalPath": True,
                },
            ),
            requests,
        )

    def test_plugin_discovery_has_no_deploy_time_npm_contract(self):
        source = (
            ROOT / "tools/platform-cli/server-paperclip-experimental.py"
        ).read_text()
        self.assertIn("require.resolve('@paperclipai/plugin-daytona')", source)
        self.assertNotIn("MTE_DAYTONA_PLUGIN_NPM_", source)
        self.assertNotIn("/tools/node_modules", source)
        self.assertIn("fs.realpathSync('/app')", source)
        self.assertIn("relative.split(path.sep).includes('node_modules')", source)
        self.assertIn("unsupported Daytona plugin file type", source)
        self.assertIn("package-files-excluding-node_modules", source)
        self.assertLess(
            source.index("relative.split(path.sep).includes('node_modules')"),
            source.index("unsupported Daytona plugin file type"),
        )

    def test_plugin_purges_then_reinstalls_when_image_package_path_drifted(self):
        plugin = {
            "packageName": "@paperclipai/plugin-daytona",
            "pluginKey": "paperclip.daytona-sandbox-provider",
            "version": "0.1.0",
            "status": "ready",
        }
        requests = []

        def json_response(_base, method, path, body=None, **_kwargs):
            requests.append((method, path, body))
            return {"status": "ready"}

        with (
            mock.patch.object(module, "plugin_rows", return_value=[plugin]),
            mock.patch.object(module, "json_request", side_effect=json_response),
        ):
            module.ensure_daytona_plugin(
                "http://paperclip.test",
                "@paperclipai/plugin-daytona",
                "0.1.0",
                {
                    "version": "0.1.0",
                    "packagePath": "/app/plugins/daytona",
                },
            )

        self.assertEqual(
            requests,
            [
                (
                    "DELETE",
                    "/api/plugins/paperclip.daytona-sandbox-provider?purge=true",
                    None,
                ),
                (
                    "POST",
                    "/api/plugins/install",
                    {
                        "packageName": "/app/plugins/daytona",
                        "isLocalPath": True,
                    },
                ),
            ],
        )

    def test_plugin_enables_existing_errored_exact_package_without_reinstall(self):
        errored = {
            "packageName": "@paperclipai/plugin-daytona",
            "packagePath": "/app/plugins/daytona",
            "pluginKey": "paperclip.daytona-sandbox-provider",
            "version": "0.1.0",
            "status": "error",
        }
        ready = {**errored, "status": "ready"}
        requests = []

        def json_response(_base, method, path, body=None, **_kwargs):
            requests.append((method, path, body))
            return ready

        with (
            mock.patch.object(module, "plugin_rows", side_effect=[[errored], [ready]]),
            mock.patch.object(module, "json_request", side_effect=json_response),
        ):
            observed = module.ensure_daytona_plugin(
                "http://paperclip.test",
                "@paperclipai/plugin-daytona",
                "0.1.0",
                {
                    "version": "0.1.0",
                    "packagePath": "/app/plugins/daytona",
                },
            )

        self.assertEqual(observed, ready)
        self.assertEqual(
            requests,
            [
                (
                    "POST",
                    "/api/plugins/paperclip.daytona-sandbox-provider/enable",
                    {},
                )
            ],
        )

    def test_environment_mutations_include_explicit_company_context(self):
        self.assertEqual(
            module.environment_mutation_path(
                "environment/default", "company with spaces"
            ),
            "/api/environments/environment%2Fdefault?companyId=company%20with%20spaces",
        )

    def test_workspace_feature_flags_are_reconciled_before_environment_use(self):
        with mock.patch.object(
            module,
            "json_request",
            side_effect=[
                {
                    "enableEnvironments": False,
                    "enableIsolatedWorkspaces": False,
                },
                {
                    "enableEnvironments": True,
                    "enableIsolatedWorkspaces": True,
                },
            ],
        ) as request:
            result = module.reconcile_workspace_feature_flags(
                "http://paperclip.invalid", mutate=True
            )

        self.assertEqual(
            result,
            {
                "enableEnvironments": True,
                "enableIsolatedWorkspaces": True,
            },
        )
        self.assertEqual(request.call_args_list[0].args[1:], ("GET", "/api/instance/settings/experimental"))
        self.assertEqual(request.call_args_list[1].args[1:], ("PATCH", "/api/instance/settings/experimental", {"enableEnvironments": True, "enableIsolatedWorkspaces": True}))

    def test_workspace_feature_flags_fail_closed_in_read_only_mode(self):
        with (
            mock.patch.object(
                module,
                "json_request",
                return_value={
                    "enableEnvironments": True,
                    "enableIsolatedWorkspaces": False,
                },
            ),
            self.assertRaises(module.ControlError) as raised,
        ):
            module.reconcile_workspace_feature_flags(
                "http://paperclip.invalid", mutate=False
            )
        self.assertEqual(raised.exception.code, "workspace_features_disabled")

    def test_local_environment_reuses_single_paperclip_default(self):
        builtin = {
            "id": "environment-default",
            "name": "Local",
            "driver": "local",
            "metadata": {
                "defaultForInstance": True,
                "managedByPaperclip": True,
            },
        }
        selected, adopted = module.select_local_environment(
            [builtin], "MTE Local Isolated Workspaces"
        )
        self.assertIs(selected, builtin)
        self.assertTrue(adopted)

    def test_local_environment_prefers_exact_managed_name(self):
        managed = {
            "id": "environment-managed",
            "name": "MTE Local Isolated Workspaces",
            "driver": "local",
        }
        selected, adopted = module.select_local_environment(
            [
                {"id": "environment-default", "name": "Local", "driver": "local"},
                managed,
            ],
            "MTE Local Isolated Workspaces",
        )
        self.assertIs(selected, managed)
        self.assertFalse(adopted)

    def test_local_environment_fails_closed_on_ambiguous_defaults(self):
        with self.assertRaisesRegex(module.ControlError, "multiple unnamed"):
            module.select_local_environment(
                [
                    {"id": "environment-one", "name": "Local", "driver": "local"},
                    {
                        "id": "environment-two",
                        "name": "Another local",
                        "driver": "local",
                    },
                ],
                "MTE Local Isolated Workspaces",
            )

    def test_secret_reconcile_binds_single_paperclip_default_environment(self):
        company_id = "company-unit"
        secret_id = "secret-unit"
        builtin = {
            "id": "environment-default",
            "name": "Local",
            "driver": "local",
            "envVars": {
                "MTE_PLATFORM_SERVICE_TOKEN": {
                    "type": "secret_ref",
                    "secretId": secret_id,
                    "version": "latest",
                }
            },
        }

        def json_response(_base, method, path, _body=None, **_kwargs):
            self.assertEqual(method, "GET")
            if path.endswith("/secret-providers"):
                return [{"id": "local_encrypted"}]
            if path.endswith("/environments"):
                return [builtin]
            if path.endswith("/secrets"):
                return [
                    {
                        "id": secret_id,
                        "name": "mte-platform-service-token",
                        "companyId": company_id,
                    }
                ]
            self.fail(f"unexpected Paperclip request: {method} {path}")

        experimental = {
            "localEnvironment": {"name": "MTE Local Isolated Workspaces"},
            "secrets": {
                "strictMode": True,
                "provider": "local_encrypted",
                "secretName": "mte-platform-service-token",
                "bindingName": "MTE_PLATFORM_SERVICE_TOKEN",
            },
        }
        with (
            mock.patch.object(module, "settings", return_value=({}, experimental)),
            mock.patch.object(
                module, "strict_mode_state", return_value={"runtime": True}
            ),
            mock.patch.object(
                module,
                "paperclip_context",
                return_value=("http://paperclip.test", company_id),
            ),
            mock.patch.object(
                module,
                "dotenv",
                return_value={"PAPERCLIP_SERVICE_TOKEN": "unit-service-token"},
            ),
            mock.patch.object(module, "json_request", side_effect=json_response),
        ):
            evidence = module.reconcile_secrets(mutate=False)

        self.assertEqual(evidence["binding"]["targetId"], builtin["id"])
        self.assertTrue(evidence["adoptedPaperclipDefault"])

    def test_actions_write_separate_root_only_evidence_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = root / "platform.env"
            config = root / "platform.json"
            canonical.write_text("UNIT=value\n")
            config.write_text("{}\n")
            with (
                mock.patch.object(module, "PLATFORM_ENV", canonical),
                mock.patch.object(module, "CONFIG", config),
                mock.patch.object(module, "BOOTSTRAP", root / "missing.json"),
                mock.patch.object(module, "EVIDENCE_ROOT", root / "evidence"),
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                for action in ("apply", "status", "verify"):
                    module.emit("daytona", action, "ready", {"actionProof": action})
            evidence_paths = sorted((root / "evidence").glob("*.json"))
            self.assertEqual(
                [path.name for path in evidence_paths],
                [
                    "paperclip-daytona-apply.json",
                    "paperclip-daytona-status.json",
                    "paperclip-daytona-verify.json",
                ],
            )
            for path in evidence_paths:
                payload = json.loads(path.read_text())
                self.assertEqual(payload["action"], path.stem.rsplit("-", 1)[-1])
                self.assertEqual(payload["details"]["actionProof"], payload["action"])
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_evidence_reference_rejects_mode_symlink_and_canonical_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = root / "platform.env"
            canonical.write_text("UNIT=value\n")
            evidence = root / "evidence.json"
            payload = {
                "apiVersion": module.API_VERSION,
                "kind": "UnitEvidence",
                "status": "ready",
                "generatedAt": module.datetime.now(module.timezone.utc).isoformat(),
                "canonicalSourceSha256": hashlib.sha256(
                    canonical.read_bytes()
                ).hexdigest(),
                "producerSha256": "b" * 64,
            }
            evidence.write_text(json.dumps(payload))
            evidence.chmod(0o600)
            with mock.patch.object(module, "PLATFORM_ENV", canonical):
                reference = module.evidence_reference(evidence, "UnitEvidence")
                self.assertEqual(
                    reference["sha256"],
                    hashlib.sha256(evidence.read_bytes()).hexdigest(),
                )
                evidence.chmod(0o644)
                with self.assertRaisesRegex(module.ControlError, "mode"):
                    module.evidence_reference(evidence, "UnitEvidence")
                evidence.chmod(0o600)
                payload["generatedAt"] = (
                    module.datetime.now(module.timezone.utc)
                    - module.timedelta(seconds=601)
                ).isoformat()
                evidence.write_text(json.dumps(payload))
                evidence.chmod(0o600)
                with self.assertRaises(module.ControlError):
                    module.evidence_reference(evidence, "UnitEvidence")
                payload["generatedAt"] = module.datetime.now(
                    module.timezone.utc
                ).isoformat()
                evidence.write_text(json.dumps(payload))
                evidence.chmod(0o600)
                canonical.write_text("UNIT=drift\n")
                with self.assertRaises(module.ControlError):
                    module.evidence_reference(evidence, "UnitEvidence")
                link = root / "link.json"
                link.symlink_to(evidence)
                with self.assertRaisesRegex(module.ControlError, "regular file"):
                    module.evidence_reference(link, "UnitEvidence")

    def test_snapshot_and_lifecycle_semantics_fail_closed(self):
        values = canonical_values()
        with tempfile.TemporaryDirectory() as directory:
            canonical = Path(directory) / "platform.env"
            canonical.write_text(
                "".join(f"{key}={value}\n" for key, value in sorted(values.items()))
            )
            images = {
                "apiVersion": module.API_VERSION,
                "kind": "DaytonaHarnessSnapshots",
                "status": "ready",
                "generatedAt": module.datetime.now(module.timezone.utc).isoformat(),
                "producerSha256": "a" * 64,
                "canonicalSourceSha256": hashlib.sha256(
                    canonical.read_bytes()
                ).hexdigest(),
                "controlPlane": {
                    "version": values["MTE_DAYTONA_CONTROL_PLANE_VERSION"],
                    "sourceCommit": values[
                        "MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT"
                    ],
                },
                "sandboxVersion": values["MTE_DAYTONA_SANDBOX_VERSION"],
                "sandboxImage": values["MTE_DAYTONA_SANDBOX_IMAGE"],
                "source": {
                    "url": values["MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL"],
                    "revision": values["MTE_DAYTONA_SANDBOX_IMAGE_REVISION"],
                },
                "snapshots": [
                    {
                        "role": "coding",
                        "id": "snapshot-coding",
                        "name": values["MTE_DAYTONA_CODING_SNAPSHOT"],
                        "state": "active",
                        "buildDockerfile": f"FROM {values['MTE_DAYTONA_SANDBOX_IMAGE']}\n",
                        "cpu": 1,
                        "memoryGiB": 2,
                        "diskGiB": 20,
                        "ref": values["MTE_DAYTONA_SANDBOX_IMAGE"],
                    },
                    {
                        "role": "general",
                        "id": "snapshot-general",
                        "name": values["MTE_DAYTONA_GENERAL_SNAPSHOT"],
                        "state": "active",
                        "buildDockerfile": f"FROM {values['MTE_DAYTONA_SANDBOX_IMAGE']}\n",
                        "cpu": 1,
                        "memoryGiB": 1,
                        "diskGiB": 20,
                        "ref": values["MTE_DAYTONA_SANDBOX_IMAGE"],
                    },
                ],
                "resources": {
                    "coding": {"cpu": 1, "memory": 2, "disk": 20},
                    "general": {"cpu": 1, "memory": 1, "disk": 20},
                },
                "harnessVersions": module.expected_snapshot_harness_versions(values),
                "deferredCleanup": [],
                "pointerSwitch": {
                    "coding": values["MTE_DAYTONA_CODING_SNAPSHOT"],
                    "general": values["MTE_DAYTONA_GENERAL_SNAPSHOT"],
                    "completed": True,
                },
                "credentialsBakedIntoImage": False,
            }
            images["snapshotContractHash"] = module.canonical_json_sha256(
                {
                    "sandboxImage": images["sandboxImage"],
                    "sandboxImageRevision": values[
                        "MTE_DAYTONA_SANDBOX_IMAGE_REVISION"
                    ],
                    "resources": images["resources"],
                    "harnessVersions": images["harnessVersions"],
                }
            )
            images["generation"] = images["snapshotContractHash"][:12]
            with mock.patch.object(module, "PLATFORM_ENV", canonical):
                module.validate_daytona_runtime_evidence(
                    images, "DaytonaHarnessSnapshots", values
                )
                expected_contract_hash = images["snapshotContractHash"]
                images["snapshotContractHash"] = "0" * 64
                with self.assertRaises(module.ControlError):
                    module.validate_daytona_runtime_evidence(
                        images, "DaytonaHarnessSnapshots", values
                    )
                images["snapshotContractHash"] = expected_contract_hash
                expected_dockerfile = images["snapshots"][0]["buildDockerfile"]
                images["snapshots"][0]["buildDockerfile"] = "FROM untrusted\n"
                with self.assertRaises(module.ControlError):
                    module.validate_daytona_runtime_evidence(
                        images, "DaytonaHarnessSnapshots", values
                    )
                images["snapshots"][0]["buildDockerfile"] = expected_dockerfile
                missing_schema = dict(images["snapshots"][0])
                missing_schema.pop("buildDockerfile")
                images["snapshots"][0] = missing_schema
                with self.assertRaises(module.ControlError):
                    module.validate_daytona_runtime_evidence(
                        images, "DaytonaHarnessSnapshots", values
                    )
                extra_schema = {**missing_schema, "buildDockerfile": expected_dockerfile, "legacy": True}
                images["snapshots"][0] = extra_schema
                with self.assertRaises(module.ControlError):
                    module.validate_daytona_runtime_evidence(
                        images, "DaytonaHarnessSnapshots", values
                    )
                images["snapshots"][0] = {**missing_schema, "buildDockerfile": expected_dockerfile}
                images["snapshots"][0]["ref"] = (
                    "ghcr.io/example/daytona-harness@sha256:" + "0" * 64
                )
                with self.assertRaises(module.ControlError):
                    module.validate_daytona_runtime_evidence(
                        images, "DaytonaHarnessSnapshots", values
                    )

            resources = {"cpu": 1, "memory": 2, "disk": 20}
            lifecycle = {
                "apiVersion": module.API_VERSION,
                "kind": "DaytonaSandboxLifecycleEvidence",
                "status": "ready",
                "generatedAt": module.datetime.now(module.timezone.utc).isoformat(),
                "producerSha256": "a" * 64,
                "canonicalSourceSha256": hashlib.sha256(
                    canonical.read_bytes()
                ).hexdigest(),
                "controlPlane": {
                    "version": values["MTE_DAYTONA_CONTROL_PLANE_VERSION"],
                    "sourceCommit": values[
                        "MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT"
                    ],
                },
                "sandboxVersion": values["MTE_DAYTONA_SANDBOX_VERSION"],
                "provider": "daytona",
                "target": values["DAYTONA_TARGET"],
                "snapshot": values["MTE_DAYTONA_CODING_SNAPSHOT"],
                "sandboxId": "sandbox-unit",
                "workspace": "/home/daytona/paperclip-workspace",
                "harnesses": [
                    {
                        "name": name,
                        "commandPath": f"/usr/local/bin/{name}",
                        "realpath": f"/opt/mte-harness/node_modules/{name}/cli.js",
                        "versionOutput": f"{name} {version}",
                    }
                    for name, version in (
                        ("codex", values["MTE_CODEX_VERSION"]),
                        ("claude", values["MTE_CLAUDE_CODE_VERSION"]),
                        ("pi", values["MTE_PI_VERSION"]),
                    )
                ],
                "credentialFileProbe": {
                    "checkedPaths": [
                        "/home/daytona/.codex/auth.json",
                        "/home/daytona/.claude/.credentials.json",
                        "/home/daytona/.pi/agent/auth.json",
                        "/home/daytona/.config/gh/hosts.yml",
                    ],
                    "foundPaths": [],
                    "credentialFree": True,
                },
                "credentialEnvProbe": {
                    "checkedNames": [
                        "OPENAI_API_KEY",
                        "ANTHROPIC_API_KEY",
                        "GH_TOKEN",
                        "CONTEXT7_API_KEY",
                        "MTE_TOOLHIVE_BEARER_TOKEN",
                    ],
                    "foundNames": [],
                    "credentialFree": True,
                },
                "resources": {
                    "expected": resources,
                    "actual": resources,
                    "equal": True,
                },
                "credentialsBakedIntoImage": False,
                "states": [
                    {
                        "phase": "create",
                        "state": "started",
                        "at": "2026-07-18T00:00:00Z",
                    },
                    {
                        "phase": "execute",
                        "state": "passed",
                        "at": "2026-07-18T00:00:01Z",
                    },
                    {
                        "phase": "delete",
                        "state": "deleted",
                        "at": "2026-07-18T00:00:02Z",
                    },
                ],
                "cleanupDeleted": True,
                "delete": {"requested": True, "getAfterDeleteStatus": 404},
            }
            module.validate_daytona_runtime_evidence(
                lifecycle, "DaytonaSandboxLifecycleEvidence", values
            )
            lifecycle["credentialFileProbe"]["foundPaths"] = [
                "/home/daytona/.codex/auth.json"
            ]
            with self.assertRaises(module.ControlError):
                module.validate_daytona_runtime_evidence(
                    lifecycle, "DaytonaSandboxLifecycleEvidence", values
                )
            lifecycle["credentialFileProbe"]["foundPaths"] = []
            missing_schema = dict(lifecycle)
            missing_schema.pop("controlPlane")
            extra_schema = {**lifecycle, "legacy": True}
            stale_provenance = {
                **lifecycle,
                "sandboxVersion": "0.0.0-stale",
            }
            for drifted in (missing_schema, extra_schema, stale_provenance):
                with self.assertRaises(module.ControlError):
                    module.validate_daytona_runtime_evidence(
                        drifted, "DaytonaSandboxLifecycleEvidence", values
                    )

    def test_tool_delivery_evidence_rejects_wrong_endpoint_or_context7_auth_drift(self):
        catalog = module.DEFAULT_PROFILE_CATALOG
        for profile in catalog.profiles:
            contract = module.validated_tool_delivery_contract(
                profile, canonical_values()
            )
            if profile["runtimeContract"]["harnessKind"] != "pi":
                self.assertEqual(
                    contract["context7"]["endpoint"],
                    canonical_values()["MTE_CONTEXT7_MCP_URL"],
                )

        context7_drift = copy.deepcopy(catalog.require("coding-daytona-codex"))
        context7_drift["toolDelivery"]["context7"]["authentication"] = "custom-header"
        with self.assertRaisesRegex(module.ControlError, "delivery"):
            module.validated_tool_delivery_contract(context7_drift, canonical_values())

        pi_drift = copy.deepcopy(catalog.require("coding-daytona-pi"))
        pi_drift["toolDelivery"]["profileTools"]["extensionRef"] = "toolhive-codex"
        with self.assertRaisesRegex(module.ControlError, "delivery"):
            module.validated_tool_delivery_contract(pi_drift, canonical_values())

    def test_daytona_snapshot_source_uses_minimal_secret_free_contract(self):
        source = (ROOT / "deployment/steps/daytona.sh").read_text()
        self.assertIn('kind:"DaytonaHarnessSnapshots"', source)
        self.assertNotIn("contextHash", source)
        self.assertNotIn("contextFiles:files", source)
        self.assertIn("sandboxImage", source)
        self.assertIn("sandboxImageRevision", source)
        self.assertIn("credentialsBakedIntoImage:false", source)
        for legacy in (
            "imageContract",
            "packageIntegrity",
            "canonicalBinding",
            "snapshotRebuiltForContractDrift",
        ):
            self.assertNotIn(legacy, source)

    def test_control_plane_requires_exact_direct_compose_services(self):
        values = canonical_values()
        payload = {
            "apiVersion": module.API_VERSION,
            "kind": "PaperclipDaytonaControlPlaneEvidence",
            "status": "ready",
            "generatedAt": "2026-07-18T00:00:00Z",
            "producerSha256": "1" * 64,
            "canonicalSourceSha256": "2" * 64,
            "controlPlane": {
                "version": values["MTE_DAYTONA_CONTROL_PLANE_VERSION"],
                "sourceCommit": values["MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT"],
            },
            "sandboxVersion": values["MTE_DAYTONA_SANDBOX_VERSION"],
            "composeServices": [
                "agent-gateway",
                "api",
                "db",
                "dex",
                "minio",
                "proxy",
                "redis",
                "registry",
                "runner",
                "ssh-gateway",
            ],
            "runtimeEvidence": {
                "images": str(module.EVIDENCE_ROOT / "daytona-images.json"),
                "lifecycle": str(module.EVIDENCE_ROOT / "daytona-lifecycle.json"),
            },
            "secretValuesPrinted": False,
        }
        module.validate_daytona_runtime_evidence(
            payload, "PaperclipDaytonaControlPlaneEvidence", values
        )
        payload["composeServices"].remove("agent-gateway")
        with self.assertRaises(module.ControlError):
            module.validate_daytona_runtime_evidence(
                payload, "PaperclipDaytonaControlPlaneEvidence", values
            )

    def test_control_plane_evidence_rejects_missing_extra_and_stale_schemas(self):
        values = canonical_values()
        current = {
            "apiVersion": module.API_VERSION,
            "kind": "PaperclipDaytonaControlPlaneEvidence",
            "status": "ready",
            "generatedAt": "2026-07-18T00:00:00Z",
            "producerSha256": "1" * 64,
            "canonicalSourceSha256": "2" * 64,
            "controlPlane": {
                "version": values["MTE_DAYTONA_CONTROL_PLANE_VERSION"],
                "sourceCommit": values["MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT"],
            },
            "sandboxVersion": values["MTE_DAYTONA_SANDBOX_VERSION"],
            "composeServices": [
                "agent-gateway",
                "api",
                "db",
                "dex",
                "minio",
                "proxy",
                "redis",
                "registry",
                "runner",
                "ssh-gateway",
            ],
            "runtimeEvidence": {
                "images": str(module.EVIDENCE_ROOT / "daytona-images.json"),
                "lifecycle": str(module.EVIDENCE_ROOT / "daytona-lifecycle.json"),
            },
            "secretValuesPrinted": False,
        }
        module.validate_daytona_runtime_evidence(
            current, "PaperclipDaytonaControlPlaneEvidence", values
        )
        missing = dict(current)
        missing.pop("sandboxVersion")
        extra = {**current, "legacySchema": True}
        stale = {
            key: value
            for key, value in current.items()
            if key not in {"controlPlane", "sandboxVersion"}
        }
        for payload in (missing, extra, stale):
            with self.assertRaises(module.ControlError):
                module.validate_daytona_runtime_evidence(
                    payload, "PaperclipDaytonaControlPlaneEvidence", values
                )

    def test_company_secret_scope_requires_distinct_local_encrypted_records(self):
        company_id = "company-unit"
        profiles = []
        secrets = []
        for index, profile_ref in enumerate(module.DAYTONA_PROFILE_REFS, 1):
            runtime_id = f"runtime-{index}"
            toolhive_id = f"toolhive-{index}"
            profiles.append(
                {
                    "profileRef": profile_ref,
                    "runtimeSecretId": runtime_id,
                    "toolhiveSecretId": toolhive_id,
                    "envKeys": ["GITHUB_TOKEN", "OPENAI_API_KEY"],
                }
            )
            for secret_id in (runtime_id, toolhive_id):
                secrets.append(
                    {
                        "id": secret_id,
                        "companyId": company_id,
                        "provider": "local_encrypted",
                    }
                )
        secrets.append(
            {
                "id": "daytona-api-key",
                "companyId": company_id,
                "provider": "local_encrypted",
            }
        )
        proof = module.validate_company_secret_scopes(
            secrets,
            company_id=company_id,
            daytona_secret_id="daytona-api-key",
            profile_bindings=profiles,
        )
        self.assertEqual(proof["distinctCompanySecretIdCount"], 7)
        self.assertEqual(proof["unsafeInlineBindings"], [])
        self.assertFalse(proof["rawValuesIncluded"])
        secrets[0]["provider"] = "env"
        with self.assertRaisesRegex(module.ControlError, "provider"):
            module.validate_company_secret_scopes(
                secrets,
                company_id=company_id,
                daytona_secret_id="daytona-api-key",
                profile_bindings=profiles,
            )

    def test_r1_profile_contract_rejects_a_partial_harness_catalog(self):
        catalog = mock.Mock()
        catalog.refs = ("coding-daytona-pi",)
        catalog.require.return_value = copy.deepcopy(
            module.DEFAULT_PROFILE_CATALOG.require("coding-daytona-pi")
        )
        with self.assertRaisesRegex(
            module.ControlError, "exactly Codex, Claude, and Pi"
        ):
            module.required_daytona_profile_refs(catalog, canonical_values())

    def test_daytona_step_records_full_canonical_hash_and_credential_probe(self):
        source = (ROOT / "deployment/steps/daytona.sh").read_text()
        self.assertIn('canonical_sha=$(sha256sum "$ENV_FILE"', source)
        self.assertIn("credentialFileProbe", source)
        self.assertIn('workspace:"/home/daytona/paperclip-workspace"', source)
        self.assertIn('const harnesses=["codex","claude","pi"]', source)
        self.assertIn('versionOutput:exec(name+" --version")', source)
        self.assertIn("cleanupDeleted=true", source)

    def test_driver_config_hash_covers_complete_sanitized_observed_contract(self):
        raw = {
            "provider": "daytona",
            "apiKey": "company-secret-id",
            "apiUrl": "http://127.0.0.1:3310/api",
            "target": "us",
            "snapshot": "mte-coding-harness-v1",
            "timeoutMs": 300000,
            "reuseLease": True,
        }
        normalized = module.normalized_driver_config(raw)
        self.assertEqual(
            set(normalized),
            {
                "provider",
                "apiKeySecretId",
                "apiUrl",
                "target",
                "snapshot",
                "image",
                "memory",
                "disk",
                "timeoutMs",
                "reuseLease",
            },
        )
        self.assertEqual(normalized["apiKeySecretId"], "company-secret-id")
        self.assertNotIn("apiKey", normalized)
        digest = module.canonical_json_sha256(normalized)
        changed = dict(normalized, timeoutMs=1)
        self.assertNotEqual(digest, module.canonical_json_sha256(changed))

    def test_driver_config_normalization_ignores_provider_owned_defaults(self):
        canonical = {
            "provider": "daytona",
            "apiKey": "company-secret-id",
            "apiUrl": "http://127.0.0.1:3310/api",
            "target": "us",
            "snapshot": "mte-coding-harness-v1",
            "timeoutMs": 300000,
            "reuseLease": True,
        }
        observed = {
            **canonical,
            "autoArchiveInterval": 60,
            "autoDeleteInterval": 10080,
            "autoStopInterval": 15,
            "cpu": None,
            "gpu": None,
            "language": None,
            "image": None,
            "memory": None,
            "disk": None,
        }
        self.assertEqual(
            module.normalized_driver_config(observed),
            module.normalized_driver_config(canonical),
        )

    def test_installed_plugin_proof_requires_manifest_and_full_content_hashes(self):
        payload = {
            "name": "@paperclipai/plugin-daytona",
            "version": "0.1.0",
            "packagePath": "/app/plugins/daytona",
            "manifestSha256": "1" * 64,
            "contentSha256": "2" * 64,
            "contentScope": "package-files-excluding-node_modules",
            "fileCount": 17,
        }
        completed = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps(payload), stderr=""
        )
        with mock.patch.object(module.subprocess, "run", return_value=completed):
            proof = module.installed_plugin_package_proof(payload["name"])
            self.assertEqual(proof, payload)
        payload["manifestSha256"] = "truncated"
        completed.stdout = json.dumps(payload)
        with (
            mock.patch.object(module.subprocess, "run", return_value=completed),
            self.assertRaises(module.ControlError),
        ):
            module.installed_plugin_package_proof(payload["name"])
        payload["manifestSha256"] = "1" * 64
        payload.pop("contentScope")
        completed.stdout = json.dumps(payload)
        with (
            mock.patch.object(module.subprocess, "run", return_value=completed),
            self.assertRaises(module.ControlError),
        ):
            module.installed_plugin_package_proof(payload["name"])


if __name__ == "__main__":
    unittest.main()

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
        "DAYTONA_TARGET": "us",
        "MTE_DAYTONA_SANDBOX_BASE_IMAGE": "daytonaio/sandbox:0.8.0",
        "MTE_CODEX_VERSION": "0.144.4",
        "MTE_CLAUDE_CODE_VERSION": "2.1.209",
        "MTE_PI_VERSION": "0.80.7",
        "MTE_CODEX_NPM_INTEGRITY": "sha512-" + "a" * 88,
        "MTE_CLAUDE_CODE_NPM_INTEGRITY": "sha512-" + "b" * 88,
        "MTE_PI_NPM_INTEGRITY": "sha512-" + "c" * 88,
        "MTE_TOOLHIVE_VERSION": "0.36.0",
        "MTE_TOOLHIVE_ARCHIVE_SHA256": "a" * 64,
        "MTE_GITHUB_CLI_VERSION": "2.96.0",
        "MTE_GITHUB_CLI_ARCHIVE_SHA256": "b" * 64,
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
        "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_PROXY_PORT": "19011",
        "TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_PROXY_PORT": "19012",
        "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_PROXY_PORT": "19013",
        "PROFILE_CODING_DAYTONA_CODEX_PACKAGE_CODEX_VERSION": "0.144.4",
        "PROFILE_CODING_DAYTONA_CLAUDE_PACKAGE_CLAUDECODE_VERSION": "2.1.209",
        "PROFILE_CODING_DAYTONA_PI_PACKAGE_PI_VERSION": "0.80.7",
    }


class PaperclipExperimentalEvidenceTests(unittest.TestCase):
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

    def test_environment_probe_pass_status_remains_accepted(self):
        self.assertEqual(
            module.accepted_environment_probe(
                "coding-daytona-codex", {"status": "pass"}
            ),
            (True, []),
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
                "checks": [
                    {"code": "codex_hello_probe_failed", "level": "error"}
                ],
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

    def test_plugin_install_uses_npm_package_version_not_manifest_version(self):
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
                "2026.707.0",
            )

        self.assertEqual(plugin, ready_plugin)
        self.assertIn(
            (
                "POST",
                "/api/plugins/install",
                {
                    "packageName": "@paperclipai/plugin-daytona",
                    "version": "2026.707.0",
                    "isLocalPath": False,
                },
            ),
            requests,
        )

    def test_plugin_purges_then_reinstalls_when_npm_package_version_drifted(self):
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
            mock.patch.object(
                module,
                "installed_plugin_package_proof",
                return_value={"version": "0.1.0"},
            ),
            mock.patch.object(module, "json_request", side_effect=json_response),
        ):
            module.ensure_daytona_plugin(
                "http://paperclip.test",
                "@paperclipai/plugin-daytona",
                "0.1.0",
                "2026.707.0",
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
                        "packageName": "@paperclipai/plugin-daytona",
                        "version": "2026.707.0",
                        "isLocalPath": False,
                    },
                ),
            ],
        )

    def test_plugin_enables_existing_errored_exact_package_without_reinstall(self):
        errored = {
            "packageName": "@paperclipai/plugin-daytona",
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
            mock.patch.object(
                module,
                "installed_plugin_package_proof",
                return_value={"version": "2026.707.0"},
            ),
            mock.patch.object(module, "json_request", side_effect=json_response),
        ):
            observed = module.ensure_daytona_plugin(
                "http://paperclip.test",
                "@paperclipai/plugin-daytona",
                "0.1.0",
                "2026.707.0",
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
            expected_contract = {
                key: values.get(key, "")
                for key in sorted(module.DAYTONA_IMAGE_CONTRACT_KEYS)
            }
            images = {
                "snapshots": [
                    {
                        "id": "snapshot-coding",
                        "name": values["MTE_DAYTONA_CODING_SNAPSHOT"],
                        "state": "active",
                        "cpu": 1,
                        "memoryGiB": 2,
                        "diskGiB": 20,
                        "digest": "sha256:" + "c" * 64,
                    },
                    {
                        "id": "snapshot-general",
                        "name": values["MTE_DAYTONA_GENERAL_SNAPSHOT"],
                        "state": "active",
                        "cpu": 1,
                        "memoryGiB": 1,
                        "diskGiB": 20,
                        "digest": "sha256:" + "d" * 64,
                    },
                ],
                "harnessVersions": {
                    "codex": values["MTE_CODEX_VERSION"],
                    "claudeCode": values["MTE_CLAUDE_CODE_VERSION"],
                    "pi": values["MTE_PI_VERSION"],
                    "toolhive": values["MTE_TOOLHIVE_VERSION"],
                    "githubCli": values["MTE_GITHUB_CLI_VERSION"],
                },
                "packageIntegrity": module.expected_package_integrity(values),
                "imageContract": expected_contract,
                "imageContractHash": module.canonical_json_sha256(expected_contract),
                "canonicalBinding": {
                    "imageContractUnchanged": True,
                    "fullCanonicalHashAfterReadinessMerge": hashlib.sha256(
                        canonical.read_bytes()
                    ).hexdigest(),
                },
                "credentialsBakedIntoImage": False,
            }
            with mock.patch.object(module, "PLATFORM_ENV", canonical):
                module.validate_daytona_runtime_evidence(
                    images, "DaytonaHarnessSnapshots", values
                )
                images["snapshots"][0]["digest"] = "sha256:truncated"
                with self.assertRaises(module.ControlError):
                    module.validate_daytona_runtime_evidence(
                        images, "DaytonaHarnessSnapshots", values
                    )

            resources = {"cpu": 1, "memory": 2, "disk": 20}
            marker_sha = "e" * 64
            lifecycle = {
                "states": [
                    {"phase": phase, "state": state}
                    for phase, state in module.DAYTONA_LIFECYCLE_STATES
                ],
                "provider": "daytona",
                "target": values["DAYTONA_TARGET"],
                "snapshot": values["MTE_DAYTONA_CODING_SNAPSHOT"],
                "credentialsBakedIntoImage": False,
                "fileRoundTrip": {"verified": True, "markerSha256": marker_sha},
                "markerSha256": marker_sha,
                "persistence": {
                    "verified": True,
                    "afterRestart": True,
                    "afterArchiveRestore": True,
                },
                "resources": {
                    "expected": resources,
                    "actual": resources,
                    "equal": True,
                },
                "agentGateway": {
                    "expectedHost": values["MTE_AGENT_GATEWAY_HOST"],
                    "observedDefaultGateway": values["MTE_AGENT_GATEWAY_HOST"],
                    "matchesCanonical": True,
                },
                "harnessVersionOutput": [
                    f"codex {values['MTE_CODEX_VERSION']}",
                    f"claude {values['MTE_CLAUDE_CODE_VERSION']}",
                    f"pi {values['MTE_PI_VERSION']}",
                    f"thv {values['MTE_TOOLHIVE_VERSION']}",
                    f"gh version {values['MTE_GITHUB_CLI_VERSION']}",
                ],
                "github": {
                    "cliVersion": values["MTE_GITHUB_CLI_VERSION"],
                    "authentication": "GH_TOKEN-runtime-env",
                    "gitCredentialHelper": "gh auth git-credential",
                    "gitIdentity": {
                        "name": "Paperclip Agent",
                        "email": "paperclip-agent@users.noreply.github.com",
                    },
                    "tokenInRemoteUrl": False,
                    "credentialFilePersisted": False,
                },
                "cleanupDeleted": True,
                "delete": {"requested": True, "getAfterDeleteStatus": 404},
                "credentialFileProbe": {
                    "checkedPaths": ["/home/daytona/.codex/auth.json"],
                    "foundPaths": [],
                    "credentialFree": True,
                },
                "workspaceDirectoryProbe": {
                    "checkedPaths": [
                        f"/home/daytona/workspaces/{profile_ref}"
                        for profile_ref in module.DAYTONA_PROFILE_REFS
                    ],
                    "missingPaths": [],
                    "allPresent": True,
                },
                "piProbeConfig": {
                    "path": "/home/daytona/.pi/mte-profile/models.json",
                    "sha256": marker_sha,
                    "apiKeyReference": "$OPENAI_API_KEY",
                    "secretEmbedded": False,
                },
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

    def test_control_plane_requires_exact_three_private_gateway_profiles(self):
        values = canonical_values()
        profiles = []
        for profile_ref, harness, upstream_port in (
            ("coding-daytona-codex", "CODEX", 19011),
            ("coding-daytona-claude", "CLAUDE", 19012),
            ("coding-daytona-pi", "PI", 19013),
        ):
            profiles.append(
                {
                    "profileRef": profile_ref,
                    "upstreamRef": f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_UPSTREAM",
                    "host": "toolhive",
                    "port": upstream_port,
                    "gatewayPort": int(
                        values[f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_PORT"]
                    ),
                    "httpStatus": 200,
                    "initialize": True,
                }
            )
        payload = {
            "action": "verify",
            "secretValuesPrinted": False,
            "agentGateway": {
                "status": "passed",
                "profileCount": 3,
                "runnerContainerId": "1" * 64,
                "gatewayContainerId": "2" * 64,
                "gatewayNetworkMode": "container:" + "1" * 64,
                "runnerNetworks": [
                    "mte-agent-plane",
                    "mte-daytona-net",
                    "mte-tool-runtime",
                ],
                "expectedRunnerNetworks": [
                    "mte-agent-plane",
                    "mte-daytona-net",
                    "mte-tool-runtime",
                ],
                "privateToolRuntimeNetwork": "mte-tool-runtime",
                "noPublishedPorts": True,
                "profiles": profiles,
            },
        }
        module.validate_daytona_runtime_evidence(
            payload, "PaperclipDaytonaControlPlaneEvidence", values
        )
        profiles[1]["initialize"] = False
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

    def test_daytona_step_records_full_canonical_hash_and_credential_probe(self):
        source = (ROOT / "deployment/steps/60-daytona.sh").read_text()
        self.assertIn('canonical_sha=$(sha256sum "$ENV_FILE"', source)
        self.assertIn('"action":"verify"', source)
        self.assertIn("credentialFileProbe", source)
        self.assertIn("workspaceDirectoryProbe", source)
        self.assertIn("mte-coding-harness-v3", source)
        self.assertIn("$OPENAI_API_KEY", source)
        self.assertIn("coding-daytona-pi", source)
        self.assertIn("getAfterDeleteStatus !== 404", source)
        self.assertNotIn(
            '"canonicalSourceSha256":sys.argv[3],"canonicalConfigHash":sys.argv[3]',
            source,
        )

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
            "version": "2026.707.0",
            "manifestSha256": "1" * 64,
            "contentSha256": "2" * 64,
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


if __name__ == "__main__":
    unittest.main()

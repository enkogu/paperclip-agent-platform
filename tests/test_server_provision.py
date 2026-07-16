import importlib.util
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "mte_server_provision", ROOT / "tools/platform-cli/server-provision.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class HarnessRouterAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def context(self, values):
        return self.module.Context(
            config={
                "spec": {
                    "components": [
                        {
                            "id": "9router",
                            "exposure": {"origin": "http://127.0.0.1:20128"},
                        }
                    ]
                }
            },
            platform_env=values,
            mutate=False,
            strict=True,
        )

    def test_all_harnesses_use_profile_scoped_router_runtime_keys(self):
        for harness in ("claude", "codex", "pi"):
            with self.subTest(harness=harness):
                key_ref = (
                    "NINEROUTER_PROFILE_CODING_DAYTONA_" + harness.upper() + "_API_KEY"
                )
                value = self.module.harness_router_auth_status(
                    self.context(
                        {
                            key_ref: "unit-only-secret",
                            "HERMES_LLM_MODEL": "mte-minimax/test-model",
                        }
                    ),
                    harness,
                )
                self.assertEqual(value["status"], "ready")
                self.assertEqual(value["method"], "profile_scoped_9router_runtime_key")
                self.assertEqual(value["keyRef"], key_ref)
                self.assertEqual(value["baseUrl"], "http://127.0.0.1:20128/v1")
                self.assertFalse(value["nativeSubscriptionCredential"])
                self.assertNotIn("unit-only-secret", str(value))

    def test_missing_scoped_key_is_configuration_failure_not_oauth(self):
        value = self.module.harness_router_auth_status(
            self.context({"HERMES_LLM_MODEL": "mte-minimax/test-model"}), "codex"
        )
        self.assertEqual(value["status"], "needs_configuration")
        self.assertFalse(value["nativeSubscriptionCredential"])

    def test_stale_interactive_subscription_contract_is_absent(self):
        source = (ROOT / "tools/platform-cli/server-provision.py").read_text()
        self.assertNotIn("interactive_9router_oauth", source)
        self.assertNotIn("HARNESS_CODEX_AUTH_REF", source)
        self.assertNotIn("HARNESS_CLAUDE_AUTH_REF", source)

    def test_canonical_renderer_is_loaded_from_synced_server_bin(self):
        self.assertEqual(
            self.module.CONFIG_RENDERER,
            self.module.ROOT / "bin/server-config.py",
        )

    def test_api_error_reports_only_safe_method_and_path(self):
        request_url = (
            "http://paperclip.test/api/agents/agent-id?companyId=company-id"
            "&token=must-not-appear"
        )
        opener = mock.Mock()
        opener.open.side_effect = self.module.urllib.error.HTTPError(
            request_url,
            422,
            "unprocessable",
            hdrs=None,
            fp=io.BytesIO(
                b'{"error":"unit validation message","token":"must-not-appear"}'
            ),
        )
        with self.assertRaises(self.module.ApiError) as raised:
            self.module.request_json(
                "PATCH",
                request_url,
                body={"value": "must-not-appear"},
                opener=opener,
            )
        error = raised.exception
        self.assertEqual(error.status, 422)
        self.assertEqual(error.operation, "PATCH /api/agents/agent-id")
        rendered = self.module.component_error("paperclip", error)
        self.assertEqual(rendered["operation"], "PATCH /api/agents/agent-id")
        self.assertEqual(
            rendered["responseErrorSha256"],
            hashlib.sha256(b"unit validation message").hexdigest(),
        )
        self.assertEqual(rendered["responseErrorLength"], 23)
        self.assertNotIn("token", json.dumps(rendered))
        self.assertNotIn("must-not-appear", json.dumps(rendered))


class ManagedIntegrationCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_alert_webhook_is_named_and_uses_managed_channel(self):
        ctx = self.module.Context(
            config={
                "spec": {
                    "components": [
                        {
                            "id": "mattermost",
                            "exposure": {"origin": "http://127.0.0.1:18065"},
                        }
                    ]
                }
            },
            platform_env={},
            mutate=True,
            strict=True,
        )
        calls = []

        def api(method, url, **kwargs):
            calls.append((method, url, kwargs.get("body")))
            if "/channels/name/mte-alerts" in url:
                return {"id": "channel-id"}
            if "/hooks/incoming?" in url:
                return []
            if method == "POST" and url.endswith("/api/v4/hooks/incoming"):
                return {"id": "hook-id"}
            raise AssertionError((method, url))

        with (
            mock.patch.object(self.module, "mmctl_config_set") as config_set,
            mock.patch.object(
                self.module,
                "mattermost_admin_session",
                return_value=({"Authorization": "Bearer unit"}, {"id": "admin"}),
            ),
            mock.patch.object(self.module, "request_json", side_effect=api),
        ):
            value = self.module.ensure_mattermost_alert_webhook(
                ctx,
                {
                    "MATTERMOST_ADMIN_USERNAME": "mte-admin",
                    "MATTERMOST_ADMIN_PASSWORD": "unit-only-password",
                },
                container="mattermost",
                team_id="team-id",
            )

        config_set.assert_called_once_with(
            "mattermost", "ServiceSettings.EnableIncomingWebhooks", "true"
        )
        self.assertEqual(
            value["MATTERMOST_ALERT_WEBHOOK_URL"],
            "http://127.0.0.1:18065/hooks/hook-id",
        )
        create = next(row for row in calls if row[0] == "POST")
        self.assertEqual(create[2]["display_name"], "MTE Alertmanager")


class CanonicalMutationGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def context(self, values, *, mutate=True, authorized=frozenset()):
        return self.module.Context(
            config={"spec": {"components": []}},
            platform_env=dict(values),
            mutate=mutate,
            strict=True,
            canonical_mutation_keys=frozenset(authorized),
        )

    def test_component_local_write_fails_before_canonical_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "platform.env"
            source.write_text("EXISTING=value\n")
            source.chmod(0o600)
            before = hashlib.sha256(source.read_bytes()).hexdigest()
            with (
                mock.patch.object(self.module, "PLATFORM_ENV", source),
                mock.patch.object(self.module, "PLATFORM_LOCK", root / ".lock"),
            ):
                ctx = self.context({"EXISTING": "value"})
                with self.assertRaisesRegex(
                    RuntimeError, "canonical_mutation_not_authorized:NEW_KEY"
                ):
                    ctx.persist_canonical({"NEW_KEY": "generated"})
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)

    def test_pre_authorized_key_is_written_and_audited(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "platform.env"
            source.write_text("EXISTING=value\n")
            source.chmod(0o600)
            with (
                mock.patch.object(self.module, "PLATFORM_ENV", source),
                mock.patch.object(self.module, "PLATFORM_LOCK", root / ".lock"),
            ):
                ctx = self.context({"EXISTING": "value"}, authorized={"NEW_KEY"})
                ctx.persist_canonical({"NEW_KEY": "generated"})
            self.assertEqual(ctx.canonical_mutations, {"NEW_KEY"})
            self.assertIn("NEW_KEY=generated", source.read_text())

    def test_read_only_context_rejects_even_pre_authorized_write(self):
        ctx = self.context({}, mutate=False, authorized={"NEW_KEY"})
        with self.assertRaisesRegex(RuntimeError, "canonical_write_in_read_only_mode"):
            ctx.persist_canonical({"NEW_KEY": "generated"})

    def test_plan_predicts_paperclip_secret_metadata_not_arbitrary_keys(self):
        values = {
            "MATTERMOST_BOT_TOKEN": "unit-only-token",
            "NINEROUTER_PROFILE_CODING_DAYTONA_CODEX_API_KEY": "unit-only-key",
            "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN": "unit-tool-token",
        }
        plan = self.module.canonical_mutation_plan(values)
        self.assertIn("PAPERCLIP_SECRET_MTE_MATTERMOST_BOT_ID", plan)
        self.assertIn("PAPERCLIP_SECRET_MTE_MATTERMOST_BOT_SOURCE_FINGERPRINT", plan)
        self.assertIn(
            "PAPERCLIP_SECRET_MTE_TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_ID",
            plan,
        )
        self.assertNotIn("UNRELATED_KEY", plan)


class PaperclipDeclarativeBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def context(self):
        return self.module.Context(
            config={
                "spec": {
                    "components": [
                        {
                            "id": "9router",
                            "exposure": {
                                "origin": "http://sandbox-router.internal:20128"
                            },
                        }
                    ]
                }
            },
            platform_env={
                "HERMES_LLM_MODEL": "mte-minimax/unit-model",
                "MTE_AGENT_GATEWAY_HOST": "172.20.0.1",
                "MTE_AGENT_GATEWAY_NINEROUTER_BASE_URL": "http://172.20.0.1:22080",
                "MTE_AGENT_GATEWAY_NINEROUTER_PORT": "22080",
                "MTE_PI_CODING_AGENT_DIR": "/home/daytona/.pi/mte-profile",
                "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_PORT": "22081",
                "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_PORT": "22082",
                "MTE_AGENT_GATEWAY_TOOLHIVE_PI_PORT": "22083",
                "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL": "http://172.20.0.1:22081/mcp",
                "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_URL": "http://172.20.0.1:22082/mcp",
                "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL": "http://172.20.0.1:22083/mcp",
            },
            mutate=False,
            strict=True,
        )

    def test_exact_secret_ref_env_and_writable_cwd_for_three_native_profiles(self):
        cases = {
            "coding-daytona-codex": (
                "codex_local",
                {
                    "GH_TOKEN",
                    "GITHUB_TOKEN",
                    "MTE_TOOLHIVE_BEARER_TOKEN",
                    "MTE_TOOLHIVE_WRONG_PROFILE_MCP_URL",
                    "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
                    "MTE_TOOLHIVE_BUNDLE_ID",
                    "MTE_TOOLHIVE_WORKLOAD_ID",
                    "MTE_TOOLHIVE_ENDPOINT_REF",
                    "MTE_TOOLHIVE_BINDING_REF",
                    "MTE_TOOLHIVE_CANARY_TOOL",
                    "OPENAI_API_KEY",
                    "OPENAI_BASE_URL",
                    "PAPERCLIP_CODEX_PROVIDERS",
                },
            ),
            "coding-daytona-claude": (
                "claude_local",
                {
                    "ANTHROPIC_API_KEY",
                    "ANTHROPIC_BASE_URL",
                    "GH_TOKEN",
                    "GITHUB_TOKEN",
                    "MTE_TOOLHIVE_BEARER_TOKEN",
                    "MTE_TOOLHIVE_WRONG_PROFILE_MCP_URL",
                    "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_URL",
                    "MTE_TOOLHIVE_BUNDLE_ID",
                    "MTE_TOOLHIVE_WORKLOAD_ID",
                    "MTE_TOOLHIVE_ENDPOINT_REF",
                    "MTE_TOOLHIVE_BINDING_REF",
                    "MTE_TOOLHIVE_CANARY_TOOL",
                },
            ),
            "coding-daytona-pi": (
                "pi_local",
                {
                    "GH_TOKEN",
                    "GITHUB_TOKEN",
                    "MTE_TOOLHIVE_BEARER_TOKEN",
                    "MTE_TOOLHIVE_WRONG_PROFILE_MCP_URL",
                    "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL",
                    "MTE_TOOLHIVE_BUNDLE_ID",
                    "MTE_TOOLHIVE_WORKLOAD_ID",
                    "MTE_TOOLHIVE_ENDPOINT_REF",
                    "MTE_TOOLHIVE_BINDING_REF",
                    "MTE_TOOLHIVE_CANARY_TOOL",
                    "OPENAI_API_KEY",
                    "OPENAI_BASE_URL",
                    "PAPERCLIP_PI_PROVIDERS",
                    "PI_CODING_AGENT_DIR",
                },
            ),
        }
        for ref, (adapter_type, expected_keys) in cases.items():
            with self.subTest(profile=ref):
                harness = ref.rsplit("-", 1)[-1].upper()
                desired = self.module.paperclip_desired_adapter_config(
                    self.context(),
                    company_id="company-unit",
                    agent_id="agent-unit",
                    profile={
                        "nativeAdapterConfig": {
                            "cwd": f"/home/daytona/workspaces/{ref}",
                            "model": "unit-model",
                        },
                        "mcpPolicy": {"allow": ["github"]},
                        "toolRouting": {
                            "mcpUrlRef": f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_URL",
                            "bearerTokenRef": f"TOOLHIVE_PROFILE_CODING_DAYTONA_{harness}_BEARER_TOKEN",
                        },
                        "toolAccess": {
                            "bundleId": f"mte-profile-{ref}",
                            "workloadId": f"mte-profile-{harness.lower()}",
                            "endpointRef": f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_URL",
                            "credentialRef": f"TOOLHIVE_PROFILE_CODING_DAYTONA_{harness}_BEARER_TOKEN",
                            "canaryTool": "echo",
                        },
                    },
                    adapter_type=adapter_type,
                    router_secret_id="secret-id-unit",
                    toolhive_secret_id="toolhive-secret-id-unit",
                    existing={
                        "cwd": "/workspaces/stale",
                        "env": {"OPENAI_API_KEY": "raw-stale-secret"},
                    },
                )
                env = desired["env"]
                self.assertEqual(set(env), expected_keys)
                self.assertEqual(desired["cwd"], f"/home/daytona/workspaces/{ref}")
                runtime_key = (
                    "ANTHROPIC_API_KEY"
                    if adapter_type == "claude_local"
                    else "OPENAI_API_KEY"
                )
                self.assertEqual(env[runtime_key]["type"], "secret_ref")
                self.assertEqual(env["MTE_TOOLHIVE_BEARER_TOKEN"]["type"], "secret_ref")
                self.assertEqual(
                    env[f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_URL"]["value"],
                    f"http://172.20.0.1:{22081 + ['CODEX', 'CLAUDE', 'PI'].index(harness)}/mcp",
                )
                wrong_harness = {
                    "CODEX": "CLAUDE",
                    "CLAUDE": "PI",
                    "PI": "CODEX",
                }[harness]
                self.assertEqual(
                    env["MTE_TOOLHIVE_WRONG_PROFILE_MCP_URL"],
                    {
                        "type": "plain",
                        "value": "http://172.20.0.1:"
                        + str(22081 + ["CODEX", "CLAUDE", "PI"].index(wrong_harness))
                        + "/mcp",
                    },
                )
                self.assertEqual(env["GITHUB_TOKEN"]["type"], "user_secret_ref")
                self.assertEqual(env["GH_TOKEN"], env["GITHUB_TOKEN"])
                self.assertNotIn("raw-stale-secret", json.dumps(desired))
                if adapter_type == "pi_local":
                    self.assertEqual(
                        env["PI_CODING_AGENT_DIR"],
                        {
                            "type": "plain",
                            "value": "/home/daytona/.pi/mte-profile",
                        },
                    )
                    provider_config = json.loads(env["PAPERCLIP_PI_PROVIDERS"]["value"])
                    self.assertEqual(set(provider_config), {"mte9router"})
                    self.assertEqual(
                        provider_config["mte9router"],
                        {
                            "baseUrl": "http://172.20.0.1:22080/v1",
                            "apiKey": "{env:OPENAI_API_KEY}",
                            "api": "openai-completions",
                            "models": [
                                {
                                    "id": "mte-minimax/unit-model",
                                    "name": "MTE MiniMax",
                                    "reasoning": False,
                                    "input": ["text"],
                                    "cost": {
                                        "input": 0,
                                        "output": 0,
                                        "cacheRead": 0,
                                        "cacheWrite": 0,
                                    },
                                    "contextWindow": 200000,
                                    "maxTokens": 32768,
                                }
                            ],
                        },
                    )

    def test_codex_preserves_only_paperclip_managed_isolated_home(self):
        profile = {
            "nativeAdapterConfig": {"cwd": "/home/daytona/workspaces/codex"},
            "mcpPolicy": {"allow": []},
            "toolRouting": {
                "mcpUrlRef": "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
                "bearerTokenRef": "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN",
            },
            "toolAccess": {
                "bundleId": "mte-profile-codex",
                "workloadId": "mte-profile-codex",
                "endpointRef": "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
                "credentialRef": "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN",
                "canaryTool": "echo",
            },
        }
        managed_home = "/data/instances/default/companies/company-unit/agents/agent-unit/codex-home"
        desired = self.module.paperclip_desired_adapter_config(
            self.context(),
            company_id="company-unit",
            agent_id="agent-unit",
            profile=profile,
            adapter_type="codex_local",
            router_secret_id="router-secret",
            toolhive_secret_id="tool-secret",
            existing={
                "env": {
                    "CODEX_HOME": {"type": "plain", "value": managed_home},
                }
            },
        )
        self.assertEqual(desired["env"]["CODEX_HOME"]["value"], managed_home)

        unsafe = self.module.paperclip_desired_adapter_config(
            self.context(),
            company_id="company-unit",
            agent_id="agent-unit",
            profile=profile,
            adapter_type="codex_local",
            router_secret_id="router-secret",
            toolhive_secret_id="tool-secret",
            existing={
                "env": {"CODEX_HOME": {"type": "plain", "value": "/tmp/operator"}}
            },
        )
        self.assertNotIn("CODEX_HOME", unsafe["env"])

    def test_codex_binding_readiness_uses_post_patch_managed_home(self):
        profile = {
            "nativeAdapterConfig": {"cwd": "/home/daytona/workspaces/codex"},
            "mcpPolicy": {"allow": []},
            "toolRouting": {
                "mcpUrlRef": "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
                "bearerTokenRef": "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN",
            },
            "toolAccess": {
                "bundleId": "mte-profile-codex",
                "workloadId": "mte-profile-codex",
                "endpointRef": "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
                "credentialRef": "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN",
                "canaryTool": "echo",
            },
        }
        managed_home = "/data/instances/default/companies/company-unit/agents/agent-unit/codex-home"
        observed = self.module.paperclip_desired_adapter_config(
            self.context(),
            company_id="company-unit",
            agent_id="agent-unit",
            profile=profile,
            adapter_type="codex_local",
            router_secret_id="router-secret",
            toolhive_secret_id="tool-secret",
            existing={
                "cwd": "/home/daytona/workspaces/codex",
                "env": {"CODEX_HOME": {"type": "plain", "value": managed_home}},
            },
        )
        desired_after_patch = self.module.paperclip_desired_adapter_config(
            self.context(),
            company_id="company-unit",
            agent_id="agent-unit",
            profile=profile,
            adapter_type="codex_local",
            router_secret_id="router-secret",
            toolhive_secret_id="tool-secret",
            existing=observed,
        )
        self.assertTrue(
            self.module.paperclip_adapter_binding_ready(
                observed,
                desired_after_patch,
                router_secret_id="router-secret",
                toolhive_secret_id="tool-secret",
            )
        )

    def test_agent_gateway_rejects_host_loopback(self):
        ctx = self.context()
        ctx.platform_env["MTE_AGENT_GATEWAY_NINEROUTER_BASE_URL"] = (
            "http://127.0.0.1:22080"
        )
        with self.assertRaisesRegex(
            RuntimeError, "paperclip_agent_gateway_contract_invalid"
        ):
            self.module.paperclip_agent_gateway_contract(
                ctx,
                {
                    "toolRouting": {
                        "mcpUrlRef": "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
                        "bearerTokenRef": "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN",
                    },
                    "toolAccess": {
                        "bundleId": "mte-profile-coding-daytona-codex",
                        "workloadId": "mte-profile-codex",
                        "endpointRef": "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
                        "credentialRef": "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN",
                        "canaryTool": "echo",
                    },
                },
            )

    def test_verify_evidence_is_redacted_and_mode_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = root / "platform.env"
            evidence = root / "account-provisioning-verify.json"
            canonical.write_text("SAFE=value\n")
            canonical.chmod(0o600)
            value = {
                "ok": True,
                "components": [
                    {
                        "component": "paperclip",
                        "status": "ready",
                        "runtimeSecurity": {
                            "provider": "local_encrypted",
                            "strictMode": True,
                            "configMode": "600",
                            "llmApiKeyConfigured": False,
                        },
                        "companySecrets": [
                            {
                                "id": "secret-id",
                                "key": "mte.unit",
                                "fingerprint": "safe-fingerprint",
                            }
                        ],
                        "agentBindings": [],
                        "unsafeInlineBindings": [],
                    }
                ],
                "security": {"ok": True, "findings": []},
            }
            with (
                mock.patch.object(self.module, "PLATFORM_ENV", canonical),
                mock.patch.object(self.module, "PROVISION_VERIFY_EVIDENCE", evidence),
            ):
                result = self.module.write_provision_verify_evidence(value)
            payload = json.loads(evidence.read_text())
            self.assertEqual(result["mode"], "0o600")
            self.assertEqual(payload["status"], "passed")
            self.assertNotIn("unit-only-secret", evidence.read_text())

    def test_generated_runtime_catalog_precedes_stale_paperclip_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "runtime/profiles/profiles.yaml"
            stale = root / "runtime/paperclip/profiles/profiles.yaml"
            active.parent.mkdir(parents=True)
            stale.parent.mkdir(parents=True)
            active.write_text(yaml.safe_dump({"profiles": [{"ref": "active"}]}))
            stale.write_text(yaml.safe_dump({"profiles": [{"ref": "stale"}]}))
            with mock.patch.object(self.module, "ROOT", root):
                self.assertEqual(
                    [row["ref"] for row in self.module.profile_catalog()], ["active"]
                )

    def test_canonical_checkout_catalog_is_used_without_runtime_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "config/profiles/catalog.yaml"
            source.parent.mkdir(parents=True)
            source.write_text(yaml.safe_dump({"profiles": [{"ref": "canonical"}]}))
            with mock.patch.object(self.module, "ROOT", root):
                self.assertEqual(
                    [row["ref"] for row in self.module.profile_catalog()],
                    ["canonical"],
                )


class PostgresNotionProvisioningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def context(self, **extra):
        values = {
            "DATA_CONTENT_PROFILE": "postgres-notion",
            "POSTGREST_PAPERCLIP_TOKEN": "unit-postgrest-token",
            "NOTION_TOKEN": "unit-notion-token",
            "NOTION_API_BASE_URL": "https://api.notion.com/v1",
            "NOTION_API_VERSION": "2025-09-03",
            "NOTION_ROOT_PAGE_ID": "root-page-id",
            "NOTION_DOCUMENTS_PAGE_ID": "documents-page-id",
            "NOTION_TABLE_DATABASE_ID": "table-database-id",
            "NOTION_TABLE_DATA_SOURCE_ID": "table-data-source-id",
            **extra,
        }
        return self.module.Context(
            config={"spec": {"components": []}},
            platform_env=values,
            mutate=False,
            strict=True,
        )

    def test_company_secrets_are_distinct_local_encrypted_inputs(self):
        ctx = self.context()
        specs = {
            row["sourceKey"]: row for row in self.module.paperclip_secret_specs(ctx)
        }
        self.assertEqual(
            specs["POSTGREST_PAPERCLIP_TOKEN"]["key"], "mte.postgrest.paperclip"
        )
        self.assertEqual(specs["NOTION_TOKEN"]["key"], "mte.notion.connector")
        self.assertNotEqual(
            specs["POSTGREST_PAPERCLIP_TOKEN"]["key"],
            specs["NOTION_TOKEN"]["key"],
        )
        plan = self.module.canonical_mutation_plan(ctx.platform_env)
        for prefix in (
            "PAPERCLIP_SECRET_MTE_POSTGREST_PAPERCLIP",
            "PAPERCLIP_SECRET_MTE_NOTION_CONNECTOR",
        ):
            self.assertIn(f"{prefix}_ID", plan)
            self.assertIn(f"{prefix}_SOURCE_FINGERPRINT", plan)

    def test_agent_env_keeps_postgrest_write_but_never_receives_notion_token(self):
        ctx = self.context()
        reconciled = self.module.reconcile_data_content_paperclip_env(
            ctx,
            {
                "POSTGREST_API_TOKEN": "stale-postgrest-raw",
                "NOTION_TOKEN": "stale-notion-raw",
                "SAFE": {"type": "plain", "value": "kept"},
            },
            {
                "POSTGREST_PAPERCLIP_TOKEN": "postgrest-secret-id",
                "NOTION_TOKEN": "notion-secret-id",
            },
        )
        self.assertEqual(
            reconciled["POSTGREST_API_TOKEN"],
            self.module.paperclip_ref("postgrest-secret-id"),
        )
        self.assertNotIn("NOTION_TOKEN", reconciled)
        self.assertEqual(
            self.module.data_content_paperclip_bindings(ctx),
            (("POSTGREST_PAPERCLIP_TOKEN", "POSTGREST_API_TOKEN"),),
        )
        self.assertEqual(reconciled["SAFE"]["value"], "kept")
        serialized = json.dumps(reconciled)
        self.assertNotIn("stale-postgrest-raw", serialized)
        self.assertNotIn("stale-notion-raw", serialized)

    def test_reference_catalog_separates_ssot_and_external_capabilities(self):
        ctx = self.context()
        refs = self.module.build_refs(ctx, [])
        postgrest = refs["services"]["postgrest"]
        notion = refs["services"]["notion"]

        self.assertEqual(postgrest["role"], "internal_ssot_api")
        self.assertEqual(postgrest["authority"], "postgres")
        self.assertTrue(postgrest["capabilities"]["records"]["sourceOfTruth"])
        self.assertEqual(postgrest["agentCredentialBinding"], "paperclip_secret_ref")

        self.assertEqual(notion["role"], "external_presentation_provider")
        self.assertEqual(notion["authority"], "postgres")
        self.assertFalse(notion["sourceOfTruth"])
        self.assertEqual(notion["managedSecretProvider"], "local_encrypted")
        self.assertEqual(
            notion["agentCredentialBinding"], "toolhive_readonly_tools_only"
        )
        self.assertFalse(notion["agentRawCredential"])
        self.assertEqual(notion["connectorIdentity"], "mte.notion.connector")
        self.assertEqual(notion["connectorExecutable"], "server-notion.py")
        self.assertFalse(notion["connectorAgentReachable"])
        self.assertEqual(notion["connectorTokenKey"], "NOTION_TOKEN")
        self.assertEqual(
            notion["capabilities"]["tables"]["dataSourceIdKey"],
            "NOTION_TABLE_DATA_SOURCE_ID",
        )
        self.assertEqual(
            notion["capabilities"]["documents"]["parentPageIdKey"],
            "NOTION_DOCUMENTS_PAGE_ID",
        )
        self.assertNotEqual(
            notion["capabilities"]["tables"]["id"],
            notion["capabilities"]["documents"]["id"],
        )
        self.assertNotIn("unit-notion-token", json.dumps(refs))

    def test_legacy_optional_profiles_remain_available(self):
        baserow = self.context(DATA_CONTENT_PROFILE="baserow-wikijs")
        legacy_nocodb = self.context(
            DATA_CONTENT_PROFILE="postgres-postgrest-nocodb-nocodocs"
        )
        self.assertEqual(
            self.module.data_content_paperclip_bindings(baserow),
            (("BASEROW_PAPERCLIP_TOKEN", "BASEROW_API_TOKEN"),),
        )
        self.assertEqual(
            self.module.data_content_paperclip_bindings(legacy_nocodb),
            (("POSTGREST_PAPERCLIP_TOKEN", "POSTGREST_API_TOKEN"),),
        )
        self.assertIn("baserow", self.module.build_refs(baserow, [])["services"])
        self.assertIn("nocodb", self.module.build_refs(legacy_nocodb, [])["services"])


class NinerouterCustomModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def context(self):
        return self.module.Context(
            config={
                "spec": {
                    "components": [
                        {
                            "id": "9router",
                            "exposure": {"origin": "http://127.0.0.1:20128"},
                        }
                    ]
                }
            },
            platform_env={},
            mutate=True,
            strict=True,
        )

    def test_first_run_reconciles_exact_record_and_second_run_is_noop(self):
        records = []
        mutations = []

        def api(method, url, **kwargs):
            if url.endswith("/api/models/custom") and method == "GET":
                return {"models": list(records)}
            if "/api/models/custom?" in url and method == "DELETE":
                mutations.append((method, url))
                records.clear()
                return {"success": True}
            if url.endswith("/api/models/custom") and method == "POST":
                mutations.append((method, kwargs.get("body")))
                records.append(dict(kwargs["body"]))
                return {"success": True}
            if url.endswith("/v1/models") and method == "GET":
                return {
                    "data": [
                        {
                            "id": "mte-minimax/MiniMax-M2.7-highspeed",
                            "object": "model",
                        }
                    ]
                }
            if url.endswith("/v1/chat/completions") and method == "POST":
                self.assertEqual(
                    kwargs["body"]["model"],
                    "mte-minimax/MiniMax-M2.7-highspeed",
                )
                return {"choices": [{"message": {"content": "OK"}}]}
            raise AssertionError((method, url))

        ctx = self.context()
        with mock.patch.object(self.module, "request_json", side_effect=api):
            first = self.module.ensure_ninerouter_custom_model(
                ctx,
                mock.sentinel.opener,
                provider_alias="mte-minimax",
                model_id="MiniMax-M2.7-highspeed",
                client_token="unit-scoped-key",
            )
            first_mutation_count = len(mutations)
            second = self.module.ensure_ninerouter_custom_model(
                ctx,
                mock.sentinel.opener,
                provider_alias="mte-minimax",
                model_id="MiniMax-M2.7-highspeed",
                client_token="unit-scoped-key",
            )

        self.assertEqual(first["status"], "ready")
        self.assertEqual(second["status"], "ready")
        self.assertEqual(first["exactRecordCount"], 1)
        self.assertEqual(first["catalogExactCount"], 1)
        self.assertEqual(first["completion"], "passed")
        self.assertEqual(first_mutation_count, 2)
        self.assertEqual(len(mutations), first_mutation_count)
        self.assertEqual(
            records,
            [
                {
                    "providerAlias": "mte-minimax",
                    "id": "MiniMax-M2.7-highspeed",
                    "type": "llm",
                }
            ],
        )

    def test_status_rejects_duplicate_or_catalog_only_record(self):
        ctx = self.context()
        ctx.mutate = False
        records = [
            {
                "providerAlias": "mte-minimax",
                "id": "MiniMax-M2.7-highspeed",
                "type": "llm",
            },
            {
                "providerAlias": "mte-minimax",
                "id": "MiniMax-M2.7-highspeed",
                "type": "llm",
            },
        ]

        def api(method, url, **_kwargs):
            if url.endswith("/api/models/custom") and method == "GET":
                return {"models": records}
            if url.endswith("/v1/models") and method == "GET":
                return {"data": [{"id": "mte-minimax/MiniMax-M2.7-highspeed"}]}
            raise AssertionError((method, url))

        with mock.patch.object(self.module, "request_json", side_effect=api):
            value = self.module.ensure_ninerouter_custom_model(
                ctx,
                mock.sentinel.opener,
                provider_alias="mte-minimax",
                model_id="MiniMax-M2.7-highspeed",
                client_token="unit-scoped-key",
            )

        self.assertEqual(value["status"], "needs_configuration")
        self.assertEqual(value["exactRecordCount"], 2)
        self.assertEqual(value["completion"], "failed_or_not_attempted")

    def test_status_rejects_exact_catalog_when_completion_has_no_choices(self):
        ctx = self.context()
        ctx.mutate = False
        record = {
            "providerAlias": "mte-minimax",
            "id": "MiniMax-M2.7-highspeed",
            "type": "llm",
        }

        def api(method, url, **_kwargs):
            if url.endswith("/api/models/custom") and method == "GET":
                return {"models": [record]}
            if url.endswith("/v1/models") and method == "GET":
                return {"data": [{"id": "mte-minimax/MiniMax-M2.7-highspeed"}]}
            if url.endswith("/v1/chat/completions") and method == "POST":
                return {"choices": []}
            raise AssertionError((method, url))

        with mock.patch.object(self.module, "request_json", side_effect=api):
            value = self.module.ensure_ninerouter_custom_model(
                ctx,
                mock.sentinel.opener,
                provider_alias="mte-minimax",
                model_id="MiniMax-M2.7-highspeed",
                client_token="unit-scoped-key",
            )

        self.assertEqual(value["exactRecordCount"], 1)
        self.assertEqual(value["catalogExactCount"], 1)
        self.assertEqual(value["completion"], "failed_or_not_attempted")
        self.assertEqual(value["status"], "needs_configuration")


if __name__ == "__main__":
    unittest.main()

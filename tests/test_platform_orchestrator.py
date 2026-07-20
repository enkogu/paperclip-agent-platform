import argparse
from contextlib import ExitStack, nullcontext, redirect_stdout
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error
import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


platform = load_module("mte_platform", ROOT / "tools/platform-cli/platform.py")
server_config = load_module(
    "mte_server_config", ROOT / "tools/platform-cli/server-config.py"
)
server_secrets = load_module(
    "mte_server_secrets", ROOT / "tools/platform-cli/server-secrets.py"
)
experimental = load_module(
    "mte_paperclip_experimental",
    ROOT / "tools/platform-cli/server-paperclip-experimental.py",
)


class PlatformOrchestratorTests(unittest.TestCase):
    def tearDown(self):
        platform.OPERATOR_ENV_OVERRIDE = None

    def test_cloudflare_legacy_tunnel_projects_before_access_tokens_exist(self):
        tunnel = "legacy-tunnel-value"
        projected_tunnel, access = (
            server_config.cloudflare_runtime_credential_projections(
                {"CLOUDFLARE_TUNNEL_TOKEN": tunnel},
                {"firecrawl": "CLOUDFLARE_ACCESS_ROUTE_FIRECRAWL"},
                "a" * 64,
            )
        )

        self.assertEqual(projected_tunnel, tunnel)
        self.assertIsNone(access)

    def test_cloudflare_complete_route_tuples_build_access_projection(self):
        values = {"CLOUDFLARE_TUNNEL_TOKEN": "tunnel-value"}
        prefixes = {
            "firecrawl": "CLOUDFLARE_ACCESS_ROUTE_FIRECRAWL",
            "toolhive": "CLOUDFLARE_ACCESS_ROUTE_TOOLHIVE",
        }
        for index, prefix in enumerate(prefixes.values(), 1):
            values.update(
                {
                    prefix + "_ID": f"route-{index}",
                    prefix + "_CLIENT_ID": f"client-{index}",
                    prefix + "_CLIENT_SECRET": f"secret-{index}",
                    prefix + "_EXPIRES_AT": "2099-01-01T00:00:00+00:00",
                }
            )

        projected_tunnel, access = (
            server_config.cloudflare_runtime_credential_projections(
                values, prefixes, "b" * 64
            )
        )

        self.assertEqual(projected_tunnel, "tunnel-value")
        self.assertEqual(set(access["routes"]), set(prefixes))
        self.assertEqual(access["_generated"]["sourceSha256"], "b" * 64)

    def test_cloudflare_partial_route_tuple_fails_closed(self):
        values = {
            "CLOUDFLARE_TUNNEL_TOKEN": "legacy-tunnel-value",
            "CLOUDFLARE_ACCESS_ROUTE_FIRECRAWL_ID": "route-id",
        }

        with self.assertRaisesRegex(
            server_config.ConfigError, "incomplete for route: firecrawl"
        ):
            server_config.cloudflare_runtime_credential_projections(
                values,
                {"firecrawl": "CLOUDFLARE_ACCESS_ROUTE_FIRECRAWL"},
                "c" * 64,
            )

    def test_server_config_cli_render_reuses_its_outer_lock(self):
        output = io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["server-config.py", "render"]),
            mock.patch.object(
                server_config, "config_lock", return_value=nullcontext(9)
            ) as lock,
            mock.patch.object(
                server_config, "render", return_value={"ok": True}
            ) as render,
            redirect_stdout(output),
        ):
            server_config.main()

        lock.assert_called_once_with()
        render.assert_called_once_with(lock_fd=9)
        self.assertEqual(json.loads(output.getvalue()), {"ok": True})

    def test_profile_apply_uses_provider_canonical_workspace(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "secretsRoot": "/root/.config/mte-secrets",
                    "excluded": [],
                }
            }
        }
        with (
            mock.patch.object(platform, "render_profiles"),
            mock.patch.object(platform, "sync"),
            mock.patch.object(platform, "ssh") as ssh,
        ):
            platform.apply_profiles(cfg)
        command = ssh.call_args.args[1]
        render = command.index("server-config.py render")
        audit = command.index("server-config.py audit")
        bootstrap = command.index("bootstrap-paperclip.py")
        self.assertLess(render, audit)
        self.assertLess(audit, bootstrap)
        self.assertIn("--workspace-root /home/daytona/paperclip-workspace", command)
        self.assertNotIn("/home/daytona/workspaces", command)

    def test_operator_env_is_explicit_and_private(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "operator.env"
            path.write_text("MTE_SSH_TARGET=root@example.test\n")
            path.chmod(0o600)
            platform.OPERATOR_ENV_OVERRIDE = path
            self.assertEqual(platform.operator_env_path(required=True), path.resolve())

            path.chmod(0o644)
            with self.assertRaisesRegex(platform.PlatformError, "group/world"):
                platform.operator_env_path(required=True)

    def test_operator_env_has_no_workstation_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            platform.OPERATOR_ENV_OVERRIDE = None
            self.assertIsNone(platform.operator_env_path())
            with self.assertRaisesRegex(platform.PlatformError, "--operator-env"):
                platform.operator_env_path(required=True)

    def test_operator_env_rejects_two_different_selected_files(self):
        with tempfile.TemporaryDirectory() as temp:
            first = Path(temp) / "first.env"
            second = Path(temp) / "second.env"
            for path in (first, second):
                path.write_text("MTE_SSH_TARGET=root@example.test\n")
                path.chmod(0o600)
            platform.OPERATOR_ENV_OVERRIDE = first
            with mock.patch.dict(
                os.environ, {"MTE_OPERATOR_ENV": str(second)}, clear=True
            ):
                with self.assertRaisesRegex(
                    platform.PlatformError, "multiple operator env files"
                ):
                    platform.operator_env_path(required=True)

    def operator_input_values(self) -> dict[str, str]:
        return {
            "MTE_SSH_TARGET": "root@198.51.100.20",
            "MTE_OPERATOR_SSH_CIDRS": "198.51.100.0/24",
            "MTE_EXCLUDED_HOST_1": "192.0.2.20",
            "MTE_EXCLUDED_HOST_2": "192.0.2.30",
            "PLATFORM_BASE_DOMAIN": "agents.example.net",
            "MTE_PAPERCLIP_IMAGE": "ghcr.io/example/paperclip-mte@sha256:" + "a" * 64,
            "MTE_PAPERCLIP_FORK_SOURCE_URL": "https://github.com/example/paperclip-mte",
            "MTE_PAPERCLIP_FORK_REVISION": "b" * 40,
            "MTE_DAYTONA_SANDBOX_IMAGE": "ghcr.io/example/daytona@sha256:"
            + "c" * 64,
            "MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL": "https://github.com/example/platform",
            "MTE_DAYTONA_SANDBOX_IMAGE_REVISION": "d" * 40,
            "CLOUDFLARE_ACCOUNT_ID": "account-id-placeholder",
            "CLOUDFLARE_EMAIL": "operator@example.test",
            "CLOUDFLARE_GLOBAL_API_KEY": "global-key-placeholder",
            "E2E_GITHUB_BASE_BRANCH": "main",
            "E2E_GITHUB_OWNER": "example-org",
            "E2E_GITHUB_REPOSITORY": "agent-canary",
            "GITHUB_TOKEN": "github-token-placeholder",
            "MINIMAX_API_KEY": "minimax-key-placeholder",
            "MINIMAX_BASE_URL": "https://minimax.example.test/v1",
            "MINIMAX_MODEL": "minimax-model-placeholder",
            "MTE_ENABLE_OPERATOR_PROVIDED_PROPRIETARY_HARNESSES": "false",
            "NOTION_TOKEN": "notion-token-placeholder",
            "NOTION_ROOT_PAGE_ID": "00000000-0000-4000-8000-000000000001",
            "CONTEXT7_API_KEY": "context7-key-must-not-be-rendered",
        }

    def test_single_environment_schema_is_compact_and_operator_owned(self):
        schema = platform.operator_environment_schema()
        self.assertTrue(schema["ok"])
        self.assertEqual(schema["example"], "config/platform.env.example")
        self.assertEqual(
            schema["canonicalRuntimeSource"],
            "/root/.config/mte-secrets/platform.env",
        )
        self.assertEqual(schema["operatorInputs"], "reconciled")
        self.assertIn("fill-only", schema["generatedValues"])
        self.assertTrue(
            {
                "E2E_GITHUB_BASE_BRANCH",
                "E2E_GITHUB_OWNER",
                "E2E_GITHUB_REPOSITORY",
            }
            <= set(schema["requiredKeys"])
        )
        self.assertIn("CONTEXT7_API_KEY", schema["optionalKeys"])
        self.assertEqual(
            set(server_config.RESOURCE_PREFLIGHT_KEYS),
            set(schema["optionalKeys"]) & set(server_config.RESOURCE_PREFLIGHT_KEYS),
        )
        documented = platform.parse_dotenv(platform.CANONICAL_ENV_EXAMPLE)
        self.assertEqual(
            server_config.resource_preflight_values({}),
            {key: documented[key] for key in server_config.RESOURCE_PREFLIGHT_KEYS},
        )
        self.assertEqual(
            documented["CONTEXT7_API_KEY"],
            "",
        )
        self.assertIn("CLOUDFLARE_GLOBAL_API_KEY", schema["localOnlyBootstrapKeys"])

    def test_config_check_validates_without_printing_values(self):
        values = self.operator_input_values()
        output = io.StringIO()
        args = platform.parser().parse_args(["config", "check"])
        with (
            mock.patch.object(platform, "operator_values", return_value=values),
            redirect_stdout(output),
        ):
            platform.cmd_config(args)
        result = json.loads(output.getvalue())
        self.assertTrue(result["ok"])
        self.assertNotIn(values["GITHUB_TOKEN"], output.getvalue())
        self.assertNotIn(values["CLOUDFLARE_GLOBAL_API_KEY"], output.getvalue())
        self.assertNotIn(values["CONTEXT7_API_KEY"], output.getvalue())

    def test_deploy_resource_preflight_runs_after_os_proof(self):
        args = platform.parser().parse_args(["preflight"])
        values = self.operator_input_values()
        cfg = {"spec": {"host": {"ssh": "root@example.test", "excluded": []}}}
        events: list[str] = []

        def ssh(_cfg, command, **_kwargs):
            self.assertIn("/etc/os-release", command)
            events.append("os-proof")
            return mock.Mock(stdout='{"ssh":"ready","os":"ubuntu"}\n')

        with (
            mock.patch.object(platform, "operator_values", return_value=values),
            mock.patch.object(platform, "validate_public_harness_enablement"),
            mock.patch.object(platform, "config", return_value=cfg),
            mock.patch.object(platform, "ensure_safe_target"),
            mock.patch.object(platform, "ssh", side_effect=ssh),
            mock.patch.object(
                platform,
                "run_resource_preflight",
                side_effect=lambda _cfg, mode, **_kwargs: events.append(mode),
            ),
            redirect_stdout(io.StringIO()),
        ):
            platform.cmd_preflight(args)

        self.assertEqual(events, ["os-proof", "deploy"])

    def test_resource_preflight_streams_only_canonical_non_secret_thresholds(self):
        cfg = {"spec": {"host": {"ssh": "root@example.test", "excluded": []}}}
        values = self.operator_input_values()
        with mock.patch.object(platform, "ssh") as ssh:
            platform.run_resource_preflight(cfg, "deploy", values=values)

        command = ssh.call_args.args[1]
        self.assertIn("bash -s -- deploy", command)
        for key in server_config.RESOURCE_PREFLIGHT_KEYS:
            self.assertEqual(command.count(f"{key}="), 1)
        self.assertNotIn("GITHUB_TOKEN", command)
        self.assertEqual(
            ssh.call_args.kwargs["input_text"],
            platform.RESOURCE_PREFLIGHT_STEP.read_text(),
        )

    def test_daytona_e2e_resource_preflight_uses_the_same_threshold_contract(self):
        cfg = {"spec": {"host": {"ssh": "root@example.test", "excluded": []}}}
        values = self.operator_input_values()
        with mock.patch.object(platform, "ssh") as ssh:
            platform.run_resource_preflight(cfg, "daytona-e2e", values=values)

        command = ssh.call_args.args[1]
        self.assertIn("bash -s -- daytona-e2e", command)
        for key in server_config.RESOURCE_PREFLIGHT_KEYS:
            self.assertEqual(command.count(f"{key}="), 1)
        self.assertNotIn("GITHUB_TOKEN", command)

    def test_config_check_requires_digest_pinned_paperclip_image(self):
        for value in ("", "ghcr.io/example/paperclip-mte:latest"):
            with self.subTest(value=value):
                values = self.operator_input_values()
                values["MTE_PAPERCLIP_IMAGE"] = value
                with self.assertRaisesRegex(
                    platform.PlatformError,
                    "MTE_PAPERCLIP_IMAGE|missing required keys",
                ):
                    platform.validate_operator_environment(
                        values, reject_documentation_values=True
                    )

    def test_paperclip_fork_provenance_is_canonical_before_bootstrap(self):
        valid_source = "https://github.com/example/paperclip-mte"
        valid_revision = "b" * 40
        server_config.validate_paperclip_fork_evidence(valid_source, valid_revision)

        invalid = (
            ("MTE_PAPERCLIP_FORK_SOURCE_URL", "http://github.com/example/paperclip-mte"),
            ("MTE_PAPERCLIP_FORK_SOURCE_URL", "HTTPS://github.com/example/paperclip-mte"),
            ("MTE_PAPERCLIP_FORK_SOURCE_URL", "https://operator@github.com/example/paperclip-mte"),
            ("MTE_PAPERCLIP_FORK_SOURCE_URL", "https://github.com/example/paperclip-mte#release"),
            ("MTE_PAPERCLIP_FORK_REVISION", "B" * 40),
            ("MTE_PAPERCLIP_FORK_REVISION", "b" * 39),
        )
        for key, value in invalid:
            with self.subTest(key=key, value=value):
                values = self.operator_input_values()
                values[key] = value
                with self.assertRaisesRegex(platform.PlatformError, key):
                    platform.validate_operator_environment(
                        values, reject_documentation_values=True
                    )

        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            bootstrap_values = {
                "MTE_PAPERCLIP_IMAGE": "ghcr.io/example/paperclip-mte@sha256:"
                + "a" * 64,
                "MTE_PAPERCLIP_FORK_SOURCE_URL": "http://github.com/example/paperclip-mte",
                "MTE_PAPERCLIP_FORK_REVISION": valid_revision,
            }
            with (
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(server_config, "config_object", return_value={}),
                mock.patch.object(
                    server_config, "active_config_object", return_value={}
                ),
                mock.patch.object(
                    server_config,
                    "declared_keys",
                    return_value=({"MTE_PAPERCLIP_IMAGE"}, {}, {}),
                ),
                self.assertRaisesRegex(
                    server_config.ConfigError, "MTE_PAPERCLIP_FORK_SOURCE_URL"
                ),
            ):
                server_config.init_source(bootstrap_values)
            self.assertFalse(canonical.exists())

        args = platform.parser().parse_args(["bootstrap"])
        values = self.operator_input_values()
        values["MTE_PAPERCLIP_FORK_REVISION"] = "B" * 40
        with (
            mock.patch.object(platform, "operator_values", return_value=values),
            mock.patch.object(platform, "run_host_bootstrap") as host_bootstrap,
            mock.patch.object(platform, "sync") as sync,
            self.assertRaisesRegex(platform.PlatformError, "MTE_PAPERCLIP_FORK_REVISION"),
        ):
            platform.cmd_bootstrap(args)
        host_bootstrap.assert_not_called()
        sync.assert_not_called()

    def test_config_check_rejects_missing_or_unchanged_documentation_inputs(self):
        values = self.operator_input_values()
        values.pop("CLOUDFLARE_GLOBAL_API_KEY")
        with self.assertRaisesRegex(platform.PlatformError, "missing required keys"):
            platform.validate_operator_environment(
                values, reject_documentation_values=True
            )

        documented = platform.parse_dotenv(platform.CANONICAL_ENV_EXAMPLE)
        documented.update(
            {
                key: value
                for key, value in self.operator_input_values().items()
                if not documented.get(key)
            }
        )
        with self.assertRaisesRegex(platform.PlatformError, "documentation-only"):
            platform.validate_operator_environment(
                documented, reject_documentation_values=True
            )

    def test_operator_env_rejects_unsafe_github_e2e_target(self):
        invalid_values = (
            ("E2E_GITHUB_OWNER", "-unsafe-owner"),
            ("E2E_GITHUB_REPOSITORY", "unsafe/repository"),
            ("E2E_GITHUB_BASE_BRANCH", "release/../unsafe"),
            ("E2E_GITHUB_BASE_BRANCH", "release branch"),
            ("E2E_GITHUB_BASE_BRANCH", "HEAD"),
            ("E2E_GITHUB_BASE_BRANCH", "release/-unsafe"),
        )
        for key, value in invalid_values:
            with self.subTest(key=key, value=value):
                values = self.operator_input_values()
                values[key] = value
                with self.assertRaisesRegex(platform.PlatformError, "E2E_GITHUB"):
                    platform.validate_operator_environment(
                        values, reject_documentation_values=False
                    )

        target = server_config.validate_e2e_github_target(self.operator_input_values())
        self.assertEqual(target["E2E_GITHUB_BASE_BRANCH"], "main")

    def test_dotenv_parser_does_not_merge_ambient_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "platform.env"
            path.write_text("MTE_SSH_TARGET=root@example.test\n")
            with mock.patch.dict(
                os.environ, {"UNRELATED_SECRET": "must-not-cross-boundary"}, clear=True
            ):
                values = platform.local_dotenv(path)
        self.assertEqual(values, {"MTE_SSH_TARGET": "root@example.test"})

    def test_selected_dotenv_replaces_conflicting_ambient_operator_values(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "operator.env"
            path.write_text(
                "MTE_SSH_TARGET=root@selected.example.test\n"
                "PLATFORM_BASE_DOMAIN=selected.example.test\n"
                "GITHUB_TOKEN=selected-token\n"
            )
            path.chmod(0o600)
            with mock.patch.dict(
                os.environ,
                {
                    "MTE_SSH_TARGET": "root@ambient.example.test",
                    "PLATFORM_BASE_DOMAIN": "ambient.example.test",
                    "GITHUB_TOKEN": "ambient-token",
                    "CONTEXT7_API_KEY": "ambient-only-token",
                },
                clear=True,
            ):
                platform.activate_operator_environment(path)
                self.assertEqual(
                    os.environ["MTE_SSH_TARGET"], "root@selected.example.test"
                )
                self.assertEqual(
                    os.environ["PLATFORM_BASE_DOMAIN"], "selected.example.test"
                )
                self.assertEqual(os.environ["GITHUB_TOKEN"], "selected-token")
                self.assertNotIn("CONTEXT7_API_KEY", os.environ)

    def test_selected_dotenv_clears_ambient_domain_aliases(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "operator.env"
            path.write_text("PLATFORM_BASE_DOMAIN=selected.example.test\n")
            path.chmod(0o600)
            with mock.patch.dict(
                os.environ,
                {
                    "MTE_DOMAIN": "ambient.example.test",
                    "PLATFORM_DOMAIN": "ambient.example.test",
                    "CLOUDFLARE_BASE_DOMAIN": "ambient.example.test",
                },
                clear=True,
            ):
                platform.activate_operator_environment(path)
                self.assertEqual(
                    os.environ["PLATFORM_BASE_DOMAIN"], "selected.example.test"
                )
                for alias in platform.server_config_contract().DOMAIN_INPUT_ALIASES:
                    self.assertNotIn(alias, os.environ)

    def test_operator_env_rejects_legacy_domain_aliases(self):
        values = self.operator_input_values()
        values["MTE_DOMAIN"] = values["PLATFORM_BASE_DOMAIN"]
        with self.assertRaisesRegex(
            platform.PlatformError, "legacy domain aliases are not accepted"
        ):
            platform.validate_operator_environment(
                values, reject_documentation_values=False
            )

    def test_domain_override_rejects_selected_dotenv_conflict_without_values(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "operator.env"
            path.write_text(
                "MTE_SSH_TARGET=root@selected.example.test\n"
                "MTE_EXCLUDED_HOST_1=192.0.2.10\n"
                "MTE_EXCLUDED_HOST_2=192.0.2.11\n"
                "PLATFORM_BASE_DOMAIN=selected.example.test\n"
            )
            path.chmod(0o600)
            platform.OPERATOR_ENV_OVERRIDE = path
            raw = {
                "spec": {
                    "host": {
                        "sshRef": "MTE_SSH_TARGET",
                        "rootRef": "MTE_PLATFORM_ROOT",
                        "secretsRootRef": "MTE_SECRETS_ROOT",
                        "excludedRefs": [
                            "MTE_EXCLUDED_HOST_1",
                            "MTE_EXCLUDED_HOST_2",
                        ],
                    },
                    "domainRef": "PLATFORM_BASE_DOMAIN",
                }
            }
            seeds = {
                "MTE_PLATFORM_ROOT": "/opt/mte-platform",
                "MTE_SECRETS_ROOT": "/root/.config/mte-secrets",
            }
            with (
                mock.patch.object(platform, "load_yaml", return_value=raw),
                mock.patch.object(platform, "bootstrap_seeds", return_value=seeds),
            ):
                with self.assertRaisesRegex(
                    platform.PlatformError, "--domain conflicts"
                ) as raised:
                    platform.config("different.example.test")
        self.assertNotIn("selected.example.test", str(raised.exception))
        self.assertNotIn("different.example.test", str(raised.exception))

    def test_selected_dotenv_uses_canonical_roots_and_ports_not_ambient(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "operator.env"
            path.write_text(
                "MTE_SSH_TARGET=root@selected.example.test\n"
                "MTE_EXCLUDED_HOST_1=192.0.2.10\n"
                "MTE_EXCLUDED_HOST_2=192.0.2.11\n"
                "PLATFORM_BASE_DOMAIN=selected.example.test\n"
            )
            path.chmod(0o600)
            platform.OPERATOR_ENV_OVERRIDE = path
            raw = {
                "spec": {
                    "host": {
                        "sshRef": "MTE_SSH_TARGET",
                        "rootRef": "MTE_PLATFORM_ROOT",
                        "secretsRootRef": "MTE_SECRETS_ROOT",
                        "excludedRefs": [
                            "MTE_EXCLUDED_HOST_1",
                            "MTE_EXCLUDED_HOST_2",
                        ],
                    },
                    "domainRef": "PLATFORM_BASE_DOMAIN",
                }
            }
            seeds = {
                "MTE_PLATFORM_ROOT": "/opt/mte-platform",
                "MTE_SECRETS_ROOT": "/root/.config/mte-secrets",
                "POSTGREST_PORT_1_MAPPING": "127.0.0.1:13000:3000",
            }
            observed_values = {}
            data_contract = mock.Mock()

            def resolve_from_paths(_raw, _lock, values, **_kwargs):
                observed_values.update(values)
                return {}

            data_contract.resolve_from_paths.side_effect = resolve_from_paths
            with (
                mock.patch.object(platform, "load_yaml", side_effect=[raw, {}]),
                mock.patch.object(platform, "bootstrap_seeds", return_value=seeds),
                mock.patch.object(
                    platform, "data_content_contract", return_value=data_contract
                ),
                mock.patch.dict(
                    os.environ,
                    {
                        "MTE_PLATFORM_ROOT": "/ambient/platform",
                        "MTE_SECRETS_ROOT": "/ambient/secrets",
                        "POSTGREST_PORT_1_MAPPING": "0.0.0.0:9999:3000",
                    },
                    clear=False,
                ),
            ):
                cfg = platform.config()

        self.assertEqual(cfg["spec"]["host"]["root"], "/opt/mte-platform")
        self.assertEqual(
            cfg["spec"]["host"]["secretsRoot"],
            "/root/.config/mte-secrets",
        )
        self.assertEqual(
            observed_values["POSTGREST_PORT_1_MAPPING"],
            "127.0.0.1:13000:3000",
        )
        self.assertNotIn("/ambient/", json.dumps(cfg))

    def test_standalone_bootstrap_imports_operator_env_before_finish(self):
        args = platform.parser().parse_args(["bootstrap"])
        cfg = {
            "spec": {"host": {"ssh": "root@example.test", "root": "/opt/mte-platform"}}
        }
        events: list[str] = []
        with (
            mock.patch.object(
                platform, "operator_values", return_value=self.operator_input_values()
            ),
            mock.patch.object(platform, "validate_operator_environment"),
            mock.patch.object(platform, "config", return_value=cfg),
            mock.patch.object(
                platform,
                "run_host_bootstrap",
                side_effect=lambda _cfg: events.append("host"),
            ),
            mock.patch.object(
                platform,
                "run_config",
                side_effect=lambda _cfg, action: events.append(f"config-{action}"),
            ),
            mock.patch.object(
                platform,
                "finish_platform_bootstrap",
                side_effect=lambda _cfg: events.append("finish"),
            ),
            redirect_stdout(io.StringIO()),
        ):
            platform.cmd_bootstrap(args)
        self.assertEqual(events, ["host", "config-init", "finish"])

    def test_finish_bootstrap_only_initializes_canonical_compose_configuration(self):
        cfg = {
            "spec": {"host": {"ssh": "root@example.test", "root": "/opt/mte-platform"}}
        }
        commands: list[str] = []
        with (
            mock.patch.object(platform, "sync"),
            mock.patch.object(
                platform,
                "ssh",
                side_effect=lambda _cfg, command, **_kwargs: commands.append(command),
            ),
        ):
            platform.finish_platform_bootstrap(cfg)
        self.assertEqual(len(commands), 1)
        self.assertIn("server-config.py", commands[0])
        self.assertNotIn("server-dokploy.py", commands[0])
        self.assertNotIn("settings.isCloud", commands[0])

    def test_host_bootstrap_seed_allowlist_exactly_matches_host_installer(self):
        source = (ROOT / "deployment/steps/host.sh").read_text().splitlines()
        consumed = {
            line.split("canonical_value ", 1)[1].split(")", 1)[0]
            for line in source
            if "=$(canonical_value " in line
        }
        self.assertEqual(consumed, set(platform.HOST_BOOTSTRAP_SEED_KEYS))
        seeds = platform.host_bootstrap_seeds()
        self.assertEqual(set(seeds), consumed)
        self.assertTrue(all(seeds.values()))
        self.assertFalse(
            set(seeds)
            & (
                set(server_config.REQUIRED_OPERATOR_ENV_KEYS)
                | set(server_config.OPTIONAL_OPERATOR_INPUT_KEYS)
                | set(server_config.OPTIONAL_EMPTY_KEYS)
            )
        )
        self.assertFalse(
            [key for key in seeds if server_config.SENSITIVE_KEY_PATTERN.search(key)]
        )

    def test_host_bootstrap_env_is_stdin_only_fill_only_and_private(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "secretsRoot": "/root/.config/mte-secrets",
                }
            }
        }
        with mock.patch.object(platform, "ssh") as ssh:
            platform.materialize_host_bootstrap_env(cfg)

        command = ssh.call_args.args[1]
        payload = ssh.call_args.kwargs["input_text"]
        values = dict(line.split("=", 1) for line in payload.splitlines())
        self.assertEqual(values, platform.host_bootstrap_seeds())
        self.assertNotIn("GITHUB_TOKEN", payload)
        self.assertNotIn("MINIMAX_API_KEY", payload)
        self.assertTrue(all(not key.startswith("DOKPLOY_") for key in values))
        self.assertNotIn("DOKPLOY_", command)
        self.assertIn('if (current == "") print key "=" incoming[key]', command)
        self.assertIn("else print $0", command)
        self.assertIn("for (position = 1; position <= count; position++)", command)
        self.assertIn('chmod 0700 "$secret_root"', command)
        self.assertIn('chmod 0600 "$canonical"', command)
        self.assertNotIn('cat "$canonical"', command)
        subprocess.run(["/bin/sh", "-n", "-c", command], check=True)

    def test_host_bootstrap_merge_awk_is_portable(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "secretsRoot": "/root/.config/mte-secrets",
                }
            }
        }
        command = platform.host_bootstrap_env_command(cfg)
        start = command.index("awk -F= '\n    NR == FNR {") + len("awk -F= '")
        end = command.index('\' "$incoming" "$existing" >"$merged"', start)
        merge_program = command[start:end]
        self.assertNotIn("for (index", merge_program)
        subprocess.run(
            ["awk", "-F=", merge_program, "/dev/null", "/dev/null"],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_host_bootstrap_seed_merge_is_clean_and_replay_idempotent(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "secretsRoot": "/root/.config/mte-secrets",
                }
            }
        }
        command = platform.host_bootstrap_env_command(cfg)
        start = command.index("awk -F= '\n    NR == FNR {") + len("awk -F= '")
        end = command.index('\' "$incoming" "$existing" >"$merged"', start)
        merge_program = command[start:end]
        seeds = platform.host_bootstrap_seeds()
        payload = "".join(f"{key}={seeds[key]}\n" for key in sorted(seeds))

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            incoming = root / "incoming.env"
            empty = root / "empty.env"
            first = root / "first.env"
            incoming.write_text(payload)
            empty.write_text("")
            first_output = subprocess.run(
                ["awk", "-F=", merge_program, incoming, empty],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            first.write_text(first_output)
            replay = subprocess.run(
                ["awk", "-F=", merge_program, incoming, first],
                check=True,
                capture_output=True,
                text=True,
            ).stdout

        self.assertEqual(first_output, payload)
        self.assertEqual(replay, payload)

    def test_host_bootstrap_materializes_frozen_contract_before_script(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "secretsRoot": "/root/.config/mte-secrets",
                    "excluded": [],
                }
            }
        }
        source = Path("/tmp/frozen-host.sh")
        contract = Path("/tmp/frozen-server-config.py")
        events: list[str] = []
        with (
            mock.patch.object(platform, "ensure_safe_target"),
            mock.patch.object(
                platform,
                "materialize_host_bootstrap_env",
                side_effect=lambda _cfg, *, contract_source: events.append(
                    f"env:{contract_source}"
                ),
            ),
            mock.patch.object(
                platform,
                "scp",
                side_effect=lambda _cfg, local, remote: events.append(
                    f"scp:{local}:{remote}"
                ),
            ),
            mock.patch.object(
                platform,
                "ssh",
                side_effect=lambda *_args, **_kwargs: events.append("execute"),
            ),
        ):
            platform.run_host_bootstrap(
                cfg,
                source=source,
                contract_source=contract,
            )
        self.assertEqual(
            events,
            [
                f"env:{contract}",
                f"scp:{source}:/tmp/mte-platform-host.sh",
                "execute",
            ],
        )

    def test_host_bootstrap_seeds_are_loaded_from_requested_contract(self):
        contract = mock.Mock()
        contract.ONE_TIME_MIGRATION_SEEDS = {
            key: f"value-{index}"
            for index, key in enumerate(sorted(platform.HOST_BOOTSTRAP_SEED_KEYS), 1)
        }
        contract.REQUIRED_OPERATOR_ENV_KEYS = set()
        contract.OPTIONAL_OPERATOR_INPUT_KEYS = set()
        contract.OPTIONAL_EMPTY_KEYS = set()
        contract.SENSITIVE_KEY_PATTERN = server_config.SENSITIVE_KEY_PATTERN
        source = Path("/tmp/frozen-server-config.py")
        with mock.patch.object(
            platform, "server_config_contract", return_value=contract
        ) as loader:
            seeds = platform.host_bootstrap_seeds(contract_source=source)
        loader.assert_called_once_with(source)
        self.assertEqual(seeds, contract.ONE_TIME_MIGRATION_SEEDS)

    def test_config_init_materializes_one_canonical_source_before_render(self):
        cfg = {
            "spec": {"host": {"ssh": "root@example.test", "root": "/opt/mte-platform"}}
        }
        events: list[str] = []
        canonical_imports: list[dict[str, str]] = []

        def record_ssh(_cfg, command, **kwargs):
            if "server-config.py')" in command:
                raise AssertionError("unexpected quoted fixture")
            if "server-config.py" in command and " init" in command:
                events.append("canonical-init")
                if kwargs.get("input_text"):
                    canonical_imports.append(json.loads(kwargs["input_text"]))
            elif "server-secrets.py" in command:
                events.append("generated-secrets")
            elif "server-config.py" in command and " render" in command:
                events.append("render")
            elif "server-config.py" in command and " audit" in command:
                events.append("audit")

        with (
            mock.patch.object(
                platform, "operator_values", return_value=self.operator_input_values()
            ),
            mock.patch.object(platform, "sync"),
            mock.patch.object(platform, "ssh", side_effect=record_ssh),
            mock.patch.object(
                platform,
                "run_cloudflare",
                side_effect=lambda _cfg, action: events.append(f"cloudflare-{action}"),
            ),
        ):
            platform.run_config(cfg, "init")

        self.assertEqual(
            events,
            [
                "canonical-init",
                "generated-secrets",
                "canonical-init",
                "cloudflare-token-apply",
                "render",
                "audit",
            ],
        )
        self.assertEqual(len(canonical_imports), 1)
        self.assertIn("CLOUDFLARE_ACCOUNT_ID", canonical_imports[0])
        self.assertNotIn("CLOUDFLARE_EMAIL", canonical_imports[0])
        self.assertNotIn("CLOUDFLARE_GLOBAL_API_KEY", canonical_imports[0])

    def test_verify_all_is_explicit_and_rejects_component_mix(self):
        args = platform.parser().parse_args(["verify", "--all"])
        self.assertTrue(args.all)
        self.assertEqual(args.components, [])
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/agent-platform",
                }
            }
        }
        with (
            mock.patch.object(platform, "config", return_value=cfg),
            mock.patch.object(platform, "run_data_content_projections"),
            mock.patch.object(platform, "sync"),
            mock.patch.object(platform, "ssh"),
        ):
            platform.cmd_verify(args)

        mixed = platform.parser().parse_args(["verify", "--all", "paperclip"])
        with mock.patch.object(platform, "config", return_value={}):
            with self.assertRaisesRegex(platform.PlatformError, "cannot be combined"):
                platform.cmd_verify(mixed)

    def test_acceptance_cli_exports_registry_and_checks_remote_acceptance(self):
        exported = platform.parser().parse_args(["acceptance", "export"])
        with (
            mock.patch.object(
                platform,
                "load_yaml",
                return_value={"kind": "ReleaseEvidenceRegistry", "requirements": []},
            ),
            mock.patch("sys.stdout"),
        ):
            platform.cmd_acceptance(exported)

        checked = platform.parser().parse_args(["acceptance", "check"])
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/agent-platform",
                }
            }
        }
        with (
            mock.patch.object(platform, "load_yaml"),
            mock.patch.object(platform, "config", return_value=cfg),
            mock.patch.object(platform, "sync"),
            mock.patch.object(platform, "ssh") as ssh,
        ):
            platform.cmd_acceptance(checked)
        self.assertIn("server-verify.py acceptance", ssh.call_args.args[1])

    def test_removed_full_deploy_flags_are_rejected(self):
        for arguments in (
            ["deploy"],
            ["deploy", "postgres"],
            ["deploy", "--all"],
            ["deploy", "--resume", "run-12345678"],
            ["plan", "--all"],
        ):
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                platform.parser().parse_args(arguments)

    def provider_manifest(self, profile: str = "postgres-notion") -> dict:
        manifest = yaml.safe_load((ROOT / "config/platform.yaml").read_text())
        manifest["_resolvedDataContentPlane"] = {
            "profile": profile,
            "componentIds": list(
                manifest["spec"]["providerProfiles"]
                .get(profile, {})
                .get("componentIds", [])
            ),
        }
        return manifest

    def test_provider_availability_is_explicit_and_required_is_profile_scoped(self):
        manifest = self.provider_manifest()
        catalog = platform.provider_profile_catalog(manifest)
        self.assertEqual(
            catalog["postgres-notion"],
            {
                "providerIds": ["postgres", "postgrest", "notion"],
                "componentIds": ["postgrest"],
            },
        )

        active = platform.components(manifest)
        active_ids = {row["id"] for row in active}
        self.assertIn("postgrest", active_ids)
        self.assertEqual(
            {
                row["id"]
                for row in manifest["spec"]["components"]
                if "enabledForProfiles" in row
            },
            {"postgrest"},
        )
        self.assertTrue(
            next(row for row in active if row["id"] == "postgrest")["required"]
        )
        ordered_ids = [row["id"] for row in platform.component_order(manifest, None)]
        self.assertEqual(active_ids, set(ordered_ids))

    def test_provider_manifest_rejects_missing_and_ambiguous_mappings(self):
        missing = self.provider_manifest()
        missing["spec"]["providerProfiles"]["postgres-notion"]["providerIds"].remove(
            "notion"
        )
        with self.assertRaisesRegex(platform.PlatformError, "differs from the lock"):
            platform.provider_profile_catalog(missing)

        ambiguous = self.provider_manifest()
        ambiguous["spec"]["providerProfiles"]["postgres-notion"]["providerIds"].append(
            "notion"
        )
        with self.assertRaisesRegex(platform.PlatformError, "unique non-empty"):
            platform.provider_profile_catalog(ambiguous)

        unknown_profile = self.provider_manifest()
        unknown_profile["spec"]["providerProfiles"]["unreviewed-provider"] = {
            "providerIds": ["unreviewed-provider"],
            "componentIds": ["unreviewed-provider"],
        }
        with self.assertRaisesRegex(
            platform.PlatformError, "unknown=unreviewed-provider"
        ):
            platform.provider_profile_catalog(unknown_profile)

        incomplete = self.provider_manifest()
        postgrest = next(
            row for row in incomplete["spec"]["components"] if row["id"] == "postgrest"
        )
        postgrest["enabledForProfiles"].remove("postgres-notion")
        with self.assertRaisesRegex(
            platform.PlatformError, "enabledForProfiles must be a unique non-empty"
        ):
            platform.provider_profile_catalog(incomplete)

    def test_provider_manifest_rejects_unknown_profile_and_incompatible_dependency(
        self,
    ):
        unknown = self.provider_manifest("not-a-provider-profile")
        with self.assertRaisesRegex(platform.PlatformError, "unknown selected"):
            platform.components(unknown)

        incompatible = self.provider_manifest()
        postgrest = next(
            row
            for row in incompatible["spec"]["components"]
            if row["id"] == "postgrest"
        )
        postgrest["dependsOn"].append("unknown-component")
        with self.assertRaisesRegex(
            platform.PlatformError, "unavailable dependencies: unknown-component"
        ):
            platform.provider_profile_catalog(incompatible)

    def test_all_remote_transport_builders_include_ssh_keepalive(self):
        expected_options = [
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ServerAliveCountMax=10",
            "-o",
            "TCPKeepAlive=yes",
        ]
        self.assertEqual(
            platform.ssh_transport_command(),
            ["ssh", *expected_options],
        )
        self.assertEqual(
            platform.ssh_transport_command("scp"),
            ["scp", *expected_options],
        )
        rsync = platform.remote_rsync_command(
            "-az", "source", "root@example.test:/destination"
        )
        self.assertEqual(rsync[:2], ["rsync", "-e"])
        self.assertEqual(shlex.split(rsync[2]), ["ssh", *expected_options])

    def test_ssh_and_scp_use_shared_keepalive_transport(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                }
            }
        }
        expected_prefix = platform.ssh_transport_command()
        with mock.patch.object(platform, "run") as run:
            platform.ssh(cfg, "true")
            platform.scp(cfg, Path("source"), "/destination")
        self.assertEqual(
            run.call_args_list[0].args[0][: len(expected_prefix)],
            expected_prefix,
        )
        expected_scp_prefix = platform.ssh_transport_command("scp")
        self.assertEqual(
            run.call_args_list[1].args[0][: len(expected_scp_prefix)],
            expected_scp_prefix,
        )

    def test_ssh_exports_no_bytecode_environment_for_child_python(self):
        cfg = {"spec": {"host": {"ssh": "root@example.test"}}}
        child = "import os; print(os.environ['PYTHONDONTWRITEBYTECODE'])"
        original = f"python3 -c {shlex.quote(child)}"

        with mock.patch.object(platform, "run") as run:
            platform.ssh(cfg, original)

        command = run.call_args.args[0]
        wrapped = command[-1]
        expected_script = f"export PYTHONDONTWRITEBYTECODE=1;\n{original}"
        self.assertEqual(
            wrapped,
            f"bash -c {shlex.quote(expected_script)}",
        )
        result = subprocess.run(
            ["/bin/sh", "-c", wrapped],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "0"},
        )
        self.assertEqual(result.stdout.strip(), "1")

    def test_existing_install_imports_reviewed_operator_and_notion_values(self):
        token = "unit-prin7r-notion-token-must-not-appear-in-commands"
        generic_token = "unit-generic-notion-token-must-not-cross-ssh"
        api_key_fallback = "unit-prin7r-api-key-must-not-cross-ssh"
        context7_key = "unit-context7-key-must-not-appear-in-command"
        telegram_token = "unit-telegram-token-must-not-appear-in-command"
        commands = []

        def fake_ssh(
            _cfg,
            command,
            *,
            check=True,
            input_text=None,
            capture_output=False,
        ):
            del check, capture_output
            commands.append((command, input_text))
            return subprocess.CompletedProcess([], 0, "", "")

        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "secretsRoot": "/root/.config/mte-secrets",
                    "excluded": [],
                }
            }
        }
        local_values = {
            "NOTION_TOKEN": generic_token,
            "PRIN7R_NOTION_TOKEN": token,
            "PRIN7R_NOTION_API_KEY": api_key_fallback,
            "NOTION_DOCUMENTS_PAGE_ID": "managed-documents",
            "NOTION_TABLE_DATABASE_ID": "managed-database",
            "NOTION_TABLE_DATA_SOURCE_ID": "managed-data-source",
            "NOTION_WORKSPACE_ID": "managed-workspace",
            "NOTION_BOT_ID": "managed-bot",
            "CONTEXT7_API_KEY": context7_key,
            "PRIN7R_HERMES_TELEGRAM_BOT_TOKEN": telegram_token,
            "HERMES_TELEGRAM_ALLOWED_USERS": "123456789",
            "PRIN7R_NOTION_PAGE_ID": "broad-parent-must-not-be-upgrade-imported",
            "MTE_OPERATOR_SSH_CIDRS": "203.0.113.9/32",
            "PLATFORM_BASE_DOMAIN": "example.test",
            "CLOUDFLARE_GLOBAL_API_KEY": "local-only-must-not-cross-ssh",
            "UNRELATED_SECRET": "must-not-cross-ssh",
        }
        with (
            mock.patch.object(platform, "ssh", side_effect=fake_ssh),
            mock.patch.object(platform, "sync"),
            mock.patch.object(
                platform, "operator_values", return_value=local_values
            ) as operator_values,
        ):
            platform.ensure_config_initialized(cfg)

        operator_values.assert_called_once_with(required=True)
        imported = json.loads(commands[1][1])
        self.assertEqual(
            imported,
            {
                "NOTION_TOKEN": token,
                "NOTION_DOCUMENTS_PAGE_ID": "managed-documents",
                "NOTION_TABLE_DATABASE_ID": "managed-database",
                "NOTION_TABLE_DATA_SOURCE_ID": "managed-data-source",
                "NOTION_WORKSPACE_ID": "managed-workspace",
                "NOTION_BOT_ID": "managed-bot",
                "CONTEXT7_API_KEY": context7_key,
                "HERMES_TELEGRAM_BOT_TOKEN": telegram_token,
                "HERMES_TELEGRAM_ALLOWED_USERS": "123456789",
                "MTE_OPERATOR_SSH_CIDRS": "203.0.113.9/32",
                "PLATFORM_BASE_DOMAIN": "example.test",
            },
        )
        self.assertNotIn(token, "\n".join(command for command, _ in commands))
        self.assertNotIn(generic_token, json.dumps(commands))
        self.assertNotIn(api_key_fallback, json.dumps(commands))
        self.assertNotIn(context7_key, "\n".join(command for command, _ in commands))
        self.assertNotIn(telegram_token, "\n".join(command for command, _ in commands))
        self.assertNotIn("PRIN7R_HERMES_TELEGRAM_BOT_TOKEN", json.dumps(commands))
        self.assertNotIn("UNRELATED_SECRET", json.dumps(commands))
        self.assertNotIn("CLOUDFLARE_GLOBAL_API_KEY", json.dumps(commands))

    def test_empty_profile_migrates_to_postgres_notion_and_imports_dedicated_root(self):
        token = "unit-notion-token-never-returned"
        root_id = "unit-managed-root"
        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            canonical.write_text("DATA_CONTENT_PROFILE=\n")
            canonical.chmod(0o600)
            observed_selection = {}
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                value = original_stat(path, *args, **kwargs)
                fields = list(value)
                if (
                    value.st_mode & 0o170000 == 0o100000
                    and path != server_config.LOCK
                ):
                    fields[4] = 0
                return os.stat_result(fields)

            def active(_cfg, values, *_args):
                observed_selection.update(values)
                return {}

            required = {
                "DATA_CONTENT_PROFILE",
                "NOTION_API_BASE_URL",
                "NOTION_API_VERSION",
                "NOTION_ROOT_PAGE_ID",
                "NOTION_TOKEN",
            }
            seeds = {
                "DATA_CONTENT_PROFILE": platform.DEFAULT_DATA_CONTENT_PROFILE,
                "NOTION_API_BASE_URL": "https://api.notion.com/v1",
                "NOTION_API_VERSION": "2025-09-03",
            }
            with (
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(server_config, "config_object", return_value={}),
                mock.patch.object(
                    server_config, "active_config_object", side_effect=active
                ),
                mock.patch.object(
                    server_config,
                    "declared_keys",
                    return_value=(required, {}, seeds),
                ),
                mock.patch.object(
                    server_config, "compose_seed_catalog", return_value={}
                ),
                mock.patch.object(Path, "stat", root_owned_stat),
            ):
                result = server_config.init_source(
                    {
                        "NOTION_TOKEN": "unit-wrong-generic-token",
                        "PRIN7R_NOTION_API_KEY": "unit-second-choice-api-key",
                        "PRIN7R_NOTION_TOKEN": token,
                        "NOTION_ROOT_PAGE_ID": root_id,
                        "NOTION_DOCUMENTS_PAGE_ID": "unit-documents",
                    }
                )
                values = server_config.parse_env(canonical)

        self.assertEqual(
            observed_selection["DATA_CONTENT_PROFILE"],
            platform.DEFAULT_DATA_CONTENT_PROFILE,
        )
        self.assertEqual(values["DATA_CONTENT_PROFILE"], "postgres-notion")
        self.assertEqual(values["NOTION_TOKEN"], token)
        self.assertEqual(values["NOTION_ROOT_PAGE_ID"], root_id)
        self.assertEqual(values["NOTION_DOCUMENTS_PAGE_ID"], "unit-documents")
        self.assertEqual(
            [
                key
                for key in values
                if key
                in {
                    "NOTION_TOKEN",
                    "PRIN7R_NOTION_TOKEN",
                    "PRIN7R_NOTION_API_KEY",
                }
            ],
            ["NOTION_TOKEN"],
        )
        self.assertNotIn("PRIN7R_NOTION_API_KEY", values)
        self.assertNotIn(token, json.dumps(result))

    def test_fresh_config_initialization_materializes_daytona_nonsecret_contract(self):
        keys = {
            "DAYTONA_DB_USER",
            "MTE_DAYTONA_API_IMAGE",
            "MTE_DAYTONA_CODING_SNAPSHOT",
            "MTE_DAYTONA_NETWORK",
            "MTE_CODEX_VERSION",
            "MTE_CONTEXT7_MCP_URL",
            "MTE_DOCKER_LOG_MAX_FILES",
            "MTE_DOCKER_LOG_MAX_SIZE",
            "MTE_GITHUB_CLI_VERSION",
            "MTE_TOOLHIVE_VERSION",
        }
        seeds = {key: server_config.ONE_TIME_MIGRATION_SEEDS[key] for key in keys}
        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            with (
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(server_config, "config_object", return_value={}),
                mock.patch.object(
                    server_config, "active_config_object", return_value={}
                ),
                mock.patch.object(
                    server_config,
                    "declared_keys",
                    return_value=(keys, {}, seeds),
                ),
                mock.patch.object(
                    server_config, "compose_seed_catalog", return_value={}
                ),
            ):
                result = server_config.init_source({})
                values = server_config.parse_env(canonical)

        self.assertEqual({key: values[key] for key in keys}, seeds)
        self.assertEqual(result["missingKeys"], [])
        self.assertNotIn("MTE_DAYTONA_SANDBOX_IMAGE", values)
        self.assertNotIn("MTE_DAYTONA_CODING_IMAGE", values)

    def test_optional_context7_input_reconciles_and_results_are_redacted(self):
        first_key = "unit-context7-first-key"
        replacement_key = "unit-context7-replacement"
        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                value = original_stat(path, *args, **kwargs)
                fields = list(value)
                fields[4] = 0
                return os.stat_result(fields)

            github_target = {
                "E2E_GITHUB_BASE_BRANCH": "main",
                "E2E_GITHUB_OWNER": "example-org",
                "E2E_GITHUB_REPOSITORY": "agent-canary",
            }
            required = {"CONTEXT7_API_KEY", *github_target}
            seeds = {
                "CONTEXT7_API_KEY": "",
                **github_target,
            }
            with (
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(server_config, "config_object", return_value={}),
                mock.patch.object(
                    server_config, "active_config_object", return_value={}
                ),
                mock.patch.object(
                    server_config,
                    "declared_keys",
                    return_value=(required, {}, seeds),
                ),
                mock.patch.object(
                    server_config, "compose_seed_catalog", return_value={}
                ),
                mock.patch.object(Path, "stat", root_owned_stat),
            ):
                anonymous = server_config.init_source(
                    {"CONTEXT7_API_KEY": "", **github_target}
                )
                self.assertEqual(
                    server_config.parse_env(canonical)["CONTEXT7_API_KEY"], ""
                )
                configured = server_config.init_source(
                    {"CONTEXT7_API_KEY": first_key, **github_target}
                )
                self.assertEqual(
                    server_config.parse_env(canonical)["CONTEXT7_API_KEY"], first_key
                )
                repeated = server_config.init_source(
                    {"CONTEXT7_API_KEY": replacement_key, **github_target}
                )
                final_values = server_config.parse_env(canonical)

        self.assertEqual(final_values["CONTEXT7_API_KEY"], replacement_key)
        self.assertEqual(repeated["reconciledOperatorKeys"], ["CONTEXT7_API_KEY"])
        rendered_results = json.dumps([anonymous, configured, repeated])
        self.assertNotIn(first_key, rendered_results)
        self.assertNotIn(replacement_key, rendered_results)

    def test_operator_ssh_allowlist_reconciles_from_explicit_normalized_input(self):
        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            canonical.write_text("MTE_OPERATOR_SSH_CIDRS=203.0.113.10/32\n")
            canonical.chmod(0o600)
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                value = original_stat(path, *args, **kwargs)
                fields = list(value)
                fields[4] = 0
                return os.stat_result(fields)

            with (
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(server_config, "config_object", return_value={}),
                mock.patch.object(
                    server_config, "active_config_object", return_value={}
                ),
                mock.patch.object(
                    server_config,
                    "declared_keys",
                    return_value=({"MTE_OPERATOR_SSH_CIDRS"}, {}, {}),
                ),
                mock.patch.object(
                    server_config, "compose_seed_catalog", return_value={}
                ),
                mock.patch.object(Path, "stat", root_owned_stat),
            ):
                result = server_config.init_source(
                    {"MTE_OPERATOR_SSH_CIDRS": "203.0.113.10/32,203.0.113.11/32"}
                )
                values = server_config.parse_env(canonical)

        self.assertEqual(
            values["MTE_OPERATOR_SSH_CIDRS"],
            "203.0.113.10/32,203.0.113.11/32",
        )
        self.assertEqual(result["reconciledOperatorKeys"], ["MTE_OPERATOR_SSH_CIDRS"])

    def test_operator_credentials_reconcile_but_provisioned_and_generated_stay_fill_only(
        self,
    ):
        canonical_token = "unit-canonical-token"
        replacement_token = "unit-replacement-token"
        generated_secret = "unit-generated-secret-preserved"
        provisioned_id = "unit-provisioned-id-preserved"
        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            canonical.write_text(
                "DATA_CONTENT_PROFILE=postgres-notion\n"
                f"NOTION_TOKEN={canonical_token}\n"
                "NOTION_ROOT_PAGE_ID=unit-root\n"
                f"NOTION_DOCUMENTS_PAGE_ID={provisioned_id}\n"
                f"PAPERCLIP_AUTH_SECRET={generated_secret}\n"
            )
            canonical.chmod(0o600)
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                value = original_stat(path, *args, **kwargs)
                fields = list(value)
                fields[4] = 0
                return os.stat_result(fields)

            required = {
                "DATA_CONTENT_PROFILE",
                "NOTION_ROOT_PAGE_ID",
                "NOTION_TOKEN",
                "NOTION_DOCUMENTS_PAGE_ID",
                "PAPERCLIP_AUTH_SECRET",
            }
            with (
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(server_config, "config_object", return_value={}),
                mock.patch.object(
                    server_config, "active_config_object", return_value={}
                ),
                mock.patch.object(
                    server_config,
                    "declared_keys",
                    return_value=(required, {}, {}),
                ),
                mock.patch.object(Path, "stat", root_owned_stat),
            ):
                result = server_config.init_source(
                    {
                        "NOTION_TOKEN": "unit-generic-token",
                        "PRIN7R_NOTION_API_KEY": "unit-api-key",
                        "PRIN7R_NOTION_TOKEN": replacement_token,
                        "NOTION_DOCUMENTS_PAGE_ID": "unit-replacement-id",
                        "PAPERCLIP_AUTH_SECRET": "unit-replacement-generated-secret",
                    }
                )
                values = server_config.parse_env(canonical)

        self.assertEqual(values["NOTION_TOKEN"], replacement_token)
        self.assertEqual(values["NOTION_DOCUMENTS_PAGE_ID"], provisioned_id)
        self.assertEqual(values["PAPERCLIP_AUTH_SECRET"], generated_secret)
        self.assertNotIn("PRIN7R_NOTION_TOKEN", values)
        self.assertNotIn("PRIN7R_NOTION_API_KEY", values)
        self.assertNotIn(canonical_token, json.dumps(result))
        self.assertNotIn(replacement_token, json.dumps(result))
        self.assertNotIn(generated_secret, json.dumps(result))

    def test_renderer_hardens_registered_secret_projections_and_lock_aliases(self):
        with tempfile.TemporaryDirectory() as temporary:
            secret_root = Path(temporary) / "secrets"
            service_root = secret_root / "services"
            service_root.mkdir(parents=True, mode=0o755)
            canonical = secret_root / "platform.env"
            manifest_path = secret_root / "projections-manifest.json"
            projection = service_root / "demo.env"
            legacy_lock = secret_root / "platform.env.lock"
            for path in (canonical, manifest_path, projection, legacy_lock):
                path.write_text("test-only\n")
                path.chmod(0o644)
            manifest = {"projections": [{"path": str(projection)}]}
            with (
                mock.patch.object(server_config, "SECRET_ROOT", secret_root),
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(server_config, "MANIFEST", manifest_path),
                mock.patch.object(
                    server_config, "LOCK", secret_root / ".platform-env.lock"
                ),
                mock.patch.object(server_config.os, "geteuid", return_value=0),
                mock.patch.object(server_config.os, "chown") as chown,
            ):
                server_config.harden_secret_projections(manifest)
            self.assertTrue(chown.called)
            self.assertTrue(
                all(
                    path.stat().st_mode & 0o777 == 0o600
                    for path in (canonical, manifest_path, projection, legacy_lock)
                )
            )
            self.assertEqual(secret_root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(service_root.stat().st_mode & 0o777, 0o700)

    def test_renderer_removes_only_unregistered_legacy_secret_projections(self):
        with tempfile.TemporaryDirectory() as temporary:
            secret_root = Path(temporary) / "secrets"
            secret_root.mkdir()
            canonical = secret_root / "platform.env"
            canonical.write_text("canonical-test-only\n")
            registered = secret_root / "claude.env"
            unregistered = {
                secret_root / "activepieces-admin.env",
                secret_root / "orloj.env",
            }
            unrelated = secret_root / "keep.env"
            for path in {registered, unrelated, *unregistered}:
                path.write_text("projection-test-only\n")

            original_lstat = Path.lstat

            def root_owned_lstat(path, *args, **kwargs):
                value = original_lstat(path, *args, **kwargs)
                fields = list(value)
                fields[4] = 0
                fields[5] = 0
                return os.stat_result(fields)

            manifest = {"projections": [{"path": str(registered)}]}
            with (
                mock.patch.object(server_config, "SECRET_ROOT", secret_root),
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(Path, "lstat", root_owned_lstat),
            ):
                removed = server_config.remove_unregistered_legacy_secret_projections(
                    manifest
                )

            self.assertEqual(set(removed), unregistered)
            self.assertTrue(canonical.is_file())
            self.assertTrue(registered.is_file())
            self.assertTrue(unrelated.is_file())
            self.assertTrue(all(not path.exists() for path in unregistered))

    def test_renderer_removes_exact_empty_legacy_secret_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            secret_root = Path(temporary) / "secrets"
            legacy = secret_root / "services/daytona-runtime.env"
            unrelated = secret_root / "services/keep.env"
            legacy.mkdir(parents=True)
            unrelated.mkdir()
            canonical = secret_root / "platform.env"
            canonical.write_text("canonical-test-only\n")

            original_lstat = Path.lstat

            def root_owned_lstat(path, *args, **kwargs):
                value = original_lstat(path, *args, **kwargs)
                if Path(path) == legacy:
                    fields = list(value)
                    fields[4] = 0
                    fields[5] = 0
                    return os.stat_result(fields)
                return value

            with (
                mock.patch.object(server_config, "SECRET_ROOT", secret_root),
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(Path, "lstat", root_owned_lstat),
            ):
                removed = server_config.remove_unregistered_legacy_secret_projections(
                    {"projections": []}
                )

            self.assertEqual(removed, [legacy])
            self.assertFalse(legacy.exists())
            self.assertTrue(unrelated.is_dir())
            self.assertTrue(canonical.is_file())

    def test_renderer_refuses_nonempty_legacy_secret_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            secret_root = Path(temporary) / "secrets"
            legacy = secret_root / "services/daytona-runtime.env"
            legacy.mkdir(parents=True)
            legacy.joinpath("unexpected").write_text("preserve-me\n")
            canonical = secret_root / "platform.env"
            canonical.write_text("canonical-test-only\n")

            original_lstat = Path.lstat

            def root_owned_lstat(path, *args, **kwargs):
                value = original_lstat(path, *args, **kwargs)
                if Path(path) == legacy:
                    fields = list(value)
                    fields[4] = 0
                    fields[5] = 0
                    return os.stat_result(fields)
                return value

            with (
                mock.patch.object(server_config, "SECRET_ROOT", secret_root),
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(Path, "lstat", root_owned_lstat),
                self.assertRaisesRegex(
                    server_config.ConfigError, "artifact directory is not empty"
                ),
            ):
                server_config.remove_unregistered_legacy_secret_projections(
                    {"projections": []}
                )

            self.assertTrue(legacy.joinpath("unexpected").is_file())
            self.assertTrue(canonical.is_file())

    def test_renderer_legacy_secret_cleanup_fails_closed_for_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            secret_root = Path(temporary) / "secrets"
            secret_root.mkdir()
            canonical = secret_root / "platform.env"
            canonical.write_text("canonical-test-only\n")
            safe_candidate = secret_root / "activepieces-admin.env"
            safe_candidate.write_text("projection-test-only\n")
            unsafe_candidate = secret_root / "claude.env"
            unsafe_candidate.symlink_to(canonical)

            original_lstat = Path.lstat

            def root_owned_lstat(path, *args, **kwargs):
                value = original_lstat(path, *args, **kwargs)
                if Path(path) == safe_candidate:
                    fields = list(value)
                    fields[4] = 0
                    fields[5] = 0
                    return os.stat_result(fields)
                return value

            with (
                mock.patch.object(server_config, "SECRET_ROOT", secret_root),
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(Path, "lstat", root_owned_lstat),
                self.assertRaisesRegex(server_config.ConfigError, "not a regular file"),
            ):
                server_config.remove_unregistered_legacy_secret_projections(
                    {"projections": []}
                )

            self.assertTrue(safe_candidate.is_file())
            self.assertTrue(unsafe_candidate.is_symlink())
            self.assertTrue(canonical.is_file())

    def test_renderer_legacy_secret_cleanup_rejects_non_root_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            secret_root = Path(temporary) / "secrets"
            secret_root.mkdir()
            canonical = secret_root / "platform.env"
            canonical.write_text("canonical-test-only\n")
            candidate = secret_root / "activepieces-admin.env"
            candidate.write_text("projection-test-only\n")

            original_lstat = Path.lstat

            def non_root_lstat(path, *args, **kwargs):
                value = original_lstat(path, *args, **kwargs)
                fields = list(value)
                fields[4] = 1000
                fields[5] = 1000
                return os.stat_result(fields)

            with (
                mock.patch.object(server_config, "SECRET_ROOT", secret_root),
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(Path, "lstat", non_root_lstat),
                self.assertRaisesRegex(server_config.ConfigError, "not root-owned"),
            ):
                server_config.remove_unregistered_legacy_secret_projections(
                    {"projections": []}
                )

            self.assertTrue(candidate.is_file())
            self.assertTrue(canonical.is_file())

    def test_renderer_legacy_secret_cleanup_never_removes_canonical_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            secret_root = Path(temporary) / "secrets"
            secret_root.mkdir()
            canonical = secret_root / "platform.env"
            canonical.write_text("canonical-test-only\n")
            with (
                mock.patch.object(server_config, "SECRET_ROOT", secret_root),
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(
                    server_config,
                    "LEGACY_SECRET_PROJECTION_RELATIVE_PATHS",
                    ("platform.env",),
                ),
                self.assertRaisesRegex(
                    server_config.ConfigError, "allowlist is unsafe"
                ),
            ):
                server_config.remove_unregistered_legacy_secret_projections(
                    {"projections": []}
                )

            self.assertTrue(canonical.is_file())

    def test_default_profile_declares_active_provider_service_projection(self):
        cfg = {
            "spec": {
                "components": [
                    {"id": "postgres"},
                    {"id": "postgrest"},
                    {"id": "toolhive"},
                ]
            }
        }
        values = {"DATA_CONTENT_PROFILE": "postgres-notion"}
        with mock.patch.object(
            server_config, "PROFILE_SOURCE", Path("/nonexistent/profile-catalog")
        ):
            required, service_keys, _ = server_config.declared_keys(cfg, values)
        self.assertIn("NOTION_TOKEN", required)
        self.assertIn("NOTION_ROOT_PAGE_ID", required)
        self.assertIn("notion", service_keys)

    def test_template_sync_render_template_sync_keeps_runtime_projections_clean(self):
        """A repeated source sync must never overwrite a rendered projection."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "platform"
            secret_root = Path(temp) / "secrets"
            config_source = root / "templates/platform.json"
            compose_source = root / "deployment/services/demo/compose.yaml"
            aggregate_compose = root / "deployment/compose.yaml"
            profile_source = root / "templates/profiles/profiles.yaml"
            runtime_config = root / "config/platform.json"
            runtime_compose = root / "runtime/deploy/demo.yaml"
            runtime_profile = root / "runtime/profiles/profiles.yaml"
            data_content_projection = root / "config/data-content-plane.json"
            platform_lock_source = root / "templates/platform.lock.yaml"
            canonical = secret_root / "platform.env"
            manifest = secret_root / "projections-manifest.json"

            config_source.parent.mkdir(parents=True)
            compose_source.parent.mkdir(parents=True)
            profile_source.parent.mkdir(parents=True)
            config_source.write_text(
                json.dumps(
                    {
                        "spec": {
                            "domainRef": "PLATFORM_BASE_DOMAIN",
                            "host": {"ssh": "root@example.test"},
                            "components": [
                                {
                                    "id": "demo",
                                    "compose": "deployment/services/demo/compose.yaml",
                                    "exposure": {
                                        "subdomainRef": "DEMO_SUBDOMAIN",
                                        "originPortRef": "DEMO_PORT",
                                        "accessClassRef": "DEMO_ACCESS_CLASS",
                                    },
                                }
                            ],
                        }
                    }
                )
            )
            compose_text = "services:\n  demo:\n    image: ${DEMO_IMAGE:?required}\n"
            profile_text = yaml.safe_dump(
                {
                    "apiVersion": "micro-task-engine/v1alpha1",
                    "kind": "PaperclipProfileCatalog",
                    "profiles": [{"ref": "unit", "nativeAdapter": "codex_local"}],
                },
                sort_keys=False,
            )
            compose_source.write_text(compose_text)
            aggregate_compose.write_text(
                "services:\n"
                "  demo:\n"
                "    extends:\n"
                "      file: services/demo/compose.yaml\n"
                "      service: demo\n"
            )
            profile_source.write_text(profile_text)
            platform_lock_source.write_text("spec: {}\n")

            replacements = {
                "ROOT": root,
                "SECRET_ROOT": secret_root,
                "SOURCE": canonical,
                "MANIFEST": manifest,
                "COMPOSE_ENV": secret_root / "compose.env",
                "AGGREGATE_COMPOSE": aggregate_compose,
                "LOCK": secret_root / ".platform-env.lock",
                "CONFIG_SOURCE": config_source,
                "CONFIG": runtime_config,
                "PLATFORM_LOCK_SOURCE": platform_lock_source,
                "DATA_CONTENT_PLANE": data_content_projection,
                "SERVICE_ROOT": secret_root / "services",
                "PROFILE_SOURCE": profile_source,
                "PROFILE_RUNTIME": runtime_profile,
                "PUBLIC_URLS": root / "config/public-urls.json",
                "CLOUDFLARE_APPS": secret_root / "cloudflare/apps.json",
                "CLOUDFLARE_API_ENV": secret_root / "cloudflare/api.env",
                "CLOUDFLARE_TUNNEL_TOKEN": secret_root / "cloudflare/tunnel-token",
                "CLOUDFLARE_ACCESS_TOKEN": secret_root
                / "cloudflare/access-service-token.json",
            }
            with ExitStack() as stack:
                for name, value in replacements.items():
                    stack.enter_context(mock.patch.object(server_config, name, value))
                fixture_contract = mock.Mock()
                fixture_contract.DataContentError = RuntimeError
                fixture_contract.resolve_from_paths.side_effect = (
                    lambda *args, **kwargs: {
                        "profile": "fixture",
                        "componentIds": ["demo"],
                        "roles": {
                            "tablesUi": {
                                "componentId": "demo",
                                "endpointRef": "DEMO_SUBDOMAIN",
                            },
                            "documentsUi": {
                                "componentId": "demo",
                                "endpointRef": "DEMO_SUBDOMAIN",
                            },
                        },
                        "adapters": {},
                        "_generated": {
                            "sourceSha256": kwargs["source_sha256"],
                            "generatorVersion": kwargs["generator_version"],
                        },
                    }
                )
                stack.enter_context(
                    mock.patch.object(
                        server_config,
                        "data_content_contract",
                        return_value=fixture_contract,
                    )
                )

                required, _, seeds = server_config.declared_keys(
                    server_config.config_object()
                )
                values = {key: seeds.get(key, "test-value") for key in required}
                values.update(
                    {
                        "DEMO_ACCESS_CLASS": "human",
                        "DEMO_IMAGE": "example/demo@sha256:" + "1" * 64,
                        "DEMO_PORT": "12345",
                        "DEMO_SUBDOMAIN": "demo",
                        "CLOUDFLARE_API_TOKEN": "unit-test-only",
                        "PLATFORM_BASE_DOMAIN": "agents.example.test",
                    }
                )
                server_config.write_env(canonical, values)

                # Unit tests run as the developer rather than root. Preserve all
                # content/hash semantics while bypassing only the server uid gate.
                stack.enter_context(
                    mock.patch.object(
                        server_config,
                        "source_state",
                        side_effect=lambda: (
                            server_config.parse_env(canonical),
                            hashlib.sha256(canonical.read_bytes()).hexdigest(),
                        ),
                    )
                )

                server_config.render()
                runtime_hashes = {
                    path: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (runtime_config, runtime_compose, runtime_profile)
                }

                # This is the second sync: rsync may replace/chmod templates,
                # but it must not share a physical path with runtime projections.
                compose_source.write_text(compose_text)
                profile_source.write_text(profile_text)
                config_source.write_text(config_source.read_text())
                for path in (config_source, compose_source, profile_source):
                    path.chmod(0o644)

                original_stat = Path.stat

                def root_owned_stat(path, *args, **kwargs):
                    value = original_stat(path, *args, **kwargs)
                    fields = list(value)
                    fields[4] = 0  # st_uid; production keeps the real root-only gate.
                    return os.stat_result(fields)

                with mock.patch.object(Path, "stat", root_owned_stat):
                    result = server_config.audit()

            self.assertTrue(result["ok"], result["findings"])
            self.assertEqual(
                runtime_hashes,
                {
                    path: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (runtime_config, runtime_compose, runtime_profile)
                },
            )
            self.assertTrue(
                all(path.stat().st_mode & 0o777 == 0o600 for path in runtime_hashes)
            )
            rendered = json.loads(runtime_config.read_text())
            self.assertEqual(
                rendered["spec"]["components"][0]["compose"],
                "runtime/deploy/demo.yaml",
            )
            self.assertTrue(
                {
                    str(runtime_config),
                    str(runtime_compose),
                    str(runtime_profile),
                }.issubset(
                    {
                        row["path"]
                        for row in json.loads(manifest.read_text())["projections"]
                    }
                )
            )

    def test_repeat_sync_targets_templates_and_never_runtime_projections(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "excluded": [],
                }
            }
        }
        commands = []
        uploaded_paths = []
        uploaded_manifests = []
        remote_commands = []

        def capture_upload(command, **_kwargs):
            commands.append(command)
            source = Path(command[-2])
            uploaded_paths.append(
                {
                    path.relative_to(source).as_posix()
                    for path in source.rglob("*")
                    if path.is_file()
                }
            )
            uploaded_manifests.append(
                (source / platform.SYNC_MANIFEST_NAME).read_text()
            )

        with (
            tempfile.TemporaryDirectory() as temp,
            mock.patch.object(
                platform, "local_evidence_root", return_value=Path(temp) / "evidence"
            ),
            mock.patch.object(
                platform.uuid,
                "uuid4",
                side_effect=[mock.Mock(hex="first"), mock.Mock(hex="second")],
            ),
            mock.patch.object(platform.fcntl, "flock") as local_locks,
            mock.patch.object(
                platform,
                "ssh",
                side_effect=lambda _cfg, command, **_kwargs: remote_commands.append(
                    command
                ),
            ),
            mock.patch.object(
                platform,
                "run",
                side_effect=capture_upload,
            ),
        ):
            platform.sync(cfg)
            platform.sync(cfg)
        stages = [
            "/opt/mte-platform/.sync-staging-first",
            "/opt/mte-platform/.sync-staging-second",
        ]
        self.assertEqual(len(commands), 2)
        self.assertEqual(
            [call.args[1] for call in local_locks.call_args_list],
            [
                platform.fcntl.LOCK_EX,
                platform.fcntl.LOCK_UN,
                platform.fcntl.LOCK_EX,
                platform.fcntl.LOCK_UN,
            ],
        )
        self.assertTrue(
            [command[-1] for command in commands]
            == [f"root@example.test:{stage}/" for stage in stages]
        )
        self.assertTrue(all("--delete" in command for command in commands))
        expected_paths = {
            "deployment/compose.yaml",
            "deployment/scripts/compose-remote.sh",
            "templates/profiles/profiles.yaml",
            "runtime/paperclip/profiles/skills/verification-before-completion/SKILL.md",
            "templates/platform.json",
            "templates/compose-seeds.lock.json",
            "config/acceptance-requirements.yaml",
            "runtime/paperclip/scripts/bootstrap-paperclip.py",
            "runtime/paperclip/scripts/profile_catalog.py",
            "runtime/paperclip/scripts/integration_canary.py",
            "bin/server-observability-canary.py",
            "bin/server-integration-canaries.py",
            platform.SYNC_MANIFEST_NAME,
        }
        self.assertTrue(all(expected_paths.issubset(paths) for paths in uploaded_paths))
        self.assertTrue(
            all(
                "templates/profiles/catalog.yaml" not in paths
                for paths in uploaded_paths
            )
        )
        self.assertTrue(
            all(
                not any(path.startswith("runtime/deploy/") for path in paths)
                for paths in uploaded_paths
            )
        )
        self.assertTrue(
            all("config/platform.json" not in paths for paths in uploaded_paths)
        )
        self.assertTrue(
            all("projections-manifest.json" not in paths for paths in uploaded_paths)
        )
        self.assertTrue(all("-rtz" in command for command in commands))
        for manifest in uploaded_manifests:
            manifest_paths = [line.split("  ", 1)[1] for line in manifest.splitlines()]
            self.assertEqual(manifest_paths, sorted(manifest_paths))
        ownership_gates = [
            command for command in remote_commands if "chown -R root:root" in command
        ]
        self.assertEqual(len(ownership_gates), 2)
        self.assertTrue(
            all(
                "! -user root -o ! -group root" in command
                for command in ownership_gates
            )
        )
        self.assertTrue(
            all(
                '-name "*.sh" -exec chmod 0700' in command
                for command in ownership_gates
            )
        )
        self.assertTrue(
            all(
                "deployment/scripts/support" not in command
                for command in ownership_gates
            )
        )
        self.assertTrue(
            all('"$root/patches"' not in command for command in ownership_gates)
        )
        self.assertTrue(
            all('rm -rf "$root/patches"' not in command for command in ownership_gates)
        )
        self.assertTrue(
            all(
                'rsync -rtp --delete --ignore-times "$stage/$rel/" "$root/$rel/"'
                in command
                for command in ownership_gates
            )
        )
        self.assertTrue(
            all(
                'lock="$root/.sync.lock"; : > "$lock"; chown root:root "$lock"; '
                'chmod 0600 "$lock"; exec 9>"$lock"; flock -x 9' in command
                for command in ownership_gates
            )
        )
        self.assertTrue(
            all('rm -rf "$stage"' in command for command in ownership_gates)
        )
        self.assertTrue(
            all(
                command.index("sha256sum -c") < command.index("chown -R root:root")
                and f"rm -f {platform.SYNC_MANIFEST_NAME}" in command
                for command in ownership_gates
            )
        )
        self.assertTrue(
            all(
                "support/paperclip/package-lock.json" not in command
                and "support/daytona/package-lock.json" not in command
                for command in ownership_gates
            )
        )

    def test_sync_manifest_failure_prevents_live_tree_publish(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "platform"
            cfg = {
                "spec": {
                    "host": {
                        "ssh": "root@example.test",
                        "root": str(root),
                        "excluded": [],
                    }
                }
            }
            remote_commands = []
            with (
                mock.patch.object(
                    platform,
                    "local_evidence_root",
                    return_value=Path(temp) / "evidence",
                ),
                mock.patch.object(
                    platform,
                    "ssh",
                    side_effect=lambda _cfg, command, **_kwargs: remote_commands.append(
                        command
                    ),
                ),
                mock.patch.object(
                    platform.uuid, "uuid4", return_value=mock.Mock(hex="test-stage")
                ),
                mock.patch.object(platform, "run"),
            ):
                platform.sync(cfg)

            live = root / "bin/proof.txt"
            live.parent.mkdir(parents=True)
            live.write_text("live\n")
            stage = root / ".sync-staging-test-stage"
            stage.mkdir()
            (stage / "proof.txt").write_text("tampered\n")
            expected = hashlib.sha256(b"expected\n").hexdigest()
            (stage / platform.SYNC_MANIFEST_NAME).write_text(f"{expected}  proof.txt\n")
            result = subprocess.run(
                ["bash", "-c", remote_commands[-1]], capture_output=True, text=True
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(live.read_text(), "live\n")

            (stage / platform.SYNC_MANIFEST_NAME).write_text("")
            omitted_result = subprocess.run(
                ["bash", "-c", remote_commands[-1]], capture_output=True, text=True
            )
            self.assertNotEqual(omitted_result.returncode, 0)
            self.assertEqual(live.read_text(), "live\n")

    def test_sync_upload_failure_removes_only_its_uuid_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "platform"
            other_stage = root / ".sync-staging-other"
            other_stage.mkdir(parents=True)
            cfg = {
                "spec": {
                    "host": {
                        "ssh": "root@example.test",
                        "root": str(root),
                        "excluded": [],
                    }
                }
            }

            def local_ssh(_cfg, command, **kwargs):
                return subprocess.run(
                    ["bash", "-c", command],
                    check=kwargs.get("check", True),
                    capture_output=True,
                    text=True,
                )

            with (
                mock.patch.object(
                    platform,
                    "local_evidence_root",
                    return_value=Path(temp) / "evidence",
                ),
                mock.patch.object(
                    platform.uuid, "uuid4", return_value=mock.Mock(hex="upload-fail")
                ),
                mock.patch.object(platform, "ssh", side_effect=local_ssh),
                mock.patch.object(
                    platform,
                    "run",
                    side_effect=subprocess.CalledProcessError(23, ["rsync"]),
                ),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    platform.sync(cfg)

            self.assertFalse((root / ".sync-staging-upload-fail").exists())
            self.assertTrue(other_stage.is_dir())

    def test_sync_publish_failure_removes_only_its_uuid_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "platform"
            current_stage = root / ".sync-staging-publish-fail"
            other_stage = root / ".sync-staging-other"
            other_stage.mkdir(parents=True)
            cfg = {
                "spec": {
                    "host": {
                        "ssh": "root@example.test",
                        "root": str(root),
                        "excluded": [],
                    }
                }
            }

            def failing_publish(_cfg, command, **kwargs):
                if 'lock="$root/.sync.lock"' in command:
                    raise subprocess.CalledProcessError(1, ["ssh"])
                return subprocess.run(
                    ["bash", "-c", command],
                    check=kwargs.get("check", True),
                    capture_output=True,
                    text=True,
                )

            with (
                mock.patch.object(
                    platform,
                    "local_evidence_root",
                    return_value=Path(temp) / "evidence",
                ),
                mock.patch.object(
                    platform.uuid,
                    "uuid4",
                    return_value=mock.Mock(hex="publish-fail"),
                ),
                mock.patch.object(platform, "ssh", side_effect=failing_publish),
                mock.patch.object(platform, "run"),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    platform.sync(cfg)

            self.assertFalse(current_stage.exists())
            self.assertTrue(other_stage.is_dir())

    def test_sync_bundle_rejects_symlinks_and_special_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            regular = source / "regular.txt"
            regular.write_text("regular\n")
            link = source / "link.txt"
            link.symlink_to(regular)
            with self.assertRaisesRegex(platform.PlatformError, "special file"):
                platform._copy_sync_tree(source, root / "link-bundle")

            link.unlink()
            fifo = source / "pipe"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(platform.PlatformError, "special file"):
                platform._copy_sync_tree(source, root / "fifo-bundle")

    def test_sync_rsync_flags_are_supported_by_local_client(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            destination.mkdir()
            (source / "proof.txt").write_text("portable\n")
            result = subprocess.run(
                ["rsync", "-rtz", "--delete", f"{source}/", f"{destination}/"],
                capture_output=True,
                text=True,
            )
            copied = (destination / "proof.txt").read_text()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(copied, "portable\n")

    def test_sync_live_permission_audit_checks_files_not_directories(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "excluded": [],
                }
            }
        }
        remote_commands = []
        with (
            tempfile.TemporaryDirectory() as temp,
            mock.patch.object(
                platform, "local_evidence_root", return_value=Path(temp) / "evidence"
            ),
            mock.patch.object(
                platform,
                "ssh",
                side_effect=lambda _cfg, command, **_kwargs: remote_commands.append(
                    command
                ),
            ),
            mock.patch.object(platform, "run"),
        ):
            platform.sync(cfg)

        publish = remote_commands[-1]
        self.assertIn(
            '"$root/config/services" -type f ! -perm 0644 -print -quit',
            publish,
        )

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            nested = root / "nested"
            nested.mkdir(mode=0o755)
            safe = nested / "safe.txt"
            safe.write_text("safe\n")
            safe.chmod(0o644)
            unsafe = nested / "unsafe.txt"
            unsafe.write_text("unsafe\n")
            unsafe.chmod(0o600)
            result = subprocess.run(
                [
                    "find",
                    str(root),
                    "-type",
                    "f",
                    "!",
                    "-perm",
                    "0644",
                    "-print",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.stdout.splitlines(), [str(unsafe)])

    def test_secret_mutation_renders_and_audits_without_deployment(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "excluded": [],
                },
                "components": [{"id": "demo", "compose": "deploy/demo.yaml"}],
            }
        }
        calls = []
        with (
            mock.patch.object(platform, "config", return_value=cfg),
            mock.patch.object(platform, "sync"),
            mock.patch.object(
                platform,
                "ssh",
                side_effect=lambda _cfg, command, **_kwargs: calls.append(command),
            ),
        ):
            platform.cmd_secrets(argparse.Namespace(domain=None, action="init"))
        self.assertIn("server-secrets.py init", calls[0])
        self.assertIn("server-config.py render", calls[1])
        self.assertIn("server-config.py audit", calls[1])

        self.assertFalse(hasattr(platform, "deploy_components"))
        self.assertFalse(hasattr(platform, "cmd_deploy"))

    def test_integration_canary_orchestrator_accepts_c029_persistence_probe(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "excluded": [],
                }
            }
        }
        commands = []
        with (
            mock.patch.object(platform, "sync") as sync,
            mock.patch.object(
                platform,
                "ssh",
                side_effect=lambda _cfg, command, **_kwargs: commands.append(command),
            ),
        ):
            platform.run_integration_canaries(cfg, "run", ["C029"])
        sync.assert_called_once_with(cfg)
        self.assertEqual(len(commands), 1)
        self.assertIn(
            "python3 /opt/mte-platform/bin/server-integration-canaries.py run C029",
            commands[0],
        )

    def test_cloudflare_token_apply_syncs_producer_before_locked_bootstrap(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "excluded": [],
                }
            }
        }
        observed = []
        with tempfile.TemporaryDirectory() as temp:
            operator_env = Path(temp) / "operator.env"
            operator_env.write_text("CLOUDFLARE_API_TOKEN=unit-token\n")
            operator_env.chmod(0o600)
            platform.OPERATOR_ENV_OVERRIDE = operator_env
            with (
                mock.patch.object(
                    platform,
                    "sync",
                    side_effect=lambda _cfg, **kwargs: observed.append(
                        ("sync", kwargs)
                    ),
                ),
                mock.patch.object(
                    platform,
                    "run",
                    side_effect=lambda command, **_kwargs: observed.append(
                        ("bootstrap", command)
                    ),
                ),
                mock.patch.object(platform, "ssh") as ssh,
            ):
                platform.run_cloudflare(cfg, "token-apply")
        self.assertEqual(observed[0], ("sync", {"render_projections": False}))
        self.assertEqual(observed[1][0], "bootstrap")
        self.assertIn("cloudflare-token-bootstrap.py", " ".join(observed[1][1]))
        ssh.assert_not_called()

    def test_cloudflare_dns_reconciler_uses_canonical_inputs_and_tunnel_output(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "secretsRoot": "/root/.config/mte-secrets",
                    "excluded": [],
                }
            }
        }
        with mock.patch.object(platform, "tofu_command", return_value="tofu-output"):
            command = platform.cloudflare_dns_command(
                cfg,
                "/root/.config/mte-secrets/cloudflare/iac",
                "/root/.config/mte-secrets/cloudflare/api.env",
                "verify",
            )
        self.assertIn('tunnel_id=$(tofu-output); test -n "$tunnel_id"', command)
        self.assertIn(
            "python3 /opt/mte-platform/bin/server-cloudflare-dns.py verify", command
        )
        self.assertIn("--env-file /root/.config/mte-secrets/platform.env", command)
        self.assertIn(
            "--tfvars /root/.config/mte-secrets/cloudflare/iac/terraform.tfvars.json",
            command,
        )
        self.assertIn('--tunnel-id "$tunnel_id"', command)
        self.assertIn(
            "--output /opt/mte-platform/evidence/cloudflare-dns-reconcile.json",
            command,
        )

    def test_cloudflare_apply_runs_the_edge_reconciler_after_iac(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "secretsRoot": "/root/.config/mte-secrets",
                    "excluded": [],
                }
            }
        }
        commands = []
        tofu_calls = []

        def record_tofu(*arguments):
            tofu_calls.append(arguments)
            return "tofu"

        with (
            mock.patch.object(platform, "cloudflare_preflight"),
            mock.patch.object(
                platform,
                "prepare_cloudflare_remote",
                return_value=(
                    "/root/.config/mte-secrets/cloudflare",
                    "/root/.config/mte-secrets/cloudflare/iac",
                    "/root/.config/mte-secrets/cloudflare/api.env",
                ),
            ),
            mock.patch.object(platform, "tofu_command", side_effect=record_tofu),
            mock.patch.object(platform, "cloudflare_dns_command", return_value="dns"),
            mock.patch.object(
                platform,
                "ssh",
                side_effect=lambda _cfg, command, **_kwargs: commands.append(command),
            ),
        ):
            platform.run_cloudflare(cfg, "apply")

        self.assertEqual(len(commands), 2)
        apply_call = next(call for call in tofu_calls if "apply" in call)
        self.assertIn("-auto-approve", apply_call)
        self.assertIn("server-cloudflare-access.py", commands[-1])
        self.assertLess(
            commands[-1].index("server-cloudflare-access.py"),
            commands[-1].index("dns"),
        )

    def test_cloudflare_access_failure_never_publishes_dns(self):
        cfg = {"spec": {}}
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "dns-published"
            with (
                mock.patch.object(
                    platform, "cloudflare_access_command", return_value="false"
                ),
                mock.patch.object(
                    platform,
                    "cloudflare_dns_command",
                    return_value=f"touch {shlex.quote(str(marker))}",
                ),
            ):
                command = platform.cloudflare_edge_command(
                    cfg, "/iac", "/api.env", "apply"
                )
            completed = subprocess.run(["sh", "-c", "set -e; " + command], check=False)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(marker.exists())

    def test_compose_seed_catalog_is_used_once_and_never_reapplied(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "platform"
            secret_root = Path(temp) / "secrets"
            config_source = root / "templates/platform.json"
            compose_source = root / "deployment/services/demo/compose.yaml"
            catalog_source = root / "templates/compose-seeds.lock.json"
            canonical = secret_root / "platform.env"
            compose_source.parent.mkdir(parents=True)
            config_source.parent.mkdir(parents=True)
            config_source.write_text(
                json.dumps(
                    {
                        "spec": {
                            "components": [
                                {
                                    "id": "demo",
                                    "compose": "deployment/services/demo/compose.yaml",
                                }
                            ]
                        }
                    }
                )
            )
            compose_source.write_text(
                "services:\n"
                "  demo:\n"
                "    image: ${DEMO_IMAGE:?required}\n"
                "    ports:\n"
                "      - ${DEMO_PORT_1_MAPPING:?required}\n"
            )
            expected_image = "example/demo@sha256:" + "1" * 64
            catalog_source.write_text(
                json.dumps(
                    {
                        "apiVersion": "micro-task-engine/v1alpha1",
                        "kind": "ComposeSeedCatalog",
                        "metadata": {"contractVersion": 1, "source": "unit-test"},
                        "seeds": {
                            "DEMO_IMAGE": expected_image,
                            "DEMO_PORT_1_MAPPING": "127.0.0.1:18000:8000",
                        },
                    }
                )
            )
            replacements = {
                "ROOT": root,
                "SECRET_ROOT": secret_root,
                "SOURCE": canonical,
                "LOCK": secret_root / ".platform-env.lock",
                "CONFIG_SOURCE": config_source,
                "PROFILE_SOURCE": root / "templates/profiles/missing.json",
                "COMPOSE_SEED_SOURCE": catalog_source,
            }
            with ExitStack() as stack:
                for name, value in replacements.items():
                    stack.enter_context(mock.patch.object(server_config, name, value))
                first = server_config.init_source({})
                values = server_config.parse_env(canonical)
                self.assertEqual(values["DEMO_IMAGE"], expected_image)
                self.assertEqual(values["DEMO_PORT_1_MAPPING"], "127.0.0.1:18000:8000")
                self.assertIn("DEMO_IMAGE", first["createdKeys"])

                # Simulate an upgrade from a canonical file created before the
                # private agent-plane gateway/profile routing contract existed.
                # General one-time seeds remain fill-only on a populated source,
                # unlike the intentionally ignored Compose bootstrap catalog.
                gateway_upgrade_keys = {
                    key
                    for key in server_config.ONE_TIME_MIGRATION_SEEDS
                    if key == "MTE_AGENT_PLANE_NETWORK"
                    or key.startswith("MTE_AGENT_GATEWAY_")
                    or (
                        key.startswith("TOOLHIVE_PROFILE_CODING_DAYTONA_")
                        and key.endswith("_PROXY_PORT")
                    )
                }
                self.assertEqual(len(gateway_upgrade_keys), 25)
                self.assertIn(
                    "MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL",
                    gateway_upgrade_keys,
                )
                for key in gateway_upgrade_keys:
                    values.pop(key, None)

                # An invalid catalog proves a non-empty canonical source does
                # not even consult bootstrap data on a repeated init.
                values["DEMO_IMAGE"] = "operator.example/demo@sha256:" + "2" * 64
                server_config.write_env(canonical, values)
                catalog_source.write_text("{}\n")
                original_stat = Path.stat

                def root_owned_stat(path, *args, **kwargs):
                    value = original_stat(path, *args, **kwargs)
                    fields = list(value)
                    fields[4] = 0
                    return os.stat_result(fields)

                with mock.patch.object(Path, "stat", root_owned_stat):
                    second = server_config.init_source({})

            self.assertEqual(
                server_config.parse_env(canonical)["DEMO_IMAGE"],
                "operator.example/demo@sha256:" + "2" * 64,
            )
            self.assertNotIn("DEMO_IMAGE", second["createdKeys"])
            upgraded = server_config.parse_env(canonical)
            self.assertEqual(upgraded["MTE_AGENT_PLANE_NETWORK"], "mte-agent-plane")
            self.assertTrue(gateway_upgrade_keys <= set(second["createdKeys"]))
            self.assertTrue(all(upgraded[key] for key in gateway_upgrade_keys))
            self.assertEqual(
                upgraded["MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM"],
                "http://toolhive:19011",
            )
            self.assertEqual(
                upgraded["MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_UPSTREAM"],
                "http://toolhive:19012",
            )
            self.assertEqual(
                upgraded["MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM"],
                "http://toolhive:19013",
            )

    def test_host_bootstrap_source_imports_compose_catalog_once(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "platform"
            secret_root = Path(temp) / "secrets"
            config_source = root / "templates/platform.json"
            compose_source = root / "deployment/services/demo/compose.yaml"
            catalog_source = root / "templates/compose-seeds.lock.json"
            canonical = secret_root / "platform.env"
            compose_source.parent.mkdir(parents=True)
            config_source.parent.mkdir(parents=True)
            secret_root.mkdir(parents=True)
            config_source.write_text(
                json.dumps(
                    {
                        "spec": {
                            "components": [
                                {
                                    "id": "demo",
                                    "compose": "deployment/services/demo/compose.yaml",
                                }
                            ]
                        }
                    }
                )
            )
            compose_source.write_text(
                "services:\n  demo:\n    image: ${DEMO_IMAGE:?required}\n"
            )
            catalog_source.write_text(
                json.dumps(
                    {
                        "apiVersion": "micro-task-engine/v1alpha1",
                        "kind": "ComposeSeedCatalog",
                        "metadata": {"contractVersion": 1, "source": "unit-test"},
                        "seeds": {"DEMO_IMAGE": "example/demo@sha256:" + "1" * 64},
                    }
                )
            )
            canonical.write_text("MTE_DOCKER_CE_VERSION=unit-host-seed\n")
            canonical.chmod(0o600)
            replacements = {
                "ROOT": root,
                "SECRET_ROOT": secret_root,
                "SOURCE": canonical,
                "LOCK": secret_root / ".platform-env.lock",
                "CONFIG_SOURCE": config_source,
                "PROFILE_SOURCE": root / "templates/profiles/missing.json",
                "COMPOSE_SEED_SOURCE": catalog_source,
            }
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                value = original_stat(path, *args, **kwargs)
                fields = list(value)
                fields[4] = 0
                return os.stat_result(fields)

            with ExitStack() as stack:
                for name, value in replacements.items():
                    stack.enter_context(mock.patch.object(server_config, name, value))
                stack.enter_context(mock.patch.object(Path, "stat", root_owned_stat))
                result = server_config.init_source({})

            values = server_config.parse_env(canonical)
            self.assertEqual(values["DATA_CONTENT_PROFILE"], "postgres-notion")
            self.assertEqual(values["DEMO_IMAGE"], "example/demo@sha256:" + "1" * 64)
            self.assertIn("DEMO_IMAGE", result["createdKeys"])

    def test_existing_install_migrates_reviewed_nested_ports_through_docker_config(
        self,
    ):
        daytona_upgrade_keys = {
            "MTE_DAYTONA_API_ENV_DB_HOST",
            "MTE_DAYTONA_API_ENV_OTEL_ENABLED",
            "MTE_DAYTONA_API_ENV_REDIS_HOST",
            "MTE_DAYTONA_API_PORT_1_MAPPING",
            "MTE_DAYTONA_DEX_PORT_1_MAPPING",
            "MTE_DAYTONA_PROXY_ENV_PREVIEW_WARNING_ENABLED",
            "MTE_DAYTONA_PROXY_ENV_REDIS_HOST",
            "MTE_DAYTONA_PROXY_ENV_TOOLBOX_ONLY_MODE",
            "MTE_DAYTONA_PROXY_PORT_1_MAPPING",
            "MTE_DAYTONA_REGISTRY_ENV_REGISTRY_STORAGE_DELETE_ENABLED",
            "MTE_DAYTONA_RUNNER_ENV_INTER_SANDBOX_NETWORK_ENABLED",
            "MTE_DAYTONA_RUNNER_ENV_RUNNER_DOMAIN",
            "MTE_DAYTONA_SSH_GATEWAY_PORT_1_MAPPING",
        }
        self.assertEqual(len(daytona_upgrade_keys), 13)

        operator_values = {
            "MTE_DAYTONA_SANDBOX_IMAGE": "ghcr.io/example/daytona@sha256:"
            + "c" * 64,
            "MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL": "https://github.com/example/platform",
            "MTE_DAYTONA_SANDBOX_IMAGE_REVISION": "d" * 40,
            "CLOUDFLARE_ACCESS_ALLOWED_EMAILS": "operator@example.test",
            "CLOUDFLARE_ACCOUNT_ID": "unit-account",
            "CLOUDFLARE_API_TOKEN": "unit-cloudflare-token-must-stay-redacted",
            "CLOUDFLARE_ZONE_ID": "unit-zone",
            "E2E_GITHUB_BASE_BRANCH": "main",
            "E2E_GITHUB_OWNER": "example-org",
            "E2E_GITHUB_REPOSITORY": "agent-canary",
            "GITHUB_TOKEN": "unit-github-token-must-stay-redacted",
            "MINIMAX_API_KEY": "unit-minimax-token-must-stay-redacted",
            "MINIMAX_BASE_URL": "https://llm.example.test/v1",
            "MINIMAX_MODEL": "unit-model",
            "MTE_EXCLUDED_HOST_1": "192.0.2.10",
            "MTE_EXCLUDED_HOST_2": "192.0.2.11",
            "MTE_OPERATOR_SSH_CIDRS": "198.51.100.0/24",
            "MTE_SSH_TARGET": "root@198.51.100.10",
            "NOTION_ROOT_PAGE_ID": "00000000-0000-4000-8000-000000000001",
            "NOTION_TOKEN": "unit-notion-token-must-stay-redacted",
            "PLATFORM_BASE_DOMAIN": "upgrade.example.test",
        }
        with tempfile.TemporaryDirectory() as temp:
            temporary = Path(temp)
            platform_root = temporary / "platform"
            secret_root = temporary / "secrets"
            shutil.copytree(ROOT / "deployment", platform_root / "deployment")
            template_root = platform_root / "templates"
            (template_root / "profiles").mkdir(parents=True)
            config_source = template_root / "platform.json"
            config_source.write_text(
                json.dumps(yaml.safe_load((ROOT / "config/platform.yaml").read_text()))
                + "\n"
            )
            shutil.copy2(
                ROOT / "config/platform.lock.yaml",
                template_root / "platform.lock.yaml",
            )
            shutil.copy2(
                ROOT / "config/compose-seeds.lock.json",
                template_root / "compose-seeds.lock.json",
            )
            shutil.copy2(
                ROOT / "config/profiles/catalog.yaml",
                template_root / "profiles/profiles.yaml",
            )
            canonical = secret_root / "platform.env"
            replacements = {
                "ROOT": platform_root,
                "SECRET_ROOT": secret_root,
                "SOURCE": canonical,
                "MANIFEST": secret_root / "projections-manifest.json",
                "COMPOSE_ENV": secret_root / "compose.env",
                "AGGREGATE_COMPOSE": platform_root / "deployment/compose.yaml",
                "LOCK": secret_root / ".platform-env.lock",
                "CONFIG_SOURCE": config_source,
                "CONFIG": platform_root / "config/platform.json",
                "SERVICE_ROOT": secret_root / "services",
                "PROFILE_SOURCE": template_root / "profiles/profiles.yaml",
                "PROFILE_RUNTIME": platform_root / "runtime/profiles/profiles.yaml",
                "COMPOSE_SEED_SOURCE": template_root / "compose-seeds.lock.json",
                "PLATFORM_LOCK_SOURCE": template_root / "platform.lock.yaml",
                "PUBLIC_URLS": platform_root / "config/public-urls.json",
                "DATA_CONTENT_PLANE": platform_root / "config/data-content-plane.json",
                "CLOUDFLARE_APPS": secret_root / "cloudflare/apps.json",
                "CLOUDFLARE_API_ENV": secret_root / "cloudflare/api.env",
                "CLOUDFLARE_TUNNEL_TOKEN": secret_root / "cloudflare/tunnel-token",
                "CLOUDFLARE_ACCESS_TOKEN": secret_root
                / "cloudflare/access-service-token.json",
            }
            secret_replacements = {
                "ROOT": platform_root,
                "SECRET_ROOT": secret_root,
                "PLATFORM_ENV": canonical,
                "SERVICE_ROOT": secret_root / "services",
                "INTEGRATION_ROOT": secret_root / "integrations",
                "CONFIG": platform_root / "config/platform.json",
                "CONFIG_TEMPLATE": config_source,
                "LOCK": secret_root / ".platform-env.lock",
            }
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                value = original_stat(path, *args, **kwargs)
                fields = list(value)
                if (
                    value.st_mode & 0o170000 == 0o100000
                    and path != server_config.LOCK
                ):
                    fields[4] = 0
                return os.stat_result(fields)

            fixture_owner = temporary.lstat()
            with ExitStack() as stack:
                for name, value in replacements.items():
                    stack.enter_context(mock.patch.object(server_config, name, value))
                for name, value in secret_replacements.items():
                    if hasattr(server_secrets, name):
                        stack.enter_context(
                            mock.patch.object(server_secrets, name, value)
                        )
                stack.enter_context(
                    mock.patch.object(
                        server_config.os,
                        "geteuid",
                        return_value=fixture_owner.st_uid,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        server_config.os,
                        "getegid",
                        return_value=fixture_owner.st_gid,
                    )
                )
                stack.enter_context(mock.patch.object(Path, "stat", root_owned_stat))

                server_config.init_source(operator_values)
                with redirect_stdout(io.StringIO()):
                    server_secrets.init()
                old_values = server_config.parse_env(canonical)
                for key in daytona_upgrade_keys:
                    self.assertIn(key, old_values)
                    old_values.pop(key)
                old_values.update(
                    server_config.REVIEWED_LEGACY_COMPOSE_VALUE_MIGRATIONS
                )
                for key in server_config.DERIVED_VALUE_KEYS:
                    old_values.pop(key, None)
                server_config.write_env(canonical, old_values)

                upgraded = server_config.init_source({})
                canonical_values = server_config.parse_env(canonical)
                migrated_canonical = dict(canonical_values)
                rendered = server_config.render()
                audited = server_config.audit()
                docker_config = None
                if shutil.which("docker"):
                    version = subprocess.run(
                        ["docker", "compose", "version"],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    if version.returncode == 0:
                        docker_config = subprocess.run(
                            [
                                "docker",
                                "compose",
                                "--env-file",
                                str(replacements["COMPOSE_ENV"]),
                                "--file",
                                str(replacements["AGGREGATE_COMPOSE"]),
                                "config",
                                "--quiet",
                            ],
                            env={
                                "HOME": os.environ.get("HOME", "/tmp"),
                                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                            },
                            text=True,
                            capture_output=True,
                            check=False,
                        )
                unknown_key = "MTE_FIRECRAWL_API_PORT_1_MAPPING"
                unknown_value = "127.0.0.1:${UNREVIEWED_HOST_PORT:-13002}:3002"
                canonical_values[unknown_key] = unknown_value
                server_config.write_env(canonical, canonical_values)
                unknown_upgrade = server_config.init_source({})
                unknown_values = server_config.parse_env(canonical)
                with self.assertRaisesRegex(
                    server_config.ConfigError,
                    f"aggregate Compose ref is invalid: {unknown_key}",
                ):
                    server_config.render()

            self.assertEqual(
                daytona_upgrade_keys,
                daytona_upgrade_keys & set(upgraded["createdKeys"]),
            )
            self.assertTrue(
                all(migrated_canonical[key] for key in daytona_upgrade_keys)
            )
            locked = json.loads((ROOT / "config/compose-seeds.lock.json").read_text())[
                "seeds"
            ]
            legacy_keys = set(server_config.REVIEWED_LEGACY_COMPOSE_VALUE_MIGRATIONS)
            self.assertEqual(
                {key: migrated_canonical[key] for key in legacy_keys},
                {key: locked[key] for key in legacy_keys},
            )
            self.assertTrue(legacy_keys <= set(upgraded["migratedKeys"]))
            self.assertTrue(
                (
                    server_config.DERIVED_VALUE_KEYS - {"MTE_DAYTONA_PROXY_DOMAIN"}
                ).isdisjoint(migrated_canonical)
            )
            self.assertEqual(
                migrated_canonical["MTE_DAYTONA_PROXY_DOMAIN"],
                "mte-daytona-proxy:4000",
            )
            for key, value in operator_values.items():
                self.assertEqual(migrated_canonical[key], value, key)
            self.assertGreater(rendered["projectionCount"], 0)
            self.assertTrue(audited["ok"])
            self.assertEqual(unknown_values[unknown_key], unknown_value)
            self.assertNotIn(unknown_key, unknown_upgrade["migratedKeys"])
            if docker_config is not None:
                self.assertEqual(docker_config.returncode, 0, docker_config.stderr)
            output = json.dumps(
                {"init": upgraded, "render": rendered, "audit": audited}
            )
            for value in operator_values.values():
                if "token" in value:
                    self.assertNotIn(value, output)

    def test_reviewed_compose_upgrade_fills_missing_without_overwriting(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "platform"
            secret_root = Path(temp) / "secrets"
            config_source = root / "templates/platform.json"
            compose_source = root / "deployment/services/demo/compose.yaml"
            catalog_source = root / "templates/compose-seeds.lock.json"
            canonical = secret_root / "platform.env"
            compose_source.parent.mkdir(parents=True)
            config_source.parent.mkdir(parents=True)
            secret_root.mkdir(parents=True)
            config_source.write_text(
                json.dumps(
                    {
                        "spec": {
                            "components": [
                                {
                                    "id": "demo",
                                    "compose": "deployment/services/demo/compose.yaml",
                                    "secrets": ["DEMO_API_TOKEN"],
                                }
                            ]
                        }
                    }
                )
            )
            compose_source.write_text(
                "services:\n"
                "  demo:\n"
                "    image: ${DEMO_IMAGE:?required}\n"
                "    ports:\n"
                "      - ${DEMO_PORT_1_MAPPING:?required}\n"
            )
            catalog_source.write_text(
                json.dumps(
                    {
                        "apiVersion": "micro-task-engine/v1alpha1",
                        "kind": "ComposeSeedCatalog",
                        "metadata": {"contractVersion": 1, "source": "unit-test"},
                        "seeds": {
                            "DEMO_IMAGE": "example/demo@sha256:" + "1" * 64,
                            "DEMO_PORT_1_MAPPING": "127.0.0.1:18000:8000",
                        },
                    }
                )
            )
            operator_image = "operator.example/demo@sha256:" + "2" * 64
            operator_secret = "operator-secret-must-be-preserved"
            canonical.write_text(
                "DATA_CONTENT_PROFILE=postgres-notion\n"
                f"DEMO_IMAGE={operator_image}\n"
                f"DEMO_API_TOKEN={operator_secret}\n"
            )
            canonical.chmod(0o600)
            replacements = {
                "ROOT": root,
                "SECRET_ROOT": secret_root,
                "SOURCE": canonical,
                "LOCK": secret_root / ".platform-env.lock",
                "CONFIG_SOURCE": config_source,
                "PROFILE_SOURCE": root / "templates/profiles/missing.json",
                "COMPOSE_SEED_SOURCE": catalog_source,
                "REVIEWED_COMPOSE_SEED_MIGRATIONS": {
                    "DEMO_IMAGE",
                    "DEMO_PORT_1_MAPPING",
                },
            }
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                value = original_stat(path, *args, **kwargs)
                fields = list(value)
                fields[4] = 0
                return os.stat_result(fields)

            with ExitStack() as stack:
                for name, value in replacements.items():
                    stack.enter_context(mock.patch.object(server_config, name, value))
                stack.enter_context(mock.patch.object(Path, "stat", root_owned_stat))
                first = server_config.init_source({})
                values = server_config.parse_env(canonical)
                self.assertEqual(values["DEMO_PORT_1_MAPPING"], "127.0.0.1:18000:8000")
                self.assertEqual(values["DEMO_IMAGE"], operator_image)
                self.assertEqual(values["DEMO_API_TOKEN"], operator_secret)
                self.assertIn("DEMO_PORT_1_MAPPING", first["createdKeys"])
                self.assertNotIn("DEMO_IMAGE", first["createdKeys"])
                self.assertNotIn("DEMO_API_TOKEN", first["createdKeys"])

                # With every reviewed key now present, repeat init retains the
                # original bootstrap-only behavior and does not consult the
                # catalog at all.
                catalog_source.write_text("{}\n")
                second = server_config.init_source({})

            repeated = server_config.parse_env(canonical)
            self.assertEqual(repeated["DEMO_IMAGE"], operator_image)
            self.assertEqual(repeated["DEMO_API_TOKEN"], operator_secret)
            self.assertNotIn("DEMO_IMAGE", second["createdKeys"])
            self.assertNotIn("DEMO_PORT_1_MAPPING", second["createdKeys"])

    def test_existing_env_backfills_daytona_static_compose_refs(self):
        catalog = json.loads((ROOT / "config/compose-seeds.lock.json").read_text())[
            "seeds"
        ]
        daytona_seeds = {
            key: value
            for key, value in catalog.items()
            if key.startswith("MTE_DAYTONA_")
        }
        self.assertEqual(len(daytona_seeds), 13)
        required = set(daytona_seeds) | {"DATA_CONTENT_PROFILE"}

        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            canonical.write_text("DATA_CONTENT_PROFILE=postgres-notion\n")
            canonical.chmod(0o600)
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                value = original_stat(path, *args, **kwargs)
                fields = list(value)
                fields[4] = 0
                return os.stat_result(fields)

            with (
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(server_config, "config_object", return_value={}),
                mock.patch.object(
                    server_config, "active_config_object", return_value={}
                ),
                mock.patch.object(
                    server_config,
                    "declared_keys",
                    return_value=(required, {}, {}),
                ),
                mock.patch.object(
                    server_config,
                    "compose_seed_catalog",
                    return_value=daytona_seeds,
                ),
                mock.patch.object(Path, "stat", root_owned_stat),
            ):
                first = server_config.init_source({})
                values = server_config.parse_env(canonical)
                self.assertEqual(set(first["createdKeys"]), set(daytona_seeds))
                self.assertEqual(first["missingKeys"], [])
                self.assertEqual(
                    {key: values[key] for key in daytona_seeds}, daytona_seeds
                )

                custom_key = "MTE_DAYTONA_RUNNER_ENV_RUNNER_DOMAIN"
                missing_key = "MTE_DAYTONA_API_ENV_DB_HOST"
                values[custom_key] = "operator-runner.example.test"
                values.pop(missing_key)
                server_config.write_env(canonical, values)
                second = server_config.init_source({})

            upgraded = server_config.parse_env(canonical)
            self.assertEqual(second["createdKeys"], [missing_key])
            self.assertEqual(upgraded[missing_key], daytona_seeds[missing_key])
            self.assertEqual(upgraded[custom_key], "operator-runner.example.test")

    def test_reviewed_compose_migrations_cover_catalog_prefixes(self):
        catalog = json.loads((ROOT / "config/compose-seeds.lock.json").read_text())[
            "seeds"
        ]
        daytona_keys = {key for key in catalog if key.startswith("MTE_DAYTONA_")}
        postgrest_keys = {
            key
            for key in catalog
            if key.startswith("MTE_POSTGREST_") or key.startswith("POSTGREST_")
        }
        self.assertEqual(len(daytona_keys), 13)
        self.assertEqual(
            server_config.REVIEWED_COMPOSE_SEED_MIGRATIONS,
            daytona_keys
            | postgrest_keys
            | {
                "MTE_FIRECRAWL_VALKEY_IMAGE",
                "MTE_OBSERVABILITY_OTEL_COLLECTOR_PORT_1_MAPPING",
            },
        )

    def test_reviewed_toolhive_runtime_values_migrate_without_overwriting_custom_value(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            canonical.write_text(
                "DATA_CONTENT_PROFILE=postgres-notion\n"
                "TOOLHIVE_MEMORY_LIMIT=384m\n"
                "MTE_TOOLHIVE_TOOL_RUNTIME_IMAGE="
                "docker:28-dind-rootless@sha256:"
                "7c3e797187e43738220462658f4586572cbd3bf009f728b21e34d9c5c06ce431\n"
                "MTE_TOOLHIVE_TOOLHIVE_ENV_DOCKER_HOST=tcp://tool-runtime:2375\n"
                "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM=http://tool-runtime:19011\n"
                "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_UPSTREAM=http://operator-proxy:29012\n"
                "MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM=http://tool-runtime:19013\n"
            )
            canonical.chmod(0o600)
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                value = original_stat(path, *args, **kwargs)
                fields = list(value)
                fields[4] = 0
                return os.stat_result(fields)

            required = {
                "DATA_CONTENT_PROFILE",
                *server_config.REVIEWED_CANONICAL_VALUE_MIGRATIONS,
            }
            with (
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(server_config, "config_object", return_value={}),
                mock.patch.object(
                    server_config, "active_config_object", return_value={}
                ),
                mock.patch.object(
                    server_config,
                    "declared_keys",
                    return_value=(required, {}, {}),
                ),
                mock.patch.object(Path, "stat", root_owned_stat),
            ):
                result = server_config.init_source({})
                values = server_config.parse_env(canonical)

        self.assertEqual(values["TOOLHIVE_MEMORY_LIMIT"], "1024m")
        self.assertEqual(
            values["MTE_TOOLHIVE_TOOL_RUNTIME_IMAGE"],
            "docker:28-dind@sha256:"
            "9a06753d2401cd049b34cd27dbbc3e0db717d4c1db7bc7f2efad1c187e00bf5a",
        )
        self.assertNotIn("MTE_TOOLHIVE_TOOLHIVE_ENV_DOCKER_HOST", values)
        self.assertEqual(
            values["MTE_TOOLHIVE_TOOLHIVE_ENV_DOCKER_SOCKET"],
            "/var/run/docker.sock",
        )
        self.assertEqual(
            values["MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM"],
            "http://toolhive:19011",
        )
        self.assertEqual(
            values["MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_UPSTREAM"],
            "http://operator-proxy:29012",
        )
        self.assertEqual(
            values["MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM"],
            "http://toolhive:19013",
        )
        self.assertEqual(
            result["migratedKeys"],
            [
                "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM",
                "MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM",
                "MTE_TOOLHIVE_TOOLHIVE_ENV_DOCKER_SOCKET",
                "MTE_TOOLHIVE_TOOL_RUNTIME_IMAGE",
                "TOOLHIVE_MEMORY_LIMIT",
            ],
        )

    def test_retired_paperclip_installer_hash_is_removed(self):
        old = "fec4dda76d6924bd50ddd3fbf07e8dc2d6986a70cda6b5562e101930e9a49854"
        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            canonical.write_text(
                "DATA_CONTENT_PROFILE=postgres-notion\n"
                f"MTE_PAPERCLIP_INSTALLER_SHA256={old}\n"
            )
            canonical.chmod(0o600)
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                value = original_stat(path, *args, **kwargs)
                fields = list(value)
                fields[4] = 0
                return os.stat_result(fields)

            with (
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(server_config, "config_object", return_value={}),
                mock.patch.object(
                    server_config, "active_config_object", return_value={}
                ),
                mock.patch.object(
                    server_config,
                    "declared_keys",
                    return_value=(
                        {"DATA_CONTENT_PROFILE"},
                        {},
                        {},
                    ),
                ),
                mock.patch.object(Path, "stat", root_owned_stat),
            ):
                result = server_config.init_source({})
                values = server_config.parse_env(canonical)

        self.assertNotIn("MTE_PAPERCLIP_INSTALLER_SHA256", values)
        self.assertEqual(result["migratedKeys"], ["MTE_PAPERCLIP_INSTALLER_SHA256"])

    def test_notion_provision_updates_are_fill_only_and_idempotent(self):
        notion_ids = {
            "NOTION_DOCUMENTS_PAGE_ID": "11111111-1111-4111-8111-111111111111",
            "NOTION_TABLE_DATABASE_ID": "22222222-2222-4222-8222-222222222222",
            "NOTION_TABLE_DATA_SOURCE_ID": "33333333-3333-4333-8333-333333333333",
            "NOTION_WORKSPACE_ID": "44444444-4444-4444-8444-444444444444",
            "NOTION_BOT_ID": "55555555-5555-4555-8555-555555555555",
        }

        def payload(changed_keys):
            return {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "NotionConnectorProvision",
                "status": "converged",
                "ok": True,
                "redacted": True,
                "dataContentProfile": "postgres-notion",
                "environmentUpdates": notion_ids,
                "changedKeys": changed_keys,
            }

        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            root_page_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            canonical.write_text(
                "DATA_CONTENT_PROFILE=postgres-notion\n"
                "NOTION_TOKEN=unit-token-must-not-be-returned\n"
                f"NOTION_ROOT_PAGE_ID={root_page_id}\n"
                + "".join(f"{key}=\n" for key in sorted(notion_ids))
            )
            canonical.chmod(0o600)
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                value = original_stat(path, *args, **kwargs)
                fields = list(value)
                fields[4] = 0
                return os.stat_result(fields)

            with (
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(Path, "stat", root_owned_stat),
            ):
                first = server_config.merge_notion_provision(
                    payload(sorted(notion_ids))
                )
                second = server_config.merge_notion_provision(
                    payload([]), expect_idempotent=True
                )
                values = server_config.parse_env(canonical)

        self.assertEqual(
            {key: values[key] for key in notion_ids},
            notion_ids,
        )
        self.assertEqual(values["NOTION_ROOT_PAGE_ID"], root_page_id)
        self.assertEqual(values["NOTION_TOKEN"], "unit-token-must-not-be-returned")
        self.assertEqual(first["mergedKeys"], sorted(notion_ids))
        self.assertFalse(first["idempotent"])
        self.assertEqual(second["mergedKeys"], [])
        self.assertEqual(second["unchangedKeys"], sorted(notion_ids))
        self.assertTrue(second["idempotent"])
        serialized_results = json.dumps([first, second])
        self.assertTrue(
            all(value not in serialized_results for value in notion_ids.values())
        )
        self.assertNotIn(values["NOTION_TOKEN"], serialized_results)

    def test_notion_provision_rejects_changed_key_mismatch_without_writing(self):
        key = "NOTION_DOCUMENTS_PAGE_ID"
        value = "11111111-1111-4111-8111-111111111111"
        payload = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "NotionConnectorProvision",
            "status": "converged",
            "ok": True,
            "redacted": True,
            "dataContentProfile": "postgres-notion",
            "environmentUpdates": {key: value},
            "changedKeys": [],
        }
        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            canonical.write_text(f"DATA_CONTENT_PROFILE=postgres-notion\n{key}=\n")
            canonical.chmod(0o600)
            before = canonical.read_bytes()
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                observed = original_stat(path, *args, **kwargs)
                fields = list(observed)
                fields[4] = 0
                return os.stat_result(fields)

            with (
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(Path, "stat", root_owned_stat),
                self.assertRaisesRegex(
                    server_config.ConfigError, "changedKeys do not match"
                ),
            ):
                server_config.merge_notion_provision(payload)
            after = canonical.read_bytes()
        self.assertEqual(after, before)

    def test_notion_provision_rejects_overwrite_and_unreviewed_keys(self):
        key = "NOTION_DOCUMENTS_PAGE_ID"
        existing = "11111111-1111-4111-8111-111111111111"
        replacement = "22222222-2222-4222-8222-222222222222"

        def payload(updates):
            return {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "NotionConnectorProvision",
                "status": "converged",
                "ok": True,
                "redacted": True,
                "dataContentProfile": "postgres-notion",
                "environmentUpdates": updates,
                "changedKeys": [],
            }

        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            canonical.write_text(
                f"DATA_CONTENT_PROFILE=postgres-notion\n{key}={existing}\n"
            )
            canonical.chmod(0o600)
            before = canonical.read_bytes()
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                observed = original_stat(path, *args, **kwargs)
                fields = list(observed)
                fields[4] = 0
                return os.stat_result(fields)

            with (
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(Path, "stat", root_owned_stat),
            ):
                with self.assertRaisesRegex(
                    server_config.ConfigError, "refusing to overwrite"
                ):
                    server_config.merge_notion_provision(payload({key: replacement}))
                with self.assertRaisesRegex(
                    server_config.ConfigError, "unreviewed update key"
                ):
                    server_config.merge_notion_provision(
                        payload({"NOTION_ROOT_PAGE_ID": existing})
                    )
            after = canonical.read_bytes()
        self.assertEqual(after, before)

    def test_run_provision_pipes_notion_ids_then_renders_and_checks_idempotency(self):
        class Contract:
            @staticmethod
            def adapter_commands(_plane, action):
                self.assertEqual(action, "provision")
                return [
                    ("server-postgrest.py", "provision"),
                    ("server-notion.py", "provision"),
                ]

        remote_command = mock.Mock()
        with (
            mock.patch.object(platform, "sync"),
            mock.patch.object(
                platform, "data_content_contract", return_value=Contract()
            ),
            mock.patch.object(platform, "resolved_data_content", return_value={}),
            mock.patch.object(
                platform,
                "remote_script",
                side_effect=lambda _cfg, name: "/opt/mte-platform/bin/" + name,
            ),
            mock.patch.object(platform, "ssh", remote_command),
        ):
            platform.run_provision({}, "provision")

        command = remote_command.call_args.args[1]
        first_notion = command.index("server-notion.py provision --json")
        render = command.index("server-config.py render")
        second_notion = command.index(
            "server-notion.py provision --json", first_notion + 1
        )
        self.assertLess(first_notion, render)
        self.assertLess(render, second_notion)
        self.assertEqual(command.count("merge-notion-provision"), 2)
        self.assertEqual(command.count("--expect-idempotent"), 1)
        self.assertIn(
            "server-notion.py provision --json | python3 "
            "/opt/mte-platform/bin/server-config.py merge-notion-provision",
            command,
        )
        self.assertNotIn("NOTION_TOKEN=", command)
        self.assertNotRegex(
            command,
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        )

    def test_projection_provision_immediately_verifies_and_persists_evidence(self):
        class Contract:
            @staticmethod
            def projection_consumer_commands(_plane, action):
                return [("server-notion-sync.py", action)]

        remote_command = mock.Mock()
        with (
            mock.patch.object(platform, "sync"),
            mock.patch.object(
                platform, "data_content_contract", return_value=Contract()
            ),
            mock.patch.object(platform, "resolved_data_content", return_value={}),
            mock.patch.object(
                platform,
                "remote_script",
                side_effect=lambda _cfg, name: "/opt/mte-platform/bin/" + name,
            ),
            mock.patch.object(platform, "ssh", remote_command),
        ):
            platform.run_data_content_projections({}, "provision")

        command = remote_command.call_args.args[1]
        provision = "python3 /opt/mte-platform/bin/server-notion-sync.py provision"
        verify = "python3 /opt/mte-platform/bin/server-notion-sync.py verify"
        self.assertEqual(command.count(provision), 1)
        self.assertEqual(command.count(verify), 1)
        self.assertLess(command.index(provision), command.index(verify))
        self.assertTrue(command.startswith("set -eu; "))

    def test_projection_verify_does_not_repeat_consumer_verification(self):
        class Contract:
            @staticmethod
            def projection_consumer_commands(_plane, action):
                return [("server-notion-sync.py", action)]

        remote_command = mock.Mock()
        with (
            mock.patch.object(platform, "sync"),
            mock.patch.object(
                platform, "data_content_contract", return_value=Contract()
            ),
            mock.patch.object(platform, "resolved_data_content", return_value={}),
            mock.patch.object(
                platform,
                "remote_script",
                side_effect=lambda _cfg, name: "/opt/mte-platform/bin/" + name,
            ),
            mock.patch.object(platform, "ssh", remote_command),
        ):
            platform.run_data_content_projections({}, "verify")

        command = remote_command.call_args.args[1]
        self.assertEqual(command.count("server-notion-sync.py verify"), 1)

    def test_notion_projection_canary_is_public_and_canonical_hash_bound(self):
        args = platform.parser().parse_args(["notion-projection", "canary"])
        self.assertEqual(args.action, "canary")
        commands = []
        cfg = {"spec": {"host": {"root": "/opt/mte-platform"}}}
        with (
            mock.patch.object(platform, "sync") as sync,
            mock.patch.object(
                platform,
                "run_canonical_hash_bound",
                side_effect=lambda _cfg, command: commands.append(command),
            ),
        ):
            platform.run_notion_projection(cfg, "canary")
        sync.assert_called_once_with(cfg)
        self.assertEqual(
            commands,
            [
                [
                    "python3",
                    "/opt/mte-platform/bin/server-notion-sync.py",
                    "canary",
                ]
            ],
        )

    def test_static_source_layout_is_the_only_orchestrator_input(self):
        self.assertEqual(platform.CONFIG_PATH, ROOT / "config/platform.yaml")
        self.assertEqual(platform.LOCK_PATH, ROOT / "config/platform.lock.yaml")
        self.assertEqual(
            platform.CANONICAL_ENV_EXAMPLE,
            ROOT / "config/platform.env.example",
        )
        self.assertEqual(platform.SERVICES_ROOT, ROOT / "deployment/services")
        self.assertEqual(platform.PROFILES_ROOT, ROOT / "config/profiles")
        self.assertEqual(platform.KESTRA_WORKFLOWS_ROOT, ROOT / "workflows/kestra")
        self.assertEqual(platform.AGENT_RUNTIME_ROOT, ROOT / "deployment/agent-runtime")
        manifest = yaml.safe_load(platform.CONFIG_PATH.read_text())
        compose_paths = [
            Path(row["compose"])
            for row in manifest["spec"]["components"]
            if row.get("compose")
        ]
        self.assertTrue(compose_paths)
        self.assertTrue(
            all(
                path.parts[:2] == ("deployment", "services")
                and path.name == "compose.yaml"
                for path in compose_paths
            )
        )
        self.assertTrue(all((ROOT / path).is_file() for path in compose_paths))

    def test_origin_firewall_step_applies_then_saves_redacted_status(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "excluded": [],
                }
            }
        }
        payload = {
            field: True
            for field in platform.ORIGIN_FIREWALL_EVIDENCE_FIELDS
            if field.startswith("firewallV")
            or field
            in {
                "firewallServiceActive",
                "firewallServiceEnabled",
                "firewallRecoveryTimerActive",
                "firewallRecoveryTimerEnabled",
                "firewallSshCidrsEnforced",
                "udp443Blocked",
                "publicTcpDefaultDenied",
                "publicUdpDefaultDenied",
            }
        }
        payload.update(
            {
                "firewallPolicyVersion": "mte-origin-firewall/v2",
                "publicInterface": "eth0",
                "publicInterfaceV4": "eth0",
                "publicInterfaceV6": "eth0",
                "operatorSshCidrsSha256": "a" * 64,
                "firewallSshCidrCount": 1,
                "firewallSshIpv4CidrCount": 1,
                "firewallSshIpv6CidrCount": 0,
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / ".runtime/evidence/cloudflare-origin-firewall.json"
            evidence.parent.mkdir(parents=True)
            evidence.write_text(json.dumps(payload))
            with (
                mock.patch.object(platform, "ROOT", root),
                mock.patch.object(platform, "sync") as synchronize,
                mock.patch.object(platform, "ssh") as remote,
                mock.patch.object(platform, "run") as transfer,
            ):
                platform.run_origin_firewall(cfg)
            evidence_mode = evidence.stat().st_mode & 0o777

        synchronize.assert_called_once_with(cfg)
        command = remote.call_args.args[1]
        self.assertIn("/steps/origin-firewall.sh", command)
        self.assertLess(command.index(" apply"), command.index(" status"))
        self.assertIn("cloudflare-origin-firewall.json", command)
        self.assertNotIn("MTE_OPERATOR_SSH_CIDRS", command)
        self.assertIn("-az", transfer.call_args.args[0])
        self.assertEqual(evidence_mode, 0o600)
        args = platform.parser().parse_args(["cloudflare", "origin-firewall"])
        self.assertEqual(args.action, "origin-firewall")

    def test_toolhive_notion_workload_ports_are_unique_from_vmcp_aggregates(self):
        seeds = server_config.ONE_TIME_MIGRATION_SEEDS
        workload_keys = {
            f"TOOLHIVE_PROFILE_CODING_DAYTONA_{harness}_{bundle}_PROXY_PORT"
            for harness in ("CODEX", "CLAUDE", "PI")
            for bundle in ("EVERYTHING", "NOTION")
        }
        aggregate_keys = {
            f"TOOLHIVE_PROFILE_CODING_DAYTONA_{harness}_PROXY_PORT"
            for harness in ("CODEX", "CLAUDE", "PI")
        }
        workload_ports = {seeds[key] for key in workload_keys}
        aggregate_ports = {seeds[key] for key in aggregate_keys}
        self.assertEqual(len(workload_ports), 6)
        self.assertFalse(workload_ports & aggregate_ports)
        self.assertTrue(all(1 <= int(port) <= 65535 for port in workload_ports))
        self.assertEqual(
            seeds["TOOLHIVE_NOTION_IMAGE"],
            "ghcr.io/stacklok/dockyard/npx/notion@sha256:"
            "180a55ce48d1d08888abb9920a6d24ba178929e4131722579466c494eec3d08f",
        )

    def test_daytona_apply_has_read_only_dependency_guard(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "excluded": [],
                }
            }
        }
        with mock.patch.object(platform, "ssh") as ssh:
            platform.require_daytona_dependencies(cfg)
        command = ssh.call_args.args[1]
        self.assertIn("set -eu", command)
        self.assertIn("server-provision.py verify", command)
        self.assertIn("server-profile-reconcile.py verify", command)
        self.assertNotIn(" provision", command)

    def test_daytona_apply_builds_snapshot_before_first_environment_reconcile(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "secretsRoot": "/root/.config/mte-secrets",
                    "excluded": [],
                }
            }
        }
        with (
            mock.patch.object(platform, "sync"),
            mock.patch.object(platform, "ssh") as ssh,
            mock.patch.object(platform, "merge_paperclip_experimental_inputs"),
            mock.patch.object(platform, "require_daytona_dependencies") as guard,
            mock.patch.object(platform, "run_paperclip_runtime") as runtime_verify,
        ):
            platform.run_paperclip_experimental(cfg, "daytona", "apply")
        commands = [call.args[1] for call in ssh.call_args_list]
        self.assertEqual(guard.call_count, 1)
        self.assertEqual(
            [commands[index].rsplit(" ", 1)[-1] for index in range(2)],
            ["install", "set-target"],
        )
        self.assertFalse(
            any(command.endswith(" provision-key") for command in commands)
        )
        images = next(
            index
            for index, command in enumerate(commands)
            if command.endswith(" images")
        )
        first_plugin_apply = next(
            index
            for index, command in enumerate(commands)
            if "server-paperclip-experimental.py daytona apply" in command
        )
        lifecycle = next(
            index
            for index, command in enumerate(commands)
            if command.endswith(" lifecycle")
        )
        step_verify = next(
            index
            for index, command in enumerate(commands)
            if command.endswith("daytona.sh verify")
        )
        plugin_verify = next(
            index
            for index, command in enumerate(commands)
            if "server-paperclip-experimental.py daytona verify" in command
        )
        self.assertLess(images, first_plugin_apply)
        self.assertLess(first_plugin_apply, lifecycle)
        self.assertLess(lifecycle, step_verify)
        self.assertLess(step_verify, plugin_verify)
        self.assertEqual(
            sum(
                "server-paperclip-experimental.py daytona apply" in command
                for command in commands
            ),
            1,
        )
        self.assertFalse(any(command.endswith(" all") for command in commands))
        runtime_verify.assert_called_once_with(cfg, "verify")

    def test_daytona_verify_finishes_with_strict_paperclip_private_route_verify(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "secretsRoot": "/root/.config/mte-secrets",
                    "excluded": [],
                }
            }
        }
        with (
            mock.patch.object(platform, "sync"),
            mock.patch.object(platform, "ssh"),
            mock.patch.object(platform, "merge_paperclip_experimental_inputs"),
            mock.patch.object(platform, "require_daytona_dependencies") as guard,
            mock.patch.object(platform, "run_paperclip_runtime") as runtime_verify,
        ):
            platform.run_paperclip_experimental(cfg, "daytona", "verify")
        self.assertEqual(guard.call_count, 2)
        runtime_verify.assert_called_once_with(cfg, "verify")

    def test_daytona_gateway_uses_private_tool_runtime_network_with_live_probe(self):
        daytona_step = (ROOT / "deployment/steps/daytona.sh").read_text()
        daytona_compose = (
            ROOT / "deployment/services/daytona/compose.yaml"
        ).read_text()
        canonical_r1_upstreams = {
            "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM": "http://toolhive:19011",
            "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_UPSTREAM": "http://toolhive:19012",
            "MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM": "http://toolhive:19013",
        }
        self.assertEqual(
            {
                key: server_config.ONE_TIME_MIGRATION_SEEDS[key]
                for key in canonical_r1_upstreams
            },
            canonical_r1_upstreams,
        )
        self.assertNotIn("defaults={", daytona_step)
        self.assertNotIn("profile_defaults={", daytona_step)
        self.assertNotIn("v.setdefault(", daytona_step)
        self.assertNotIn("http://tool-runtime:19011", daytona_step)
        self.assertIn("networks: [daytona, agent-plane, tool-runtime]", daytona_compose)
        self.assertIn("name: ${MTE_TOOL_RUNTIME_NETWORK:?required}", daytona_compose)
        self.assertNotIn("tool-control", daytona_compose)
        self.assertNotIn("docker.sock", daytona_compose)
        self.assertIn("network_mode: service:runner", daytona_compose)
        self.assertIn(
            "command: [python3, /app/agent-plane-gateway.py]", daytona_compose
        )
        self.assertIn("MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM:", daytona_compose)
        self.assertIn(
            'command,"/home/daytona/paperclip-workspace",undefined,120',
            daytona_step,
        )
        self.assertNotIn(
            "MTE_DAYTONA_REGISTRY_EVIDENCE_URL}/v2/${match[1]}", daytona_step
        )

    def test_daytona_step_consumes_canonical_config_and_only_generates_owned_secrets(
        self,
    ):
        source = (ROOT / "deployment/steps/daytona.sh").read_text()
        current_digest = hashlib.sha256(source.encode()).hexdigest()
        self.assertEqual(
            server_config.ONE_TIME_MIGRATION_SEEDS["MTE_DAYTONA_INSTALLER_SHA256"],
            current_digest,
        )
        self.assertEqual(
            server_config.REVIEWED_CANONICAL_VALUE_MIGRATIONS[
                "MTE_DAYTONA_INSTALLER_SHA256"
            ][-1],
            current_digest,
        )
        self.assertIn(
            "2a89ffbd67866ad542ba801f7a31c1228780315cc133cf85eb59d8b860d5ad0a",
            server_config.REVIEWED_CANONICAL_VALUE_MIGRATIONS[
                "MTE_DAYTONA_INSTALLER_SHA256"
            ][:-1],
        )
        self.assertIn('"MTE_DAYTONA_NETWORK",', source)
        self.assertIn('"MTE_DAYTONA_PAPERCLIP_NETWORK",', source)
        self.assertIn('"TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN",', source)
        self.assertIn('"TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_BEARER_TOKEN",', source)
        self.assertIn('"TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN",', source)
        self.assertNotIn(
            '"TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN": lambda',
            source,
        )
        self.assertNotIn('values["DAYTONA_TARGET"] =', source)
        self.assertNotIn('target: safe("DAYTONA_TARGET")', source)
        self.assertIn(
            "Self-hosted Daytona resolves an omitted SDK target through the organization's",
            source,
        )
        self.assertIn("os.replace(temporary, path)", source)
        self.assertIn("os.O_RDWR | nofollow | cloexec", source)
        self.assertIn("fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)", source)
        self.assertIn("fcntl.F_OFD_SETLK", source)
        self.assertNotIn('9>"$ENV_LOCK"', source)
        self.assertIn(
            "DAYTONA_ENV_FILE=/root/.config/mte-secrets/services/daytona.env", source
        )
        self.assertIn(
            'python3 - "$ENV_FILE" "$DAYTONA_ENV_FILE" "$RUNTIME_ENV"', source
        )
        self.assertIn("render_daytona_projection", source)
        compose = (ROOT / "deployment/services/daytona/compose.yaml").read_text()
        self.assertIn("x-logging: &logging", compose)
        self.assertIn("max-size: ${MTE_DOCKER_LOG_MAX_SIZE:?required}", compose)
        self.assertIn("max-file: ${MTE_DOCKER_LOG_MAX_FILES:?required}", compose)
        self.assertEqual(compose.count("logging: *logging"), 10)

        canonical = server_config.ONE_TIME_MIGRATION_SEEDS
        for key in (
            "MTE_DAYTONA_API_IMAGE",
            "MTE_DAYTONA_API_INTERNAL_PORT",
            "MTE_DAYTONA_DEFAULT_ORG_TOTAL_CPU",
            "MTE_DAYTONA_DEFAULT_RUNNER_CPU",
            "MTE_DAYTONA_NETWORK",
            "MTE_DAYTONA_RUNNER_START_SCORE_THRESHOLD",
            "MTE_CODEX_VERSION",
            "MTE_CONTEXT7_MCP_URL",
            "MTE_DOCKER_LOG_MAX_FILES",
            "MTE_DOCKER_LOG_MAX_SIZE",
            "MTE_GITHUB_CLI_VERSION",
            "MTE_TOOL_RUNTIME_NETWORK",
            "MTE_TOOLHIVE_VERSION",
        ):
            self.assertIn(key, canonical)
        self.assertNotIn("MTE_DAYTONA_SANDBOX_IMAGE", canonical)
        self.assertIn(
            "MTE_DAYTONA_SANDBOX_IMAGE",
            server_config.REQUIRED_OPERATOR_BOOTSTRAP_KEYS,
        )
        self.assertNotIn("MTE_DAYTONA_CODING_IMAGE", canonical)

    def test_redis_passwords_are_generated_and_all_app_paths_use_derived_urls(self):
        passwords = {
            key: value
            for key, value in server_secrets.generated_defaults(
                "postgres-notion"
            ).items()
            if key
            in {
                "FIRECRAWL_REDIS_PASSWORD",
                "SEARXNG_VALKEY_PASSWORD",
            }
        }
        self.assertEqual(len(passwords), 2)
        self.assertEqual(len(set(passwords.values())), 2)
        self.assertTrue(all(len(value) >= 32 for value in passwords.values()))

        expected = {
            "FIRECRAWL_REDIS_URL",
            "SEARXNG_VALKEY_URL",
        }
        self.assertTrue(expected <= server_config.DERIVED_VALUE_KEYS)
        for filename, service, password_ref in (
            ("searxng.yaml", "valkey", "SEARXNG_VALKEY_PASSWORD"),
        ):
            compose = yaml.safe_load(
                (
                    ROOT / "deployment/services" / Path(filename).stem / "compose.yaml"
                ).read_text()
            )
            runtime = compose["services"][service]
            command = " ".join(runtime["command"])
            self.assertNotIn("--requirepass", runtime["command"])
            self.assertNotIn("${" + password_ref, command)
            self.assertIn("printenv " + password_ref, command)
            self.assertIn("umask 077", command)
            self.assertIn("unset password " + password_ref, command)
            health = " ".join(runtime["healthcheck"]["test"])
            self.assertIn(password_ref, health)
            self.assertIn("PONG", health)
            self.assertNotIn("-a ", health)

    @unittest.skipUnless(shutil.which("docker"), "Docker Compose CLI is required")
    def test_redis_secret_stays_out_of_rendered_command_and_healthcheck_argv(self):
        password = "compose-semantic-test-password-not-a-secret"
        for filename, service, password_ref in (
            ("searxng.yaml", "valkey", "SEARXNG_VALKEY_PASSWORD"),
        ):
            source = yaml.safe_load(
                (
                    ROOT / "deployment/services" / Path(filename).stem / "compose.yaml"
                ).read_text()
            )
            runtime = source["services"][service]
            minimal = {
                "services": {
                    service: {
                        "image": "redis:7.4-alpine",
                        "environment": runtime.get("environment", {}),
                        "command": runtime["command"],
                        "healthcheck": runtime["healthcheck"],
                    }
                }
            }
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                compose_path = root / "compose.yaml"
                env_path = root / "platform.env"
                compose_path.write_text(yaml.safe_dump(minimal, sort_keys=False))
                env_path.write_text(
                    f"{password_ref}={password}\n"
                    "MTE_HEALTHCHECK_FAST_INTERVAL=10s\n"
                    "MTE_HEALTHCHECK_FAST_TIMEOUT=5s\n"
                    "MTE_HEALTHCHECK_FAST_RETRIES=15\n"
                )
                result = subprocess.run(
                    [
                        "docker",
                        "compose",
                        "--env-file",
                        str(env_path),
                        "-f",
                        str(compose_path),
                        "config",
                        "--format",
                        "json",
                    ],
                    text=True,
                    capture_output=True,
                    check=True,
                )
            rendered = json.loads(result.stdout)["services"][service]
            command = " ".join(rendered["command"])
            self.assertNotIn(password, command)
            self.assertNotIn("${" + password_ref, command)
            self.assertIn("printenv " + password_ref, command)
            health = " ".join(rendered["healthcheck"]["test"])
            self.assertIn("$${" + password_ref + ":?required}", health)
            self.assertNotIn(password, health)
            self.assertNotIn("-a ", health)

    def test_e2e_hook_fails_closed_when_independent_runner_is_missing(self):
        cfg = {
            "spec": {
                "host": {"ssh": "root@example.test", "root": "/opt/mte-platform"},
                "e2eCanary": {"runner": "missing-e2e-runner.py"},
            }
        }
        with (
            tempfile.TemporaryDirectory() as temp,
            mock.patch.object(platform, "ROOT", Path(temp)),
        ):
            with self.assertRaisesRegex(
                platform.PlatformError, "dedicated flow implementation"
            ):
                platform.run_kestra_canary(cfg, "apply")

    def test_e2e_hook_syncs_native_sources_before_running_canary(self):
        cfg = {
            "spec": {
                "host": {"ssh": "root@example.test", "root": "/opt/mte-platform"},
                "e2eCanary": {"runner": "server-e2e-canary.py"},
            }
        }
        observed = []
        ssh_commands = []
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tool_root = root / "tools/platform-cli"
            tool_root.mkdir(parents=True)
            runner = tool_root / "server-e2e-canary.py"
            runner.write_text("pass\n")
            expected = hashlib.sha256(runner.read_bytes()).hexdigest()

            def record_ssh(_cfg, command, **_kwargs):
                ssh_commands.append(command)
                observed.append("canary")

            with (
                mock.patch.object(platform, "ROOT", root),
                mock.patch.object(platform, "TOOL_ROOT", tool_root),
                mock.patch.object(
                    platform,
                    "run_paperclip_runtime",
                    side_effect=lambda _cfg, action: observed.append(action),
                ),
                mock.patch.object(
                    platform,
                    "operator_values",
                    return_value=self.operator_input_values(),
                ),
                mock.patch.object(
                    platform,
                    "run_resource_preflight",
                    side_effect=lambda _cfg, mode, **_kwargs: observed.append(mode),
                ),
                mock.patch.object(
                    platform, "sync", side_effect=lambda _cfg: observed.append("sync")
                ),
                mock.patch.object(
                    platform,
                    "merge_paperclip_experimental_inputs",
                ),
                mock.patch.object(platform, "run"),
                mock.patch.object(
                    platform,
                    "ssh",
                    side_effect=record_ssh,
                ),
            ):
                platform.run_kestra_canary(cfg, "apply")
        self.assertEqual(observed[0], "daytona-e2e")
        self.assertEqual(observed[1], "sync")
        self.assertEqual(observed[-1], "canary")
        self.assertEqual(len(ssh_commands), 1)
        self.assertIn(
            "sha256sum /opt/mte-platform/bin/server-e2e-canary.py", ssh_commands[0]
        )
        self.assertIn(expected, ssh_commands[0])
        self.assertIn(
            "python3 /opt/mte-platform/bin/server-e2e-canary.py apply", ssh_commands[0]
        )

    def test_e2e_acceptance_always_runs_apply_then_verify(self):
        actions = []
        with mock.patch.object(
            platform,
            "run_kestra_canary",
            side_effect=lambda _cfg, action: actions.append(action),
        ):
            platform.run_kestra_canary_acceptance({})
        self.assertEqual(actions, ["apply", "verify"])

    def test_observability_acceptance_runs_indexed_passes_before_live_canary(self):
        expected = "a" * 64
        cfg = {"spec": {"host": {"root": "/opt/mte-platform"}}}
        with (
            mock.patch.object(platform, "sync") as sync,
            mock.patch.object(
                platform, "canonical_source_sha256", return_value=expected
            ),
            mock.patch.object(platform, "run_canonical_hash_bound") as run,
        ):
            platform.run_observability_acceptance(cfg)
        sync.assert_called_once_with(cfg)
        run.assert_called_once()
        command = run.call_args.args[1]
        self.assertEqual(command[:2], ["sh", "-c"])
        script = command[2]
        self.assertIn(
            'exec 9>"$lock"; flock -x 9; python3',
            script,
        )
        self.assertIn(
            "/opt/mte-platform/evidence/.observability-acceptance.lock",
            script,
        )
        self.assertLess(
            script.index("reconcile-pass --pass-number 1"),
            script.index("reconcile-pass --pass-number 2"),
        )
        self.assertLess(
            script.index("reconcile-pass --pass-number 2"),
            script.index("finalize-idempotency"),
        )
        self.assertLess(script.index("finalize-idempotency"), script.index(" apply "))
        self.assertEqual(script.count(expected), 4)

    def test_integration_canary_orchestrator_rejects_removed_ids(self):
        with self.assertRaisesRegex(
            platform.PlatformError, "unknown integration canary IDs"
        ):
            platform.run_integration_canaries({}, "run", ["C013"])
        with self.assertRaisesRegex(
            platform.PlatformError, "unknown integration canary IDs"
        ):
            platform.run_integration_canaries({}, "run", ["C028"])

    def test_final_evidence_rebind_regenerates_and_verifies_e2e_attestation(self):
        observed = []
        with (
            mock.patch.object(
                platform,
                "run_config",
                side_effect=lambda _cfg, action: observed.append(("config", action)),
            ),
            mock.patch.object(
                platform,
                "run_provision",
                side_effect=lambda _cfg, action: observed.append(("provision", action)),
            ),
            mock.patch.object(
                platform,
                "run_notion_projection",
                side_effect=lambda _cfg, action: observed.append(("notion", action)),
            ),
            mock.patch.object(
                platform,
                "run_tools",
                side_effect=lambda _cfg, action: observed.append(("tools", action)),
            ),
            mock.patch.object(
                platform,
                "run_kestra_canary",
                side_effect=lambda _cfg, action: observed.append(("kestra", action)),
            ),
            mock.patch.object(
                platform,
                "run_profile_acceptance",
                side_effect=lambda _cfg: observed.append(("profiles", "verify")),
            ),
            mock.patch.object(
                platform,
                "run_integration_canaries",
                side_effect=lambda _cfg, action, _ids: observed.append(
                    ("integrations", action)
                ),
            ),
            mock.patch.object(
                platform,
                "run_hermes_acceptance",
                side_effect=lambda _cfg: observed.append(("hermes", "acceptance")),
            ),
            mock.patch.object(
                platform,
                "run_observability_acceptance",
                side_effect=lambda _cfg: observed.append(
                    ("observability", "acceptance")
                ),
            ),
        ):
            platform.run_final_evidence_rebind({})
        self.assertEqual(
            observed,
            [
                ("config", "render"),
                ("config", "audit"),
                ("provision", "verify"),
                ("tools", "verify"),
                ("kestra", "apply"),
                ("kestra", "verify"),
                ("profiles", "verify"),
                ("integrations", "run"),
                ("hermes", "acceptance"),
                ("observability", "acceptance"),
                ("notion", "canary"),
            ],
        )

    def test_public_evidence_and_hermes_acceptance_commands_use_existing_producers(
        self,
    ):
        cfg = {"spec": {"host": {"root": "/opt/mte-platform"}}}
        with (
            mock.patch.object(platform, "config", return_value=cfg),
            mock.patch.object(platform, "run_final_evidence_rebind") as rebind,
        ):
            platform.cmd_evidence_rebind(
                platform.parser().parse_args(["evidence-rebind"])
            )
        rebind.assert_called_once_with(cfg)

        with (
            mock.patch.object(platform, "config", return_value=cfg),
            mock.patch.object(platform, "run_hermes_acceptance") as hermes,
        ):
            platform.cmd_hermes(platform.parser().parse_args(["hermes", "acceptance"]))
        hermes.assert_called_once_with(cfg)

    def test_hermes_install_forwards_host_admin_only_when_explicit(self):
        cfg = {"spec": {"host": {"root": "/opt/mte-platform"}}}
        with (
            mock.patch.object(platform, "sync"),
            mock.patch.object(platform, "merge_hermes_inputs"),
            mock.patch.object(
                platform,
                "remote_script",
                return_value="/opt/mte-platform/bin/server-hermes.py",
            ),
            mock.patch.object(platform, "ssh") as ssh,
        ):
            platform.run_hermes(cfg, "install")
            public_command = ssh.call_args.args[1]
            platform.run_hermes(cfg, "install", grant_platform_admin=True)
            private_command = ssh.call_args.args[1]

        self.assertNotIn("--grant-platform-admin", public_command)
        self.assertIn("--grant-platform-admin", private_command)


class ExperimentalControllerTests(unittest.TestCase):
    def test_daytona_control_plane_reference_is_hash_bound_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "paperclip-daytona-control-plane.json"
            canonical = root / "platform.env"
            canonical.write_text("UNIT=value\n")
            payload = {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "PaperclipDaytonaControlPlaneEvidence",
                "status": "ready",
                "generatedAt": experimental.datetime.now(
                    experimental.timezone.utc
                ).isoformat(),
                "canonicalSourceSha256": hashlib.sha256(
                    canonical.read_bytes()
                ).hexdigest(),
                "producerSha256": "a" * 64,
                "agentGateway": {"status": "passed", "profileCount": 3},
            }
            evidence.write_text(json.dumps(payload) + "\n")
            evidence.chmod(0o600)
            with mock.patch.object(experimental, "PLATFORM_ENV", canonical):
                reference = experimental.evidence_reference(
                    evidence, "PaperclipDaytonaControlPlaneEvidence"
                )
            self.assertEqual(reference["path"], str(evidence))
            self.assertEqual(reference["kind"], payload["kind"])
            self.assertEqual(reference["status"], "ready")
            self.assertEqual(
                reference["sha256"], hashlib.sha256(evidence.read_bytes()).hexdigest()
            )
            evidence.write_text(json.dumps({**payload, "status": "failed"}) + "\n")
            evidence.chmod(0o600)
            with (
                mock.patch.object(experimental, "PLATFORM_ENV", canonical),
                self.assertRaises(experimental.ControlError),
            ):
                experimental.evidence_reference(evidence, payload["kind"])
        source = Path(experimental.__file__).read_text()
        self.assertIn('"controlPlane": evidence_reference(', source)
        self.assertIn('"paperclip-daytona-control-plane.json"', source)

    def test_http_error_body_is_never_exposed(self):
        leaked = b'{"error":"provider echoed SECRET_VALUE"}'
        error = urllib.error.HTTPError(
            "http://127.0.0.1/api/test",
            400,
            "bad request",
            {},
            io.BytesIO(leaked),
        )
        with (
            mock.patch.object(
                experimental,
                "dotenv",
                return_value={"PAPERCLIP_BOARD_API_KEY": "unit-board-key"},
            ),
            mock.patch("urllib.request.urlopen", side_effect=error),
        ):
            with self.assertRaises(experimental.ControlError) as raised:
                experimental.json_request(
                    "http://127.0.0.1", "POST", "/api/test", {"value": "SECRET_VALUE"}
                )
        self.assertNotIn("SECRET_VALUE", str(raised.exception))
        self.assertEqual(raised.exception.status, 400)

    def test_evidence_is_bound_to_canonical_and_installed_producer_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = root / "platform.env"
            canonical.write_text("UNIT_KEY=value\n")
            canonical_hash = hashlib.sha256(canonical.read_bytes()).hexdigest()
            with (
                mock.patch.object(experimental, "PLATFORM_ENV", canonical),
                mock.patch.object(experimental, "EVIDENCE_ROOT", root / "evidence"),
                mock.patch.object(experimental, "CONFIG", canonical),
                mock.patch.object(experimental, "BOOTSTRAP", root / "missing.json"),
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                experimental.emit("daytona", "verify", "ready", {"probe": "passed"})
            payload = json.loads(
                (root / "evidence/paperclip-daytona-verify.json").read_text()
            )
        self.assertEqual(
            payload["canonicalSourceSha256"],
            canonical_hash,
        )
        self.assertEqual(
            payload["producerSha256"],
            hashlib.sha256(Path(experimental.__file__).read_bytes()).hexdigest(),
        )
        self.assertEqual(payload["status"], "ready")
        self.assertIn("observedAt", payload)

    def test_probe_cleanup_retries_only_transient_state_conflicts(self):
        conflict = experimental.ControlError(
            "daytona_api_error", "state change", status=409
        )
        responses = [conflict, {}, None]

        def request(*_args, **_kwargs):
            value = responses.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value

        with (
            mock.patch.object(
                experimental, "daytona_json_request", side_effect=request
            ),
            mock.patch.object(experimental.time, "sleep"),
        ):
            experimental.destroy_daytona_probe_sandbox({}, "sandbox-unit")
        self.assertEqual(responses, [])


if __name__ == "__main__":
    unittest.main()

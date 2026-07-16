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
server_config = load_module("mte_server_config", ROOT / "tools/platform-cli/server-config.py")
server_secrets = load_module("mte_server_secrets", ROOT / "tools/platform-cli/server-secrets.py")
experimental = load_module(
    "mte_paperclip_experimental",
    ROOT / "tools/platform-cli/server-paperclip-experimental.py",
)


class PlatformOrchestratorTests(unittest.TestCase):
    def tearDown(self):
        platform.OPERATOR_ENV_OVERRIDE = None

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

    def operator_input_values(self) -> dict[str, str]:
        return {
            "MTE_SSH_TARGET": "root@198.51.100.20",
            "MTE_OPERATOR_SSH_CIDRS": "198.51.100.0/24",
            "MTE_EXCLUDED_HOST_1": "192.0.2.20",
            "MTE_EXCLUDED_HOST_2": "192.0.2.30",
            "PLATFORM_BASE_DOMAIN": "agents.example.net",
            "CLOUDFLARE_ACCOUNT_ID": "account-id-placeholder",
            "CLOUDFLARE_EMAIL": "operator@example.test",
            "CLOUDFLARE_GLOBAL_API_KEY": "global-key-placeholder",
            "GITHUB_TOKEN": "github-token-placeholder",
            "MINIMAX_API_KEY": "minimax-key-placeholder",
            "MINIMAX_BASE_URL": "https://minimax.example.test/v1",
            "MINIMAX_MODEL": "minimax-model-placeholder",
            "NOTION_TOKEN": "notion-token-placeholder",
            "NOTION_ROOT_PAGE_ID": "00000000-0000-4000-8000-000000000001",
        }

    def test_single_environment_schema_is_compact_and_operator_owned(self):
        schema = platform.operator_environment_schema()
        self.assertTrue(schema["ok"])
        self.assertEqual(schema["example"], "config/platform.env.example")
        self.assertEqual(
            schema["canonicalRuntimeSource"],
            "/root/.config/mte-secrets/platform.env",
        )
        self.assertTrue(schema["fillOnly"])
        self.assertIn("CLOUDFLARE_GLOBAL_API_KEY", schema["localOnlyBootstrapKeys"])
        self.assertNotIn(
            "MTE_ACTIVEPIECES_WORKER_ENV_AP_FRONTEND_URL", schema["requiredKeys"]
        )

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

    def test_dotenv_parser_does_not_merge_ambient_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "platform.env"
            path.write_text("MTE_SSH_TARGET=root@example.test\n")
            with mock.patch.dict(
                os.environ, {"UNRELATED_SECRET": "must-not-cross-boundary"}, clear=True
            ):
                values = platform.local_dotenv(path)
        self.assertEqual(values, {"MTE_SSH_TARGET": "root@example.test"})

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
        self.assertNotIn("baserow", active_ids)
        self.assertNotIn("wikijs", active_ids)
        self.assertNotIn("nocodb", active_ids)
        self.assertTrue(
            next(row for row in active if row["id"] == "postgrest")["required"]
        )
        self.assertTrue(
            next(
                row for row in manifest["spec"]["components"] if row["id"] == "nocodb"
            )["required"]
        )
        ordered_ids = [row["id"] for row in platform.component_order(manifest, None)]
        self.assertEqual(active_ids, set(ordered_ids))

    def test_provider_manifest_rejects_missing_and_ambiguous_mappings(self):
        missing_profile = self.provider_manifest()
        del missing_profile["spec"]["providerProfiles"]["baserow-wikijs"]
        with self.assertRaisesRegex(platform.PlatformError, "missing=baserow-wikijs"):
            platform.provider_profile_catalog(missing_profile)

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
        postgrest["enabledForProfiles"].remove("baserow-wikijs")
        with self.assertRaisesRegex(
            platform.PlatformError, "enabledForProfiles mapping is incomplete"
        ):
            platform.provider_profile_catalog(incomplete)

    def test_provider_manifest_rejects_unknown_profile_and_incompatible_dependency(
        self,
    ):
        unknown = self.provider_manifest("not-a-provider-profile")
        with self.assertRaisesRegex(platform.PlatformError, "unknown selected"):
            platform.components(unknown)

        incompatible = self.provider_manifest()
        activepieces = next(
            row
            for row in incompatible["spec"]["components"]
            if row["id"] == "activepieces"
        )
        activepieces["dependsOn"].append("nocodb")
        with self.assertRaisesRegex(
            platform.PlatformError, "unavailable dependencies: nocodb"
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

    def test_ssh_scp_and_deploy_lock_use_shared_keepalive_transport(self):
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

        process = mock.Mock()
        process.stdout.readline.return_value = "MTE_DEPLOY_LOCKED\n"
        process.wait.return_value = 0
        with mock.patch.object(
            platform.subprocess, "Popen", return_value=process
        ) as popen:
            with platform.remote_deploy_lock(cfg):
                pass
        self.assertEqual(
            popen.call_args.args[0][: len(expected_prefix)],
            expected_prefix,
        )

    def test_ssh_exports_no_bytecode_environment_for_child_python(self):
        cfg = {"spec": {"host": {"ssh": "root@example.test"}}}
        child = "import os; print(os.environ['PYTHONDONTWRITEBYTECODE'])"
        original = f"python3 -c {shlex.quote(child)}"

        with mock.patch.object(platform, "run") as run:
            platform.ssh(cfg, original)

        command = run.call_args.args[0]
        wrapped = command[-1]
        self.assertEqual(
            wrapped,
            f"export PYTHONDONTWRITEBYTECODE=1;\n{original}",
        )
        result = subprocess.run(
            ["/bin/sh", "-c", wrapped],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "0"},
        )
        self.assertEqual(result.stdout.strip(), "1")

    def test_nocodocs_license_gate_uses_canonical_presence_only(self):
        command_env = dict(os.environ)

        def local_ssh(
            _cfg,
            command,
            *,
            check=True,
            input_text=None,
            capture_output=False,
        ):
            return subprocess.run(
                command,
                shell=True,
                check=check,
                text=True,
                input=input_text,
                capture_output=capture_output,
                env=command_env,
            )

        with tempfile.TemporaryDirectory() as temp:
            fake_bin = Path(temp) / "bin"
            fake_bin.mkdir()
            stat = fake_bin / "stat"
            stat.write_text(
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "value = os.stat(sys.argv[3])\n"
                "if sys.argv[2] == '%u':\n"
                "    print(value.st_uid)\n"
                "elif sys.argv[2] == '%a':\n"
                "    print(format(value.st_mode & 0o777, 'o'))\n"
                "else:\n"
                "    raise SystemExit(2)\n"
            )
            stat.chmod(0o700)
            command_env["PATH"] = str(fake_bin) + os.pathsep + command_env["PATH"]
            secret_root = Path(temp) / "secrets"
            secret_root.mkdir()
            canonical = secret_root / "platform.env"

            def fixture(profile=platform.NOCODOCS_LICENSED_PROFILE):
                return {
                    "_resolvedDataContentPlane": {"profile": profile},
                    "spec": {
                        "host": {
                            "ssh": "root@example.test",
                            "root": "/opt/mte-platform",
                            "secretsRoot": str(secret_root),
                            "excluded": [],
                        }
                    },
                }

            with mock.patch.object(platform, "ssh", side_effect=local_ssh):
                # Missing canonical source and a canonical source with neither
                # selector nor key both resolve to the reviewed source default.
                with self.assertRaises(platform.PreMutationGateError) as absent:
                    platform.pre_mutation_license_gate(fixture())
                self.assertEqual(absent.exception.code, "business_license_required")
                self.assertEqual(
                    absent.exception.result,
                    {
                        "profile": platform.NOCODOCS_LICENSED_PROFILE,
                        "licenseKey": "missing",
                    },
                )

                canonical.write_text("# no selector and no license\n")
                canonical.chmod(0o600)
                with self.assertRaises(platform.PreMutationGateError) as defaulted:
                    platform.pre_mutation_license_gate(fixture())
                self.assertEqual(defaulted.exception.code, "business_license_required")

                canonical.write_text(
                    "DATA_CONTENT_PROFILE="
                    + platform.NOCODOCS_LICENSED_PROFILE
                    + "\nNOCODB_LICENSE_KEY=   \n"
                )
                canonical.chmod(0o600)
                with self.assertRaises(platform.PreMutationGateError) as empty:
                    platform.pre_mutation_license_gate(fixture())
                self.assertEqual(empty.exception.code, "business_license_required")

                canonical.write_text(
                    "DATA_CONTENT_PROFILE="
                    + platform.NOCODOCS_LICENSED_PROFILE
                    + "\nNOCODB_LICENSE_KEY=''\n"
                )
                canonical.chmod(0o600)
                with self.assertRaises(platform.PreMutationGateError) as quoted_empty:
                    platform.pre_mutation_license_gate(fixture())
                self.assertEqual(
                    quoted_empty.exception.code, "business_license_required"
                )

                sentinel = "unit-license-value-must-never-cross-ssh"
                canonical.write_text(
                    "DATA_CONTENT_PROFILE="
                    + platform.NOCODOCS_LICENSED_PROFILE
                    + "\nNOCODB_LICENSE_KEY="
                    + sentinel
                    + "\n"
                )
                canonical.chmod(0o600)
                result = platform.pre_mutation_license_gate(fixture())
                self.assertEqual(
                    result,
                    {
                        "profile": platform.NOCODOCS_LICENSED_PROFILE,
                        "licenseKey": "present",
                    },
                )
                self.assertNotIn(sentinel, json.dumps(result))

                # An exact, explicitly selected rollback profile does not need
                # the NocoDB Business key.
                canonical.write_text("DATA_CONTENT_PROFILE=baserow-wikijs\n")
                canonical.chmod(0o600)
                self.assertEqual(
                    platform.pre_mutation_license_gate(fixture("baserow-wikijs")),
                    {"profile": "baserow-wikijs", "licenseKey": "not-required"},
                )

                canonical.write_text(
                    "DATA_CONTENT_PROFILE=postgres-postgrest-nocodb-nocodocs\n"
                )
                self.assertEqual(
                    platform.pre_mutation_license_gate(
                        fixture(platform.DEFAULT_DATA_CONTENT_PROFILE)
                    ),
                    {
                        "profile": platform.DEFAULT_DATA_CONTENT_PROFILE,
                        "licenseKey": "not-required",
                    },
                )

    def test_existing_install_imports_reviewed_operator_and_notion_values(self):
        token = "unit-prin7r-notion-token-must-not-appear-in-commands"
        generic_token = "unit-generic-notion-token-must-not-cross-ssh"
        api_key_fallback = "unit-prin7r-api-key-must-not-cross-ssh"
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
            "PRIN7R_NOTION_PAGE_ID": "broad-parent-must-not-be-upgrade-imported",
            "MTE_OPERATOR_SSH_CIDRS": "203.0.113.9/32",
            "PLATFORM_BASE_DOMAIN": "example.test",
            "CLOUDFLARE_GLOBAL_API_KEY": "local-only-must-not-cross-ssh",
            "UNRELATED_SECRET": "must-not-cross-ssh",
        }
        with (
            mock.patch.object(platform, "ssh", side_effect=fake_ssh),
            mock.patch.object(platform, "sync"),
            mock.patch.object(platform, "operator_values", return_value=local_values),
        ):
            platform.ensure_config_initialized(cfg)

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
                "MTE_OPERATOR_SSH_CIDRS": "203.0.113.9/32",
                "PLATFORM_BASE_DOMAIN": "example.test",
            },
        )
        self.assertNotIn(token, "\n".join(command for command, _ in commands))
        self.assertNotIn(generic_token, json.dumps(commands))
        self.assertNotIn(api_key_fallback, json.dumps(commands))
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

    def test_nonempty_canonical_notion_token_is_never_overwritten(self):
        canonical_token = "unit-canonical-token-preserved"
        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            canonical.write_text(
                "DATA_CONTENT_PROFILE=postgres-notion\n"
                f"NOTION_TOKEN={canonical_token}\n"
                "NOTION_ROOT_PAGE_ID=unit-root\n"
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
                        "NOTION_TOKEN": "unit-wrong-generic",
                        "PRIN7R_NOTION_API_KEY": "unit-wrong-api-key",
                        "PRIN7R_NOTION_TOKEN": "unit-wrong-preferred",
                    }
                )
                values = server_config.parse_env(canonical)

        self.assertEqual(values["NOTION_TOKEN"], canonical_token)
        self.assertNotIn("PRIN7R_NOTION_TOKEN", values)
        self.assertNotIn("PRIN7R_NOTION_API_KEY", values)
        self.assertNotIn(canonical_token, json.dumps(result))

    def test_renderer_hardens_registered_secret_projections_and_lock_aliases(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
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

    def test_default_profile_excludes_dormant_provider_service_projections(self):
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
        self.assertNotIn("baserow", service_keys)
        self.assertNotIn("wikijs", service_keys)
        self.assertNotIn("nocodb", service_keys)

    def test_template_sync_render_template_sync_keeps_runtime_projections_clean(self):
        """A repeated source sync must never overwrite a rendered projection."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "platform"
            secret_root = Path(temp) / "secrets"
            config_source = root / "templates/platform.json"
            compose_source = root / "templates/deploy/demo.compose.yaml"
            profile_source = root / "templates/profiles/profiles.yaml"
            runtime_config = root / "config/platform.json"
            runtime_compose = root / "runtime/deploy/demo.compose.yaml"
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
                                    "compose": "deploy/demo.compose.yaml",
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
            profile_source.write_text(profile_text)
            platform_lock_source.write_text("spec: {}\n")

            replacements = {
                "ROOT": root,
                "SECRET_ROOT": secret_root,
                "SOURCE": canonical,
                "MANIFEST": manifest,
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
                        "AP_REDIS_PASSWORD": "unit-test-only",
                        "BASEROW_DB_HOST": "mte-postgres",
                        "BASEROW_DB_NAME": "baserow",
                        "BASEROW_DB_PASSWORD": "unit-test-only",
                        "BASEROW_DB_PORT": "5432",
                        "BASEROW_DB_USER": "baserow",
                        "BASEROW_REDIS_DB": "8",
                        "BASEROW_REDIS_HOST": "redis",
                        "BASEROW_REDIS_PASSWORD": "unit-test-only",
                        "BASEROW_REDIS_PORT": "6379",
                        "CLOUDFLARE_API_TOKEN": "unit-test-only",
                        "PLATFORM_BASE_DOMAIN": "prin7r.com",
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
                "runtime/deploy/demo.compose.yaml",
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
        remote_commands = []
        with (
            tempfile.TemporaryDirectory() as temp,
            mock.patch.object(platform, "ROOT", Path(temp)),
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
                side_effect=lambda command, **_kwargs: commands.append(command),
            ),
        ):
            platform.sync(cfg)
            platform.sync(cfg)
        destinations = "\n".join(
            item
            for command in commands
            for item in command
            if isinstance(item, str) and "root@example.test:" in item
        )
        stage = "/opt/mte-platform/.sync-staging"
        self.assertIn(stage + "/templates/deploy/", destinations)
        self.assertIn(stage + "/templates/profiles/", destinations)
        self.assertIn(stage + "/templates/platform.json", destinations)
        self.assertIn(stage + "/templates/compose-seeds.lock.json", destinations)
        self.assertIn(stage + "/steps/", destinations)
        self.assertIn(
            stage + "/runtime/paperclip/scripts/bootstrap-paperclip.py",
            destinations,
        )
        self.assertIn(
            stage + "/runtime/paperclip/scripts/profile_catalog.py",
            destinations,
        )
        self.assertIn(
            stage + "/runtime/paperclip/profiles/instructions/",
            destinations,
        )
        self.assertIn(
            stage + "/runtime/paperclip/scripts/integration_canary.py",
            destinations,
        )
        self.assertIn(
            stage + "/bin/server-observability-canary.py",
            destinations,
        )
        self.assertIn(
            stage + "/bin/server-host-dokploy-acceptance.py",
            destinations,
        )
        self.assertIn(
            stage + "/bin/server-integration-canaries.py",
            destinations,
        )
        self.assertNotIn("/opt/mte-platform/runtime/deploy/", destinations)
        self.assertNotIn("/opt/mte-platform/runtime/profiles/", destinations)
        self.assertNotIn("/opt/mte-platform/config/platform.json", destinations)
        self.assertNotIn("projections-manifest.json", destinations)
        pushes = [
            command
            for command in commands
            if command
            and command[0] == "rsync"
            and any(
                isinstance(item, str) and item.startswith("root@example.test:")
                for item in command
            )
        ]
        self.assertTrue(pushes)
        self.assertTrue(
            all(
                any(
                    isinstance(item, str)
                    and item.startswith("root@example.test:" + stage + "/")
                    for item in command
                )
                for command in pushes
            )
        )
        self.assertTrue(all("--chown=root:root" not in command for command in pushes))
        self.assertTrue(all("-rtz" in command for command in pushes))
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
            all('rm -rf "$root/patches"' in command for command in ownership_gates)
        )
        self.assertTrue(
            all(
                'rsync -rtp --delete --ignore-times "$stage/$rel/" "$root/$rel/"'
                in command
                for command in ownership_gates
            )
        )
        self.assertTrue(
            all('rm -rf "$stage"' in command for command in ownership_gates)
        )

    def test_active_full_deploy_sync_only_verifies_frozen_transaction(self):
        transaction = mock.Mock()
        original = platform.ACTIVE_DEPLOY_TRANSACTION
        platform.ACTIVE_DEPLOY_TRANSACTION = transaction
        try:
            with (
                mock.patch.object(platform, "run") as run,
                mock.patch.object(platform, "ssh") as ssh,
            ):
                platform.sync({})
                platform.sync({}, render_projections=False)
        finally:
            platform.ACTIVE_DEPLOY_TRANSACTION = original
        self.assertEqual(transaction.ensure_synced.call_count, 2)
        run.assert_not_called()
        ssh.assert_not_called()

    def _transaction_fixture(self, root):
        source = root / "source"
        helper = source / "bin/server-deploy-transaction.py"
        helper.parent.mkdir(parents=True)
        helper.write_text("# governed helper\n")
        snapshot = mock.Mock()
        snapshot.source = source
        snapshot.source_sha256 = "a" * 64
        snapshot.release_id = "release-12345678"
        snapshot.verify = mock.Mock()
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/agent-platform",
                }
            }
        }
        return platform.DeployTransaction(cfg, snapshot, "run-12345678", attempt=1)

    @staticmethod
    def _remote_json(**payload):
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({"ok": True, **payload}) + "\n",
            stderr="",
        )

    def test_promotion_lost_ack_accepts_authoritative_current_activation(self):
        with tempfile.TemporaryDirectory() as temp:
            transaction = self._transaction_fixture(Path(temp))
            observed = []

            def remote(_cfg, command, **_kwargs):
                observed.append(command)
                if " promote " in command:
                    raise subprocess.CalledProcessError(255, command)
                if " inspect-activation " in command:
                    return self._remote_json(
                        status="current",
                        activationId=transaction.activation_id,
                        current=True,
                        currentActivationId=transaction.activation_id,
                        currentStatus="active",
                        journalStatus="active",
                        releaseId=transaction.release_id,
                        sourceSha256="a" * 64,
                    )
                if " verify-current " in command:
                    return self._remote_json(
                        status="active",
                        sourceSha256="a" * 64,
                        fileCount=1,
                    )
                self.fail(f"unexpected remote command: {command}")

            with mock.patch.object(platform, "ssh", side_effect=remote):
                result = transaction.promote()

        self.assertTrue(transaction.promoted)
        self.assertTrue(result["current"])
        self.assertEqual(sum(" inspect-activation " in row for row in observed), 1)
        self.assertEqual(sum(" verify-current " in row for row in observed), 1)

    def test_interrupted_rollback_retries_while_activation_is_current(self):
        with tempfile.TemporaryDirectory() as temp:
            transaction = self._transaction_fixture(Path(temp))
            transaction.promoted = True
            rollback_attempts = 0

            def remote(_cfg, command, **_kwargs):
                nonlocal rollback_attempts
                if " rollback-if-current " in command:
                    rollback_attempts += 1
                    if rollback_attempts == 1:
                        raise subprocess.CalledProcessError(255, command)
                    return self._remote_json(
                        action="rolledBack",
                        status="rolledBack",
                        activationId=transaction.activation_id,
                        sourceSha256="a" * 64,
                    )
                if " inspect-activation " in command:
                    return self._remote_json(
                        status="current",
                        activationId=transaction.activation_id,
                        current=True,
                        currentActivationId=transaction.activation_id,
                        currentStatus="active",
                        journalStatus="active",
                        releaseId=transaction.release_id,
                        sourceSha256="a" * 64,
                    )
                self.fail(f"unexpected remote command: {command}")

            with mock.patch.object(platform, "ssh", side_effect=remote):
                result = transaction.rollback()

        self.assertEqual(rollback_attempts, 2)
        self.assertEqual(result["action"], "rolledBack")
        self.assertFalse(transaction.promoted)

    def test_lost_rollback_ack_is_proved_by_remote_journal(self):
        with tempfile.TemporaryDirectory() as temp:
            transaction = self._transaction_fixture(Path(temp))

            def remote(_cfg, command, **_kwargs):
                if " rollback-if-current " in command:
                    raise subprocess.CalledProcessError(255, command)
                if " inspect-activation " in command:
                    return self._remote_json(
                        status="notCurrent",
                        activationId=transaction.activation_id,
                        current=False,
                        currentActivationId="previous-12345678",
                        currentStatus="active",
                        journalStatus="rolledBack",
                        releaseId=transaction.release_id,
                        sourceSha256="a" * 64,
                    )
                self.fail(f"unexpected remote command: {command}")

            with mock.patch.object(platform, "ssh", side_effect=remote):
                result = transaction.rollback()

        self.assertEqual(result["action"], "alreadyRolledBack")

    def test_failed_checkpoint_does_not_skip_authoritative_rollback(self):
        transaction = mock.Mock()
        transaction.checkpoint.side_effect = platform.PlatformError(
            "checkpoint unavailable"
        )
        transaction.rollback.return_value = {
            "action": "rolledBack",
            "status": "rolledBack",
            "activationId": "run-12345678-a1",
        }

        checkpoint, rollback = platform.best_effort_transaction_failure(
            transaction,
            failed_step="daytona",
            live_mutation_possible=True,
        )

        transaction.rollback.assert_called_once_with()
        self.assertEqual(checkpoint["status"], "failed")
        self.assertEqual(checkpoint["errorType"], "PlatformError")
        self.assertEqual(rollback["status"], "completed")
        self.assertEqual(rollback["authoritativeState"], "rolled-back")

    def test_non_current_activation_never_claims_completed_rollback(self):
        evidence = platform.authoritative_source_rollback_evidence(
            {"action": "notCurrent", "current": False},
            live_mutation_possible=False,
        )
        self.assertEqual(evidence["status"], "not-required")
        self.assertEqual(evidence["authoritativeState"], "not-current")

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

    def test_secret_mutation_paths_render_and_audit_before_dokploy(self):
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

        calls.clear()
        with (
            mock.patch.object(platform, "sync"),
            mock.patch.object(
                platform,
                "ssh",
                side_effect=lambda _cfg, command, **_kwargs: calls.append(command),
            ),
        ):
            platform.deploy_components(cfg, None)
        self.assertIn("server-secrets.py init", calls[0])
        self.assertIn("server-config.py render", calls[1])
        self.assertIn("server-config.py audit", calls[2])
        self.assertIn("server-dokploy.py deploy demo", calls[3])

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

    def test_compose_seed_catalog_is_used_once_and_never_reapplied(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "platform"
            secret_root = Path(temp) / "secrets"
            config_source = root / "templates/platform.json"
            compose_source = root / "templates/deploy/demo.compose.yaml"
            catalog_source = root / "templates/compose-seeds.lock.json"
            canonical = secret_root / "platform.env"
            compose_source.parent.mkdir(parents=True)
            config_source.write_text(
                json.dumps(
                    {
                        "spec": {
                            "components": [
                                {"id": "demo", "compose": "deploy/demo.compose.yaml"}
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

    def test_reviewed_compose_upgrade_fills_missing_without_overwriting(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "platform"
            secret_root = Path(temp) / "secrets"
            config_source = root / "templates/platform.json"
            compose_source = root / "templates/deploy/demo.compose.yaml"
            catalog_source = root / "templates/compose-seeds.lock.json"
            canonical = secret_root / "platform.env"
            compose_source.parent.mkdir(parents=True)
            secret_root.mkdir(parents=True)
            config_source.write_text(
                json.dumps(
                    {
                        "spec": {
                            "components": [
                                {
                                    "id": "demo",
                                    "compose": "deploy/demo.compose.yaml",
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

    def test_reviewed_postgrest_compose_migrations_cover_catalog_prefixes(self):
        catalog = json.loads((ROOT / "config/compose-seeds.lock.json").read_text())[
            "seeds"
        ]
        postgrest_keys = {
            key
            for key in catalog
            if key.startswith("MTE_POSTGREST_") or key.startswith("POSTGREST_")
        }
        self.assertEqual(
            server_config.REVIEWED_COMPOSE_SEED_MIGRATIONS,
            postgrest_keys,
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

    def test_full_deploy_indexes_experimental_steps_in_dependency_order(self):
        steps = list(platform.FULL_DEPLOY_STEPS)
        self.assertEqual(
            steps[:4],
            [
                "config-initialize",
                "config-render",
                "config-audit",
                "bootstrap",
            ],
        )
        self.assertLess(
            steps.index("paperclip-runtime-config"), steps.index("paperclip-runtime")
        )
        self.assertLess(
            steps.index("dokploy-foundation"), steps.index("application-databases")
        )
        self.assertLess(
            steps.index("application-databases"), steps.index("dokploy-components")
        )
        self.assertLess(steps.index("paperclip-runtime"), steps.index("profiles"))
        self.assertLess(steps.index("profiles"), steps.index("paperclip-environments"))
        self.assertLess(
            steps.index("paperclip-environments"), steps.index("paperclip-secrets")
        )
        self.assertLess(steps.index("paperclip-secrets"), steps.index("provision"))
        self.assertLess(steps.index("provision"), steps.index("provision-idempotency"))
        self.assertLess(
            steps.index("provision-idempotency"),
            steps.index("data-content-projections"),
        )
        self.assertLess(
            steps.index("data-content-projections"), steps.index("kestra-control")
        )
        self.assertLess(steps.index("kestra-control"), steps.index("tool-bundles"))
        self.assertLess(
            steps.index("tool-bundles"), steps.index("tool-bundles-idempotency")
        )
        self.assertLess(steps.index("tool-bundles-idempotency"), steps.index("daytona"))
        self.assertLess(steps.index("daytona"), steps.index("harness-auth"))
        self.assertLess(steps.index("daytona"), steps.index("kestra-e2e-canary"))
        self.assertLess(
            steps.index("kestra-e2e-canary"), steps.index("profile-acceptance")
        )
        self.assertLess(
            steps.index("profile-acceptance"), steps.index("integration-canaries")
        )
        self.assertLess(
            steps.index("integration-canaries"), steps.index("hermes-acceptance")
        )
        self.assertLess(
            steps.index("host-dokploy-acceptance"),
            steps.index("observability-reconcile-pass-1"),
        )
        self.assertLess(
            steps.index("observability-reconcile-pass-2"),
            steps.index("observability-idempotency"),
        )
        self.assertLess(
            steps.index("observability-acceptance"), steps.index("cloudflare-plan")
        )
        self.assertLess(steps.index("cloudflare-plan"), steps.index("cloudflare-apply"))
        self.assertLess(
            steps.index("cloudflare-apply"),
            steps.index("cloudflare-origin-firewall"),
        )
        self.assertLess(
            steps.index("cloudflare-origin-firewall"),
            steps.index("post-cloudflare-evidence-rebind"),
        )
        self.assertLess(
            steps.index("post-cloudflare-evidence-rebind"),
            steps.index("cloudflare-acceptance"),
        )
        self.assertLess(
            steps.index("cloudflare-acceptance"), steps.index("connections")
        )
        self.assertLess(steps.index("connections"), steps.index("verify"))

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
        self.assertNotIn("config-source-normalize", platform.FULL_DEPLOY_STEPS)

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

    def test_release_snapshot_projects_static_layout_to_stable_server_contract(self):
        values = platform.parse_dotenv(platform.CANONICAL_ENV_EXAMPLE)
        values.update(platform.bootstrap_seeds())
        with mock.patch.dict(os.environ, values, clear=True):
            cfg = platform.config("agents.example.com")
            snapshot = platform.ReleaseSnapshot(cfg, "unit-static-layout")
        try:
            expected = {
                "templates/deploy/postgres.yaml",
                "templates/profiles/profiles.yaml",
                "runtime/paperclip/scripts/bootstrap-paperclip.py",
                "runtime/paperclip/scripts/profile_catalog.py",
                "templates/platform.lock.yaml",
                "manifests/kestra/application.yaml",
                "manifests/kestra/flows/control-plane.yaml",
                "manifests/hermes/config.yaml.template",
                "manifests/hermes/SOUL.md",
                "manifests/hermes/hermes.service",
                "manifests/cloudflare/main.tf",
                "config/connections.yaml",
                "steps/10-host.sh",
                "steps/50-paperclip.sh",
                "steps/60-daytona.sh",
                "steps/90-cloudflare-tunnel.sh",
                "steps/91-origin-firewall.sh",
            }
            self.assertTrue(
                all((snapshot.source / relative).is_file() for relative in expected)
            )
            self.assertFalse(
                (snapshot.source / "templates/profiles/catalog.yaml").exists()
            )
            catalog = yaml.safe_load(
                (snapshot.source / "templates/profiles/profiles.yaml").read_text()
            )
            for profile in catalog["profiles"]:
                relative = Path(profile["instructions"])
                packaged = snapshot.source / "runtime/paperclip/profiles" / relative
                canonical = platform.PROFILES_ROOT / relative
                self.assertTrue(packaged.is_file())
                self.assertEqual(packaged.read_bytes(), canonical.read_bytes())

            isolated_env = os.environ.copy()
            isolated_env["MTE_PROFILES_FILE"] = str(
                snapshot.source / "templates/profiles/profiles.yaml"
            )
            isolated_env.pop("PYTHONPATH", None)
            imported = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(
                        snapshot.source
                        / "runtime/paperclip/scripts/bootstrap-paperclip.py"
                    ),
                    "--help",
                ],
                cwd=snapshot.root,
                env=isolated_env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertFalse((snapshot.source / "patches").exists())
            snapshot.verify()
        finally:
            snapshot.close()

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
        self.assertIn("/steps/91-origin-firewall.sh", command)
        self.assertLess(command.index(" apply"), command.index(" status"))
        self.assertIn("cloudflare-origin-firewall.json", command)
        self.assertNotIn("MTE_OPERATOR_SSH_CIDRS", command)
        self.assertIn("-az", transfer.call_args.args[0])
        self.assertEqual(evidence_mode, 0o600)
        args = platform.parser().parse_args(["cloudflare", "origin-firewall"])
        self.assertEqual(args.action, "origin-firewall")

    def test_legacy_remote_patch_projection_is_removed_only_after_steps_exist(self):
        cfg = {
            "spec": {
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "excluded": [],
                }
            }
        }
        with mock.patch.object(platform, "ssh") as remote:
            platform.remove_legacy_patch_projection(cfg)
        command = remote.call_args.args[1]
        self.assertIn("test -d /opt/mte-platform/steps", command)
        self.assertIn("rm -rf /opt/mte-platform/patches", command)

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

    def test_legacy_postgres_refs_are_moved_without_duplicate_secret_values(self):
        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            canonical.write_text(
                "NOCODB_DB_USER=legacy-admin\n"
                "NOCODB_DB_PASSWORD=move-only-secret\n"
                "NOCODB_DB_NAME=legacy-database\n"
            )
            canonical.chmod(0o600)
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                value = original_stat(path, *args, **kwargs)
                fields = list(value)
                fields[4] = 0
                return os.stat_result(fields)

            required = {
                "POSTGRES_ADMIN_USER",
                "POSTGRES_ADMIN_PASSWORD",
                "POSTGRES_ADMIN_DB",
            }
            with (
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(server_config, "config_object", return_value={}),
                mock.patch.object(
                    server_config,
                    "declared_keys",
                    return_value=(required, {}, {}),
                ),
                mock.patch.object(Path, "stat", root_owned_stat),
            ):
                result = server_config.init_source({})
            values = server_config.parse_env(canonical)
        self.assertEqual(values["POSTGRES_ADMIN_USER"], "legacy-admin")
        self.assertEqual(values["POSTGRES_ADMIN_PASSWORD"], "move-only-secret")
        self.assertEqual(values["POSTGRES_ADMIN_DB"], "legacy-database")
        self.assertFalse(any(key.startswith("NOCODB_") for key in values))
        self.assertEqual(
            sorted(result["createdKeys"]),
            sorted(required),
        )

    def test_missing_nocodocs_license_blocks_before_any_remote_mutation(self):
        cfg = {
            "_resolvedDataContentPlane": {
                "profile": platform.NOCODOCS_LICENSED_PROFILE
            },
            "spec": {
                "resolvedDomain": "agents.example.test",
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "secretsRoot": "/root/.config/mte-secrets",
                    "excluded": [],
                },
            },
        }
        args = argparse.Namespace(domain=None, components=[], no_wait=False)
        with ExitStack() as stack:
            temp = stack.enter_context(tempfile.TemporaryDirectory())
            root = Path(temp)
            governed_files = {
                "platform.yaml": "kind: PlatformDeployment\n",
                "platform.lock.yaml": "spec: {}\n",
                "connections.yaml": "connections: []\n",
                "deploy/demo.compose.yaml": "services:\n  demo:\n    image: before\n",
                "scripts/demo.py": "VALUE = 'before'\n",
                "profiles/demo.yaml": "profiles: []\n",
                "kestra/demo.yaml": "id: demo\n",
                "hermes/demo.py": "VALUE = 'before'\n",
                "cloudflare/demo.tf": "# before\n",
                "adapter/demo.js": "export const value = 'before';\n",
                "deployment/steps/10-demo.sh": "#!/bin/sh\nexit 0\n",
            }
            for relative, content in governed_files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
                path.chmod(0o700 if path.suffix == ".sh" else 0o600)

            def governed_snapshot():
                return {
                    str(path.relative_to(root)): (
                        hashlib.sha256(path.read_bytes()).hexdigest(),
                        path.stat().st_mode & 0o777,
                    )
                    for path in sorted(root.rglob("*"))
                    if path.is_file() and "evidence" not in path.relative_to(root).parts
                }

            before = governed_snapshot()

            gate_result = {
                "profile": platform.NOCODOCS_LICENSED_PROFILE,
                "licenseKey": "missing",
            }
            deploy_lock = mock.Mock(return_value=nullcontext())
            release_snapshot = mock.Mock(
                side_effect=AssertionError("release snapshot must not be created")
            )
            host_bootstrap = mock.Mock(
                side_effect=AssertionError("host bootstrap must not run")
            )
            for context in (
                mock.patch.object(platform, "ROOT", root),
                mock.patch.object(platform, "config", return_value=cfg),
                mock.patch.object(platform, "ensure_safe_target"),
                mock.patch.object(platform, "ReleaseSnapshot", release_snapshot),
                mock.patch.object(platform, "remote_deploy_lock", deploy_lock),
                mock.patch.object(
                    platform,
                    "pre_mutation_license_gate",
                    side_effect=platform.PreMutationGateError(
                        "business_license_required", gate_result
                    ),
                ),
                mock.patch.object(platform, "run_host_bootstrap", host_bootstrap),
            ):
                stack.enter_context(context)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                with self.assertRaisesRegex(
                    platform.PreMutationGateError, "business_license_required"
                ):
                    platform.deploy_all(args)
            after = governed_snapshot()
            evidence_files = list(
                (root / ".runtime/evidence").glob("deploy-all-*.json")
            )
            self.assertEqual(len(evidence_files), 1)
            evidence_text = evidence_files[0].read_text()
            evidence = json.loads(evidence_text)

        self.assertEqual(after, before)
        release_snapshot.assert_not_called()
        deploy_lock.assert_not_called()
        host_bootstrap.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(evidence["failedStep"], "license-preflight")
        self.assertEqual(evidence["failureCode"], "business_license_required")
        self.assertEqual(evidence["licenseGate"], gate_result)
        self.assertEqual(
            evidence["rollback"],
            {
                "status": "not-required",
                "scope": "none",
                "releaseMutation": "none",
                "serviceMutation": "none",
                "recovery": "safe-after-gate-remediation",
            },
        )
        self.assertNotIn("unit-license-value-must-never-cross-ssh", evidence_text)

    def test_late_nocodocs_probe_failure_is_explicit_roll_forward_risk(self):
        cfg = {
            "spec": {
                "resolvedDomain": "agents.example.test",
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "excluded": [],
                },
            }
        }
        args = argparse.Namespace(domain=None, components=[], no_wait=False)
        with ExitStack() as stack:
            temp = stack.enter_context(tempfile.TemporaryDirectory())

            class FakeSnapshot:
                def __init__(self, _cfg, run_id):
                    self.source_sha256 = "c" * 64
                    self.release_id = run_id + "-" + "c" * 16
                    self.source = Path(temp) / "frozen-source"
                    self.manifest_path = Path(temp) / "manifest.json"
                    self.manifest_path.write_text("{}\n")

                def verify(self):
                    return None

                def close(self):
                    return None

            class FakeTransaction:
                def __init__(self, _cfg, snapshot, run_id, *, attempt, release_id=None):
                    self.release_id = release_id or snapshot.release_id
                    self.activation_id = f"{run_id}-a{attempt}"

                def ensure_synced(self):
                    return None

                def verify(self):
                    return None

                def checkpoint(self, *_args, **_kwargs):
                    return None

                def rollback(self):
                    return {
                        "action": "rolledBack",
                        "status": "rolledBack",
                        "activationId": self.activation_id,
                    }

                def cleanup(self):
                    return None

            for context in (
                mock.patch.object(platform, "ROOT", Path(temp)),
                mock.patch.object(
                    platform, "FULL_DEPLOY_STEPS", ("integration-canaries",)
                ),
                mock.patch.object(platform, "config", return_value=cfg),
                mock.patch.object(platform, "ensure_safe_target"),
                mock.patch.object(platform, "ReleaseSnapshot", FakeSnapshot),
                mock.patch.object(platform, "DeployTransaction", FakeTransaction),
                mock.patch.object(
                    platform, "remote_deploy_lock", return_value=nullcontext()
                ),
                mock.patch.object(
                    platform,
                    "pre_mutation_license_gate",
                    return_value={
                        "profile": platform.NOCODOCS_LICENSED_PROFILE,
                        "licenseKey": "present",
                    },
                ),
                mock.patch.object(platform, "run_host_bootstrap"),
                mock.patch.object(platform, "remove_legacy_patch_projection"),
                mock.patch.object(
                    platform,
                    "run_integration_canaries",
                    side_effect=platform.PlatformError(
                        "synthetic live NocoDocs probe failure"
                    ),
                ),
            ):
                stack.enter_context(context)
            with self.assertRaises(platform.PlatformError):
                platform.deploy_all(args)
            evidence_path = next(
                (Path(temp) / ".runtime/evidence").glob("deploy-all-*.json")
            )
            evidence_text = evidence_path.read_text()
            evidence = json.loads(evidence_text)

        self.assertEqual(evidence["failedStep"], "integration-canaries")
        self.assertEqual(evidence["rollback"]["status"], "completed")
        self.assertEqual(evidence["rollback"]["coverage"], "source-only")
        self.assertEqual(evidence["rollback"]["serviceRollback"], "not-performed")
        self.assertEqual(evidence["rollback"]["liveServiceState"], "may-have-mutated")
        self.assertEqual(evidence["rollback"]["recovery"], "roll-forward-required")
        self.assertNotIn("synthetic live NocoDocs probe failure", evidence_text)

    def test_full_deploy_stops_at_failed_daytona_and_writes_redacted_evidence(self):
        observed = []

        def mark(name):
            return lambda *args, **kwargs: observed.append(name)

        def experimental_step(_cfg, feature, _action):
            name = {
                "environments": "paperclip-environments",
                "secrets": "paperclip-secrets",
                "daytona": "daytona",
            }[feature]
            observed.append(name)
            if feature == "daytona":
                raise platform.PlatformError("synthetic secret-free failure")

        cfg = {
            "spec": {
                "resolvedDomain": "agents.example.test",
                "host": {
                    "ssh": "root@example.test",
                    "root": "/opt/mte-platform",
                    "excluded": [],
                },
            }
        }
        args = argparse.Namespace(domain=None, components=[], no_wait=False)
        with ExitStack() as stack:
            temp = stack.enter_context(tempfile.TemporaryDirectory())

            class FakeSnapshot:
                def __init__(self, _cfg, run_id):
                    self.source_sha256 = "a" * 64
                    self.release_id = run_id + "-" + "a" * 16
                    self.source = Path(temp) / "frozen-source"
                    self.manifest_path = Path(temp) / "manifest.json"
                    self.manifest_path.write_text("{}\n")

                def verify(self):
                    return None

                def close(self):
                    return None

            class FakeTransaction:
                def __init__(self, _cfg, snapshot, run_id, *, attempt, release_id=None):
                    self.release_id = release_id or snapshot.release_id
                    self.activation_id = f"{run_id}-a{attempt}"

                def ensure_synced(self):
                    return None

                def verify(self):
                    return None

                def checkpoint(self, *_args, **_kwargs):
                    return None

                def rollback(self):
                    observed.append("source-rollback")
                    return {
                        "action": "rolledBack",
                        "status": "rolledBack",
                        "activationId": self.activation_id,
                    }

                def cleanup(self):
                    return None

            for context in (
                mock.patch.object(platform, "ROOT", Path(temp)),
                mock.patch.object(platform, "config", return_value=cfg),
                mock.patch.object(platform, "ensure_safe_target"),
                mock.patch.object(platform, "ReleaseSnapshot", FakeSnapshot),
                mock.patch.object(platform, "DeployTransaction", FakeTransaction),
                mock.patch.object(
                    platform, "remote_deploy_lock", return_value=nullcontext()
                ),
                mock.patch.object(
                    platform,
                    "pre_mutation_license_gate",
                    side_effect=lambda _cfg: (
                        observed.append("license-preflight")
                        or {
                            "profile": platform.NOCODOCS_LICENSED_PROFILE,
                            "licenseKey": "present",
                        }
                    ),
                ),
                mock.patch.object(
                    platform, "run_host_bootstrap", mark("host-bootstrap-preflight")
                ),
                mock.patch.object(platform, "remove_legacy_patch_projection"),
                mock.patch.object(
                    platform, "ensure_config_initialized", mark("config-initialize")
                ),
                mock.patch.object(
                    platform,
                    "run_config",
                    lambda _cfg, action: observed.append(f"config-{action}"),
                ),
                mock.patch.object(
                    platform, "finish_platform_bootstrap", mark("bootstrap")
                ),
                mock.patch.object(
                    platform,
                    "run_tools",
                    lambda _cfg, action: observed.append(
                        "toolhive-binary" if action == "install" else "tool-bundles"
                    ),
                ),
                mock.patch.object(
                    platform,
                    "deploy_components",
                    lambda _cfg, selected: observed.append(
                        "dokploy-foundation"
                        if selected == ["postgres"]
                        else "dokploy-components"
                    ),
                ),
                mock.patch.object(
                    platform,
                    "run_application_databases",
                    mark("application-databases"),
                ),
                mock.patch.object(
                    platform,
                    "run_paperclip_runtime",
                    lambda _cfg, action: observed.append(
                        {
                            "config-migrate": "paperclip-runtime-config",
                            "install": "paperclip-runtime",
                        }[action]
                    ),
                ),
                mock.patch.object(platform, "apply_profiles", mark("profiles")),
                mock.patch.object(
                    platform, "run_paperclip_experimental", experimental_step
                ),
                mock.patch.object(platform, "run_provision", mark("provision")),
                mock.patch.object(
                    platform,
                    "run_data_content_projections",
                    mark("data-content-projections"),
                ),
                mock.patch.object(
                    platform, "run_kestra_control", mark("kestra-control")
                ),
                mock.patch.object(platform, "run_harness_auth", mark("harness-auth")),
                mock.patch.object(platform, "run_hermes", mark("hermes")),
                mock.patch.object(platform, "run_cloudflare", mark("cloudflare")),
                mock.patch.object(
                    platform, "run_kestra_canary", mark("kestra-e2e-canary")
                ),
                mock.patch.object(platform, "cmd_connections", mark("connections")),
                mock.patch.object(platform, "cmd_verify", mark("verify")),
            ):
                stack.enter_context(context)
            with self.assertRaises(platform.PlatformError):
                platform.deploy_all(args)
            evidence_files = list(
                (Path(temp) / ".runtime/evidence").glob("deploy-all-*.json")
            )
            self.assertEqual(len(evidence_files), 1)
            evidence_text = evidence_files[0].read_text()
            evidence = json.loads(evidence_text)

        self.assertEqual(
            observed,
            [
                "license-preflight",
                "license-preflight",
                "host-bootstrap-preflight",
                "config-initialize",
                "config-render",
                "config-audit",
                "bootstrap",
                "toolhive-binary",
                "dokploy-foundation",
                "application-databases",
                "dokploy-components",
                "paperclip-runtime-config",
                "paperclip-runtime",
                "profiles",
                "paperclip-environments",
                "paperclip-secrets",
                "provision",
                "provision",
                "data-content-projections",
                "kestra-control",
                "tool-bundles",
                "tool-bundles",
                "daytona",
                "source-rollback",
            ],
        )
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(evidence["failedStep"], "daytona")
        self.assertEqual(evidence["steps"][-1]["errorType"], "PlatformError")
        self.assertEqual(evidence["rollback"]["status"], "completed")
        self.assertEqual(evidence["rollback"]["scope"], "governed-source-tree")
        self.assertEqual(evidence["rollback"]["coverage"], "source-only")
        self.assertEqual(evidence["rollback"]["serviceRollback"], "not-performed")
        self.assertEqual(evidence["rollback"]["liveServiceState"], "may-have-mutated")
        self.assertEqual(evidence["rollback"]["recovery"], "roll-forward-required")
        self.assertRegex(evidence["runId"], r"^[0-9T-]+[0-9a-f]{12}$")
        self.assertTrue(evidence["releaseId"].startswith(evidence["runId"] + "-"))
        self.assertEqual(evidence["sourceSha256"], "a" * 64)
        self.assertTrue(
            evidence["remoteCheckpoint"].endswith(evidence["runId"] + ".json")
        )
        self.assertNotIn("synthetic secret-free failure", evidence_text)

    def test_full_deploy_resume_is_explicit_and_scoped_to_all(self):
        args = platform.parser().parse_args(
            ["deploy", "--all", "--resume", "20260715T120000-deadbeefcafe"]
        )
        self.assertTrue(args.all)
        self.assertEqual(args.resume, "20260715T120000-deadbeefcafe")

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

    def test_daytona_apply_orders_plugin_before_snapshot_acceptance_and_probes(self):
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
        ):
            platform.run_paperclip_experimental(cfg, "daytona", "apply")
        commands = [call.args[1] for call in ssh.call_args_list]
        self.assertEqual(guard.call_count, 1)
        self.assertEqual(
            [commands[index].rsplit(" ", 1)[-1] for index in range(3)],
            ["install", "provision-key", "set-target"],
        )
        first_plugin_apply = next(
            index
            for index, command in enumerate(commands)
            if "server-paperclip-experimental.py daytona apply" in command
        )
        acceptance = next(
            index for index, command in enumerate(commands) if command.endswith(" acceptance")
        )
        plugin_verify = next(
            index
            for index, command in enumerate(commands)
            if "server-paperclip-experimental.py daytona verify" in command
        )
        self.assertLess(first_plugin_apply, acceptance)
        self.assertLess(acceptance, plugin_verify)
        self.assertEqual(
            sum(
                "server-paperclip-experimental.py daytona apply" in command
                for command in commands
            ),
            2,
        )
        self.assertFalse(any(command.endswith(" all") for command in commands))

    def test_daytona_gateway_uses_private_tool_runtime_network_with_live_probe(self):
        daytona_step = (ROOT / "deployment/steps/60-daytona.sh").read_text()
        self.assertIn(
            '"MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM":"http://toolhive:19011"',
            daytona_step,
        )
        self.assertIn(
            '"MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_UPSTREAM":"http://toolhive:19012"',
            daytona_step,
        )
        self.assertIn(
            '"MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM":"http://toolhive:19013"',
            daytona_step,
        )
        self.assertNotIn("http://tool-runtime:19011", daytona_step)
        self.assertIn("networks: [daytona, agent-plane, tool-runtime]", daytona_step)
        self.assertIn(
            "tool-runtime: {{name: mte-tool-runtime, external: true}}", daytona_step
        )
        self.assertIn("network_mode: service:runner", daytona_step)
        self.assertIn("def no_host_bindings(container):", daytona_step)
        self.assertIn('"noPublishedPorts": True', daytona_step)
        self.assertIn('"gatewayNetworkMode": gateway_network_mode', daytona_step)
        self.assertIn('"method":"initialize"', daytona_step)
        self.assertIn('"agentGateway":gateway', daytona_step)
        self.assertIn('import http from "node:http";', daytona_step)
        self.assertIn("const request = http.request(manifestUrl", daytona_step)
        self.assertNotIn(
            "MTE_DAYTONA_REGISTRY_EVIDENCE_URL}/v2/${match[1]}", daytona_step
        )

    def test_activepieces_has_data_plane(self):
        compose = yaml.safe_load(
            (ROOT / "deployment/services/activepieces/compose.yaml").read_text()
        )
        for service in ("app", "worker"):
            networks = compose["services"][service]["networks"]
            names = set(networks if isinstance(networks, list) else networks)
            self.assertIn("data-plane", names)
        self.assertEqual(
            compose["networks"]["data-plane"],
            {
                "name": "mte-data-plane",
                "external": True,
            },
        )

    def test_redis_passwords_are_generated_and_all_app_paths_use_derived_urls(self):
        passwords = {
            key: value
            for key, value in server_secrets.generated_defaults(
                "baserow-wikijs"
            ).items()
            if key
            in {
                "BASEROW_REDIS_PASSWORD",
                "FIRECRAWL_REDIS_PASSWORD",
                "SEARXNG_VALKEY_PASSWORD",
            }
        }
        self.assertEqual(len(passwords), 3)
        self.assertEqual(len(set(passwords.values())), 3)
        self.assertTrue(all(len(value) >= 32 for value in passwords.values()))

        expected = {
            "FIRECRAWL_REDIS_URL",
            "SEARXNG_VALKEY_URL",
        }
        self.assertTrue(expected <= server_config.DERIVED_VALUE_KEYS)
        for filename, service, password_ref in (
            ("baserow.yaml", "redis", "BASEROW_REDIS_PASSWORD"),
            ("searxng.yaml", "valkey", "SEARXNG_VALKEY_PASSWORD"),
        ):
            compose = yaml.safe_load(
                (
                    ROOT
                    / "deployment/services"
                    / Path(filename).stem
                    / "compose.yaml"
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
            ("baserow.yaml", "redis", "BASEROW_REDIS_PASSWORD"),
            ("searxng.yaml", "valkey", "SEARXNG_VALKEY_PASSWORD"),
            ("activepieces-data.yaml", "redis", "AP_REDIS_PASSWORD"),
        ):
            source = yaml.safe_load(
                (
                    ROOT
                    / "deployment/services"
                    / Path(filename).stem
                    / "compose.yaml"
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
                extra = "BASEROW_REDIS_DB=0\n" if filename == "baserow.yaml" else ""
                env_path.write_text(f"{password_ref}={password}\n{extra}")
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
            if filename == "activepieces-data.yaml":
                self.assertIn("/run/mte-activepieces-redis/redis.password", health)
                self.assertNotIn(password_ref, health)
            else:
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
        self.assertEqual(observed[0], "sync")
        self.assertEqual(observed[-1], "canary")
        self.assertEqual(len(ssh_commands), 1)
        self.assertIn(
            "sha256sum /opt/mte-platform/bin/server-e2e-canary.py", ssh_commands[0]
        )
        self.assertIn(expected, ssh_commands[0])
        self.assertIn(
            "python3 /opt/mte-platform/bin/server-e2e-canary.py apply", ssh_commands[0]
        )


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
        with mock.patch("urllib.request.urlopen", side_effect=error):
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

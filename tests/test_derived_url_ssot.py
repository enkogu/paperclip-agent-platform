from __future__ import annotations

import ast
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_server_config():
    path = ROOT / "tools/platform-cli/server-config.py"
    spec = importlib.util.spec_from_file_location("derived_url_server_config", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load server-config.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server_config = load_server_config()


class DerivedUrlSsotTests(unittest.TestCase):
    def test_derived_url_targets_are_not_duplicated_as_literal_defaults(self):
        tree = ast.parse((ROOT / "tools/platform-cli/server-config.py").read_text())
        literal_defaults = None
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            if any(
                isinstance(target, ast.Name) and target.id == "ONE_TIME_MIGRATION_SEEDS"
                for target in node.targets
            ):
                literal_defaults = ast.literal_eval(node.value)
                break
        self.assertIsInstance(literal_defaults, dict)
        self.assertTrue(
            set(server_config.CANONICAL_DERIVED_URL_SPECS).isdisjoint(literal_defaults)
        )

    def test_all_canonical_url_defaults_are_generated_from_primary_refs(self):
        expected = server_config.derive_canonical_urls(
            server_config.ONE_TIME_MIGRATION_SEEDS
        )
        self.assertEqual(
            {
                key: server_config.ONE_TIME_MIGRATION_SEEDS[key]
                for key in server_config.CANONICAL_DERIVED_URL_SPECS
            },
            expected,
        )
        self.assertTrue(
            {
                "MATTERMOST_URL",
                "HERMES_PAPERCLIP_URL",
                "HERMES_KESTRA_URL",
                "HERMES_LLM_BASE_URL",
                "MTE_PAPERCLIP_API_BASE",
                "DAYTONA_API_URL",
                "MTE_DAYTONA_API_URL",
                "MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL",
            }
            <= set(server_config.CANONICAL_DERIVED_URL_SPECS)
        )

    def test_reconcile_replaces_url_drift_and_records_only_changed_keys(self):
        targets = {
            "MATTERMOST_URL",
            "HERMES_PAPERCLIP_URL",
            "HERMES_KESTRA_URL",
            "HERMES_LLM_BASE_URL",
        }
        values = {
            "MTE_OPERATOR_LOOPBACK_HOST": "127.0.0.1",
            "MATTERMOST_ORIGIN_PORT": "28065",
            "PAPERCLIP_LOOPBACK_HOST": "127.0.0.1",
            "PAPERCLIP_PORT": "23100",
            "KESTRA_LOOPBACK_HOST": "127.0.0.1",
            "KESTRA_HTTP_PORT": "28082",
            "NINEROUTER_ORIGIN_PORT": "20129",
            "MATTERMOST_URL": "http://127.0.0.1:18065",
            "HERMES_PAPERCLIP_URL": "http://127.0.0.1:3100/api",
            "HERMES_KESTRA_URL": "http://127.0.0.1:18082",
        }

        created, migrated = server_config.reconcile_canonical_urls(
            values, targets=targets
        )

        self.assertEqual(created, ["HERMES_LLM_BASE_URL"])
        self.assertEqual(
            migrated,
            [
                "HERMES_KESTRA_URL",
                "HERMES_PAPERCLIP_URL",
                "MATTERMOST_URL",
            ],
        )
        self.assertEqual(values["MATTERMOST_URL"], "http://127.0.0.1:28065")
        self.assertEqual(values["HERMES_PAPERCLIP_URL"], "http://127.0.0.1:23100/api")
        self.assertEqual(values["HERMES_KESTRA_URL"], "http://127.0.0.1:28082")
        self.assertEqual(values["HERMES_LLM_BASE_URL"], "http://127.0.0.1:20129/v1")

    def test_source_state_fails_closed_when_primary_port_and_url_drift(self):
        values = dict(server_config.ONE_TIME_MIGRATION_SEEDS)
        values["NINEROUTER_ORIGIN_PORT"] = "20129"
        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            server_config.write_env(canonical, values)
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                value = original_stat(path, *args, **kwargs)
                fields = list(value)
                fields[4] = 0
                return os.stat_result(fields)

            with (
                mock.patch.object(server_config, "SOURCE", canonical),
                mock.patch.object(Path, "stat", root_owned_stat),
                self.assertRaisesRegex(
                    server_config.ConfigError,
                    "HERMES_LLM_BASE_URL.*NINEROUTER_HEALTH_URL",
                ),
            ):
                server_config.source_state()

    def test_init_reconciles_existing_url_drift_before_writing_source(self):
        targets = {
            "MATTERMOST_URL",
            "HERMES_PAPERCLIP_URL",
            "HERMES_KESTRA_URL",
            "HERMES_LLM_BASE_URL",
        }
        primary_refs = {
            ref
            for target in targets
            for ref in server_config.CANONICAL_DERIVED_URL_SPECS[target][:2]
        }
        required = targets | primary_refs | {"DATA_CONTENT_PROFILE"}
        values = {key: server_config.ONE_TIME_MIGRATION_SEEDS[key] for key in required}
        values["HERMES_PAPERCLIP_URL"] = "http://127.0.0.1:9999/api"
        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            server_config.write_env(canonical, values)
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
                mock.patch.object(Path, "stat", root_owned_stat),
            ):
                result = server_config.init_source({})
                reconciled = server_config.parse_env(canonical)

        self.assertEqual(
            reconciled["HERMES_PAPERCLIP_URL"],
            server_config.ONE_TIME_MIGRATION_SEEDS["HERMES_PAPERCLIP_URL"],
        )
        self.assertIn("HERMES_PAPERCLIP_URL", result["migratedKeys"])

    def test_init_persists_daytona_proxy_domain_and_is_idempotent(self):
        primary_refs = {
            "MTE_DAYTONA_API_PORT",
            "MTE_DAYTONA_API_INTERNAL_PORT",
            "MTE_DAYTONA_DEX_PORT",
            "MTE_DAYTONA_DEX_INTERNAL_PORT",
            "MTE_DAYTONA_MINIO_INTERNAL_PORT",
            "MTE_DAYTONA_PROXY_PORT",
            "MTE_DAYTONA_PROXY_INTERNAL_PORT",
            "MTE_DAYTONA_REGISTRY_INTERNAL_PORT",
            "MTE_DAYTONA_RUNNER_INTERNAL_PORT",
            "MTE_DAYTONA_SSH_PORT",
        }
        required = primary_refs | {"DATA_CONTENT_PROFILE"}
        values = {key: server_config.ONE_TIME_MIGRATION_SEEDS[key] for key in required}
        with tempfile.TemporaryDirectory() as temp:
            canonical = Path(temp) / "platform.env"
            server_config.write_env(canonical, values)
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
                mock.patch.object(Path, "stat", root_owned_stat),
            ):
                first = server_config.init_source({})
                first_values = server_config.parse_env(canonical)
                drifted_values = dict(first_values)
                drifted_values["MTE_DAYTONA_PROXY_DOMAIN"] = "stale.invalid:4999"
                server_config.write_env(canonical, drifted_values)
                second = server_config.init_source({})
                second_values = server_config.parse_env(canonical)
                third = server_config.init_source({})
                third_values = server_config.parse_env(canonical)

        self.assertEqual(
            first_values["MTE_DAYTONA_PROXY_DOMAIN"],
            "mte-daytona-proxy:4000",
        )
        self.assertEqual(first_values, second_values)
        self.assertEqual(second_values, third_values)
        self.assertIn("MTE_DAYTONA_PROXY_DOMAIN", first["createdKeys"])
        self.assertNotIn("MTE_DAYTONA_PROXY_DOMAIN", second["createdKeys"])
        self.assertIn("MTE_DAYTONA_PROXY_DOMAIN", second["migratedKeys"])
        self.assertNotIn("MTE_DAYTONA_PROXY_DOMAIN", third["createdKeys"])
        self.assertNotIn("MTE_DAYTONA_PROXY_DOMAIN", third["migratedKeys"])

if __name__ == "__main__":
    unittest.main()

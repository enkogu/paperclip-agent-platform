import base64
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
ROOT_COMPOSE = ROOT / "deployment/compose.yaml"
SERVICES_ROOT = ROOT / "deployment/services"
ENV_REF = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?::[^}]*)?\}")
DIGEST_PIN = re.compile(r"@sha256:[0-9a-f]{64}$")


def load_server_config():
    path = ROOT / "tools/platform-cli/server-config.py"
    spec = importlib.util.spec_from_file_location("compose_aggregation_config", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load server-config.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def representative_values() -> dict[str, str]:
    values = dict(load_server_config().ONE_TIME_MIGRATION_SEEDS)
    values.update(
        json.loads((ROOT / "config/compose-seeds.lock.json").read_text())["seeds"]
    )
    values.update(
        {
            "FIRECRAWL_DB_PASSWORD": "compose-test-secret",
            "FIRECRAWL_REDIS_PASSWORD": "compose-test-secret",
            "FIRECRAWL_REDIS_URL": "redis://:compose-test-secret@redis:6379",
            "GRAFANA_ADMIN_PASSWORD": "compose-test-secret",
            "GRAFANA_ADMIN_USER": "compose-test-user",
            "KESTRA_ADMIN_PASSWORD": "compose-test-secret",
            "KESTRA_ADMIN_USER": "compose-test-user",
            "KESTRA_DB_PASSWORD": "compose-test-secret",
            "MATTERMOST_ALERT_WEBHOOK_URL": "https://example.invalid/hooks/test",
            "MATTERMOST_DB_PASSWORD": "compose-test-secret",
            "MATTERMOST_SITE_URL": "https://mattermost.example.invalid",
            "NINEROUTER_API_KEY_SECRET": "compose-test-secret",
            "NINEROUTER_INITIAL_PASSWORD": "compose-test-secret",
            "NINEROUTER_JWT_SECRET": "compose-test-secret",
            "NINEROUTER_MACHINE_ID_SALT": "compose-test-secret",
            "POSTGREST_AUTHENTICATOR_PASSWORD": "compose-test-secret",
            "POSTGREST_JWT_SECRET": "compose-test-secret-compose-test-secret",
            "POSTGRES_ADMIN_PASSWORD": "compose-test-secret",
            "SEARXNG_BASE_URL": "https://search.example.invalid/",
            "SEARXNG_SECRET": "compose-test-secret",
            "SEARXNG_VALKEY_PASSWORD": "compose-test-secret",
            "SEARXNG_VALKEY_URL": "redis://:compose-test-secret@valkey:6379/0",
        }
    )
    return {key: str(value) for key, value in values.items()}


def aggregate_compose_paths() -> list[Path]:
    platform = yaml.safe_load((ROOT / "config/platform.yaml").read_text())
    explicit = {
        ROOT / row["compose"]
        for row in platform["spec"]["components"]
        if row.get("management") == "explicit-step" and row.get("compose")
    }
    return [
        path
        for path in sorted(SERVICES_ROOT.glob("*/compose.yaml"))
        if path not in explicit
    ]


class ComposeAggregationTests(unittest.TestCase):
    def test_redis_projection_percent_encodes_credentials(self):
        server_config = load_server_config()
        values = representative_values()
        values["PLATFORM_BASE_DOMAIN"] = "example.test"
        values["FIRECRAWL_REDIS_PASSWORD"] = "fire:@/ %#"
        values["SEARXNG_VALKEY_PASSWORD"] = "search:@/ %#"

        projected = server_config.resolved_projection_values({}, values)

        self.assertEqual(
            projected["FIRECRAWL_REDIS_URL"],
            "redis://:fire%3A%40%2F%20%25%23@redis:6379",
        )
        self.assertEqual(
            projected["SEARXNG_VALKEY_URL"],
            "redis://:search%3A%40%2F%20%25%23@valkey:6379/0",
        )

    def test_root_projects_every_component_service_without_include_conflicts(self):
        root = yaml.safe_load(ROOT_COMPOSE.read_text())
        self.assertNotIn("include", root)

        projected = {
            (definition["extends"]["file"], definition["extends"]["service"])
            for definition in root["services"].values()
        }
        expected = {
            (
                path.relative_to(ROOT_COMPOSE.parent).as_posix(),
                service_name,
            )
            for path in aggregate_compose_paths()
            for service_name in yaml.safe_load(path.read_text())["services"]
        }
        self.assertEqual(projected, expected)
        self.assertEqual(len(root["services"]), len(expected))

    def test_root_externalizes_only_cross_compose_networks(self):
        root = yaml.safe_load(ROOT_COMPOSE.read_text())
        source_network_names = {
            definition["name"]
            for path in aggregate_compose_paths()
            for definition in (
                yaml.safe_load(path.read_text()).get("networks") or {}
            ).values()
        }
        root_network_names = {
            definition["name"] for definition in root["networks"].values()
        }
        self.assertEqual(root_network_names, source_network_names)
        self.assertEqual(
            {
                key
                for key, definition in root["networks"].items()
                if definition.get("external")
            },
            {"data-plane", "control", "tool-runtime", "tool-plane", "agent-plane"},
        )
        self.assertEqual(
            root["networks"]["agent-plane"]["name"],
            "${MTE_AGENT_PLANE_NETWORK:?required}",
        )
        self.assertEqual(root["networks"]["control"], {"name": "mte-control", "external": True})

        expected_volumes = {
            key
            for path in aggregate_compose_paths()
            for key in (yaml.safe_load(path.read_text()).get("volumes") or {})
        }
        self.assertEqual(set(root["volumes"]), expected_volumes)

    def test_docker_compose_config_resolves_pinned_image_only_runtime(self):
        if shutil.which("docker") is None:
            self.skipTest("docker CLI is unavailable")
        version = subprocess.run(
            ["docker", "compose", "version"],
            text=True,
            capture_output=True,
            check=False,
        )
        if version.returncode != 0:
            self.skipTest("Docker Compose plugin is unavailable")

        server_config = load_server_config()
        values = representative_values()
        values["MATTERMOST_ALERT_WEBHOOK_URL"] = ""
        projection = server_config.aggregate_compose_projection_content(
            values, "0" * 64, ROOT_COMPOSE
        )
        with tempfile.TemporaryDirectory() as temporary:
            env_file = Path(temporary) / "compose.env"
            env_file.write_text(projection)
            completed = subprocess.run(
                [
                    "docker",
                    "compose",
                    "--env-file",
                    str(env_file),
                    "--file",
                    str(ROOT_COMPOSE),
                    "config",
                    "--format",
                    "json",
                ],
                env={
                    "HOME": os.environ.get("HOME", "/tmp"),
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                },
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        rendered = json.loads(completed.stdout)
        self.assertEqual(len(rendered["services"]), 29)
        for service_name, service in rendered["services"].items():
            with self.subTest(service=service_name):
                self.assertNotIn("build", service)
                self.assertRegex(service["image"], DIGEST_PIN)

        self.assertEqual(
            set(rendered["services"]["searxng"]["depends_on"]),
            {"searxng-config-init", "valkey"},
        )

    def test_aggregate_projection_has_exact_sorted_graph_refs_and_no_extras(self):
        server_config = load_server_config()
        values = representative_values()
        values["PAPERCLIP_BOARD_API_KEY"] = "unit-paperclip-board-key"
        content = server_config.aggregate_compose_projection_content(
            values, "1" * 64, ROOT_COMPOSE
        )
        payload = content.splitlines()[1:]
        keys = [line.split("=", 1)[0] for line in payload]
        root = yaml.safe_load(ROOT_COMPOSE.read_text())
        graph_sources = {ROOT_COMPOSE}
        graph_sources.update(
            (ROOT_COMPOSE.parent / service["extends"]["file"]).resolve()
            for service in root["services"].values()
        )
        expected = {
            match.group(1)
            for source in graph_sources
            for match in ENV_REF.finditer(source.read_text())
        }

        self.assertEqual(keys, sorted(expected))
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(set(keys), expected)
        self.assertIn("SEARXNG_VALKEY_URL", expected)
        self.assertIn("FIRECRAWL_REDIS_URL", expected)
        self.assertNotIn("MTE_DAYTONA_INTERNAL_API_URL", expected)
        empty_allowed = {
            key
            for key, allowed in server_config.aggregate_compose_environment_contract(
                ROOT_COMPOSE
            ).items()
            if allowed
        }
        self.assertEqual(
            empty_allowed,
            {
                "MATTERMOST_ALERT_WEBHOOK_URL",
                "KESTRA_SECRET_PAPERCLIP_BOARD_API_KEY",
            },
        )
        projected = dict(line.split("=", 1) for line in payload)
        self.assertEqual(
            base64.b64decode(
                projected["KESTRA_SECRET_PAPERCLIP_BOARD_API_KEY"]
            ).decode(),
            values["PAPERCLIP_BOARD_API_KEY"],
        )
        self.assertNotIn("PAPERCLIP_BOARD_API_KEY", projected)
        self.assertEqual(
            content,
            server_config.aggregate_compose_projection_content(
                values, "1" * 64, ROOT_COMPOSE
            ),
        )

    def test_aggregate_projection_rejects_missing_newline_and_unresolved_values(self):
        server_config = load_server_config()
        values = representative_values()
        for invalid in (None, "bad\nvalue", "${OTHER:?required}"):
            with self.subTest(invalid=invalid):
                candidate = dict(values)
                if invalid is None:
                    candidate.pop("SEARXNG_VALKEY_URL")
                else:
                    candidate["SEARXNG_VALKEY_URL"] = invalid
                with self.assertRaises(server_config.ConfigError):
                    server_config.aggregate_compose_projection_content(
                        candidate, "2" * 64, ROOT_COMPOSE
                    )

    def test_post_provision_webhook_is_projected_empty_only_while_fully_optional(self):
        server_config = load_server_config()
        values = representative_values()
        values["MATTERMOST_ALERT_WEBHOOK_URL"] = ""
        content = server_config.aggregate_compose_projection_content(
            values, "2" * 64, ROOT_COMPOSE
        )
        self.assertIn("\nMATTERMOST_ALERT_WEBHOOK_URL=\n", content)

        values.pop("MATTERMOST_ALERT_WEBHOOK_URL")
        with self.assertRaises(server_config.ConfigError):
            server_config.aggregate_compose_projection_content(
                values, "2" * 64, ROOT_COMPOSE
            )

    def test_alertmanager_webhook_uses_private_mattermost_endpoint(self):
        server_config = load_server_config()
        values = representative_values()
        operator_url = "http://127.0.0.1:28065/hooks/unit-secret-path"
        values["MATTERMOST_ALERT_WEBHOOK_URL"] = operator_url

        content = server_config.aggregate_compose_projection_content(
            values, "2" * 64, ROOT_COMPOSE
        )
        projected = dict(line.split("=", 1) for line in content.splitlines()[1:])

        self.assertEqual(values["MATTERMOST_ALERT_WEBHOOK_URL"], operator_url)
        self.assertEqual(
            projected["MATTERMOST_ALERT_WEBHOOK_URL"],
            "http://mattermost:8065/hooks/unit-secret-path",
        )
        self.assertNotIn("127.0.0.1", projected["MATTERMOST_ALERT_WEBHOOK_URL"])
        operator_projection = server_config.service_projection_content(
            "observability",
            {"MATTERMOST_ALERT_WEBHOOK_URL"},
            values,
            "2" * 64,
        )
        self.assertIn(
            f"MATTERMOST_ALERT_WEBHOOK_URL={operator_url}\n", operator_projection
        )
        self.assertNotIn("http://mattermost:8065", operator_projection)

    def test_one_required_occurrence_disables_post_provision_empty_allowance(self):
        server_config = load_server_config()
        with tempfile.TemporaryDirectory() as temporary:
            deployment = Path(temporary) / "deployment"
            service_root = deployment / "services/demo"
            service_root.mkdir(parents=True)
            aggregate = deployment / "compose.yaml"
            aggregate.write_text(
                "services:\n  demo:\n    extends:\n"
                "      file: services/demo/compose.yaml\n      service: demo\n"
            )
            service_root.joinpath("compose.yaml").write_text(
                "services:\n  demo:\n    image: example.invalid/demo\n"
                "    environment:\n"
                "      OPTIONAL: ${MATTERMOST_ALERT_WEBHOOK_URL:-}\n"
                "      REQUIRED: ${MATTERMOST_ALERT_WEBHOOK_URL:?required}\n"
            )
            contract = server_config.aggregate_compose_environment_contract(aggregate)
            self.assertFalse(contract["MATTERMOST_ALERT_WEBHOOK_URL"])
            with self.assertRaises(server_config.ConfigError):
                server_config.aggregate_compose_projection_content(
                    {"MATTERMOST_ALERT_WEBHOOK_URL": ""}, "2" * 64, aggregate
                )

    def test_audit_rejects_missing_aggregate_projection_manifest_binding(self):
        server_config = load_server_config()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "projections-manifest.json"
            compose_env = root / "compose.env"
            compose_env.write_text("EXPECTED=value\n")
            compose_env.chmod(0o600)
            manifest.write_text(
                json.dumps(
                    {
                        "sourceSha256": "3" * 64,
                        "generatorVersion": server_config.GENERATOR_VERSION,
                        "projections": [],
                    }
                )
            )
            manifest.chmod(0o600)
            findings = self._compose_audit_findings(
                server_config, manifest, compose_env, "EXPECTED=value\n"
            )

        self.assertIn(
            "projection_manifest_binding_invalid",
            {row["reason"] for row in findings if row["path"] == str(compose_env)},
        )

    def test_audit_rejects_tamper_even_when_manifest_hash_is_rewritten(self):
        server_config = load_server_config()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "projections-manifest.json"
            compose_env = root / "compose.env"
            compose_env.write_text("TAMPERED=value\n")
            compose_env.chmod(0o600)
            manifest.write_text(
                json.dumps(
                    {
                        "sourceSha256": "3" * 64,
                        "generatorVersion": server_config.GENERATOR_VERSION,
                        "projections": [
                            {
                                "path": str(compose_env),
                                "contentSha256": server_config.sha256_path(compose_env),
                                "sourceSha256": "3" * 64,
                                "generatorVersion": server_config.GENERATOR_VERSION,
                            }
                        ],
                    }
                )
            )
            manifest.chmod(0o600)
            findings = self._compose_audit_findings(
                server_config, manifest, compose_env, "EXPECTED=value\n"
            )

        self.assertIn(
            "projection_resolved_content_drift",
            {row["reason"] for row in findings if row["path"] == str(compose_env)},
        )

    @staticmethod
    def _compose_audit_findings(server_config, manifest, compose_env, expected):
        original_stat = Path.stat

        def root_owned_stat(path, *args, **kwargs):
            value = original_stat(path, *args, **kwargs)
            fields = list(value)
            fields[4] = 0
            fields[5] = 0
            return os.stat_result(fields)

        with (
            mock.patch.object(server_config, "MANIFEST", manifest),
            mock.patch.object(server_config, "COMPOSE_ENV", compose_env),
            mock.patch.object(
                server_config, "DATA_CONTENT_PLANE", manifest.parent / "missing.json"
            ),
            mock.patch.object(
                server_config,
                "source_state",
                return_value=({"PLATFORM_BASE_DOMAIN": "example.test"}, "3" * 64),
            ),
            mock.patch.object(server_config, "config_object", return_value={}),
            mock.patch.object(server_config, "platform_lock_object", return_value={}),
            mock.patch.object(
                server_config, "active_config_object", return_value={}
            ),
            mock.patch.object(
                server_config,
                "resolved_projection_values",
                return_value={"EXPECTED": "value"},
            ),
            mock.patch.object(
                server_config,
                "aggregate_compose_projection_content",
                return_value=expected,
            ),
            mock.patch.object(Path, "stat", root_owned_stat),
        ):
            return server_config.drift()


if __name__ == "__main__":
    unittest.main()

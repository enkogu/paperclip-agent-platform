from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_local_verify():
    path = ROOT / "tools/platform-cli/local-verify.py"
    spec = importlib.util.spec_from_file_location("test_local_verify_module", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


local_verify = load_local_verify()


class LocalVerifyRegressionTests(unittest.TestCase):
    def assert_fresh_render_is_ready(self, result: dict) -> None:
        self.assertEqual(result["findings"], [])
        self.assertTrue(result["ok"], result["findings"])
        self.assertTrue(result["runtimeReady"])

    def test_profile_coverage_reads_real_yaml_through_canonical_loader(self):
        source = ROOT / "config/profiles/catalog.yaml"
        self.assertFalse(source.read_text().lstrip().startswith("{"))
        with mock.patch.object(
            local_verify,
            "load_profile_catalog",
            wraps=local_verify.load_profile_catalog,
        ) as loader:
            result = local_verify.profile_coverage()

        self.assertTrue(result["ok"], result["findings"])
        loader.assert_called_once_with(source)

    def test_compose_static_distinguishes_internal_dind_from_host_socket_bind(self):
        documents, yaml_findings = local_verify.yaml_documents()
        self.assertEqual(yaml_findings, [])
        result = local_verify.compose_static(documents)
        self.assertTrue(result["ok"], result["findings"])
        self.assertNotIn(
            "host_docker_socket_present",
            {finding["finding"] for finding in result["findings"]},
        )

        toolhive_path = ROOT / "deployment/services/toolhive/compose.yaml"
        unsafe = yaml.safe_load(toolhive_path.read_text())
        unsafe["services"]["toolhive"]["volumes"].append(
            "/var/run/docker.sock:/var/run/docker.sock"
        )
        unsafe_documents = {**documents, toolhive_path: unsafe}
        unsafe_result = local_verify.compose_static(unsafe_documents)
        self.assertIn(
            "host_docker_socket_present",
            {finding["finding"] for finding in unsafe_result["findings"]},
        )

        result = local_verify.platform_consistency(documents)
        self.assertTrue(result["ok"], result["findings"])

    def test_compose_engine_uses_secret_free_isolated_runtime_fixture(self):
        observed_daytona = False

        def fake_command(argv, timeout=60):
            nonlocal observed_daytona
            if argv == ["docker", "compose", "version"]:
                return {"ok": True, "state": "passed", "outputTail": "v2"}
            compose_path = Path(argv[argv.index("-f") + 1])
            self.assertFalse(compose_path.is_relative_to(ROOT))
            self.assertIn("mte-compose-audit-", str(compose_path))
            if compose_path.parent.name == "daytona":
                observed_daytona = True
                for name in (
                    "ssh.env",
                    "api-ssh.env",
                    "dex.yaml",
                    "runner-daemon.json",
                ):
                    self.assertTrue((compose_path.parent / name).is_file(), name)
                self.assertEqual((compose_path.parent / "ssh.env").read_text(), "")
                self.assertEqual((compose_path.parent / "api-ssh.env").read_text(), "")
            return {"ok": True, "state": "passed", "outputTail": ""}

        with mock.patch.object(local_verify, "command", side_effect=fake_command):
            result = local_verify.docker_compose_check()

        self.assertTrue(observed_daytona)
        self.assertTrue(result["ok"], result["results"])
        self.assertEqual(
            result["composeFilesTested"], len(local_verify.canonical_compose_sources())
        )

    def test_only_exact_host_governed_external_networks_are_accepted(self):
        documents, yaml_findings = local_verify.yaml_documents()
        self.assertEqual(yaml_findings, [])
        aggregate_path = ROOT / "deployment/compose.yaml"
        aggregate = yaml.safe_load(aggregate_path.read_text())
        aggregate["networks"]["unowned"] = {
            "name": "arbitrary-unowned-network",
            "external": True,
        }
        mutated = {**documents, aggregate_path: aggregate}

        result = local_verify.platform_consistency(mutated)

        self.assertIn(
            {
                "network": "arbitrary-unowned-network",
                "finding": "aggregate_external_network_not_host_governed",
            },
            result["findings"],
        )

    def test_fresh_install_copies_and_projects_reviewed_data_content_lock(self):
        result = local_verify.fresh_install_render()
        self.assert_fresh_render_is_ready(result)
        self.assertGreater(result["projectionCount"], 0)
        self.assertGreater(result["composeFilesRendered"], 0)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux import shadow probe")
    def test_fresh_install_does_not_shadow_stdlib_platform_with_sibling_module(self):
        script = """
import importlib.util
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
tool_root = root / "tools/platform-cli"
source = tool_root / "local-verify.py"
spec = importlib.util.spec_from_file_location("linux_local_verify_probe", source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sys.modules.pop("platform", None)
sys.modules.pop("uuid", None)
result = module.fresh_install_render()
import platform as platform_module
print(json.dumps({
    "findings": result["findings"],
    "ok": result["ok"],
    "platformPath": str(Path(platform_module.__file__).resolve()),
    "toolRootOnPath": str(tool_root) in sys.path,
}))
"""
        completed = subprocess.run(
            [sys.executable, "-I", "-c", script, str(ROOT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertTrue(result["ok"], result["findings"])
        self.assertFalse(result["toolRootOnPath"])
        self.assertNotEqual(
            Path(result["platformPath"]), ROOT / "tools/platform-cli/platform.py"
        )

    def test_fresh_install_reports_setup_exception_without_masking_it(self):
        with mock.patch.object(
            local_verify.tempfile,
            "TemporaryDirectory",
            side_effect=RuntimeError("test-only setup failure"),
        ):
            result = local_verify.fresh_install_render()

        self.assertFalse(result["ok"])
        self.assertEqual(result["generatedSecretInputs"], [])
        self.assertEqual(result["classificationCounts"], {})
        self.assertEqual(
            result["findings"],
            [{"finding": "fresh_install_exception", "errorType": "RuntimeError"}],
        )

        with (
            mock.patch.object(
                local_verify.tempfile,
                "TemporaryDirectory",
                side_effect=KeyboardInterrupt,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            local_verify.fresh_install_render()

    def test_postgres_notion_external_inputs_are_typed_and_fail_closed(self):
        result = local_verify.fresh_install_render()
        self.assert_fresh_render_is_ready(result)
        self.assertIn("NOTION_TOKEN", result["externalSecretInputs"])
        self.assertNotIn("NOTION_TOKEN", result["operatorConfigInputs"])
        self.assertIn("PAPERCLIP_AGENT_JWT_SECRET", result["generatedSecretInputs"])
        self.assertNotIn("PAPERCLIP_AGENT_JWT_SECRET", result["externalSecretInputs"])
        self.assertIn("NOTION_ROOT_PAGE_ID", result["operatorConfigInputs"])
        self.assertNotIn("NOTION_ROOT_PAGE_ID", result["externalSecretInputs"])
        self.assertTrue(
            {
                "MTE_SSH_TARGET",
                "MTE_OPERATOR_SSH_CIDRS",
                "MTE_EXCLUDED_HOST_1",
                "MTE_EXCLUDED_HOST_2",
                "PLATFORM_BASE_DOMAIN",
            }
            <= set(result["operatorConfigInputs"])
        )
        self.assertEqual(result["canonicalEnvMode"], "0o600")
        self.assertEqual(
            result["postProvisionedNotionInputs"],
            [
                "NOTION_BOT_ID",
                "NOTION_DOCUMENTS_PAGE_ID",
                "NOTION_TABLE_DATABASE_ID",
                "NOTION_TABLE_DATA_SOURCE_ID",
                "NOTION_WORKSPACE_ID",
            ],
        )

    def test_release_check_requires_a_fully_ready_fresh_install(self):
        fresh_install = local_verify.fresh_install_render()
        self.assert_fresh_render_is_ready(fresh_install)

        result = local_verify.release_check_fresh_install_contract(fresh_install)
        self.assertTrue(result["ok"], result["findings"])
        self.assertEqual(result["state"], "passed")
        self.assertEqual(result["runtimeDeployment"], "ready")

    def test_release_check_rejects_an_unready_fresh_install(self):
        unready = {
            "ok": False,
            "runtimeReady": False,
            "findings": [{"finding": "runtime_image_not_digest_pinned"}],
        }
        gate = local_verify.release_check_fresh_install_contract(unready)
        self.assertFalse(gate["ok"])
        self.assertEqual(gate["runtimeDeployment"], "blocked")

    def test_configuration_source_normalizer_is_closed_over_canonical_contracts(self):
        path = ROOT / "tools/platform-cli/server-config.py"
        spec = importlib.util.spec_from_file_location(
            "test_local_verify_config_contract", path
        )
        assert spec is not None and spec.loader is not None
        server_config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(server_config)

        known = [
            {
                "finding": "compose_seed_catalog_coverage_mismatch",
                "path": "config/compose-seeds.lock.json",
                "missing": [
                    "KESTRA_HEALTH_URL",
                ],
                "extra": [],
            },
            {
                "finding": "runtime_domain_alias",
                "path": "tools/platform-cli/local-verify.py",
                "alias": "MTE_DOMAIN",
            },
            {
                "finding": "script_configurable_literal_outside_canonical",
                "path": "tools/platform-cli/server-integration-canaries.py",
                "key": "API_VERSION",
            },
            {
                "finding": "script_configurable_literal_outside_canonical",
                "path": "tools/platform-cli/server-config.py",
                "key": "PAPERCLIP_AGENT_JWT_SECRET",
            },
            {
                "finding": "literal_environment_value_outside_canonical",
                "path": "deployment/services/observability/compose.yaml",
                "service": "config-init",
                "key": "MATTERMOST_ALERT_WEBHOOK_URL",
            },
        ]
        retained, recognized = local_verify.normalize_configuration_source_findings(
            known, server_config
        )
        self.assertEqual(retained, [])
        self.assertEqual(len(recognized), len(known))

        unknown = [
            {
                "finding": "runtime_domain_alias",
                "path": "tools/platform-cli/local-verify.py",
                "alias": "MTE_UNRECOGNIZED_ALIAS",
            },
            {
                "finding": "script_configurable_literal_outside_canonical",
                "path": "tools/platform-cli/server-integration-canaries.py",
                "key": "UNRECOGNIZED_LITERAL",
            },
            {
                "finding": "script_configurable_literal_outside_canonical",
                "path": "tools/platform-cli/server-config.py",
                "key": "UNRECOGNIZED_GENERATED_SECRET",
            },
        ]
        retained, recognized = local_verify.normalize_configuration_source_findings(
            unknown, server_config
        )
        self.assertEqual(retained, unknown)
        self.assertEqual(recognized, [])

    def test_required_operator_inputs_are_not_compose_seed_obligations(self):
        path = ROOT / "tools/platform-cli/server-config.py"
        spec = importlib.util.spec_from_file_location(
            "test_local_verify_operator_seed_contract", path
        )
        assert spec is not None and spec.loader is not None
        server_config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(server_config)

        operator_inputs = sorted(server_config.REQUIRED_OPERATOR_ENV_KEYS)
        retained, recognized = local_verify.normalize_configuration_source_findings(
            [
                {
                    "finding": "compose_seed_catalog_coverage_mismatch",
                    "path": "config/compose-seeds.lock.json",
                    "missing": operator_inputs,
                    "extra": [],
                }
            ],
            server_config,
        )
        self.assertEqual(retained, [])
        self.assertEqual(recognized[0]["missing"], operator_inputs)
        self.assertTrue(
            {
                "MTE_DAYTONA_SANDBOX_IMAGE",
                "MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL",
                "MTE_DAYTONA_SANDBOX_IMAGE_REVISION",
            }
            <= set(server_config.REQUIRED_OPERATOR_BOOTSTRAP_KEYS)
        )

        real_seed = "MTE_DAYTONA_API_PORT_1_MAPPING"
        catalog = json.loads(
            (ROOT / "config/compose-seeds.lock.json").read_text()
        )["seeds"]
        self.assertIn(real_seed, catalog)
        retained, recognized = local_verify.normalize_configuration_source_findings(
            [
                {
                    "finding": "compose_seed_catalog_coverage_mismatch",
                    "path": "config/compose-seeds.lock.json",
                    "missing": ["MTE_DAYTONA_SANDBOX_IMAGE", real_seed],
                    "extra": [],
                }
            ],
            server_config,
        )
        self.assertEqual(
            retained,
            [
                {
                    "finding": "compose_seed_catalog_coverage_mismatch",
                    "path": "config/compose-seeds.lock.json",
                    "missing": [real_seed],
                    "extra": [],
                }
            ],
        )
        self.assertEqual(recognized, [])

    def test_optional_compose_normalizer_rejects_unreviewed_and_weakened_refs(self):
        path = ROOT / "tools/platform-cli/server-config.py"
        spec = importlib.util.spec_from_file_location(
            "test_local_verify_optional_contract", path
        )
        assert spec is not None and spec.loader is not None
        server_config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(server_config)

        for key in ("OTHER_URL", "NINEROUTER_HEALTH_URL"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                service_root = root / "deployment/services/demo"
                service_root.mkdir(parents=True)
                (root / "deployment/compose.yaml").write_text(
                    "services:\n  demo:\n    extends:\n"
                    "      file: services/demo/compose.yaml\n      service: demo\n"
                )
                service_root.joinpath("compose.yaml").write_text(
                    "services:\n  demo:\n    image: example.invalid/demo\n"
                    f"    environment:\n      {key}: ${{{key}:-}}\n"
                )
                finding = {
                    "finding": "literal_environment_value_outside_canonical",
                    "path": "deployment/services/demo/compose.yaml",
                    "service": "demo",
                    "key": key,
                }
                self.assertFalse(
                    local_verify.reviewed_optional_compose_environment_finding(
                        finding, server_config, root
                    )
                )

    def test_secret_generator_does_not_invent_notion_operator_inputs(self):
        path = ROOT / "tools/platform-cli/server-secrets.py"
        spec = importlib.util.spec_from_file_location(
            "test_local_verify_server_secrets", path
        )
        assert spec is not None and spec.loader is not None
        server_secrets = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(server_secrets)

        generated = server_secrets.generated_defaults("postgres-notion")
        self.assertNotIn("NOTION_TOKEN", generated)
        self.assertNotIn("NOTION_ROOT_PAGE_ID", generated)
        self.assertTrue(
            {
                "POSTGREST_DATA_DB_PASSWORD",
                "POSTGREST_AUTHENTICATOR_PASSWORD",
                "POSTGREST_JWT_SECRET",
            }
            <= set(generated)
        )

    def test_infrastructure_identity_is_not_a_migration_seed(self):
        path = ROOT / "tools/platform-cli/server-config.py"
        spec = importlib.util.spec_from_file_location(
            "test_local_verify_server_config", path
        )
        assert spec is not None and spec.loader is not None
        server_config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(server_config)

        operator_keys = {
            "MTE_SSH_TARGET",
            "MTE_OPERATOR_SSH_CIDRS",
            "MTE_EXCLUDED_HOST_1",
            "MTE_EXCLUDED_HOST_2",
            "PLATFORM_BASE_DOMAIN",
            "MTE_PAPERCLIP_IMAGE",
            "MTE_PAPERCLIP_FORK_SOURCE_URL",
            "MTE_PAPERCLIP_FORK_REVISION",
            "MTE_DAYTONA_SANDBOX_IMAGE",
            "MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL",
            "MTE_DAYTONA_SANDBOX_IMAGE_REVISION",
        }
        self.assertEqual(
            operator_keys, set(server_config.REQUIRED_OPERATOR_BOOTSTRAP_KEYS)
        )
        self.assertTrue(
            operator_keys.isdisjoint(server_config.ONE_TIME_MIGRATION_SEEDS)
        )

    def test_local_evidence_binds_producer_and_canonical_sources(self):
        binding = local_verify.canonical_source_binding()
        producer = binding["producer"]
        self.assertEqual(producer["path"], "tools/platform-cli/local-verify.py")
        self.assertEqual(
            producer["sha256"],
            hashlib.sha256((ROOT / producer["path"]).read_bytes()).hexdigest(),
        )
        expected_sources = {
            "config/platform.yaml",
            "config/platform.lock.yaml",
            "config/acceptance-requirements.yaml",
            "config/compose-seeds.lock.json",
            "config/profiles/catalog.yaml",
        }
        self.assertEqual(set(binding["canonicalSources"]), expected_sources)
        encoded = json.dumps(
            binding["canonicalSources"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        self.assertEqual(
            binding["canonicalSourcesSha256"], hashlib.sha256(encoded).hexdigest()
        )


if __name__ == "__main__":
    unittest.main()

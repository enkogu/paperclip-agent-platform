from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
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

    def test_activepieces_declares_external_data_plane_owner_dependency(self):
        platform = yaml.safe_load((ROOT / "config/platform.yaml").read_text())
        rows = {row["id"]: row for row in platform["spec"]["components"]}
        self.assertIn("postgres", rows["activepieces"]["dependsOn"])

        documents, yaml_findings = local_verify.yaml_documents()
        self.assertEqual(yaml_findings, [])
        result = local_verify.platform_consistency(documents)
        self.assertTrue(result["ok"], result["findings"])

    def test_fresh_install_copies_and_projects_reviewed_data_content_lock(self):
        result = local_verify.fresh_install_render()
        self.assertTrue(result["ok"], result["findings"])
        self.assertGreater(result["projectionCount"], 0)
        self.assertGreater(result["composeFilesRendered"], 0)

    def test_postgres_notion_external_inputs_are_typed_and_fail_closed(self):
        result = local_verify.fresh_install_render()
        self.assertTrue(result["ok"], result["findings"])
        self.assertIn("NOTION_TOKEN", result["externalSecretInputs"])
        self.assertNotIn("NOTION_TOKEN", result["operatorConfigInputs"])
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
            "config/connections.yaml",
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

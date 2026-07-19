from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


contract = load(
    ROOT / "tools/platform-cli/data_content_plane.py", "test_data_content_contract"
)
server_verify = load(
    ROOT / "tools/platform-cli/server-verify.py", "test_data_content_server_verify"
)
platform = load(ROOT / "tools/platform-cli/platform.py", "test_data_content_platform")


class DataContentPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config_path = ROOT / "config/platform.yaml"
        self.lock_path = ROOT / "config/platform.lock.yaml"
        self.config = yaml.safe_load(self.config_path.read_text())
        self.lock = yaml.safe_load(self.lock_path.read_text())
        self.values = {
            "DATA_CONTENT_PROFILE": "postgres-notion",
            "POSTGREST_PUBLIC_URL": "http://127.0.0.1:18084",
            "NOTION_API_BASE_URL": "https://api.notion.com/v1",
            "NOTION_TABLE_DATABASE_ID": "database-id",
            "NOTION_TABLE_DATA_SOURCE_ID": "data-source-id",
            "NOTION_DOCUMENTS_PAGE_ID": "documents-page-id",
        }

    def resolve(
        self,
        *,
        config: dict | None = None,
        lock: dict | None = None,
        values: dict[str, str] | None = None,
        config_path: Path | None = None,
        lock_path: Path | None = None,
    ) -> dict:
        return contract.resolve_from_paths(
            config or self.config,
            lock or self.lock,
            values or self.values,
            config_path=config_path or self.config_path,
            lock_path=lock_path or self.lock_path,
            source_sha256="a" * 64,
            generator_version="test-renderer/v1",
        )

    def test_default_bundle_projects_postgres_ssot_external_notion_capabilities(
        self,
    ) -> None:
        plane = self.resolve()
        self.assertEqual(plane["profile"], "postgres-notion")
        self.assertEqual(plane["selectableProfiles"], ["postgres-notion"])
        self.assertEqual(
            plane["systemOfRecord"],
            {
                "providerId": "postgres",
                "componentId": "postgres",
                "ownership": "authoritative",
            },
        )
        self.assertEqual(plane["componentIds"], ["postgrest"])
        self.assertEqual(plane["providers"]["notion"]["deployment"], "external")
        self.assertIsNone(plane["providers"]["notion"]["componentId"])
        self.assertEqual(
            plane["providers"]["notion"]["capabilities"],
            {
                "tables": {
                    "interfaces": ["ui", "api"],
                    "configurationRefs": [
                        "NOTION_TABLE_DATABASE_ID",
                        "NOTION_TABLE_DATA_SOURCE_ID",
                    ],
                },
                "documents": {
                    "interfaces": ["ui", "api"],
                    "configurationRefs": ["NOTION_DOCUMENTS_PAGE_ID"],
                },
            },
        )
        self.assertEqual(set(plane["roles"]), set(contract.REQUIRED_ROLES))
        self.assertEqual(
            {role: row["providerId"] for role, row in plane["roles"].items()},
            {
                "tablesUi": "notion",
                "tablesApi": "notion",
                "documentsUi": "notion",
                "documentsApi": "notion",
            },
        )
        self.assertEqual(
            contract.adapter_commands(plane, "database"),
            [("server-postgrest.py", "database")],
        )
        self.assertEqual(
            contract.adapter_commands(plane, "provision"),
            [
                ("server-postgrest.py", "provision"),
                ("server-notion.py", "provision"),
            ],
        )
        self.assertEqual(
            contract.projection_consumer_commands(plane, "provision"),
            [("server-notion-sync.py", "provision")],
        )
        self.assertEqual(
            plane["binding"]["platformConfigSha256"],
            hashlib.sha256(self.config_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            plane["binding"]["platformLockSha256"],
            hashlib.sha256(self.lock_path.read_bytes()).hexdigest(),
        )

    def test_adapter_execution_order_is_reviewed_and_incomplete_projections_fail_closed(
        self,
    ) -> None:
        plane = self.resolve()
        # JSON object order is not part of the provider contract.  Rendering
        # serializes keys alphabetically, while the reviewed lifecycle starts
        # with the database provider.
        plane["adapters"] = {
            "notion": plane["adapters"]["notion"],
            "postgrest": plane["adapters"]["postgrest"],
        }
        self.assertEqual(
            contract.adapter_commands(plane, "provision"),
            [
                ("server-postgrest.py", "provision"),
                ("server-notion.py", "provision"),
            ],
        )

        incomplete = json.loads(json.dumps(plane))
        incomplete["adapters"].pop("postgrest")
        for resolver in (
            lambda: contract.adapter_commands(incomplete, "provision"),
            lambda: contract.projection_consumer_commands(incomplete, "verify"),
        ):
            with self.subTest(resolver=resolver):
                with self.assertRaisesRegex(
                    contract.DataContentError, "adapter set is incomplete"
                ):
                    resolver()

    def test_default_orchestration_selects_internal_postgrest_without_ui_containers(
        self,
    ) -> None:
        with mock.patch.dict(
            platform.os.environ,
            {
                "DATA_CONTENT_PROFILE": "postgres-notion",
                "MTE_EXCLUDED_HOST_1": "192.0.2.10",
                "MTE_EXCLUDED_HOST_2": "192.0.2.11",
                "MTE_SSH_TARGET": "root@198.51.100.10",
                "NOTION_API_BASE_URL": "https://api.notion.com/v1",
                "PLATFORM_BASE_DOMAIN": "example.test",
            },
            clear=True,
        ):
            config = platform.config("example.test")
        ordered = [row["id"] for row in platform.component_order(config, None)]
        self.assertEqual(
            {
                row["id"]
                for row in config["spec"]["components"]
                if "enabledForProfiles" in row
            },
            {"postgrest"},
        )
        self.assertNotIn("notion", ordered)

        commands: list[str] = []
        with (
            mock.patch.object(platform, "sync"),
            mock.patch.object(
                platform,
                "ssh",
                side_effect=lambda _cfg, command, **_kwargs: commands.append(command),
            ),
        ):
            platform.run_application_databases(config)
            platform.run_provision(config, "verify")
        self.assertIn("server-postgrest.py database", commands[0])
        self.assertNotIn("server-notion.py database", commands[0])
        self.assertIn("server-postgrest.py verify", commands[1])
        self.assertIn("server-notion.py verify", commands[1])

    def test_provider_manifest_selection_matches_platform_planner_for_every_profile(
        self,
    ) -> None:
        data_catalog = contract.provider_profile_catalog(self.config, self.lock)
        planner_catalog = platform.provider_profile_catalog(self.config)
        self.assertEqual(data_catalog, planner_catalog)

        for profile_id in sorted(data_catalog):
            with self.subTest(profile=profile_id):
                manifest = json.loads(json.dumps(self.config))
                manifest["_resolvedDataContentPlane"] = {
                    "profile": profile_id,
                    "componentIds": data_catalog[profile_id]["componentIds"],
                }
                planner_ids = [row["id"] for row in platform.components(manifest)]
                data_plane_ids = [
                    row["id"]
                    for row in contract._component_rows_for_profile(
                        manifest, profile_id
                    )
                ]
                self.assertEqual(data_plane_ids, planner_ids)

        filtered = contract.filter_platform_config(self.config, self.lock, self.values)
        selected_optional = {
            row["id"]
            for row in filtered["spec"]["components"]
            if "enabledForProfiles" in row
        }
        self.assertEqual(selected_optional, {"postgrest"})

    def test_provider_manifest_filter_fails_closed_on_invalid_declarations(
        self,
    ) -> None:
        ambiguous_provider = json.loads(json.dumps(self.config))
        ambiguous_provider["spec"]["providerProfiles"]["postgres-notion"][
            "providerIds"
        ].append("notion")
        with self.assertRaisesRegex(contract.DataContentError, "unique non-empty"):
            contract.filter_platform_config(ambiguous_provider, self.lock, self.values)

        unknown_profile = json.loads(json.dumps(self.config))
        postgrest = next(
            row
            for row in unknown_profile["spec"]["components"]
            if row["id"] == "postgrest"
        )
        postgrest["enabledForProfiles"].append("unknown-provider")
        with self.assertRaisesRegex(contract.DataContentError, "unknown profile"):
            contract.filter_platform_config(unknown_profile, self.lock, self.values)

        incompatible_dependency = json.loads(json.dumps(self.config))
        postgrest = next(
            row
            for row in incompatible_dependency["spec"]["components"]
            if row["id"] == "postgrest"
        )
        postgrest["dependsOn"].append("unknown-component")
        with self.assertRaisesRegex(
            contract.DataContentError, "unavailable dependencies: unknown-component"
        ):
            contract.filter_platform_config(
                incompatible_dependency, self.lock, self.values
            )

    def test_acceptance_registry_requires_profile_scoped_internal_api(self) -> None:
        requirements = {
            row["id"]: row
            for row in yaml.safe_load(
                (ROOT / "config/acceptance-requirements.yaml").read_text()
            )[
                "requirements"
            ]
        }
        self.assertEqual(requirements["C027"]["to"], "data-content/scopedDataApi")
        self.assertEqual(requirements["C029"]["from"], "postgres-ssot")

    def test_unknown_and_retired_profiles_fail_closed(self) -> None:
        for profile in ("unknown-provider", "mathesar-postgrest-memos"):
            with self.subTest(profile=profile):
                values = dict(self.values)
                values["DATA_CONTENT_PROFILE"] = profile
                with self.assertRaisesRegex(
                    contract.DataContentError, "outside the exact allowlist"
                ):
                    self.resolve(values=values)

    def test_provider_capability_and_component_mismatches_fail_closed(self) -> None:
        missing_component = json.loads(json.dumps(self.config))
        missing_component["spec"]["components"] = [
            row
            for row in missing_component["spec"]["components"]
            if row["id"] != "postgrest"
        ]
        with self.assertRaisesRegex(
            contract.DataContentError, "components are missing"
        ):
            self.resolve(config=missing_component)

        unreviewed_adapter = json.loads(json.dumps(self.lock))
        unreviewed_adapter["spec"]["dataContentProfiles"]["postgres-notion"][
            "adapters"
        ]["notion"]["script"] = "arbitrary.py"
        with self.assertRaisesRegex(contract.DataContentError, "not an allowlisted"):
            self.resolve(lock=unreviewed_adapter)

        mismatched_capability = json.loads(json.dumps(self.lock))
        mismatched_capability["spec"]["dataContentProfiles"]["postgres-notion"][
            "roles"
        ]["tablesUi"]["capability"] = "documents"
        with self.assertRaisesRegex(
            contract.DataContentError, "capability/interface differs"
        ):
            self.resolve(lock=mismatched_capability)

        external_component = json.loads(json.dumps(self.lock))
        external_component["spec"]["dataContentProfiles"]["postgres-notion"][
            "providers"
        ]["notion"]["componentId"] = "notion"
        with self.assertRaisesRegex(
            contract.DataContentError, "external provider cannot claim"
        ):
            self.resolve(lock=external_component)

    def test_server_verifier_requires_exact_manifest_and_registry_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_source = root / "templates/platform.json"
            lock_source = root / "templates/platform.lock.yaml"
            runtime_config = root / "config/platform.json"
            plane_path = root / "config/data-content-plane.json"
            module_path = root / "bin/data_content_plane.py"
            for path in (
                config_source,
                lock_source,
                runtime_config,
                plane_path,
                module_path,
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
            config_source.write_text(json.dumps(self.config, sort_keys=True) + "\n")
            lock_source.write_text(self.lock_path.read_text())
            runtime_config.write_text(json.dumps(self.config, sort_keys=True) + "\n")
            module_path.write_text(
                (ROOT / "tools/platform-cli/data_content_plane.py").read_text()
            )
            source_sha = "a" * 64
            plane = contract.resolve_from_paths(
                self.config,
                self.lock,
                self.values,
                config_path=config_source,
                lock_path=lock_source,
                source_sha256=source_sha,
                generator_version="test-renderer/v1",
            )
            plane_path.write_text(json.dumps(plane, indent=2, sort_keys=True) + "\n")
            row = {
                "path": str(plane_path),
                "contentSha256": hashlib.sha256(plane_path.read_bytes()).hexdigest(),
                "sourceSha256": source_sha,
                "generatorVersion": "test-renderer/v1",
            }
            self.assertEqual(
                server_verify.data_content_projection_findings(
                    root,
                    self.values,
                    source_sha,
                    [row],
                ),
                [],
            )

            extra_field = {**row, "providerPath": "forbidden"}
            findings = server_verify.data_content_projection_findings(
                root,
                self.values,
                source_sha,
                [extra_field],
            )
            self.assertIn(
                "data_content_projection_manifest_binding_invalid",
                {item["finding"] for item in findings},
            )

            stale_values = dict(self.values)
            stale_values.pop("NOTION_API_BASE_URL")
            findings = server_verify.data_content_projection_findings(
                root,
                stale_values,
                source_sha,
                [row],
            )
            self.assertIn(
                "data_content_projection_contract_invalid",
                {item["finding"] for item in findings},
            )

    def test_server_verifier_uses_selected_provider_components(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "config/platform.json"
            lock_path = root / "templates/platform.lock.yaml"
            plane_path = root / "config/data-content-plane.json"
            module_path = root / "bin/data_content_plane.py"
            for path in (config_path, lock_path, plane_path, module_path):
                path.parent.mkdir(parents=True, exist_ok=True)
            runtime = json.loads(json.dumps(self.config))
            config_path.write_text(json.dumps(runtime))
            lock_path.write_text(self.lock_path.read_text())
            plane_path.write_text(json.dumps({"componentIds": ["postgrest"]}))
            module_path.write_text(
                (ROOT / "tools/platform-cli/data_content_plane.py").read_text()
            )
            with (
                mock.patch.object(server_verify, "ROOT", root),
                mock.patch.object(server_verify, "CONFIG", config_path),
            ):
                component_ids = {row["id"] for row in server_verify.load_components()}
            self.assertIn("postgrest", component_ids)


if __name__ == "__main__":
    unittest.main()

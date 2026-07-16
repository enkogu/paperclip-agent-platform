from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOL_ROOT = ROOT / "tools/platform-cli"
server_config = load(TOOL_ROOT / "server-config.py", "test_server_config")
renderer = load(TOOL_ROOT / "render-cloudflare.py", "test_cloudflare_renderer")
server_config.PLATFORM_LOCK_SOURCE = ROOT / "config/platform.lock.yaml"


class CloudflareRenderingTests(unittest.TestCase):
    def test_operator_infrastructure_identity_has_no_application_defaults(self) -> None:
        required = {
            "MTE_SSH_TARGET",
            "MTE_OPERATOR_SSH_CIDRS",
            "MTE_EXCLUDED_HOST_1",
            "MTE_EXCLUDED_HOST_2",
            "PLATFORM_BASE_DOMAIN",
        }
        self.assertEqual(server_config.REQUIRED_OPERATOR_BOOTSTRAP_KEYS, required)
        self.assertTrue(required.isdisjoint(server_config.ONE_TIME_MIGRATION_SEEDS))
        example = (ROOT / "config/platform.env.example").read_text()
        self.assertIn("203.0.113.10", example)
        self.assertIn("agents.example.com", example)
        self.assertIn("CLOUDFLARE_ACCOUNT_ID=", example)
        self.assertIn("CLOUDFLARE_EMAIL=", example)
        self.assertIn("CLOUDFLARE_GLOBAL_API_KEY=", example)

    def canonical_values(self, config: dict) -> dict[str, str]:
        values = {"PLATFORM_BASE_DOMAIN": "prin7r.com"}
        cloudflare = config["spec"]["cloudflare"]
        declarations = [
            row["exposure"]
            for row in config["spec"]["components"]
            if isinstance(row.get("exposure"), dict)
        ] + cloudflare["additionalApps"]
        for row in declarations:
            label_ref = row["subdomainRef"]
            port_ref = row["originPortRef"]
            class_ref = row["accessClassRef"]
            values[label_ref] = (
                label_ref.removesuffix("_SUBDOMAIN")
                .lower()
                .replace("ninerouter", "9router")
            )
            values[port_ref] = "19000"
            values[class_ref] = (
                "service"
                if label_ref
                in {"FIRECRAWL_SUBDOMAIN", "TOOLHIVE_SUBDOMAIN", "NINEROUTER_SUBDOMAIN"}
                else "human"
            )
        return values

    def test_external_notion_roles_are_not_cloudflare_applications(self) -> None:
        config = yaml.safe_load((ROOT / "config/platform.yaml").read_text())
        lock = yaml.safe_load((ROOT / "config/platform.lock.yaml").read_text())
        values = self.canonical_values(config)
        values.update(
            {
                "DATA_CONTENT_PROFILE": "postgres-notion",
                "POSTGREST_PUBLIC_URL": "https://data-api.prin7r.com",
                "NOTION_API_BASE_URL": "https://api.notion.com/v1",
            }
        )
        contract = server_config.data_content_contract()
        data_content_plane = contract.resolve_from_paths(
            config,
            lock,
            values,
            config_path=ROOT / "config/platform.yaml",
            lock_path=ROOT / "config/platform.lock.yaml",
            source_sha256="b" * 64,
            generator_version=server_config.GENERATOR_VERSION,
        )
        filtered_config = contract.filter_platform_config(config, lock, values)
        serialized_plane = (
            json.dumps(data_content_plane, indent=2, sort_keys=True) + "\n"
        ).encode()
        projection = server_config.cloudflare_apps_projection(
            filtered_config,
            values,
            "prin7r.com",
            "b" * 64,
            data_content_plane,
            hashlib.sha256(serialized_plane).hexdigest(),
        )
        self.assertNotIn("notion", projection["apps"])
        self.assertNotIn("nocodb", projection["apps"])
        self.assertEqual(projection["dataContent"]["roles"], {})

    def test_renderer_requires_hash_governed_apps_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = root / "platform.env"
            env.write_text("PLATFORM_BASE_DOMAIN=prin7r.com\n")
            digest = hashlib.sha256(env.read_bytes()).hexdigest()
            projection = root / "apps.json"
            projection.write_text(
                json.dumps(
                    {
                        "_generated": {"sourceSha256": digest},
                        "baseDomain": "prin7r.com",
                        "apps": {
                            "paperclip": {
                                "hostname": "paperclip.prin7r.com",
                                "origin": "http://127.0.0.1:3100",
                                "accessClass": "human",
                            }
                        },
                    }
                )
            )
            apps = renderer.read_apps_projection(projection, env, "prin7r.com")
            self.assertEqual(apps["paperclip"]["access_class"], "human")
            env.write_text("PLATFORM_BASE_DOMAIN=other.example\n")
            with self.assertRaises(renderer.RenderError):
                renderer.read_apps_projection(projection, env, "prin7r.com")

    def test_renderer_requires_exact_logical_data_content_binding(self) -> None:
        config = yaml.safe_load((ROOT / "config/platform.yaml").read_text())
        lock = yaml.safe_load((ROOT / "config/platform.lock.yaml").read_text())
        values = self.canonical_values(config)
        values.update(
            {
                "DATA_CONTENT_PROFILE": "postgres-notion",
                "POSTGREST_PUBLIC_URL": "https://data-api.prin7r.com",
                "NOTION_API_BASE_URL": "https://api.notion.com/v1",
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = root / "platform.env"
            env.write_text("PLATFORM_BASE_DOMAIN=prin7r.com\n")
            source_sha = hashlib.sha256(env.read_bytes()).hexdigest()
            contract = server_config.data_content_contract()
            plane = contract.resolve_from_paths(
                config,
                lock,
                values,
                config_path=ROOT / "config/platform.yaml",
                lock_path=ROOT / "config/platform.lock.yaml",
                source_sha256=source_sha,
                generator_version=server_config.GENERATOR_VERSION,
            )
            plane_path = root / "data-content-plane.json"
            plane_path.write_text(json.dumps(plane, indent=2, sort_keys=True) + "\n")
            plane_sha = hashlib.sha256(plane_path.read_bytes()).hexdigest()
            filtered_config = contract.filter_platform_config(config, lock, values)
            apps_payload = server_config.cloudflare_apps_projection(
                filtered_config,
                values,
                "prin7r.com",
                source_sha,
                plane,
                plane_sha,
            )
            apps_path = root / "apps.json"
            apps_path.write_text(
                json.dumps(apps_payload, indent=2, sort_keys=True) + "\n"
            )
            apps = renderer.read_apps_projection(
                apps_path,
                env,
                "prin7r.com",
                plane_path,
            )
            self.assertNotIn("notion", apps)

            plane["profile"] = "tampered"
            plane_path.write_text(json.dumps(plane, indent=2, sort_keys=True) + "\n")
            with self.assertRaises(renderer.RenderError):
                renderer.read_apps_projection(
                    apps_path,
                    env,
                    "prin7r.com",
                    plane_path,
                )

    def test_empty_roles_fail_closed_for_internal_mixed_or_malformed_providers(
        self,
    ) -> None:
        config = yaml.safe_load((ROOT / "config/platform.yaml").read_text())
        lock = yaml.safe_load((ROOT / "config/platform.lock.yaml").read_text())
        values = self.canonical_values(config)
        values.update(
            {
                "DATA_CONTENT_PROFILE": "postgres-notion",
                "POSTGREST_PUBLIC_URL": "https://data-api.prin7r.com",
                "NOTION_API_BASE_URL": "https://api.notion.com/v1",
            }
        )
        contract = server_config.data_content_contract()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = root / "platform.env"
            env.write_text("PLATFORM_BASE_DOMAIN=prin7r.com\n")
            source_sha = hashlib.sha256(env.read_bytes()).hexdigest()
            plane = contract.resolve_from_paths(
                config,
                lock,
                values,
                config_path=ROOT / "config/platform.yaml",
                lock_path=ROOT / "config/platform.lock.yaml",
                source_sha256=source_sha,
                generator_version=server_config.GENERATOR_VERSION,
            )
            plane_path = root / "data-content-plane.json"
            apps_path = root / "apps.json"
            filtered_config = contract.filter_platform_config(config, lock, values)

            def assert_rejected(mutated_plane: dict) -> None:
                plane_path.write_text(
                    json.dumps(mutated_plane, indent=2, sort_keys=True) + "\n"
                )
                apps_payload = server_config.cloudflare_apps_projection(
                    filtered_config,
                    values,
                    "prin7r.com",
                    source_sha,
                    plane,
                    hashlib.sha256(plane_path.read_bytes()).hexdigest(),
                )
                apps_payload["dataContent"]["roles"] = {}
                apps_path.write_text(
                    json.dumps(apps_payload, indent=2, sort_keys=True) + "\n"
                )
                with self.assertRaises(renderer.RenderError):
                    renderer.read_apps_projection(
                        apps_path,
                        env,
                        "prin7r.com",
                        plane_path,
                    )

            internal = json.loads(json.dumps(plane))
            internal["providers"]["notion"]["deployment"] = "profile-component"
            internal["providers"]["notion"]["componentId"] = "paperclip"
            assert_rejected(internal)

            mixed = json.loads(json.dumps(plane))
            mixed["providers"]["internal-docs"] = {
                "kind": "self-hosted-workspace",
                "deployment": "profile-component",
                "componentId": "paperclip",
                "capabilities": {
                    "documents": {
                        "interfaces": ["ui"],
                        "configurationRefs": [],
                    }
                },
                "adapterIds": ["notion"],
            }
            mixed["roles"]["documentsUi"].update(
                {
                    "providerId": "internal-docs",
                    "endpointRef": "INTERNAL_DOCS_URL",
                }
            )
            assert_rejected(mixed)

            malformed = json.loads(json.dumps(plane))
            malformed["providers"]["notion"]["unexpected"] = True
            assert_rejected(malformed)

    def test_internal_roles_keep_exact_role_and_component_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = root / "platform.env"
            env.write_text("PLATFORM_BASE_DOMAIN=prin7r.com\n")
            source_sha = hashlib.sha256(env.read_bytes()).hexdigest()
            plane = {
                "_generated": {"sourceSha256": source_sha},
                "profile": "internal-presentation",
                "roles": {
                    "tablesUi": {
                        "providerId": "tables-provider",
                        "capability": "tables",
                        "interface": "ui",
                        "endpointRef": "TABLES_PUBLIC_URL",
                        "adapterId": "tables-adapter",
                    },
                    "documentsUi": {
                        "providerId": "documents-provider",
                        "capability": "documents",
                        "interface": "ui",
                        "endpointRef": "DOCUMENTS_PUBLIC_URL",
                        "adapterId": "documents-adapter",
                    },
                },
                "providers": {
                    "tables-provider": {
                        "kind": "self-hosted-workspace",
                        "deployment": "profile-component",
                        "componentId": "tables-app",
                        "capabilities": {
                            "tables": {
                                "interfaces": ["ui", "api"],
                                "configurationRefs": ["TABLES_PUBLIC_URL"],
                            }
                        },
                        "adapterIds": ["tables-adapter"],
                    },
                    "documents-provider": {
                        "kind": "self-hosted-workspace",
                        "deployment": "profile-component",
                        "componentId": "documents-app",
                        "capabilities": {
                            "documents": {
                                "interfaces": ["ui", "api"],
                                "configurationRefs": ["DOCUMENTS_PUBLIC_URL"],
                            }
                        },
                        "adapterIds": ["documents-adapter"],
                    },
                },
            }
            plane_path = root / "data-content-plane.json"
            plane_path.write_text(json.dumps(plane, sort_keys=True) + "\n")
            payload = {
                "_generated": {"sourceSha256": source_sha},
                "baseDomain": "prin7r.com",
                "apps": {
                    "tables-app": {
                        "hostname": "tables.prin7r.com",
                        "origin": "http://127.0.0.1:18085",
                        "accessClass": "human",
                    },
                    "documents-app": {
                        "hostname": "documents.prin7r.com",
                        "origin": "http://127.0.0.1:18086",
                        "accessClass": "human",
                    },
                },
                "dataContent": {
                    "profile": "internal-presentation",
                    "projectionSha256": hashlib.sha256(
                        plane_path.read_bytes()
                    ).hexdigest(),
                    "roles": {
                        "tablesUi": {
                            "applicationId": "tables-app",
                            "hostname": "tables.prin7r.com",
                            "accessClass": "human",
                        },
                        "documentsUi": {
                            "applicationId": "documents-app",
                            "hostname": "documents.prin7r.com",
                            "accessClass": "human",
                        },
                    },
                },
            }
            apps_path = root / "apps.json"
            apps_path.write_text(json.dumps(payload, sort_keys=True) + "\n")
            apps = renderer.read_apps_projection(
                apps_path, env, "prin7r.com", plane_path
            )
            self.assertEqual(set(apps), {"tables-app", "documents-app"})

            for mutation in ("missing-role", "component-drift"):
                with self.subTest(mutation=mutation):
                    tampered = json.loads(json.dumps(payload))
                    if mutation == "missing-role":
                        del tampered["dataContent"]["roles"]["documentsUi"]
                    else:
                        tampered["dataContent"]["roles"]["documentsUi"][
                            "applicationId"
                        ] = "tables-app"
                    apps_path.write_text(json.dumps(tampered, sort_keys=True) + "\n")
                    with self.assertRaises(renderer.RenderError):
                        renderer.read_apps_projection(
                            apps_path, env, "prin7r.com", plane_path
                        )

    def test_terraform_durations_have_no_mutable_defaults(self) -> None:
        variables = (ROOT / "deployment/cloudflare/variables.tf").read_text()
        for name in ("human_session_duration", "service_token_duration"):
            block = variables.split(f'variable "{name}"', 1)[1].split("}\n", 1)[0]
            self.assertNotIn("default", block)

    def test_profile_projection_is_fully_driven_by_canonical_values(self) -> None:
        values = {
            key: value
            for key, value in server_config.ONE_TIME_MIGRATION_SEEDS.items()
            if key.startswith("PROFILE_CODING_DAYTONA_")
            or key == "MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL"
        }
        rendered, required = server_config.profile_projection(
            ROOT / "config/profiles/catalog.yaml", values
        )
        catalog = yaml.safe_load(rendered)
        profiles = {row["ref"]: row for row in catalog["profiles"]}
        self.assertEqual(
            profiles["coding-daytona-codex"]["nativeAdapterConfig"]["model"],
            "mte-minimax/MiniMax-M2.7-highspeed",
        )
        self.assertEqual(
            profiles["coding-daytona-codex"]["nativeAdapterConfig"]["extraArgs"],
            [
                "-c",
                'model_provider="mte9router"',
                "-c",
                'model_providers.mte9router.name="MTE 9Router"',
                "-c",
                'model_providers.mte9router.base_url="http://172.20.0.1:22080/v1"',
                "-c",
                'model_providers.mte9router.env_key="OPENAI_API_KEY"',
                "-c",
                'model_providers.mte9router.wire_api="responses"',
            ],
        )
        self.assertEqual(
            profiles["coding-daytona-pi"]["nativeAdapterConfig"]["provider"],
            "mte9router",
        )
        self.assertEqual(
            profiles["coding-daytona-pi"]["nativeAdapterConfig"]["model"],
            "mte9router/mte-minimax/MiniMax-M2.7-highspeed",
        )
        self.assertEqual(
            profiles["coding-daytona-pi"]["nativeAdapterConfig"]["cwd"],
            "/home/daytona/workspaces/coding-daytona-pi",
        )
        self.assertIn("NINEROUTER_PROFILE_CODING_DAYTONA_PI_API_KEY", required)
        self.assertIn("MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL", required)


if __name__ == "__main__":
    unittest.main()

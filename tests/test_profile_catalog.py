from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
TOOL_ROOT = ROOT / "tools/platform-cli"
if str(TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOL_ROOT))

from profile_catalog import CatalogError, load_profile_catalog, semantic_sha256  # noqa: E402


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(
        "test_" + name.replace("-", "_"), TOOL_ROOT / name
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def rendered_document(value):
    if isinstance(value, dict):
        return {key: rendered_document(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [rendered_document(nested) for nested in value]
    if isinstance(value, str):
        return re.sub(r"\$\{[^}]+\}", "rendered-unit-value", value)
    return value


def fourth_profile_document() -> dict:
    document = yaml.safe_load((ROOT / "config/profiles/catalog.yaml").read_text())
    profiles = document["profiles"]
    fourth = copy.deepcopy(profiles[-1])
    fourth.update(
        {
            "ref": "coding-daytona-fourth",
            "title": "Coding - Daytona / Fourth",
            "nativeAdapter": "fourth_local",
        }
    )
    fourth["runtimeContract"].update(
        {
            "harnessKind": "fourth",
            "adapterType": "fourth_local",
            "protocol": "openai-chat-completions",
            "packageKey": "fourth",
            "runtimeSecretEnv": "OPENAI_API_KEY",
            "probe": {
                "helloCode": "fourth_hello_probe_passed",
                "acceptedWarnings": [],
            },
        }
    )
    fourth["runtimeContract"]["envAllowlist"] = [
        value.replace(
            "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL", "MTE_AGENT_GATEWAY_TOOLHIVE_FOURTH_URL"
        )
        for value in fourth["runtimeContract"]["envAllowlist"]
    ]
    fourth["runtimePackages"] = {
        "fourth": "4.0.0",
        "toolhive": "0.36.0",
    }
    fourth["nativeAdapterConfig"]["cwd"] = (
        "/home/daytona/workspaces/coding-daytona-fourth"
    )
    access = fourth["toolAccess"]
    access.update(
        {
            "bundleId": "mte-profile-coding-daytona-fourth",
            "workloadId": "mte-profile-fourth",
            "endpointRef": "MTE_AGENT_GATEWAY_TOOLHIVE_FOURTH_URL",
            "credentialRef": "TOOLHIVE_PROFILE_CODING_DAYTONA_FOURTH_BEARER_TOKEN",
            "paperclipProfileRef": "coding-daytona-fourth",
            "wrongProfileEndpointRef": "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
            "aggregateWorkloadIds": [
                "mte-profile-fourth",
                "mte-profile-fourth-notion",
            ],
            "notionWorkloadId": "mte-profile-fourth-notion",
        }
    )
    routing = fourth["toolRouting"]
    routing.update(
        {
            "mcpUrlRef": access["endpointRef"],
            "bearerTokenRef": access["credentialRef"],
            "servers": [
                {
                    "id": "coding-daytona-fourth-tools",
                    "endpointRef": access["endpointRef"],
                    "credentialRef": access["credentialRef"],
                    "transport": "streamable-http",
                    "aggregation": "toolhive-vmcp",
                    "workloadRefs": access["aggregateWorkloadIds"],
                    "capabilities": access["capabilities"],
                }
            ],
        }
    )
    fourth["topology"] = {
        "wrongProfileRef": "coding-daytona-codex",
        "toolhiveUpstreamRef": "MTE_AGENT_GATEWAY_TOOLHIVE_FOURTH_UPSTREAM",
        "toolhiveGatewayPortRef": "MTE_AGENT_GATEWAY_TOOLHIVE_FOURTH_PORT",
        "toolhiveProxyPortRef": "TOOLHIVE_PROFILE_CODING_DAYTONA_FOURTH_PROXY_PORT",
        "toolhiveIdentityPortRef": "TOOLHIVE_PROFILE_CODING_DAYTONA_FOURTH_EVERYTHING_PROXY_PORT",
        "toolhiveNotionPortRef": "TOOLHIVE_PROFILE_CODING_DAYTONA_FOURTH_NOTION_PROXY_PORT",
    }
    profiles[-1]["topology"]["wrongProfileRef"] = "coding-daytona-fourth"
    profiles[-1]["toolAccess"]["wrongProfileEndpointRef"] = access["endpointRef"]
    profiles.append(fourth)
    return document


class ProfileCatalogTests(unittest.TestCase):
    def test_public_catalog_is_readable_yaml_with_stable_semantic_identity(self):
        source = ROOT / "config/profiles/catalog.yaml"
        raw = source.read_text()
        document = yaml.safe_load(raw)

        self.assertFalse(raw.lstrip().startswith("{"))
        self.assertTrue(raw.startswith("apiVersion: micro-task-engine/v1alpha1\n"))
        self.assertIn("\nprofiles:\n  - ref: coding-daytona-codex\n", raw)
        self.assertEqual(
            load_profile_catalog(source).semantic_sha256,
            "35abd9ae3c52f706bcb28987fc9c94ec2a38ba28a54b7724669b5ac0107fd338",
        )
        self.assertEqual(document["profiles"][0]["toolAccess"]["notionToolCount"], 13)
        self.assertIs(
            document["toolPolicies"]["postgres-ssot-notion-readonly-v1"]
            ["notionAgentAccess"]["rawCredentialInHarness"],
            False,
        )

    def test_yaml_roundtrip_preserves_placeholders_lists_nulls_and_booleans(self):
        source = ROOT / "config/profiles/catalog.yaml"
        document = yaml.safe_load(source.read_text())
        document["_generated"] = {
            "doNotEdit": True,
            "optionalSource": None,
            "placeholder": "${ROUNDTRIP_VALUE:?required}",
            "items": [False, None, "${ROUNDTRIP_LIST_VALUE:?required}"],
        }
        encoded = yaml.safe_dump(document, sort_keys=False)
        decoded = yaml.safe_load(encoded)

        self.assertEqual(decoded, document)
        self.assertEqual(
            decoded["_generated"]["placeholder"],
            "${ROUNDTRIP_VALUE:?required}",
        )
        self.assertEqual(
            decoded["_generated"]["items"],
            [False, None, "${ROUNDTRIP_LIST_VALUE:?required}"],
        )
        self.assertEqual(
            semantic_sha256(decoded),
            load_profile_catalog(source).semantic_sha256,
        )

    def test_existing_three_profiles_keep_the_normalized_bundle_shape(self):
        renderer = load_script("render-profiles.py")
        catalog = load_profile_catalog(ROOT / "config/profiles/catalog.yaml")
        with tempfile.TemporaryDirectory() as directory:
            paths = renderer.render_profile_bundles(
                ROOT / "config/profiles/catalog.yaml", Path(directory)
            )
            rendered = [json.loads(Path(path).read_text()) for path in paths]
        self.assertEqual([row["id"] for row in rendered], list(catalog.refs))
        for profile, bundle in zip(catalog.profiles, rendered, strict=True):
            self.assertEqual(
                bundle["runtime"],
                {
                    "adapter": profile["nativeAdapter"],
                    "config": profile["nativeAdapterConfig"],
                },
            )
            self.assertEqual(
                bundle["specialization"],
                {
                    "instructions": profile["instructions"],
                    "skills": profile.get("skills", []),
                    "plugins": profile.get("plugins", []),
                    "mcpPolicy": profile.get("mcpPolicy", {}),
                },
            )

    def test_server_config_projection_renders_the_shared_runtime_contract(self):
        server_config = load_script("server-config.py")
        source = ROOT / "config/profiles/catalog.yaml"
        _catalog, required, seeds = server_config.profile_declarations(source)
        values = dict(seeds)
        for key in required:
            if key in values:
                continue
            values[key] = (
                "1"
                if key.endswith(
                    ("_TIMEOUT_SEC", "_TIMEOUT_SECONDS", "_MAX_CONCURRENT_RUNS")
                )
                else "rendered-unit-value"
            )
        rendered, _ = server_config.profile_projection(source, values)
        self.assertFalse(rendered.lstrip().startswith("{"))
        self.assertIn("\nprofiles:\n- ref: coding-daytona-codex\n", rendered)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.yaml"
            path.write_text(rendered)
            loaded = load_profile_catalog(path, require_rendered=True)
        self.assertEqual(loaded.refs, load_profile_catalog(source).refs)
        self.assertTrue(
            all(
                profile["runtimeContract"]["adapterType"] == profile["nativeAdapter"]
                for profile in loaded.profiles
            )
        )

    def test_duplicate_malformed_and_unknown_profiles_fail_closed(self):
        document = yaml.safe_load((ROOT / "config/profiles/catalog.yaml").read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.yaml"
            duplicate = copy.deepcopy(document)
            duplicate["profiles"].append(copy.deepcopy(duplicate["profiles"][0]))
            path.write_text(yaml.safe_dump(duplicate, sort_keys=False))
            with self.assertRaisesRegex(CatalogError, "duplicate"):
                load_profile_catalog(path)

            malformed = copy.deepcopy(document)
            del malformed["profiles"][0]["runtimeContract"]["protocol"]
            path.write_text(yaml.safe_dump(malformed, sort_keys=False))
            with self.assertRaisesRegex(CatalogError, "runtime_contract_keys"):
                load_profile_catalog(path)

            path.write_text(yaml.safe_dump(document, sort_keys=False))
            with self.assertRaisesRegex(CatalogError, "profile_unknown"):
                load_profile_catalog(path).require("not-declared")

    def test_fourth_profile_flows_through_all_owned_catalog_consumers(self):
        document = rendered_document(fourth_profile_document())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog_path = root / "profiles.yaml"
            output = root / "rendered"
            catalog_path.write_text(yaml.safe_dump(document, sort_keys=False))
            loaded = load_profile_catalog(catalog_path, require_rendered=True)
            self.assertEqual(loaded.refs[-1], "coding-daytona-fourth")

            subprocess.run(
                [
                    sys.executable,
                    str(TOOL_ROOT / "render-profiles.py"),
                    "--catalog",
                    str(catalog_path),
                    "--output",
                    str(output),
                ],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(
                sorted(path.parent.name for path in output.glob("*/profile.json")),
                sorted(loaded.refs),
            )

            bootstrap = load_script("bootstrap-paperclip.py")
            rows, _ = bootstrap.profile_catalog(catalog_path)
            self.assertEqual([row["ref"] for row in rows], list(loaded.refs))

            profile_reconcile = load_script("server-profile-reconcile.py")
            values = {
                "TOOLHIVE_CANARY_IMAGE": "mcp/everything@sha256:" + "1" * 64,
                "TOOLHIVE_NOTION_IMAGE": profile_reconcile.NOTION_IMAGE,
                "NOTION_TOKEN": "unit-notion-token-never-printed",
            }
            for index, profile in enumerate(loaded.profiles, 1):
                topology = profile["topology"]
                values[topology["toolhiveProxyPortRef"]] = str(20000 + index * 10)
                values[topology["toolhiveIdentityPortRef"]] = str(
                    20000 + index * 10 + 1
                )
                values[topology["toolhiveNotionPortRef"]] = str(20000 + index * 10 + 2)
            specs = profile_reconcile.desired(
                list(loaded.profiles),
                values,
                profile_reconcile.expected_tool_policy(),
            )
            self.assertEqual([row["profileRef"] for row in specs], list(loaded.refs))

            kestra = load_script("server-kestra-reconcile.py")
            with mock.patch.object(
                kestra,
                "profile_source_paths",
                return_value=(catalog_path, catalog_path),
            ):
                binding = kestra.load_profile_contract()
            self.assertEqual(binding["refs"], loaded.refs)
            self.assertEqual(len(binding["value"]["profiles"]), 4)


if __name__ == "__main__":
    unittest.main()

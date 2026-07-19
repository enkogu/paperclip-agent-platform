from __future__ import annotations

import copy
import hashlib
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
    fourth["nativeAdapterConfig"]["cwd"] = "/home/daytona/paperclip-workspace"
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
    fourth["extensions"] = ["context7-fourth", "toolhive-fourth"]
    profiles.append(fourth)
    for source_extension in document["extensions"]:
        if source_extension["ref"] not in {"context7-pi", "toolhive-pi"}:
            continue
        extension = copy.deepcopy(source_extension)
        extension["ref"] = extension["ref"].replace("-pi", "-fourth")
        extension["enabledProfiles"] = ["coding-daytona-fourth"]
        document["extensions"].append(extension)
    document["skillPackages"]["verification-before-completion"]["nativeDestinations"][
        "fourth"
    ] = "/home/daytona/.fourth/skills/verification-before-completion"
    return document


class ProfileCatalogTests(unittest.TestCase):
    def test_extension_catalog_is_profile_scoped_and_data_driven(self):
        catalog = load_profile_catalog(ROOT / "config/profiles/catalog.yaml")

        self.assertEqual(
            tuple(row["ref"] for row in catalog.extensions),
            (
                "context7-codex",
                "context7-claude",
                "context7-pi",
                "toolhive-codex",
                "toolhive-claude",
                "toolhive-pi",
            ),
        )
        self.assertEqual(
            tuple(row["ref"] for row in catalog.extensions_for("coding-daytona-pi")),
            ("context7-pi", "toolhive-pi"),
        )
        self.assertEqual(
            catalog.require("coding-daytona-codex")["extensions"],
            ["context7-codex", "toolhive-codex"],
        )
        pi_toolhive = catalog.require_extension("toolhive-pi")
        self.assertEqual(pi_toolhive["kind"], "extension")
        self.assertEqual(pi_toolhive["package"]["kind"], "local")
        self.assertEqual(
            pi_toolhive["package"]["ref"],
            "deployment/agent-runtime/pi/mte-toolhive.js",
        )
        self.assertEqual(pi_toolhive["credentialRefs"], ["MTE_TOOLHIVE_BEARER_TOKEN"])

    def test_extension_catalog_rejects_unpinned_packages(self):
        document = yaml.safe_load((ROOT / "config/profiles/catalog.yaml").read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.yaml"
            unpinned = copy.deepcopy(document)
            row = next(
                item for item in unpinned["extensions"] if item["ref"] == "context7-pi"
            )
            del row["package"]["integrityRef"]
            path.write_text(yaml.safe_dump(unpinned, sort_keys=False))
            with self.assertRaisesRegex(CatalogError, "extension_package_unpinned"):
                load_profile_catalog(path)

            ranged = copy.deepcopy(document)
            row = next(
                item for item in ranged["extensions"] if item["ref"] == "context7-pi"
            )
            row["package"]["versionRef"] = "^0.1.1"
            path.write_text(yaml.safe_dump(ranged, sort_keys=False))
            with self.assertRaisesRegex(CatalogError, "extension_package_unpinned"):
                load_profile_catalog(path)

            floating_runtime = copy.deepcopy(document)
            floating_runtime["profiles"][0]["runtimePackages"]["codex"] = "latest"
            path.write_text(yaml.safe_dump(floating_runtime, sort_keys=False))
            with self.assertRaisesRegex(CatalogError, "extension_package_unpinned"):
                load_profile_catalog(path)

    def test_extension_catalog_rejects_undeclared_credentials(self):
        document = yaml.safe_load((ROOT / "config/profiles/catalog.yaml").read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.yaml"
            undeclared = copy.deepcopy(document)
            row = next(
                item
                for item in undeclared["extensions"]
                if item["ref"] == "toolhive-pi"
            )
            row["config"]["credentialRef"] = "UNDECLARED_TOKEN"
            path.write_text(yaml.safe_dump(undeclared, sort_keys=False))
            with self.assertRaisesRegex(
                CatalogError, "extension_credential_undeclared"
            ):
                load_profile_catalog(path)

            not_allowed = copy.deepcopy(document)
            row = next(
                item
                for item in not_allowed["extensions"]
                if item["ref"] == "toolhive-pi"
            )
            row["credentialRefs"] = ["UNDECLARED_TOKEN"]
            row["config"]["credentialRef"] = "UNDECLARED_TOKEN"
            path.write_text(yaml.safe_dump(not_allowed, sort_keys=False))
            with self.assertRaisesRegex(
                CatalogError, "extension_credential_not_allowed"
            ):
                load_profile_catalog(path)

            literal = copy.deepcopy(document)
            row = next(
                item for item in literal["extensions"] if item["ref"] == "toolhive-pi"
            )
            row["config"]["bearerToken"] = "raw-value-is-forbidden"
            path.write_text(yaml.safe_dump(literal, sort_keys=False))
            with self.assertRaisesRegex(
                CatalogError, "extension_credential_literal_forbidden"
            ):
                load_profile_catalog(path)

    def test_extension_catalog_rejects_unknown_scope_and_kind(self):
        document = yaml.safe_load((ROOT / "config/profiles/catalog.yaml").read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.yaml"
            unknown_scope = copy.deepcopy(document)
            unknown_scope["profiles"][0]["extensions"] = ["missing-extension"]
            path.write_text(yaml.safe_dump(unknown_scope, sort_keys=False))
            with self.assertRaisesRegex(CatalogError, "profile_extension_unknown"):
                load_profile_catalog(path)

            unknown_registry_scope = copy.deepcopy(document)
            unknown_registry_scope["extensions"][0]["enabledProfiles"] = [
                "missing-profile"
            ]
            path.write_text(yaml.safe_dump(unknown_registry_scope, sort_keys=False))
            with self.assertRaisesRegex(CatalogError, "extension_profile_unknown"):
                load_profile_catalog(path)

            unknown_kind = copy.deepcopy(document)
            unknown_kind["extensions"][0]["kind"] = "runtime-loop"
            path.write_text(yaml.safe_dump(unknown_kind, sort_keys=False))
            with self.assertRaisesRegex(CatalogError, "extension_kind_invalid"):
                load_profile_catalog(path)

    def test_extension_catalog_allows_a_credentialless_plugin(self):
        document = yaml.safe_load((ROOT / "config/profiles/catalog.yaml").read_text())
        plugin = copy.deepcopy(document["extensions"][0])
        plugin.update({"ref": "credentialless-plugin", "kind": "plugin"})
        plugin["config"].pop("credentialRef")
        plugin["config"].pop("credentialRequired")
        plugin["credentialRefs"] = []
        plugin["mcpCapability"] = "credentialless-plugin"
        plugin["deliveryKey"] = "credentiallessPlugin"
        document["profiles"][0]["extensions"].append(plugin["ref"])
        document["profiles"][0]["mcpPolicy"]["allow"].append(plugin["mcpCapability"])
        document["profiles"][0]["toolDelivery"][plugin["deliveryKey"]] = {
            "mode": "credentialless-plugin"
        }
        document["extensions"].append(plugin)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.yaml"
            path.write_text(yaml.safe_dump(document, sort_keys=False))
            loaded = load_profile_catalog(path)
        self.assertEqual(
            loaded.require_extension("credentialless-plugin")["credentialRefs"], []
        )

    def test_profile_owned_extension_selection_fails_closed_on_any_drift(self):
        document = yaml.safe_load((ROOT / "config/profiles/catalog.yaml").read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.yaml"

            scope_drift = copy.deepcopy(document)
            scope_drift["extensions"][2]["enabledProfiles"] = ["coding-daytona-codex"]
            path.write_text(yaml.safe_dump(scope_drift, sort_keys=False))
            with self.assertRaisesRegex(CatalogError, "profile_extension_scope_drift"):
                load_profile_catalog(path)

            capability_drift = copy.deepcopy(document)
            capability_drift["profiles"][0]["mcpPolicy"]["allow"].remove("context7")
            path.write_text(yaml.safe_dump(capability_drift, sort_keys=False))
            with self.assertRaisesRegex(
                CatalogError, "profile_extension_capability_not_allowed"
            ):
                load_profile_catalog(path)

            delivery_drift = copy.deepcopy(document)
            del delivery_drift["profiles"][0]["toolDelivery"]["context7"]
            path.write_text(yaml.safe_dump(delivery_drift, sort_keys=False))
            with self.assertRaisesRegex(
                CatalogError, "profile_extension_delivery_drift"
            ):
                load_profile_catalog(path)

    def test_public_catalog_is_readable_yaml_with_stable_semantic_identity(self):
        source = ROOT / "config/profiles/catalog.yaml"
        raw = source.read_text()
        document = yaml.safe_load(raw)

        self.assertFalse(raw.lstrip().startswith("{"))
        self.assertTrue(raw.startswith("apiVersion: micro-task-engine/v1alpha1\n"))
        self.assertIn("\nprofiles:\n  - ref: coding-daytona-codex\n", raw)
        self.assertEqual(
            load_profile_catalog(source).semantic_sha256,
            "87708ad778e0fc434487979539c39f20b5753dc30979c9c9b7a222189d42fcc8",
        )
        self.assertEqual(document["profiles"][0]["toolAccess"]["notionToolCount"], 13)
        self.assertIs(
            document["toolPolicies"]["postgres-ssot-notion-readonly-v1"][
                "notionAgentAccess"
            ]["rawCredentialInHarness"],
            False,
        )

    def test_tool_delivery_contract_is_native_for_all_coding_harnesses(self):
        document = yaml.safe_load((ROOT / "config/profiles/catalog.yaml").read_text())
        profiles = {row["ref"]: row for row in document["profiles"]}
        codex = profiles["coding-daytona-codex"]
        claude = profiles["coding-daytona-claude"]
        pi = profiles["coding-daytona-pi"]

        for profile in (codex, claude, pi):
            self.assertEqual(
                profile["nativeAdapterConfig"]["cwd"],
                "/home/daytona/paperclip-workspace",
            )

        for profile in (codex, pi):
            self.assertEqual(
                profile["nativeAdapterConfig"]["bootstrapPromptTemplate"],
                "{{context.paperclipTaskMarkdown}}",
            )
        self.assertNotIn("bootstrapPromptTemplate", claude["nativeAdapterConfig"])

        self.assertEqual(
            codex["toolDelivery"]["context7"]["runtimeConfigSource"],
            "nativeAdapterConfig.extraArgs",
        )
        for profile in (codex, claude):
            cheap = profile["paperclipRuntimeConfig"]["modelProfiles"]["cheap"]
            self.assertTrue(cheap["enabled"])
            self.assertEqual(
                cheap["adapterConfig"]["model"],
                profile["nativeAdapterConfig"]["model"],
            )
        self.assertEqual(pi["paperclipRuntimeConfig"]["modelProfiles"], {})
        self.assertNotIn("configPath", codex["toolDelivery"]["context7"])
        self.assertNotIn("configPath", codex["toolDelivery"]["profileTools"])
        self.assertEqual(
            claude["toolDelivery"]["context7"]["configPath"],
            "/etc/claude-code/managed-mcp.json",
        )
        for profile in (codex, claude):
            self.assertEqual(
                profile["toolDelivery"]["profileTools"]["mode"],
                "native_remote_mcp",
            )
            self.assertEqual(
                profile["toolDelivery"]["context7"]["authentication"],
                "optional_bearer_env",
            )
            self.assertIn("context7", profile["mcpPolicy"]["allow"])
        for profile in profiles.values():
            self.assertIn(
                "CONTEXT7_API_KEY", profile["runtimeContract"]["envAllowlist"]
            )
            self.assertEqual(
                profile["toolDelivery"]["context7"]["authentication"],
                "optional_bearer_env",
            )

        self.assertEqual(
            pi["toolDelivery"]["context7"],
            {
                "mode": "official_pi_extension",
                "package": "${MTE_CONTEXT7_PI_PACKAGE:?required}",
                "version": "${MTE_CONTEXT7_PI_VERSION:?required}",
                "npmIntegrity": "${MTE_CONTEXT7_PI_NPM_INTEGRITY:?required}",
                "configPath": "/home/daytona/.pi/mte-profile/settings.json",
                "authentication": "optional_bearer_env",
                "tools": ["resolve-library-id", "query-docs"],
            },
        )
        self.assertEqual(
            pi["toolDelivery"]["profileTools"],
            {
                "mode": "reviewed_pi_extension",
                "status": "available",
                "failClosed": True,
                "extensionRef": "toolhive-pi",
                "endpointRef": "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL",
                "bearerTokenEnv": "MTE_TOOLHIVE_BEARER_TOKEN",
                "sandboxReachabilityProbeOnly": False,
            },
        )
        self.assertIn("toolhive-pi-extension", pi["mcpPolicy"]["allow"])
        self.assertNotIn("toolhive-mcp", pi["mcpPolicy"]["deny"])

        postgrest = document["toolPolicies"]["postgres-ssot-notion-readonly-v1"][
            "agentCanonicalWrite"
        ]["toolBundleDelivery"]
        self.assertEqual(
            postgrest,
            {
                "status": "blocked",
                "failClosed": True,
                "inProfileToolBundle": False,
                "blocker": "postgrest-mcp-workload-not-reviewed",
            },
        )

    def test_recovery_model_profile_cannot_drift_from_primary_route(self):
        document = yaml.safe_load((ROOT / "config/profiles/catalog.yaml").read_text())
        document["profiles"][0]["paperclipRuntimeConfig"]["modelProfiles"]["cheap"][
            "adapterConfig"
        ]["model"] = "gpt-5.3-codex-spark"

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.yaml"
            path.write_text(yaml.safe_dump(document, sort_keys=False))
            with self.assertRaisesRegex(
                CatalogError, "cheap_model_profile_route_drift"
            ):
                load_profile_catalog(path)

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
            self.assertEqual(
                bundle["extensions"],
                list(catalog.extensions_for(profile["ref"])),
            )

    def test_server_config_projection_renders_the_shared_runtime_contract(self):
        server_config = load_script("server-config.py")
        source = ROOT / "config/profiles/catalog.yaml"
        pi_extension = ROOT / "deployment/agent-runtime/pi/mte-toolhive.js"
        self.assertEqual(
            server_config.ONE_TIME_MIGRATION_SEEDS["MTE_PI_TOOLHIVE_EXTENSION_SHA256"],
            hashlib.sha256(pi_extension.read_bytes()).hexdigest(),
        )
        _catalog, required, seeds = server_config.profile_declarations(source)
        self.assertTrue(
            {
                "MTE_CONTEXT7_MCP_URL",
                "MTE_CONTEXT7_PI_VERSION",
                "MTE_CONTEXT7_PI_NPM_INTEGRITY",
                "MTE_PI_CODING_AGENT_DIR",
                "MTE_PI_TOOLHIVE_EXTENSION_SHA256",
            }.issubset(required)
        )
        self.assertTrue(
            {
                "CONTEXT7_API_KEY",
                "MTE_TOOLHIVE_BEARER_TOKEN",
                "MTE_TOOLHIVE_BINDING_REF",
                "MTE_TOOLHIVE_BUNDLE_ID",
                "MTE_TOOLHIVE_WORKLOAD_ID",
            }.isdisjoint(required)
        )
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
        codex = loaded.require("coding-daytona-codex")
        self.assertIn(
            'mcp_servers.mte-profile-tools.url="rendered-unit-value"',
            codex["nativeAdapterConfig"]["extraArgs"],
        )
        self.assertIn(
            'mcp_servers.context7.url="rendered-unit-value"',
            codex["nativeAdapterConfig"]["extraArgs"],
        )
        self.assertEqual(
            codex["toolDelivery"]["context7"]["endpoint"],
            "rendered-unit-value",
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

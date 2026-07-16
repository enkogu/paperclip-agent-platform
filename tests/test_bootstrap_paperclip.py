from __future__ import annotations

import argparse
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "mte_bootstrap_paperclip", ROOT / "tools/platform-cli/bootstrap-paperclip.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class BootstrapPaperclipTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_agent_identity_is_metadata_profile_ref_not_display_name(self):
        agents = [
            {
                "id": "agent-1",
                "name": "arbitrary-renamed-display-name",
                "metadata": {
                    "profileRef": "coding-daytona-codex",
                    "managedBy": "mte-profile-reconciler",
                },
            }
        ]
        indexed = self.module.index_agents_by_profile(agents)
        self.assertEqual(indexed["coding-daytona-codex"]["id"], "agent-1")

    def test_duplicate_and_extra_managed_agents_fail_closed(self):
        duplicate = [
            {"metadata": {"profileRef": "coding-daytona-codex"}},
            {"metadata": {"profileRef": "coding-daytona-codex"}},
        ]
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            self.module.index_agents_by_profile(duplicate)
        extra = [
            {
                "metadata": {
                    "profileRef": "unexpected-profile",
                    "managedBy": "mte-profile-reconciler",
                }
            }
        ]
        with self.assertRaisesRegex(RuntimeError, "extra"):
            self.module.index_agents_by_profile(extra)

    def test_generated_attestation_does_not_change_catalog_identity(self):
        document = yaml.safe_load(self.module.PROFILE_SOURCE.read_text())
        first = self.module.profile_catalog_semantic_sha256(document)
        document["_generated"] = {
            "sourceSha256": "1" * 64,
            "generatorVersion": "test",
        }
        second = self.module.profile_catalog_semantic_sha256(document)
        document["profiles"][0]["title"] += " changed"
        third = self.module.profile_catalog_semantic_sha256(document)
        self.assertEqual(first, second)
        self.assertNotEqual(second, third)

    def test_native_profile_is_the_only_product_bootstrap_mode(self):
        profiles, catalog_sha = self.module.profile_catalog()
        profile = profiles[0]
        common = {
            "profile": profile,
            "workspace_root": Path("/workspaces"),
            "instructions_root": Path("/profiles"),
            "max_concurrency": None,
            "catalog_sha256": catalog_sha,
        }
        native = self.module.desired_agent(mode="native", **common)
        self.assertEqual(native["metadata"]["profileRef"], profile["ref"])
        self.assertEqual(native["metadata"]["managedBy"], "mte-profile-reconciler")
        self.assertEqual(native["metadata"]["catalogSha256"], catalog_sha)
        self.assertEqual(
            native["metadata"]["toolBundleRef"],
            profile["toolAccess"]["bundleId"],
        )
        with self.assertRaisesRegex(ValueError, "only native"):
            self.module.desired_agent(mode="smoke", **common)

    def test_unchanged_agent_requires_no_patch_and_output_is_mode_0600(self):
        profiles, catalog_sha = self.module.profile_catalog()
        desired = self.module.desired_agent(
            profiles[0],
            mode="native",
            workspace_root=Path("/workspaces"),
            instructions_root=Path("/profiles"),
            max_concurrency=None,
            catalog_sha256=catalog_sha,
        )
        self.assertFalse(self.module.agent_has_drift(dict(desired), desired))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bootstrap.json"
            self.module.atomic_json(path, {"secretValuesPrinted": False})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_apply_provisioned_env_reapply_is_idempotent(self):
        profiles, catalog_sha = self.module.profile_catalog()
        profile = profiles[0]
        company = {
            "id": "company-1",
            "name": "Micro Task Engine Prototype",
        }
        state: dict[str, list] = {"agents": [], "patches": []}

        def request(_base, _token, method, path, body=None):
            if method == "GET" and path == "/api/companies":
                return [copy.deepcopy(company)]
            if method == "GET" and path.endswith("/agents"):
                return copy.deepcopy(state["agents"])
            if method == "POST" and path.endswith("/agents"):
                created = {**copy.deepcopy(body), "id": "agent-1"}
                state["agents"].append(created)
                return copy.deepcopy(created)
            if method == "PATCH" and path == "/api/agents/agent-1":
                state["patches"].append(copy.deepcopy(body))
                updated = state["agents"][0]
                for key, value in body.items():
                    if key != "replaceAdapterConfig":
                        updated[key] = copy.deepcopy(value)
                return copy.deepcopy(updated)
            raise AssertionError(f"unexpected request: {method} {path}")

        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(
                url="http://paperclip.test",
                token="",
                mode="native",
                workspace_root="/workspaces",
                instructions_root="/profiles",
                max_concurrency=None,
                output=Path(directory) / "bootstrap.json",
            )
            with (
                mock.patch.object(
                    self.module,
                    "profile_catalog",
                    return_value=([profile], catalog_sha),
                ),
                mock.patch.object(self.module, "request", side_effect=request),
            ):
                first = self.module.reconcile(args)
                self.assertEqual(first["actions"], {profile["ref"]: "created"})

                provisioned_env = {
                    "OPENAI_API_KEY": {
                        "type": "secret_ref",
                        "secretId": "router-secret-id",
                        "version": "latest",
                    },
                    "GITHUB_TOKEN": {
                        "type": "user_secret_ref",
                        "key": "GITHUB_TOKEN",
                        "version": "latest",
                        "required": True,
                        "allowMissingOverride": False,
                    },
                }
                state["agents"][0]["adapterConfig"]["env"] = copy.deepcopy(
                    provisioned_env
                )

                second = self.module.reconcile(args)

        self.assertEqual(second["actions"], {profile["ref"]: "unchanged"})
        self.assertEqual(
            state["agents"][0]["adapterConfig"]["env"], provisioned_env
        )
        self.assertEqual(state["patches"], [])


if __name__ == "__main__":
    unittest.main()

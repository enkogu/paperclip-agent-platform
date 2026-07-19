from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


def rendered_catalog(value):
    if isinstance(value, dict):
        return {key: rendered_catalog(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [rendered_catalog(nested) for nested in value]
    if isinstance(value, str):
        return re.sub(r"\$\{[^}]+\}", "rendered-unit-value", value)
    return value


def load_module():
    spec = importlib.util.spec_from_file_location(
        "mte_server_profile_reconcile",
        ROOT / "tools/platform-cli/server-profile-reconcile.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_kestra_module():
    spec = importlib.util.spec_from_file_location(
        "mte_server_kestra_reconcile_for_profile_test",
        ROOT / "tools/platform-cli/server-kestra-reconcile.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ProfileReconcileTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        self.policy = self.module.expected_tool_policy()
        source = yaml.safe_load((ROOT / "config/profiles/catalog.yaml").read_text())
        self.rows = source["profiles"]
        self.values = {
            "TOOLHIVE_CANARY_IMAGE": "mcp/everything@sha256:" + "1" * 64,
            "TOOLHIVE_NOTION_IMAGE": self.module.NOTION_IMAGE,
            "NOTION_TOKEN": "unit-notion-token-never-printed",
            "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_PROXY_PORT": "19011",
            "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_EVERYTHING_PROXY_PORT": "19211",
            "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_NOTION_PROXY_PORT": "19212",
            "TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_PROXY_PORT": "19012",
            "TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_EVERYTHING_PROXY_PORT": "19221",
            "TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_NOTION_PROXY_PORT": "19222",
            "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_PROXY_PORT": "19013",
            "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_EVERYTHING_PROXY_PORT": "19231",
            "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_NOTION_PROXY_PORT": "19232",
        }

    def test_exact_catalog_derives_three_bundles_groups_and_workloads(self):
        specs = self.module.desired(self.rows, self.values, self.policy)
        self.assertEqual(len(specs), 3)
        self.assertEqual(len({row["bundleId"] for row in specs}), 3)
        self.assertEqual(len({row["workloadId"] for row in specs}), 3)
        self.assertEqual(len({row["proxyPort"] for row in specs}), 3)
        self.assertTrue(all(row["groupActsAsIdentity"] is False for row in specs))
        self.assertTrue(
            all(row["identityMode"] == "mte_gateway_profile_bearer" for row in specs)
        )
        self.assertTrue(all(len(row["bundleSha256"]) == 64 for row in specs))

    def test_failed_payload_exposes_only_safe_symbolic_reason_code(self):
        symbolic = self.module.failed_payload(
            "ProfileReconcileEvidence",
            RuntimeError("paperclip_profile_catalog_ref_drift"),
        )
        unsafe = self.module.failed_payload(
            "ProfileReconcileEvidence",
            RuntimeError("request failed with token secret-value"),
        )
        self.assertEqual(
            symbolic["errorCode"], "paperclip_profile_catalog_ref_drift"
        )
        self.assertEqual(unsafe["errorCode"], "unclassified_failure")
        self.assertNotIn("secret-value", json.dumps(unsafe))

    def test_bundle_identity_ignores_unrelated_values_but_tracks_notion_rotation(self):
        baseline = self.module.desired(self.rows, self.values, self.policy)
        unrelated = dict(self.values)
        unrelated["NINEROUTER_MINIMAX_CANARY_AT"] = "2099-01-01T00:00:00Z"
        unchanged = self.module.desired(self.rows, unrelated, self.policy)
        self.assertEqual(
            [row["bundleSha256"] for row in baseline],
            [row["bundleSha256"] for row in unchanged],
        )
        rotated = dict(self.values)
        rotated["NOTION_TOKEN"] = "rotated-unit-notion-token"
        changed = self.module.desired(self.rows, rotated, self.policy)
        self.assertNotEqual(
            [row["bundleSha256"] for row in baseline],
            [row["bundleSha256"] for row in changed],
        )

    def test_notion_registry_tool_order_is_not_contract_drift(self):
        entry = {
            "name": self.module.NOTION_REGISTRY_PACKAGE,
            "tier": "Official",
            "status": "Active",
            "transport": "stdio",
            "repository_url": self.module.NOTION_REPOSITORY_URL,
            "image": self.module.NOTION_REGISTRY_IMAGE,
            "tools": list(reversed(self.module.NOTION_TOOLS)),
        }
        result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(entry), stderr=""
        )
        with mock.patch.object(self.module, "thv", return_value=result):
            contract = self.module.notion_registry_contract(
                "toolhive", self.module.NOTION_IMAGE
            )
        self.assertEqual(contract["toolCount"], len(self.module.NOTION_TOOLS))
        self.assertEqual(len(contract["toolsSha256"]), 64)

    def test_notion_registry_still_rejects_a_different_tool_set(self):
        entry = {
            "name": self.module.NOTION_REGISTRY_PACKAGE,
            "tier": "Official",
            "status": "Active",
            "transport": "stdio",
            "repository_url": self.module.NOTION_REPOSITORY_URL,
            "image": self.module.NOTION_REGISTRY_IMAGE,
            "tools": [*self.module.NOTION_TOOLS[:-1], "unexpected-tool"],
        }
        result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(entry), stderr=""
        )
        with (
            mock.patch.object(self.module, "thv", return_value=result),
            self.assertRaisesRegex(
                RuntimeError, "profile_notion_registry_contract_drift"
            ),
        ):
            self.module.notion_registry_contract("toolhive", self.module.NOTION_IMAGE)

    def test_generated_attestation_does_not_change_runtime_catalog_identity(self):
        document = {
            "_generated": {"sourceSha256": "1" * 64},
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "PaperclipProfileCatalog",
            "profiles": self.rows,
        }
        first = self.module.profile_catalog_semantic_sha256(document)
        document["_generated"]["sourceSha256"] = "2" * 64
        second = self.module.profile_catalog_semantic_sha256(document)
        document["profiles"][0]["title"] = "changed"
        third = self.module.profile_catalog_semantic_sha256(document)
        self.assertEqual(first, second)
        self.assertNotEqual(second, third)

    def test_kestra_builder_is_declarative_and_does_not_claim_apply(self):
        specs = self.module.desired(self.rows, self.values, self.policy)
        with mock.patch.object(
            self.module, "PROFILES_SOURCE", ROOT / "config/profiles/catalog.yaml"
        ):
            result = self.module.kestra_catalog_payload(self.rows, specs, "a" * 64)
        self.assertEqual(result["namespace"], "mte.platform")
        self.assertEqual(result["key"], "mte.profile.catalog")
        self.assertEqual(result["method"], "PUT")
        self.assertEqual(result["status"], "payload-ready")
        self.assertFalse(result["applied"])
        self.assertEqual(result["document"]["kind"], "KestraProfileCatalogBinding")
        self.assertEqual(result["document"]["key"], "mte.profile.catalog")
        self.assertEqual(result["document"]["profileRuntimeSha256"], "a" * 64)
        self.assertEqual(len(result["document"]["profiles"]), 3)
        self.assertEqual(len(result["documentSha256"]), 64)

    def test_profile_and_kestra_producers_build_identical_catalog_document(self):
        kestra = load_kestra_module()
        source_catalog = yaml.safe_load(
            (ROOT / "config/profiles/catalog.yaml").read_text()
        )
        catalog = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "PaperclipProfileCatalog",
            "extensions": source_catalog["extensions"],
            "skillPackages": source_catalog["skillPackages"],
            "profiles": self.rows,
        }
        runtime_catalog = rendered_catalog(catalog)
        runtime_rows = runtime_catalog["profiles"]
        with tempfile.TemporaryDirectory(prefix="mte-profile-catalog-") as temporary:
            root = Path(temporary)
            source = root / "source.json"
            runtime = root / "runtime.json"
            source.write_text(json.dumps(catalog))
            runtime.write_text(json.dumps(runtime_catalog))
            runtime_sha = self.module.profile_catalog_semantic_sha256(runtime_catalog)
            specs = self.module.desired(runtime_rows, self.values, self.policy)
            with mock.patch.object(self.module, "PROFILES_SOURCE", source):
                profile_document = self.module.kestra_catalog_payload(
                    runtime_rows, specs, runtime_sha
                )
            with mock.patch.object(
                kestra, "profile_source_paths", return_value=(source, runtime)
            ):
                kestra_document = kestra.load_profile_contract()["value"]
            self.assertEqual(profile_document["document"], kestra_document)
            self.assertEqual(
                profile_document["documentSha256"],
                kestra.canonical_json_sha256(kestra_document),
            )

    def test_two_pass_evidence_is_prepared_not_falsely_connection_ready(self):
        specs = self.module.desired(self.rows, self.values, self.policy)
        profile_state = [
            {
                "profileRef": row["profileRef"],
                "bundleId": row["bundleId"],
                "workloadId": row["workloadId"],
                "proxyPort": row["proxyPort"],
                "bundleSha256": row["bundleSha256"],
                "toolSchemaSha256": "b" * 64,
                "canaryResultSha256": "c" * 64,
            }
            for row in specs
        ]
        first = {
            "pass": 1,
            "mutationCount": 6,
            "duplicateCount": 0,
            "extraCount": 0,
            "inventoryIdentitySha256": "d" * 64,
            "profiles": profile_state,
        }
        second = {
            **first,
            "pass": 2,
            "mutationCount": 0,
        }
        paperclip = [
            {"profileRef": row["ref"], "agentId": f"agent-{index}"}
            for index, row in enumerate(self.rows, 1)
        ]
        with (
            mock.patch.object(self.module, "dotenv", return_value=self.values),
            mock.patch.object(
                self.module,
                "catalog",
                return_value=(self.rows, "a" * 64, self.policy),
            ),
            mock.patch.object(self.module, "desired", return_value=specs),
            mock.patch.object(
                self.module,
                "reconcile_toolhive_two_pass",
                return_value=(first, second),
            ),
            mock.patch.object(
                self.module, "paperclip_inventory", return_value=paperclip
            ),
            mock.patch.object(self.module, "sha256_path", return_value="f" * 64),
            mock.patch.object(self.module, "atomic_json"),
        ):
            evidence = self.module.execute(mutate=True)
        self.assertEqual(evidence["status"], "prepared")
        self.assertTrue(evidence["producerReady"])
        self.assertFalse(evidence["connectionReady"])
        self.assertFalse(evidence["ok"])
        self.assertEqual(evidence["passes"][0]["mutationCount"], 6)
        self.assertEqual(evidence["passes"][1]["mutationCount"], 0)
        self.assertTrue(evidence["secondRunNoOp"])
        self.assertEqual(evidence["duplicateCount"], 0)
        self.assertEqual(evidence["extraCount"], 0)
        self.assertIn(
            "kestra-catalog-apply-and-readback-not-integrated",
            evidence["completionBlockers"],
        )
        self.assertTrue(
            all(
                row["toolhive"]["groupProvidesIdentity"] is False
                for row in evidence["profiles"]
            )
        )
        self.assertTrue(
            all(
                "initialize" not in row["toolhive"]
                and "canaryCall" not in row["toolhive"]
                for row in evidence["profiles"]
            )
        )

    def test_notion_policy_is_complete_readonly_and_keeps_postgrest_write(self):
        policy = self.module.expected_tool_policy()
        source = yaml.safe_load((ROOT / "config/profiles/catalog.yaml").read_text())
        self.assertEqual(self.module.tool_policy(source), policy)
        self.assertTrue(
            all(
                row["toolAccess"]["toolPolicyRef"] == "postgres-ssot-notion-readonly-v1"
                for row in source["profiles"]
            )
        )
        notion = policy["notionAgentAccess"]
        allowed = set(notion["allowedTools"])
        denied = set(notion["deniedTools"])
        self.assertFalse(allowed & denied)
        self.assertEqual(allowed | denied, set(self.module.NOTION_TOOLS))
        self.assertTrue(policy["agentCanonicalWrite"]["allowed"])
        self.assertEqual(policy["agentCanonicalWrite"]["provider"], "postgrest")
        self.assertFalse(policy["notionWriteConnector"]["agentReachable"])
        self.assertEqual(
            policy["notionWriteConnector"]["identity"], "mte.notion.connector"
        )
        for dangerous in (
            "API-post-page",
            "API-patch-page",
            "API-delete-a-block",
            "API-update-a-data-source",
        ):
            self.assertIn(dangerous, denied)
            self.assertNotIn(dangerous, allowed)

    def test_catalog_policy_drift_fails_closed(self):
        document = rendered_catalog(
            yaml.safe_load((ROOT / "config/profiles/catalog.yaml").read_text())
        )
        document["toolPolicies"]["postgres-ssot-notion-readonly-v1"][
            "notionAgentAccess"
        ]["allowedTools"].append("API-post-page")
        with tempfile.TemporaryDirectory(prefix="mte-tool-policy-") as temporary:
            path = Path(temporary) / "profiles.yaml"
            path.write_text(yaml.safe_dump(document, sort_keys=False))
            with mock.patch.object(self.module, "PROFILES", path):
                with self.assertRaisesRegex(RuntimeError, "tool_policy_drift"):
                    self.module.catalog()

    def test_registry_tag_warms_only_the_exact_pinned_digest(self):
        pinned = self.module.NOTION_IMAGE
        missing = mock.Mock(returncode=1, stdout="")
        pulled = mock.Mock(returncode=0, stdout="pulled")
        inspected = mock.Mock(returncode=0, stdout=json.dumps([pinned]))
        calls = []

        def fake_run(argv, **_kwargs):
            calls.append(argv)
            if "inspect" in argv:
                return (
                    missing
                    if len([row for row in calls if "inspect" in row]) == 1
                    else inspected
                )
            return pulled

        with (
            mock.patch.object(
                self.module, "toolhive_runtime", return_value="runtime-id"
            ),
            mock.patch.object(self.module, "run", side_effect=fake_run),
        ):
            mutations, evidence = self.module.ensure_notion_image_cache(
                self.values,
                {"registryImage": self.module.NOTION_REGISTRY_IMAGE},
                mutate=True,
            )
        self.assertEqual(mutations, 1)
        self.assertTrue(evidence["pinnedDigestVerified"])
        self.assertIn(
            [
                "docker",
                "exec",
                "runtime-id",
                "docker",
                "pull",
                self.module.NOTION_REGISTRY_IMAGE,
            ],
            calls,
        )
        self.assertNotIn(
            ["docker", "exec", "runtime-id", "docker", "pull", pinned], calls
        )

    def test_toolhive_sha_labels_fit_the_63_character_limit(self):
        digest = "a" * 64
        self.assertEqual(self.module.toolhive_label_sha(digest), "a" * 63)
        with self.assertRaisesRegex(RuntimeError, "label_sha_invalid"):
            self.module.toolhive_label_sha("not-a-sha")

    def test_notion_workload_passes_exact_readonly_allowlist_to_toolhive(self):
        spec = self.module.desired(self.rows, self.values, self.policy)[0]
        workload = spec["notionWorkload"]
        completed = mock.Mock(returncode=0, stdout="")
        with (
            mock.patch.object(self.module, "write_container_file"),
            mock.patch.object(
                self.module,
                "container_file_state",
                side_effect=[("600", "a" * 64), None],
            ),
            mock.patch.object(
                self.module, "docker_exec", return_value=completed
            ) as docker_exec,
        ):
            projection = self.module.run_workload(
                "manager", spec, workload, self.values["NOTION_TOKEN"]
            )
        command = docker_exec.call_args_list[0].args
        exposed = {
            command[index + 1]
            for index, value in enumerate(command[:-1])
            if value == "--tools"
        }
        self.assertEqual(exposed, set(self.module.NOTION_AGENT_READ_TOOLS))
        self.assertEqual(command.count("--tools"), len(exposed))
        self.assertFalse(any("," in name for name in exposed))
        self.assertFalse(exposed & set(self.module.NOTION_WRITE_TOOLS))
        self.assertNotIn(self.values["NOTION_TOKEN"], command)
        self.assertTrue(projection["used"])

    def test_workload_filter_identity_label_is_exact_and_bounded(self):
        spec = self.module.desired(self.rows, self.values, self.policy)[0]
        workload = spec["notionWorkload"]
        completed = mock.Mock(returncode=0, stdout="")
        with (
            mock.patch.object(self.module, "write_container_file"),
            mock.patch.object(
                self.module,
                "container_file_state",
                side_effect=[("600", "a" * 64), None],
            ),
            mock.patch.object(
                self.module, "docker_exec", return_value=completed
            ) as docker_exec,
        ):
            self.module.run_workload(
                "manager", spec, workload, self.values["NOTION_TOKEN"]
            )
        command = docker_exec.call_args_list[0].args
        labels = {
            command[index + 1]
            for index, value in enumerate(command[:-1])
            if value == "--label"
        }
        expected = "mte.tools-sha256=" + self.module.workload_tools_sha(workload)
        self.assertIn(expected, labels)
        self.assertEqual(len(expected.split("=", 1)[1]), 63)
        current = {
            "name": workload["workloadId"],
            "group": spec["bundleId"],
            "port": workload["proxyPort"],
            "status": "running",
            "labels": {
                "mte.managed-by": "profile-reconciler",
                "mte.profile-ref": spec["profileRef"],
                "mte.bundle-sha256": self.module.toolhive_label_sha(
                    spec["bundleSha256"]
                ),
                "mte.workload-role": workload["role"],
                "mte.image-ref-sha256": self.module.toolhive_label_sha(
                    self.module.sha256_bytes(workload["image"].encode())
                ),
                "mte.tools-sha256": self.module.workload_tools_sha(workload),
            },
        }
        self.assertTrue(self.module.is_current(current, spec, workload))
        del current["labels"]["mte.tools-sha256"]
        self.assertFalse(self.module.is_current(current, spec, workload))

    def test_toolhive_manager_memory_budget_and_oom_gate(self):
        catalog = json.loads((ROOT / "config/compose-seeds.lock.json").read_text())
        self.assertEqual(catalog["seeds"]["TOOLHIVE_MEMORY_LIMIT"], "1024m")
        completed = mock.Mock(returncode=0, stdout="false\n")
        with mock.patch.object(self.module, "run", return_value=completed) as run:
            self.module.assert_manager_not_oom_killed("manager")
        self.assertEqual(
            run.call_args.args[0],
            ["docker", "inspect", "manager", "--format", "{{.State.OOMKilled}}"],
        )
        completed.stdout = "true\n"
        with (
            mock.patch.object(self.module, "run", return_value=completed),
            self.assertRaisesRegex(RuntimeError, "toolhive_manager_oom_killed"),
        ):
            self.module.assert_manager_not_oom_killed("manager")

    def test_vmcp_backends_are_manager_loopback_not_dind(self):
        spec = self.module.desired(self.rows, self.values, self.policy)[0]
        document = self.module.vmcp_document(spec)
        urls = [row["url"] for row in document["backends"]]
        self.assertEqual(
            urls,
            [
                "http://127.0.0.1:19211/mcp",
                "http://127.0.0.1:19212/mcp",
            ],
        )
        self.assertTrue(all("tool-runtime" not in url for url in urls))

    def test_workload_readiness_retries_transient_list_timeout(self):
        spec = self.module.desired(self.rows, self.values, self.policy)[0]
        workload = spec["identityWorkload"]
        schema = json.dumps({"tools": [{"name": "echo"}]})
        marker = "mte-c019-" + spec["bundleSha256"][:16]
        list_calls = 0

        def fake_thv(_target, *args, **_kwargs):
            nonlocal list_calls
            if args[:3] == ("mcp", "list", "tools"):
                list_calls += 1
                if list_calls == 1:
                    raise subprocess.TimeoutExpired(cmd="thv", timeout=30)
                return mock.Mock(returncode=0, stdout=schema)
            return mock.Mock(returncode=0, stdout=marker)

        with (
            mock.patch.object(self.module, "thv", side_effect=fake_thv),
            mock.patch.object(self.module.time, "monotonic", side_effect=[0, 1, 2]),
            mock.patch.object(self.module.time, "sleep"),
        ):
            evidence = self.module.wait_workload_ready("manager", spec, workload)
        self.assertEqual(list_calls, 2)
        self.assertEqual(evidence["toolCount"], 1)

    def test_workload_readiness_retries_transient_mcp_timeout(self):
        spec = self.module.desired(self.rows, self.values, self.policy)[0]
        workload = spec["identityWorkload"]
        schema = json.dumps({"tools": [{"name": "echo"}]})
        marker = "mte-c019-" + spec["bundleSha256"][:16]
        calls = 0

        def fake_thv(_target, *args, **_kwargs):
            nonlocal calls
            if args[:3] == ("mcp", "list", "tools"):
                return mock.Mock(returncode=0, stdout=schema)
            calls += 1
            if calls == 1:
                raise subprocess.TimeoutExpired(cmd="thv", timeout=60)
            return mock.Mock(returncode=0, stdout=marker)

        with (
            mock.patch.object(self.module, "thv", side_effect=fake_thv),
            mock.patch.object(self.module.time, "monotonic", side_effect=[0, 1, 2]),
            mock.patch.object(self.module.time, "sleep"),
        ):
            evidence = self.module.wait_workload_ready("manager", spec, workload)
        self.assertEqual(calls, 2)
        self.assertEqual(evidence["toolCount"], 1)

    def test_aggregate_readiness_retries_transient_mcp_timeout(self):
        spec = self.module.desired(self.rows, self.values, self.policy)[0]
        schema = json.dumps(
            {"tools": [{"name": name} for name in spec["aggregateTools"]]}
        )
        marker = "mte-c019-aggregate-" + spec["bundleSha256"][:12]
        echo_calls = 0

        def fake_thv(_target, *args, **_kwargs):
            nonlocal echo_calls
            if args[:3] == ("mcp", "list", "tools"):
                return mock.Mock(returncode=0, stdout=schema)
            tool = args[2]
            if tool == "echo":
                echo_calls += 1
                if echo_calls == 1:
                    raise subprocess.TimeoutExpired(cmd="thv", timeout=60)
                return mock.Mock(returncode=0, stdout=marker)
            return mock.Mock(returncode=0, stdout="notion-ready")

        with (
            mock.patch.object(self.module, "thv", side_effect=fake_thv),
            mock.patch.object(self.module.time, "monotonic", side_effect=[0, 1, 2]),
            mock.patch.object(self.module.time, "sleep"),
        ):
            evidence = self.module.wait_aggregate_ready("manager", spec)
        self.assertEqual(echo_calls, 2)
        self.assertEqual(evidence["toolCount"], len(spec["aggregateTools"]))

    def test_noop_identity_ignores_ephemeral_results_but_not_schema_drift(self):
        base = {
            "coding-daytona-codex": {
                "workloads": [
                    {
                        "role": "identity-canary",
                        "workloadId": "mte-profile-codex",
                        "proxyPort": 19211,
                        "toolCount": 1,
                        "toolSchemaSha256": "a" * 64,
                        "readOnlyCanaryTool": "echo",
                        "readOnlyCanaryResultSha256": "b" * 64,
                    }
                ],
                "aggregate": {
                    "mode": "toolhive-vmcp",
                    "port": 19011,
                    "endpointPath": "/mcp",
                    "toolCount": 14,
                    "notionAccessMode": "read_only",
                    "notionDeniedToolCount": 9,
                    "notionWriteConnectorIdentity": "mte.notion.connector",
                    "toolSchemaSha256": "c" * 64,
                    "configSha256": "d" * 64,
                    "canaryResultSha256": "e" * 64,
                    "notionGetSelfResultSha256": "f" * 64,
                },
            }
        }
        changed_results = json.loads(json.dumps(base))
        changed_results["coding-daytona-codex"]["workloads"][0][
            "readOnlyCanaryResultSha256"
        ] = "1" * 64
        changed_results["coding-daytona-codex"]["aggregate"][
            "notionGetSelfResultSha256"
        ] = "2" * 64
        self.assertEqual(
            self.module.stable_readiness_identity(base),
            self.module.stable_readiness_identity(changed_results),
        )
        changed_schema = json.loads(json.dumps(base))
        changed_schema["coding-daytona-codex"]["aggregate"]["toolSchemaSha256"] = (
            "3" * 64
        )
        self.assertNotEqual(
            self.module.stable_readiness_identity(base),
            self.module.stable_readiness_identity(changed_schema),
        )

    def test_duplicate_and_extra_toolhive_resources_fail_closed(self):
        specs = self.module.desired(self.rows, self.values, self.policy)
        first = specs[0]
        current = {
            "name": first["workloadId"],
            "group": first["bundleId"],
            "port": first["proxyPort"],
            "status": "running",
            "labels": {
                "mte.managed-by": "profile-reconciler",
                "mte.profile-ref": first["profileRef"],
                "mte.bundle-sha256": first["bundleSha256"],
            },
        }
        inventory = [current, dict(current)]
        with (
            mock.patch.object(self.module, "manager", return_value="manager"),
            mock.patch.object(
                self.module, "workload_inventory", return_value=inventory
            ),
            mock.patch.object(
                self.module,
                "group_names",
                return_value={row["bundleId"] for row in specs},
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "duplicate"):
                self.module.reconcile_toolhive_pass(specs, mutate=True, pass_number=1)

        extra = {
            "name": "mte-profile-extra",
            "labels": {"mte.managed-by": "profile-reconciler"},
        }
        _identities, findings = self.module.audit_toolhive(
            specs,
            [extra],
            {row["bundleId"] for row in specs} | {"mte-profile-extra"},
        )
        self.assertIn("toolhive_profile_workload_extra", findings)
        self.assertIn("toolhive_profile_group_set_invalid", findings)

    def c010_subject(self):
        runs = []
        for index, row in enumerate(self.rows, 1):
            access = row["toolAccess"]
            runs.append(
                {
                    "profile": row["ref"],
                    "semanticChecks": {
                        "runner-toolhive-profile": {
                            "status": "passed",
                            "profileRef": row["ref"],
                            "runId": f"run-{index}",
                            "bundleId": access["bundleId"],
                            "workloadId": access["workloadId"],
                            "endpointRef": access["endpointRef"],
                            "credentialRef": access["credentialRef"],
                            "runnerOrigin": "daytona",
                            "initialize": True,
                            "toolsList": True,
                            "canaryCall": True,
                            "toolName": "echo",
                            "httpStatus": 200,
                            "unauthorizedStatus": 401,
                            "wrongProfileEndpointRef": access[
                                "wrongProfileEndpointRef"
                            ],
                            "wrongProfileDenied": True,
                            "wrongProfileStatus": 401,
                            "credentialLeak": False,
                            "markerSha256": "a" * 64,
                            "toolsListSha256": "b" * 64,
                            "resultSha256": "c" * 64,
                        }
                    },
                }
            )
        return {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "KestraPaperclipGitHubE2E",
            "status": "passed",
            "runs": runs,
        }

    def test_c010_requires_runner_origin_call_and_cross_profile_denial(self):
        subject = self.c010_subject()
        rows = self.module.profile_access_from_subject(subject, self.rows, {})
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row["runnerOrigin"] == "daytona" for row in rows))
        self.assertTrue(all(row["wrongProfileStatus"] == 401 for row in rows))

        subject["runs"][0]["semanticChecks"]["runner-toolhive-profile"][
            "wrongProfileStatus"
        ] = 200
        with self.assertRaisesRegex(RuntimeError, "semantics_invalid"):
            self.module.profile_access_from_subject(subject, self.rows, {})

        subject = self.c010_subject()
        subject["runs"][0]["semanticChecks"]["runner-toolhive-profile"]["status"] = (
            "failed"
        )
        with self.assertRaisesRegex(RuntimeError, "semantics_invalid"):
            self.module.profile_access_from_subject(subject, self.rows, {})

    def test_c010_evidence_rejects_embedded_secret_values(self):
        subject = self.c010_subject()
        subject["forbidden"] = "profile-secret-value-123456"
        with self.assertRaisesRegex(RuntimeError, "secret_value_in_evidence"):
            self.module.profile_access_from_subject(
                subject,
                self.rows,
                {
                    "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN": (
                        "profile-secret-value-123456"
                    )
                },
            )

    def test_identity_model_never_treats_group_as_identity(self):
        model = self.module.identity_model()
        self.assertFalse(model["groupProvidesIdentity"])
        self.assertFalse(model["toolHiveNativeIncomingOidc"]["configured"])
        self.assertEqual(
            model["boundedAlternative"]["type"],
            "mte-agent-plane-gateway-profile-bearer",
        )

    def completion_fixture(self, root: Path, catalog_sha: str = "d" * 64):
        canonical = root / "platform.env"
        canonical.write_text("SAFE_SETTING=unit\n")
        canonical.chmod(0o600)
        subject = root / "kestra-paperclip-github-e2e.json"
        subject.write_text(json.dumps(self.c010_subject()))
        subject.chmod(0o600)
        access_path = root / "profile-access.json"
        access = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "ToolHiveProfileAccessVerification",
            "status": "passed",
            "ok": True,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "canonicalSourceSha256": hashlib.sha256(canonical.read_bytes()).hexdigest(),
            "producerPath": str(Path(self.module.__file__)),
            "producerSha256": hashlib.sha256(
                Path(self.module.__file__).read_bytes()
            ).hexdigest(),
            "profileCatalogSha256": catalog_sha,
            "subjectEvidencePath": str(subject),
            "subjectEvidenceSha256": hashlib.sha256(subject.read_bytes()).hexdigest(),
            "profiles": self.module.profile_access_from_subject(
                self.c010_subject(), self.rows, {}
            ),
        }
        access_path.write_text(json.dumps(access))
        access_path.chmod(0o600)
        kestra_path = root / "kestra-reconcile-verify.json"
        kestra = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "KestraReconcileEvidence",
            "status": "passed",
            "action": "verify",
            "finishedAt": datetime.now(timezone.utc).isoformat(),
            "canonicalSourceSha256": access["canonicalSourceSha256"],
            "controlNamespace": "mte.platform",
            "profileCatalogKey": "mte.profile.catalog",
            "profileRuntimeSha256": catalog_sha,
            "profileRefs": [row["ref"] for row in self.rows],
            "stableRemoteState": True,
            "secondPass": {
                "mutationCount": 0,
                "noOp": True,
                "kv": [
                    {
                        "namespace": "mte.platform",
                        "key": "mte.profile.catalog",
                        "type": "JSON",
                        "valueSha256": "e" * 64,
                    }
                ],
            },
        }
        kestra_path.write_text(json.dumps(kestra))
        kestra_path.chmod(0o600)
        return canonical, access_path, kestra_path

    def test_completion_requires_bound_kestra_and_runner_access_evidence(self):
        with tempfile.TemporaryDirectory(prefix="mte-profile-completion-") as temporary:
            canonical, access, kestra = self.completion_fixture(Path(temporary))
            with (
                mock.patch.object(self.module, "CANONICAL", canonical),
                mock.patch.object(self.module, "ACCESS_EVIDENCE", access),
                mock.patch.object(self.module, "KESTRA_VERIFY_EVIDENCE", kestra),
            ):
                result = self.module.completion_subjects("d" * 64, "e" * 64)
                self.assertEqual(result["kestraProfileCatalogSha256"], "e" * 64)
                payload = json.loads(kestra.read_text())
                payload["secondPass"]["mutationCount"] = 1
                kestra.write_text(json.dumps(payload))
                kestra.chmod(0o600)
                with self.assertRaisesRegex(RuntimeError, "kestra_evidence"):
                    self.module.completion_subjects("d" * 64, "e" * 64)


if __name__ == "__main__":
    unittest.main()

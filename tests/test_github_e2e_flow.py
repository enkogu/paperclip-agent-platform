from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
FLOW = ROOT / "workflows/kestra/paperclip-github-e2e.yaml"


class GithubE2EFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = FLOW.read_text()
        cls.flow = yaml.safe_load(cls.raw)
        cls.tasks = {task["id"]: task for task in cls.flow["tasks"]}

    def test_flow_is_native_and_uses_only_core_tasks(self):
        self.assertEqual(self.flow["id"], "paperclip-github-e2e")
        for task in self.flow["tasks"] + self.flow["errors"]:
            self.assertTrue(task["type"].startswith("io.kestra.plugin.core."), task)
        for forbidden in (
            "adapter_base_url",
            "/v1/runs",
            "normalizedRunId",
        ):
            self.assertNotIn(forbidden, self.raw)

    def test_native_deployment_values_are_required_inputs(self):
        inputs = {item["id"]: item for item in self.flow["inputs"]}
        required = {
            "paperclip_base_url",
            "paperclip_company_id",
            "paperclip_project_id",
            "profile",
            "github_owner",
            "github_repository",
            "base_branch",
        }
        self.assertEqual(set(inputs), required)
        self.assertTrue(all(item["required"] for item in inputs.values()))

    def test_submission_reconciles_a_durable_execution_marker(self):
        submit = self.tasks["submit"]
        self.assertIn("outputs.issues_before.body", submit["runIf"])
        self.assertIn("[kestra:", submit["runIf"])
        self.assertNotIn("retry", submit)
        self.assertIn("/api/companies/", submit["uri"])
        self.assertIn("executionWorkspacePreference", submit["body"])
        self.assertIn('"cloud_sandbox"', submit["body"])
        reconcile = "\n".join(self.tasks["assert_issue_reconciled"]["conditions"])
        self.assertIn("length == 1", reconcile)

    def test_duplicate_or_missing_marker_fails_closed(self):
        reconcile = "\n".join(self.tasks["assert_issue_reconciled"]["conditions"])
        self.assertNotIn("length > 0", reconcile)
        self.assertIn("length == 1", reconcile)
        self.assertIn("assigneeAgentId != null", reconcile)

    def test_native_issue_heartbeat_wake_and_lease_are_polled_directly(self):
        for marker in (
            "/api/issues/",
            "/runs",
            "/api/heartbeat-runs/",
            "/events",
            "/diagnostics/wakes",
            "/api/environment-leases/",
            "/documents/harness-evidence",
        ):
            self.assertIn(marker, self.raw)
        identity = "\n".join(self.tasks["assert_native_identity"]["conditions"])
        self.assertIn("wakeupRequestId", identity)
        self.assertIn("length == 1", identity)
        self.assertIn('provider == "daytona"', identity)

    def test_harness_evidence_uses_direct_cli_contract(self):
        conditions = "\n".join(self.tasks["assert_harness_evidence"]["conditions"])
        for marker in (
            'schemaVersion == "paperclip-agent-platform/harness-evidence/v3"',
            '.daytona.provider == "daytona"',
            ".harness.name ==",
            '"nativeInvocation"',
            '"runnerAttestation"',
        ):
            self.assertIn(marker, conditions)
        prompt = self.tasks["submit"]["body"]
        self.assertIn("official", prompt.lower())
        self.assertIn("verifies Paperclip lifecycle", prompt)
        self.assertNotIn("selfAttestationSha256", self.raw)

    def test_github_proof_is_exact_and_bounded(self):
        self.assertTrue(self.tasks["wait_for_agent"]["failOnMaxReached"])
        self.assertTrue(self.tasks["wait_for_draft_pr"]["failOnMaxReached"])
        self.assertTrue(self.tasks["wait_for_github_checks"]["failOnMaxReached"])
        revision = "\n".join(
            self.tasks["assert_exact_revision_and_diff"]["conditions"]
        )
        self.assertIn(".parents | length == 1", revision)
        self.assertIn("length == 3", revision)
        checks = "\n".join(self.tasks["assert_checks_passed"]["conditions"])
        self.assertIn('.name == "paperclip-e2e"', checks)
        self.assertIn('.conclusion == "success"', checks)

    def test_evidence_contains_exact_native_and_external_identities(self):
        values = self.tasks["evidence_values"]["values"]
        required = {
            "kestraExecutionId",
            "durableIssueMarker",
            "paperclipIssueId",
            "paperclipHeartbeatRunId",
            "paperclipClaimLeaseId",
            "paperclipEnvironmentLeaseId",
            "paperclipProviderLeaseId",
            "daytonaSandboxId",
            "paperclipExecutionWorkspaceId",
            "harnessEvidence",
            "commitSha",
            "baseSha",
            "commitParentSha",
            "changedFiles",
            "pullRequestNumber",
            "pullRequestUrl",
            "checkRunIds",
            "checkConclusions",
            "requiredCheck",
        }
        self.assertTrue(required <= set(values))
        self.assertEqual(self.tasks["write_evidence"]["extension"], ".json")

    def test_flow_contains_no_secret_values_or_secret_inputs(self):
        for marker in ("sk-ant-", "sk-proj-", "github_pat_", "ghp_", "api_key"):
            self.assertNotIn(marker, self.raw)


if __name__ == "__main__":
    unittest.main()

from pathlib import Path
import shutil
import subprocess
import tempfile
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
            "controller_correlation_id",
            "github_owner",
            "github_repository",
            "base_branch",
        }
        self.assertEqual(set(inputs), required)
        self.assertTrue(all(item["required"] for item in inputs.values()))
        self.assertIn("inputs.controller_correlation_id", self.tasks["submit"]["body"])

    def test_r1_requires_an_explicit_minimax_backed_9router_harness_per_run(self):
        profile = {item["id"]: item for item in self.flow["inputs"]}["profile"]
        self.assertEqual(profile["type"], "SELECT")
        self.assertTrue(profile["required"])
        self.assertNotIn("defaults", profile)
        self.assertEqual(
            profile["values"],
            [
                "coding-daytona-codex",
                "coding-daytona-claude",
                "coding-daytona-pi",
            ],
        )
        profile_guard = "\n".join(self.tasks["assert_r1_profile"]["conditions"])
        self.assertIn("isIn", profile_guard)
        for profile_ref in profile["values"]:
            self.assertIn(profile_ref, profile_guard)
        self.assertIn("MiniMax", self.flow["description"])
        self.assertIn("9router", self.flow["description"])
        self.assertNotIn("MTE_ENABLE_OPERATOR_PROVIDED_PROPRIETARY_HARNESSES", self.raw)

        prompt = self.tasks["submit"]["body"]
        self.assertIn("Codex, Claude Code, or Pi", prompt)
        self.assertIn("MiniMax route in 9router", prompt)
        self.assertIn("subscription, login, or OAuth", prompt)

        harness = "\n".join(self.tasks["assert_harness_evidence"]["conditions"])
        self.assertIn('.harness.name == ({', harness)
        for profile_ref, harness_name in (
            ("coding-daytona-codex", "codex"),
            ("coding-daytona-claude", "claude"),
            ("coding-daytona-pi", "pi"),
        ):
            self.assertIn(profile_ref, harness)
            self.assertIn(harness_name, harness)

        # One Kestra execution is intentionally one selected harness.  The
        # controller invokes this flow once for each canonical profile and is
        # the only layer that requires aggregate all-three evidence.
        self.assertEqual(self.raw.count("- id: profile\n"), 1)
        self.assertNotIn("requiredProfiles", self.raw)

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
        self.assertIn("(.id // .runId)", self.tasks["native_heartbeat"]["uri"])
        self.assertIn("(.id // .runId)", self.tasks["heartbeat_events"]["uri"])
        self.assertIn("wakeupRequestId", identity)
        self.assertIn("length == 1", identity)
        self.assertIn('provider == "daytona"', identity)
        self.assertIn(
            '.cleanupStatus == "success"', self.tasks["environment_lease"]["uri"]
        )
        group_cleanup = self.tasks["verify_environment_lease_groups"]
        self.assertIn(".providerLeaseId] | unique", group_cleanup["values"])
        group_tasks = {task["id"]: task for task in group_cleanup["tasks"]}
        self.assertIn(
            '.cleanupStatus == "success"',
            group_tasks["provider_environment_lease"]["uri"],
        )
        self.assertIn(
            '.providerLeaseId == "',
            group_tasks["provider_environment_lease"]["uri"],
        )
        self.assertIn("| .id] | first", group_tasks["provider_environment_lease"]["uri"])
        self.assertNotIn("all(.[]", group_tasks["provider_environment_lease"]["uri"])
        self.assertNotIn("unique | length == 1", self.raw)

    def test_harness_evidence_uses_native_issue_document_api_contract(self):
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
        self.assertIn("no __main__ block", prompt)
        self.assertIn("Never create paperclip-e2e/__init__.py", prompt)
        self.assertIn("a fourth file", prompt)
        self.assertIn(
            'returning \\"PAPERCLIP_DAYTONA_E2E\\"', prompt
        )
        self.assertIn(
            'self.assertEqual(marker(), \\"PAPERCLIP_DAYTONA_E2E\\")', prompt
        )
        self.assertIn("on is only pull_request", prompt)
        self.assertIn("only two steps", prompt)
        self.assertIn(
            "cd paperclip-e2e && python -m unittest test_marker.py", prompt
        )
        for marker in (
            "has no paperclipai CLI",
            "/tmp/harness-evidence.json",
            "set +x; set -euo pipefail",
            "umask 077",
            "trap 'rm -f /tmp/harness-evidence.json /tmp/harness-evidence-envelope.json' EXIT",
            "jq -e . /tmp/harness-evidence.json >/dev/null",
            "jq -n --rawfile body",
            "> /tmp/harness-evidence-envelope.json",
            "printf 'Authorization: Bearer %s\\\\n'",
            "--request PUT",
            '--url \\"${PAPERCLIP_API_URL%/}/api/issues/${PAPERCLIP_TASK_ID}/documents/harness-evidence\\"',
            "--header @-",
            '--header \\"Content-Type: application/json\\"',
            "--data-binary @/tmp/harness-evidence-envelope.json >/dev/null",
            "PATCH done runs only after PUT succeeds",
            "bearer stays out of arguments",
            "temporary files are removed on exit",
            "print no PAPERCLIP value",
        ):
            self.assertIn(marker, prompt)
        sandbox_manifest = (
            ROOT / "deployment/image-build/daytona-harness/package.json"
        ).read_text()
        sandbox_dockerfile = (
            ROOT / "deployment/image-build/daytona-harness/Dockerfile"
        ).read_text()
        self.assertNotIn('"paperclipai"', sandbox_manifest)
        self.assertIn("curl -fsSL", sandbox_dockerfile)
        self.assertIn("/usr/local/bin/jq", sandbox_dockerfile)
        self.assertNotIn("selfAttestationSha256", self.raw)

    def test_agent_prompt_is_action_first_and_checkpoint_ordered(self):
        prompt = self.tasks["submit"]["body"]
        markers = [
            "EXECUTE NOW",
            "CHECKPOINT 1 - adopt or resume git",
            "CHECKPOINT 2 - create or correct only",
            "CHECKPOINT 3 - run exactly",
            "CHECKPOINT 4 - run git fetch",
            "CHECKPOINT 5 - execute the ToolHive audit here",
            "CHECKPOINT 6 - after test",
        ]
        offsets = [prompt.index(marker) for marker in markers]
        self.assertEqual(offsets, sorted(offsets))
        self.assertLess(
            prompt.index("use the harness shell or tool interface"),
            prompt.index("plan-only and rejected"),
        )
        self.assertIn("Do not answer with a plan", prompt)
        self.assertIn("Perform every checkpoint in order in this heartbeat", prompt)
        self.assertIn("after a command failure inspect once and repair immediately", prompt)
        self.assertIn("otherwise report the failed checkpoint, not a plan", prompt)

    def test_plan_only_completion_is_rejected_by_contract_and_gates(self):
        prompt = self.tasks["submit"]["body"]
        self.assertIn("real-change canary, not a planning task", prompt)
        self.assertIn("plan-only and rejected", prompt)
        self.assertIn("without observed command output", prompt)
        self.assertIn("Completion is eligible only after", prompt)

        agent_gate = "\n".join(self.tasks["assert_agent_succeeded"]["conditions"])
        self.assertIn("== 'done'", agent_gate)
        self.assertIn('last | .status) == "succeeded"', agent_gate)

        evidence_gate = "\n".join(self.tasks["assert_harness_evidence"]["conditions"])
        for marker in (
            '.commitSha | type == "string"',
            ".pullRequest.number",
            ".pullRequest.url",
            ".changedFiles ==",
            '.githubCheck.name == "paperclip-e2e"',
            '.githubCheck.conclusion == "success"',
        ):
            self.assertIn(marker, evidence_gate)

    def test_observed_action_evidence_has_a_complete_finish_path(self):
        prompt = self.tasks["submit"]["body"]
        for marker in (
            "one commit SHA",
            "one draft PR number and URL",
            "successful paperclip-e2e check",
            "changedFiles is exactly",
            'githubCheck={name:\\"paperclip-e2e\\",conclusion:\\"success\\"}',
            "These are observed action evidence, never planned values",
        ):
            self.assertIn(marker, prompt)

        draft_pr = "\n".join(self.tasks["assert_draft_pr"]["conditions"])
        revision = "\n".join(self.tasks["assert_exact_revision_and_diff"]["conditions"])
        checks = "\n".join(self.tasks["assert_checks_passed"]["conditions"])
        self.assertIn(".pullRequest.number", draft_pr)
        self.assertIn(".pullRequest.url", draft_pr)
        self.assertIn(".commitSha", revision)
        self.assertIn(".changedFiles", revision)
        self.assertIn(".githubCheck", checks)

    def test_coding_profile_requires_observed_actions_not_plans(self):
        instructions = (ROOT / "config/profiles/instructions/coding.md").read_text()
        for marker in (
            "use the supplied harness tools",
            "A plan, explanation, proposed",
            "changed paths, command/test result",
            "concrete failed checkpoint",
        ):
            self.assertIn(marker, instructions)

    def test_agent_prompt_preserves_runner_origin_toolhive_audit(self):
        prompt = self.tasks["submit"]["body"]
        for marker in (
            "endpoint_ref=$MTE_TOOLHIVE_ENDPOINT_REF",
            "mte-c010:",
            "MTE_TOOLHIVE_WRONG_PROFILE_MCP_URL",
            "unauthorizedStatus=401",
            "wrongProfileDenied=true",
            "wrongProfileStatus=401",
            "runnerOrigin=daytona",
            "echoedMarkerSha256",
            "no controller synthesis",
        ):
            self.assertIn(marker, prompt)

        for protocol_marker in (
            "POST JSON-RPC 2.0",
            "protocolVersion 2025-03-26",
            "notifications/initialized",
            "tools/list id 2",
            "tools/call id 3",
            'arguments {\\"message\\":marker}',
            "exact tools/list body bytes",
            "exact tools/call body bytes",
            "credentialRef=$MTE_TOOLHIVE_BINDING_REF",
            "mcp-session-id request header on notifications/initialized, tools/list id 2, and tools/call id 3",
            "statuses exactly 200 for initialize, 202 for notifications/initialized, 200 for tools/list, and 200 for tools/call",
            "httpStatus=the tools/call HTTP status 200",
            "gatewayReachableHost/Port parsed from endpoint",
        ):
            self.assertIn(protocol_marker, prompt)

    def test_kestra_hard_gates_complete_toolhive_evidence(self):
        conditions = "\n".join(self.tasks["assert_harness_evidence"]["conditions"])
        for marker in (
            '"coding-daytona-codex":"mte-profile-coding-daytona-codex"',
            '"coding-daytona-claude":"mte-profile-claude"',
            '"coding-daytona-pi":"MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL"',
            '"coding-daytona-codex":"TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN"',
            "$t.runtimeEndpointEnv == $endpoint",
            '$t.bearerRuntimeEnv == "MTE_TOOLHIVE_BEARER_TOKEN"',
            '$t.runnerOrigin == "daytona"',
            "$t.initialize == true",
            "$t.toolsList == true",
            "$t.canaryCall == true",
            "$t.httpStatus == 200",
            "$t.unauthorizedStatus == 401",
            "$t.wrongProfileDenied == true",
            "$t.wrongProfileStatus == 401",
            '$t.gatewayReachableHost == "172.20.0.1"',
            "$t.markerSha256 == $t.echoedMarkerSha256",
            'test("^[0-9a-f]{64}$")',
        ):
            self.assertIn(marker, conditions)

    def test_agent_prompt_requires_typed_nested_evidence_and_done_patch(self):
        prompt = self.tasks["submit"]["body"]
        for marker in (
            "profileRef=",
            "repository=",
            "branch=agent/paperclip-e2e-",
            "commitSha is the draft PR head SHA",
            "pullRequest={number:integer,url:nonempty string,draft:true}",
            'localTest={command:\\"cd paperclip-e2e && python -m unittest test_marker.py\\",exitCode:0}',
            'daytona={provider:\\"daytona\\",sandboxId:nonempty string}',
            "harness={name:codex/claude/pi matching profile}",
            "startedAt/finishedAt timezone-aware ISO-8601 strings",
            "finishedAt not earlier",
            "/api/issues/${PAPERCLIP_TASK_ID}/runs",
            "equals injected $PAPERCLIP_RUN_ID",
            ".environmentLease.metadata.sandboxId // .environmentLease.providerLeaseId",
        ):
            self.assertIn(marker, prompt)

        put = prompt.index("--request PUT")
        patch = prompt.index("--request PATCH")
        self.assertLess(put, patch)
        self.assertIn(
            '--url \\"${PAPERCLIP_API_URL%/}/api/issues/${PAPERCLIP_TASK_ID}\\"',
            prompt,
        )
        self.assertIn('--data-binary \'{\\"status\\":\\"done\\"}\' >/dev/null', prompt)
        self.assertEqual(
            prompt.count(
                "printf 'Authorization: Bearer %s\\\\n' \\\"$PAPERCLIP_API_KEY\\\" | curl"
            ),
            2,
        )
        self.assertIn("Because set -e is active, PATCH done runs only after PUT succeeds", prompt)

    def test_agent_prompt_pins_exact_fixture_identifiers(self):
        prompt = self.tasks["submit"]["body"]
        for marker in (
            "name is exactly paperclip-e2e",
            "job ID paperclip-e2e",
            "name is exactly paperclip-e2e",
            "def test_marker(self):",
            "class TestMarker(unittest.TestCase)",
        ):
            self.assertIn(marker, prompt)

    def test_agent_bootstraps_git_in_place_and_reuses_it_on_heartbeats(self):
        prompt = self.tasks["submit"]["body"]
        for marker in (
            "Never use gh repo clone",
            "git init",
            "git fetch --no-tags origin",
            "git reset --hard FETCH_HEAD",
            "git checkout -B agent/paperclip-e2e-",
            'test \\"$(git rev-parse HEAD)\\" = \\"$(git rev-parse FETCH_HEAD)\\"',
            "grep -qxF '/.paperclip-runtime/' .git/info/exclude",
            "git status --porcelain --untracked-files=all -- . ':(exclude)paperclip-e2e/marker.py'",
            "permitted only for first bootstrap",
            "git remote get-url origin",
            "git branch --show-current",
            "If .git exists",
            "without init, clone, reset, checkout, cleanup, or discarding changes",
            "amend it if it already exists",
            "stage only those exact three paths",
        ):
            self.assertIn(marker, prompt)
        self.assertNotIn("git clean", prompt)
        self.assertNotIn("rm -rf", prompt)
        self.assertNotIn("Use the installed GitHub CLI for GitHub operations: gh repo clone", prompt)

    def test_first_bootstrap_adopts_a_conflicting_full_tree_and_later_reuses_it(self):
        def git(cwd, *args):
            return subprocess.run(
                ["git", *args],
                cwd=cwd,
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip()

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            origin = root / "origin.git"
            seed = root / "seed"
            workspace = root / "workspace"
            base_branch = "base"
            agent_branch = "agent/paperclip-e2e-fixture"

            git(root, "init", "--bare", str(origin))
            git(root, "init", str(seed))
            git(seed, "config", "user.name", "Fixture")
            git(seed, "config", "user.email", "fixture@example.invalid")
            (seed / "tracked.txt").write_text("base\n")
            (seed / "nested").mkdir()
            (seed / "nested" / "tracked.txt").write_text("nested base\n")
            git(seed, "add", "tracked.txt", "nested/tracked.txt")
            git(seed, "commit", "-m", "base")
            base_sha = git(seed, "rev-parse", "HEAD")
            git(seed, "remote", "add", "origin", str(origin))
            git(seed, "push", "origin", f"HEAD:refs/heads/{base_branch}")

            shutil.copytree(seed, workspace, ignore=shutil.ignore_patterns(".git"))
            (workspace / "tracked.txt").write_text("conflicting Daytona copy\n")
            (workspace / ".paperclip-runtime").mkdir()
            (workspace / ".paperclip-runtime" / "state.json").write_text("runtime\n")
            (workspace / "paperclip-e2e").mkdir()
            allowed_work = workspace / "paperclip-e2e" / "marker.py"
            allowed_work.write_text("def marker():\n    return 'work in progress'\n")

            git(workspace, "init")
            exclude = workspace / ".git" / "info" / "exclude"
            exclude.write_text(exclude.read_text() + "/.paperclip-runtime/\n")
            git(workspace, "remote", "add", "origin", str(origin))
            git(workspace, "fetch", "--no-tags", "origin", base_branch)
            git(workspace, "reset", "--hard", "FETCH_HEAD")
            git(workspace, "checkout", "-B", agent_branch, "FETCH_HEAD")

            self.assertEqual(git(workspace, "rev-parse", "HEAD"), base_sha)
            self.assertEqual(git(workspace, "rev-parse", "FETCH_HEAD"), base_sha)
            self.assertEqual(git(workspace, "branch", "--show-current"), agent_branch)
            self.assertEqual(
                git(
                    workspace,
                    "status",
                    "--porcelain",
                    "--untracked-files=all",
                    "--",
                    ".",
                    ":(exclude)paperclip-e2e/marker.py",
                    ":(exclude)paperclip-e2e/test_marker.py",
                    ":(exclude).github/workflows/paperclip-e2e.yml",
                ),
                "",
            )
            self.assertEqual((workspace / "tracked.txt").read_text(), "base\n")
            self.assertEqual(
                allowed_work.read_text(), "def marker():\n    return 'work in progress'\n"
            )

            (workspace / "tracked.txt").write_text("later heartbeat work\n")
            (workspace / "later-untracked.txt").write_text("keep me\n")
            self.assertEqual(git(workspace, "remote", "get-url", "origin"), str(origin))
            self.assertEqual(git(workspace, "branch", "--show-current"), agent_branch)
            self.assertEqual((workspace / "tracked.txt").read_text(), "later heartbeat work\n")
            self.assertEqual((workspace / "later-untracked.txt").read_text(), "keep me\n")

    def test_github_proof_is_exact_and_bounded(self):
        self.assertTrue(self.tasks["wait_for_agent"]["failOnMaxReached"])
        self.assertTrue(self.tasks["wait_for_draft_pr"]["failOnMaxReached"])
        self.assertTrue(self.tasks["wait_for_github_checks"]["failOnMaxReached"])
        self.assertEqual(
            self.tasks["wait_for_draft_pr"]["checkFrequency"]["maxDuration"],
            "PT3M",
        )
        self.assertEqual(
            self.tasks["wait_for_draft_pr"]["checkFrequency"]["maxIterations"],
            18,
        )
        draft_pr = "\n".join(self.tasks["assert_draft_pr"]["conditions"])
        self.assertIn("length == 1", draft_pr)
        revision = "\n".join(
            self.tasks["assert_exact_revision_and_diff"]["conditions"]
        )
        self.assertIn(".parents | length == 1", revision)
        self.assertIn("length == 3", revision)
        checks = "\n".join(self.tasks["assert_checks_passed"]["conditions"])
        self.assertIn('.name == "paperclip-e2e"', checks)
        self.assertIn('.conclusion == "success"', checks)

    def test_agent_waits_for_issue_and_accepts_only_bounded_native_continuations(self):
        wait_condition = self.tasks["wait_for_agent"]["condition"]
        self.assertIn("['blocked', 'cancelled']", wait_condition)
        self.assertIn("== 'done'", wait_condition)
        self.assertIn("last | .status", wait_condition)
        for terminal_run_status in (
            "succeeded",
            "failed",
            "cancelled",
            "timed_out",
        ):
            self.assertIn(terminal_run_status, wait_condition)
        conditions = "\n".join(self.tasks["assert_agent_succeeded"]["conditions"])
        self.assertIn("length >= 1 and length <= 32", conditions)
        self.assertNotIn("length == 1", conditions)
        self.assertIn(".agentId ==", conditions)
        self.assertIn(".adapterType ==", conditions)
        self.assertIn('last | .status) == "succeeded"', conditions)
        self.assertEqual(
            self.tasks["wait_for_agent"]["checkFrequency"],
            {"interval": "PT10S", "maxDuration": "PT35M", "maxIterations": 210},
        )
        self.assertIn("35-minute", self.tasks["assert_agent_succeeded"]["errorMessage"])
        self.assertIn("at-most-32-run", self.tasks["assert_agent_succeeded"]["errorMessage"])

    def test_evidence_contains_exact_native_and_external_identities(self):
        values = self.tasks["evidence_values"]["values"]
        required = {
            "kestraExecutionId",
            "selectedProfile",
            "llmProvider",
            "llmGateway",
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
        self.assertEqual(values["selectedProfile"], "{{ inputs.profile }}")
        self.assertEqual(values["llmProvider"], "minimax")
        self.assertEqual(values["llmGateway"], "9router")
        self.assertEqual(self.tasks["write_evidence"]["extension"], ".json")

    def test_flow_contains_no_secret_values_or_secret_inputs(self):
        for marker in ("sk-ant-", "sk-proj-", "github_pat_", "ghp_", "api_key"):
            self.assertNotIn(marker, self.raw)

    def test_error_path_is_valid_and_preserves_root_cause_evidence(self):
        errors = {task["id"]: task for task in self.flow["errors"]}
        cancellation = errors["cancel_issue_and_native_chain"]
        self.assertEqual(cancellation["method"], "PATCH")
        self.assertIn("/api/issues/", cancellation["uri"])
        self.assertEqual(cancellation["body"], '{"status":"cancelled"}')
        self.assertNotIn("allowFailure", cancellation)
        self.assertNotIn("/api/heartbeat-runs/", cancellation["uri"])
        self.assertIn("| length", cancellation["runIf"])
        self.assertIn("== 1", cancellation["runIf"])

        cancelled_wait = errors["wait_for_cancelled_chain"]
        self.assertTrue(cancelled_wait["failOnMaxReached"])
        self.assertEqual(
            cancelled_wait["checkFrequency"],
            {"interval": "PT5S", "maxDuration": "PT2M", "maxIterations": 24},
        )
        self.assertIn("length <= 32", cancelled_wait["condition"])
        self.assertNotIn("length >= 1", cancelled_wait["condition"])
        self.assertIn("all(.[]", cancelled_wait["condition"])
        self.assertIn("== 1", cancelled_wait["runIf"])

        lease_cleanup = errors["verify_cancelled_environment_leases"]
        self.assertEqual(lease_cleanup["type"], "io.kestra.plugin.core.flow.ForEach")
        self.assertEqual(lease_cleanup["concurrencyLimit"], 1)
        self.assertIn(".providerLeaseId] | unique", lease_cleanup["values"])
        lease_tasks = {task["id"]: task for task in lease_cleanup["tasks"]}
        self.assertIn(
            '.cleanupStatus == "success"',
            lease_tasks["cancelled_environment_lease"]["uri"],
        )
        self.assertIn(
            "| .id] | first", lease_tasks["cancelled_environment_lease"]["uri"]
        )
        self.assertNotIn(
            "all(.[]", lease_tasks["cancelled_environment_lease"]["uri"]
        )
        lease_assert = "\n".join(
            lease_tasks["assert_cancelled_environment_lease_deleted"]["conditions"]
        )
        self.assertIn('.status == "expired"', lease_assert)
        self.assertIn('.cleanupStatus == "success"', lease_assert)
        self.assertIn("taskrun.value", lease_assert)
        self.assertIn(".issueId ==", lease_assert)

        success_cleanup = "\n".join(self.tasks["assert_native_identity"]["conditions"])
        self.assertIn('.status == "expired"', success_cleanup)
        self.assertIn('.cleanupStatus == "success"', success_cleanup)

        failure_values = errors["failure_values"]["values"]
        self.assertEqual(failure_values["selectedProfile"], "{{ inputs.profile }}")
        self.assertEqual(failure_values["llmProvider"], "minimax")
        self.assertEqual(failure_values["llmGateway"], "9router")
        self.assertIn("errorLogs()", failure_values["errorLogs"])
        self.assertIn("tasksWithState('FAILED')", failure_values["failedTaskId"])
        self.assertIn("tasksWithState('FAILED')", failure_values["failedTasks"])
        self.assertIn("if length == 1", failure_values["paperclipIssueId"])
        self.assertEqual(errors["write_failure_evidence"]["extension"], ".json")
        self.assertIn(
            "outputs.failure_values.values",
            errors["write_failure_evidence"]["content"],
        )

    def test_flow_outputs_are_safe_on_success_and_failure(self):
        outputs = {item["id"]: item for item in self.flow["outputs"]}
        for output_id in (
            "result",
            "evidence_uri",
            "pull_request_url",
            "commit_sha",
            "paperclip_issue_id",
        ):
            value = outputs[output_id]["value"]
            self.assertIn("outputs.final_summary is defined ?", value)
            self.assertIn(" : ", value)
        self.assertEqual(outputs["evidence_uri"]["type"], "FILE")
        self.assertIn("outputs.error_summary.values.evidenceUri", outputs["evidence_uri"]["value"])
        self.assertIn("failure_task_id", outputs)
        self.assertIn("failure_logs", outputs)
        self.assertEqual(outputs["selected_profile"]["value"], "{{ inputs.profile }}")
        self.assertEqual(outputs["llm_gateway"]["value"], "9router")


if __name__ == "__main__":
    unittest.main()

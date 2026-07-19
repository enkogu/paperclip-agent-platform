import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "mte_server_integration_canaries",
        ROOT / "tools/platform-cli/server-integration-canaries.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_worker_fixture():
    spec = importlib.util.spec_from_file_location(
        "mte_integration_canary_fixture",
        ROOT / "tests/fixtures/agents/integration_canary.py",
    )
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(
        os.environ,
        {
            "PAPERCLIP_API_URL": "http://paperclip.test",
            "PAPERCLIP_COMPANY_ID": "company-1",
            "PAPERCLIP_AGENT_ID": "agent-1",
        },
        clear=True,
    ):
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return module


def evidence_payload(module, *, producer="producer", canonical="canonical"):
    return {
        "apiVersion": module.API_VERSION,
        "kind": "IntegrationCanaryEvidence",
        "producerSha256": producer,
        "canonicalSourceSha256": canonical,
        "selected": ["C023"],
        "canaries": [{"id": "C023", "ok": True, "state": "passed"}],
        "ok": True,
        "status": "passed",
    }


class ExecutionBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_subprocess_timeout_is_a_sanitized_canary_error(self):
        with mock.patch.object(
            self.module.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["docker", "secret-value"], 1),
        ):
            with self.assertRaises(self.module.CanaryError) as raised:
                self.module.run(["docker", "secret-value"], timeout=1)
        self.assertEqual(raised.exception.code, "command_timeout")
        self.assertNotIn("secret-value", str(raised.exception))

    def test_invalid_remote_json_is_a_sanitized_canary_error(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b"not-json"
        with mock.patch.object(
            self.module.urllib.request, "urlopen", return_value=response
        ):
            with self.assertRaises(self.module.CanaryError) as raised:
                self.module.request_json("GET", "http://127.0.0.1:1")
        self.assertEqual(raised.exception.code, "remote_json_invalid")

    def test_duplicate_canary_arguments_fail_before_running_live_actions(self):
        output = io.StringIO()
        with (
            mock.patch.object(
                self.module.sys,
                "argv",
                ["server-integration-canaries.py", "run", "C023", "C023"],
            ),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(self.module.main(), 2)
        self.assertEqual(json.loads(output.getvalue())["error"], "duplicate_canary")

    def test_status_rejects_evidence_with_stale_source_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "integration-canaries.json"
            evidence.write_text(
                json.dumps(evidence_payload(self.module, producer="old-producer"))
            )
            evidence.chmod(0o600)
            with (
                mock.patch.object(self.module, "EVIDENCE", evidence),
                mock.patch.object(self.module, "producer_hash", return_value="producer"),
                mock.patch.object(self.module, "canonical_hash", return_value="canonical"),
            ):
                status = self.module.status_payload()
        self.assertEqual(status, {"ok": False, "state": "evidence_binding_invalid"})

    def test_status_rejects_evidence_with_non_private_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "integration-canaries.json"
            evidence.write_text(json.dumps(evidence_payload(self.module)))
            evidence.chmod(0o640)
            with mock.patch.object(self.module, "EVIDENCE", evidence):
                status = self.module.status_payload()
        self.assertEqual(status, {"ok": False, "state": "evidence_mode_invalid"})

    def test_status_never_replays_a_canonical_secret_from_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "integration-canaries.json"
            payload = evidence_payload(self.module)
            payload["canaries"][0]["unsafe"] = "secret-unit-value"
            evidence.write_text(json.dumps(payload))
            evidence.chmod(0o600)
            with (
                mock.patch.object(self.module, "EVIDENCE", evidence),
                mock.patch.object(self.module, "producer_hash", return_value="producer"),
                mock.patch.object(self.module, "canonical_hash", return_value="canonical"),
                mock.patch.object(
                    self.module,
                    "dotenv",
                    return_value={"FIRECRAWL_API_KEY": "secret-unit-value"},
                ),
            ):
                status = self.module.status_payload()
        self.assertEqual(status, {"ok": False, "state": "evidence_secret_leak"})




class CanonicalOperatorOriginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_operator_base_propagates_canonical_host_and_port_mutations(self):
        self.assertEqual(
            self.module.operator_base(
                {
                    "MTE_OPERATOR_LOOPBACK_HOST": "::1",
                    "FIRECRAWL_ORIGIN_PORT": "28090",
                },
                "FIRECRAWL_ORIGIN_PORT",
            ),
            "http://[::1]:28090",
        )

    def test_operator_base_fails_closed_on_missing_or_non_loopback_values(self):
        for values in (
            {"FIRECRAWL_ORIGIN_PORT": "28090"},
            {
                "MTE_OPERATOR_LOOPBACK_HOST": "192.0.2.1",
                "FIRECRAWL_ORIGIN_PORT": "28090",
            },
        ):
            with (
                self.subTest(values=values),
                self.assertRaisesRegex(
                    self.module.CanaryError, "operator_loopback_host_invalid"
                ),
            ):
                self.module.operator_base(values, "FIRECRAWL_ORIGIN_PORT")
        for port in ("", "not-a-port", "80", "65536"):
            with (
                self.subTest(port=port),
                self.assertRaisesRegex(
                    self.module.CanaryError, "operator_origin_port_invalid"
                ),
            ):
                self.module.operator_base(
                    {
                        "MTE_OPERATOR_LOOPBACK_HOST": "127.0.0.1",
                        "FIRECRAWL_ORIGIN_PORT": port,
                    },
                    "FIRECRAWL_ORIGIN_PORT",
                )


    def test_transient_toolhive_proxy_range_mutations_propagate(self):
        run_id = "mutated-canonical-range"
        first = self.module.canary_proxy_port(
            {
                "TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_BASE": "25100",
                "TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_RANGE": "17",
            },
            base_key="TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_BASE",
            range_key="TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_RANGE",
            run_id=run_id,
        )
        second = self.module.canary_proxy_port(
            {
                "TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_BASE": "26100",
                "TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_RANGE": "17",
            },
            base_key="TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_BASE",
            range_key="TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_RANGE",
            run_id=run_id,
        )
        self.assertEqual(second, first + 1000)
        self.assertIn(first, range(25100, 25117))

    def test_transient_toolhive_proxy_range_fails_closed(self):
        for base, size in (("", "10"), ("19100", ""), ("80", "10"), ("65530", "7")):
            with (
                self.subTest(base=base, size=size),
                self.assertRaisesRegex(
                    self.module.CanaryError, "toolhive_canary_proxy_range_invalid"
                ),
            ):
                self.module.canary_proxy_port(
                    {
                        "BASE": base,
                        "RANGE": size,
                    },
                    base_key="BASE",
                    range_key="RANGE",
                    run_id="run",
                )

    def test_only_immutable_container_protocol_ports_remain_literal(self):
        source = (
            ROOT / "tools/platform-cli/server-integration-canaries.py"
        ).read_text()
        for forbidden in (
            "http://127.0.0.1:18090",
            "http://127.0.0.1:3100",
            "http://127.0.0.1:18065",
            "proxy_port = 19100",
            "proxy_port = 19500",
        ):
            self.assertNotIn(forbidden, source)
        for internal in (
            "http://firecrawl-api:3002",
        ):
            self.assertIn(internal, source)


class ToolHiveLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()



    def test_manager_secret_file_accepts_multiline_env_projection(self):
        with mock.patch.object(self.module, "run") as run:
            self.module.write_manager_secret(
                "toolhive",
                "/tmp/firecrawl.env",
                "FIRECRAWL_API_KEY=unit\nFIRECRAWL_API_URL=http://firecrawl-api:3002\n",
            )
        self.assertIn("chmod 600", run.call_args.args[0][6])

    def test_manager_secret_file_rejects_a_shell_like_path(self):
        with self.assertRaisesRegex(
            self.module.CanaryError, "unsafe_ephemeral_secret"
        ):
            self.module.write_manager_secret(
                "toolhive",
                "/tmp/firecrawl.env;rm -rf /",
                "FIRECRAWL_API_KEY=unit\n",
            )

    def test_c023_uses_dind_host_namespace_and_outer_runtime_alias(self):
        calls = []
        run_id = "20260716T084549-9180af705fef"
        marker = f"MTE-C023-{run_id}"

        def toolhive(_manager, *args, **kwargs):
            calls.append((args, kwargs))
            stdout = marker if "call" in args else "{}"
            return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

        with (
            mock.patch.object(self.module, "toolhive_manager", return_value="manager"),
            mock.patch.object(self.module, "write_manager_secret") as write_secret,
            mock.patch.object(self.module, "toolhive", side_effect=toolhive),
            mock.patch.object(
                self.module,
                "wait_toolhive_tool",
                return_value='{"tools":[{"name":"firecrawl_scrape"}]}',
            ),
            mock.patch.object(self.module, "remove_manager_file"),
            mock.patch.object(self.module, "run"),
        ):
            result = self.module.c023(
                {
                    "FIRECRAWL_API_KEY": "unit-secret-value",
                    "TOOLHIVE_FIRECRAWL_IMAGE": (
                        "docker.io/mcp/firecrawl@sha256:" + "1" * 64
                    ),
                    "TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_BASE": "25200",
                    "TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_RANGE": "19",
                },
                run_id,
            )

        workload_run = next(row for row in calls if "run" in row[0])
        network_index = workload_run[0].index("--network")
        self.assertEqual(workload_run[0][network_index + 1], "host")
        transport_index = workload_run[0].index("--transport")
        self.assertEqual(workload_run[0][transport_index + 1], "stdio")
        proxy_index = workload_run[0].index("--proxy-port")
        self.assertIn(int(workload_run[0][proxy_index + 1]), range(25200, 25219))
        self.assertIn(
            "docker.io/mcp/firecrawl@sha256:" + "1" * 64,
            workload_run[0],
        )
        self.assertNotIn("io.github.stacklok/firecrawl", workload_run[0])
        projected = write_secret.call_args.args[2]
        self.assertIn("FIRECRAWL_API_URL=http://firecrawl-api:3002", projected)
        self.assertNotIn("unit-secret-value", str(calls))
        self.assertNotIn("unit-secret-value", str(result))
        self.assertTrue(result["controlledMarkerObserved"])
        call = next(row for row in calls if "call" in row[0])
        arguments = json.loads(call[1]["input_text"])
        self.assertEqual(
            arguments["url"],
            "https://httpbin.org/anything/" + marker,
        )

    def test_c023_refuses_to_report_success_when_cleanup_is_unproved(self):
        marker = "MTE-C023-run-id"

        def toolhive(_manager, *args, **_kwargs):
            stdout = marker if "call" in args else "{}"
            return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

        with (
            mock.patch.object(self.module, "toolhive_manager", return_value="manager"),
            mock.patch.object(self.module, "write_manager_secret"),
            mock.patch.object(self.module, "toolhive", side_effect=toolhive),
            mock.patch.object(self.module, "wait_toolhive_tool"),
            mock.patch.object(
                self.module, "remove_toolhive_workload", return_value=False
            ),
            mock.patch.object(self.module, "remove_manager_file", return_value=True),
        ):
            with self.assertRaisesRegex(
                self.module.CanaryError, "toolhive_canary_cleanup_incomplete"
            ):
                self.module.c023(
                    {
                        "FIRECRAWL_API_KEY": "unit-only",
                        "TOOLHIVE_FIRECRAWL_IMAGE": "example@sha256:" + "1" * 64,
                        "TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_BASE": "25200",
                        "TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_RANGE": "19",
                    },
                    "run-id",
                )

    def test_c023_records_that_no_marker_server_is_created(self):
        marker = "MTE-C023-run-id"

        def toolhive(_manager, *args, **_kwargs):
            stdout = marker if "call" in args else "{}"
            return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

        with (
            mock.patch.object(self.module, "toolhive_manager", return_value="manager"),
            mock.patch.object(self.module, "write_manager_secret"),
            mock.patch.object(self.module, "toolhive", side_effect=toolhive),
            mock.patch.object(self.module, "wait_toolhive_tool"),
            mock.patch.object(
                self.module, "remove_toolhive_workload", return_value=True
            ),
            mock.patch.object(self.module, "remove_manager_file", return_value=True),
        ):
            result = self.module.c023(
                {
                    "FIRECRAWL_API_KEY": "unit-only",
                    "TOOLHIVE_FIRECRAWL_IMAGE": "example@sha256:" + "1" * 64,
                    "TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_BASE": "25200",
                    "TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_RANGE": "19",
                },
                "run-id",
            )
        self.assertEqual(
            result["cleanup"],
            {
                "workloadRemoved": True,
                "envFileRemoved": True,
                "markerServerRemoved": True,
            },
        )


class SearxngIntegrationCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    @staticmethod
    def response(count: int, *, returncode: int = 0):
        return subprocess.CompletedProcess(
            (),
            returncode,
            stdout=json.dumps(
                {
                    "status": 200,
                    "resultCount": count,
                    "responseKeys": ["query", "results"],
                }
            ),
            stderr="",
        )

    def test_c024_retries_empty_upstream_results_without_weakening_gate(self):
        with (
            mock.patch.object(self.module, "find_container", return_value="firecrawl"),
            mock.patch.object(
                self.module,
                "run",
                side_effect=[self.response(0), self.response(12)],
            ) as run,
            mock.patch.object(self.module.time, "sleep") as sleep,
        ):
            result = self.module.c024({}, "unique-run-id")

        self.assertEqual(run.call_count, 2)
        self.assertEqual(sleep.call_count, 1)
        self.assertEqual(result["attemptCount"], 2)
        self.assertEqual(result["resultCount"], 12)
        for call in run.call_args_list:
            self.assertEqual(json.loads(call.kwargs["input_text"]), {"query": "OpenAI"})
            self.assertFalse(call.kwargs["check"])

    def test_c024_fails_after_three_valid_but_empty_responses(self):
        with (
            mock.patch.object(self.module, "find_container", return_value="firecrawl"),
            mock.patch.object(
                self.module,
                "run",
                side_effect=[self.response(0), self.response(0), self.response(0)],
            ) as run,
            mock.patch.object(self.module.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                self.module.CanaryError, "searxng_json_results_missing"
            ):
                self.module.c024({}, "unique-run-id")

        self.assertEqual(run.call_count, 3)
        self.assertEqual(sleep.call_count, 2)


class ConsentAndSanitizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()



    def test_error_evidence_does_not_include_exception_message(self):
        secret = "do-not-leak-this-value"
        row = self.module.error_result("C028", RuntimeError(secret))
        self.assertNotIn(secret, str(row))
        self.assertEqual(row["errorCode"], "unexpected_error")

    def test_exact_paperclip_container_avoids_prefix_collision(self):
        with mock.patch.object(
            self.module,
            "containers",
            return_value=[
                ("mte-paperclip", "node:22"),
                ("mte-paperclip-backup", "node:22"),
            ],
        ):
            self.assertEqual(
                self.module.find_container_exact("mte-paperclip"), "mte-paperclip"
            )


class RealWorkflowOriginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def paperclip_run(self, action):
        result = {
            "action": action,
            "taskId": "task-1",
            "heartbeatRunId": "heartbeat-1",
            "credentialSource": "paperclip_project_secret_ref",
        }
        return {
            "project": {"id": "project-1"},
            "agent": {"id": "agent-1"},
            "issue": {"id": "task-1"},
            "heartbeatRun": {"id": "heartbeat-1"},
            "secretAccessEvent": {"id": "access-event-1"},
            "cleanup": {"runTerminalOrCancelled": True, "issueDeleted": True},
            "result": result,
        }

    def test_process_worker_gets_canonical_paperclip_api_url(self):
        responses = [
            [],
            {"agent": {"id": "agent-1"}},
        ]
        with mock.patch.object(
            self.module, "paperclip_request", side_effect=responses
        ) as request:
            agent = self.module.ensure_paperclip_canary_agent(
                {
                    "MTE_OPERATOR_LOOPBACK_HOST": "127.0.0.1",
                    "PAPERCLIP_PORT": "23100",
                },
                "company-1",
            )
        self.assertEqual(agent["id"], "agent-1")
        config = request.call_args_list[1].args[3]["adapterConfig"]
        self.assertEqual(
            config["env"]["PAPERCLIP_API_URL"],
            {"type": "plain", "value": "http://127.0.0.1:23100"},
        )

    def test_c027_dispatches_target_profile_to_postgrest(self):
        run_value = self.paperclip_run("postgrest_crud")
        run_value["result"].update(
            {
                "createStatus": 201,
                "readStatus": 200,
                "deleteStatus": 204,
                "postDeleteStatus": 200,
                "postDeleteAbsent": True,
                "markerObserved": True,
                "cleanup": "verified_deleted",
            }
        )
        dependency = {
            "path": "/e/postgrest.json",
            "sha256": "1" * 64,
            "kind": "PostgrestVerification",
            "producerSha256": "2" * 64,
        }
        with (
            mock.patch.object(
                self.module, "paperclip_integration_run", return_value=run_value
            ) as start,
            mock.patch.object(
                self.module,
                "_postgrest_dependency_reference",
                return_value=dependency,
            ),
        ):
            value = self.module.c027(
                {
                    "DATA_CONTENT_PROFILE": "postgres-notion",
                    "POSTGREST_ORIGIN_PORT": "28093",
                    "MTE_OPERATOR_LOOPBACK_HOST": "127.0.0.1",
                },
                "control-1",
            )
        self.assertEqual(start.call_args.args[2], "postgrest_crud")
        self.assertEqual(
            start.call_args.args[3]["postgrestApiBase"], "http://127.0.0.1:28093"
        )
        self.assertEqual(value["tablesApiComponent"], "postgrest")
        self.assertTrue(value["postDeleteAbsent"])
        self.assertEqual(value["dependencyEvidence"], dependency)



    def test_c030_observes_real_paperclip_notification_then_deletes_it(self):
        run_value = self.paperclip_run("mattermost_notification")
        message = (
            "MTE integration canary C030 task_id=task-1 "
            "run_id=heartbeat-1 control_run_id=control-1"
        )
        run_value["result"].update(
            {
                "postId": "post-1",
                "authorUserId": "bot-1",
                "channelId": "channel-1",
                "httpStatus": 201,
                "messageSha256": self.module.hashlib.sha256(
                    message.encode()
                ).hexdigest(),
            }
        )
        responses = [
            (200, {"id": "channel-1"}),
            (200, {"user_id": "bot-1", "message": message}),
            (200, None),
            (404, None),
        ]
        with (
            mock.patch.object(
                self.module,
                "paperclip_integration_run",
                return_value=run_value,
            ),
            mock.patch.object(
                self.module, "request_json", side_effect=responses
            ) as request,
        ):
            value = self.module.c030(
                {
                    "MATTERMOST_BOT_TOKEN": "unit-only-token",
                    "MATTERMOST_BOT_USER_ID": "bot-1",
                    "MATTERMOST_TEAM_ID": "team-1",
                    "MATTERMOST_ORIGIN_PORT": "28065",
                    "MTE_OPERATOR_LOOPBACK_HOST": "127.0.0.1",
                },
                "control-1",
            )

        self.assertEqual(value["source"], "paperclip_process_heartbeat_run")
        self.assertEqual(value["cleanup"], "verified_deleted")
        self.assertTrue(value["contentMatchesTaskAndRun"])
        self.assertEqual(request.call_count, 4)
        self.assertTrue(
            all(
                call.args[1].startswith("http://127.0.0.1:28065/")
                for call in request.call_args_list
            )
        )

    def test_paperclip_cleanup_waits_for_cancelled_run_before_issue_delete(self):
        run_value = {"issue": {"id": "issue-1"}}
        with (
            mock.patch.object(
                self.module,
                "paperclip_request",
                side_effect=[
                    [{"id": "heartbeat-1", "status": "running"}],
                    [{"id": "heartbeat-1", "status": "cancelled"}],
                ],
            ) as paperclip_request,
            mock.patch.object(
                self.module,
                "request_json",
                side_effect=[(202, None), (204, None), (404, None)],
            ) as request,
        ):
            cleanup = self.module.cleanup_paperclip_canary_run(
                {
                    "MTE_OPERATOR_LOOPBACK_HOST": "127.0.0.1",
                    "PAPERCLIP_PORT": "23100",
                },
                "control-1",
                "postgrest_crud",
                run_value,
            )
        self.assertEqual(
            cleanup, {"runTerminalOrCancelled": True, "issueDeleted": True}
        )
        self.assertEqual(paperclip_request.call_count, 2)
        self.assertEqual(request.call_args_list[0].args[0], "POST")
        self.assertEqual(request.call_args_list[1].args[0], "DELETE")

    def test_paperclip_cleanup_checks_every_active_run_before_failing_closed(self):
        with (
            mock.patch.object(
                self.module,
                "paperclip_request",
                return_value=[
                    {"id": "heartbeat-1", "status": "running"},
                    {"id": "heartbeat-2", "status": "running"},
                ],
            ),
            mock.patch.object(
                self.module,
                "paperclip_run_terminal_or_absent",
                side_effect=[False, True],
            ) as terminal,
            mock.patch.object(
                self.module,
                "request_json",
                side_effect=[(202, None), (202, None), (204, None), (404, None)],
            ),
        ):
            with self.assertRaisesRegex(
                self.module.CanaryError, "paperclip_canary_cleanup_incomplete"
            ):
                self.module.cleanup_paperclip_canary_run(
                    {
                        "MTE_OPERATOR_LOOPBACK_HOST": "127.0.0.1",
                        "PAPERCLIP_PORT": "23100",
                    },
                    "control-1",
                    "postgrest_crud",
                    {"issue": {"id": "issue-1"}},
                )
        self.assertEqual(terminal.call_count, 2)


class WorkerContextSafetyTests(unittest.TestCase):
    def test_worker_refuses_ambiguous_fallback_task_selection(self):
        worker = load_worker_fixture()
        with mock.patch.object(
            worker,
            "paperclip",
            return_value=[
                {
                    "id": "task-1",
                    "title": "[MTE integration canary postgrest_crud] one",
                },
                {
                    "id": "task-2",
                    "title": "[MTE integration canary postgrest_crud] two",
                },
            ],
        ):
            with self.assertRaises(worker.WorkerError) as raised:
                worker.resolve_context()
        self.assertEqual(str(raised.exception), "paperclip_canary_task_ambiguous")


class PersistenceCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_c029_is_supported_and_part_of_default_run(self):
        self.assertIn("C029", self.module.SUPPORTED)
        self.assertIs(self.module.CANARIES["C029"], self.module.c029)


@unittest.skip("superseded by the lease-safe projection consumer contract")
class PostgresNotionCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    @staticmethod
    def postgres_state():
        return {
            "record": {
                "objectIdSha256": "1" * 64,
                "initialRevision": 1,
                "finalRevision": 2,
                "initialContentSha256": "2" * 64,
                "finalContentSha256": "3" * 64,
                "created": True,
                "readBackVerified": True,
                "updated": True,
                "projectionIntentVerified": True,
            },
            "document": {
                "objectIdSha256": "4" * 64,
                "initialRevision": 1,
                "finalRevision": 2,
                "initialContentSha256": "5" * 64,
                "finalContentSha256": "6" * 64,
                "created": True,
                "readBackVerified": True,
                "updated": True,
                "projectionIntentVerified": True,
            },
        }

    def notion_result(self):
        postgres = self.postgres_state()
        return {
            "kind": "NotionConnectorCanary",
            "status": "passed",
            "dataContentProfile": "postgres-notion",
            "canonicalSourceSha256": "7" * 64,
            "producerSha256": "8" * 64,
            "linkage": {
                kind: {
                    key: value
                    for key, value in row.items()
                    if key
                    in {
                        "objectIdSha256",
                        "initialRevision",
                        "finalRevision",
                        "initialContentSha256",
                        "finalContentSha256",
                    }
                }
                for kind, row in postgres.items()
            },
            "notion": {
                "table": {
                    "pageId": "raw-notion-table-page-id",
                    "created": True,
                    "queryVerified": True,
                    "updated": True,
                    "archived": True,
                    "cleanupVerified": True,
                    "objectIdMatches": True,
                    "initialRevisionMatches": True,
                    "finalRevisionMatches": True,
                    "initialContentSha256Matches": True,
                    "finalContentSha256Matches": True,
                },
                "document": {
                    "pageId": "raw-notion-document-page-id",
                    "created": True,
                    "appendVerified": True,
                    "readBackVerified": True,
                    "archived": True,
                    "cleanupVerified": True,
                    "objectIdMatches": True,
                    "initialRevisionMatches": True,
                    "finalRevisionMatches": True,
                    "initialContentSha256Matches": True,
                    "finalContentSha256Matches": True,
                },
            },
            "cleanup": {
                "notionTableRowArchived": True,
                "notionDocumentArchived": True,
                "verified": True,
            },
            "redacted": True,
            "_resultSha256": "9" * 64,
            "_producerPath": "/opt/mte-platform/bin/server-notion.py",
            "_evidenceReference": {
                "path": "/opt/mte-platform/evidence/notion-connector-verify.json",
                "sha256": "a" * 64,
                "kind": "NotionConnectorVerification",
                "producerSha256": "8" * 64,
            },
        }

    @staticmethod
    def cleanup_state():
        return {
            "postgresRecordDeleted": True,
            "postgresDocumentDeleted": True,
            "postgresProjectionRowsDeleted": True,
            "verified": True,
        }

    def test_c029_proves_postgres_ssot_and_both_notion_capabilities(self):
        postgres = self.postgres_state()
        notion = self.notion_result()
        with (
            mock.patch.object(
                self.module,
                "_postgrest_dependency_reference",
                return_value={
                    "path": "/e/postgrest.json",
                    "sha256": "b" * 64,
                    "kind": "PostgrestVerification",
                    "producerSha256": "c" * 64,
                },
            ),
            mock.patch.object(
                self.module,
                "_postgres_ssot_prepare",
                return_value=(postgres, {"private": True}),
            ) as prepare,
            mock.patch.object(
                self.module, "_notion_runtime_payload", return_value=notion
            ) as notion_runtime,
            mock.patch.object(
                self.module,
                "_postgres_ssot_cleanup",
                return_value=self.cleanup_state(),
            ) as cleanup,
        ):
            value = self.module.c029(
                {"DATA_CONTENT_PROFILE": "postgres-notion"}, "control-1"
            )

        cleanup.assert_called_once()
        linkage_run_id = prepare.call_args.args[1]
        self.assertNotEqual(linkage_run_id, "control-1")
        self.assertRegex(linkage_run_id, r"^[0-9a-f]{24}$")
        self.assertEqual(notion_runtime.call_args.args[1], linkage_run_id)
        self.assertEqual(value["roles"], {key: "notion" for key in value["roles"]})
        self.assertEqual(value["internalApis"], {"scopedDataApi": "postgrest"})
        self.assertTrue(value["crossProviderLinkageVerified"])
        self.assertTrue(value["cleanup"]["verified"])
        self.assertTrue(value["postgresSsot"]["record"]["postDeleteAbsent"])
        for notion_kind, postgres_kind in (
            ("table", "record"),
            ("document", "document"),
        ):
            self.assertEqual(
                value["notion"][notion_kind]["objectIdSha256"],
                value["postgresSsot"][postgres_kind]["objectIdSha256"],
            )
            self.assertEqual(
                value["notion"][notion_kind]["finalContentSha256"],
                value["postgresSsot"][postgres_kind]["finalContentSha256"],
            )
        self.assertEqual(value["dependencyEvidence"], notion["_evidenceReference"])
        self.assertEqual(value["internalApiEvidence"]["kind"], "PostgrestVerification")
        serialized = json.dumps(value, sort_keys=True)
        self.assertNotIn("raw-notion-table-page-id", serialized)
        self.assertNotIn("raw-notion-document-page-id", serialized)
        self.assertNotIn("control-1", serialized)

    def test_c029_fails_closed_on_cross_provider_hash_mismatch_and_cleans_up(self):
        notion = self.notion_result()
        notion["linkage"]["record"]["finalContentSha256"] = "f" * 64
        with (
            mock.patch.object(
                self.module,
                "_postgrest_dependency_reference",
                return_value={"kind": "PostgrestVerification"},
            ),
            mock.patch.object(
                self.module,
                "_postgres_ssot_prepare",
                return_value=(self.postgres_state(), {"private": True}),
            ),
            mock.patch.object(
                self.module, "_notion_runtime_payload", return_value=notion
            ),
            mock.patch.object(
                self.module,
                "_postgres_ssot_cleanup",
                return_value=self.cleanup_state(),
            ) as cleanup,
        ):
            with self.assertRaisesRegex(
                self.module.CanaryError, "notion_postgres_linkage_mismatch"
            ):
                self.module.c029(
                    {"DATA_CONTENT_PROFILE": "postgres-notion"}, "control-1"
                )
        cleanup.assert_called_once()

    def test_postgres_ssot_uses_exact_object_revision_hash_and_cleans_rows(self):
        states = {"canonical_entities": {}, "canonical_documents": {}}

        def request(method, url, *, body=None, **_kwargs):
            table = url.split("/", 3)[-1].split("?", 1)[0]
            if table in states:
                state = states[table]
                if method == "POST":
                    state.update({"id": "uuid-" + table, **body})
                    return 201, [dict(state)]
                if method == "PATCH":
                    state.update(body)
                    return 200, [dict(state)]
                if method == "DELETE":
                    state.clear()
                    return 204, None
                return 200, [dict(state)] if state else []
            if table == "provider_sync_state":
                external_id = (
                    "mte-notion-canary:run-1:record"
                    if "record" in url
                    else "mte-notion-canary:run-1:document"
                )
                source = (
                    states["canonical_entities"]
                    if "record" in url
                    else states["canonical_documents"]
                )
                if method == "DELETE":
                    return 204, None
                if not source:
                    return 200, []
                return 200, [
                    {
                        "provider": "notion",
                        "object_kind": ("entity" if "record" in url else "document"),
                        "canonical_object_id": source["id"],
                        "external_object_id": external_id,
                        "canonical_revision": source["revision"],
                        "canonical_content_hash": source["content_hash"],
                        "desired_operation": "upsert",
                    }
                ]
            if table == "provider_outbox":
                return (204, None) if method == "DELETE" else (200, [])
            raise AssertionError((method, url, body))

        values = {
            "POSTGREST_ORIGIN_PORT": "28093",
            "POSTGREST_WRITER_ROLE": "writer",
            "POSTGREST_API_AUDIENCE": "mte",
            "POSTGREST_JWT_SECRET": "s" * 64,
            "MTE_OPERATOR_LOOPBACK_HOST": "127.0.0.1",
        }
        with mock.patch.object(self.module, "request_json", side_effect=request):
            evidence, private = self.module._postgres_ssot_prepare(values, "run-1")
            cleanup = self.module._postgres_ssot_cleanup(values, private)
        self.assertEqual(evidence["record"]["initialRevision"], 1)
        self.assertEqual(evidence["record"]["finalRevision"], 2)
        self.assertRegex(evidence["record"]["objectIdSha256"], r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            evidence["document"]["initialContentSha256"],
            evidence["document"]["finalContentSha256"],
        )
        self.assertTrue(cleanup["verified"])

    def test_runtime_payload_binds_mode_0600_persisted_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "bin/server-notion.py"
            script.parent.mkdir(parents=True)
            script.write_text("# producer\n")
            producer_sha = self.module.hashlib.sha256(script.read_bytes()).hexdigest()
            payload = self.notion_result()
            for key in ("_resultSha256", "_producerPath", "_evidenceReference"):
                payload.pop(key)
            payload["canonicalSourceSha256"] = "b" * 64
            payload["producerSha256"] = producer_sha
            evidence_path = root / "evidence/notion-connector-verify.json"
            evidence_path.parent.mkdir(parents=True)
            persisted = {
                "kind": "NotionConnectorVerification",
                "status": "passed",
                "ok": True,
                "dataContentProfile": "postgres-notion",
                "canonicalSourceSha256": "b" * 64,
                "producerSha256": producer_sha,
                "canary": payload,
                "cleanup": {"verified": True},
                "redacted": True,
            }
            evidence_path.write_text(json.dumps(persisted))
            evidence_path.chmod(0o600)
            completed = subprocess.CompletedProcess(
                (), 0, stdout=json.dumps(payload), stderr=""
            )
            with (
                mock.patch.object(self.module, "ROOT", root),
                mock.patch.object(self.module, "canonical_hash", return_value="b" * 64),
                mock.patch.object(self.module, "run", return_value=completed),
            ):
                result = self.module._notion_runtime_payload(
                    {"NOTION_TOKEN": "secret-unit-value"}, "run-1"
                )
        self.assertEqual(
            result["_evidenceReference"]["kind"], "NotionConnectorVerification"
        )
        self.assertRegex(result["_evidenceReference"]["sha256"], r"^[0-9a-f]{64}$")


class ProjectionConsumerC029Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    @staticmethod
    def projection_payload(module, producer_sha="a" * 64):
        state = {
            "canonicalExact": True,
            "syncStateExact": True,
            "outboxDelivered": True,
            "attemptCount": 1,
            "leaseReleased": True,
            "errorFree": True,
        }
        return {
            "kind": "NotionProjectionLiveCanary",
            "status": "passed",
            "ok": True,
            "dataContentProfile": "postgres-notion",
            "canonicalSourceSha256": "b" * 64,
            "producerSha256": producer_sha,
            "redacted": True,
            "linkage": {
                kind: {
                    "canonicalObjectIdSha256": object_id,
                    "providerObjectIdSha256": provider_id,
                    "initialRevision": 1,
                    "finalRevision": 2,
                    "initialContentSha256": initial,
                    "finalContentSha256": final,
                }
                for kind, object_id, provider_id, initial, final in (
                    ("entity", "1" * 64, "2" * 64, "3" * 64, "4" * 64),
                    ("document", "5" * 64, "6" * 64, "7" * 64, "8" * 64),
                )
            },
            "phases": {
                phase: {
                    "objects": {"entity": dict(state), "document": dict(state)},
                    **(
                        {"notionArchived": {"entity": True, "document": True}}
                        if phase == "archive"
                        else {}
                    ),
                }
                for phase in ("create", "update", "archive")
            },
            "cleanup": {
                "postgresCanonicalAbsent": True,
                "postgresSyncStateAbsent": True,
                "postgresOutboxAbsent": True,
                "notionEntityArchived": True,
                "notionDocumentArchived": True,
                "verified": True,
            },
        }

    def test_runtime_runs_consumer_canary_then_verify_and_binds_private_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "bin/server-notion-sync.py"
            script.parent.mkdir(parents=True)
            script.write_text("# consumer producer\n")
            producer_sha = hashlib.sha256(script.read_bytes()).hexdigest()
            canary = self.projection_payload(self.module, producer_sha)
            verification = {
                "kind": "NotionProjectionConsumerVerification",
                "status": "passed",
                "ok": True,
                "dataContentProfile": "postgres-notion",
                "canonicalSourceSha256": "b" * 64,
                "producerSha256": producer_sha,
                "redacted": True,
            }
            evidence = root / "evidence"
            evidence.mkdir()
            for name, payload in (
                ("notion-projection-live-canary.json", canary),
                ("notion-projection-consumer-verify.json", verification),
            ):
                path = evidence / name
                path.write_text(json.dumps(payload))
                path.chmod(0o600)
            completed = [
                subprocess.CompletedProcess((), 0, stdout=json.dumps(canary), stderr=""),
                subprocess.CompletedProcess((), 0, stdout=json.dumps(verification), stderr=""),
            ]
            with (
                mock.patch.object(self.module, "ROOT", root),
                mock.patch.object(self.module, "canonical_hash", return_value="b" * 64),
                mock.patch.object(self.module, "run", side_effect=completed) as invoke,
            ):
                result = self.module._projection_runtime_payload(
                    {"NOTION_TOKEN": "unit-secret-value"}, "linked-run"
                )
        self.assertEqual(invoke.call_args_list[0].args[0][1:3], [str(script), "canary"])
        self.assertEqual(invoke.call_args_list[1].args[0], [sys.executable, str(script), "verify"])
        self.assertEqual(result["_canaryEvidenceReference"]["kind"], "NotionProjectionLiveCanary")
        self.assertEqual(
            result["_consumerVerificationEvidenceReference"]["kind"],
            "NotionProjectionConsumerVerification",
        )

    def test_c029_rejects_connector_only_payload_and_requires_consumer_delivery(self):
        direct_only = {
            "kind": "NotionConnectorCanary",
            "status": "passed",
            "linkage": {},
        }
        with mock.patch.object(
            self.module, "_projection_runtime_payload", return_value=direct_only
        ):
            with self.assertRaisesRegex(
                self.module.CanaryError, "notion_projection_linkage_invalid"
            ):
                self.module.c029({"DATA_CONTENT_PROFILE": "postgres-notion"}, "run")

    def test_c029_reports_only_consumer_linked_hashes(self):
        payload = self.projection_payload(self.module)
        payload["_canaryEvidenceReference"] = {"kind": "NotionProjectionLiveCanary"}
        payload["_consumerVerificationEvidenceReference"] = {
            "kind": "NotionProjectionConsumerVerification"
        }
        with (
            mock.patch.object(self.module, "_projection_runtime_payload", return_value=payload),
            mock.patch.object(
                self.module, "_postgrest_dependency_reference", return_value={"kind": "PostgrestVerification"}
            ),
        ):
            result = self.module.c029({"DATA_CONTENT_PROFILE": "postgres-notion"}, "run")
        self.assertEqual(result["source"], "server_notion_projection_consumer_canary")
        self.assertEqual(result["postgresSsot"]["record"]["objectIdSha256"], "1" * 64)
        self.assertEqual(result["notion"]["document"]["pageIdSha256"], "6" * 64)
        self.assertEqual(result["dependencyEvidence"]["kind"], "NotionProjectionLiveCanary")
        self.assertNotIn("run", json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    unittest.main()

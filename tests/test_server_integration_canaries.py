import importlib.util
import json
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


class CredentialProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_projection_token_accepts_matching_renderer_hash(self):
        with mock.patch.object(
            self.module,
            "dotenv",
            return_value={
                "MTE_PROJECTION_SOURCE_SHA256": "source-hash",
                "BASEROW_ACTIVEPIECES_TOKEN": "activepieces-token",
            },
        ):
            value = self.module.projection_token(
                Path("/renderer-owned/activepieces.env"),
                "BASEROW_ACTIVEPIECES_TOKEN",
                "source-hash",
            )
        self.assertEqual(value, "activepieces-token")

    def test_projection_token_rejects_stale_renderer_hash(self):
        with mock.patch.object(
            self.module,
            "dotenv",
            return_value={
                "MTE_PROJECTION_SOURCE_SHA256": "stale-hash",
                "BASEROW_ACTIVEPIECES_TOKEN": "activepieces-token",
            },
        ):
            with self.assertRaisesRegex(
                self.module.CanaryError, "projection_source_hash_mismatch"
            ):
                self.module.projection_token(
                    Path("/renderer-owned/activepieces.env"),
                    "BASEROW_ACTIVEPIECES_TOKEN",
                    "source-hash",
                )

    def test_activepieces_project_variable_is_exact_and_revealed_only_in_memory(self):
        calls = []

        def request(method, url, **_kwargs):
            calls.append((method, url))
            if method == "GET":
                return 200, {
                    "data": [
                        {
                            "id": "variable-1",
                            "name": self.module.POSTGREST_ACTIVEPIECES_VARIABLE,
                        }
                    ]
                }
            return 200, {"value": "unit-secret-value"}

        with mock.patch.object(self.module, "request_json", side_effect=request):
            value = self.module.activepieces_project_variable(
                "http://activepieces",
                "project-1",
                {"Authorization": "Bearer session"},
                name=self.module.POSTGREST_ACTIVEPIECES_VARIABLE,
                expected_value="unit-secret-value",
            )

        self.assertEqual(
            value,
            {
                "id": "variable-1",
                "name": self.module.POSTGREST_ACTIVEPIECES_VARIABLE,
            },
        )
        self.assertEqual(calls[0][0], "GET")
        self.assertEqual(calls[1][0], "POST")
        self.assertTrue(calls[1][1].endswith("/variables/variable-1/reveal"))
        self.assertNotIn("unit-secret-value", json.dumps(value))

    def test_activepieces_project_variable_fails_closed_on_value_mismatch(self):
        responses = [
            (
                200,
                {
                    "data": [
                        {
                            "id": "variable-1",
                            "name": self.module.POSTGREST_ACTIVEPIECES_VARIABLE,
                        }
                    ]
                },
            ),
            (200, {"value": "wrong-value"}),
        ]
        with mock.patch.object(self.module, "request_json", side_effect=responses):
            with self.assertRaisesRegex(
                self.module.CanaryError,
                "activepieces_project_variable_value_mismatch",
            ):
                self.module.activepieces_project_variable(
                    "http://activepieces",
                    "project-1",
                    {"Authorization": "Bearer session"},
                    name=self.module.POSTGREST_ACTIVEPIECES_VARIABLE,
                    expected_value="expected-value",
                )


class ActivepiecesMcpLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_c013_renews_ephemeral_token_and_cleans_up(self):
        calls = []

        def request(method, url, **_kwargs):
            self.assertEqual(method, "POST")
            self.assertIn("/mcp-server/token", url)
            return 200, {"mcpToken": "short-lived-only"}

        def toolhive(_manager, *args, **kwargs):
            calls.append((args, kwargs))
            stdout = (
                '{"tools":[{"name":"ap_list_flows"}]}'
                if "list" in args
                else '{"flows":[]}'
            )
            return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

        with (
            mock.patch.object(
                self.module,
                "activepieces_session",
                return_value=("http://activepieces", "session", "project"),
            ),
            mock.patch.object(self.module, "request_json", side_effect=request),
            mock.patch.object(self.module, "toolhive_manager", return_value="toolhive"),
            mock.patch.object(self.module, "write_ephemeral_secret") as write_secret,
            mock.patch.object(self.module, "toolhive", side_effect=toolhive),
            mock.patch.object(
                self.module, "remove_toolhive_workload"
            ) as remove_workload,
            mock.patch.object(self.module, "run"),
        ):
            result = self.module.c013({}, "1234567890abcdef")

        remove_workload.assert_called_once()
        write_secret.assert_called_once()
        self.assertEqual(write_secret.call_args.args[1], "short-lived-only")
        self.assertTrue(result["shortLivedToken"])
        self.assertTrue(result["ephemeral0600TokenMount"])
        self.assertFalse(result["tokenPersisted"])
        self.assertEqual(
            result["cleanup"],
            {
                "workloadRemoved": True,
                "tokenFileRemoved": True,
            },
        )
        run_call = next(row for row in calls if "python:3.13-slim" in row[0])
        self.assertIn("stdio", run_call[0])
        network_index = run_call[0].index("--network")
        self.assertEqual(run_call[0][network_index + 1], "host")
        self.assertNotIn("--target-port", run_call[0])
        self.assertIn("/run/secret/token:ro", " ".join(run_call[0]))
        self.assertNotIn("short-lived-only", str(run_call))
        self.assertNotIn("short-lived-only", str(result))
        self.assertTrue(any("ap_list_flows" in row[0] for row in calls))
        self.assertEqual(result["action"], "ap_list_flows")
        self.assertRegex(result["toolSchemaSha256"], r"^[a-f0-9]{64}$")

    def test_wait_toolhive_tool_requires_exact_live_schema_name(self):
        responses = [
            subprocess.CompletedProcess(
                (), 0, stdout='{"tools":[{"name":"ap-list-flows"}]}', stderr=""
            ),
            subprocess.CompletedProcess(
                (), 0, stdout='{"tools":[{"name":"ap_list_flows"}]}', stderr=""
            ),
        ]
        with (
            mock.patch.object(self.module, "toolhive", side_effect=responses) as call,
            mock.patch.object(self.module.time, "sleep"),
        ):
            schema = self.module.wait_toolhive_tool(
                "toolhive", "activepieces", "ap_list_flows", timeout=1
            )

        self.assertEqual(call.call_count, 2)
        self.assertEqual(schema, '{"tools":[{"name":"ap_list_flows"}]}')

    def test_manager_secret_file_accepts_multiline_env_projection(self):
        with mock.patch.object(self.module, "run") as run:
            self.module.write_manager_secret(
                "toolhive",
                "/tmp/firecrawl.env",
                "FIRECRAWL_API_KEY=unit\n"
                "FIRECRAWL_API_URL=http://firecrawl-api:3002\n",
            )
        self.assertIn("chmod 600", run.call_args.args[0][-1])

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
                },
                run_id,
            )

        workload_run = next(row for row in calls if "run" in row[0])
        network_index = workload_run[0].index("--network")
        self.assertEqual(workload_run[0][network_index + 1], "host")
        transport_index = workload_run[0].index("--transport")
        self.assertEqual(workload_run[0][transport_index + 1], "stdio")
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

    def test_unconnected_github_is_conditional_external_consent(self):
        with (
            mock.patch.object(
                self.module,
                "activepieces_session",
                return_value=("http://activepieces", "session", "project"),
            ),
            mock.patch.object(
                self.module,
                "request_json",
                return_value=(200, {"data": []}),
            ),
        ):
            rows = self.module.oauth_assessment({})

        self.assertEqual([row["id"] for row in rows], ["C021", "C022"])
        for row in rows:
            self.assertEqual(row["state"], "conditional_external_provider_consent")
            self.assertFalse(row["liveGateIncluded"])
            self.assertTrue(row["humanAuthorizationRequired"])
            self.assertIsNone(row["ok"])

    def test_authorized_github_connection_enters_hard_live_gate(self):
        with (
            mock.patch.object(
                self.module,
                "activepieces_session",
                return_value=("http://activepieces", "session", "project"),
            ),
            mock.patch.object(
                self.module,
                "request_json",
                return_value=(
                    200,
                    {
                        "data": [
                            {
                                "pieceName": "@activepieces/piece-github",
                                "status": "ACTIVE",
                            }
                        ]
                    },
                ),
            ),
        ):
            rows = self.module.oauth_assessment({})

        for row in rows:
            self.assertEqual(row["state"], "authorized_connection_requires_live_canary")
            self.assertTrue(row["liveGateIncluded"])
            self.assertFalse(row["ok"])
            self.assertFalse(row["humanAuthorizationRequired"])

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
        if action == "baserow_crud":
            result.update(
                {
                    "createStatus": 200,
                    "readStatus": 200,
                    "deleteStatus": 200,
                    "postDeleteStatus": 404,
                    "markerObserved": True,
                    "cleanup": "verified_deleted",
                }
            )
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
                {"PAPERCLIP_PORT": "3100"}, "company-1"
            )
        self.assertEqual(agent["id"], "agent-1")
        config = request.call_args_list[1].args[3]["adapterConfig"]
        self.assertEqual(
            config["env"]["PAPERCLIP_API_URL"],
            {"type": "plain", "value": "http://127.0.0.1:3100"},
        )

    def test_c027_uses_real_paperclip_run_without_host_baserow_token(self):
        with mock.patch.object(
            self.module,
            "paperclip_integration_run",
            return_value=self.paperclip_run("baserow_crud"),
        ) as start:
            value = self.module.c027(
                {
                    "DATA_CONTENT_PROFILE": "baserow-wikijs",
                    "BASEROW_TABLE_ID": "41",
                    "BASEROW_ORIGIN_PORT": "18085",
                },
                "control-1",
            )

        self.assertEqual(value["source"], "paperclip_process_heartbeat_run")
        self.assertEqual(value["paperclipTaskId"], "task-1")
        self.assertEqual(value["paperclipHeartbeatRunId"], "heartbeat-1")
        self.assertEqual(start.call_args.args[2], "baserow_crud")
        self.assertEqual(
            start.call_args.args[3]["baserowApiBase"], "http://127.0.0.1:18085"
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
                    "POSTGREST_ORIGIN_PORT": "18093",
                },
                "control-1",
            )
        self.assertEqual(start.call_args.args[2], "postgrest_crud")
        self.assertEqual(
            start.call_args.args[3]["postgrestApiBase"], "http://127.0.0.1:18093"
        )
        self.assertEqual(value["tablesApiComponent"], "postgrest")
        self.assertTrue(value["postDeleteAbsent"])
        self.assertEqual(value["dependencyEvidence"], dependency)

    def test_c028_dispatches_postgres_notion_to_postgrest_flow(self):
        expected = {"id": "C028", "ok": True, "state": "passed"}
        with mock.patch.object(
            self.module, "c028_postgrest", return_value=expected
        ) as postgrest:
            value = self.module.c028(
                {"DATA_CONTENT_PROFILE": "postgres-notion"}, "control-1"
            )
        self.assertIs(value, expected)
        postgrest.assert_called_once_with(
            {"DATA_CONTENT_PROFILE": "postgres-notion"}, "control-1"
        )

    def test_c028_postgrest_uses_native_encrypted_project_variable(self):
        import inspect

        source = inspect.getsource(self.module.c028_postgrest)
        self.assertIn("activepieces_project_variable", source)
        self.assertIn("credentialVariablePreserved", source)
        self.assertIn('"encrypted_project_variable"', source)
        self.assertNotIn("/api/v1/app-connections", source)

    def test_c028_uses_native_activepieces_flow_and_piece_actions(self):
        import inspect

        source = inspect.getsource(self.module.c028)
        self.assertIn("/api/v1/app-connections", source)
        self.assertIn("/api/v1/flows", source)
        self.assertIn("@activepieces/piece-baserow", source)
        self.assertIn("baserow_create_row", source)
        self.assertIn("baserow_get_row", source)
        self.assertIn("baserow_delete_row", source)
        self.assertNotIn('"node", "-e"', source)

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
                },
                "control-1",
            )

        self.assertEqual(value["source"], "paperclip_process_heartbeat_run")
        self.assertEqual(value["cleanup"], "verified_deleted")
        self.assertTrue(value["contentMatchesTaskAndRun"])
        self.assertEqual(request.call_count, 4)


class OsePersistenceCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_c029_binds_baserow_and_wikijs_restart_evidence(self):
        baserow = {
            "distribution": {
                "version": "2.3.1",
                "license": "MIT",
                "image": "baserow/baserow:2.3.1@sha256:" + "a" * 64,
                "enterpriseLicenseConfigured": False,
            },
            "baserowPersistence": {
                "databaseId": 11,
                "tableId": 12,
                "rowId": 13,
                "markerSha256": "b" * 64,
                "restartObserved": True,
                "persistenceVerified": True,
                "postDeleteStatus": 404,
                "cleanupCompleted": True,
            },
        }
        wikijs = {
            "image": {
                "version": "2.5.314",
                "digest": "sha256:" + "c" * 64,
                "license": {"spdx": "AGPL-3.0-only"},
            },
            "graphql": {
                "pageId": 21,
                "pathHashSha256": "d" * 64,
                "markerSha256": "e" * 64,
                "restartObserved": True,
                "persistenceVerified": True,
                "postDeleteStatus404": 404,
                "cleanupCompleted": True,
            },
        }
        refs = (
            {
                "path": "/e/baserow.json",
                "sha256": "1" * 64,
                "kind": "BaserowAcceptance",
                "producerSha256": "2" * 64,
            },
            {
                "path": "/e/wikijs.json",
                "sha256": "3" * 64,
                "kind": "WikiJsVerification",
                "producerSha256": "4" * 64,
            },
        )
        with mock.patch.object(
            self.module,
            "bound_component_evidence",
            side_effect=[(baserow, refs[0]), (wikijs, refs[1])],
        ):
            value = self.module.c029({"DATA_CONTENT_PROFILE": "baserow-wikijs"}, "run")
        self.assertEqual(value["source"], "controlled_ose_application_restarts")
        self.assertTrue(value["tablePersistenceVerified"])
        self.assertTrue(value["documentPersistenceVerified"])
        self.assertTrue(value["cleanupCompleted"])
        self.assertEqual(value["wikijsPersistence"]["postDeleteStatus"], 404)
        self.assertEqual(
            [row["component"] for row in value["osiLicenses"]],
            ["baserow", "wikijs"],
        )
        self.assertEqual(value["dependencyEvidence"]["baserow"], refs[0])

    def test_c029_is_supported_and_part_of_default_run(self):
        self.assertIn("C029", self.module.SUPPORTED)
        self.assertIs(self.module.CANARIES["C029"], self.module.c029)

    def test_c029_target_proves_one_postgres_state_and_real_nocodocs(self):
        postgrest = {
            "release": {"image": "postgrest/postgrest:v14.15@sha256:" + "a" * 64},
            "persistence": {
                "markerSha256": "b" * 64,
                "restartObserved": True,
                "persistenceVerified": True,
                "postDeleteAbsent": True,
                "cleanupCompleted": True,
            },
        }
        nocodb = {
            "release": {
                "image": "nocodb/nocodb:2026.06.2@sha256:" + "c" * 64,
                "license": "LicenseRef-NocoDB-Sustainable-Use-1.0",
                "exception": {"approval": "user-approved-2026-07-15"},
            },
            "dataState": {
                "owner": "postgres-postgrest",
                "nocodbUniqueTableState": False,
                "postgrestCreated": True,
                "nocodbDiagnosticReadVisible": True,
                "cleanupCompleted": True,
            },
            "documentsApi": {
                "endpoint": "/api/v3/docs",
                "restartObserved": True,
                "persistenceVerified": True,
                "postDeleteAbsent": True,
                "cleanupCompleted": True,
            },
        }
        refs = (
            {"path": "/e/postgrest.json", "sha256": "1" * 64},
            {"path": "/e/nocodb.json", "sha256": "2" * 64},
        )
        with mock.patch.object(
            self.module,
            "bound_component_evidence",
            side_effect=[(postgrest, refs[0]), (nocodb, refs[1])],
        ):
            value = self.module.c029(
                {"DATA_CONTENT_PROFILE": "postgres-postgrest-nocodb-nocodocs"},
                "run",
            )
        self.assertEqual(value["roles"]["tablesApi"], "postgrest")
        self.assertEqual(value["roles"]["documentsApi"], "nocodb")
        self.assertTrue(value["tablesPersistence"]["singlePostgresStateVerified"])
        self.assertEqual(value["documentsPersistence"]["endpoint"], "/api/v3/docs")


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
            "POSTGREST_ORIGIN_PORT": "18093",
            "POSTGREST_WRITER_ROLE": "writer",
            "POSTGREST_API_AUDIENCE": "mte",
            "POSTGREST_JWT_SECRET": "s" * 64,
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


if __name__ == "__main__":
    unittest.main()

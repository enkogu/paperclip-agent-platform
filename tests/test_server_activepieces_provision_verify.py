import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock
import urllib.error


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "mte_server_activepieces_provision_verify",
        ROOT / "tools/platform-cli/server-activepieces-provision-verify.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ActivepiecesProvisionTests(unittest.TestCase):
    def test_transport_errors_expose_only_safe_operation(self):
        with mock.patch.object(
            self.module.urllib.request,
            "urlopen",
            side_effect=TimeoutError("secret upstream detail"),
        ):
            with self.assertRaisesRegex(
                self.module.ProvisionError,
                r"^activepieces_timeout:GET:/api/v1/flows$",
            ) as caught:
                self.module.request_json(
                    "GET",
                    "http://127.0.0.1:1234/api/v1/flows?token=must-not-leak",
                )
        self.assertNotIn("secret", str(caught.exception))
        self.assertNotIn("token", str(caught.exception))

        with mock.patch.object(
            self.module.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("secret transport detail"),
        ):
            with self.assertRaisesRegex(
                self.module.ProvisionError,
                r"^activepieces_transport_error:POST:/api/v1/flows$",
            ):
                self.module.request_json(
                    "POST",
                    "http://127.0.0.1:1234/api/v1/flows?token=must-not-leak",
                )

    def test_postgres_notion_uses_an_encrypted_project_variable(self):
        values = {
            "DATA_CONTENT_PROFILE": "postgres-notion",
            "POSTGREST_ACTIVEPIECES_TOKEN": "unit-token",
        }
        with mock.patch.object(
            self.module,
            "reconcile_postgrest_variable",
            return_value=([{"id": "variable"}], 0, 0),
        ) as reconcile:
            result = self.module.reconcile_credentials(
                "http://activepieces", "project", "session", values, mutate=False
            )
        self.assertEqual(result, ([{"id": "variable"}], 0, 0))
        reconcile.assert_called_once_with(
            "http://activepieces",
            "project",
            "session",
            "unit-token",
            mutate=False,
        )

    def setUp(self):
        self.module = load_module()

    def test_flow_reconcile_creates_exact_curated_slots_then_is_noop(self):
        rows = []

        def request(method, url, **kwargs):
            if method == "GET":
                return {"data": list(rows)}
            created = {
                "id": f"flow-{len(rows) + 1}",
                "version": {"displayName": kwargs["body"]["displayName"]},
                "projectId": "project",
            }
            rows.append(created)
            return created

        with mock.patch.object(self.module, "request_json", side_effect=request):
            first, mutations, duplicates = self.module.reconcile_flows(
                "http://activepieces", "project", "session", mutate=True
            )
            second, second_mutations, second_duplicates = self.module.reconcile_flows(
                "http://activepieces", "project", "session", mutate=True
            )
        self.assertEqual(
            [row["displayName"] for row in first], list(self.module.MANAGED_FLOW_NAMES)
        )
        self.assertEqual(mutations, 3)
        self.assertEqual(duplicates, 0)
        self.assertEqual(second, first)
        self.assertEqual(second_mutations, 0)
        self.assertEqual(second_duplicates, 0)

    def test_flow_reconcile_deletes_only_exact_managed_duplicates_and_proves_404(
        self,
    ):
        rows = [
            {
                "id": "flow-b",
                "displayName": "top-level-name-must-not-win",
                "version": {"displayName": self.module.MANAGED_FLOW_NAMES[0]},
            },
            {
                "id": "flow-a",
                "version": {"displayName": self.module.MANAGED_FLOW_NAMES[0]},
            },
            {
                "id": "unrelated",
                "version": {"displayName": "MTE Curated Slot - Research Copy"},
            },
        ]
        deleted = []

        def request(method, url, **kwargs):
            if method == "GET" and "?" in url:
                return {"data": list(rows)}
            if method == "DELETE":
                identifier = url.rsplit("/", 1)[-1]
                deleted.append(identifier)
                rows[:] = [row for row in rows if row["id"] != identifier]
                return None
            if method == "GET":
                identifier = url.rsplit("/", 1)[-1]
                if all(row["id"] != identifier for row in rows):
                    raise self.module.ProvisionError(
                        f"activepieces_http_404:GET:/api/v1/flows/{identifier}"
                    )
                return next(row for row in rows if row["id"] == identifier)
            created = {
                "id": f"flow-{len(rows) + 1}",
                "version": {"displayName": kwargs["body"]["displayName"]},
            }
            rows.append(created)
            return created

        with mock.patch.object(self.module, "request_json", side_effect=request):
            first, mutations, duplicates = self.module.reconcile_flows(
                "http://activepieces", "project", "session", mutate=True
            )
            second, second_mutations, second_duplicates = self.module.reconcile_flows(
                "http://activepieces", "project", "session", mutate=True
            )

        self.assertEqual(deleted, ["flow-b"])
        self.assertEqual(first[0]["id"], "flow-a")
        self.assertIn("unrelated", [row["id"] for row in rows])
        self.assertEqual((mutations, duplicates), (3, 0))
        self.assertEqual(second, first)
        self.assertEqual((second_mutations, second_duplicates), (0, 0))

    def test_flow_delete_fails_when_get_does_not_prove_absence(self):
        with (
            mock.patch.object(self.module, "request_json", return_value={}),
            mock.patch.object(self.module.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                self.module.ProvisionError,
                "activepieces_managed_flow_delete_unverified",
            ):
                self.module.delete_flow_and_verify_absent(
                    "http://activepieces", "flow", "session"
                )
        self.assertEqual(sleep.call_count, 120)

    def test_connection_slot_uses_real_baserow_piece_without_leaking_token(self):
        calls = []

        def request(method, _url, **kwargs):
            calls.append((method, kwargs.get("body")))
            if method == "GET":
                return {"data": []}
            return {"id": "connection-1", **kwargs["body"]}

        secret = "never-render-this-token"
        with mock.patch.object(self.module, "request_json", side_effect=request):
            result, mutations, duplicates = self.module.reconcile_connections(
                "http://activepieces",
                "project",
                "session",
                {
                    "DATA_CONTENT_PROFILE": "baserow-wikijs",
                    "BASEROW_ACTIVEPIECES_TOKEN": secret,
                },
                mutate=True,
            )
        self.assertEqual(mutations, 1)
        self.assertEqual(duplicates, 0)
        self.assertEqual(result[0]["pieceName"], "@activepieces/piece-baserow")
        self.assertNotIn(secret, str(result))
        posted = next(body for method, body in calls if method == "POST")
        self.assertEqual(posted["value"]["props"]["token"], secret)
        self.assertEqual(posted["value"]["props"]["authType"], "database_token")
        self.assertEqual(posted["value"]["props"]["apiUrl"], "http://baserow:80")

    def test_postgrest_variable_create_then_second_pass_is_noop_and_redacted(self):
        calls = []
        rows = []
        values = {}

        def request(method, url, **kwargs):
            calls.append((method, url, kwargs.get("body")))
            if method == "GET":
                return {"data": list(rows)}
            if url.endswith("/reveal"):
                return {"value": values["secret"]}
            if url.endswith("/variables"):
                values["secret"] = kwargs["body"]["value"]
                created = {
                    "id": "variable-1",
                    "name": kwargs["body"]["name"],
                    "projectId": kwargs["body"]["projectId"],
                }
                rows.append(created)
                return created
            self.fail(f"unexpected request {method} {url}")

        secret = "postgrest-activepieces-only"
        with mock.patch.object(self.module, "request_json", side_effect=request):
            result, mutations, duplicates = self.module.reconcile_postgrest_variable(
                "http://activepieces",
                "project",
                "session",
                secret,
                mutate=True,
            )
            second, second_mutations, second_duplicates = (
                self.module.reconcile_postgrest_variable(
                    "http://activepieces",
                    "project",
                    "session",
                    secret,
                    mutate=True,
                )
            )
        self.assertEqual((mutations, duplicates), (1, 0))
        self.assertEqual(result[0]["type"], "project-variable")
        self.assertTrue(result[0]["valueRedacted"])
        self.assertNotIn(secret, str(result))
        self.assertEqual(second, result)
        self.assertEqual((second_mutations, second_duplicates), (0, 0))
        create_body = next(
            body
            for method, url, body in calls
            if method == "POST" and url.endswith("/variables")
        )
        self.assertEqual(create_body["value"], secret)
        self.assertFalse(any("app-connections" in url for _, url, _ in calls))

    def test_postgrest_variable_drift_is_updated_and_verified(self):
        secret = {"value": "stale"}
        update_bodies = []
        rows = [
            {
                "id": "variable-1",
                "name": self.module.POSTGREST_VARIABLE_NAME,
                "projectId": "project",
            }
        ]

        def request(method, url, **kwargs):
            if method == "GET":
                return {"data": rows}
            if url.endswith("/reveal"):
                return {"value": secret["value"]}
            if url.endswith("/variables/variable-1"):
                update_bodies.append(kwargs["body"])
                secret["value"] = kwargs["body"]["value"]
                return {"id": "variable-1"}
            self.fail(f"unexpected request {method} {url}")

        with mock.patch.object(self.module, "request_json", side_effect=request):
            result, mutations, duplicates = self.module.reconcile_postgrest_variable(
                "http://activepieces",
                "project",
                "session",
                "current",
                mutate=True,
            )
        self.assertEqual((mutations, duplicates), (1, 0))
        self.assertEqual(secret["value"], "current")
        self.assertEqual(update_bodies, [{"value": "current"}])
        self.assertNotIn("current", str(result))

    def test_postgrest_variable_drift_fails_closed_in_verify_mode(self):
        rows = [{"id": "variable-1", "name": self.module.POSTGREST_VARIABLE_NAME}]

        def request(method, url, **_kwargs):
            if method == "GET":
                return {"data": rows}
            if url.endswith("/reveal"):
                return {"value": "stale"}
            self.fail(f"unexpected request {method} {url}")

        with mock.patch.object(self.module, "request_json", side_effect=request):
            with self.assertRaisesRegex(
                self.module.ProvisionError,
                "activepieces_managed_variable_value_drift",
            ):
                self.module.reconcile_postgrest_variable(
                    "http://activepieces",
                    "project",
                    "session",
                    "current",
                    mutate=False,
                )

    def test_execute_first_pass_applied_second_pass_passed(self):
        auth = {"id": "owner", "platformId": "platform", "projectId": "project"}
        patches = (
            mock.patch.object(
                self.module,
                "dotenv",
                return_value={
                    "ACTIVEPIECES_ADMIN_EMAIL": "owner@example.test",
                    "ACTIVEPIECES_ADMIN_PASSWORD": "secret",
                    "ACTIVEPIECES_ORIGIN_PORT": "18090",
                    "DATA_CONTENT_PROFILE": "postgres-notion",
                    "POSTGREST_ACTIVEPIECES_TOKEN": "secret-2",
                },
            ),
            mock.patch.object(
                self.module,
                "session",
                return_value=("http://activepieces", "session", auth),
            ),
            mock.patch.object(self.module, "identity_counts", return_value=(1, 1)),
            mock.patch.object(self.module, "prove_mcp_token", return_value=True),
            mock.patch.object(self.module, "sha256_path", return_value="a" * 64),
        )
        flows = [
            {
                "id": "flow",
                "type": "flow",
                "displayName": "slot",
                "status": "ready",
            }
        ]
        credentials = [
            {
                "id": "variable",
                "type": "project-variable",
                "name": "slot",
                "status": "ready",
                "valueRedacted": True,
            }
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            with (
                mock.patch.object(
                    self.module, "reconcile_flows", return_value=(flows, 3, 0)
                ),
                mock.patch.object(
                    self.module,
                    "reconcile_credentials",
                    return_value=(credentials, 1, 0),
                ),
            ):
                first = self.module.execute(mutate=True)
            with (
                mock.patch.object(
                    self.module, "reconcile_flows", return_value=(flows, 0, 0)
                ),
                mock.patch.object(
                    self.module,
                    "reconcile_credentials",
                    return_value=(credentials, 0, 0),
                ),
            ):
                second = self.module.execute(mutate=True)
        self.assertEqual(first["status"], "applied")
        self.assertFalse(first["secondRunNoOp"])
        self.assertEqual(second["status"], "passed")
        self.assertTrue(second["secondRunNoOp"])
        self.assertFalse(second["mcpTokenPersisted"])
        self.assertNotIn("secret", str(second))
        self.assertEqual(second["credentialSlots"], credentials)
        self.assertNotIn("connectionSlots", second)

    def test_duplicate_capacity_fails_closed(self):
        auth = {"id": "owner", "platformId": "platform", "projectId": "project"}
        with (
            mock.patch.object(
                self.module,
                "dotenv",
                return_value={
                    "ACTIVEPIECES_ADMIN_EMAIL": "owner@example.test",
                    "ACTIVEPIECES_ADMIN_PASSWORD": "secret",
                    "ACTIVEPIECES_ORIGIN_PORT": "18090",
                    "DATA_CONTENT_PROFILE": "baserow-wikijs",
                    "BASEROW_ACTIVEPIECES_TOKEN": "secret-2",
                },
            ),
            mock.patch.object(
                self.module,
                "session",
                return_value=("http://activepieces", "session", auth),
            ),
            mock.patch.object(self.module, "identity_counts", return_value=(1, 1)),
            mock.patch.object(self.module, "reconcile_flows", return_value=([], 0, 1)),
            mock.patch.object(
                self.module, "reconcile_credentials", return_value=([], 0, 0)
            ),
            mock.patch.object(self.module, "prove_mcp_token", return_value=True),
            mock.patch.object(self.module, "sha256_path", return_value="a" * 64),
        ):
            result = self.module.execute(mutate=True)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["ok"])
        self.assertEqual(result["duplicateCount"], 1)


if __name__ == "__main__":
    unittest.main()

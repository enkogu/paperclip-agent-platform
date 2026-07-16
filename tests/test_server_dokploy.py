import importlib.util
import json
from contextlib import nullcontext
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/platform-cli/server-dokploy.py"


def load_module():
    spec = importlib.util.spec_from_file_location("server_dokploy", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class DokployDedicatedApiTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_api_only_client_has_no_cookie_handler_and_requires_dedicated_ref(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            canonical = Path(temporary) / "platform.env"
            canonical.write_text("DOKPLOY_API_TOKEN=" + "x" * 32 + "\n")
            with mock.patch.object(self.module, "PLATFORM_ENV", canonical):
                client = self.module.Dokploy(
                    "http://127.0.0.1:3000/api",
                    api_key_only=True,
                )
                self.assertFalse(
                    any(
                        handler.__class__.__name__ == "HTTPCookieProcessor"
                        for handler in client.opener.handlers
                    )
                )
            canonical.write_text("")
            with (
                mock.patch.object(self.module, "PLATFORM_ENV", canonical),
                self.assertRaises(RuntimeError),
            ):
                self.module.Dokploy(
                    "http://127.0.0.1:3000/api",
                    api_key_only=True,
                )

    def test_session_auth_posts_include_better_auth_origin(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b"{}"

        class Opener:
            def __init__(self):
                self.requests = []

            def open(self, request, timeout):
                self.requests.append((request, timeout))
                return Response()

        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            canonical = Path(temporary) / "platform.env"
            canonical.write_text("")
            with mock.patch.object(self.module, "PLATFORM_ENV", canonical):
                client = self.module.Dokploy("http://127.0.0.1:3000/api")
                opener = Opener()
                client.opener = opener
                client.auth_request(
                    "POST",
                    "api-key/create",
                    body={"name": "mte-platform-cli"},
                )

        request, timeout = opener.requests[0]
        self.assertEqual(timeout, 30)
        self.assertEqual(request.get_header("Origin"), "http://127.0.0.1:3000")
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertNotIn("127.0.0.1:3000/api", request.get_header("Origin"))

    def test_api_key_bootstrap_replaces_unrecoverable_named_key_and_persists_once(self):
        calls = []

        class FakeDokploy:
            def __init__(self, _base, *, session_only=False):
                self.session_only = session_only

            def session(self):
                return {"user": {"id": "user-1"}}

            def login(self):
                raise AssertionError("existing session must be reused")

            def auth_request(self, method, path, body=None, query=None):
                calls.append((method, path, body, query))
                if path == "organization/list":
                    return [{"id": "org-1", "name": "Managed"}]
                if path == "api-key/list":
                    return {"apiKeys": [{"id": "stale-1", "name": "mte-platform-cli"}]}
                raise AssertionError(path)

            def request(self, method, path, body=None):
                calls.append((method, path, body, None))
                if path == "user.deleteApiKey":
                    return True
                if path == "user.createApiKey":
                    return {"id": "created-1", "key": "mte_" + "z" * 40}
                raise AssertionError(path)

        written = {}
        with (
            mock.patch.object(self.module, "Dokploy", FakeDokploy),
            mock.patch.object(
                self.module,
                "persist_canonical_api_token",
                side_effect=lambda value: written.update({"DOKPLOY_API_TOKEN": value}),
            ),
            mock.patch.object(
                self.module,
                "api_key_proof",
                return_value={
                    "apiKeyAuthenticated": True,
                    "credentialRef": "DOKPLOY_API_TOKEN",
                    "credentialSource": "/root/.config/mte-secrets/platform.env",
                    "credentialFingerprintSha256": "a" * 64,
                    "projectCount": 1,
                },
            ),
        ):
            result = self.module.ensure_api_key("http://127.0.0.1:3000/api")
        self.assertEqual(result["action"], "created")
        self.assertEqual(set(written), {"DOKPLOY_API_TOKEN"})
        self.assertNotIn(written["DOKPLOY_API_TOKEN"], json.dumps(result))
        self.assertIn(
            ("POST", "user.deleteApiKey", {"apiKeyId": "stale-1"}, None),
            calls,
        )
        create = next(row for row in calls if row[1] == "user.createApiKey")
        self.assertEqual(create[2]["metadata"], {"organizationId": "org-1"})
        self.assertIs(create[2]["rateLimitEnabled"], False)

    def test_dokploy_credentials_use_only_canonical_source_not_sidecars(self):
        source = SCRIPT.read_text()
        self.assertNotIn("dokploy-api.env", source)
        self.assertNotIn("dokploy-admin.env", source)
        self.assertIn("dotenv(PLATFORM_ENV).get(API_KEY_REF", source)
        self.assertIn("admin = dotenv(PLATFORM_ENV)", source)
        self.assertIn("persist_canonical_api_token(raw)", source)

    def test_canonical_token_mutation_renders_and_audits_before_return(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            canonical = Path(temporary) / "platform.env"
            canonical.write_text("EXISTING=value\n")
            calls = []
            with (
                mock.patch.object(self.module, "PLATFORM_ENV", canonical),
                mock.patch.object(self.module, "SECRET_ROOT", Path(temporary)),
                mock.patch.object(
                    self.module,
                    "canonical_writer_guard",
                    return_value=nullcontext(),
                ),
                mock.patch.object(self.module, "verify_canonical_permissions"),
                mock.patch.object(self.module, "verify_canonical_projection_state"),
                mock.patch.object(
                    self.module.subprocess,
                    "run",
                    side_effect=lambda argv, **_kwargs: calls.append(argv),
                ),
            ):
                digest = self.module.persist_canonical_api_token("x" * 32)
            self.assertEqual(
                self.module.dotenv(canonical)["DOKPLOY_API_TOKEN"],
                "x" * 32,
            )
            self.assertEqual([row[-1] for row in calls], ["render", "audit"])
            self.assertEqual(
                digest,
                self.module.hashlib.sha256(canonical.read_bytes()).hexdigest(),
            )

    def test_wait_terminal_binds_done_to_a_new_deployment_marker(self):
        class Api:
            def request(self, _method, _path):
                return {
                    "composeStatus": "done",
                    "lastDeployment": {"deploymentId": "deployment-new"},
                }

        baseline = self.module.deployment_marker(
            {"lastDeployment": {"deploymentId": "deployment-old"}}
        )
        result = self.module.wait_terminal(
            Api(),
            "compose-1",
            baseline_marker=baseline,
            requested_marker="",
            timeout=1,
        )
        self.assertEqual(result["status"], "done")
        self.assertNotEqual(result["deploymentMarker"], baseline)

    def test_wait_terminal_rejects_idle_instead_of_treating_it_as_success(self):
        class Api:
            def request(self, _method, _path):
                return {"composeStatus": "idle"}

        with self.assertRaisesRegex(RuntimeError, "idle"):
            self.module.wait_terminal(
                Api(),
                "compose-1",
                baseline_marker="",
                requested_marker="deployment-requested",
                timeout=1,
            )

    def test_unchanged_digest_health_gate_executes_real_declared_command(self):
        result = self.module.wait_declared_health(
            {"id": "demo", "health": {"command": "exit 0"}},
            timeout=1,
            app_name="mte-demo-abc123",
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["kind"], "command")
        with (
            mock.patch.object(self.module.time, "sleep", return_value=None),
            mock.patch.object(
                self.module.time,
                "monotonic",
                side_effect=[0.0, 0.0, 2.0],
            ),
            self.assertRaisesRegex(RuntimeError, "health gate failed"),
        ):
            self.module.wait_declared_health(
                {"id": "demo", "health": {"command": "exit 1"}},
                timeout=1,
                app_name="mte-demo-abc123",
            )

    def test_command_health_uses_observed_dokploy_app_name_as_environment(self):
        observed = {}

        def run(_argv, **kwargs):
            observed.update(kwargs)
            return mock.Mock(returncode=0)

        with mock.patch.object(self.module.subprocess, "run", side_effect=run):
            result = self.module.wait_declared_health(
                {
                    "id": "postgres",
                    "health": {
                        "command": 'test "$DOKPLOY_APP_NAME" = mte-postgres-ekpcdn'
                    },
                },
                timeout=1,
                app_name="mte-postgres-ekpcdn",
            )

        self.assertEqual(result["status"], "passed")
        self.assertEqual(observed["env"]["DOKPLOY_APP_NAME"], "mte-postgres-ekpcdn")
        self.assertNotIn("DOKPLOY_APP_NAME", os.environ)

    def test_command_health_rejects_unsafe_or_missing_dokploy_app_name(self):
        for app_name in ("", "mte-postgres; false"):
            with (
                self.subTest(app_name=app_name),
                self.assertRaisesRegex(RuntimeError, "safe Dokploy appName"),
            ):
                self.module.wait_declared_health(
                    {"id": "postgres", "health": {"command": "exit 0"}},
                    timeout=1,
                    app_name=app_name,
                )

    def test_no_wait_reconcile_is_fail_closed_before_any_mutation(self):
        with (
            mock.patch.object(self.module, "verify_projection") as verify,
            self.assertRaisesRegex(RuntimeError, "terminal and health-gated"),
        ):
            self.module.reconcile(["demo"], True)
        verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()

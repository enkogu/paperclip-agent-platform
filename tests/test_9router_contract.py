import contextlib
import http.server
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment/services/9router/contract.py"
COMPOSE = ROOT / "deployment/services/9router/compose.yaml"


def load_module():
    spec = importlib.util.spec_from_file_location("ninerouter_contract", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RouterHandler(http.server.BaseHTTPRequestHandler):
    connections = []
    accepted_keys = set()

    def response(self, status, payload, *, cookie=False):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if cookie:
            self.send_header("Set-Cookie", "auth_token=unit; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/api/health":
            self.response(200, {"status": "ok"})
            return
        if self.path == "/api/providers":
            if "auth_token=unit" not in self.headers.get("Cookie", ""):
                self.response(401, {"error": "unauthorized"})
                return
            self.response(200, {"connections": type(self).connections})
            return
        if self.path == "/v1/models":
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            if token not in type(self).accepted_keys:
                self.response(401, {"error": "invalid key"})
                return
            self.response(200, {"data": [{"id": "mte-minimax/unit"}]})
            return
        self.response(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/api/auth/login":
            size = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(size))
            if payload.get("password") == "initial-password":
                self.response(200, {"success": True}, cookie=True)
            else:
                self.response(401, {"success": False})
            return
        self.response(404, {"error": "not found"})

    def log_message(self, *_args):
        return


class RouterContractTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        RouterHandler.connections = [
            {"provider": "codex", "authType": "oauth", "testStatus": "active"},
            {
                "provider": "claude",
                "authType": "access_token",
                "testStatus": "active",
            },
        ]
        RouterHandler.accepted_keys = {
            "codex-profile-secret",
            "claude-profile-secret",
            "pi-profile-secret",
        }
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RouterHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    @property
    def values(self):
        return {
            "NINEROUTER_INITIAL_PASSWORD": "initial-password",
            "NINEROUTER_PROFILE_CODING_DAYTONA_CODEX_API_KEY": "codex-profile-secret",
            "NINEROUTER_PROFILE_CODING_DAYTONA_CLAUDE_API_KEY": "claude-profile-secret",
            "NINEROUTER_PROFILE_CODING_DAYTONA_PI_API_KEY": "pi-profile-secret",
        }

    def test_profile_routes_and_required_operator_subscriptions_are_ready(self):
        result = self.module.evaluate(
            self.base_url,
            self.values,
            require_subscriptions=("codex", "claude"),
        )
        self.assertEqual(result["status"], "ready")
        self.assertEqual(
            [row["profile"] for row in result["profileRoutes"]],
            ["coding-daytona-codex", "coding-daytona-claude", "coding-daytona-pi"],
        )
        self.assertTrue(all(row["modelCount"] == 1 for row in result["profileRoutes"]))
        self.assertTrue(all(row["status"] == "ready" for row in result["subscriptions"]))

    def test_missing_required_subscription_fails_closed_without_leaking_secrets(self):
        RouterHandler.connections = [
            {"provider": "codex", "authType": "oauth", "testStatus": "active"}
        ]
        result = self.module.evaluate(
            self.base_url,
            self.values,
            require_subscriptions=("codex", "claude"),
        )
        rendered = json.dumps(result)
        self.assertEqual(result["status"], "needs_configuration")
        self.assertNotIn("initial-password", rendered)
        self.assertNotIn("codex-profile-secret", rendered)
        self.assertNotIn("claude-profile-secret", rendered)
        self.assertNotIn("pi-profile-secret", rendered)

    def test_cli_reads_env_and_emits_safe_json_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            env_file = Path(temporary) / "platform.env"
            env_file.write_text(
                "\n".join(f"{key}={value}" for key, value in self.values.items())
                + "\n"
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = self.module.main(
                    [
                        "--base-url",
                        self.base_url,
                        "--env-file",
                        str(env_file),
                        "--require-subscription-provider",
                        "codex",
                        "--require-subscription-provider",
                        "claude",
                    ]
                )
        rendered = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(rendered)["status"], "ready")
        for secret in self.values.values():
            self.assertNotIn(secret, rendered)

    def test_rejects_base_url_with_credentials(self):
        with self.assertRaises(self.module.RouterContractError) as raised:
            self.module.normalized_base_url("http://secret@127.0.0.1:20128")
        self.assertEqual(str(raised.exception), "invalid_base_url")
        with self.assertRaises(self.module.RouterContractError) as raised:
            self.module.normalized_base_url("http://127.0.0.1:20128/v1")
        self.assertEqual(str(raised.exception), "invalid_base_url")

    def test_compose_healthcheck_uses_the_configured_router_port(self):
        compose = yaml.safe_load(COMPOSE.read_text())
        service = compose["services"]["9router"]
        probe = service["healthcheck"]["test"][-1]
        self.assertIn("process.env.PORT", probe)
        self.assertNotIn("${", probe)
        self.assertNotIn("127.0.0.1:20128", probe)
        self.assertEqual(service["environment"]["REQUIRE_API_KEY"], "true")


if __name__ == "__main__":
    unittest.main()

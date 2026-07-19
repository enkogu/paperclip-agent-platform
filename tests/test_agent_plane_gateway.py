import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request

import yaml


ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class Upstream(http.server.BaseHTTPRequestHandler):
    authorization = None

    def do_POST(self):
        type(self).authorization = self.headers.get("Authorization")
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class AgentPlaneGatewayTests(unittest.TestCase):
    def test_profile_route_requires_identity_and_strips_it_upstream(self):
        upstream_port = free_port()
        upstream = http.server.ThreadingHTTPServer(
            ("127.0.0.1", upstream_port), Upstream
        )
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        gateway_ports = [free_port() for _ in range(4)]
        env = {
            **os.environ,
            "MTE_AGENT_GATEWAY_NINEROUTER_PORT": str(gateway_ports[0]),
            "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_PORT": str(gateway_ports[1]),
            "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_PORT": str(gateway_ports[2]),
            "MTE_AGENT_GATEWAY_TOOLHIVE_PI_PORT": str(gateway_ports[3]),
            "MTE_AGENT_GATEWAY_NINEROUTER_UPSTREAM": f"http://127.0.0.1:{upstream_port}",
            "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM": f"http://127.0.0.1:{upstream_port}",
            "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_UPSTREAM": f"http://127.0.0.1:{upstream_port}",
            "MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM": f"http://127.0.0.1:{upstream_port}",
            "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN": "codex-token",
            "TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_BEARER_TOKEN": "claude-token",
            "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN": "pi-token",
        }
        process = subprocess.Popen(
            [sys.executable, str(ROOT / "tools/platform-cli/agent-plane-gateway.py")],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        url = f"http://127.0.0.1:{gateway_ports[3]}"
        try:
            for _ in range(100):
                try:
                    with urllib.request.urlopen(
                        url + "/healthz", timeout=0.2
                    ) as response:
                        self.assertEqual(response.status, 200)
                    break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.02)
            else:
                self.fail("gateway did not start")

            request = urllib.request.Request(
                url + "/mcp",
                data=b"{}",
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request, timeout=2)
            self.assertEqual(error.exception.code, 401)

            payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            request = urllib.request.Request(
                url + "/mcp",
                data=json.dumps(payload).encode(),
                method="POST",
                headers={
                    "Authorization": "Bearer pi-token",
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                self.assertEqual(json.load(response), payload)
            self.assertIsNone(Upstream.authorization)

            forbidden = urllib.request.Request(
                url + "/not-mcp",
                data=b"{}",
                method="POST",
                headers={"Authorization": "Bearer pi-token"},
            )
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(forbidden, timeout=2)
            self.assertEqual(error.exception.code, 404)

            prefix_confusion = urllib.request.Request(
                url + "/mcp-evil",
                data=b"{}",
                method="POST",
                headers={"Authorization": "Bearer pi-token"},
            )
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(prefix_confusion, timeout=2)
            self.assertEqual(error.exception.code, 404)
        finally:
            process.terminate()
            process.wait(timeout=5)
            upstream.shutdown()
            upstream.server_close()

    def test_daytona_sidecar_has_no_host_or_cloudflare_port(self):
        compose = yaml.safe_load(
            (ROOT / "deployment/services/daytona/compose.yaml").read_text()
        )
        services = compose["services"]
        gateway = services["agent-gateway"]
        runner = services["runner"]

        self.assertEqual(gateway["network_mode"], "service:runner")
        for service in (gateway, runner):
            self.assertNotIn("ports", service)
            self.assertNotIn("expose", service)
        self.assertNotIn("networks", gateway)
        self.assertNotIn("labels", gateway)
        self.assertIn(
            "/opt/mte-platform/bin/agent-plane-gateway.py:"
            "/app/agent-plane-gateway.py:ro",
            gateway["volumes"],
        )


if __name__ == "__main__":
    unittest.main()

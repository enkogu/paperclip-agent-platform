#!/usr/bin/env python3
"""Private fixed-route gateway from Daytona sandboxes to agent services.

The process runs in the Daytona runner network namespace. Nested sandbox
containers reach it through their bridge gateway (normally 172.20.0.1). It
never binds a host/public port and it can proxy only the four explicitly
declared upstreams. ToolHive routes require a distinct profile bearer token;
9Router continues to enforce its own profile-scoped API keys.
"""

from __future__ import annotations

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import urllib.error
import urllib.parse
import urllib.request


HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"missing required gateway ref {name}")
    return value


def integer(name: str) -> int:
    value = int(required(name))
    if not 1024 <= value <= 65535:
        raise RuntimeError(f"invalid gateway port ref {name}")
    return value


ROUTES = (
    {
        "name": "9router",
        "port": integer("MTE_AGENT_GATEWAY_NINEROUTER_PORT"),
        "upstream": required("MTE_AGENT_GATEWAY_NINEROUTER_UPSTREAM"),
        "token": "",
        "prefixes": ("/v1/", "/api/health"),
    },
    *(
        {
            "name": f"toolhive-{harness.lower()}",
            "port": integer(f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_PORT"),
            "upstream": required(f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_UPSTREAM"),
            "token": required(
                f"TOOLHIVE_PROFILE_CODING_DAYTONA_{harness}_BEARER_TOKEN"
            ),
            "prefixes": ("/mcp",),
        }
        for harness in ("CODEX", "CLAUDE", "PI")
    ),
)


def response(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    if handler.command != "HEAD":
        handler.wfile.write(body)


def handler_for(route: dict[str, object]):
    class Handler(BaseHTTPRequestHandler):
        server_version = "mte-agent-gateway/1"

        def do_GET(self):
            self.forward()

        def do_POST(self):
            self.forward()

        def do_DELETE(self):
            self.forward()

        def do_HEAD(self):
            self.forward()

        def forward(self) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path == "/healthz":
                response(self, 200, {"status": "ready", "route": route["name"]})
                return
            if not any(
                parsed.path.startswith(prefix)
                if str(prefix).endswith("/")
                else parsed.path == prefix or parsed.path.startswith(str(prefix) + "/")
                for prefix in route["prefixes"]
            ):
                response(self, 404, {"error": "route_not_allowed"})
                return
            token = str(route["token"])
            if token:
                supplied = self.headers.get("Authorization", "")
                expected = "Bearer " + token
                if not hmac.compare_digest(supplied, expected):
                    response(self, 401, {"error": "profile_identity_required"})
                    return
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length < 0 or length > 16_000_000:
                response(self, 413, {"error": "request_too_large"})
                return
            body = self.rfile.read(length) if length else None
            headers = {
                key: value
                for key, value in self.headers.items()
                if key.lower() not in HOP_HEADERS
                and key.lower() not in {"host", "content-length", "authorization"}
            }
            if not token and self.headers.get("Authorization"):
                headers["Authorization"] = self.headers["Authorization"]
            target = str(route["upstream"]).rstrip("/") + self.path
            request = urllib.request.Request(
                target, data=body, headers=headers, method=self.command
            )
            try:
                upstream = urllib.request.urlopen(request, timeout=300)
            except urllib.error.HTTPError as exc:
                upstream = exc
            except (urllib.error.URLError, TimeoutError, OSError):
                response(self, 502, {"error": "upstream_unavailable"})
                return
            with upstream:
                raw = upstream.read(64_000_001)
                if len(raw) > 64_000_000:
                    response(self, 502, {"error": "upstream_response_too_large"})
                    return
                self.send_response(upstream.status)
                for key, value in upstream.headers.items():
                    if (
                        key.lower() not in HOP_HEADERS
                        and key.lower() != "content-length"
                    ):
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(raw)

        def log_message(self, *_args) -> None:
            return

    return Handler


def main() -> None:
    servers = [
        ThreadingHTTPServer(("0.0.0.0", int(route["port"])), handler_for(route))
        for route in ROUTES
    ]
    threads = [threading.Thread(target=server.serve_forever) for server in servers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()

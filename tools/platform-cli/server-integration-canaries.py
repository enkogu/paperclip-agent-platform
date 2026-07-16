#!/usr/bin/env python3
"""Produce sanitized live evidence for cross-service integration canaries.

The controller runs on the deployment host. Long-lived credentials are read
only from canonical state or renderer-owned projections. Activepieces MCP
access tokens are deliberately short-lived: one is issued for each C013 run,
placed in a mode-0600 file inside the ToolHive manager, and removed together
with the remote workload in ``finally``. No expiring MCP token is persisted.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(os.environ.get("MTE_PLATFORM_ROOT", "/opt/mte-platform"))
SECRET_ROOT = Path(os.environ.get("MTE_SECRET_ROOT", "/root/.config/mte-secrets"))
CANONICAL = SECRET_ROOT / "platform.env"
SERVICES = SECRET_ROOT / "services"
EVIDENCE = ROOT / "evidence/integration-canaries.json"
SUPPORTED = ("C013", "C023", "C024", "C027", "C028", "C029", "C030")
ACTIVEPIECES_LIST_FLOWS_TOOL = "ap_list_flows"
POSTGREST_ACTIVEPIECES_VARIABLE = "MTE_POSTGREST_ACTIVEPIECES_TOKEN"
DEFAULT_DATA_CONTENT_PROFILE = "postgres-notion"
LEGACY_NOCODB_PROFILE = "postgres-postgrest-nocodb-nocodocs"
POSTGREST_DATA_PROFILES = frozenset(
    (DEFAULT_DATA_CONTENT_PROFILE, LEGACY_NOCODB_PROFILE)
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CanaryError(RuntimeError):
    def __init__(self, code: str, *, status: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def canonical_hash() -> str:
    return hashlib.sha256(CANONICAL.read_bytes()).hexdigest()


def producer_hash() -> str:
    path = Path(__file__)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def request_json(
    method: str,
    url: str,
    *,
    body: Any | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 45,
    allow_status: set[int] | None = None,
) -> tuple[int, Any]:
    request_headers = {"Accept": "application/json", **(headers or {})}
    data = json.dumps(body).encode() if body is not None else None
    if body is not None:
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(
        url, data=data, method=method, headers=request_headers
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(4_000_000)
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        if allow_status and exc.code in allow_status:
            return exc.code, None
        raise CanaryError("remote_http_error", status=exc.code) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CanaryError("remote_unavailable") from exc


def run(
    argv: list[str],
    *,
    input_text: str | None = None,
    environment: dict[str, str] | None = None,
    check: bool = True,
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    process_environment = None
    if environment:
        process_environment = {**os.environ, **environment}
    completed = subprocess.run(
        argv,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=process_environment,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode != 0:
        raise CanaryError("command_failed")
    return completed


def containers() -> list[tuple[str, str]]:
    output = run(
        ["docker", "ps", "--format", "{{.Names}}|{{.Image}}"]
    ).stdout.splitlines()
    return [tuple(line.split("|", 1)) for line in output if "|" in line]


def find_container(*, image: str = "", name: str = "") -> str:
    matches = [
        row_name
        for row_name, row_image in containers()
        if (not image or image.lower() in row_image.lower())
        and (not name or name.lower() in row_name.lower())
    ]
    if len(matches) != 1:
        raise CanaryError("container_not_unique")
    return matches[0]


def find_container_exact(name: str) -> str:
    matches = [row_name for row_name, _row_image in containers() if row_name == name]
    if len(matches) != 1:
        raise CanaryError("container_not_unique")
    return matches[0]


def toolhive_manager() -> str:
    matches = [
        name for name, _image in containers() if re.search(r"(?:^|-)toolhive-1$", name)
    ]
    if len(matches) != 1:
        raise CanaryError("toolhive_manager_not_unique")
    return matches[0]


def toolhive(
    manager: str,
    *args: str,
    input_text: str | None = None,
    secret_environment: dict[str, str] | None = None,
    check: bool = True,
    timeout: int = 240,
) -> subprocess.CompletedProcess[str]:
    exec_args = ["docker", "exec", "-i"]
    for key in sorted(secret_environment or {}):
        if not re.fullmatch(r"TOOLHIVE_SECRET_[A-Z0-9_]+", key):
            raise CanaryError("unsafe_toolhive_secret_name")
        exec_args.extend(["-e", key])
    exec_args.extend([manager, "thv", *args])
    return run(
        exec_args,
        input_text=input_text,
        environment=secret_environment,
        check=check,
        timeout=timeout,
    )


def write_manager_secret(manager: str, path: str, value: str) -> None:
    if "\x00" in value:
        raise CanaryError("unsafe_ephemeral_secret")
    run(
        [
            "docker",
            "exec",
            "-i",
            manager,
            "sh",
            "-c",
            f"umask 077; cat > {path}; chmod 600 {path}",
        ],
        input_text=value,
    )


def remove_manager_file(manager: str, path: str) -> None:
    run(
        ["docker", "exec", manager, "rm", "-f", path],
        check=False,
    )


def remove_toolhive_workload(manager: str, name: str) -> None:
    toolhive(manager, "rm", name, check=False, timeout=60)


def wait_toolhive_tool(
    manager: str, workload: str, tool_name: str, timeout: int = 60
) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = toolhive(
            manager,
            "mcp",
            "list",
            "tools",
            "--server",
            workload,
            "--format",
            "json",
            check=False,
            timeout=30,
        )
        if result.returncode == 0:
            try:
                payload = json.loads(result.stdout)
            except (json.JSONDecodeError, TypeError):
                payload = {}
            tools = payload.get("tools") if isinstance(payload, dict) else None
            names = {
                str(row.get("name"))
                for row in tools or []
                if isinstance(row, dict) and row.get("name")
            }
            if tool_name in names:
                return result.stdout
        time.sleep(1)
    raise CanaryError("toolhive_workload_not_ready")


def write_ephemeral_secret(path: Path, value: str) -> None:
    if not value or "\x00" in value:
        raise CanaryError("unsafe_ephemeral_secret")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, value.encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if path.stat().st_mode & 0o777 != 0o600:
        raise CanaryError("ephemeral_secret_mode_invalid")


def activepieces_stdio_bridge_code() -> str:
    return r"""
import json
import sys
import urllib.request

with open('/run/secret/token', encoding='utf-8') as source:
    token = source.read().strip()
if not token:
    raise SystemExit('missing token')

def response_payload(raw, content_type):
    if not raw:
        return None
    if 'text/event-stream' not in content_type:
        return json.loads(raw)
    for line in raw.splitlines():
        if line.startswith('data:'):
            return json.loads(line[5:].strip())
    raise RuntimeError('upstream_sse_data_missing')

for raw_line in sys.stdin:
    message = None
    try:
        message = json.loads(raw_line)
        request = urllib.request.Request(
            'http://activepieces/mcp',
            data=json.dumps(message, separators=(',', ':')).encode(),
            method='POST',
            headers={
                'Accept': 'application/json, text/event-stream',
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json',
            },
        )
        with urllib.request.urlopen(request, timeout=180) as upstream:
            payload = response_payload(
                upstream.read(4_000_000).decode(),
                upstream.headers.get('Content-Type', ''),
            )
        if payload is not None:
            sys.stdout.write(json.dumps(payload, separators=(',', ':')) + '\n')
            sys.stdout.flush()
    except Exception:
        request_id = message.get('id') if isinstance(message, dict) else None
        if request_id is not None:
            sys.stdout.write(json.dumps({
                'jsonrpc': '2.0',
                'id': request_id,
                'error': {'code': -32603, 'message': 'upstream_mcp_error'},
            }, separators=(',', ':')) + '\n')
            sys.stdout.flush()
"""


def activepieces_session(values: dict[str, str]) -> tuple[str, str, str]:
    base = "http://127.0.0.1:18090"
    _status, auth = request_json(
        "POST",
        f"{base}/api/v1/authentication/sign-in",
        body={
            "email": values["ACTIVEPIECES_ADMIN_EMAIL"],
            "password": values["ACTIVEPIECES_ADMIN_PASSWORD"],
        },
    )
    token = str((auth or {}).get("token") or "")
    project_id = str((auth or {}).get("projectId") or "")
    if not token or not project_id:
        raise CanaryError("activepieces_session_missing")
    return base, token, project_id


def c013(values: dict[str, str], run_id: str) -> dict[str, Any]:
    base, session, project_id = activepieces_session(values)
    _status, issued = request_json(
        "POST",
        f"{base}/api/v1/projects/{project_id}/mcp-server/token",
        headers={"Authorization": f"Bearer {session}"},
    )
    mcp_token = str((issued or {}).get("mcpToken") or "")
    if not mcp_token:
        raise CanaryError("activepieces_mcp_token_missing")
    manager = toolhive_manager()
    suffix = run_id[-8:].lower()
    workload = f"mte-ap-canary-{suffix}"
    token_path = ROOT / "toolhive/tmp" / f"{workload}.token"
    proxy_port = 19100 + int(hashlib.sha256(run_id.encode()).hexdigest()[:3], 16) % 400
    cleanup = {
        "workloadRemoved": False,
        "tokenFileRemoved": False,
    }
    try:
        write_ephemeral_secret(token_path, mcp_token)
        toolhive(
            manager,
            "run",
            "--name",
            workload,
            "--network",
            "host",
            "--isolate-network=false",
            "--proxy-port",
            str(proxy_port),
            "--permission-profile",
            "network",
            "--transport",
            "stdio",
            "--volume",
            f"{token_path}:/run/secret/token:ro",
            "python:3.13-slim",
            "--",
            "python",
            "-u",
            "-c",
            activepieces_stdio_bridge_code(),
            timeout=180,
        )
        tool_schema = wait_toolhive_tool(
            manager, workload, ACTIVEPIECES_LIST_FLOWS_TOOL
        )
        called = toolhive(
            manager,
            "mcp",
            "call",
            ACTIVEPIECES_LIST_FLOWS_TOOL,
            "--server",
            workload,
            "--args-file",
            "-",
            "--format",
            "json",
            input_text="{}",
            timeout=120,
        ).stdout
        return {
            "id": "C013",
            "ok": True,
            "state": "passed",
            "source": "toolhive_stdio_mcp_bridge_workload",
            "action": ACTIVEPIECES_LIST_FLOWS_TOOL,
            "toolSchemaSha256": hashlib.sha256(tool_schema.encode()).hexdigest(),
            "activepiecesProjectId": project_id,
            "bridgeTarget": "activepieces:80/mcp",
            "bridgeManagedByToolHive": True,
            "resultSha256": hashlib.sha256(called.encode()).hexdigest(),
            "shortLivedToken": True,
            "ephemeral0600TokenMount": True,
            "tokenPersisted": False,
            "cleanup": cleanup,
        }
    finally:
        remove_toolhive_workload(manager, workload)
        cleanup["workloadRemoved"] = True
        token_path.unlink(missing_ok=True)
        cleanup["tokenFileRemoved"] = not token_path.exists()
        mcp_token = ""


def c023(values: dict[str, str], run_id: str) -> dict[str, Any]:
    manager = toolhive_manager()
    suffix = run_id[-8:].lower()
    workload = f"mte-firecrawl-canary-{suffix}"
    env_file = f"/tmp/{workload}.env"
    marker = f"MTE-C023-{run_id}"
    proxy_port = 19500 + int(hashlib.sha256(run_id.encode()).hexdigest()[:3], 16) % 300
    cleanup = {
        "workloadRemoved": False,
        "envFileRemoved": False,
    }
    try:
        write_manager_secret(
            manager,
            env_file,
            "FIRECRAWL_API_KEY="
            + values["FIRECRAWL_API_KEY"]
            + "\nFIRECRAWL_API_URL=http://firecrawl-api:3002\n",
        )
        toolhive(
            manager,
            "run",
            "--name",
            workload,
            "--network",
            "host",
            "--isolate-network=false",
            "--permission-profile",
            "network",
            "--transport",
            "stdio",
            "--proxy-port",
            str(proxy_port),
            "--env-file",
            env_file,
            values["TOOLHIVE_FIRECRAWL_IMAGE"],
            timeout=240,
        )
        wait_toolhive_tool(manager, workload, "firecrawl_scrape", timeout=120)
        called = toolhive(
            manager,
            "mcp",
            "call",
            "firecrawl_scrape",
            "--server",
            workload,
            "--args-file",
            "-",
            "--format",
            "json",
            input_text=json.dumps(
                {
                    "url": "https://httpbin.org/anything/"
                    + urllib.parse.quote(marker, safe=""),
                    "formats": ["markdown"],
                    "onlyMainContent": False,
                }
            ),
            timeout=180,
        ).stdout
        if marker not in called:
            raise CanaryError("firecrawl_marker_not_observed")
        return {
            "id": "C023",
            "ok": True,
            "state": "passed",
            "source": "toolhive_firecrawl_mcp_public_echo",
            "action": "firecrawl_scrape",
            "controlledMarkerObserved": True,
            "resultSha256": hashlib.sha256(called.encode()).hexdigest(),
            "cleanup": cleanup,
        }
    finally:
        remove_toolhive_workload(manager, workload)
        cleanup["workloadRemoved"] = True
        remove_manager_file(manager, env_file)
        cleanup["envFileRemoved"] = True


def c024(_values: dict[str, str], run_id: str) -> dict[str, Any]:
    container = find_container(image="ghcr.io/firecrawl/firecrawl")
    script = r"""
const fs = require('fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const endpoint = String(process.env.SEARXNG_ENDPOINT || '').replace(/\/$/, '');
if (!endpoint) throw new Error('missing_searxng_endpoint');
fetch(endpoint + '/search?q=' + encodeURIComponent(input.query) + '&format=json')
  .then(async (response) => {
    const payload = await response.json();
    process.stdout.write(JSON.stringify({
      status: response.status,
      resultCount: Array.isArray(payload.results) ? payload.results.length : 0,
      responseKeys: Object.keys(payload).sort(),
      endpointScheme: endpoint.split(':', 1)[0],
    }));
    if (!response.ok || !Array.isArray(payload.results)) process.exitCode = 1;
  })
  .catch((error) => {
    process.stdout.write(JSON.stringify({status: 0, errorType: error.name}));
    process.exitCode = 1;
  });
"""
    payload: dict[str, Any] = {}
    attempt_count = 0
    for attempt_count in range(1, 4):
        completed = run(
            ["docker", "exec", "-i", container, "node", "-e", script],
            input_text=json.dumps({"query": "OpenAI"}),
            check=False,
            timeout=90,
        )
        try:
            candidate = json.loads(completed.stdout or "{}")
        except (json.JSONDecodeError, TypeError):
            candidate = {}
        payload = candidate if isinstance(candidate, dict) else {}
        ok = (
            completed.returncode == 0
            and payload.get("status") == 200
            and "results" in payload.get("responseKeys", [])
            and payload.get("resultCount", 0) > 0
        )
        if ok:
            break
        if attempt_count < 3:
            time.sleep(3)
    else:
        raise CanaryError("searxng_json_results_missing")
    return {
        "id": "C024",
        "ok": True,
        "state": "passed",
        "source": "firecrawl_api_container",
        "path": "SEARXNG_ENDPOINT/search?format=json",
        "httpStatus": payload.get("status"),
        "resultCount": payload.get("resultCount"),
        "responseKeys": payload.get("responseKeys"),
        "attemptCount": attempt_count,
    }


def list_value(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        for key in ("list", "data", "items", "results"):
            if isinstance(payload.get(key), list):
                return [row for row in payload[key] if isinstance(row, dict)]
    return []


def bound_component_evidence(
    script_name: str,
    evidence_name: str,
    expected_kind: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    script = ROOT / "bin" / script_name
    evidence_path = ROOT / "evidence" / evidence_name
    run([sys.executable, str(script), "verify"], timeout=900)
    if not script.is_file() or not evidence_path.is_file():
        raise CanaryError("ose_component_evidence_missing")
    info = evidence_path.stat()
    if info.st_mode & 0o777 != 0o600:
        raise CanaryError("ose_component_evidence_mode_invalid")
    if os.geteuid() == 0 and (info.st_uid != 0 or info.st_gid != 0):
        raise CanaryError("ose_component_evidence_owner_invalid")
    try:
        value = json.loads(evidence_path.read_text())
    except json.JSONDecodeError as exc:
        raise CanaryError("ose_component_evidence_invalid") from exc
    if (
        not isinstance(value, dict)
        or value.get("kind") != expected_kind
        or value.get("status") != "passed"
        or value.get("canonicalSourceSha256") != canonical_hash()
        or value.get("producerSha256")
        != hashlib.sha256(script.read_bytes()).hexdigest()
    ):
        raise CanaryError("ose_component_evidence_binding_invalid")
    reference = {
        "path": str(evidence_path),
        "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
        "kind": expected_kind,
        "producerSha256": str(value["producerSha256"]),
    }
    return value, reference


def _postgrest_dependency_reference() -> dict[str, str]:
    _value, reference = bound_component_evidence(
        "server-postgrest.py",
        "postgrest-verify.json",
        "PostgrestVerification",
    )
    return reference


def _jwt(values: dict[str, str], role: str, *, lifetime: int = 300) -> str:
    """Mint an in-memory PostgREST JWT without persisting or reporting it."""

    def encode(value: Any) -> str:
        return (
            base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
            .decode()
            .rstrip("=")
        )

    issued_at = int(time.time())
    header = encode({"alg": "HS256", "typ": "JWT"})
    payload = encode(
        {
            "role": role,
            "aud": values["POSTGREST_API_AUDIENCE"],
            "iat": issued_at,
            "exp": issued_at + lifetime,
        }
    )
    signature = hmac.new(
        values["POSTGREST_JWT_SECRET"].encode(),
        f"{header}.{payload}".encode(),
        hashlib.sha256,
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{header}.{payload}.{encoded_signature}"


def _postgrest_url(values: dict[str, str], table: str, external_id: str = "") -> str:
    base = f"http://127.0.0.1:{values['POSTGREST_ORIGIN_PORT']}/{table}"
    if not external_id:
        return base
    return (
        base + "?" + urllib.parse.urlencode({"external_object_id": f"eq.{external_id}"})
    )


def _single_postgrest_row(payload: Any, code: str) -> dict[str, Any]:
    rows = list_value(payload)
    if len(rows) != 1:
        raise CanaryError(code)
    return rows[0]


def _postgres_ssot_prepare(
    values: dict[str, str], run_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Create and update the canonical entity/document before projection.

    Raw deterministic canary values remain in memory. The returned evidence
    surface contains hashes only; the second result is private cleanup state.
    """

    token = _jwt(values, values["POSTGREST_WRITER_ROLE"])
    headers = {
        "Authorization": f"Bearer {token}",
        "Prefer": "return=representation",
    }
    specifications = {
        "record": {
            "table": "canonical_entities",
            "externalId": f"mte-notion-canary:{run_id}:record",
            "initialContent": f"mte-notion-canary:{run_id}:record:initial",
            "finalContent": f"mte-notion-canary:{run_id}:record:final",
        },
        "document": {
            "table": "canonical_documents",
            "externalId": f"mte-notion-canary:{run_id}:document",
            "initialContent": f"mte-notion-canary:{run_id}:document:initial",
            "finalContent": f"mte-notion-canary:{run_id}:document:final",
        },
    }
    private: dict[str, Any] = {"specifications": specifications}
    evidence: dict[str, Any] = {}
    try:
        for kind, specification in specifications.items():
            initial_hash = hashlib.sha256(
                specification["initialContent"].encode()
            ).hexdigest()
            final_hash = hashlib.sha256(
                specification["finalContent"].encode()
            ).hexdigest()
            common = {
                "external_object_id": specification["externalId"],
                "title": "MTE Notion connector canary",
                "revision": 1,
                "content_hash": initial_hash,
                "metadata": {"canary": True},
            }
            if kind == "record":
                create_body = {
                    **common,
                    "entity_type": "integration_canary",
                    "data": {"content": specification["initialContent"]},
                }
                update_body = {
                    "revision": 2,
                    "content_hash": final_hash,
                    "data": {"content": specification["finalContent"]},
                }
            else:
                create_body = {
                    **common,
                    "body": specification["initialContent"],
                    "content_type": "text/markdown",
                }
                update_body = {
                    "revision": 2,
                    "content_hash": final_hash,
                    "body": specification["finalContent"],
                }
            create_status, created = request_json(
                "POST",
                _postgrest_url(values, specification["table"]),
                body=create_body,
                headers=headers,
            )
            created_row = _single_postgrest_row(
                created, "postgres_ssot_create_response_invalid"
            )
            read_status, read_value = request_json(
                "GET",
                _postgrest_url(
                    values, specification["table"], specification["externalId"]
                ),
                headers={"Authorization": headers["Authorization"]},
            )
            read_row = _single_postgrest_row(
                read_value, "postgres_ssot_read_response_invalid"
            )
            update_status, updated = request_json(
                "PATCH",
                _postgrest_url(
                    values, specification["table"], specification["externalId"]
                ),
                body=update_body,
                headers=headers,
            )
            updated_row = _single_postgrest_row(
                updated, "postgres_ssot_update_response_invalid"
            )
            if (
                create_status != 201
                or read_status != 200
                or update_status != 200
                or created_row.get("external_object_id") != specification["externalId"]
                or created_row.get("revision") != 1
                or created_row.get("content_hash") != initial_hash
                or read_row.get("id") != created_row.get("id")
                or read_row.get("revision") != 1
                or read_row.get("content_hash") != initial_hash
                or updated_row.get("id") != created_row.get("id")
                or updated_row.get("revision") != 2
                or updated_row.get("content_hash") != final_hash
            ):
                raise CanaryError("postgres_ssot_linkage_invalid")
            if kind == "record":
                content_matches = (updated_row.get("data") or {}).get(
                    "content"
                ) == specification["finalContent"]
            else:
                content_matches = (
                    updated_row.get("body") == specification["finalContent"]
                )
            if not content_matches:
                raise CanaryError("postgres_ssot_content_invalid")
            _sync_status, sync_value = request_json(
                "GET",
                _postgrest_url(
                    values, "provider_sync_state", specification["externalId"]
                ),
                headers={"Authorization": headers["Authorization"]},
            )
            sync_row = _single_postgrest_row(
                sync_value, "postgres_projection_intent_missing"
            )
            if (
                sync_row.get("provider") != "notion"
                or sync_row.get("object_kind")
                != ("entity" if kind == "record" else "document")
                or sync_row.get("canonical_object_id") != created_row.get("id")
                or sync_row.get("external_object_id") != specification["externalId"]
                or sync_row.get("canonical_revision") != 2
                or sync_row.get("canonical_content_hash") != final_hash
                or sync_row.get("desired_operation") != "upsert"
            ):
                raise CanaryError("postgres_projection_intent_invalid")
            evidence[kind] = {
                "objectIdSha256": hashlib.sha256(
                    specification["externalId"].encode()
                ).hexdigest(),
                "initialRevision": 1,
                "finalRevision": 2,
                "initialContentSha256": initial_hash,
                "finalContentSha256": final_hash,
                "created": True,
                "readBackVerified": True,
                "updated": True,
                "projectionIntentVerified": True,
            }
        return evidence, private
    except BaseException:
        _postgres_ssot_cleanup(values, private)
        raise
    finally:
        token = ""


def _postgres_ssot_cleanup(
    values: dict[str, str], private: dict[str, Any]
) -> dict[str, bool]:
    specifications = dict(private.get("specifications") or {})
    if not specifications:
        return {
            "postgresRecordDeleted": False,
            "postgresDocumentDeleted": False,
            "postgresProjectionRowsDeleted": False,
            "verified": False,
        }
    cleanup_token = _jwt(values, values["POSTGREST_WRITER_ROLE"])
    auth_headers = {"Authorization": f"Bearer {cleanup_token}"}
    absent: dict[str, bool] = {}
    for kind, specification in specifications.items():
        request_json(
            "DELETE",
            _postgrest_url(values, specification["table"], specification["externalId"]),
            headers=auth_headers,
        )
        _status, after = request_json(
            "GET",
            _postgrest_url(values, specification["table"], specification["externalId"]),
            headers=auth_headers,
        )
        absent[kind] = after == []
    projection_absent = True
    for table in ("provider_outbox", "provider_sync_state"):
        for specification in specifications.values():
            url = _postgrest_url(values, table, specification["externalId"])
            request_json("DELETE", url, headers=auth_headers)
            _status, after = request_json("GET", url, headers=auth_headers)
            projection_absent = projection_absent and after == []
    result = {
        "postgresRecordDeleted": absent.get("record") is True,
        "postgresDocumentDeleted": absent.get("document") is True,
        "postgresProjectionRowsDeleted": projection_absent,
        "verified": all(absent.values()) and projection_absent,
    }
    cleanup_token = ""
    return result


def _notion_runtime_payload(values: dict[str, str], run_id: str) -> dict[str, Any]:
    script = ROOT / "bin/server-notion.py"
    evidence_path = ROOT / "evidence/notion-connector-verify.json"
    if not script.is_file():
        raise CanaryError("notion_connector_producer_missing")
    completed = run(
        [sys.executable, str(script), "canary", "--run-id", run_id, "--json"],
        timeout=900,
    )
    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise CanaryError("notion_connector_result_invalid") from exc
    if not isinstance(payload, dict):
        raise CanaryError("notion_connector_result_invalid")
    serialized = json.dumps(payload, sort_keys=True)
    secret_values = [
        value
        for key, value in values.items()
        if re.search(r"(?:TOKEN|SECRET|PASSWORD|API_KEY|LICENSE_KEY)$", key)
        and len(value) >= 8
    ]
    if any(secret in serialized for secret in secret_values):
        raise CanaryError("notion_connector_secret_leak")
    if (
        payload.get("kind") != "NotionConnectorCanary"
        or payload.get("status") != "passed"
        or payload.get("dataContentProfile") != DEFAULT_DATA_CONTENT_PROFILE
        or payload.get("canonicalSourceSha256") != canonical_hash()
        or payload.get("producerSha256")
        != hashlib.sha256(script.read_bytes()).hexdigest()
        or payload.get("redacted") is not True
    ):
        raise CanaryError("notion_connector_binding_invalid")
    if not evidence_path.is_file() or evidence_path.is_symlink():
        raise CanaryError("notion_connector_evidence_missing")
    info = evidence_path.stat()
    if info.st_mode & 0o777 != 0o600:
        raise CanaryError("notion_connector_evidence_mode_invalid")
    if os.geteuid() == 0 and (info.st_uid != 0 or info.st_gid != 0):
        raise CanaryError("notion_connector_evidence_owner_invalid")
    try:
        persisted = json.loads(evidence_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise CanaryError("notion_connector_evidence_invalid") from exc
    if (
        not isinstance(persisted, dict)
        or persisted.get("kind") != "NotionConnectorVerification"
        or persisted.get("status") != "passed"
        or persisted.get("ok") is not True
        or persisted.get("dataContentProfile") != DEFAULT_DATA_CONTENT_PROFILE
        or persisted.get("canonicalSourceSha256") != canonical_hash()
        or persisted.get("producerSha256")
        != hashlib.sha256(script.read_bytes()).hexdigest()
        or persisted.get("canary") != payload
        or persisted.get("redacted") is not True
        or (persisted.get("cleanup") or {}).get("verified") is not True
    ):
        raise CanaryError("notion_connector_evidence_binding_invalid")
    persisted_serialized = json.dumps(persisted, sort_keys=True)
    if any(secret in persisted_serialized for secret in secret_values):
        raise CanaryError("notion_connector_evidence_secret_leak")
    payload["_resultSha256"] = hashlib.sha256(completed.stdout.encode()).hexdigest()
    payload["_producerPath"] = str(script)
    payload["_evidenceReference"] = {
        "path": str(evidence_path),
        "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
        "kind": "NotionConnectorVerification",
        "producerSha256": str(persisted["producerSha256"]),
    }
    return payload


def _linked_notion_projection(
    postgres: dict[str, Any], notion_payload: dict[str, Any]
) -> dict[str, Any]:
    linkage = dict(notion_payload.get("linkage") or {})
    table = dict((notion_payload.get("notion") or {}).get("table") or {})
    document = dict((notion_payload.get("notion") or {}).get("document") or {})
    cleanup = dict(notion_payload.get("cleanup") or {})
    for kind in ("record", "document"):
        candidate = dict(linkage.get(kind) or {})
        expected = postgres[kind]
        if any(
            candidate.get(key) != expected[key]
            for key in (
                "objectIdSha256",
                "initialRevision",
                "finalRevision",
                "initialContentSha256",
                "finalContentSha256",
            )
        ):
            raise CanaryError("notion_postgres_linkage_mismatch")
        if not all(
            SHA256.fullmatch(str(candidate.get(key) or ""))
            for key in (
                "objectIdSha256",
                "initialContentSha256",
                "finalContentSha256",
            )
        ):
            raise CanaryError("notion_linkage_hash_invalid")
    table_required = (
        "created",
        "queryVerified",
        "updated",
        "archived",
        "cleanupVerified",
        "objectIdMatches",
        "initialRevisionMatches",
        "finalRevisionMatches",
        "initialContentSha256Matches",
        "finalContentSha256Matches",
    )
    document_required = (
        "created",
        "appendVerified",
        "readBackVerified",
        "archived",
        "cleanupVerified",
        "objectIdMatches",
        "initialRevisionMatches",
        "finalRevisionMatches",
        "initialContentSha256Matches",
        "finalContentSha256Matches",
    )
    if not all(table.get(key) is True for key in table_required):
        raise CanaryError("notion_table_acceptance_invalid")
    if not all(document.get(key) is True for key in document_required):
        raise CanaryError("notion_document_acceptance_invalid")
    if not all(
        cleanup.get(key) is True
        for key in ("notionTableRowArchived", "notionDocumentArchived", "verified")
    ):
        raise CanaryError("notion_connector_cleanup_invalid")
    page_ids = (str(table.get("pageId") or ""), str(document.get("pageId") or ""))
    if not all(page_ids) or page_ids[0] == page_ids[1]:
        raise CanaryError("notion_connector_page_identity_invalid")
    return {
        "table": {
            "pageIdSha256": hashlib.sha256(page_ids[0].encode()).hexdigest(),
            **{
                key: linkage["record"][key]
                for key in (
                    "objectIdSha256",
                    "initialRevision",
                    "finalRevision",
                    "initialContentSha256",
                    "finalContentSha256",
                )
            },
            **{key: True for key in table_required},
            "linkageVerified": True,
        },
        "document": {
            "pageIdSha256": hashlib.sha256(page_ids[1].encode()).hexdigest(),
            **{
                key: linkage["document"][key]
                for key in (
                    "objectIdSha256",
                    "initialRevision",
                    "finalRevision",
                    "initialContentSha256",
                    "finalContentSha256",
                )
            },
            **{key: True for key in document_required},
            "linkageVerified": True,
        },
        "cleanup": {
            "notionTableRowArchived": True,
            "notionDocumentArchived": True,
            "verified": True,
        },
    }


def _c029_postgres_notion(values: dict[str, str], run_id: str) -> dict[str, Any]:
    postgrest_reference = _postgrest_dependency_reference()
    # The aggregate evidence intentionally retains its control run ID. Use a
    # one-way-derived, separate linkage ID so neither that ID nor the raw
    # deterministic Notion/PostgreSQL markers can appear in stored evidence.
    linkage_run_id = hashlib.sha256(f"C029:{run_id}".encode()).hexdigest()[:24]
    postgres, private = _postgres_ssot_prepare(values, linkage_run_id)
    postgres_cleanup: dict[str, bool] = {}
    try:
        notion_payload = _notion_runtime_payload(values, linkage_run_id)
        notion = _linked_notion_projection(postgres, notion_payload)
    finally:
        postgres_cleanup = _postgres_ssot_cleanup(values, private)
    if postgres_cleanup.get("verified") is not True:
        raise CanaryError("postgres_ssot_cleanup_invalid")
    for value in postgres.values():
        value.update(
            {
                "postDeleteAbsent": True,
                "cleanupVerified": True,
            }
        )
    cleanup = {
        **postgres_cleanup,
        **notion["cleanup"],
        "verified": postgres_cleanup["verified"] and notion["cleanup"]["verified"],
    }
    return {
        "id": "C029",
        "ok": True,
        "state": "passed",
        "source": "server_notion_connector_canary",
        "dataContentProfile": DEFAULT_DATA_CONTENT_PROFILE,
        "roles": {
            "tablesUi": "notion",
            "tablesApi": "notion",
            "documentsUi": "notion",
            "documentsApi": "notion",
        },
        "internalApis": {"scopedDataApi": "postgrest"},
        "postgresSsot": postgres,
        "notion": {
            "table": notion["table"],
            "document": notion["document"],
        },
        "tablePersistenceVerified": True,
        "documentPersistenceVerified": True,
        "crossProviderLinkageVerified": True,
        "cleanupCompleted": cleanup["verified"],
        "cleanup": cleanup,
        "redacted": True,
        "dependencyEvidence": notion_payload["_evidenceReference"],
        "internalApiEvidence": postgrest_reference,
    }


def c029(_values: dict[str, str], _run_id: str) -> dict[str, Any]:
    profile = _values.get("DATA_CONTENT_PROFILE", "")
    if profile == DEFAULT_DATA_CONTENT_PROFILE:
        return _c029_postgres_notion(_values, _run_id)
    if profile == LEGACY_NOCODB_PROFILE:
        postgrest, postgrest_ref = bound_component_evidence(
            "server-postgrest.py", "postgrest-verify.json", "PostgrestVerification"
        )
        nocodb, nocodb_ref = bound_component_evidence(
            "server-nocodb.py",
            "nocodb-verify.json",
            "NocoDbNocoDocsVerification",
        )
        tables = dict(postgrest.get("persistence") or {})
        visibility = dict(nocodb.get("dataState") or {})
        documents = dict(nocodb.get("documentsApi") or {})
        if not all(
            (
                tables.get("restartObserved") is True,
                tables.get("persistenceVerified") is True,
                tables.get("postDeleteAbsent") is True,
                tables.get("cleanupCompleted") is True,
                visibility.get("owner") == "postgres-postgrest",
                visibility.get("nocodbUniqueTableState") is False,
                visibility.get("postgrestCreated") is True,
                visibility.get("nocodbDiagnosticReadVisible") is True,
                visibility.get("cleanupCompleted") is True,
                documents.get("endpoint") == "/api/v3/docs",
                documents.get("restartObserved") is True,
                documents.get("persistenceVerified") is True,
                documents.get("postDeleteAbsent") is True,
                documents.get("cleanupCompleted") is True,
            )
        ):
            raise CanaryError("data_content_persistence_invalid")
        release = dict(nocodb.get("release") or {})
        return {
            "id": "C029",
            "ok": True,
            "state": "passed",
            "source": "controlled_data_content_application_restarts",
            "dataContentProfile": profile,
            "roles": {
                "tablesUi": "nocodb",
                "tablesApi": "postgrest",
                "documentsUi": "nocodb",
                "documentsApi": "nocodb",
            },
            "tablesPersistence": {
                **tables,
                "nocodbVisibilityVerified": True,
                "singlePostgresStateVerified": True,
            },
            "documentsPersistence": documents,
            "licenses": [
                {
                    "component": "postgrest",
                    "license": "MIT",
                    "image": postgrest["release"]["image"],
                    "exception": None,
                },
                {
                    "component": "nocodb",
                    "license": release["license"],
                    "image": release["image"],
                    "exception": release["exception"],
                },
            ],
            "applicationRestartObserved": True,
            "tablePersistenceVerified": True,
            "documentPersistenceVerified": True,
            "cleanupCompleted": True,
            "dependencyEvidence": {
                "postgrest": postgrest_ref,
                "nocodb": nocodb_ref,
            },
        }
    if profile != "baserow-wikijs":
        raise CanaryError("data_content_profile_unsupported")
    baserow, baserow_ref = bound_component_evidence(
        "server-baserow.py", "baserow-verify.json", "BaserowAcceptance"
    )
    wikijs, wikijs_ref = bound_component_evidence(
        "server-wikijs.py", "wikijs-verify.json", "WikiJsVerification"
    )
    baserow_persistence = dict(baserow.get("baserowPersistence") or {})
    wiki_graphql = dict(wikijs.get("graphql") or {})
    required_true = (
        baserow_persistence.get("restartObserved") is True,
        baserow_persistence.get("persistenceVerified") is True,
        baserow_persistence.get("postDeleteStatus") == 404,
        baserow_persistence.get("cleanupCompleted") is True,
        wiki_graphql.get("restartObserved") is True,
        wiki_graphql.get("persistenceVerified") is True,
        wiki_graphql.get("postDeleteStatus404") == 404,
        wiki_graphql.get("cleanupCompleted") is True,
    )
    if not all(required_true):
        raise CanaryError("ose_data_content_persistence_invalid")
    distribution = dict(baserow.get("distribution") or {})
    wiki_image = dict(wikijs.get("image") or {})
    return {
        "id": "C029",
        "ok": True,
        "state": "passed",
        "source": "controlled_ose_application_restarts",
        "dataContentProfile": profile,
        "roles": {
            "tablesUi": "baserow",
            "tablesApi": "baserow",
            "documentsUi": "wikijs",
            "documentsApi": "wikijs",
        },
        "tablesPersistence": {
            "markerSha256": baserow_persistence["markerSha256"],
            "restartObserved": baserow_persistence["restartObserved"],
            "persistenceVerified": baserow_persistence["persistenceVerified"],
            "postDeleteAbsent": baserow_persistence["postDeleteStatus"] == 404,
            "cleanupCompleted": baserow_persistence["cleanupCompleted"],
        },
        "documentsPersistence": {
            "markerSha256": wiki_graphql["markerSha256"],
            "restartObserved": wiki_graphql["restartObserved"],
            "persistenceVerified": wiki_graphql["persistenceVerified"],
            "postDeleteAbsent": wiki_graphql["postDeleteStatus404"] == 404,
            "cleanupCompleted": wiki_graphql["cleanupCompleted"],
        },
        "baserowPersistence": {
            key: baserow_persistence[key]
            for key in (
                "databaseId",
                "tableId",
                "rowId",
                "markerSha256",
                "restartObserved",
                "persistenceVerified",
                "postDeleteStatus",
                "cleanupCompleted",
            )
        },
        "wikijsPersistence": {
            "pageId": wiki_graphql["pageId"],
            "pathHashSha256": wiki_graphql["pathHashSha256"],
            "markerSha256": wiki_graphql["markerSha256"],
            "restartObserved": wiki_graphql["restartObserved"],
            "persistenceVerified": wiki_graphql["persistenceVerified"],
            "postDeleteStatus": wiki_graphql["postDeleteStatus404"],
            "cleanupCompleted": wiki_graphql["cleanupCompleted"],
        },
        "osiLicenses": [
            {
                "component": "baserow",
                "version": distribution["version"],
                "spdx": distribution["license"],
                "imageDigest": distribution["image"].split("@", 1)[1],
                "verified": distribution.get("enterpriseLicenseConfigured") is False,
            },
            {
                "component": "wikijs",
                "version": wiki_image["version"],
                "spdx": wiki_image["license"]["spdx"],
                "imageDigest": wiki_image["digest"],
                "verified": True,
            },
        ],
        "applicationRestartObserved": True,
        "tablePersistenceVerified": True,
        "documentPersistenceVerified": True,
        "cleanupCompleted": True,
        "dependencyEvidence": {
            "baserow": baserow_ref,
            "wikijs": wikijs_ref,
        },
    }


def paperclip_project(values: dict[str, str]) -> dict[str, Any]:
    headers = {}
    if values.get("PAPERCLIP_BOARD_API_KEY"):
        headers["Authorization"] = f"Bearer {values['PAPERCLIP_BOARD_API_KEY']}"
    _status, project = request_json(
        "GET",
        f"http://127.0.0.1:3100/api/projects/{values['PAPERCLIP_PROJECT_ID']}",
        headers=headers,
    )
    if not isinstance(project, dict):
        raise CanaryError("paperclip_project_missing")
    return project


def paperclip_headers(values: dict[str, str]) -> dict[str, str]:
    token = values.get("PAPERCLIP_BOARD_API_KEY", "")
    return {"Authorization": f"Bearer {token}"} if token else {}


def paperclip_request(
    values: dict[str, str], method: str, path: str, body: Any | None = None
) -> Any:
    _status, value = request_json(
        method,
        "http://127.0.0.1:3100" + path,
        headers=paperclip_headers(values),
        body=body,
    )
    return value


def ensure_paperclip_canary_agent(
    values: dict[str, str], company_id: str
) -> dict[str, Any]:
    agents = list_value(
        paperclip_request(values, "GET", f"/api/companies/{company_id}/agents")
    )
    name = "MTE Integration Canary (process)"
    agent = next((row for row in agents if row.get("name") == name), None)
    paperclip_port = int(values.get("PAPERCLIP_PORT") or 0)
    if not 1024 <= paperclip_port <= 65535:
        raise CanaryError("paperclip_origin_port_invalid")
    adapter_config = {
        "command": "python3",
        "args": ["/prototype/scripts/integration_canary.py"],
        "cwd": "/prototype",
        "env": {},
        "timeoutSec": 180,
        "graceSec": 5,
    }
    adapter_config["env"]["PAPERCLIP_API_URL"] = {
        "type": "plain",
        "value": f"http://127.0.0.1:{paperclip_port}",
    }
    body = {
        "name": name,
        "title": "Integration Canary Worker",
        "role": "operator",
        "adapterType": "process",
        "adapterConfig": adapter_config,
        "runtimeConfig": {
            "heartbeat": {
                "enabled": False,
                "wakeOnDemand": True,
                "maxConcurrentRuns": 1,
            }
        },
        "budgetMonthlyCents": 0,
        "metadata": {
            "managedBy": "mte-integration-canary-producer",
            "purpose": "secret-ref cross-service evidence",
        },
    }
    if agent is None:
        created = paperclip_request(
            values, "POST", f"/api/companies/{company_id}/agents", body
        )
        agent = created.get("agent", created) if isinstance(created, dict) else created
    elif (
        agent.get("adapterType") != "process"
        or agent.get("adapterConfig") != adapter_config
        or (agent.get("metadata") or {}).get("managedBy")
        != "mte-integration-canary-producer"
    ):
        updated = paperclip_request(
            values,
            "PATCH",
            f"/api/agents/{agent['id']}",
            {**body, "replaceAdapterConfig": True},
        )
        if isinstance(updated, dict):
            agent = updated.get("agent", updated)
    if not isinstance(agent, dict) or not agent.get("id"):
        raise CanaryError("paperclip_canary_agent_missing")
    return agent


def parse_document_json(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CanaryError("paperclip_canary_result_missing")
    body = str(value.get("body") or "")
    match = re.search(r"```json\s*(\{.*\})\s*```", body, re.DOTALL)
    if not match:
        raise CanaryError("paperclip_canary_result_invalid")
    try:
        result = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        raise CanaryError("paperclip_canary_result_invalid") from exc
    if not isinstance(result, dict):
        raise CanaryError("paperclip_canary_result_invalid")
    return result


def paperclip_secret_access_proof(
    values: dict[str, str],
    *,
    secret_id: str,
    project_id: str,
    agent_id: str,
    issue_id: str,
    heartbeat_run_id: str,
    env_key: str,
) -> dict[str, Any]:
    events = list_value(
        paperclip_request(values, "GET", f"/api/secrets/{secret_id}/access-events")
    )
    event = next(
        (
            row
            for row in reversed(events)
            if str(row.get("consumerType") or "") == "project"
            and str(row.get("consumerId") or "") == project_id
            and str(row.get("configPath") or "") == f"env.{env_key}"
            and str(row.get("issueId") or "") == issue_id
            and str(row.get("heartbeatRunId") or "") == heartbeat_run_id
            and str(row.get("actorType") or "") == "agent"
            and str(row.get("actorId") or "") == agent_id
            and str(row.get("outcome") or "").lower() == "success"
        ),
        None,
    )
    if event is None:
        raise CanaryError("paperclip_secret_access_event_missing")
    return {
        "id": str(event.get("id") or ""),
        "consumerType": "project",
        "configPath": f"env.{env_key}",
        "actorType": "agent",
        "outcome": "success",
    }


def _paperclip_integration_run(
    values: dict[str, str], run_id: str, action: str, action_input: dict[str, Any]
) -> dict[str, Any]:
    project = paperclip_project(values)
    project_id = str(project.get("id") or "")
    company_id = str(project.get("companyId") or "")
    if not project_id or not company_id:
        raise CanaryError("paperclip_project_context_missing")
    required_env = {
        "baserow_crud": (
            "BASEROW_API_TOKEN",
            "PAPERCLIP_SECRET_MTE_BASEROW_PAPERCLIP_ID",
        ),
        "postgrest_crud": (
            "POSTGREST_API_TOKEN",
            "PAPERCLIP_SECRET_MTE_POSTGREST_PAPERCLIP_ID",
        ),
        "mattermost_notification": (
            "MATTERMOST_BOT_TOKEN",
            "PAPERCLIP_SECRET_MTE_MATTERMOST_BOT_ID",
        ),
    }
    if action not in required_env:
        raise CanaryError("paperclip_canary_action_unknown")
    env_key, canonical_id_key = required_env[action]
    binding = (project.get("env") or {}).get(env_key)
    expected_secret_id = values.get(canonical_id_key, "")
    if (
        not isinstance(binding, dict)
        or binding.get("type") != "secret_ref"
        or not expected_secret_id
        or str(binding.get("secretId") or "") != expected_secret_id
    ):
        raise CanaryError("paperclip_project_secret_ref_mismatch")
    agent = ensure_paperclip_canary_agent(values, company_id)
    description = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "MTEIntegrationCanaryInput",
        "action": action,
        "controlRunId": run_id,
        **action_input,
    }
    issue = paperclip_request(
        values,
        "POST",
        f"/api/companies/{company_id}/issues",
        {
            "title": f"[MTE integration canary {action}] {run_id}",
            "description": json.dumps(description, sort_keys=True),
            "status": "todo",
            "priority": "medium",
            "assigneeAgentId": agent["id"],
            "projectId": project_id,
        },
    )
    issue_id = str((issue or {}).get("id") or "")
    if not issue_id:
        raise CanaryError("paperclip_canary_task_missing")
    latest_run: dict[str, Any] = {}
    deadline = time.monotonic() + 210
    while time.monotonic() < deadline:
        issue = paperclip_request(values, "GET", f"/api/issues/{issue_id}")
        runs = list_value(
            paperclip_request(values, "GET", f"/api/issues/{issue_id}/runs")
        )
        if runs:
            latest_run = max(runs, key=lambda row: str(row.get("createdAt") or ""))
        issue_status = str((issue or {}).get("status") or "")
        run_status = str(latest_run.get("status") or "")
        if issue_status == "done" and run_status in {"succeeded", "running", ""}:
            break
        if issue_status in {"blocked", "cancelled"} or run_status in {
            "failed",
            "timed_out",
            "cancelled",
        }:
            raise CanaryError("paperclip_canary_run_failed")
        time.sleep(1)
    else:
        raise CanaryError("paperclip_canary_run_timeout")
    native_run_id = str(latest_run.get("id") or "")
    if not native_run_id:
        raise CanaryError("paperclip_canary_native_run_missing")
    document = paperclip_request(
        values,
        "GET",
        f"/api/issues/{issue_id}/documents/integration-canary-result",
    )
    result = parse_document_json(document)
    if (
        str(result.get("taskId") or "") != issue_id
        or str(result.get("heartbeatRunId") or "") != native_run_id
        or result.get("action") != action
        or result.get("credentialSource") != "paperclip_project_secret_ref"
    ):
        raise CanaryError("paperclip_canary_result_mismatch")
    access_event = paperclip_secret_access_proof(
        values,
        secret_id=expected_secret_id,
        project_id=project_id,
        agent_id=str(agent["id"]),
        issue_id=issue_id,
        heartbeat_run_id=native_run_id,
        env_key=env_key,
    )
    return {
        "project": project,
        "agent": agent,
        "issue": issue,
        "heartbeatRun": latest_run,
        "result": result,
        "envKey": env_key,
        "secretId": expected_secret_id,
        "secretAccessEvent": access_event,
    }


def cleanup_paperclip_canary_run(
    values: dict[str, str], run_id: str, action: str, run_value: dict[str, Any] | None
) -> dict[str, Any]:
    if run_value:
        issues = [run_value["issue"]]
    else:
        project = paperclip_project(values)
        company_id = str(project.get("companyId") or "")
        issues = [
            row
            for row in list_value(
                paperclip_request(
                    values,
                    "GET",
                    f"/api/companies/{company_id}/issues?projectId={project['id']}",
                )
            )
            if row.get("title") == f"[MTE integration canary {action}] {run_id}"
        ]
    cleanup = {"runTerminalOrCancelled": True, "issueDeleted": True}
    for issue in issues:
        issue_id = str(issue.get("id") or "")
        if not issue_id:
            continue
        runs = list_value(
            paperclip_request(values, "GET", f"/api/issues/{issue_id}/runs")
        )
        for heartbeat_run in runs:
            native_id = str(heartbeat_run.get("id") or "")
            status = str(heartbeat_run.get("status") or "")
            if native_id and status not in {
                "succeeded",
                "failed",
                "timed_out",
                "cancelled",
            }:
                cancel_status, _cancelled = request_json(
                    "POST",
                    f"http://127.0.0.1:3100/api/heartbeat-runs/{native_id}/cancel",
                    headers=paperclip_headers(values),
                    allow_status={404, 409},
                )
                cleanup["runTerminalOrCancelled"] = cancel_status in {
                    200,
                    201,
                    204,
                    404,
                    409,
                }
        request_json(
            "DELETE",
            f"http://127.0.0.1:3100/api/issues/{issue_id}",
            headers=paperclip_headers(values),
            allow_status={404},
        )
        after_status, _after = request_json(
            "GET",
            f"http://127.0.0.1:3100/api/issues/{issue_id}",
            headers=paperclip_headers(values),
            allow_status={404},
        )
        cleanup["issueDeleted"] = cleanup["issueDeleted"] and after_status == 404
    if not all(cleanup.values()):
        raise CanaryError("paperclip_canary_cleanup_incomplete")
    return cleanup


def paperclip_integration_run(
    values: dict[str, str], run_id: str, action: str, action_input: dict[str, Any]
) -> dict[str, Any]:
    run_value: dict[str, Any] | None = None
    try:
        run_value = _paperclip_integration_run(values, run_id, action, action_input)
        return run_value
    finally:
        cleanup = cleanup_paperclip_canary_run(values, run_id, action, run_value)
        if run_value is not None:
            run_value["cleanup"] = cleanup


def c027(values: dict[str, str], run_id: str) -> dict[str, Any]:
    profile = values.get("DATA_CONTENT_PROFILE", "")
    if profile in POSTGREST_DATA_PROFILES:
        run_value = paperclip_integration_run(
            values,
            run_id,
            "postgrest_crud",
            {
                "postgrestApiBase": (
                    "http://127.0.0.1:" + values["POSTGREST_ORIGIN_PORT"]
                )
            },
        )
        result = run_value["result"]
        if (
            result.get("markerObserved") is not True
            or result.get("cleanup") != "verified_deleted"
            or result.get("postDeleteAbsent") is not True
        ):
            raise CanaryError("paperclip_postgrest_crud_failed")
        postgrest_reference = _postgrest_dependency_reference()
        return {
            "id": "C027",
            "ok": True,
            "state": "passed",
            "source": "paperclip_process_heartbeat_run",
            "dataContentProfile": profile,
            "tablesApiComponent": "postgrest",
            "paperclipTaskId": str(run_value["issue"]["id"]),
            "paperclipHeartbeatRunId": str(run_value["heartbeatRun"]["id"]),
            "paperclipAgentId": str(run_value["agent"]["id"]),
            "paperclipProjectId": str(run_value["project"]["id"]),
            "bindingType": "secret_ref",
            "secretIdMatchesManaged": True,
            "credentialResolvedBy": "paperclip_runtime",
            "secretAccessEventVerified": True,
            "secretAccessEventId": str(run_value["secretAccessEvent"]["id"]),
            "createStatus": result.get("createStatus"),
            "readStatus": result.get("readStatus"),
            "deleteStatus": result.get("deleteStatus"),
            "postDeleteStatus": result.get("postDeleteStatus"),
            "postDeleteAbsent": True,
            "markerObserved": True,
            "cleanup": "verified_deleted",
            "paperclipCleanup": run_value["cleanup"],
            "dependencyEvidence": postgrest_reference,
        }
    if profile != "baserow-wikijs":
        raise CanaryError("data_content_profile_unsupported")
    run_value = paperclip_integration_run(
        values,
        run_id,
        "baserow_crud",
        {
            "baserowApiBase": ("http://127.0.0.1:" + values["BASEROW_ORIGIN_PORT"]),
            "baserowTableId": values["BASEROW_TABLE_ID"],
        },
    )
    result = run_value["result"]
    if (
        result.get("markerObserved") is not True
        or result.get("cleanup") != "verified_deleted"
        or result.get("postDeleteStatus") != 404
    ):
        raise CanaryError("paperclip_baserow_crud_failed")
    return {
        "id": "C027",
        "ok": True,
        "state": "passed",
        "source": "paperclip_process_heartbeat_run",
        "dataContentProfile": profile,
        "tablesApiComponent": "baserow",
        "paperclipTaskId": str(run_value["issue"]["id"]),
        "paperclipHeartbeatRunId": str(run_value["heartbeatRun"]["id"]),
        "paperclipAgentId": str(run_value["agent"]["id"]),
        "paperclipProjectId": str(run_value["project"]["id"]),
        "bindingType": "secret_ref",
        "secretIdMatchesManaged": True,
        "credentialResolvedBy": "paperclip_runtime",
        "secretAccessEventVerified": True,
        "secretAccessEventId": str(run_value["secretAccessEvent"]["id"]),
        "createStatus": result.get("createStatus"),
        "readStatus": result.get("readStatus"),
        "deleteStatus": result.get("deleteStatus"),
        "postDeleteStatus": result.get("postDeleteStatus"),
        "markerObserved": True,
        "cleanup": "verified_deleted",
        "paperclipCleanup": run_value["cleanup"],
    }


def projection_token(path: Path, key: str, source_hash: str) -> str:
    values = dotenv(path)
    if values.get("MTE_PROJECTION_SOURCE_SHA256") != source_hash:
        raise CanaryError("projection_source_hash_mismatch")
    token = values.get(key, "")
    if not token:
        raise CanaryError("projected_token_missing")
    return token


def activepieces_project_variable(
    base: str,
    project_id: str,
    headers: dict[str, str],
    *,
    name: str,
    expected_value: str,
) -> dict[str, str]:
    query = urllib.parse.urlencode({"projectId": project_id, "limit": 100})
    _status, value = request_json(
        "GET", f"{base}/api/v1/variables?{query}", headers=headers
    )
    matches = [row for row in list_value(value) if row.get("name") == name]
    if len(matches) != 1:
        raise CanaryError("activepieces_project_variable_not_unique")
    variable_id = str(matches[0].get("id") or "")
    if not variable_id:
        raise CanaryError("activepieces_project_variable_id_missing")
    _status, revealed = request_json(
        "POST",
        f"{base}/api/v1/variables/{urllib.parse.quote(variable_id)}/reveal",
        headers=headers,
    )
    revealed_value = str((revealed or {}).get("value") or "")
    try:
        if not revealed_value or not hmac.compare_digest(
            revealed_value, expected_value
        ):
            raise CanaryError("activepieces_project_variable_value_mismatch")
    finally:
        revealed_value = ""
    return {"id": variable_id, "name": name}


def c028_postgrest(values: dict[str, str], run_id: str) -> dict[str, Any]:
    source_hash = canonical_hash()
    token = projection_token(
        SERVICES / "activepieces.env",
        "POSTGREST_ACTIVEPIECES_TOKEN",
        source_hash,
    )
    if token == values.get("POSTGREST_PAPERCLIP_TOKEN"):
        raise CanaryError("postgrest_activepieces_token_not_distinct")
    for container in (
        find_container(image="activepieces", name="app"),
        find_container(image="activepieces", name="worker"),
    ):
        resolution = run(
            ["docker", "exec", container, "getent", "hosts", "postgrest"],
            check=False,
        )
        if resolution.returncode != 0:
            raise CanaryError("durable_network_missing")
    base, session, project_id = activepieces_session(values)
    headers = {"Authorization": f"Bearer {session}"}
    suffix = run_id[-12:].lower()
    webhook_secret = secrets.token_urlsafe(32)
    marker = f"mte-ap-postgrest-{run_id}"
    credential_variable = activepieces_project_variable(
        base,
        project_id,
        headers,
        name=POSTGREST_ACTIVEPIECES_VARIABLE,
        expected_value=token,
    )
    flow_id = ""
    flow_run_id = ""
    record_key = ""
    published = False
    cleanup = {
        "recordDeleted": False,
        "flowDeleted": False,
        "credentialVariablePreserved": False,
    }

    def http_action(
        name: str,
        display: str,
        parent: str,
        method: str,
        url: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "type": "ADD_ACTION",
            "request": {
                "parentStep": parent,
                "stepLocationRelativeToParent": "AFTER",
                "action": {
                    "name": name,
                    "displayName": display,
                    "valid": False,
                    "type": "PIECE",
                    "settings": {
                        "pieceName": "@activepieces/piece-http",
                        "pieceVersion": "0.11.10",
                        "actionName": "send_request",
                        "input": {
                            "method": method,
                            "url": url,
                            "headers": (
                                {"Prefer": "return=representation"}
                                if method == "POST"
                                else {}
                            ),
                            "queryParams": {},
                            "authType": "BEARER_TOKEN",
                            "authFields": {
                                "token": (
                                    "{{variables['"
                                    + POSTGREST_ACTIVEPIECES_VARIABLE
                                    + "']}}"
                                )
                            },
                            "body_type": "json" if body is not None else "none",
                            "body": {"data": body} if body is not None else {},
                            "response_is_binary": False,
                            "use_proxy": False,
                            "timeout": 30,
                            "followRedirects": False,
                            "failureMode": "continue_none",
                        },
                        "propertySettings": {},
                        "errorHandlingOptions": {},
                    },
                },
            },
        }

    try:
        _status, flow = request_json(
            "POST",
            f"{base}/api/v1/flows",
            headers=headers,
            body={
                "displayName": f"MTE PostgREST CRUD canary {suffix}",
                "projectId": project_id,
            },
        )
        flow_id = str((flow or {}).get("id") or "")
        if not flow_id:
            raise CanaryError("activepieces_canary_flow_missing")
        updates = [
            {
                "type": "UPDATE_TRIGGER",
                "request": {
                    "name": "trigger",
                    "displayName": "Canary Webhook",
                    "valid": False,
                    "type": "PIECE_TRIGGER",
                    "settings": {
                        "pieceName": "@activepieces/piece-webhook",
                        "pieceVersion": "0.1.36",
                        "triggerName": "catch_webhook",
                        "input": {
                            "authType": "header",
                            "authFields": {
                                "headerName": "X-MTE-Canary",
                                "headerValue": webhook_secret,
                            },
                        },
                        "propertySettings": {},
                    },
                },
            },
            http_action(
                "step_1",
                "Create PostgREST record",
                "trigger",
                "POST",
                "http://postgrest:3000/prototype_items",
                {"title": "{{trigger['output'].body.marker}}", "status": "created"},
            ),
            http_action(
                "step_2",
                "Read PostgREST record",
                "step_1",
                "GET",
                (
                    "http://postgrest:3000/prototype_items?id=eq."
                    "{{step_1['output'].body[0].id}}"
                ),
            ),
            http_action(
                "step_3",
                "Delete PostgREST record",
                "step_2",
                "DELETE",
                (
                    "http://postgrest:3000/prototype_items?id=eq."
                    "{{step_1['output'].body[0].id}}"
                ),
            ),
        ]
        for update in updates:
            request_json(
                "POST", f"{base}/api/v1/flows/{flow_id}", headers=headers, body=update
            )
        request_json(
            "POST",
            f"{base}/api/v1/flows/{flow_id}",
            headers=headers,
            body={"type": "LOCK_AND_PUBLISH", "request": {"status": "ENABLED"}},
        )
        published = True
        created_after = utcnow()
        trigger_status, _trigger = request_json(
            "POST",
            f"{base}/api/v1/webhooks/{flow_id}",
            headers={"X-MTE-Canary": webhook_secret},
            body={"marker": marker},
        )
        if trigger_status != 200:
            raise CanaryError("activepieces_webhook_failed", status=trigger_status)
        deadline = time.monotonic() + 180
        full_run: dict[str, Any] = {}
        while time.monotonic() < deadline:
            query = urllib.parse.urlencode(
                {
                    "projectId": project_id,
                    "flowId": flow_id,
                    "createdAfter": created_after,
                    "limit": 10,
                }
            )
            _status, runs_value = request_json(
                "GET", f"{base}/api/v1/flow-runs?{query}", headers=headers
            )
            run_rows = list_value(runs_value)
            if run_rows:
                flow_run = max(run_rows, key=lambda row: str(row.get("created") or ""))
                flow_run_id = str(flow_run.get("id") or "")
                state = str(flow_run.get("status") or "").upper()
                if state in {"SUCCEEDED", "FAILED", "TIMEOUT", "STOPPED"}:
                    if state != "SUCCEEDED":
                        raise CanaryError("activepieces_canary_flow_failed")
                    _status, value = request_json(
                        "GET", f"{base}/api/v1/flow-runs/{flow_run_id}", headers=headers
                    )
                    if isinstance(value, dict):
                        full_run = value
                    break
            time.sleep(1)
        if not full_run:
            raise CanaryError("activepieces_canary_flow_timeout")
        steps = full_run.get("steps") or {}
        create_step = steps.get("step_1") or {}
        read_step = steps.get("step_2") or {}
        delete_step = steps.get("step_3") or {}
        created_body = (create_step.get("output") or {}).get("body") or []
        read_body = (read_step.get("output") or {}).get("body") or []
        if isinstance(created_body, list) and created_body:
            record_key = str((created_body[0] or {}).get("id") or "")
        if (
            create_step.get("status") != "SUCCEEDED"
            or read_step.get("status") != "SUCCEEDED"
            or delete_step.get("status") != "SUCCEEDED"
            or not record_key
            or not isinstance(read_body, list)
            or len(read_body) != 1
            or str(read_body[0].get("id") or "") != record_key
            or read_body[0].get("title") != marker
        ):
            raise CanaryError("activepieces_canary_step_evidence_invalid")
        after_status, after = request_json(
            "GET",
            (
                f"http://127.0.0.1:{values['POSTGREST_ORIGIN_PORT']}"
                f"/prototype_items?id=eq.{record_key}"
            ),
            headers={"Authorization": f"Bearer {token}"},
        )
        if after != []:
            raise CanaryError("activepieces_postgrest_cleanup_not_observed")
        record_key = ""
        cleanup["recordDeleted"] = True
        result = {
            "flowRunStatus": "SUCCEEDED",
            "triggerStatus": trigger_status,
            "stepStatuses": {
                "create": "SUCCEEDED",
                "read": "SUCCEEDED",
                "delete": "SUCCEEDED",
            },
            "markerObserved": True,
            "postDeleteStatus": after_status,
            "postDeleteAbsent": True,
        }
    finally:
        webhook_secret = ""
        if record_key:
            request_json(
                "DELETE",
                (
                    f"http://127.0.0.1:{values['POSTGREST_ORIGIN_PORT']}"
                    f"/prototype_items?id=eq.{record_key}"
                ),
                headers={"Authorization": f"Bearer {token}"},
            )
            cleanup["recordDeleted"] = True
        if flow_id:
            if published:
                request_json(
                    "POST",
                    f"{base}/api/v1/flows/{flow_id}",
                    headers=headers,
                    body={"type": "CHANGE_STATUS", "request": {"status": "DISABLED"}},
                    allow_status={404},
                )
            request_json(
                "DELETE",
                f"{base}/api/v1/flows/{flow_id}",
                headers=headers,
                allow_status={404},
            )
            for _attempt in range(30):
                flow_status, _flow = request_json(
                    "GET",
                    f"{base}/api/v1/flows/{flow_id}",
                    headers=headers,
                    allow_status={404},
                )
                if flow_status == 404:
                    cleanup["flowDeleted"] = True
                    break
                time.sleep(0.5)
        else:
            cleanup["flowDeleted"] = True
        variable_query = urllib.parse.urlencode({"projectId": project_id, "limit": 100})
        _status, variables_value = request_json(
            "GET", f"{base}/api/v1/variables?{variable_query}", headers=headers
        )
        cleanup["credentialVariablePreserved"] = any(
            row.get("id") == credential_variable["id"]
            and row.get("name") == credential_variable["name"]
            for row in list_value(variables_value)
        )
    if not all(cleanup.values()):
        raise CanaryError("activepieces_canary_cleanup_incomplete")
    postgrest_reference = _postgrest_dependency_reference()
    return {
        "id": "C028",
        "ok": True,
        "state": "passed",
        "source": "activepieces_native_flow",
        "dataContentProfile": values["DATA_CONTENT_PROFILE"],
        "tablesApiComponent": "postgrest",
        "activepiecesProjectId": project_id,
        "activepiecesFlowRunId": flow_run_id,
        "piece": "@activepieces/piece-http@0.11.10",
        "actions": ["postgrest_create", "postgrest_read", "postgrest_delete"],
        "credentialProjection": str(SERVICES / "activepieces.env"),
        "projectionSourceHash": source_hash,
        "tokenDistinctFromPaperclip": True,
        "credentialStorage": "encrypted_project_variable",
        "credentialVariableId": credential_variable["id"],
        "credentialVariableName": credential_variable["name"],
        "credentialReference": (
            "{{variables['" + POSTGREST_ACTIVEPIECES_VARIABLE + "']}}"
        ),
        "credentialValueReadBackVerified": True,
        "osiLicense": {
            "component": "postgrest",
            "version": "14.15",
            "spdx": "MIT",
            "imageDigest": (
                "sha256:2f8e7b656f09db697a8875177694b417b35cb76c21370de07fc54e711e902326"
            ),
            "verified": True,
        },
        **result,
        "cleanup": cleanup,
        "dependencyEvidence": postgrest_reference,
    }


def c028(values: dict[str, str], run_id: str) -> dict[str, Any]:
    profile = values.get("DATA_CONTENT_PROFILE", "")
    if profile in POSTGREST_DATA_PROFILES:
        return c028_postgrest(values, run_id)
    if profile != "baserow-wikijs":
        raise CanaryError("data_content_profile_unsupported")
    source_hash = canonical_hash()
    token = projection_token(
        SERVICES / "activepieces.env", "BASEROW_ACTIVEPIECES_TOKEN", source_hash
    )
    if token == values.get("BASEROW_PAPERCLIP_TOKEN"):
        raise CanaryError("baserow_activepieces_token_not_distinct")
    table_id = values["BASEROW_TABLE_ID"]
    for container in (
        find_container(image="activepieces", name="app"),
        find_container(image="activepieces", name="worker"),
    ):
        resolution = run(
            ["docker", "exec", container, "getent", "hosts", "baserow"], check=False
        )
        if resolution.returncode != 0:
            raise CanaryError("durable_network_missing")
    base, session, project_id = activepieces_session(values)
    headers = {"Authorization": f"Bearer {session}"}
    suffix = run_id[-12:].lower()
    external_id = f"mte-baserow-canary-{suffix}"
    webhook_secret = secrets.token_urlsafe(32)
    marker = f"mte-ap-crud-{run_id}"
    connection_id = ""
    flow_id = ""
    flow_run_id = ""
    record_key = ""
    published = False
    cleanup = {
        "recordDeleted": False,
        "flowDeleted": False,
        "connectionDeleted": False,
    }
    try:
        _status, connection = request_json(
            "POST",
            f"{base}/api/v1/app-connections",
            headers=headers,
            body={
                "externalId": external_id,
                "displayName": f"MTE Baserow OSE canary {suffix}",
                "pieceName": "@activepieces/piece-baserow",
                "pieceVersion": "0.9.5",
                "projectId": project_id,
                "type": "CUSTOM_AUTH",
                "value": {
                    "type": "CUSTOM_AUTH",
                    "props": {
                        "authType": "database_token",
                        "apiUrl": "http://baserow:80",
                        "token": token,
                    },
                },
            },
        )
        connection_id = str((connection or {}).get("id") or "")
        if not connection_id:
            raise CanaryError("activepieces_baserow_connection_missing")
        _status, flow = request_json(
            "POST",
            f"{base}/api/v1/flows",
            headers=headers,
            body={
                "displayName": f"MTE Baserow CRUD canary {suffix}",
                "projectId": project_id,
            },
        )
        flow_id = str((flow or {}).get("id") or "")
        if not flow_id:
            raise CanaryError("activepieces_canary_flow_missing")
        updates = [
            {
                "type": "UPDATE_TRIGGER",
                "request": {
                    "name": "trigger",
                    "displayName": "Canary Webhook",
                    "valid": False,
                    "type": "PIECE_TRIGGER",
                    "settings": {
                        "pieceName": "@activepieces/piece-webhook",
                        "pieceVersion": "0.1.36",
                        "triggerName": "catch_webhook",
                        "input": {
                            "authType": "header",
                            "authFields": {
                                "headerName": "X-MTE-Canary",
                                "headerValue": webhook_secret,
                            },
                        },
                        "propertySettings": {},
                    },
                },
            },
            {
                "parent": "trigger",
                "name": "step_1",
                "display": "Create canary record",
                "action": "baserow_create_row",
                "input": {
                    "auth": f"{{{{connections['{external_id}']}}}}",
                    "table_id": table_id,
                    "table_fields": {
                        "Value": "{{trigger['output'].body.marker}}",
                    },
                    "create_missing_select_options": False,
                },
            },
            {
                "parent": "step_1",
                "name": "step_2",
                "display": "Read canary record",
                "action": "baserow_get_row",
                "input": {
                    "auth": f"{{{{connections['{external_id}']}}}}",
                    "table_id": table_id,
                    "row_id": "{{step_1['output'].id}}",
                },
            },
            {
                "parent": "step_2",
                "name": "step_3",
                "display": "Delete canary record",
                "action": "baserow_delete_row",
                "input": {
                    "auth": f"{{{{connections['{external_id}']}}}}",
                    "table_id": table_id,
                    "row_id": "{{step_1['output'].id}}",
                },
            },
        ]
        for update in updates:
            if "type" in update:
                body = update
            else:
                body = {
                    "type": "ADD_ACTION",
                    "request": {
                        "parentStep": update["parent"],
                        "stepLocationRelativeToParent": "AFTER",
                        "action": {
                            "name": update["name"],
                            "displayName": update["display"],
                            "valid": False,
                            "type": "PIECE",
                            "settings": {
                                "pieceName": "@activepieces/piece-baserow",
                                "pieceVersion": "0.9.5",
                                "actionName": update["action"],
                                "input": update["input"],
                                "propertySettings": {},
                                "errorHandlingOptions": {},
                            },
                        },
                    },
                }
            request_json(
                "POST", f"{base}/api/v1/flows/{flow_id}", headers=headers, body=body
            )
        request_json(
            "POST",
            f"{base}/api/v1/flows/{flow_id}",
            headers=headers,
            body={"type": "LOCK_AND_PUBLISH", "request": {"status": "ENABLED"}},
        )
        published = True
        created_after = utcnow()
        trigger_status, _trigger = request_json(
            "POST",
            f"{base}/api/v1/webhooks/{flow_id}",
            headers={"X-MTE-Canary": webhook_secret},
            body={"marker": marker},
        )
        if trigger_status != 200:
            raise CanaryError("activepieces_webhook_failed", status=trigger_status)
        deadline = time.monotonic() + 180
        full_run: dict[str, Any] = {}
        while time.monotonic() < deadline:
            query = urllib.parse.urlencode(
                {
                    "projectId": project_id,
                    "flowId": flow_id,
                    "createdAfter": created_after,
                    "limit": 10,
                }
            )
            _status, runs_value = request_json(
                "GET", f"{base}/api/v1/flow-runs?{query}", headers=headers
            )
            run_rows = list_value(runs_value)
            if run_rows:
                flow_run = max(run_rows, key=lambda row: str(row.get("created") or ""))
                flow_run_id = str(flow_run.get("id") or "")
                status = str(flow_run.get("status") or "").upper()
                if status in {"SUCCEEDED", "FAILED", "TIMEOUT", "STOPPED"}:
                    if status != "SUCCEEDED":
                        raise CanaryError("activepieces_canary_flow_failed")
                    _status, full_run_value = request_json(
                        "GET",
                        f"{base}/api/v1/flow-runs/{flow_run_id}",
                        headers=headers,
                    )
                    if isinstance(full_run_value, dict):
                        full_run = full_run_value
                    break
            time.sleep(1)
        if not full_run:
            raise CanaryError("activepieces_canary_flow_timeout")
        steps = full_run.get("steps") or {}
        create_step = steps.get("step_1") or {}
        read_step = steps.get("step_2") or {}
        delete_step = steps.get("step_3") or {}
        record_key = str((create_step.get("output") or {}).get("id") or "")
        read_output = read_step.get("output") or {}
        if (
            create_step.get("status") != "SUCCEEDED"
            or read_step.get("status") != "SUCCEEDED"
            or delete_step.get("status") != "SUCCEEDED"
            or not record_key
            or str(read_output.get("id") or "") != record_key
            or read_output.get("Value") != marker
        ):
            raise CanaryError("activepieces_canary_step_evidence_invalid")
        after_status, _after = request_json(
            "GET",
            f"http://127.0.0.1:{values['BASEROW_ORIGIN_PORT']}"
            f"/api/database/rows/table/{table_id}/{record_key}/",
            headers={"Authorization": f"Token {token}"},
            allow_status={404},
        )
        if after_status != 404:
            raise CanaryError("activepieces_baserow_cleanup_not_observed")
        record_key = ""
        cleanup["recordDeleted"] = True
        result = {
            "flowRunStatus": "SUCCEEDED",
            "triggerStatus": trigger_status,
            "stepStatuses": {
                "create": "SUCCEEDED",
                "read": "SUCCEEDED",
                "delete": "SUCCEEDED",
            },
            "markerObserved": True,
            "postDeleteStatus": after_status,
        }
    finally:
        webhook_secret = ""
        if record_key:
            request_json(
                "DELETE",
                f"http://127.0.0.1:{values['BASEROW_ORIGIN_PORT']}"
                f"/api/database/rows/table/{table_id}/{record_key}/",
                headers={"Authorization": f"Token {token}"},
                allow_status={404},
            )
            cleanup["recordDeleted"] = True
        if flow_id:
            if published:
                request_json(
                    "POST",
                    f"{base}/api/v1/flows/{flow_id}",
                    headers=headers,
                    body={
                        "type": "CHANGE_STATUS",
                        "request": {"status": "DISABLED"},
                    },
                    allow_status={404},
                )
            request_json(
                "DELETE",
                f"{base}/api/v1/flows/{flow_id}",
                headers=headers,
                allow_status={404},
            )
            for _attempt in range(30):
                flow_status, _flow = request_json(
                    "GET",
                    f"{base}/api/v1/flows/{flow_id}",
                    headers=headers,
                    allow_status={404},
                )
                if flow_status == 404:
                    cleanup["flowDeleted"] = True
                    break
                time.sleep(0.5)
        else:
            cleanup["flowDeleted"] = True
        if connection_id and cleanup["flowDeleted"]:
            request_json(
                "DELETE",
                f"{base}/api/v1/app-connections/{connection_id}",
                headers=headers,
                allow_status={404},
            )
            connection_status, _connection = request_json(
                "GET",
                f"{base}/api/v1/app-connections/{connection_id}",
                headers=headers,
                allow_status={404},
            )
            cleanup["connectionDeleted"] = connection_status == 404
        elif not connection_id:
            cleanup["connectionDeleted"] = True
    if not all(cleanup.values()):
        raise CanaryError("activepieces_canary_cleanup_incomplete")
    return {
        "id": "C028",
        "ok": True,
        "state": "passed",
        "source": "activepieces_native_flow",
        "dataContentProfile": profile,
        "tablesApiComponent": "baserow",
        "activepiecesProjectId": project_id,
        "activepiecesFlowRunId": flow_run_id,
        "piece": "@activepieces/piece-baserow@0.9.5",
        "actions": [
            "baserow_create_row",
            "baserow_get_row",
            "baserow_delete_row",
        ],
        "credentialProjection": str(SERVICES / "activepieces.env"),
        "projectionSourceHash": source_hash,
        "tokenDistinctFromPaperclip": True,
        "connectionType": "CUSTOM_AUTH",
        "osiLicense": {
            "component": "baserow",
            "version": "2.3.1",
            "spdx": "MIT",
            "imageDigest": (
                "sha256:496889c4fe22ee6b632698c3c74f7ccaee734c8002b5ebc8d194c5fcacffc98a"
            ),
            "verified": True,
        },
        **result,
        "cleanup": cleanup,
    }


def c030(values: dict[str, str], run_id: str) -> dict[str, Any]:
    base = "http://127.0.0.1:18065"
    token = values["MATTERMOST_BOT_TOKEN"]
    headers = {"Authorization": f"Bearer {token}"}
    _status, channel = request_json(
        "GET",
        f"{base}/api/v4/teams/{values['MATTERMOST_TEAM_ID']}/channels/name/mte-alerts",
        headers=headers,
    )
    channel_id = str((channel or {}).get("id") or "")
    if not channel_id:
        raise CanaryError("mattermost_canary_channel_missing")
    run_value = paperclip_integration_run(
        values,
        run_id,
        "mattermost_notification",
        {
            "mattermostApiBase": base,
            "mattermostChannelId": channel_id,
        },
    )
    result = run_value["result"]
    post_id = str(result.get("postId") or "")
    if not post_id:
        raise CanaryError("mattermost_post_missing")
    issue_id = str(run_value["issue"]["id"])
    native_run_id = str(run_value["heartbeatRun"]["id"])
    expected_message = (
        "MTE integration canary C030 "
        f"task_id={issue_id} run_id={native_run_id} control_run_id={run_id}"
    )
    try:
        _status, observed = request_json(
            "GET", f"{base}/api/v4/posts/{post_id}", headers=headers
        )
        author_matches = str((observed or {}).get("user_id") or "") == values.get(
            "MATTERMOST_BOT_USER_ID"
        )
        content_matches = (observed or {}).get("message") == expected_message
        source_matches = (
            result.get("authorUserId") == values.get("MATTERMOST_BOT_USER_ID")
            and result.get("channelId") == channel_id
            and result.get("messageSha256")
            == hashlib.sha256(expected_message.encode()).hexdigest()
        )
        if not author_matches or not content_matches or not source_matches:
            raise CanaryError("mattermost_post_observation_mismatch")
        request_json("DELETE", f"{base}/api/v4/posts/{post_id}", headers=headers)
        after_status, _after = request_json(
            "GET",
            f"{base}/api/v4/posts/{post_id}",
            headers=headers,
            allow_status={404},
        )
        if after_status != 404:
            raise CanaryError("mattermost_cleanup_not_observed")
        post_id = ""
        return {
            "id": "C030",
            "ok": True,
            "state": "passed",
            "source": "paperclip_process_heartbeat_run",
            "transport": "mattermost_bot_api",
            "paperclipTaskId": issue_id,
            "paperclipHeartbeatRunId": native_run_id,
            "paperclipAgentId": str(run_value["agent"]["id"]),
            "paperclipProjectId": str(run_value["project"]["id"]),
            "bindingType": "secret_ref",
            "credentialResolvedBy": "paperclip_runtime",
            "secretAccessEventVerified": True,
            "secretAccessEventId": str(run_value["secretAccessEvent"]["id"]),
            "httpStatus": result.get("httpStatus"),
            "authorMatchesManagedBot": True,
            "contentMatchesTaskAndRun": True,
            "cleanup": "verified_deleted",
            "paperclipCleanup": run_value["cleanup"],
        }
    finally:
        if post_id:
            request_json(
                "DELETE",
                f"{base}/api/v4/posts/{post_id}",
                headers=headers,
                allow_status={404},
            )


def oauth_assessment(values: dict[str, str]) -> list[dict[str, Any]]:
    base, session, project_id = activepieces_session(values)
    _status, payload = request_json(
        "GET",
        f"{base}/api/v1/app-connections?projectId={urllib.parse.quote(project_id)}&limit=100",
        headers={"Authorization": f"Bearer {session}"},
    )
    connections = list_value(payload)
    authorized = [
        row
        for row in connections
        if "github" in str(row.get("pieceName") or "").lower()
        and str(row.get("status") or "").upper() in {"ACTIVE", "VALID"}
    ]
    configured_client = bool(
        values.get("ACTIVEPIECES_GITHUB_OAUTH_CLIENT_ID")
        and values.get("ACTIVEPIECES_GITHUB_OAUTH_CLIENT_SECRET")
    )
    if authorized:
        common = {
            "state": "authorized_connection_requires_live_canary",
            "liveGateIncluded": True,
            "ok": False,
            "authorizedGitHubConnectionCount": len(authorized),
            "selfHostedOAuthClientConfigured": configured_client,
            "humanAuthorizationRequired": False,
            "reason": "authorized_connection_must_be_exercised_before_green",
        }
    else:
        common = {
            "state": "conditional_external_provider_consent",
            "liveGateIncluded": False,
            "ok": None,
            "authorizedGitHubConnectionCount": 0,
            "selfHostedOAuthClientConfigured": configured_client,
            "humanAuthorizationRequired": True,
            "reason": "external_provider_consent_required",
        }
    return [
        {"id": "C021", **common},
        {"id": "C022", **common},
    ]


CANARIES = {
    "C013": c013,
    "C023": c023,
    "C024": c024,
    "C027": c027,
    "C028": c028,
    "C029": c029,
    "C030": c030,
}


def error_result(canary_id: str, exc: BaseException) -> dict[str, Any]:
    return {
        "id": canary_id,
        "ok": False,
        "state": "failed",
        "errorCode": exc.code if isinstance(exc, CanaryError) else "unexpected_error",
        "httpStatus": exc.status if isinstance(exc, CanaryError) else None,
        "errorType": type(exc).__name__,
    }


def execute(selected: list[str]) -> dict[str, Any]:
    values = dotenv(CANONICAL)
    run_id = secrets.token_hex(12)
    rows: list[dict[str, Any]] = []
    for canary_id in selected:
        try:
            rows.append(CANARIES[canary_id](values, run_id))
        except BaseException as exc:
            rows.append(error_result(canary_id, exc))
    try:
        external = oauth_assessment(values)
    except BaseException as exc:
        external = [
            {
                "id": canary_id,
                "ok": None,
                "state": "conditional_external_provider_consent",
                "liveGateIncluded": False,
                "assessmentErrorType": type(exc).__name__,
            }
            for canary_id in ("C021", "C022")
        ]
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "IntegrationCanaryEvidence",
        "generatedAt": utcnow(),
        "runId": run_id,
        "dataContentProfile": values.get("DATA_CONTENT_PROFILE", ""),
        "canonicalSourceSha256": canonical_hash(),
        "producerSha256": producer_hash(),
        "ok": all(row.get("ok") is True for row in rows)
        and all(
            row.get("ok") is True
            for row in external
            if row.get("liveGateIncluded") is True
        ),
        "selected": selected,
        "canaries": rows,
        "externalProviderConsent": external,
    }
    payload["status"] = "passed" if payload["ok"] else "failed"
    atomic_json(EVIDENCE, payload)
    # Keep one current, producer-bound attestation per criterion. A later run
    # of a different canary updates only the aggregate and its own split file,
    # so Cloudflare and the semantic verifier can bind C029 without races.
    for row in rows:
        canary_id = str(row["id"])
        split_payload = {
            **payload,
            "selected": [canary_id],
            "canaries": [row],
        }
        atomic_json(
            ROOT / f"evidence/integration-canary-{canary_id}.json",
            split_payload,
        )
    return payload


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    if action == "run":
        selected = sys.argv[2:] or list(SUPPORTED)
        unknown = sorted(set(selected) - set(SUPPORTED))
        if unknown:
            print(json.dumps({"ok": False, "error": "unknown_canary", "ids": unknown}))
            return 2
        payload = execute(selected)
    elif action == "status" and len(sys.argv) == 2:
        if not EVIDENCE.is_file():
            payload = {"ok": False, "state": "evidence_missing"}
        else:
            payload = json.loads(EVIDENCE.read_text())
    else:
        print(
            "usage: server-integration-canaries.py run [C013 ...]|status",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

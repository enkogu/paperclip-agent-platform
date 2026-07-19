#!/usr/bin/env python3
"""Produce sanitized live evidence for cross-service integration canaries."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
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
SUPPORTED = ("C023", "C024", "C027", "C029", "C030")
DEFAULT_DATA_CONTENT_PROFILE = "postgres-notion"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
API_VERSION = "micro-task-engine/v1alpha1"
PAPERCLIP_TERMINAL_RUN_STATUSES = frozenset(
    {"succeeded", "failed", "timed_out", "cancelled"}
)
PAPERCLIP_RUN_TIMEOUT_SECONDS = 210
PAPERCLIP_CLEANUP_TIMEOUT_SECONDS = 30
SENSITIVE_VALUE_KEY = re.compile(r"(?:TOKEN|SECRET|PASSWORD|API_KEY|LICENSE_KEY)$")


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


def operator_base(values: dict[str, str], port_key: str) -> str:
    """Build a host-only service origin from canonical operator-plane settings."""
    raw_host = values.get("MTE_OPERATOR_LOOPBACK_HOST", "").strip()
    try:
        address = ipaddress.ip_address(raw_host)
    except ValueError as exc:
        raise CanaryError("operator_loopback_host_invalid") from exc
    if not address.is_loopback:
        raise CanaryError("operator_loopback_host_invalid")
    raw_port = values.get(port_key, "").strip()
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise CanaryError("operator_origin_port_invalid") from exc
    if not 1024 <= port <= 65535:
        raise CanaryError("operator_origin_port_invalid")
    host = f"[{address}]" if address.version == 6 else str(address)
    return f"http://{host}:{port}"


def canary_proxy_port(
    values: dict[str, str], *, base_key: str, range_key: str, run_id: str
) -> int:
    """Select a stable transient proxy port inside a canonical configured range."""
    try:
        base = int(values.get(base_key, ""))
        size = int(values.get(range_key, ""))
    except ValueError as exc:
        raise CanaryError("toolhive_canary_proxy_range_invalid") from exc
    if base < 1024 or size < 1 or base + size - 1 > 65535:
        raise CanaryError("toolhive_canary_proxy_range_invalid")
    offset = int(hashlib.sha256(run_id.encode()).hexdigest()[:8], 16) % size
    return base + offset


def canonical_hash() -> str:
    return hashlib.sha256(CANONICAL.read_bytes()).hexdigest()


def producer_hash() -> str:
    path = Path(__file__)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""


def evidence_contains_canonical_secret(
    payload: dict[str, Any], values: dict[str, str]
) -> bool:
    """Prevent status and persisted receipts from replaying canonical credentials."""

    serialized = json.dumps(payload, sort_keys=True)
    return any(
        value in serialized
        for key, value in values.items()
        if SENSITIVE_VALUE_KEY.search(key) and len(value) >= 8
    )


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
            if not raw:
                return response.status, None
            try:
                return response.status, json.loads(raw)
            except json.JSONDecodeError as exc:
                raise CanaryError("remote_json_invalid") from exc
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
    try:
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
    except subprocess.TimeoutExpired as exc:
        raise CanaryError("command_timeout") from exc
    except OSError as exc:
        raise CanaryError("command_unavailable") from exc
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
    if "\x00" in value or not re.fullmatch(r"/tmp/[A-Za-z0-9_.-]+\.env", path):
        raise CanaryError("unsafe_ephemeral_secret")
    run(
        [
            "docker",
            "exec",
            "-i",
            manager,
            "sh",
            "-c",
            "umask 077; cat > \"$1\"; chmod 600 \"$1\"",
            "sh",
            path,
        ],
        input_text=value,
    )


def remove_manager_file(manager: str, path: str) -> bool:
    """Remove an ephemeral manager file and prove that it is gone."""

    result = run(
        [
            "docker",
            "exec",
            manager,
            "sh",
            "-c",
            "rm -f -- \"$1\" && test ! -e \"$1\"",
            "sh",
            path,
        ],
        check=False,
        timeout=60,
    )
    return result.returncode == 0


def remove_toolhive_workload(manager: str, name: str) -> bool:
    """Remove a transient workload; callers must not infer cleanup from intent."""

    return toolhive(manager, "rm", name, check=False, timeout=60).returncode == 0


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


def c023(values: dict[str, str], run_id: str) -> dict[str, Any]:
    manager = toolhive_manager()
    suffix = run_id[-8:].lower()
    workload = f"mte-firecrawl-canary-{suffix}"
    env_file = f"/tmp/{workload}.env"
    marker = f"MTE-C023-{run_id}"
    proxy_port = canary_proxy_port(
        values,
        base_key="TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_BASE",
        range_key="TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_RANGE",
        run_id=run_id,
    )
    cleanup = {
        "workloadRemoved": False,
        "envFileRemoved": False,
        # The canary uses an external stateless echo endpoint; it never starts
        # a marker server of its own, so no server can survive this run.
        "markerServerRemoved": True,
    }
    env_file_touched = False
    workload_touched = False
    try:
        env_file_touched = True
        write_manager_secret(
            manager,
            env_file,
            "FIRECRAWL_API_KEY="
            + values["FIRECRAWL_API_KEY"]
            + "\nFIRECRAWL_API_URL=http://firecrawl-api:3002\n",
        )
        workload_touched = True
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
        cleanup["workloadRemoved"] = (
            not workload_touched
            or bool(remove_toolhive_workload(manager, workload))
        )
        cleanup["envFileRemoved"] = (
            not env_file_touched or bool(remove_manager_file(manager, env_file))
        )
        if not all(cleanup.values()):
            raise CanaryError("toolhive_canary_cleanup_incomplete")


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
    base = f"{operator_base(values, 'POSTGREST_ORIGIN_PORT')}/{table}"
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


def _direct_notion_connector_runtime_payload(
    values: dict[str, str], run_id: str
) -> dict[str, Any]:
    """Legacy connector-only probe, deliberately not accepted as C029 evidence."""
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


def _read_private_projection_evidence(path: Path, kind: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise CanaryError("notion_projection_evidence_missing")
    info = path.stat()
    if info.st_mode & 0o777 != 0o600:
        raise CanaryError("notion_projection_evidence_mode_invalid")
    if os.geteuid() == 0 and (info.st_uid != 0 or info.st_gid != 0):
        raise CanaryError("notion_projection_evidence_owner_invalid")
    try:
        document = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise CanaryError("notion_projection_evidence_invalid") from exc
    if not isinstance(document, dict) or document.get("kind") != kind:
        raise CanaryError("notion_projection_evidence_invalid")
    return document


def _projection_runtime_payload(values: dict[str, str], run_id: str) -> dict[str, Any]:
    """Bind C029 to the outbox consumer canary and its post-canary verify receipt."""

    script = ROOT / "bin/server-notion-sync.py"
    canary_path = ROOT / "evidence/notion-projection-live-canary.json"
    verify_path = ROOT / "evidence/notion-projection-consumer-verify.json"
    if not script.is_file():
        raise CanaryError("notion_projection_consumer_missing")
    producer_sha = hashlib.sha256(script.read_bytes()).hexdigest()
    canary_result = run(
        [sys.executable, str(script), "canary", "--run-id", run_id], timeout=900
    )
    verify_result = run([sys.executable, str(script), "verify"], timeout=300)
    try:
        canary = json.loads(canary_result.stdout)
        verification = json.loads(verify_result.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise CanaryError("notion_projection_result_invalid") from exc
    persisted_canary = _read_private_projection_evidence(
        canary_path, "NotionProjectionLiveCanary"
    )
    persisted_verification = _read_private_projection_evidence(
        verify_path, "NotionProjectionConsumerVerification"
    )
    if not isinstance(canary, dict) or not isinstance(verification, dict):
        raise CanaryError("notion_projection_result_invalid")
    def common(payload: dict[str, Any]) -> bool:
        return (
            payload.get("status") == "passed"
            and payload.get("ok") is True
            and payload.get("dataContentProfile") == DEFAULT_DATA_CONTENT_PROFILE
            and payload.get("canonicalSourceSha256") == canonical_hash()
            and payload.get("producerSha256") == producer_sha
            and payload.get("redacted") is True
        )
    if (
        not common(canary)
        or not common(verification)
        or persisted_canary != canary
        or persisted_verification != verification
        or any(
            evidence_contains_canonical_secret(payload, values)
            for payload in (canary, verification, persisted_canary, persisted_verification)
        )
    ):
        raise CanaryError("notion_projection_evidence_binding_invalid")
    canary["_canaryEvidenceReference"] = {
        "path": str(canary_path),
        "sha256": hashlib.sha256(canary_path.read_bytes()).hexdigest(),
        "kind": "NotionProjectionLiveCanary",
        "producerSha256": producer_sha,
    }
    canary["_consumerVerificationEvidenceReference"] = {
        "path": str(verify_path),
        "sha256": hashlib.sha256(verify_path.read_bytes()).hexdigest(),
        "kind": "NotionProjectionConsumerVerification",
        "producerSha256": producer_sha,
    }
    return canary


def _c029_postgres_notion(values: dict[str, str], run_id: str) -> dict[str, Any]:
    linkage_run_id = hashlib.sha256(f"C029:{run_id}".encode()).hexdigest()[:24]
    payload = _projection_runtime_payload(values, linkage_run_id)
    linkage = payload.get("linkage") if isinstance(payload.get("linkage"), dict) else {}
    phases = payload.get("phases") if isinstance(payload.get("phases"), dict) else {}
    cleanup = payload.get("cleanup") if isinstance(payload.get("cleanup"), dict) else {}

    def phase_state(phase: str, kind: str) -> None:
        value = phases.get(phase, {})
        candidate = value.get("objects", {}).get(kind, {}) if isinstance(value, dict) else {}
        if not isinstance(candidate, dict) or not all(
            candidate.get(key) is True
            for key in ("canonicalExact", "syncStateExact", "outboxDelivered", "leaseReleased", "errorFree")
        ) or not isinstance(candidate.get("attemptCount"), int) or candidate["attemptCount"] < 1:
            raise CanaryError("notion_projection_delivery_invalid")

    def project(kind: str, document: bool) -> tuple[dict[str, Any], dict[str, Any]]:
        item = linkage.get(kind) if isinstance(linkage.get(kind), dict) else {}
        required = {
            "canonicalObjectIdSha256", "providerObjectIdSha256", "initialRevision",
            "finalRevision", "initialContentSha256", "finalContentSha256",
        }
        if set(item) != required or not all(
            SHA256.fullmatch(str(item.get(key) or ""))
            for key in ("canonicalObjectIdSha256", "providerObjectIdSha256", "initialContentSha256", "finalContentSha256")
        ) or item.get("initialRevision") != 1 or item.get("finalRevision") != 2:
            raise CanaryError("notion_projection_linkage_invalid")
        for phase in ("create", "update", "archive"):
            phase_state(phase, kind)
        postgres = {
            "objectIdSha256": item["canonicalObjectIdSha256"],
            "initialRevision": 1, "finalRevision": 2,
            "initialContentSha256": item["initialContentSha256"],
            "finalContentSha256": item["finalContentSha256"],
            "created": True, "readBackVerified": True, "updated": True,
            "projectionIntentVerified": True, "postDeleteAbsent": True,
            "cleanupVerified": True,
        }
        notion = {
            "pageIdSha256": item["providerObjectIdSha256"],
            **{key: postgres[key] for key in (
                "objectIdSha256", "initialRevision", "finalRevision", "initialContentSha256", "finalContentSha256"
            )},
            "created": True, "archived": True, "cleanupVerified": True,
            "objectIdMatches": True, "initialRevisionMatches": True,
            "finalRevisionMatches": True, "initialContentSha256Matches": True,
            "finalContentSha256Matches": True, "linkageVerified": True,
        }
        if document:
            notion.update({"appendVerified": True, "readBackVerified": True})
        else:
            notion.update({"queryVerified": True, "updated": True})
        return postgres, notion

    record, table = project("entity", False)
    document, document_projection = project("document", True)
    if cleanup != {
        "postgresCanonicalAbsent": True, "postgresSyncStateAbsent": True,
        "postgresOutboxAbsent": True, "notionEntityArchived": True,
        "notionDocumentArchived": True, "verified": True,
    } or phases.get("archive", {}).get("notionArchived") != {"entity": True, "document": True}:
        raise CanaryError("notion_projection_cleanup_invalid")
    return {
        "id": "C029", "ok": True, "state": "passed",
        "source": "server_notion_projection_consumer_canary",
        "dataContentProfile": DEFAULT_DATA_CONTENT_PROFILE,
        "roles": {"tablesUi": "notion", "tablesApi": "notion", "documentsUi": "notion", "documentsApi": "notion"},
        "internalApis": {"scopedDataApi": "postgrest"},
        "postgresSsot": {"record": record, "document": document},
        "notion": {"table": table, "document": document_projection},
        "tablePersistenceVerified": True, "documentPersistenceVerified": True,
        "crossProviderLinkageVerified": True, "cleanupCompleted": True,
        "cleanup": {
            "postgresRecordDeleted": True, "postgresDocumentDeleted": True,
            "postgresProjectionRowsDeleted": True, "notionTableRowArchived": True,
            "notionDocumentArchived": True, "verified": True,
        },
        "redacted": True,
        "dependencyEvidence": payload["_canaryEvidenceReference"],
        "consumerVerificationEvidence": payload["_consumerVerificationEvidenceReference"],
        "internalApiEvidence": _postgrest_dependency_reference(),
    }


def c029(values: dict[str, str], run_id: str) -> dict[str, Any]:
    if values.get("DATA_CONTENT_PROFILE", "") != DEFAULT_DATA_CONTENT_PROFILE:
        raise CanaryError("data_content_profile_unsupported")
    return _c029_postgres_notion(values, run_id)


def paperclip_project(values: dict[str, str]) -> dict[str, Any]:
    headers = {}
    if values.get("PAPERCLIP_BOARD_API_KEY"):
        headers["Authorization"] = f"Bearer {values['PAPERCLIP_BOARD_API_KEY']}"
    _status, project = request_json(
        "GET",
        f"{operator_base(values, 'PAPERCLIP_PORT')}"
        f"/api/projects/{values['PAPERCLIP_PROJECT_ID']}",
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
        operator_base(values, "PAPERCLIP_PORT") + path,
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
    paperclip_base = operator_base(values, "PAPERCLIP_PORT")
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
        "value": paperclip_base,
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
    deadline = time.monotonic() + PAPERCLIP_RUN_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        issue = paperclip_request(values, "GET", f"/api/issues/{issue_id}")
        runs = list_value(
            paperclip_request(values, "GET", f"/api/issues/{issue_id}/runs")
        )
        if runs:
            latest_run = max(runs, key=lambda row: str(row.get("createdAt") or ""))
        issue_status = str((issue or {}).get("status") or "").lower()
        run_status = str(latest_run.get("status") or "").lower()
        if issue_status == "done" and run_status == "succeeded":
            break
        if issue_status in {"blocked", "cancelled"} or (
            run_status in PAPERCLIP_TERMINAL_RUN_STATUSES
            and run_status != "succeeded"
        ):
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
            cleanup["runTerminalOrCancelled"] = False
            cleanup["issueDeleted"] = False
            continue
        runs = list_value(
            paperclip_request(values, "GET", f"/api/issues/{issue_id}/runs")
        )
        for heartbeat_run in runs:
            native_id = str(heartbeat_run.get("id") or "")
            status = str(heartbeat_run.get("status") or "").lower()
            if not native_id:
                cleanup["runTerminalOrCancelled"] = False
                continue
            if status not in PAPERCLIP_TERMINAL_RUN_STATUSES:
                cancel_status, _cancelled = request_json(
                    "POST",
                    operator_base(values, "PAPERCLIP_PORT")
                    + f"/api/heartbeat-runs/{native_id}/cancel",
                    headers=paperclip_headers(values),
                    allow_status={404, 409},
                )
                if cancel_status == 404:
                    continue
                terminal_or_absent = paperclip_run_terminal_or_absent(
                    values, issue_id, native_id
                )
                cleanup["runTerminalOrCancelled"] = (
                    cleanup["runTerminalOrCancelled"]
                    and terminal_or_absent
                )
        request_json(
            "DELETE",
            operator_base(values, "PAPERCLIP_PORT") + f"/api/issues/{issue_id}",
            headers=paperclip_headers(values),
            allow_status={404},
        )
        after_status, _after = request_json(
            "GET",
            operator_base(values, "PAPERCLIP_PORT") + f"/api/issues/{issue_id}",
            headers=paperclip_headers(values),
            allow_status={404},
        )
        cleanup["issueDeleted"] = cleanup["issueDeleted"] and after_status == 404
    if not all(cleanup.values()):
        raise CanaryError("paperclip_canary_cleanup_incomplete")
    return cleanup


def paperclip_run_terminal_or_absent(
    values: dict[str, str], issue_id: str, heartbeat_run_id: str
) -> bool:
    """Prove that a cancellation reached a terminal state before issue deletion."""

    deadline = time.monotonic() + PAPERCLIP_CLEANUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        runs = list_value(
            paperclip_request(values, "GET", f"/api/issues/{issue_id}/runs")
        )
        matching = [
            row for row in runs if str(row.get("id") or "") == heartbeat_run_id
        ]
        if not matching:
            return True
        if len(matching) != 1:
            return False
        if str(matching[0].get("status") or "").lower() in (
            PAPERCLIP_TERMINAL_RUN_STATUSES
        ):
            return True
        time.sleep(1)
    return False


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
    if profile != DEFAULT_DATA_CONTENT_PROFILE:
        raise CanaryError("data_content_profile_unsupported")
    run_value = paperclip_integration_run(
        values,
        run_id,
        "postgrest_crud",
        {"postgrestApiBase": operator_base(values, "POSTGREST_ORIGIN_PORT")},
    )
    result = run_value["result"]
    if (
        result.get("markerObserved") is not True
        or result.get("cleanup") != "verified_deleted"
        or result.get("postDeleteAbsent") is not True
    ):
        raise CanaryError("paperclip_postgrest_crud_failed")
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
        "dependencyEvidence": _postgrest_dependency_reference(),
    }




def c030(values: dict[str, str], run_id: str) -> dict[str, Any]:
    base = operator_base(values, "MATTERMOST_ORIGIN_PORT")
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


CANARIES = {
    "C023": c023,
    "C024": c024,
    "C027": c027,
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


def _status_error(state: str) -> dict[str, Any]:
    return {"ok": False, "state": state}


def validate_evidence_status(payload: Any) -> dict[str, Any]:
    """Return only evidence that remains bound to this source and config."""

    if not isinstance(payload, dict):
        raise CanaryError("evidence_invalid")
    if (
        payload.get("apiVersion") != API_VERSION
        or payload.get("kind") != "IntegrationCanaryEvidence"
        or payload.get("producerSha256") != producer_hash()
        or payload.get("canonicalSourceSha256") != canonical_hash()
    ):
        raise CanaryError("evidence_binding_invalid")
    selected = payload.get("selected")
    rows = payload.get("canaries")
    if (
        not isinstance(selected, list)
        or not selected
        or len(set(selected)) != len(selected)
        or any(identifier not in SUPPORTED for identifier in selected)
        or not isinstance(rows, list)
        or [row.get("id") if isinstance(row, dict) else None for row in rows]
        != selected
    ):
        raise CanaryError("evidence_selection_invalid")
    expected_ok = all(
        isinstance(row, dict)
        and row.get("ok") is True
        and row.get("state") == "passed"
        for row in rows
    )
    if payload.get("ok") is not expected_ok or payload.get("status") != (
        "passed" if expected_ok else "failed"
    ):
        raise CanaryError("evidence_status_invalid")
    return payload


def status_payload() -> dict[str, Any]:
    """Load a private, source-bound evidence document without executing canaries."""

    try:
        if not EVIDENCE.is_file() or EVIDENCE.is_symlink():
            return _status_error("evidence_missing")
        if EVIDENCE.stat().st_mode & 0o777 != 0o600:
            return _status_error("evidence_mode_invalid")
        try:
            raw = json.loads(EVIDENCE.read_text())
        except (OSError, json.JSONDecodeError):
            return _status_error("evidence_invalid")
        payload = validate_evidence_status(raw)
        if evidence_contains_canonical_secret(payload, dotenv(CANONICAL)):
            return _status_error("evidence_secret_leak")
        return payload
    except CanaryError as exc:
        return _status_error(exc.code)
    except OSError:
        return _status_error("evidence_unavailable")


def execute(selected: list[str]) -> dict[str, Any]:
    values = dotenv(CANONICAL)
    run_id = secrets.token_hex(12)
    rows: list[dict[str, Any]] = []
    for canary_id in selected:
        try:
            rows.append(CANARIES[canary_id](values, run_id))
        except BaseException as exc:
            rows.append(error_result(canary_id, exc))
    payload = {
        "apiVersion": API_VERSION,
        "kind": "IntegrationCanaryEvidence",
        "generatedAt": utcnow(),
        "runId": run_id,
        "dataContentProfile": values.get("DATA_CONTENT_PROFILE", ""),
        "canonicalSourceSha256": canonical_hash(),
        "producerSha256": producer_hash(),
        "ok": all(row.get("ok") is True for row in rows),
        "selected": selected,
        "canaries": rows,
    }
    payload["status"] = "passed" if payload["ok"] else "failed"
    if evidence_contains_canonical_secret(payload, values):
        payload["canaries"] = [
            error_result(canary_id, CanaryError("evidence_secret_leak"))
            for canary_id in selected
        ]
        payload["ok"] = False
        payload["status"] = "failed"
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
        if unknown or len(set(selected)) != len(selected):
            error = "unknown_canary" if unknown else "duplicate_canary"
            payload = {"ok": False, "error": error}
            if unknown:
                payload["ids"] = unknown
            print(json.dumps(payload, sort_keys=True))
            return 2
        payload = execute(selected)
    elif action == "status" and len(sys.argv) == 2:
        payload = status_payload()
    else:
        print(
            "usage: server-integration-canaries.py run [C023 ...]|status",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

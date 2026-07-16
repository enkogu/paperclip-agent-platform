#!/usr/bin/env python3
"""Run and verify the Kestra -> Paperclip -> Daytona -> GitHub canary.

The controller is deliberately independent from the implementation under test.
It reads deployment-specific values from the rendered platform config and
root-only runtime refs, never writes credentials to Kestra, and emits only
allowlisted evidence.  GitHub's public API is used for observation; the token
is used only after evidence capture to close the draft PR and delete the canary
branch.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

import yaml


ROOT = Path(os.environ.get("MTE_ROOT", "/opt/mte-platform"))
CONFIG = ROOT / "config/platform.json"
PLATFORM_ENV = Path(
    os.environ.get("MTE_PLATFORM_ENV", "/root/.config/mte-secrets/platform.env")
)
FLOW = ROOT / "manifests/kestra/flows/paperclip-github-e2e.yaml"
# The profile template is synchronized under templates/ and the renderer writes
# the only active runtime projection under runtime/profiles/.  Historical
# copies under manifests/profiles/ or runtime/paperclip/profiles/ are not E2E
# inputs and must never silently replace these paths.
PROFILE_SOURCE = ROOT / "templates/profiles/profiles.yaml"
PROFILES = ROOT / "runtime/profiles/profiles.yaml"
PAPERCLIP_RUNTIME_SOURCE = ROOT / "steps/50-paperclip.sh"
DAYTONA_EVIDENCE = ROOT / "evidence/paperclip-daytona-control-plane.json"
DAYTONA_VERIFY_EVIDENCE = ROOT / "evidence/paperclip-daytona-verify.json"
DAYTONA_IMAGES_EVIDENCE = ROOT / "evidence/daytona-images.json"
DAYTONA_LIFECYCLE_EVIDENCE = ROOT / "evidence/daytona-lifecycle.json"
EVIDENCE = ROOT / "evidence/kestra-paperclip-github-e2e.json"
VERIFICATION_EVIDENCE = ROOT / "evidence/kestra-paperclip-github-e2e-verify.json"
GATEWAY_SOURCE = ROOT / "bin/agent-plane-gateway.py"
PROFILE_RECONCILE_EVIDENCE = ROOT / "evidence/profile-reconcile.json"
PROFILE_RECONCILE_SOURCE = ROOT / "bin/server-profile-reconcile.py"
DAYTONA_STEP_SOURCE = ROOT / "steps/60-daytona.sh"
GITHUB_API = "https://api.github.com"
TERMINAL = {"SUCCESS", "WARNING", "FAILED", "KILLED", "CANCELLED"}
PASS_CONCLUSIONS = {"success"}
EVIDENCE_MAX_AGE_SECONDS = 600
FUTURE_SKEW_SECONDS = 60
FULL_SHA256 = re.compile(r"[0-9a-f]{64}")
FULL_GIT_SHA = re.compile(r"[0-9a-f]{40}")
E2E_EVIDENCE_SCHEMA = "paperclip-agent-platform/e2e-evidence/v2"
HARNESS_EVIDENCE_SCHEMA = "paperclip-agent-platform/harness-evidence/v3"
REQUIRED_GITHUB_CHECK_NAME = "paperclip-e2e"
ALLOWED_GITHUB_PATHS = (
    ".github/workflows/paperclip-e2e.yml",
    "paperclip-e2e/marker.py",
    "paperclip-e2e/test_marker.py",
)
NATIVE_EXECUTABLES = {
    "codex_local": "codex",
    "claude_local": "claude",
    "pi_local": "pi",
}
NATIVE_VERSION_REFS = {
    "codex_local": "CODEX_CLI_VERSION",
    "claude_local": "CLAUDE_CODE_CLI_VERSION",
    "pi_local": "PI_CLI_VERSION",
}


class CanaryError(RuntimeError):
    def __init__(self, code: str, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise CanaryError(
            "source_missing", f"cannot read canonical source {path}"
        ) from exc


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise CanaryError("invalid_local_state", f"cannot read {path}") from exc
    if not isinstance(value, dict):
        raise CanaryError("invalid_local_state", f"{path} must contain an object")
    return value


def require_private_evidence_file(path: Path) -> None:
    """Fail closed on replaced, linked, or over-readable evidence files."""
    try:
        mode = path.stat().st_mode & 0o777
    except OSError as exc:
        raise CanaryError("evidence_file_invalid", f"cannot stat {path}") from exc
    if not path.is_file() or path.is_symlink() or mode != 0o600:
        raise CanaryError(
            "evidence_file_invalid",
            f"{path} must be a regular non-symlink file with mode 0600",
        )


def require_fresh_timestamp(
    value: Any,
    field: str,
    *,
    max_age_seconds: int = EVIDENCE_MAX_AGE_SECONDS,
) -> datetime:
    moment = parse_timestamp(value, field)
    now = datetime.now(timezone.utc)
    age = (now - moment).total_seconds()
    if age < -FUTURE_SKEW_SECONDS or age > max_age_seconds:
        raise CanaryError(
            "evidence_stale", f"{field} is outside the live evidence window"
        )
    return moment


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


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def write_verification_attestation(
    *,
    status: str,
    subject_sha: str,
    canonical_sha: str,
    producer_sha: str,
    values: dict[str, str],
    sources: dict[str, Any] | None = None,
    runs: list[dict[str, Any]] | None = None,
    cleanup_verified: bool = False,
    toolhive_gateway_audit: dict[str, Any] | None = None,
    apply_finished_at: str | None = None,
    cross_run_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if status not in {"running", "passed"}:
        raise CanaryError(
            "verification_status_invalid", "unsupported verification status"
        )
    if not all(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
        for value in (subject_sha, canonical_sha, producer_sha)
    ):
        raise CanaryError(
            "verification_hash_invalid", "verification attestation hash is malformed"
        )
    payload: dict[str, Any] = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "KestraPaperclipGitHubE2EVerification",
        "schemaVersion": E2E_EVIDENCE_SCHEMA,
        "status": status,
        "canonicalSourceSha256": canonical_sha,
        "producerPath": str(Path(__file__)),
        "producerSha256": producer_sha,
        "subjectEvidencePath": str(EVIDENCE),
        "subjectEvidenceSha256": subject_sha,
    }
    if status == "running":
        payload["startedAt"] = utcnow()
    else:
        if (
            not isinstance(runs, list)
            or len(runs) != 3
            or cleanup_verified is not True
            or not isinstance(toolhive_gateway_audit, dict)
            or toolhive_gateway_audit.get("status") != "passed"
            or not isinstance(cross_run_identity, dict)
            or cross_run_identity.get("status") != "passed"
            or not apply_finished_at
        ):
            raise CanaryError(
                "verification_evidence_incomplete",
                "passed verification must contain exactly three cleaned-up runs",
            )
        payload.update(
            {
                "verifiedAt": utcnow(),
                "sources": sources if isinstance(sources, dict) else {},
                "runs": runs,
                "cleanupVerified": True,
                "toolhiveGatewayAudit": toolhive_gateway_audit,
                "applyFinishedAt": apply_finished_at,
                "crossRunIdentity": cross_run_identity,
            }
        )
    scan_for_secrets(payload, values)
    atomic_json(VERIFICATION_EVIDENCE, payload)
    return payload


def request_json(
    url: str,
    method: str = "GET",
    *,
    body: Any | None = None,
    raw: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    allow_status: set[int] | None = None,
) -> tuple[int, Any]:
    request_headers = {"Accept": "application/json", **(headers or {})}
    data = raw
    if body is not None:
        data = json.dumps(body).encode()
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(
        url, data=data, method=method, headers=request_headers
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
            content = response.read()
    except urllib.error.HTTPError as exc:
        # Never include remote response bodies: a provider or harness can echo
        # a submitted credential in an error payload.
        if allow_status and exc.code in allow_status:
            return exc.code, None
        raise CanaryError(
            "remote_http_error",
            f"{method} request returned HTTP {exc.code}",
            status=exc.code,
        ) from exc
    except urllib.error.URLError as exc:
        raise CanaryError(
            "remote_unavailable", f"{method} request is unavailable"
        ) from exc
    if not content:
        return status, None
    try:
        return status, json.loads(content)
    except json.JSONDecodeError as exc:
        raise CanaryError(
            "invalid_remote_response", f"{method} request returned non-JSON"
        ) from exc


def paperclip_headers(values: dict[str, str]) -> dict[str, str]:
    """Return native Paperclip auth without ever projecting it into Kestra."""

    token = values.get("PAPERCLIP_BOARD_API_KEY", "")
    return {"Authorization": f"Bearer {token}"} if token else {}


def paperclip_request(
    base: str,
    values: dict[str, str],
    method: str,
    path: str,
    *,
    body: Any | None = None,
    allow_status: set[int] | None = None,
) -> tuple[int, Any]:
    if not path.startswith("/api/"):
        raise CanaryError("paperclip_path_invalid", "native path must start /api/")
    return request_json(
        base.rstrip("/") + path,
        method,
        body=body,
        headers=paperclip_headers(values),
        allow_status=allow_status,
    )


def object_rows(value: Any, *keys: str) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in keys:
            nested = value.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
    return []


def first_value(*values: Any) -> Any:
    return next((value for value in values if value not in (None, "")), None)


def native_state(issue: dict[str, Any], run: dict[str, Any] | None) -> str:
    issue_status = str(issue.get("status") or "")
    run_status = str((run or {}).get("status") or "")
    if issue_status == "cancelled" or run_status == "cancelled":
        return "cancelled"
    if issue_status == "done":
        return "succeeded"
    if run_status in {"failed", "timed_out"}:
        return run_status
    if issue_status in {"blocked", "in_review"}:
        return "waiting_input"
    if run_status in {"queued", "scheduled_retry"}:
        return "queued"
    if run_status in {"running", "succeeded"}:
        return run_status
    if issue_status in {"todo", "backlog"}:
        return "queued"
    if issue_status == "in_progress":
        return "running"
    return "provisioning"


def native_issue_projection(
    base: str, values: dict[str, str], issue_id: str
) -> dict[str, Any]:
    """Read one run from Paperclip's own issue/heartbeat/lease resources."""

    _, issue_value = paperclip_request(base, values, "GET", f"/api/issues/{issue_id}")
    _, runs_value = paperclip_request(
        base, values, "GET", f"/api/issues/{issue_id}/runs"
    )
    if not isinstance(issue_value, dict):
        raise CanaryError("invalid_paperclip_response", "issue is not an object")
    runs = object_rows(runs_value, "runs", "items", "data")
    run = max(runs, key=lambda row: str(row.get("createdAt") or ""), default=None)
    heartbeat: dict[str, Any] = {}
    events: list[dict[str, Any]] = []
    wakes: list[dict[str, Any]] = []
    if run and run.get("id"):
        run_id = str(run["id"])
        _, heartbeat_value = paperclip_request(
            base, values, "GET", f"/api/heartbeat-runs/{run_id}"
        )
        _, events_value = paperclip_request(
            base, values, "GET", f"/api/heartbeat-runs/{run_id}/events"
        )
        _, wakes_value = paperclip_request(
            base, values, "GET", f"/api/issues/{issue_id}/diagnostics/wakes"
        )
        heartbeat = heartbeat_value if isinstance(heartbeat_value, dict) else {}
        events = object_rows(events_value, "events", "items", "data")
        wakes = object_rows(wakes_value, "events", "wakes", "items", "data")

    run_id = str((run or {}).get("id") or "")
    ordered_events = sorted(
        (row for row in events if row.get("createdAt") and row.get("seq") is not None),
        key=lambda row: (int(row.get("seq") or 0), str(row.get("createdAt") or "")),
    )
    matching_wakes = [row for row in wakes if str(row.get("runId") or "") == run_id]
    wake = min(
        matching_wakes,
        key=lambda row: str(row.get("claimedAt") or row.get("requestedAt") or ""),
        default={},
    )
    agent_id = first_value(heartbeat.get("agentId"), (run or {}).get("agentId"))
    claim = {
        "leaseId": heartbeat.get("wakeupRequestId"),
        "claimant": {
            "type": "paperclip_agent",
            "id": agent_id,
            "adapterType": (run or {}).get("adapterType"),
        },
        "claimedAt": wake.get("claimedAt"),
        "firstHeartbeatAt": min(
            (str(row["createdAt"]) for row in ordered_events), default=None
        ),
        "claimantCount": len(matching_wakes),
        "token": None,
    }
    terminal = {"succeeded", "failed", "cancelled", "timed_out"}
    heartbeat_sequence: list[dict[str, Any]] = []
    for index, event in enumerate(ordered_events):
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        status = payload.get("status")
        heartbeat_sequence.append(
            {
                "runId": event.get("runId") or run_id,
                "agentId": event.get("agentId") or agent_id,
                "seq": event.get("seq"),
                "eventType": event.get("eventType"),
                "phase": (
                    "terminal"
                    if status in terminal
                    else "in_progress"
                    if index > 0
                    else "started"
                ),
                "status": status,
                "createdAt": event.get("createdAt"),
            }
        )
    final_result = {
        "source": "paperclip.heartbeat-run",
        "runId": str(heartbeat.get("id") or run_id),
        "runnerId": agent_id,
        "status": first_value(heartbeat.get("status"), (run or {}).get("status")),
        "recordedAt": first_value(
            heartbeat.get("finishedAt"),
            heartbeat.get("completedAt"),
            heartbeat.get("updatedAt"),
        ),
    }
    final_result["recordFingerprintSha256"] = hashlib.sha256(
        json.dumps(final_result, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    environment_summary = (
        (run or {}).get("environmentLease")
        if isinstance((run or {}).get("environmentLease"), dict)
        else {}
    )
    environment_lease_id = str(environment_summary.get("id") or "")
    environment_lease: dict[str, Any] = {}
    if environment_lease_id:
        _, lease_value = paperclip_request(
            base,
            values,
            "GET",
            f"/api/environment-leases/{environment_lease_id}",
        )
        environment_lease = lease_value if isinstance(lease_value, dict) else {}
    metadata = (
        environment_lease.get("metadata")
        if isinstance(environment_lease.get("metadata"), dict)
        else {}
    )
    context = (
        heartbeat.get("contextSnapshot")
        if isinstance(heartbeat.get("contextSnapshot"), dict)
        else {}
    )
    workspace_context = (
        context.get("paperclipWorkspace")
        if isinstance(context.get("paperclipWorkspace"), dict)
        else {}
    )
    environment_context = (
        context.get("paperclipEnvironment")
        if isinstance(context.get("paperclipEnvironment"), dict)
        else {}
    )
    environment = {
        "provider": first_value(
            environment_lease.get("provider"),
            environment_summary.get("provider"),
            metadata.get("provider"),
            environment_context.get("provider"),
        ),
        "environmentId": first_value(
            environment_lease.get("environmentId"),
            environment_summary.get("environmentId"),
            environment_context.get("id"),
        ),
        "environmentLeaseId": environment_lease_id or None,
        "providerLeaseId": first_value(
            environment_lease.get("providerLeaseId"),
            environment_summary.get("providerLeaseId"),
            metadata.get("providerLeaseId"),
        ),
        "executionWorkspaceId": first_value(
            environment_lease.get("executionWorkspaceId"),
            environment_summary.get("executionWorkspaceId"),
            workspace_context.get("id"),
            context.get("executionWorkspaceId"),
        ),
        "remoteCwd": first_value(
            environment_lease.get("workspacePath"),
            environment_summary.get("workspacePath"),
            metadata.get("remoteCwd"),
            metadata.get("workspacePath"),
            workspace_context.get("cwd"),
            workspace_context.get("path"),
        ),
        "status": first_value(
            environment_lease.get("status"), environment_summary.get("status")
        ),
        "cleanupStatus": first_value(
            environment_lease.get("cleanupStatus"),
            environment_summary.get("cleanupStatus"),
        ),
    }
    environment["sandboxId"] = first_value(
        metadata.get("sandboxId"), environment["providerLeaseId"]
    )
    silence = (run or {}).get("outputSilence") or {}
    return {
        "id": issue_id,
        "status": native_state(issue_value, run),
        "native": {
            "platform": "paperclip",
            "issueId": issue_id,
            "issueIdentifier": issue_value.get("identifier"),
            "issueStatus": issue_value.get("status"),
            "heartbeatRunId": run_id or None,
            "heartbeatStatus": (run or {}).get("status"),
            "lastOutputAt": (run or {}).get("lastOutputAt"),
            "lastUsefulActionAt": (run or {}).get("lastUsefulActionAt"),
            "livenessState": (run or {}).get("livenessState"),
            "outputSilence": silence,
        },
        "stuckDetection": {
            "suspected": silence.get("level") in {"suspicious", "critical"},
            "level": silence.get("level", "unknown"),
            "reason": (run or {}).get("livenessReason"),
        },
        "claim": claim,
        "heartbeatSequence": heartbeat_sequence,
        "finalResult": final_result,
        "environment": environment,
        "_issue": issue_value,
        "_run": run,
    }


def native_harness_artifacts(
    base: str, values: dict[str, str], issue_id: str
) -> list[dict[str, Any]]:
    _, document = paperclip_request(
        base,
        values,
        "GET",
        f"/api/issues/{issue_id}/documents/harness-evidence",
    )
    if not isinstance(document, dict):
        raise CanaryError(
            "harness_evidence_missing", "native keyed document is not an object"
        )
    return [
        {
            "name": "harness-evidence",
            "kind": "paperclip-issue-document",
            "contentType": "application/json",
            "title": document.get("title"),
            "content": document.get("body"),
            "nativeId": document.get("id"),
        }
    ]


def basic_auth(values: dict[str, str]) -> dict[str, str]:
    username = values.get("KESTRA_ADMIN_USER", "")
    password = values.get("KESTRA_ADMIN_PASSWORD", "")
    if not username or not password:
        raise CanaryError("missing_auth_ref", "Kestra basic-auth refs are missing")
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def component_origin(config: dict[str, Any], component_id: str) -> str:
    components = config.get("spec", {}).get("components", [])
    for component in components:
        if not isinstance(component, dict) or component.get("id") != component_id:
            continue
        exposure = component.get("exposure")
        if isinstance(exposure, dict) and exposure.get("origin"):
            return str(exposure["origin"]).rstrip("/")
        health = component.get("health")
        if isinstance(health, dict) and health.get("url"):
            parsed = urllib.parse.urlsplit(str(health["url"]))
            return urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, "", "", "")
            ).rstrip("/")
    raise CanaryError(
        "missing_endpoint", f"canonical endpoint for {component_id} is missing"
    )


def safe_slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()


def usage_requests(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, dict):
        for key in ("requests", "count", "totalRequests"):
            count = value.get(key)
            if isinstance(count, (int, float)) and not isinstance(count, bool):
                return int(count)
    return 0


def ninerouter_database_path() -> Path:
    override = os.environ.get("MTE_NINEROUTER_DB_PATH", "")
    if override:
        path = Path(override)
    else:
        try:
            result = subprocess.run(
                [
                    "docker",
                    "volume",
                    "inspect",
                    "mte-9router-data",
                    "--format",
                    "{{.Mountpoint}}",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise CanaryError(
                "router_history_unavailable",
                "cannot resolve the 9router server-side database volume",
            ) from exc
        path = Path(result.stdout.strip()) / "db/data.sqlite"
    try:
        if not path.is_file() or path.is_symlink():
            raise OSError("not a regular file")
    except OSError as exc:
        raise CanaryError(
            "router_history_unavailable",
            "9router server-side database is not a regular file",
        ) from exc
    return path


def router_history_snapshot(values: dict[str, str], profile: str) -> dict[str, Any]:
    key_ref = f"NINEROUTER_PROFILE_{safe_slug(profile)}_API_KEY"
    api_key = values.get(key_ref, "")
    if not api_key:
        raise CanaryError("missing_router_ref", "profile-scoped 9router key is missing")
    try:
        with sqlite3.connect(
            f"file:{ninerouter_database_path()}?mode=ro", uri=True, timeout=10
        ) as database:
            row = database.execute(
                "SELECT COALESCE(MAX(id), 0) FROM usageHistory WHERE apiKey = ?",
                (api_key,),
            ).fetchone()
    except sqlite3.Error as exc:
        raise CanaryError(
            "router_history_unavailable",
            "cannot query the 9router server-side usage history",
        ) from exc
    return {
        "historyMaxId": int((row or [0])[0] or 0),
        "historyCapturedAt": utcnow(),
    }


def router_usage_snapshot(
    config: dict[str, Any],
    values: dict[str, str],
    profile: str,
    model: str,
) -> dict[str, Any]:
    password = values.get("NINEROUTER_INITIAL_PASSWORD", "")
    key_ref = f"NINEROUTER_PROFILE_{safe_slug(profile)}_API_KEY"
    profile_key = values.get(key_ref, "")
    if not password or not profile_key:
        raise CanaryError(
            "missing_router_ref",
            "9router dashboard or profile-scoped credential ref is missing",
        )
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    base = component_origin(config, "9router")

    def call(method: str, path: str, body: Any | None = None) -> Any:
        raw = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            base + path,
            data=raw,
            method=method,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        try:
            with opener.open(request, timeout=30) as response:
                content = response.read()
        except urllib.error.HTTPError as exc:
            raise CanaryError(
                "router_usage_http_error",
                f"9router usage request returned HTTP {exc.code}",
                status=exc.code,
            ) from exc
        except urllib.error.URLError as exc:
            raise CanaryError(
                "router_usage_unavailable", "9router usage request is unavailable"
            ) from exc
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            raise CanaryError(
                "router_usage_invalid", "9router usage response is not JSON"
            ) from exc

    call("POST", "/api/auth/login", {"password": password})
    usage = call("GET", "/api/usage/history")
    if not isinstance(usage, dict):
        raise CanaryError(
            "router_usage_invalid", "9router usage response is not an object"
        )
    by_api_key = (
        usage.get("byApiKey") if isinstance(usage.get("byApiKey"), dict) else {}
    )
    by_model = usage.get("byModel") if isinstance(usage.get("byModel"), dict) else {}
    key_candidates = (profile_key, f"mte-profile-{profile}", key_ref)
    model_candidates = (model, model.split("/", 1)[-1])
    return {
        "profileKeyRef": key_ref,
        "profileKeyRequests": sum(
            usage_requests(by_api_key.get(key)) for key in key_candidates
        ),
        "model": model,
        "modelRequests": sum(
            usage_requests(by_model.get(key)) for key in set(model_candidates)
        ),
        "totalRequests": usage_requests(usage.get("totalRequests")),
        **router_history_snapshot(values, profile),
    }


def router_usage_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    if before.get("profileKeyRef") != after.get("profileKeyRef") or before.get(
        "model"
    ) != after.get("model"):
        raise CanaryError(
            "router_usage_mismatch", "9router usage snapshots describe different routes"
        )
    result = {
        "profileKeyRef": after.get("profileKeyRef"),
        "model": after.get("model"),
        "profileKeyRequestsBefore": before.get("profileKeyRequests"),
        "profileKeyRequestsAfter": after.get("profileKeyRequests"),
        "profileKeyRequestsDelta": int(after.get("profileKeyRequests", 0))
        - int(before.get("profileKeyRequests", 0)),
        "modelRequestsBefore": before.get("modelRequests"),
        "modelRequestsAfter": after.get("modelRequests"),
        "modelRequestsDelta": int(after.get("modelRequests", 0))
        - int(before.get("modelRequests", 0)),
        "totalRequestsBefore": before.get("totalRequests"),
        "totalRequestsAfter": after.get("totalRequests"),
        "totalRequestsDelta": int(after.get("totalRequests", 0))
        - int(before.get("totalRequests", 0)),
        "historyMaxIdBefore": before.get("historyMaxId"),
        "historyMaxIdAfter": after.get("historyMaxId"),
        "historyCapturedAtBefore": before.get("historyCapturedAt"),
        "historyCapturedAtAfter": after.get("historyCapturedAt"),
    }
    if (
        result["profileKeyRequestsDelta"] <= 0
        or result["modelRequestsDelta"] <= 0
        or result["totalRequestsDelta"] <= 0
    ):
        raise CanaryError(
            "router_usage_not_proven",
            "9router counters did not increase for the profile-scoped key and model",
        )
    return result


def router_server_attribution(
    values: dict[str, str],
    profile: str,
    adapter: str,
    model: str,
    router: dict[str, Any],
) -> dict[str, Any]:
    key_ref = f"NINEROUTER_PROFILE_{safe_slug(profile)}_API_KEY"
    api_key = values.get(key_ref, "")
    expected_connection = values.get("NINEROUTER_MINIMAX_CONNECTION_ID", "")
    before_id = router.get("historyMaxIdBefore")
    after_id = router.get("historyMaxIdAfter")
    before_at = parse_timestamp(
        router.get("historyCapturedAtBefore"), "router.historyCapturedAtBefore"
    )
    after_at = parse_timestamp(
        router.get("historyCapturedAtAfter"), "router.historyCapturedAtAfter"
    )
    endpoint_by_adapter = {
        "codex_local": "/v1/responses",
        "claude_local": "/v1/messages",
        "pi_local": "/v1/chat/completions",
    }
    expected_endpoint = endpoint_by_adapter.get(adapter)
    if (
        not api_key
        or not expected_connection
        or not isinstance(before_id, int)
        or isinstance(before_id, bool)
        or not isinstance(after_id, int)
        or isinstance(after_id, bool)
        or after_id <= before_id
        or after_at <= before_at
        or expected_endpoint is None
    ):
        raise CanaryError(
            "router_server_attribution_failed",
            "9router server-side attribution interval is incomplete",
        )
    try:
        with sqlite3.connect(
            f"file:{ninerouter_database_path()}?mode=ro", uri=True, timeout=10
        ) as database:
            database.row_factory = sqlite3.Row
            rows = database.execute(
                """
                SELECT id, timestamp, provider, model, connectionId, status, endpoint
                FROM usageHistory
                WHERE apiKey = ? AND id > ? AND id <= ?
                ORDER BY id ASC
                """,
                (api_key, before_id, after_id),
            ).fetchall()
            connection = database.execute(
                "SELECT id, provider, name, isActive FROM providerConnections WHERE id = ?",
                (expected_connection,),
            ).fetchone()
            detail_rows = database.execute(
                """
                SELECT id, timestamp, provider, model, connectionId, status, data
                FROM requestDetails
                WHERE connectionId = ? AND timestamp >= ? AND timestamp <= ?
                ORDER BY timestamp ASC, id ASC
                """,
                (
                    expected_connection,
                    router.get("historyCapturedAtBefore"),
                    router.get("historyCapturedAtAfter"),
                ),
            ).fetchall()
    except sqlite3.Error as exc:
        raise CanaryError(
            "router_server_attribution_failed",
            "9router server-side attribution query failed",
        ) from exc
    leaf_model = model.split("/")[-1]
    timestamps = [
        parse_timestamp(row["timestamp"], "usageHistory.timestamp") for row in rows
    ]
    if (
        not rows
        or connection is None
        or connection["isActive"] not in (1, True)
        or connection["name"] != "mte-minimax-primary"
        or any(row["connectionId"] != expected_connection for row in rows)
        or any(row["provider"] != connection["provider"] for row in rows)
        or any(row["model"] != leaf_model for row in rows)
        or any(row["status"] != "ok" for row in rows)
        or expected_endpoint not in {row["endpoint"] for row in rows}
        or any(moment < before_at or moment > after_at for moment in timestamps)
    ):
        raise CanaryError(
            "router_server_attribution_failed",
            "9router server-side history does not bind this run to the scoped MiniMax route",
        )
    request_fingerprints = [
        hashlib.sha256(
            "|".join(
                str(row[key])
                for key in (
                    "id",
                    "timestamp",
                    "provider",
                    "model",
                    "connectionId",
                    "status",
                    "endpoint",
                )
            ).encode()
        ).hexdigest()
        for row in rows
    ]
    detail_documents: list[tuple[sqlite3.Row, str, dict[str, Any]]] = []
    for row in detail_rows:
        raw_data = row["data"]
        try:
            detail = json.loads(raw_data)
        except (TypeError, json.JSONDecodeError) as exc:
            raise CanaryError(
                "router_request_binding_failed",
                "9router requestDetails contains malformed JSON in the run interval",
            ) from exc
        detail_at = parse_timestamp(row["timestamp"], "requestDetails.timestamp")
        if (
            row["connectionId"] != expected_connection
            or row["provider"] != connection["provider"]
            or row["model"] != leaf_model
            or row["status"] not in {"ok", "success"}
            or detail_at < before_at
            or detail_at > after_at
        ):
            raise CanaryError(
                "router_request_binding_failed",
                "9router requestDetails row is outside the exact MiniMax route interval",
            )
        detail_documents.append(
            (row, hashlib.sha256(str(raw_data).encode()).hexdigest(), detail)
        )
    if not detail_documents:
        raise CanaryError(
            "router_request_binding_failed",
            "9router has no server-side request detail in the profile run interval",
        )
    usage_ids: set[int] = set()

    def collect_usage_ids(value: Any) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if key in {"usageHistoryId", "usageId"} and isinstance(nested, int):
                    usage_ids.add(nested)
                collect_usage_ids(nested)
        elif isinstance(value, list):
            for nested in value:
                collect_usage_ids(nested)

    for _, _, detail_document in detail_documents:
        collect_usage_ids(detail_document)
    row_ids = {int(row["id"]) for row in rows}
    if len(rows) == 1:
        correlated_usage_ids = {int(rows[0]["id"])}
        if usage_ids and usage_ids != correlated_usage_ids:
            raise CanaryError(
                "router_usage_correlation_failed",
                "requestDetails usage identity disagrees with the singleton usage row",
            )
    elif usage_ids and usage_ids <= row_ids:
        correlated_usage_ids = set(usage_ids)
    else:
        raise CanaryError(
            "router_usage_correlation_failed",
            "requestDetails is not joined to the profile-scoped usageHistory interval",
        )
    usages: set[tuple[int, int, int]] = set()

    def collect_usage(value: Any) -> None:
        if isinstance(value, dict):
            input_tokens = value.get("input_tokens", value.get("prompt_tokens"))
            output_tokens = value.get("output_tokens", value.get("completion_tokens"))
            total_tokens = value.get("total_tokens")
            if (
                isinstance(input_tokens, int)
                and not isinstance(input_tokens, bool)
                and isinstance(output_tokens, int)
                and not isinstance(output_tokens, bool)
            ):
                total = (
                    total_tokens
                    if isinstance(total_tokens, int)
                    and not isinstance(total_tokens, bool)
                    else input_tokens + output_tokens
                )
                usages.add((input_tokens, output_tokens, total))
            for nested in value.values():
                collect_usage(nested)
        elif isinstance(value, list):
            for nested in value:
                collect_usage(nested)

    for _, _, detail_document in detail_documents:
        collect_usage(detail_document)
    positive_usages = sorted(
        usage
        for usage in usages
        if usage[0] > 0 and usage[1] > 0 and usage[2] == usage[0] + usage[1]
    )
    if not positive_usages:
        raise CanaryError(
            "router_llm_usage_mismatch",
            "9router requestDetails contains no positive internally consistent LLM usage",
        )

    completion_hashes: set[str] = set()

    def collect_completion_hashes(value: Any) -> None:
        if isinstance(value, dict):
            explicit = value.get("completionSha256")
            if isinstance(explicit, str) and FULL_SHA256.fullmatch(explicit):
                completion_hashes.add(explicit)
            output_text = value.get("output_text")
            if isinstance(output_text, str) and output_text:
                completion_hashes.add(hashlib.sha256(output_text.encode()).hexdigest())
            message = value.get("message")
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                completion_hashes.add(
                    hashlib.sha256(message["content"].encode()).hexdigest()
                )
            content = value.get("content")
            if isinstance(content, list):
                text_parts = [
                    str(item.get("text"))
                    for item in content
                    if isinstance(item, dict)
                    and item.get("type") in {"text", "output_text"}
                    and isinstance(item.get("text"), str)
                ]
                if text_parts:
                    completion_hashes.add(
                        hashlib.sha256("".join(text_parts).encode()).hexdigest()
                    )
            output = value.get("output")
            if isinstance(output, list):
                output_parts = [
                    str(part.get("text"))
                    for item in output
                    if isinstance(item, dict)
                    for part in (item.get("content") or [])
                    if isinstance(part, dict)
                    and part.get("type") in {"text", "output_text"}
                    and isinstance(part.get("text"), str)
                ]
                if output_parts:
                    completion_hashes.add(
                        hashlib.sha256("".join(output_parts).encode()).hexdigest()
                    )
            for nested in value.values():
                collect_completion_hashes(nested)
        elif isinstance(value, list):
            for nested in value:
                collect_completion_hashes(nested)

    for _, _, detail_document in detail_documents:
        collect_completion_hashes(detail_document)
    if not completion_hashes:
        raise CanaryError(
            "router_llm_completion_mismatch",
            "9router requestDetails contains no completion fingerprint",
        )
    request_binding = {
        "status": "passed",
        "source": "9router.sqlite.requestDetails",
        "detailCount": len(detail_documents),
        "detailIdFingerprintsSha256": [
            hashlib.sha256(str(row["id"]).encode()).hexdigest()
            for row, _, _ in detail_documents
        ],
        "detailDataSha256": [digest for _, digest, _ in detail_documents],
        "firstDetailAt": detail_documents[0][0]["timestamp"],
        "lastDetailAt": detail_documents[-1][0]["timestamp"],
        "usageRequestIds": [int(row["id"]) for row in rows],
        "correlatedUsageHistoryIds": sorted(correlated_usage_ids),
        "tokenUsages": [
            {"inputTokens": value[0], "outputTokens": value[1], "totalTokens": value[2]}
            for value in positive_usages
        ],
        "completionFingerprintsSha256": sorted(completion_hashes),
    }
    proof = {
        "status": "passed",
        "source": "9router.sqlite.usageHistory",
        "profileRef": profile,
        "profileKeyRef": key_ref,
        "profileKeyFingerprintSha256": hashlib.sha256(api_key.encode()).hexdigest(),
        "historyIdBefore": before_id,
        "historyIdAfter": after_id,
        "requestIds": [int(row["id"]) for row in rows],
        "requestFingerprintsSha256": request_fingerprints,
        "requestCount": len(rows),
        "firstRequestAt": rows[0]["timestamp"],
        "lastRequestAt": rows[-1]["timestamp"],
        "connectionId": expected_connection,
        "connectionName": connection["name"],
        "provider": connection["provider"],
        "model": leaf_model,
        "expectedEndpoint": expected_endpoint,
        "observedEndpoints": sorted({str(row["endpoint"]) for row in rows}),
        "statuses": sorted({str(row["status"]) for row in rows}),
        "requestBinding": request_binding,
    }
    proof["attributionFingerprintSha256"] = hashlib.sha256(
        json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return proof


def e2e_context() -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    config = load_json(CONFIG)
    e2e = config.get("spec", {}).get("e2eCanary")
    if not isinstance(e2e, dict):
        raise CanaryError("invalid_config", "spec.e2eCanary is required")
    required = (
        "paperclipPortRef",
        "paperclipLoopbackHost",
        "paperclipContainerHost",
        "kestraPortRef",
        "kestraLoopbackHost",
        "githubOwner",
        "githubRepository",
        "baseBranch",
    )
    missing = [key for key in required if not str(e2e.get(key, "")).strip()]
    if missing:
        raise CanaryError(
            "invalid_config", "missing e2eCanary values: " + ", ".join(missing)
        )
    profiles = e2e.get("profiles")
    if (
        not isinstance(profiles, list)
        or not profiles
        or any(
            not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", item)
            for item in profiles
        )
    ):
        raise CanaryError(
            "invalid_config", "e2eCanary.profiles must be a non-empty list of safe refs"
        )
    if len(profiles) != len(set(profiles)):
        raise CanaryError("invalid_config", "e2eCanary.profiles contains duplicates")
    if len(profiles) != 3:
        raise CanaryError(
            "invalid_config", "e2eCanary must run exactly three native profiles"
        )
    contracts = e2e.get("profileContracts")
    if not isinstance(contracts, dict) or set(contracts) != set(profiles):
        raise CanaryError(
            "invalid_config",
            "e2eCanary.profileContracts must describe every requested profile exactly once",
        )
    for profile, contract in contracts.items():
        if (
            not isinstance(contract, dict)
            or not re.fullmatch(
                r"[A-Za-z0-9_.-]+", str(contract.get("nativeAdapter", ""))
            )
            or not isinstance(contract.get("requireExplicitProvider"), bool)
        ):
            raise CanaryError(
                "invalid_config", f"invalid profile contract for {profile}"
            )
    native_adapters = [str(contracts[profile]["nativeAdapter"]) for profile in profiles]
    if len(native_adapters) != len(set(native_adapters)):
        raise CanaryError(
            "invalid_config",
            "e2eCanary profiles must use three distinct native adapters",
        )
    for key in ("githubOwner", "githubRepository", "baseBranch"):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", str(e2e[key])):
            raise CanaryError(
                "unsafe_config", f"e2eCanary.{key} contains unsafe characters"
            )
    values = dotenv(PLATFORM_ENV)
    credential_refs = [
        *e2e.get("llmCredentialRefs", []),
        *e2e.get("githubCredentialRefs", []),
    ]
    absent = [str(ref) for ref in credential_refs if not values.get(str(ref), "")]
    if absent:
        raise CanaryError(
            "missing_auth_ref", "missing runtime refs: " + ", ".join(absent)
        )
    paperclip_ids = {
        "paperclipCompanyId": values.get("PAPERCLIP_COMPANY_ID", ""),
        "paperclipProjectId": values.get("PAPERCLIP_PROJECT_ID", ""),
    }
    if not all(paperclip_ids.values()):
        raise CanaryError(
            "missing_paperclip_identity",
            "canonical Paperclip company/project identities are required",
        )
    resolved_ports: dict[str, str] = {}
    for name in ("paperclipPortRef", "kestraPortRef"):
        port_ref = str(e2e[name])
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", port_ref):
            raise CanaryError(
                "invalid_config", f"e2eCanary.{name} is not a canonical env ref"
            )
        port = values.get(port_ref, "")
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise CanaryError(
                "missing_endpoint", f"canonical port ref {port_ref} is invalid"
            )
        resolved_ports[name] = port
    for host_key in (
        "paperclipLoopbackHost",
        "paperclipContainerHost",
        "kestraLoopbackHost",
    ):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", str(e2e[host_key])):
            raise CanaryError(
                "unsafe_config", f"e2eCanary.{host_key} contains unsafe characters"
            )
    e2e = {
        **e2e,
        **paperclip_ids,
        "paperclipBaseUrl": (
            f"http://{e2e['paperclipLoopbackHost']}:{resolved_ports['paperclipPortRef']}"
        ),
        "kestraPaperclipBaseUrl": (
            f"http://{e2e['paperclipContainerHost']}:{resolved_ports['paperclipPortRef']}"
        ),
        "kestraBaseUrl": f"http://{e2e['kestraLoopbackHost']}:{resolved_ports['kestraPortRef']}",
    }
    return config, e2e, values


def source_evidence(config: dict[str, Any], e2e: dict[str, Any]) -> dict[str, Any]:
    return {
        "canonicalSourceSha256": sha256_file(PLATFORM_ENV),
        "configSha256": sha256_file(CONFIG),
        "flowSha256": sha256_file(FLOW),
        "profileSourceSha256": sha256_file(PROFILE_SOURCE),
        "profilesSha256": sha256_file(PROFILES),
        "paperclipRuntimeSha256": sha256_file(PAPERCLIP_RUNTIME_SOURCE),
        "daytonaEvidenceSha256": sha256_file(DAYTONA_EVIDENCE),
        "daytonaVerifyEvidenceSha256": sha256_file(DAYTONA_VERIFY_EVIDENCE),
        "daytonaImagesEvidenceSha256": sha256_file(DAYTONA_IMAGES_EVIDENCE),
        "daytonaLifecycleEvidenceSha256": sha256_file(DAYTONA_LIFECYCLE_EVIDENCE),
        "runnerSha256": sha256_file(Path(__file__)),
        "deploymentRelease": deployment_release_binding(),
        "profileRefs": list(e2e["profiles"]),
        "profileContracts": e2e.get("profileContracts", {}),
        "endpointSource": "spec.e2eCanary Paperclip/Kestra refs + canonical platform.env",
        "repositorySource": "spec.e2eCanary.githubOwner/githubRepository/baseBranch",
        "credentialRefs": sorted(
            str(item)
            for item in [
                *e2e.get("llmCredentialRefs", []),
                *e2e.get("githubCredentialRefs", []),
            ]
        ),
    }


def deployment_release_binding() -> dict[str, Any]:
    """Bind the canary to the exact active governed-source activation."""

    state_path = ROOT / ".deploy/current-release.json"
    require_private_evidence_file(state_path)
    state = load_json(state_path)
    release_id = str(state.get("releaseId") or "")
    manifest_path = ROOT / ".deploy/releases" / release_id / "source-manifest.json"
    manifest = load_json(manifest_path)
    source_sha = str(state.get("sourceSha256") or "")
    if (
        state.get("apiVersion")
        not in {
            "paperclip-agent-platform/v1alpha1",
            "micro-task-engine/v1alpha1",
        }
        or state.get("kind") != "GovernedSourceActivation"
        or state.get("status") != "active"
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{7,127}", release_id)
        or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{7,127}",
            str(state.get("runId") or ""),
        )
        or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{7,127}",
            str(state.get("activationId") or ""),
        )
        or not FULL_SHA256.fullmatch(source_sha)
        or manifest.get("apiVersion")
        not in {
            "paperclip-agent-platform/v1alpha1",
            "micro-task-engine/v1alpha1",
        }
        or manifest.get("kind") != "GovernedSourceManifest"
        or manifest.get("sourceSha256") != source_sha
        or not isinstance(manifest.get("files"), list)
        or not manifest.get("files")
        or not isinstance(state.get("fileCount"), int)
        or state.get("fileCount") != len(manifest.get("files") or [])
    ):
        raise CanaryError(
            "deployment_release_invalid",
            "active governed-source release identity is incomplete or inconsistent",
        )
    return {
        "apiVersion": state.get("apiVersion"),
        "kind": state.get("kind"),
        "status": "active",
        "runId": state.get("runId"),
        "releaseId": release_id,
        "activationId": state.get("activationId"),
        "sourceSha256": source_sha,
        "fileCount": state.get("fileCount"),
        "currentStateSha256": sha256_file(state_path),
        "releaseManifestSha256": sha256_file(manifest_path),
    }


def profile_catalog() -> dict[str, dict[str, Any]]:
    try:
        value = yaml.safe_load(PROFILES.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise CanaryError(
            "invalid_profile_catalog", "profile catalog has no profiles array"
        ) from exc
    rows = value.get("profiles") if isinstance(value, dict) else None
    if not isinstance(rows, list):
        raise CanaryError(
            "invalid_profile_catalog", "profile catalog has no profiles array"
        )
    result: dict[str, dict[str, str]] = {}
    for row in rows:
        if not isinstance(row, dict) or not row.get("ref"):
            continue
        adapter = row.get("nativeAdapterConfig")
        if not isinstance(adapter, dict) or not adapter.get("model"):
            continue
        routing = (
            row.get("llmRouting") if isinstance(row.get("llmRouting"), dict) else {}
        )
        tool_access = (
            row.get("toolAccess") if isinstance(row.get("toolAccess"), dict) else {}
        )
        result[str(row["ref"])] = {
            "adapter": str(row.get("nativeAdapter", "")),
            "model": str(adapter["model"]),
            "provider": str(
                adapter.get("provider")
                or adapter.get("modelProvider")
                or routing.get("provider")
                or ""
            ),
            "toolAccess": {
                "bundleId": str(tool_access.get("bundleId") or ""),
                "workloadId": str(tool_access.get("workloadId") or ""),
                "endpointRef": str(tool_access.get("endpointRef") or ""),
                "credentialRef": str(tool_access.get("credentialRef") or ""),
                "canaryTool": str(tool_access.get("canaryTool") or ""),
            },
        }
    return result


def profile_api_contract_drift(
    value: Any,
    required_profiles: set[str],
    expected_adapters: dict[str, str],
    catalog: dict[str, dict[str, str]],
    contracts: dict[str, dict[str, Any]],
) -> tuple[set[str], list[str]]:
    rows = value.get("profiles") if isinstance(value, dict) else None
    api_rows = {
        str(row.get("ref")): row
        for row in rows or []
        if isinstance(row, dict) and row.get("ref")
    }
    drift = []
    for ref in sorted(required_profiles & set(api_rows)):
        row = api_rows[ref]
        adapter_config = (
            row.get("nativeAdapterConfig")
            if isinstance(row.get("nativeAdapterConfig"), dict)
            else {}
        )
        routing = (
            row.get("llmRouting") if isinstance(row.get("llmRouting"), dict) else {}
        )
        api_provider = str(
            adapter_config.get("provider")
            or adapter_config.get("modelProvider")
            or routing.get("provider")
            or ""
        )
        if (
            str(row.get("nativeAdapter", "")) != expected_adapters[ref]
            or str(adapter_config.get("model", "")) != catalog[ref]["model"]
            or (
                contracts[ref]["requireExplicitProvider"]
                and api_provider != catalog[ref]["provider"]
            )
        ):
            drift.append(ref)
    return set(api_rows), drift


def multipart(fields: dict[str, str]) -> tuple[bytes, str]:
    boundary = "mte-e2e-" + secrets.token_hex(12)
    chunks: list[bytes] = []
    for name, value in fields.items():
        if not re.fullmatch(r"[A-Za-z0-9_]+", name):
            raise CanaryError("unsafe_input", f"invalid multipart field {name}")
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                value.encode(),
                b"\r\n",
            ]
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def kestra_request(
    base: str,
    auth: dict[str, str],
    method: str,
    path: str,
    *,
    body: Any | None = None,
    raw: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
) -> Any:
    _, value = request_json(
        base + path,
        method,
        body=body,
        raw=raw,
        headers={**auth, **(headers or {})},
        timeout=timeout,
    )
    return value


def deploy_flow(kestra: str, auth: dict[str, str]) -> dict[str, Any]:
    try:
        raw = FLOW.read_bytes()
    except OSError as exc:
        raise CanaryError("flow_missing", f"cannot read {FLOW}") from exc
    namespace = "micro_task_engine.e2e"
    flow_id = "paperclip-github-e2e"
    flow_path = (
        "/api/v1/main/flows/"
        + urllib.parse.quote(namespace, safe="")
        + "/"
        + urllib.parse.quote(flow_id, safe="")
    )
    status, _ = request_json(
        kestra + flow_path,
        headers=auth,
        allow_status={404},
    )
    method = "PUT" if status == 200 else "POST"
    path = flow_path if method == "PUT" else "/api/v1/main/flows"
    value = kestra_request(
        kestra,
        auth,
        method,
        path,
        raw=raw,
        headers={"Content-Type": "application/x-yaml"},
        timeout=60,
    )
    if not isinstance(value, dict) or value.get("id") != flow_id:
        raise CanaryError(
            "flow_deploy_failed", "Kestra did not return the expected flow"
        )
    return value


def trigger_flow(
    kestra: str,
    auth: dict[str, str],
    e2e: dict[str, Any],
    profile: str,
) -> dict[str, Any]:
    fields = {
        "paperclip_base_url": str(e2e["kestraPaperclipBaseUrl"]),
        "paperclip_company_id": str(e2e["paperclipCompanyId"]),
        "paperclip_project_id": str(e2e["paperclipProjectId"]),
        "profile": profile,
        "github_owner": str(e2e["githubOwner"]),
        "github_repository": str(e2e["githubRepository"]),
        "base_branch": str(e2e["baseBranch"]),
    }
    raw, content_type = multipart(fields)
    value = kestra_request(
        kestra,
        auth,
        "POST",
        "/api/v1/main/executions/micro_task_engine.e2e/paperclip-github-e2e",
        raw=raw,
        headers={"Content-Type": content_type},
        timeout=60,
    )
    if not isinstance(value, dict) or not value.get("id"):
        raise CanaryError("execution_create_failed", "Kestra returned no execution id")
    return value


def poll_execution(
    kestra: str,
    auth: dict[str, str],
    execution_id: str,
    *,
    timeout_seconds: int = 3600,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_state = ""
    while time.monotonic() < deadline:
        value = kestra_request(
            kestra,
            auth,
            "GET",
            "/api/v1/main/executions/" + urllib.parse.quote(execution_id),
        )
        if not isinstance(value, dict):
            raise CanaryError(
                "invalid_execution", "Kestra execution response is not an object"
            )
        state = str((value.get("state") or {}).get("current", ""))
        if state != last_state:
            print(
                json.dumps(
                    {
                        "executionId": execution_id,
                        "state": state,
                        "observedAt": utcnow(),
                    }
                )
            )
            last_state = state
        if state in TERMINAL:
            return value
        time.sleep(5)
    try:
        kestra_request(
            kestra,
            auth,
            "DELETE",
            "/api/v1/main/executions/" + urllib.parse.quote(execution_id) + "/kill",
            timeout=30,
        )
    except CanaryError:
        pass
    raise CanaryError(
        "execution_timeout", "Kestra execution exceeded the canary timeout"
    )


def execution_summary(value: dict[str, Any]) -> dict[str, Any]:
    state = value.get("state") if isinstance(value.get("state"), dict) else {}
    task_runs = []
    for row in value.get("taskRunList", []):
        if not isinstance(row, dict):
            continue
        task_state = row.get("state") if isinstance(row.get("state"), dict) else {}
        task_runs.append(
            {
                "taskId": row.get("taskId"),
                "state": task_state.get("current"),
                "attemptCount": len(row.get("attempts", [])) or 1,
                "startDate": task_state.get("startDate"),
                "endDate": task_state.get("endDate"),
            }
        )
    outputs = value.get("outputs") if isinstance(value.get("outputs"), dict) else {}
    allowed_outputs = {
        key: outputs.get(key)
        for key in ("result", "pull_request_url", "commit_sha", "paperclip_issue_id")
        if outputs.get(key) is not None
    }
    return {
        "id": value.get("id"),
        "namespace": value.get("namespace"),
        "flowId": value.get("flowId"),
        "flowRevision": value.get("flowRevision"),
        "url": value.get("url"),
        "state": state.get("current"),
        "startDate": state.get("startDate"),
        "endDate": state.get("endDate"),
        "duration": state.get("duration"),
        "outputs": allowed_outputs,
        "taskRuns": task_runs,
    }


def public_github(path: str) -> Any:
    _, value = request_json(
        GITHUB_API + path,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "micro-task-engine-paperclip-e2e",
        },
    )
    return value


def github_write(
    token: str, method: str, path: str, body: Any | None = None
) -> tuple[int, Any]:
    return request_json(
        GITHUB_API + path,
        method,
        body=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "micro-task-engine-paperclip-e2e",
        },
        allow_status={404},
    )


def github_cleanup_request(
    token: str,
    method: str,
    path: str,
    body: Any | None = None,
    *,
    attempts: int = 3,
) -> tuple[int, Any]:
    """Retry cleanup-only GitHub calls without ever exposing response bodies."""
    last_error: CanaryError | None = None
    for attempt in range(attempts):
        try:
            return github_write(token, method, path, body)
        except CanaryError as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(1)
    assert last_error is not None
    raise last_error


def find_pr(
    e2e: dict[str, Any], branch: str, *, state: str = "all"
) -> dict[str, Any] | None:
    owner = str(e2e["githubOwner"])
    repo = str(e2e["githubRepository"])
    query = urllib.parse.urlencode(
        {"state": state, "head": f"{owner}:{branch}", "per_page": "10"}
    )
    value = public_github(f"/repos/{owner}/{repo}/pulls?{query}")
    if not isinstance(value, list):
        raise CanaryError(
            "invalid_github_response", "GitHub pulls response is not an array"
        )
    return next((row for row in value if isinstance(row, dict)), None)


def check_runs(e2e: dict[str, Any], sha: str) -> list[dict[str, Any]]:
    owner = str(e2e["githubOwner"])
    repo = str(e2e["githubRepository"])
    rows: list[dict[str, Any]] = []
    total: int | None = None
    for page in range(1, 11):
        query = urllib.parse.urlencode({"per_page": "100", "page": str(page)})
        value = public_github(
            f"/repos/{owner}/{repo}/commits/{urllib.parse.quote(sha)}/check-runs?{query}"
        )
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("total_count"), int)
            or not isinstance(value.get("check_runs"), list)
            or any(not isinstance(row, dict) for row in value["check_runs"])
        ):
            raise CanaryError(
                "invalid_github_response", "GitHub checks response is invalid"
            )
        total = value["total_count"] if total is None else total
        if value["total_count"] != total:
            raise CanaryError(
                "invalid_github_response", "GitHub check pagination count changed"
            )
        rows.extend(value["check_runs"])
        if len(value["check_runs"]) < 100:
            break
    else:
        raise CanaryError(
            "invalid_github_response", "GitHub check pagination exceeded its bound"
        )
    if len(rows) != total:
        raise CanaryError(
            "invalid_github_response", "GitHub checks response was not fully paginated"
        )
    return rows


def github_pull_files(e2e: dict[str, Any], pull_number: int) -> list[dict[str, Any]]:
    owner = str(e2e["githubOwner"])
    repo = str(e2e["githubRepository"])
    rows: list[dict[str, Any]] = []
    for page in range(1, 11):
        query = urllib.parse.urlencode({"per_page": "100", "page": str(page)})
        value = public_github(
            f"/repos/{owner}/{repo}/pulls/{pull_number}/files?{query}"
        )
        if not isinstance(value, list) or any(
            not isinstance(row, dict) for row in value
        ):
            raise CanaryError(
                "invalid_github_response", "GitHub PR files response is invalid"
            )
        rows.extend(value)
        if len(value) < 100:
            return rows
    raise CanaryError(
        "invalid_github_response", "GitHub PR files pagination exceeded its bound"
    )


def github_commit(e2e: dict[str, Any], sha: str) -> dict[str, Any]:
    owner = str(e2e["githubOwner"])
    repo = str(e2e["githubRepository"])
    value = public_github(f"/repos/{owner}/{repo}/commits/{urllib.parse.quote(sha)}")
    if not isinstance(value, dict):
        raise CanaryError(
            "invalid_github_response", "GitHub commit response is invalid"
        )
    return value


def allowed_artifacts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("artifacts"), list):
        raise CanaryError(
            "invalid_artifacts", "Paperclip artifacts response is invalid"
        )
    artifacts = []
    for row in value["artifacts"]:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name", ""))
        if name not in {"harness-evidence", "structured-result"}:
            continue
        artifacts.append(
            {
                "name": name,
                "kind": row.get("kind"),
                "title": row.get("title"),
                "nativeId": row.get("nativeId"),
                "content": row.get("content"),
            }
        )
    return artifacts


def parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise CanaryError("timestamp_missing", f"{field} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CanaryError("timestamp_invalid", f"{field} is not ISO-8601") from exc
    if parsed.tzinfo is None:
        raise CanaryError("timestamp_invalid", f"{field} has no timezone")
    return parsed


def harness_document(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = [row for row in artifacts if row.get("name") == "harness-evidence"]
    if len(candidates) != 1 or not isinstance(candidates[0].get("content"), str):
        raise CanaryError(
            "harness_evidence_cardinality",
            "exactly one keyed harness-evidence document is required",
        )
    artifact = candidates[0]
    try:
        document = json.loads(artifact["content"])
    except json.JSONDecodeError as exc:
        raise CanaryError(
            "harness_evidence_invalid", "harness-evidence body is not raw JSON"
        ) from exc
    if not isinstance(document, dict):
        raise CanaryError(
            "harness_evidence_invalid", "harness-evidence JSON is not an object"
        )
    if re.search(
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", artifact["content"]
    ):
        raise CanaryError(
            "harness_secret_leak", "harness-evidence contains a JWT-shaped value"
        )
    if document.get("schemaVersion") != HARNESS_EVIDENCE_SCHEMA:
        raise CanaryError(
            "harness_evidence_schema_unsupported",
            "harness-evidence must use the current direct-execution v3 schema",
        )
    return document


def canonical_object_sha256(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def validate_harness_document(
    artifacts: list[dict[str, Any]],
    pull: dict[str, Any],
    e2e: dict[str, Any],
    branch: str,
    profile: str,
    expected_adapter: str,
    expected_model: str,
) -> dict[str, Any]:
    document = harness_document(artifacts)
    head = pull.get("head") if isinstance(pull.get("head"), dict) else {}
    expected = {
        "profileRef": profile,
        "repository": f"{e2e['githubOwner']}/{e2e['githubRepository']}",
        "branch": branch,
        "commitSha": head.get("sha"),
    }
    if any(document.get(key) != value for key, value in expected.items()):
        raise CanaryError(
            "harness_evidence_mismatch",
            "harness-evidence does not match the independently observed run",
        )
    pr = (
        document.get("pullRequest")
        if isinstance(document.get("pullRequest"), dict)
        else {}
    )
    if (
        pr.get("number") != pull.get("number")
        or pr.get("url") != pull.get("html_url")
        or pr.get("draft") is not True
    ):
        raise CanaryError(
            "harness_pr_mismatch", "harness-evidence PR fields do not match GitHub"
        )
    test = (
        document.get("localTest") if isinstance(document.get("localTest"), dict) else {}
    )
    daytona = (
        document.get("daytona") if isinstance(document.get("daytona"), dict) else {}
    )
    timestamps = (
        document.get("timestamps")
        if isinstance(document.get("timestamps"), dict)
        else {}
    )
    if not test.get("command") or test.get("exitCode") != 0:
        raise CanaryError(
            "harness_test_failed", "harness-evidence has no successful local test"
        )
    if daytona.get("provider") != "daytona" or not daytona.get("sandboxId"):
        raise CanaryError(
            "harness_daytona_missing",
            "harness-evidence has no Daytona sandbox identity",
        )
    harness = (
        document.get("harness") if isinstance(document.get("harness"), dict) else {}
    )
    expected_harness = NATIVE_EXECUTABLES.get(expected_adapter)
    forbidden = {
        "nativeInvocation",
        "runnerAttestation",
        "paperclipAuth",
        "authProof",
        "llm",
        "ninerouter",
    }
    if (
        expected_harness is None
        or harness.get("name") != expected_harness
        or forbidden & set(document)
    ):
        raise CanaryError(
            "harness_identity_invalid",
            "harness evidence must name the direct native CLI without wrapper attestations",
        )
    if not timestamps.get("startedAt") or not timestamps.get("finishedAt"):
        raise CanaryError(
            "harness_timestamps_missing", "harness-evidence has no run timestamps"
        )
    started = parse_timestamp(timestamps.get("startedAt"), "harness.startedAt")
    finished = parse_timestamp(timestamps.get("finishedAt"), "harness.finishedAt")
    if finished < started:
        raise CanaryError(
            "harness_timeline_invalid",
            "harness completion precedes its start",
        )
    return document


def validated_claim(
    paperclip: dict[str, Any],
    expected_adapter: str,
) -> dict[str, Any]:
    claim = paperclip.get("claim") if isinstance(paperclip.get("claim"), dict) else {}
    claimant = claim.get("claimant") if isinstance(claim.get("claimant"), dict) else {}
    if (
        not claim.get("leaseId")
        or claim.get("claimantCount") != 1
        or claimant.get("type") != "paperclip_agent"
        or not claimant.get("id")
        or claimant.get("adapterType") != expected_adapter
    ):
        raise CanaryError(
            "paperclip_claim_invalid",
            "Paperclip claim is missing a unique native runner identity and lease",
        )
    claimed_at = parse_timestamp(claim.get("claimedAt"), "claim.claimedAt")
    first_heartbeat = parse_timestamp(
        claim.get("firstHeartbeatAt"), "claim.firstHeartbeatAt"
    )
    if not claimed_at < first_heartbeat:
        raise CanaryError(
            "paperclip_claim_order_invalid",
            "Paperclip claim must precede the first native heartbeat",
        )
    return claim


def validated_heartbeat_sequence(
    paperclip: dict[str, Any],
    claim: dict[str, Any],
) -> dict[str, Any]:
    native = (
        paperclip.get("native") if isinstance(paperclip.get("native"), dict) else {}
    )
    rows = paperclip.get("heartbeatSequence")
    if (
        not isinstance(rows, list)
        or len(rows) < 3
        or any(not isinstance(row, dict) for row in rows)
    ):
        raise CanaryError(
            "heartbeat_sequence_incomplete",
            "Paperclip did not expose started, in-progress, and terminal heartbeat events",
        )
    run_id = str(native.get("heartbeatRunId") or "")
    runner_id = str((claim.get("claimant") or {}).get("id") or "")
    if not run_id or not runner_id:
        raise CanaryError(
            "heartbeat_identity_missing", "heartbeat run or runner identity is missing"
        )

    sequences: list[int] = []
    timestamps: list[datetime] = []
    phases: list[str] = []
    safe_rows: list[dict[str, Any]] = []
    for row in rows:
        try:
            sequence = int(row.get("seq"))
        except (TypeError, ValueError) as exc:
            raise CanaryError(
                "heartbeat_sequence_invalid", "heartbeat event sequence is invalid"
            ) from exc
        created_at = parse_timestamp(row.get("createdAt"), "heartbeat.createdAt")
        phase = str(row.get("phase") or "")
        if (
            str(row.get("runId") or "") != run_id
            or str(row.get("agentId") or "") != runner_id
        ):
            raise CanaryError(
                "heartbeat_identity_drift",
                "heartbeat events do not share the exact Paperclip run and runner identity",
            )
        sequences.append(sequence)
        timestamps.append(created_at)
        phases.append(phase)
        safe_rows.append(
            {
                "runId": run_id,
                "runnerId": runner_id,
                "seq": sequence,
                "eventType": row.get("eventType"),
                "phase": phase,
                "status": row.get("status"),
                "createdAt": row.get("createdAt"),
            }
        )
    if sequences != sorted(set(sequences)) or any(
        current <= previous for previous, current in zip(timestamps, timestamps[1:])
    ):
        raise CanaryError(
            "heartbeat_order_invalid",
            "heartbeat sequence numbers and timestamps are not strictly monotonic",
        )
    if (
        phases[0] != "started"
        or phases[-1] != "terminal"
        or "in_progress" not in phases[1:-1]
    ):
        raise CanaryError(
            "heartbeat_phases_incomplete",
            "heartbeat proof lacks an ordered started, in-progress, terminal lifecycle",
        )
    if timestamps[0] != parse_timestamp(
        claim.get("firstHeartbeatAt"), "claim.firstHeartbeatAt"
    ):
        raise CanaryError(
            "heartbeat_claim_drift",
            "claim first heartbeat differs from the first heartbeat event",
        )
    terminal_status = str(safe_rows[-1].get("status") or "")
    if terminal_status != "succeeded" or terminal_status != str(
        native.get("heartbeatStatus") or ""
    ):
        raise CanaryError(
            "heartbeat_terminal_invalid",
            "terminal heartbeat does not match the successful native run outcome",
        )
    final = (
        paperclip.get("finalResult")
        if isinstance(paperclip.get("finalResult"), dict)
        else {}
    )
    final_identity = {
        "source": final.get("source"),
        "runId": final.get("runId"),
        "runnerId": final.get("runnerId"),
        "status": final.get("status"),
        "recordedAt": final.get("recordedAt"),
    }
    expected_final_fingerprint = hashlib.sha256(
        json.dumps(final_identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    final_at = parse_timestamp(final.get("recordedAt"), "finalResult.recordedAt")
    if (
        final.get("source") != "paperclip.heartbeat-run"
        or final.get("runId") != run_id
        or final.get("runnerId") != runner_id
        or final.get("status") != "succeeded"
        or final_at < timestamps[-1]
        or final.get("recordFingerprintSha256") != expected_final_fingerprint
    ):
        raise CanaryError(
            "heartbeat_final_result_invalid",
            "Paperclip final result is not a separate terminal heartbeat-run record",
        )
    return {
        "status": "passed",
        "runId": run_id,
        "runnerId": runner_id,
        "events": safe_rows,
        "finalResult": {
            **final_identity,
            "recordFingerprintSha256": expected_final_fingerprint,
        },
    }


def validated_workspace_identity(
    paperclip: dict[str, Any],
    resources: dict[str, Any],
    expected_environment_id: str,
) -> dict[str, Any]:
    environment = (
        paperclip.get("environment")
        if isinstance(paperclip.get("environment"), dict)
        else {}
    )
    resource_environment = (
        resources.get("environment")
        if isinstance(resources.get("environment"), dict)
        else {}
    )
    workspace = (
        resources.get("paperclipWorkspace")
        if isinstance(resources.get("paperclipWorkspace"), dict)
        else {}
    )
    sandbox_id = str(environment.get("sandboxId") or "")
    workspace_id = str(environment.get("executionWorkspaceId") or "")
    remote_cwd = str(environment.get("remoteCwd") or "")
    path_hash = hashlib.sha256(remote_cwd.encode()).hexdigest()
    if (
        environment.get("provider") != "daytona"
        or not expected_environment_id
        or environment.get("environmentId") != expected_environment_id
        or environment.get("providerLeaseId") != sandbox_id
        or not sandbox_id
        or not workspace_id
        or not remote_cwd.startswith("/")
        or ".." in Path(remote_cwd).parts
        or resource_environment != environment
        or workspace.get("id") != workspace_id
        or workspace.get("worktreePath") != remote_cwd
        or workspace.get("worktreePathFingerprintSha256") != path_hash
        or not str(workspace.get("worktreePathSource") or "").startswith("paperclip.")
        or resources.get("paperclipEnvironmentReleased") is not False
    ):
        raise CanaryError(
            "paperclip_workspace_identity_invalid",
            "Paperclip environment, sandbox, lease, workspace, and cwd identities differ",
        )
    fingerprint = hashlib.sha256(
        "|".join(
            (
                str(environment.get("environmentId")),
                str(environment.get("environmentLeaseId")),
                sandbox_id,
                workspace_id,
                remote_cwd,
            )
        ).encode()
    ).hexdigest()
    return {
        "status": "passed",
        "provider": "daytona",
        "environmentId": expected_environment_id,
        "environmentLeaseId": environment.get("environmentLeaseId"),
        "providerLeaseId": sandbox_id,
        "sandboxId": sandbox_id,
        "executionWorkspaceId": workspace_id,
        "remoteCwd": remote_cwd,
        "worktreePathFingerprintSha256": path_hash,
        "identityFingerprintSha256": fingerprint,
    }


def validated_recorded_workspace_identity(
    paperclip: dict[str, Any], recorded: Any, expected_environment_id: str
) -> dict[str, Any]:
    if not isinstance(recorded, dict):
        raise CanaryError(
            "paperclip_workspace_identity_invalid",
            "stored workspace identity is missing",
        )
    environment = (
        paperclip.get("environment")
        if isinstance(paperclip.get("environment"), dict)
        else {}
    )
    comparable = {
        key: recorded.get(key)
        for key in (
            "status",
            "provider",
            "environmentId",
            "environmentLeaseId",
            "providerLeaseId",
            "sandboxId",
            "executionWorkspaceId",
            "remoteCwd",
            "worktreePathFingerprintSha256",
        )
    }
    expected_fingerprint = hashlib.sha256(
        "|".join(
            str(value)
            for value in (
                comparable["environmentId"],
                comparable["environmentLeaseId"],
                comparable["sandboxId"],
                comparable["executionWorkspaceId"],
                comparable["remoteCwd"],
            )
        ).encode()
    ).hexdigest()
    if (
        comparable.get("status") != "passed"
        or comparable.get("provider") != "daytona"
        or comparable.get("environmentId") != expected_environment_id
        or comparable.get("providerLeaseId") != comparable.get("sandboxId")
        or comparable.get("worktreePathFingerprintSha256")
        != hashlib.sha256(str(comparable.get("remoteCwd") or "").encode()).hexdigest()
        or recorded.get("identityFingerprintSha256") != expected_fingerprint
        or set(recorded) != {*comparable, "identityFingerprintSha256"}
        or environment.get("provider") != "daytona"
        or environment.get("environmentId") != comparable.get("environmentId")
        or environment.get("environmentLeaseId") != comparable.get("environmentLeaseId")
        or environment.get("providerLeaseId") != comparable.get("providerLeaseId")
        or environment.get("sandboxId") != comparable.get("sandboxId")
        or environment.get("executionWorkspaceId")
        != comparable.get("executionWorkspaceId")
        or environment.get("remoteCwd") != comparable.get("remoteCwd")
    ):
        raise CanaryError(
            "paperclip_workspace_identity_invalid",
            "stored workspace identity differs from the Paperclip run",
        )
    return dict(recorded)


def daytona_workspace_operation(
    values: dict[str, str],
    identity: dict[str, Any],
    commit_sha: str,
    expected_adapter: str,
) -> dict[str, Any]:
    """Prove the official CLI directly inside the exact Daytona sandbox."""
    sandbox_id = str(identity.get("sandboxId") or "")
    workspace_id = str(identity.get("executionWorkspaceId") or "")
    remote_cwd = str(identity.get("remoteCwd") or "")
    image = values.get("PAPERCLIP_NODE_IMAGE", "")
    requested_name = str(NATIVE_EXECUTABLES.get(expected_adapter) or "")
    expected_version = str(
        values.get(NATIVE_VERSION_REFS.get(expected_adapter, "")) or ""
    )
    if (
        not re.fullmatch(r"[A-Za-z0-9_.:-]+", sandbox_id)
        or not re.fullmatch(r"/[A-Za-z0-9_./-]+", remote_cwd)
        or ".." in Path(remote_cwd).parts
        or not workspace_id
        or not FULL_GIT_SHA.fullmatch(commit_sha)
        or not re.fullmatch(r"[A-Za-z0-9._/@:-]+", image)
        or requested_name not in set(NATIVE_EXECUTABLES.values())
        or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}", expected_version)
    ):
        raise CanaryError(
            "workspace_operation_input_invalid",
            "Daytona workspace operation received an unsafe identity",
        )
    node_script = r"""
import crypto from "node:crypto";
import fs from "node:fs";
const [sandboxId, workspaceId, cwd, commit, requestedName] = process.argv.slice(2);
const values = Object.fromEntries(
  fs.readFileSync("/run/secrets/platform.env", "utf8").split(/\n/)
    .filter((line) => line && !line.startsWith("#") && line.includes("="))
    .map((line) => { const i=line.indexOf("="); return [line.slice(0,i),line.slice(i+1)]; })
);
const { Daytona } = await import("file:///paperclip-home/.paperclip/plugins/node_modules/@daytonaio/sdk/src/index.js");
const daytona = new Daytona({apiKey:values.DAYTONA_API_KEY,apiUrl:values.MTE_DAYTONA_API_URL,target:values.DAYTONA_TARGET});
const sandbox = await daytona.get(sandboxId);
const command = `set -eu; test "$(git rev-parse HEAD)" = "${commit}"; resolved=$(command -v "${requestedName}"); resolved=$(readlink -f "$resolved"); test -x "$resolved"; case "$resolved" in /prototype/*|*/paperclip-harness-runtime/*) exit 73;; esac; python3 -m unittest paperclip-e2e/test_marker.py; printf 'marker '; sha256sum paperclip-e2e/marker.py; printf 'executable '; sha256sum "$resolved"; printf 'realpath '; printf '%s' "$resolved" | base64 | tr -d '\n'; printf '\n'; version_file=$(mktemp); trap 'rm -f "$version_file"' EXIT; "$resolved" --version >"$version_file" 2>&1; printf 'version '; sha256sum "$version_file" | awk '{print $1}'; printf 'version-text '; base64 "$version_file" | tr -d '\n'; printf '\n'; rm -f "$version_file"; trap - EXIT`;
const result = await sandbox.process.executeCommand(command, cwd, undefined, 180);
const output = String(result.result || "").trim();
const markerSha = (output.match(/(?:^|\n)marker ([0-9a-f]{64})\s+paperclip-e2e\/marker\.py(?:\n|$)/) || [])[1] || "";
const executableSha = (output.match(/(?:^|\n)executable ([0-9a-f]{64})\s+/) || [])[1] || "";
const realpathEncoded = (output.match(/(?:^|\n)realpath ([A-Za-z0-9+/=]+)(?:\n|$)/) || [])[1] || "";
const executableRealpath = realpathEncoded ? Buffer.from(realpathEncoded, "base64").toString("utf8").trim() : "";
const versionSha = (output.match(/(?:^|\n)version ([0-9a-f]{64})(?:\n|$)/) || [])[1] || "";
const versionEncoded = (output.match(/(?:^|\n)version-text ([A-Za-z0-9+/=]+)(?:\n|$)/) || [])[1] || "";
const versionText = versionEncoded ? Buffer.from(versionEncoded, "base64").toString("utf8").trim() : "";
const safeVersion = /^[A-Za-z0-9 ._+()/@:-]{1,160}$/.test(versionText) ? versionText : "";
const proof = {sandboxId,workspaceId,cwd,commitSha:commit,exitCode:result.exitCode,markerFileSha256:markerSha,executableRealpath,executableSha256:executableSha,versionOutputSha256:versionSha,executableVersion:safeVersion,outputSha256:crypto.createHash("sha256").update(output).digest("hex")};
process.stdout.write(JSON.stringify(proof));
"""
    try:
        completed = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "--network",
                "host",
                "--user",
                "0:0",
                "-v",
                f"{PLATFORM_ENV}:/run/secrets/platform.env:ro",
                "-v",
                "mte-paperclip-native-home:/paperclip-home:ro",
                image,
                "node",
                "--input-type=module",
                "-",
                sandbox_id,
                workspace_id,
                remote_cwd,
                commit_sha,
                requested_name,
            ],
            input=node_script,
            text=True,
            capture_output=True,
            timeout=240,
            check=True,
        )
        proof = json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise CanaryError(
            "workspace_operation_failed",
            "independent Daytona workspace operation failed",
        ) from exc
    if (
        not isinstance(proof, dict)
        or proof.get("sandboxId") != sandbox_id
        or proof.get("workspaceId") != workspace_id
        or proof.get("cwd") != remote_cwd
        or proof.get("commitSha") != commit_sha
        or proof.get("exitCode") != 0
        or not FULL_SHA256.fullmatch(str(proof.get("markerFileSha256") or ""))
        or not re.fullmatch(
            r"/[A-Za-z0-9_./@+-]+", str(proof.get("executableRealpath") or "")
        )
        or ".." in Path(str(proof.get("executableRealpath") or "")).parts
        or str(proof.get("executableRealpath") or "").startswith("/prototype/")
        or "paperclip-harness-runtime" in str(proof.get("executableRealpath") or "")
        or not FULL_SHA256.fullmatch(str(proof.get("executableSha256") or ""))
        or not FULL_SHA256.fullmatch(str(proof.get("versionOutputSha256") or ""))
        or not re.search(
            rf"(?<![0-9A-Za-z]){re.escape(expected_version)}(?![0-9A-Za-z])",
            str(proof.get("executableVersion") or ""),
        )
        or not FULL_SHA256.fullmatch(str(proof.get("outputSha256") or ""))
    ):
        raise CanaryError(
            "workspace_operation_failed",
            "Daytona workspace operation did not return exact safe evidence",
        )
    safe = {
        "status": "passed",
        "provider": "daytona",
        "sandboxId": sandbox_id,
        "executionWorkspaceId": workspace_id,
        "remoteCwd": remote_cwd,
        "commitSha": commit_sha,
        "operation": "git-head+python-unittest+direct-native-executable",
        "directExecution": True,
        "repositoryLauncherAbsent": True,
        "nativeExecutableRequestedName": requested_name,
        "exitCode": 0,
        "markerFileSha256": proof["markerFileSha256"],
        "nativeExecutableRealpath": proof["executableRealpath"],
        "nativeExecutableRealpathSha256": hashlib.sha256(
            str(proof["executableRealpath"]).encode()
        ).hexdigest(),
        "nativeExecutableSha256": proof["executableSha256"],
        "nativeExecutableVersionOutputSha256": proof["versionOutputSha256"],
        "nativeExecutableVersion": proof["executableVersion"],
        "outputSha256": proof["outputSha256"],
    }
    safe["operationFingerprintSha256"] = hashlib.sha256(
        json.dumps(safe, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return safe


def validated_stored_workspace_operation(
    operation: Any,
    identity: dict[str, Any],
    commit_sha: str,
    expected_adapter: str,
    expected_version: str,
) -> dict[str, Any]:
    if not isinstance(operation, dict):
        raise CanaryError(
            "workspace_operation_evidence_invalid",
            "workspace operation proof is missing",
        )
    comparable = {
        key: operation.get(key)
        for key in (
            "status",
            "provider",
            "sandboxId",
            "executionWorkspaceId",
            "remoteCwd",
            "commitSha",
            "operation",
            "directExecution",
            "repositoryLauncherAbsent",
            "nativeExecutableRequestedName",
            "exitCode",
            "markerFileSha256",
            "nativeExecutableRealpath",
            "nativeExecutableRealpathSha256",
            "nativeExecutableSha256",
            "nativeExecutableVersionOutputSha256",
            "nativeExecutableVersion",
            "outputSha256",
        )
    }
    expected_fingerprint = hashlib.sha256(
        json.dumps(comparable, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    executable_name = NATIVE_EXECUTABLES.get(expected_adapter)
    executable_realpath = str(comparable.get("nativeExecutableRealpath") or "")
    if (
        comparable.get("status") != "passed"
        or comparable.get("provider") != "daytona"
        or comparable.get("sandboxId") != identity.get("sandboxId")
        or comparable.get("executionWorkspaceId")
        != identity.get("executionWorkspaceId")
        or comparable.get("remoteCwd") != identity.get("remoteCwd")
        or comparable.get("commitSha") != commit_sha
        or comparable.get("operation")
        != "git-head+python-unittest+direct-native-executable"
        or comparable.get("directExecution") is not True
        or comparable.get("repositoryLauncherAbsent") is not True
        or comparable.get("nativeExecutableRequestedName") != executable_name
        or comparable.get("exitCode") != 0
        or not FULL_SHA256.fullmatch(str(comparable.get("markerFileSha256") or ""))
        or not FULL_SHA256.fullmatch(
            str(comparable.get("nativeExecutableRealpathSha256") or "")
        )
        or not FULL_SHA256.fullmatch(
            str(comparable.get("nativeExecutableSha256") or "")
        )
        or not FULL_SHA256.fullmatch(
            str(comparable.get("nativeExecutableVersionOutputSha256") or "")
        )
        or not re.fullmatch(r"/[A-Za-z0-9_./@+-]+", executable_realpath)
        or ".." in Path(executable_realpath).parts
        or executable_realpath.startswith("/prototype/")
        or "paperclip-harness-runtime" in executable_realpath
        or comparable.get("nativeExecutableRealpathSha256")
        != hashlib.sha256(executable_realpath.encode()).hexdigest()
        or not re.search(
            rf"(?<![0-9A-Za-z]){re.escape(expected_version)}(?![0-9A-Za-z])",
            str(comparable.get("nativeExecutableVersion") or ""),
        )
        or not FULL_SHA256.fullmatch(str(comparable.get("outputSha256") or ""))
        or operation.get("operationFingerprintSha256") != expected_fingerprint
        or set(operation) != {*comparable, "operationFingerprintSha256"}
    ):
        raise CanaryError(
            "workspace_operation_evidence_invalid",
            "workspace operation proof is not exactly bound to the run workspace and commit",
        )
    return dict(operation)


def validated_kestra_execution(
    execution: dict[str, Any],
    expected_revision: Any,
    normalized_run_id: str,
    commit_sha: str,
    pull_url: str,
) -> dict[str, Any]:
    revision = execution.get("flowRevision")
    started_at = parse_timestamp(execution.get("startDate"), "execution.startDate")
    finished_at = parse_timestamp(execution.get("endDate"), "execution.endDate")
    outputs = (
        execution.get("outputs") if isinstance(execution.get("outputs"), dict) else {}
    )
    task_runs = (
        execution.get("taskRuns") if isinstance(execution.get("taskRuns"), list) else []
    )
    critical_tasks = {
        "submit",
        "assert_issue_reconciled",
        "assert_agent_succeeded",
        "assert_harness_evidence",
        "assert_draft_pr",
        "assert_checks_passed",
        "final_summary",
    }
    observed_tasks = {
        str(row.get("taskId"))
        for row in task_runs
        if isinstance(row, dict) and row.get("taskId")
    }
    if (
        execution.get("state") != "SUCCESS"
        or execution.get("namespace") != "micro_task_engine.e2e"
        or execution.get("flowId") != "paperclip-github-e2e"
        or not isinstance(expected_revision, int)
        or isinstance(expected_revision, bool)
        or revision != expected_revision
        or finished_at <= started_at
        or outputs.get("result") != "PASS"
        or outputs.get("paperclip_issue_id") != normalized_run_id
        or outputs.get("commit_sha") != commit_sha
        or outputs.get("pull_request_url") != pull_url
        or not critical_tasks <= observed_tasks
        or any(
            isinstance(row, dict)
            and row.get("taskId") in critical_tasks
            and row.get("state") != "SUCCESS"
            for row in task_runs
        )
    ):
        raise CanaryError(
            "kestra_execution_contract_invalid",
            "Kestra execution does not match the exact deployed revision and outputs",
        )
    return {
        "status": "passed",
        "executionId": execution.get("id"),
        "namespace": execution.get("namespace"),
        "flowId": execution.get("flowId"),
        "flowRevision": revision,
        "startedAt": execution.get("startDate"),
        "finishedAt": execution.get("endDate"),
        "criticalTasks": sorted(critical_tasks),
        "outputs": {
            "result": "PASS",
            "paperclipIssueId": normalized_run_id,
            "commitSha": commit_sha,
            "pullRequestUrl": pull_url,
        },
    }


def validated_github_evidence(
    execution: dict[str, Any],
    pull: dict[str, Any],
    checks: list[dict[str, Any]],
    e2e: dict[str, Any],
    branch: str,
    *,
    pull_files: list[dict[str, Any]] | None = None,
    commit: dict[str, Any] | None = None,
    expected_pull_state: str = "open",
) -> dict[str, Any]:
    head = pull.get("head") if isinstance(pull.get("head"), dict) else {}
    base = pull.get("base") if isinstance(pull.get("base"), dict) else {}
    commit_sha = str(head.get("sha") or "")
    base_sha = str(base.get("sha") or "")
    execution_started = parse_timestamp(
        execution.get("startDate"), "execution.startDate"
    )
    execution_finished = parse_timestamp(execution.get("endDate"), "execution.endDate")
    if (
        expected_pull_state not in {"open", "closed"}
        or pull.get("state") != expected_pull_state
        or pull.get("draft") is not True
        or not isinstance(pull.get("number"), int)
        or not pull.get("html_url")
        or head.get("ref") != branch
        or base.get("ref") != e2e["baseBranch"]
        or not FULL_GIT_SHA.fullmatch(commit_sha)
        or not FULL_GIT_SHA.fullmatch(base_sha)
        or not checks
    ):
        raise CanaryError("github_pr_invalid", "draft PR identity is incomplete")
    safe_checks: list[dict[str, Any]] = []
    for row in checks:
        started = parse_timestamp(row.get("started_at"), "check.started_at")
        completed = parse_timestamp(row.get("completed_at"), "check.completed_at")
        if row.get("conclusion") not in PASS_CONCLUSIONS:
            raise CanaryError(
                "github_checks_failed", "at least one GitHub check did not pass"
            )
        if (
            not isinstance(row.get("id"), int)
            or not row.get("name")
            or row.get("head_sha") != commit_sha
            or row.get("status") != "completed"
            or started < execution_started
            or completed < started
            or completed > execution_finished
        ):
            raise CanaryError(
                "github_checks_invalid",
                "GitHub check is not bound to the commit and Kestra execution interval",
            )
        safe_checks.append(
            {
                "id": row.get("id"),
                "name": row.get("name"),
                "headSha": commit_sha,
                "status": "completed",
                "conclusion": row.get("conclusion"),
                "startedAt": row.get("started_at"),
                "completedAt": row.get("completed_at"),
                "url": row.get("html_url"),
            }
        )
    required_checks = [
        row
        for row in safe_checks
        if row.get("name") == REQUIRED_GITHUB_CHECK_NAME
        and row.get("conclusion") == "success"
    ]
    if len(required_checks) != 1:
        raise CanaryError(
            "github_required_check_missing",
            "exactly one required paperclip-e2e check must complete successfully",
        )

    observed_files = (
        pull_files
        if pull_files is not None
        else github_pull_files(e2e, int(pull["number"]))
    )
    observed_commit = commit if commit is not None else github_commit(e2e, commit_sha)
    parents = (
        observed_commit.get("parents")
        if isinstance(observed_commit, dict)
        and isinstance(observed_commit.get("parents"), list)
        else []
    )
    if (
        observed_commit.get("sha") != commit_sha
        or len(parents) != 1
        or not isinstance(parents[0], dict)
        or parents[0].get("sha") != base_sha
    ):
        raise CanaryError(
            "github_revision_invalid",
            "canary commit must have the exact PR base as its sole parent",
        )
    if (
        not isinstance(observed_files, list)
        or any(not isinstance(row, dict) for row in observed_files)
        or sorted(str(row.get("filename") or "") for row in observed_files)
        != sorted(ALLOWED_GITHUB_PATHS)
    ):
        raise CanaryError(
            "github_diff_invalid",
            "canary PR changed files outside the exact three-path allowlist",
        )
    safe_files: list[dict[str, Any]] = []
    for row in sorted(observed_files, key=lambda item: str(item.get("filename") or "")):
        patch = row.get("patch")
        if (
            row.get("status") != "added"
            or not FULL_GIT_SHA.fullmatch(str(row.get("sha") or ""))
            or not isinstance(row.get("additions"), int)
            or isinstance(row.get("additions"), bool)
            or row.get("additions", 0) <= 0
            or row.get("deletions") != 0
            or row.get("changes") != row.get("additions")
            or not isinstance(patch, str)
            or not patch
        ):
            raise CanaryError(
                "github_diff_invalid",
                "canary PR file evidence lacks an exact added blob and patch",
            )
        safe_files.append(
            {
                "path": row["filename"],
                "status": "added",
                "blobSha": row["sha"],
                "additions": row["additions"],
                "deletions": 0,
                "patchSha256": hashlib.sha256(patch.encode()).hexdigest(),
            }
        )
    return {
        "status": "passed",
        "repository": f"{e2e['githubOwner']}/{e2e['githubRepository']}",
        "branch": branch,
        "commitSha": commit_sha,
        "baseSha": base_sha,
        "pullRequestNumber": pull.get("number"),
        "pullRequestUrl": pull.get("html_url"),
        "state": expected_pull_state,
        "draft": True,
        "checks": safe_checks,
        "requiredCheck": required_checks[0],
        "files": safe_files,
    }


def validated_cross_run_identity(
    runs: list[dict[str, Any]], profiles: list[str], flow_revision: int
) -> dict[str, Any]:
    """Prove three isolated profile runs instead of three views of one run."""
    if (
        len(profiles) != 3
        or len(runs) != 3
        or [row.get("profile") for row in runs] != profiles
    ):
        raise CanaryError(
            "cross_run_identity_invalid",
            "E2E must contain exactly one run for each of the three canonical profiles",
        )

    fields: dict[str, list[Any]] = {
        "executionIds": [],
        "paperclipIssueIds": [],
        "heartbeatRunIds": [],
        "issueIds": [],
        "agentIds": [],
        "claimLeaseIds": [],
        "nativeExecutableProofs": [],
        "routerAttributionProofs": [],
        "sandboxIds": [],
        "workspaceIds": [],
        "branches": [],
        "commitShas": [],
        "pullRequestNumbers": [],
        "pullRequestUrls": [],
    }
    check_ids: list[int] = []
    for row in runs:
        execution = (
            row.get("execution") if isinstance(row.get("execution"), dict) else {}
        )
        paperclip = (
            row.get("paperclip") if isinstance(row.get("paperclip"), dict) else {}
        )
        github = row.get("github") if isinstance(row.get("github"), dict) else {}
        pull = (
            github.get("pullRequest")
            if isinstance(github.get("pullRequest"), dict)
            else {}
        )
        workspace = (
            paperclip.get("workspaceIdentity")
            if isinstance(paperclip.get("workspaceIdentity"), dict)
            else {}
        )
        checks = github.get("checks") if isinstance(github.get("checks"), list) else []
        claim = (
            paperclip.get("claim") if isinstance(paperclip.get("claim"), dict) else {}
        )
        claimant = (
            claim.get("claimant") if isinstance(claim.get("claimant"), dict) else {}
        )
        workspace_operation = (
            paperclip.get("workspaceOperation")
            if isinstance(paperclip.get("workspaceOperation"), dict)
            else {}
        )
        router = row.get("router") if isinstance(row.get("router"), dict) else {}
        attribution = (
            router.get("serverAttribution")
            if isinstance(router.get("serverAttribution"), dict)
            else {}
        )
        execution_id = str(execution.get("id") or "")
        branch = str(github.get("branch") or "")
        if (
            not execution_id
            or execution.get("flowRevision") != flow_revision
            or branch != f"agent/paperclip-e2e-{execution_id}"
            or not checks
            or any(
                not isinstance(check, dict) or not isinstance(check.get("id"), int)
                for check in checks
            )
        ):
            raise CanaryError(
                "cross_run_identity_invalid",
                "run revision, branch, or check identity is not exact",
            )
        fields["executionIds"].append(execution_id)
        fields["paperclipIssueIds"].append(paperclip.get("issueId"))
        fields["heartbeatRunIds"].append(paperclip.get("heartbeatRunId"))
        fields["issueIds"].append(paperclip.get("issueId"))
        fields["agentIds"].append(claimant.get("id"))
        fields["claimLeaseIds"].append(claim.get("leaseId"))
        fields["nativeExecutableProofs"].append(
            workspace_operation.get("operationFingerprintSha256")
        )
        fields["routerAttributionProofs"].append(
            attribution.get("attributionFingerprintSha256")
        )
        fields["sandboxIds"].append(workspace.get("sandboxId"))
        fields["workspaceIds"].append(workspace.get("executionWorkspaceId"))
        fields["branches"].append(branch)
        fields["commitShas"].append(github.get("commitSha"))
        fields["pullRequestNumbers"].append(pull.get("number"))
        fields["pullRequestUrls"].append(pull.get("url"))
        check_ids.extend(int(check["id"]) for check in checks)

    for name, identities in fields.items():
        if (
            any(value in {None, ""} for value in identities)
            or len(set(identities)) != 3
        ):
            raise CanaryError(
                "cross_run_identity_invalid",
                f"{name} are not three distinct identities",
            )
    if len(set(check_ids)) != len(check_ids):
        raise CanaryError(
            "cross_run_identity_invalid", "GitHub check identities overlap between runs"
        )
    safe_fields = {
        name: values
        for name, values in fields.items()
        if name not in {"pullRequestUrls"}
    }
    proof = {
        "status": "passed",
        "profileOrder": profiles,
        "flowRevision": flow_revision,
        **safe_fields,
        "pullRequestUrlFingerprintsSha256": [
            hashlib.sha256(str(value).encode()).hexdigest()
            for value in fields["pullRequestUrls"]
        ],
        "checkIds": check_ids,
    }
    proof["identityFingerprintSha256"] = hashlib.sha256(
        json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return proof


def harness_scoped_router_auth(
    router: dict[str, Any],
    *,
    profile: str,
    adapter: str,
    model: str,
    router_origin: str,
) -> dict[str, Any]:
    key_ref = f"NINEROUTER_PROFILE_{safe_slug(profile)}_API_KEY"
    canonical_origin = router_origin.rstrip("/")
    if adapter == "claude_local":
        expected_base = canonical_origin
    elif adapter in {"codex_local", "pi_local"}:
        expected_base = canonical_origin + "/v1"
    else:
        raise CanaryError(
            "harness_scoped_router_auth_failed",
            "native adapter has no exact 9router base URL contract",
        )
    if (
        router.get("profileKeyRef") != key_ref
        or router.get("model") != model
        or router.get("profileKeyRequestsDelta", 0) <= 0
        or router.get("modelRequestsDelta", 0) <= 0
        or router.get("totalRequestsDelta", 0) <= 0
    ):
        raise CanaryError(
            "harness_scoped_router_auth_failed",
            "profile-scoped 9router usage was not independently observed",
        )
    return {
        "check": "harness-scoped-router-auth",
        "status": "passed",
        "profileRef": profile,
        "nativeAdapter": adapter,
        "evidenceSource": "9router-server-side-usage",
        "routerBaseUrl": expected_base,
        "routerProfileKeyRef": key_ref,
        "model": model,
        "profileKeyRequestsDelta": router["profileKeyRequestsDelta"],
        "modelRequestsDelta": router["modelRequestsDelta"],
        "totalRequestsDelta": router["totalRequestsDelta"],
    }


def validated_toolhive_profile(
    document: dict[str, Any],
    values: dict[str, str],
    catalog_row: dict[str, Any],
    *,
    profile: str,
    normalized_run_id: str,
) -> dict[str, Any]:
    """Validate the native runner's profile-scoped ToolHive protocol proof.

    The evidence contains only refs and hashes.  Raw bearer values, endpoint
    contents, tool arguments, and tool results are deliberately excluded.
    """
    access = (
        catalog_row.get("toolAccess")
        if isinstance(catalog_row.get("toolAccess"), dict)
        else {}
    )
    proof = (
        document.get("toolhive") if isinstance(document.get("toolhive"), dict) else {}
    )
    endpoint_ref = str(access.get("endpointRef") or "")
    credential_ref = str(access.get("credentialRef") or "")
    endpoint = values.get(endpoint_ref, "")
    credential = values.get(credential_ref, "")
    parsed_endpoint = urllib.parse.urlparse(endpoint)
    wrong_profile_endpoint_ref = {
        "coding-daytona-codex": "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_URL",
        "coding-daytona-claude": "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL",
        "coding-daytona-pi": "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
    }.get(profile, "")
    wrong_profile_endpoint = values.get(wrong_profile_endpoint_ref, "")
    parsed_wrong_profile_endpoint = urllib.parse.urlparse(wrong_profile_endpoint)
    marker = f"mte-c010:{profile}:{normalized_run_id}"
    marker_hash = hashlib.sha256(marker.encode()).hexdigest()
    hash_fields = (
        "markerSha256",
        "echoedMarkerSha256",
        "toolsListSha256",
        "resultSha256",
    )
    contract_values = (
        access.get("bundleId"),
        access.get("workloadId"),
        endpoint_ref,
        credential_ref,
        access.get("canaryTool"),
    )
    if (
        not all(isinstance(value, str) and value for value in contract_values)
        or not endpoint.startswith("http://172.20.0.1:")
        or not endpoint.endswith("/mcp")
        or parsed_endpoint.scheme != "http"
        or parsed_endpoint.hostname is None
        or parsed_endpoint.port is None
        or parsed_endpoint.path != "/mcp"
        or parsed_endpoint.username is not None
        or parsed_endpoint.password is not None
        or parsed_endpoint.query
        or parsed_endpoint.fragment
        or not wrong_profile_endpoint_ref
        or parsed_wrong_profile_endpoint.scheme != "http"
        or parsed_wrong_profile_endpoint.hostname != parsed_endpoint.hostname
        or parsed_wrong_profile_endpoint.port is None
        or parsed_wrong_profile_endpoint.port == parsed_endpoint.port
        or parsed_wrong_profile_endpoint.path != "/mcp"
        or parsed_wrong_profile_endpoint.username is not None
        or parsed_wrong_profile_endpoint.password is not None
        or parsed_wrong_profile_endpoint.query
        or parsed_wrong_profile_endpoint.fragment
        or not credential
        or proof.get("profileRef") != profile
        or proof.get("runId") != normalized_run_id
        or proof.get("bundleId") != access.get("bundleId")
        or proof.get("workloadId") != access.get("workloadId")
        or proof.get("endpointRef") != endpoint_ref
        or proof.get("runtimeEndpointEnv") != endpoint_ref
        or proof.get("endpointSha256") != hashlib.sha256(endpoint.encode()).hexdigest()
        or proof.get("credentialRef") != credential_ref
        or proof.get("bearerRuntimeEnv") != "MTE_TOOLHIVE_BEARER_TOKEN"
        or proof.get("canaryTool") != access.get("canaryTool")
        or proof.get("runnerOrigin") != "daytona"
        or proof.get("toolName") != access.get("canaryTool")
        or proof.get("initialize") is not True
        or proof.get("toolsList") is not True
        or proof.get("canaryCall") is not True
        or proof.get("httpStatus") != 200
        or proof.get("unauthorizedStatus") != 401
        or proof.get("wrongProfileEndpointRef") != wrong_profile_endpoint_ref
        or proof.get("wrongProfileDenied") is not True
        or proof.get("wrongProfileStatus") != 401
        or proof.get("gatewayReachableHost") != parsed_endpoint.hostname
        or proof.get("gatewayReachablePort") != parsed_endpoint.port
        or proof.get("credentialLeak") is not False
        or proof.get("markerSha256") != marker_hash
        or proof.get("echoedMarkerSha256") != marker_hash
        or any(
            not isinstance(proof.get(field), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(proof.get(field)))
            for field in hash_fields
        )
    ):
        raise CanaryError(
            "runner_toolhive_profile_failed",
            "native runner did not prove its exact profile ToolHive initialize/list/echo contract",
        )
    return {
        "check": "runner-toolhive-profile",
        "status": "passed",
        "profileRef": profile,
        "runId": normalized_run_id,
        "bundleId": access["bundleId"],
        "workloadId": access["workloadId"],
        "endpointRef": endpoint_ref,
        "runtimeEndpointEnv": endpoint_ref,
        "endpointSha256": hashlib.sha256(endpoint.encode()).hexdigest(),
        "credentialRef": credential_ref,
        "bearerRuntimeEnv": "MTE_TOOLHIVE_BEARER_TOKEN",
        "canaryTool": access["canaryTool"],
        "runnerOrigin": "daytona",
        "toolName": access["canaryTool"],
        "initialize": True,
        "toolsList": True,
        "canaryCall": True,
        "httpStatus": 200,
        "unauthorizedStatus": 401,
        "wrongProfileEndpointRef": wrong_profile_endpoint_ref,
        "wrongProfileDenied": True,
        "wrongProfileStatus": 401,
        "gatewayReachableHost": parsed_endpoint.hostname,
        "gatewayReachablePort": parsed_endpoint.port,
        "credentialLeak": False,
        "markerSha256": marker_hash,
        "toolsListSha256": proof["toolsListSha256"],
        "resultSha256": proof["resultSha256"],
    }


def validated_daytona_gateway_evidence(
    values: dict[str, str], runtime_network: dict[str, Any]
) -> str:
    document = load_json(DAYTONA_EVIDENCE)
    gateway = (
        document.get("agentGateway")
        if isinstance(document.get("agentGateway"), dict)
        else {}
    )
    rows = gateway.get("profiles") if isinstance(gateway.get("profiles"), list) else []
    expected_networks = sorted(
        {
            "mte-daytona-net",
            values.get("MTE_AGENT_PLANE_NETWORK", ""),
            "mte-tool-runtime",
        }
    )
    expected_rows = []
    for profile_ref, harness in (
        ("coding-daytona-codex", "CODEX"),
        ("coding-daytona-claude", "CLAUDE"),
        ("coding-daytona-pi", "PI"),
    ):
        upstream_ref = f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_UPSTREAM"
        upstream = urllib.parse.urlparse(values.get(upstream_ref, ""))
        gateway_port = values.get(f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_PORT", "")
        expected_rows.append(
            {
                "profileRef": profile_ref,
                "upstreamRef": upstream_ref,
                "host": "tool-runtime",
                "port": upstream.port,
                "gatewayPort": int(gateway_port) if gateway_port.isdigit() else None,
                "httpStatus": 200,
                "initialize": True,
            }
        )
    runner_id = str(gateway.get("runnerContainerId") or "")
    gateway_id = str(gateway.get("gatewayContainerId") or "")
    if (
        document.get("apiVersion") != "micro-task-engine/v1alpha1"
        or document.get("kind") != "PaperclipDaytonaControlPlaneEvidence"
        or document.get("status") != "ready"
        or document.get("canonicalSourceSha256") != sha256_file(PLATFORM_ENV)
        or document.get("producerPath") != str(DAYTONA_STEP_SOURCE)
        or document.get("producerSha256") != sha256_file(DAYTONA_STEP_SOURCE)
        or document.get("secretValuesPrinted") is not False
        or gateway.get("status") != "passed"
        or gateway.get("profileCount") != 3
        or not runner_id
        or not gateway_id
        or gateway.get("gatewayNetworkMode") != f"container:{runner_id}"
        or gateway.get("runnerNetworks") != expected_networks
        or gateway.get("expectedRunnerNetworks") != expected_networks
        or gateway.get("privateToolRuntimeNetwork") != "mte-tool-runtime"
        or gateway.get("noPublishedPorts") is not True
        or rows != expected_rows
        or runtime_network.get("runnerContainerId") != runner_id
        or runtime_network.get("gatewayContainerId") != gateway_id
        or runtime_network.get("runnerNetworkNames") != expected_networks
        or runtime_network.get("gatewaySharesRunnerNamespace") is not True
        or runtime_network.get("publishedPorts") != []
    ):
        raise CanaryError(
            "daytona_gateway_evidence_invalid",
            "Daytona control-plane evidence is not bound to the current private gateway",
        )
    return sha256_file(DAYTONA_EVIDENCE)


def toolhive_gateway_audit(
    values: dict[str, str],
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Create a durable, secret-free audit bound to live gateway sources.

    The native harness supplies protocol results, while this controller binds
    the allowlisted result to the exact canonical endpoint, deployed gateway
    producer, and independently reconciled profile catalog. No endpoint URL,
    token, authorization header, token fingerprint, or raw echo marker is
    retained.
    """
    reconcile = load_json(PROFILE_RECONCILE_EVIDENCE)
    canonical_sha = sha256_file(PLATFORM_ENV)
    gateway_sha = sha256_file(GATEWAY_SOURCE)
    reconcile_producer_sha = sha256_file(PROFILE_RECONCILE_SOURCE)
    runtime_network = gateway_runtime_network_proof()
    daytona_gateway_evidence_sha = validated_daytona_gateway_evidence(
        values, runtime_network
    )
    if (
        reconcile.get("apiVersion") != "micro-task-engine/v1alpha1"
        or reconcile.get("kind") != "ProfileReconcileEvidence"
        or reconcile.get("status") != "passed"
        or reconcile.get("ok") is not True
        or reconcile.get("canonicalSourceSha256") != canonical_sha
        or reconcile.get("producerPath") != str(PROFILE_RECONCILE_SOURCE)
        or reconcile.get("producerSha256") != reconcile_producer_sha
    ):
        raise CanaryError(
            "toolhive_gateway_audit_provenance_invalid",
            "profile reconcile evidence is not bound to current canonical sources",
        )
    expected_profiles = (
        "coding-daytona-codex",
        "coding-daytona-claude",
        "coding-daytona-pi",
    )
    if (
        len(rows) != 3
        or tuple(row.get("profileRef") for row in rows) != expected_profiles
    ):
        raise CanaryError(
            "toolhive_gateway_audit_runs_invalid",
            "gateway audit requires the exact ordered native profile set",
        )
    allowed_rows: list[dict[str, Any]] = []
    for row in rows:
        profile_ref = str(row.get("profileRef") or "")
        harness = profile_ref.rsplit("-", 1)[-1].upper()
        upstream_ref = f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_UPSTREAM"
        proxy_port_ref = f"TOOLHIVE_PROFILE_CODING_DAYTONA_{harness}_PROXY_PORT"
        upstream = urllib.parse.urlparse(values.get(upstream_ref, ""))
        proxy_port = values.get(proxy_port_ref, "")
        audit_row = {
            key: row.get(key)
            for key in (
                "profileRef",
                "bundleId",
                "workloadId",
                "endpointRef",
                "credentialRef",
                "runnerOrigin",
                "initialize",
                "toolsList",
                "toolName",
                "canaryCall",
                "markerSha256",
                "httpStatus",
                "wrongProfileEndpointRef",
                "wrongProfileDenied",
                "wrongProfileStatus",
                "gatewayReachableHost",
                "gatewayReachablePort",
            )
        }
        audit_row.update(
            {
                "gatewayUpstreamRef": upstream_ref,
                "gatewayUpstreamHost": upstream.hostname,
                "gatewayUpstreamPort": upstream.port,
            }
        )
        if (
            audit_row["runnerOrigin"] != "daytona"
            or audit_row["initialize"] is not True
            or audit_row["toolsList"] is not True
            or audit_row["toolName"] != "echo"
            or audit_row["canaryCall"] is not True
            or audit_row["httpStatus"] != 200
            or audit_row["wrongProfileDenied"] is not True
            or audit_row["wrongProfileStatus"] != 401
            or not re.fullmatch(r"[0-9a-f]{64}", str(audit_row["markerSha256"] or ""))
            or audit_row["gatewayReachableHost"] != "172.20.0.1"
            or not isinstance(audit_row["gatewayReachablePort"], int)
            or upstream.scheme != "http"
            or upstream.hostname != "tool-runtime"
            or upstream.path not in {"", "/"}
            or upstream.params
            or upstream.query
            or upstream.fragment
            or upstream.username is not None
            or upstream.password is not None
            or not proxy_port.isdigit()
            or upstream.port != int(proxy_port)
        ):
            raise CanaryError(
                "toolhive_gateway_audit_runs_invalid",
                "gateway audit row does not prove the exact cross-profile contract",
            )
        allowed_rows.append(audit_row)
    payload = {
        "status": "passed",
        "generatedAt": utcnow(),
        "canonicalSourceSha256": canonical_sha,
        "gatewayProducerPath": str(GATEWAY_SOURCE),
        "gatewayProducerSha256": gateway_sha,
        "profileReconcileEvidencePath": str(PROFILE_RECONCILE_EVIDENCE),
        "profileReconcileEvidenceSha256": sha256_file(PROFILE_RECONCILE_EVIDENCE),
        "profileReconcileProducerPath": str(PROFILE_RECONCILE_SOURCE),
        "profileReconcileProducerSha256": reconcile_producer_sha,
        "daytonaStepPath": str(DAYTONA_STEP_SOURCE),
        "daytonaStepSha256": sha256_file(DAYTONA_STEP_SOURCE),
        "daytonaGatewayEvidencePath": str(DAYTONA_EVIDENCE),
        "daytonaGatewayEvidenceSha256": daytona_gateway_evidence_sha,
        "gatewayRuntimeNetwork": "mte-tool-runtime",
        "runtimeNetworkProof": runtime_network,
        "profiles": allowed_rows,
    }
    scan_for_secrets(payload, values)
    return payload


def verify_stored_toolhive_gateway_audit(
    stored: Any,
    values: dict[str, str],
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(stored, dict):
        raise CanaryError(
            "toolhive_gateway_audit_missing", "stored gateway audit is missing"
        )
    generated = parse_timestamp(
        stored.get("generatedAt"), "toolhiveGatewayAudit.generatedAt"
    )
    now = datetime.now(timezone.utc)
    age = (now - generated.astimezone(timezone.utc)).total_seconds()
    if age < -60 or age > 600:
        raise CanaryError(
            "toolhive_gateway_audit_stale",
            "stored gateway audit is outside the 600 second verification window",
        )
    current = toolhive_gateway_audit(values, rows)
    comparable_current = {
        key: value for key, value in current.items() if key != "generatedAt"
    }
    comparable_stored = {
        key: value for key, value in stored.items() if key != "generatedAt"
    }
    if comparable_stored != comparable_current:
        raise CanaryError(
            "toolhive_gateway_audit_drift",
            "stored gateway audit differs from current sources or live run validation",
        )
    return current


def gateway_runtime_network_proof() -> dict[str, Any]:
    containers = ("mte-daytona-runner", "mte-agent-plane-gateway")
    try:
        result = subprocess.run(
            ["docker", "inspect", *containers],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        documents = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise CanaryError(
            "toolhive_gateway_runtime_network_unavailable",
            "cannot inspect the live Daytona runner/gateway network contract",
        ) from exc
    by_name = {
        str(document.get("Name") or "").lstrip("/"): document
        for document in documents
        if isinstance(document, dict)
    }
    runner = by_name.get(containers[0])
    gateway = by_name.get(containers[1])
    if not isinstance(runner, dict) or not isinstance(gateway, dict):
        raise CanaryError(
            "toolhive_gateway_runtime_network_invalid",
            "Daytona runner/gateway inspect identity is incomplete",
        )
    runner_id = str(runner.get("Id") or "")
    gateway_mode = str((gateway.get("HostConfig") or {}).get("NetworkMode") or "")
    runner_networks = sorted(
        str(name)
        for name in ((runner.get("NetworkSettings") or {}).get("Networks") or {})
    )
    published: list[str] = []
    for name, document in ((containers[0], runner), (containers[1], gateway)):
        bindings = (document.get("HostConfig") or {}).get("PortBindings") or {}
        published.extend(f"{name}:{port}" for port, rows in bindings.items() if rows)
    expected_networks = ["mte-agent-plane", "mte-daytona-net", "mte-tool-runtime"]
    shares_runner = bool(runner_id) and gateway_mode == f"container:{runner_id}"
    if runner_networks != expected_networks or not shares_runner or published:
        raise CanaryError(
            "toolhive_gateway_runtime_network_invalid",
            "gateway is not isolated on the exact private runtime network contract",
        )
    return {
        "runnerContainer": containers[0],
        "gatewayContainer": containers[1],
        "runnerContainerId": runner_id,
        "gatewayContainerId": str(gateway.get("Id") or ""),
        "runnerNetworkNames": runner_networks,
        "gatewaySharesRunnerNamespace": True,
        "publishedPorts": [],
    }


def validate_evidence(
    execution: dict[str, Any],
    paperclip: dict[str, Any],
    artifacts: list[dict[str, Any]],
    pull: dict[str, Any],
    checks: list[dict[str, Any]],
    e2e: dict[str, Any],
    branch: str,
    profile: str,
    expected_adapter: str | None = None,
    *,
    expected_model: str = "",
    pull_files: list[dict[str, Any]] | None = None,
    commit: dict[str, Any] | None = None,
    expected_pull_state: str = "open",
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if execution.get("state") != "SUCCESS":
        raise CanaryError("kestra_failed", "Kestra execution did not finish SUCCESS")
    native = (
        paperclip.get("native") if isinstance(paperclip.get("native"), dict) else {}
    )
    if (
        paperclip.get("status") != "succeeded"
        or native.get("platform") != "paperclip"
        or not native.get("issueId")
        or not native.get("heartbeatRunId")
    ):
        raise CanaryError(
            "paperclip_failed",
            "normalized Paperclip run lacks terminal native evidence",
        )
    adapter = expected_adapter or str(
        (paperclip.get("claim") or {}).get("claimant", {}).get("adapterType", "")
    )
    document = validate_harness_document(
        artifacts,
        pull,
        e2e,
        branch,
        profile,
        adapter,
        expected_model,
    )
    environment = (
        paperclip.get("environment")
        if isinstance(paperclip.get("environment"), dict)
        else {}
    )
    daytona = (
        document.get("daytona") if isinstance(document.get("daytona"), dict) else {}
    )
    if (
        not environment.get("sandboxId")
        or daytona.get("sandboxId") != environment.get("sandboxId")
        or environment.get("providerLeaseId") != environment.get("sandboxId")
    ):
        raise CanaryError(
            "harness_daytona_mismatch",
            "harness Daytona sandbox does not match the Paperclip environment lease",
        )
    claim = validated_claim(
        paperclip,
        adapter,
    )
    heartbeat = validated_heartbeat_sequence(paperclip, claim)
    github = validated_github_evidence(
        execution,
        pull,
        checks,
        e2e,
        branch,
        pull_files=pull_files,
        commit=commit,
        expected_pull_state=expected_pull_state,
    )
    timestamps = (
        document.get("timestamps")
        if isinstance(document.get("timestamps"), dict)
        else {}
    )
    harness_started = parse_timestamp(timestamps.get("startedAt"), "harness.startedAt")
    harness_finished = parse_timestamp(
        timestamps.get("finishedAt"), "harness.finishedAt"
    )
    execution_started = parse_timestamp(
        execution.get("startDate"), "execution.startDate"
    )
    execution_finished = parse_timestamp(execution.get("endDate"), "execution.endDate")
    if (
        harness_started < execution_started
        or harness_finished < harness_started
        or harness_finished > execution_finished
        or document.get("commitSha") != github.get("commitSha")
    ):
        raise CanaryError(
            "harness_timeline_invalid",
            "harness timestamps or commit are outside the Kestra/GitHub run",
        )
    return document, claim, heartbeat


def scan_for_secrets(payload: dict[str, Any], values: dict[str, str]) -> None:
    rendered = json.dumps(payload, sort_keys=True)
    protected = {
        name: secret
        for name, secret in values.items()
        if re.search(r"(?:PASSWORD|TOKEN|API_KEY|SECRET)$", name)
    }
    for name, secret in protected.items():
        if len(secret) >= 8 and secret in rendered:
            raise CanaryError(
                "evidence_secret_leak", f"evidence contains protected ref {name}"
            )
    if re.search(
        r"(?i)(github_pat_|ghp_|sk-ant-|sk-proj-|authorization\s*[:=]\s*bearer)",
        rendered,
    ):
        raise CanaryError(
            "evidence_secret_pattern", "evidence contains a credential-shaped value"
        )


def cleanup_github(
    e2e: dict[str, Any], token: str, branch: str, pull: dict[str, Any] | None
) -> dict[str, Any]:
    owner = str(e2e["githubOwner"])
    repo = str(e2e["githubRepository"])
    query = urllib.parse.urlencode(
        {"state": "all", "head": f"{owner}:{branch}", "per_page": "10"}
    )
    if pull is None:
        status, candidates = github_cleanup_request(
            token,
            "GET",
            f"/repos/{owner}/{repo}/pulls?{query}",
        )
        if status != 200 or not isinstance(candidates, list):
            raise CanaryError(
                "github_cleanup_lookup_failed", "could not verify canary PR state"
            )
        pull = next((row for row in candidates if isinstance(row, dict)), None)
    if pull and pull.get("number") and pull.get("state") == "open":
        github_cleanup_request(
            token,
            "PATCH",
            f"/repos/{owner}/{repo}/pulls/{int(pull['number'])}",
            {"state": "closed"},
        )
    delete_ref_path = f"/repos/{owner}/{repo}/git/refs/heads/{branch}"
    get_ref_path = f"/repos/{owner}/{repo}/git/ref/heads/{branch}"
    github_cleanup_request(token, "DELETE", delete_ref_path)
    ref_status, _ = github_cleanup_request(token, "GET", get_ref_path)
    deleted = ref_status == 404
    pull_number = int(pull["number"]) if pull and pull.get("number") else None
    pr_status: int | None = None
    current_state: str | None = None
    if pull_number is not None:
        pr_status, current = github_cleanup_request(
            token,
            "GET",
            f"/repos/{owner}/{repo}/pulls/{pull_number}",
        )
        current_state = (
            str(current.get("state") or "") if isinstance(current, dict) else None
        )
        closed = (
            pr_status == 200 and isinstance(current, dict) and current_state == "closed"
        )
    else:
        list_status, candidates = github_cleanup_request(
            token,
            "GET",
            f"/repos/{owner}/{repo}/pulls?{query}",
        )
        closed = list_status == 200 and isinstance(candidates, list) and not candidates
    return {
        "requested": True,
        "pullRequestNumber": pull_number,
        "pullRequestGetStatus": pr_status if pull_number is not None else list_status,
        "pullRequestState": current_state if pull_number is not None else "absent",
        "pullRequestClosed": closed,
        "branchRef": f"refs/heads/{branch}",
        "branchGetStatus": ref_status,
        "branchDeleted": deleted,
    }


def daytona_request(
    values: dict[str, str],
    method: str,
    sandbox_id: str,
) -> tuple[int, Any]:
    base = values.get("DAYTONA_API_URL", "").rstrip("/")
    key = values.get("DAYTONA_API_KEY", "")
    if not base.endswith("/api") or not key:
        raise CanaryError(
            "missing_daytona_ref",
            "canonical Daytona API URL or credential ref is missing",
        )
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", sandbox_id):
        raise CanaryError(
            "unsafe_daytona_id", "Daytona sandbox id contains unsafe characters"
        )
    return request_json(
        base + "/sandbox/" + urllib.parse.quote(sandbox_id, safe=""),
        method,
        headers={"Authorization": f"Bearer {key}"},
        allow_status={404},
        timeout=30,
    )


def daytona_environment_sandboxes(
    values: dict[str, str], environment_id: str
) -> list[dict[str, Any]]:
    base = values.get("DAYTONA_API_URL", "").rstrip("/")
    key = values.get("DAYTONA_API_KEY", "")
    if not base.endswith("/api") or not key or not environment_id:
        raise CanaryError(
            "missing_daytona_ref",
            "Daytona environment lookup is missing canonical identity or auth refs",
        )
    labels = json.dumps(
        {"paperclip-environment-id": environment_id}, separators=(",", ":")
    )
    rows: list[dict[str, Any]] = []
    for page in range(1, 101):
        query = urllib.parse.urlencode(
            {"page": str(page), "limit": "100", "labels": labels}
        )
        _, value = request_json(
            base + "/sandbox/paginated?" + query,
            headers={"Authorization": f"Bearer {key}"},
            timeout=30,
        )
        page_rows = (
            value.get("items")
            if isinstance(value, dict) and isinstance(value.get("items"), list)
            else value.get("data")
            if isinstance(value, dict) and isinstance(value.get("data"), list)
            else None
        )
        if page_rows is None or any(not isinstance(item, dict) for item in page_rows):
            raise CanaryError(
                "daytona_global_lookup_invalid",
                "Daytona paginated sandbox response is invalid",
            )
        rows.extend(page_rows)
        if len(page_rows) < 100:
            break
    else:
        raise CanaryError(
            "daytona_global_lookup_invalid",
            "Daytona paginated sandbox lookup exceeded the bounded page limit",
        )
    return rows


def global_cleanup_absence(
    e2e: dict[str, Any], values: dict[str, str], environment_id: str
) -> dict[str, Any]:
    sandboxes = daytona_environment_sandboxes(values, environment_id)
    owner = str(e2e["githubOwner"])
    repo = str(e2e["githubRepository"])
    ref_prefix = "refs/heads/agent/paperclip-e2e-"
    refs: list[dict[str, Any]] = []
    pulls: list[dict[str, Any]] = []
    for page in range(1, 11):
        query = urllib.parse.urlencode({"per_page": "100", "page": str(page)})
        page_rows = public_github(
            f"/repos/{owner}/{repo}/git/matching-refs/heads/agent/paperclip-e2e-?{query}"
        )
        if not isinstance(page_rows, list) or any(
            not isinstance(item, dict) for item in page_rows
        ):
            raise CanaryError(
                "github_global_lookup_invalid",
                "GitHub matching-ref response is invalid",
            )
        refs.extend(page_rows)
        if len(page_rows) < 100:
            break
    else:
        raise CanaryError(
            "github_global_lookup_invalid",
            "GitHub matching-ref pagination exceeded its bound",
        )
    matching_refs = [
        str(item.get("ref"))
        for item in refs
        if str(item.get("ref") or "").startswith(ref_prefix)
    ]
    for page in range(1, 11):
        query = urllib.parse.urlencode(
            {"state": "open", "per_page": "100", "page": str(page)}
        )
        page_rows = public_github(f"/repos/{owner}/{repo}/pulls?{query}")
        if not isinstance(page_rows, list) or any(
            not isinstance(item, dict) for item in page_rows
        ):
            raise CanaryError(
                "github_global_lookup_invalid", "GitHub open-PR response is invalid"
            )
        pulls.extend(page_rows)
        if len(page_rows) < 100:
            break
    else:
        raise CanaryError(
            "github_global_lookup_invalid",
            "GitHub open-PR pagination exceeded its bound",
        )
    matching_pulls = [
        int(item["number"])
        for item in pulls
        if isinstance(item.get("number"), int)
        and isinstance(item.get("head"), dict)
        and str(item["head"].get("ref") or "").startswith("agent/paperclip-e2e-")
    ]
    if sandboxes or matching_refs or matching_pulls:
        raise CanaryError(
            "global_cleanup_incomplete",
            "global canary sandbox/ref/open-PR lookup found residual resources",
        )
    return {
        "status": "passed",
        "daytonaEnvironmentId": environment_id,
        "daytonaLabelFingerprintSha256": hashlib.sha256(
            f"paperclip-environment-id={environment_id}".encode()
        ).hexdigest(),
        "daytonaSandboxIds": [],
        "githubRepository": f"{owner}/{repo}",
        "githubRefPrefix": ref_prefix,
        "githubRefs": [],
        "githubOpenPullRequests": [],
    }


def paperclip_resource_state(
    paperclip: str, values: dict[str, str], issue_id: str
) -> dict[str, Any]:
    projection = native_issue_projection(paperclip, values, issue_id)
    environment = projection.get("environment") or {}
    workspace_id = str(environment.get("executionWorkspaceId") or "")
    workspace: dict[str, Any] = {}
    if workspace_id:
        _, workspace_value = paperclip_request(
            paperclip,
            values,
            "GET",
            f"/api/execution-workspaces/{workspace_id}",
        )
        workspace = workspace_value if isinstance(workspace_value, dict) else {}
    worktree_path = first_value(
        workspace.get("worktreePath"),
        workspace.get("workspacePath"),
        workspace.get("cwd"),
        workspace.get("path"),
        environment.get("remoteCwd"),
    )
    lease_released = environment.get("status") in {"released", "expired"} and (
        environment.get("cleanupStatus") in {None, "success"}
    )
    return {
        "runId": issue_id,
        "environment": environment,
        "paperclipWorkspace": {
            "id": workspace_id or None,
            "status": workspace.get("status"),
            "closedAt": workspace.get("closedAt"),
            "cleanupReason": workspace.get("cleanupReason"),
            "worktreePath": worktree_path,
            "worktreePathSource": "paperclip-native-workspace",
            "worktreePathFingerprintSha256": (
                hashlib.sha256(str(worktree_path).encode()).hexdigest()
                if worktree_path
                else None
            ),
            "worktreeAbsent": None,
            "filesystemAbsenceVerified": False,
        },
        "paperclipEnvironmentReleased": lease_released,
    }


def cleanup_paperclip_daytona(
    paperclip: str,
    values: dict[str, str],
    issue_id: str,
    *,
    attempts: int = 30,
    poll_interval: float = 2,
) -> dict[str, Any]:
    before = paperclip_resource_state(paperclip, values, issue_id)
    environment = (
        before.get("environment") if isinstance(before.get("environment"), dict) else {}
    )
    workspace = (
        before.get("paperclipWorkspace")
        if isinstance(before.get("paperclipWorkspace"), dict)
        else {}
    )
    sandbox_id = str(environment.get("sandboxId") or "")
    workspace_id = str(
        workspace.get("id") or environment.get("executionWorkspaceId") or ""
    )
    environment_lease_id = str(environment.get("environmentLeaseId") or "")
    provider_lease_id = str(environment.get("providerLeaseId") or "")
    remote_cwd = str(environment.get("remoteCwd") or "")
    worktree_path = str(workspace.get("worktreePath") or "")
    worktree_path_fingerprint = str(
        workspace.get("worktreePathFingerprintSha256") or ""
    )
    if (
        environment.get("provider") != "daytona"
        or not sandbox_id
        or not workspace_id
        or not environment_lease_id
        or not provider_lease_id
        or not remote_cwd
        or worktree_path != remote_cwd
        or not re.fullmatch(r"[0-9a-f]{64}", worktree_path_fingerprint)
        or worktree_path_fingerprint
        != hashlib.sha256(worktree_path.encode()).hexdigest()
    ):
        raise CanaryError(
            "paperclip_resource_identity_missing",
            "run lacks exact Paperclip/Daytona lease, sandbox, workspace, and cwd identities",
        )
    fingerprint = hashlib.sha256(
        "|".join(
            (
                "daytona",
                environment_lease_id,
                provider_lease_id,
                sandbox_id,
                workspace_id,
                remote_cwd,
            )
        ).encode()
    ).hexdigest()
    cleanup_error: CanaryError | None = None
    cleanup_request_attempts = 0
    for _ in range(attempts):
        cleanup_request_attempts += 1
        try:
            if workspace_id:
                paperclip_request(
                    paperclip,
                    values,
                    "PATCH",
                    f"/api/execution-workspaces/{workspace_id}",
                    body={"status": "archived"},
                )
            cleanup_error = None
            break
        except CanaryError as exc:
            cleanup_error = exc
            time.sleep(poll_interval)
    if cleanup_error is not None:
        raise CanaryError(
            "paperclip_resource_cleanup_failed",
            "Paperclip did not accept bounded workspace cleanup retries",
        ) from cleanup_error

    paperclip_after: dict[str, Any] | None = None
    paperclip_poll_attempts = 0
    for _ in range(attempts):
        paperclip_poll_attempts += 1
        paperclip_after = paperclip_resource_state(paperclip, values, issue_id)
        current_workspace = (
            paperclip_after.get("paperclipWorkspace")
            if isinstance(paperclip_after.get("paperclipWorkspace"), dict)
            else {}
        )
        if (
            current_workspace.get("id") == workspace_id
            and current_workspace.get("status") == "archived"
            and current_workspace.get("worktreePath") == worktree_path
            and current_workspace.get("worktreePathFingerprintSha256")
            == worktree_path_fingerprint
            and current_workspace.get("worktreeAbsent") is not True
            and current_workspace.get("filesystemAbsenceVerified") is not True
            and paperclip_after.get("paperclipEnvironmentReleased") is True
        ):
            break
        time.sleep(poll_interval)
    else:
        raise CanaryError(
            "paperclip_resource_cleanup_failed",
            "Paperclip workspace/worktree and environment lease were not released",
        )

    daytona_status, _ = daytona_request(values, "GET", sandbox_id)
    delete_requested = daytona_status == 200
    daytona_delete_attempts = 0
    if delete_requested:
        delete_error: CanaryError | None = None
        for _ in range(3):
            daytona_delete_attempts += 1
            try:
                daytona_request(values, "DELETE", sandbox_id)
                delete_error = None
                break
            except CanaryError as exc:
                delete_error = exc
                time.sleep(poll_interval)
        if delete_error is not None:
            raise CanaryError(
                "daytona_sandbox_cleanup_failed",
                "Daytona did not accept bounded sandbox deletion retries",
            ) from delete_error
    daytona_poll_attempts = 0
    for _ in range(attempts):
        daytona_poll_attempts += 1
        daytona_status, _ = daytona_request(values, "GET", sandbox_id)
        if daytona_status == 404:
            break
        time.sleep(poll_interval)
    else:
        raise CanaryError(
            "daytona_sandbox_cleanup_failed",
            "Daytona sandbox still exists after bounded cleanup",
        )

    current_workspace = paperclip_after["paperclipWorkspace"]
    return {
        "requested": True,
        "completed": True,
        "paperclipIssueId": issue_id,
        "provider": "daytona",
        "environmentLeaseId": environment_lease_id,
        "providerLeaseId": provider_lease_id,
        "sandboxId": sandbox_id,
        "executionWorkspaceId": workspace_id,
        "remoteCwd": remote_cwd,
        "worktreePath": worktree_path,
        "worktreePathFingerprintSha256": worktree_path_fingerprint,
        "resourceFingerprintSha256": fingerprint,
        "cleanupAttempts": {
            "paperclipDelete": cleanup_request_attempts,
            "paperclipPoll": paperclip_poll_attempts,
            "daytonaDelete": daytona_delete_attempts,
            "daytonaPoll": daytona_poll_attempts,
        },
        "paperclip": {
            "workspaceStatus": current_workspace.get("status"),
            "workspaceApiObserved": True,
            "worktreeAbsent": True,
            "filesystemAbsenceVerified": True,
            "filesystemProof": {
                "method": "exact_path_bound_to_absent_daytona_sandbox",
                "worktreePathFingerprintSha256": worktree_path_fingerprint,
                "sandboxId": sandbox_id,
                "providerGetStatus": 404,
            },
            "environmentLeaseReleased": True,
        },
        "daytona": {
            "deleteRequested": delete_requested,
            "providerGetStatus": 404,
            "sandboxAbsent": True,
        },
    }


def verify_resource_absence(
    paperclip: str,
    values: dict[str, str],
    issue_id: str,
    recorded: dict[str, Any],
) -> dict[str, Any]:
    current = paperclip_resource_state(paperclip, values, issue_id)
    workspace = (
        current.get("paperclipWorkspace")
        if isinstance(current.get("paperclipWorkspace"), dict)
        else {}
    )
    environment = (
        current.get("environment")
        if isinstance(current.get("environment"), dict)
        else {}
    )
    sandbox_id = str(recorded.get("sandboxId") or "")
    worktree_path = str(recorded.get("worktreePath") or "")
    worktree_path_fingerprint = str(recorded.get("worktreePathFingerprintSha256") or "")
    expected_fingerprint = hashlib.sha256(
        "|".join(
            (
                "daytona",
                str(recorded.get("environmentLeaseId") or ""),
                str(recorded.get("providerLeaseId") or ""),
                sandbox_id,
                str(recorded.get("executionWorkspaceId") or ""),
                str(recorded.get("remoteCwd") or ""),
            )
        ).encode()
    ).hexdigest()
    if (
        recorded.get("completed") is not True
        or recorded.get("resourceFingerprintSha256") != expected_fingerprint
        or workspace.get("id") != recorded.get("executionWorkspaceId")
        or environment.get("environmentLeaseId") != recorded.get("environmentLeaseId")
        or environment.get("providerLeaseId") != recorded.get("providerLeaseId")
        or environment.get("sandboxId") != sandbox_id
        or environment.get("remoteCwd") != recorded.get("remoteCwd")
        or workspace.get("status") != "archived"
        or workspace.get("worktreePath") != worktree_path
        or workspace.get("worktreePathFingerprintSha256") != worktree_path_fingerprint
        or worktree_path != recorded.get("remoteCwd")
        or not re.fullmatch(r"[0-9a-f]{64}", worktree_path_fingerprint)
        or worktree_path_fingerprint
        != hashlib.sha256(worktree_path.encode()).hexdigest()
        or (recorded.get("paperclip") or {}).get("workspaceApiObserved") is not True
        or (recorded.get("paperclip") or {}).get("worktreeAbsent") is not True
        or (recorded.get("paperclip") or {}).get("filesystemAbsenceVerified")
        is not True
        or current.get("paperclipEnvironmentReleased") is not True
    ):
        raise CanaryError(
            "resource_cleanup_drift",
            "Paperclip workspace or lease cleanup no longer matches recorded evidence",
        )
    daytona_status, _ = daytona_request(values, "GET", sandbox_id)
    if daytona_status != 404:
        raise CanaryError("resource_cleanup_drift", "recorded Daytona sandbox exists")
    return {
        "environmentLeaseId": recorded.get("environmentLeaseId"),
        "providerLeaseId": recorded.get("providerLeaseId"),
        "sandboxId": sandbox_id,
        "executionWorkspaceId": recorded.get("executionWorkspaceId"),
        "worktreePathFingerprintSha256": worktree_path_fingerprint,
        "resourceFingerprintSha256": recorded.get("resourceFingerprintSha256"),
        "paperclipWorktreeAbsent": True,
        "paperclipFilesystemAbsenceVerified": True,
        "daytonaSandboxAbsent": True,
    }


def paperclip_issue_id_from_execution(
    kestra: str,
    auth: dict[str, str],
    execution_id: str,
) -> str:
    execution = kestra_request(
        kestra,
        auth,
        "GET",
        "/api/v1/main/executions/" + urllib.parse.quote(execution_id),
    )
    if not isinstance(execution, dict):
        raise CanaryError(
            "invalid_execution", "Kestra execution response is not an object"
        )
    issue_id = ""
    for task_run in execution.get("taskRunList", []):
        if not isinstance(task_run, dict) or task_run.get("taskId") != "poll_issue":
            continue
        outputs = (
            task_run.get("outputs") if isinstance(task_run.get("outputs"), dict) else {}
        )
        body = outputs.get("body")
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                body = None
        if isinstance(body, dict) and body.get("id"):
            issue_id = str(body["id"])
            break
    if not issue_id:
        return ""
    return issue_id


def cleanup_nonterminal_paperclip_run(
    kestra: str,
    auth: dict[str, str],
    paperclip: str,
    values: dict[str, str],
    execution_id: str,
) -> dict[str, Any]:
    issue_id = paperclip_issue_id_from_execution(kestra, auth, execution_id)
    if not issue_id:
        return {"requested": False, "reason": "not_submitted"}
    run = native_issue_projection(paperclip, values, issue_id)
    if run.get("status") in {"succeeded", "failed", "cancelled", "timed_out"}:
        return {
            "requested": False,
            "paperclipIssueId": issue_id,
            "statusAfter": run.get("status"),
        }
    run_id = str((run.get("native") or {}).get("heartbeatRunId") or "")
    if run_id:
        paperclip_request(
            paperclip,
            values,
            "POST",
            f"/api/heartbeat-runs/{run_id}/cancel",
            body={},
        )
    paperclip_request(
        paperclip,
        values,
        "PATCH",
        f"/api/issues/{issue_id}",
        body={"status": "cancelled"},
    )
    after = native_issue_projection(paperclip, values, issue_id)
    if not isinstance(after, dict) or after.get("status") not in {
        "cancelled",
        "failed",
        "timed_out",
    }:
        raise CanaryError(
            "paperclip_cancel_failed", "nonterminal Paperclip run was not cancelled"
        )
    return {
        "requested": True,
        "paperclipIssueId": issue_id,
        "statusAfter": after.get("status"),
    }


def daytona_profile_refs(details: dict[str, Any]) -> set[str]:
    """Read only explicit profileRef/profileRefs fields from Daytona evidence."""
    refs: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            profile_ref = value.get("profileRef")
            if isinstance(profile_ref, str) and profile_ref:
                refs.add(profile_ref)
            profile_refs = value.get("profileRefs")
            if isinstance(profile_refs, list):
                refs.update(
                    str(item) for item in profile_refs if isinstance(item, str) and item
                )
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(details)
    return refs


def validated_daytona_runtime_evidence(
    values: dict[str, str], required_profiles: set[str]
) -> dict[str, Any]:
    """Bind E2E to the fresh Paperclip verify and its immutable runtime proofs."""
    canonical_sha = sha256_file(PLATFORM_ENV)
    require_private_evidence_file(DAYTONA_VERIFY_EVIDENCE)
    verify = load_json(DAYTONA_VERIFY_EVIDENCE)
    require_fresh_timestamp(
        verify.get("generatedAt"), "paperclip-daytona-verify.generatedAt"
    )
    details = verify.get("details") if isinstance(verify.get("details"), dict) else {}
    if (
        verify.get("apiVersion") != "micro-task-engine/v1alpha1"
        or verify.get("kind") != "PaperclipExperimentalReconcile"
        or verify.get("feature") != "daytona"
        or verify.get("action") != "verify"
        or verify.get("status") != "ready"
        or verify.get("canonicalSourceSha256") != canonical_sha
        or not FULL_SHA256.fullmatch(str(verify.get("producerSha256") or ""))
        or details.get("provider") != "daytona"
        or details.get("probe") != "passed"
        or set(details.get("profileRefs") or []) != required_profiles
        or not details.get("environmentId")
    ):
        raise CanaryError(
            "daytona_verify_invalid",
            "Paperclip Daytona verify evidence is not current and exact",
        )

    runtime = (
        details.get("runtimeEvidence")
        if isinstance(details.get("runtimeEvidence"), dict)
        else {}
    )
    specifications = (
        ("controlPlane", DAYTONA_EVIDENCE, "PaperclipDaytonaControlPlaneEvidence"),
        ("images", DAYTONA_IMAGES_EVIDENCE, "DaytonaHarnessSnapshots"),
        ("lifecycle", DAYTONA_LIFECYCLE_EVIDENCE, "DaytonaSandboxLifecycleEvidence"),
    )
    summaries: dict[str, Any] = {}
    for key, path, kind in specifications:
        require_private_evidence_file(path)
        document = load_json(path)
        reference = runtime.get(key) if isinstance(runtime.get(key), dict) else {}
        if (
            reference
            != {
                "path": str(path),
                "kind": kind,
                "status": "ready",
                "sha256": sha256_file(path),
            }
            or document.get("apiVersion") != "micro-task-engine/v1alpha1"
            or document.get("kind") != kind
            or document.get("status") != "ready"
            or document.get("canonicalSourceSha256") != canonical_sha
            or not FULL_SHA256.fullmatch(str(document.get("producerSha256") or ""))
            or parse_timestamp(document.get("generatedAt"), f"{path.name}.generatedAt")
            > datetime.now(timezone.utc)
        ):
            raise CanaryError(
                "daytona_runtime_evidence_invalid",
                f"{path.name} is not hash-bound to the Daytona verify evidence",
            )
        summaries[key] = {
            "path": str(path),
            "kind": kind,
            "sha256": reference["sha256"],
            "producerSha256": document.get("producerSha256"),
        }

    images = load_json(DAYTONA_IMAGES_EVIDENCE)
    snapshots = (
        images.get("snapshots") if isinstance(images.get("snapshots"), list) else []
    )
    lifecycle = load_json(DAYTONA_LIFECYCLE_EVIDENCE)
    coding_snapshot = values.get("MTE_DAYTONA_CODING_SNAPSHOT", "")
    snapshot = next(
        (
            row
            for row in snapshots
            if isinstance(row, dict) and row.get("name") == coding_snapshot
        ),
        None,
    )
    if (
        len(snapshots) != 2
        or not isinstance(snapshot, dict)
        or snapshot.get("state") != "active"
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(snapshot.get("digest") or ""))
        or images.get("credentialsBakedIntoImage") is not False
        or lifecycle.get("snapshot") != coding_snapshot
        or lifecycle.get("cleanupDeleted") is not True
        or (lifecycle.get("delete") or {}).get("getAfterDeleteStatus") != 404
        or (lifecycle.get("fileRoundTrip") or {}).get("verified") is not True
        or (lifecycle.get("persistence") or {}).get("verified") is not True
        or (lifecycle.get("credentialFileProbe") or {}).get("credentialFree")
        is not True
        or (lifecycle.get("github") or {}).get("cliVersion")
        != values.get("MTE_GITHUB_CLI_VERSION")
        or (lifecycle.get("github") or {}).get("authentication")
        != "GH_TOKEN-runtime-env"
        or (lifecycle.get("github") or {}).get("gitCredentialHelper")
        != "gh auth git-credential"
        or (lifecycle.get("github") or {}).get("tokenInRemoteUrl") is not False
        or (lifecycle.get("github") or {}).get("credentialFilePersisted") is not False
    ):
        raise CanaryError(
            "daytona_runtime_contract_invalid",
            "Daytona image/lifecycle evidence does not prove the coding snapshot contract",
        )
    return {
        "status": "passed",
        "verifyEvidenceSha256": sha256_file(DAYTONA_VERIFY_EVIDENCE),
        "environmentId": details.get("environmentId"),
        "snapshot": coding_snapshot,
        "snapshotDigest": snapshot.get("digest"),
        "runtimeEvidence": summaries,
        "lifecycleDeleteStatus": 404,
        "credentialsBakedIntoImage": False,
    }


def preflight(
    config: dict[str, Any], e2e: dict[str, Any], values: dict[str, str]
) -> dict[str, Any]:
    if e2e.get("cleanup") is not True:
        raise CanaryError(
            "cleanup_required",
            "E2E canary must release every Paperclip workspace and Daytona sandbox",
        )
    if not values.get("DAYTONA_API_URL", "").rstrip("/").endswith(
        "/api"
    ) or not values.get("DAYTONA_API_KEY", ""):
        raise CanaryError(
            "missing_daytona_ref",
            "canonical Daytona API URL or credential ref is missing",
        )
    if not values.get("NINEROUTER_MINIMAX_CONNECTION_ID", ""):
        raise CanaryError(
            "missing_router_ref",
            "canonical MiniMax connection identity is missing for server-side attribution",
        )
    required_profiles = set(str(item) for item in e2e["profiles"])
    daytona_runtime = validated_daytona_runtime_evidence(values, required_profiles)
    daytona_verify = load_json(DAYTONA_VERIFY_EVIDENCE)
    details = (
        daytona_verify.get("details")
        if isinstance(daytona_verify.get("details"), dict)
        else {}
    )
    catalog = profile_catalog()
    missing_catalog_profiles = sorted(required_profiles - set(catalog))
    if missing_catalog_profiles:
        raise CanaryError(
            "profile_catalog_incomplete",
            "requested profiles are absent from the canonical catalog: "
            + ", ".join(missing_catalog_profiles),
        )
    tool_access_drift = []
    for ref in sorted(required_profiles):
        access = (
            catalog[ref].get("toolAccess")
            if isinstance(catalog[ref].get("toolAccess"), dict)
            else {}
        )
        endpoint_ref = str(access.get("endpointRef") or "")
        credential_ref = str(access.get("credentialRef") or "")
        endpoint = values.get(endpoint_ref, "")
        if (
            not all(
                str(access.get(key) or "")
                for key in (
                    "bundleId",
                    "workloadId",
                    "endpointRef",
                    "credentialRef",
                    "canaryTool",
                )
            )
            or not endpoint.startswith("http://172.20.0.1:")
            or not endpoint.endswith("/mcp")
            or not values.get(credential_ref, "")
        ):
            tool_access_drift.append(ref)
    if tool_access_drift:
        raise CanaryError(
            "profile_tool_access_drift",
            "profile ToolHive endpoint/credential contracts are incomplete: "
            + ", ".join(tool_access_drift),
        )
    expected_adapters = {
        str(ref): str(contract["nativeAdapter"])
        for ref, contract in e2e["profileContracts"].items()
    }
    adapter_drift = [
        ref
        for ref, expected in expected_adapters.items()
        if ref in required_profiles and catalog[ref]["adapter"] != expected
    ]
    if adapter_drift:
        raise CanaryError(
            "profile_adapter_drift",
            "requested profile adapter types do not match the acceptance contract: "
            + ", ".join(sorted(adapter_drift)),
        )
    implicit_routes = [
        ref
        for ref, contract in e2e["profileContracts"].items()
        if contract["requireExplicitProvider"]
        and (not catalog[ref].get("provider") or not catalog[ref].get("model"))
    ]
    if implicit_routes:
        raise CanaryError(
            "profile_route_implicit",
            "profiles requiring explicit provider and model are incomplete: "
            + ", ".join(sorted(implicit_routes)),
        )
    evidenced_profiles = daytona_profile_refs(details)
    if (
        details.get("provider") != "daytona"
        or details.get("probe") != "passed"
        or not required_profiles <= evidenced_profiles
    ):
        raise CanaryError(
            "daytona_not_ready",
            "Daytona evidence is not ready for every requested profile",
        )

    kestra = str(e2e["kestraBaseUrl"]).rstrip("/")
    auth = basic_auth(values)
    flow_namespace = "micro_task_engine.e2e"
    flow_id = "paperclip-github-e2e"
    existing_flow = kestra_request(
        kestra,
        auth,
        "GET",
        "/api/v1/main/flows/"
        + urllib.parse.quote(flow_namespace, safe="")
        + "/"
        + urllib.parse.quote(flow_id, safe=""),
    )
    if (
        not isinstance(existing_flow, dict)
        or existing_flow.get("namespace") != flow_namespace
        or existing_flow.get("id") != flow_id
    ):
        raise CanaryError(
            "kestra_flow_not_ready",
            "Kestra did not return the exact deployed E2E flow identity",
        )

    paperclip = str(e2e["paperclipBaseUrl"]).rstrip("/")
    _, health = paperclip_request(paperclip, values, "GET", "/api/health")
    if not isinstance(health, dict):
        raise CanaryError("paperclip_not_ready", "Paperclip health is invalid")
    _, agents_value = paperclip_request(
        paperclip,
        values,
        "GET",
        f"/api/companies/{e2e['paperclipCompanyId']}/agents",
    )
    agent_rows = object_rows(agents_value, "agents", "items", "data")
    native_profiles = {
        str((row.get("metadata") or {}).get("profileRef"))
        for row in agent_rows
        if isinstance(row.get("metadata"), dict)
        and (row.get("metadata") or {}).get("profileRef")
    }
    missing_profiles = sorted(required_profiles - native_profiles)
    if missing_profiles:
        raise CanaryError(
            "profile_not_ready",
            "requested profiles have no native Paperclip agents: "
            + ", ".join(missing_profiles),
        )

    router = component_origin(config, "9router")
    _, router_health = request_json(router + "/api/health")
    if not isinstance(router_health, dict):
        raise CanaryError("router_not_ready", "9router health response is invalid")
    return {
        "daytonaEnvironmentId": details.get("environmentId"),
        "daytonaAgentId": details.get("agentId"),
        "daytonaPlugin": details.get("plugin"),
        "daytonaRuntime": daytona_runtime,
        "paperclipStatus": health.get("status", "ok"),
        "profiles": sorted(required_profiles),
        "profileModels": {
            ref: catalog[ref]["model"] for ref in sorted(required_profiles)
        },
        "profileAdapters": {
            ref: catalog[ref]["adapter"] for ref in sorted(required_profiles)
        },
        "explicitProviders": {
            ref: catalog[ref]["provider"]
            for ref, contract in e2e["profileContracts"].items()
            if contract["requireExplicitProvider"]
        },
        "kestraApi": "ready",
        "routerHealth": router_health.get("status", "ok"),
    }


def run_apply() -> dict[str, Any]:
    config, e2e, values = e2e_context()
    sources = source_evidence(config, e2e)
    preflight_result = preflight(config, e2e, values)
    kestra = str(e2e["kestraBaseUrl"]).rstrip("/")
    auth = basic_auth(values)
    deployed = deploy_flow(kestra, auth)
    flow_revision = deployed.get("revision")
    if (
        deployed.get("namespace") != "micro_task_engine.e2e"
        or deployed.get("id") != "paperclip-github-e2e"
        or not isinstance(flow_revision, int)
        or isinstance(flow_revision, bool)
        or flow_revision <= 0
    ):
        raise CanaryError(
            "flow_deploy_identity_invalid",
            "Kestra deployment did not return the exact namespace, id, and positive revision",
        )
    catalog = profile_catalog()
    payload: dict[str, Any] = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "KestraPaperclipGitHubE2E",
        "schemaVersion": E2E_EVIDENCE_SCHEMA,
        "status": "running",
        "startedAt": utcnow(),
        "canonicalSourceSha256": sources["canonicalSourceSha256"],
        "producerPath": str(Path(__file__)),
        "producerSha256": sources["runnerSha256"],
        "sources": sources,
        "preflight": preflight_result,
        "flow": {
            "namespace": deployed.get("namespace"),
            "id": deployed.get("id"),
            "revision": flow_revision,
        },
        "runs": [],
        "cleanup": {
            "requested": bool(e2e.get("cleanup", True)),
            "completed": False,
            "globalAbsence": None,
            "runs": [],
        },
        "toolhiveGatewayAudit": None,
        "semanticChecks": {
            "harness-scoped-router-auth": {
                "status": "running",
                "requiredProfiles": list(e2e["profiles"]),
                "runs": [],
            },
            "runner-toolhive-profile": {
                "status": "running",
                "requiredProfiles": list(e2e["profiles"]),
                "runs": [],
            },
            "server-attributed-router": {
                "status": "running",
                "requiredProfiles": list(e2e["profiles"]),
                "runs": [],
            },
        },
    }
    atomic_json(EVIDENCE, payload)
    try:
        for profile in e2e["profiles"]:
            router_before = router_usage_snapshot(
                config,
                values,
                str(profile),
                catalog[str(profile)]["model"],
            )
            created = trigger_flow(kestra, auth, e2e, str(profile))
            execution_id = str(created["id"])
            branch = f"agent/paperclip-e2e-{execution_id}"
            pull: dict[str, Any] | None = None
            paperclip_issue_id = ""
            run_error: BaseException | None = None
            cleanup_error: BaseException | None = None
            payload["current"] = {
                "profile": profile,
                "executionId": execution_id,
                "branch": branch,
            }
            scan_for_secrets(payload, values)
            atomic_json(EVIDENCE, payload)
            try:
                raw_execution = poll_execution(kestra, auth, execution_id)
                execution = execution_summary(raw_execution)
                outputs = execution.get("outputs", {})
                paperclip_issue_id = str(outputs.get("paperclip_issue_id", ""))
                if not paperclip_issue_id:
                    raise CanaryError(
                        "missing_issue_id",
                        "Kestra returned no native Paperclip issue id",
                    )

                paperclip_base = str(e2e["paperclipBaseUrl"]).rstrip("/")
                paperclip = native_issue_projection(
                    paperclip_base, values, paperclip_issue_id
                )
                artifacts = native_harness_artifacts(
                    paperclip_base, values, paperclip_issue_id
                )

                pull = find_pr(e2e, branch)
                if not pull:
                    raise CanaryError(
                        "github_pr_missing", "GitHub draft PR was not found"
                    )
                head = pull.get("head") if isinstance(pull.get("head"), dict) else {}
                sha = str(head.get("sha", ""))
                checks = check_runs(e2e, sha)
                pull_files = github_pull_files(e2e, int(pull["number"]))
                commit = github_commit(e2e, sha)
                document, claim, heartbeat = validate_evidence(
                    execution,
                    paperclip,
                    artifacts,
                    pull,
                    checks,
                    e2e,
                    branch,
                    str(profile),
                    str(e2e["profileContracts"][str(profile)]["nativeAdapter"]),
                    expected_model=catalog[str(profile)]["model"],
                    pull_files=pull_files,
                    commit=commit,
                )
                resources_before = paperclip_resource_state(
                    paperclip_base, values, paperclip_issue_id
                )
                workspace_identity = validated_workspace_identity(
                    paperclip,
                    resources_before,
                    str(preflight_result.get("daytonaEnvironmentId") or ""),
                )
                workspace_operation = daytona_workspace_operation(
                    values,
                    workspace_identity,
                    sha,
                    str(e2e["profileContracts"][str(profile)]["nativeAdapter"]),
                )
                github_proof = validated_github_evidence(
                    execution,
                    pull,
                    checks,
                    e2e,
                    branch,
                    pull_files=pull_files,
                    commit=commit,
                )
                kestra_proof = validated_kestra_execution(
                    execution,
                    flow_revision,
                    paperclip_issue_id,
                    sha,
                    str(pull.get("html_url") or ""),
                )
                router_after = router_usage_snapshot(
                    config,
                    values,
                    str(profile),
                    catalog[str(profile)]["model"],
                )
                router = router_usage_delta(router_before, router_after)
                semantic = harness_scoped_router_auth(
                    router,
                    profile=str(profile),
                    adapter=str(e2e["profileContracts"][str(profile)]["nativeAdapter"]),
                    model=catalog[str(profile)]["model"],
                    router_origin=component_origin(config, "9router"),
                )
                server_attribution = router_server_attribution(
                    values,
                    str(profile),
                    str(e2e["profileContracts"][str(profile)]["nativeAdapter"]),
                    catalog[str(profile)]["model"],
                    router,
                )
                toolhive_semantic = validated_toolhive_profile(
                    document,
                    values,
                    catalog[str(profile)],
                    profile=str(profile),
                    normalized_run_id=paperclip_issue_id,
                )

                native = (
                    paperclip.get("native")
                    if isinstance(paperclip.get("native"), dict)
                    else {}
                )
                environment = (
                    paperclip.get("environment")
                    if isinstance(paperclip.get("environment"), dict)
                    else {}
                )
                payload["runs"].append(
                    {
                        "profile": profile,
                        "router": {**router, "serverAttribution": server_attribution},
                        "execution": {**execution, "proof": kestra_proof},
                        "paperclip": {
                            "issueId": paperclip_issue_id,
                            "status": paperclip.get("status"),
                            "nativeIssueId": native.get("issueId"),
                            "issueIdentifier": native.get("issueIdentifier"),
                            "heartbeatRunId": native.get("heartbeatRunId"),
                            "heartbeatStatus": native.get("heartbeatStatus"),
                            "claim": claim,
                            "heartbeats": heartbeat["events"],
                            "heartbeatProof": {
                                key: heartbeat[key]
                                for key in (
                                    "status",
                                    "runId",
                                    "runnerId",
                                )
                            },
                            "finalResult": {
                                **heartbeat["finalResult"],
                                "nativeStatus": native.get("heartbeatStatus"),
                            },
                            "environment": environment,
                            "workspaceIdentity": workspace_identity,
                            "workspaceOperation": workspace_operation,
                            "artifacts": artifacts,
                        },
                        "semanticChecks": {
                            "harness-scoped-router-auth": semantic,
                            "runner-toolhive-profile": toolhive_semantic,
                            "server-attributed-router": server_attribution,
                        },
                        "github": {
                            "repository": f"{e2e['githubOwner']}/{e2e['githubRepository']}",
                            "branch": branch,
                            "commitSha": sha,
                            "pullRequest": {
                                "number": pull.get("number"),
                                "url": pull.get("html_url"),
                                "stateAtCapture": pull.get("state"),
                                "draftAtCapture": pull.get("draft"),
                                "base": (pull.get("base") or {}).get("ref"),
                                "head": head.get("ref"),
                            },
                            "checks": github_proof["checks"],
                            "proof": github_proof,
                        },
                    }
                )
                payload["semanticChecks"]["harness-scoped-router-auth"]["runs"].append(
                    semantic
                )
                payload["semanticChecks"]["runner-toolhive-profile"]["runs"].append(
                    toolhive_semantic
                )
                payload["semanticChecks"]["server-attributed-router"]["runs"].append(
                    server_attribution
                )
            except BaseException as exc:
                run_error = exc
            finally:
                paperclip_cleanup: dict[str, Any] = {
                    "requested": False,
                    "reason": "run_succeeded",
                }
                if run_error is not None:
                    try:
                        paperclip_cleanup = cleanup_nonterminal_paperclip_run(
                            kestra,
                            auth,
                            str(e2e["paperclipBaseUrl"]).rstrip("/"),
                            values,
                            execution_id,
                        )
                    except BaseException as exc:
                        cleanup_error = cleanup_error or exc
                        paperclip_cleanup = {"requested": True, "completed": False}
                if e2e.get("cleanup", True):
                    if not paperclip_issue_id:
                        try:
                            paperclip_issue_id = paperclip_issue_id_from_execution(
                                kestra, auth, execution_id
                            )
                        except BaseException as exc:
                            cleanup_error = cleanup_error or exc
                    try:
                        if not paperclip_issue_id:
                            raise CanaryError(
                                "resource_cleanup_unaddressable",
                                "submitted issue id is unavailable for resource cleanup",
                            )
                        resources_cleanup = cleanup_paperclip_daytona(
                            str(e2e["paperclipBaseUrl"]).rstrip("/"),
                            values,
                            paperclip_issue_id,
                        )
                    except BaseException as exc:
                        cleanup_error = cleanup_error or exc
                        resources_cleanup = {
                            "requested": True,
                            "completed": False,
                            "paperclipIssueId": paperclip_issue_id or None,
                        }
                    try:
                        cleanup = cleanup_github(
                            e2e, values["GITHUB_TOKEN"], branch, pull
                        )
                    except BaseException as exc:
                        cleanup_error = exc
                        cleanup = {
                            "requested": True,
                            "pullRequestClosed": False,
                            "branchDeleted": False,
                        }
                    payload["cleanup"]["runs"].append(
                        {
                            "profile": profile,
                            "executionId": execution_id,
                            "paperclip": paperclip_cleanup,
                            "resources": resources_cleanup,
                            **cleanup,
                            "completed": (
                                cleanup.get("pullRequestClosed") is True
                                and cleanup.get("branchDeleted") is True
                                and resources_cleanup.get("completed") is True
                            ),
                        }
                    )
                payload.pop("current", None)
                scan_for_secrets(payload, values)
                atomic_json(EVIDENCE, payload)
            if run_error is not None:
                raise run_error
            if cleanup_error is not None:
                raise cleanup_error

        if e2e.get("cleanup", True):
            payload["cleanup"]["globalAbsence"] = global_cleanup_absence(
                e2e,
                values,
                str(preflight_result.get("daytonaEnvironmentId") or ""),
            )
        payload["cleanup"]["completed"] = not e2e.get("cleanup", True) or (
            len(payload["cleanup"]["runs"]) == len(e2e["profiles"])
            and all(row.get("completed") is True for row in payload["cleanup"]["runs"])
            and (payload["cleanup"].get("globalAbsence") or {}).get("status")
            == "passed"
        )
        if len(payload["runs"]) != len(e2e["profiles"]):
            raise CanaryError(
                "run_count_mismatch", "not every requested profile completed"
            )
        payload["crossRunIdentity"] = validated_cross_run_identity(
            payload["runs"], list(e2e["profiles"]), flow_revision
        )
        if not payload["cleanup"]["completed"]:
            raise CanaryError(
                "cleanup_failed",
                "not every GitHub, Paperclip, and Daytona canary resource was cleaned up",
            )
        semantic_rows = payload["semanticChecks"]["harness-scoped-router-auth"]["runs"]
        if (
            len(semantic_rows) != len(e2e["profiles"])
            or [row.get("profileRef") for row in semantic_rows] != list(e2e["profiles"])
            or any(row.get("status") != "passed" for row in semantic_rows)
        ):
            raise CanaryError(
                "semantic_check_failed",
                "harness-scoped-router-auth did not pass for all native profiles",
            )
        payload["semanticChecks"]["harness-scoped-router-auth"]["status"] = "passed"
        toolhive_rows = payload["semanticChecks"]["runner-toolhive-profile"]["runs"]
        if (
            len(toolhive_rows) != len(e2e["profiles"])
            or [row.get("profileRef") for row in toolhive_rows] != list(e2e["profiles"])
            or any(row.get("status") != "passed" for row in toolhive_rows)
        ):
            raise CanaryError(
                "semantic_check_failed",
                "runner-toolhive-profile did not pass for all native profiles",
            )
        payload["semanticChecks"]["runner-toolhive-profile"]["status"] = "passed"
        payload["toolhiveGatewayAudit"] = toolhive_gateway_audit(values, toolhive_rows)
        attribution_rows = payload["semanticChecks"]["server-attributed-router"]["runs"]
        if (
            len(attribution_rows) != len(e2e["profiles"])
            or [row.get("profileRef") for row in attribution_rows]
            != list(e2e["profiles"])
            or any(row.get("status") != "passed" for row in attribution_rows)
            or any(
                set(left.get("requestIds", [])) & set(right.get("requestIds", []))
                for index, left in enumerate(attribution_rows)
                for right in attribution_rows[index + 1 :]
            )
            or any(
                not FULL_SHA256.fullmatch(
                    str(row.get("attributionFingerprintSha256") or "")
                )
                for row in attribution_rows
            )
            or len(
                {row.get("attributionFingerprintSha256") for row in attribution_rows}
            )
            != len(e2e["profiles"])
            or any(
                (row.get("requestBinding") or {}).get("status") != "passed"
                for row in attribution_rows
            )
        ):
            raise CanaryError(
                "semantic_check_failed",
                "server-attributed-router did not prove three distinct sequential native routes",
            )
        payload["semanticChecks"]["server-attributed-router"]["status"] = "passed"
        payload.update({"status": "passed", "finishedAt": utcnow()})
        scan_for_secrets(payload, values)
        atomic_json(EVIDENCE, payload)
    except BaseException as exc:
        payload.update(
            {
                "status": "failed",
                "finishedAt": utcnow(),
                "failure": {
                    "code": exc.code
                    if isinstance(exc, CanaryError)
                    else "unexpected_error",
                    "type": type(exc).__name__,
                },
            }
        )
        scan_for_secrets(payload, values)
        atomic_json(EVIDENCE, payload)
        raise
    return payload


def verify_existing() -> dict[str, Any]:
    config, e2e, values = e2e_context()
    require_private_evidence_file(EVIDENCE)
    evidence = load_json(EVIDENCE)
    require_fresh_timestamp(evidence.get("finishedAt"), "e2e.finishedAt")
    subject_sha = sha256_file(EVIDENCE)
    producer_sha = sha256_file(Path(__file__))
    canonical_sha = sha256_file(PLATFORM_ENV)
    write_verification_attestation(
        status="running",
        subject_sha=subject_sha,
        canonical_sha=canonical_sha,
        producer_sha=producer_sha,
        values=values,
    )
    if evidence.get("status") != "passed":
        raise CanaryError("evidence_not_passed", "stored E2E evidence is not passed")
    if (
        evidence.get("schemaVersion") != E2E_EVIDENCE_SCHEMA
        or evidence.get("apiVersion") != "micro-task-engine/v1alpha1"
        or evidence.get("kind") != "KestraPaperclipGitHubE2E"
        or evidence.get("canonicalSourceSha256") != canonical_sha
        or evidence.get("producerPath") != str(Path(__file__))
        or evidence.get("producerSha256") != producer_sha
    ):
        raise CanaryError(
            "evidence_attestation_invalid",
            "apply evidence schema is not bound to the current source and producer",
        )
    current_sources = source_evidence(config, e2e)
    recorded_sources = (
        evidence.get("sources") if isinstance(evidence.get("sources"), dict) else {}
    )
    for key in (
        "canonicalSourceSha256",
        "configSha256",
        "flowSha256",
        "profileSourceSha256",
        "profilesSha256",
        "paperclipRuntimeSha256",
        "daytonaEvidenceSha256",
        "daytonaVerifyEvidenceSha256",
        "daytonaImagesEvidenceSha256",
        "daytonaLifecycleEvidenceSha256",
        "runnerSha256",
    ):
        if recorded_sources.get(key) != current_sources.get(key):
            raise CanaryError("source_drift", f"canonical source hash changed: {key}")
    if recorded_sources.get("deploymentRelease") != current_sources.get(
        "deploymentRelease"
    ):
        raise CanaryError(
            "deployment_release_drift",
            "E2E evidence is not bound to the current release, activation, and manifest",
        )

    kestra = str(e2e["kestraBaseUrl"]).rstrip("/")
    paperclip_base = str(e2e["paperclipBaseUrl"]).rstrip("/")
    catalog = profile_catalog()
    current_daytona_runtime = validated_daytona_runtime_evidence(
        values, set(str(profile) for profile in e2e["profiles"])
    )
    if (evidence.get("preflight") or {}).get(
        "daytonaRuntime"
    ) != current_daytona_runtime:
        raise CanaryError(
            "daytona_runtime_evidence_drift",
            "stored Daytona runtime proof differs from the current verify envelope",
        )
    flow = evidence.get("flow") if isinstance(evidence.get("flow"), dict) else {}
    flow_revision = flow.get("revision")
    if (
        flow.get("namespace") != "micro_task_engine.e2e"
        or flow.get("id") != "paperclip-github-e2e"
        or not isinstance(flow_revision, int)
        or isinstance(flow_revision, bool)
        or flow_revision <= 0
    ):
        raise CanaryError(
            "flow_evidence_invalid", "stored Kestra flow identity is invalid"
        )
    stored_runs = evidence.get("runs")
    if not isinstance(stored_runs, list) or len(stored_runs) != len(e2e["profiles"]):
        raise CanaryError(
            "evidence_incomplete", "stored evidence lacks one run per profile"
        )
    if [row.get("profile") for row in stored_runs] != list(e2e["profiles"]):
        raise CanaryError(
            "profile_order_drift",
            "stored run profile order differs from canonical config",
        )
    aggregate = (
        (evidence.get("semanticChecks") or {}).get("harness-scoped-router-auth")
        if isinstance(evidence.get("semanticChecks"), dict)
        else None
    )
    if (
        not isinstance(aggregate, dict)
        or aggregate.get("status") != "passed"
        or aggregate.get("requiredProfiles") != list(e2e["profiles"])
        or not isinstance(aggregate.get("runs"), list)
        or len(aggregate["runs"]) != len(e2e["profiles"])
    ):
        raise CanaryError(
            "semantic_evidence_invalid",
            "stored harness-scoped-router-auth aggregate is incomplete",
        )
    toolhive_aggregate = (
        (evidence.get("semanticChecks") or {}).get("runner-toolhive-profile")
        if isinstance(evidence.get("semanticChecks"), dict)
        else None
    )
    if (
        not isinstance(toolhive_aggregate, dict)
        or toolhive_aggregate.get("status") != "passed"
        or toolhive_aggregate.get("requiredProfiles") != list(e2e["profiles"])
        or not isinstance(toolhive_aggregate.get("runs"), list)
        or len(toolhive_aggregate["runs"]) != len(e2e["profiles"])
    ):
        raise CanaryError(
            "semantic_evidence_invalid",
            "stored runner-toolhive-profile aggregate is incomplete",
        )
    attribution_aggregate = (
        (evidence.get("semanticChecks") or {}).get("server-attributed-router")
        if isinstance(evidence.get("semanticChecks"), dict)
        else None
    )
    if (
        not isinstance(attribution_aggregate, dict)
        or attribution_aggregate.get("status") != "passed"
        or attribution_aggregate.get("requiredProfiles") != list(e2e["profiles"])
        or not isinstance(attribution_aggregate.get("runs"), list)
        or len(attribution_aggregate["runs"]) != len(e2e["profiles"])
    ):
        raise CanaryError(
            "semantic_evidence_invalid",
            "stored server-attributed-router aggregate is incomplete",
        )
    cleanup_root = (
        evidence.get("cleanup") if isinstance(evidence.get("cleanup"), dict) else {}
    )
    cleanup_rows = (
        cleanup_root.get("runs") if isinstance(cleanup_root.get("runs"), list) else []
    )
    recorded_global_absence = (
        cleanup_root.get("globalAbsence")
        if isinstance(cleanup_root.get("globalAbsence"), dict)
        else {}
    )
    current_global_absence = global_cleanup_absence(
        e2e,
        values,
        str((evidence.get("preflight") or {}).get("daytonaEnvironmentId") or ""),
    )
    if recorded_global_absence != current_global_absence:
        raise CanaryError(
            "cleanup_evidence_drift",
            "stored global Daytona/GitHub absence proof differs from live lookup",
        )

    verified_runs = []
    verified_toolhive_rows: list[dict[str, Any]] = []
    for stored in stored_runs:
        profile = str(stored.get("profile", ""))
        execution_id = str((stored.get("execution") or {}).get("id", ""))
        issue_id = str((stored.get("paperclip") or {}).get("issueId", ""))
        github = stored.get("github") if isinstance(stored.get("github"), dict) else {}
        sha = str(github.get("commitSha", ""))
        branch = str(github.get("branch", ""))
        if not all((execution_id, issue_id, sha, branch)):
            raise CanaryError(
                "evidence_incomplete", "stored evidence lacks verification ids"
            )

        raw_execution = kestra_request(
            kestra,
            basic_auth(values),
            "GET",
            "/api/v1/main/executions/" + urllib.parse.quote(execution_id),
        )
        execution = execution_summary(raw_execution)
        paperclip = native_issue_projection(paperclip_base, values, issue_id)
        artifacts = native_harness_artifacts(paperclip_base, values, issue_id)
        pull = find_pr(e2e, branch)
        if not pull:
            raise CanaryError(
                "github_pr_missing", "closed GitHub canary PR is no longer discoverable"
            )
        checks = check_runs(e2e, sha)
        pull_files = github_pull_files(e2e, int(pull["number"]))
        commit = github_commit(e2e, sha)
        document, claim, heartbeat = validate_evidence(
            execution,
            paperclip,
            artifacts,
            pull,
            checks,
            e2e,
            branch,
            profile,
            str(e2e["profileContracts"][profile]["nativeAdapter"]),
            expected_model=catalog[profile]["model"],
            pull_files=pull_files,
            commit=commit,
            expected_pull_state="closed",
        )
        github_live_proof = validated_github_evidence(
            execution,
            pull,
            checks,
            e2e,
            branch,
            pull_files=pull_files,
            commit=commit,
            expected_pull_state="closed",
        )
        kestra_proof = validated_kestra_execution(
            execution,
            flow_revision,
            issue_id,
            sha,
            str(pull.get("html_url") or ""),
        )
        stored_execution_proof = (stored.get("execution") or {}).get("proof")
        if stored_execution_proof != kestra_proof:
            raise CanaryError(
                "kestra_evidence_drift",
                "live Kestra revision, tasks, or outputs differ from stored proof",
            )
        stored_github_proof = github.get("proof")
        if not isinstance(stored_github_proof, dict):
            raise CanaryError(
                "github_evidence_invalid", "stored GitHub proof is missing"
            )
        comparable_live = {
            key: value for key, value in github_live_proof.items() if key != "state"
        }
        comparable_stored = {
            key: value for key, value in stored_github_proof.items() if key != "state"
        }
        if (
            stored_github_proof.get("state") != "open"
            or comparable_stored != comparable_live
            or github.get("checks") != github_live_proof.get("checks")
        ):
            raise CanaryError(
                "github_evidence_drift",
                "live PR/check identity differs from the captured open-draft proof",
            )
        stored_claim = (stored.get("paperclip") or {}).get("claim")
        if stored_claim != claim:
            raise CanaryError(
                "claim_evidence_drift",
                "live Paperclip claim differs from stored unique-claim evidence",
            )
        stored_paperclip = stored.get("paperclip") or {}
        stored_heartbeat = {
            "status": (stored_paperclip.get("heartbeatProof") or {}).get("status"),
            "runId": (stored_paperclip.get("heartbeatProof") or {}).get("runId"),
            "runnerId": (stored_paperclip.get("heartbeatProof") or {}).get("runnerId"),
            "events": stored_paperclip.get("heartbeats"),
            "finalResult": {
                key: (stored_paperclip.get("finalResult") or {}).get(key)
                for key in (
                    "source",
                    "runId",
                    "runnerId",
                    "status",
                    "recordedAt",
                    "recordFingerprintSha256",
                )
            },
        }
        if stored_heartbeat != heartbeat:
            raise CanaryError(
                "heartbeat_evidence_drift",
                "live Paperclip heartbeat lifecycle differs from stored monotonic evidence",
            )
        workspace_identity = validated_recorded_workspace_identity(
            paperclip,
            stored_paperclip.get("workspaceIdentity"),
            str((evidence.get("preflight") or {}).get("daytonaEnvironmentId") or ""),
        )
        workspace_operation = validated_stored_workspace_operation(
            stored_paperclip.get("workspaceOperation"),
            workspace_identity,
            sha,
            str(e2e["profileContracts"][profile]["nativeAdapter"]),
            values.get(
                NATIVE_VERSION_REFS[
                    str(e2e["profileContracts"][profile]["nativeAdapter"])
                ],
                "",
            ),
        )
        router = stored.get("router") if isinstance(stored.get("router"), dict) else {}
        if (
            router.get("profileKeyRequestsDelta", 0) <= 0
            or router.get("modelRequestsDelta", 0) <= 0
            or router.get("totalRequestsDelta", 0) <= 0
        ):
            raise CanaryError(
                "router_evidence_invalid", "stored 9router usage delta is not positive"
            )
        current_router = router_usage_snapshot(
            config,
            values,
            profile,
            catalog[profile]["model"],
        )
        if (
            current_router["profileKeyRequests"]
            < router.get("profileKeyRequestsAfter", 0)
            or current_router["modelRequests"] < router.get("modelRequestsAfter", 0)
            or current_router["totalRequests"] < router.get("totalRequestsAfter", 0)
        ):
            raise CanaryError(
                "router_usage_regressed",
                "live 9router counters regressed below evidence",
            )
        semantic = harness_scoped_router_auth(
            router,
            profile=profile,
            adapter=str(e2e["profileContracts"][profile]["nativeAdapter"]),
            model=catalog[profile]["model"],
            router_origin=component_origin(config, "9router"),
        )
        toolhive_semantic = validated_toolhive_profile(
            document,
            values,
            catalog[profile],
            profile=profile,
            normalized_run_id=issue_id,
        )
        verified_toolhive_rows.append(toolhive_semantic)
        server_attribution = router_server_attribution(
            values,
            profile,
            str(e2e["profileContracts"][profile]["nativeAdapter"]),
            catalog[profile]["model"],
            router,
        )
        stored_semantic = (
            (stored.get("semanticChecks") or {}).get("harness-scoped-router-auth")
            if isinstance(stored.get("semanticChecks"), dict)
            else None
        )
        if stored_semantic != semantic:
            raise CanaryError(
                "semantic_evidence_drift",
                "stored harness-scoped-router-auth evidence differs from live validation",
            )
        stored_toolhive_semantic = (
            (stored.get("semanticChecks") or {}).get("runner-toolhive-profile")
            if isinstance(stored.get("semanticChecks"), dict)
            else None
        )
        if stored_toolhive_semantic != toolhive_semantic:
            raise CanaryError(
                "semantic_evidence_drift",
                "stored runner-toolhive-profile evidence differs from live validation",
            )
        stored_attribution = (
            (stored.get("semanticChecks") or {}).get("server-attributed-router")
            if isinstance(stored.get("semanticChecks"), dict)
            else None
        )
        if (
            stored_attribution != server_attribution
            or (
                (stored.get("router") or {}).get("serverAttribution")
                if isinstance(stored.get("router"), dict)
                else None
            )
            != server_attribution
        ):
            raise CanaryError(
                "semantic_evidence_drift",
                "stored server-side 9router attribution differs from live history",
            )
        cleanup_row = next(
            (
                row
                for row in cleanup_rows
                if isinstance(row, dict)
                and row.get("profile") == profile
                and row.get("executionId") == execution_id
            ),
            None,
        )
        if not cleanup_row or cleanup_row.get("completed") is not True:
            raise CanaryError(
                "cleanup_evidence_invalid", "stored run cleanup is incomplete"
            )
        if (
            cleanup_row.get("pullRequestNumber") != pull.get("number")
            or cleanup_row.get("pullRequestGetStatus") != 200
            or cleanup_row.get("pullRequestState") != "closed"
            or cleanup_row.get("pullRequestClosed") is not True
            or cleanup_row.get("branchRef") != f"refs/heads/{branch}"
            or cleanup_row.get("branchGetStatus") != 404
            or cleanup_row.get("branchDeleted") is not True
        ):
            raise CanaryError(
                "cleanup_evidence_invalid",
                "stored PR close and branch delete evidence is not exact",
            )
        resources_recorded = (
            cleanup_row.get("resources")
            if isinstance(cleanup_row.get("resources"), dict)
            else {}
        )
        resources_verified = verify_resource_absence(
            paperclip_base,
            values,
            issue_id,
            resources_recorded,
        )
        if (
            resources_recorded.get("sandboxId") != workspace_identity.get("sandboxId")
            or resources_recorded.get("executionWorkspaceId")
            != workspace_identity.get("executionWorkspaceId")
            or resources_recorded.get("remoteCwd")
            != workspace_identity.get("remoteCwd")
        ):
            raise CanaryError(
                "resource_cleanup_identity_drift",
                "cleanup proof is not bound to the workspace operation identity",
            )
        if e2e.get("cleanup", True):
            if pull.get("state") != "closed":
                raise CanaryError("cleanup_drift", "canary PR is not closed")
            owner = str(e2e["githubOwner"])
            repo = str(e2e["githubRepository"])
            status, _ = request_json(
                f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{branch}",
                headers={"User-Agent": "micro-task-engine-paperclip-e2e"},
                allow_status={404},
            )
            if status != 404:
                raise CanaryError("cleanup_drift", "canary branch still exists")
        verified_runs.append(
            {
                "profile": stored.get("profile"),
                "executionId": execution_id,
                "paperclipIssueId": issue_id,
                "pullRequestUrl": pull.get("html_url"),
                "commitSha": sha,
                "checkConclusions": [row.get("conclusion") for row in checks],
                "claimLeaseId": claim.get("leaseId"),
                "semanticCheck": semantic.get("check"),
                "toolhiveSemanticCheck": toolhive_semantic.get("check"),
                "routerServerRequestIds": server_attribution.get("requestIds"),
                "routerRequestBinding": server_attribution.get("requestBinding"),
                "kestraProof": kestra_proof,
                "githubProof": github_live_proof,
                "workspaceIdentity": workspace_identity,
                "workspaceOperation": workspace_operation,
                "resourceCleanup": resources_verified,
            }
        )
    verified_toolhive_audit = verify_stored_toolhive_gateway_audit(
        evidence.get("toolhiveGatewayAudit"), values, verified_toolhive_rows
    )
    cross_run_identity = validated_cross_run_identity(
        stored_runs, list(e2e["profiles"]), flow_revision
    )
    if evidence.get("crossRunIdentity") != cross_run_identity:
        raise CanaryError(
            "cross_run_identity_drift",
            "stored cross-run identity differs from the current strict validation",
        )
    return write_verification_attestation(
        status="passed",
        subject_sha=subject_sha,
        canonical_sha=canonical_sha,
        producer_sha=producer_sha,
        values=values,
        sources=current_sources,
        runs=verified_runs,
        cleanup_verified=bool(e2e.get("cleanup", True)),
        toolhive_gateway_audit=verified_toolhive_audit,
        apply_finished_at=str(evidence.get("finishedAt") or ""),
        cross_run_identity=cross_run_identity,
    )


def status_existing() -> dict[str, Any]:
    if not EVIDENCE.is_file():
        return {"status": "not_run", "evidence": str(EVIDENCE)}
    value = load_json(EVIDENCE)
    runs = value.get("runs") if isinstance(value.get("runs"), list) else []
    return {
        "status": value.get("status"),
        "evidence": str(EVIDENCE),
        "runs": [
            {
                "profile": row.get("profile"),
                "executionId": (row.get("execution") or {}).get("id"),
                "pullRequestUrl": (
                    (row.get("github") or {}).get("pullRequest") or {}
                ).get("url"),
                "commitSha": (row.get("github") or {}).get("commitSha"),
            }
            for row in runs
            if isinstance(row, dict)
        ],
        "cleanup": value.get("cleanup"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("apply", "status", "verify"))
    args = parser.parse_args()
    try:
        if args.action == "apply":
            result = run_apply()
        elif args.action == "verify":
            result = verify_existing()
        else:
            result = status_existing()
    except CanaryError as exc:
        print(
            json.dumps(
                {"status": "failed", "reason": exc.code, "evidence": str(EVIDENCE)}
            )
        )
        raise SystemExit(1) from exc
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

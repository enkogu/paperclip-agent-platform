#!/usr/bin/env python3
"""Live acceptance for the native Hermes runtime.

The canary talks only to upstream Hermes surfaces. It submits a real API turn,
lets Hermes use its native terminal tool for one read-only platform command,
and records redacted messaging and 9Router evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import http.cookiejar
import ipaddress
import json
from pathlib import Path
import re
import sys
import time
from typing import Any
import urllib.error
import urllib.request
import uuid


ENV_FILE = Path("/root/.config/mte-secrets/platform.env")
EVIDENCE = Path("/opt/mte-platform/evidence/hermes-live.json")
PRODUCER = Path(__file__).resolve()
HERMES_CLI = Path("/opt/mte-hermes/current/venv/bin/hermes")
TERMINAL = {"completed", "failed", "cancelled"}
RUN_ID_RE = re.compile(r"run_[0-9a-f]{32}")
READ_ONLY_COMMAND = "python3 /opt/mte-platform/bin/server-verify.py status"


class CanaryError(RuntimeError):
    pass


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def file_sha256(path: Path) -> str:
    if not path.is_file():
        raise CanaryError(f"required acceptance producer is missing: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def producer_metadata() -> dict[str, str]:
    return {
        "producerPath": str(PRODUCER),
        "producerSha256": file_sha256(PRODUCER),
        "nativeHermesCliPath": str(HERMES_CLI),
        "nativeHermesCliSha256": file_sha256(HERMES_CLI),
    }


def env_values() -> dict[str, str]:
    if not ENV_FILE.is_file():
        raise CanaryError("canonical Hermes configuration is missing")
    raw = ENV_FILE.read_bytes()
    values: dict[str, str] = {}
    for number, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            raise CanaryError(f"invalid canonical configuration at line {number}")
        name, value = stripped.split("=", 1)
        values[name.strip()] = value.strip()
    return values


def required(values: dict[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise CanaryError(f"required configuration reference is empty: {name}")
    return value


def request_json(
    url: str,
    *,
    method: str = "GET",
    bearer: str | None = None,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    opener: urllib.request.OpenerDirector | None = None,
    timeout: int = 30,
) -> Any:
    request_headers = {
        "Accept": "application/json",
        "User-Agent": "paperclip-platform-hermes-acceptance/1",
        **(headers or {}),
    }
    if bearer:
        request_headers["Authorization"] = f"Bearer {bearer}"
    data = None
    if body is not None:
        request_headers["Content-Type"] = "application/json"
        data = json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(
        url, method=method, data=data, headers=request_headers
    )
    try:
        response = (
            opener.open(request, timeout=timeout)
            if opener is not None
            else urllib.request.urlopen(request, timeout=timeout)
        )
        with response:
            payload = response.read(5_000_001)
            if len(payload) > 5_000_000:
                raise CanaryError("remote API response exceeded the size limit")
            if not payload:
                return {}
            return json.loads(payload)
    except urllib.error.HTTPError as error:
        error.read(1_000_001)
        raise CanaryError(
            f"remote API rejected the request with {error.code}"
        ) from error
    except json.JSONDecodeError as error:
        raise CanaryError("remote API returned invalid JSON") from error


def api_server(values: dict[str, str]) -> tuple[str, str]:
    host = required(values, "HERMES_API_SERVER_HOST")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise CanaryError("Hermes native API server host is invalid") from error
    if not (address.is_loopback or address.is_private) or any(
        (address.is_unspecified, address.is_link_local, address.is_multicast)
    ):
        raise CanaryError("Hermes native API server is not privately bound")
    port = int(required(values, "HERMES_API_SERVER_PORT"))
    rendered_host = f"[{host}]" if address.version == 6 else host
    return f"http://{rendered_host}:{port}", required(values, "HERMES_API_SERVER_KEY")


def stop_run(base: str, token: str, run_id: str) -> None:
    try:
        request_json(
            f"{base}/v1/runs/{run_id}/stop",
            method="POST",
            bearer=token,
            body={},
        )
    except CanaryError:
        pass


def run_native_terminal_check(
    values: dict[str, str], marker: str, *, timeout_seconds: int = 600
) -> dict[str, Any]:
    base, token = api_server(values)
    command = READ_ONLY_COMMAND
    started = request_json(
        base + "/v1/runs",
        method="POST",
        bearer=token,
        headers={"X-Hermes-Session-Key": f"acceptance:{marker}"},
        body={
            "input": (
                "Use your native terminal tool exactly once to execute this read-only "
                f"command: `{command}`. Do not add another command, redirect, pipe, "
                "or shell operator. Report whether it succeeded."
            ),
            "instructions": (
                "This is a deterministic native Hermes acceptance check. Execute only "
                "the supplied read-only command with the built-in terminal tool."
            ),
            "session_id": f"hermes-native-acceptance-{marker}",
        },
    )
    run_id = str(started.get("run_id", ""))
    if not RUN_ID_RE.fullmatch(run_id):
        raise CanaryError("Hermes native API returned an invalid run id")

    event_types: list[str] = []
    approvals = 0
    stream_request = urllib.request.Request(
        f"{base}/v1/runs/{run_id}/events",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "text/event-stream",
            "User-Agent": "paperclip-platform-hermes-acceptance/1",
        },
    )
    deadline = time.monotonic() + timeout_seconds
    try:
        with urllib.request.urlopen(
            stream_request, timeout=timeout_seconds
        ) as response:
            for raw_line in response:
                if time.monotonic() >= deadline:
                    raise CanaryError("Hermes native turn exceeded its timeout")
                line = raw_line.decode(errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                try:
                    event = json.loads(line[5:].strip())
                except json.JSONDecodeError as error:
                    raise CanaryError(
                        "Hermes event stream returned invalid JSON"
                    ) from error
                event_type = str(event.get("event", ""))
                if event_type:
                    event_types.append(event_type)
                if event_type == "approval.request":
                    requested_command = str(event.get("command", "")).strip()
                    if requested_command != command or approvals:
                        request_json(
                            f"{base}/v1/runs/{run_id}/approval",
                            method="POST",
                            bearer=token,
                            body={"choice": "deny", "all": False},
                        )
                        raise CanaryError(
                            "Hermes requested a command outside the native canary boundary"
                        )
                    request_json(
                        f"{base}/v1/runs/{run_id}/approval",
                        method="POST",
                        bearer=token,
                        body={"choice": "once", "all": False},
                    )
                    approvals += 1
                if event_type in {"run.completed", "run.failed", "run.cancelled"}:
                    break
    except BaseException:
        stop_run(base, token, run_id)
        raise

    status = request_json(f"{base}/v1/runs/{run_id}", bearer=token)
    if status.get("status") not in TERMINAL:
        settle_deadline = time.monotonic() + 20
        while time.monotonic() < settle_deadline:
            status = request_json(f"{base}/v1/runs/{run_id}", bearer=token)
            if status.get("status") in TERMINAL:
                break
            time.sleep(1)
    if status.get("status") != "completed":
        raise CanaryError("Hermes native terminal turn did not complete")
    usage = status.get("usage") if isinstance(status.get("usage"), dict) else {}
    return {
        "runId": run_id,
        "status": "completed",
        "command": command,
        "nativeTerminal": True,
        "eventTypes": sorted(set(event_types)),
        "approvalCount": approvals,
        "usage": {
            "inputTokens": int(usage.get("input_tokens", 0) or 0),
            "outputTokens": int(usage.get("output_tokens", 0) or 0),
            "totalTokens": int(usage.get("total_tokens", 0) or 0),
        },
    }


def usage_count(value: Any) -> int:
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


def router_usage(values: dict[str, str]) -> dict[str, int]:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    base = required(values, "HERMES_LLM_BASE_URL").rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    request_json(
        base + "/api/auth/login",
        method="POST",
        opener=opener,
        body={"password": required(values, "NINEROUTER_INITIAL_PASSWORD")},
    )
    usage = request_json(base + "/api/usage/history", opener=opener)
    if not isinstance(usage, dict):
        raise CanaryError("9Router usage response is invalid")
    key = required(values, "HERMES_LLM_API_KEY")
    model = required(values, "HERMES_LLM_MODEL")
    model_id = model.split("/", 1)[-1]
    provider_node_id = required(values, "NINEROUTER_MINIMAX_PROVIDER_NODE_ID")
    by_key = usage.get("byApiKey") if isinstance(usage.get("byApiKey"), dict) else {}
    by_model = usage.get("byModel") if isinstance(usage.get("byModel"), dict) else {}
    key_counts = [
        usage_count(value) for name, value in by_key.items() if key in str(name)
    ]
    exact_model_names = {model, model_id, f"{model_id} ({provider_node_id})"}
    model_counts = [
        usage_count(value)
        for name, value in by_model.items()
        if str(name) in exact_model_names
    ]
    if len(key_counts) != 1 or len(model_counts) != 1:
        raise CanaryError("9Router could not isolate the Hermes key and model route")
    return {
        "hermesKeyRequests": key_counts[0],
        "modelRequests": model_counts[0],
        "totalRequests": usage_count(usage.get("totalRequests")),
    }


def usage_delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    delta = {
        "hermesKeyRequests": after["hermesKeyRequests"] - before["hermesKeyRequests"],
        "modelRequests": after["modelRequests"] - before["modelRequests"],
        "totalRequests": after["totalRequests"] - before["totalRequests"],
    }
    if any(value <= 0 for value in delta.values()):
        raise CanaryError("9Router did not record the real Hermes turn")
    return delta


def wait_router_delta(
    values: dict[str, str], before: dict[str, int], *, timeout_seconds: int = 45
) -> dict[str, int]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            return usage_delta(before, router_usage(values))
        except CanaryError:
            time.sleep(2)
    raise CanaryError("9Router usage counters did not settle after the Hermes turn")


def telegram_connection(values: dict[str, str]) -> dict[str, Any]:
    token = values.get("HERMES_TELEGRAM_BOT_TOKEN", "").strip()
    allowed = values.get("HERMES_TELEGRAM_ALLOWED_USERS", "").strip()
    if not token and not allowed:
        return {"ok": None, "state": "conditional_disabled", "notFabricated": True}
    if not token or not allowed or "*" in {item.strip() for item in allowed.split(",")}:
        raise CanaryError("Telegram native integration is not fail-closed")
    value = request_json(f"https://api.telegram.org/bot{token}/getMe")
    if not (
        isinstance(value, dict)
        and value.get("ok") is True
        and isinstance(value.get("result"), dict)
        and value["result"].get("is_bot") is True
    ):
        raise CanaryError("Telegram rejected the native Hermes bot")
    return {"ok": True, "state": "ready", "nativeHermesIntegration": True}


def mattermost_connection(values: dict[str, str]) -> dict[str, Any]:
    base = values.get("MATTERMOST_URL", "").strip().rstrip("/")
    token = values.get("MATTERMOST_TOKEN", "").strip()
    allowed = values.get("MATTERMOST_ALLOWED_USERS", "").strip()
    home_channel = values.get("MATTERMOST_HOME_CHANNEL", "").strip()
    if not base and not token and not allowed and not home_channel:
        return {"ok": None, "state": "conditional_disabled", "notFabricated": True}
    if (
        not base
        or not token
        or not allowed
        or not re.fullmatch(r"[a-z0-9]{26}", home_channel)
        or "*" in {item.strip() for item in allowed.split(",")}
    ):
        raise CanaryError("Mattermost native integration is not fail-closed")
    value = request_json(base + "/api/v4/users/me", bearer=token)
    if not (
        isinstance(value, dict) and value.get("id") and value.get("is_bot") is True
    ):
        raise CanaryError("Mattermost rejected the native Hermes bot")
    channel = request_json(
        base + f"/api/v4/channels/{home_channel}", bearer=token
    )
    if not isinstance(channel, dict) or channel.get("id") != home_channel:
        raise CanaryError("Mattermost rejected the Hermes operator channel")
    return {
        "ok": True,
        "state": "ready",
        "nativeHermesIntegration": True,
        "operatorChannelAccessible": True,
    }


def atomic_evidence(value: dict[str, Any]) -> None:
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = EVIDENCE.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(EVIDENCE)
    EVIDENCE.chmod(0o600)


def apply() -> dict[str, Any]:
    values = env_values()
    marker = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid.uuid4().hex[:8]
    )
    evidence: dict[str, Any] = {
        "apiVersion": "paperclip-agent-platform/v1alpha1",
        "kind": "HermesNativeAcceptance",
        "status": "running",
        "startedAt": utcnow(),
        "canonicalSha256": hashlib.sha256(ENV_FILE.read_bytes()).hexdigest(),
        **producer_metadata(),
        "connections": {},
    }
    atomic_evidence(evidence)

    before = router_usage(values)
    run = run_native_terminal_check(values, marker)
    evidence["connections"]["nativeTerminal"] = {
        "ok": True,
        "nativeHermes": True,
        "run": run,
    }
    evidence["connections"]["9router"] = {
        "ok": True,
        "runId": run["runId"],
        "usageDelta": wait_router_delta(values, before),
    }
    evidence["connections"]["mattermost"] = mattermost_connection(values)
    evidence["connections"]["telegram"] = telegram_connection(values)
    evidence["status"] = "passed"
    evidence["finishedAt"] = utcnow()
    evidence["summary"] = {
        "total": len(evidence["connections"]),
        "passed": sum(
            row.get("ok") is True for row in evidence["connections"].values()
        ),
        "failed": sum(
            row.get("ok") is False for row in evidence["connections"].values()
        ),
        "conditionalDisabled": sum(
            row.get("state") == "conditional_disabled"
            for row in evidence["connections"].values()
        ),
    }
    atomic_evidence(evidence)
    return evidence


def main() -> None:
    try:
        value = apply()
    except Exception as error:
        failure: dict[str, Any] = {}
        if EVIDENCE.is_file():
            try:
                previous = json.loads(EVIDENCE.read_text())
            except (OSError, json.JSONDecodeError):
                previous = {}
            if (
                isinstance(previous, dict)
                and previous.get("kind") == "HermesNativeAcceptance"
            ):
                failure = previous
        failure.update(
            {
                "apiVersion": "paperclip-agent-platform/v1alpha1",
                "kind": "HermesNativeAcceptance",
                "status": "failed",
                "finishedAt": utcnow(),
                "errorType": type(error).__name__,
            }
        )
        atomic_evidence(failure)
        print(json.dumps({"ok": False, "error": type(error).__name__}), file=sys.stderr)
        raise SystemExit(1) from error
    print(
        json.dumps(
            {
                "ok": True,
                "status": value["status"],
                "summary": value["summary"],
                "evidence": str(EVIDENCE),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

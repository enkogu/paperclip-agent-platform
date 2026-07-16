#!/usr/bin/env python3
"""Deterministic Paperclip process worker for live integration canaries.

The worker receives data-plane and Mattermost credentials only through Paperclip
project ``secret_ref`` resolution. It never reads canonical state and never
prints credential values. Its sanitized result is written back to the source
Paperclip task, so the controller can prove the side effect came from a real
Paperclip heartbeat run.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"missing required runtime ref {name}")
    return value


PAPERCLIP_API = required_env("PAPERCLIP_API_URL").rstrip("/")
PAPERCLIP_TOKEN = os.environ.get("PAPERCLIP_API_KEY", "")
COMPANY_ID = os.environ.get("PAPERCLIP_COMPANY_ID", "")
AGENT_ID = os.environ.get("PAPERCLIP_AGENT_ID", "")
TASK_ID = os.environ.get("PAPERCLIP_TASK_ID", "")
HEARTBEAT_RUN_ID = os.environ.get("PAPERCLIP_RUN_ID", "")


class WorkerError(RuntimeError):
    pass


def request_json(
    method: str,
    url: str,
    *,
    body: Any | None = None,
    headers: dict[str, str] | None = None,
    allow_status: set[int] | None = None,
) -> tuple[int, Any]:
    request_headers = {"Accept": "application/json", **(headers or {})}
    data = json.dumps(body).encode() if body is not None else None
    if body is not None:
        request_headers.setdefault("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(
            urllib.request.Request(
                url, data=data, headers=request_headers, method=method
            ),
            timeout=30,
        ) as response:
            raw = response.read(2_000_000)
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        if allow_status and exc.code in allow_status:
            return exc.code, None
        raise WorkerError(f"remote_http_{exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise WorkerError("remote_unavailable") from exc


def paperclip(method: str, path: str, body: Any | None = None) -> Any:
    headers = {}
    if PAPERCLIP_TOKEN:
        headers["Authorization"] = f"Bearer {PAPERCLIP_TOKEN}"
    _status, value = request_json(
        method, PAPERCLIP_API + path, body=body, headers=headers
    )
    return value


def rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    if isinstance(value, dict):
        for key in ("data", "items", "list", "results"):
            if isinstance(value.get(key), list):
                return [row for row in value[key] if isinstance(row, dict)]
    return []


def resolve_context() -> tuple[dict[str, Any], str]:
    task_id = TASK_ID
    if not task_id:
        if not COMPANY_ID or not AGENT_ID:
            raise WorkerError("paperclip_context_missing")
        query = urllib.parse.urlencode(
            {
                "assigneeAgentId": AGENT_ID,
                "status": "todo,in_progress,blocked",
            }
        )
        assigned = rows(paperclip("GET", f"/api/companies/{COMPANY_ID}/issues?{query}"))
        candidates = [
            row
            for row in assigned
            if str(row.get("title") or "").startswith("[MTE integration canary ")
        ]
        if not candidates:
            raise WorkerError("paperclip_canary_task_missing")
        task_id = str(
            max(
                candidates,
                key=lambda row: str(row.get("createdAt") or row.get("updatedAt") or ""),
            )["id"]
        )
    task = paperclip("GET", f"/api/issues/{task_id}")
    if not isinstance(task, dict):
        raise WorkerError("paperclip_task_missing")
    run_id = HEARTBEAT_RUN_ID
    if not run_id:
        for _attempt in range(20):
            runs = rows(paperclip("GET", f"/api/issues/{task_id}/runs"))
            if runs:
                run_id = str(
                    max(runs, key=lambda row: str(row.get("createdAt") or "")).get("id")
                    or ""
                )
                if run_id:
                    break
            time.sleep(0.25)
    if not run_id:
        raise WorkerError("paperclip_heartbeat_run_missing")
    return task, run_id


def task_input(task: dict[str, Any]) -> dict[str, Any]:
    try:
        value = json.loads(str(task.get("description") or ""))
    except json.JSONDecodeError as exc:
        raise WorkerError("canary_task_input_invalid") from exc
    if not isinstance(value, dict) or value.get("kind") != "MTEIntegrationCanaryInput":
        raise WorkerError("canary_task_input_invalid")
    return value


def record_id(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("Id", "id"):
            if value.get(key) is not None:
                return str(value[key])
        for nested in value.values():
            found = record_id(nested)
            if found:
                return found
    if isinstance(value, list):
        for nested in value:
            found = record_id(nested)
            if found:
                return found
    return ""


def baserow_canary(value: dict[str, Any], task_id: str, run_id: str) -> dict[str, Any]:
    token = os.environ.get("BASEROW_API_TOKEN", "")
    if not token:
        raise WorkerError("paperclip_baserow_secret_not_resolved")
    api_base = str(value.get("baserowApiBase") or "").rstrip("/")
    table_id = str(value.get("baserowTableId") or "")
    if not api_base or not table_id:
        raise WorkerError("baserow_target_missing")
    headers = {"Authorization": f"Token {token}"}
    marker = f"MTE-C027-{task_id}-{run_id}"
    created_id = ""
    try:
        create_status, created = request_json(
            "POST",
            f"{api_base}/api/database/rows/table/{table_id}/?user_field_names=true",
            headers=headers,
            body={"Value": marker},
        )
        created_id = record_id(created)
        if not created_id:
            raise WorkerError("baserow_row_id_missing")
        read_status, observed = request_json(
            "GET",
            f"{api_base}/api/database/rows/table/{table_id}/{created_id}/?user_field_names=true",
            headers=headers,
        )
        if not isinstance(observed, dict) or observed.get("Value") != marker:
            raise WorkerError("baserow_row_read_mismatch")
        delete_status, _deleted = request_json(
            "DELETE",
            f"{api_base}/api/database/rows/table/{table_id}/{created_id}/",
            headers=headers,
        )
        after_status, _after = request_json(
            "GET",
            f"{api_base}/api/database/rows/table/{table_id}/{created_id}/",
            headers=headers,
            allow_status={404},
        )
        if after_status != 404:
            raise WorkerError("baserow_row_cleanup_not_observed")
        created_id = ""
        return {
            "action": "baserow_crud",
            "taskId": task_id,
            "heartbeatRunId": run_id,
            "createStatus": create_status,
            "readStatus": read_status,
            "deleteStatus": delete_status,
            "postDeleteStatus": after_status,
            "markerSha256": hashlib.sha256(marker.encode()).hexdigest(),
            "markerObserved": True,
            "cleanup": "verified_deleted",
            "credentialSource": "paperclip_project_secret_ref",
        }
    finally:
        if created_id:
            request_json(
                "DELETE",
                f"{api_base}/api/database/rows/table/{table_id}/{created_id}/",
                headers=headers,
                allow_status={404},
            )


def postgrest_canary(
    value: dict[str, Any], task_id: str, run_id: str
) -> dict[str, Any]:
    token = os.environ.get("POSTGREST_API_TOKEN", "")
    if not token:
        raise WorkerError("paperclip_postgrest_secret_not_resolved")
    api_base = str(value.get("postgrestApiBase") or "").rstrip("/")
    if not api_base:
        raise WorkerError("postgrest_target_missing")
    headers = {"Authorization": f"Bearer {token}", "Prefer": "return=representation"}
    marker = f"MTE-C027-{task_id}-{run_id}"
    created_id = ""
    try:
        create_status, created = request_json(
            "POST",
            api_base + "/prototype_items",
            headers=headers,
            body={"title": marker, "status": "created"},
        )
        created_id = record_id(created)
        if not created_id:
            raise WorkerError("postgrest_row_id_missing")
        read_status, observed = request_json(
            "GET",
            api_base + f"/prototype_items?id=eq.{created_id}",
            headers=headers,
        )
        if (
            not isinstance(observed, list)
            or len(observed) != 1
            or observed[0].get("title") != marker
        ):
            raise WorkerError("postgrest_row_read_mismatch")
        delete_status, _deleted = request_json(
            "DELETE",
            api_base + f"/prototype_items?id=eq.{created_id}",
            headers=headers,
        )
        after_status, after = request_json(
            "GET",
            api_base + f"/prototype_items?id=eq.{created_id}",
            headers=headers,
        )
        if after != []:
            raise WorkerError("postgrest_row_cleanup_not_observed")
        created_id = ""
        return {
            "action": "postgrest_crud",
            "taskId": task_id,
            "heartbeatRunId": run_id,
            "createStatus": create_status,
            "readStatus": read_status,
            "deleteStatus": delete_status,
            "postDeleteStatus": after_status,
            "postDeleteAbsent": True,
            "markerSha256": hashlib.sha256(marker.encode()).hexdigest(),
            "markerObserved": True,
            "cleanup": "verified_deleted",
            "credentialSource": "paperclip_project_secret_ref",
        }
    finally:
        if created_id:
            request_json(
                "DELETE",
                api_base + f"/prototype_items?id=eq.{created_id}",
                headers=headers,
                allow_status={404},
            )


def mattermost_canary(
    value: dict[str, Any], task_id: str, run_id: str
) -> dict[str, Any]:
    token = os.environ.get("MATTERMOST_BOT_TOKEN", "")
    if not token:
        raise WorkerError("paperclip_mattermost_secret_not_resolved")
    api_base = str(value.get("mattermostApiBase") or "").rstrip("/")
    channel_id = str(value.get("mattermostChannelId") or "")
    control_run_id = str(value.get("controlRunId") or "")
    if not api_base or not channel_id or not control_run_id:
        raise WorkerError("mattermost_target_missing")
    message = (
        "MTE integration canary C030 "
        f"task_id={task_id} run_id={run_id} control_run_id={control_run_id}"
    )
    create_status, created = request_json(
        "POST",
        f"{api_base}/api/v4/posts",
        headers={"Authorization": f"Bearer {token}"},
        body={"channel_id": channel_id, "message": message},
    )
    post_id = str((created or {}).get("id") or "")
    if not post_id:
        raise WorkerError("mattermost_post_missing")
    return {
        "action": "mattermost_notification",
        "taskId": task_id,
        "heartbeatRunId": run_id,
        "postId": post_id,
        "authorUserId": str((created or {}).get("user_id") or ""),
        "channelId": str((created or {}).get("channel_id") or ""),
        "httpStatus": create_status,
        "messageSha256": hashlib.sha256(message.encode()).hexdigest(),
        "credentialSource": "paperclip_project_secret_ref",
    }


def save_result(task_id: str, result: dict[str, Any]) -> None:
    paperclip(
        "PUT",
        f"/api/issues/{task_id}/documents/integration-canary-result",
        {
            "title": "Integration canary result",
            "format": "markdown",
            "body": "```json\n" + json.dumps(result, sort_keys=True) + "\n```\n",
            "changeSummary": "Sanitized result from Paperclip integration canary run",
        },
    )
    paperclip(
        "PATCH",
        f"/api/issues/{task_id}",
        {
            "status": "done",
            "comment": (
                "Integration canary completed from heartbeat run "
                + str(result["heartbeatRunId"])
            ),
        },
    )


def main() -> int:
    task, run_id = resolve_context()
    value = task_input(task)
    task_id = str(task["id"])
    action = str(value.get("action") or "")
    if action == "baserow_crud":
        result = baserow_canary(value, task_id, run_id)
    elif action == "postgrest_crud":
        result = postgrest_canary(value, task_id, run_id)
    elif action == "mattermost_notification":
        result = mattermost_canary(value, task_id, run_id)
    else:
        raise WorkerError("canary_action_unknown")
    save_result(task_id, result)
    print(
        json.dumps(
            {
                "ok": True,
                "action": action,
                "taskId": task_id,
                "heartbeatRunId": run_id,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

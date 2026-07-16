#!/usr/bin/env python3
"""Reconcile minimal, curated Activepieces capacity and prove a no-op pass."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
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
EVIDENCE = ROOT / "evidence/provision-activepieces.json"
MANAGED_FLOW_NAMES = (
    "MTE Curated Slot - Research",
    "MTE Curated Slot - Content",
    "MTE Curated Slot - Operations",
)
SUPPORTED_PROFILES = frozenset(
    {
        "baserow-wikijs",
        "postgres-postgrest-nocodb-nocodocs",
        "postgres-notion",
    }
)
POSTGREST_PROFILES = frozenset(
    {"postgres-postgrest-nocodb-nocodocs", "postgres-notion"}
)
MANAGED_CONNECTIONS = {
    "baserow-wikijs": (
        {
            "externalId": "mte-curated-baserow",
            "displayName": "MTE Curated Baserow OSE",
            "pieceName": "@activepieces/piece-baserow",
            "pieceVersion": "0.9.5",
        },
    ),
}
POSTGREST_VARIABLE_NAME = "MTE_POSTGREST_ACTIVEPIECES_TOKEN"


class ProvisionError(RuntimeError):
    pass


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def dotenv(path: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1)
        for line in path.read_text().splitlines()
        if line and not line.startswith("#") and "=" in line
    )


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    token: str = "",
    body: Any | None = None,
    timeout: int = 45,
) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    operation = f"{method}:{urllib.parse.urlsplit(url).path}"
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(4_000_000)
    except urllib.error.HTTPError as exc:
        # Do not include upstream bodies: they can echo submitted credentials.
        raise ProvisionError(f"activepieces_http_{exc.code}:{operation}") from None
    except TimeoutError:
        raise ProvisionError(f"activepieces_timeout:{operation}") from None
    except urllib.error.URLError:
        raise ProvisionError(f"activepieces_transport_error:{operation}") from None
    value = json.loads(raw) if raw else None
    return value


def list_value(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    if isinstance(value, dict):
        for key in ("data", "items", "flows", "connections"):
            if isinstance(value.get(key), list):
                return [row for row in value[key] if isinstance(row, dict)]
    return []


def activepieces_base(values: dict[str, str]) -> str:
    port = int(values.get("ACTIVEPIECES_ORIGIN_PORT") or 0)
    if not 1024 <= port <= 65535:
        raise ProvisionError("activepieces_origin_port_invalid")
    return f"http://127.0.0.1:{port}"


def session(values: dict[str, str]) -> tuple[str, str, dict[str, Any]]:
    base = activepieces_base(values)
    auth = request_json(
        "POST",
        base + "/api/v1/authentication/sign-in",
        body={
            "email": values["ACTIVEPIECES_ADMIN_EMAIL"],
            "password": values["ACTIVEPIECES_ADMIN_PASSWORD"],
        },
    )
    if not isinstance(auth, dict):
        raise ProvisionError("activepieces_auth_invalid")
    token = str(auth.get("token") or "")
    for key in ("id", "platformId", "projectId"):
        if not auth.get(key):
            raise ProvisionError("activepieces_identity_missing")
    if not token:
        raise ProvisionError("activepieces_session_missing")
    return base, token, auth


def activepieces_app_container() -> str:
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}|{{.Image}}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise ProvisionError("docker_ps_failed")
    matches: list[str] = []
    for row in result.stdout.splitlines():
        name, _, image = row.partition("|")
        if "activepieces" not in image.lower():
            continue
        inspected = subprocess.run(
            ["docker", "inspect", "--format", "{{json .Config.Env}}", name],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if inspected.returncode != 0:
            continue
        try:
            environment = json.loads(inspected.stdout or "[]")
        except json.JSONDecodeError:
            continue
        if "AP_CONTAINER_TYPE=APP" in environment:
            matches.append(name)
    if len(matches) != 1:
        raise ProvisionError("activepieces_app_container_not_unique")
    return matches[0]


def identity_counts(expected_email: str) -> tuple[int, int]:
    code = r"""
const { Client } = require('pg');
async function main() {
  const client = new Client({
    host: process.env.AP_POSTGRES_HOST,
    port: Number(process.env.AP_POSTGRES_PORT || 5432),
    user: process.env.AP_POSTGRES_USERNAME,
    password: process.env.AP_POSTGRES_PASSWORD,
    database: process.env.AP_POSTGRES_DATABASE,
  });
  await client.connect();
  try {
    const identities = await client.query(
      'SELECT email FROM user_identity ORDER BY created ASC'
    );
    const users = await client.query('SELECT id FROM "user"');
    const emailMatches = identities.rows.filter(
      (row) => String(row.email).toLowerCase() === process.argv[1].toLowerCase()
    ).length;
    process.stdout.write(JSON.stringify({
      identityCount: identities.rowCount,
      userCount: users.rowCount,
      emailMatches,
    }));
  } finally { await client.end(); }
}
main().catch(() => process.exit(1));
"""
    result = subprocess.run(
        [
            "docker",
            "exec",
            activepieces_app_container(),
            "node",
            "-e",
            code,
            expected_email,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise ProvisionError("activepieces_identity_query_failed")
    try:
        value = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        raise ProvisionError("activepieces_identity_query_invalid") from None
    identity_count = int(value.get("identityCount") or 0)
    user_count = int(value.get("userCount") or 0)
    if identity_count != 1 or user_count != 1 or value.get("emailMatches") != 1:
        raise ProvisionError("activepieces_managed_identity_not_unique")
    return identity_count, user_count


def flow_display_name(row: dict[str, Any]) -> str:
    """Return the effective flow name from the Activepieces 0.86 list shape."""
    version = row.get("version")
    if isinstance(version, dict) and isinstance(version.get("displayName"), str):
        return version["displayName"]
    # Creation responses from older compatible builds can still expose the name
    # at top level. The list contract above remains authoritative when present.
    display_name = row.get("displayName")
    return display_name if isinstance(display_name, str) else ""


def flow_id(row: dict[str, Any]) -> str:
    value = row.get("id")
    return value if isinstance(value, str) else ""


def delete_flow_and_verify_absent(base: str, flow: str, token: str) -> None:
    encoded = urllib.parse.quote(flow, safe="")
    endpoint = f"{base}/api/v1/flows/{encoded}"
    request_json("DELETE", endpoint, token=token)
    expected = f"activepieces_http_404:GET:/api/v1/flows/{encoded}"
    for _attempt in range(120):
        try:
            request_json("GET", endpoint, token=token)
        except ProvisionError as exc:
            if str(exc) == expected:
                return
            raise
        time.sleep(0.5)
    raise ProvisionError("activepieces_managed_flow_delete_unverified")


def reconcile_flows(
    base: str, project_id: str, token: str, *, mutate: bool
) -> tuple[list[dict[str, str]], int, int]:
    url = (
        base
        + "/api/v1/flows?projectId="
        + urllib.parse.quote(project_id)
        + "&limit=100"
    )
    rows = list_value(request_json("GET", url, token=token))
    mutations = 0
    duplicates = 0
    result: list[dict[str, str]] = []
    for display_name in MANAGED_FLOW_NAMES:
        matches = [row for row in rows if flow_display_name(row) == display_name]
        if len(matches) > 1:
            if not mutate:
                duplicates += len(matches) - 1
            else:
                matches = sorted(matches, key=flow_id)
                if any(not flow_id(row) for row in matches):
                    raise ProvisionError("activepieces_managed_flow_id_missing")
                for duplicate in matches[1:]:
                    duplicate_id = flow_id(duplicate)
                    delete_flow_and_verify_absent(base, duplicate_id, token)
                    rows.remove(duplicate)
                    mutations += 1
                matches = matches[:1]
        if not matches:
            if not mutate:
                raise ProvisionError("activepieces_managed_flow_missing")
            created = request_json(
                "POST",
                base + "/api/v1/flows",
                token=token,
                body={"displayName": display_name, "projectId": project_id},
            )
            if not isinstance(created, dict) or not created.get("id"):
                raise ProvisionError("activepieces_managed_flow_create_failed")
            matches = [created]
            rows.append(created)
            mutations += 1
        current_flow_id = flow_id(matches[0])
        if not current_flow_id:
            raise ProvisionError("activepieces_managed_flow_id_missing")
        result.append(
            {
                "id": current_flow_id,
                "type": "flow",
                "displayName": display_name,
                "status": "ready",
            }
        )
    return result, mutations, duplicates


def connection_current(row: dict[str, Any], spec: dict[str, str]) -> bool:
    return all(
        row.get(key) == spec[key] for key in ("externalId", "displayName", "pieceName")
    )


def managed_connection_specs(values: dict[str, str]) -> tuple[dict[str, str], ...]:
    profile = values.get("DATA_CONTENT_PROFILE", "")
    try:
        return MANAGED_CONNECTIONS[profile]
    except KeyError as exc:
        raise ProvisionError("data_content_profile_unsupported") from exc


def managed_connection_props(values: dict[str, str]) -> dict[str, str]:
    profile = values["DATA_CONTENT_PROFILE"]
    if profile == "baserow-wikijs":
        return {
            "authType": "database_token",
            "apiUrl": "http://baserow:80",
            "token": values["BASEROW_ACTIVEPIECES_TOKEN"],
        }
    raise ProvisionError("data_content_profile_unsupported")


def reconcile_connections(
    base: str,
    project_id: str,
    token: str,
    values: dict[str, str],
    *,
    mutate: bool,
) -> tuple[list[dict[str, Any]], int, int]:
    url = (
        base
        + "/api/v1/app-connections?projectId="
        + urllib.parse.quote(project_id)
        + "&limit=100"
    )
    rows = list_value(request_json("GET", url, token=token))
    mutations = 0
    duplicates = 0
    result: list[dict[str, Any]] = []
    for spec in managed_connection_specs(values):
        matches = [row for row in rows if row.get("externalId") == spec["externalId"]]
        duplicates += max(0, len(matches) - 1)
        current = matches[0] if matches else None
        if current is not None and not connection_current(current, spec):
            raise ProvisionError("activepieces_managed_connection_drift")
        if current is None:
            if not mutate:
                raise ProvisionError("activepieces_managed_connection_missing")
            created = request_json(
                "POST",
                base + "/api/v1/app-connections",
                token=token,
                body={
                    **spec,
                    "projectId": project_id,
                    "type": "CUSTOM_AUTH",
                    "value": {
                        "type": "CUSTOM_AUTH",
                        "props": managed_connection_props(values),
                    },
                },
            )
            if not isinstance(created, dict) or not created.get("id"):
                raise ProvisionError("activepieces_managed_connection_create_failed")
            current = created
            mutations += 1
        connection_id = str(current.get("id") or "")
        if not connection_id:
            raise ProvisionError("activepieces_managed_connection_id_missing")
        result.append(
            {
                "id": connection_id,
                "type": "app-connection",
                "externalId": spec["externalId"],
                "displayName": spec["displayName"],
                "pieceName": spec["pieceName"],
                "status": "ready",
                "valueRedacted": True,
            }
        )
    return result, mutations, duplicates


def revealed_variable_value(base: str, variable_id: str, token: str) -> str:
    encoded = urllib.parse.quote(variable_id, safe="")
    revealed = request_json(
        "POST", f"{base}/api/v1/variables/{encoded}/reveal", token=token
    )
    if isinstance(revealed, str):
        return revealed
    if isinstance(revealed, dict) and isinstance(revealed.get("value"), str):
        return revealed["value"]
    raise ProvisionError("activepieces_managed_variable_reveal_invalid")


def reconcile_postgrest_variable(
    base: str,
    project_id: str,
    token: str,
    expected_value: str,
    *,
    mutate: bool,
) -> tuple[list[dict[str, Any]], int, int]:
    url = (
        base
        + "/api/v1/variables?projectId="
        + urllib.parse.quote(project_id)
        + "&limit=100"
    )
    rows = list_value(request_json("GET", url, token=token))
    matches = [row for row in rows if row.get("name") == POSTGREST_VARIABLE_NAME]
    duplicates = max(0, len(matches) - 1)
    if duplicates:
        raise ProvisionError("activepieces_managed_variable_not_unique")

    mutations = 0
    current = matches[0] if matches else None
    if current is None:
        if not mutate:
            raise ProvisionError("activepieces_managed_variable_missing")
        current = request_json(
            "POST",
            base + "/api/v1/variables",
            token=token,
            body={
                "projectId": project_id,
                "name": POSTGREST_VARIABLE_NAME,
                "value": expected_value,
            },
        )
        if not isinstance(current, dict):
            raise ProvisionError("activepieces_managed_variable_create_failed")
        mutations += 1

    variable_id = str(current.get("id") or "")
    if not variable_id:
        raise ProvisionError("activepieces_managed_variable_id_missing")
    if current.get("name") not in {None, POSTGREST_VARIABLE_NAME}:
        raise ProvisionError("activepieces_managed_variable_name_drift")

    current_value = revealed_variable_value(base, variable_id, token)
    if not hmac.compare_digest(current_value, expected_value):
        current_value = ""
        if not mutate:
            raise ProvisionError("activepieces_managed_variable_value_drift")
        updated = request_json(
            "POST",
            f"{base}/api/v1/variables/{urllib.parse.quote(variable_id, safe='')}",
            token=token,
            body={"value": expected_value},
        )
        if not isinstance(updated, dict) or str(updated.get("id") or "") not in {
            "",
            variable_id,
        }:
            raise ProvisionError("activepieces_managed_variable_update_failed")
        mutations += 1
        current_value = revealed_variable_value(base, variable_id, token)
        if not hmac.compare_digest(current_value, expected_value):
            current_value = ""
            raise ProvisionError("activepieces_managed_variable_update_unverified")
    current_value = ""
    return (
        [
            {
                "id": variable_id,
                "type": "project-variable",
                "name": POSTGREST_VARIABLE_NAME,
                "purpose": "postgrest-bearer-token",
                "status": "ready",
                "valueRedacted": True,
            }
        ],
        mutations,
        duplicates,
    )


def reconcile_credentials(
    base: str,
    project_id: str,
    token: str,
    values: dict[str, str],
    *,
    mutate: bool,
) -> tuple[list[dict[str, Any]], int, int]:
    profile = values["DATA_CONTENT_PROFILE"]
    if profile in POSTGREST_PROFILES:
        return reconcile_postgrest_variable(
            base,
            project_id,
            token,
            values["POSTGREST_ACTIVEPIECES_TOKEN"],
            mutate=mutate,
        )
    if profile == "baserow-wikijs":
        return reconcile_connections(base, project_id, token, values, mutate=mutate)
    raise ProvisionError("data_content_profile_unsupported")


def prove_mcp_token(base: str, project_id: str, token: str) -> bool:
    issued = request_json(
        "POST",
        f"{base}/api/v1/projects/{urllib.parse.quote(project_id)}/mcp-server/token",
        token=token,
    )
    mcp_token = str((issued or {}).get("mcpToken") or "")
    valid = len(mcp_token) >= 24
    # This one-time capability is deliberately not returned, logged, or stored.
    mcp_token = ""
    return valid


def execute(*, mutate: bool) -> dict[str, Any]:
    values = dotenv(CANONICAL)
    profile = values.get("DATA_CONTENT_PROFILE", "")
    required = (
        "ACTIVEPIECES_ADMIN_EMAIL",
        "ACTIVEPIECES_ADMIN_PASSWORD",
        "ACTIVEPIECES_ORIGIN_PORT",
        (
            "BASEROW_ACTIVEPIECES_TOKEN"
            if profile == "baserow-wikijs"
            else "POSTGREST_ACTIVEPIECES_TOKEN"
        ),
    )
    if profile not in SUPPORTED_PROFILES:
        raise ProvisionError("data_content_profile_unsupported")
    if any(not values.get(key) for key in required):
        raise ProvisionError("activepieces_canonical_refs_missing")
    base, token, auth = session(values)
    try:
        identity_count, user_count = identity_counts(values["ACTIVEPIECES_ADMIN_EMAIL"])
        flows, flow_mutations, flow_duplicates = reconcile_flows(
            base, str(auth["projectId"]), token, mutate=mutate
        )
        credentials, credential_mutations, credential_duplicates = (
            reconcile_credentials(
                base, str(auth["projectId"]), token, values, mutate=mutate
            )
        )
        mcp_token_issuable = prove_mcp_token(base, str(auth["projectId"]), token)
    finally:
        token = ""
    mutation_count = flow_mutations + credential_mutations
    duplicate_count = flow_duplicates + credential_duplicates
    ok = mutation_count == 0 and duplicate_count == 0 and mcp_token_issuable
    if ok:
        status = "passed"
    elif mutate and mutation_count > 0 and duplicate_count == 0:
        status = "applied"
    else:
        status = "failed"
    return {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "ActivepiecesProvisionEvidence",
        "dataContentProfile": profile,
        "status": status,
        "ok": ok,
        "generatedAt": utcnow(),
        "canonicalSourceSha256": sha256_path(CANONICAL),
        "producerPath": str(Path(__file__)),
        "producerSha256": sha256_path(Path(__file__)),
        "ownerId": str(auth["id"]),
        "platformId": str(auth["platformId"]),
        "projectId": str(auth["projectId"]),
        "identityCount": identity_count,
        "userCount": user_count,
        "managedFlows": flows,
        "credentialSlots": credentials,
        "mcpTokenIssuable": mcp_token_issuable,
        "mcpTokenPersisted": False,
        "secondRunNoOp": mutation_count == 0,
        "mutationCount": mutation_count,
        "duplicateCount": duplicate_count,
    }


def main() -> int:
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    if action not in {"provision", "verify", "status"}:
        print(
            "usage: server-activepieces-provision-verify.py provision|verify|status",
            file=sys.stderr,
        )
        return 2
    try:
        payload = execute(mutate=action == "provision")
    except BaseException as exc:
        payload = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "ActivepiecesProvisionEvidence",
            "status": "failed",
            "ok": False,
            "generatedAt": utcnow(),
            "canonicalSourceSha256": sha256_path(CANONICAL)
            if CANONICAL.is_file()
            else "",
            "producerPath": str(Path(__file__)),
            "producerSha256": sha256_path(Path(__file__)),
            "errorType": type(exc).__name__,
        }
        if isinstance(exc, ProvisionError):
            payload["error"] = str(exc)
    atomic_json(EVIDENCE, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload.get("status") in {"applied", "passed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

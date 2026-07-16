#!/usr/bin/env python3
"""Provision and prove the self-hosted Baserow OSE replacement track.

The producer is intentionally standalone so every method can be invoked alone.
It never emits secret values. Generated credentials are persisted only through
the root-owned canonical ``platform.env`` under the platform lock.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import http.client
import json
import os
import queue
import re
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(os.environ.get("MTE_PLATFORM_ROOT", "/opt/mte-platform"))
UNCONFIGURED_SECRET_ROOT = Path("/__mte_secrets_root_unconfigured__")
_secret_root = os.environ.get("MTE_SECRETS_ROOT")
SECRET_ROOT = Path(_secret_root) if _secret_root else UNCONFIGURED_SECRET_ROOT
CANONICAL_ENV = SECRET_ROOT / "platform.env"
CANONICAL_LOCK = SECRET_ROOT / ".platform-env.lock"
EVIDENCE = ROOT / "evidence/baserow-verify.json"
PRODUCER = ROOT / "bin/server-baserow.py"

BASEROW_IMAGE = (
    "baserow/baserow:2.3.1@"
    "sha256:496889c4fe22ee6b632698c3c74f7ccaee734c8002b5ebc8d194c5fcacffc98a"
)
BASEROW_AMD64_DIGEST = (
    "sha256:16d9dd21b3f282c9300d876da66c8036e217143cae0af8f1dd2da5b45af0e30b"
)
REDIS_IMAGE = (
    "redis:7.4.9-alpine@"
    "sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
)
REDIS_AMD64_DIGEST = (
    "sha256:b1addbe72465a718643cff9e60a58e6df1841e29d6d7d60c9a85d8d72f08d1a7"
)
LICENSE_SOURCE = "https://github.com/baserow/baserow/blob/2.3.1/LICENSE"
LICENSE_SOURCE_SHA256 = (
    "1c1fa26d7bb6fddee61c4120803a7190ee3199ac29062bcc1ff0f00a0de08e2b"
)

GENERATED_REFS = {
    "BASEROW_WORKSPACE_ID",
    "BASEROW_DATABASE_ID",
    "BASEROW_TABLE_ID",
    "BASEROW_PAPERCLIP_TOKEN",
    "BASEROW_PAPERCLIP_TOKEN_ID",
    "BASEROW_ACTIVEPIECES_TOKEN",
    "BASEROW_ACTIVEPIECES_TOKEN_ID",
    "BASEROW_MCP_ENDPOINT_KEY",
    "BASEROW_MCP_ENDPOINT_ID",
}
REQUIRED_REFS = {
    "BASEROW_ADMIN_EMAIL",
    "BASEROW_ADMIN_NAME",
    "BASEROW_ADMIN_PASSWORD",
    "BASEROW_DATABASE_NAME",
    "BASEROW_DB_HOST",
    "BASEROW_DB_NAME",
    "BASEROW_DB_PASSWORD",
    "BASEROW_DB_PORT",
    "BASEROW_DB_USER",
    "BASEROW_MCP_ENDPOINT_NAME",
    "BASEROW_ORIGIN_PORT",
    "BASEROW_PAPERCLIP_TOKEN_NAME",
    "BASEROW_ACTIVEPIECES_TOKEN_NAME",
    "BASEROW_CPU_LIMIT",
    "BASEROW_MEMORY_LIMIT",
    "BASEROW_PUBLIC_URL",
    "BASEROW_SECRET_KEY",
    "BASEROW_REDIS_DB",
    "BASEROW_REDIS_CPU_LIMIT",
    "BASEROW_REDIS_HOST",
    "BASEROW_REDIS_MEMORY_LIMIT",
    "BASEROW_REDIS_PASSWORD",
    "BASEROW_REDIS_PORT",
    "BASEROW_TABLE_NAME",
    "BASEROW_WORKSPACE_NAME",
    "MTE_BASEROW_BASEROW_IMAGE",
    "MTE_BASEROW_BASEROW_PORT_1_MAPPING",
    "MTE_BASEROW_REDIS_IMAGE",
    "PLATFORM_BASE_DOMAIN",
}
EXPECTED_MCP_TOOLS = {
    "list_databases",
    "list_tables",
    "get_table_schema",
    "list_table_rows",
    "create_rows",
    "update_rows",
    "delete_rows",
}
SAFE_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class BaserowError(RuntimeError):
    pass


class ApiError(BaserowError):
    def __init__(self, status: int, reason: str, payload: Any = None):
        super().__init__(f"http_{status}:{reason}")
        self.status = status
        self.reason = reason
        self.payload = payload


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def fingerprint(value: str) -> str:
    if not value:
        raise BaserowError("empty_secret_fingerprint")
    return sha256_bytes(value.encode())


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        raise BaserowError(f"canonical_env_missing:{path}")
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def require_values(values: dict[str, str], refs: set[str] = REQUIRED_REFS) -> None:
    missing = sorted(key for key in refs if not values.get(key))
    if missing:
        raise BaserowError("missing_canonical_refs:" + ",".join(missing))
    if values["MTE_BASEROW_BASEROW_IMAGE"] != BASEROW_IMAGE:
        raise BaserowError("baserow_image_not_exactly_pinned")
    if values["MTE_BASEROW_REDIS_IMAGE"] != REDIS_IMAGE:
        raise BaserowError("baserow_redis_image_not_exactly_pinned")
    if values["BASEROW_REDIS_DB"] != "8":
        raise BaserowError("baserow_redis_db_must_be_8")
    if (
        values["BASEROW_REDIS_HOST"] != "redis"
        or values["BASEROW_REDIS_PORT"] != "6379"
    ):
        raise BaserowError("baserow_redis_endpoint_not_private")
    if (
        values["BASEROW_DB_HOST"] != "mte-postgres"
        or values["BASEROW_DB_PORT"] != "5432"
    ):
        raise BaserowError("baserow_postgres_endpoint_not_shared_data_plane")
    for key in ("BASEROW_DB_NAME", "BASEROW_DB_USER"):
        if not SAFE_IDENTIFIER.fullmatch(values[key]):
            raise BaserowError(f"invalid_database_identifier:{key}")
    if (
        values["BASEROW_PAPERCLIP_TOKEN_NAME"]
        == values["BASEROW_ACTIVEPIECES_TOKEN_NAME"]
    ):
        raise BaserowError("baserow_token_names_not_distinct")
    if values["BASEROW_DB_PASSWORD"] == values["BASEROW_REDIS_PASSWORD"]:
        raise BaserowError("baserow_database_and_redis_credentials_not_distinct")


def atomic_text(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(mode)
        if os.geteuid() == 0:
            os.chown(temporary, 0, 0)
        temporary.replace(path)
        path.chmod(mode)
        if os.geteuid() == 0:
            os.chown(path, 0, 0)
    finally:
        temporary.unlink(missing_ok=True)


def update_canonical(updates: dict[str, str]) -> dict[str, Any]:
    if SECRET_ROOT == UNCONFIGURED_SECRET_ROOT:
        raise BaserowError("missing_runtime_env:MTE_SECRETS_ROOT")
    unknown = sorted(set(updates) - GENERATED_REFS)
    if unknown:
        raise BaserowError("canonical_update_ref_not_allowed:" + ",".join(unknown))
    if any(not value for value in updates.values()):
        raise BaserowError("canonical_update_empty_value")
    SECRET_ROOT.mkdir(parents=True, exist_ok=True)
    SECRET_ROOT.chmod(0o700)
    CANONICAL_LOCK.touch(mode=0o600, exist_ok=True)
    CANONICAL_LOCK.chmod(0o600)
    with CANONICAL_LOCK.open("r+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        current = parse_env(CANONICAL_ENV)
        changed: list[str] = []
        for key, value in updates.items():
            if current.get(key) != str(value):
                current[key] = str(value)
                changed.append(key)
        body = "".join(f"{key}={current[key]}\n" for key in sorted(current))
        atomic_text(CANONICAL_ENV, body)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    return {
        "changedKeys": sorted(changed),
        "canonicalSourceSha256": sha256_path(CANONICAL_ENV),
    }


def request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: Any = None,
    expected: set[int] = {200},
    timeout: int = 30,
) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body).encode()
    merged = {"Accept": "application/json", "User-Agent": "mte-baserow/1"}
    if body is not None:
        merged["Content-Type"] = "application/json"
    merged.update(headers or {})
    request = urllib.request.Request(url, data=data, headers=merged, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(4_000_000)
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read(4_000_000)
        status = exc.code
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ApiError(0, type(exc).__name__) from None
    payload: Any = None
    if raw:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = raw.decode(errors="replace")[:500]
    if status not in expected:
        reason = "unexpected_status"
        if isinstance(payload, dict):
            reason = str(payload.get("error") or payload.get("detail") or reason)
        raise ApiError(status, reason, payload)
    return status, payload


def base_url(values: dict[str, str]) -> str:
    explicit = values.get("BASEROW_INTERNAL_URL", "").rstrip("/")
    if explicit:
        return explicit
    port = values.get("BASEROW_ORIGIN_PORT", "")
    if not port.isdigit():
        raise BaserowError("baserow_origin_port_missing")
    return f"http://127.0.0.1:{port}"


def jwt_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"JWT {token}"}


def database_token_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Token {token}"}


def select_one(
    rows: list[dict[str, Any]], predicate: Any, label: str
) -> dict[str, Any] | None:
    matches = [row for row in rows if predicate(row)]
    if len(matches) > 1:
        raise BaserowError(f"duplicate_managed_resource:{label}")
    return matches[0] if matches else None


def docker(*args: str, input_text: str | None = None) -> str:
    completed = subprocess.run(
        ["docker", *args],
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise BaserowError(f"docker_command_failed:{args[0] if args else 'unknown'}")
    return completed.stdout.strip()


def compose_container(service: str) -> str:
    output = docker(
        "ps",
        "--filter",
        "label=com.docker.compose.project=mte-baserow",
        "--filter",
        f"label=com.docker.compose.service={service}",
        "--format",
        "{{.Names}}",
    )
    names = [line for line in output.splitlines() if line]
    if len(names) != 1:
        raise BaserowError(f"baserow_container_count_invalid:{service}:{len(names)}")
    return names[0]


def postgres_container() -> str:
    output = docker(
        "ps",
        "--filter",
        "label=com.docker.compose.project=mte-postgres",
        "--filter",
        "label=com.docker.compose.service=postgres",
        "--format",
        "{{.Names}}",
    )
    names = [line for line in output.splitlines() if line]
    if len(names) != 1:
        raise BaserowError(f"postgres_container_count_invalid:{len(names)}")
    return names[0]


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def ensure_database(values: dict[str, str]) -> dict[str, Any]:
    require_values(values)
    container = postgres_container()
    user = values["BASEROW_DB_USER"]
    database = values["BASEROW_DB_NAME"]
    password = sql_literal(values["BASEROW_DB_PASSWORD"])
    sql = f"""
DO $mte$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{user}') THEN
    CREATE ROLE \"{user}\" LOGIN PASSWORD {password};
  ELSE
    ALTER ROLE \"{user}\" WITH LOGIN PASSWORD {password};
  END IF;
END
$mte$;
SELECT 'CREATE DATABASE \"{database}\" OWNER \"{user}\"'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = '{database}')\\gexec
ALTER DATABASE \"{database}\" OWNER TO \"{user}\";
SELECT json_build_object(
  'role', EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{user}'),
  'database', EXISTS (SELECT 1 FROM pg_database WHERE datname = '{database}'),
  'owner', (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '{database}')
)::text;
"""
    output = docker(
        "exec",
        "-i",
        container,
        "sh",
        "-ec",
        'PGPASSWORD="$POSTGRES_PASSWORD" psql -X -qAt -v ON_ERROR_STOP=1 '
        '-U "$POSTGRES_USER" -d "$POSTGRES_DB"',
        input_text=sql,
    )
    try:
        result = json.loads(output.splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        raise BaserowError("baserow_database_reconcile_invalid_output") from exc
    if result != {"role": True, "database": True, "owner": user}:
        raise BaserowError("baserow_database_reconcile_failed")
    return {
        "ok": True,
        "database": database,
        "role": user,
        "ownerExact": True,
        "isolatedRoleAndDatabase": database == "baserow" and user == "baserow",
    }


def wait_health(url: str, timeout: int = 360) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            request_json("GET", f"{url}/api/_health/", expected={200}, timeout=10)
            return
        except ApiError:
            time.sleep(3)
    raise BaserowError("baserow_health_timeout")


def admin_session(values: dict[str, str]) -> str:
    url = base_url(values)
    login = {
        "email": values["BASEROW_ADMIN_EMAIL"],
        "password": values["BASEROW_ADMIN_PASSWORD"],
    }
    try:
        _, payload = request_json(
            "POST", f"{url}/api/user/token-auth/", body=login, expected={200}
        )
    except ApiError as exc:
        if exc.status not in {400, 401}:
            raise
        register = {
            "name": values["BASEROW_ADMIN_NAME"],
            "email": values["BASEROW_ADMIN_EMAIL"],
            "password": values["BASEROW_ADMIN_PASSWORD"],
            "authenticate": True,
            "language": "en",
            "template_id": None,
        }
        _, payload = request_json(
            "POST", f"{url}/api/user/", body=register, expected={200}
        )
    if not isinstance(payload, dict):
        raise BaserowError("baserow_admin_auth_invalid")
    token = str(payload.get("access_token") or payload.get("token") or "")
    if not token:
        _, payload = request_json(
            "POST", f"{url}/api/user/token-auth/", body=login, expected={200}
        )
        token = str(
            (payload or {}).get("access_token") or (payload or {}).get("token") or ""
        )
    if not token:
        raise BaserowError("baserow_admin_jwt_missing")
    return token


def ensure_workspace(values: dict[str, str], token: str) -> dict[str, Any]:
    url = base_url(values)
    headers = jwt_headers(token)
    _, rows = request_json("GET", f"{url}/api/workspaces/", headers=headers)
    if not isinstance(rows, list):
        raise BaserowError("baserow_workspaces_invalid")
    name = values["BASEROW_WORKSPACE_NAME"]
    row = select_one(rows, lambda item: item.get("name") == name, "workspace")
    if row is None:
        _, row = request_json(
            "POST", f"{url}/api/workspaces/", headers=headers, body={"name": name}
        )
    if not isinstance(row, dict) or not str(row.get("id", "")).isdigit():
        raise BaserowError("baserow_workspace_invalid")
    return row


def ensure_database_application(
    values: dict[str, str], token: str, workspace_id: int
) -> dict[str, Any]:
    url = base_url(values)
    headers = jwt_headers(token)
    endpoint = f"{url}/api/applications/workspace/{workspace_id}/"
    _, rows = request_json("GET", endpoint, headers=headers)
    if not isinstance(rows, list):
        raise BaserowError("baserow_applications_invalid")
    name = values["BASEROW_DATABASE_NAME"]
    row = select_one(
        rows,
        lambda item: item.get("name") == name and item.get("type") == "database",
        "database",
    )
    if row is None:
        _, row = request_json(
            "POST",
            endpoint,
            headers=headers,
            body={"name": name, "type": "database", "init_with_data": False},
        )
    if not isinstance(row, dict) or not str(row.get("id", "")).isdigit():
        raise BaserowError("baserow_database_application_invalid")
    return row


def ensure_table(
    values: dict[str, str], token: str, database_id: int
) -> dict[str, Any]:
    url = base_url(values)
    headers = jwt_headers(token)
    endpoint = f"{url}/api/database/tables/database/{database_id}/"
    _, rows = request_json("GET", endpoint, headers=headers)
    if not isinstance(rows, list):
        raise BaserowError("baserow_tables_invalid")
    name = values["BASEROW_TABLE_NAME"]
    row = select_one(rows, lambda item: item.get("name") == name, "table")
    if row is None:
        _, row = request_json(
            "POST",
            endpoint,
            headers=headers,
            body={"name": name, "data": [["Value"]], "first_row_header": True},
        )
    if not isinstance(row, dict) or not str(row.get("id", "")).isdigit():
        raise BaserowError("baserow_table_invalid")
    return row


def ensure_database_token(
    values: dict[str, str],
    jwt: str,
    *,
    workspace_id: int,
    database_id: int,
    name: str,
) -> dict[str, Any]:
    url = base_url(values)
    headers = jwt_headers(jwt)
    endpoint = f"{url}/api/database/tokens/"
    _, rows = request_json("GET", endpoint, headers=headers)
    if not isinstance(rows, list):
        raise BaserowError("baserow_tokens_invalid")
    token = select_one(
        rows,
        lambda item: item.get("name") == name
        and int(item.get("workspace") or 0) == workspace_id,
        f"token:{name}",
    )
    if token is None:
        _, token = request_json(
            "POST",
            endpoint,
            headers=headers,
            body={"name": name, "workspace": workspace_id},
        )
    if not isinstance(token, dict) or not str(token.get("id", "")).isdigit():
        raise BaserowError("baserow_token_invalid")
    token_id = int(token["id"])
    permission = [["database", database_id]]
    desired = {
        "create": permission,
        "read": permission,
        "update": permission,
        "delete": permission,
    }
    if token.get("permissions") != desired:
        _, token = request_json(
            "PATCH",
            f"{endpoint}{token_id}/",
            headers=headers,
            body={"permissions": desired},
        )
    key = str((token or {}).get("key") or "")
    if not key:
        _, token = request_json("GET", f"{endpoint}{token_id}/", headers=headers)
        key = str((token or {}).get("key") or "")
    if not key:
        raise BaserowError("baserow_token_key_missing")
    return {**token, "key": key}


def ensure_mcp_endpoint(
    values: dict[str, str], jwt: str, workspace_id: int
) -> dict[str, Any]:
    url = base_url(values)
    headers = jwt_headers(jwt)
    endpoint = f"{url}/api/mcp/endpoints/"
    _, rows = request_json("GET", endpoint, headers=headers)
    if not isinstance(rows, list):
        raise BaserowError("baserow_mcp_endpoints_invalid")
    name = values["BASEROW_MCP_ENDPOINT_NAME"]
    row = select_one(
        rows,
        lambda item: item.get("name") == name
        and int(item.get("workspace_id") or 0) == workspace_id,
        "mcp-endpoint",
    )
    if row is None:
        _, row = request_json(
            "POST",
            endpoint,
            headers=headers,
            body={"name": name, "workspace_id": workspace_id},
        )
    if (
        not isinstance(row, dict)
        or not str(row.get("id", "")).isdigit()
        or not row.get("key")
    ):
        raise BaserowError("baserow_mcp_endpoint_invalid")
    return row


def provision(values: dict[str, str]) -> dict[str, Any]:
    require_values(values)
    url = base_url(values)
    wait_health(url)
    jwt = admin_session(values)
    workspace = ensure_workspace(values, jwt)
    workspace_id = int(workspace["id"])
    database = ensure_database_application(values, jwt, workspace_id)
    database_id = int(database["id"])
    table = ensure_table(values, jwt, database_id)
    table_id = int(table["id"])
    paperclip = ensure_database_token(
        values,
        jwt,
        workspace_id=workspace_id,
        database_id=database_id,
        name=values["BASEROW_PAPERCLIP_TOKEN_NAME"],
    )
    activepieces = ensure_database_token(
        values,
        jwt,
        workspace_id=workspace_id,
        database_id=database_id,
        name=values["BASEROW_ACTIVEPIECES_TOKEN_NAME"],
    )
    if paperclip["key"] == activepieces["key"]:
        raise BaserowError("baserow_managed_tokens_not_distinct")
    mcp = ensure_mcp_endpoint(values, jwt, workspace_id)
    persisted = update_canonical(
        {
            "BASEROW_WORKSPACE_ID": str(workspace_id),
            "BASEROW_DATABASE_ID": str(database_id),
            "BASEROW_TABLE_ID": str(table_id),
            "BASEROW_PAPERCLIP_TOKEN": str(paperclip["key"]),
            "BASEROW_PAPERCLIP_TOKEN_ID": str(paperclip["id"]),
            "BASEROW_ACTIVEPIECES_TOKEN": str(activepieces["key"]),
            "BASEROW_ACTIVEPIECES_TOKEN_ID": str(activepieces["id"]),
            "BASEROW_MCP_ENDPOINT_KEY": str(mcp["key"]),
            "BASEROW_MCP_ENDPOINT_ID": str(mcp["id"]),
        }
    )
    return {
        "ok": True,
        "ownerAuthenticated": True,
        "workspaceId": workspace_id,
        "databaseId": database_id,
        "tableId": table_id,
        "paperclipTokenId": int(paperclip["id"]),
        "activepiecesTokenId": int(activepieces["id"]),
        "mcpEndpointId": int(mcp["id"]),
        "tokensDistinct": True,
        "tokenFingerprints": {
            "paperclip": fingerprint(str(paperclip["key"])),
            "activepieces": fingerprint(str(activepieces["key"])),
        },
        "mcpKeyFingerprint": fingerprint(str(mcp["key"])),
        "canonical": persisted,
    }


class SSESession:
    def __init__(self, url: str):
        self.url = url
        self.events: queue.Queue[tuple[str, str] | Exception] = queue.Queue()
        self.response: Any = None
        self.thread = threading.Thread(target=self._read, daemon=True)

    def _read(self) -> None:
        request = urllib.request.Request(
            self.url,
            headers={"Accept": "text/event-stream", "User-Agent": "mte-baserow/1"},
        )
        try:
            self.response = urllib.request.urlopen(request, timeout=60)
            event = "message"
            data: list[str] = []
            while True:
                raw = self.response.readline()
                if not raw:
                    return
                line = raw.decode(errors="replace").rstrip("\r\n")
                if not line:
                    if data:
                        self.events.put((event, "\n".join(data)))
                    event, data = "message", []
                elif line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    data.append(line[5:].strip())
        except Exception as exc:  # forwarded to the main thread
            self.events.put(exc)

    def start(self) -> None:
        self.thread.start()

    def next(self, timeout: int = 30) -> tuple[str, str]:
        try:
            value = self.events.get(timeout=timeout)
        except queue.Empty as exc:
            raise BaserowError("baserow_mcp_sse_timeout") from exc
        if isinstance(value, Exception):
            raise BaserowError(
                f"baserow_mcp_sse_error:{type(value).__name__}"
            ) from value
        return value

    def close(self) -> None:
        if self.response is not None:
            self.response.close()


def mcp_post(url: str, payload: dict[str, Any]) -> int:
    parsed = urllib.parse.urlsplit(url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=30)
    path = urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))
    try:
        connection.request(
            "POST",
            path,
            body=json.dumps(payload),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        response = connection.getresponse()
        response.read()
        if response.status not in {200, 202}:
            raise BaserowError(f"baserow_mcp_post_status:{response.status}")
        return response.status
    finally:
        connection.close()


def wait_jsonrpc(session: SSESession, request_id: int) -> dict[str, Any]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        _, raw = session.next(max(1, int(deadline - time.monotonic())))
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("id") == request_id:
            if payload.get("error"):
                raise BaserowError("baserow_mcp_jsonrpc_error")
            return payload
    raise BaserowError("baserow_mcp_jsonrpc_timeout")


def mcp_probe(values: dict[str, str]) -> dict[str, Any]:
    key = values.get("BASEROW_MCP_ENDPOINT_KEY", "")
    if not key:
        raise BaserowError("baserow_mcp_key_missing")
    url = base_url(values)
    session = SSESession(f"{url}/mcp/{urllib.parse.quote(key, safe='')}/sse")
    session.start()
    try:
        event, endpoint = session.next()
        if event != "endpoint" or not endpoint:
            raise BaserowError("baserow_mcp_endpoint_event_missing")
        post_url = urllib.parse.urljoin(url + "/", endpoint)
        initialize = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mte-baserow-verifier", "version": "1"},
            },
        }
        mcp_post(post_url, initialize)
        init_response = wait_jsonrpc(session, 1)
        mcp_post(
            post_url,
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )
        mcp_post(
            post_url,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        tools_response = wait_jsonrpc(session, 2)
        tools = (tools_response.get("result") or {}).get("tools") or []
        names = sorted(
            str(item.get("name"))
            for item in tools
            if isinstance(item, dict) and item.get("name")
        )
        missing = sorted(EXPECTED_MCP_TOOLS - set(names))
        if missing:
            raise BaserowError("baserow_mcp_tools_missing:" + ",".join(missing))
        return {
            "ok": True,
            "transport": "sse",
            "initializeOk": bool(init_response.get("result")),
            "toolsListOk": True,
            "toolNames": names,
            "endpointId": int(values["BASEROW_MCP_ENDPOINT_ID"]),
            "keyFingerprint": fingerprint(key),
        }
    finally:
        session.close()


def runtime_distribution(values: dict[str, str]) -> dict[str, Any]:
    baserow = compose_container("baserow")
    redis = compose_container("redis")
    baserow_image = docker("inspect", "--format", "{{.Config.Image}}", baserow)
    redis_image = docker("inspect", "--format", "{{.Config.Image}}", redis)
    if baserow_image != BASEROW_IMAGE or redis_image != REDIS_IMAGE:
        raise BaserowError("baserow_runtime_image_drift")
    raw_env = docker("inspect", "--format", "{{json .Config.Env}}", baserow)
    environment = json.loads(raw_env)
    licensed = [
        item.split("=", 1)[0]
        for item in environment
        if "LICENSE" in item.split("=", 1)[0].upper() and item.split("=", 1)[-1]
    ]
    if licensed:
        raise BaserowError("baserow_commercial_license_configured")
    return {
        "name": "Baserow OSE",
        "version": "2.3.1",
        "image": BASEROW_IMAGE,
        "platformDigest": BASEROW_AMD64_DIGEST,
        "redisImage": REDIS_IMAGE,
        "redisPlatformDigest": REDIS_AMD64_DIGEST,
        "license": "MIT",
        "licenseSource": LICENSE_SOURCE,
        "licenseSourceSha256": LICENSE_SOURCE_SHA256,
        "enterpriseLicenseConfigured": False,
        "premiumFeaturesUsed": False,
        "runtimeImagesExact": True,
    }


def rest_probe(values: dict[str, str]) -> dict[str, Any]:
    url = base_url(values)
    paperclip = values.get("BASEROW_PAPERCLIP_TOKEN", "")
    activepieces = values.get("BASEROW_ACTIVEPIECES_TOKEN", "")
    table_id = values.get("BASEROW_TABLE_ID", "")
    if not paperclip or not activepieces or not table_id.isdigit():
        raise BaserowError("baserow_rest_canonical_refs_missing")
    first, _ = request_json(
        "GET",
        f"{url}/api/database/tokens/check/",
        headers=database_token_headers(paperclip),
    )
    second, _ = request_json(
        "GET",
        f"{url}/api/database/tokens/check/",
        headers=database_token_headers(activepieces),
    )
    rows_status, rows = request_json(
        "GET",
        f"{url}/api/database/rows/table/{table_id}/?user_field_names=true&size=1",
        headers=database_token_headers(paperclip),
    )
    if not isinstance(rows, dict) or not isinstance(rows.get("results"), list):
        raise BaserowError("baserow_rows_response_invalid")
    return {
        "ok": True,
        "tokenCheckStatus": first if first == second else 0,
        "paperclipTokenCheckStatus": first,
        "activepiecesTokenCheckStatus": second,
        "rowsStatus": rows_status,
        "tokensDistinct": paperclip != activepieces,
        "tokenFingerprints": {
            "paperclip": fingerprint(paperclip),
            "activepieces": fingerprint(activepieces),
        },
    }


def restart_persistence_canary(values: dict[str, str]) -> dict[str, Any]:
    url = base_url(values)
    table_id = int(values["BASEROW_TABLE_ID"])
    paperclip_headers = database_token_headers(values["BASEROW_PAPERCLIP_TOKEN"])
    activepieces_headers = database_token_headers(values["BASEROW_ACTIVEPIECES_TOKEN"])
    marker = f"mte-baserow-{uuid.uuid4()}"
    marker_updated = marker + "-updated"
    marker_sha = sha256_bytes(marker_updated.encode())
    row_id: int | None = None
    cleanup = False
    post_delete_status = 0
    container = compose_container("baserow")
    container_id = docker("inspect", "--format", "{{.Id}}", container)
    started_before = docker("inspect", "--format", "{{.State.StartedAt}}", container)
    try:
        created_status, created = request_json(
            "POST",
            f"{url}/api/database/rows/table/{table_id}/?user_field_names=true",
            headers=paperclip_headers,
            body={"Value": marker},
        )
        if not isinstance(created, dict) or not str(created.get("id", "")).isdigit():
            raise BaserowError("baserow_canary_create_invalid")
        row_id = int(created["id"])
        read_status, read = request_json(
            "GET",
            f"{url}/api/database/rows/table/{table_id}/{row_id}/?user_field_names=true",
            headers=activepieces_headers,
        )
        if not isinstance(read, dict) or read.get("Value") != marker:
            raise BaserowError("baserow_canary_read_invalid")
        update_status, updated = request_json(
            "PATCH",
            f"{url}/api/database/rows/table/{table_id}/{row_id}/?user_field_names=true",
            headers=paperclip_headers,
            body={"Value": marker_updated},
        )
        if not isinstance(updated, dict) or updated.get("Value") != marker_updated:
            raise BaserowError("baserow_canary_update_invalid")
        docker("restart", container)
        wait_health(url)
        started_after = docker("inspect", "--format", "{{.State.StartedAt}}", container)
        if started_after == started_before:
            raise BaserowError("baserow_restart_not_observed")
        persisted_status, persisted = request_json(
            "GET",
            f"{url}/api/database/rows/table/{table_id}/{row_id}/?user_field_names=true",
            headers=activepieces_headers,
        )
        if not isinstance(persisted, dict) or persisted.get("Value") != marker_updated:
            raise BaserowError("baserow_restart_persistence_invalid")
        delete_status, _ = request_json(
            "DELETE",
            f"{url}/api/database/rows/table/{table_id}/{row_id}/?user_field_names=true",
            headers=paperclip_headers,
            expected={204},
        )
        post_delete_status, _ = request_json(
            "GET",
            f"{url}/api/database/rows/table/{table_id}/{row_id}/?user_field_names=true",
            headers=activepieces_headers,
            expected={404},
        )
        cleanup = True
        return {
            "ok": True,
            "workspaceId": int(values["BASEROW_WORKSPACE_ID"]),
            "databaseId": int(values["BASEROW_DATABASE_ID"]),
            "tableId": table_id,
            "rowId": row_id,
            "markerSha256": marker_sha,
            "createdStatus": created_status,
            "readStatus": read_status,
            "updateStatus": update_status,
            "persistedReadStatus": persisted_status,
            "deleteStatus": delete_status,
            "restartObserved": True,
            "persistenceVerified": True,
            "containerId": container_id,
            "startedAtChanged": True,
            "postDeleteStatus": post_delete_status,
            "postDeleteStatus404": post_delete_status == 404,
            "cleanupCompleted": cleanup,
        }
    finally:
        if row_id is not None and not cleanup:
            try:
                request_json(
                    "DELETE",
                    f"{url}/api/database/rows/table/{table_id}/{row_id}/?user_field_names=true",
                    headers=paperclip_headers,
                    expected={204, 404},
                )
            except BaserowError:
                pass


def source_gate() -> dict[str, Any]:
    producer = PRODUCER if PRODUCER.is_file() else Path(__file__).resolve()
    stat = CANONICAL_ENV.stat()
    if stat.st_mode & 0o777 != 0o600:
        raise BaserowError("canonical_env_mode_not_0600")
    if os.geteuid() == 0 and stat.st_uid != 0:
        raise BaserowError("canonical_env_owner_not_root")
    return {
        "canonicalSourceSha256": sha256_path(CANONICAL_ENV),
        "producerSha256": sha256_path(producer),
        "canonicalMode": "0600",
        "canonicalOwner": "root" if stat.st_uid == 0 else str(stat.st_uid),
    }


def verify(values: dict[str, str], *, restart_canary: bool) -> dict[str, Any]:
    require_values(values, REQUIRED_REFS | GENERATED_REFS)
    if values["BASEROW_PAPERCLIP_TOKEN"] == values["BASEROW_ACTIVEPIECES_TOKEN"]:
        raise BaserowError("baserow_managed_tokens_not_distinct")
    url = base_url(values)
    wait_health(url)
    distribution = runtime_distribution(values)
    rest = rest_probe(values)
    mcp = mcp_probe(values)
    persistence_detail = (
        restart_persistence_canary(values)
        if restart_canary
        else {
            "ok": None,
            "skipped": True,
        }
    )
    persistence = (
        {
            key: persistence_detail[key]
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
        }
        if persistence_detail.get("ok") is True
        else {"ok": None, "skipped": True}
    )
    gate = source_gate()
    return {
        "apiVersion": f"mte.{values['PLATFORM_BASE_DOMAIN']}/v1",
        "kind": "BaserowAcceptance",
        "status": "passed" if persistence_detail.get("ok") is True else "incomplete",
        "ok": persistence_detail.get("ok") is True,
        "generatedAt": utc_now(),
        **gate,
        "distribution": distribution,
        "ids": {
            "workspaceId": int(values["BASEROW_WORKSPACE_ID"]),
            "databaseId": int(values["BASEROW_DATABASE_ID"]),
            "tableId": int(values["BASEROW_TABLE_ID"]),
            "paperclipTokenId": int(values["BASEROW_PAPERCLIP_TOKEN_ID"]),
            "activepiecesTokenId": int(values["BASEROW_ACTIVEPIECES_TOKEN_ID"]),
            "mcpEndpointId": int(values["BASEROW_MCP_ENDPOINT_ID"]),
        },
        "restApi": rest,
        "mcp": mcp,
        "baserowPersistence": persistence,
        "crudCanary": persistence_detail,
        "secrets": {
            "rawValuesIncluded": False,
            "tokensDistinct": rest["tokensDistinct"],
            "paperclipTokenFingerprint": rest["tokenFingerprints"]["paperclip"],
            "activepiecesTokenFingerprint": rest["tokenFingerprints"]["activepieces"],
            "mcpKeyFingerprint": mcp["keyFingerprint"],
        },
    }


def write_evidence(payload: dict[str, Any]) -> None:
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    forbidden = [
        parse_env(CANONICAL_ENV).get(key, "")
        for key in (
            "BASEROW_ADMIN_PASSWORD",
            "BASEROW_DB_PASSWORD",
            "BASEROW_REDIS_PASSWORD",
            "BASEROW_PAPERCLIP_TOKEN",
            "BASEROW_ACTIVEPIECES_TOKEN",
            "BASEROW_MCP_ENDPOINT_KEY",
        )
    ]
    if any(value and value in serialized for value in forbidden):
        raise BaserowError("baserow_evidence_contains_secret")
    atomic_text(EVIDENCE, serialized, 0o600)


def preflight(values: dict[str, str]) -> dict[str, Any]:
    require_values(values)
    mapping = values.get("MTE_BASEROW_BASEROW_PORT_1_MAPPING", "")
    match = re.fullmatch(r"127\.0\.0\.1:([0-9]+):80", mapping)
    if match is None:
        raise BaserowError("baserow_origin_mapping_not_loopback_only")
    if match.group(1) != values["BASEROW_ORIGIN_PORT"]:
        raise BaserowError("baserow_origin_mapping_port_drift")
    public = urllib.parse.urlsplit(values["BASEROW_PUBLIC_URL"])
    if (
        public.scheme != "https"
        or not public.hostname
        or public.username
        or public.password
    ):
        raise BaserowError("baserow_public_url_not_safe_https")
    return {
        "ok": True,
        "imagesExact": True,
        "loopbackOnly": True,
        "databaseIsolated": (
            values["BASEROW_DB_NAME"] == "baserow"
            and values["BASEROW_DB_USER"] == "baserow"
        ),
        "redisIsolated": True,
        "redisDatabase": int(values["BASEROW_REDIS_DB"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=("preflight", "database", "provision", "verify", "canary", "all"),
    )
    args = parser.parse_args()
    try:
        if SECRET_ROOT == UNCONFIGURED_SECRET_ROOT:
            raise BaserowError("missing_runtime_env:MTE_SECRETS_ROOT")
        values = parse_env(CANONICAL_ENV)
        if args.action == "preflight":
            result = preflight(values)
        elif args.action == "database":
            result = ensure_database(values)
        elif args.action == "provision":
            result = provision(values)
        elif args.action == "canary":
            result = restart_persistence_canary(values)
        elif args.action == "verify":
            result = verify(values, restart_canary=True)
            write_evidence(result)
        else:
            preflight_result = preflight(values)
            database_result = ensure_database(values)
            provision_result = provision(values)
            values = parse_env(CANONICAL_ENV)
            result = verify(values, restart_canary=True)
            result["preflight"] = preflight_result
            result["database"] = database_result
            result["provision"] = provision_result
            write_evidence(result)
        print(json.dumps(result, indent=2, sort_keys=True))
    except (BaserowError, ApiError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {"status": "failed", "reason": str(exc), "evidence": str(EVIDENCE)},
                indent=2,
                sort_keys=True,
            )
        )
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()

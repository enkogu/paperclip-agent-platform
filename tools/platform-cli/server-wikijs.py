#!/usr/bin/env python3
"""Provision and prove the isolated Wiki.js documentation plane."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import time
from typing import Any
import urllib.error
import urllib.request

import yaml


ROOT = Path(os.environ.get("MTE_PLATFORM_ROOT", "/opt/mte-platform"))
SECRET_ROOT = Path(os.environ.get("MTE_SECRET_ROOT", "/root/.config/mte-secrets"))
CANONICAL = SECRET_ROOT / "platform.env"
LOCK = SECRET_ROOT / ".platform-env.lock"
EVIDENCE = ROOT / "evidence/wikijs-verify.json"
PLATFORM_LOCK = ROOT / "config/platform.lock.yaml"
EVIDENCE_KIND = "WikiJsVerification"
UPSTREAM_COMMIT = "6f042e97cc2d3acda6b6ff611de8e0faacce91c1"
LICENSE_SPDX = "AGPL-3.0-only"
LICENSE_SOURCE = "https://github.com/requarks/wiki/blob/v2.5.314/LICENSE"
IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
MANAGED_CANONICAL_KEYS = frozenset({"WIKIJS_API_TOKEN", "WIKIJS_API_TOKEN_ID"})


class WikiError(RuntimeError):
    """Fail-closed error with a secret-safe message."""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode())


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def fingerprint(value: str) -> str:
    return sha256_text(value)[:16]


def release_contract(values: dict[str, str]) -> dict[str, str]:
    """Bind runtime evidence to the reviewed immutable platform lock."""
    require(values, "MTE_WIKIJS_WIKI_IMAGE")
    try:
        document = yaml.safe_load(PLATFORM_LOCK.read_text())
        api_version = document["apiVersion"]
        locked_image = document["spec"]["images"]["wikijs"]
    except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
        raise WikiError("platform_lock_wikijs_contract_invalid") from exc
    if not isinstance(api_version, str) or not re.fullmatch(
        r"[a-z0-9.-]+/v[0-9]+(?:alpha|beta)?[0-9]*", api_version
    ):
        raise WikiError("platform_lock_api_version_invalid")
    canonical_image = values["MTE_WIKIJS_WIKI_IMAGE"]
    if canonical_image != locked_image:
        raise WikiError("wikijs_image_not_bound_to_platform_lock")
    match = re.fullmatch(
        r"ghcr\.io/requarks/wiki:"
        r"(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)"
        r"@(?P<digest>sha256:[0-9a-f]{64})",
        canonical_image,
    )
    if not match:
        raise WikiError("wikijs_locked_image_invalid")
    return {
        "apiVersion": api_version,
        "imageRef": canonical_image,
        "version": match.group("version"),
        "digest": match.group("digest"),
    }


def dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        raise WikiError("canonical_env_missing")
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key] = value
    return values


def require(values: dict[str, str], *keys: str) -> None:
    missing = sorted(key for key in keys if not values.get(key))
    if missing:
        raise WikiError("missing_canonical_refs:" + ",".join(missing))


def validate_identifier(value: str, label: str) -> str:
    if not IDENTIFIER.fullmatch(value):
        raise WikiError(f"invalid_{label}_identifier")
    return value


def sql_identifier(value: str, label: str) -> str:
    return '"' + validate_identifier(value, label) + '"'


def sql_literal(value: str) -> str:
    if not value or "\n" in value or "\r" in value or "\x00" in value:
        raise WikiError("invalid_sql_secret")
    return "'" + value.replace("'", "''") + "'"


def run(
    argv: list[str],
    *,
    check: bool = True,
    capture: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=check,
        text=True,
        input=input_text,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def postgres_container() -> str:
    result = run(
        [
            "docker",
            "ps",
            "-q",
            "--filter",
            "label=com.docker.compose.project=mte-postgres",
            "--filter",
            "label=com.docker.compose.service=postgres",
        ]
    )
    matches = result.stdout.strip().splitlines()
    if len(matches) != 1:
        raise WikiError("postgres_container_not_unique")
    return matches[0]


def wiki_container() -> str:
    result = run(
        [
            "docker",
            "ps",
            "-q",
            "--filter",
            "label=com.docker.compose.project=mte-wikijs",
            "--filter",
            "label=com.docker.compose.service=wiki",
        ]
    )
    matches = result.stdout.strip().splitlines()
    if len(matches) != 1:
        raise WikiError("wikijs_container_not_unique")
    return matches[0]


def psql(container_id: str, user: str, database: str, sql: str) -> str:
    result = run(
        [
            "docker",
            "exec",
            "-i",
            container_id,
            "psql",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-At",
            "-U",
            user,
            "-d",
            database,
        ],
        input_text=sql,
    )
    return result.stdout.strip()


def database_state(values: dict[str, str]) -> dict[str, Any]:
    require(
        values,
        "POSTGRES_ADMIN_USER",
        "WIKIJS_DB_NAME",
        "WIKIJS_DB_USER",
        "WIKIJS_DB_PASSWORD",
    )
    superuser = validate_identifier(values["POSTGRES_ADMIN_USER"], "postgres_superuser")
    database = validate_identifier(values["WIKIJS_DB_NAME"], "wikijs_database")
    role = validate_identifier(values["WIKIJS_DB_USER"], "wikijs_role")
    container_id = postgres_container()
    row = psql(
        container_id,
        superuser,
        "postgres",
        (
            "SELECT d.datname || '|' || r.rolname "
            "FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba "
            f"WHERE d.datname={sql_literal(database)};"
        ),
    )
    name, separator, owner = row.partition("|")
    return {
        "type": "postgres",
        "name": name,
        "user": role,
        "owner": owner,
        "isIsolated": name == database and role != superuser,
        "ownerMatches": bool(separator) and owner == role,
    }


def database() -> dict[str, Any]:
    values = dotenv(CANONICAL)
    require(
        values,
        "POSTGRES_ADMIN_USER",
        "WIKIJS_DB_NAME",
        "WIKIJS_DB_USER",
        "WIKIJS_DB_PASSWORD",
    )
    superuser = validate_identifier(values["POSTGRES_ADMIN_USER"], "postgres_superuser")
    database_name = validate_identifier(values["WIKIJS_DB_NAME"], "wikijs_database")
    role_name = validate_identifier(values["WIKIJS_DB_USER"], "wikijs_role")
    if role_name == superuser:
        raise WikiError("wikijs_role_not_isolated")
    container_id = postgres_container()
    role_exists = (
        psql(
            container_id,
            superuser,
            "postgres",
            f"SELECT 1 FROM pg_roles WHERE rolname={sql_literal(role_name)};",
        )
        == "1"
    )
    role_sql = (
        f"ALTER ROLE {sql_identifier(role_name, 'wikijs_role')} LOGIN PASSWORD "
        f"{sql_literal(values['WIKIJS_DB_PASSWORD'])};"
        if role_exists
        else f"CREATE ROLE {sql_identifier(role_name, 'wikijs_role')} LOGIN PASSWORD "
        f"{sql_literal(values['WIKIJS_DB_PASSWORD'])};"
    )
    psql(container_id, superuser, "postgres", role_sql)
    database_exists = (
        psql(
            container_id,
            superuser,
            "postgres",
            f"SELECT 1 FROM pg_database WHERE datname={sql_literal(database_name)};",
        )
        == "1"
    )
    if not database_exists:
        run(
            [
                "docker",
                "exec",
                container_id,
                "createdb",
                "-U",
                superuser,
                "-O",
                role_name,
                database_name,
            ]
        )
    psql(
        container_id,
        superuser,
        "postgres",
        (
            f"ALTER DATABASE {sql_identifier(database_name, 'wikijs_database')} "
            f"OWNER TO {sql_identifier(role_name, 'wikijs_role')};"
            f"REVOKE ALL ON DATABASE {sql_identifier(database_name, 'wikijs_database')} "
            "FROM PUBLIC;"
            f"GRANT ALL ON DATABASE {sql_identifier(database_name, 'wikijs_database')} "
            f"TO {sql_identifier(role_name, 'wikijs_role')};"
        ),
    )
    psql(
        container_id,
        superuser,
        database_name,
        (
            f"ALTER SCHEMA public OWNER TO {sql_identifier(role_name, 'wikijs_role')};"
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC;"
            f"GRANT USAGE,CREATE ON SCHEMA public TO "
            f"{sql_identifier(role_name, 'wikijs_role')};"
        ),
    )
    state = database_state(values)
    if not state["isIsolated"] or not state["ownerMatches"]:
        raise WikiError("wikijs_database_isolation_failed")
    return {"ok": True, "status": "passed", "database": state}


def base_url(values: dict[str, str]) -> str:
    require(values, "WIKIJS_ORIGIN_PORT")
    try:
        port = int(values["WIKIJS_ORIGIN_PORT"])
    except ValueError as exc:
        raise WikiError("wikijs_origin_port_invalid") from exc
    if not 1024 <= port <= 65535:
        raise WikiError("wikijs_origin_port_invalid")
    return f"http://127.0.0.1:{port}"


def request_json(
    method: str,
    url: str,
    *,
    body: Any | None = None,
    token: str = "",
    timeout: int = 45,
) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(4_000_000)
    except urllib.error.HTTPError as exc:
        raise WikiError(f"wikijs_http_{exc.code}") from None
    except urllib.error.URLError:
        raise WikiError("wikijs_unreachable") from None
    try:
        return json.loads(raw) if raw else None
    except json.JSONDecodeError:
        raise WikiError("wikijs_response_not_json") from None


def graphql(
    base: str,
    query: str,
    *,
    variables: dict[str, Any] | None = None,
    token: str = "",
) -> dict[str, Any]:
    value = request_json(
        "POST",
        base + "/graphql",
        token=token,
        body={"query": query, "variables": variables or {}},
    )
    if (
        not isinstance(value, dict)
        or value.get("errors")
        or not isinstance(value.get("data"), dict)
    ):
        raise WikiError("wikijs_graphql_failed")
    return value["data"]


def system_info(base: str, token: str = "") -> dict[str, Any]:
    data = graphql(
        base,
        "query { system { info { currentVersion dbType dbHost } } }",
        token=token,
    )
    info = (
        data.get("system", {}).get("info")
        if isinstance(data.get("system"), dict)
        else None
    )
    if not isinstance(info, dict):
        raise WikiError("wikijs_system_info_missing")
    return info


def wait_ready(base: str, *, token: str = "", timeout: int = 120) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return system_info(base, token)
        except WikiError:
            time.sleep(2)
    raise WikiError("wikijs_readiness_timeout")


def setup_required(base: str, expected_version: str) -> bool:
    try:
        info = system_info(base)
    except WikiError:
        return True
    return info.get("currentVersion") != expected_version


def finalize_setup(base: str, values: dict[str, str]) -> bool:
    require(values, "WIKIJS_ADMIN_EMAIL", "WIKIJS_ADMIN_PASSWORD", "WIKIJS_SITE_URL")
    if not setup_required(base, release_contract(values)["version"]):
        return False
    site_url = values["WIKIJS_SITE_URL"]
    if not site_url.startswith("https://") or site_url.endswith("/"):
        raise WikiError("wikijs_site_url_invalid")
    if (
        "@" not in values["WIKIJS_ADMIN_EMAIL"]
        or len(values["WIKIJS_ADMIN_PASSWORD"]) < 8
    ):
        raise WikiError("wikijs_admin_seed_invalid")
    response = request_json(
        "POST",
        base + "/finalize",
        body={
            "adminEmail": values["WIKIJS_ADMIN_EMAIL"],
            "adminPassword": values["WIKIJS_ADMIN_PASSWORD"],
            "adminPasswordConfirm": values["WIKIJS_ADMIN_PASSWORD"],
            "siteUrl": site_url,
            "telemetry": False,
        },
    )
    if not isinstance(response, dict) or response.get("ok") is not True:
        raise WikiError("wikijs_setup_finalize_failed")
    wait_ready(base)
    return True


def admin_login(base: str, values: dict[str, str]) -> str:
    require(values, "WIKIJS_ADMIN_EMAIL", "WIKIJS_ADMIN_PASSWORD")
    data = graphql(
        base,
        """
        mutation Login($username: String!, $password: String!) {
          authentication {
            login(username: $username, password: $password, strategy: "local") {
              jwt
              responseResult { succeeded }
            }
          }
        }
        """,
        variables={
            "username": values["WIKIJS_ADMIN_EMAIL"],
            "password": values["WIKIJS_ADMIN_PASSWORD"],
        },
    )
    login = data.get("authentication", {}).get("login")
    if (
        not isinstance(login, dict)
        or login.get("responseResult", {}).get("succeeded") is not True
    ):
        raise WikiError("wikijs_admin_login_failed")
    token = str(login.get("jwt") or "")
    if not token:
        raise WikiError("wikijs_admin_session_missing")
    return token


def api_snapshot(base: str, admin_token: str) -> tuple[bool, list[dict[str, Any]]]:
    data = graphql(
        base,
        """
        query ApiState {
          authentication {
            apiState
            apiKeys { id name keyShort expiration isRevoked }
          }
        }
        """,
        token=admin_token,
    )
    auth = data.get("authentication")
    if not isinstance(auth, dict) or not isinstance(auth.get("apiKeys"), list):
        raise WikiError("wikijs_api_state_missing")
    return auth.get("apiState") is True, [
        row for row in auth["apiKeys"] if isinstance(row, dict)
    ]


def set_api_state(base: str, admin_token: str) -> None:
    data = graphql(
        base,
        """
        mutation EnableApi {
          authentication { setApiState(enabled: true) { succeeded } }
        }
        """,
        token=admin_token,
    )
    result = data.get("authentication", {}).get("setApiState")
    if not isinstance(result, dict) or result.get("succeeded") is not True:
        raise WikiError("wikijs_api_enable_failed")


def revoke_api_key(base: str, admin_token: str, key_id: int) -> None:
    data = graphql(
        base,
        """
        mutation Revoke($id: Int!) {
          authentication { revokeApiKey(id: $id) { succeeded } }
        }
        """,
        variables={"id": key_id},
        token=admin_token,
    )
    result = data.get("authentication", {}).get("revokeApiKey")
    if not isinstance(result, dict) or result.get("succeeded") is not True:
        raise WikiError("wikijs_api_key_revoke_failed")


def create_api_key(base: str, admin_token: str, name: str, expiration: str) -> str:
    data = graphql(
        base,
        """
        mutation Create($name: String!, $expiration: String!) {
          authentication {
            createApiKey(name: $name, expiration: $expiration, fullAccess: true) {
              key
              responseResult { succeeded }
            }
          }
        }
        """,
        variables={"name": name, "expiration": expiration},
        token=admin_token,
    )
    created = data.get("authentication", {}).get("createApiKey")
    if (
        not isinstance(created, dict)
        or created.get("responseResult", {}).get("succeeded") is not True
    ):
        raise WikiError("wikijs_api_key_create_failed")
    token = str(created.get("key") or "")
    if len(token) < 40:
        raise WikiError("wikijs_api_key_invalid")
    return token


def bearer_works(base: str, token: str, expected_version: str) -> bool:
    if not token:
        return False
    try:
        info = system_info(base, token)
    except WikiError:
        return False
    return info.get("currentVersion") == expected_version


def write_canonical_updates(updates: dict[str, str]) -> None:
    if not updates or not set(updates).issubset(MANAGED_CANONICAL_KEYS):
        raise WikiError("wikijs_canonical_update_not_authorized")
    SECRET_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    with LOCK.open("a+") as handle:
        LOCK.chmod(0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        source_stat = CANONICAL.stat()
        if stat.S_IMODE(source_stat.st_mode) != 0o600:
            raise WikiError("canonical_env_permissions_invalid")
        if os.geteuid() == 0 and (source_stat.st_uid, source_stat.st_gid) != (0, 0):
            raise WikiError("canonical_env_ownership_invalid")
        values = dotenv(CANONICAL)
        values.update(updates)
        temporary = CANONICAL.with_suffix(".env.tmp")
        temporary.write_text(
            "".join(f"{key}={values[key]}\n" for key in sorted(values))
        )
        temporary.chmod(0o600)
        temporary.replace(CANONICAL)
        CANONICAL.chmod(0o600)
        if os.geteuid() == 0:
            os.chown(CANONICAL, 0, 0)
            os.chown(LOCK, 0, 0)


def managed_api_key(
    base: str, values: dict[str, str], admin_token: str
) -> dict[str, Any]:
    require(values, "WIKIJS_API_KEY_NAME", "WIKIJS_API_KEY_EXPIRATION")
    name = values["WIKIJS_API_KEY_NAME"]
    if not 2 <= len(name) <= 255:
        raise WikiError("wikijs_api_key_name_invalid")
    api_enabled, rows = api_snapshot(base, admin_token)
    mutations = 0
    if not api_enabled:
        set_api_state(base, admin_token)
        mutations += 1
        api_enabled = True
    active = [
        row for row in rows if row.get("name") == name and row.get("isRevoked") is False
    ]
    canonical_token = values.get("WIKIJS_API_TOKEN", "")
    canonical_id = values.get("WIKIJS_API_TOKEN_ID", "")
    expected_version = release_contract(values)["version"]
    exact = [
        row
        for row in active
        if str(row.get("id")) == canonical_id
        and canonical_token.endswith(str(row.get("keyShort") or "").removeprefix("..."))
    ]
    if (
        len(active) == 1
        and len(exact) == 1
        and bearer_works(base, canonical_token, expected_version)
    ):
        return {
            "apiEnabled": api_enabled,
            "apiKeyId": int(exact[0]["id"]),
            "apiKeyName": name,
            "apiTokenFingerprint": fingerprint(canonical_token),
            "mutations": mutations,
        }
    for row in active:
        revoke_api_key(base, admin_token, int(row["id"]))
        mutations += 1
    token = create_api_key(base, admin_token, name, values["WIKIJS_API_KEY_EXPIRATION"])
    mutations += 1
    _, refreshed = api_snapshot(base, admin_token)
    matching = [
        row
        for row in refreshed
        if row.get("name") == name
        and row.get("isRevoked") is False
        and token.endswith(str(row.get("keyShort") or "").removeprefix("..."))
    ]
    if len(matching) != 1 or not bearer_works(base, token, expected_version):
        raise WikiError("wikijs_api_key_reconcile_failed")
    key_id = int(matching[0]["id"])
    write_canonical_updates(
        {"WIKIJS_API_TOKEN": token, "WIKIJS_API_TOKEN_ID": str(key_id)}
    )
    return {
        "apiEnabled": True,
        "apiKeyId": key_id,
        "apiKeyName": name,
        "apiTokenFingerprint": fingerprint(token),
        "mutations": mutations,
    }


def provision_once() -> dict[str, Any]:
    values = dotenv(CANONICAL)
    base = base_url(values)
    setup_mutated = finalize_setup(base, values)
    admin_token = admin_login(base, values)
    result = managed_api_key(base, values, admin_token)
    result["setupMutated"] = setup_mutated
    result["mutations"] += int(setup_mutated)
    return result


def provision() -> dict[str, Any]:
    first = provision_once()
    second = provision_once()
    if second["mutations"] != 0:
        raise WikiError("wikijs_second_provision_not_noop")
    return {
        "ok": True,
        "status": "passed",
        "firstRunMutations": first["mutations"],
        "secondRunNoOp": True,
        "apiEnabled": second["apiEnabled"],
        "apiKeyId": second["apiKeyId"],
        "apiKeyName": second["apiKeyName"],
        "apiTokenFingerprint": second["apiTokenFingerprint"],
    }


def response_succeeded(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("responseResult", {}).get("succeeded") is True
    )


def create_page(base: str, token: str, path: str, content: str) -> int:
    data = graphql(
        base,
        """
        mutation CreatePage($path: String!, $content: String!) {
          pages {
            create(
              content: $content, description: "MTE verification page",
              editor: "markdown", isPublished: true, isPrivate: true,
              locale: "en", path: $path, tags: ["mte-verification"],
              title: "MTE Wiki Verification"
            ) { responseResult { succeeded } page { id } }
          }
        }
        """,
        variables={"path": path, "content": content},
        token=token,
    )
    created = data.get("pages", {}).get("create")
    if not response_succeeded(created) or not created.get("page", {}).get("id"):
        raise WikiError("wikijs_page_create_failed")
    return int(created["page"]["id"])


def update_page(base: str, token: str, page_id: int, content: str) -> None:
    data = graphql(
        base,
        """
        mutation UpdatePage($id: Int!, $content: String!) {
          pages { update(id: $id, content: $content) { responseResult { succeeded } page { id } } }
        }
        """,
        variables={"id": page_id, "content": content},
        token=token,
    )
    updated = data.get("pages", {}).get("update")
    if (
        not response_succeeded(updated)
        or int(updated.get("page", {}).get("id") or 0) != page_id
    ):
        raise WikiError("wikijs_page_update_failed")


def read_page(base: str, token: str, page_id: int) -> dict[str, Any] | None:
    try:
        data = graphql(
            base,
            """
            query ReadPage($id: Int!) {
              pages { single(id: $id) { id path content } }
            }
            """,
            variables={"id": page_id},
            token=token,
        )
    except WikiError as exc:
        if str(exc) == "wikijs_graphql_failed":
            return None
        raise
    value = data.get("pages", {}).get("single")
    return value if isinstance(value, dict) else None


def delete_page(base: str, token: str, page_id: int) -> None:
    data = graphql(
        base,
        """
        mutation DeletePage($id: Int!) {
          pages { delete(id: $id) { succeeded } }
        }
        """,
        variables={"id": page_id},
        token=token,
    )
    result = data.get("pages", {}).get("delete")
    if not isinstance(result, dict) or result.get("succeeded") is not True:
        raise WikiError("wikijs_page_delete_failed")


def http_status(url: str) -> int:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except urllib.error.URLError:
        raise WikiError("wikijs_unreachable") from None


def container_snapshot(container_id: str) -> dict[str, Any]:
    result = run(["docker", "inspect", container_id])
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise WikiError("wikijs_container_inspect_invalid") from exc
    if not isinstance(rows, list) or len(rows) != 1:
        raise WikiError("wikijs_container_inspect_invalid")
    row = rows[0]
    return {
        "id": str(row.get("Id") or "")[:12],
        "name": str(row.get("Name") or "").removeprefix("/"),
        "image": str(row.get("Config", {}).get("Image") or ""),
        "restartCount": int(row.get("RestartCount") or 0),
        "startedAt": str(row.get("State", {}).get("StartedAt") or ""),
    }


def atomic_evidence(value: dict[str, Any]) -> None:
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    temporary = EVIDENCE.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(EVIDENCE)
    EVIDENCE.chmod(0o600)
    if os.geteuid() == 0:
        os.chown(EVIDENCE, 0, 0)


def verify() -> dict[str, Any]:
    bootstrap = provision()
    values = dotenv(CANONICAL)
    release = release_contract(values)
    require(
        values,
        "MTE_WIKIJS_WIKI_IMAGE",
        "WIKIJS_DB_HOST",
        "WIKIJS_DB_NAME",
        "WIKIJS_DB_USER",
        "WIKIJS_API_TOKEN",
        "WIKIJS_API_TOKEN_ID",
        "WIKIJS_API_KEY_NAME",
    )
    base = base_url(values)
    token = values["WIKIJS_API_TOKEN"]
    info = system_info(base, token)
    if info != {
        "currentVersion": release["version"],
        "dbType": "postgres",
        "dbHost": values["WIKIJS_DB_HOST"],
    }:
        raise WikiError("wikijs_system_contract_drift")
    db = database_state(values)
    if not db["isIsolated"] or not db["ownerMatches"]:
        raise WikiError("wikijs_database_contract_drift")
    container_id = wiki_container()
    before = container_snapshot(container_id)
    if before["image"] != values["MTE_WIKIJS_WIKI_IMAGE"]:
        raise WikiError("wikijs_container_image_drift")
    path = "mte-verification/" + secrets.token_hex(12)
    content = "mte-wikijs-marker-" + secrets.token_hex(24)
    updated_content = content + "-updated"
    page_id: int | None = None
    cleaned = False
    try:
        page_id = create_page(base, token, path, content)
        update_page(base, token, page_id, updated_content)
        before_restart_page = read_page(base, token, page_id)
        if (
            not before_restart_page
            or int(before_restart_page.get("id") or 0) != page_id
            or before_restart_page.get("path") != path
            or before_restart_page.get("content") != updated_content
        ):
            raise WikiError("wikijs_page_before_restart_drift")
        run(["docker", "restart", container_id])
        wait_ready(base, token=token)
        after = container_snapshot(container_id)
        after_restart_page = read_page(base, token, page_id)
        if (
            not after_restart_page
            or int(after_restart_page.get("id") or 0) != page_id
            or after_restart_page.get("path") != path
            or after_restart_page.get("content") != updated_content
        ):
            raise WikiError("wikijs_page_restart_persistence_failed")
        delete_page(base, token, page_id)
        missing = read_page(base, token, page_id) is None
        deleted_status = http_status(base + "/" + path)
        cleaned = missing and deleted_status == 404
        if not cleaned:
            raise WikiError("wikijs_page_cleanup_failed")
    finally:
        if page_id is not None and not cleaned:
            try:
                delete_page(base, token, page_id)
            except WikiError:
                pass
    canonical_sha = sha256_path(CANONICAL)
    producer_sha = sha256_path(Path(__file__))
    evidence: dict[str, Any] = {
        "apiVersion": release["apiVersion"],
        "kind": EVIDENCE_KIND,
        "ok": True,
        "status": "passed",
        "generatedAt": utcnow(),
        "canonicalSourceSha256": canonical_sha,
        "producerSha256": producer_sha,
        "image": {
            "ref": release["imageRef"],
            "digest": release["digest"],
            "version": release["version"],
            "upstreamCommit": UPSTREAM_COMMIT,
            "license": {"spdx": LICENSE_SPDX, "source": LICENSE_SOURCE},
        },
        "database": db,
        "bootstrap": {
            "adminId": 1,
            "apiEnabled": bootstrap["apiEnabled"],
            "apiKeyId": bootstrap["apiKeyId"],
            "apiKeyName": bootstrap["apiKeyName"],
            "secondRunNoOp": bootstrap["secondRunNoOp"],
            "apiTokenFingerprint": bootstrap["apiTokenFingerprint"],
        },
        "graphql": {
            "bearerAuthenticated": True,
            "pageId": page_id,
            "pathHashSha256": sha256_text(path),
            "markerSha256": sha256_text(updated_content),
            "beforeRestartPageId": int(before_restart_page["id"]),
            "afterRestartPageId": int(after_restart_page["id"]),
            "restartObserved": bool(after["startedAt"])
            and after["startedAt"] != before["startedAt"],
            "persistenceVerified": int(after_restart_page["id"]) == page_id,
            "postDeleteGraphqlMissing": missing,
            "postDeleteStatus404": deleted_status,
            "cleanupCompleted": cleaned,
        },
        "container": {
            "id": after["id"],
            "name": after["name"],
            "image": after["image"],
            "restartCountBefore": before["restartCount"],
            "restartCountAfter": after["restartCount"],
            "startedAtBefore": before["startedAt"],
            "startedAtAfter": after["startedAt"],
        },
        "secretAudit": {"rawSecretsPresent": False, "contentMarkerPresent": False},
        "evidence": {
            "path": str(EVIDENCE),
            "mode": "0600",
            "uid": 0 if os.geteuid() == 0 else os.geteuid(),
            "gid": 0 if os.geteuid() == 0 else os.getegid(),
        },
    }
    serialized = json.dumps(evidence, sort_keys=True)
    sensitive = [
        value
        for key, value in values.items()
        if value
        and (
            key.endswith("_PASSWORD")
            or key.endswith("_TOKEN")
            or key.endswith("_SECRET")
            or key.endswith("_API_KEY")
        )
    ]
    if (
        any(secret in serialized for secret in sensitive)
        or content in serialized
        or path in serialized
    ):
        raise WikiError("wikijs_evidence_contains_sensitive_material")
    if not evidence["graphql"]["restartObserved"]:
        raise WikiError("wikijs_restart_not_observed")
    atomic_evidence(evidence)
    mode = stat.S_IMODE(EVIDENCE.stat().st_mode)
    if mode != 0o600 or (
        os.geteuid() == 0 and (EVIDENCE.stat().st_uid, EVIDENCE.stat().st_gid) != (0, 0)
    ):
        raise WikiError("wikijs_evidence_permissions_invalid")
    return evidence


def status() -> dict[str, Any]:
    values = dotenv(CANONICAL)
    release = release_contract(values)
    base = base_url(values)
    info = system_info(base, values.get("WIKIJS_API_TOKEN", ""))
    target = wiki_container()
    snapshot = container_snapshot(target)
    return {
        "ok": info.get("currentVersion") == release["version"],
        "version": info.get("currentVersion"),
        "database": {"type": info.get("dbType"), "host": info.get("dbHost")},
        "container": snapshot,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("database", "provision", "status", "verify"))
    args = parser.parse_args()
    action = {
        "database": database,
        "provision": provision,
        "status": status,
        "verify": verify,
    }[args.action]
    try:
        result = action()
    except WikiError as exc:
        print(json.dumps({"ok": False, "status": "failed", "reason": str(exc)}))
        raise SystemExit(1) from None
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

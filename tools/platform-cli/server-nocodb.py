#!/usr/bin/env python3
"""Provision NocoDB as a replaceable UI and verify licensed NocoDocs live."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

import yaml


ROOT = Path(os.environ.get("MTE_PLATFORM_ROOT", "/opt/mte-platform"))
SECRET_ROOT = Path(
    os.environ.get(
        "MTE_SECRETS_ROOT",
        os.environ.get("MTE_SECRET_ROOT", "/root/.config/mte-secrets"),
    )
)
CANONICAL = SECRET_ROOT / "platform.env"
CANONICAL_LOCK = SECRET_ROOT / ".platform-env.lock"
LOCK = ROOT / "templates/platform.lock.yaml"
EVIDENCE = ROOT / "evidence/nocodb-verify.json"
PROFILE = "postgres-postgrest-nocodb-nocodocs"
IMAGE = "nocodb/nocodb:2026.06.2@sha256:0745850b14869bde4c972181c52607d72b1f3f85b9f7c96180803f0ced76e465"
LICENSE_ID = "LicenseRef-NocoDB-Sustainable-Use-1.0"
LICENSE_EXCEPTION = {
    "component": "nocodb",
    "scope": "internal-self-hosted-tables-ui-and-nocodocs",
    "approval": "user-approved-2026-07-15",
    "source": "https://github.com/nocodb/nocodb/blob/2026.06.2/LICENSE.md",
}
INACTIVE_ACTIVATION_BLOCKERS = [
    "inactive optional provider; requires explicit operator activation and refreshed license acceptance"
]
REVIEWED_ADAPTER = {
    "script": "server-nocodb.py",
    "providerId": "nocodb",
    "componentId": "nocodb",
    "capabilities": ["tables", "documents"],
    "actions": ["database", "provision", "verify"],
}
REVIEWED_PROVIDER = {
    "kind": "self-hosted-workspace",
    "deployment": "profile-component",
    "componentId": "nocodb",
    "capabilities": {
        "tables": {"interfaces": ["ui", "api"], "configurationRefs": []},
        "documents": {"interfaces": ["ui", "api"], "configurationRefs": []},
    },
    "adapterIds": ["nocodb"],
}
REVIEWED_ROLES = {
    role: {
        "providerId": "nocodb",
        "capability": capability,
        "interface": interface,
        "endpointRef": "NOCODB_PUBLIC_URL",
        "adapterId": "nocodb",
    }
    for role, capability, interface in (
        ("tablesUi", "tables", "ui"),
        ("tablesApi", "tables", "api"),
        ("documentsUi", "documents", "ui"),
        ("documentsApi", "documents", "api"),
    )
}
REVIEWED_CANONICAL_PREFIXES = [
    "POSTGREST_",
    "NOCODB_",
    "MTE_POSTGREST_",
    "MTE_NOCODB_",
]
TOKEN_DESCRIPTION = "MTE NocoDB verification"
SOURCE_ALIAS = "MTE PostgreSQL SSOT"
GENERATED_REFS = {
    "NOCODB_API_TOKEN",
    "NOCODB_API_TOKEN_ID",
    "NOCODB_API_TOKEN_SHA256",
    "NOCODB_BASE_ID",
    "NOCODB_SOURCE_ID",
    "NOCODB_TABLE_ID",
}
REQUIRED_REFS = {
    "DATA_CONTENT_PROFILE",
    "POSTGRES_ADMIN_DB",
    "POSTGRES_ADMIN_USER",
    "POSTGREST_DATA_DB_NAME",
    "POSTGREST_DATA_DB_USER",
    "POSTGREST_WRITER_ROLE",
    "POSTGREST_PAPERCLIP_ROLE",
    "POSTGREST_ACTIVEPIECES_ROLE",
    "POSTGREST_JWT_SECRET",
    "POSTGREST_API_AUDIENCE",
    "POSTGREST_ORIGIN_PORT",
    "NOCODB_DB_HOST",
    "NOCODB_DB_PORT",
    "NOCODB_DB_SSLMODE",
    "NOCODB_META_DB_NAME",
    "NOCODB_META_DB_USER",
    "NOCODB_META_DB_PASSWORD",
    "NOCODB_DATA_DB_USER",
    "NOCODB_DATA_DB_PASSWORD",
    "NOCODB_ADMIN_EMAIL",
    "NOCODB_ADMIN_PASSWORD",
    "NOCODB_BASE_TITLE",
    "NOCODB_TABLE_TITLE",
    "NOCODB_HEALTH_URL",
    "NOCODB_ORIGIN_PORT",
}
IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class NocoError(RuntimeError):
    def __init__(self, code: str, *, status: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dotenv(path: Path = CANONICAL) -> dict[str, str]:
    if not path.is_file():
        raise NocoError("canonical_env_missing")
    values: dict[str, str] = {}
    for line_no, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise NocoError(f"canonical_env_invalid_line:{line_no}")
        key, value = line.split("=", 1)
        if key in values:
            raise NocoError(f"canonical_env_duplicate_key:{key}")
        values[key] = value
    return values


def require_values(values: dict[str, str], *, provisioned: bool = False) -> None:
    required = set(REQUIRED_REFS)
    if provisioned:
        required.update(GENERATED_REFS)
    missing = sorted(key for key in required if not values.get(key))
    if missing:
        raise NocoError("missing_canonical_refs:" + ",".join(missing))
    if values["DATA_CONTENT_PROFILE"] != PROFILE:
        raise NocoError("provider_profile_not_selected")
    for key in (
        "POSTGRES_ADMIN_DB",
        "POSTGRES_ADMIN_USER",
        "POSTGREST_DATA_DB_NAME",
        "POSTGREST_DATA_DB_USER",
        "POSTGREST_WRITER_ROLE",
        "POSTGREST_PAPERCLIP_ROLE",
        "POSTGREST_ACTIVEPIECES_ROLE",
        "NOCODB_META_DB_NAME",
        "NOCODB_META_DB_USER",
        "NOCODB_DATA_DB_USER",
    ):
        if not IDENTIFIER.fullmatch(values[key]):
            raise NocoError(f"invalid_identifier:{key}")
    if (
        len(
            {
                values["NOCODB_META_DB_USER"],
                values["NOCODB_DATA_DB_USER"],
                values["POSTGREST_WRITER_ROLE"],
                values["POSTGREST_PAPERCLIP_ROLE"],
                values["POSTGREST_ACTIVEPIECES_ROLE"],
            }
        )
        != 5
    ):
        raise NocoError("nocodb_database_roles_not_distinct")
    if values["NOCODB_DB_HOST"] != "mte-postgres" or values["NOCODB_DB_PORT"] != "5432":
        raise NocoError("nocodb_database_not_shared_data_plane")


def release_contract(*, activation_requested: bool = False) -> dict[str, Any]:
    """Validate the exact reviewed inactive release contract.

    The legacy provider remains inspectable by static checks, but no operational
    command may activate it merely by selecting its profile in the environment.
    Reactivation requires a new reviewed contract and refreshed license
    acceptance, so changes to either activation bit deliberately fail closed.
    """

    try:
        lock = yaml.safe_load(LOCK.read_text())
        bundle = lock["spec"]["dataContentProfiles"][PROFILE]
    except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
        raise NocoError("provider_lock_contract_invalid") from exc
    if (
        bundle.get("selectable") is not False
        or bundle.get("contractComplete") is not False
        or bundle.get("activationBlockers") != INACTIVE_ACTIVATION_BLOCKERS
        or bundle.get("images", {}).get("nocodb") != IMAGE
        or bundle.get("licenses", {}).get("nocodb") != LICENSE_ID
        or bundle.get("licenseExceptions", {}).get("nocodb") != LICENSE_EXCEPTION
        or bundle.get("adapters", {}).get("nocodb") != REVIEWED_ADAPTER
        or bundle.get("providers", {}).get("nocodb") != REVIEWED_PROVIDER
        or any(
            bundle.get("roles", {}).get(role) != expected
            for role, expected in REVIEWED_ROLES.items()
        )
        or bundle.get("canonicalKeyPrefixes") != REVIEWED_CANONICAL_PREFIXES
        or "nocodb" not in bundle.get("componentIds", [])
        or bundle.get("systemOfRecord")
        != {
            "providerId": "postgres",
            "componentId": "postgres",
            "ownership": "authoritative",
        }
    ):
        raise NocoError("nocodb_release_contract_drift")
    release = {
        "profile": PROFILE,
        "status": "reviewed-inactive",
        "selectable": False,
        "contractComplete": False,
        "activationBlockers": list(INACTIVE_ACTIVATION_BLOCKERS),
        "image": IMAGE,
        "license": LICENSE_ID,
        "exception": LICENSE_EXCEPTION,
    }
    if activation_requested:
        raise NocoError("provider_profile_inactive")
    return release


def run(
    argv: list[str], *, input_text: str | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if check and result.returncode:
        raise NocoError(f"command_failed:{Path(argv[0]).name}")
    return result


def unique_container(project: str, service: str) -> str:
    result = run(
        [
            "docker",
            "ps",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            f"label=com.docker.compose.service={service}",
        ]
    )
    rows = [row for row in result.stdout.splitlines() if row]
    if len(rows) != 1:
        raise NocoError(f"container_not_unique:{project}:{service}")
    return rows[0]


def psql(values: dict[str, str], database: str, sql: str) -> str:
    return run(
        [
            "docker",
            "exec",
            "-i",
            unique_container("mte-postgres", "postgres"),
            "psql",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-At",
            "-U",
            values["POSTGRES_ADMIN_USER"],
            "-d",
            database,
        ],
        input_text=sql,
    ).stdout.strip()


def sql_identifier(value: str) -> str:
    if not IDENTIFIER.fullmatch(value):
        raise NocoError("unsafe_database_identifier")
    return '"' + value + '"'


def sql_literal(value: str) -> str:
    if not value or any(character in value for character in ("\n", "\r", "\x00")):
        raise NocoError("unsafe_sql_value")
    return "'" + value.replace("'", "''") + "'"


def converge_login(values: dict[str, str], role: str, password: str) -> None:
    psql(
        values,
        values["POSTGRES_ADMIN_DB"],
        f"""
DO $mte$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname={sql_literal(role)}) THEN
    CREATE ROLE {sql_identifier(role)};
  END IF;
END
$mte$;
ALTER ROLE {sql_identifier(role)} LOGIN NOINHERIT NOCREATEDB NOCREATEROLE NOSUPERUSER NOREPLICATION NOBYPASSRLS PASSWORD {sql_literal(password)};
""",
    )


def converge_database(values: dict[str, str], name: str, owner: str) -> None:
    exists = psql(
        values,
        values["POSTGRES_ADMIN_DB"],
        f"SELECT 1 FROM pg_database WHERE datname={sql_literal(name)};",
    )
    if exists not in {"", "1"}:
        raise NocoError("database_existence_query_invalid")
    if not exists:
        psql(
            values,
            values["POSTGRES_ADMIN_DB"],
            f"CREATE DATABASE {sql_identifier(name)} OWNER {sql_identifier(owner)};",
        )
    psql(
        values,
        values["POSTGRES_ADMIN_DB"],
        f"ALTER DATABASE {sql_identifier(name)} OWNER TO {sql_identifier(owner)};",
    )


def verify_database_isolation(values: dict[str, str]) -> dict[str, bool]:
    meta_user = values["NOCODB_META_DB_USER"]
    data_user = values["NOCODB_DATA_DB_USER"]
    meta_db = values["NOCODB_META_DB_NAME"]
    data_db = values["POSTGREST_DATA_DB_NAME"]
    database_privileges = psql(
        values,
        values["POSTGRES_ADMIN_DB"],
        f"""
SELECT concat_ws('|',
  has_database_privilege({sql_literal(meta_user)}, {sql_literal(meta_db)}, 'CONNECT'),
  has_database_privilege({sql_literal(data_user)}, {sql_literal(meta_db)}, 'CONNECT'),
  has_database_privilege({sql_literal(meta_user)}, {sql_literal(data_db)}, 'CONNECT'),
  has_database_privilege({sql_literal(data_user)}, {sql_literal(data_db)}, 'CONNECT')
);
""",
    )
    if database_privileges != "t|f|f|t":
        raise NocoError("nocodb_database_connect_isolation_invalid")
    schema_privileges = psql(
        values,
        data_db,
        f"""
SELECT concat_ws('|',
  has_schema_privilege({sql_literal(meta_user)}, 'api', 'USAGE'),
  has_schema_privilege({sql_literal(data_user)}, 'api', 'USAGE'),
  has_table_privilege({sql_literal(meta_user)}, 'api.prototype_items', 'SELECT'),
  has_table_privilege({sql_literal(data_user)}, 'api.prototype_items', 'SELECT,INSERT,UPDATE,DELETE'),
  (SELECT count(*) FROM pg_policies WHERE schemaname='api' AND tablename='prototype_items' AND policyname='mte_nocodb_external_source_all' AND {sql_literal(data_user)}=ANY(roles))
);
""",
    )
    if schema_privileges != "f|t|f|t|1":
        raise NocoError("nocodb_data_schema_isolation_invalid")
    return {
        "metadataRoleConnectsMetadata": True,
        "externalSourceRoleDeniedMetadata": True,
        "metadataRoleDeniedData": True,
        "metadataRoleDeniedDataSchema": True,
        "externalSourceRoleConnectsData": True,
    }


def database() -> dict[str, Any]:
    values = dotenv()
    require_values(values)
    release_contract(activation_requested=True)
    meta_user = values["NOCODB_META_DB_USER"]
    data_user = values["NOCODB_DATA_DB_USER"]
    converge_login(values, meta_user, values["NOCODB_META_DB_PASSWORD"])
    converge_login(values, data_user, values["NOCODB_DATA_DB_PASSWORD"])
    converge_database(values, values["NOCODB_META_DB_NAME"], meta_user)
    data_db = values["POSTGREST_DATA_DB_NAME"]
    meta_db = values["NOCODB_META_DB_NAME"]
    admin_user = values["POSTGRES_ADMIN_USER"]
    psql(
        values,
        values["POSTGRES_ADMIN_DB"],
        f"""
REVOKE CONNECT ON DATABASE {sql_identifier(meta_db)} FROM PUBLIC;
REVOKE CONNECT ON DATABASE {sql_identifier(meta_db)} FROM {sql_identifier(data_user)};
GRANT CONNECT ON DATABASE {sql_identifier(meta_db)} TO {sql_identifier(meta_user)};
GRANT CONNECT ON DATABASE {sql_identifier(meta_db)} TO {sql_identifier(admin_user)};
REVOKE CONNECT ON DATABASE {sql_identifier(data_db)} FROM PUBLIC;
REVOKE CONNECT ON DATABASE {sql_identifier(data_db)} FROM {sql_identifier(meta_user)};
GRANT CONNECT ON DATABASE {sql_identifier(data_db)} TO {sql_identifier(data_user)};
GRANT CONNECT ON DATABASE {sql_identifier(data_db)} TO {sql_identifier(values["POSTGREST_DATA_DB_USER"])};
GRANT CONNECT ON DATABASE {sql_identifier(data_db)} TO {sql_identifier(values["POSTGREST_WRITER_ROLE"])};
GRANT CONNECT ON DATABASE {sql_identifier(data_db)} TO {sql_identifier(values["POSTGREST_PAPERCLIP_ROLE"])};
GRANT CONNECT ON DATABASE {sql_identifier(data_db)} TO {sql_identifier(values["POSTGREST_ACTIVEPIECES_ROLE"])};
GRANT CONNECT ON DATABASE {sql_identifier(data_db)} TO {sql_identifier(admin_user)};
""",
    )
    psql(
        values,
        data_db,
        f"""
GRANT USAGE ON SCHEMA api TO {sql_identifier(data_user)};
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA api TO {sql_identifier(data_user)};
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA api TO {sql_identifier(data_user)};
REVOKE ALL PRIVILEGES ON SCHEMA api FROM {sql_identifier(meta_user)};
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA api FROM {sql_identifier(meta_user)};
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA api FROM {sql_identifier(meta_user)};
ALTER TABLE api.prototype_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.prototype_items FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mte_nocodb_external_source_all ON api.prototype_items;
CREATE POLICY mte_nocodb_external_source_all ON api.prototype_items FOR ALL TO {sql_identifier(data_user)} USING (true) WITH CHECK (true);
ALTER DEFAULT PRIVILEGES FOR ROLE {sql_identifier(values["POSTGREST_DATA_DB_USER"])} IN SCHEMA api GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {sql_identifier(data_user)};
ALTER DEFAULT PRIVILEGES FOR ROLE {sql_identifier(values["POSTGREST_DATA_DB_USER"])} IN SCHEMA api GRANT USAGE, SELECT ON SEQUENCES TO {sql_identifier(data_user)};
""",
    )
    isolation = verify_database_isolation(values)
    return {
        "status": "converged",
        "metadataDatabase": values["NOCODB_META_DB_NAME"],
        "dataDatabase": data_db,
        "dataStateOwner": "postgres-postgrest",
        "isolation": isolation,
    }


def request(
    method: str,
    url: str,
    *,
    auth: str = "",
    api_token: str = "",
    body: Any | None = None,
    expected: set[int] = {200},
    allow_status: set[int] | None = None,
    license_gate: bool = False,
) -> tuple[int, Any]:
    headers = {"Accept": "application/json", "User-Agent": "mte-nocodb/1"}
    if auth:
        headers["xc-auth"] = auth
    if api_token:
        headers["xc-token"] = api_token
    data = None
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, data=data, headers=headers, method=method),
            timeout=30,
        ) as response:
            status = response.status
            raw = response.read(4_000_000)
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read(4_000_000)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise NocoError("nocodb_http_unreachable") from exc
    if license_gate and status in {403, 404}:
        raise NocoError("business_license_required", status=status)
    if status not in expected and not (allow_status and status in allow_status):
        raise NocoError(f"nocodb_http_status:{status}", status=status)
    if not raw:
        return status, None
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError as exc:
        raise NocoError("nocodb_http_response_invalid", status=status) from exc


def wait_ready(values: dict[str, str], timeout: int = 240) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            request("GET", values["NOCODB_HEALTH_URL"])
            return
        except NocoError:
            time.sleep(2)
    raise NocoError("nocodb_readiness_timeout")


def rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    if isinstance(value, dict):
        for key in ("list", "data", "items", "records"):
            if isinstance(value.get(key), list):
                return [row for row in value[key] if isinstance(row, dict)]
    return []


def session(values: dict[str, str]) -> tuple[str, str]:
    base = f"http://127.0.0.1:{int(values['NOCODB_ORIGIN_PORT'])}"
    credentials = {
        "email": values["NOCODB_ADMIN_EMAIL"],
        "password": values["NOCODB_ADMIN_PASSWORD"],
    }
    status, signed_in = request(
        "POST",
        base + "/api/v1/auth/user/signin",
        body=credentials,
        expected={200},
        allow_status={400, 401},
    )
    if status in {400, 401}:
        _, signed_in = request(
            "POST", base + "/api/v1/auth/user/signup", body=credentials, expected={200}
        )
    token = str((signed_in or {}).get("token") or "")
    if not token:
        raise NocoError("nocodb_admin_session_missing")
    return base, token


def ensure_base(values: dict[str, str], base: str, auth: str) -> dict[str, str]:
    _, listed = request("GET", base + "/api/v2/meta/bases", auth=auth)
    matches = [
        row for row in rows(listed) if row.get("title") == values["NOCODB_BASE_TITLE"]
    ]
    if len(matches) > 1:
        raise NocoError("nocodb_managed_base_ambiguous")
    if not matches:
        source = {
            "alias": SOURCE_ALIAS,
            "type": "pg",
            "is_meta": False,
            "is_local": False,
            "is_schema_readonly": True,
            "is_data_readonly": False,
            "config": {
                "client": "pg",
                "connection": {
                    "host": values["NOCODB_DB_HOST"],
                    "port": int(values["NOCODB_DB_PORT"]),
                    "user": values["NOCODB_DATA_DB_USER"],
                    "password": values["NOCODB_DATA_DB_PASSWORD"],
                    "database": values["POSTGREST_DATA_DB_NAME"],
                    "ssl": False,
                },
                "searchPath": ["api"],
            },
        }
        _, created = request(
            "POST",
            base + "/api/v2/meta/bases",
            auth=auth,
            body={
                "title": values["NOCODB_BASE_TITLE"],
                "type": "database",
                "sources": [source],
            },
        )
        if not isinstance(created, dict) or not created.get("id"):
            raise NocoError("nocodb_base_create_contract_invalid")
        matches = [created]
    base_id = str(matches[0].get("id") or "")
    if not base_id:
        raise NocoError("nocodb_base_id_missing")
    deadline = time.monotonic() + 180
    source_rows: list[dict[str, Any]] = []
    table_rows: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        _, source_value = request(
            "GET", f"{base}/api/v2/meta/bases/{base_id}/sources", auth=auth
        )
        source_rows = [
            row for row in rows(source_value) if row.get("alias") == SOURCE_ALIAS
        ]
        _, table_value = request(
            "GET", f"{base}/api/v2/meta/bases/{base_id}/tables", auth=auth
        )
        table_rows = [
            row
            for row in rows(table_value)
            if row.get("title") == values["NOCODB_TABLE_TITLE"]
            or row.get("table_name") == values["NOCODB_TABLE_TITLE"]
        ]
        if len(source_rows) == 1 and len(table_rows) == 1:
            break
        time.sleep(2)
    if len(source_rows) != 1 or len(table_rows) != 1:
        raise NocoError("nocodb_external_source_not_converged")
    source_id = str(source_rows[0].get("id") or "")
    table_id = str(table_rows[0].get("id") or "")
    if not source_id or not table_id:
        raise NocoError("nocodb_external_source_identity_missing")
    return {"baseId": base_id, "sourceId": source_id, "tableId": table_id}


def secret_fingerprint(value: str) -> str:
    if len(value) < 24:
        raise NocoError("nocodb_api_token_material_missing")
    return hashlib.sha256(value.encode()).hexdigest()


def ensure_api_token(
    values: dict[str, str], base: str, auth: str, base_id: str
) -> dict[str, Any]:
    path = f"{base}/api/v2/meta/bases/{base_id}/api-tokens"
    _, listing = request("GET", path, auth=auth)
    listed_rows = rows(listing)
    if any(row.get("token") for row in listed_rows):
        raise NocoError("nocodb_api_token_list_exposed_material")
    matches = [
        row for row in listed_rows if row.get("description") == TOKEN_DESCRIPTION
    ]
    if len(matches) > 1:
        raise NocoError("nocodb_api_token_ambiguous")
    stored_id = values.get("NOCODB_API_TOKEN_ID", "")
    stored_token = values.get("NOCODB_API_TOKEN", "")
    stored_fingerprint = values.get("NOCODB_API_TOKEN_SHA256", "")
    if len({bool(stored_id), bool(stored_token), bool(stored_fingerprint)}) != 1:
        raise NocoError("nocodb_api_token_material_missing")
    if not matches:
        if stored_id or stored_token or stored_fingerprint:
            if any(str(row.get("id") or "") == stored_id for row in listed_rows):
                raise NocoError("nocodb_api_token_description_mismatch")
            raise NocoError("nocodb_api_token_identity_missing")
        _, created = request(
            "POST", path, auth=auth, body={"description": TOKEN_DESCRIPTION}
        )
        if not isinstance(created, dict):
            raise NocoError("nocodb_api_token_create_contract_invalid")
        token_id = str(created.get("id") or "")
        token = str(created.get("token") or "")
        description = str(created.get("description") or TOKEN_DESCRIPTION)
        if not token_id or description != TOKEN_DESCRIPTION:
            raise NocoError("nocodb_api_token_create_contract_invalid")
        fingerprint = secret_fingerprint(token)
        return {
            "tokenId": token_id,
            "token": token,
            "fingerprint": fingerprint,
            "created": True,
            "rawListMaterialAbsent": True,
        }

    if not stored_id or not stored_token:
        raise NocoError("nocodb_api_token_material_missing")
    listed = matches[0]
    token_id = str(listed.get("id") or "")
    if not token_id or not hmac.compare_digest(token_id, stored_id):
        raise NocoError("nocodb_api_token_identity_mismatch")
    if str(listed.get("description") or "") != TOKEN_DESCRIPTION:
        raise NocoError("nocodb_api_token_description_mismatch")
    token_prefix = str(listed.get("token_prefix") or "")
    if token_prefix and not hmac.compare_digest(
        token_prefix, stored_token[: len(token_prefix)]
    ):
        raise NocoError("nocodb_api_token_fingerprint_mismatch")
    fingerprint = secret_fingerprint(stored_token)
    if not hmac.compare_digest(fingerprint, stored_fingerprint):
        raise NocoError("nocodb_api_token_fingerprint_mismatch")
    return {
        "tokenId": stored_id,
        "token": stored_token,
        "fingerprint": fingerprint,
        "created": False,
        "rawListMaterialAbsent": True,
    }


def verify_api_token_binding(
    base: str, table_id: str, token: str, expected_fingerprint: str
) -> None:
    if not hmac.compare_digest(secret_fingerprint(token), expected_fingerprint):
        raise NocoError("nocodb_api_token_fingerprint_mismatch")
    try:
        request(
            "GET",
            f"{base}/api/v2/tables/{table_id}/records?limit=1",
            api_token=token,
        )
    except NocoError as exc:
        raise NocoError(
            "nocodb_api_token_fingerprint_mismatch", status=exc.status
        ) from exc


def atomic_text(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w") as handle:
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
    if set(updates) - GENERATED_REFS or any(not value for value in updates.values()):
        raise NocoError("canonical_update_contract_invalid")
    SECRET_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    SECRET_ROOT.chmod(0o700)
    CANONICAL_LOCK.touch(mode=0o600, exist_ok=True)
    CANONICAL_LOCK.chmod(0o600)
    with CANONICAL_LOCK.open("r+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        current = dotenv()
        changed = sorted(
            key for key, value in updates.items() if current.get(key) != value
        )
        current.update(updates)
        if changed:
            atomic_text(
                CANONICAL,
                "".join(f"{key}={current[key]}\n" for key in sorted(current)),
            )
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    return {"changedKeys": changed, "canonicalSourceSha256": sha256_path(CANONICAL)}


def provision() -> dict[str, Any]:
    values = dotenv()
    require_values(values)
    release_contract(activation_requested=True)
    database()
    wait_ready(values)
    base, auth = session(values)
    try:
        identities = ensure_base(values, base, auth)
        api = ensure_api_token(values, base, auth, identities["baseId"])
        canonical = update_canonical(
            {
                "NOCODB_API_TOKEN": api["token"],
                "NOCODB_API_TOKEN_ID": api["tokenId"],
                "NOCODB_API_TOKEN_SHA256": api["fingerprint"],
                "NOCODB_BASE_ID": identities["baseId"],
                "NOCODB_SOURCE_ID": identities["sourceId"],
                "NOCODB_TABLE_ID": identities["tableId"],
            }
        )
        verify_api_token_binding(
            base, identities["tableId"], api["token"], api["fingerprint"]
        )
    finally:
        auth = ""
    return {
        "status": "converged",
        "baseId": identities["baseId"],
        "sourceId": identities["sourceId"],
        "tableId": identities["tableId"],
        "apiToken": {
            "id": api["tokenId"],
            "description": TOKEN_DESCRIPTION,
            "fingerprintSha256": api["fingerprint"],
            "created": api["created"],
            "rawListMaterialAbsent": api["rawListMaterialAbsent"],
            "bindingVerified": True,
        },
        "canonical": canonical,
    }


def postgrest_jwt(values: dict[str, str]) -> str:
    def encode(value: Any) -> str:
        return (
            base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
            .decode()
            .rstrip("=")
        )

    now = int(time.time())
    header = encode({"alg": "HS256", "typ": "JWT"})
    payload = encode(
        {
            "role": values["POSTGREST_WRITER_ROLE"],
            "aud": values["POSTGREST_API_AUDIENCE"],
            "iat": now,
            "exp": now + 300,
        }
    )
    signature = hmac.new(
        values["POSTGREST_JWT_SECRET"].encode(),
        f"{header}.{payload}".encode(),
        hashlib.sha256,
    ).digest()
    return (
        f"{header}.{payload}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"
    )


def postgrest_request(
    values: dict[str, str], method: str, path: str, *, body: Any | None = None
) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer " + postgrest_jwt(values),
        "Prefer": "return=representation",
        "Content-Type": "application/json",
    }
    try:
        with urllib.request.urlopen(
            urllib.request.Request(
                f"http://127.0.0.1:{values['POSTGREST_ORIGIN_PORT']}" + path,
                data=data,
                headers=headers,
                method=method,
            ),
            timeout=20,
        ) as response:
            raw = response.read(2_000_000)
            return response.status, json.loads(raw) if raw else None
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        OSError,
    ) as exc:
        raise NocoError("postgrest_visibility_canary_failed") from exc


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    atomic_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def verify() -> dict[str, Any]:
    values = dotenv()
    require_values(values, provisioned=True)
    release = release_contract(activation_requested=True)
    wait_ready(values)
    base = f"http://127.0.0.1:{int(values['NOCODB_ORIGIN_PORT'])}"
    token = values["NOCODB_API_TOKEN"]
    marker = "mte-nocodb-" + secrets.token_hex(12)
    marker_hash = hashlib.sha256(marker.encode()).hexdigest()
    row_id: int | None = None
    doc_id = ""
    table_cleanup = False
    document_cleanup = False
    try:
        status, created = postgrest_request(
            values,
            "POST",
            "/prototype_items",
            body={"title": marker, "status": "verified"},
        )
        if status != 201 or not isinstance(created, list) or len(created) != 1:
            raise NocoError("postgrest_visibility_create_invalid")
        row_id = created[0].get("id")
        if not isinstance(row_id, int):
            raise NocoError("postgrest_visibility_row_id_missing")
        where = urllib.parse.quote(f"(id,eq,{row_id})")
        _, visible = request(
            "GET",
            f"{base}/api/v2/tables/{values['NOCODB_TABLE_ID']}/records?where={where}",
            api_token=token,
        )
        visible_rows = rows(visible)
        if len(visible_rows) != 1 or visible_rows[0].get("title") != marker:
            raise NocoError("nocodb_postgres_row_not_visible")

        docs_path = f"{base}/api/v3/docs/{values['NOCODB_BASE_ID']}"
        _, document = request(
            "POST",
            docs_path,
            api_token=token,
            license_gate=True,
            body={
                "title": "MTE licensed NocoDocs canary",
                "content": {
                    "type": "doc",
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": marker}],
                        }
                    ],
                },
            },
        )
        doc_id = str((document or {}).get("id") or "")
        if not doc_id or (document or {}).get("base_id") != values["NOCODB_BASE_ID"]:
            raise NocoError("nocodocs_create_contract_invalid")
        run(["docker", "restart", unique_container("mte-nocodb", "nocodb")])
        wait_ready(values)
        _, persisted = request(
            "GET",
            docs_path + "/" + doc_id,
            api_token=token,
            license_gate=True,
        )
        if marker not in json.dumps((persisted or {}).get("content"), sort_keys=True):
            raise NocoError("nocodocs_restart_persistence_invalid")
        request(
            "DELETE",
            docs_path + "/" + doc_id,
            api_token=token,
            license_gate=True,
        )
        status, _ = request(
            "GET",
            docs_path + "/" + doc_id,
            api_token=token,
            expected={200},
            allow_status={404},
        )
        document_cleanup = status == 404
        if not document_cleanup:
            raise NocoError("nocodocs_cleanup_not_observed")
        doc_id = ""
        postgrest_request(values, "DELETE", f"/prototype_items?id=eq.{row_id}")
        row_id = None
        table_cleanup = True
    finally:
        if doc_id:
            request(
                "DELETE",
                f"{base}/api/v3/docs/{values['NOCODB_BASE_ID']}/{doc_id}",
                api_token=token,
                allow_status={403, 404},
            )
        if row_id is not None:
            postgrest_request(values, "DELETE", f"/prototype_items?id=eq.{row_id}")
    if not table_cleanup or not document_cleanup:
        raise NocoError("nocodb_verification_cleanup_incomplete")
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "NocoDbNocoDocsVerification",
        "status": "passed",
        "ok": True,
        "generatedAt": utcnow(),
        "profile": PROFILE,
        "canonicalSourceSha256": sha256_path(CANONICAL),
        "producerSha256": sha256_path(Path(__file__).resolve()),
        "release": release,
        "dataState": {
            "owner": "postgres-postgrest",
            "nocodbUniqueTableState": False,
            "postgrestCreated": True,
            "nocodbDiagnosticReadVisible": True,
            "markerSha256": marker_hash,
            "cleanupCompleted": table_cleanup,
        },
        "documentsApi": {
            "endpoint": "/api/v3/docs",
            "requiredPlan": "licensed-self-hosted-business-or-higher",
            "restartObserved": True,
            "persistenceVerified": True,
            "postDeleteAbsent": document_cleanup,
            "cleanupCompleted": document_cleanup,
            "markerSha256": marker_hash,
        },
    }
    atomic_json(EVIDENCE, payload)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("database", "provision", "verify"))
    args = parser.parse_args()
    try:
        result = {"database": database, "provision": provision, "verify": verify}[
            args.action
        ]()
    except NocoError as exc:
        print(
            json.dumps({"ok": False, "error": exc.code, "httpStatus": exc.status}),
            file=sys.stderr,
        )
        raise SystemExit(1) from exc
    print(json.dumps({"ok": True, **result}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Provision and verify the target profile's PostgreSQL + PostgREST plane."""

from __future__ import annotations

import argparse
import base64
import binascii
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
EVIDENCE = ROOT / "evidence/postgrest-verify.json"
DEFAULT_PROFILE = "postgres-notion"
SUPPORTED_PROFILES = frozenset((DEFAULT_PROFILE,))
# Compatibility for callers that use the module-level default profile.
PROFILE = DEFAULT_PROFILE
IMAGE = "postgrest/postgrest:v14.15@sha256:2f8e7b656f09db697a8875177694b417b35cb76c21370de07fc54e711e902326"
LICENSE = "MIT"
GENERATED_REFS = {
    "POSTGREST_PAPERCLIP_TOKEN",
}
SCOPED_TOKEN_SPECS = {
    "POSTGREST_PAPERCLIP_TOKEN": ("mte-paperclip", "POSTGREST_PAPERCLIP_ROLE"),
}
REQUIRED_REFS = {
    "DATA_CONTENT_PROFILE",
    "POSTGRES_ADMIN_DB",
    "POSTGRES_ADMIN_USER",
    "POSTGREST_DB_HOST",
    "POSTGREST_DB_PORT",
    "POSTGREST_DB_SSLMODE",
    "POSTGREST_DATA_DB_NAME",
    "POSTGREST_DATA_DB_USER",
    "POSTGREST_DATA_DB_PASSWORD",
    "POSTGREST_DB_LOGIN_ROLE",
    "POSTGREST_AUTHENTICATOR_PASSWORD",
    "POSTGREST_ANON_ROLE",
    "POSTGREST_READER_ROLE",
    "POSTGREST_WRITER_ROLE",
    "POSTGREST_PAPERCLIP_ROLE",
    "POSTGREST_JWT_SECRET",
    "POSTGREST_API_AUDIENCE",
    "POSTGREST_HEALTH_URL",
    "POSTGREST_ORIGIN_PORT",
}
IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
COMPOSE_PROJECT = "mte-platform"
DIRECT_COMPOSE_SERVICES = {
    "postgres": "postgres",
    "postgrest": "postgrest",
}


class PostgrestError(RuntimeError):
    """Secret-safe, fail-closed provider error."""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dotenv(path: Path = CANONICAL) -> dict[str, str]:
    if not path.is_file():
        raise PostgrestError("canonical_env_missing")
    values: dict[str, str] = {}
    for line_no, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise PostgrestError(f"canonical_env_invalid_line:{line_no}")
        key, value = line.split("=", 1)
        if key in values:
            raise PostgrestError(f"canonical_env_duplicate_key:{key}")
        values[key] = value
    return values


def require_values(values: dict[str, str]) -> None:
    missing = sorted(key for key in REQUIRED_REFS if not values.get(key))
    if missing:
        raise PostgrestError("missing_canonical_refs:" + ",".join(missing))
    if values["DATA_CONTENT_PROFILE"] not in SUPPORTED_PROFILES:
        raise PostgrestError("provider_profile_not_selected")
    role_keys = (
        "POSTGREST_DATA_DB_USER",
        "POSTGREST_DB_LOGIN_ROLE",
        "POSTGREST_ANON_ROLE",
        "POSTGREST_READER_ROLE",
        "POSTGREST_WRITER_ROLE",
        "POSTGREST_PAPERCLIP_ROLE",
    )
    for key in (
        "POSTGRES_ADMIN_DB",
        "POSTGRES_ADMIN_USER",
        "POSTGREST_DATA_DB_NAME",
        *role_keys,
    ):
        if not IDENTIFIER.fullmatch(values[key]):
            raise PostgrestError(f"invalid_identifier:{key}")
    if len({values[key] for key in role_keys}) != len(role_keys):
        raise PostgrestError("postgrest_database_roles_not_distinct")
    if len(values["POSTGREST_JWT_SECRET"]) < 32:
        raise PostgrestError("postgrest_jwt_secret_too_short")
    if (
        values["POSTGREST_DB_HOST"] != "mte-postgres"
        or values["POSTGREST_DB_PORT"] != "5432"
    ):
        raise PostgrestError("postgrest_database_not_shared_data_plane")


def release_contract(profile: str = PROFILE) -> dict[str, Any]:
    if profile not in SUPPORTED_PROFILES:
        raise PostgrestError("provider_profile_not_selected")
    try:
        lock = yaml.safe_load(LOCK.read_text())
        bundle = lock["spec"]["dataContentProfiles"][profile]
    except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
        raise PostgrestError("provider_lock_contract_invalid") from exc
    adapter = bundle.get("adapters", {}).get("postgrest", {})
    image = bundle.get("images", {}).get("postgrest")
    license_name = bundle.get("licenses", {}).get("postgrest")
    if (
        bundle.get("selectable") is not True
        or bundle.get("contractComplete") is not True
        or image != IMAGE
        or license_name != LICENSE
        or adapter.get("script") != "server-postgrest.py"
        or adapter.get("componentId") != "postgrest"
        or not {"database", "provision", "verify"}.issubset(
            set(adapter.get("actions", ()))
        )
    ):
        raise PostgrestError("postgrest_release_contract_drift")
    return {"profile": profile, "image": IMAGE, "license": LICENSE}


def projection_provider(profile: str) -> str:
    if profile == DEFAULT_PROFILE:
        return "notion"
    raise PostgrestError("provider_profile_not_selected")


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
        raise PostgrestError(f"command_failed:{Path(argv[0]).name}")
    return result


def unique_container(component: str, service: str) -> str:
    expected_service = DIRECT_COMPOSE_SERVICES.get(component)
    if expected_service is None or service != expected_service:
        raise PostgrestError(f"direct_compose_identity_invalid:{component}:{service}")
    result = run(
        [
            "docker",
            "ps",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={COMPOSE_PROJECT}",
            "--filter",
            f"label=com.docker.compose.service={service}",
            "--filter",
            "status=running",
        ]
    )
    rows = [row for row in result.stdout.splitlines() if row]
    if len(rows) != 1:
        raise PostgrestError(f"container_not_unique:{component}:{service}")
    return rows[0]


def psql(values: dict[str, str], database: str, sql: str) -> str:
    return run(
        [
            "docker",
            "exec",
            "-i",
            unique_container("postgres", "postgres"),
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
        raise PostgrestError("unsafe_database_identifier")
    return '"' + value + '"'


def sql_literal(value: str) -> str:
    if not value or any(character in value for character in ("\n", "\r", "\x00")):
        raise PostgrestError("unsafe_sql_value")
    return "'" + value.replace("'", "''") + "'"


def converge_role(values: dict[str, str], role: str, *, password: str | None) -> None:
    identifier = sql_identifier(role)
    attributes = (
        "LOGIN" if password is not None else "NOLOGIN"
    ) + " NOINHERIT NOCREATEDB NOCREATEROLE NOSUPERUSER NOREPLICATION NOBYPASSRLS"
    password_sql = f" PASSWORD {sql_literal(password)}" if password is not None else ""
    psql(
        values,
        values["POSTGRES_ADMIN_DB"],
        f"""
DO $mte$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname={sql_literal(role)}) THEN
    CREATE ROLE {identifier};
  END IF;
END
$mte$;
ALTER ROLE {identifier} {attributes}{password_sql};
""",
    )


def converge_database(values: dict[str, str], name: str, owner: str) -> None:
    exists = psql(
        values,
        values["POSTGRES_ADMIN_DB"],
        f"SELECT 1 FROM pg_database WHERE datname={sql_literal(name)};",
    )
    if exists not in {"", "1"}:
        raise PostgrestError("database_existence_query_invalid")
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


def database() -> dict[str, Any]:
    values = dotenv()
    require_values(values)
    active_profile = values["DATA_CONTENT_PROFILE"]
    release_contract(active_profile)
    provider = projection_provider(active_profile)
    roles = (
        ("POSTGREST_DATA_DB_USER", "POSTGREST_DATA_DB_PASSWORD"),
        ("POSTGREST_DB_LOGIN_ROLE", "POSTGREST_AUTHENTICATOR_PASSWORD"),
        ("POSTGREST_ANON_ROLE", None),
        ("POSTGREST_READER_ROLE", None),
        ("POSTGREST_WRITER_ROLE", None),
        ("POSTGREST_PAPERCLIP_ROLE", None),
    )
    for role_key, password_key in roles:
        converge_role(
            values,
            values[role_key],
            password=values[password_key] if password_key else None,
        )
    database_name = values["POSTGREST_DATA_DB_NAME"]
    owner = values["POSTGREST_DATA_DB_USER"]
    converge_database(values, database_name, owner)
    auth = sql_identifier(values["POSTGREST_DB_LOGIN_ROLE"])
    anon = sql_identifier(values["POSTGREST_ANON_ROLE"])
    reader = sql_identifier(values["POSTGREST_READER_ROLE"])
    writer = sql_identifier(values["POSTGREST_WRITER_ROLE"])
    paperclip = sql_identifier(values["POSTGREST_PAPERCLIP_ROLE"])
    owner_id = sql_identifier(owner)
    psql(
        values,
        values["POSTGRES_ADMIN_DB"],
        f"""
REVOKE CONNECT ON DATABASE {sql_identifier(database_name)} FROM PUBLIC;
GRANT {anon}, {reader}, {writer}, {paperclip} TO {auth};
GRANT CONNECT ON DATABASE {sql_identifier(database_name)} TO {owner_id}, {auth}, {paperclip};
""",
    )
    psql(
        values,
        database_name,
        f"""
CREATE SCHEMA IF NOT EXISTS api AUTHORIZATION {owner_id};
ALTER SCHEMA api OWNER TO {owner_id};
REVOKE ALL ON SCHEMA api FROM PUBLIC;
GRANT USAGE ON SCHEMA api TO {reader}, {writer}, {paperclip};
CREATE TABLE IF NOT EXISTS api.prototype_items (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  title text NOT NULL,
  status text NOT NULL CHECK (status IN ('created', 'verified', 'deleted')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE api.prototype_items OWNER TO {owner_id};
CREATE TABLE IF NOT EXISTS api.canonical_entities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  external_object_id text NOT NULL UNIQUE CHECK (length(external_object_id) BETWEEN 1 AND 512),
  entity_type text NOT NULL CHECK (length(entity_type) BETWEEN 1 AND 128),
  title text NOT NULL,
  data jsonb NOT NULL DEFAULT '{{}}'::jsonb,
  metadata jsonb NOT NULL DEFAULT '{{}}'::jsonb,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{{64}}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE api.canonical_entities OWNER TO {owner_id};
CREATE TABLE IF NOT EXISTS api.canonical_documents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  external_object_id text NOT NULL UNIQUE CHECK (length(external_object_id) BETWEEN 1 AND 512),
  title text NOT NULL,
  body text NOT NULL,
  content_type text NOT NULL DEFAULT 'text/markdown' CHECK (length(content_type) BETWEEN 1 AND 128),
  metadata jsonb NOT NULL DEFAULT '{{}}'::jsonb,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{{64}}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE api.canonical_documents OWNER TO {owner_id};
CREATE TABLE IF NOT EXISTS api.provider_sync_state (
  provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 64),
  object_kind text NOT NULL CHECK (object_kind IN ('entity', 'document')),
  canonical_object_id uuid NOT NULL,
  external_object_id text NOT NULL CHECK (length(external_object_id) BETWEEN 1 AND 512),
  provider_object_id text,
  desired_operation text NOT NULL DEFAULT 'upsert' CHECK (desired_operation IN ('upsert', 'delete')),
  canonical_revision bigint NOT NULL CHECK (canonical_revision > 0),
  canonical_content_hash text NOT NULL CHECK (canonical_content_hash ~ '^[0-9a-f]{{64}}$'),
  projected_revision bigint NOT NULL DEFAULT 0 CHECK (projected_revision >= 0),
  projected_content_hash text CHECK (projected_content_hash IS NULL OR projected_content_hash ~ '^[0-9a-f]{{64}}$'),
  sync_status text NOT NULL DEFAULT 'pending' CHECK (sync_status IN ('pending', 'syncing', 'synced', 'error')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  last_error_digest text CHECK (last_error_digest IS NULL OR last_error_digest ~ '^[0-9a-f]{{64}}$'),
  locked_by text CHECK (locked_by IS NULL OR length(locked_by) BETWEEN 1 AND 128),
  lease_expires_at timestamptz,
  last_attempt_at timestamptz,
  synced_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (provider, object_kind, canonical_object_id),
  UNIQUE (provider, object_kind, external_object_id)
);
ALTER TABLE api.provider_sync_state OWNER TO {owner_id};
CREATE TABLE IF NOT EXISTS api.provider_outbox (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 64),
  object_kind text NOT NULL CHECK (object_kind IN ('entity', 'document')),
  canonical_object_id uuid NOT NULL,
  external_object_id text NOT NULL CHECK (length(external_object_id) BETWEEN 1 AND 512),
  operation text NOT NULL CHECK (operation IN ('upsert', 'delete')),
  canonical_revision bigint NOT NULL CHECK (canonical_revision > 0),
  canonical_content_hash text NOT NULL CHECK (canonical_content_hash ~ '^[0-9a-f]{{64}}$'),
  delivery_state text NOT NULL DEFAULT 'pending' CHECK (delivery_state IN ('pending', 'processing', 'delivered', 'failed')),
  available_at timestamptz NOT NULL DEFAULT now(),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  last_error_digest text CHECK (last_error_digest IS NULL OR last_error_digest ~ '^[0-9a-f]{{64}}$'),
  locked_by text CHECK (locked_by IS NULL OR length(locked_by) BETWEEN 1 AND 128),
  lease_expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  UNIQUE (provider, object_kind, canonical_object_id, canonical_revision, operation)
);
ALTER TABLE api.provider_outbox OWNER TO {owner_id};
ALTER TABLE api.provider_sync_state ADD COLUMN IF NOT EXISTS locked_by text;
ALTER TABLE api.provider_sync_state ADD COLUMN IF NOT EXISTS lease_expires_at timestamptz;
ALTER TABLE api.provider_outbox ADD COLUMN IF NOT EXISTS locked_by text;
ALTER TABLE api.provider_outbox ADD COLUMN IF NOT EXISTS lease_expires_at timestamptz;
CREATE INDEX IF NOT EXISTS provider_outbox_delivery_idx
  ON api.provider_outbox (provider, delivery_state, available_at, id);
CREATE INDEX IF NOT EXISTS provider_outbox_lease_idx
  ON api.provider_outbox (provider, delivery_state, lease_expires_at, id);
CREATE OR REPLACE FUNCTION api.mte_touch_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $mte$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END
$mte$;
ALTER FUNCTION api.mte_touch_updated_at() OWNER TO {owner_id};
CREATE OR REPLACE FUNCTION api.mte_enforce_canonical_revision()
RETURNS trigger LANGUAGE plpgsql AS $mte$
BEGIN
  IF NEW.revision < OLD.revision THEN
    RAISE EXCEPTION 'canonical revision cannot decrease';
  END IF;
  IF (to_jsonb(NEW) - ARRAY['created_at', 'updated_at', 'revision'])
       IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['created_at', 'updated_at', 'revision'])
     AND NEW.revision <= OLD.revision THEN
    RAISE EXCEPTION 'canonical content change requires a new revision';
  END IF;
  RETURN NEW;
END
$mte$;
ALTER FUNCTION api.mte_enforce_canonical_revision() OWNER TO {owner_id};
CREATE OR REPLACE FUNCTION api.mte_enqueue_provider_projection()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, api
AS $mte$
DECLARE
  object_id uuid;
  external_id text;
  canonical_revision_value bigint;
  canonical_hash text;
  desired_operation_value text;
BEGIN
  IF TG_OP = 'UPDATE'
     AND NEW.external_object_id = OLD.external_object_id
     AND NEW.revision = OLD.revision
     AND NEW.content_hash = OLD.content_hash THEN
    RETURN NEW;
  END IF;
  IF TG_OP = 'DELETE' THEN
    object_id := OLD.id;
    external_id := OLD.external_object_id;
    canonical_revision_value := OLD.revision;
    canonical_hash := OLD.content_hash;
    desired_operation_value := 'delete';
  ELSE
    object_id := NEW.id;
    external_id := NEW.external_object_id;
    canonical_revision_value := NEW.revision;
    canonical_hash := NEW.content_hash;
    desired_operation_value := 'upsert';
  END IF;
  INSERT INTO api.provider_sync_state (
    provider, object_kind, canonical_object_id, external_object_id,
    desired_operation, canonical_revision, canonical_content_hash,
    sync_status, updated_at
  ) VALUES (
    {sql_literal(provider)}, TG_ARGV[0], object_id, external_id,
    desired_operation_value, canonical_revision_value, canonical_hash,
    'pending', now()
  )
  ON CONFLICT (provider, object_kind, canonical_object_id) DO UPDATE SET
    external_object_id = EXCLUDED.external_object_id,
    desired_operation = EXCLUDED.desired_operation,
    canonical_revision = EXCLUDED.canonical_revision,
    canonical_content_hash = EXCLUDED.canonical_content_hash,
    sync_status = CASE
      WHEN api.provider_sync_state.sync_status = 'syncing'
       AND api.provider_sync_state.lease_expires_at > now()
      THEN 'syncing'
      ELSE 'pending'
    END,
    attempt_count = CASE
      WHEN api.provider_sync_state.sync_status = 'syncing'
       AND api.provider_sync_state.lease_expires_at > now()
      THEN api.provider_sync_state.attempt_count
      ELSE 0
    END,
    last_error_digest = NULL,
    synced_at = NULL,
    updated_at = now();
  INSERT INTO api.provider_outbox (
    provider, object_kind, canonical_object_id, external_object_id,
    operation, canonical_revision, canonical_content_hash
  ) VALUES (
    {sql_literal(provider)}, TG_ARGV[0], object_id, external_id,
    desired_operation_value, canonical_revision_value, canonical_hash
  ) ON CONFLICT DO NOTHING;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END
$mte$;
ALTER FUNCTION api.mte_enqueue_provider_projection() OWNER TO {owner_id};
REVOKE ALL ON FUNCTION api.mte_enqueue_provider_projection() FROM PUBLIC;
DROP TRIGGER IF EXISTS mte_entities_touch_updated_at ON api.canonical_entities;
CREATE TRIGGER mte_entities_touch_updated_at BEFORE UPDATE ON api.canonical_entities
  FOR EACH ROW EXECUTE FUNCTION api.mte_touch_updated_at();
DROP TRIGGER IF EXISTS mte_entities_enforce_revision ON api.canonical_entities;
CREATE TRIGGER mte_entities_enforce_revision BEFORE UPDATE ON api.canonical_entities
  FOR EACH ROW EXECUTE FUNCTION api.mte_enforce_canonical_revision();
DROP TRIGGER IF EXISTS mte_documents_touch_updated_at ON api.canonical_documents;
CREATE TRIGGER mte_documents_touch_updated_at BEFORE UPDATE ON api.canonical_documents
  FOR EACH ROW EXECUTE FUNCTION api.mte_touch_updated_at();
DROP TRIGGER IF EXISTS mte_documents_enforce_revision ON api.canonical_documents;
CREATE TRIGGER mte_documents_enforce_revision BEFORE UPDATE ON api.canonical_documents
  FOR EACH ROW EXECUTE FUNCTION api.mte_enforce_canonical_revision();
DROP TRIGGER IF EXISTS mte_entities_projection_outbox ON api.canonical_entities;
CREATE TRIGGER mte_entities_projection_outbox
  AFTER INSERT OR UPDATE OR DELETE ON api.canonical_entities
  FOR EACH ROW EXECUTE FUNCTION api.mte_enqueue_provider_projection('entity');
DROP TRIGGER IF EXISTS mte_documents_projection_outbox ON api.canonical_documents;
CREATE TRIGGER mte_documents_projection_outbox
  AFTER INSERT OR UPDATE OR DELETE ON api.canonical_documents
  FOR EACH ROW EXECUTE FUNCTION api.mte_enqueue_provider_projection('document');
REVOKE ALL ON ALL TABLES IN SCHEMA api FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA api FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA api FROM {anon}, {reader}, {writer}, {paperclip};
REVOKE ALL ON ALL SEQUENCES IN SCHEMA api FROM {anon}, {reader}, {writer}, {paperclip};
GRANT SELECT ON ALL TABLES IN SCHEMA api TO {reader};
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA api TO {writer};
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA api TO {writer};
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  api.prototype_items, api.canonical_entities, api.canonical_documents
  TO {paperclip};
GRANT SELECT ON TABLE api.provider_sync_state, api.provider_outbox
  TO {paperclip};
GRANT USAGE, SELECT ON SEQUENCE api.prototype_items_id_seq TO {paperclip};
ALTER DEFAULT PRIVILEGES FOR ROLE {owner_id} IN SCHEMA api GRANT SELECT ON TABLES TO {reader};
ALTER DEFAULT PRIVILEGES FOR ROLE {owner_id} IN SCHEMA api GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {writer};
ALTER DEFAULT PRIVILEGES FOR ROLE {owner_id} IN SCHEMA api GRANT USAGE, SELECT ON SEQUENCES TO {writer};
ALTER TABLE api.prototype_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.prototype_items FORCE ROW LEVEL SECURITY;
ALTER TABLE api.canonical_entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.canonical_entities FORCE ROW LEVEL SECURITY;
ALTER TABLE api.canonical_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.canonical_documents FORCE ROW LEVEL SECURITY;
ALTER TABLE api.provider_sync_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.provider_sync_state FORCE ROW LEVEL SECURITY;
ALTER TABLE api.provider_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE api.provider_outbox FORCE ROW LEVEL SECURITY;
DO $policies$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'prototype_items', 'canonical_entities', 'canonical_documents',
    'provider_sync_state', 'provider_outbox'
  ] LOOP
    EXECUTE format('DROP POLICY IF EXISTS mte_reader_all ON api.%I', table_name);
    EXECUTE format('DROP POLICY IF EXISTS mte_writer_all ON api.%I', table_name);
    EXECUTE format('DROP POLICY IF EXISTS mte_owner_all ON api.%I', table_name);
    EXECUTE format('DROP POLICY IF EXISTS mte_paperclip_canary_rows ON api.%I', table_name);
    EXECUTE format('CREATE POLICY mte_reader_all ON api.%I FOR SELECT TO %I USING (true)', table_name, {sql_literal(values["POSTGREST_READER_ROLE"])});
    EXECUTE format('CREATE POLICY mte_writer_all ON api.%I FOR ALL TO %I USING (true) WITH CHECK (true)', table_name, {sql_literal(values["POSTGREST_WRITER_ROLE"])});
    EXECUTE format('CREATE POLICY mte_owner_all ON api.%I FOR ALL TO %I USING (true) WITH CHECK (true)', table_name, {sql_literal(owner)});
  END LOOP;
END
$policies$;
CREATE POLICY mte_paperclip_canary_rows ON api.prototype_items FOR ALL TO {paperclip}
  USING (title LIKE 'MTE-C027-%') WITH CHECK (title LIKE 'MTE-C027-%');
CREATE POLICY mte_paperclip_canary_rows ON api.canonical_entities FOR ALL TO {paperclip}
  USING (external_object_id LIKE 'MTE-C027-%') WITH CHECK (external_object_id LIKE 'MTE-C027-%');
CREATE POLICY mte_paperclip_canary_rows ON api.canonical_documents FOR ALL TO {paperclip}
  USING (external_object_id LIKE 'MTE-C027-%') WITH CHECK (external_object_id LIKE 'MTE-C027-%');
CREATE POLICY mte_paperclip_canary_rows ON api.provider_sync_state FOR SELECT TO {paperclip}
  USING (external_object_id LIKE 'MTE-C027-%');
CREATE POLICY mte_paperclip_canary_rows ON api.provider_outbox FOR SELECT TO {paperclip}
  USING (external_object_id LIKE 'MTE-C027-%');
NOTIFY pgrst, 'reload schema';
""",
    )
    authorization = verify_database_authorization(values)
    return {
        "status": "converged",
        "database": database_name,
        "roles": len(roles),
        "authorization": authorization,
    }


def verify_database_authorization(values: dict[str, str]) -> dict[str, Any]:
    database_name = values["POSTGREST_DATA_DB_NAME"]
    paperclip = values["POSTGREST_PAPERCLIP_ROLE"]
    reader = values["POSTGREST_READER_ROLE"]
    writer = values["POSTGREST_WRITER_ROLE"]
    anon = values["POSTGREST_ANON_ROLE"]
    policy_state = psql(
        values,
        database_name,
        f"""
SELECT concat_ws('|',
  (SELECT bool_and(c.relrowsecurity AND c.relforcerowsecurity)
     FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='api' AND c.relname=ANY(ARRAY['prototype_items','canonical_entities','canonical_documents','provider_sync_state','provider_outbox'])),
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='api' AND c.relname=ANY(ARRAY['prototype_items','canonical_entities','canonical_documents','provider_sync_state','provider_outbox'])),
  (SELECT count(*) FROM pg_policies WHERE schemaname='api' AND policyname='mte_reader_all'),
  (SELECT count(*) FROM pg_policies WHERE schemaname='api' AND policyname='mte_writer_all'),
  (SELECT count(*) FROM pg_policies WHERE schemaname='api' AND policyname='mte_paperclip_canary_rows' AND {sql_literal(paperclip)}=ANY(roles) AND qual LIKE '%MTE-C027-%')
);
""",
    )
    if policy_state != "t|5|5|5|5":
        raise PostgrestError("postgrest_rls_policy_contract_invalid")
    privilege_state = psql(
        values,
        database_name,
        f"""
SELECT concat_ws('|',
  has_table_privilege({sql_literal(paperclip)}, 'api.prototype_items', 'SELECT,INSERT,UPDATE,DELETE'),
  has_table_privilege({sql_literal(paperclip)}, 'api.canonical_entities', 'SELECT,INSERT,UPDATE,DELETE'),
  has_table_privilege({sql_literal(paperclip)}, 'api.canonical_documents', 'SELECT,INSERT,UPDATE,DELETE'),
  has_table_privilege({sql_literal(paperclip)}, 'api.provider_sync_state', 'SELECT'),
  has_table_privilege({sql_literal(paperclip)}, 'api.provider_sync_state', 'INSERT'),
  has_table_privilege({sql_literal(paperclip)}, 'api.provider_outbox', 'SELECT'),
  has_table_privilege({sql_literal(paperclip)}, 'api.provider_outbox', 'INSERT'),
  has_table_privilege({sql_literal(reader)}, 'api.canonical_entities', 'SELECT'),
  has_table_privilege({sql_literal(writer)}, 'api.canonical_documents', 'SELECT,INSERT,UPDATE,DELETE'),
  has_schema_privilege({sql_literal(paperclip)}, 'api', 'USAGE'),
  has_table_privilege({sql_literal(anon)}, 'api.canonical_entities', 'SELECT')
);
""",
    )
    if privilege_state != "t|t|t|t|f|t|f|t|t|t|f":
        raise PostgrestError("postgrest_role_privilege_contract_invalid")
    ownership_state = psql(
        values,
        database_name,
        """
SELECT concat_ws('|',
  (SELECT count(*) FROM information_schema.tables WHERE table_schema='api' AND table_name IN ('canonical_entities','canonical_documents')),
  (SELECT count(*) FROM information_schema.columns WHERE table_schema='api' AND table_name IN ('canonical_entities','canonical_documents') AND column_name IN ('external_object_id','revision','content_hash')),
  (SELECT count(*) FROM information_schema.tables WHERE table_schema='api' AND table_name IN ('provider_sync_state','provider_outbox')),
  (SELECT count(*) FROM information_schema.columns WHERE table_schema='api' AND table_name IN ('provider_sync_state','provider_outbox') AND column_name IN ('body','data','metadata','payload')),
  (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgname IN ('mte_entities_projection_outbox','mte_documents_projection_outbox')),
  (SELECT count(*) FROM information_schema.columns WHERE table_schema='api' AND table_name='canonical_documents' AND column_name='body'),
  (SELECT count(*) FROM information_schema.columns WHERE table_schema='api' AND table_name='canonical_entities' AND column_name='data')
);
""",
    )
    if ownership_state != "2|6|2|0|2|1|1":
        raise PostgrestError("postgres_canonical_ownership_contract_invalid")
    return {
        "rlsEnabled": True,
        "paperclipRole": paperclip,
        "paperclipRoleScoped": True,
        "anonymousDenied": True,
        "canonicalTables": ["canonical_entities", "canonical_documents"],
        "projectionStateTables": ["provider_sync_state", "provider_outbox"],
        "projectionTablesContainCanonicalPayload": False,
        "canonicalSystem": "postgresql",
        "projectionProvider": projection_provider(values["DATA_CONTENT_PROFILE"]),
    }


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
        raise PostgrestError("canonical_update_contract_invalid")
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


def jwt(
    values: dict[str, str], role: str, *, lifetime: int = 300, token_id: str = ""
) -> str:
    def encode(value: Any) -> str:
        return (
            base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
            .decode()
            .rstrip("=")
        )

    issued_at = int(time.time())
    claims: dict[str, Any] = {
        "role": role,
        "aud": values["POSTGREST_API_AUDIENCE"],
        "iat": issued_at,
        "exp": issued_at + lifetime,
    }
    if token_id:
        claims["jti"] = token_id
    header = encode({"alg": "HS256", "typ": "JWT"})
    payload = encode(claims)
    signature = hmac.new(
        values["POSTGREST_JWT_SECRET"].encode(),
        f"{header}.{payload}".encode(),
        hashlib.sha256,
    ).digest()
    return (
        f"{header}.{payload}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"
    )


def token_claims(values: dict[str, str], token: str) -> dict[str, Any] | None:
    try:
        header, payload, supplied = token.split(".")
        decoded_header = json.loads(
            base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
        )
        claims = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        )
        expected = (
            base64.urlsafe_b64encode(
                hmac.new(
                    values["POSTGREST_JWT_SECRET"].encode(),
                    f"{header}.{payload}".encode(),
                    hashlib.sha256,
                ).digest()
            )
            .decode()
            .rstrip("=")
        )
    except (ValueError, TypeError, json.JSONDecodeError, binascii.Error):
        return None
    if decoded_header != {"alg": "HS256", "typ": "JWT"} or not hmac.compare_digest(
        supplied, expected
    ):
        return None
    return claims if isinstance(claims, dict) else None


def scoped_token_valid(
    values: dict[str, str], token: str, token_id: str, role: str
) -> bool:
    claims = token_claims(values, token)
    return bool(
        claims
        and claims.get("role") == role
        and claims.get("aud") == values["POSTGREST_API_AUDIENCE"]
        and claims.get("jti") == token_id
        and isinstance(claims.get("exp"), int)
        and claims["exp"] > int(time.time()) + 2_592_000
    )


def provision_scoped_tokens(values: dict[str, str]) -> dict[str, Any]:
    updates = {
        key: jwt(
            values,
            values[role_ref],
            lifetime=31_536_000,
            token_id=token_id,
        )
        for key, (token_id, role_ref) in SCOPED_TOKEN_SPECS.items()
        if not scoped_token_valid(
            values, values.get(key, ""), token_id, values[role_ref]
        )
    }
    result = (
        update_canonical(updates)
        if updates
        else {
            "changedKeys": [],
            "canonicalSourceSha256": sha256_path(CANONICAL),
        }
    )
    current = dotenv()
    tokens = [current.get(key, "") for key in SCOPED_TOKEN_SPECS]
    if len(set(tokens)) != len(SCOPED_TOKEN_SPECS) or not all(tokens) or not all(
        scoped_token_valid(values, current.get(key, ""), token_id, values[role_ref])
        for key, (token_id, role_ref) in SCOPED_TOKEN_SPECS.items()
    ):
        raise PostgrestError("postgrest_scoped_token_contract_invalid")
    return result


def request(
    method: str,
    url: str,
    *,
    token: str | None = None,
    body: Any | None = None,
    expected: set[int] = {200},
    prefer: str | None = None,
) -> tuple[int, Any]:
    headers = {"Accept": "application/json", "User-Agent": "mte-postgrest/1"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if prefer:
        headers["Prefer"] = prefer
    data = None
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, data=data, headers=headers, method=method),
            timeout=20,
        ) as response:
            status = response.status
            raw = response.read(2_000_000)
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read(2_000_000)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise PostgrestError("postgrest_http_unreachable") from exc
    if status not in expected:
        raise PostgrestError(f"postgrest_http_status:{status}")
    if not raw:
        return status, None
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PostgrestError("postgrest_http_response_invalid") from exc


def wait_ready(url: str, timeout: int = 180) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            request("GET", url, expected={200, 204})
            return
        except PostgrestError:
            time.sleep(2)
    raise PostgrestError("postgrest_readiness_timeout")


def provision() -> dict[str, Any]:
    values = dotenv()
    require_values(values)
    release_contract(values["DATA_CONTENT_PROFILE"])
    database()
    wait_ready(values["POSTGREST_HEALTH_URL"])
    return {
        "status": "converged",
        "canonical": provision_scoped_tokens(values),
        "roleBindings": {
            "paperclip": values["POSTGREST_PAPERCLIP_ROLE"],
            "scoped": True,
        },
    }


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    atomic_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def paperclip_scope_canary(values: dict[str, str], base: str) -> dict[str, Any]:
    token = values.get("POSTGREST_PAPERCLIP_TOKEN", "")
    if not token:
        raise PostgrestError("postgrest_scoped_token_missing")
    marker = "MTE-C027-postgrest-verifier-" + secrets.token_hex(8)
    row_id: int | None = None
    try:
        _, value = request(
            "POST",
            base,
            token=token,
            body={"title": marker, "status": "created"},
            expected={201},
            prefer="return=representation",
        )
        if (
            not isinstance(value, list)
            or len(value) != 1
            or not isinstance(value[0].get("id"), int)
        ):
            raise PostgrestError("postgrest_rls_create_contract_invalid")
        row_id = value[0]["id"]
        item = base + f"?id=eq.{row_id}"
        _, own_rows = request("GET", item, token=token)
        if (
            not isinstance(own_rows, list)
            or len(own_rows) != 1
            or own_rows[0].get("title") != marker
        ):
            raise PostgrestError("postgrest_paperclip_rls_visibility_invalid")
        denied_status, _ = request(
            "POST",
            base,
            token=token,
            body={
                "title": "outside-paperclip-scope-" + secrets.token_hex(8),
                "status": "created",
            },
            expected={403},
            prefer="return=representation",
        )
        request("DELETE", item, token=token, expected={200, 204})
        row_id = None
        return {
            "paperclipRoleScoped": True,
            "outOfScopeWriteDenied": denied_status == 403,
            "cleanupCompleted": True,
        }
    finally:
        if row_id is not None:
            request(
                "DELETE",
                base + f"?id=eq.{row_id}",
                token=token,
                expected={200, 204},
            )

def canonical_ssot_canary(
    values: dict[str, str], api_root: str, reader: str, writer: str
) -> dict[str, Any]:
    marker = "mte-postgrest-ssot-" + secrets.token_hex(10)
    provider = projection_provider(values["DATA_CONTENT_PROFILE"])
    entity_hash_v1 = hashlib.sha256((marker + ":entity:v1").encode()).hexdigest()
    entity_hash_v2 = hashlib.sha256((marker + ":entity:v2").encode()).hexdigest()
    document_hash = hashlib.sha256((marker + ":document:v1").encode()).hexdigest()
    entity_id: str | None = None
    document_id: str | None = None
    cleanup_filters = (
        f"external_object_id=eq.{marker}-entity",
        f"external_object_id=eq.{marker}-document",
    )
    try:
        _, entities = request(
            "POST",
            api_root + "/canonical_entities",
            token=writer,
            body={
                "external_object_id": marker + "-entity",
                "entity_type": "verification_canary",
                "title": "PostgreSQL canonical entity canary",
                "data": {"markerSha256": hashlib.sha256(marker.encode()).hexdigest()},
                "metadata": {"canonicalOwner": "postgresql"},
                "revision": 1,
                "content_hash": entity_hash_v1,
            },
            expected={201},
            prefer="return=representation",
        )
        _, documents = request(
            "POST",
            api_root + "/canonical_documents",
            token=writer,
            body={
                "external_object_id": marker + "-document",
                "title": "PostgreSQL canonical document canary",
                "body": "Canonical body owned by PostgreSQL.",
                "content_type": "text/markdown",
                "metadata": {"canonicalOwner": "postgresql"},
                "revision": 1,
                "content_hash": document_hash,
            },
            expected={201},
            prefer="return=representation",
        )
        if (
            not isinstance(entities, list)
            or len(entities) != 1
            or not isinstance(entities[0].get("id"), str)
            or not isinstance(documents, list)
            or len(documents) != 1
            or not isinstance(documents[0].get("id"), str)
        ):
            raise PostgrestError("postgres_canonical_create_contract_invalid")
        entity_id = entities[0]["id"]
        document_id = documents[0]["id"]
        for object_marker, object_kind, expected_hash in (
            (marker + "-entity", "entity", entity_hash_v1),
            (marker + "-document", "document", document_hash),
        ):
            query = "?external_object_id=eq." + object_marker
            _, states = request(
                "GET", api_root + "/provider_sync_state" + query, token=reader
            )
            _, events = request(
                "GET", api_root + "/provider_outbox" + query, token=reader
            )
            if (
                not isinstance(states, list)
                or len(states) != 1
                or states[0].get("provider") != provider
                or states[0].get("object_kind") != object_kind
                or states[0].get("canonical_content_hash") != expected_hash
                or states[0].get("sync_status") != "pending"
                or not isinstance(events, list)
                or len(events) != 1
                or events[0].get("operation") != "upsert"
                or events[0].get("canonical_content_hash") != expected_hash
            ):
                raise PostgrestError("postgres_projection_outbox_contract_invalid")
        request(
            "PATCH",
            api_root + f"/canonical_entities?id=eq.{entity_id}",
            token=writer,
            body={
                "revision": 2,
                "content_hash": entity_hash_v2,
                "data": {"revision": 2, "canonicalOwner": "postgresql"},
            },
            expected={200, 204},
        )
        _, entity_state = request(
            "GET",
            api_root
            + "/provider_sync_state?external_object_id=eq."
            + marker
            + "-entity",
            token=reader,
        )
        _, entity_events = request(
            "GET",
            api_root
            + "/provider_outbox?external_object_id=eq."
            + marker
            + "-entity&order=canonical_revision.asc",
            token=reader,
        )
        if (
            not isinstance(entity_state, list)
            or len(entity_state) != 1
            or entity_state[0].get("canonical_revision") != 2
            or entity_state[0].get("canonical_content_hash") != entity_hash_v2
            or not isinstance(entity_events, list)
            or len(entity_events) != 2
            or entity_events[-1].get("canonical_revision") != 2
        ):
            raise PostgrestError("postgres_projection_revision_contract_invalid")
        run(["docker", "restart", unique_container("postgrest", "postgrest")])
        wait_ready(values["POSTGREST_HEALTH_URL"])
        _, persisted_entity = request(
            "GET", api_root + f"/canonical_entities?id=eq.{entity_id}", token=reader
        )
        _, persisted_document = request(
            "GET", api_root + f"/canonical_documents?id=eq.{document_id}", token=reader
        )
        if (
            not isinstance(persisted_entity, list)
            or len(persisted_entity) != 1
            or persisted_entity[0].get("revision") != 2
            or persisted_entity[0].get("content_hash") != entity_hash_v2
            or not isinstance(persisted_document, list)
            or len(persisted_document) != 1
            or persisted_document[0].get("body")
            != "Canonical body owned by PostgreSQL."
            or persisted_document[0].get("content_hash") != document_hash
        ):
            raise PostgrestError("postgres_canonical_restart_persistence_invalid")
        request(
            "DELETE",
            api_root + f"/canonical_entities?id=eq.{entity_id}",
            token=writer,
            expected={200, 204},
        )
        entity_id = None
        request(
            "DELETE",
            api_root + f"/canonical_documents?id=eq.{document_id}",
            token=writer,
            expected={200, 204},
        )
        document_id = None
        for object_marker in (marker + "-entity", marker + "-document"):
            _, delete_events = request(
                "GET",
                api_root
                + "/provider_outbox?external_object_id=eq."
                + object_marker
                + "&operation=eq.delete",
                token=reader,
            )
            if not isinstance(delete_events, list) or len(delete_events) != 1:
                raise PostgrestError("postgres_projection_delete_contract_invalid")
        return {
            "canonicalSystem": "postgresql",
            "projectionProvider": provider,
            "canonicalEntityRevision": 2,
            "canonicalDocumentRevision": 1,
            "canonicalEntityHashSha256": entity_hash_v2,
            "canonicalDocumentHashSha256": document_hash,
            "outboxGeneratedByDatabaseTriggers": True,
            "projectionTablesContainCanonicalPayload": False,
            "restartPersistenceVerified": True,
        }
    finally:
        if entity_id is not None:
            request(
                "DELETE",
                api_root + f"/canonical_entities?id=eq.{entity_id}",
                token=writer,
                expected={200, 204},
            )
        if document_id is not None:
            request(
                "DELETE",
                api_root + f"/canonical_documents?id=eq.{document_id}",
                token=writer,
                expected={200, 204},
            )
        for item_filter in cleanup_filters:
            request(
                "DELETE",
                api_root + "/provider_outbox?" + item_filter,
                token=writer,
                expected={200, 204},
            )
            request(
                "DELETE",
                api_root + "/provider_sync_state?" + item_filter,
                token=writer,
                expected={200, 204},
            )


def verify() -> dict[str, Any]:
    values = dotenv()
    require_values(values)
    active_profile = values["DATA_CONTENT_PROFILE"]
    release = release_contract(active_profile)
    wait_ready(values["POSTGREST_HEALTH_URL"])
    database_authorization = verify_database_authorization(values)
    api_root = f"http://127.0.0.1:{int(values['POSTGREST_ORIGIN_PORT'])}"
    base = api_root + "/prototype_items"
    role_isolation = paperclip_scope_canary(values, base)
    reader = jwt(values, values["POSTGREST_READER_ROLE"])
    writer = jwt(values, values["POSTGREST_WRITER_ROLE"])
    canonical_ownership = canonical_ssot_canary(values, api_root, reader, writer)
    request("GET", base + "?limit=1", expected={401, 403})
    request(
        "POST",
        base,
        token=reader,
        body={"title": "denied", "status": "created"},
        expected={401, 403},
    )
    marker = "mte-postgrest-" + secrets.token_hex(12)
    marker_hash = hashlib.sha256(marker.encode()).hexdigest()
    created_id: int | None = None
    try:
        _, created = request(
            "POST",
            base,
            token=writer,
            body={"title": marker, "status": "created"},
            expected={201},
            prefer="return=representation",
        )
        if (
            not isinstance(created, list)
            or len(created) != 1
            or not isinstance(created[0].get("id"), int)
        ):
            raise PostgrestError("postgrest_create_contract_invalid")
        created_id = created[0]["id"]
        item = base + f"?id=eq.{created_id}"
        _, rows = request("GET", item, token=reader)
        if (
            not isinstance(rows, list)
            or len(rows) != 1
            or rows[0].get("title") != marker
        ):
            raise PostgrestError("postgrest_reader_contract_invalid")
        run(["docker", "restart", unique_container("postgrest", "postgrest")])
        wait_ready(values["POSTGREST_HEALTH_URL"])
        _, rows = request("GET", item, token=reader)
        if (
            not isinstance(rows, list)
            or len(rows) != 1
            or rows[0].get("title") != marker
        ):
            raise PostgrestError("postgrest_restart_persistence_invalid")
        request("DELETE", item, token=writer, expected={200, 204})
        created_id = None
        _, rows = request("GET", item, token=reader)
        if rows != []:
            raise PostgrestError("postgrest_cleanup_contract_invalid")
    finally:
        if created_id is not None:
            request(
                "DELETE",
                base + f"?id=eq.{created_id}",
                token=writer,
                expected={200, 204},
            )
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "PostgrestVerification",
        "status": "passed",
        "ok": True,
        "generatedAt": utcnow(),
        "profile": active_profile,
        "canonicalSourceSha256": sha256_path(CANONICAL),
        "producerSha256": sha256_path(Path(__file__).resolve()),
        "release": release,
        "authorization": {
            **database_authorization,
            "anonymousDenied": True,
            "readerWriteDenied": True,
            **role_isolation,
        },
        "persistence": {
            "markerSha256": marker_hash,
            "restartObserved": True,
            "persistenceVerified": True,
            "postDeleteAbsent": True,
            "cleanupCompleted": True,
        },
        "dataOwnership": canonical_ownership,
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
    except PostgrestError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from exc
    print(json.dumps({"ok": True, **result}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

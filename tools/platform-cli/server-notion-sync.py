#!/usr/bin/env python3
"""Lease-safe PostgreSQL outbox consumer for the Notion projection plane.

PostgreSQL remains authoritative.  This process only projects the current
``provider_sync_state`` revision to Notion and records delivery metadata after
an exact read-back.  Raw credentials and canonical payloads are never emitted.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
from types import ModuleType
from typing import Any, Callable, Mapping
import uuid


ROOT = Path(os.environ.get("MTE_PLATFORM_ROOT", "/opt/mte-platform"))
SECRET_ROOT = Path(
    os.environ.get(
        "MTE_SECRETS_ROOT",
        os.environ.get("MTE_SECRET_ROOT", "/root/.config/mte-secrets"),
    )
)
CANONICAL = SECRET_ROOT / "platform.env"
EVIDENCE = ROOT / "evidence/notion-projection-consumer-verify.json"
CANARY_EVIDENCE = ROOT / "evidence/notion-projection-live-canary.json"
SYSTEMD_ROOT = Path("/etc/systemd/system")
SERVICE_NAME = "mte-notion-projection.service"
TIMER_NAME = "mte-notion-projection.timer"
PROVIDER = "notion"
PROFILE = "postgres-notion"
MARKER_PREFIX = "MTE_PROJECTION_V1 "
DOCUMENT_MARKER = re.compile(
    r" \[mte:([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\]$"
)
IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class ProjectionError(RuntimeError):
    """A stable, secret-safe consumer error code."""


@dataclass(frozen=True)
class Settings:
    batch_size: int
    max_attempts: int
    lease_seconds: int
    retry_base_seconds: int
    interval_seconds: int


@dataclass(frozen=True)
class Event:
    id: int
    event_id: str
    object_kind: str
    canonical_object_id: str
    external_object_id: str
    operation: str
    canonical_revision: int
    canonical_content_hash: str
    attempt_count: int
    provider_object_id: str | None


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_source_sha() -> str:
    if CANONICAL.is_symlink() or not CANONICAL.is_file():
        raise ProjectionError("canonical_env_missing_or_invalid")
    info = CANONICAL.stat()
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ProjectionError("canonical_env_mode_invalid")
    if os.geteuid() == 0 and (info.st_uid != 0 or info.st_gid != 0):
        raise ProjectionError("canonical_env_owner_invalid")
    return sha256_path(CANONICAL)


def load_sibling(filename: str, module_name: str) -> ModuleType:
    candidates = (ROOT / "bin" / filename, Path(__file__).resolve().with_name(filename))
    path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if path is None:
        raise ProjectionError(f"consumer_dependency_missing:{filename}")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ProjectionError(f"consumer_dependency_invalid:{filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


NOTION = load_sibling("server-notion.py", "mte_projection_notion")
POSTGREST = load_sibling("server-postgrest.py", "mte_projection_postgrest")


def exact_int(values: Mapping[str, str], key: str, minimum: int, maximum: int) -> int:
    raw = values.get(key, "")
    if not re.fullmatch(r"[1-9][0-9]*", raw):
        raise ProjectionError(f"invalid_consumer_setting:{key}")
    value = int(raw)
    if not minimum <= value <= maximum:
        raise ProjectionError(f"invalid_consumer_setting:{key}")
    return value


def settings_from_env(values: Mapping[str, str]) -> Settings:
    if values.get("DATA_CONTENT_PROFILE") != PROFILE:
        raise ProjectionError("notion_projection_profile_not_selected")
    for key in ("POSTGREST_DATA_DB_NAME", "POSTGRES_ADMIN_USER"):
        if not IDENTIFIER.fullmatch(values.get(key, "")):
            raise ProjectionError(f"invalid_database_identifier:{key}")
    return Settings(
        batch_size=exact_int(values, "NOTION_SYNC_BATCH_SIZE", 1, 100),
        max_attempts=exact_int(values, "NOTION_SYNC_MAX_ATTEMPTS", 1, 32),
        lease_seconds=exact_int(values, "NOTION_SYNC_LEASE_SECONDS", 60, 3600),
        retry_base_seconds=exact_int(values, "NOTION_SYNC_RETRY_BASE_SECONDS", 1, 900),
        interval_seconds=exact_int(values, "NOTION_SYNC_INTERVAL_SECONDS", 5, 3600),
    )


def parse_event(payload: Mapping[str, Any]) -> Event:
    exact_keys = {
        "id",
        "event_id",
        "object_kind",
        "canonical_object_id",
        "external_object_id",
        "operation",
        "canonical_revision",
        "canonical_content_hash",
        "attempt_count",
        "provider_object_id",
    }
    if set(payload) != exact_keys:
        raise ProjectionError("claimed_event_shape_invalid")
    try:
        canonical_object_id = str(uuid.UUID(str(payload["canonical_object_id"])))
        event_id = str(uuid.UUID(str(payload["event_id"])))
    except (ValueError, AttributeError) as exc:
        raise ProjectionError("claimed_event_uuid_invalid") from exc
    revision = payload["canonical_revision"]
    attempt_count = payload["attempt_count"]
    event_row_id = payload["id"]
    content_hash = payload["canonical_content_hash"]
    provider_object_id = payload["provider_object_id"]
    if (
        not isinstance(event_row_id, int)
        or event_row_id <= 0
        or payload["object_kind"] not in {"entity", "document"}
        or payload["operation"] not in {"upsert", "delete"}
        or not isinstance(payload["external_object_id"], str)
        or not 1 <= len(payload["external_object_id"]) <= 512
        or not isinstance(revision, int)
        or revision <= 0
        or not isinstance(attempt_count, int)
        or attempt_count <= 0
        or not isinstance(content_hash, str)
        or not re.fullmatch(r"[0-9a-f]{64}", content_hash)
        or (
            provider_object_id is not None
            and (
                not isinstance(provider_object_id, str) or len(provider_object_id) > 512
            )
        )
    ):
        raise ProjectionError("claimed_event_values_invalid")
    return Event(
        id=event_row_id,
        event_id=event_id,
        object_kind=str(payload["object_kind"]),
        canonical_object_id=canonical_object_id,
        external_object_id=str(payload["external_object_id"]),
        operation=str(payload["operation"]),
        canonical_revision=revision,
        canonical_content_hash=content_hash,
        attempt_count=attempt_count,
        provider_object_id=provider_object_id,
    )


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def chunks(value: str, size: int = 1800) -> list[str]:
    if not value:
        return []
    return [value[index : index + size] for index in range(0, len(value), size)]


def document_title(title: str, canonical_object_id: str) -> str:
    suffix = f" [mte:{canonical_object_id}]"
    normalized = " ".join(title.split()) or "Untitled"
    return normalized[: 2000 - len(suffix)] + suffix


def stable_error_digest(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class Consumer:
    def __init__(
        self,
        values: dict[str, str],
        notion_config: Any,
        settings: Settings,
        *,
        instance_id: str | None = None,
        psql: Callable[[dict[str, str], str, str], str] | None = None,
        notion: ModuleType = NOTION,
    ) -> None:
        self.values = values
        self.notion_config = notion_config
        self.settings = settings
        self.notion = notion
        self.psql = psql or POSTGREST.psql
        if instance_id is None:
            material = f"{socket.gethostname()}:{os.getpid()}:{secrets.token_hex(16)}"
            instance_id = (
                "mte-notion-sync-" + hashlib.sha256(material.encode()).hexdigest()[:20]
            )
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", instance_id):
            raise ProjectionError("consumer_instance_id_invalid")
        self.instance_id = instance_id

    @property
    def database(self) -> str:
        return self.values["POSTGREST_DATA_DB_NAME"]

    def sql(self, statement: str) -> str:
        return self.psql(self.values, self.database, statement).strip()

    def sql_json(self, statement: str) -> dict[str, Any] | None:
        raw = self.sql(statement)
        if not raw:
            return None
        if "\n" in raw:
            raise ProjectionError("database_response_cardinality_invalid")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProjectionError("database_response_json_invalid") from exc
        if not isinstance(payload, dict):
            raise ProjectionError("database_response_shape_invalid")
        return payload

    def ack_superseded(self) -> int:
        raw = self.sql(
            """
WITH superseded AS (
  UPDATE api.provider_outbox o
     SET delivery_state='delivered', delivered_at=now(), updated_at=now(),
         locked_by=NULL, lease_expires_at=NULL, last_error_digest=NULL
    FROM api.provider_sync_state s
   WHERE o.provider='notion'
     AND s.provider=o.provider
     AND s.object_kind=o.object_kind
     AND s.canonical_object_id=o.canonical_object_id
     AND (
       o.delivery_state IN ('pending','failed')
       OR (o.delivery_state='processing' AND o.lease_expires_at <= now())
     )
     AND s.canonical_revision > o.canonical_revision
  RETURNING o.id
)
SELECT count(*) FROM superseded;
"""
        )
        if not re.fullmatch(r"[0-9]+", raw):
            raise ProjectionError("superseded_count_invalid")
        return int(raw)

    def reap_exhausted(self) -> int:
        digest = POSTGREST.sql_literal(stable_error_digest("max_attempts_exhausted"))
        raw = self.sql(
            f"""
WITH candidate AS MATERIALIZED (
  SELECT o.id, o.object_kind, o.canonical_object_id, o.operation,
         o.canonical_revision, o.canonical_content_hash, o.locked_by
    FROM api.provider_outbox o
    JOIN api.provider_sync_state s
      ON s.provider=o.provider
     AND s.object_kind=o.object_kind
     AND s.canonical_object_id=o.canonical_object_id
   WHERE o.provider='notion'
     AND o.delivery_state='processing'
     AND o.lease_expires_at <= now()
     AND o.attempt_count >= {self.settings.max_attempts}
   ORDER BY o.id
   FOR UPDATE OF o, s SKIP LOCKED
   LIMIT {self.settings.batch_size}
), failed AS (
  UPDATE api.provider_outbox o
     SET delivery_state='failed', available_at=now(), updated_at=now(),
         locked_by=NULL, lease_expires_at=NULL, last_error_digest={digest}
    FROM candidate c
   WHERE o.id=c.id
  RETURNING o.id
), errored AS (
  UPDATE api.provider_sync_state s
     SET sync_status='error', updated_at=now(), locked_by=NULL,
         lease_expires_at=NULL, last_error_digest={digest}
    FROM candidate c
   WHERE s.provider='notion' AND s.object_kind=c.object_kind
     AND s.canonical_object_id=c.canonical_object_id
     AND s.canonical_revision=c.canonical_revision
     AND s.canonical_content_hash=c.canonical_content_hash
     AND s.desired_operation=c.operation
     AND s.sync_status='syncing'
     AND s.locked_by=c.locked_by
     AND EXISTS (SELECT 1 FROM failed WHERE id=c.id)
  RETURNING s.canonical_object_id
)
SELECT count(*) FROM failed;
"""
        )
        if not re.fullmatch(r"[0-9]+", raw):
            raise ProjectionError("exhausted_count_invalid")
        return int(raw)

    def claim_next(self) -> Event | None:
        owner = POSTGREST.sql_literal(self.instance_id)
        statement = f"""
WITH candidate AS MATERIALIZED (
  SELECT o.id, o.event_id, o.object_kind, o.canonical_object_id,
         o.external_object_id, o.operation, o.canonical_revision,
         o.canonical_content_hash, o.attempt_count,
         s.provider_object_id
    FROM api.provider_sync_state s
    JOIN api.provider_outbox o
      ON o.provider=s.provider
     AND o.object_kind=s.object_kind
     AND o.canonical_object_id=s.canonical_object_id
     AND o.operation=s.desired_operation
     AND o.canonical_revision=s.canonical_revision
     AND o.canonical_content_hash=s.canonical_content_hash
   WHERE s.provider='notion'
     AND o.attempt_count < {self.settings.max_attempts}
     AND (
       (o.delivery_state IN ('pending','failed') AND o.available_at <= now())
       OR (o.delivery_state='processing' AND o.lease_expires_at <= now())
     )
     AND (
       s.sync_status IN ('pending','error')
       OR (s.sync_status='syncing' AND s.lease_expires_at <= now())
     )
   ORDER BY o.id
   FOR UPDATE OF s, o SKIP LOCKED
   LIMIT 1
), claimed_sync AS (
  UPDATE api.provider_sync_state s
     SET sync_status='syncing', attempt_count=s.attempt_count+1,
         last_attempt_at=now(), updated_at=now(), locked_by={owner},
         lease_expires_at=now()+make_interval(secs => {self.settings.lease_seconds}),
         last_error_digest=NULL
    FROM candidate c
   WHERE s.provider='notion'
     AND s.object_kind=c.object_kind
     AND s.canonical_object_id=c.canonical_object_id
  RETURNING s.canonical_object_id
), claimed_outbox AS (
  UPDATE api.provider_outbox o
     SET delivery_state='processing', attempt_count=o.attempt_count+1,
         updated_at=now(), locked_by={owner},
         lease_expires_at=now()+make_interval(secs => {self.settings.lease_seconds}),
         last_error_digest=NULL
    FROM candidate c
   WHERE o.id=c.id
  RETURNING o.id, o.event_id, o.object_kind, o.canonical_object_id,
            o.external_object_id, o.operation, o.canonical_revision,
            o.canonical_content_hash, o.attempt_count
)
SELECT jsonb_build_object(
  'id', o.id,
  'event_id', o.event_id,
  'object_kind', o.object_kind,
  'canonical_object_id', o.canonical_object_id,
  'external_object_id', o.external_object_id,
  'operation', o.operation,
  'canonical_revision', o.canonical_revision,
  'canonical_content_hash', o.canonical_content_hash,
  'attempt_count', o.attempt_count,
  'provider_object_id', c.provider_object_id
)::text
FROM claimed_outbox o
JOIN candidate c ON c.id=o.id
JOIN claimed_sync s ON s.canonical_object_id=o.canonical_object_id;
"""
        payload = self.sql_json(statement)
        return parse_event(payload) if payload is not None else None

    def canonical_row(self, event: Event) -> dict[str, Any] | None:
        table = (
            "api.canonical_entities"
            if event.object_kind == "entity"
            else "api.canonical_documents"
        )
        object_id = POSTGREST.sql_literal(event.canonical_object_id)
        return self.sql_json(
            f"SELECT row_to_json(t)::text FROM {table} t WHERE id={object_id}::uuid;"
        )

    def validate_canonical(self, event: Event) -> tuple[dict[str, Any] | None, bool]:
        row = self.canonical_row(event)
        if row is not None:
            try:
                row_id = str(uuid.UUID(str(row.get("id"))))
            except (ValueError, AttributeError) as exc:
                raise ProjectionError("canonical_row_id_invalid") from exc
            revision = row.get("revision")
            if isinstance(revision, int) and revision > event.canonical_revision:
                return row, True
            if (
                row_id != event.canonical_object_id
                or row.get("external_object_id") != event.external_object_id
                or revision != event.canonical_revision
                or row.get("content_hash") != event.canonical_content_hash
            ):
                raise ProjectionError("canonical_event_linkage_drift")
        if event.operation == "upsert" and row is None:
            raise ProjectionError("canonical_object_missing_for_upsert")
        if event.operation == "delete" and row is not None:
            raise ProjectionError("canonical_object_present_for_delete")
        return row, False

    def renew_lease(self, event: Event) -> None:
        owner = POSTGREST.sql_literal(self.instance_id)
        raw = self.sql(
            f"""
WITH renewed_outbox AS (
  UPDATE api.provider_outbox
     SET lease_expires_at=now()+make_interval(secs => {self.settings.lease_seconds}),
         updated_at=now()
   WHERE id={event.id} AND event_id={POSTGREST.sql_literal(event.event_id)}::uuid
     AND delivery_state='processing' AND locked_by={owner}
  RETURNING id
), renewed_sync AS (
  UPDATE api.provider_sync_state
     SET lease_expires_at=now()+make_interval(secs => {self.settings.lease_seconds}),
         updated_at=now()
   WHERE provider='notion' AND object_kind={POSTGREST.sql_literal(event.object_kind)}
     AND canonical_object_id={POSTGREST.sql_literal(event.canonical_object_id)}::uuid
     AND sync_status='syncing' AND locked_by={owner}
     AND EXISTS (SELECT 1 FROM renewed_outbox)
  RETURNING canonical_object_id
)
SELECT concat_ws('|',(SELECT count(*) FROM renewed_outbox),
  (SELECT count(*) FROM renewed_sync));
"""
        )
        if raw != "1|1":
            raise ProjectionError("projection_lease_lost")

    def metadata(self, event: Event, row: Mapping[str, Any]) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "canonicalObjectId": event.canonical_object_id,
            "externalObjectId": event.external_object_id,
            "objectKind": event.object_kind,
            "revision": event.canonical_revision,
            "contentHash": event.canonical_content_hash,
            "metadataHash": hashlib.sha256(
                canonical_json(row.get("metadata")).encode()
            ).hexdigest(),
        }
        if event.object_kind == "document":
            metadata["contentType"] = row.get("content_type")
        return metadata

    def projection_body(self, event: Event, row: Mapping[str, Any]) -> str:
        if event.object_kind == "document":
            body = row.get("body")
            if not isinstance(body, str):
                raise ProjectionError("canonical_document_body_invalid")
            return body
        return canonical_json(
            {"data": row.get("data"), "metadata": row.get("metadata")}
        )

    def projection_children(
        self, event: Event, row: Mapping[str, Any]
    ) -> list[dict[str, Any]]:
        envelope = MARKER_PREFIX + canonical_json(self.metadata(event, row))
        if len(envelope) > 2000:
            raise ProjectionError("projection_metadata_too_large")
        return [self.notion.paragraph(envelope)] + [
            self.notion.paragraph(part)
            for part in chunks(self.projection_body(event, row))
        ]

    def replace_children(
        self, page_id: str, event: Event, row: Mapping[str, Any]
    ) -> None:
        existing = self.notion.paginated(
            self.notion_config, "/blocks/" + page_id + "/children"
        )
        for index, block in enumerate(existing):
            if index % 20 == 0:
                self.renew_lease(event)
            if not isinstance(block, dict):
                raise ProjectionError("notion_child_block_invalid")
            block_id = self.notion.api_id(block.get("id"), "projection_block")
            self.notion.request_json(
                self.notion_config,
                "DELETE",
                "/blocks/" + block_id,
                expected={200},
                retry_safe=True,
            )
        desired = self.projection_children(event, row)
        for index in range(0, len(desired), 100):
            self.renew_lease(event)
            # Appending is not response-retry safe.  A failed/ambiguous request
            # leaves the event leased until it is retried from a clean replace.
            self.notion.request_json(
                self.notion_config,
                "PATCH",
                "/blocks/" + page_id + "/children",
                body={"children": desired[index : index + 100]},
                expected={200},
                retry_safe=False,
            )

    def readback_body(self, page_id: str) -> tuple[dict[str, Any], str]:
        children = self.notion.paginated(
            self.notion_config, "/blocks/" + page_id + "/children"
        )
        texts = [self.notion.block_text(block) for block in children]
        if not texts or not texts[0].startswith(MARKER_PREFIX):
            raise ProjectionError("notion_projection_marker_missing")
        try:
            metadata = json.loads(texts[0][len(MARKER_PREFIX) :])
        except json.JSONDecodeError as exc:
            raise ProjectionError("notion_projection_marker_invalid") from exc
        if not isinstance(metadata, dict):
            raise ProjectionError("notion_projection_metadata_invalid")
        return metadata, "".join(texts[1:])

    def verify_readback(
        self, page_id: str, event: Event, row: Mapping[str, Any]
    ) -> None:
        metadata, body = self.readback_body(page_id)
        if metadata != self.metadata(event, row):
            raise ProjectionError("notion_projection_metadata_drift")
        if body != self.projection_body(event, row):
            raise ProjectionError("notion_projection_body_drift")

    def resolve_entity_page(self, event: Event) -> dict[str, Any] | None:
        if event.provider_object_id:
            return self.notion.retrieve_page(
                self.notion_config,
                self.notion.canonical_id(
                    event.provider_object_id, "provider_object_id"
                ),
            )
        rows = self.notion.query_object(
            self.notion_config,
            self.notion_config.data_source_id or "",
            event.external_object_id,
        )
        if len(rows) > 1:
            raise ProjectionError("duplicate_notion_entity_projection")
        if rows and not isinstance(rows[0], dict):
            raise ProjectionError("notion_entity_projection_invalid")
        return rows[0] if rows else None

    def document_pages(self, event: Event) -> list[dict[str, Any]]:
        rows = self.notion.paginated(
            self.notion_config,
            "/blocks/" + (self.notion_config.documents_page_id or "") + "/children",
        )
        matches: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict) or row.get("type") != "child_page":
                continue
            child = row.get("child_page")
            title = child.get("title") if isinstance(child, dict) else None
            marker = DOCUMENT_MARKER.search(title) if isinstance(title, str) else None
            if marker and marker.group(1) == event.canonical_object_id:
                matches.append(row)
        if len(matches) > 1:
            raise ProjectionError("duplicate_notion_document_projection")
        return matches

    def resolve_document_page(self, event: Event) -> dict[str, Any] | None:
        if event.provider_object_id:
            return self.notion.retrieve_page(
                self.notion_config,
                self.notion.canonical_id(
                    event.provider_object_id, "provider_object_id"
                ),
            )
        rows = self.document_pages(event)
        if not rows:
            return None
        return self.notion.retrieve_page(
            self.notion_config,
            self.notion.api_id(rows[0].get("id"), "document_projection"),
        )

    def upsert_entity(self, event: Event, row: Mapping[str, Any]) -> str:
        page = self.resolve_entity_page(event)
        properties = self.notion.table_properties(
            str(row.get("title") or "Untitled"),
            event.external_object_id,
            event.canonical_revision,
            event.canonical_content_hash,
            "synced",
        )
        if page is None:
            _, payload = self.notion.request_json(
                self.notion_config,
                "POST",
                "/pages",
                body={
                    "parent": {
                        "type": "data_source_id",
                        "data_source_id": self.notion_config.data_source_id,
                    },
                    "properties": properties,
                },
                expected={200},
                retry_safe=False,
            )
            if not isinstance(payload, dict):
                raise ProjectionError("notion_entity_create_invalid")
            page = payload
        page_id = self.notion.api_id(page.get("id"), "entity_projection")
        if event.provider_object_id and page_id != event.provider_object_id:
            raise ProjectionError("notion_provider_object_mapping_drift")
        self.notion.request_json(
            self.notion_config,
            "PATCH",
            "/pages/" + page_id,
            body={"archived": False, "properties": properties},
            expected={200},
            retry_safe=True,
        )
        self.replace_children(page_id, event, row)
        final = self.notion.retrieve_page(self.notion_config, page_id)
        if (
            final.get("archived") is True
            or self.notion.property_text(final, "Postgres Object ID", "rich_text")
            != event.external_object_id
            or self.notion.property_number(final, "Postgres Revision")
            != event.canonical_revision
            or self.notion.property_text(final, "Sync Hash", "rich_text")
            != event.canonical_content_hash
            or self.notion.property_select(final, "Sync State") != "synced"
        ):
            raise ProjectionError("notion_entity_readback_drift")
        self.verify_readback(page_id, event, row)
        return page_id

    def upsert_document(self, event: Event, row: Mapping[str, Any]) -> str:
        page = self.resolve_document_page(event)
        title = document_title(
            str(row.get("title") or "Untitled"), event.canonical_object_id
        )
        if page is None:
            _, payload = self.notion.request_json(
                self.notion_config,
                "POST",
                "/pages",
                body={
                    "parent": {
                        "type": "page_id",
                        "page_id": self.notion_config.documents_page_id,
                    },
                    "properties": {"title": self.notion.title_property(title)},
                },
                expected={200},
                retry_safe=False,
            )
            if not isinstance(payload, dict):
                raise ProjectionError("notion_document_create_invalid")
            page = payload
        page_id = self.notion.api_id(page.get("id"), "document_projection")
        if event.provider_object_id and page_id != event.provider_object_id:
            raise ProjectionError("notion_provider_object_mapping_drift")
        self.notion.request_json(
            self.notion_config,
            "PATCH",
            "/pages/" + page_id,
            body={
                "archived": False,
                "properties": {"title": self.notion.title_property(title)},
            },
            expected={200},
            retry_safe=True,
        )
        self.replace_children(page_id, event, row)
        final = self.notion.retrieve_page(self.notion_config, page_id)
        marker = DOCUMENT_MARKER.search(self.notion.page_title(final))
        if (
            final.get("archived") is True
            or marker is None
            or marker.group(1) != event.canonical_object_id
        ):
            raise ProjectionError("notion_document_readback_drift")
        self.verify_readback(page_id, event, row)
        return page_id

    def archive(self, event: Event) -> str | None:
        self.renew_lease(event)
        page = (
            self.resolve_entity_page(event)
            if event.object_kind == "entity"
            else self.resolve_document_page(event)
        )
        if page is None:
            return event.provider_object_id
        page_id = self.notion.api_id(page.get("id"), "archive_projection")
        if event.provider_object_id and page_id != event.provider_object_id:
            raise ProjectionError("notion_provider_object_mapping_drift")
        self.notion.request_json(
            self.notion_config,
            "PATCH",
            "/pages/" + page_id,
            body={"archived": True},
            expected={200},
            retry_safe=True,
        )
        if (
            self.notion.retrieve_page(self.notion_config, page_id).get("archived")
            is not True
        ):
            raise ProjectionError("notion_archive_readback_drift")
        return page_id

    def finalize_success(self, event: Event, provider_object_id: str | None) -> None:
        owner = POSTGREST.sql_literal(self.instance_id)
        provider_id = (
            "NULL"
            if provider_object_id is None
            else POSTGREST.sql_literal(provider_object_id)
        )
        raw = self.sql(
            f"""
WITH delivered AS (
  UPDATE api.provider_outbox
     SET delivery_state='delivered', delivered_at=now(), updated_at=now(),
         locked_by=NULL, lease_expires_at=NULL, last_error_digest=NULL
   WHERE id={event.id} AND event_id={POSTGREST.sql_literal(event.event_id)}::uuid
     AND delivery_state='processing' AND locked_by={owner}
  RETURNING id
), synced AS (
  UPDATE api.provider_sync_state
     SET provider_object_id=COALESCE({provider_id}, provider_object_id),
         projected_revision={event.canonical_revision},
         projected_content_hash={POSTGREST.sql_literal(event.canonical_content_hash)},
         sync_status='synced', synced_at=now(), updated_at=now(),
         locked_by=NULL, lease_expires_at=NULL, last_error_digest=NULL
   WHERE provider='notion' AND object_kind={POSTGREST.sql_literal(event.object_kind)}
     AND canonical_object_id={POSTGREST.sql_literal(event.canonical_object_id)}::uuid
     AND canonical_revision={event.canonical_revision}
     AND canonical_content_hash={POSTGREST.sql_literal(event.canonical_content_hash)}
     AND desired_operation={POSTGREST.sql_literal(event.operation)}
     AND sync_status='syncing' AND locked_by={owner}
     AND EXISTS (SELECT 1 FROM delivered)
  RETURNING canonical_object_id
), released AS (
  UPDATE api.provider_sync_state
     SET sync_status='pending', updated_at=now(), locked_by=NULL,
         lease_expires_at=NULL
   WHERE provider='notion' AND object_kind={POSTGREST.sql_literal(event.object_kind)}
     AND canonical_object_id={POSTGREST.sql_literal(event.canonical_object_id)}::uuid
     AND canonical_revision > {event.canonical_revision}
     AND sync_status='syncing' AND locked_by={owner}
     AND EXISTS (SELECT 1 FROM delivered)
  RETURNING canonical_object_id
)
SELECT concat_ws('|',(SELECT count(*) FROM delivered),(SELECT count(*) FROM synced),
  (SELECT count(*) FROM released));
"""
        )
        if raw not in {"1|1|0", "1|0|1"}:
            raise ProjectionError("projection_finalize_lost_lease")

    def finalize_superseded(self, event: Event) -> None:
        owner = POSTGREST.sql_literal(self.instance_id)
        raw = self.sql(
            f"""
WITH delivered AS (
  UPDATE api.provider_outbox
     SET delivery_state='delivered', delivered_at=now(), updated_at=now(),
         locked_by=NULL, lease_expires_at=NULL, last_error_digest=NULL
   WHERE id={event.id} AND event_id={POSTGREST.sql_literal(event.event_id)}::uuid
     AND delivery_state='processing' AND locked_by={owner}
  RETURNING id
), released AS (
  UPDATE api.provider_sync_state
     SET sync_status='pending', updated_at=now(), locked_by=NULL,
         lease_expires_at=NULL
   WHERE provider='notion' AND object_kind={POSTGREST.sql_literal(event.object_kind)}
     AND canonical_object_id={POSTGREST.sql_literal(event.canonical_object_id)}::uuid
     AND sync_status='syncing' AND locked_by={owner}
     AND canonical_revision > {event.canonical_revision}
  RETURNING canonical_object_id
)
SELECT concat_ws('|',(SELECT count(*) FROM delivered),(SELECT count(*) FROM released));
"""
        )
        if raw != "1|1":
            raise ProjectionError("projection_supersede_lost_lease")

    def finalize_error(self, event: Event, code: str) -> bool:
        owner = POSTGREST.sql_literal(self.instance_id)
        digest = stable_error_digest(code)
        exponent = min(max(event.attempt_count - 1, 0), 12)
        delay = min(self.settings.retry_base_seconds * (2**exponent), 86400)
        raw = self.sql(
            f"""
WITH failed AS (
  UPDATE api.provider_outbox
     SET delivery_state='failed', updated_at=now(),
         available_at=now()+make_interval(secs => {delay}),
         locked_by=NULL, lease_expires_at=NULL,
         last_error_digest={POSTGREST.sql_literal(digest)}
   WHERE id={event.id} AND event_id={POSTGREST.sql_literal(event.event_id)}::uuid
     AND delivery_state='processing' AND locked_by={owner}
  RETURNING id
), errored AS (
  UPDATE api.provider_sync_state
     SET sync_status='error', updated_at=now(), locked_by=NULL,
         lease_expires_at=NULL,
         last_error_digest={POSTGREST.sql_literal(digest)}
   WHERE provider='notion' AND object_kind={POSTGREST.sql_literal(event.object_kind)}
     AND canonical_object_id={POSTGREST.sql_literal(event.canonical_object_id)}::uuid
     AND canonical_revision={event.canonical_revision}
     AND canonical_content_hash={POSTGREST.sql_literal(event.canonical_content_hash)}
     AND desired_operation={POSTGREST.sql_literal(event.operation)}
     AND sync_status='syncing' AND locked_by={owner}
     AND EXISTS (SELECT 1 FROM failed)
  RETURNING canonical_object_id
), released AS (
  UPDATE api.provider_sync_state
     SET sync_status='pending', updated_at=now(), locked_by=NULL,
         lease_expires_at=NULL
   WHERE provider='notion' AND object_kind={POSTGREST.sql_literal(event.object_kind)}
     AND canonical_object_id={POSTGREST.sql_literal(event.canonical_object_id)}::uuid
     AND canonical_revision > {event.canonical_revision}
     AND sync_status='syncing' AND locked_by={owner}
     AND EXISTS (SELECT 1 FROM failed)
  RETURNING canonical_object_id
), superseded AS (
  UPDATE api.provider_outbox
     SET delivery_state='delivered', delivered_at=now(), updated_at=now(),
         available_at=now(), last_error_digest=NULL
   WHERE id={event.id} AND EXISTS (SELECT 1 FROM released)
  RETURNING id
)
SELECT concat_ws('|',(SELECT count(*) FROM failed),(SELECT count(*) FROM errored),
  (SELECT count(*) FROM released),(SELECT count(*) FROM superseded));
"""
        )
        if raw == "1|0|1|1":
            return True
        if raw != "1|1|0|0":
            raise ProjectionError("projection_failure_lost_lease")
        return False

    def process(self, event: Event) -> str:
        try:
            row, superseded = self.validate_canonical(event)
            if superseded:
                self.finalize_superseded(event)
                return "superseded"
            self.renew_lease(event)
            if event.operation == "delete":
                provider_object_id = self.archive(event)
            elif event.object_kind == "entity":
                if row is None:
                    raise ProjectionError("canonical_object_missing_for_upsert")
                provider_object_id = self.upsert_entity(event, row)
            else:
                if row is None:
                    raise ProjectionError("canonical_object_missing_for_upsert")
                provider_object_id = self.upsert_document(event, row)
            self.renew_lease(event)
            self.finalize_success(event, provider_object_id)
            return "delivered"
        except Exception as exc:
            code = (
                str(exc)
                if isinstance(exc, ProjectionError)
                else getattr(exc, "code", type(exc).__name__)
            )
            safe_code = re.sub(r"[^A-Za-z0-9_.:-]", "_", str(code))[:160]
            superseded = self.finalize_error(event, safe_code or "projection_error")
            return "superseded" if superseded else "failed"

    def drain(self, max_events: int | None = None) -> dict[str, int]:
        limit = max_events if max_events is not None else self.settings.batch_size
        if not 1 <= limit <= 10_000:
            raise ProjectionError("consumer_drain_limit_invalid")
        result = {"claimed": 0, "delivered": 0, "superseded": 0, "failed": 0}
        result["superseded"] += self.ack_superseded()
        result["failed"] += self.reap_exhausted()
        for _ in range(limit):
            event = self.claim_next()
            if event is None:
                break
            result["claimed"] += 1
            outcome = self.process(event)
            result[outcome] += 1
        return result

    def database_status(self) -> dict[str, Any]:
        payload = self.sql_json(
            f"""
SELECT jsonb_build_object(
  'pending', count(*) FILTER (WHERE delivery_state='pending'),
  'processing', count(*) FILTER (WHERE delivery_state='processing'),
  'failed', count(*) FILTER (WHERE delivery_state='failed'),
  'delivered', count(*) FILTER (WHERE delivery_state='delivered'),
  'eligible', count(*) FILTER (WHERE
      attempt_count < {self.settings.max_attempts}
      AND ((delivery_state IN ('pending','failed') AND available_at <= now())
           OR (delivery_state='processing' AND lease_expires_at <= now()))),
  'exhausted', count(*) FILTER (WHERE delivery_state='failed'
      AND attempt_count >= {self.settings.max_attempts}),
  'expiredLeases', count(*) FILTER (WHERE delivery_state='processing'
      AND lease_expires_at <= now()),
  'schemaReady', (
    SELECT count(*)=4 FROM information_schema.columns
     WHERE table_schema='api'
       AND table_name IN ('provider_outbox','provider_sync_state')
       AND column_name IN ('locked_by','lease_expires_at')
  )
)::text
FROM api.provider_outbox
WHERE provider='notion';
"""
        )
        if payload is None:
            raise ProjectionError("consumer_status_missing")
        expected = {
            "pending",
            "processing",
            "failed",
            "delivered",
            "eligible",
            "exhausted",
            "expiredLeases",
            "schemaReady",
        }
        if set(payload) != expected or any(
            not isinstance(payload[key], int) for key in expected - {"schemaReady"}
        ):
            raise ProjectionError("consumer_status_invalid")
        return payload


def atomic_text(path: Path, content: str, mode: int) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ProjectionError("refusing_systemd_symlink")
    encoded = content.encode()
    if (
        path.is_file()
        and path.read_bytes() == encoded
        and stat.S_IMODE(path.stat().st_mode) == mode
    ):
        return False
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(encoded)
    temporary.chmod(mode)
    temporary.replace(path)
    path.chmod(mode)
    return True


def run_command(
    argv: list[str], *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if check and result.returncode:
        raise ProjectionError(f"command_failed:{Path(argv[0]).name}")
    return result


def unit_documents(settings: Settings) -> tuple[str, str]:
    executable = ROOT / "bin/server-notion-sync.py"
    service = f"""[Unit]
Description=MTE PostgreSQL to Notion projection consumer
After=docker.service network-online.target
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=/usr/bin/python3 {executable} drain
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadOnlyPaths={SECRET_ROOT}
ReadWritePaths={ROOT / "evidence"} /run/docker.sock
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
"""
    timer = f"""[Unit]
Description=Schedule MTE PostgreSQL to Notion projection consumer

[Timer]
OnBootSec={settings.interval_seconds}s
OnUnitActiveSec={settings.interval_seconds}s
AccuracySec=1s
Persistent=true
Unit={SERVICE_NAME}

[Install]
WantedBy=timers.target
"""
    return service, timer


def install_units(settings: Settings) -> dict[str, Any]:
    service, timer = unit_documents(settings)
    changed = [
        name
        for name, content in ((SERVICE_NAME, service), (TIMER_NAME, timer))
        if atomic_text(SYSTEMD_ROOT / name, content, 0o644)
    ]
    run_command(["systemctl", "daemon-reload"])
    run_command(["systemctl", "enable", "--now", TIMER_NAME])
    return {"changedUnits": changed, "timerEnabled": True}


def unit_status(settings: Settings) -> dict[str, Any]:
    expected_service, expected_timer = unit_documents(settings)
    exact = (
        (SYSTEMD_ROOT / SERVICE_NAME).is_file()
        and (SYSTEMD_ROOT / TIMER_NAME).is_file()
        and (SYSTEMD_ROOT / SERVICE_NAME).read_text() == expected_service
        and (SYSTEMD_ROOT / TIMER_NAME).read_text() == expected_timer
        and stat.S_IMODE((SYSTEMD_ROOT / SERVICE_NAME).stat().st_mode) == 0o644
        and stat.S_IMODE((SYSTEMD_ROOT / TIMER_NAME).stat().st_mode) == 0o644
    )
    enabled = (
        run_command(
            ["systemctl", "is-enabled", "--quiet", TIMER_NAME], check=False
        ).returncode
        == 0
    )
    active = (
        run_command(
            ["systemctl", "is-active", "--quiet", TIMER_NAME], check=False
        ).returncode
        == 0
    )
    return {"exact": exact, "enabled": enabled, "active": active}


def atomic_evidence(payload: dict[str, Any], path: Path = EVIDENCE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def canary_identifiers(run_id: str) -> dict[str, str]:
    if not RUN_ID.fullmatch(run_id):
        raise ProjectionError("invalid_projection_canary_run_id")
    run_hash = sha256_text(run_id)
    namespace = uuid.UUID("61a314bf-d3cf-4c1a-aaf4-a8472f8719a0")
    return {
        "runHash": run_hash,
        "entityId": str(uuid.uuid5(namespace, run_hash + ":entity")),
        "documentId": str(uuid.uuid5(namespace, run_hash + ":document")),
        "entityExternalId": "mte-notion-projection:" + run_hash[:24] + ":entity",
        "documentExternalId": "mte-notion-projection:" + run_hash[:24] + ":document",
    }


def canary_state(
    worker: Consumer,
    *,
    object_kind: str,
    canonical_object_id: str,
    operation: str,
    revision: int,
    content_hash: str,
    canonical_expected: bool,
) -> tuple[dict[str, Any], str]:
    table = {
        "entity": "api.canonical_entities",
        "document": "api.canonical_documents",
    }.get(object_kind)
    if table is None or operation not in {"upsert", "delete"}:
        raise ProjectionError("projection_canary_state_request_invalid")
    object_id = POSTGREST.sql_literal(canonical_object_id)
    payload = worker.sql_json(
        f"""
SELECT jsonb_build_object(
  'canonicalExists', EXISTS(SELECT 1 FROM {table} WHERE id={object_id}::uuid),
  'canonicalRevision', (SELECT revision FROM {table} WHERE id={object_id}::uuid),
  'canonicalContentHash', (SELECT content_hash FROM {table} WHERE id={object_id}::uuid),
  'sync', (
    SELECT jsonb_build_object(
      'desiredOperation', desired_operation,
      'canonicalRevision', canonical_revision,
      'canonicalContentHash', canonical_content_hash,
      'projectedRevision', projected_revision,
      'projectedContentHash', projected_content_hash,
      'syncStatus', sync_status,
      'providerObjectId', provider_object_id,
      'errorFree', last_error_digest IS NULL,
      'leaseReleased', locked_by IS NULL AND lease_expires_at IS NULL
    )
      FROM api.provider_sync_state
     WHERE provider='notion'
       AND object_kind={POSTGREST.sql_literal(object_kind)}
       AND canonical_object_id={object_id}::uuid
  ),
  'outbox', (
    SELECT jsonb_build_object(
      'deliveryState', delivery_state,
      'attemptCount', attempt_count,
      'delivered', delivered_at IS NOT NULL,
      'errorFree', last_error_digest IS NULL,
      'leaseReleased', locked_by IS NULL AND lease_expires_at IS NULL
    )
      FROM api.provider_outbox
     WHERE provider='notion'
       AND object_kind={POSTGREST.sql_literal(object_kind)}
       AND canonical_object_id={object_id}::uuid
       AND operation={POSTGREST.sql_literal(operation)}
       AND canonical_revision={revision}
       AND canonical_content_hash={POSTGREST.sql_literal(content_hash)}
  )
)::text;
"""
    )
    if payload is None or payload.get("canonicalExists") is not canonical_expected:
        raise ProjectionError("projection_canary_canonical_presence_drift")
    if canonical_expected and (
        payload.get("canonicalRevision") != revision
        or payload.get("canonicalContentHash") != content_hash
    ):
        raise ProjectionError("projection_canary_canonical_linkage_drift")
    sync = payload.get("sync")
    outbox = payload.get("outbox")
    if not isinstance(sync, dict) or not isinstance(outbox, dict):
        raise ProjectionError("projection_canary_state_missing")
    if (
        sync.get("desiredOperation") != operation
        or sync.get("canonicalRevision") != revision
        or sync.get("canonicalContentHash") != content_hash
        or sync.get("projectedRevision") != revision
        or sync.get("projectedContentHash") != content_hash
        or sync.get("syncStatus") != "synced"
        or sync.get("errorFree") is not True
        or sync.get("leaseReleased") is not True
        or outbox.get("deliveryState") != "delivered"
        or outbox.get("delivered") is not True
        or outbox.get("errorFree") is not True
        or outbox.get("leaseReleased") is not True
        or not isinstance(outbox.get("attemptCount"), int)
        or outbox["attemptCount"] < 1
    ):
        raise ProjectionError("projection_canary_delivery_state_drift")
    provider_object_id = sync.get("providerObjectId")
    if not isinstance(provider_object_id, str) or not provider_object_id:
        raise ProjectionError("projection_canary_provider_object_missing")
    provider_object_id = NOTION.canonical_id(
        provider_object_id, "projection_canary_provider_object"
    )
    return {
        "canonicalExact": True,
        "syncStateExact": True,
        "outboxDelivered": True,
        "attemptCount": outbox["attemptCount"],
        "leaseReleased": True,
        "errorFree": True,
    }, provider_object_id


def cleanup_canary(
    worker: Consumer,
    identifiers: Mapping[str, str],
    provider_ids: Mapping[str, str],
) -> dict[str, bool]:
    entity_id = POSTGREST.sql_literal(identifiers["entityId"])
    document_id = POSTGREST.sql_literal(identifiers["documentId"])
    archived = {"entity": False, "document": False}
    for object_kind in ("entity", "document"):
        canonical_object_id = identifiers[object_kind + "Id"]
        external_object_id = identifiers[object_kind + "ExternalId"]
        provider_object_id = provider_ids.get(object_kind)
        event = Event(
            id=1,
            event_id=str(uuid.uuid4()),
            object_kind=object_kind,
            canonical_object_id=canonical_object_id,
            external_object_id=external_object_id,
            operation="delete",
            canonical_revision=2,
            canonical_content_hash="0" * 64,
            attempt_count=1,
            provider_object_id=provider_object_id,
        )
        try:
            page = (
                worker.resolve_entity_page(event)
                if object_kind == "entity"
                else worker.resolve_document_page(event)
            )
            if page is None:
                archived[object_kind] = True
                continue
            page_id = worker.notion.api_id(page.get("id"), "projection_canary_cleanup")
            if page.get("archived") is True:
                archived[object_kind] = True
                continue
            worker.notion.request_json(
                worker.notion_config,
                "PATCH",
                "/pages/" + page_id,
                body={"archived": True},
                expected={200},
                retry_safe=True,
            )
            archived[object_kind] = (
                worker.notion.retrieve_page(worker.notion_config, page_id).get(
                    "archived"
                )
                is True
            )
        except Exception:
            archived[object_kind] = False
    worker.sql(
        f"""
DELETE FROM api.canonical_entities WHERE id={entity_id}::uuid;
DELETE FROM api.canonical_documents WHERE id={document_id}::uuid;
DELETE FROM api.provider_outbox
 WHERE provider='notion'
   AND canonical_object_id IN ({entity_id}::uuid,{document_id}::uuid);
DELETE FROM api.provider_sync_state
 WHERE provider='notion'
   AND canonical_object_id IN ({entity_id}::uuid,{document_id}::uuid);
"""
    )
    remaining = worker.sql_json(
        f"""
SELECT jsonb_build_object(
  'canonical',
    (SELECT count(*) FROM api.canonical_entities WHERE id={entity_id}::uuid)
    +(SELECT count(*) FROM api.canonical_documents WHERE id={document_id}::uuid),
  'syncState', (SELECT count(*) FROM api.provider_sync_state
     WHERE provider='notion'
       AND canonical_object_id IN ({entity_id}::uuid,{document_id}::uuid)),
  'outbox', (SELECT count(*) FROM api.provider_outbox
     WHERE provider='notion'
       AND canonical_object_id IN ({entity_id}::uuid,{document_id}::uuid))
)::text;
"""
    )
    if remaining is None:
        raise ProjectionError("projection_canary_cleanup_state_missing")
    return {
        "postgresCanonicalAbsent": remaining.get("canonical") == 0,
        "postgresSyncStateAbsent": remaining.get("syncState") == 0,
        "postgresOutboxAbsent": remaining.get("outbox") == 0,
        "notionEntityArchived": archived["entity"],
        "notionDocumentArchived": archived["document"],
    }


def assert_canary_redacted(
    payload: Mapping[str, Any], values: Mapping[str, str], raw_values: list[str]
) -> None:
    serialized = json.dumps(payload, sort_keys=True)
    secret_values = [
        value
        for key, value in values.items()
        if re.search(r"(?:TOKEN|SECRET|PASSWORD|API_KEY|LICENSE_KEY)$", key)
        and len(value) >= 8
    ]
    if any(value in serialized for value in secret_values):
        raise ProjectionError("projection_canary_secret_leak")
    if any(value and value in serialized for value in raw_values):
        raise ProjectionError("projection_canary_raw_marker_leak")


def live_canary_action(run_id: str) -> dict[str, Any]:
    worker, _settings = consumer()
    identifiers = canary_identifiers(run_id)
    run_hash = identifiers["runHash"]
    metadata = {"canary": True, "source": "postgres-notion-outbox"}
    entity_data = {
        "canary": True,
        "phase": "initial",
        "run": run_hash[:16],
    }
    entity_data_updated = {**entity_data, "phase": "updated"}
    document_body = "MTE projection document initial " + run_hash[:24]
    document_body_updated = "MTE projection document updated " + run_hash[:24]
    entity_body = canonical_json({"data": entity_data, "metadata": metadata})
    entity_body_updated = canonical_json(
        {"data": entity_data_updated, "metadata": metadata}
    )
    entity_hash = sha256_text(entity_body)
    entity_hash_updated = sha256_text(entity_body_updated)
    document_hash = sha256_text(document_body)
    document_hash_updated = sha256_text(document_body_updated)
    entity_id = POSTGREST.sql_literal(identifiers["entityId"])
    document_id = POSTGREST.sql_literal(identifiers["documentId"])
    provider_ids: dict[str, str] = {}
    cleanup: dict[str, bool] = {}
    raw_values = [
        run_id,
        identifiers["entityId"],
        identifiers["documentId"],
        identifiers["entityExternalId"],
        identifiers["documentExternalId"],
        entity_body,
        entity_body_updated,
        document_body,
        document_body_updated,
    ]
    try:
        preexisting = worker.sql_json(
            f"""
SELECT jsonb_build_object(
  'canonical',
    (SELECT count(*) FROM api.canonical_entities WHERE id={entity_id}::uuid)
    +(SELECT count(*) FROM api.canonical_documents WHERE id={document_id}::uuid),
  'syncState', (SELECT count(*) FROM api.provider_sync_state
     WHERE provider='notion'
       AND canonical_object_id IN ({entity_id}::uuid,{document_id}::uuid)),
  'outbox', (SELECT count(*) FROM api.provider_outbox
     WHERE provider='notion'
       AND canonical_object_id IN ({entity_id}::uuid,{document_id}::uuid))
)::text;
"""
        )
        if preexisting != {"canonical": 0, "syncState": 0, "outbox": 0}:
            raise ProjectionError("projection_canary_run_id_not_clean")
        worker.sql(
            f"""
BEGIN;
INSERT INTO api.canonical_entities (
  id, external_object_id, entity_type, title, data, metadata, revision, content_hash
) VALUES (
  {entity_id}::uuid,
  {POSTGREST.sql_literal(identifiers["entityExternalId"])},
  'record', 'MTE projection live entity',
  {POSTGREST.sql_literal(canonical_json(entity_data))}::jsonb,
  {POSTGREST.sql_literal(canonical_json(metadata))}::jsonb,
  1, {POSTGREST.sql_literal(entity_hash)}
);
INSERT INTO api.canonical_documents (
  id, external_object_id, title, body, content_type, metadata, revision, content_hash
) VALUES (
  {document_id}::uuid,
  {POSTGREST.sql_literal(identifiers["documentExternalId"])},
  'MTE projection live document', {POSTGREST.sql_literal(document_body)},
  'text/markdown', {POSTGREST.sql_literal(canonical_json(metadata))}::jsonb,
  1, {POSTGREST.sql_literal(document_hash)}
);
COMMIT;
"""
        )
        created_drain = worker.drain(max_events=8)
        created: dict[str, Any] = {}
        created["entity"], provider_ids["entity"] = canary_state(
            worker,
            object_kind="entity",
            canonical_object_id=identifiers["entityId"],
            operation="upsert",
            revision=1,
            content_hash=entity_hash,
            canonical_expected=True,
        )
        created["document"], provider_ids["document"] = canary_state(
            worker,
            object_kind="document",
            canonical_object_id=identifiers["documentId"],
            operation="upsert",
            revision=1,
            content_hash=document_hash,
            canonical_expected=True,
        )
        worker.sql(
            f"""
BEGIN;
UPDATE api.canonical_entities
   SET title='MTE projection live entity updated',
       data={POSTGREST.sql_literal(canonical_json(entity_data_updated))}::jsonb,
       revision=2, content_hash={POSTGREST.sql_literal(entity_hash_updated)}
 WHERE id={entity_id}::uuid;
UPDATE api.canonical_documents
   SET title='MTE projection live document updated',
       body={POSTGREST.sql_literal(document_body_updated)},
       revision=2, content_hash={POSTGREST.sql_literal(document_hash_updated)}
 WHERE id={document_id}::uuid;
COMMIT;
"""
        )
        updated_drain = worker.drain(max_events=8)
        updated: dict[str, Any] = {}
        updated["entity"], provider_ids["entity"] = canary_state(
            worker,
            object_kind="entity",
            canonical_object_id=identifiers["entityId"],
            operation="upsert",
            revision=2,
            content_hash=entity_hash_updated,
            canonical_expected=True,
        )
        updated["document"], provider_ids["document"] = canary_state(
            worker,
            object_kind="document",
            canonical_object_id=identifiers["documentId"],
            operation="upsert",
            revision=2,
            content_hash=document_hash_updated,
            canonical_expected=True,
        )
        worker.sql(
            f"""
BEGIN;
DELETE FROM api.canonical_entities WHERE id={entity_id}::uuid;
DELETE FROM api.canonical_documents WHERE id={document_id}::uuid;
COMMIT;
"""
        )
        archived_drain = worker.drain(max_events=8)
        archived: dict[str, Any] = {}
        archived["entity"], provider_ids["entity"] = canary_state(
            worker,
            object_kind="entity",
            canonical_object_id=identifiers["entityId"],
            operation="delete",
            revision=2,
            content_hash=entity_hash_updated,
            canonical_expected=False,
        )
        archived["document"], provider_ids["document"] = canary_state(
            worker,
            object_kind="document",
            canonical_object_id=identifiers["documentId"],
            operation="delete",
            revision=2,
            content_hash=document_hash_updated,
            canonical_expected=False,
        )
        notion_archived = {
            object_kind: worker.notion.retrieve_page(worker.notion_config, page_id).get(
                "archived"
            )
            is True
            for object_kind, page_id in provider_ids.items()
        }
        if notion_archived != {"entity": True, "document": True}:
            raise ProjectionError("projection_canary_notion_archive_drift")
        cleanup = cleanup_canary(worker, identifiers, provider_ids)
        if not all(cleanup.values()):
            raise ProjectionError("projection_canary_cleanup_failed")
        payload = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "NotionProjectionLiveCanary",
            "status": "passed",
            "ok": True,
            "generatedAt": utcnow(),
            "dataContentProfile": PROFILE,
            "provider": PROVIDER,
            "runIdSha256": sha256_text(run_id),
            "canonicalSourceSha256": canonical_source_sha(),
            "producerSha256": sha256_path(Path(__file__).resolve()),
            "dependencies": {
                "notionConnectorProducerSha256": sha256_path(
                    Path(NOTION.__file__).resolve()
                ),
                "postgrestProducerSha256": sha256_path(
                    Path(POSTGREST.__file__).resolve()
                ),
            },
            "phases": {
                "create": {"drain": created_drain, "objects": created},
                "update": {"drain": updated_drain, "objects": updated},
                "archive": {
                    "drain": archived_drain,
                    "objects": archived,
                    "notionArchived": notion_archived,
                },
            },
            "linkage": {
                "entity": {
                    "canonicalObjectIdSha256": sha256_text(identifiers["entityId"]),
                    "providerObjectIdSha256": sha256_text(provider_ids["entity"]),
                    "initialRevision": 1,
                    "finalRevision": 2,
                    "initialContentSha256": entity_hash,
                    "finalContentSha256": entity_hash_updated,
                },
                "document": {
                    "canonicalObjectIdSha256": sha256_text(identifiers["documentId"]),
                    "providerObjectIdSha256": sha256_text(provider_ids["document"]),
                    "initialRevision": 1,
                    "finalRevision": 2,
                    "initialContentSha256": document_hash,
                    "finalContentSha256": document_hash_updated,
                },
            },
            "cleanup": {**cleanup, "verified": all(cleanup.values())},
            "evidence": {"path": str(CANARY_EVIDENCE), "mode": "0600"},
            "redacted": True,
        }
        assert_canary_redacted(payload, worker.values, raw_values)
        atomic_evidence(payload, CANARY_EVIDENCE)
        return payload
    except Exception:
        try:
            cleanup_canary(worker, identifiers, provider_ids)
        except Exception:
            pass
        raise


def consumer() -> tuple[Consumer, Settings]:
    values = POSTGREST.dotenv(CANONICAL)
    settings = settings_from_env(values)
    POSTGREST.require_values(values)
    config = NOTION.config_from_env(values)
    if not config.documents_page_id or not config.data_source_id:
        raise ProjectionError("notion_projection_resources_not_provisioned")
    return Consumer(values, config, settings), settings


def provision_action() -> dict[str, Any]:
    worker, settings = consumer()
    installed = install_units(settings)
    drained = worker.drain()
    return {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "NotionProjectionConsumerProvision",
        "status": "converged",
        "ok": drained["failed"] == 0,
        "dataContentProfile": PROFILE,
        "provider": PROVIDER,
        "installed": installed,
        "drain": drained,
        "redacted": True,
    }


def verify_action() -> dict[str, Any]:
    worker, settings = consumer()
    drained = worker.drain(max_events=min(settings.batch_size * 4, 10_000))
    status = worker.database_status()
    units = unit_status(settings)
    ok = (
        drained["failed"] == 0
        and status["pending"] == 0
        and status["processing"] == 0
        and status["failed"] == 0
        and status["eligible"] == 0
        and status["exhausted"] == 0
        and status["expiredLeases"] == 0
        and status["schemaReady"] is True
        and all(units.values())
    )
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "NotionProjectionConsumerVerification",
        "status": "passed" if ok else "failed",
        "ok": ok,
        "generatedAt": utcnow(),
        "dataContentProfile": PROFILE,
        "provider": PROVIDER,
        "delivery": status,
        "drain": drained,
        "systemd": units,
        "settings": {
            "batchSize": settings.batch_size,
            "maxAttempts": settings.max_attempts,
            "leaseSeconds": settings.lease_seconds,
            "retryBaseSeconds": settings.retry_base_seconds,
            "intervalSeconds": settings.interval_seconds,
        },
        "canonicalSourceSha256": canonical_source_sha(),
        "producerSha256": sha256_path(Path(__file__).resolve()),
        "dependencies": {
            "notionConnectorProducerSha256": sha256_path(
                Path(NOTION.__file__).resolve()
            ),
            "postgrestProducerSha256": sha256_path(Path(POSTGREST.__file__).resolve()),
        },
        "evidence": {"path": str(EVIDENCE), "mode": "0600"},
        "redacted": True,
    }
    atomic_evidence(payload)
    if not ok:
        raise ProjectionError("notion_projection_verification_failed")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action", choices=("provision", "drain", "status", "verify", "canary")
    )
    parser.add_argument("--max-events", type=int)
    parser.add_argument("--run-id")
    args = parser.parse_args()
    try:
        if args.action == "provision":
            result = provision_action()
        elif args.action == "verify":
            result = verify_action()
        elif args.action == "canary":
            result = live_canary_action(args.run_id or secrets.token_hex(16))
        else:
            worker, settings = consumer()
            if args.action == "drain":
                result = {
                    "status": "completed",
                    "ok": True,
                    "drain": worker.drain(args.max_events),
                    "redacted": True,
                }
            else:
                result = {
                    "status": "observed",
                    "ok": True,
                    "delivery": worker.database_status(),
                    "systemd": unit_status(settings),
                    "redacted": True,
                }
        print(json.dumps(result, indent=2, sort_keys=True))
    except Exception as exc:
        code = (
            str(exc)
            if isinstance(exc, ProjectionError)
            else getattr(exc, "code", type(exc).__name__)
        )
        print(
            json.dumps({"ok": False, "error": str(code)[:160], "redacted": True}),
            file=sys.stderr,
        )
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()

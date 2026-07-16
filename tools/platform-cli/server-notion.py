#!/usr/bin/env python3
"""Provision and verify Notion as a replaceable PostgreSQL presentation plane."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from typing import Any, Mapping
import urllib.error
import urllib.parse
import urllib.request
import uuid


ROOT = Path(os.environ.get("MTE_PLATFORM_ROOT", "/opt/mte-platform"))
SECRET_ROOT = Path(
    os.environ.get(
        "MTE_SECRETS_ROOT",
        os.environ.get("MTE_SECRET_ROOT", "/root/.config/mte-secrets"),
    )
)
CANONICAL = SECRET_ROOT / "platform.env"
EVIDENCE = ROOT / "evidence/notion-connector-verify.json"
OFFICIAL_NOTION_BASE_URL = "https://api.notion.com/v1"
NOTION_API_VERSION = "2025-09-03"
DATA_CONTENT_PROFILE = "postgres-notion"
ROOT_TITLE = "MTE Agent Platform Connector"
DOCUMENTS_TITLE = "MTE Synced Documents"
DATABASE_TITLE = "MTE Synced Entities"
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

EXPECTED_PROPERTIES: dict[str, dict[str, Any]] = {
    "Name": {"title": {}},
    "Postgres Object ID": {"rich_text": {}},
    "Postgres Revision": {"number": {}},
    "Sync Hash": {"rich_text": {}},
    "Sync State": {
        "select": {
            "options": [
                {"name": "pending", "color": "yellow"},
                {"name": "synced", "color": "green"},
                {"name": "error", "color": "red"},
            ]
        }
    },
    "Entity Type": {
        "select": {
            "options": [
                {"name": "record", "color": "blue"},
                {"name": "document", "color": "purple"},
            ]
        }
    },
    "Updated At": {"date": {}},
}


class NotionError(RuntimeError):
    """Secret-safe, fail-closed connector error."""

    def __init__(self, code: str, *, status: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class Config:
    token: str = field(repr=False)
    base_url: str
    api_version: str
    root_page_id: str
    documents_page_id: str | None
    database_id: str | None
    data_source_id: str | None
    expected_workspace_id: str | None
    expected_bot_id: str | None


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_id(value: str, label: str) -> str:
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError) as exc:
        raise NotionError(f"invalid_notion_id:{label}") from exc


def optional_id(values: Mapping[str, str], key: str) -> str | None:
    value = values.get(key, "").strip()
    return canonical_id(value, key) if value else None


def canonical_env_values() -> dict[str, str]:
    if CANONICAL.is_symlink() or not CANONICAL.is_file():
        raise NotionError("canonical_env_missing_or_invalid")
    info = CANONICAL.stat()
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise NotionError("canonical_env_mode_invalid")
    if os.geteuid() == 0 and (info.st_uid != 0 or info.st_gid != 0):
        raise NotionError("canonical_env_owner_invalid")
    values: dict[str, str] = {}
    for raw in CANONICAL.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise NotionError("canonical_env_line_invalid")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in values:
            raise NotionError("canonical_env_key_invalid")
        values[key] = value
    return values


def config_from_env(values: Mapping[str, str] | None = None) -> Config:
    source = canonical_env_values() if values is None else values
    token = source.get("NOTION_TOKEN", "").strip()
    base_url = source.get("NOTION_API_BASE_URL", "").strip().rstrip("/")
    api_version = source.get("NOTION_API_VERSION", "").strip()
    root = source.get("NOTION_ROOT_PAGE_ID", "").strip()
    missing = [
        key
        for key, value in (
            ("NOTION_TOKEN", token),
            ("NOTION_API_BASE_URL", base_url),
            ("NOTION_API_VERSION", api_version),
            ("NOTION_ROOT_PAGE_ID", root),
        )
        if not value
    ]
    if missing:
        raise NotionError("missing_environment_refs:" + ",".join(missing))
    if api_version != NOTION_API_VERSION:
        raise NotionError("notion_api_version_drift")
    if base_url != OFFICIAL_NOTION_BASE_URL:
        raise NotionError("notion_api_base_url_drift")
    return Config(
        token=token,
        base_url=base_url,
        api_version=api_version,
        root_page_id=canonical_id(root, "NOTION_ROOT_PAGE_ID"),
        documents_page_id=optional_id(source, "NOTION_DOCUMENTS_PAGE_ID"),
        database_id=optional_id(source, "NOTION_TABLE_DATABASE_ID"),
        data_source_id=optional_id(source, "NOTION_TABLE_DATA_SOURCE_ID"),
        expected_workspace_id=optional_id(source, "NOTION_WORKSPACE_ID"),
        expected_bot_id=optional_id(source, "NOTION_BOT_ID"),
    )


def request_json(
    config: Config,
    method: str,
    path: str,
    *,
    body: Any | None = None,
    expected: set[int] = {200},
    retry_safe: bool = False,
) -> tuple[int, Any]:
    data = None
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer " + config.token,
        "Notion-Version": config.api_version,
        "User-Agent": "mte-notion-connector/1",
    }
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    url = config.base_url + path
    attempts = 3 if retry_safe else 1
    status = 0
    raw = b""
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, data=data, headers=headers, method=method),
                timeout=30,
            ) as response:
                status = int(response.status)
                raw = response.read(4_000_000)
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            raw = exc.read(4_000_000)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt + 1 < attempts:
                time.sleep(0.25 * (attempt + 1))
                continue
            raise NotionError("notion_http_unreachable") from exc
        if status not in {429, 500, 502, 503, 504} or attempt + 1 == attempts:
            break
        time.sleep(0.25 * (attempt + 1))
    if status not in expected:
        raise NotionError(f"notion_http_status:{status}", status=status)
    if not raw:
        return status, None
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError as exc:
        raise NotionError("notion_http_response_invalid") from exc


def api_id(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise NotionError(f"notion_response_id_missing:{label}")
    return canonical_id(value, label)


def rich_text(value: str) -> list[dict[str, Any]]:
    return [{"type": "text", "text": {"content": value}}]


def plain_text(items: Any) -> str:
    if not isinstance(items, list):
        return ""
    parts: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("plain_text"), str):
            parts.append(item["plain_text"])
        elif isinstance(item.get("text"), dict) and isinstance(
            item["text"].get("content"), str
        ):
            parts.append(item["text"]["content"])
    return "".join(parts)


def page_title(page: dict[str, Any]) -> str:
    properties = page.get("properties")
    if not isinstance(properties, dict):
        return ""
    titles = [
        plain_text(value.get("title"))
        for value in properties.values()
        if isinstance(value, dict) and value.get("type") == "title"
    ]
    return titles[0] if len(titles) == 1 else ""


def database_title(database: dict[str, Any]) -> str:
    return plain_text(database.get("title"))


def data_source_title(data_source: dict[str, Any]) -> str:
    return plain_text(data_source.get("title"))


def parent_id(resource: dict[str, Any], expected_type: str, label: str) -> str:
    parent = resource.get("parent")
    if not isinstance(parent, dict) or parent.get("type") != expected_type:
        raise NotionError(f"notion_parent_type_drift:{label}")
    return api_id(parent.get(expected_type), label + "_parent")


def retrieve_page(config: Config, page_id: str) -> dict[str, Any]:
    _, payload = request_json(config, "GET", "/pages/" + page_id, retry_safe=True)
    if not isinstance(payload, dict) or payload.get("object") != "page":
        raise NotionError("notion_page_response_invalid")
    return payload


def retrieve_database(config: Config, database_id: str) -> dict[str, Any]:
    _, payload = request_json(
        config, "GET", "/databases/" + database_id, retry_safe=True
    )
    if not isinstance(payload, dict) or payload.get("object") != "database":
        raise NotionError("notion_database_response_invalid")
    return payload


def retrieve_data_source(config: Config, data_source_id: str) -> dict[str, Any]:
    _, payload = request_json(
        config, "GET", "/data_sources/" + data_source_id, retry_safe=True
    )
    if not isinstance(payload, dict) or payload.get("object") != "data_source":
        raise NotionError("notion_data_source_response_invalid")
    return payload


def paginated(
    config: Config, path: str, *, body: dict[str, Any] | None = None
) -> list[Any]:
    rows: list[Any] = []
    cursor: str | None = None
    while True:
        if body is None:
            query = "?page_size=100"
            if cursor:
                query += "&start_cursor=" + urllib.parse.quote(cursor, safe="")
            _, payload = request_json(config, "GET", path + query, retry_safe=True)
        else:
            request_body = {**body, "page_size": 100}
            if cursor:
                request_body["start_cursor"] = cursor
            _, payload = request_json(
                config,
                "POST",
                path,
                body=request_body,
                retry_safe=True,
            )
        if not isinstance(payload, dict) or not isinstance(
            payload.get("results"), list
        ):
            raise NotionError("notion_paginated_response_invalid")
        rows.extend(payload["results"])
        if payload.get("has_more") is not True:
            return rows
        cursor_value = payload.get("next_cursor")
        if not isinstance(cursor_value, str) or not cursor_value:
            raise NotionError("notion_pagination_cursor_invalid")
        cursor = cursor_value


def identity(config: Config) -> dict[str, Any]:
    _, payload = request_json(config, "GET", "/users/me", retry_safe=True)
    if (
        not isinstance(payload, dict)
        or payload.get("object") != "user"
        or payload.get("type") != "bot"
        or not isinstance(payload.get("bot"), dict)
    ):
        raise NotionError("notion_bot_identity_invalid")
    bot = payload["bot"]
    owner = bot.get("owner")
    if (
        not isinstance(owner, dict)
        or owner.get("type") != "workspace"
        or owner.get("workspace") is not True
    ):
        raise NotionError("notion_bot_owner_not_workspace")
    bot_id = api_id(payload.get("id"), "bot")
    workspace_id = api_id(bot.get("workspace_id"), "workspace")
    if config.expected_bot_id and bot_id != config.expected_bot_id:
        raise NotionError("notion_bot_identity_drift")
    if config.expected_workspace_id and workspace_id != config.expected_workspace_id:
        raise NotionError("notion_workspace_identity_drift")
    if not isinstance(bot.get("workspace_name"), str) or not bot["workspace_name"]:
        raise NotionError("notion_workspace_name_missing")
    return {
        "botId": bot_id,
        "workspaceId": workspace_id,
        "botExact": True,
        "workspaceExact": True,
    }


def verify_managed_page(
    page: dict[str, Any], *, page_id: str, title: str, parent: str | None
) -> None:
    if api_id(page.get("id"), title) != page_id or page.get("archived") is True:
        raise NotionError("notion_managed_page_identity_drift")
    if page_title(page) != title:
        raise NotionError("notion_managed_page_title_drift")
    if parent is not None and parent_id(page, "page_id", title) != parent:
        raise NotionError("notion_managed_page_parent_drift")


def find_document_page(config: Config, root_page_id: str) -> dict[str, Any] | None:
    rows = paginated(
        config,
        "/search",
        body={
            "query": DOCUMENTS_TITLE,
            "filter": {"property": "object", "value": "page"},
        },
    )
    matches: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or page_title(row) != DOCUMENTS_TITLE:
            continue
        try:
            if parent_id(row, "page_id", "documents_search") == root_page_id:
                matches.append(row)
        except NotionError:
            continue
    if len(matches) > 1:
        raise NotionError("duplicate_managed_documents_page")
    return matches[0] if matches else None


def ensure_documents_page(config: Config) -> tuple[dict[str, Any], bool]:
    if config.documents_page_id:
        page = retrieve_page(config, config.documents_page_id)
        verify_managed_page(
            page,
            page_id=config.documents_page_id,
            title=DOCUMENTS_TITLE,
            parent=config.root_page_id,
        )
        return page, False
    page = find_document_page(config, config.root_page_id)
    if page is not None:
        return page, False
    _, created = request_json(
        config,
        "POST",
        "/pages",
        body={
            "parent": {"type": "page_id", "page_id": config.root_page_id},
            "properties": {
                "title": {"type": "title", "title": rich_text(DOCUMENTS_TITLE)}
            },
        },
        expected={200},
    )
    if not isinstance(created, dict):
        raise NotionError("notion_documents_create_response_invalid")
    page_id = api_id(created.get("id"), "documents_created")
    page = retrieve_page(config, page_id)
    verify_managed_page(
        page, page_id=page_id, title=DOCUMENTS_TITLE, parent=config.root_page_id
    )
    return page, True


def child_databases(config: Config, root_page_id: str) -> list[dict[str, Any]]:
    rows = paginated(config, "/blocks/" + root_page_id + "/children")
    databases: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("type") != "child_database":
            continue
        database = retrieve_database(config, api_id(row.get("id"), "child_database"))
        if database_title(database) == DATABASE_TITLE:
            databases.append(database)
    return databases


def verify_managed_database(
    database: dict[str, Any], *, database_id: str, root_page_id: str
) -> None:
    if api_id(database.get("id"), "database") != database_id:
        raise NotionError("notion_database_identity_drift")
    if database.get("archived") is True or database_title(database) != DATABASE_TITLE:
        raise NotionError("notion_database_title_drift")
    if parent_id(database, "page_id", "database") != root_page_id:
        raise NotionError("notion_database_parent_drift")


def ensure_database(config: Config) -> tuple[dict[str, Any], bool]:
    if config.database_id:
        database = retrieve_database(config, config.database_id)
        verify_managed_database(
            database,
            database_id=config.database_id,
            root_page_id=config.root_page_id,
        )
        return database, False
    matches = child_databases(config, config.root_page_id)
    if len(matches) > 1:
        raise NotionError("duplicate_managed_database")
    if matches:
        return matches[0], False
    _, created = request_json(
        config,
        "POST",
        "/databases",
        body={
            "parent": {"type": "page_id", "page_id": config.root_page_id},
            "title": rich_text(DATABASE_TITLE),
            "properties": {"Name": {"title": {}}},
        },
        expected={200},
    )
    if not isinstance(created, dict):
        raise NotionError("notion_database_create_response_invalid")
    database_id = api_id(created.get("id"), "database_created")
    database = retrieve_database(config, database_id)
    verify_managed_database(
        database, database_id=database_id, root_page_id=config.root_page_id
    )
    return database, True


def database_data_source_ids(database: dict[str, Any]) -> list[str]:
    rows = database.get("data_sources")
    if not isinstance(rows, list):
        raise NotionError("notion_database_data_sources_invalid")
    return [
        api_id(row.get("id"), "database_data_source")
        for row in rows
        if isinstance(row, dict)
    ]


def ensure_data_source(
    config: Config, database: dict[str, Any]
) -> tuple[dict[str, Any], bool]:
    database_id = api_id(database.get("id"), "database_for_data_source")
    source_ids = database_data_source_ids(database)
    if config.data_source_id:
        if config.data_source_id not in source_ids:
            raise NotionError("notion_data_source_not_bound_to_database")
        source = retrieve_data_source(config, config.data_source_id)
        return source, False
    matches = []
    for source_id in source_ids:
        source = retrieve_data_source(config, source_id)
        if data_source_title(source) == DATABASE_TITLE:
            matches.append(source)
    if len(matches) > 1:
        raise NotionError("duplicate_managed_data_source")
    if matches:
        return matches[0], False
    if source_ids:
        if len(source_ids) != 1:
            raise NotionError("managed_data_source_ambiguous")
        return retrieve_data_source(config, source_ids[0]), False
    _, created = request_json(
        config,
        "POST",
        "/data_sources",
        body={
            "parent": {"type": "database_id", "database_id": database_id},
            "title": rich_text(DATABASE_TITLE),
        },
        expected={200},
    )
    if not isinstance(created, dict):
        raise NotionError("notion_data_source_create_response_invalid")
    source_id = api_id(created.get("id"), "data_source_created")
    database = retrieve_database(config, database_id)
    if source_id not in database_data_source_ids(database):
        raise NotionError("notion_created_data_source_not_bound")
    return retrieve_data_source(config, source_id), True


def schema_signature(source: dict[str, Any]) -> dict[str, Any]:
    properties = source.get("properties")
    if not isinstance(properties, dict):
        raise NotionError("notion_data_source_schema_invalid")
    signature: dict[str, Any] = {}
    for name, value in properties.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            raise NotionError("notion_data_source_property_invalid")
        property_type = value.get("type")
        if not isinstance(property_type, str):
            raise NotionError("notion_data_source_property_type_invalid")
        item: dict[str, Any] = {"type": property_type}
        if property_type == "select":
            select = value.get("select")
            options = select.get("options") if isinstance(select, dict) else None
            if not isinstance(options, list):
                raise NotionError("notion_data_source_select_invalid")
            item["options"] = sorted(
                option.get("name")
                for option in options
                if isinstance(option, dict) and isinstance(option.get("name"), str)
            )
        signature[name] = item
    return signature


def expected_schema_signature() -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, definition in EXPECTED_PROPERTIES.items():
        property_type = next(iter(definition))
        item: dict[str, Any] = {"type": property_type}
        if property_type == "select":
            item["options"] = sorted(
                option["name"] for option in definition["select"]["options"]
            )
        result[name] = item
    return result


def reconcile_schema(
    config: Config, source: dict[str, Any]
) -> tuple[dict[str, Any], bool]:
    source_id = api_id(source.get("id"), "data_source_schema")
    current = schema_signature(source)
    expected = expected_schema_signature()
    unexpected = sorted(set(current) - set(expected))
    if unexpected:
        raise NotionError("notion_managed_schema_has_unexpected_properties")
    patch = {
        name: EXPECTED_PROPERTIES[name]
        for name, value in expected.items()
        if current.get(name) != value
    }
    changed = bool(patch)
    if patch:
        request_json(
            config,
            "PATCH",
            "/data_sources/" + source_id,
            body={"properties": patch},
            expected={200},
            retry_safe=True,
        )
    converged = retrieve_data_source(config, source_id)
    if data_source_title(converged) != DATABASE_TITLE:
        raise NotionError("notion_data_source_title_drift")
    database_parent = parent_id(converged, "database_id", "data_source")
    if schema_signature(converged) != expected:
        raise NotionError("notion_managed_schema_not_exact")
    return {
        **converged,
        "_mte_database_parent": database_parent,
    }, changed


def resource_summary(
    config: Config,
    root: dict[str, Any],
    documents: dict[str, Any],
    database: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    root_id = api_id(root.get("id"), "root_summary")
    documents_id = api_id(documents.get("id"), "documents_summary")
    database_id = api_id(database.get("id"), "database_summary")
    source_id = api_id(source.get("id"), "source_summary")
    return {
        "root": {
            "pageId": root_id,
            "title": ROOT_TITLE,
            "exact": root_id == config.root_page_id and page_title(root) == ROOT_TITLE,
        },
        "documents": {
            "pageId": documents_id,
            "title": DOCUMENTS_TITLE,
            "parentPageId": root_id,
            "exact": parent_id(documents, "page_id", "documents_summary") == root_id,
        },
        "database": {
            "databaseId": database_id,
            "title": DATABASE_TITLE,
            "parentPageId": root_id,
            "exact": parent_id(database, "page_id", "database_summary") == root_id,
        },
        "dataSource": {
            "dataSourceId": source_id,
            "title": DATABASE_TITLE,
            "databaseId": database_id,
            "exact": source.get("_mte_database_parent") == database_id,
        },
    }


def connector_config_sha(config: Config, resources: dict[str, Any]) -> str:
    safe = {
        "provider": DATA_CONTENT_PROFILE,
        "baseUrl": config.base_url,
        "apiVersion": config.api_version,
        "botId": config.expected_bot_id,
        "workspaceId": config.expected_workspace_id,
        "resources": resources,
    }
    return sha256_text(json.dumps(safe, sort_keys=True, separators=(",", ":")))


def canonical_source_sha() -> str:
    if not CANONICAL.is_file():
        raise NotionError("canonical_env_missing")
    return sha256_path(CANONICAL)


def inspect_resources(config: Config) -> dict[str, Any]:
    who = identity(config)
    root = retrieve_page(config, config.root_page_id)
    verify_managed_page(
        root, page_id=config.root_page_id, title=ROOT_TITLE, parent=None
    )
    if not all((config.documents_page_id, config.database_id, config.data_source_id)):
        raise NotionError("notion_managed_resource_ids_missing")
    documents = retrieve_page(config, config.documents_page_id or "")
    verify_managed_page(
        documents,
        page_id=config.documents_page_id or "",
        title=DOCUMENTS_TITLE,
        parent=config.root_page_id,
    )
    database = retrieve_database(config, config.database_id or "")
    verify_managed_database(
        database,
        database_id=config.database_id or "",
        root_page_id=config.root_page_id,
    )
    if (config.data_source_id or "") not in database_data_source_ids(database):
        raise NotionError("notion_data_source_not_bound_to_database")
    source = retrieve_data_source(config, config.data_source_id or "")
    if parent_id(source, "database_id", "data_source") != config.database_id:
        raise NotionError("notion_data_source_parent_drift")
    if data_source_title(source) != DATABASE_TITLE:
        raise NotionError("notion_data_source_title_drift")
    if schema_signature(source) != expected_schema_signature():
        raise NotionError("notion_managed_schema_not_exact")
    source = {**source, "_mte_database_parent": config.database_id}
    resources = resource_summary(config, root, documents, database, source)
    return {
        "identity": who,
        "resources": resources,
        "schema": {
            "exact": True,
            "properties": expected_schema_signature(),
        },
        "canonicalSourceSha256": canonical_source_sha(),
        "connectorConfigSha256": connector_config_sha(config, resources),
    }


def provision(config: Config) -> dict[str, Any]:
    who = identity(config)
    root = retrieve_page(config, config.root_page_id)
    verify_managed_page(
        root, page_id=config.root_page_id, title=ROOT_TITLE, parent=None
    )
    documents, documents_created = ensure_documents_page(config)
    database, database_created = ensure_database(config)
    source, source_created = ensure_data_source(config, database)
    source, schema_changed = reconcile_schema(config, source)
    database = retrieve_database(config, api_id(database.get("id"), "database_final"))
    source_id = api_id(source.get("id"), "source_final")
    if source_id not in database_data_source_ids(database):
        raise NotionError("notion_data_source_not_bound_to_database")
    resources = resource_summary(config, root, documents, database, source)
    updates = {
        "NOTION_DOCUMENTS_PAGE_ID": resources["documents"]["pageId"],
        "NOTION_TABLE_DATABASE_ID": resources["database"]["databaseId"],
        "NOTION_TABLE_DATA_SOURCE_ID": resources["dataSource"]["dataSourceId"],
        "NOTION_WORKSPACE_ID": who["workspaceId"],
        "NOTION_BOT_ID": who["botId"],
    }
    changed = [
        key
        for key, configured in (
            ("NOTION_DOCUMENTS_PAGE_ID", config.documents_page_id),
            ("NOTION_TABLE_DATABASE_ID", config.database_id),
            ("NOTION_TABLE_DATA_SOURCE_ID", config.data_source_id),
            ("NOTION_WORKSPACE_ID", config.expected_workspace_id),
            ("NOTION_BOT_ID", config.expected_bot_id),
        )
        if configured is None
    ]
    return {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "NotionConnectorProvision",
        "status": "converged",
        "ok": True,
        "dataContentProfile": DATA_CONTENT_PROFILE,
        "notionApiVersion": config.api_version,
        "identity": who,
        "resources": resources,
        "schema": {
            "exact": True,
            "changed": schema_changed,
            "properties": expected_schema_signature(),
        },
        "created": {
            "documentsPage": documents_created,
            "database": database_created,
            "dataSource": source_created,
        },
        "environmentUpdates": updates,
        "changedKeys": sorted(changed),
        "canonicalSourceSha256": canonical_source_sha(),
        "connectorConfigSha256": connector_config_sha(config, resources),
        "producerSha256": sha256_path(Path(__file__).resolve()),
        "redacted": True,
    }


def title_property(value: str) -> dict[str, Any]:
    return {"title": rich_text(value)}


def table_properties(
    title: str,
    object_id: str,
    revision: int,
    content_hash: str,
    state: str,
) -> dict[str, Any]:
    return {
        "Name": title_property(title),
        "Postgres Object ID": {"rich_text": rich_text(object_id)},
        "Postgres Revision": {"number": revision},
        "Sync Hash": {"rich_text": rich_text(content_hash)},
        "Sync State": {"select": {"name": state}},
        "Entity Type": {"select": {"name": "record"}},
        "Updated At": {"date": {"start": utcnow()}},
    }


def property_text(page: dict[str, Any], name: str, kind: str) -> str:
    properties = page.get("properties")
    value = properties.get(name) if isinstance(properties, dict) else None
    if not isinstance(value, dict):
        return ""
    return plain_text(value.get(kind))


def property_number(page: dict[str, Any], name: str) -> int | None:
    properties = page.get("properties")
    value = properties.get(name) if isinstance(properties, dict) else None
    number = value.get("number") if isinstance(value, dict) else None
    return number if isinstance(number, int) else None


def property_select(page: dict[str, Any], name: str) -> str:
    properties = page.get("properties")
    value = properties.get(name) if isinstance(properties, dict) else None
    select = value.get("select") if isinstance(value, dict) else None
    name_value = select.get("name") if isinstance(select, dict) else None
    return name_value if isinstance(name_value, str) else ""


def query_object(config: Config, data_source_id: str, object_id: str) -> list[Any]:
    return paginated(
        config,
        "/data_sources/" + data_source_id + "/query",
        body={
            "filter": {
                "property": "Postgres Object ID",
                "rich_text": {"equals": object_id},
            }
        },
    )


def table_canary(
    config: Config,
    *,
    run_id: str,
    object_id: str,
    initial_hash: str,
    final_hash: str,
) -> tuple[dict[str, Any], list[str]]:
    data_source_id = config.data_source_id or ""
    title = "MTE table canary " + run_id + " " + secrets.token_hex(4)
    raw_values = [title, object_id]
    page_id: str | None = None
    archived = False
    try:
        _, created = request_json(
            config,
            "POST",
            "/pages",
            body={
                "parent": {
                    "type": "data_source_id",
                    "data_source_id": data_source_id,
                },
                "properties": table_properties(
                    title, object_id, 1, initial_hash, "pending"
                ),
            },
            expected={200},
        )
        if not isinstance(created, dict):
            raise NotionError("notion_table_canary_create_invalid")
        page_id = api_id(created.get("id"), "table_canary")
        initial_rows = query_object(config, data_source_id, object_id)
        if len(initial_rows) != 1 or not isinstance(initial_rows[0], dict):
            raise NotionError("notion_table_canary_initial_query_invalid")
        initial = initial_rows[0]
        object_initial = property_text(initial, "Postgres Object ID", "rich_text")
        initial_revision = property_number(initial, "Postgres Revision")
        initial_sync_hash = property_text(initial, "Sync Hash", "rich_text")
        request_json(
            config,
            "PATCH",
            "/pages/" + page_id,
            body={
                "properties": table_properties(
                    title, object_id, 2, final_hash, "synced"
                )
            },
            expected={200},
            retry_safe=True,
        )
        final_rows = query_object(config, data_source_id, object_id)
        if len(final_rows) != 1 or not isinstance(final_rows[0], dict):
            raise NotionError("notion_table_canary_final_query_invalid")
        final = final_rows[0]
        final_revision = property_number(final, "Postgres Revision")
        final_sync_hash = property_text(final, "Sync Hash", "rich_text")
        final_state = property_select(final, "Sync State")
        if (
            object_initial != object_id
            or initial_revision != 1
            or initial_sync_hash != initial_hash
            or final_revision != 2
            or final_sync_hash != final_hash
            or final_state != "synced"
        ):
            raise NotionError("notion_table_canary_linkage_drift")
        request_json(
            config,
            "PATCH",
            "/pages/" + page_id,
            body={"archived": True},
            expected={200},
            retry_safe=True,
        )
        archived_page = retrieve_page(config, page_id)
        after = query_object(config, data_source_id, object_id)
        archived = archived_page.get("archived") is True and after == []
        if not archived:
            raise NotionError("notion_table_canary_cleanup_invalid")
        return {
            "pageId": page_id,
            "dataSourceId": data_source_id,
            "created": True,
            "queryVerified": True,
            "updated": True,
            "archived": True,
            "cleanupVerified": True,
            "objectIdMatches": True,
            "initialRevisionMatches": True,
            "finalRevisionMatches": True,
            "initialContentSha256Matches": True,
            "finalContentSha256Matches": True,
        }, raw_values
    finally:
        if page_id is not None and not archived:
            try:
                request_json(
                    config,
                    "PATCH",
                    "/pages/" + page_id,
                    body={"archived": True},
                    expected={200},
                    retry_safe=True,
                )
            except NotionError:
                pass


def paragraph(value: str) -> dict[str, Any]:
    return {
        "object": "block",
        "type": "paragraph",
        "paragraph": {"rich_text": rich_text(value)},
    }


def block_text(block: Any) -> str:
    if not isinstance(block, dict):
        return ""
    block_type = block.get("type")
    value = block.get(block_type) if isinstance(block_type, str) else None
    return plain_text(value.get("rich_text")) if isinstance(value, dict) else ""


def document_canary(
    config: Config,
    *,
    run_id: str,
    object_id: str,
    initial_content: str,
    final_content: str,
) -> tuple[dict[str, Any], list[str]]:
    documents_page_id = config.documents_page_id or ""
    title = "MTE document canary " + run_id + " " + secrets.token_hex(4)
    initial_body = json.dumps(
        {
            "objectId": object_id,
            "revision": 1,
            "content": initial_content,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    final_body = json.dumps(
        {
            "objectId": object_id,
            "revision": 2,
            "content": final_content,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    raw_values = [
        title,
        object_id,
        initial_content,
        final_content,
        initial_body,
        final_body,
    ]
    page_id: str | None = None
    archived = False
    try:
        _, created = request_json(
            config,
            "POST",
            "/pages",
            body={
                "parent": {
                    "type": "page_id",
                    "page_id": documents_page_id,
                },
                "properties": {"title": title_property(title)},
                "children": [paragraph(initial_body)],
            },
            expected={200},
        )
        if not isinstance(created, dict):
            raise NotionError("notion_document_canary_create_invalid")
        page_id = api_id(created.get("id"), "document_canary")
        request_json(
            config,
            "PATCH",
            "/blocks/" + page_id + "/children",
            body={"children": [paragraph(final_body)]},
            expected={200},
            retry_safe=True,
        )
        children = paginated(config, "/blocks/" + page_id + "/children")
        texts = [block_text(block) for block in children]
        if texts != [initial_body, final_body]:
            raise NotionError("notion_document_canary_readback_invalid")
        request_json(
            config,
            "PATCH",
            "/pages/" + page_id,
            body={"archived": True},
            expected={200},
            retry_safe=True,
        )
        archived = retrieve_page(config, page_id).get("archived") is True
        if not archived:
            raise NotionError("notion_document_canary_cleanup_invalid")
        return {
            "pageId": page_id,
            "documentsPageId": documents_page_id,
            "created": True,
            "appendVerified": True,
            "readBackVerified": True,
            "archived": True,
            "cleanupVerified": True,
            "objectIdMatches": True,
            "initialRevisionMatches": True,
            "finalRevisionMatches": True,
            "initialContentSha256Matches": True,
            "finalContentSha256Matches": True,
        }, raw_values
    finally:
        if page_id is not None and not archived:
            try:
                request_json(
                    config,
                    "PATCH",
                    "/pages/" + page_id,
                    body={"archived": True},
                    expected={200},
                    retry_safe=True,
                )
            except NotionError:
                pass


def linkage_values(run_id: str, kind: str) -> tuple[str, str, str]:
    return (
        f"mte-notion-canary:{run_id}:{kind}",
        f"mte-notion-canary:{run_id}:{kind}:initial",
        f"mte-notion-canary:{run_id}:{kind}:final",
    )


def assert_redacted(payload: dict[str, Any], token: str, raw_values: list[str]) -> None:
    serialized = json.dumps(payload, sort_keys=True)
    if token in serialized:
        raise NotionError("notion_output_contains_token")
    if any(value and value in serialized for value in raw_values):
        raise NotionError("notion_output_contains_raw_marker")


def run_canary(
    config: Config, run_id: str, inspected: dict[str, Any]
) -> dict[str, Any]:
    if not RUN_ID.fullmatch(run_id):
        raise NotionError("invalid_run_id")
    record_object, record_initial, record_final = linkage_values(run_id, "record")
    document_object, document_initial, document_final = linkage_values(
        run_id, "document"
    )
    record_initial_hash = sha256_text(record_initial)
    record_final_hash = sha256_text(record_final)
    document_initial_hash = sha256_text(document_initial)
    document_final_hash = sha256_text(document_final)
    table, table_raw = table_canary(
        config,
        run_id=run_id,
        object_id=record_object,
        initial_hash=record_initial_hash,
        final_hash=record_final_hash,
    )
    document, document_raw = document_canary(
        config,
        run_id=run_id,
        object_id=document_object,
        initial_content=document_initial,
        final_content=document_final,
    )
    raw_values = [
        run_id,
        record_object,
        record_initial,
        record_final,
        document_object,
        document_initial,
        document_final,
        *table_raw,
        *document_raw,
    ]
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "NotionConnectorCanary",
        "status": "passed",
        "ok": True,
        "generatedAt": utcnow(),
        "dataContentProfile": DATA_CONTENT_PROFILE,
        "notionApiVersion": config.api_version,
        "canonicalSourceSha256": inspected["canonicalSourceSha256"],
        "connectorConfigSha256": inspected["connectorConfigSha256"],
        "producerSha256": sha256_path(Path(__file__).resolve()),
        "identity": inspected["identity"],
        "resources": inspected["resources"],
        "runIdSha256": sha256_text(run_id),
        "linkage": {
            "record": {
                "objectIdSha256": sha256_text(record_object),
                "initialRevision": 1,
                "finalRevision": 2,
                "initialContentSha256": record_initial_hash,
                "finalContentSha256": record_final_hash,
            },
            "document": {
                "objectIdSha256": sha256_text(document_object),
                "initialRevision": 1,
                "finalRevision": 2,
                "initialContentSha256": document_initial_hash,
                "finalContentSha256": document_final_hash,
            },
        },
        "notion": {"table": table, "document": document},
        "cleanup": {
            "notionTableRowArchived": table["cleanupVerified"],
            "notionDocumentArchived": document["cleanupVerified"],
            "verified": table["cleanupVerified"] and document["cleanupVerified"],
        },
        "redacted": True,
    }
    assert_redacted(payload, config.token, raw_values)
    return payload


def atomic_evidence(payload: dict[str, Any]) -> None:
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    temporary = EVIDENCE.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(EVIDENCE)
    EVIDENCE.chmod(0o600)
    if stat.S_IMODE(EVIDENCE.stat().st_mode) != 0o600:
        raise NotionError("notion_evidence_mode_invalid")


def verification_payload(
    config: Config, inspected: dict[str, Any], canary: dict[str, Any]
) -> dict[str, Any]:
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "NotionConnectorVerification",
        "status": "passed",
        "ok": True,
        "generatedAt": utcnow(),
        "dataContentProfile": DATA_CONTENT_PROFILE,
        "notionApiVersion": config.api_version,
        "canonicalSourceSha256": inspected["canonicalSourceSha256"],
        "connectorConfigSha256": inspected["connectorConfigSha256"],
        "producerSha256": sha256_path(Path(__file__).resolve()),
        "identity": inspected["identity"],
        "resources": inspected["resources"],
        "schema": inspected["schema"],
        "canary": canary,
        "cleanup": canary["cleanup"],
        "redacted": True,
        "secretAudit": {"tokenPresent": False, "rawMarkerPresent": False},
        "evidence": {"path": str(EVIDENCE), "mode": "0600"},
    }
    return payload


def canary_action(config: Config, run_id: str) -> dict[str, Any]:
    inspected = inspect_resources(config)
    canary = run_canary(config, run_id, inspected)
    evidence = verification_payload(config, inspected, canary)
    assert_redacted(
        evidence,
        config.token,
        [
            run_id,
            *linkage_values(run_id, "record"),
            *linkage_values(run_id, "document"),
        ],
    )
    atomic_evidence(evidence)
    return canary


def verify(config: Config, run_id: str) -> dict[str, Any]:
    inspected = inspect_resources(config)
    canary = run_canary(config, run_id, inspected)
    payload = verification_payload(config, inspected, canary)
    assert_redacted(
        payload,
        config.token,
        [
            run_id,
            *linkage_values(run_id, "record"),
            *linkage_values(run_id, "document"),
        ],
    )
    atomic_evidence(payload)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("provision", "status", "canary", "verify"))
    parser.add_argument("--run-id")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        config = config_from_env()
        run_id = args.run_id or secrets.token_hex(12)
        if args.action == "provision":
            result = provision(config)
        elif args.action == "status":
            inspected = inspect_resources(config)
            result = {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "NotionConnectorStatus",
                "status": "passed",
                "ok": True,
                "dataContentProfile": DATA_CONTENT_PROFILE,
                "notionApiVersion": config.api_version,
                **inspected,
                "producerSha256": sha256_path(Path(__file__).resolve()),
                "redacted": True,
            }
        elif args.action == "canary":
            result = canary_action(config, run_id)
        else:
            result = verify(config, run_id)
        serialized = json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":") if args.json else None,
            indent=None if args.json else 2,
        )
        print(serialized)
    except NotionError as exc:
        print(
            json.dumps(
                {"ok": False, "status": "failed", "reason": exc.code},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()

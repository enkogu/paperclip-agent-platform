#!/usr/bin/env python3
"""Render and audit all runtime projections from the canonical platform.env."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import stat
import struct
import sys
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import yaml

ROOT = Path("/opt/mte-platform")
SECRET_ROOT = Path("/root/.config/mte-secrets")
SOURCE = SECRET_ROOT / "platform.env"
MANIFEST = SECRET_ROOT / "projections-manifest.json"
COMPOSE_ENV = SECRET_ROOT / "compose.env"
AGGREGATE_COMPOSE = ROOT / "deployment" / "compose.yaml"
LOCK = SECRET_ROOT / ".platform-env.lock"
CONFIG_SOURCE = ROOT / "templates/platform.json"
CONFIG = ROOT / "config/platform.json"
SERVICE_ROOT = SECRET_ROOT / "services"
PROFILE_SOURCE = ROOT / "templates/profiles/profiles.yaml"
PROFILE_RUNTIME = ROOT / "runtime/profiles/profiles.yaml"
COMPOSE_SEED_SOURCE = ROOT / "templates/compose-seeds.lock.json"
PLATFORM_LOCK_SOURCE = ROOT / "templates/platform.lock.yaml"
PUBLIC_URLS = ROOT / "config/public-urls.json"
DATA_CONTENT_PLANE = ROOT / "config/data-content-plane.json"
CLOUDFLARE_APPS = SECRET_ROOT / "cloudflare/apps.json"
CLOUDFLARE_API_ENV = SECRET_ROOT / "cloudflare/api.env"
CLOUDFLARE_TUNNEL_TOKEN = SECRET_ROOT / "cloudflare/tunnel-token"
CLOUDFLARE_ACCESS_TOKEN = SECRET_ROOT / "cloudflare/access-service-token.json"
LEGACY_SECRET_PROJECTION_RELATIVE_PATHS = (
    "activepieces-admin.env",
    "claude.env",
    "hermes-runtime.env",
    "hermes-runtime.env.sha256",
    "orloj.env",
)
LEGACY_EMPTY_SECRET_DIRECTORY_RELATIVE_PATHS = (
    # A historical operator-side Daytona SDK probe used Docker's short `-v`
    # bind syntax with this nonexistent source path. Docker materialized it as
    # an empty 0755 directory before the probe failed. It was never a managed
    # projection; remove only this exact, root-owned, empty artifact.
    "services/daytona-runtime.env",
)
GENERATOR_VERSION = "mte-config-renderer/v1"


def validate_canonical_https_source_url(value: str, key: str) -> str:
    """Require an exact, non-rewritten HTTPS repository provenance URL.

    Operator evidence is compared byte-for-byte with the OCI image label, so
    this validation intentionally does not normalize input.  The accepted
    canonical form is ``https://lowercase-host/path``: no credentials, port,
    query, fragment, trailing slash, or dot path segments.  Keeping one form
    prevents an equivalent-looking URL from becoming ambiguous evidence.
    """

    raw = str(value)
    if raw != raw.strip():
        raise ConfigError(f"{key} must be a canonical HTTPS source URL")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise ConfigError(f"{key} must be a canonical HTTPS source URL") from exc
    path_segments = parsed.path.split("/")
    if (
        not raw.startswith("https://")
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.hostname != parsed.hostname.lower()
        or parsed.username
        or parsed.password
        or port is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or parsed.path.endswith("/")
        or any(segment in {"", ".", ".."} for segment in path_segments[1:])
    ):
        raise ConfigError(
            f"{key} must be a canonical HTTPS source URL "
            "(lowercase host; no credentials, port, query, fragment, trailing "
            "slash, or dot segments)"
        )
    return raw


def validate_paperclip_fork_evidence(source_url: str, revision: str) -> None:
    """Validate immutable Paperclip provenance before canonical env mutation."""

    validate_canonical_https_source_url(source_url, "MTE_PAPERCLIP_FORK_SOURCE_URL")
    if not re.fullmatch(r"[0-9a-f]{40}", str(revision)):
        raise ConfigError(
            "MTE_PAPERCLIP_FORK_REVISION must be an immutable lowercase "
            "40-character commit"
        )

# Hermes is a native systemd service, so it cannot consume the canonical
# root-only platform.env.  The renderer owns its narrow service projection;
# server-hermes.py only validates and consumes the registered result.
HERMES_SERVICE_ENV_KEYS = frozenset(
    {
        "CONTEXT7_API_KEY",
        "HERMES_APPROVALS_CRON_MODE",
        "HERMES_APPROVALS_DESTRUCTIVE_SLASH_CONFIRM",
        "HERMES_APPROVALS_MCP_RELOAD_CONFIRM",
        "HERMES_APPROVALS_MODE",
        "HERMES_APPROVALS_TIMEOUT",
        "HERMES_API_SERVER_ENABLED",
        "HERMES_API_SERVER_HOST",
        "HERMES_API_SERVER_KEY",
        "HERMES_API_SERVER_MODEL_NAME",
        "HERMES_API_SERVER_PORT",
        "HERMES_DISPLAY_TOOL_PROGRESS",
        "HERMES_EXEC_ASK",
        "HERMES_GATEWAY_STREAMING_ENABLED",
        "HERMES_GATEWAY_STREAMING_TRANSPORT",
        "HERMES_KESTRA_PASSWORD",
        "HERMES_KESTRA_URL",
        "HERMES_KESTRA_USERNAME",
        "KESTRA_HEALTH_URL",
        "HERMES_LLM_API_KEY",
        "HERMES_LLM_API_MODE",
        "HERMES_LLM_BASE_URL",
        "HERMES_LLM_MODEL",
        "HERMES_LLM_PROVIDER",
        "HERMES_OPERATOR_MODE",
        "HERMES_PAPERCLIP_API_KEY",
        "HERMES_PAPERCLIP_URL",
        "HERMES_TELEGRAM_ALLOWED_USERS",
        "HERMES_TELEGRAM_BOT_TOKEN",
        "HERMES_TELEGRAM_EXCLUSIVE_BOT_MENTIONS",
        "HERMES_TELEGRAM_GUEST_MODE",
        "HERMES_TELEGRAM_NOTIFICATIONS",
        "HERMES_TELEGRAM_REQUIRE_MENTION",
        "HERMES_TERMINAL_BACKEND",
        "HERMES_TERMINAL_CWD",
        "HERMES_TERMINAL_HOME_MODE",
        "HERMES_TERMINAL_LIFETIME_SECONDS",
        "HERMES_TERMINAL_TIMEOUT",
        "MATTERMOST_ALLOWED_USERS",
        "MATTERMOST_HOME_CHANNEL",
        "MATTERMOST_REPLY_MODE",
        "MATTERMOST_REQUIRE_MENTION",
        "MATTERMOST_TOKEN",
        "MATTERMOST_URL",
    }
)
HERMES_NATIVE_ENV_NAMES = {
    "HERMES_LLM_API_KEY": "OPENAI_API_KEY",
    "HERMES_LLM_BASE_URL": "OPENAI_BASE_URL",
    "HERMES_TELEGRAM_BOT_TOKEN": "TELEGRAM_BOT_TOKEN",
    "HERMES_TELEGRAM_ALLOWED_USERS": "TELEGRAM_ALLOWED_USERS",
    "HERMES_API_SERVER_ENABLED": "API_SERVER_ENABLED",
    "HERMES_API_SERVER_KEY": "API_SERVER_KEY",
    "HERMES_API_SERVER_HOST": "API_SERVER_HOST",
    "HERMES_API_SERVER_PORT": "API_SERVER_PORT",
    "HERMES_API_SERVER_MODEL_NAME": "API_SERVER_MODEL_NAME",
    "HERMES_PAPERCLIP_URL": "PAPERCLIP_API_URL",
    "HERMES_PAPERCLIP_API_KEY": "PAPERCLIP_BRIDGE_API_KEY",
}
ENV_PATTERN = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?:(:-|:\?)([^}]*))?\}")
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ENCRYPT|JWT|SALT|"
    r"COOKIE|CREDENTIAL|AUTH|WEBHOOK|CONNECTION_STRING)",
    re.IGNORECASE,
)
MUTABLE_KEY_PATTERN = re.compile(
    r"(?:PORT|URL|URI|HOST|DOMAIN|ENDPOINT|IMAGE|VERSION|CPU|MEMORY|LIMIT|"
    r"CONCURRENCY|WORKERS|POOL|ENABLED|MODE)$",
    re.IGNORECASE,
)
GENERATED_PREFIX = "# GENERATED by mte-config-renderer; DO NOT EDIT; "
PUBLIC_URL_PROJECTIONS = {
    "MATHESAR_PUBLIC_URL": "MATHESAR_SUBDOMAIN",
    "POSTGREST_PUBLIC_URL": "POSTGREST_SUBDOMAIN",
    "MEMOS_PUBLIC_URL": "MEMOS_SUBDOMAIN",
    "MATTERMOST_SITE_URL": "MATTERMOST_SUBDOMAIN",
    "SEARXNG_BASE_URL": "SEARXNG_SUBDOMAIN",
}
DAYTONA_INTERNAL_DERIVED_KEYS = {
    "MTE_DAYTONA_DASHBOARD_BASE_API_URL",
    "MTE_DAYTONA_DASHBOARD_URL",
    "MTE_DAYTONA_DEFAULT_RUNNER_DOMAIN",
    "MTE_DAYTONA_INTERNAL_API_URL",
    "MTE_DAYTONA_INTERNAL_OIDC_URL",
    "MTE_DAYTONA_INTERNAL_REGISTRY_URL",
    "MTE_DAYTONA_INTERNAL_RUNNER_URL",
    "MTE_DAYTONA_MINIO_ENDPOINT_URL",
    "MTE_DAYTONA_MINIO_STS_ENDPOINT_URL",
    "MTE_DAYTONA_PROXY_DOMAIN",
    "MTE_DAYTONA_PROXY_TEMPLATE_URL",
    "MTE_DAYTONA_PUBLIC_OIDC_URL",
    "MTE_DAYTONA_SSH_GATEWAY_URL",
}
DERIVED_VALUE_KEYS = {
    *PUBLIC_URL_PROJECTIONS,
    *DAYTONA_INTERNAL_DERIVED_KEYS,
    "MATHESAR_DOMAIN_NAME",
    "MATHESAR_ALLOWED_HOSTS",
    "MEMOS_DSN",
    "MEMOS_MCP_URL",
    "FIRECRAWL_REDIS_URL",
    "SEARXNG_VALKEY_URL",
    "KESTRA_SECRET_PAPERCLIP_BOARD_API_KEY",
}
# These URLs are persisted in platform.env because runtime consumers read the
# single canonical file or its narrow projections. Their host and port refs
# are the primary operator-owned values; the URL strings themselves are always
# generated and may never be overridden independently.
CANONICAL_DERIVED_URL_SPECS = {
    "MATTERMOST_URL": (
        "MTE_OPERATOR_LOOPBACK_HOST",
        "MATTERMOST_ORIGIN_PORT",
        "",
    ),
    "HERMES_PAPERCLIP_URL": (
        "PAPERCLIP_LOOPBACK_HOST",
        "PAPERCLIP_PORT",
        "/api",
    ),
    "HERMES_KESTRA_URL": (
        "KESTRA_LOOPBACK_HOST",
        "KESTRA_HTTP_PORT",
        "",
    ),
    "HERMES_LLM_BASE_URL": (
        "MTE_OPERATOR_LOOPBACK_HOST",
        "NINEROUTER_ORIGIN_PORT",
        "/v1",
    ),
    "MTE_PAPERCLIP_API_BASE": (
        "PAPERCLIP_LOOPBACK_HOST",
        "PAPERCLIP_PORT",
        "/api",
    ),
    "PAPERCLIP_API_BASE": (
        "PAPERCLIP_LOOPBACK_HOST",
        "PAPERCLIP_PORT",
        "",
    ),
    "DAYTONA_API_URL": (
        "MTE_OPERATOR_LOOPBACK_HOST",
        "MTE_DAYTONA_API_PORT",
        "/api",
    ),
    "MTE_DAYTONA_API_URL": (
        "MTE_OPERATOR_LOOPBACK_HOST",
        "MTE_DAYTONA_API_PORT",
        "/api",
    ),
    "NINEROUTER_HEALTH_URL": (
        "MTE_OPERATOR_LOOPBACK_HOST",
        "NINEROUTER_ORIGIN_PORT",
        "/api/health",
    ),
    "KESTRA_HEALTH_URL": (
        "KESTRA_LOOPBACK_HOST",
        "KESTRA_HEALTH_PORT",
        "/health",
    ),
    "PAPERCLIP_HEALTH_URL": (
        "PAPERCLIP_LOOPBACK_HOST",
        "PAPERCLIP_PORT",
        "/api/health",
    ),
    "TOOLHIVE_HEALTH_URL": (
        "MTE_OPERATOR_LOOPBACK_HOST",
        "TOOLHIVE_ORIGIN_PORT",
        "/api/openapi.json",
    ),
    "MATTERMOST_HEALTH_URL": (
        "MTE_OPERATOR_LOOPBACK_HOST",
        "MATTERMOST_ORIGIN_PORT",
        "/api/v4/system/ping",
    ),
    "SEARXNG_HEALTH_URL": (
        "MTE_OPERATOR_LOOPBACK_HOST",
        "SEARXNG_ORIGIN_PORT",
        "/",
    ),
    "FIRECRAWL_HEALTH_URL": (
        "MTE_OPERATOR_LOOPBACK_HOST",
        "FIRECRAWL_ORIGIN_PORT",
        "/",
    ),
    "OBSERVABILITY_HEALTH_URL": (
        "MTE_OPERATOR_LOOPBACK_HOST",
        "GRAFANA_ORIGIN_PORT",
        "/api/health",
    ),
    "MTE_AGENT_GATEWAY_NINEROUTER_BASE_URL": (
        "MTE_AGENT_GATEWAY_HOST",
        "MTE_AGENT_GATEWAY_NINEROUTER_PORT",
        "",
    ),
    "MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL": (
        "MTE_AGENT_GATEWAY_HOST",
        "MTE_AGENT_GATEWAY_NINEROUTER_PORT",
        "/v1",
    ),
    "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL": (
        "MTE_AGENT_GATEWAY_HOST",
        "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_PORT",
        "/mcp",
    ),
    "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_URL": (
        "MTE_AGENT_GATEWAY_HOST",
        "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_PORT",
        "/mcp",
    ),
    "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL": (
        "MTE_AGENT_GATEWAY_HOST",
        "MTE_AGENT_GATEWAY_TOOLHIVE_PI_PORT",
        "/mcp",
    ),
}
NOTION_BOOTSTRAP_ID_KEYS = {
    "NOTION_DOCUMENTS_PAGE_ID",
    "NOTION_TABLE_DATABASE_ID",
    "NOTION_TABLE_DATA_SOURCE_ID",
    "NOTION_WORKSPACE_ID",
    "NOTION_BOT_ID",
}
NOTION_TOKEN_IMPORT_PRIORITY = (
    "PRIN7R_NOTION_TOKEN",
    "PRIN7R_NOTION_API_KEY",
    "NOTION_TOKEN",
)
DOMAIN_INPUT_ALIASES = {
    "MTE_DOMAIN": "PLATFORM_BASE_DOMAIN",
    "PLATFORM_DOMAIN": "PLATFORM_BASE_DOMAIN",
    "CLOUDFLARE_BASE_DOMAIN": "PLATFORM_BASE_DOMAIN",
}
REVIEWED_CANONICAL_VALUE_MIGRATIONS = {
    # Upstream Hermes no longer forwards OPENAI_API_KEY to an arbitrary
    # loopback custom endpoint. The named provider declares key_env explicitly
    # and preserves the secret outside config.yaml.
    "HERMES_LLM_PROVIDER": ("custom", "custom:mte9router"),
    # Paperclip reaches the host-native Hermes API through the private Docker
    # control-network gateway. The old loopback-only bind was unreachable from
    # the Paperclip container and made the documented hermes_gateway adapter
    # impossible to use without an extra proxy.
    "HERMES_API_SERVER_HOST": ("127.0.0.1", "172.30.0.1"),
    # The synced platform tree is root-only. Hermes starts in its own state
    # directory and uses explicit sudo commands from the installed skill when
    # platform administration is required.
    "HERMES_TERMINAL_CWD": ("/opt/mte-platform", "/var/lib/mte-hermes"),
    # Paperclip is reached by Kestra and Daytona over reviewed private Docker
    # networks.  The runtime intentionally launches Paperclip with the LAN
    # bind preset, which requires authenticated/private mode upstream.
    "PAPERCLIP_DEPLOYMENT_MODE": ("local_trusted", "authenticated"),
    "MTE_FIRECRAWL_API_IMAGE": (
        "ghcr.io/firecrawl/firecrawl@sha256:2a03830cd27028ebdb0d776db6582c8236597ad59f5bc2fd7fc6d412da0e9f02",
        "ghcr.io/firecrawl/firecrawl:2.11.113-production@sha256:57ca4ba0c3aee60c988f0c52890d1a0a859d3dd1c69c20408ca91975e764a08b",
    ),
    "MTE_FIRECRAWL_PLAYWRIGHT_SERVICE_IMAGE": (
        "ghcr.io/firecrawl/playwright-service@sha256:c13a0e147e8b6a503093d68edfb223ac65c989058f7e0ef606ee2958b38ff604",
        "ghcr.io/firecrawl/playwright-service@sha256:c2cb9d7e982f9ddaf7902ec79da1e63961ae3760f315cddaa161200a7937162b",
    ),
    "MTE_FIRECRAWL_NUQ_POSTGRES_IMAGE": (
        "ghcr.io/firecrawl/nuq-postgres@sha256:4ca6718b2cef40404b046db5cd37ae45db3e44d1a5750c80522f3587a5b193d5",
        "ghcr.io/firecrawl/nuq-postgres@sha256:aed86f62858f29bd971abddcdeb301c12888098d2cf5d33c1ba42b053bc460f6",
    ),
    "MTE_DAYTONA_INSTALLER_SHA256": (
        "8e4363185851605e1fa9863797f3d2d7dbb323f1b1e50421010aced1b619a98d",
        "d3f3523ce521dc7a71f4d915b01053a6f7e9ff013dfbedf902ae44c8d9defd70",
        "5eee75d25641c5d04efe164007796eab864b25786ec6b19515ab9f6eed8195ab",
        "60e97e75a7706129784341b0a3e7e71ac663fde6bc9df7c3ff20026851629c07",
        "c4fffbeaa0774f3a2be7dfe5a08f784ca42b1d1ab68c50eb0f0204b25556fbe6",
        "59a13624fc11128877fc8ab359e11d61371d640b1ace788e103c4eee5518fbb7",
        "c75620fffb6c51d45dcc767775b25b16a3c7fcd0c72a5c5ca124085d69df5664",
        "9da1555d1d328d80ba2d5d0cacb4327633d530a297e58cc5805797e208838f96",
        "c0752d53534b0360fac4077c22cb30810938b1580260e7547bc7adde35572aa5",
        "895517b416896ecc650e393a25e75e6c2fdf3ff7763064e3bb330f9a308a9662",
        "58cee979c329539c68098afe2be5558d5edf04edefe55fbc8ca17b09b09ceb5b",
        "658bab51334183f0b241ed700983ef114474cf80992d352dc70c67949d219fa7",
        "ead5620ddb7955f19cbcb56f410ebb818cda0b9418f96b607316f6ab1e9bd061",
        "04aa4be2ea866bb35e8aea2a0b2d121562b46947e6461225438fad8c9b39ef97",
        "b4d167bcbe4d64345afeb05931e13349bdf2707802a6c58ff22499b41ce67f3b",
        "0c5d24a9c20f490d75d275e80207d162fa01779fce5ca89fc3491e55056c0d23",
        "63652b380ffeb98beb25a0a48eca7a5d1ef376a7af11ca24d016483967e7b276",
        "6ba2b3e9525ef716d0f076f3ad873f2664c42ad68c9170a5fd2b2a44d96924a8",
        "13a58ac70aa452c8b02e8038dea563e378249b8d995f55c5b56fb766aaae98a8",
        "a5d099f96f8c8102dd79eede5ffc90d5e81467e230185711f2861c8c5971d0e9",
        "c9f4c32e8cfd2d445616cff079d5072741e45218f9f855dc0fc5bf57972a573b",
        "02423af31b6d497e763c2bdec27eb5d4bc7d2bef7d33bfcc62916a878a150705",
        "e218352c6d9436dcc25599f627c8645cdef2a285e050f28359fedbacb366fccf",
        "fc715f42c098b9a495d098c774c4365996879cdfd405ffbe04831c0cc116ca71",
        "b3d9415ffef8263aa9a02277d002e05508d6585704e6528e96c677a0f866f7c2",
        "ee89bba4ce4a943e5be4ba93ad7d435fce2f468a2c0590ae76bb35e1697a8262",
        "e424ea285185dc430a9cac6a1a93ec87505320e73e109866c03121b982678a5a",
        "7ac9c50f661d668de4f4e6d34abb526293f5066526aed1b0d4fc2aa6265bac73",
        "a5f2975c3bab3ed69bf69a0800e6d9796d825d0ddb31bbc4be39b427d4ff4236",
        "93ef9ac36aaef79875c77b7a729b5508eaef7867dd77a9e12d4cac8840a3aa9e",
        "3f6405faad4cb765b4268b5f985d6b51e9d3833e93c545cc817300f5d4c5c26a",
        "8b8c17f24885b7dc55b2e8c952a6f1ce177ab5e023a4fdccff5b37cc8111bd0e",
        "cb6f2bdae64b2d2f990c152f9bdfd7e1d586448f3b44516b7818f2caae7ff857",
        "b60493ed92b8a561dddad00902ec4582467174a7f65a22c416a6f0cffc83d42b",
        "3d60ee52b40c5e786426156eb9ad0f4abe229661764bea20a3f89e1efc3b1e44",
        "668470b13cd9b37d58253866cd2bec97f5a04b970aff7e5129fd2da9a2ecb04a",
        "5891917c9b4a0611cf489d499a5515ff26d977a2bdc04746d5c099dc1f1d941b",
        "a566b3de0b7848fa26245c242ee2a8814288cc4b2adeb006ecb98e138836c552",
        "cd32b106a79781bbe322b0ec5f159bd0244f2fe50e9599cc623369f8d0995064",
        "28a993bbf447369a4835fe202095665798b60a3124bcd2fb0a1508979f892a94",
        "74a21913c2d91a935959a35b5a1dba9b3346d7882f212d9faad630e2186084f5",
        "d69ded85bed5b6b1af7a5841eb91246081002f63fea67bda5f82680b90d7fc49",
        "fd378c9e140db8fc8a8d12210fd38d586e3e9c9875ab4a9452e93292b65c9e15",
        "3ab7096a0deb908931f743cbe078a2d5623990d7dc881d0f7a90a3aff86f7e51",
        "aab1e9417213083be73d2d0328e862319a09ef77571643bf4be07446edaf7322",
        "6ff0ca9938d7fc9a63e976656884de172fa9c6baf20654b3ddb86212dfa3d611",
        "2a89ffbd67866ad542ba801f7a31c1228780315cc133cf85eb59d8b860d5ad0a",
        "088ca38cbebf40d4b3c6471ff0b2693fa411bb3532a828de5f54c2d85f8f724b",
    ),
    # The runtime verifies its own release-script digest before it starts.
    # Upgrade only reviewed historical script digests; unknown overrides fail
    # closed at the runtime boundary.
    "MTE_DAYTONA_CODING_SNAPSHOT": (
        "mte-coding-harness-v1",
        "mte-coding-harness-v2",
        "mte-coding-harness-v3",
        "mte-coding-harness-v4",
    ),
    "MTE_DAYTONA_GENERAL_SNAPSHOT": (
        "mte-general-harness-v1",
        "mte-general-harness-v2",
        "mte-general-harness-v3",
        "mte-general-harness-v4",
    ),
    "TOOLHIVE_MEMORY_LIMIT": ("384m", "1024m"),
    "MTE_TOOLHIVE_TOOL_RUNTIME_IMAGE": (
        "docker:28-dind-rootless@sha256:7c3e797187e43738220462658f4586572cbd3bf009f728b21e34d9c5c06ce431",
        "docker:28-dind@sha256:9a06753d2401cd049b34cd27dbbc3e0db717d4c1db7bc7f2efad1c187e00bf5a",
    ),
    "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM": (
        "http://tool-runtime:19011",
        "http://toolhive:19011",
    ),
    "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_UPSTREAM": (
        "http://tool-runtime:19012",
        "http://toolhive:19012",
    ),
    "MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM": (
        "http://tool-runtime:19013",
        "http://toolhive:19013",
    ),
}
# These version contracts are owned by immutable runtime artifacts. Unlike the
# compatibility migrations above, an unknown existing value cannot safely be
# preserved: doing so would defer the mismatch until the runtime ABI gate after
# deployment has already started.
GOVERNED_CANONICAL_VALUE_MIGRATIONS = {
    "PAPERCLIP_DAYTONA_SDK_VERSION": ("0.171.0", "0.175.0"),
}


def reconcile_governed_canonical_value_migrations(
    values: dict[str, str],
) -> set[str]:
    migrated: set[str] = set()
    for key, (
        legacy_value,
        current_value,
    ) in GOVERNED_CANONICAL_VALUE_MIGRATIONS.items():
        existing = values.get(key, "").strip()
        if not existing or existing == current_value:
            continue
        if existing == legacy_value:
            values[key] = current_value
            migrated.add(key)
            continue
        raise ConfigError(
            f"refusing automatic {key} migration from an unreviewed value; "
            f"after verifying the immutable Paperclip image, set {key}={current_value} "
            "in the canonical environment and rerun the one-command install"
        )
    return migrated


REVIEWED_CANONICAL_KEY_MIGRATIONS = {
    # The original collector mapping used a generic name. Compose now owns
    # every published port through its deterministic ``PORT_1`` key. Migrate
    # only the reviewed old default, leaving any unknown operator override
    # untouched for an explicit follow-up.
    "MTE_OBSERVABILITY_OTEL_COLLECTOR_PORT_MAPPING": (
        "127.0.0.1:4318:4318",
        "MTE_OBSERVABILITY_OTEL_COLLECTOR_PORT_1_MAPPING",
        "127.0.0.1:4318:4318",
    ),
    "MTE_TOOLHIVE_TOOLHIVE_ENV_DOCKER_HOST": (
        "tcp://tool-runtime:2375",
        "MTE_TOOLHIVE_TOOLHIVE_ENV_DOCKER_SOCKET",
        "/var/run/docker.sock",
    ),
}
# These Compose inputs were introduced after the first server bootstrap.
# Existing canonical sources may therefore legitimately lack them. This
# explicit allowlist permits a fill-only upgrade from the reviewed Compose seed
# catalog without turning that bootstrap catalog into recurring mutations.
REVIEWED_COMPOSE_SEED_MIGRATIONS = {
    # Daytona's explicit-step Compose gained these implementation-owned refs
    # after existing servers had already materialized their canonical env.
    # They are safe fill-only upgrades from the reviewed Compose seed catalog;
    # any existing non-empty value remains authoritative.
    "MTE_DAYTONA_API_ENV_DB_HOST",
    "MTE_DAYTONA_API_ENV_OTEL_ENABLED",
    "MTE_DAYTONA_API_ENV_REDIS_HOST",
    "MTE_DAYTONA_API_PORT_1_MAPPING",
    "MTE_DAYTONA_DEX_PORT_1_MAPPING",
    "MTE_DAYTONA_PROXY_ENV_PREVIEW_WARNING_ENABLED",
    "MTE_DAYTONA_PROXY_ENV_REDIS_HOST",
    "MTE_DAYTONA_PROXY_ENV_TOOLBOX_ONLY_MODE",
    "MTE_DAYTONA_PROXY_PORT_1_MAPPING",
    "MTE_DAYTONA_REGISTRY_ENV_REGISTRY_STORAGE_DELETE_ENABLED",
    "MTE_DAYTONA_RUNNER_ENV_INTER_SANDBOX_NETWORK_ENABLED",
    "MTE_DAYTONA_RUNNER_ENV_RUNNER_DOMAIN",
    "MTE_DAYTONA_SSH_GATEWAY_PORT_1_MAPPING",
    "MTE_FIRECRAWL_VALKEY_IMAGE",
    "MTE_OBSERVABILITY_OTEL_COLLECTOR_PORT_1_MAPPING",
    "MTE_POSTGREST_POSTGREST_ENV_PGRST_ADMIN_SERVER_PORT",
    "MTE_POSTGREST_POSTGREST_ENV_PGRST_DB_URI",
    "MTE_POSTGREST_POSTGREST_ENV_PGRST_OPENAPI_MODE",
    "MTE_POSTGREST_POSTGREST_ENV_PGRST_SERVER_PORT",
    "MTE_POSTGREST_POSTGREST_IMAGE",
    "MTE_POSTGREST_POSTGREST_PORT_1_MAPPING",
    "MTE_POSTGREST_POSTGREST_PORT_2_MAPPING",
    "POSTGREST_ANON_ROLE",
    "POSTGREST_API_AUDIENCE",
    "POSTGREST_CPU_LIMIT",
    "POSTGREST_DB_HOST",
    "POSTGREST_DB_LOGIN_ROLE",
    "POSTGREST_DB_PORT",
    "POSTGREST_DB_SSLMODE",
    "POSTGREST_MEMORY_LIMIT",
    "POSTGREST_PIDS_LIMIT",
}
REVIEWED_TOOLHIVE_COMPOSE_SEED_MIGRATIONS = {
    "MTE_TOOLHIVE_TOOLHIVE_ENV_DOCKER_SOCKET",
}
# Exact legacy values emitted by the former nested-default Compose projection.
# Only these byte-for-byte reviewed forms are eligible for replacement with the
# corresponding literal from compose-seeds.lock.json. Any operator override or
# unfamiliar nested ref remains untouched and is rejected by render/audit.
REVIEWED_LEGACY_COMPOSE_VALUE_MIGRATIONS = {
    "MTE_9ROUTER_9ROUTER_PORT_1_MAPPING": (
        "127.0.0.1:${NINEROUTER_HOST_PORT:-20128}:20128"
    ),
    "MTE_FIRECRAWL_API_PORT_1_MAPPING": (
        "127.0.0.1:${FIRECRAWL_HOST_PORT:-13002}:3002"
    ),
    "MTE_KESTRA_KESTRA_PORT_1_MAPPING": ("127.0.0.1:${KESTRA_HTTP_PORT:-18082}:8080"),
    "MTE_KESTRA_KESTRA_PORT_2_MAPPING": (
        "127.0.0.1:${KESTRA_MANAGEMENT_PORT:-18081}:8081"
    ),
    "MTE_MATTERMOST_MATTERMOST_PORT_1_MAPPING": (
        "127.0.0.1:${MATTERMOST_HOST_PORT:-18065}:8065"
    ),
    "MTE_SEARXNG_SEARXNG_PORT_1_MAPPING": (
        "127.0.0.1:${SEARXNG_HOST_PORT:-18088}:8080"
    ),
    "MTE_TOOLHIVE_TOOLHIVE_PORT_1_MAPPING": (
        "127.0.0.1:${TOOLHIVE_API_HOST_PORT:-18880}:8080"
    ),
    "MTE_TOOLHIVE_TOOLHIVE_PORT_2_MAPPING": (
        "127.0.0.1:${TOOLHIVE_MCP_HOST_PORT:-19001}:19001"
    ),
}
PAPERCLIP_OWNER_BOOTSTRAP_STATE_KEYS = frozenset(
    {
        # Redacted state only: the installer returns a fingerprint and browser
        # path, never either value. These values are not service credentials.
        "PAPERCLIP_OWNER_INVITE_ID",
        "PAPERCLIP_OWNER_BOOTSTRAP_REQUEST_TYPE",
    }
)
POST_RENDER_PROVISIONED_KEYS = {
    "NINEROUTER_PROFILE_CODING_DAYTONA_CODEX_API_KEY",
    "NINEROUTER_PROFILE_CODING_DAYTONA_CLAUDE_API_KEY",
    "NINEROUTER_PROFILE_CODING_DAYTONA_PI_API_KEY",
    "POSTGREST_PAPERCLIP_TOKEN",
    "PAPERCLIP_BOARD_API_KEY",
    *PAPERCLIP_OWNER_BOOTSTRAP_STATE_KEYS,
    "KESTRA_SECRET_PAPERCLIP_BOARD_API_KEY",
    *NOTION_BOOTSTRAP_ID_KEYS,
    "MEMOS_SERVICE_PAT",
    "MEMOS_SERVICE_PAT_NAME",
    "MATTERMOST_ALERT_WEBHOOK_URL",
}
COMPOSE_DERIVED_ENV_REFS = {
    ("memos", "MEMOS_DSN"): "MEMOS_DSN",
    (
        "memos",
        "MEMOS_ALLOW_PRIVATE_WEBHOOKS",
    ): "MEMOS_ALLOW_PRIVATE_WEBHOOKS_ENABLED",
}
OPTIONAL_EMPTY_KEYS = {
    # These integrations are intentionally disabled by an empty value until
    # an operator enables them. Presence is required for deterministic
    # projections, but an empty value is not configuration drift.
    "CONTEXT7_API_KEY",
    "HERMES_TELEGRAM_BOT_TOKEN",
    "HERMES_TELEGRAM_ALLOWED_USERS",
    # Issued by the 9Router bootstrap after the first runtime render.  The
    # provision stage fills it and triggers the next canonical projection.
    "HERMES_LLM_API_KEY",
    # The Daytona control-plane creates its API key during the Daytona stage.
    # The indexed deploy re-renders immediately after that atomic mutation.
    "DAYTONA_API_KEY",
}
CANONICAL_GENERATED_SECRET_LENGTHS = {
    # Paperclip's authenticated/private LAN binding is consumed by host and
    # private Docker-network clients.  It must exist before render validates
    # the component's required secret projection.
    "PAPERCLIP_AGENT_JWT_SECRET": 36,
}
RETIRED_CANONICAL_KEYS = {
    "DAYTONA_CUSTOM_IMAGE_LIFECYCLE",
    "MTE_DAYTONA_NPM_LOCK_SHA256",
    "MTE_DAYTONA_NPM_PACKAGE_SHA256",
    "MTE_DAYTONA_SANDBOX_BASE_IMAGE",
    "MTE_DAYTONA_PLUGIN_NPM_INTEGRITY",
    "MTE_DAYTONA_PLUGIN_NPM_VERSION",
    "MTE_DAYTONA_PLUGIN_PACKAGE",
    "MTE_DAYTONA_OSS_VERSION",
    "MTE_FIRECRAWL_API_EXPECTED_DIGEST",
    "MTE_FIRECRAWL_BUILD_REGISTRY_HOST",
    "MTE_FIRECRAWL_BUILD_REGISTRY_IMAGE",
    "MTE_FIRECRAWL_BUILD_REGISTRY_PORT",
    "MTE_FIRECRAWL_BUILD_REGISTRY_VOLUME",
    "MTE_FIRECRAWL_BUILD_SCRIPT_SHA256",
    "MTE_FIRECRAWL_INSTALLER_SHA256",
    "MTE_FIRECRAWL_NUQ_POSTGRES_EXPECTED_DIGEST",
    "MTE_FIRECRAWL_PATCH_APPLY_SHA256",
    "MTE_FIRECRAWL_PLAYWRIGHT_EXPECTED_DIGEST",
    "MTE_FIRECRAWL_RECIPE_LOCK_SHA256",
    "MTE_PAPERCLIP_INSTALLER_SHA256",
    "MTE_PAPERCLIP_NPM_INTEGRITY",
    "MTE_PAPERCLIP_NPM_LOCK_SHA256",
    "MTE_PAPERCLIP_NPM_MANIFEST_SHA256",
    "MTE_PAPERCLIP_VERSION",
    "PAPERCLIP_NODE_IMAGE",
    "PAPERCLIP_RUNTIME_VERSION",
    "PI_CLI_VERSION",
}
# Values that identify an operator's infrastructure must never be invented by
# the renderer or committed as deployment defaults.  They are accepted only
# from the explicit bootstrap input (or an already-existing canonical source).
REQUIRED_OPERATOR_BOOTSTRAP_KEYS = {
    "MTE_DAYTONA_SANDBOX_IMAGE",
    "MTE_DAYTONA_SANDBOX_IMAGE_REVISION",
    "MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL",
    "MTE_PAPERCLIP_IMAGE",
    "MTE_PAPERCLIP_FORK_SOURCE_URL",
    "MTE_PAPERCLIP_FORK_REVISION",
    "MTE_SSH_TARGET",
    "MTE_OPERATOR_SSH_CIDRS",
    "MTE_EXCLUDED_HOST_1",
    "MTE_EXCLUDED_HOST_2",
    "PLATFORM_BASE_DOMAIN",
}

# The checked-in environment template describes only values owned by the
# operator. CLOUDFLARE_EMAIL/GLOBAL_API_KEY are local bootstrap credentials and
# are deliberately never persisted to the server-side canonical source. The
# remaining external values are imported fill-only and then consumed from the
# canonical source by runtime services and acceptance checks.
LOCAL_ONLY_OPERATOR_INPUT_KEYS = {
    "CLOUDFLARE_EMAIL",
    "CLOUDFLARE_GLOBAL_API_KEY",
}
REQUIRED_EXTERNAL_OPERATOR_INPUT_KEYS = {
    "CLOUDFLARE_ACCOUNT_ID",
    *LOCAL_ONLY_OPERATOR_INPUT_KEYS,
    "E2E_GITHUB_BASE_BRANCH",
    "E2E_GITHUB_OWNER",
    "E2E_GITHUB_REPOSITORY",
    "GITHUB_TOKEN",
    "MINIMAX_API_KEY",
    "MINIMAX_BASE_URL",
    "MINIMAX_MODEL",
    "MTE_ENABLE_OPERATOR_PROVIDED_PROPRIETARY_HARNESSES",
    "NOTION_TOKEN",
    "NOTION_ROOT_PAGE_ID",
}
RESOURCE_PREFLIGHT_KEYS = frozenset(
    {
        "MTE_RESOURCE_PREFLIGHT_MIN_MEM_TOTAL_KIB",
        "MTE_RESOURCE_PREFLIGHT_MIN_MEM_AVAILABLE_KIB",
        "MTE_RESOURCE_PREFLIGHT_MAX_SWAP_USED_KIB",
        "MTE_RESOURCE_PREFLIGHT_MAX_LOAD_PER_CPU_MILLI",
        "MTE_RESOURCE_PREFLIGHT_MIN_ROOT_FREE_KIB",
        "MTE_RESOURCE_PREFLIGHT_MIN_DOCKER_FREE_KIB",
    }
)
OPTIONAL_OPERATOR_INPUT_KEYS = {
    "CONTEXT7_API_KEY",
    "HERMES_TELEGRAM_BOT_TOKEN",
    "HERMES_TELEGRAM_ALLOWED_USERS",
    # A deliberate high-risk exception. The canonical safe default remains
    # false when this optional operator input is absent.
    "MTE_ALLOW_UNATTENDED_PAPERCLIP_OWNER_BOOTSTRAP",
    *RESOURCE_PREFLIGHT_KEYS,
}
REQUIRED_OPERATOR_ENV_KEYS = (
    REQUIRED_OPERATOR_BOOTSTRAP_KEYS | REQUIRED_EXTERNAL_OPERATOR_INPUT_KEYS
)
OPERATOR_ENV_EXAMPLE_KEYS = REQUIRED_OPERATOR_ENV_KEYS | OPTIONAL_OPERATOR_INPUT_KEYS
OPERATOR_RECONCILED_KEYS = (
    REQUIRED_OPERATOR_ENV_KEYS | OPTIONAL_OPERATOR_INPUT_KEYS
) - LOCAL_ONLY_OPERATOR_INPUT_KEYS
E2E_GITHUB_TARGET_KEYS = frozenset(
    {
        "E2E_GITHUB_OWNER",
        "E2E_GITHUB_REPOSITORY",
        "E2E_GITHUB_BASE_BRANCH",
    }
)
GITHUB_OWNER_SLUG = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
GITHUB_REPOSITORY_SLUG = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?")
SAFE_GITHUB_BRANCH_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,254}")


def normalize_operator_ssh_cidrs(raw: str) -> str:
    """Return the canonical, fail-closed operator SSH allowlist."""
    tokens = [value for value in re.split(r"[\s,]+", raw.strip()) if value]
    if not tokens:
        raise ConfigError("MTE_OPERATOR_SSH_CIDRS must contain at least one CIDR")
    networks: set[str] = set()
    for token in tokens:
        try:
            networks.add(str(ipaddress.ip_network(token, strict=True)))
        except ValueError as exc:
            raise ConfigError(
                f"MTE_OPERATOR_SSH_CIDRS contains invalid CIDR {token!r}"
            ) from exc
    return ",".join(sorted(networks))


def validate_e2e_github_target(values: dict[str, str]) -> dict[str, str]:
    """Validate the operator-owned repository target without normalizing it."""

    target = {key: str(values.get(key, "")).strip() for key in E2E_GITHUB_TARGET_KEYS}
    missing = sorted(key for key, value in target.items() if not value)
    if missing:
        raise ConfigError("E2E GitHub target is missing: " + ", ".join(missing))
    owner = target["E2E_GITHUB_OWNER"]
    repository = target["E2E_GITHUB_REPOSITORY"]
    branch = target["E2E_GITHUB_BASE_BRANCH"]
    if not GITHUB_OWNER_SLUG.fullmatch(owner):
        raise ConfigError("E2E_GITHUB_OWNER is not a safe GitHub owner slug")
    if not GITHUB_REPOSITORY_SLUG.fullmatch(repository) or repository in {".", ".."}:
        raise ConfigError("E2E_GITHUB_REPOSITORY is not a safe GitHub repository slug")
    invalid_branch = (
        not SAFE_GITHUB_BRANCH_REF.fullmatch(branch)
        or branch == "HEAD"
        or branch.startswith(("-", ".", "/"))
        or branch.endswith((".", "/", ".lock"))
        or ".." in branch
        or "@{" in branch
        or "//" in branch
        or any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            or character in "~^:?*[\\"
            for character in branch
        )
        or any(
            not segment
            or segment.startswith((".", "-"))
            or segment.endswith((".", ".lock"))
            for segment in branch.split("/")
        )
    )
    if invalid_branch:
        raise ConfigError("E2E_GITHUB_BASE_BRANCH is not a safe Git branch ref")
    return target


ONE_TIME_MIGRATION_SEEDS = {
    "MTE_PLATFORM_ROOT": "/opt/mte-platform",
    "MTE_SECRETS_ROOT": "/root/.config/mte-secrets",
    "DATA_CONTENT_PROFILE": "postgres-notion",
    "NOTION_API_BASE_URL": "https://api.notion.com/v1",
    "NOTION_API_VERSION": "2025-09-03",
    "NOTION_SYNC_BATCH_SIZE": "25",
    "NOTION_SYNC_MAX_ATTEMPTS": "8",
    "NOTION_SYNC_LEASE_SECONDS": "300",
    "NOTION_SYNC_RETRY_BASE_SECONDS": "5",
    "NOTION_SYNC_INTERVAL_SECONDS": "15",
    "MTE_RESOURCE_PREFLIGHT_MIN_MEM_TOTAL_KIB": "20971520",
    "MTE_RESOURCE_PREFLIGHT_MIN_MEM_AVAILABLE_KIB": "6291456",
    "MTE_RESOURCE_PREFLIGHT_MAX_SWAP_USED_KIB": "1048576",
    "MTE_RESOURCE_PREFLIGHT_MAX_LOAD_PER_CPU_MILLI": "1500",
    "MTE_RESOURCE_PREFLIGHT_MIN_ROOT_FREE_KIB": "31457280",
    "MTE_RESOURCE_PREFLIGHT_MIN_DOCKER_FREE_KIB": "31457280",
    "PAPERCLIP_SUBDOMAIN": "paperclip",
    "KESTRA_SUBDOMAIN": "kestra",
    "MATTERMOST_SUBDOMAIN": "chat",
    "POSTGREST_SUBDOMAIN": "data-api",
    "POSTGREST_ORIGIN_PORT": "18093",
    "POSTGREST_HEALTH_URL": "http://127.0.0.1:18095/ready",
    "POSTGREST_ACCESS_CLASS": "service",
    "POSTGREST_DATA_DB_NAME": "mte_agent_data",
    "POSTGREST_DATA_DB_USER": "mte_agent_data_owner",
    "POSTGREST_READER_ROLE": "mte_pgrst_reader",
    "POSTGREST_WRITER_ROLE": "mte_pgrst_writer",
    "POSTGREST_PAPERCLIP_ROLE": "mte_pgrst_paperclip",
    "GRAFANA_SUBDOMAIN": "grafana",
    "SEARXNG_SUBDOMAIN": "search",
    "FIRECRAWL_SUBDOMAIN": "firecrawl",
    "TOOLHIVE_SUBDOMAIN": "toolhive",
    "NINEROUTER_SUBDOMAIN": "9router",
    "HERMES_SUBDOMAIN": "hermes",
    "MATTERMOST_HERMES_BOT_USERNAME": "hermes-operator",
    "MATTERMOST_OPERATOR_USERNAME": "mte-operator",
    "MATTERMOST_OPERATOR_EMAIL": "operator@mte.local",
    "MATTERMOST_PLATFORM_TEAM_NAME": "mte-platform",
    "MATTERMOST_OPERATOR_CHANNEL_NAME": "operator",
    "MATTERMOST_BOOTSTRAP_HTTP_TIMEOUT_SECONDS": "15",
    "MATTERMOST_BOOTSTRAP_COMMAND_TIMEOUT_SECONDS": "60",
    "MATTERMOST_CONTAINER_NAME_SUFFIX": "mattermost-1",
    "MATTERMOST_REQUIRE_MENTION": "true",
    "MATTERMOST_REPLY_MODE": "thread",
    "HERMES_APPROVALS_CRON_MODE": "deny",
    "HERMES_APPROVALS_DESTRUCTIVE_SLASH_CONFIRM": "true",
    "HERMES_APPROVALS_MCP_RELOAD_CONFIRM": "true",
    "HERMES_APPROVALS_MODE": "manual",
    "HERMES_APPROVALS_TIMEOUT": "600",
    "HERMES_API_SERVER_ENABLED": "true",
    "HERMES_API_SERVER_HOST": "172.30.0.1",
    "HERMES_API_SERVER_MODEL_NAME": "mte-hermes",
    "HERMES_API_SERVER_PORT": "8642",
    "HERMES_EXEC_ASK": "1",
    "HERMES_DISPLAY_TOOL_PROGRESS": "new",
    "HERMES_GATEWAY_STREAMING_ENABLED": "true",
    "HERMES_GATEWAY_STREAMING_TRANSPORT": "edit",
    "HERMES_LLM_MODEL": "mte-minimax/MiniMax-M2.7-highspeed",
    "HERMES_LLM_API_MODE": "chat_completions",
    "HERMES_LLM_PROVIDER": "custom:mte9router",
    "HERMES_OPERATOR_MODE": "unprivileged_service",
    "HERMES_WHEEL_URL": (
        "https://files.pythonhosted.org/packages/0c/4c/"
        "91652c61450763bfe165c65b83026503de0ac9ddad2c11ee522490bf4c2d/"
        "hermes_agent-0.18.2-py3-none-any.whl"
    ),
    "HERMES_WHEEL_SHA256": (
        "8f02155cfc84b28bd98551cd18dffec0efa9ec070dd08f90f1a850f1c779492f"
    ),
    "HERMES_PYPI_PROVENANCE_URL": (
        "https://pypi.org/integrity/hermes-agent/0.18.2/"
        "hermes_agent-0.18.2-py3-none-any.whl/provenance"
    ),
    "HERMES_SIGSTORE_BUNDLE_URL": (
        "https://github.com/NousResearch/hermes-agent/releases/download/"
        "v2026.7.7.2/hermes_agent-0.18.2-py3-none-any.whl.sigstore.json"
    ),
    "HERMES_SIGSTORE_BUNDLE_SHA256": (
        "20cea7962a0773b21c75652845742ae5d414632864cd08684993f286f486c0ad"
    ),
    "HERMES_SIGSTORE_PACKAGE_VERSION": "3.0.0",
    "HERMES_SIGSTORE_VERIFIER_IMAGE": "node:22-bookworm@sha256:5647be709086c696ff32edaaf1c70cd26d1da6ab2b39c32f3c7b4c4a31957e37",
    "HERMES_TELEGRAM_EXCLUSIVE_BOT_MENTIONS": "true",
    "HERMES_TELEGRAM_GUEST_MODE": "false",
    "HERMES_TELEGRAM_NOTIFICATIONS": "important",
    "HERMES_TELEGRAM_REQUIRE_MENTION": "true",
    "HERMES_TERMINAL_BACKEND": "local",
    "HERMES_TERMINAL_CWD": "/var/lib/mte-hermes",
    "HERMES_TERMINAL_HOME_MODE": "real",
    "HERMES_TERMINAL_LIFETIME_SECONDS": "1800",
    "HERMES_TERMINAL_TIMEOUT": "600",
    "MTE_CONTROL_NETWORK_SUBNET": "172.30.0.0/16",
    "MTE_CONTROL_NETWORK_GATEWAY": "172.30.0.1",
    "HERMES_APT_PACKAGES": (
        "ca-certificates=20260601~24.04.1,curl=8.5.0-2ubuntu10.11,"
        "ffmpeg=7:6.1.1-3ubuntu5,"
        "python3=3.12.3-0ubuntu2.1,python3-venv=3.12.3-0ubuntu2.1,"
        "ripgrep=14.1.0-1,sudo=1.9.15p5-3ubuntu5.24.04.2"
    ),
    "MTE_DOCKER_APT_KEY_URL": "https://download.docker.com/linux/ubuntu/gpg",
    "MTE_DOCKER_APT_REPOSITORY_URL": "https://download.docker.com/linux/ubuntu",
    "MTE_DOCKER_APT_KEY_SHA256": "1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570",
    "MTE_DOCKER_APT_KEY_FINGERPRINT": "9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
    "MTE_DOCKER_CE_VERSION": "5:29.6.1-1~ubuntu.24.04~noble",
    "MTE_DOCKER_CLI_VERSION": "5:29.6.1-1~ubuntu.24.04~noble",
    "MTE_CONTAINERD_IO_VERSION": "2.2.6-1~ubuntu.24.04~noble",
    "MTE_DOCKER_COMPOSE_VERSION": "5.3.1-1~ubuntu.24.04~noble",
    "MTE_DOCKER_ALLOW_PROVIDER_MIGRATION": "false",
    "MTE_DOCKER_UBUNTU_DOCKER_IO_VERSION": "29.1.3-0ubuntu3~24.04.2",
    "MTE_DOCKER_UBUNTU_CONTAINERD_VERSION": "2.2.1-0ubuntu1~24.04.3",
    "MTE_DOCKER_UBUNTU_COMPOSE_VERSION": "2.40.3+ds1-0ubuntu1~24.04.1",
    "MTE_HOST_REQUIRED_TCP_PORTS": "80,443",
    "PAPERCLIP_PORT": "3100",
    "PAPERCLIP_LEGACY_PORT": "18110",
    "PAPERCLIP_DEPLOYMENT_MODE": "authenticated",
    "PAPERCLIP_DEPLOYMENT_EXPOSURE": "private",
    # Daytona stopped publishing self-hosted control-plane images after 0.187.0.
    # Keep that frozen runtime provenance separate from the newer sandbox base.
    "MTE_DAYTONA_CONTROL_PLANE_VERSION": "0.187.0",
    "MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT": (
        "8a446cb96331737e5a2118cbcaa0604d95c07f71"
    ),
    "MTE_DAYTONA_SANDBOX_VERSION": "0.190.0",
    "CODEX_CLI_VERSION": "0.144.4",
    "CLAUDE_CODE_CLI_VERSION": "2.1.209",
    "MTE_ENABLE_OPERATOR_PROVIDED_PROPRIETARY_HARNESSES": "false",
    "MTE_ALLOW_UNATTENDED_PAPERCLIP_OWNER_BOOTSTRAP": "false",
    "MTE_CONTEXT7_MCP_URL": "https://mcp.context7.com/mcp",
    "MTE_CONTEXT7_PI_PACKAGE": "@upstash/context7-pi",
    "MTE_CONTEXT7_PI_VERSION": "0.1.1",
    "MTE_CONTEXT7_PI_NPM_INTEGRITY": "sha512-RVwu0alq02SoniWzn3oRbtRzQmM3g/UuVwKEGHGKj77B0twq6RHRyXuq1Gs/WF+hgtA2eI2QaSnSVq7lGjElbA==",
    "PAPERCLIP_CPU_LIMIT": "1.0",
    "PAPERCLIP_MEMORY_LIMIT": "3g",
    "PAPERCLIP_PIDS_LIMIT": "1024",
    "PAPERCLIP_DAYTONA_UPSTREAM_URL": "http://mte-daytona-api:3000/api",
    "KESTRA_HTTP_PORT": "18082",
    "KESTRA_HEALTH_PORT": "18081",
    "FIRECRAWL_HARNESS_STARTUP_TIMEOUT_MS": "300000",
    "DAYTONA_TARGET": "us",
    "DAYTONA_DB_USER": "daytona",
    "DAYTONA_MINIO_USER": "mte_daytona",
    "DAYTONA_REGISTRY_USER": "mte_daytona",
    "DAYTONA_BOOTSTRAP_EMAIL": "daytona-admin@mte.local",
    "MTE_DAYTONA_ENVIRONMENT_NAME": "MTE Daytona Coding",
    "MTE_DAYTONA_NETWORK": "mte-daytona-net",
    "MTE_DAYTONA_PAPERCLIP_NETWORK": "mte-daytona-api",
    # The nested runner daemon owns this bridge.  Its first usable address is
    # the fixed gateway exposed to sandboxes; both values are validated as one
    # fail-closed network contract before Compose starts.
    "MTE_DAYTONA_SANDBOX_SUBNET": "172.20.0.0/16",
    "MTE_DAYTONA_CODING_CPU": "1",
    "MTE_DAYTONA_CODING_MEMORY_GIB": "2",
    "MTE_DAYTONA_CODING_SNAPSHOT_PREFIX": "mte-coding-harness",
    "MTE_DAYTONA_CODING_SNAPSHOT": "mte-coding-harness-v4",
    "MTE_DAYTONA_GENERAL_CPU": "1",
    "MTE_DAYTONA_GENERAL_MEMORY_GIB": "1",
    "MTE_DAYTONA_GENERAL_SNAPSHOT_PREFIX": "mte-general-harness",
    "MTE_DAYTONA_GENERAL_SNAPSHOT": "mte-general-harness-v4",
    "MTE_DAYTONA_DISK_GIB": "20",
    "MTE_DAYTONA_TIMEOUT_MS": "300000",
    "MTE_DAYTONA_REUSE_LEASE": "true",
    "MTE_PI_CODING_AGENT_DIR": "/home/daytona/.pi/mte-profile",
    "MTE_PI_TOOLHIVE_EXTENSION_SHA256": (
        "1a20934ff084fee0e84b7ffad6da8e825ba0e6171be2da1564bdf267675a63e6"
    ),
    "MTE_DAYTONA_API_PORT": "3310",
    "MTE_DAYTONA_PROXY_PORT": "3410",
    "MTE_DAYTONA_DEX_PORT": "3556",
    "MTE_DAYTONA_SSH_PORT": "3222",
    "MTE_DAYTONA_API_INTERNAL_PORT": "3000",
    "MTE_DAYTONA_DEX_INTERNAL_PORT": "5556",
    "MTE_DAYTONA_MINIO_CONSOLE_INTERNAL_PORT": "9001",
    "MTE_DAYTONA_MINIO_INTERNAL_PORT": "9000",
    "MTE_DAYTONA_POSTGRES_INTERNAL_PORT": "5432",
    "MTE_DAYTONA_PROXY_INTERNAL_PORT": "4000",
    "MTE_DAYTONA_REDIS_INTERNAL_PORT": "6379",
    "MTE_DAYTONA_REGISTRY_INTERNAL_PORT": "6000",
    "MTE_DAYTONA_RUNNER_INTERNAL_PORT": "3003",
    "MTE_DAYTONA_SSH_INTERNAL_PORT": "2222",
    "MTE_DAYTONA_DEFAULT_RUNNER_CPU": "4",
    "MTE_DAYTONA_DEFAULT_RUNNER_MEMORY_GIB": "8",
    "MTE_DAYTONA_DEFAULT_RUNNER_DISK_GIB": "50",
    "MTE_DAYTONA_DEFAULT_ORG_TOTAL_CPU": "4",
    "MTE_DAYTONA_DEFAULT_ORG_TOTAL_MEMORY_GIB": "8",
    "MTE_DAYTONA_DEFAULT_ORG_TOTAL_DISK_GIB": "200",
    "MTE_DAYTONA_DEFAULT_ORG_MAX_CPU_PER_SANDBOX": "2",
    "MTE_DAYTONA_DEFAULT_ORG_MAX_MEMORY_GIB_PER_SANDBOX": "4",
    "MTE_DAYTONA_DEFAULT_ORG_MAX_DISK_GIB_PER_SANDBOX": "30",
    "MTE_DAYTONA_DEFAULT_ORG_SNAPSHOT_QUOTA": "20",
    "MTE_DAYTONA_DEFAULT_ORG_MAX_SNAPSHOT_SIZE_GIB": "30",
    "MTE_DAYTONA_DEFAULT_ORG_VOLUME_QUOTA": "20",
    "MTE_DAYTONA_RUNNER_DECLARATIVE_BUILD_SCORE_THRESHOLD": "10",
    "MTE_DAYTONA_RUNNER_AVAILABILITY_SCORE_THRESHOLD": "10",
    "MTE_DAYTONA_RUNNER_START_SCORE_THRESHOLD": "3",
    "MTE_DAYTONA_INSTALLER_SHA256": (
        "088ca38cbebf40d4b3c6471ff0b2693fa411bb3532a828de5f54c2d85f8f724b"
    ),
    "MTE_JQ_VERSION": "1.8.1",
    "MTE_JQ_LINUX_AMD64_SHA256": (
        "020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d"
    ),
    "MTE_AGENT_PLANE_NETWORK": "mte-agent-plane",
    "MTE_TOOL_RUNTIME_NETWORK": "mte-tool-runtime",
    "MTE_TOOLHIVE_CONTROL_NETWORK": "mte-toolhive-control",
    "MTE_AGENT_GATEWAY_IMAGE": "python:3.13-slim@sha256:bffeb7bd6a85767587059c6ba23e1e9122078e3aa3fa836099171b9bb5a9bb00",
    "MTE_AGENT_GATEWAY_HOST": "172.20.0.1",
    "MTE_AGENT_GATEWAY_NINEROUTER_PORT": "22080",
    "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_PORT": "22081",
    "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_PORT": "22082",
    "MTE_AGENT_GATEWAY_TOOLHIVE_PI_PORT": "22083",
    "MTE_AGENT_GATEWAY_NINEROUTER_UPSTREAM": "http://9router:20128",
    "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM": "http://toolhive:19011",
    "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_UPSTREAM": "http://toolhive:19012",
    "MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM": "http://toolhive:19013",
    "MTE_CODEX_VERSION": "0.144.4",
    "MTE_CLAUDE_CODE_VERSION": "2.1.209",
    "MTE_PI_VERSION": "0.80.7",
    "MTE_TOOLHIVE_VERSION": "0.36.0",
    "MTE_CODEX_NPM_INTEGRITY": (
        "sha512-DTHzYatlKq9dw55E0/HsbK4tRCEKabuJ10ybbqpsG8gVv/"
        "kvwEdg3Z4OI3cvLXKa21xkIa4lkGlZoO/HmqmFFw=="
    ),
    "MTE_CODEX_LINUX_X64_NPM_INTEGRITY": (
        "sha512-2jxrmV6+/7eBNdg5uhhmOEPFu2o28eYY/ClLzWhSBHH8uo3f2KA1z9JQcVtw"
        "lbToW03nEPlEzYNYfCF1UBqsVQ=="
    ),
    "MTE_CLAUDE_CODE_NPM_INTEGRITY": (
        "sha512-pouVZMdA3Dl4+x4Nlr+AInZla+L6yCiHe0L+AuprM3L6Gko4ErQxwl/"
        "DprLKXMF/IhckJhdsgGEaO1gYku+lZw=="
    ),
    "MTE_CLAUDE_CODE_LINUX_X64_NPM_INTEGRITY": (
        "sha512-3iYBnPhuN3X+OJeBn2dIpa0DQ+c0UF9Fc68NKq7Q0fT5SvI5bR9zkll2xI"
        "Hym1MAlQcfHpT9xbc8CraEBYP85Q=="
    ),
    "MTE_PI_NPM_INTEGRITY": (
        "sha512-mxq3IClhdgmCrYiKuzKehs4QKCVJgKmlA70nUEzsgeNsGdxriT7o5sKQTC"
        "cxzVJkzDRMcHD/8tAP4/eGrV4gKQ=="
    ),
    "MTE_TOOLHIVE_ARCHIVE_SHA256": (
        "ca87b9d9eec394d953868a8fbbbda88d7c6105ac65c1a45327b7af75bfcfbce9"
    ),
    "MTE_GITHUB_CLI_VERSION": "2.96.0",
    "MTE_GITHUB_CLI_ARCHIVE_SHA256": (
        "83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60"
    ),
    "MTE_DAYTONA_API_IMAGE": (
        "daytonaio/daytona-api@sha256:"
        "8de6315a378430a58a44ce6c20b41050c2f602446e75f3ff559edbaa0b3758a7"
    ),
    "MTE_DAYTONA_PROXY_IMAGE": (
        "daytonaio/daytona-proxy@sha256:"
        "63834f0477e154f92de8d44efb0809dffbd2392c188b6cf41dac94ed8ade26c2"
    ),
    "MTE_DAYTONA_RUNNER_IMAGE": (
        "daytonaio/daytona-runner@sha256:"
        "3253f4fdfda80bfc3b13e9e7ddf022cb5412dca94230371091e16cd0860427e0"
    ),
    "MTE_DAYTONA_SSH_IMAGE": (
        "daytonaio/daytona-ssh-gateway@sha256:"
        "b931ec8b4713bc80596d867f892febd7638220b92ad0825a0fbae9e3e4cef17f"
    ),
    "MTE_DAYTONA_POSTGRES_IMAGE": (
        "postgres:18@sha256:"
        "c2d42a104eb6b37b286a2d9c5cf83f349de4d6516d513d00a2bd9610e2c2e5e4"
    ),
    "MTE_DAYTONA_VALKEY_IMAGE": (
        "valkey/valkey:9.1.0-alpine@sha256:"
        "c9b77919daeba2c02ad954d0c844cc4e7142069d177b89c5fd771f405daf9e02"
    ),
    "MTE_DAYTONA_DEX_IMAGE": (
        "dexidp/dex:v2.42.0@sha256:"
        "1b4a6eee8550240b0faedad04d984ca939513650e1d9bd423502c67355e3822f"
    ),
    "MTE_DAYTONA_REGISTRY_IMAGE": (
        "registry:2.8.3@sha256:"
        "a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
    ),
    "MTE_DAYTONA_MINIO_IMAGE": (
        "minio/minio@sha256:"
        "14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
    ),
    "CLOUDFLARE_ENABLED": "true",
    "CLOUDFLARE_TUNNEL_NAME": "paperclip-agent-platform",
    "CLOUDFLARE_ACCESS_SESSION_DURATION": "12h",
    "CLOUDFLARE_SERVICE_TOKEN_DURATION": "8760h",
    "CLOUDFLARED_IMAGE": (
        "cloudflare/cloudflared:2026.7.1@sha256:"
        "188bb03589a32affed3cf4d0590565ffe67b78866e6b5582574afab2b705bafe"
    ),
    "CLOUDFLARED_CONTAINER_NAME": "mte-cloudflared",
    "CLOUDFLARED_RESTART_POLICY": "unless-stopped",
    "CLOUDFLARED_NETWORK_MODE": "host",
    "CLOUDFLARED_USER": "0:0",
    "CLOUDFLARED_CPU_LIMIT": "0.25",
    "CLOUDFLARED_MEMORY_LIMIT": "256m",
    "CLOUDFLARED_LOG_LOOKBACK": "5m",
    "CLOUDFLARED_METRICS_ADDRESS": "127.0.0.1:20241",
    "PAPERCLIP_ORIGIN_PORT": "3100",
    "PAPERCLIP_ACCESS_CLASS": "human",
    "KESTRA_ORIGIN_PORT": "18082",
    "KESTRA_DB_HOST": "mte-kestra-postgres",
    "KESTRA_DB_PORT": "5432",
    "KESTRA_DB_USER": "kestra",
    "KESTRA_DB_NAME": "kestra",
    "KESTRA_ACCESS_CLASS": "human",
    "MATTERMOST_ORIGIN_PORT": "18065",
    "MATTERMOST_DB_HOST": "mte-mattermost-postgres",
    "MATTERMOST_DB_PORT": "5432",
    "MATTERMOST_ACCESS_CLASS": "human",
    "GRAFANA_ORIGIN_PORT": "13000",
    "GRAFANA_ACCESS_CLASS": "human",
    "SEARXNG_ORIGIN_PORT": "18088",
    "SEARXNG_ACCESS_CLASS": "human",
    "FIRECRAWL_ORIGIN_PORT": "13002",
    "FIRECRAWL_ACCESS_CLASS": "service",
    "TOOLHIVE_ORIGIN_PORT": "18880",
    "TOOLHIVE_ACCESS_CLASS": "service",
    "NINEROUTER_ORIGIN_PORT": "20128",
    "NINEROUTER_ACCESS_CLASS": "service",
    "OBSERVABILITY_OTLP_HTTP_URL": "http://127.0.0.1:4318",
    "OBSERVABILITY_CONTAINER_OTLP_HTTP_URL": "http://otel-collector:4318",
    "OBSERVABILITY_QUERY_TIMEOUT_SECONDS": "90",
    "OBSERVABILITY_POLL_INTERVAL_SECONDS": "5",
    "OBSERVABILITY_SERIES_MAX_AGE_SECONDS": "180",
    "OBSERVABILITY_ALERT_FIRE_TIMEOUT_SECONDS": "300",
    "OBSERVABILITY_ALERT_RESOLVE_TIMEOUT_SECONDS": "420",
    "OBSERVABILITY_ALERT_POLL_INTERVAL_SECONDS": "20",
    "OBSERVABILITY_HTTP_TIMEOUT_SECONDS": "30",
    "OBSERVABILITY_COMMAND_TIMEOUT_SECONDS": "60",
    "MTE_PIDS_INIT_LIMIT": "64",
    "MTE_PIDS_LIGHTWEIGHT_LIMIT": "128",
    "MTE_PIDS_DATASTORE_LIMIT": "256",
    "MTE_PIDS_SERVICE_LIMIT": "256",
    "MTE_PIDS_DOCKER_LIMIT": "512",
    "MTE_PIDS_APP_LIMIT": "768",
    "MTE_PIDS_BROWSER_LIMIT": "768",
    "MTE_PIDS_HEAVY_LIMIT": "1024",
    "MTE_HEALTHCHECK_FAST_INTERVAL": "10s",
    "MTE_HEALTHCHECK_FAST_TIMEOUT": "5s",
    "MTE_HEALTHCHECK_FAST_RETRIES": "15",
    "MTE_HEALTHCHECK_FAST_START_PERIOD": "30s",
    "MTE_HEALTHCHECK_STANDARD_INTERVAL": "30s",
    "MTE_HEALTHCHECK_STANDARD_TIMEOUT": "5s",
    "MTE_HEALTHCHECK_STANDARD_RETRIES": "10",
    "MTE_HEALTHCHECK_STANDARD_START_PERIOD": "60s",
    "MTE_HEALTHCHECK_SLOW_INTERVAL": "30s",
    "MTE_HEALTHCHECK_SLOW_TIMEOUT": "15s",
    "MTE_HEALTHCHECK_SLOW_RETRIES": "20",
    "MTE_HEALTHCHECK_SLOW_START_PERIOD": "120s",
    "MTE_OBSERVABILITY_VICTORIAMETRICS_RETENTION_PERIOD": "14d",
    "MTE_OBSERVABILITY_VICTORIALOGS_RETENTION_PERIOD": "7d",
    "MTE_OBSERVABILITY_VICTORIATRACES_RETENTION_PERIOD": "7d",
    "MTE_DOCKER_LOG_DRIVER": "json-file",
    "MTE_DOCKER_LOG_MAX_SIZE": "10m",
    "MTE_DOCKER_LOG_MAX_FILES": "3",
    "PAPERCLIP_WORKSPACE_ROOT": "/workspaces/mte-isolated-canary",
    "PAPERCLIP_SECRETS_STRICT_MODE": "true",
    "DAYTONA_ENABLED": "true",
    "DAYTONA_PLUGIN_VERSION": "0.1.0",
    "PAPERCLIP_DAYTONA_SDK_VERSION": "0.175.0",
    "PAPERCLIP_AWS_S3_CLIENT_VERSION": "3.1075.0",
    "DAYTONA_MEMORY_GIB": "4",
    "DAYTONA_PROBE_ENABLED": "true",
    "PAPERCLIP_LOOPBACK_HOST": "127.0.0.1",
    "PAPERCLIP_CONTAINER_HOST": "mte-paperclip",
    "KESTRA_LOOPBACK_HOST": "127.0.0.1",
    "MTE_OPERATOR_LOOPBACK_HOST": "127.0.0.1",
    "E2E_CLEANUP_ENABLED": "true",
    "E2E_REQUIRE_ARTIFACTS_ENDPOINT": "true",
    "E2E_REQUIRE_GITHUB_DRAFT_PR": "true",
    "E2E_REQUIRE_CHECKS": "true",
    "TOOLHIVE_VERSION": "0.36.0",
    "TOOLHIVE_ARCHIVE_URL": "https://github.com/stacklok/toolhive/releases/download/v0.36.0/toolhive_0.36.0_linux_amd64.tar.gz",
    "TOOLHIVE_ARCHIVE_SHA256": "ca87b9d9eec394d953868a8fbbbda88d7c6105ac65c1a45327b7af75bfcfbce9",
    "TOOLHIVE_CANARY_IMAGE": "mcp/everything@sha256:330885a0c4b2eed6f0cd3aae0f0b37152ccdf2852e2f6af6d616a5d5c1e9817d",
    "TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_BASE": "19500",
    "TOOLHIVE_CANARY_FIRECRAWL_PROXY_PORT_RANGE": "300",
    "KESTRA_RECONCILE_HTTP_TIMEOUT_SECONDS": "60",
    "TOOLHIVE_NOTION_IMAGE": "ghcr.io/stacklok/dockyard/npx/notion@sha256:180a55ce48d1d08888abb9920a6d24ba178929e4131722579466c494eec3d08f",
    "TOOLHIVE_FIRECRAWL_IMAGE": "docker.io/mcp/firecrawl@sha256:00f5e4f01d3d63185059f39ecb091df13b159e2a63bc840e9d7a414a139425fe",
    "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_PROXY_PORT": "19011",
    "TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_PROXY_PORT": "19012",
    "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_PROXY_PORT": "19013",
    "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_EVERYTHING_PROXY_PORT": "19211",
    "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_NOTION_PROXY_PORT": "19212",
    "TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_EVERYTHING_PROXY_PORT": "19221",
    "TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_NOTION_PROXY_PORT": "19222",
    "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_EVERYTHING_PROXY_PORT": "19231",
    "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_NOTION_PROXY_PORT": "19232",
    "PROFILE_CODING_DAYTONA_CODEX_ADAPTER": "codex_local",
    "PROFILE_CODING_DAYTONA_CODEX_DEFAULT_ENVIRONMENT": "daytona-coding",
    "PROFILE_CODING_DAYTONA_CODEX_MODEL": "mte-minimax/MiniMax-M2.7-highspeed",
    "PROFILE_CODING_DAYTONA_CODEX_TIMEOUT_SEC": "1800",
    "PROFILE_CODING_DAYTONA_CODEX_MAX_CONCURRENT_RUNS": "1",
    "PROFILE_CODING_DAYTONA_CODEX_TIMEOUT_SECONDS": "1800",
    "PROFILE_CODING_DAYTONA_CODEX_CPU_LIMIT": "1",
    "PROFILE_CODING_DAYTONA_CODEX_MEMORY_LIMIT": "2Gi",
    "PROFILE_CODING_DAYTONA_CODEX_PACKAGE_CODEX_VERSION": "0.144.4",
    "PROFILE_CODING_DAYTONA_CODEX_PACKAGE_TOOLHIVE_VERSION": "0.36.0",
    "PROFILE_CODING_DAYTONA_CLAUDE_ADAPTER": "claude_local",
    "PROFILE_CODING_DAYTONA_CLAUDE_DEFAULT_ENVIRONMENT": "daytona-coding",
    "PROFILE_CODING_DAYTONA_CLAUDE_MODEL": "mte-minimax/MiniMax-M2.7-highspeed",
    "PROFILE_CODING_DAYTONA_CLAUDE_TIMEOUT_SEC": "1800",
    "PROFILE_CODING_DAYTONA_CLAUDE_MAX_CONCURRENT_RUNS": "1",
    "PROFILE_CODING_DAYTONA_CLAUDE_TIMEOUT_SECONDS": "1800",
    "PROFILE_CODING_DAYTONA_CLAUDE_CPU_LIMIT": "1",
    "PROFILE_CODING_DAYTONA_CLAUDE_MEMORY_LIMIT": "2Gi",
    "PROFILE_CODING_DAYTONA_CLAUDE_PACKAGE_CLAUDECODE_VERSION": "2.1.209",
    "PROFILE_CODING_DAYTONA_CLAUDE_PACKAGE_TOOLHIVE_VERSION": "0.36.0",
    "PROFILE_CODING_DAYTONA_PI_ADAPTER": "pi_local",
    "PROFILE_CODING_DAYTONA_PI_DEFAULT_ENVIRONMENT": "daytona-coding",
    "PROFILE_CODING_DAYTONA_PI_PROVIDER": "mte9router",
    "PROFILE_CODING_DAYTONA_PI_MODEL": "mte9router/mte-minimax/MiniMax-M2.7-highspeed",
    "PROFILE_CODING_DAYTONA_PI_TIMEOUT_SEC": "1800",
    "PROFILE_CODING_DAYTONA_PI_MAX_CONCURRENT_RUNS": "1",
    "PROFILE_CODING_DAYTONA_PI_TIMEOUT_SECONDS": "1800",
    "PROFILE_CODING_DAYTONA_PI_CPU_LIMIT": "1",
    "PROFILE_CODING_DAYTONA_PI_MEMORY_LIMIT": "2Gi",
    "PROFILE_CODING_DAYTONA_PI_PACKAGE_PI_VERSION": "0.80.7",
    "PROFILE_CODING_DAYTONA_PI_PACKAGE_TOOLHIVE_VERSION": "0.36.0",
}
PUBLIC_COMPONENT_SUBDOMAINS = {
    "paperclip": "PAPERCLIP_SUBDOMAIN",
    "kestra": "KESTRA_SUBDOMAIN",
    "mattermost": "MATTERMOST_SUBDOMAIN",
    "mathesar": "MATHESAR_SUBDOMAIN",
    "postgrest": "POSTGREST_SUBDOMAIN",
    "memos": "MEMOS_SUBDOMAIN",
    "grafana": "GRAFANA_SUBDOMAIN",
    "searxng": "SEARXNG_SUBDOMAIN",
    "firecrawl": "FIRECRAWL_SUBDOMAIN",
    "toolhive": "TOOLHIVE_SUBDOMAIN",
    "9router": "NINEROUTER_SUBDOMAIN",
    "hermes": "HERMES_SUBDOMAIN",
}


class ConfigError(RuntimeError):
    pass


def _canonical_url(values: dict[str, str], target: str) -> str:
    host_ref, port_ref, path = CANONICAL_DERIVED_URL_SPECS[target]
    raw_host = str(values.get(host_ref, ""))
    host = raw_host.strip()
    if (
        not host
        or raw_host != host
        or "://" in host
        or any(character in host for character in "/?#@[]")
    ):
        raise ConfigError(f"canonical URL primary host is invalid: {host_ref}")
    raw_port = str(values.get(port_ref, ""))
    if not raw_port.isdigit():
        raise ConfigError(f"canonical URL primary port is invalid: {port_ref}")
    port = int(raw_port)
    if not 1 <= port <= 65535 or raw_port != str(port):
        raise ConfigError(f"canonical URL primary port is invalid: {port_ref}")
    url_host = f"[{host}]" if ":" in host else host
    return f"http://{url_host}:{port}{path}"


def derive_canonical_urls(
    values: dict[str, str], *, targets: set[str] | None = None
) -> dict[str, str]:
    selected = set(CANONICAL_DERIVED_URL_SPECS) if targets is None else set(targets)
    unknown = selected - set(CANONICAL_DERIVED_URL_SPECS)
    if unknown:
        raise ConfigError(
            "unknown canonical derived URL targets: " + ", ".join(sorted(unknown))
        )
    return {target: _canonical_url(values, target) for target in sorted(selected)}


def reconcile_canonical_urls(
    values: dict[str, str], *, targets: set[str]
) -> tuple[list[str], list[str]]:
    expected = derive_canonical_urls(values, targets=targets)
    created: list[str] = []
    migrated: list[str] = []
    for target, url in expected.items():
        existing = str(values.get(target, ""))
        if existing == url:
            continue
        if existing:
            migrated.append(target)
        else:
            created.append(target)
        values[target] = url
    return created, migrated


def canonical_url_drift(values: dict[str, str]) -> list[str]:
    drifted: list[str] = []
    # Partial unit fixtures and pre-bootstrap files may omit an entire URL
    # family. Once a target is present, however, both primary refs and its
    # exact deterministic value are mandatory. Full audit still reports a
    # deleted target through the normal required-key contract.
    for target in sorted(CANONICAL_DERIVED_URL_SPECS):
        if target not in values:
            continue
        try:
            expected = _canonical_url(values, target)
        except ConfigError:
            drifted.append(target)
            continue
        if values[target] != expected:
            drifted.append(target)
    return drifted


# Keep the literal dependency catalog AST-readable for the offline supply-chain
# validator while materializing URL defaults exclusively from primary refs.
ONE_TIME_MIGRATION_SEEDS.update(derive_canonical_urls(ONE_TIME_MIGRATION_SEEDS))


def resource_preflight_values(values: dict[str, str]) -> dict[str, str]:
    """Return the validated canonical non-secret resource admission policy."""

    resolved: dict[str, str] = {}
    for key in sorted(RESOURCE_PREFLIGHT_KEYS):
        raw = str(values.get(key, "")).strip()
        if not raw:
            raw = ONE_TIME_MIGRATION_SEEDS[key]
        if not re.fullmatch(r"0|[1-9][0-9]{0,16}", raw):
            raise ConfigError(f"{key} must be a canonical unsigned integer")
        resolved[key] = raw
    return resolved


@contextmanager
def config_lock():
    SECRET_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    root_stat = SECRET_ROOT.lstat()
    expected_uid = os.geteuid()
    expected_gid = os.getegid()
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or root_stat.st_uid != expected_uid
        or root_stat.st_gid != expected_gid
    ):
        raise ConfigError("canonical secret root ownership or type is unsafe")
    SECRET_ROOT.chmod(0o700)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ConfigError("canonical lock requires O_NOFOLLOW support")
    flags = os.O_CREAT | os.O_RDWR | nofollow | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(LOCK, flags, 0o600)
    except OSError as exc:
        raise ConfigError("cannot safely open canonical lock") from exc
    try:
        # Inspect the opened inode before chmod/chown so an unsafe hardlink or
        # special file is rejected without mutating its target.
        _verify_canonical_lock_inode(descriptor, require_mode=False)
        os.fchmod(descriptor, 0o600)
        if os.geteuid() == 0:
            os.fchown(descriptor, 0, 0)
        _verify_canonical_lock_inode(descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        # Detect a pathname replacement that raced the lock acquisition.
        _verify_canonical_lock_inode(descriptor)
        yield descriptor
    finally:
        os.close(descriptor)


def _verify_canonical_lock_inode(
    lock_fd: int, *, require_mode: bool = True
) -> os.stat_result:
    """Fail closed unless ``lock_fd`` is the sole canonical regular inode."""
    try:
        path_stat = LOCK.lstat()
        descriptor_stat = os.fstat(lock_fd)
    except OSError as exc:
        raise ConfigError("canonical lock inode cannot be verified") from exc
    expected_uid = os.geteuid()
    expected_gid = os.getegid()
    if (
        not stat.S_ISREG(path_stat.st_mode)
        or not stat.S_ISREG(descriptor_stat.st_mode)
        or path_stat.st_nlink != 1
        or descriptor_stat.st_nlink != 1
        or path_stat.st_uid != expected_uid
        or descriptor_stat.st_uid != expected_uid
        or path_stat.st_gid != expected_gid
        or descriptor_stat.st_gid != expected_gid
        or (require_mode and stat.S_IMODE(path_stat.st_mode) != 0o600)
        or (require_mode and stat.S_IMODE(descriptor_stat.st_mode) != 0o600)
        or (path_stat.st_dev, path_stat.st_ino)
        != (descriptor_stat.st_dev, descriptor_stat.st_ino)
    ):
        raise ConfigError("canonical lock inode is unsafe")
    return descriptor_stat


def verify_canonical_lock_fd(lock_fd: int) -> int:
    """Prove that ``lock_fd`` is the held canonical lock description."""
    if type(lock_fd) is not int or lock_fd < 0:
        raise ConfigError("canonical lock proof requires an open file descriptor")
    try:
        os.fstat(lock_fd)
    except OSError as exc:
        raise ConfigError("canonical lock proof is not an open descriptor") from exc
    descriptor_stat = _verify_canonical_lock_inode(lock_fd)

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ConfigError("canonical lock proof requires O_NOFOLLOW support")
    try:
        contender = os.open(LOCK, os.O_RDWR | nofollow | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise ConfigError("canonical lock proof cannot open the lock inode") from exc
    try:
        contender_stat = os.fstat(contender)
        if (descriptor_stat.st_dev, descriptor_stat.st_ino) != (
            contender_stat.st_dev,
            contender_stat.st_ino,
        ):
            raise ConfigError("canonical lock proof references a different inode")

        # Daytona uses Linux OFD locks so validation can first observe a
        # conflicting lock from a separate description, then prove that this
        # exact description owns it.  The initial GETLK makes the unlocked case
        # reject without accidentally acquiring a lock during validation.
        if sys.platform.startswith("linux") and all(
            hasattr(fcntl, name)
            for name in ("F_OFD_GETLK", "F_OFD_SETLK", "F_WRLCK", "F_UNLCK")
        ):
            request = struct.pack("hhqqi4x", fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0)
            observed = fcntl.fcntl(contender, fcntl.F_OFD_GETLK, request)
            lock_type = struct.unpack("hhqqi4x", observed)[0]
            if lock_type != fcntl.F_UNLCK:
                try:
                    fcntl.fcntl(lock_fd, fcntl.F_OFD_SETLK, request)
                except OSError as exc:
                    raise ConfigError(
                        "canonical lock descriptor does not own the OFD lock"
                    ) from exc
                return lock_fd

        # Retain compatibility with existing canonical writers that use
        # flock(2): a separate description must be blocked before the supplied
        # description is tested, so the unlocked case is never acquired.
        try:
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(contender, fcntl.LOCK_UN)
            raise ConfigError("canonical lock descriptor is not already held")
    finally:
        os.close(contender)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise ConfigError("canonical lock descriptor does not own the lock") from exc
    return lock_fd


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def missing_required(values: dict[str, str], required: set[str]) -> list[str]:
    return sorted(
        key
        for key in required
        if key not in values or (key not in OPTIONAL_EMPTY_KEYS and not values[key])
    )


def reconcile_generated_canonical_secrets(
    values: dict[str, str], required: set[str]
) -> list[str]:
    """Create missing renderer-owned secrets without rotating existing values."""
    created: list[str] = []
    for key, length in CANONICAL_GENERATED_SECRET_LENGTHS.items():
        if key in required and not values.get(key):
            values[key] = secrets.token_urlsafe(length)
            created.append(key)
    return created


def _materialize_render_generated_secrets() -> list[str]:
    """Fill renderer-owned required secrets inside the render transaction."""
    values, _ = source_state()
    cfg = active_config_object(config_object(), values, platform_lock_object())
    required, _, _ = declared_keys(cfg, values)
    created = reconcile_generated_canonical_secrets(values, required)
    if created:
        write_env(SOURCE, values, mode=0o600)
    return created


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ConfigError(f"invalid canonical key {key!r}")
        if "\n" in value or "\r" in value:
            raise ConfigError(f"canonical key {key} is not single-line")
        values[key] = value
    return values


def source_state() -> tuple[dict[str, str], str]:
    if not SOURCE.is_file():
        raise ConfigError(f"canonical runtime SSOT is missing: {SOURCE}")
    stat = SOURCE.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o777 != 0o600:
        raise ConfigError("canonical platform.env must be owned by root with mode 0600")
    values = parse_env(SOURCE)
    drifted_urls = canonical_url_drift(values)
    if drifted_urls:
        raise ConfigError("canonical derived URL drift: " + ", ".join(drifted_urls))
    return values, sha256_path(SOURCE)


def write_env(path: Path, values: dict[str, str], *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    secure_path(path.parent, 0o700)
    atomic_text(path, "".join(f"{key}={values[key]}\n" for key in sorted(values)), mode)


def config_object() -> dict[str, Any]:
    try:
        value = json.loads(CONFIG_SOURCE.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(
            f"invalid structural config template {CONFIG_SOURCE}"
        ) from exc
    if not isinstance(value, dict):
        raise ConfigError("structural platform config must be an object")
    return value


def platform_lock_object() -> dict[str, Any]:
    try:
        value = yaml.safe_load(PLATFORM_LOCK_SOURCE.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(
            f"invalid structural platform lock {PLATFORM_LOCK_SOURCE}"
        ) from exc
    if not isinstance(value, dict):
        raise ConfigError("structural platform lock must be an object")
    return value


def data_content_contract():
    path = Path(__file__).with_name("data_content_plane.py")
    spec = importlib.util.spec_from_file_location("mte_data_content_plane", path)
    if spec is None or spec.loader is None:
        raise ConfigError("cannot load the reviewed data/content contract")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def active_config_object(
    cfg: dict[str, Any],
    values: dict[str, str],
    platform_lock: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(cfg.get("spec"), dict) or "dataContentPlane" not in cfg["spec"]:
        return cfg
    if platform_lock is None:
        platform_lock = platform_lock_object()
    contract = data_content_contract()
    try:
        return contract.filter_platform_config(cfg, platform_lock, values)
    except contract.DataContentError as exc:
        raise ConfigError(str(exc)) from exc


def compose_projection_name(compose: str | Path) -> str:
    source = Path(str(compose))
    if source.name == "compose.yaml" and source.parent.parent.name == "services":
        return f"{source.parent.name}.yaml"
    return source.name


def compose_paths(cfg: dict[str, Any]) -> list[tuple[str, Path]]:
    result = []
    for component in cfg.get("spec", {}).get("components", []):
        compose = component.get("compose")
        if compose:
            result.append(
                (
                    str(component["id"]),
                    ROOT / str(compose),
                )
            )
    return result


def aggregate_compose_sources(path: Path | None = None) -> set[Path]:
    """Return the aggregate and its exact path-confined extends sources."""

    aggregate = path or AGGREGATE_COMPOSE
    services_root = aggregate.parent / "services"
    try:
        document = yaml.safe_load(aggregate.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"invalid aggregate Compose source {aggregate}") from exc
    services = document.get("services") if isinstance(document, dict) else None
    if not isinstance(services, dict) or not services:
        raise ConfigError(f"aggregate Compose source has no services: {aggregate}")

    sources = {aggregate}
    confined_root = services_root.resolve()
    for service_name, service in services.items():
        extension = service.get("extends") if isinstance(service, dict) else None
        relative = extension.get("file") if isinstance(extension, dict) else None
        if not isinstance(relative, str) or not relative:
            raise ConfigError(
                f"aggregate Compose service {service_name} has no extends.file"
            )
        candidate = aggregate.parent / relative
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise ConfigError(
                f"aggregate Compose extends source is missing: {candidate}"
            ) from exc
        if resolved.parent.parent != confined_root or resolved.name != "compose.yaml":
            raise ConfigError(
                f"aggregate Compose extends source escapes deployment/services: {candidate}"
            )
        sources.add(resolved)

    return sources


def aggregate_compose_environment_contract(
    path: Path | None = None,
) -> dict[str, bool]:
    """Return exact aggregate refs mapped to their reviewed empty-value policy."""

    occurrences: dict[str, list[bool]] = {}
    sources = aggregate_compose_sources(path)
    for source in sorted(sources, key=str):
        try:
            text = source.read_text()
        except OSError as exc:
            raise ConfigError(f"cannot read aggregate Compose source {source}") from exc
        for match in ENV_PATTERN.finditer(text):
            occurrences.setdefault(match.group(1), []).append(match.group(2) == ":-")
    return {
        key: key in POST_RENDER_PROVISIONED_KEYS and all(optional_occurrences)
        for key, optional_occurrences in sorted(occurrences.items())
    }


def aggregate_compose_keys(path: Path | None = None) -> set[str]:
    """Return exact refs from the aggregate and its confined extends graph."""

    return set(aggregate_compose_environment_contract(path))


def aggregate_compose_projection_content(
    values: dict[str, str], source_sha: str, path: Path | None = None
) -> str:
    """Render only exact aggregate refs from already-resolved canonical values."""

    selected: dict[str, str] = {}
    for key, allow_empty in aggregate_compose_environment_contract(path).items():
        if key == "KESTRA_SECRET_PAPERCLIP_BOARD_API_KEY":
            source_value = values.get("PAPERCLIP_BOARD_API_KEY")
            value = (
                base64.b64encode(source_value.encode()).decode()
                if isinstance(source_value, str) and source_value
                else None
            )
        else:
            value = values.get(key)
        if key == "MATTERMOST_ALERT_WEBHOOK_URL" and isinstance(value, str) and value:
            projected = dict(values)
            apply_container_webhook_projection(projected)
            value = projected[key]
        if (
            value is None
            and allow_empty
            and key
            in {
                "PAPERCLIP_BOARD_API_KEY",
                "KESTRA_SECRET_PAPERCLIP_BOARD_API_KEY",
            }
        ):
            value = ""
        if not isinstance(value, str) or (not value and not allow_empty):
            raise ConfigError(f"aggregate Compose ref is unresolved: {key}")
        if "\n" in value or "\r" in value or ENV_PATTERN.search(value):
            raise ConfigError(f"aggregate Compose ref is invalid: {key}")
        selected[key] = value
    return generated_header(source_sha) + "".join(
        f"{key}={selected[key]}\n" for key in sorted(selected)
    )


def runtime_compose_path(component_id: str) -> Path:
    """Return the legacy acceptance projection for one canonical component."""

    return ROOT / "runtime" / "deploy" / f"{component_id}.yaml"


def key_part(value: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", value.upper()).strip("_")


def generated_key(component_id: str, service_name: str, suffix: str) -> str:
    return "MTE_" + "_".join(
        key_part(item) for item in (component_id, service_name, suffix) if item
    )


def scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def compose_declarations(
    component_id: str,
    path: Path,
) -> tuple[dict[str, Any], set[str], dict[str, str]]:
    try:
        document = yaml.safe_load(strip_generated_header(path.read_text()))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"invalid compose source {path}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("services"), dict):
        raise ConfigError(f"compose source has no services: {path}")
    required: set[str] = set()
    seeds: dict[str, str] = {}
    raw = path.read_text()
    for match in ENV_PATTERN.finditer(raw):
        key, operator, default = match.groups()
        required.add(key)
        if operator == ":-" and default:
            seeds.setdefault(key, default)
    for service_name, service in document["services"].items():
        if not isinstance(service, dict):
            continue
        image = service.get("image")
        if isinstance(image, str) and not image.startswith("${"):
            key = generated_key(component_id, str(service_name), "IMAGE")
            required.add(key)
            seeds.setdefault(key, image)
        for field, suffix in (("cpus", "CPU_LIMIT"), ("mem_limit", "MEMORY_LIMIT")):
            value = service.get(field)
            if value is not None and not str(value).startswith("${"):
                key = generated_key(component_id, str(service_name), suffix)
                required.add(key)
                seeds.setdefault(key, scalar(value))
        for index, port in enumerate(service.get("ports", []) or [], 1):
            if not str(port).startswith("${"):
                key = generated_key(
                    component_id, str(service_name), f"PORT_{index}_MAPPING"
                )
                required.add(key)
                seeds.setdefault(key, scalar(port))
        environment = service.get("environment")
        if isinstance(environment, dict):
            for name, value in environment.items():
                if value is None or not MUTABLE_KEY_PATTERN.search(str(name)):
                    continue
                derived_ref = COMPOSE_DERIVED_ENV_REFS.get((component_id, str(name)))
                if derived_ref:
                    required.add(derived_ref)
                    continue
                text = scalar(value)
                refs = ENV_PATTERN.findall(text)
                if refs:
                    required.update(item[0] for item in refs)
                    continue
                if (
                    component_id == "firecrawl"
                    and str(name) == "HARNESS_STARTUP_TIMEOUT_MS"
                ):
                    key = "FIRECRAWL_HARNESS_STARTUP_TIMEOUT_MS"
                else:
                    key = generated_key(component_id, str(service_name), f"ENV_{name}")
                required.add(key)
                seeds.setdefault(key, text)
    return document, required, seeds


def _compose_seed_keys(cfg: dict[str, Any]) -> set[str]:
    compose_required: set[str] = set()
    for component_id, path in compose_paths(cfg):
        if not path.is_file():
            raise ConfigError(f"missing compose projection source {path}")
        _, required, _ = compose_declarations(component_id, path)
        compose_required.update(required)
    component_secrets = {
        str(key)
        for component in cfg.get("spec", {}).get("components", [])
        for key in component.get("secrets", [])
    }
    return (
        compose_required
        - component_secrets
        - DERIVED_VALUE_KEYS
        - REQUIRED_OPERATOR_BOOTSTRAP_KEYS
        - set(ONE_TIME_MIGRATION_SEEDS)
    )


def compose_seed_catalog(cfg: dict[str, Any]) -> dict[str, str]:
    """Load the reviewed, non-secret Compose seed catalog for first install only."""
    try:
        document = json.loads(COMPOSE_SEED_SOURCE.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(
            f"invalid Compose seed catalog {COMPOSE_SEED_SOURCE}"
        ) from exc
    if not isinstance(document, dict):
        raise ConfigError("Compose seed catalog must be an object")
    if document.get("apiVersion") != "micro-task-engine/v1alpha1":
        raise ConfigError("Compose seed catalog apiVersion is unsupported")
    if document.get("kind") != "ComposeSeedCatalog":
        raise ConfigError("Compose seed catalog kind is invalid")
    metadata = document.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("contractVersion") != 1:
        raise ConfigError("Compose seed catalog contractVersion is unsupported")
    raw_seeds = document.get("seeds")
    if not isinstance(raw_seeds, dict):
        raise ConfigError("Compose seed catalog seeds must be an object")

    # The checked-in catalog covers every selectable provider, while a render
    # consumes only the selected profile's rows. This keeps one reviewed seed
    # source without leaking inactive-provider keys into canonical platform.env.
    universe_cfg = config_object()
    expected = _compose_seed_keys(universe_cfg)
    active_expected = _compose_seed_keys(cfg)
    actual = {str(key) for key in raw_seeds}
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ConfigError(
            "Compose seed catalog coverage mismatch; "
            f"missing={','.join(missing) or '-'}; extra={','.join(extra) or '-'}"
        )

    seeds: dict[str, str] = {}
    for key in sorted(actual):
        value = raw_seeds[key]
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ConfigError(f"Compose seed catalog key {key!r} is invalid")
        if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
            raise ConfigError(
                f"Compose seed catalog value for {key} must be non-empty and single-line"
            )
        if ENV_PATTERN.search(value):
            raise ConfigError(
                f"Compose seed catalog value for {key} contains an unresolved ref"
            )
        if SENSITIVE_KEY_PATTERN.search(key) and not key.endswith("_ENABLED"):
            raise ConfigError(
                f"Compose seed catalog contains sensitive-looking key {key}"
            )
        if key.endswith("_IMAGE") and not re.search(r"@sha256:[0-9a-f]{64}$", value):
            raise ConfigError(f"Compose seed catalog image {key} is not digest-pinned")
        if re.search(r"_PORT_[0-9]+_MAPPING$", key) and not value.startswith(
            "127.0.0.1:"
        ):
            raise ConfigError(f"Compose seed catalog port {key} is not loopback-only")
        seeds[key] = value
    return {key: value for key, value in seeds.items() if key in active_expected}


def compose_projection(
    component_id: str,
    path: Path,
) -> tuple[str, set[str]]:
    document, required, _ = compose_declarations(component_id, path)
    for service_name, service in document["services"].items():
        if not isinstance(service, dict):
            continue
        image = service.get("image")
        if isinstance(image, str) and not image.startswith("${"):
            service["image"] = (
                "${"
                + generated_key(component_id, str(service_name), "IMAGE")
                + ":?required}"
            )
        for field, suffix in (("cpus", "CPU_LIMIT"), ("mem_limit", "MEMORY_LIMIT")):
            value = service.get(field)
            if value is not None and not str(value).startswith("${"):
                service[field] = (
                    "${"
                    + generated_key(component_id, str(service_name), suffix)
                    + ":?required}"
                )
        ports = service.get("ports", []) or []
        service["ports"] = [
            port
            if str(port).startswith("${")
            else "${"
            + generated_key(component_id, str(service_name), f"PORT_{index}_MAPPING")
            + ":?required}"
            for index, port in enumerate(ports, 1)
        ]
        environment = service.get("environment")
        if isinstance(environment, dict):
            for name, value in list(environment.items()):
                if value is None or not MUTABLE_KEY_PATTERN.search(str(name)):
                    continue
                derived_ref = COMPOSE_DERIVED_ENV_REFS.get((component_id, str(name)))
                if derived_ref:
                    environment[name] = "${" + derived_ref + ":?required}"
                    required.add(derived_ref)
                    continue
                text = scalar(value)
                if ENV_PATTERN.search(text):
                    environment[name] = ENV_PATTERN.sub(
                        lambda match: "${" + match.group(1) + ":?required}",
                        text,
                    )
                else:
                    key = (
                        "FIRECRAWL_HARNESS_STARTUP_TIMEOUT_MS"
                        if component_id == "firecrawl"
                        and str(name) == "HARNESS_STARTUP_TIMEOUT_MS"
                        else generated_key(
                            component_id, str(service_name), f"ENV_{name}"
                        )
                    )
                    environment[name] = "${" + key + ":?required}"
    rendered = yaml.safe_dump(document, sort_keys=False, default_flow_style=False)
    rendered = ENV_PATTERN.sub(
        lambda match: "${" + match.group(1) + ":?required}",
        rendered,
    )
    return rendered, required


def profile_key(profile_ref: str, suffix: str) -> str:
    return "PROFILE_" + key_part(profile_ref) + "_" + key_part(suffix)


def profile_environment_refs(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set().union(*(profile_environment_refs(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(profile_environment_refs(item) for item in value))
    if isinstance(value, str):
        return {match.group(1) for match in ENV_PATTERN.finditer(value)}
    return set()


def extension_build_refs(catalog: dict[str, Any]) -> set[str]:
    """Return canonical build refs, excluding profile-runtime credential aliases."""
    profiles = {
        str(profile.get("ref")): profile
        for profile in catalog.get("profiles", [])
        if isinstance(profile, dict)
    }
    refs: set[str] = set()

    def config_refs(value: Any) -> set[str]:
        if isinstance(value, dict):
            result: set[str] = set()
            for key, nested in value.items():
                if (
                    str(key).endswith("Ref")
                    and isinstance(nested, str)
                    and re.fullmatch(r"[A-Z][A-Z0-9_]*", nested)
                ):
                    result.add(nested)
                result.update(config_refs(nested))
            return result
        if isinstance(value, list):
            return set().union(*(config_refs(item) for item in value))
        return set()

    for extension in catalog.get("extensions", []):
        if not isinstance(extension, dict):
            continue
        package = extension.get("package")
        if isinstance(package, dict):
            for key in ("versionRef", "integrityRef"):
                value = package.get(key)
                if isinstance(value, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", value):
                    refs.add(value)
        runtime_keys: set[str] = set(extension.get("credentialRefs") or [])
        for profile_ref in extension.get("enabledProfiles") or []:
            profile = profiles.get(str(profile_ref), {})
            runtime = profile.get("runtimeContract", {})
            if isinstance(runtime, dict):
                runtime_keys.update(runtime.get("envAllowlist") or [])
        config = extension.get("config")
        if isinstance(config, dict):
            refs.update(config_refs(config) - runtime_keys)
    return refs


def profile_declarations(path: Path) -> tuple[dict[str, Any], set[str], dict[str, str]]:
    try:
        catalog = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"invalid profile catalog {path}") from exc
    if not isinstance(catalog, dict):
        raise ConfigError(f"invalid profile catalog {path}")
    required: set[str] = set()
    seeds: dict[str, str] = {}
    for profile in catalog.get("profiles", []):
        ref = str(profile["ref"])
        fields: list[tuple[dict[str, Any], str, str]] = [
            (profile, "nativeAdapter", "ADAPTER"),
        ]
        if "defaultEnvironment" in profile:
            fields.append((profile, "defaultEnvironment", "DEFAULT_ENVIRONMENT"))
        adapter = profile.get("nativeAdapterConfig", {})
        fields.extend(
            [
                (adapter, "provider", "PROVIDER"),
                (adapter, "model", "MODEL"),
                (adapter, "timeoutSec", "TIMEOUT_SEC"),
            ]
        )
        limits = profile.get("limits", {})
        fields.extend(
            [
                (limits, "maxConcurrentRuns", "MAX_CONCURRENT_RUNS"),
                (limits, "timeoutSeconds", "TIMEOUT_SECONDS"),
                (limits, "cpu", "CPU_LIMIT"),
                (limits, "memory", "MEMORY_LIMIT"),
            ]
        )
        packages = profile.get("runtimePackages", {})
        for package, value in packages.items():
            fields.append((packages, str(package), f"PACKAGE_{package}_VERSION"))
        for container, name, suffix in fields:
            if name not in container:
                continue
            key = profile_key(ref, suffix)
            required.add(key)
            value = container[name]
            if not (isinstance(value, str) and ENV_PATTERN.fullmatch(value)):
                seeds.setdefault(key, scalar(value))
        # llmRouting.apiKeyRef is recorded as a declared secret dependency, but
        # declared_keys excludes it from the first render gate because 9Router
        # issues the value during the subsequent provision stage.
        llm_routing = profile.get("llmRouting", {})
        api_key_ref = (
            llm_routing.get("apiKeyRef") if isinstance(llm_routing, dict) else None
        )
        if isinstance(api_key_ref, str) and re.fullmatch(
            r"[A-Z][A-Z0-9_]*", api_key_ref
        ):
            required.add(api_key_ref)
        required.update(profile_environment_refs(profile))
    required.update(extension_build_refs(catalog))
    return catalog, required, seeds


def profile_projection(path: Path, values: dict[str, str]) -> tuple[str, set[str]]:
    catalog, required, _ = profile_declarations(path)
    integer_suffixes = ("_TIMEOUT_SEC", "_TIMEOUT_SECONDS", "_MAX_CONCURRENT_RUNS")

    for profile in catalog.get("profiles", []):
        ref = str(profile["ref"])
        fields: list[tuple[dict[str, Any], str, str]] = [
            (profile, "nativeAdapter", "ADAPTER")
        ]
        if "defaultEnvironment" in profile:
            fields.append((profile, "defaultEnvironment", "DEFAULT_ENVIRONMENT"))
        adapter = profile.get("nativeAdapterConfig", {})
        fields.extend(
            [
                (adapter, "provider", "PROVIDER"),
                (adapter, "model", "MODEL"),
                (adapter, "timeoutSec", "TIMEOUT_SEC"),
            ]
        )
        limits = profile.get("limits", {})
        fields.extend(
            [
                (limits, "maxConcurrentRuns", "MAX_CONCURRENT_RUNS"),
                (limits, "timeoutSeconds", "TIMEOUT_SECONDS"),
                (limits, "cpu", "CPU_LIMIT"),
                (limits, "memory", "MEMORY_LIMIT"),
            ]
        )
        packages = profile.get("runtimePackages", {})
        fields.extend(
            (packages, str(name), f"PACKAGE_{name}_VERSION") for name in packages
        )
        for container, name, suffix in fields:
            if name in container:
                container[name] = "${" + profile_key(ref, suffix) + ":?required}"

    def resolve(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: resolve(nested) for key, nested in value.items()}
        if isinstance(value, list):
            return [resolve(nested) for nested in value]
        if isinstance(value, str):
            match = ENV_PATTERN.fullmatch(value)
            if match:
                key = match.group(1)
                if key == "WORKSPACE":
                    return value
                if key not in values:
                    raise ConfigError(
                        f"canonical platform.env is missing required key {key}"
                    )
                raw = values[key]
                if key.endswith(integer_suffixes):
                    return int(raw)
                return raw
            matches = list(ENV_PATTERN.finditer(value))
            if matches:
                for nested_match in matches:
                    key = nested_match.group(1)
                    if SENSITIVE_KEY_PATTERN.search(key) and not key.endswith(
                        "_ENABLED"
                    ):
                        raise ConfigError(
                            f"profile strings cannot interpolate sensitive key {key}"
                        )
                    if key not in values:
                        raise ConfigError(
                            f"canonical platform.env is missing required key {key}"
                        )
                return ENV_PATTERN.sub(
                    lambda nested_match: values[nested_match.group(1)], value
                )
        return value

    rendered = resolve(catalog)
    rendered["_generated"] = {
        "doNotEdit": True,
        "generatorVersion": GENERATOR_VERSION,
    }
    return yaml.safe_dump(rendered, sort_keys=False, default_flow_style=False), required


def declared_keys(
    cfg: dict[str, Any],
    values: dict[str, str] | None = None,
) -> tuple[set[str], dict[str, set[str]], dict[str, str]]:
    required: set[str] = set()
    service_keys: dict[str, set[str]] = {}
    seeds: dict[str, str] = {}
    active_component_ids = {
        str(component.get("id"))
        for component in cfg.get("spec", {}).get("components", [])
        if isinstance(component, dict) and component.get("id")
    }
    for component_id, path in compose_paths(cfg):
        if not path.is_file():
            raise ConfigError(f"missing compose projection source {path}")
        keys = service_keys.setdefault(component_id, set())
        _, compose_keys, _ = compose_declarations(component_id, path)
        required.update(compose_keys)
        keys.update(compose_keys)
    for component in cfg.get("spec", {}).get("components", []):
        keys = service_keys.setdefault(str(component["id"]), set())
        for key in component.get("secrets", []):
            required.add(str(key))
            keys.add(str(key))
    if "hermes" in active_component_ids:
        service_keys.setdefault("hermes", set()).update(HERMES_SERVICE_ENV_KEYS)
    required.update(
        {
            "FIRECRAWL_HARNESS_STARTUP_TIMEOUT_MS",
            "FIRECRAWL_API_MEMORY_LIMIT",
        }
    )
    service_keys.setdefault("firecrawl", set()).update(
        {
            "FIRECRAWL_HARNESS_STARTUP_TIMEOUT_MS",
            "FIRECRAWL_API_MEMORY_LIMIT",
        }
    )
    if "postgrest" in active_component_ids:
        service_keys.setdefault("postgrest", set()).update(
            {
                "POSTGREST_PUBLIC_URL",
                "POSTGREST_PAPERCLIP_TOKEN",
            }
        )
    selected_profile = str(
        (values or ONE_TIME_MIGRATION_SEEDS).get(
            "DATA_CONTENT_PROFILE", ONE_TIME_MIGRATION_SEEDS["DATA_CONTENT_PROFILE"]
        )
    ).strip()
    if selected_profile == "postgres-notion":
        notion_keys = {
            "NOTION_TOKEN",
            "NOTION_API_BASE_URL",
            "NOTION_API_VERSION",
            "NOTION_ROOT_PAGE_ID",
            "NOTION_DOCUMENTS_PAGE_ID",
            "NOTION_TABLE_DATABASE_ID",
            "NOTION_TABLE_DATA_SOURCE_ID",
            "NOTION_WORKSPACE_ID",
            "NOTION_BOT_ID",
        }
        required.update(notion_keys)
        service_keys.setdefault("notion", set()).update(notion_keys)

    def refs(value: Any) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if (
                    key.endswith("Ref")
                    and isinstance(nested, str)
                    and re.fullmatch(r"[A-Z][A-Z0-9_]*", nested)
                ):
                    required.add(nested)
                elif key.endswith("Refs") and isinstance(nested, list):
                    required.update(
                        str(item)
                        for item in nested
                        if re.fullmatch(r"[A-Z][A-Z0-9_]*", str(item))
                    )
                refs(nested)
        elif isinstance(value, list):
            for nested in value:
                refs(nested)
        elif isinstance(value, str):
            required.update(match.group(1) for match in ENV_PATTERN.finditer(value))

    refs(cfg)
    required.difference_update(DERIVED_VALUE_KEYS)
    if PROFILE_SOURCE.is_file():
        _, profile_keys, _ = profile_declarations(PROFILE_SOURCE)
        required.update(profile_keys)
    required.difference_update(POST_RENDER_PROVISIONED_KEYS)
    required.update(ONE_TIME_MIGRATION_SEEDS)
    for key, value in ONE_TIME_MIGRATION_SEEDS.items():
        seeds.setdefault(key, value)
    required.update(OPTIONAL_EMPTY_KEYS)
    for key in OPTIONAL_EMPTY_KEYS:
        seeds.setdefault(key, "")
    required.difference_update(PUBLIC_URL_PROJECTIONS)
    required.add("PAPERCLIP_PORT")
    spec = cfg.get("spec", {})
    host = spec.get("host", {}) if isinstance(spec, dict) else {}
    if isinstance(host, dict) and host.get("ssh"):
        seeds.setdefault("MTE_SSH_TARGET", str(host["ssh"]))
    domain = (
        spec.get("resolvedDomain") or spec.get("domain")
        if isinstance(spec, dict)
        else ""
    )
    if domain:
        seeds.setdefault("PLATFORM_BASE_DOMAIN", str(domain))
    for component in spec.get("components", []) if isinstance(spec, dict) else []:
        if component.get("id") != "paperclip":
            continue
        url = str(component.get("health", {}).get("url", ""))
        match = re.search(r":([0-9]+)/", url)
        if match:
            seeds.setdefault("PAPERCLIP_PORT", match.group(1))
    if "MTE_DAYTONA_SANDBOX_IMAGE" in required:
        evidence_keys = {
            "MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL",
            "MTE_DAYTONA_SANDBOX_IMAGE_REVISION",
        }
        required.update(evidence_keys)
        service_keys.setdefault("daytona", set()).update(evidence_keys)
    return required, service_keys, seeds


def init_source(imported: dict[str, str]) -> dict[str, Any]:
    if SOURCE.exists():
        stat = SOURCE.stat()
        if stat.st_uid != 0 or stat.st_mode & 0o777 != 0o600:
            raise ConfigError(
                "refusing to initialize an incorrectly permissioned canonical env"
            )
    values = parse_env(SOURCE)
    fresh_source = not values
    migrated_keys: set[str] = set()
    reconciled_operator_keys: set[str] = set()
    for key in RETIRED_CANONICAL_KEYS:
        if key in values:
            values.pop(key)
            migrated_keys.add(key)
    for legacy_key, (
        expected_value,
        canonical_key,
        canonical_value,
    ) in REVIEWED_CANONICAL_KEY_MIGRATIONS.items():
        if values.get(legacy_key) == expected_value:
            values.pop(legacy_key)
            if not values.get(canonical_key):
                values[canonical_key] = canonical_value
                migrated_keys.add(canonical_key)
    for key, migration in REVIEWED_CANONICAL_VALUE_MIGRATIONS.items():
        *old_values, new_value = migration
        if values.get(key) in old_values:
            values[key] = new_value
            migrated_keys.add(key)
    migrated_keys.update(reconcile_governed_canonical_value_migrations(values))
    imported = dict(imported)
    aliases = {
        **DOMAIN_INPUT_ALIASES,
        "GH_TOKEN": "GITHUB_TOKEN",
        "PRIN7R_HERMES_TELEGRAM_BOT_TOKEN": "HERMES_TELEGRAM_BOT_TOKEN",
        "MINIMAX_OPENAI_ENDPOINT": "MINIMAX_BASE_URL",
        "PRIN7R_NOTION_TOKEN": "NOTION_TOKEN",
        "PRIN7R_NOTION_API_KEY": "NOTION_TOKEN",
    }
    selected_notion_token = next(
        (
            str(imported[key]).strip()
            for key in NOTION_TOKEN_IMPORT_PRIORITY
            if str(imported.get(key, "")).strip()
        ),
        "",
    )
    for key in NOTION_TOKEN_IMPORT_PRIORITY:
        imported.pop(key, None)
    if selected_notion_token:
        imported["NOTION_TOKEN"] = selected_notion_token
    for legacy, canonical in aliases.items():
        if canonical not in imported and legacy in imported:
            imported[canonical] = imported[legacy]
        imported.pop(legacy, None)

    # Values in the explicit operator contract are declarative and may be
    # changed only by importing that same selected dotenv. Generated service
    # secrets and provisioned identifiers are intentionally absent from this
    # set and remain on the fill-only paths below.
    imported_operator_cidrs = str(imported.get("MTE_OPERATOR_SSH_CIDRS", "")).strip()
    if imported_operator_cidrs:
        canonical_operator_cidrs = normalize_operator_ssh_cidrs(imported_operator_cidrs)
        if imported_operator_cidrs != canonical_operator_cidrs:
            raise ConfigError(
                "MTE_OPERATOR_SSH_CIDRS must be sorted, unique, normalized and "
                f"comma-separated: {canonical_operator_cidrs}"
            )
    for key in sorted(OPERATOR_RECONCILED_KEYS & set(imported)):
        value = str(imported[key]).strip()
        if values.get(key) != value:
            values[key] = value
            reconciled_operator_keys.add(key)
    selection_values = dict(ONE_TIME_MIGRATION_SEEDS)
    selection_values.update(imported)
    selection_values.update(values)
    resource_preflight_values(selection_values)
    # Host bootstrap creates a deliberately tiny canonical file containing
    # only Docker prerequisites.  Until the data profile is materialized it
    # is not an initialized platform source, so the first config init must
    # also import the immutable Compose catalog.
    bootstrap_source = (
        fresh_source or not values.get("DATA_CONTENT_PROFILE", "").strip()
    )
    if not selection_values.get("DATA_CONTENT_PROFILE", "").strip():
        selection_values["DATA_CONTENT_PROFILE"] = ONE_TIME_MIGRATION_SEEDS[
            "DATA_CONTENT_PROFILE"
        ]
    cfg = active_config_object(
        config_object(),
        selection_values,
    )
    required, _, seeds = declared_keys(cfg, selection_values)
    missing_operator_inputs = sorted(
        key
        for key in REQUIRED_OPERATOR_BOOTSTRAP_KEYS & required
        if not str(values.get(key) or imported.get(key) or "").strip()
    )
    if missing_operator_inputs:
        raise ConfigError(
            "explicit operator bootstrap input is missing required keys: "
            + ", ".join(missing_operator_inputs)
        )
    if "MTE_PAPERCLIP_IMAGE" in required:
        paperclip_image = str(
            values.get("MTE_PAPERCLIP_IMAGE")
            or imported.get("MTE_PAPERCLIP_IMAGE")
            or ""
        ).strip()
        if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", paperclip_image):
            raise ConfigError(
                "MTE_PAPERCLIP_IMAGE must be set to the published immutable "
                "Paperclip MTE image by sha256 digest"
            )
        validate_paperclip_fork_evidence(
            str(
                values.get("MTE_PAPERCLIP_FORK_SOURCE_URL")
                or imported.get("MTE_PAPERCLIP_FORK_SOURCE_URL")
                or ""
            ),
            str(
                values.get("MTE_PAPERCLIP_FORK_REVISION")
                or imported.get("MTE_PAPERCLIP_FORK_REVISION")
                or ""
            ),
        )
    if "MTE_DAYTONA_SANDBOX_IMAGE" in required:
        sandbox_image = str(
            values.get("MTE_DAYTONA_SANDBOX_IMAGE")
            or imported.get("MTE_DAYTONA_SANDBOX_IMAGE")
            or ""
        ).strip()
        if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", sandbox_image):
            raise ConfigError(
                "MTE_DAYTONA_SANDBOX_IMAGE must be set to the published "
                "immutable Daytona harness image by sha256 digest"
            )
        sandbox_source = str(
            values.get("MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL")
            or imported.get("MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL")
            or ""
        ).strip()
        sandbox_revision = str(
            values.get("MTE_DAYTONA_SANDBOX_IMAGE_REVISION")
            or imported.get("MTE_DAYTONA_SANDBOX_IMAGE_REVISION")
            or ""
        ).strip()
        if not re.fullmatch(r"https://[^\s]+", sandbox_source):
            raise ConfigError(
                "MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL must be an HTTPS source URL"
            )
        if not re.fullmatch(r"[0-9a-f]{40}", sandbox_revision):
            raise ConfigError(
                "MTE_DAYTONA_SANDBOX_IMAGE_REVISION must be an immutable "
                "40-character commit"
            )
    if E2E_GITHUB_TARGET_KEYS & required:
        validate_e2e_github_target(selection_values)
    if "MTE_OPERATOR_SSH_CIDRS" in required:
        raw_operator_cidrs = str(
            values.get("MTE_OPERATOR_SSH_CIDRS")
            or imported.get("MTE_OPERATOR_SSH_CIDRS")
            or ""
        ).strip()
        canonical_operator_cidrs = normalize_operator_ssh_cidrs(raw_operator_cidrs)
        if raw_operator_cidrs != canonical_operator_cidrs:
            raise ConfigError(
                "MTE_OPERATOR_SSH_CIDRS must be sorted, unique, normalized and "
                f"comma-separated: {canonical_operator_cidrs}"
            )
    clean_install_aliases = {"PRIN7R_NOTION_PAGE_ID": "NOTION_ROOT_PAGE_ID"}
    allowed_imports = required | OPTIONAL_OPERATOR_INPUT_KEYS | set(aliases)
    if selection_values["DATA_CONTENT_PROFILE"] == "postgres-notion":
        # Reuse operator-reviewed Notion resources on an existing deployment.
        # These non-secret IDs remain fill-only; the provisioner creates only
        # resources whose canonical ID is absent.
        allowed_imports.update(NOTION_BOOTSTRAP_ID_KEYS)
    if fresh_source:
        allowed_imports.update(clean_install_aliases)
    created = []
    # Non-operator imports are fill-only. A repeated init must never overwrite
    # a generated value already issued or rotated on the server.
    for key, value in imported.items():
        if value and key in allowed_imports and not values.get(key):
            values[key] = value
    if fresh_source:
        for legacy, canonical in clean_install_aliases.items():
            if not values.get(canonical) and values.get(legacy):
                values[canonical] = values[legacy]
                created.append(canonical)
            values.pop(legacy, None)
    for legacy, canonical in aliases.items():
        if not values.get(canonical) and values.get(legacy):
            values[canonical] = values[legacy]
            created.append(canonical)
        values.pop(legacy, None)
    for key, migration in REVIEWED_CANONICAL_VALUE_MIGRATIONS.items():
        *old_values, new_value = migration
        if values.get(key) in old_values:
            values[key] = new_value
            migrated_keys.add(key)
    migrated_keys.update(reconcile_governed_canonical_value_migrations(values))
    prior_daytona_proxy_domain = values.get("MTE_DAYTONA_PROXY_DOMAIN", "").strip()
    for derived in DERIVED_VALUE_KEYS:
        values.pop(derived, None)
    # The reviewed Compose catalog is bootstrap-only except for explicitly
    # reviewed fill-only migrations. Existing non-empty canonical values win;
    # operator-owned inputs were reconciled above and generated secrets remain
    # untouched here.
    reviewed_compose_missing = {
        key
        for key in required
        & (REVIEWED_COMPOSE_SEED_MIGRATIONS | REVIEWED_TOOLHIVE_COMPOSE_SEED_MIGRATIONS)
        if not values.get(key, "").strip()
    }
    reviewed_legacy_values = {
        key
        for key, legacy_value in REVIEWED_LEGACY_COMPOSE_VALUE_MIGRATIONS.items()
        if values.get(key) == legacy_value
    }
    if bootstrap_source or reviewed_compose_missing or reviewed_legacy_values:
        compose_seeds = compose_seed_catalog(cfg)
        overlap = sorted(set(seeds) & set(compose_seeds))
        if overlap:
            raise ConfigError(
                "Compose and general bootstrap seed classes overlap: "
                + ", ".join(overlap)
            )
        if bootstrap_source:
            for key, value in compose_seeds.items():
                seeds.setdefault(key, value)
        else:
            unavailable = sorted(reviewed_compose_missing - set(compose_seeds))
            if unavailable:
                raise ConfigError(
                    "reviewed Compose migration seed is unavailable: "
                    + ", ".join(unavailable)
                )
            for key in reviewed_compose_missing:
                values[key] = compose_seeds[key]
                created.append(key)
        unavailable_legacy = sorted(reviewed_legacy_values - set(compose_seeds))
        if unavailable_legacy:
            raise ConfigError(
                "reviewed legacy Compose migration seed is unavailable: "
                + ", ".join(unavailable_legacy)
            )
        for key in reviewed_legacy_values:
            values[key] = compose_seeds[key]
            migrated_keys.add(key)
    for key, value in seeds.items():
        if key in DERIVED_VALUE_KEYS:
            continue
        if key not in values or (
            key == "DATA_CONTENT_PROFILE" and not values[key].strip()
        ):
            values[key] = value
            created.append(key)
    if values.get("MTE_DAYTONA_PROXY_INTERNAL_PORT", "").strip():
        apply_daytona_proxy_domain_projection(values)
        daytona_proxy_domain = values["MTE_DAYTONA_PROXY_DOMAIN"]
        if not prior_daytona_proxy_domain:
            created.append("MTE_DAYTONA_PROXY_DOMAIN")
        elif prior_daytona_proxy_domain != daytona_proxy_domain:
            migrated_keys.add("MTE_DAYTONA_PROXY_DOMAIN")
    url_targets = set(CANONICAL_DERIVED_URL_SPECS) & required
    url_created, url_migrated = reconcile_canonical_urls(values, targets=url_targets)
    created.extend(url_created)
    migrated_keys.update(url_migrated)
    created.extend(reconcile_generated_canonical_secrets(values, required))
    missing = missing_required(values, required)
    # Init may run before generated service credentials exist.  It reports
    # missing refs but never fabricates external credentials.
    write_env(SOURCE, values, mode=0o600)
    return {
        "initialized": True,
        "createdKeys": sorted(created),
        "migratedKeys": sorted(migrated_keys),
        "reconciledOperatorKeys": sorted(reconciled_operator_keys),
        "missingKeys": missing,
    }


def merge_notion_provision(
    payload: dict[str, Any], *, expect_idempotent: bool = False
) -> dict[str, Any]:
    """Fill canonical Notion resource IDs from the governed provisioner output.

    The caller passes the producer JSON over stdin.  Only the five reviewed,
    non-secret Notion identity keys may cross this boundary.  Existing values
    must either match exactly or the whole update is rejected before writing.
    """

    if (
        payload.get("apiVersion") != "micro-task-engine/v1alpha1"
        or payload.get("kind") != "NotionConnectorProvision"
        or payload.get("status") != "converged"
        or payload.get("ok") is not True
        or payload.get("redacted") is not True
        or payload.get("dataContentProfile") != "postgres-notion"
    ):
        raise ConfigError("notion provision envelope is invalid")
    updates = payload.get("environmentUpdates")
    changed_keys = payload.get("changedKeys")
    if not isinstance(updates, dict) or not updates:
        raise ConfigError("notion provision updates are missing")
    if set(updates) - NOTION_BOOTSTRAP_ID_KEYS:
        raise ConfigError("notion provision contains an unreviewed update key")
    if (
        not isinstance(changed_keys, list)
        or any(not isinstance(key, str) for key in changed_keys)
        or len(changed_keys) != len(set(changed_keys))
        or set(changed_keys) - NOTION_BOOTSTRAP_ID_KEYS
    ):
        raise ConfigError("notion provision changedKeys are invalid")

    validated: dict[str, str] = {}
    for key, raw_value in updates.items():
        if not isinstance(raw_value, str) or raw_value != raw_value.strip():
            raise ConfigError(f"notion provision UUID is invalid for {key}")
        try:
            canonical = str(uuid.UUID(raw_value))
        except (ValueError, AttributeError) as exc:
            raise ConfigError(f"notion provision UUID is invalid for {key}") from exc
        if canonical != raw_value:
            raise ConfigError(f"notion provision UUID is not canonical for {key}")
        validated[key] = canonical

    values, _ = source_state()
    if values.get("DATA_CONTENT_PROFILE", "").strip() != "postgres-notion":
        raise ConfigError("notion provision profile does not match canonical source")
    missing = {key for key in validated if not values.get(key, "").strip()}
    if set(changed_keys) != missing:
        raise ConfigError("notion provision changedKeys do not match canonical source")
    for key, value in validated.items():
        existing = values.get(key, "").strip()
        if existing and existing != value:
            raise ConfigError(f"refusing to overwrite canonical Notion ID {key}")
    if expect_idempotent and missing:
        raise ConfigError("notion provision did not converge idempotently")

    for key in missing:
        values[key] = validated[key]
    if missing:
        write_env(SOURCE, values, mode=0o600)
    return {
        "acceptedKeys": sorted(validated),
        "mergedKeys": sorted(missing),
        "unchangedKeys": sorted(set(validated) - missing),
        "idempotent": not missing,
        "sourceSha256": sha256_path(SOURCE),
    }


def generated_header(source_sha: str) -> str:
    return (
        f"{GENERATED_PREFIX}sourceSha256={source_sha}; "
        f"generatorVersion={GENERATOR_VERSION}\n"
    )


def strip_generated_header(text: str) -> str:
    lines = text.splitlines(keepends=True)
    if lines and lines[0].startswith(GENERATED_PREFIX):
        return "".join(lines[1:])
    return text


def projection_row(path: Path, source_sha: str) -> dict[str, str]:
    return {
        "path": str(path),
        "contentSha256": sha256_path(path),
        "sourceSha256": source_sha,
        "generatorVersion": GENERATOR_VERSION,
    }


def cloudflare_runtime_credential_projections(
    values: dict[str, str],
    route_prefixes: dict[str, str],
    source_sha: str,
) -> tuple[str | None, dict[str, Any] | None]:
    """Resolve independently deployable Cloudflare runtime credentials.

    A legacy installation can already have a valid tunnel token before the
    Cloudflare stage has created per-route Access service tokens.  Keep that
    state renderable while rejecting a torn credential tuple for any route.
    The aggregate Access projection is emitted only after every configured
    service route has a complete tuple.
    """
    tunnel_token = values.get("CLOUDFLARE_TUNNEL_TOKEN", "").strip() or None
    route_fields = {
        "id": "_ID",
        "client_id": "_CLIENT_ID",
        "client_secret": "_CLIENT_SECRET",
        "expires_at": "_EXPIRES_AT",
    }
    complete_routes: dict[str, dict[str, str]] = {}
    for app_id, prefix in route_prefixes.items():
        route = {
            field: values.get(prefix + suffix, "").strip()
            for field, suffix in route_fields.items()
        }
        present = [bool(value) for value in route.values()]
        if any(present) and not all(present):
            raise ConfigError(
                f"canonical Cloudflare runtime credentials are incomplete for route: {app_id}"
            )
        if all(present):
            complete_routes[app_id] = route

    access_payload = None
    if route_prefixes and len(complete_routes) == len(route_prefixes):
        access_payload = {
            "routes": complete_routes,
            "_generated": {
                "doNotEdit": True,
                "sourceSha256": source_sha,
                "generatorVersion": GENERATOR_VERSION,
            },
        }
    return tunnel_token, access_payload


def service_projection_content(
    component_id: str,
    keys: set[str],
    values: dict[str, str],
    source_sha: str,
) -> str:
    aliases = HERMES_NATIVE_ENV_NAMES if component_id == "hermes" else {}
    selected = {
        aliases.get(key, key): values[key]
        for key in sorted(keys)
        if values.get(key, "").strip()
    }
    return generated_header(source_sha) + "".join(
        f"{key}={selected[key]}\n" for key in sorted(selected)
    )


def validate_atomic_output_path(path: Path) -> None:
    """Reject destinations or direct parents that could redirect privileged writes."""
    if not path.is_absolute():
        raise ConfigError(f"refusing a relative output path: {path}")
    try:
        parent_info = path.parent.lstat()
    except FileNotFoundError:
        parent_info = None
    if parent_info is not None and stat.S_ISLNK(parent_info.st_mode):
        raise ConfigError(f"refusing an unsafe output path: {path.parent}")
    if parent_info is not None and not stat.S_ISDIR(parent_info.st_mode):
        raise ConfigError(f"refusing an unsafe output path: {path.parent}")
    try:
        destination_info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(destination_info.st_mode):
        raise ConfigError(f"refusing an unsafe output path: {path}")


def atomic_text(path: Path, content: str, mode: int) -> None:
    validate_atomic_output_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Re-check after creation so a pre-existing or concurrently introduced
    # symlink is rejected before the private temporary receives any content.
    validate_atomic_output_path(path)
    if path == SECRET_ROOT or SECRET_ROOT in path.parents:
        secure_path(path.parent, 0o700)
    descriptor, raw_temporary = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(raw_temporary)
    try:
        os.fchmod(descriptor, mode)
        if os.geteuid() == 0:
            os.fchown(descriptor, 0, 0)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def secure_path(path: Path, mode: int) -> None:
    """Apply the root-only ownership contract without weakening local tests."""
    path.chmod(mode)
    if os.geteuid() == 0:
        os.chown(path, 0, 0)


def remove_unregistered_legacy_secret_projections(
    manifest: dict[str, Any],
) -> list[Path]:
    """Remove exact obsolete artifacts after validating the complete candidate set."""
    rows = manifest.get("projections", [])
    if not isinstance(rows, list):
        raise ConfigError("projection manifest rows are invalid")
    registered = {
        Path(str(row["path"]))
        for row in rows
        if isinstance(row, dict) and row.get("path")
    }
    candidates: list[tuple[Path, str]] = []
    allowlisted = [
        *((name, "file") for name in LEGACY_SECRET_PROJECTION_RELATIVE_PATHS),
        *(
            (name, "empty-directory")
            for name in LEGACY_EMPTY_SECRET_DIRECTORY_RELATIVE_PATHS
        ),
    ]
    for relative_name, expected_kind in allowlisted:
        relative_path = Path(relative_name)
        candidate = SECRET_ROOT / relative_path
        if (
            relative_path.is_absolute()
            or not relative_path.parts
            or ".." in relative_path.parts
            or candidate == SECRET_ROOT
            or SECRET_ROOT not in candidate.parents
            or candidate == SOURCE
        ):
            raise ConfigError("legacy secret projection allowlist is unsafe")
        if candidate in registered:
            continue
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ConfigError(
                f"cannot inspect legacy secret projection: {candidate}"
            ) from exc
        if expected_kind == "file" and not stat.S_ISREG(info.st_mode):
            raise ConfigError(
                f"legacy secret projection is not a regular file: {candidate}"
            )
        if expected_kind == "empty-directory" and not stat.S_ISDIR(info.st_mode):
            raise ConfigError(f"legacy secret artifact is not a directory: {candidate}")
        if info.st_uid != 0 or info.st_gid != 0:
            raise ConfigError(
                f"legacy secret projection is not root-owned: {candidate}"
            )
        if expected_kind == "empty-directory":
            try:
                if next(candidate.iterdir(), None) is not None:
                    raise ConfigError(
                        f"legacy secret artifact directory is not empty: {candidate}"
                    )
            except OSError as exc:
                raise ConfigError(
                    f"cannot inspect legacy secret artifact directory: {candidate}"
                ) from exc
        candidates.append((candidate, expected_kind))

    for candidate, expected_kind in candidates:
        try:
            if expected_kind == "empty-directory":
                candidate.rmdir()
            else:
                candidate.unlink()
        except OSError as exc:
            raise ConfigError(
                f"cannot remove legacy secret projection: {candidate}"
            ) from exc
    return [candidate for candidate, _ in candidates]


def harden_secret_projections(manifest: dict[str, Any]) -> None:
    """Re-assert ownership/modes for canonical and generated secret artifacts."""
    secure_path(SECRET_ROOT, 0o700)
    files = {SOURCE, MANIFEST}
    files.update(
        path
        for name in (".platform-env.lock", ".platform.env.lock", "platform.env.lock")
        if (path := SECRET_ROOT / name).exists()
    )
    for row in manifest.get("projections", []):
        if not isinstance(row, dict) or not row.get("path"):
            continue
        path = Path(str(row["path"]))
        if path == SECRET_ROOT or SECRET_ROOT in path.parents:
            files.add(path)
    for path in sorted(files, key=str):
        if not path.is_file():
            raise ConfigError(f"secret projection is missing: {path}")
        secure_path(path, 0o600)
        parent = path.parent
        while parent == SECRET_ROOT or SECRET_ROOT in parent.parents:
            secure_path(parent, 0o700)
            if parent == SECRET_ROOT:
                break
            parent = parent.parent


def cloudflare_apps_projection(
    cfg: dict[str, Any],
    values: dict[str, str],
    base_domain: str,
    source_sha: str,
    data_content_plane: dict[str, Any],
    data_content_plane_sha: str,
) -> dict[str, Any]:
    cloudflare = cfg.get("spec", {}).get("cloudflare", {})
    contract = data_content_contract()
    try:
        try:
            lock = platform_lock_object()
        except ConfigError:
            installed = Path(__file__).resolve()
            source_root = (
                installed.parents[2]
                if installed.parent.name == "platform-cli"
                and installed.parent.parent.name == "tools"
                else installed.parents[1]
            )
            local_lock = source_root / "config" / "platform.lock.yaml"
            lock = yaml.safe_load(local_lock.read_text())
        registry = contract.validate_registry(lock)
    except (OSError, yaml.YAMLError, contract.DataContentError) as exc:
        raise ConfigError(str(exc)) from exc
    provider_components = (
        {
            str(component_id)
            for bundle in registry.values()
            for component_id in bundle["componentIds"]
        }
        if isinstance(registry, dict)
        else set()
    )
    selected_components = {
        str(component_id) for component_id in data_content_plane.get("componentIds", [])
    }
    declarations: list[dict[str, Any]] = []
    for component in cfg.get("spec", {}).get("components", []):
        component_id = (
            str(component.get("id", "")) if isinstance(component, dict) else ""
        )
        if (
            component_id in provider_components
            and component_id not in selected_components
        ):
            continue
        if isinstance(component, dict) and isinstance(component.get("exposure"), dict):
            declarations.append({"id": component.get("id"), **component["exposure"]})
    additional = (
        cloudflare.get("additionalApps", []) if isinstance(cloudflare, dict) else []
    )
    if not isinstance(additional, list):
        raise ConfigError("cloudflare.additionalApps must be a list")
    declarations.extend(row for row in additional if isinstance(row, dict))

    apps: dict[str, dict[str, str]] = {}
    hostnames: set[str] = set()
    for declaration in declarations:
        app_id = str(declaration.get("id", "")).strip()
        if not app_id or app_id in apps:
            raise ConfigError("Cloudflare applications require unique non-empty ids")
        refs = {
            name: str(declaration.get(name, "")).strip()
            for name in ("subdomainRef", "originPortRef", "accessClassRef")
        }
        if any(not re.fullmatch(r"[A-Z][A-Z0-9_]*", ref) for ref in refs.values()):
            raise ConfigError(
                f"Cloudflare application {app_id} has an invalid canonical ref"
            )
        label = values.get(refs["subdomainRef"], "").strip().lower()
        port = values.get(refs["originPortRef"], "").strip()
        access_class = values.get(refs["accessClassRef"], "").strip().lower()
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise ConfigError(
                f"Cloudflare application {app_id} has an invalid subdomain label"
            )
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ConfigError(
                f"Cloudflare application {app_id} has an invalid origin port"
            )
        if access_class not in {"human", "service"}:
            raise ConfigError(
                f"Cloudflare application {app_id} has an invalid access class"
            )
        hostname = f"{label}.{base_domain}"
        if hostname in hostnames:
            raise ConfigError(
                f"Cloudflare application {app_id} has a duplicate hostname"
            )
        apps[app_id] = {
            "hostname": hostname,
            "origin": f"http://127.0.0.1:{int(port)}",
            "accessClass": access_class,
        }
        hostnames.add(hostname)
    if not apps:
        raise ConfigError("Cloudflare application registry is empty")
    roles = data_content_plane.get("roles", {})
    providers = data_content_plane.get("providers", {})
    logical_roles: dict[str, dict[str, str]] = {}
    for role_id in ("tablesUi", "documentsUi"):
        role = roles.get(role_id) if isinstance(roles, dict) else None
        provider_id = str(role.get("providerId", "")) if isinstance(role, dict) else ""
        provider = (
            providers.get(provider_id)
            if isinstance(providers, dict) and provider_id
            else None
        )
        if isinstance(provider, dict) and provider.get("deployment") == "external":
            continue
        component_id = ""
        if isinstance(role, dict):
            component_id = str(role.get("componentId", ""))
        if not component_id and isinstance(provider, dict):
            component_id = str(provider.get("componentId") or "")
        if component_id not in apps:
            raise ConfigError(
                f"logical data/content role {role_id} is not Cloudflare-exposed"
            )
        logical_roles[role_id] = {
            "applicationId": component_id,
            "hostname": apps[component_id]["hostname"],
            "accessClass": apps[component_id]["accessClass"],
        }
    return {
        "_generated": {
            "doNotEdit": True,
            "sourceSha256": source_sha,
            "generatorVersion": GENERATOR_VERSION,
        },
        "baseDomain": base_domain,
        "apps": dict(sorted(apps.items())),
        "dataContent": {
            "profile": data_content_plane.get("profile"),
            "projectionSha256": data_content_plane_sha,
            "roles": logical_roles,
        },
    }


def apply_public_projections(
    cfg: dict[str, Any], values: dict[str, str], base_domain: str
) -> None:
    active_subdomain_refs = {
        str(exposure.get("subdomainRef"))
        for component in cfg.get("spec", {}).get("components", [])
        if isinstance(component, dict)
        and isinstance((exposure := component.get("exposure")), dict)
        and exposure.get("subdomainRef")
    }
    for key, subdomain_ref in PUBLIC_URL_PROJECTIONS.items():
        if subdomain_ref not in active_subdomain_refs:
            continue
        subdomain = values.get(subdomain_ref, "").strip().strip(".")
        if not subdomain:
            raise ConfigError(f"canonical platform.env is missing {subdomain_ref}")
        suffix = "/" if key == "SEARXNG_BASE_URL" else ""
        values[key] = f"https://{subdomain}.{base_domain}{suffix}"
    if "MATHESAR_SUBDOMAIN" in active_subdomain_refs:
        hostname = values["MATHESAR_PUBLIC_URL"].removeprefix("https://")
        values["MATHESAR_DOMAIN_NAME"] = hostname
        values["MATHESAR_ALLOWED_HOSTS"] = hostname
    if "MEMOS_SUBDOMAIN" in active_subdomain_refs:
        values["MEMOS_MCP_URL"] = values["MEMOS_PUBLIC_URL"].rstrip("/") + "/mcp"


def apply_daytona_proxy_domain_projection(values: dict[str, str]) -> None:
    """Persist Paperclip's Daytona proxy endpoint from its canonical port ref."""
    proxy_internal_port = values.get("MTE_DAYTONA_PROXY_INTERNAL_PORT", "").strip()
    if not proxy_internal_port:
        raise ConfigError(
            "canonical platform.env is missing MTE_DAYTONA_PROXY_INTERNAL_PORT"
        )
    values["MTE_DAYTONA_PROXY_DOMAIN"] = f"mte-daytona-proxy:{proxy_internal_port}"


def apply_daytona_internal_projections(values: dict[str, str]) -> None:
    """Derive Daytona-only endpoints from canonical host and port refs."""
    required = {
        "MTE_DAYTONA_API_PORT",
        "MTE_DAYTONA_API_INTERNAL_PORT",
        "MTE_DAYTONA_DEX_PORT",
        "MTE_DAYTONA_DEX_INTERNAL_PORT",
        "MTE_DAYTONA_MINIO_INTERNAL_PORT",
        "MTE_DAYTONA_PROXY_PORT",
        "MTE_DAYTONA_PROXY_INTERNAL_PORT",
        "MTE_DAYTONA_REGISTRY_INTERNAL_PORT",
        "MTE_DAYTONA_RUNNER_INTERNAL_PORT",
        "MTE_DAYTONA_SSH_PORT",
    }
    missing = sorted(key for key in required if not values.get(key, "").strip())
    if missing:
        raise ConfigError(
            "canonical platform.env is missing Daytona endpoint refs: "
            + ", ".join(missing)
        )
    api_port = values["MTE_DAYTONA_API_PORT"]
    api_internal_port = values["MTE_DAYTONA_API_INTERNAL_PORT"]
    dex_port = values["MTE_DAYTONA_DEX_PORT"]
    dex_internal_port = values["MTE_DAYTONA_DEX_INTERNAL_PORT"]
    minio_port = values["MTE_DAYTONA_MINIO_INTERNAL_PORT"]
    proxy_port = values["MTE_DAYTONA_PROXY_PORT"]
    registry_port = values["MTE_DAYTONA_REGISTRY_INTERNAL_PORT"]
    runner_port = values["MTE_DAYTONA_RUNNER_INTERNAL_PORT"]
    ssh_port = values["MTE_DAYTONA_SSH_PORT"]
    values["MTE_DAYTONA_DASHBOARD_BASE_API_URL"] = f"http://127.0.0.1:{api_port}"
    values["MTE_DAYTONA_DASHBOARD_URL"] = f"http://127.0.0.1:{api_port}/dashboard"
    values["MTE_DAYTONA_DEFAULT_RUNNER_DOMAIN"] = f"runner:{runner_port}"
    values["MTE_DAYTONA_INTERNAL_API_URL"] = f"http://api:{api_internal_port}/api"
    values["MTE_DAYTONA_INTERNAL_OIDC_URL"] = f"http://dex:{dex_internal_port}/dex"
    values["MTE_DAYTONA_INTERNAL_REGISTRY_URL"] = f"http://registry:{registry_port}"
    values["MTE_DAYTONA_INTERNAL_RUNNER_URL"] = f"http://runner:{runner_port}"
    values["MTE_DAYTONA_MINIO_ENDPOINT_URL"] = f"http://minio:{minio_port}"
    values["MTE_DAYTONA_MINIO_STS_ENDPOINT_URL"] = (
        f"http://minio:{minio_port}/minio/v1/assume-role"
    )
    apply_daytona_proxy_domain_projection(values)
    values["MTE_DAYTONA_PROXY_TEMPLATE_URL"] = (
        f"http://{{{{PORT}}}}-{{{{sandboxId}}}}.proxy.localhost:{proxy_port}"
    )
    values["MTE_DAYTONA_PUBLIC_OIDC_URL"] = f"http://127.0.0.1:{dex_port}/dex"
    values["MTE_DAYTONA_SSH_GATEWAY_URL"] = f"127.0.0.1:{ssh_port}"


def apply_container_webhook_projection(values: dict[str, str]) -> None:
    """Keep the canonical operator URL while routing Alertmanager over Docker DNS."""

    key = "MATTERMOST_ALERT_WEBHOOK_URL"
    webhook = values.get(key, "").strip()
    if not webhook:
        return
    parsed = urlsplit(webhook)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/hooks/")
    ):
        raise ConfigError("canonical Mattermost alert webhook URL is invalid")
    values[key] = f"http://mattermost:8065{parsed.path}"


def resolved_projection_values(
    cfg: dict[str, Any], canonical_values: dict[str, str]
) -> dict[str, str]:
    """Resolve every generated value without mutating the canonical source."""

    values = dict(canonical_values)
    values.update(resource_preflight_values(values))
    base_domain = values.get("PLATFORM_BASE_DOMAIN", "").strip().strip(".")
    if not base_domain:
        raise ConfigError("canonical platform.env is missing PLATFORM_BASE_DOMAIN")
    apply_public_projections(cfg, values, base_domain)
    apply_daytona_internal_projections(values)
    if values.get("MEMOS_DB_PASSWORD"):
        values["MEMOS_DSN"] = (
            "postgresql://"
            + quote(values["MEMOS_DB_USER"], safe="")
            + ":"
            + quote(values["MEMOS_DB_PASSWORD"], safe="")
            + "@"
            + values["MEMOS_DB_HOST"]
            + ":"
            + values["MEMOS_DB_PORT"]
            + "/"
            + quote(values["MEMOS_DB_NAME"], safe="")
            + "?sslmode="
            + quote(values["MEMOS_DB_SSLMODE"], safe="")
        )
    if values.get("FIRECRAWL_REDIS_PASSWORD"):
        values["FIRECRAWL_REDIS_URL"] = (
            "redis://:"
            + quote(values["FIRECRAWL_REDIS_PASSWORD"], safe="")
            + "@redis:6379"
        )
    if values.get("SEARXNG_VALKEY_PASSWORD"):
        values["SEARXNG_VALKEY_URL"] = (
            "redis://:"
            + quote(values["SEARXNG_VALKEY_PASSWORD"], safe="")
            + "@valkey:6379/0"
        )
    return values


def render(*, lock_fd: int | None = None) -> dict[str, Any]:
    if lock_fd is None:
        with config_lock():
            return _render_locked()
    verify_canonical_lock_fd(lock_fd)
    return _render_locked()


def _render_locked() -> dict[str, Any]:
    _materialize_render_generated_secrets()
    canonical_values, source_sha = source_state()
    platform_lock = platform_lock_object()
    cfg = active_config_object(config_object(), canonical_values, platform_lock)
    values = resolved_projection_values(cfg, canonical_values)
    base_domain = values["PLATFORM_BASE_DOMAIN"].strip().strip(".")
    required, service_keys, _ = declared_keys(cfg, values)
    missing = missing_required(values, required)
    if missing:
        raise ConfigError(
            "canonical platform.env is missing required keys: " + ", ".join(missing)
        )

    projections: list[dict[str, str]] = []
    atomic_text(
        COMPOSE_ENV,
        aggregate_compose_projection_content(values, source_sha),
        0o600,
    )
    projections.append(projection_row(COMPOSE_ENV, source_sha))

    contract = data_content_contract()
    try:
        data_content_plane = contract.resolve_from_paths(
            cfg,
            platform_lock,
            values,
            config_path=CONFIG_SOURCE,
            lock_path=PLATFORM_LOCK_SOURCE,
            source_sha256=source_sha,
            generator_version=GENERATOR_VERSION,
        )
    except contract.DataContentError as exc:
        raise ConfigError(str(exc)) from exc
    atomic_text(
        DATA_CONTENT_PLANE,
        json.dumps(data_content_plane, indent=2, sort_keys=True) + "\n",
        0o600,
    )
    projections.append(projection_row(DATA_CONTENT_PLANE, source_sha))
    data_content_plane_sha = sha256_path(DATA_CONTENT_PLANE)

    cloudflare_apps = cloudflare_apps_projection(
        cfg,
        values,
        base_domain,
        source_sha,
        data_content_plane,
        data_content_plane_sha,
    )
    atomic_text(
        CLOUDFLARE_APPS,
        json.dumps(cloudflare_apps, indent=2, sort_keys=True) + "\n",
        0o600,
    )
    projections.append(projection_row(CLOUDFLARE_APPS, source_sha))

    api_token = values.get("CLOUDFLARE_API_TOKEN", "").strip()
    if not api_token:
        raise ConfigError("canonical platform.env is missing CLOUDFLARE_API_TOKEN")
    atomic_text(
        CLOUDFLARE_API_ENV,
        generated_header(source_sha) + f"CLOUDFLARE_API_TOKEN={api_token}\n",
        0o600,
    )
    projections.append(projection_row(CLOUDFLARE_API_ENV, source_sha))

    service_app_ids = sorted(
        app_id
        for app_id, row in cloudflare_apps["apps"].items()
        if row["accessClass"] == "service"
    )
    route_prefixes = {
        app_id: "CLOUDFLARE_ACCESS_ROUTE_" + app_id.upper().replace("-", "_")
        for app_id in service_app_ids
    }
    tunnel_token, access_payload = cloudflare_runtime_credential_projections(
        values, route_prefixes, source_sha
    )
    if tunnel_token is not None:
        atomic_text(
            CLOUDFLARE_TUNNEL_TOKEN,
            tunnel_token + "\n",
            0o600,
        )
        projections.append(projection_row(CLOUDFLARE_TUNNEL_TOKEN, source_sha))
    if access_payload is not None:
        atomic_text(
            CLOUDFLARE_ACCESS_TOKEN,
            json.dumps(access_payload, indent=2, sort_keys=True) + "\n",
            0o600,
        )
        projections.append(projection_row(CLOUDFLARE_ACCESS_TOKEN, source_sha))
    SERVICE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    for component_id, keys in sorted(service_keys.items()):
        path = SERVICE_ROOT / f"{component_id}.env"
        content = service_projection_content(component_id, keys, values, source_sha)
        atomic_text(path, content, 0o600)
        projections.append(projection_row(path, source_sha))

    for component_id, source_path in compose_paths(cfg):
        content, _ = compose_projection(component_id, source_path)
        runtime_path = runtime_compose_path(component_id)
        atomic_text(runtime_path, generated_header(source_sha) + content, 0o600)
        projections.append(projection_row(runtime_path, source_sha))

    if PROFILE_SOURCE.is_file():
        content, _ = profile_projection(PROFILE_SOURCE, values)
        profile_value = yaml.safe_load(content)
        if not isinstance(profile_value, dict):
            raise ConfigError("rendered profile catalog is not an object")
        profile_value["_generated"]["sourceSha256"] = source_sha
        atomic_text(
            PROFILE_RUNTIME,
            yaml.safe_dump(profile_value, sort_keys=False, default_flow_style=False),
            0o600,
        )
        projections.append(projection_row(PROFILE_RUNTIME, source_sha))

    active_component_ids = {
        str(component.get("id"))
        for component in cfg.get("spec", {}).get("components", [])
        if isinstance(component, dict) and component.get("id")
    }
    public_urls = {
        component: f"https://{values[subdomain_ref]}.{base_domain}"
        for component, subdomain_ref in PUBLIC_COMPONENT_SUBDOMAINS.items()
        if component in active_component_ids
    }
    public_payload = {
        "_generated": {
            "doNotEdit": True,
            "sourceSha256": source_sha,
            "generatorVersion": GENERATOR_VERSION,
        },
        "baseDomainRef": "PLATFORM_BASE_DOMAIN",
        "urls": public_urls,
        "dataContentRoles": {
            role_id: values[str(role["endpointRef"])]
            for role_id, role in data_content_plane["roles"].items()
        },
        "origins": {},
    }
    atomic_text(
        PUBLIC_URLS, json.dumps(public_payload, indent=2, sort_keys=True) + "\n", 0o600
    )
    projections.append(projection_row(PUBLIC_URLS, source_sha))

    def resolve_config(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: resolve_config(nested) for key, nested in value.items()}
        if isinstance(value, list):
            return [resolve_config(nested) for nested in value]
        if isinstance(value, str):
            match = ENV_PATTERN.fullmatch(value)
            if match:
                key = match.group(1)
                raw = values.get(key, value)
                if key.endswith(("_ENABLED", "_STRICT_MODE", "_LIFECYCLE")) or key in {
                    "E2E_REQUIRE_ARTIFACTS_ENDPOINT",
                    "E2E_REQUIRE_GITHUB_DRAFT_PR",
                    "E2E_REQUIRE_CHECKS",
                }:
                    if raw not in {"true", "false"}:
                        raise ConfigError(
                            f"canonical boolean {key} must be true or false"
                        )
                    return raw == "true"
                if key.endswith(("_GIB", "_TIMEOUT_MS")):
                    try:
                        return int(raw)
                    except ValueError as exc:
                        raise ConfigError(
                            f"canonical integer {key} is invalid"
                        ) from exc
                return raw
            return ENV_PATTERN.sub(
                lambda item: values.get(item.group(1), item.group(0)), value
            )
        return value

    cfg = resolve_config(cfg)
    spec = cfg.get("spec", {})
    host = spec.get("host", {}) if isinstance(spec, dict) else {}
    if isinstance(host, dict):
        for target_key, ref_key in (
            ("ssh", "sshRef"),
            ("root", "rootRef"),
            ("secretsRoot", "secretsRootRef"),
        ):
            ref = str(host.get(ref_key, ""))
            if ref:
                host[target_key] = values[ref]
        excluded_refs = host.get("excludedRefs", [])
        if isinstance(excluded_refs, list):
            host["excluded"] = [values[str(ref)] for ref in excluded_refs]
    if isinstance(spec, dict):
        spec["domain"] = base_domain
        spec["resolvedDomain"] = base_domain
    for component in cfg.get("spec", {}).get("components", []):
        compose = component.get("compose") if isinstance(component, dict) else None
        if compose:
            component["compose"] = "runtime/deploy/" + compose_projection_name(compose)
    cfg["_generated"] = {
        "doNotEdit": True,
        "sourceSha256": source_sha,
        "generatorVersion": GENERATOR_VERSION,
    }
    atomic_text(CONFIG, json.dumps(cfg, indent=2, sort_keys=True) + "\n", 0o600)
    projections.append(projection_row(CONFIG, source_sha))

    manifest = {
        "sourceSha256": source_sha,
        "generatorVersion": GENERATOR_VERSION,
        "projections": sorted(projections, key=lambda row: row["path"]),
    }
    removed_legacy_projections = remove_unregistered_legacy_secret_projections(manifest)
    atomic_text(MANIFEST, json.dumps(manifest, indent=2, sort_keys=True) + "\n", 0o600)
    harden_secret_projections(manifest)
    return {
        "rendered": True,
        "sourceSha256": source_sha,
        "generatorVersion": GENERATOR_VERSION,
        "projectionCount": len(projections),
        "removedLegacyProjectionCount": len(removed_legacy_projections),
        "removedLegacyProjections": [
            str(path.relative_to(SECRET_ROOT)) for path in removed_legacy_projections
        ],
        "manifest": str(MANIFEST),
    }


def drift() -> list[dict[str, str]]:
    values, source_sha = source_state()
    if not MANIFEST.is_file():
        return [{"path": str(MANIFEST), "reason": "manifest_missing"}]
    manifest_stat = MANIFEST.stat()
    if manifest_stat.st_uid != 0 or manifest_stat.st_mode & 0o777 != 0o600:
        return [{"path": str(MANIFEST), "reason": "manifest_permissions"}]
    try:
        manifest = json.loads(MANIFEST.read_text())
    except json.JSONDecodeError:
        return [{"path": str(MANIFEST), "reason": "manifest_invalid"}]
    findings = []
    if manifest.get("sourceSha256") != source_sha:
        findings.append({"path": str(MANIFEST), "reason": "source_hash_drift"})
    if manifest.get("generatorVersion") != GENERATOR_VERSION:
        findings.append({"path": str(MANIFEST), "reason": "generator_version_drift"})
    rows = manifest.get("projections", [])
    if not isinstance(rows, list):
        return [{"path": str(MANIFEST), "reason": "projection_rows_invalid"}]
    plane_rows = [
        row
        for row in rows
        if isinstance(row, dict) and row.get("path") == str(DATA_CONTENT_PLANE)
    ]
    if len(plane_rows) != 1 or set(plane_rows[0]) != {
        "path",
        "contentSha256",
        "sourceSha256",
        "generatorVersion",
    }:
        findings.append(
            {
                "path": str(DATA_CONTENT_PLANE),
                "reason": "projection_manifest_binding_invalid",
            }
        )
    compose_env_rows = [
        row
        for row in rows
        if isinstance(row, dict) and row.get("path") == str(COMPOSE_ENV)
    ]
    if len(compose_env_rows) != 1 or set(compose_env_rows[0]) != {
        "path",
        "contentSha256",
        "sourceSha256",
        "generatorVersion",
    }:
        findings.append(
            {
                "path": str(COMPOSE_ENV),
                "reason": "projection_manifest_binding_invalid",
            }
        )
    for row in rows:
        if not isinstance(row, dict):
            findings.append({"path": str(MANIFEST), "reason": "projection_row_invalid"})
            continue
        path = Path(str(row.get("path", "")))
        if not path.is_file():
            findings.append({"path": str(path), "reason": "projection_missing"})
            continue
        stat = path.stat()
        if stat.st_uid != 0 or stat.st_mode & 0o777 != 0o600:
            findings.append({"path": str(path), "reason": "projection_permissions"})
        if row.get("sourceSha256") != source_sha:
            findings.append(
                {"path": str(path), "reason": "projection_source_hash_drift"}
            )
        if row.get("generatorVersion") != GENERATOR_VERSION:
            findings.append({"path": str(path), "reason": "projection_generator_drift"})
        if row.get("contentSha256") != sha256_path(path):
            findings.append({"path": str(path), "reason": "projection_content_drift"})
    if COMPOSE_ENV.is_file():
        try:
            expected_cfg = active_config_object(
                config_object(), values, platform_lock_object()
            )
            expected_values = resolved_projection_values(expected_cfg, values)
            expected_content = aggregate_compose_projection_content(
                expected_values, source_sha
            )
            if COMPOSE_ENV.read_text() != expected_content:
                findings.append(
                    {
                        "path": str(COMPOSE_ENV),
                        "reason": "projection_resolved_content_drift",
                    }
                )
        except (OSError, ConfigError) as exc:
            findings.append(
                {
                    "path": str(COMPOSE_ENV),
                    "reason": "projection_resolved_content_invalid",
                    "error": type(exc).__name__,
                }
            )
    if DATA_CONTENT_PLANE.is_file():
        try:
            observed = json.loads(DATA_CONTENT_PLANE.read_text())
            resolved_values = dict(values)
            base_domain = (
                resolved_values.get("PLATFORM_BASE_DOMAIN", "").strip().strip(".")
            )
            drift_cfg = active_config_object(
                config_object(), resolved_values, platform_lock_object()
            )
            if base_domain:
                apply_public_projections(drift_cfg, resolved_values, base_domain)
            contract = data_content_contract()
            expected = contract.resolve_from_paths(
                config_object(),
                platform_lock_object(),
                resolved_values,
                config_path=CONFIG_SOURCE,
                lock_path=PLATFORM_LOCK_SOURCE,
                source_sha256=source_sha,
                generator_version=GENERATOR_VERSION,
            )
            if observed != expected:
                findings.append(
                    {
                        "path": str(DATA_CONTENT_PLANE),
                        "reason": "provider_binding_drift",
                    }
                )
        except (OSError, json.JSONDecodeError, ConfigError) as exc:
            findings.append(
                {
                    "path": str(DATA_CONTENT_PLANE),
                    "reason": "provider_binding_invalid",
                    "error": type(exc).__name__,
                }
            )
        except Exception as exc:
            if type(exc).__module__ == "mte_data_content_plane":
                findings.append(
                    {
                        "path": str(DATA_CONTENT_PLANE),
                        "reason": "provider_binding_invalid",
                        "error": type(exc).__name__,
                    }
                )
            else:
                raise
    return findings


def audit() -> dict[str, Any]:
    values, source_sha = source_state()
    resource_preflight_values(values)
    cfg = active_config_object(config_object(), values, platform_lock_object())
    required, _, _ = declared_keys(cfg, values)
    if E2E_GITHUB_TARGET_KEYS & required:
        validate_e2e_github_target(values)
    missing = missing_required(values, required)
    findings = drift()
    if missing:
        findings.append({"path": str(SOURCE), "reason": "missing_required_keys"})
    result = {
        "ok": not findings,
        "source": str(SOURCE),
        "sourceSha256": source_sha,
        "generatorVersion": GENERATOR_VERSION,
        "missingKeys": missing,
        "findings": findings,
    }
    if findings:
        raise ConfigError(json.dumps(result, sort_keys=True))
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=(
            "init",
            "merge-notion-provision",
            "render",
            "audit",
            "diff",
        ),
    )
    parser.add_argument("--expect-idempotent", action="store_true")
    args = parser.parse_args()
    try:
        with config_lock() as lock_fd:
            if args.action == "init":
                if args.expect_idempotent:
                    raise ConfigError(
                        "--expect-idempotent requires merge-notion-provision"
                    )
                raw = sys.stdin.read().strip()
                imported = json.loads(raw) if raw else {}
                if not isinstance(imported, dict):
                    raise ConfigError("init input must be a JSON object")
                result = init_source(
                    {str(key): str(value) for key, value in imported.items()}
                )
            elif args.action == "merge-notion-provision":
                raw = sys.stdin.read().strip()
                payload = json.loads(raw) if raw else {}
                if not isinstance(payload, dict):
                    raise ConfigError("notion provision input must be a JSON object")
                result = merge_notion_provision(
                    payload, expect_idempotent=args.expect_idempotent
                )
            elif args.action == "render":
                if args.expect_idempotent:
                    raise ConfigError(
                        "--expect-idempotent requires merge-notion-provision"
                    )
                result = render(lock_fd=lock_fd)
            elif args.action == "audit":
                if args.expect_idempotent:
                    raise ConfigError(
                        "--expect-idempotent requires merge-notion-provision"
                    )
                result = audit()
            else:
                if args.expect_idempotent:
                    raise ConfigError(
                        "--expect-idempotent requires merge-notion-provision"
                    )
                findings = drift()
                result = {"clean": not findings, "findings": findings}
                if findings:
                    print(json.dumps(result, indent=2, sort_keys=True))
                    raise SystemExit(1)
    except ConfigError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True))
        raise SystemExit(1) from exc
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

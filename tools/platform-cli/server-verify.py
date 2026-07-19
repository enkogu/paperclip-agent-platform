#!/usr/bin/env python3
"""Fail-closed live server checks with machine-readable evidence.

An unavailable, unknown, malformed, or not-yet-implemented required check is a
failure. This verifier must never turn missing coverage into a green result.
"""

from __future__ import annotations

import ast
import datetime
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml


_HARNESS_VERSION_PATTERNS = {
    "codex": re.compile(r"(?:codex(?:-cli)?\s+)?v?([0-9]+\.[0-9]+\.[0-9]+)"),
    "claude": re.compile(
        r"(?:claude\s+)?v?([0-9]+\.[0-9]+\.[0-9]+)(?: \(Claude Code\))?"
    ),
    "pi": re.compile(r"(?:pi\s+)?v?([0-9]+\.[0-9]+\.[0-9]+)"),
}


def normalized_harness_version(name: str, output: object) -> str | None:
    """Return the sole exact CLI semantic version, or fail closed."""
    pattern = _HARNESS_VERSION_PATTERNS.get(name)
    match = pattern.fullmatch(str(output or "").strip()) if pattern else None
    return match.group(1) if match else None

ROOT = Path(os.environ.get("MTE_PLATFORM_ROOT", "/opt/mte-platform"))
SECRET_ROOT = Path(os.environ.get("MTE_SECRET_ROOT", "/root/.config/mte-secrets"))
CONFIG = ROOT / "config/platform.json"
ACCEPTANCE_REQUIREMENTS = ROOT / "config/acceptance-requirements.yaml"
EVIDENCE = ROOT / "evidence"
CANONICAL_ENV = SECRET_ROOT / "platform.env"
PROJECTION_MANIFEST = SECRET_ROOT / "projections-manifest.json"
DATA_CONTENT_PLANE = ROOT / "config/data-content-plane.json"
SERVICE_ROOT = SECRET_ROOT / "services"

# Every declared check is owned by one strict connection-evidence validator
# below.  Keeping this table explicit prevents a newly declared registry row
# from becoming green merely because it shares a component health endpoint.
# A validator may return RED when its producer evidence is absent; that is an
# implemented fail-closed check, not a reason to substitute shallow health.
CONNECTION_CHECK_COMPONENTS = {
    "paperclip-task-canary": "connection-C001",
    "runner-claim": "connection-C002",
    "paperclip-heartbeats-result": "connection-C003",
    "cloudflare-paperclip": "connection-C004",
    "cloudflare-kestra": "connection-C005",
    "hermes-native-api": "connection-C006",
    "hermes-native-turn": "connection-C007",
    "runner-llm-completion": "connection-C008",
    "hermes-llm-completion": "connection-C009",
    "toolhive-mcp-initialize": "connection-C010",
    "hermes-native-terminal": "connection-C011",
    "toolhive-workload-canary": "connection-C012",
    "provision-paperclip": "connection-C014",
    "provision-9router": "connection-C015",
    "provision-toolhive": "connection-C016",
    "profile-llm-completion": "connection-C017",
    "harness-scoped-router-auth": "connection-C018",
    "profile-reconcile": "connection-C019",
    "firecrawl-scrape": "connection-C023",
    "searxng-json-search": "connection-C024",
    "cloudflare-searxng": "connection-C025",
    "cloudflare-firecrawl": "connection-C026",
    "paperclip-tables-api-scoped-token": "connection-C027",
    "data-content-persistence": "connection-C029",
    "mattermost-notification": "connection-C030",
    "hermes-mattermost-auth": "connection-C031",
    "cloudflare-mattermost": "connection-C032",
    "hermes-telegram-auth": "connection-C033",
    "hermes-platform-status": "connection-C034",
    "hermes-host-operator-policy": "connection-C035",
    "provision-data-content": "connection-C036",
    "provision-mattermost": "connection-C037",
    "provision-kestra": "connection-C039",
    "telemetry-canary": "connection-C040",
    "host-container-metrics": "connection-C041",
    "victoria-metrics-canary": "connection-C042",
    "victoria-logs-canary": "connection-C043",
    "victoria-traces-canary": "connection-C044",
    "grafana-datasources": "connection-C045",
    "cloudflare-grafana": "connection-C046",
    "alertmanager-canary": "connection-C047",
    "alertmanager-mattermost": "connection-C048",
    "blackbox-probes": "connection-C049",
    "provision-grafana": "connection-C050",
    "host-preflight": "connection-C060",
    "postgres-ready-query": "connection-C063",
    "redis-auth-ping": "connection-C064",
    "tunnel-health": "connection-C065",
    "tunnel-routes": "connection-C066",
    "cloudflare-empty-plan": "connection-C067",
    "restore-canary": "connection-C068",
    "deploy-idempotency": "connection-C069",
    "secret-permissions-audit": "connection-C070",
    "canonical-projections-audit": "connection-C071",
    "paperclip-daytona-provider": "connection-C072",
    "paperclip-workspace-canary": "connection-C073",
    "daytona-sandbox-runtime": "connection-C074",
    "paperclip-harness-env": "connection-C075",
    "kestra-e2e-flow": "connection-C076",
    "harness-minimax-completion": "connection-C077",
    "harness-github-pr": "connection-C078",
    "github-checks-kestra-terminal": "connection-C079",
    "e2e-cleanup-state": "connection-C080",
}

# Security-sensitive registry rows are part of the verifier contract, not free
# form documentation.  In particular, native harnesses must never drift back
# to copied Codex/Claude/Pi subscription homes: they use only their dedicated
# 9Router runtime key.  A semantic producer may be mapped above only after it
# proves the complete contract.
CONNECTION_CONTRACT_EXPECTATIONS = {
    "C006": {
        "from": "operator",
        "to": "hermes-native-api",
        "required": True,
        "auth": "loopback-bearer",
        "exposure": "loopback",
        "check": "hermes-native-api",
    },
    "C007": {
        "from": "hermes-native-api",
        "to": "hermes-llm-loop",
        "required": True,
        "auth": "native-session",
        "exposure": "none",
        "check": "hermes-native-turn",
    },
    "C009": {
        "from": "hermes",
        "to": "9router",
        "required": True,
        "auth": "hermes-client-key",
        "exposure": "internal",
        "check": "hermes-llm-completion",
    },
    "C011": {
        "from": "hermes-llm-loop",
        "to": "hermes-native-terminal",
        "required": True,
        "auth": "native-approval",
        "exposure": "none",
        "check": "hermes-native-terminal",
    },
    "C018": {
        "from": "native-harness",
        "to": "9router-profile-route",
        "required": True,
        "auth": "profile-scoped-runtime-key",
        "exposure": "internal",
        "check": "harness-scoped-router-auth",
    },
    "C033": {
        "from": "telegram",
        "to": "hermes",
        "required": True,
        "condition": "telegram-configured",
        "auth": "bot-token+allowed-user",
        "exposure": "egress",
        "check": "hermes-telegram-auth",
    },
    "C031": {
        "from": "mattermost",
        "to": "hermes",
        "required": True,
        "auth": "bot-token+allowed-user",
        "exposure": "internal",
        "check": "hermes-mattermost-auth",
    },
    "C034": {
        "from": "hermes-native-terminal",
        "to": "platform-cli",
        "required": True,
        "auth": "native-approval",
        "exposure": "none",
        "check": "hermes-platform-status",
    },
    "C035": {
        "from": "hermes",
        "to": "platform-host",
        "required": True,
        "auth": "declared-operator-mode",
        "exposure": "none",
        "check": "hermes-host-operator-policy",
    },
    "C069": {
        "from": "indexed-deploy",
        "to": "provisioning-methods",
        "required": True,
        "auth": "secret-refs",
        "exposure": "none",
        "check": "deploy-idempotency",
    },
    "C070": {
        "from": "verifier",
        "to": "integrations-secret-store",
        "required": True,
        "auth": "root-files",
        "exposure": "none",
        "check": "secret-permissions-audit",
    },
    "C071": {
        "from": "canonical-platform-env",
        "to": "runtime-projections",
        "required": True,
        "auth": "root-source-hash",
        "exposure": "none",
        "check": "canonical-projections-audit",
    },
    "C072": {
        "from": "paperclip",
        "to": "daytona-provider",
        "required": True,
        "auth": "plugin-secret-ref",
        "exposure": "egress",
        "check": "paperclip-daytona-provider",
    },
    "C073": {
        "from": "paperclip",
        "to": "execution-workspace",
        "required": True,
        "auth": "runtime-identity",
        "exposure": "none",
        "check": "paperclip-workspace-canary",
    },
    "C074": {
        "from": "daytona",
        "to": "sandbox-image-runtime",
        "required": True,
        "auth": "provider-credential",
        "exposure": "egress",
        "check": "daytona-sandbox-runtime",
    },
    "C075": {
        "from": "paperclip-secrets",
        "to": "harness-env",
        "required": True,
        "auth": "secret-refs",
        "exposure": "none",
        "check": "paperclip-harness-env",
    },
    "C076": {
        "from": "kestra",
        "to": "e2e-flow",
        "required": True,
        "auth": "service",
        "exposure": "internal",
        "check": "kestra-e2e-flow",
    },
    "C077": {
        "from": "harness",
        "to": "9router-minimax",
        "required": True,
        "auth": "profile-client-key",
        "exposure": "internal",
        "check": "harness-minimax-completion",
    },
    "C078": {
        "from": "harness",
        "to": "github-branch-pr",
        "required": True,
        "auth": "scoped-github-token",
        "exposure": "egress",
        "check": "harness-github-pr",
    },
    "C079": {
        "from": "github-checks",
        "to": "kestra-terminal-status",
        "required": True,
        "auth": "public-observation+service",
        "exposure": "egress",
        "check": "github-checks-kestra-terminal",
    },
    "C080": {
        "from": "e2e-cleanup",
        "to": "sandbox-workspace-state",
        "required": True,
        "auth": "provider+runtime-identity",
        "exposure": "none",
        "check": "e2e-cleanup-state",
    },
}

NATIVE_HARNESS_PROFILES = (
    "coding-daytona-codex",
    "coding-daytona-claude",
    "coding-daytona-pi",
)
# R1 treats the three installed native clients as independent paths: the
# routing protocol differs for Codex, Claude Code, and Pi even though every
# profile terminates at the same MiniMax provider through 9router.
R1_E2E_HARNESS_PROFILES = NATIVE_HARNESS_PROFILES
ACCOUNT_PROFILE_ENV_KEYS = {
    "coding-daytona-codex": frozenset(
        {
            "GITHUB_TOKEN",
            "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
            "MTE_TOOLHIVE_BEARER_TOKEN",
            "MTE_TOOLHIVE_BUNDLE_ID",
            "MTE_TOOLHIVE_CANARY_TOOL",
            "MTE_TOOLHIVE_BINDING_REF",
            "MTE_TOOLHIVE_ENDPOINT_REF",
            "MTE_TOOLHIVE_WORKLOAD_ID",
            "MTE_TOOLHIVE_WRONG_PROFILE_MCP_URL",
            "OPENAI_API_KEY",
            "OPENAI_BASE_URL",
            "PAPERCLIP_CODEX_PROVIDERS",
        }
    ),
    "coding-daytona-claude": frozenset(
        {
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_BASE_URL",
            "GITHUB_TOKEN",
            "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_URL",
            "MTE_TOOLHIVE_BEARER_TOKEN",
            "MTE_TOOLHIVE_BUNDLE_ID",
            "MTE_TOOLHIVE_CANARY_TOOL",
            "MTE_TOOLHIVE_BINDING_REF",
            "MTE_TOOLHIVE_ENDPOINT_REF",
            "MTE_TOOLHIVE_WORKLOAD_ID",
            "MTE_TOOLHIVE_WRONG_PROFILE_MCP_URL",
        }
    ),
    "coding-daytona-pi": frozenset(
        {
            "GITHUB_TOKEN",
            "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL",
            "MTE_TOOLHIVE_BEARER_TOKEN",
            "MTE_TOOLHIVE_BUNDLE_ID",
            "MTE_TOOLHIVE_CANARY_TOOL",
            "MTE_TOOLHIVE_BINDING_REF",
            "MTE_TOOLHIVE_ENDPOINT_REF",
            "MTE_TOOLHIVE_WORKLOAD_ID",
            "MTE_TOOLHIVE_WRONG_PROFILE_MCP_URL",
            "OPENAI_API_KEY",
            "OPENAI_BASE_URL",
            "PAPERCLIP_PI_PROVIDERS",
            "PI_CODING_AGENT_DIR",
        }
    ),
}
E2E_EVIDENCE = ROOT / "evidence/kestra-paperclip-github-e2e.json"
E2E_VERIFY_EVIDENCE = ROOT / "evidence/kestra-paperclip-github-e2e-verify.json"
E2E_PORTABLE_BUNDLE = ROOT / "evidence/kestra-paperclip-github-e2e-bundle.json"
INTEGRATION_EVIDENCE = ROOT / "evidence/integration-canaries.json"
C029_INTEGRATION_EVIDENCE = ROOT / "evidence/integration-canary-C029.json"
HERMES_EVIDENCE = ROOT / "evidence/hermes-live.json"
HERMES_ACCEPTANCE_SOURCE = ROOT / "manifests/hermes/acceptance-canary.py"
HERMES_ACCEPTANCE_RUNTIME = Path("/opt/mte-hermes/bin/acceptance-canary")
HERMES_CLI_RUNTIME = Path("/opt/mte-hermes/current/venv/bin/hermes")
HERMES_UNIT_RUNTIME = Path("/etc/systemd/system/mte-hermes.service")
HERMES_SUDOERS_RUNTIME = Path("/etc/sudoers.d/mte-hermes-platform-admin")
OBSERVABILITY_EVIDENCE = ROOT / "evidence/observability-data-canary.json"
INDEXED_IDEMPOTENCY_EVIDENCE = ROOT / "evidence/indexed-reconcile-idempotency.json"
INDEXED_PASS_EVIDENCE = {
    1: ROOT / "evidence/indexed-reconcile-pass-1.json",
    2: ROOT / "evidence/indexed-reconcile-pass-2.json",
}
CLOUDFLARE_EVIDENCE = ROOT / "evidence/cloudflare-deployment-live.json"
CLOUDFLARE_ACCEPTANCE_EVIDENCE = ROOT / "evidence/cloudflare-acceptance.json"
CLOUDFLARE_SEMANTIC_EVIDENCE = ROOT / "evidence/cloudflare-app-semantics.json"
CLOUDFLARE_SPLIT_CONNECTION_IDS = (
    "C004",
    "C005",
    "C025",
    "C026",
    "C032",
)
CLOUDFLARE_CONNECTION_EVIDENCE = {
    connection_id: ROOT / f"evidence/cloudflare-connection-{connection_id}.json"
    for connection_id in CLOUDFLARE_SPLIT_CONNECTION_IDS
}
POSTGREST_VERIFY_EVIDENCE = ROOT / "evidence/postgrest-verify.json"
NOTION_VERIFY_EVIDENCE = ROOT / "evidence/notion-connector-verify.json"
SERVER_NOTION_SOURCE = ROOT / "bin/server-notion.py"
NOTION_PROJECTION_VERIFY_EVIDENCE = (
    ROOT / "evidence/notion-projection-consumer-verify.json"
)
NOTION_PROJECTION_CANARY_EVIDENCE = ROOT / "evidence/notion-projection-live-canary.json"
SERVER_NOTION_PROJECTION_SOURCE = ROOT / "bin/server-notion-sync.py"
SERVER_CLOUDFLARE_ACCEPTANCE_SOURCE = ROOT / "bin/server-cloudflare-acceptance.py"
PAPERCLIP_DAYTONA_CONTROL_PLANE_EVIDENCE = (
    ROOT / "evidence/paperclip-daytona-control-plane.json"
)
PAPERCLIP_DAYTONA_VERIFY_EVIDENCE = ROOT / "evidence/paperclip-daytona-verify.json"
DAYTONA_IMAGES_EVIDENCE = ROOT / "evidence/daytona-images.json"
DAYTONA_LIFECYCLE_EVIDENCE = ROOT / "evidence/daytona-lifecycle.json"
PROFILE_RECONCILE_EVIDENCE = ROOT / "evidence/profile-reconcile.json"
PROFILE_ACCESS_EVIDENCE = ROOT / "evidence/profile-access.json"
SERVER_PROFILE_RECONCILE_SOURCE = ROOT / "bin/server-profile-reconcile.py"
KESTRA_RECONCILE_VERIFY_EVIDENCE = ROOT / "evidence/kestra-reconcile-verify.json"
SERVER_KESTRA_RECONCILE_SOURCE = ROOT / "bin/server-kestra-reconcile.py"
ACCOUNT_PROVISION_VERIFY_EVIDENCE = ROOT / "evidence/account-provisioning-verify.json"
SERVER_CONFIG_SOURCE = ROOT / "bin/server-config.py"
SERVER_PROVISION_SOURCE = ROOT / "bin/server-provision.py"
SERVER_TOOLHIVE_SOURCE = ROOT / "bin/server-toolhive.py"
SERVER_OBSERVABILITY_SOURCE = ROOT / "bin/server-observability-canary.py"
SERVER_INTEGRATION_SOURCE = ROOT / "bin/server-integration-canaries.py"
SERVER_E2E_SOURCE = ROOT / "bin/server-e2e-canary.py"
SERVER_AGENT_GATEWAY_SOURCE = ROOT / "bin/agent-plane-gateway.py"
SERVER_PAPERCLIP_EXPERIMENTAL_SOURCE = ROOT / "bin/server-paperclip-experimental.py"
PAPERCLIP_DAYTONA_STEP_SOURCE = ROOT / "steps/daytona.sh"
CONNECTION_EVIDENCE_MAX_AGE_SECONDS = 600
E2E_PROFILE_SOURCE = ROOT / "templates/profiles/profiles.yaml"
E2E_PROFILES = ROOT / "runtime/profiles/profiles.yaml"
E2E_SOURCE_PATHS = {
    "canonicalSourceSha256": CANONICAL_ENV,
    "configSha256": CONFIG,
    "flowSha256": ROOT / "manifests/kestra/flows/paperclip-github-e2e.yaml",
    "profileSourceSha256": E2E_PROFILE_SOURCE,
    "profilesSha256": E2E_PROFILES,
    "paperclipRuntimeSha256": ROOT / "steps/paperclip.sh",
    "daytonaEvidenceSha256": PAPERCLIP_DAYTONA_CONTROL_PLANE_EVIDENCE,
    "runnerSha256": SERVER_E2E_SOURCE,
}

ENV_REF_PATTERN = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?::[-?][^}]*)?\}")
ENV_DEFAULT_PATTERN = re.compile(r"\$\{([A-Z][A-Z0-9_]*):-([^}]+)\}")
MUTABLE_KEY_PATTERN = re.compile(
    r"(?:PORT|URL|URI|HOST|DOMAIN|ENDPOINT|IMAGE|VERSION|CPU|MEMORY|LIMIT|"
    r"CONCURRENCY|WORKERS|POOL|ENABLED|MODE)$",
    re.IGNORECASE,
)
CONFIG_KEY_PATTERN = re.compile(
    r"(?:PORT|URL|URI|HOST|DOMAIN|ENDPOINT|IMAGE|VERSION|CPU|MEMORY|LIMIT|"
    r"CONCURRENCY|WORKERS|POOL|ENABLED|MODE|PASSWORD|PASSWD|SECRET|TOKEN|"
    r"API_KEY|PRIVATE_KEY|ENCRYPT|JWT|SALT|COOKIE|CREDENTIAL|AUTH|WEBHOOK|"
    r"CONNECTION_STRING|EMAIL|USERNAME|USER|DATABASE|DB|NAME)$",
    re.IGNORECASE,
)
STRUCTURAL_ENV_DEFAULT_KEYS = {
    "MTE_PLATFORM_ROOT",
    "MTE_SECRET_ROOT",
    "MTE_ROOT",
    "MTE_PLATFORM_ENV",
    "MTE_PAPERCLIP_CONTAINER",
}
DOMAIN_ALIAS_KEYS = {"PLATFORM_DOMAIN", "CLOUDFLARE_BASE_DOMAIN", "MTE_DOMAIN"}
DOMAIN_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
LOCK_TOP_LEVEL_KEYS = {"apiVersion", "kind", "metadata", "spec"}
LOCK_SPEC_VERSION_KEYS = {
    "paperclip",
    "kestra",
    "9router",
    "hermesAgent",
    "toolHive",
    "openTofu",
}
LOCK_HARNESS_KEYS = {"pi", "codex", "claudeCode"}
LOCK_IMAGE_KEYS = {
    "nodeHarness",
    "openTofu",
    "cloudflared",
    "mcpEverything",
    "postgres",
    "postgrest",
    "searxng",
}
BOOTSTRAP_LITERAL_ASSIGNMENTS = {
    "BOOTSTRAP_ONLY_DEFAULTS",
    "PROFILE_BOOTSTRAP_DEFAULTS",
    "ONE_TIME_MIGRATION_SEEDS",
}
STRUCTURAL_LITERAL_ASSIGNMENTS = {
    "HERMES_NATIVE_ENV_NAMES",
    "PUBLIC_URL_PROJECTIONS",
    "PUBLIC_COMPONENT_SUBDOMAINS",
}
# This reviewed table is compatibility metadata used only to recognize the
# former nested-default Compose projection during its one-way migration. It is
# deliberately separate from bootstrap and structural defaults: no runtime
# setting may use this exemption.
COMPATIBILITY_MIGRATION_METADATA_ASSIGNMENTS = {
    "REVIEWED_LEGACY_COMPOSE_VALUE_MIGRATIONS",
}
TEST_FIXTURE_LITERAL_ASSIGNMENTS = {
    "FRESH_INSTALL_EXTERNAL_FIXTURES",
    "FRESH_INSTALL_EXTERNAL_SECRET_FIXTURES",
    "FRESH_INSTALL_OPERATOR_CONFIG_FIXTURES",
    "FRESH_INSTALL_PATH_REPLACEMENTS",
}
IMMUTABLE_STRUCTURAL_ENV_DEFAULT_KEYS = {
    # These are values reported by /etc/os-release. They select the supported
    # Ubuntu bootstrap branch and are not platform runtime configuration.
    "deployment/steps/host.sh": {"ID", "UBUNTU_CODENAME"},
    # The release gate's private scratch directory is an execution location,
    # not an operator-controlled platform setting.
    "tools/platform-cli/release-check.sh": {"TMPDIR"},
}
IMMUTABLE_GLOBAL_CONSTANTS = {
    "deployment/steps/origin-firewall.sh": {"POLICY_VERSION"},
    "tools/platform-cli/server-config.py": {"GENERATOR_VERSION"},
    "tools/platform-cli/server-hermes.py": {
        "CONTEXT7_MCP_PROTOCOL_VERSION",
        "CONTEXT7_MCP_URL",
    },
    "tools/platform-cli/server-kestra-reconcile.py": {"API_VERSION"},
    "tools/platform-cli/server-observability-canary.py": {
        "GENERATOR_VERSION",
        "OBSERVABILITY_EVIDENCE_SCHEMA_VERSION",
    },
    "tools/platform-cli/server-paperclip-experimental.py": {"API_VERSION"},
    "tools/platform-cli/server-notion.py": {
        "OFFICIAL_NOTION_BASE_URL",
        "NOTION_API_VERSION",
    },
    "tools/platform-cli/server-profile-reconcile.py": {
        "NOTION_REPOSITORY_URL",
        "NOTION_API_VERSION",
        "TOOLHIVE_RUNTIME_HOST",
    },
    "tools/platform-cli/server-toolhive.py": {
        "TCP_PING_URL",
        "UNIX_DOCKER_HOST",
    },
}
LEGACY_PROJECTION_REGISTRY_OWNERS = {
    "activepieces-admin.env": "activepieces",
    "claude.env": "coding-daytona-claude",
    "orloj.env": "orloj",
}
INACTIVE_PROFILE_KEY_PREFIXES = {
    "postgres-notion": (),
}
LEGACY_ALIAS_MAPPING = {
    "MTE_DOMAIN": "PLATFORM_BASE_DOMAIN",
    "PLATFORM_DOMAIN": "PLATFORM_BASE_DOMAIN",
    "CLOUDFLARE_BASE_DOMAIN": "PLATFORM_BASE_DOMAIN",
    "GH_TOKEN": "GITHUB_TOKEN",
    "MINIMAX_OPENAI_ENDPOINT": "MINIMAX_BASE_URL",
    "PRIN7R_NOTION_TOKEN": "NOTION_TOKEN",
    "PRIN7R_NOTION_API_KEY": "NOTION_TOKEN",
}
COMPOSE_DERIVED_KEYS = {
    # These values are generated into canonical platform.env from host/port
    # sources. Keeping them out of the bootstrap seed catalog preserves one
    # source of truth for URLs while allowing Compose to consume them.
    "NINEROUTER_HEALTH_URL",
    "KESTRA_HEALTH_URL",
    "PAPERCLIP_HEALTH_URL",
    "TOOLHIVE_HEALTH_URL",
    "MATTERMOST_HEALTH_URL",
    "SEARXNG_HEALTH_URL",
    "FIRECRAWL_HEALTH_URL",
    "OBSERVABILITY_HEALTH_URL",
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
    "MATTERMOST_SITE_URL",
    "SEARXNG_BASE_URL",
    "FIRECRAWL_REDIS_URL",
    "SEARXNG_VALKEY_URL",
}
OPTIONAL_CANONICAL_COMPOSE_DEFAULTS = {"MATTERMOST_ALERT_WEBHOOK_URL"}
SENSITIVE_SEED_KEY_PATTERN = re.compile(
    r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ENCRYPT|JWT|SALT|"
    r"COOKIE|CREDENTIAL|AUTH|WEBHOOK|CONNECTION_STRING)",
    re.IGNORECASE,
)


def data_content_contract(root: Path = ROOT):
    candidates = (
        root / "tools/platform-cli/data_content_plane.py",
        root / "bin/data_content_plane.py",
        Path(__file__).with_name("data_content_plane.py"),
    )
    path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if path is None:
        raise RuntimeError("reviewed data/content contract module is missing")
    spec = importlib.util.spec_from_file_location("mte_data_content_plane", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load reviewed data/content contract module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def reviewed_platform_source(root: Path) -> Path:
    """Return the reviewed source path for a checkout or projected release."""
    source = root / "config/platform.yaml"
    projected = root / "templates/platform.json"
    return source if source.is_file() else projected


def reviewed_platform_lock(root: Path) -> Path:
    """Return the reviewed lock path for a checkout or projected release."""
    source = root / "config/platform.lock.yaml"
    projected = root / "templates/platform.lock.yaml"
    return source if source.is_file() else projected


def reviewed_compose_seed_catalog(root: Path) -> Path:
    """Return the curated seed catalog for a checkout or projected release."""
    source = root / "config/compose-seeds.lock.json"
    projected = root / "templates/compose-seeds.lock.json"
    return source if source.is_file() else projected


def compose_seed_catalog_findings(root: Path) -> list[dict]:
    """Validate the bootstrap-only, non-secret Compose seed catalog."""
    path = reviewed_compose_seed_catalog(root)
    relative = str(path.relative_to(root))
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return [{"finding": "compose_seed_catalog_invalid_json", "path": relative}]
    findings: list[dict] = []

    def exact_keys(value, expected: set[str], location: str) -> None:
        if not isinstance(value, dict):
            findings.append(
                {
                    "finding": "compose_seed_catalog_invalid_schema",
                    "path": relative,
                    "location": location,
                }
            )
            return
        if set(value) - expected:
            findings.append(
                {
                    "finding": "compose_seed_catalog_unknown_field",
                    "path": relative,
                    "location": location,
                    "fields": sorted(set(value) - expected),
                }
            )
        if expected - set(value):
            findings.append(
                {
                    "finding": "compose_seed_catalog_missing_field",
                    "path": relative,
                    "location": location,
                    "fields": sorted(expected - set(value)),
                }
            )

    exact_keys(document, {"apiVersion", "kind", "metadata", "seeds"}, "")
    if not isinstance(document, dict):
        return findings
    if document.get("apiVersion") != "micro-task-engine/v1alpha1":
        findings.append(
            {"finding": "compose_seed_catalog_invalid_api_version", "path": relative}
        )
    if document.get("kind") != "ComposeSeedCatalog":
        findings.append(
            {"finding": "compose_seed_catalog_invalid_kind", "path": relative}
        )
    metadata = document.get("metadata")
    exact_keys(metadata, {"contractVersion", "source"}, "metadata")
    if not isinstance(metadata, dict) or metadata.get("contractVersion") != 1:
        findings.append(
            {"finding": "compose_seed_catalog_invalid_contract", "path": relative}
        )
    if (
        not isinstance(metadata, dict)
        or metadata.get("source") != "curated-safe-nonsecret-bootstrap"
    ):
        findings.append(
            {"finding": "compose_seed_catalog_invalid_source", "path": relative}
        )

    raw_seeds = document.get("seeds")
    if not isinstance(raw_seeds, dict):
        findings.append(
            {"finding": "compose_seed_catalog_seeds_not_object", "path": relative}
        )
        raw_seeds = {}
    platform_path = reviewed_platform_source(root)
    try:
        platform = (
            yaml.safe_load(platform_path.read_text())
            if platform_path.suffix != ".json"
            else json.loads(platform_path.read_text())
        )
    except (OSError, yaml.YAMLError, json.JSONDecodeError):
        findings.append(
            {"finding": "compose_seed_catalog_platform_unreadable", "path": relative}
        )
        platform = {}
    components = (
        platform.get("spec", {}).get("components", [])
        if isinstance(platform, dict)
        else []
    )
    compose_required: set[str] = set()
    component_secrets: set[str] = set()
    for component in components if isinstance(components, list) else []:
        if not isinstance(component, dict):
            continue
        component_secrets.update(str(key) for key in component.get("secrets", []))
        compose = component.get("compose")
        if not compose:
            continue
        local_compose = root / str(compose)
        declared = Path(str(compose))
        projected_name = (
            f"{declared.parent.name}.yaml"
            if declared.name == "compose.yaml"
            and declared.parent.parent.name == "services"
            else declared.name
        )
        server_compose = root / "templates/deploy" / projected_name
        compose_path = local_compose if local_compose.is_file() else server_compose
        if not compose_path.is_file():
            findings.append(
                {
                    "finding": "compose_seed_catalog_compose_missing",
                    "path": relative,
                    "compose": str(compose),
                }
            )
            continue
        compose_required.update(
            ENV_REF_PATTERN.findall(compose_path.read_text(errors="ignore"))
        )
    general_seed_keys: set[str] = set()
    post_render_keys: set[str] = set()
    for config_source in (
        root / "tools/platform-cli/server-config.py",
        root / "bin/server-config.py",
    ):
        if not config_source.is_file():
            continue
        try:
            tree = ast.parse(config_source.read_text())
        except (OSError, SyntaxError):
            continue
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {
                target.id for target in targets if isinstance(target, ast.Name)
            }
            if "ONE_TIME_MIGRATION_SEEDS" in names and isinstance(node.value, ast.Dict):
                general_seed_keys.update(
                    str(key.value)
                    for key in node.value.keys
                    if isinstance(key, ast.Constant) and isinstance(key.value, str)
                )
            if "POST_RENDER_PROVISIONED_KEYS" in names and isinstance(
                node.value, (ast.Set, ast.Tuple, ast.List)
            ):
                post_render_keys.update(
                    str(item.value)
                    for item in node.value.elts
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)
                )
        break
    expected = (
        compose_required
        - component_secrets
        - COMPOSE_DERIVED_KEYS
        - general_seed_keys
        - post_render_keys
    )
    actual = {str(key) for key in raw_seeds}
    if expected != actual:
        findings.append(
            {
                "finding": "compose_seed_catalog_coverage_mismatch",
                "path": relative,
                "missing": sorted(expected - actual),
                "extra": sorted(actual - expected),
            }
        )
    for key, value in raw_seeds.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", str(key)):
            findings.append(
                {
                    "finding": "compose_seed_catalog_invalid_key",
                    "path": relative,
                    "key": str(key),
                }
            )
            continue
        if (
            not isinstance(value, str)
            or not value
            or "\n" in value
            or "\r" in value
            or ENV_REF_PATTERN.search(value)
        ):
            findings.append(
                {
                    "finding": "compose_seed_catalog_invalid_value",
                    "path": relative,
                    "key": key,
                }
            )
            continue
        if SENSITIVE_SEED_KEY_PATTERN.search(key) and not key.endswith("_ENABLED"):
            findings.append(
                {
                    "finding": "compose_seed_catalog_sensitive_key",
                    "path": relative,
                    "key": key,
                }
            )
        if key.endswith("_IMAGE") and not re.fullmatch(
            r"[^\s]+@sha256:[0-9a-f]{64}", value
        ):
            findings.append(
                {
                    "finding": "compose_seed_catalog_image_not_digest_pinned",
                    "path": relative,
                    "key": key,
                }
            )
        if re.search(r"_PORT_[0-9]+_MAPPING$", key) and not re.fullmatch(
            r"127\.0\.0\.1:[0-9]{1,5}:[0-9]{1,5}(?:/(?:tcp|udp))?", value
        ):
            findings.append(
                {
                    "finding": "compose_seed_catalog_port_not_loopback",
                    "path": relative,
                    "key": key,
                }
            )
        if key.endswith("_ENABLED") and value not in {"true", "false"}:
            findings.append(
                {
                    "finding": "compose_seed_catalog_invalid_boolean",
                    "path": relative,
                    "key": key,
                }
            )
    return findings


def platform_lock_findings(path: Path, root: Path) -> list[dict]:
    """Validate the immutable supply-chain lock instead of treating it as config.

    Only the documented version and digest-pin schema is accepted. An unknown
    field cannot use the lockfile exemption to smuggle mutable runtime config.
    """
    relative = str(path.relative_to(root))
    try:
        document = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError):
        return [{"finding": "lockfile_invalid_yaml", "path": relative}]
    if not isinstance(document, dict):
        return [
            {"finding": "lockfile_invalid_schema", "path": relative, "location": ""}
        ]
    findings: list[dict] = []

    def exact_keys(value, expected: set[str], location: str) -> None:
        if not isinstance(value, dict):
            findings.append(
                {
                    "finding": "lockfile_invalid_schema",
                    "path": relative,
                    "location": location,
                }
            )
            return
        unknown = sorted(set(value) - expected)
        missing = sorted(expected - set(value))
        if unknown:
            findings.append(
                {
                    "finding": "lockfile_unknown_field",
                    "path": relative,
                    "location": location,
                    "fields": unknown,
                }
            )
        if missing:
            findings.append(
                {
                    "finding": "lockfile_missing_field",
                    "path": relative,
                    "location": location,
                    "fields": missing,
                }
            )

    exact_keys(document, LOCK_TOP_LEVEL_KEYS, "")
    if document.get("apiVersion") != "micro-task-engine/v1alpha1":
        findings.append({"finding": "lockfile_invalid_api_version", "path": relative})
    if document.get("kind") != "PlatformLock":
        findings.append({"finding": "lockfile_invalid_kind", "path": relative})
    metadata = document.get("metadata")
    exact_keys(metadata, {"generatedAt"}, "metadata")
    generated_at = metadata.get("generatedAt") if isinstance(metadata, dict) else None
    try:
        datetime.date.fromisoformat(str(generated_at))
    except ValueError:
        findings.append({"finding": "lockfile_invalid_generated_at", "path": relative})

    spec = document.get("spec")
    expected_spec = LOCK_SPEC_VERSION_KEYS | {
        "harnesses",
        "images",
        "dataContentProfiles",
    }
    exact_keys(spec, expected_spec, "spec")
    if not isinstance(spec, dict):
        return findings
    version_pattern = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
    for key in sorted(LOCK_SPEC_VERSION_KEYS):
        if not version_pattern.fullmatch(str(spec.get(key, ""))):
            findings.append(
                {
                    "finding": "lockfile_invalid_version_pin",
                    "path": relative,
                    "location": f"spec.{key}",
                }
            )
    harnesses = spec.get("harnesses")
    exact_keys(harnesses, LOCK_HARNESS_KEYS, "spec.harnesses")
    if isinstance(harnesses, dict):
        for key in sorted(LOCK_HARNESS_KEYS):
            if not version_pattern.fullmatch(str(harnesses.get(key, ""))):
                findings.append(
                    {
                        "finding": "lockfile_invalid_version_pin",
                        "path": relative,
                        "location": f"spec.harnesses.{key}",
                    }
                )
    images = spec.get("images")
    exact_keys(images, LOCK_IMAGE_KEYS, "spec.images")
    if isinstance(images, dict):
        for key in sorted(LOCK_IMAGE_KEYS):
            value = str(images.get(key, ""))
            if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", value):
                findings.append(
                    {
                        "finding": "lockfile_image_not_digest_pinned",
                        "path": relative,
                        "location": f"spec.images.{key}",
                    }
                )
    try:
        data_content_contract(root).validate_registry(document)
    except Exception as exc:
        findings.append(
            {
                "finding": "lockfile_data_content_registry_invalid",
                "path": relative,
                "error": type(exc).__name__,
            }
        )
    return findings


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dotenv(path: Path) -> tuple[dict[str, str], list[dict]]:
    values: dict[str, str] = {}
    findings: list[dict] = []
    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        return values, [
            {
                "finding": "dotenv_unreadable",
                "path": str(path),
                "error": type(exc).__name__,
            }
        ]
    for line_number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            findings.append(
                {
                    "finding": "invalid_dotenv_line",
                    "path": str(path),
                    "line": line_number,
                }
            )
            continue
        key, value = stripped.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            findings.append(
                {
                    "finding": "invalid_dotenv_key",
                    "path": str(path),
                    "line": line_number,
                }
            )
            continue
        if key in values:
            findings.append(
                {"finding": "duplicate_dotenv_key", "path": str(path), "key": key}
            )
        values[key] = value
    return values, findings


def canonical_domain(value: str) -> str | None:
    """Normalize a configured DNS base domain without inventing a default."""
    domain = value.strip().lower().rstrip(".")
    labels = domain.split(".")
    if (
        not domain
        or "://" in domain
        or "/" in domain
        or len(domain) > 253
        or len(labels) < 2
        or not all(DOMAIN_LABEL_PATTERN.fullmatch(label) for label in labels)
    ):
        return None
    return domain


def canonical_operator_ssh_cidrs(value: str) -> list[str] | None:
    raw = [item for item in re.split(r"[\s,]+", value.strip()) if item]
    if not raw:
        return None
    try:
        normalized = sorted(
            str(ipaddress.ip_network(item, strict=False)) for item in raw
        )
    except ValueError:
        return None
    if len(set(normalized)) != len(normalized):
        return None
    if value.strip() != ",".join(normalized):
        return None
    return normalized


def _server_config_contract_path(root: Path) -> Path | None:
    return next(
        (
            path
            for path in (
                root / "bin/server-config.py",
                root / "tools/platform-cli/server-config.py",
            )
            if path.is_file()
        ),
        None,
    )


def _filter_active_profile_keys(
    keys: set[str], optional: set[str], values: dict[str, str]
) -> tuple[set[str], set[str]]:
    prefixes = INACTIVE_PROFILE_KEY_PREFIXES.get(
        values.get("DATA_CONTENT_PROFILE", "").strip(), ()
    )
    if not prefixes:
        return keys, optional
    return (
        {key for key in keys if not key.startswith(prefixes)},
        {key for key in optional if not key.startswith(prefixes)},
    )


def _active_service_projection_owners(
    root: Path, source_values: dict[str, str]
) -> set[str]:
    try:
        config = json.loads((root / "config/platform.json").read_text())
    except (OSError, json.JSONDecodeError):
        return set()
    components = (
        config.get("spec", {}).get("components", []) if isinstance(config, dict) else []
    )
    owners = {
        str(row.get("id"))
        for row in components
        if isinstance(row, dict) and row.get("id")
    }
    if source_values.get("DATA_CONTENT_PROFILE", "").strip() == "postgres-notion":
        owners.add("notion")
    return owners


def _required_config_contract(
    root: Path, source_values: dict[str, str] | None = None
) -> tuple[set[str], set[str], set[str], list[dict]]:
    """Return active required, optional-empty, and operator-owned keys.

    The renderer is the authoritative declaration owner when it is installed.
    The small fallback exists only for isolated verifier fixtures and derives
    refs from the rendered active config; it deliberately never scans dormant
    provider templates.
    """

    values = source_values or {}
    findings: list[dict] = []
    config_path = root / "config/platform.json"
    config: dict = {}
    if config_path.is_file():
        try:
            config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            findings.append(
                {
                    "finding": "required_config_contract_invalid",
                    "path": str(config_path),
                    "reason": "runtime_config_unreadable",
                }
            )

    contract_path = _server_config_contract_path(root)
    if contract_path is not None and isinstance(config, dict) and config:
        old_root = os.environ.get("MTE_PLATFORM_ROOT")
        os.environ["MTE_PLATFORM_ROOT"] = str(root)
        try:
            spec = importlib.util.spec_from_file_location(
                f"mte_server_config_contract_{id(root)}", contract_path
            )
            if spec is None or spec.loader is None:
                raise RuntimeError("module_loader_unavailable")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            required, _service_keys, _seeds = module.declared_keys(config, values)
            optional = set(getattr(module, "OPTIONAL_EMPTY_KEYS", set()))
            operator = set(getattr(module, "REQUIRED_OPERATOR_BOOTSTRAP_KEYS", set()))
            # MTE_OPERATOR_SSH_CIDRS is an external host boundary even during a
            # rolling upgrade where the deployed renderer predates the field.
            if "MTE_OPERATOR_SSH_CIDRS" in required or values.get(
                "MTE_OPERATOR_SSH_CIDRS"
            ):
                operator.add("MTE_OPERATOR_SSH_CIDRS")
                required.add("MTE_OPERATOR_SSH_CIDRS")
            required, optional = _filter_active_profile_keys(
                set(required), optional, values
            )
            return required, optional, operator & required, findings
        except Exception as exc:
            findings.append(
                {
                    "finding": "required_config_contract_invalid",
                    "path": str(contract_path),
                    "reason": type(exc).__name__,
                }
            )
        finally:
            if old_root is None:
                os.environ.pop("MTE_PLATFORM_ROOT", None)
            else:
                os.environ["MTE_PLATFORM_ROOT"] = old_root

    keys: set[str] = {"PLATFORM_BASE_DOMAIN"}
    optional: set[str] = set()
    operator: set[str] = set()
    if isinstance(config, dict) and config:

        def visit(value, parent: str = "") -> None:
            if isinstance(value, dict):
                for key, nested in value.items():
                    if (
                        key.endswith("Ref")
                        and isinstance(nested, str)
                        and re.fullmatch(r"[A-Z][A-Z0-9_]*", nested)
                    ):
                        keys.add(nested)
                    if key == "secrets" and isinstance(nested, list):
                        keys.update(
                            str(item)
                            for item in nested
                            if re.fullmatch(r"[A-Z][A-Z0-9_]*", str(item))
                        )
                    visit(nested, key)
            elif isinstance(value, list):
                for nested in value:
                    visit(nested, parent)

        visit(config)
        spec_value = config.get("spec", {})
        host = spec_value.get("host", {}) if isinstance(spec_value, dict) else {}
        if isinstance(host, dict):
            for field in ("sshRef", "rootRef", "secretsRootRef", "sshAllowedCidrsRef"):
                ref = host.get(field)
                if isinstance(ref, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", ref):
                    keys.add(ref)
                    operator.add(ref)
            excluded = host.get("excludedRefs")
            if isinstance(excluded, list):
                operator.update(
                    str(ref)
                    for ref in excluded
                    if re.fullmatch(r"[A-Z][A-Z0-9_]*", str(ref))
                )
                keys.update(operator)
        domain_ref = (
            spec_value.get("domainRef") if isinstance(spec_value, dict) else None
        )
        if isinstance(domain_ref, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", domain_ref):
            keys.add(domain_ref)
            operator.add(domain_ref)
        components = (
            config.get("spec", {}).get("components", [])
            if isinstance(config, dict)
            else []
        )
        if any(
            isinstance(row, dict) and row.get("id") == "paperclip" for row in components
        ):
            keys.update({"PAPERCLIP_PORT", "PAPERCLIP_LEGACY_PORT"})
        for component in components if isinstance(components, list) else []:
            if not isinstance(component, dict) or not component.get("compose"):
                continue
            declared = Path(str(component["compose"]))
            projected_name = (
                f"{declared.parent.name}.yaml"
                if declared.name == "compose.yaml"
                and declared.parent.parent.name == "services"
                else declared.name
            )
            candidates = (
                root / declared,
                root / "templates/deploy" / projected_name,
                root / "runtime/deploy" / projected_name,
            )
            compose_path = next((path for path in candidates if path.is_file()), None)
            if compose_path is not None:
                keys.update(
                    ENV_REF_PATTERN.findall(compose_path.read_text(errors="ignore"))
                )
    keys, optional = _filter_active_profile_keys(keys, optional, values)
    return keys, optional, operator & keys, findings


def required_config_keys(root: Path) -> set[str]:
    keys, _optional, _operator, _findings = _required_config_contract(root)
    return keys


def canonical_compose_environment_value(value: object) -> bool:
    """Accept a direct canonical ref or an endpoint composed only from refs."""
    text = str(value)
    if re.fullmatch(r"\$\{[A-Z][A-Z0-9_]*:\?[^}]*\}", text):
        return True
    if re.fullmatch(r"\$\{MATTERMOST_ALERT_WEBHOOK_URL:-\}", text):
        return True
    refs = ENV_REF_PATTERN.findall(text)
    remainder = ENV_REF_PATTERN.sub("", text)
    return bool(refs) and remainder in {"http://", "https://", "http://:", "https://:"}


def hash_governed_generated_projections(root: Path) -> set[Path]:
    """Return generated runtime JSON files proven by the canonical manifest.

    A self-declared ``_generated`` marker is not sufficient: the path, source
    hash, generator version, content hash, and restrictive mode must all match
    the registered projection.  The allowlist is intentionally limited to the
    two JSON runtime projections that legitimately contain resolved domains.
    """

    allowed = {
        root / "config/platform.json",
        root / "config/public-urls.json",
    }
    if (
        not CANONICAL_ENV.is_file()
        or CANONICAL_ENV.is_symlink()
        or not PROJECTION_MANIFEST.is_file()
        or PROJECTION_MANIFEST.is_symlink()
    ):
        return set()
    try:
        source_hash = sha256(CANONICAL_ENV)
        manifest = json.loads(PROJECTION_MANIFEST.read_text())
    except (OSError, json.JSONDecodeError):
        return set()
    if not isinstance(manifest, dict):
        return set()
    generator = str(manifest.get("generatorVersion") or "")
    if manifest.get("sourceSha256") != source_hash or not generator:
        return set()
    rows = manifest.get("projections")
    if not isinstance(rows, list):
        return set()

    governed: set[Path] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        path = Path(str(row.get("path") or ""))
        if (
            path not in allowed
            or not path.is_file()
            or path.is_symlink()
            or path.stat().st_mode & 0o777 != 0o600
            or row.get("sourceSha256") != source_hash
            or row.get("generatorVersion") != generator
            or row.get("contentSha256") != sha256(path)
        ):
            continue
        try:
            document = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        generated = document.get("_generated") if isinstance(document, dict) else None
        if not isinstance(generated, dict):
            continue
        if (
            generated.get("doNotEdit") is True
            and generated.get("sourceSha256") == source_hash
            and generated.get("generatorVersion") == generator
        ):
            governed.add(path)
    return governed


def static_config_findings(
    root: Path, canonical_base_domain: str | None = None
) -> list[dict]:
    """Reject duplicated defaults and mutable values outside platform.env."""
    findings: list[dict] = []
    declared_component_secrets: set[str] = set()
    platform_source = reviewed_platform_source(root)
    if platform_source.is_file():
        try:
            platform_document = (
                json.loads(platform_source.read_text())
                if platform_source.suffix == ".json"
                else yaml.safe_load(platform_source.read_text())
            )
        except (OSError, json.JSONDecodeError, yaml.YAMLError):
            platform_document = {}
        components = (
            platform_document.get("spec", {}).get("components", [])
            if isinstance(platform_document, dict)
            else []
        )
        for component in components if isinstance(components, list) else []:
            if isinstance(component, dict):
                declared_component_secrets.update(
                    str(key) for key in component.get("secrets", [])
                )
    governed_projections = hash_governed_generated_projections(root)
    findings.extend(configuration_writer_findings(root))
    if reviewed_platform_source(root).is_file():
        findings.extend(compose_seed_catalog_findings(root))
    compose_paths = sorted(
        {
            *root.glob("deployment/services/*/compose.yaml"),
            *root.glob("templates/deploy/*.compose.yaml"),
        }
    )
    for path in compose_paths:
        relative = str(path.relative_to(root))
        raw = path.read_text()
        if raw.startswith("# GENERATED by mte-config-renderer; DO NOT EDIT;"):
            # Runtime projections are governed by the manifest/source/content
            # hashes below. Their rendered literals are not parallel sources.
            continue
        for match in ENV_DEFAULT_PATTERN.finditer(raw):
            if match.group(1) not in OPTIONAL_CANONICAL_COMPOSE_DEFAULTS:
                findings.append(
                    {
                        "finding": "configurable_default_outside_canonical",
                        "path": relative,
                        "key": match.group(1),
                    }
                )
        try:
            document = yaml.safe_load(raw)
        except yaml.YAMLError:
            continue
        services = document.get("services", {}) if isinstance(document, dict) else {}
        for service_name, service in services.items():
            if not isinstance(service, dict):
                continue
            image = service.get("image")
            if isinstance(image, str) and not image.startswith("${"):
                findings.append(
                    {
                        "finding": "literal_image_outside_canonical",
                        "path": relative,
                        "service": service_name,
                    }
                )
            for key in ("cpus", "mem_limit"):
                if key in service and not str(service[key]).startswith("${"):
                    findings.append(
                        {
                            "finding": "literal_limit_outside_canonical",
                            "path": relative,
                            "service": service_name,
                            "key": key,
                        }
                    )
            for port in service.get("ports", []) or []:
                without_refs = ENV_REF_PATTERN.sub("", str(port))
                if re.search(r"\d", without_refs):
                    findings.append(
                        {
                            "finding": "literal_port_outside_canonical",
                            "path": relative,
                            "service": service_name,
                        }
                    )
            environment = service.get("environment", {})
            if isinstance(environment, dict):
                for key, value in environment.items():
                    if MUTABLE_KEY_PATTERN.search(
                        str(key)
                    ) and not canonical_compose_environment_value(value):
                        findings.append(
                            {
                                "finding": "literal_environment_value_outside_canonical",
                                "path": relative,
                                "service": service_name,
                                "key": str(key),
                            }
                        )

    lock_path = reviewed_platform_lock(root)
    if lock_path.is_file():
        findings.extend(platform_lock_findings(lock_path, root))

    for path in (root / "config/platform.yaml", root / "config/platform.json"):
        if not path.is_file():
            continue
        relative = str(path.relative_to(root))
        try:
            document = (
                json.loads(path.read_text())
                if path.suffix == ".json"
                else yaml.safe_load(path.read_text())
            )
        except (json.JSONDecodeError, yaml.YAMLError):
            continue
        if path in governed_projections:
            continue

        def visit(value, location: str, mutable_context: bool = False) -> None:
            if isinstance(value, dict):
                for key, nested in value.items():
                    key_text = str(key)
                    mutable = (
                        mutable_context
                        or key_text in {"images", "harnesses", "versions", "limits"}
                        or key_text.lower()
                        in {
                            "ssh",
                            "enabled",
                            "baseurl",
                            "origin",
                            "url",
                            "tunnelname",
                            "githubowner",
                            "githubrepository",
                            "basebranch",
                        }
                        or MUTABLE_KEY_PATTERN.search(key_text) is not None
                    )
                    if key_text.endswith("Ref") or key_text == "operatorMode":
                        mutable = False
                    visit(
                        nested,
                        f"{location}.{key_text}" if location else key_text,
                        mutable,
                    )
            elif isinstance(value, list):
                for index, nested in enumerate(value):
                    visit(nested, f"{location}[{index}]", mutable_context)
            elif (
                mutable_context
                and location
                not in {
                    "apiVersion",
                    "kind",
                    "metadata.name",
                    "spec.host.name",
                }
                and not (
                    isinstance(value, str)
                    and (
                        re.fullmatch(r"\$\{[A-Z][A-Z0-9_]*:\?[^}]*\}", value)
                        or re.fullmatch(r"[A-Z][A-Z0-9_]*", value)
                    )
                )
            ):
                findings.append(
                    {
                        "finding": "yaml_configurable_literal_outside_canonical",
                        "path": relative,
                        "location": location,
                    }
                )

        visit(document, "")

    runtime_paths: set[Path] = set()
    for candidate in (
        root / "config/platform.yaml",
        root / "config/platform.lock.yaml",
    ):
        if candidate.is_file():
            runtime_paths.add(candidate)
    for directory in (
        "tools/platform-cli",
        "config",
        "deployment",
        "workflows",
    ):
        base = root / directory
        if base.exists():
            runtime_paths.update(
                path
                for path in base.rglob("*")
                if path.is_file()
                and path.suffix
                in {
                    ".py",
                    ".sh",
                    ".yaml",
                    ".yml",
                    ".json",
                    ".env",
                    ".example",
                    ".tf",
                    ".template",
                    ".txt",
                    ".service",
                }
                and not path.name.endswith(".orig")
            )
    for path in sorted(runtime_paths):
        relative = str(path.relative_to(root))
        for line_number, line in enumerate(
            path.read_text(errors="ignore").splitlines(), 1
        ):
            for alias in DOMAIN_ALIAS_KEYS:
                if not re.search(rf"\b{re.escape(alias)}\b", line):
                    continue
                migration_mapping = (
                    relative == "tools/platform-cli/server-config.py"
                    and re.search(
                        rf"['\"]{re.escape(alias)}['\"]\s*:\s*['\"]PLATFORM_BASE_DOMAIN['\"]",
                        line,
                    )
                )
                policy_declaration = (
                    relative == "tools/platform-cli/server-verify.py"
                    and line.lstrip().startswith("DOMAIN_ALIAS_KEYS =")
                )
                policy_mapping = (
                    relative == "tools/platform-cli/server-verify.py"
                    and re.search(
                        rf"['\"]{re.escape(alias)}['\"]\s*:\s*['\"]PLATFORM_BASE_DOMAIN['\"]",
                        line,
                    )
                )
                if not (migration_mapping or policy_declaration or policy_mapping):
                    findings.append(
                        {
                            "finding": "runtime_domain_alias",
                            "path": relative,
                            "line": line_number,
                            "alias": alias,
                        }
                    )
            if (
                canonical_base_domain
                and canonical_base_domain in line
                and path not in governed_projections
            ):
                findings.append(
                    {
                        "finding": "hardcoded_base_domain_outside_canonical_source",
                        "path": relative,
                        "line": line_number,
                    }
                )

    script_roots = [root / "tools/platform-cli", root / "deployment/steps"]
    for base in script_roots:
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.suffix not in {".py", ".sh"}:
                continue
            relative = str(path.relative_to(root))
            raw = path.read_text(errors="ignore")
            compatibility_migration_metadata_lines: set[int] = set()
            if path.suffix == ".py" and relative == "tools/platform-cli/server-config.py":
                try:
                    source_tree = ast.parse(raw)
                except SyntaxError:
                    source_tree = None
                if source_tree is not None:
                    for assignment in ast.walk(source_tree):
                        if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                            continue
                        targets = (
                            assignment.targets
                            if isinstance(assignment, ast.Assign)
                            else [assignment.target]
                        )
                        names = {
                            target.id
                            for target in targets
                            if isinstance(target, ast.Name)
                        }
                        value = assignment.value
                        if (
                            names == COMPATIBILITY_MIGRATION_METADATA_ASSIGNMENTS
                            and isinstance(value, ast.Dict)
                        ):
                            compatibility_migration_metadata_lines.update(
                                range(value.lineno, value.end_lineno + 1)
                            )
            if relative == "deployment/steps/daytona.sh":
                for assignment in ("defaults", "profile_defaults"):
                    match = re.search(rf"^\s*{assignment}\s*=\s*\{{", raw, re.MULTILINE)
                    if match:
                        findings.append(
                            {
                                "finding": "deployment_step_config_catalog_outside_canonical",
                                "path": relative,
                                "assignment": assignment,
                                "line": raw[: match.start()].count("\n") + 1,
                            }
                        )
            for match in ENV_DEFAULT_PATTERN.finditer(raw):
                if match.group(1) in IMMUTABLE_STRUCTURAL_ENV_DEFAULT_KEYS.get(
                    relative, set()
                ) or raw[: match.start()].count("\n") + 1 in (
                    compatibility_migration_metadata_lines
                ):
                    continue
                findings.append(
                    {
                        "finding": "script_env_default_outside_canonical",
                        "path": relative,
                        "key": match.group(1),
                    }
                )
            for match in re.finditer(
                r"os\.environ\.get\(\s*['\"]([A-Z][A-Z0-9_]*)['\"]\s*,\s*['\"][^'\"]+['\"]",
                raw,
            ):
                if match.group(1) not in STRUCTURAL_ENV_DEFAULT_KEYS:
                    findings.append(
                        {
                            "finding": "script_env_default_outside_canonical",
                            "path": relative,
                            "key": match.group(1),
                        }
                    )
            assignment_key = (
                r"(?:[A-Z][A-Z0-9_]*_)?(?:PORT|URL|URI|HOST|DOMAIN|ENDPOINT|"
                r"IMAGE|VERSION|LIMIT|ENABLED|NAME)"
                if relative.startswith("deployment/steps/")
                else r"[A-Z][A-Z0-9_]*(?:PORT|URL|URI|HOST|DOMAIN|ENDPOINT|IMAGE|VERSION|LIMIT|ENABLED)"
            )
            for match in re.finditer(
                rf"^\s*({assignment_key})\s*=\s*((?!os\.environ)(?!None\b)(?:['\"][^'\"]+['\"]|[0-9][^\n#]*))",
                raw,
                re.MULTILINE,
            ):
                if match.group(1) in IMMUTABLE_GLOBAL_CONSTANTS.get(relative, set()):
                    continue
                if re.fullmatch(
                    r"['\"]\$(?:[A-Z][A-Z0-9_]*|\{[A-Z][A-Z0-9_]*\})['\"]",
                    match.group(2),
                ):
                    # A command-scoped export of a value already read from the
                    # canonical source is a consumer, not another default.
                    continue
                findings.append(
                    {
                        "finding": "script_configurable_literal_outside_canonical",
                        "path": relative,
                        "key": match.group(1),
                    }
                )
            if path.suffix == ".py":
                try:
                    tree = ast.parse(raw)
                except SyntaxError:
                    continue
                allowed_dicts: set[int] = set()
                for assignment in ast.walk(tree):
                    if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                        continue
                    targets = (
                        assignment.targets
                        if isinstance(assignment, ast.Assign)
                        else [assignment.target]
                    )
                    names = {
                        target.id for target in targets if isinstance(target, ast.Name)
                    }
                    value = assignment.value
                    if not isinstance(value, ast.Dict):
                        continue
                    if relative == "tools/platform-cli/server-config.py" and names & (
                        BOOTSTRAP_LITERAL_ASSIGNMENTS | STRUCTURAL_LITERAL_ASSIGNMENTS
                    ):
                        allowed_dicts.update(
                            id(nested)
                            for nested in ast.walk(value)
                            if isinstance(nested, ast.Dict)
                        )
                    if (
                        relative == "tools/platform-cli/server-config.py"
                        and names == COMPATIBILITY_MIGRATION_METADATA_ASSIGNMENTS
                    ):
                        allowed_dicts.update(
                            id(nested)
                            for nested in ast.walk(value)
                            if isinstance(nested, ast.Dict)
                        )
                    if relative in {
                        "tools/platform-cli/server-config.py",
                        "tools/platform-cli/server-verify.py",
                    } and names & {
                        "aliases",
                        "LEGACY_ALIAS_MAPPING",
                    }:
                        try:
                            literal = ast.literal_eval(value)
                        except (ValueError, TypeError):
                            literal = None
                        if literal == LEGACY_ALIAS_MAPPING:
                            allowed_dicts.update(
                                id(nested)
                                for nested in ast.walk(value)
                                if isinstance(nested, ast.Dict)
                            )
                    if (
                        relative == "tools/platform-cli/platform.py"
                        and "aliases" in names
                    ):
                        try:
                            literal = ast.literal_eval(value)
                        except (ValueError, TypeError):
                            literal = None
                        if isinstance(literal, dict) and all(
                            LEGACY_ALIAS_MAPPING.get(key) == mapped
                            for key, mapped in literal.items()
                            if CONFIG_KEY_PATTERN.search(key)
                        ):
                            allowed_dicts.update(
                                id(nested)
                                for nested in ast.walk(value)
                                if isinstance(nested, ast.Dict)
                            )
                    if (
                        relative == "tools/platform-cli/server-hermes.py"
                        and "HERMES_NATIVE_ENV_NAMES" in names
                    ):
                        allowed_dicts.update(
                            id(nested)
                            for nested in ast.walk(value)
                            if isinstance(nested, ast.Dict)
                        )
                    if (
                        relative == "tools/platform-cli/server-secrets.py"
                        and names & BOOTSTRAP_LITERAL_ASSIGNMENTS
                    ):
                        allowed_dicts.update(
                            id(nested)
                            for nested in ast.walk(value)
                            if isinstance(nested, ast.Dict)
                        )
                    if (
                        relative == "tools/platform-cli/local-verify.py"
                        and names & TEST_FIXTURE_LITERAL_ASSIGNMENTS
                    ):
                        allowed_dicts.update(
                            id(nested)
                            for nested in ast.walk(value)
                            if isinstance(nested, ast.Dict)
                        )
                if relative == "tools/platform-cli/server-config.py":
                    for expression in ast.walk(tree):
                        if not isinstance(expression, ast.Call) or not isinstance(
                            expression.func, ast.Attribute
                        ):
                            continue
                        owner = expression.func.value
                        if (
                            expression.func.attr == "update"
                            and isinstance(owner, ast.Name)
                            and owner.id in BOOTSTRAP_LITERAL_ASSIGNMENTS
                            and expression.args
                            and isinstance(expression.args[0], ast.Dict)
                        ):
                            allowed_dicts.update(
                                id(nested)
                                for nested in ast.walk(expression.args[0])
                                if isinstance(nested, ast.Dict)
                            )

                def derived_expression(value_node: ast.AST) -> bool:
                    if isinstance(value_node, (ast.Name, ast.Subscript)):
                        return True
                    if isinstance(value_node, ast.FormattedValue):
                        return derived_expression(value_node.value)
                    if isinstance(value_node, ast.JoinedStr):
                        formatted = [
                            part
                            for part in value_node.values
                            if isinstance(part, ast.FormattedValue)
                        ]
                        return bool(formatted) and all(
                            derived_expression(part) for part in formatted
                        )
                    if isinstance(value_node, ast.Call):
                        function = value_node.func
                        if isinstance(function, ast.Name) and function.id in {
                            "str",
                            "int",
                            "float",
                            "bool",
                            "sorted",
                            "list",
                            "dict",
                        }:
                            return all(
                                derived_expression(argument)
                                for argument in value_node.args
                            )
                        if isinstance(function, ast.Attribute) and function.attr in {
                            "get",
                            "lower",
                            "lstrip",
                            "operator_email",
                            "rstrip",
                            "strip",
                            "url",
                        }:
                            return derived_expression(function.value)
                    return False

                def generated_secret_expression(value_node: ast.AST) -> bool:
                    """Recognize secret material built only by a CSPRNG call.

                    Prefixing generated material (for example, an API-key type
                    marker) remains generation, not a configurable default.
                    The caller additionally requires the key to be declared as
                    a component secret in the reviewed platform manifest.
                    """
                    if isinstance(value_node, ast.Call):
                        function = value_node.func
                        name = (
                            function.id
                            if isinstance(function, ast.Name)
                            else (
                                function.attr
                                if isinstance(function, ast.Attribute)
                                else ""
                            )
                        )
                        return name in {
                            "token",
                            "token_hex",
                            "token_urlsafe",
                            "password",
                        }
                    if isinstance(value_node, ast.BinOp) and isinstance(
                        value_node.op, ast.Add
                    ):
                        left_constant = isinstance(
                            value_node.left, ast.Constant
                        ) and isinstance(value_node.left.value, str)
                        right_constant = isinstance(
                            value_node.right, ast.Constant
                        ) and isinstance(value_node.right.value, str)
                        return (
                            left_constant
                            and generated_secret_expression(value_node.right)
                        ) or (
                            right_constant
                            and generated_secret_expression(value_node.left)
                        )
                    return False

                for node in ast.walk(tree):
                    if not isinstance(node, ast.Dict):
                        continue
                    if id(node) in allowed_dicts:
                        continue
                    for key_node, value_node in zip(node.keys, node.values):
                        if not isinstance(key_node, ast.Constant) or not isinstance(
                            key_node.value, str
                        ):
                            continue
                        key = key_node.value
                        if not re.fullmatch(
                            r"[A-Z][A-Z0-9_]*", key
                        ) or not CONFIG_KEY_PATTERN.search(key):
                            continue
                        generated_secret = generated_secret_expression(value_node)
                        if generated_secret and not isinstance(value_node, ast.Call):
                            generated_secret = key in declared_component_secrets
                        source_reference = derived_expression(value_node)
                        structural_metadata = isinstance(
                            value_node, (ast.Tuple, ast.List)
                        ) and all(
                            isinstance(item, ast.Constant)
                            and isinstance(item.value, str)
                            for item in value_node.elts
                        )
                        if isinstance(value_node, ast.Constant) or not (
                            generated_secret or source_reference or structural_metadata
                        ):
                            findings.append(
                                {
                                    "finding": "script_configurable_literal_outside_canonical",
                                    "path": relative,
                                    "key": key,
                                    "line": getattr(value_node, "lineno", None),
                                }
                            )

    # Multiple dotenv examples with values are parallel mutable sources, not a
    # schema. Empty values are allowed to document/import a key once.
    seen_defaults: dict[str, str] = {}
    for path in sorted(root.glob("**/*.env.example")):
        if any(part in {"state", "evidence", ".runtime"} for part in path.parts):
            continue
        values, _ = dotenv(path)
        for key, value in values.items():
            if not value:
                continue
            if key in seen_defaults:
                findings.append(
                    {
                        "finding": "duplicate_configurable_default",
                        "path": str(path.relative_to(root)),
                        "key": key,
                        "otherPath": seen_defaults[key],
                    }
                )
            else:
                seen_defaults[key] = str(path.relative_to(root))
    return findings


def configuration_writer_findings(root: Path) -> list[dict]:
    """Enforce serialized canonical writes and renderer-owned projections.

    ``platform.env`` is mutable runtime state, so an atomic rename alone is not
    sufficient: every writer must participate in the one shared flock.  Derived
    service/integration dotenv files are owned exclusively by server-config.py;
    other scripts may read and verify them, but must not write them.
    """

    findings: list[dict] = []
    roots = (root / "tools/platform-cli",)
    for base in roots:
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            if not path.is_file() or path.name.endswith(".orig"):
                continue
            relative = str(path.relative_to(root))
            raw = path.read_text(errors="ignore")
            try:
                tree = ast.parse(raw)
            except SyntaxError:
                continue

            canonical_mutations: list[int] = []
            projection_mutations: list[int] = []

            def assigned_names(nodes: list[ast.stmt]) -> tuple[set[str], set[str]]:
                canonical: set[str] = set()
                projections: set[str] = set()
                for statement in nodes:
                    for assignment in ast.walk(statement):
                        if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                            continue
                        targets = (
                            assignment.targets
                            if isinstance(assignment, ast.Assign)
                            else [assignment.target]
                        )
                        names = {
                            target.id
                            for target in targets
                            if isinstance(target, ast.Name)
                        }
                        expression = ast.get_source_segment(raw, assignment.value) or ""
                        if re.search(r"platform\.env(?:['\"]|\s*$)", expression):
                            canonical.update(names)
                        if ".env" in expression and re.search(
                            r"(?:services|integrations|[-_]admin\.env|[-_]api\.env|"
                            r"hermes[-_]runtime\.env)",
                            expression,
                        ):
                            projections.update(names)
                return canonical, projections

            module_statements = [
                statement
                for statement in tree.body
                if not isinstance(
                    statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                )
            ]
            global_canonical, global_projections = assigned_names(module_statements)
            scopes: list[tuple[ast.AST, set[str], set[str]]] = [
                (
                    ast.Module(body=module_statements, type_ignores=[]),
                    global_canonical,
                    global_projections,
                )
            ]
            for function_node in (
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ):
                local_canonical, local_projections = assigned_names(function_node.body)
                scopes.append(
                    (
                        function_node,
                        global_canonical | local_canonical,
                        global_projections | local_projections,
                    )
                )

            seen_calls: set[int] = set()
            for scope, canonical_names, projection_names in scopes:
                for call in (
                    node for node in ast.walk(scope) if isinstance(node, ast.Call)
                ):
                    if id(call) in seen_calls:
                        continue
                    seen_calls.add(id(call))
                    function = call.func
                    function_name = (
                        function.id
                        if isinstance(function, ast.Name)
                        else function.attr
                        if isinstance(function, ast.Attribute)
                        else ""
                    )
                    target: ast.AST | None = None
                    if function_name == "replace":
                        if (
                            isinstance(function, ast.Attribute)
                            and isinstance(function.value, ast.Name)
                            and function.value.id == "os"
                            and len(call.args) >= 2
                        ):
                            target = call.args[1]
                        elif call.args:
                            target = call.args[0]
                    elif (
                        function_name
                        in {
                            "atomic_env",
                            "atomic_text",
                            "save_env",
                            "write_env",
                        }
                        and call.args
                    ):
                        target = call.args[0]
                    target_name = target.id if isinstance(target, ast.Name) else ""
                    fixture_only_write = (
                        relative == "tools/platform-cli/local-verify.py"
                        and ast.get_source_segment(raw, function)
                        == "server_config.write_env"
                        and target_name == "canonical"
                    )
                    if target_name in canonical_names and not fixture_only_write:
                        canonical_mutations.append(call.lineno)
                    if target_name in projection_names:
                        projection_mutations.append(call.lineno)

            # cloudflare-token-bootstrap historically embedded the remote
            # writer as source text.  Parse that representation fail-closed as
            # well; an undefined outer SERVER_PROJECTION must not evade AST
            # target tracking.
            embedded_projection_write = bool(
                re.search(r"projection\s*=\s*Path\(", raw)
                and re.search(r"os\.replace\([^\n]+,\s*projection\s*\)", raw)
            )
            if embedded_projection_write:
                projection_mutations.append(
                    raw[: raw.index("projection=Path(")].count("\n") + 1
                )
            embedded_canonical_write = bool(
                re.search(r"canonical\s*=\s*Path\(", raw)
                and re.search(r"os\.replace\([^\n]+,\s*canonical\s*\)", raw)
            )
            if embedded_canonical_write:
                canonical_mutations.append(
                    raw[: raw.index("canonical=Path(")].count("\n") + 1
                )

            if canonical_mutations and (
                ".platform-env.lock" not in raw
                or not re.search(r"\b(?:fcntl\.)?flock\s*\(", raw)
            ):
                findings.append(
                    {
                        "finding": "canonical_writer_without_shared_lock",
                        "path": relative,
                        "lines": sorted(set(canonical_mutations)),
                    }
                )
            if (
                projection_mutations
                and relative != "tools/platform-cli/server-config.py"
            ):
                findings.append(
                    {
                        "finding": "projection_write_outside_renderer",
                        "path": relative,
                        "lines": sorted(set(projection_mutations)),
                    }
                )
    return findings


def data_content_projection_findings(
    root: Path,
    source_values: dict[str, str],
    source_hash: str | None,
    manifest_rows: list[dict],
) -> list[dict]:
    """Verify the logical role projection against all three reviewed inputs."""
    runtime_config_path = root / "config/platform.json"
    if not runtime_config_path.is_file():
        return []
    try:
        runtime_config = json.loads(runtime_config_path.read_text())
    except (OSError, json.JSONDecodeError):
        return [{"finding": "data_content_runtime_config_invalid"}]
    runtime_spec = (
        runtime_config.get("spec") if isinstance(runtime_config, dict) else None
    )
    if not isinstance(runtime_spec, dict) or "dataContentPlane" not in runtime_spec:
        return []

    plane_path = root / "config/data-content-plane.json"
    findings: list[dict] = []
    plane_rows = [
        row
        for row in manifest_rows
        if isinstance(row, dict) and row.get("path") == str(plane_path)
    ]
    if len(plane_rows) != 1 or set(plane_rows[0]) != {
        "path",
        "contentSha256",
        "sourceSha256",
        "generatorVersion",
    }:
        findings.append(
            {
                "finding": "data_content_projection_manifest_binding_invalid",
                "path": str(plane_path),
            }
        )
    if not plane_path.is_file() or plane_path.is_symlink():
        findings.append(
            {
                "finding": "data_content_projection_missing_or_unsafe",
                "path": str(plane_path),
            }
        )
        return findings
    try:
        observed = json.loads(plane_path.read_text())
    except (OSError, json.JSONDecodeError):
        findings.append(
            {"finding": "data_content_projection_invalid_json", "path": str(plane_path)}
        )
        return findings
    if not isinstance(observed, dict):
        return [
            {
                "finding": "data_content_projection_invalid_schema",
                "path": str(plane_path),
            }
        ]

    config_source_path = reviewed_platform_source(root)
    lock_path = reviewed_platform_lock(root)
    if not config_source_path.is_file() or not lock_path.is_file():
        findings.append({"finding": "data_content_reviewed_inputs_missing"})
        return findings
    try:
        if config_source_path.suffix == ".json":
            config_source = json.loads(config_source_path.read_text())
        else:
            config_source = yaml.safe_load(config_source_path.read_text())
        lock = yaml.safe_load(lock_path.read_text())
        if not isinstance(config_source, dict) or not isinstance(lock, dict):
            raise ValueError("reviewed inputs must be objects")
        values = dict(source_values)
        generated = observed.get("_generated")
        generator = (
            str(generated.get("generatorVersion", ""))
            if isinstance(generated, dict)
            else ""
        )
        if not source_hash or not generator:
            raise ValueError("projection source or generator binding is missing")
        contract = data_content_contract(root)
        expected = contract.resolve_from_paths(
            config_source,
            lock,
            values,
            config_path=config_source_path,
            lock_path=lock_path,
            source_sha256=source_hash,
            generator_version=generator,
        )
        if observed != expected:
            findings.append(
                {
                    "finding": "data_content_projection_binding_mismatch",
                    "path": str(plane_path),
                }
            )
    except Exception as exc:
        findings.append(
            {
                "finding": "data_content_projection_contract_invalid",
                "path": str(plane_path),
                "error": type(exc).__name__,
            }
        )
    return findings


def config_source_check(
    root: Path = ROOT, secret_root: Path = SECRET_ROOT, *, include_static: bool = True
) -> dict:
    canonical = secret_root / "platform.env"
    manifest_path = secret_root / "projections-manifest.json"
    findings: list[dict] = []
    source_values: dict[str, str] = {}
    source_hash = None
    base_domain: str | None = None
    required_keys: set[str] = {"PLATFORM_BASE_DOMAIN"}
    optional_empty_keys: set[str] = set()
    operator_keys: set[str] = set()
    active_service_owners: set[str] = set()

    candidates = (
        sorted(path for path in secret_root.rglob("platform.env") if path.is_file())
        if secret_root.exists()
        else []
    )
    if len(candidates) != 1 or (candidates and candidates[0] != canonical):
        findings.append(
            {
                "finding": "canonical_source_count_mismatch",
                "expected": str(canonical),
                "actualCount": len(candidates),
            }
        )
    if not canonical.is_file() or canonical.is_symlink():
        findings.append(
            {"finding": "canonical_source_missing_or_unsafe", "path": str(canonical)}
        )
    else:
        mode = canonical.stat().st_mode & 0o777
        if mode != 0o600:
            findings.append(
                {
                    "finding": "canonical_source_mode_mismatch",
                    "path": str(canonical),
                    "actualMode": oct(mode),
                    "expectedMode": "0o600",
                }
            )
        source_values, dotenv_findings = dotenv(canonical)
        findings.extend(dotenv_findings)
        source_hash = sha256(canonical)
        configured_domain = source_values.get("PLATFORM_BASE_DOMAIN", "")
        base_domain = canonical_domain(configured_domain)
        if base_domain is None:
            findings.append(
                {
                    "finding": "canonical_base_domain_missing_or_invalid",
                    "key": "PLATFORM_BASE_DOMAIN",
                    "actualConfigured": bool(configured_domain),
                }
            )
        for alias in sorted(DOMAIN_ALIAS_KEYS & set(source_values)):
            findings.append(
                {"finding": "domain_alias_in_canonical_source", "alias": alias}
            )
        (
            required_keys,
            optional_empty_keys,
            operator_keys,
            contract_findings,
        ) = _required_config_contract(root, source_values)
        findings.extend(contract_findings)
        for key in sorted(required_keys - set(source_values)):
            findings.append({"finding": "required_key_missing", "key": key})
        for key in sorted(required_keys & set(source_values)):
            if key not in optional_empty_keys and not source_values[key].strip():
                findings.append(
                    {"finding": "required_key_missing_or_empty", "key": key}
                )
        for key in sorted(operator_keys):
            if not source_values.get(key, "").strip():
                findings.append(
                    {
                        "finding": "operator_bootstrap_key_missing_or_empty",
                        "key": key,
                    }
                )
        ssh_cidrs = source_values.get("MTE_OPERATOR_SSH_CIDRS", "").strip()
        if "MTE_OPERATOR_SSH_CIDRS" in operator_keys and ssh_cidrs:
            if canonical_operator_ssh_cidrs(ssh_cidrs) is None:
                findings.append(
                    {
                        "finding": "operator_ssh_cidrs_invalid_or_not_normalized",
                        "key": "MTE_OPERATOR_SSH_CIDRS",
                    }
                )
        telegram_token = source_values.get("HERMES_TELEGRAM_BOT_TOKEN", "").strip()
        telegram_users_raw = source_values.get(
            "HERMES_TELEGRAM_ALLOWED_USERS", ""
        ).strip()
        if bool(telegram_token) != bool(telegram_users_raw):
            findings.append({"finding": "telegram_configuration_incomplete"})
        elif telegram_token:
            telegram_users = [
                item.strip() for item in telegram_users_raw.split(",") if item.strip()
            ]
            if not re.fullmatch(r"[0-9]{6,15}:[A-Za-z0-9_-]{20,}", telegram_token):
                findings.append({"finding": "telegram_token_shape_invalid"})
            if (
                not telegram_users
                or "*" in telegram_users
                or len(set(telegram_users)) != len(telegram_users)
                or any(
                    not re.fullmatch(r"[1-9][0-9]{4,19}", item)
                    for item in telegram_users
                )
            ):
                findings.append({"finding": "telegram_allowlist_invalid"})
        active_service_owners = _active_service_projection_owners(root, source_values)

    manifest: dict = {}
    if not manifest_path.is_file() or manifest_path.is_symlink():
        findings.append(
            {
                "finding": "projection_manifest_missing_or_unsafe",
                "path": str(manifest_path),
            }
        )
    else:
        mode = manifest_path.stat().st_mode & 0o777
        if mode != 0o600:
            findings.append(
                {
                    "finding": "projection_manifest_mode_mismatch",
                    "path": str(manifest_path),
                    "actualMode": oct(mode),
                    "expectedMode": "0o600",
                }
            )
        try:
            loaded = json.loads(manifest_path.read_text())
            manifest = loaded if isinstance(loaded, dict) else {}
        except (json.JSONDecodeError, OSError):
            findings.append(
                {
                    "finding": "projection_manifest_invalid_json",
                    "path": str(manifest_path),
                }
            )
        if source_hash and manifest.get("sourceSha256") != source_hash:
            findings.append(
                {
                    "finding": "canonical_source_hash_drift",
                    "expectedSha256": source_hash,
                    "actualSha256": manifest.get("sourceSha256"),
                }
            )

    rows = manifest.get("projections", []) if isinstance(manifest, dict) else []
    if not isinstance(rows, list):
        findings.append({"finding": "projection_rows_not_a_list"})
        rows = []
    registered: set[Path] = set()
    registered_service_owners: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            findings.append({"finding": "projection_row_not_an_object", "index": index})
            continue
        missing = sorted(
            {"path", "contentSha256", "sourceSha256", "generatorVersion"} - set(row)
        )
        if missing:
            findings.append(
                {
                    "finding": "projection_row_missing_fields",
                    "index": index,
                    "fields": missing,
                }
            )
            continue
        path = Path(str(row["path"]))
        registered.add(path)
        expected_owner = LEGACY_PROJECTION_REGISTRY_OWNERS.get(path.name)
        if expected_owner is not None and row.get("owner") != expected_owner:
            findings.append(
                {
                    "finding": "legacy_projection_registry_ownership_missing",
                    "path": str(path),
                    "expectedOwner": expected_owner,
                    "remediation": "remove stale projection or register its exact owner",
                }
            )
        if path.parent == secret_root / "services":
            legacy_owned = (
                expected_owner is not None and row.get("owner") == expected_owner
            )
            if path.stem in active_service_owners:
                registered_service_owners.add(path.stem)
            if path.stem not in active_service_owners and not legacy_owned:
                findings.append(
                    {
                        "finding": "service_projection_owner_not_active",
                        "path": str(path),
                        "owner": path.stem,
                        "activeOwners": sorted(active_service_owners),
                    }
                )
        if path.parent == secret_root / "integrations":
            declared_owner = row.get("owner")
            legacy_owned = (
                expected_owner is not None and declared_owner == expected_owner
            )
            if declared_owner not in active_service_owners and not legacy_owned:
                findings.append(
                    {
                        "finding": "integration_projection_owner_not_active",
                        "path": str(path),
                        "owner": declared_owner,
                        "activeOwners": sorted(active_service_owners),
                    }
                )
        if source_hash and row.get("sourceSha256") != source_hash:
            findings.append(
                {"finding": "projection_source_hash_drift", "path": str(path)}
            )
        if not row.get("generatorVersion"):
            findings.append(
                {"finding": "projection_generator_version_missing", "path": str(path)}
            )
        if not path.is_file() or path.is_symlink():
            findings.append(
                {"finding": "projection_missing_or_unsafe", "path": str(path)}
            )
            continue
        mode = path.stat().st_mode & 0o777
        if mode != 0o600:
            findings.append(
                {
                    "finding": "projection_mode_mismatch",
                    "path": str(path),
                    "actualMode": oct(mode),
                    "expectedMode": "0o600",
                }
            )
        actual_hash = sha256(path)
        if row.get("contentSha256") != actual_hash:
            findings.append(
                {
                    "finding": "projection_content_hash_drift",
                    "path": str(path),
                    "actualSha256": actual_hash,
                }
            )
    for owner in sorted(active_service_owners - registered_service_owners):
        findings.append(
            {
                "finding": "active_service_projection_missing",
                "owner": owner,
                "expectedPath": str(secret_root / "services" / f"{owner}.env"),
            }
        )

    derived: set[Path] = set()
    # The canonical file is the only top-level dotenv under SECRET_ROOT.
    # Generated service/integration projections live in their registered
    # subdirectories; any other top-level dotenv is a parallel secret store.
    derived.update(
        path
        for path in secret_root.glob("*.env")
        if path != canonical and (path.is_file() or path.is_symlink())
    )
    for directory in (secret_root / "services", secret_root / "integrations"):
        if directory.exists():
            derived.update(
                path
                for path in directory.glob("*.env")
                if path.is_file() or path.is_symlink()
            )
    derived.update(path for path in secret_root.glob("*-admin.env") if path.is_file())
    runtime = root / ".runtime"
    if runtime.exists():
        derived.update(
            path
            for path in runtime.rglob("*")
            if path.is_file() and ("tfvars" in path.name or path.suffix == ".env")
        )
    for path in sorted(derived - registered):
        findings.append({"finding": "unregistered_projection", "path": str(path)})

    findings.extend(
        data_content_projection_findings(
            root,
            source_values,
            source_hash,
            rows,
        )
    )

    public_hostnames: list[str] = []
    config_path = root / "config/platform.json"
    if config_path.is_file():
        try:
            runtime_config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            runtime_config = {}
        runtime_spec = (
            runtime_config.get("spec", {}) if isinstance(runtime_config, dict) else {}
        )
        configured_base = (
            runtime_spec.get("resolvedDomain") or runtime_spec.get("domain")
            if isinstance(runtime_spec, dict)
            else None
        )
        if configured_base and canonical_domain(str(configured_base)) != base_domain:
            findings.append(
                {
                    "finding": "rendered_base_domain_drift",
                    "expected": base_domain,
                    "actual": str(configured_base).strip().rstrip(".").lower(),
                }
            )
        components = (
            runtime_spec.get("components", []) if isinstance(runtime_spec, dict) else []
        )
        for component in components if isinstance(components, list) else []:
            if not isinstance(component, dict):
                continue
            exposure = component.get("exposure")
            hostname = exposure.get("hostname") if isinstance(exposure, dict) else None
            if not hostname:
                continue
            hostname = str(hostname).strip().rstrip(".").lower()
            if "." in hostname:
                if not base_domain or not hostname.endswith("." + base_domain):
                    findings.append(
                        {
                            "finding": "public_hostname_outside_canonical_domain",
                            "component": component.get("id"),
                            "hostname": hostname,
                        }
                    )
                    continue
                fqdn = hostname
            elif re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", hostname):
                if not base_domain:
                    findings.append(
                        {
                            "finding": "public_hostname_without_canonical_domain",
                            "component": component.get("id"),
                            "hostname": hostname,
                        }
                    )
                    continue
                fqdn = f"{hostname}.{base_domain}"
            else:
                findings.append(
                    {
                        "finding": "public_hostname_invalid",
                        "component": component.get("id"),
                        "hostname": hostname,
                    }
                )
                continue
            public_hostnames.append(fqdn)
    projection_contents: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or not row.get("path"):
            continue
        path = Path(str(row["path"]))
        if path.is_file() and path.stat().st_size <= 5_000_000:
            projection_contents.append(path.read_text(errors="ignore"))
    for hostname in sorted(set(public_hostnames)):
        if not any(hostname in content for content in projection_contents):
            findings.append(
                {"finding": "public_hostname_projection_missing", "hostname": hostname}
            )

    if include_static:
        findings.extend(static_config_findings(root, base_domain))
    return {
        "component": "configuration-source",
        "check": "canonical-platform-env",
        "ok": not findings,
        "state": "passed" if not findings else "failed",
        "canonicalSource": str(canonical),
        "projectionManifest": str(manifest_path),
        "requiredKeys": len(required_keys),
        "projections": len(rows),
        "canonicalBaseDomain": base_domain,
        "publicHostnames": sorted(set(public_hostnames)),
        "findings": findings,
    }


def probe(url: str) -> dict:
    started = time.monotonic()
    request = urllib.request.Request(
        url, headers={"User-Agent": "mte-platform-verify/1"}
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read(512)
            return {
                "ok": 200 <= response.status < 400,
                "httpStatus": response.status,
                "latencyMs": round((time.monotonic() - started) * 1000),
            }
    except urllib.error.HTTPError as exc:
        return {
            "ok": False,
            "httpStatus": exc.code,
            "error": "http_error",
            "latencyMs": round((time.monotonic() - started) * 1000),
        }
    except (OSError, TimeoutError) as exc:
        return {
            "ok": False,
            "httpStatus": 0,
            "error": type(exc).__name__,
            "latencyMs": round((time.monotonic() - started) * 1000),
        }


def mcp_initialize() -> dict:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "mte-verify", "version": "1"},
            },
        }
    ).encode()
    request = urllib.request.Request(
        "http://127.0.0.1:19001/mcp",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read(4096).decode(errors="replace")
            return {
                "ok": response.status == 200
                and ("serverInfo" in raw or "result" in raw),
                "httpStatus": response.status,
            }
    except urllib.error.HTTPError as exc:
        return {"ok": False, "httpStatus": exc.code, "error": "http_error"}
    except OSError as exc:
        return {"ok": False, "httpStatus": 0, "error": type(exc).__name__}


def paperclip_runtime_settings() -> dict:
    if not CANONICAL_ENV.is_file():
        return {
            "ok": False,
            "state": "canonical_source_missing",
            "missingKeys": ["PAPERCLIP_PORT", "PAPERCLIP_LEGACY_PORT"],
        }
    values, findings = dotenv(CANONICAL_ENV)
    keys = ("PAPERCLIP_PORT", "PAPERCLIP_LEGACY_PORT")
    missing = [key for key in keys if not values.get(key)]
    ports: dict[str, int] = {}
    invalid: list[str] = []
    for key in keys:
        if key in missing:
            continue
        try:
            port = int(values[key])
        except ValueError:
            invalid.append(key)
            continue
        if not (1 <= port <= 65535):
            invalid.append(key)
            continue
        ports[key] = port
    ok = not findings and not missing and not invalid and len(set(ports.values())) == 2
    return {
        "ok": ok,
        "state": "passed" if ok else "invalid_configuration",
        "missingKeys": missing,
        "invalidKeys": invalid,
        "portsUnique": len(set(ports.values())) == len(ports),
        "canonicalUrl": f"http://127.0.0.1:{ports['PAPERCLIP_PORT']}/api/health"
        if "PAPERCLIP_PORT" in ports
        else None,
        "legacyUrl": f"http://127.0.0.1:{ports['PAPERCLIP_LEGACY_PORT']}/api/health"
        if "PAPERCLIP_LEGACY_PORT" in ports
        else None,
        "paperclipPort": ports.get("PAPERCLIP_PORT"),
    }


def container_env_check(name: str, expected: dict[str, str]) -> dict:
    """Check selected container env without returning unrelated secret values."""
    try:
        completed = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{range .Config.Env}}{{println .}}{{end}}",
                name,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "state": "timeout", "container": name}
    except OSError as exc:
        return {
            "ok": False,
            "state": "unavailable",
            "container": name,
            "error": type(exc).__name__,
        }
    if completed.returncode != 0:
        return {
            "ok": False,
            "state": "inspect_failed",
            "container": name,
            "exitCode": completed.returncode,
        }
    actual: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in expected:
            actual[key] = value
    mismatched = sorted(
        key for key, value in expected.items() if actual.get(key) != value
    )
    return {
        "ok": not mismatched,
        "state": "passed" if not mismatched else "mismatch",
        "container": name,
        "checkedKeys": sorted(expected),
        "mismatchedKeys": mismatched,
    }


def paperclip_persisted_port_check(expected_port: int) -> dict:
    script = (
        "const fs=require('fs');"
        "const p='/data/instances/default/config.json';"
        "const v=JSON.parse(fs.readFileSync(p,'utf8'));"
        "process.stdout.write(String(v?.server?.port ?? ''));"
    )
    try:
        completed = subprocess.run(
            ["docker", "exec", "mte-paperclip", "node", "-e", script],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "state": "timeout", "expectedPort": expected_port}
    except OSError as exc:
        return {
            "ok": False,
            "state": "unavailable",
            "expectedPort": expected_port,
            "error": type(exc).__name__,
        }
    raw = completed.stdout.strip()
    try:
        actual = int(raw)
    except ValueError:
        actual = None
    ok = completed.returncode == 0 and actual == expected_port
    return {
        "ok": ok,
        "state": "passed" if ok else "mismatch",
        "expectedPort": expected_port,
        "actualPort": actual,
        "exitCode": completed.returncode,
    }


def paperclip_runtime_ports() -> dict:
    """Validate desired env, persisted config, and the actual HTTP listeners."""
    settings = paperclip_runtime_settings()
    if settings.get("ok") is not True:
        return {
            "ok": False,
            "state": "listener_configuration_invalid",
            "settings": settings,
        }
    canonical = probe(settings["canonicalUrl"])
    legacy = probe(settings["legacyUrl"])
    paperclip_env = container_env_check(
        "mte-paperclip",
        {
            "PORT": str(settings["paperclipPort"]),
            "PAPERCLIP_LISTEN_PORT": str(settings["paperclipPort"]),
        },
    )
    persisted = paperclip_persisted_port_check(settings["paperclipPort"])
    ok = all(
        (
            canonical.get("ok") is True,
            legacy.get("ok") is not True,
            paperclip_env.get("ok") is True,
            persisted.get("ok") is True,
        )
    )
    return {
        "ok": ok,
        "state": "passed" if ok else "listener_mismatch",
        "canonicalListener": canonical,
        "legacyListenerActive": legacy.get("ok") is True,
        "settings": settings,
        "paperclipEnv": paperclip_env,
        "persistedConfig": persisted,
    }


def _json_object(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _profile_catalog_semantic_sha256(path: Path) -> str | None:
    document = _yaml_object(path)
    if document is None:
        return None
    semantic = {key: value for key, value in document.items() if key != "_generated"}
    encoded = json.dumps(
        semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _profile_catalog_object(path: Path) -> dict | None:
    return _yaml_object(path)


def _yaml_object(path: Path) -> dict | None:
    try:
        value = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError):
        return None
    return value if isinstance(value, dict) else None


def _is_full_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _router_origin(config: dict) -> str | None:
    components = config.get("spec", {}).get("components", [])
    if not isinstance(components, list):
        return None
    router = next(
        (
            row
            for row in components
            if isinstance(row, dict) and row.get("id") == "9router"
        ),
        None,
    )
    if not isinstance(router, dict):
        return None
    exposure = router.get("exposure")
    if isinstance(exposure, dict) and exposure.get("origin"):
        base = str(exposure["origin"])
    else:
        health = router.get("health")
        base = str(health.get("url", "")) if isinstance(health, dict) else ""
        if base.endswith("/api/health"):
            base = base[: -len("/api/health")]
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip(
        "/"
    )


def _profile_key_ref(profile: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", profile).strip("_").upper()
    return f"NINEROUTER_PROFILE_{slug}_API_KEY"


def _positive_counter(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def harness_scoped_router_auth_evidence() -> dict:
    """Validate current, secret-free C018 evidence against canonical sources."""
    findings: list[dict] = []
    evidence = _json_object(E2E_EVIDENCE)
    config = _json_object(CONFIG)
    profiles_document = _profile_catalog_object(E2E_PROFILES)
    if evidence is None:
        findings.append({"finding": "e2e_evidence_missing_or_invalid"})
    elif E2E_EVIDENCE.stat().st_mode & 0o777 != 0o600:
        findings.append(
            {
                "finding": "e2e_evidence_mode_mismatch",
                "actualMode": oct(E2E_EVIDENCE.stat().st_mode & 0o777),
                "expectedMode": "0o600",
            }
        )
    if config is None:
        findings.append({"finding": "platform_config_missing_or_invalid"})
    if profiles_document is None:
        findings.append({"finding": "runtime_profiles_missing_or_invalid"})
    if findings:
        return {
            "ok": False,
            "state": "invalid_evidence",
            "evidence": str(E2E_EVIDENCE),
            "findings": findings,
        }

    assert evidence is not None and config is not None and profiles_document is not None
    if evidence.get("status") != "passed":
        findings.append({"finding": "e2e_evidence_not_passed"})

    sources = (
        evidence.get("sources") if isinstance(evidence.get("sources"), dict) else {}
    )
    for key, path in E2E_SOURCE_PATHS.items():
        current = _sha256_file(path)
        if current is None:
            findings.append({"finding": "e2e_source_missing", "source": key})
        elif sources.get(key) != current:
            findings.append({"finding": "e2e_source_hash_drift", "source": key})

    e2e = config.get("spec", {}).get("e2eCanary")
    if not isinstance(e2e, dict):
        findings.append({"finding": "e2e_contract_missing"})
        e2e = {}
    expected_profiles = list(R1_E2E_HARNESS_PROFILES)
    if e2e.get("profiles") != expected_profiles:
        findings.append({"finding": "e2e_profile_contract_mismatch"})
    contracts = e2e.get("profileContracts")
    contracts = contracts if isinstance(contracts, dict) else {}

    profile_rows = profiles_document.get("profiles")
    profile_rows = profile_rows if isinstance(profile_rows, list) else []
    catalog = {
        str(row.get("ref")): row
        for row in profile_rows
        if isinstance(row, dict) and row.get("ref")
    }
    if set(catalog) & set(expected_profiles) != set(expected_profiles):
        findings.append({"finding": "native_profile_missing"})

    origin = _router_origin(config)
    if origin is None:
        findings.append({"finding": "canonical_router_origin_invalid"})

    aggregate = (
        evidence.get("semanticChecks", {}).get("harness-scoped-router-auth")
        if isinstance(evidence.get("semanticChecks"), dict)
        else None
    )
    if not isinstance(aggregate, dict):
        findings.append({"finding": "semantic_aggregate_missing"})
        aggregate = {}
    if aggregate.get("status") != "passed":
        findings.append({"finding": "semantic_aggregate_not_passed"})
    if aggregate.get("requiredProfiles") != expected_profiles:
        findings.append({"finding": "semantic_required_profiles_mismatch"})
    aggregate_runs = aggregate.get("runs")
    aggregate_runs = aggregate_runs if isinstance(aggregate_runs, list) else []
    if len(aggregate_runs) != len(expected_profiles):
        findings.append({"finding": "semantic_run_count_mismatch"})
    if [
        row.get("profileRef") for row in aggregate_runs if isinstance(row, dict)
    ] != expected_profiles:
        findings.append({"finding": "semantic_profile_order_mismatch"})

    stored_runs = evidence.get("runs")
    stored_runs = stored_runs if isinstance(stored_runs, list) else []
    if [
        row.get("profile") for row in stored_runs if isinstance(row, dict)
    ] != expected_profiles:
        findings.append({"finding": "e2e_run_profile_order_mismatch"})

    validated_profiles: list[str] = []
    for profile in expected_profiles:
        semantic = next(
            (
                row
                for row in aggregate_runs
                if isinstance(row, dict) and row.get("profileRef") == profile
            ),
            None,
        )
        runtime = catalog.get(profile)
        contract = contracts.get(profile)
        stored = next(
            (
                row
                for row in stored_runs
                if isinstance(row, dict) and row.get("profile") == profile
            ),
            None,
        )
        if not all(
            isinstance(row, dict) for row in (semantic, runtime, contract, stored)
        ):
            findings.append(
                {"finding": "profile_semantic_evidence_incomplete", "profile": profile}
            )
            continue
        assert isinstance(semantic, dict)
        assert isinstance(runtime, dict)
        assert isinstance(contract, dict)
        assert isinstance(stored, dict)
        duplicate = (
            stored.get("semanticChecks", {}).get("harness-scoped-router-auth")
            if isinstance(stored.get("semanticChecks"), dict)
            else None
        )
        if duplicate != semantic:
            findings.append(
                {"finding": "per_run_semantic_evidence_drift", "profile": profile}
            )

        adapter = str(contract.get("nativeAdapter", ""))
        adapter_config = runtime.get("nativeAdapterConfig")
        adapter_config = adapter_config if isinstance(adapter_config, dict) else {}
        routing = runtime.get("llmRouting")
        routing = routing if isinstance(routing, dict) else {}
        auth_policy = runtime.get("authPolicy")
        auth_policy = auth_policy if isinstance(auth_policy, dict) else {}
        model = str(adapter_config.get("model", ""))
        key_ref = _profile_key_ref(profile)
        expected_base = (
            origin if adapter == "claude_local" else f"{origin}/v1" if origin else None
        )
        if adapter not in {"codex_local", "claude_local", "pi_local"}:
            expected_base = None

        expected_values = {
            "check": "harness-scoped-router-auth",
            "status": "passed",
            "profileRef": profile,
            "nativeAdapter": adapter,
            "evidenceSource": "9router-server-side-usage",
            "routerBaseUrl": expected_base,
            "routerProfileKeyRef": key_ref,
            "model": model,
        }
        mismatched = sorted(
            key
            for key, expected in expected_values.items()
            if semantic.get(key) != expected
        )
        if mismatched:
            findings.append(
                {
                    "finding": "profile_semantic_value_mismatch",
                    "profile": profile,
                    "fields": mismatched,
                }
            )
        counters = (
            "profileKeyRequestsDelta",
            "modelRequestsDelta",
            "totalRequestsDelta",
        )
        invalid_counters = [
            key for key in counters if not _positive_counter(semantic.get(key))
        ]
        if invalid_counters:
            findings.append(
                {
                    "finding": "scoped_router_usage_not_positive",
                    "profile": profile,
                    "fields": invalid_counters,
                }
            )
        if (
            runtime.get("nativeAdapter") != adapter
            or routing.get("provider") != "9router"
            or routing.get("apiKeyRef") != key_ref
            or not model
            or auth_policy
            != {
                "oauthInImage": False,
                "persistentSecretsInImage": False,
                "runtimeSecretRefsOnly": True,
            }
        ):
            findings.append(
                {"finding": "runtime_profile_auth_contract_drift", "profile": profile}
            )
        if not any(item.get("profile") == profile for item in findings):
            validated_profiles.append(profile)

    ok = not findings and validated_profiles == expected_profiles
    return {
        "ok": ok,
        "state": "passed" if ok else "invalid_evidence",
        "evidence": str(E2E_EVIDENCE),
        "requiredProfiles": expected_profiles,
        "validatedProfiles": validated_profiles,
        "findings": findings,
    }


def _connection_result(
    connection_id: str,
    findings: list[dict],
    *,
    evidence: Path | None = None,
    state: str | None = None,
    details: dict | None = None,
) -> dict:
    """Return one sanitized, fail-closed semantic connection result."""
    ok = not findings
    return {
        "component": f"connection-{connection_id}",
        "connectionId": connection_id,
        "ok": ok,
        "state": state or ("passed" if ok else "failed"),
        "evidence": str(evidence) if evidence is not None else None,
        "findings": findings,
        **(details or {}),
    }


def _expect(
    findings: list[dict], condition: bool, finding: str, **details: object
) -> None:
    if not condition:
        findings.append({"finding": finding, **details})


def _nested(value: object, *path: str) -> object:
    current = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _exact_string_set(value: object, expected: set[str]) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) for item in value)
        and set(value) == expected
        and len(value) == len(expected)
    )


def _dependency_refs_current(value: object) -> bool:
    if not isinstance(value, list) or not value:
        return False
    for row in value:
        if not isinstance(row, dict):
            return False
        raw_path = row.get("path")
        digest = row.get("sha256")
        if not isinstance(raw_path, str) or not raw_path.startswith(str(ROOT) + "/"):
            return False
        path = Path(raw_path)
        if _sha256_file(path) != digest:
            return False
    return True


def _contains_legacy_storage_key(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            re.search(r"noco(?:db|docs)", str(key), re.IGNORECASE)
            or _contains_legacy_storage_key(nested)
            for key, nested in value.items()
        )
    if isinstance(value, list):
        return any(_contains_legacy_storage_key(nested) for nested in value)
    return False


def _mode_is_0600(path: Path) -> bool:
    try:
        return not path.is_symlink() and path.stat().st_mode & 0o777 == 0o600
    except OSError:
        return False


def _root_owned_regular(path: Path, mode: int) -> bool:
    try:
        info = path.stat()
        return (
            path.is_file()
            and not path.is_symlink()
            and info.st_uid == 0
            and info.st_gid == 0
            and info.st_mode & 0o777 == mode
        )
    except OSError:
        return False


def _full_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00", value
    ):
        return False
    try:
        moment = datetime.datetime.fromisoformat(value)
    except ValueError:
        return False
    return moment.utcoffset() == datetime.timedelta(0)


def _canonical_json_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _portable_e2e_redaction(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(key): _portable_e2e_redaction(nested) for key, nested in value.items()
        }
    if isinstance(value, list):
        return [_portable_e2e_redaction(nested) for nested in value]
    if isinstance(value, str):
        canonical = str(CANONICAL_ENV)
        root = str(ROOT).rstrip("/")
        if value == canonical:
            return "$MTE_PLATFORM_ENV"
        if root and (value == root or value.startswith(root + "/")):
            suffix = value[len(root) :].lstrip("/")
            return "$MTE_ROOT" + (f"/{suffix}" if suffix else "")
    return value


def _file_security_contract(path: Path, mode: int) -> dict:
    return {
        "path": str(path),
        "ownerUid": 0,
        "ownerGid": 0,
        "mode": f"{mode:04o}",
        "regularFile": True,
        "symlink": False,
    }


def _cloudflare_security_findings(
    document: dict, evidence_path: Path, findings: list[dict]
) -> None:
    expected = {
        "producer": _file_security_contract(SERVER_CLOUDFLARE_ACCEPTANCE_SOURCE, 0o700),
        "evidence": _file_security_contract(evidence_path, 0o600),
    }
    _expect(
        findings,
        document.get("fileSecurity") == expected,
        "cloudflare_file_security_contract_mismatch",
        path=str(evidence_path),
    )
    _expect(
        findings,
        _root_owned_regular(evidence_path, 0o600),
        "cloudflare_evidence_owner_or_mode_invalid",
        path=str(evidence_path),
    )
    _expect(
        findings,
        _root_owned_regular(SERVER_CLOUDFLARE_ACCEPTANCE_SOURCE, 0o700),
        "cloudflare_producer_owner_or_mode_invalid",
        path=str(SERVER_CLOUDFLARE_ACCEPTANCE_SOURCE),
    )
    _expect(
        findings,
        _full_utc_timestamp(document.get("generatedAt")),
        "cloudflare_full_utc_timestamp_invalid",
        path=str(evidence_path),
    )


def _fresh_field(
    document: dict,
    names: tuple[str, ...],
    *,
    max_age_seconds: int = CONNECTION_EVIDENCE_MAX_AGE_SECONDS,
) -> bool:
    return any(
        _evidence_is_fresh(document.get(name), max_age_seconds=max_age_seconds)
        for name in names
    )


def _canonical_sha256() -> str | None:
    return _sha256_file(CANONICAL_ENV)


def _source_gate() -> dict[str, str] | None:
    config = _json_object(CONFIG)
    manifest = _json_object(PROJECTION_MANIFEST)
    canonical = _canonical_sha256()
    generated = config.get("_generated") if isinstance(config, dict) else None
    if (
        not isinstance(generated, dict)
        or not isinstance(manifest, dict)
        or canonical is None
    ):
        return None
    generator = str(generated.get("generatorVersion") or "")
    if (
        generated.get("sourceSha256") != canonical
        or manifest.get("sourceSha256") != canonical
        or manifest.get("generatorVersion") != generator
        or not generator
    ):
        return None
    return {"sourceSha256": canonical, "generatorVersion": generator}


def _bound_evidence(
    path: Path,
    *,
    kind: str,
    api_version: str = "micro-task-engine/v1alpha1",
    status: str | None,
    time_fields: tuple[str, ...],
    canonical_field: tuple[str, ...] | None,
    producer_field: tuple[str, ...] | None,
    producer_path: Path | None,
) -> tuple[dict | None, list[dict]]:
    findings: list[dict] = []
    document = _json_object(path)
    if document is None:
        return None, [{"finding": "evidence_missing_or_invalid", "path": str(path)}]
    _expect(
        findings,
        _mode_is_0600(path),
        "evidence_mode_or_symlink_invalid",
        path=str(path),
    )
    _expect(
        findings,
        document.get("apiVersion") == api_version,
        "evidence_api_version_mismatch",
    )
    _expect(findings, document.get("kind") == kind, "evidence_kind_mismatch")
    if status is not None:
        _expect(findings, document.get("status") == status, "evidence_status_mismatch")
    _expect(
        findings,
        _fresh_field(document, time_fields),
        "evidence_stale_or_timestamp_missing",
    )
    canonical = _canonical_sha256()
    if canonical_field is not None:
        _expect(
            findings,
            canonical is not None and _nested(document, *canonical_field) == canonical,
            "evidence_canonical_hash_mismatch",
        )
    if producer_field is not None and producer_path is not None:
        producer_sha = _sha256_file(producer_path)
        _expect(
            findings,
            producer_sha is not None
            and _nested(document, *producer_field) == producer_sha,
            "evidence_producer_hash_mismatch",
            producer=str(producer_path),
        )
    return document, findings


def _daytona_control_plane_evidence() -> tuple[dict | None, list[dict]]:
    """Validate the direct-Compose Daytona control-plane attestation."""
    document, findings = _bound_evidence(
        PAPERCLIP_DAYTONA_CONTROL_PLANE_EVIDENCE,
        kind="PaperclipDaytonaControlPlaneEvidence",
        status="ready",
        time_fields=("generatedAt",),
        canonical_field=("canonicalSourceSha256",),
        producer_field=("producerSha256",),
        producer_path=PAPERCLIP_DAYTONA_STEP_SOURCE,
    )
    if document is None:
        return None, findings
    values, canonical_findings = dotenv(CANONICAL_ENV)
    findings.extend(canonical_findings)
    expected_control_plane = {
        "version": values.get("MTE_DAYTONA_CONTROL_PLANE_VERSION"),
        "sourceCommit": values.get("MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT"),
    }
    _expect(
        findings,
        set(document)
        == {
            "apiVersion",
            "kind",
            "status",
            "generatedAt",
            "producerSha256",
            "canonicalSourceSha256",
            "controlPlane",
            "sandboxVersion",
            "composeServices",
            "runtimeEvidence",
            "secretValuesPrinted",
        }
        and document.get("composeServices")
        == [
            "agent-gateway",
            "api",
            "db",
            "dex",
            "minio",
            "proxy",
            "redis",
            "registry",
            "runner",
            "ssh-gateway",
        ]
        and document.get("runtimeEvidence")
        == {
            "images": str(DAYTONA_IMAGES_EVIDENCE),
            "lifecycle": str(DAYTONA_LIFECYCLE_EVIDENCE),
        }
        and document.get("controlPlane") == expected_control_plane
        and document.get("sandboxVersion")
        == values.get("MTE_DAYTONA_SANDBOX_VERSION")
        and document.get("secretValuesPrinted") is False,
        "daytona_compose_control_plane_invalid",
    )
    return document, findings


def _exact_keys(value: object, expected: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == expected


def _dependency_ref(path: Path, kind: str, producer: Path) -> dict:
    return {
        "path": str(path),
        "sha256": _sha256_file(path),
        "kind": kind,
        "producerSha256": _sha256_file(producer),
    }


def _raw_notion_material_present(document: dict, values: dict[str, str]) -> bool:
    """Reject raw Notion credentials or canary payloads in persisted evidence."""
    serialized = json.dumps(document, sort_keys=True, separators=(",", ":"))
    for key in ("NOTION_TOKEN", "NOTION_API_KEY"):
        secret = values.get(key, "")
        if secret and secret in serialized:
            return True

    forbidden_keys = {
        "token",
        "apiToken",
        "apiKey",
        "secret",
        "marker",
        "rawMarker",
        "rawToken",
        "content",
        "initialContent",
        "finalContent",
    }

    def inspect(value: object) -> bool:
        if isinstance(value, dict):
            return any(
                key in forbidden_keys or inspect(nested)
                for key, nested in value.items()
            )
        if isinstance(value, list):
            return any(inspect(nested) for nested in value)
        if isinstance(value, str):
            lowered = value.lower()
            return (
                lowered.startswith(("secret_", "ntn_"))
                or "mte-notion-canary:" in lowered
            )
        return False

    return inspect(document)


def _postgres_ssot_row_valid(row: object) -> bool:
    expected = {
        "objectIdSha256",
        "initialRevision",
        "finalRevision",
        "initialContentSha256",
        "finalContentSha256",
        "created",
        "readBackVerified",
        "updated",
        "projectionIntentVerified",
        "postDeleteAbsent",
        "cleanupVerified",
    }
    return (
        _exact_keys(row, expected)
        and _is_full_sha256(row.get("objectIdSha256"))
        and row.get("initialRevision") == 1
        and row.get("finalRevision") == 2
        and _is_full_sha256(row.get("initialContentSha256"))
        and _is_full_sha256(row.get("finalContentSha256"))
        and row.get("initialContentSha256") != row.get("finalContentSha256")
        and all(
            row.get(key) is True
            for key in (
                "created",
                "readBackVerified",
                "updated",
                "projectionIntentVerified",
                "postDeleteAbsent",
                "cleanupVerified",
            )
        )
    )


def _notion_projection_row_valid(
    row: object, postgres_row: object, *, document: bool
) -> bool:
    common = {
        "pageIdSha256",
        "objectIdSha256",
        "initialRevision",
        "finalRevision",
        "initialContentSha256",
        "finalContentSha256",
        "created",
        "archived",
        "cleanupVerified",
        "objectIdMatches",
        "initialContentSha256Matches",
        "finalContentSha256Matches",
        "linkageVerified",
    }
    surface = (
        common
        | {
            "appendVerified",
            "readBackVerified",
            "initialRevisionMatches",
            "finalRevisionMatches",
        }
        if document
        else common
        | {
            "queryVerified",
            "updated",
            "initialRevisionMatches",
            "finalRevisionMatches",
        }
    )
    if not _exact_keys(row, surface) or not _postgres_ssot_row_valid(postgres_row):
        return False
    assert isinstance(row, dict) and isinstance(postgres_row, dict)
    direct_fields = (
        "objectIdSha256",
        "initialRevision",
        "finalRevision",
        "initialContentSha256",
        "finalContentSha256",
    )
    required_true = {
        "created",
        "archived",
        "cleanupVerified",
        "objectIdMatches",
        "initialContentSha256Matches",
        "finalContentSha256Matches",
        "linkageVerified",
    }
    if document:
        required_true |= {
            "appendVerified",
            "readBackVerified",
            "initialRevisionMatches",
            "finalRevisionMatches",
        }
    else:
        required_true |= {
            "queryVerified",
            "updated",
            "initialRevisionMatches",
            "finalRevisionMatches",
        }
    return (
        _is_full_sha256(row.get("pageIdSha256"))
        and all(row.get(key) == postgres_row.get(key) for key in direct_fields)
        and all(row.get(key) is True for key in required_true)
    )


def _notion_c029_row_valid(row: dict) -> bool:
    expected_keys = {
        "id",
        "ok",
        "state",
        "source",
        "dataContentProfile",
        "roles",
        "internalApis",
        "postgresSsot",
        "notion",
        "tablePersistenceVerified",
        "documentPersistenceVerified",
        "crossProviderLinkageVerified",
        "cleanupCompleted",
        "cleanup",
        "redacted",
        "dependencyEvidence",
        "consumerVerificationEvidence",
        "internalApiEvidence",
    }
    postgres = (
        row.get("postgresSsot") if isinstance(row.get("postgresSsot"), dict) else {}
    )
    notion = row.get("notion") if isinstance(row.get("notion"), dict) else {}
    record = postgres.get("record") if isinstance(postgres.get("record"), dict) else {}
    document = (
        postgres.get("document") if isinstance(postgres.get("document"), dict) else {}
    )
    table_projection = (
        notion.get("table") if isinstance(notion.get("table"), dict) else {}
    )
    document_projection = (
        notion.get("document") if isinstance(notion.get("document"), dict) else {}
    )
    cleanup = row.get("cleanup") if isinstance(row.get("cleanup"), dict) else {}
    return (
        set(row) == expected_keys
        and row.get("id") == "C029"
        and row.get("ok") is True
        and row.get("state") == "passed"
        and row.get("source") == "server_notion_projection_consumer_canary"
        and row.get("dataContentProfile") == "postgres-notion"
        and row.get("roles")
        == {
            "tablesUi": "notion",
            "tablesApi": "notion",
            "documentsUi": "notion",
            "documentsApi": "notion",
        }
        and row.get("internalApis") == {"scopedDataApi": "postgrest"}
        and _exact_keys(postgres, {"record", "document"})
        and _exact_keys(notion, {"table", "document"})
        and _postgres_ssot_row_valid(record)
        and _postgres_ssot_row_valid(document)
        and _notion_projection_row_valid(table_projection, record, document=False)
        and _notion_projection_row_valid(document_projection, document, document=True)
        and row.get("tablePersistenceVerified") is True
        and row.get("documentPersistenceVerified") is True
        and row.get("crossProviderLinkageVerified") is True
        and row.get("cleanupCompleted") is True
        and cleanup
        == {
            "postgresRecordDeleted": True,
            "postgresDocumentDeleted": True,
            "postgresProjectionRowsDeleted": True,
            "notionTableRowArchived": True,
            "notionDocumentArchived": True,
            "verified": True,
        }
        and row.get("redacted") is True
        and row.get("dependencyEvidence")
        == _dependency_ref(
            NOTION_PROJECTION_CANARY_EVIDENCE,
            "NotionProjectionLiveCanary",
            SERVER_NOTION_PROJECTION_SOURCE,
        )
        and row.get("consumerVerificationEvidence")
        == _dependency_ref(
            NOTION_PROJECTION_VERIFY_EVIDENCE,
            "NotionProjectionConsumerVerification",
            SERVER_NOTION_PROJECTION_SOURCE,
        )
        and row.get("internalApiEvidence")
        == _dependency_ref(
            POSTGREST_VERIFY_EVIDENCE,
            "PostgrestVerification",
            ROOT / "bin/server-postgrest.py",
        )
    )


def _postgrest_verify_findings(profile: str) -> list[dict]:
    document, findings = _bound_evidence(
        POSTGREST_VERIFY_EVIDENCE,
        kind="PostgrestVerification",
        status="passed",
        time_fields=("generatedAt",),
        canonical_field=("canonicalSourceSha256",),
        producer_field=("producerSha256",),
        producer_path=ROOT / "bin/server-postgrest.py",
    )
    if document is None:
        return findings
    authorization = (
        document.get("authorization")
        if isinstance(document.get("authorization"), dict)
        else {}
    )
    persistence = (
        document.get("persistence")
        if isinstance(document.get("persistence"), dict)
        else {}
    )
    ownership = (
        document.get("dataOwnership")
        if isinstance(document.get("dataOwnership"), dict)
        else {}
    )
    expected_projection_provider = "notion" if profile == "postgres-notion" else None
    _expect(
        findings,
        document.get("ok") is True
        and document.get("profile") == profile
        and _nested(document, "release", "profile") == profile
        and _nested(document, "release", "license") == "MIT"
        and authorization.get("anonymousDenied") is True
        and authorization.get("readerWriteDenied") is True
        and authorization.get("rlsEnabled") is True
        and authorization.get("paperclipRoleScoped") is True
        and _is_full_sha256(persistence.get("markerSha256"))
        and all(
            persistence.get(key) is True
            for key in (
                "restartObserved",
                "persistenceVerified",
                "postDeleteAbsent",
                "cleanupCompleted",
            )
        )
        and ownership.get("canonicalSystem") == "postgresql"
        and ownership.get("canonicalTables")
        == ["canonical_entities", "canonical_documents"]
        and ownership.get("projectionStateTables")
        == ["provider_sync_state", "provider_outbox"]
        and ownership.get("projectionTablesContainCanonicalPayload") is False
        and ownership.get("projectionProvider") == expected_projection_provider,
        "postgrest_provisioning_semantics_invalid",
    )
    return findings


def _data_content_projection_contract_findings(profile: str) -> list[dict]:
    findings: list[dict] = []
    values, dotenv_findings = dotenv(CANONICAL_ENV)
    findings.extend(dotenv_findings)
    plane = _json_object(DATA_CONTENT_PLANE)
    lock_path = reviewed_platform_lock(ROOT)
    config_source_path = reviewed_platform_source(ROOT)
    manifest = _json_object(PROJECTION_MANIFEST)
    if (
        plane is None
        or not lock_path.is_file()
        or not config_source_path.is_file()
        or manifest is None
    ):
        return findings + [{"finding": "data_content_projection_inputs_missing"}]
    try:
        lock = yaml.safe_load(lock_path.read_text())
        config_source = (
            json.loads(config_source_path.read_text())
            if config_source_path.suffix == ".json"
            else yaml.safe_load(config_source_path.read_text())
        )
        contract = data_content_contract(ROOT)
        registry = contract.validate_registry(lock)
        selected_profile, bundle, _registry = contract.selected_bundle(lock, values)
        contract_spec = contract.validate_platform_contract(config_source)
    except Exception as exc:
        return findings + [
            {
                "finding": "data_content_projection_contract_invalid",
                "error": type(exc).__name__,
            }
        ]
    source_sha = _canonical_sha256()
    binding = plane.get("binding") if isinstance(plane.get("binding"), dict) else {}
    generated = (
        plane.get("_generated") if isinstance(plane.get("_generated"), dict) else {}
    )
    manifest_rows = (
        manifest.get("projections")
        if isinstance(manifest.get("projections"), list)
        else []
    )
    findings.extend(
        data_content_projection_findings(ROOT, values, source_sha, manifest_rows)
    )
    projection_fields = {
        "componentIds": "componentIds",
        "systemOfRecord": "systemOfRecord",
        "providers": "providers",
        "internalApis": "internalApis",
        "roles": "roles",
        "adapters": "adapters",
        "images": "images",
        "licenses": "licenses",
        "licenseExceptions": "licenseExceptions",
        "canonicalKeyPrefixes": "canonicalKeyPrefixes",
    }
    projection_exact = all(
        plane.get(plane_key) == bundle.get(bundle_key)
        for plane_key, bundle_key in projection_fields.items()
    )
    _expect(
        findings,
        selected_profile == profile
        and values.get("DATA_CONTENT_PROFILE") == profile
        and plane.get("apiVersion") == "micro-task-engine/v1alpha1"
        and plane.get("kind") == "DataContentPlane"
        and plane.get("contractVersion") == contract.CONTRACT_REVISION
        and plane.get("profile") == profile
        and plane.get("selectableProfiles") == ["postgres-notion"]
        and projection_exact
        and binding.get("sourceSha256") == source_sha
        and binding.get("platformConfigSha256") == _sha256_file(config_source_path)
        and binding.get("platformLockSha256") == _sha256_file(lock_path)
        and binding.get("contractSha256") == _canonical_json_sha256(contract_spec)
        and binding.get("registrySha256") == _canonical_json_sha256(registry)
        and binding.get("bundleSha256") == _canonical_json_sha256(bundle)
        and generated.get("doNotEdit") is True
        and generated.get("sourceSha256") == source_sha
        and isinstance(generated.get("generatorVersion"), str)
        and bool(generated.get("generatorVersion")),
        "postgres_notion_projection_invalid",
    )
    return findings


def _notion_projection_consumer_findings() -> list[dict]:
    document, findings = _bound_evidence(
        NOTION_PROJECTION_VERIFY_EVIDENCE,
        kind="NotionProjectionConsumerVerification",
        status="passed",
        time_fields=("generatedAt",),
        canonical_field=("canonicalSourceSha256",),
        producer_field=("producerSha256",),
        producer_path=SERVER_NOTION_PROJECTION_SOURCE,
    )
    if document is None:
        return findings
    values, canonical_findings = dotenv(CANONICAL_ENV)
    findings.extend(canonical_findings)
    delivery = (
        document.get("delivery") if isinstance(document.get("delivery"), dict) else {}
    )
    drain = document.get("drain") if isinstance(document.get("drain"), dict) else {}
    systemd = (
        document.get("systemd") if isinstance(document.get("systemd"), dict) else {}
    )
    settings = (
        document.get("settings") if isinstance(document.get("settings"), dict) else {}
    )
    dependencies = (
        document.get("dependencies")
        if isinstance(document.get("dependencies"), dict)
        else {}
    )

    def configured_int(key: str) -> int | None:
        value = values.get(key, "")
        return int(value) if re.fullmatch(r"[1-9][0-9]*", value) else None

    expected_top_keys = {
        "apiVersion",
        "kind",
        "status",
        "ok",
        "generatedAt",
        "dataContentProfile",
        "provider",
        "delivery",
        "drain",
        "systemd",
        "settings",
        "canonicalSourceSha256",
        "producerSha256",
        "dependencies",
        "evidence",
        "redacted",
    }
    _expect(
        findings,
        set(document) == expected_top_keys
        and document.get("ok") is True
        and document.get("dataContentProfile") == "postgres-notion"
        and document.get("provider") == "notion"
        and delivery.get("pending") == 0
        and delivery.get("processing") == 0
        and delivery.get("failed") == 0
        and delivery.get("eligible") == 0
        and delivery.get("exhausted") == 0
        and delivery.get("expiredLeases") == 0
        and isinstance(delivery.get("delivered"), int)
        and delivery.get("delivered") >= 0
        and delivery.get("schemaReady") is True
        and set(drain) == {"claimed", "delivered", "superseded", "failed"}
        and all(isinstance(value, int) and value >= 0 for value in drain.values())
        and drain.get("failed") == 0
        and systemd == {"exact": True, "enabled": True, "active": True}
        and settings
        == {
            "batchSize": configured_int("NOTION_SYNC_BATCH_SIZE"),
            "maxAttempts": configured_int("NOTION_SYNC_MAX_ATTEMPTS"),
            "leaseSeconds": configured_int("NOTION_SYNC_LEASE_SECONDS"),
            "retryBaseSeconds": configured_int("NOTION_SYNC_RETRY_BASE_SECONDS"),
            "intervalSeconds": configured_int("NOTION_SYNC_INTERVAL_SECONDS"),
        }
        and dependencies
        == {
            "notionConnectorProducerSha256": _sha256_file(SERVER_NOTION_SOURCE),
            "postgrestProducerSha256": _sha256_file(ROOT / "bin/server-postgrest.py"),
        }
        and document.get("evidence")
        == {"path": str(NOTION_PROJECTION_VERIFY_EVIDENCE), "mode": "0600"}
        and document.get("redacted") is True
        and not _raw_notion_material_present(document, values),
        "notion_projection_consumer_evidence_invalid",
    )
    return findings


def _notion_projection_canary_findings() -> list[dict]:
    document, findings = _bound_evidence(
        NOTION_PROJECTION_CANARY_EVIDENCE,
        kind="NotionProjectionLiveCanary",
        status="passed",
        time_fields=("generatedAt",),
        canonical_field=("canonicalSourceSha256",),
        producer_field=("producerSha256",),
        producer_path=SERVER_NOTION_PROJECTION_SOURCE,
    )
    if document is None:
        return findings
    values, canonical_findings = dotenv(CANONICAL_ENV)
    findings.extend(canonical_findings)
    dependencies = (
        document.get("dependencies")
        if isinstance(document.get("dependencies"), dict)
        else {}
    )
    phases = document.get("phases") if isinstance(document.get("phases"), dict) else {}
    linkage = (
        document.get("linkage") if isinstance(document.get("linkage"), dict) else {}
    )
    cleanup = (
        document.get("cleanup") if isinstance(document.get("cleanup"), dict) else {}
    )
    expected_top_keys = {
        "apiVersion",
        "kind",
        "status",
        "ok",
        "generatedAt",
        "dataContentProfile",
        "provider",
        "runIdSha256",
        "canonicalSourceSha256",
        "producerSha256",
        "dependencies",
        "phases",
        "linkage",
        "cleanup",
        "evidence",
        "redacted",
    }
    state_keys = {
        "canonicalExact",
        "syncStateExact",
        "outboxDelivered",
        "attemptCount",
        "leaseReleased",
        "errorFree",
    }

    def drain_exact(value: object) -> bool:
        return (
            isinstance(value, dict)
            and set(value) == {"claimed", "delivered", "superseded", "failed"}
            and all(isinstance(count, int) and count >= 0 for count in value.values())
            and value.get("failed") == 0
        )

    def object_state_exact(value: object) -> bool:
        return (
            isinstance(value, dict)
            and set(value) == state_keys
            and value.get("canonicalExact") is True
            and value.get("syncStateExact") is True
            and value.get("outboxDelivered") is True
            and isinstance(value.get("attemptCount"), int)
            and value["attemptCount"] >= 1
            and value.get("leaseReleased") is True
            and value.get("errorFree") is True
        )

    def phase_exact(name: str) -> bool:
        phase = phases.get(name)
        if not isinstance(phase, dict):
            return False
        expected = {"drain", "objects"}
        if name == "archive":
            expected.add("notionArchived")
        objects = phase.get("objects")
        exact = (
            set(phase) == expected
            and drain_exact(phase.get("drain"))
            and isinstance(objects, dict)
            and set(objects) == {"entity", "document"}
            and all(
                object_state_exact(objects.get(kind)) for kind in ("entity", "document")
            )
        )
        if name == "archive":
            exact = exact and phase.get("notionArchived") == {
                "entity": True,
                "document": True,
            }
        return exact

    def linkage_exact(value: object) -> bool:
        return (
            isinstance(value, dict)
            and set(value)
            == {
                "canonicalObjectIdSha256",
                "providerObjectIdSha256",
                "initialRevision",
                "finalRevision",
                "initialContentSha256",
                "finalContentSha256",
            }
            and all(
                _is_full_sha256(value.get(field))
                for field in (
                    "canonicalObjectIdSha256",
                    "providerObjectIdSha256",
                    "initialContentSha256",
                    "finalContentSha256",
                )
            )
            and value.get("initialRevision") == 1
            and value.get("finalRevision") == 2
            and value.get("initialContentSha256") != value.get("finalContentSha256")
        )

    _expect(
        findings,
        set(document) == expected_top_keys
        and document.get("ok") is True
        and document.get("dataContentProfile") == "postgres-notion"
        and document.get("provider") == "notion"
        and _is_full_sha256(document.get("runIdSha256"))
        and dependencies
        == {
            "notionConnectorProducerSha256": _sha256_file(SERVER_NOTION_SOURCE),
            "postgrestProducerSha256": _sha256_file(ROOT / "bin/server-postgrest.py"),
        }
        and set(phases) == {"create", "update", "archive"}
        and all(phase_exact(name) for name in ("create", "update", "archive"))
        and set(linkage) == {"entity", "document"}
        and all(linkage_exact(linkage.get(kind)) for kind in ("entity", "document"))
        and cleanup
        == {
            "postgresCanonicalAbsent": True,
            "postgresSyncStateAbsent": True,
            "postgresOutboxAbsent": True,
            "notionEntityArchived": True,
            "notionDocumentArchived": True,
            "verified": True,
        }
        and document.get("evidence")
        == {"path": str(NOTION_PROJECTION_CANARY_EVIDENCE), "mode": "0600"}
        and document.get("redacted") is True
        and not _raw_notion_material_present(document, values),
        "notion_projection_live_canary_invalid",
    )
    return findings


def _notion_connector_evidence() -> tuple[dict | None, list[dict]]:
    document, findings = _bound_evidence(
        NOTION_VERIFY_EVIDENCE,
        kind="NotionConnectorVerification",
        status="passed",
        time_fields=("generatedAt",),
        canonical_field=("canonicalSourceSha256",),
        producer_field=("producerSha256",),
        producer_path=SERVER_NOTION_SOURCE,
    )
    if document is None:
        return None, findings
    values, canonical_findings = dotenv(CANONICAL_ENV)
    findings.extend(canonical_findings)
    identity = (
        document.get("identity") if isinstance(document.get("identity"), dict) else {}
    )
    resources = (
        document.get("resources") if isinstance(document.get("resources"), dict) else {}
    )
    root = resources.get("root") if isinstance(resources.get("root"), dict) else {}
    documents = (
        resources.get("documents")
        if isinstance(resources.get("documents"), dict)
        else {}
    )
    database = (
        resources.get("database") if isinstance(resources.get("database"), dict) else {}
    )
    data_source = (
        resources.get("dataSource")
        if isinstance(resources.get("dataSource"), dict)
        else {}
    )
    schema = document.get("schema") if isinstance(document.get("schema"), dict) else {}
    expected_schema = {
        "Name": {"type": "title"},
        "Postgres Object ID": {"type": "rich_text"},
        "Postgres Revision": {"type": "number"},
        "Sync Hash": {"type": "rich_text"},
        "Sync State": {
            "type": "select",
            "options": ["error", "pending", "synced"],
        },
        "Entity Type": {
            "type": "select",
            "options": ["document", "record"],
        },
        "Updated At": {"type": "date"},
    }
    expected_resources = {
        "root": {
            "pageId": values.get("NOTION_ROOT_PAGE_ID"),
            "title": "MTE Agent Platform Connector",
            "exact": True,
        },
        "documents": {
            "pageId": values.get("NOTION_DOCUMENTS_PAGE_ID"),
            "title": "MTE Synced Documents",
            "parentPageId": values.get("NOTION_ROOT_PAGE_ID"),
            "exact": True,
        },
        "database": {
            "databaseId": values.get("NOTION_TABLE_DATABASE_ID"),
            "title": "MTE Synced Entities",
            "parentPageId": values.get("NOTION_ROOT_PAGE_ID"),
            "exact": True,
        },
        "dataSource": {
            "dataSourceId": values.get("NOTION_TABLE_DATA_SOURCE_ID"),
            "title": "MTE Synced Entities",
            "databaseId": values.get("NOTION_TABLE_DATABASE_ID"),
            "exact": True,
        },
    }
    safe_config = {
        "provider": "postgres-notion",
        "baseUrl": values.get("NOTION_API_BASE_URL"),
        "apiVersion": values.get("NOTION_API_VERSION"),
        "botId": values.get("NOTION_BOT_ID") or None,
        "workspaceId": values.get("NOTION_WORKSPACE_ID") or None,
        "resources": expected_resources,
    }
    expected_connector_hash = _canonical_json_sha256(safe_config)
    canary = document.get("canary") if isinstance(document.get("canary"), dict) else {}
    linkage = canary.get("linkage") if isinstance(canary.get("linkage"), dict) else {}
    record = linkage.get("record") if isinstance(linkage.get("record"), dict) else {}
    doc_link = (
        linkage.get("document") if isinstance(linkage.get("document"), dict) else {}
    )
    notion = canary.get("notion") if isinstance(canary.get("notion"), dict) else {}
    table = notion.get("table") if isinstance(notion.get("table"), dict) else {}
    notion_document = (
        notion.get("document") if isinstance(notion.get("document"), dict) else {}
    )
    cleanup = canary.get("cleanup") if isinstance(canary.get("cleanup"), dict) else {}
    link_keys = {
        "objectIdSha256",
        "initialRevision",
        "finalRevision",
        "initialContentSha256",
        "finalContentSha256",
    }
    linkage_valid = all(
        _exact_keys(item, link_keys)
        and _is_full_sha256(item.get("objectIdSha256"))
        and item.get("initialRevision") == 1
        and item.get("finalRevision") == 2
        and _is_full_sha256(item.get("initialContentSha256"))
        and _is_full_sha256(item.get("finalContentSha256"))
        and item.get("initialContentSha256") != item.get("finalContentSha256")
        for item in (record, doc_link)
    )
    table_keys = {
        "pageId",
        "dataSourceId",
        "created",
        "queryVerified",
        "updated",
        "archived",
        "cleanupVerified",
        "objectIdMatches",
        "initialRevisionMatches",
        "finalRevisionMatches",
        "initialContentSha256Matches",
        "finalContentSha256Matches",
    }
    document_keys = {
        "pageId",
        "documentsPageId",
        "created",
        "appendVerified",
        "readBackVerified",
        "archived",
        "cleanupVerified",
        "objectIdMatches",
        "initialRevisionMatches",
        "finalRevisionMatches",
        "initialContentSha256Matches",
        "finalContentSha256Matches",
    }
    table_valid = (
        _exact_keys(table, table_keys)
        and bool(table.get("pageId"))
        and table.get("dataSourceId") == values.get("NOTION_TABLE_DATA_SOURCE_ID")
        and all(
            table.get(key) is True for key in table_keys - {"pageId", "dataSourceId"}
        )
    )
    document_valid = (
        _exact_keys(notion_document, document_keys)
        and bool(notion_document.get("pageId"))
        and notion_document.get("documentsPageId")
        == values.get("NOTION_DOCUMENTS_PAGE_ID")
        and all(
            notion_document.get(key) is True
            for key in document_keys - {"pageId", "documentsPageId"}
        )
    )
    expected_top_keys = {
        "apiVersion",
        "kind",
        "status",
        "ok",
        "generatedAt",
        "dataContentProfile",
        "notionApiVersion",
        "canonicalSourceSha256",
        "connectorConfigSha256",
        "producerSha256",
        "identity",
        "resources",
        "schema",
        "canary",
        "cleanup",
        "redacted",
        "secretAudit",
        "evidence",
    }
    canary_top_keys = {
        "apiVersion",
        "kind",
        "status",
        "ok",
        "generatedAt",
        "dataContentProfile",
        "notionApiVersion",
        "canonicalSourceSha256",
        "connectorConfigSha256",
        "producerSha256",
        "identity",
        "resources",
        "runIdSha256",
        "linkage",
        "notion",
        "cleanup",
        "redacted",
    }
    _expect(
        findings,
        bool(values.get("NOTION_TOKEN"))
        and values.get("NOTION_API_BASE_URL") == "https://api.notion.com/v1"
        and values.get("NOTION_API_VERSION") == "2025-09-03"
        and all(
            values.get(key)
            for key in (
                "NOTION_ROOT_PAGE_ID",
                "NOTION_DOCUMENTS_PAGE_ID",
                "NOTION_TABLE_DATABASE_ID",
                "NOTION_TABLE_DATA_SOURCE_ID",
                "NOTION_WORKSPACE_ID",
                "NOTION_BOT_ID",
            )
        )
        and set(document) == expected_top_keys
        and document.get("ok") is True
        and document.get("dataContentProfile") == "postgres-notion"
        and document.get("notionApiVersion") == "2025-09-03"
        and document.get("connectorConfigSha256") == expected_connector_hash
        and identity
        == {
            "botId": values.get("NOTION_BOT_ID"),
            "workspaceId": values.get("NOTION_WORKSPACE_ID"),
            "botExact": True,
            "workspaceExact": True,
        }
        and resources == expected_resources
        and root == expected_resources["root"]
        and documents == expected_resources["documents"]
        and database == expected_resources["database"]
        and data_source == expected_resources["dataSource"]
        and schema == {"exact": True, "properties": expected_schema}
        and set(canary) == canary_top_keys
        and canary.get("apiVersion") == "micro-task-engine/v1alpha1"
        and canary.get("kind") == "NotionConnectorCanary"
        and canary.get("status") == "passed"
        and canary.get("ok") is True
        and _fresh_field(canary, ("generatedAt",))
        and canary.get("dataContentProfile") == "postgres-notion"
        and canary.get("notionApiVersion") == "2025-09-03"
        and canary.get("canonicalSourceSha256") == _canonical_sha256()
        and canary.get("connectorConfigSha256") == expected_connector_hash
        and canary.get("producerSha256") == _sha256_file(SERVER_NOTION_SOURCE)
        and canary.get("identity") == identity
        and canary.get("resources") == resources
        and _is_full_sha256(canary.get("runIdSha256"))
        and _exact_keys(linkage, {"record", "document"})
        and linkage_valid
        and record.get("objectIdSha256") != doc_link.get("objectIdSha256")
        and _exact_keys(notion, {"table", "document"})
        and table_valid
        and document_valid
        and cleanup
        == {
            "notionTableRowArchived": True,
            "notionDocumentArchived": True,
            "verified": True,
        }
        and canary.get("redacted") is True
        and document.get("cleanup") == cleanup
        and document.get("redacted") is True
        and document.get("secretAudit")
        == {"tokenPresent": False, "rawMarkerPresent": False}
        and document.get("evidence")
        == {"path": str(NOTION_VERIFY_EVIDENCE), "mode": "0600"}
        and not _raw_notion_material_present(document, values),
        "notion_connector_evidence_invalid",
    )
    return document, findings


def _c029_integration_evidence() -> tuple[dict | None, list[dict]]:
    """Validate the single reviewed data/content profile's C029 attestation."""
    document, findings = _bound_evidence(
        C029_INTEGRATION_EVIDENCE,
        kind="IntegrationCanaryEvidence",
        status="passed",
        time_fields=("generatedAt",),
        canonical_field=("canonicalSourceSha256",),
        producer_field=("producerSha256",),
        producer_path=SERVER_INTEGRATION_SOURCE,
    )
    if document is None:
        return None, findings
    rows = (
        document.get("canaries") if isinstance(document.get("canaries"), list) else []
    )
    row = rows[0] if len(rows) == 1 and isinstance(rows[0], dict) else {}
    profile = row.get("dataContentProfile")
    values, canonical_findings = dotenv(CANONICAL_ENV)
    findings.extend(canonical_findings)
    findings.extend(_notion_projection_canary_findings())
    findings.extend(_notion_projection_consumer_findings())
    findings.extend(_postgrest_verify_findings("postgres-notion"))
    expected_dependency = {
        "path": str(NOTION_PROJECTION_CANARY_EVIDENCE),
        "sha256": _sha256_file(NOTION_PROJECTION_CANARY_EVIDENCE),
        "kind": "NotionProjectionLiveCanary",
        "producerSha256": _sha256_file(SERVER_NOTION_PROJECTION_SOURCE),
    }
    expected_consumer_verification = {
        "path": str(NOTION_PROJECTION_VERIFY_EVIDENCE),
        "sha256": _sha256_file(NOTION_PROJECTION_VERIFY_EVIDENCE),
        "kind": "NotionProjectionConsumerVerification",
        "producerSha256": _sha256_file(SERVER_NOTION_PROJECTION_SOURCE),
    }
    _expect(
        findings,
        set(document)
        == {
            "apiVersion",
            "kind",
            "generatedAt",
            "runId",
            "dataContentProfile",
            "canonicalSourceSha256",
            "producerSha256",
            "ok",
            "status",
            "selected",
            "canaries",
        }
        and document.get("ok") is True
        and document.get("dataContentProfile") == "postgres-notion"
        and profile == "postgres-notion"
        and document.get("selected") == ["C029"]
        and len(rows) == 1
        and _notion_c029_row_valid(row)
        and row.get("dependencyEvidence") == expected_dependency
        and row.get("consumerVerificationEvidence") == expected_consumer_verification
        and not _raw_notion_material_present(document, values),
        "data_content_persistence_evidence_invalid",
    )
    return document, findings


def _ose_provision_connection_proofs(requested: set[str]) -> dict[str, dict]:
    """Prove C036 from the active PostgREST and Notion connectors."""
    if "C036" not in requested:
        return {}
    findings: list[dict] = []
    if CANONICAL_ENV.is_file():
        values, canonical_findings = dotenv(CANONICAL_ENV)
        findings.extend(canonical_findings)
    else:
        values = {}
        findings.append(
            {"finding": "canonical_env_missing", "path": str(CANONICAL_ENV)}
        )
    profile = values.get("DATA_CONTENT_PROFILE", "")
    _expect(findings, profile == "postgres-notion", "data_content_profile_unsupported")
    findings.extend(_data_content_projection_contract_findings(profile))
    findings.extend(_postgrest_verify_findings(profile))
    _notion, notion_findings = _notion_connector_evidence()
    findings.extend(notion_findings)
    return {
        "C036": _connection_result(
            "C036",
            findings,
            evidence=NOTION_VERIFY_EVIDENCE,
            details={
                "postgrestEvidence": str(POSTGREST_VERIFY_EVIDENCE),
                "notionEvidence": str(NOTION_VERIFY_EVIDENCE),
                "dataContentProjection": str(DATA_CONTENT_PLANE),
            },
        )
    }


def _toolhive_gateway_audit_findings(audit: dict | None) -> list[dict]:
    findings: list[dict] = []
    if not isinstance(audit, dict):
        return [{"finding": "e2e_toolhive_gateway_audit_missing"}]
    allowed_profile_fields = {
        "profileRef",
        "bundleId",
        "workloadId",
        "endpointRef",
        "credentialRef",
        "runnerOrigin",
        "initialize",
        "toolsList",
        "toolName",
        "canaryCall",
        "markerSha256",
        "httpStatus",
        "wrongProfileEndpointRef",
        "wrongProfileDenied",
        "wrongProfileStatus",
        "gatewayReachableHost",
        "gatewayReachablePort",
        "gatewayUpstreamRef",
        "gatewayUpstreamHost",
        "gatewayUpstreamPort",
    }
    profiles = audit.get("profiles") if isinstance(audit.get("profiles"), list) else []
    runtime_network = (
        audit.get("runtimeNetworkProof")
        if isinstance(audit.get("runtimeNetworkProof"), dict)
        else {}
    )
    daytona_document, daytona_findings = _daytona_control_plane_evidence()
    findings.extend(daytona_findings)
    _expect(
        findings,
        isinstance(daytona_document, dict),
        "daytona_compose_control_plane_missing",
    )
    values, canonical_findings = dotenv(CANONICAL_ENV)
    findings.extend(canonical_findings)
    expected_upstreams = {
        "coding-daytona-codex": (
            "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM",
            19011,
        ),
        "coding-daytona-claude": (
            "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_UPSTREAM",
            19012,
        ),
        "coding-daytona-pi": (
            "MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM",
            19013,
        ),
    }
    _expect(
        findings,
        audit.get("status") == "passed"
        and _fresh_field(audit, ("generatedAt",))
        and audit.get("canonicalSourceSha256") == _canonical_sha256()
        and audit.get("gatewayProducerPath") == str(SERVER_AGENT_GATEWAY_SOURCE)
        and audit.get("gatewayProducerSha256")
        == _sha256_file(SERVER_AGENT_GATEWAY_SOURCE)
        and audit.get("profileReconcileEvidencePath") == str(PROFILE_RECONCILE_EVIDENCE)
        and audit.get("profileReconcileEvidenceSha256")
        == _sha256_file(PROFILE_RECONCILE_EVIDENCE)
        and audit.get("profileReconcileProducerPath")
        == str(SERVER_PROFILE_RECONCILE_SOURCE)
        and audit.get("profileReconcileProducerSha256")
        == _sha256_file(SERVER_PROFILE_RECONCILE_SOURCE)
        and audit.get("gatewayRuntimeNetwork") == values.get("MTE_TOOL_RUNTIME_NETWORK")
        and audit.get("daytonaStepPath") == str(PAPERCLIP_DAYTONA_STEP_SOURCE)
        and audit.get("daytonaStepSha256")
        == _sha256_file(PAPERCLIP_DAYTONA_STEP_SOURCE)
        and audit.get("daytonaGatewayEvidencePath")
        == str(PAPERCLIP_DAYTONA_CONTROL_PLANE_EVIDENCE)
        and audit.get("daytonaGatewayEvidenceSha256")
        == _sha256_file(PAPERCLIP_DAYTONA_CONTROL_PLANE_EVIDENCE),
        "e2e_toolhive_gateway_audit_provenance_invalid",
    )
    _expect(
        findings,
        set(runtime_network)
        == {
            "runnerContainer": "mte-daytona-runner",
            "gatewayContainer": "mte-agent-plane-gateway",
            "runnerContainerId": None,
            "gatewayContainerId": None,
            "runnerNetworkNames": None,
            "gatewaySharesRunnerNamespace": True,
            "publishedPorts": [],
            "canonicalEnvironmentMounted": False,
            "mountInventorySha256": None,
        }.keys()
        and runtime_network.get("runnerContainer") == "mte-daytona-runner"
        and runtime_network.get("gatewayContainer") == "mte-agent-plane-gateway"
        and _is_full_sha256(runtime_network.get("runnerContainerId"))
        and _is_full_sha256(runtime_network.get("gatewayContainerId"))
        and runtime_network.get("runnerNetworkNames")
        == [
            values.get("MTE_AGENT_PLANE_NETWORK"),
            values.get("MTE_DAYTONA_NETWORK"),
            values.get("MTE_TOOL_RUNTIME_NETWORK"),
        ]
        and runtime_network.get("gatewaySharesRunnerNamespace") is True
        and runtime_network.get("publishedPorts") == []
        and runtime_network.get("canonicalEnvironmentMounted") is False
        and _is_full_sha256(runtime_network.get("mountInventorySha256")),
        "e2e_toolhive_private_runtime_network_invalid",
    )
    _expect(
        findings,
        len(profiles) == len(R1_E2E_HARNESS_PROFILES)
        and all(isinstance(row, dict) for row in profiles)
        and [row.get("profileRef") for row in profiles] == list(R1_E2E_HARNESS_PROFILES)
        and all(set(row) == allowed_profile_fields for row in profiles)
        and all(
            row.get("gatewayUpstreamRef") == expected_upstreams[row["profileRef"]][0]
            and row.get("gatewayUpstreamHost") == "toolhive"
            and row.get("gatewayUpstreamPort")
            == expected_upstreams[row["profileRef"]][1]
            and values.get(row["gatewayUpstreamRef"])
            == f"http://toolhive:{row['gatewayUpstreamPort']}"
            for row in profiles
        ),
        "e2e_toolhive_gateway_audit_profile_set_invalid",
    )
    return findings


def _e2e_document() -> tuple[dict | None, list[dict]]:
    findings: list[dict] = []
    document = _json_object(E2E_EVIDENCE)
    if document is None:
        return None, [{"finding": "e2e_evidence_missing_or_invalid"}]
    _expect(findings, _mode_is_0600(E2E_EVIDENCE), "e2e_evidence_mode_invalid")
    _expect(
        findings,
        document.get("apiVersion") == "micro-task-engine/v1alpha1"
        and document.get("kind") == "KestraPaperclipGitHubE2E"
        and document.get("status") == "passed",
        "e2e_envelope_invalid",
    )
    _expect(
        findings,
        _fresh_field(document, ("finishedAt",)),
        "e2e_evidence_stale_or_timestamp_missing",
    )
    sources = (
        document.get("sources") if isinstance(document.get("sources"), dict) else {}
    )
    for key, path in E2E_SOURCE_PATHS.items():
        _expect(
            findings,
            _sha256_file(path) is not None and sources.get(key) == _sha256_file(path),
            "e2e_source_hash_mismatch",
            source=key,
        )
    runs = document.get("runs") if isinstance(document.get("runs"), list) else []
    _expect(
        findings,
        [row.get("profile") for row in runs if isinstance(row, dict)]
        == list(R1_E2E_HARNESS_PROFILES),
        "e2e_profile_run_set_mismatch",
    )
    audit = (
        document.get("toolhiveGatewayAudit")
        if isinstance(document.get("toolhiveGatewayAudit"), dict)
        else None
    )
    findings.extend(_toolhive_gateway_audit_findings(audit))
    verification, verification_findings = _bound_evidence(
        E2E_VERIFY_EVIDENCE,
        kind="KestraPaperclipGitHubE2EVerification",
        status="passed",
        time_fields=("verifiedAt",),
        canonical_field=("canonicalSourceSha256",),
        producer_field=("producerSha256",),
        producer_path=SERVER_E2E_SOURCE,
    )
    findings.extend(verification_findings)
    if verification is not None:
        verified_runs = (
            verification.get("runs")
            if isinstance(verification.get("runs"), list)
            else []
        )
        _expect(
            findings,
            verification.get("producerPath") == str(SERVER_E2E_SOURCE)
            and verification.get("subjectEvidencePath") == str(E2E_EVIDENCE)
            and verification.get("subjectEvidenceSha256") == _sha256_file(E2E_EVIDENCE)
            and verification.get("sources") == sources
            and verification.get("cleanupVerified") is True,
            "e2e_live_verification_subject_invalid",
        )
        _expect(
            findings,
            len(verified_runs) == len(R1_E2E_HARNESS_PROFILES)
            and all(isinstance(row, dict) for row in verified_runs)
            and [row.get("profile") for row in verified_runs]
            == list(R1_E2E_HARNESS_PROFILES)
            and all(
                bool(row.get("executionId"))
                and bool(row.get("paperclipIssueId"))
                and bool(row.get("pullRequestUrl"))
                and bool(re.fullmatch(r"[0-9a-f]{40}", str(row.get("commitSha") or "")))
                and bool(row.get("checkConclusions"))
                and all(value == "success" for value in row.get("checkConclusions", []))
                and row.get("semanticCheck") == "harness-scoped-router-auth"
                and row.get("toolhiveSemanticCheck") == "runner-toolhive-profile"
                and bool(row.get("routerServerRequestIds"))
                and _nested(row, "resourceCleanup", "daytonaSandboxAbsent") is True
                for row in verified_runs
            )
            and all(
                row.get("executionId") == _nested(runs[index], "execution", "id")
                and row.get("paperclipIssueId")
                == _nested(runs[index], "paperclip", "issueId")
                and row.get("claimLeaseId")
                == _nested(runs[index], "paperclip", "claim", "leaseId")
                for index, row in enumerate(verified_runs)
            ),
            "e2e_live_verification_runs_invalid",
        )
        verification_audit = (
            verification.get("toolhiveGatewayAudit")
            if isinstance(verification.get("toolhiveGatewayAudit"), dict)
            else None
        )
        findings.extend(_toolhive_gateway_audit_findings(verification_audit))
        _expect(
            findings,
            isinstance(audit, dict)
            and isinstance(verification_audit, dict)
            and {key: value for key, value in audit.items() if key != "generatedAt"}
            == {
                key: value
                for key, value in verification_audit.items()
                if key != "generatedAt"
            },
            "e2e_toolhive_gateway_audit_verification_mismatch",
        )
    bundle = _json_object(E2E_PORTABLE_BUNDLE)
    _expect(
        findings,
        isinstance(bundle, dict) and _mode_is_0600(E2E_PORTABLE_BUNDLE),
        "e2e_portable_bundle_missing_or_invalid",
    )
    if isinstance(bundle, dict):
        bundle_documents = (
            bundle.get("documents") if isinstance(bundle.get("documents"), dict) else {}
        )
        expected_documents = {"apply.json": _portable_e2e_redaction(document)}
        if verification is not None:
            expected_documents["verify.json"] = _portable_e2e_redaction(verification)
        expected_hashes = {
            name: _canonical_json_sha256(value)
            for name, value in expected_documents.items()
        }
        expected_bundle_hash = _canonical_json_sha256(
            {
                "documents": expected_documents,
                "documentSha256": expected_hashes,
                "sourceSha256": {
                    "canonical": _sha256_file(CANONICAL_ENV),
                    "producer": _sha256_file(SERVER_E2E_SOURCE),
                },
            }
        )
        _expect(
            findings,
            bundle.get("apiVersion") == "micro-task-engine/v1alpha1"
            and bundle.get("kind") == "PortableKestraPaperclipGitHubE2EEvidenceBundle"
            and bundle.get("schemaVersion")
            == "paperclip-agent-platform/e2e-evidence/v2"
            and bundle.get("status") == "passed"
            and _fresh_field(bundle, ("generatedAt",))
            and bundle.get("redaction")
            == {
                "status": "passed",
                "hostPathsReplaced": True,
                "rawSecretsPresent": False,
                "canonicalEnvironmentIncluded": False,
            }
            and bundle_documents == expected_documents
            and bundle.get("documentSha256") == expected_hashes
            and bundle.get("sourceSha256")
            == {
                "canonical": _sha256_file(CANONICAL_ENV),
                "producer": _sha256_file(SERVER_E2E_SOURCE),
            }
            and bundle.get("bundleSha256") == expected_bundle_hash,
            "e2e_portable_bundle_contract_invalid",
        )
    return document, findings


def _e2e_connection_proofs(requested: set[str]) -> dict[str, dict]:
    ids = requested & {
        "C001",
        "C002",
        "C003",
        "C008",
        "C010",
        "C017",
        "C018",
        "C073",
        "C075",
        "C076",
        "C077",
        "C078",
        "C079",
        "C080",
    }
    if not ids:
        return {}
    document, envelope = _e2e_document()
    if document is None or envelope:
        return {
            connection_id: _connection_result(
                connection_id, list(envelope), evidence=E2E_EVIDENCE
            )
            for connection_id in ids
        }
    runs = [row for row in document.get("runs", []) if isinstance(row, dict)]
    cleanup = (
        document.get("cleanup") if isinstance(document.get("cleanup"), dict) else {}
    )
    cleanup_rows = [row for row in cleanup.get("runs", []) if isinstance(row, dict)]
    results: dict[str, dict] = {}

    def all_runs(predicate) -> bool:
        return len(runs) == len(R1_E2E_HARNESS_PROFILES) and all(
            predicate(row) for row in runs
        )

    def full_sha256(value: object) -> bool:
        return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))

    def parsed_time(value: object) -> datetime.datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            result = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return result if result.tzinfo is not None else None

    def valid_c003(row: dict) -> bool:
        paperclip = (
            row.get("paperclip") if isinstance(row.get("paperclip"), dict) else {}
        )
        claim = (
            paperclip.get("claim") if isinstance(paperclip.get("claim"), dict) else {}
        )
        claimant = (
            claim.get("claimant") if isinstance(claim.get("claimant"), dict) else {}
        )
        proof = (
            paperclip.get("heartbeatProof")
            if isinstance(paperclip.get("heartbeatProof"), dict)
            else {}
        )
        final = (
            paperclip.get("finalResult")
            if isinstance(paperclip.get("finalResult"), dict)
            else {}
        )
        events = paperclip.get("heartbeats")
        if (
            not isinstance(events, list)
            or len(events) < 3
            or any(not isinstance(event, dict) for event in events)
        ):
            return False
        run_id = paperclip.get("heartbeatRunId")
        runner_id = claimant.get("id")
        sequences: list[int] = []
        times: list[datetime.datetime] = []
        phases: list[str] = []
        for event in events:
            sequence = event.get("seq")
            moment = parsed_time(event.get("createdAt"))
            if (
                not isinstance(sequence, int)
                or isinstance(sequence, bool)
                or moment is None
                or event.get("runId") != run_id
                or event.get("runnerId") != runner_id
            ):
                return False
            sequences.append(sequence)
            times.append(moment)
            phases.append(str(event.get("phase") or ""))
        return (
            bool(run_id)
            and bool(runner_id)
            and proof.get("status") == "passed"
            and proof.get("runId") == run_id
            and proof.get("runnerId") == runner_id
            and claim.get("token") is None
            and sequences == sorted(set(sequences))
            and all(current > previous for previous, current in zip(times, times[1:]))
            and phases[0] == "started"
            and "in_progress" in phases[1:-1]
            and phases[-1] == "terminal"
            and events[-1].get("status") == "succeeded"
            and paperclip.get("heartbeatStatus") == "succeeded"
            and final.get("status") == "succeeded"
            and final.get("nativeStatus") == "succeeded"
            and final.get("source") == "paperclip.heartbeat-run"
            and final.get("runId") == run_id
            and final.get("runnerId") == runner_id
            and parsed_time(final.get("recordedAt")) is not None
            and parsed_time(final.get("recordedAt")) >= times[-1]
            and final.get("recordFingerprintSha256")
            == hashlib.sha256(
                json.dumps(
                    {
                        "recordedAt": final.get("recordedAt"),
                        "runId": final.get("runId"),
                        "runnerId": final.get("runnerId"),
                        "source": final.get("source"),
                        "status": final.get("status"),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            and parsed_time(claim.get("firstHeartbeatAt")) == times[0]
        )

    profiles_document = _profile_catalog_object(E2E_PROFILES) or {}
    profile_rows = profiles_document.get("profiles")
    profile_access = {
        str(item.get("ref")): item.get("toolAccess")
        for item in (profile_rows if isinstance(profile_rows, list) else [])
        if isinstance(item, dict)
        and item.get("ref")
        and isinstance(item.get("toolAccess"), dict)
    }

    def valid_c010(row: dict) -> bool:
        profile = str(row.get("profile") or "")
        semantic = _nested(row, "semanticChecks", "runner-toolhive-profile")
        access = profile_access.get(profile)
        if not isinstance(semantic, dict) or not isinstance(access, dict):
            return False
        endpoint_ref = str(access.get("endpointRef") or "")
        endpoint_value = canonical_values.get(endpoint_ref, "")
        parsed_endpoint = urllib.parse.urlsplit(endpoint_value)
        credential_ref = str(access.get("credentialRef") or "")
        wrong_profile_endpoint_ref = {
            "coding-daytona-codex": "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_URL",
            "coding-daytona-claude": "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL",
            "coding-daytona-pi": "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
        }.get(profile)
        return (
            not canonical_findings
            and semantic.get("check") == "runner-toolhive-profile"
            and semantic.get("status") == "passed"
            and semantic.get("profileRef") == profile
            and semantic.get("runId") == _nested(row, "paperclip", "issueId")
            and semantic.get("bundleId") == access.get("bundleId")
            and semantic.get("workloadId") == access.get("workloadId")
            and semantic.get("endpointRef") == endpoint_ref
            and semantic.get("runtimeEndpointEnv") == endpoint_ref
            and bool(endpoint_value)
            and semantic.get("endpointSha256")
            == hashlib.sha256(endpoint_value.encode()).hexdigest()
            and semantic.get("credentialRef") == credential_ref
            and bool(canonical_values.get(credential_ref, ""))
            and semantic.get("bearerRuntimeEnv") == "MTE_TOOLHIVE_BEARER_TOKEN"
            and semantic.get("canaryTool") == access.get("canaryTool") == "echo"
            and semantic.get("runnerOrigin") == "daytona"
            and semantic.get("toolName") == "echo"
            and semantic.get("initialize") is True
            and semantic.get("toolsList") is True
            and semantic.get("canaryCall") is True
            and semantic.get("httpStatus") == 200
            and semantic.get("unauthorizedStatus") == 401
            and semantic.get("wrongProfileEndpointRef") == wrong_profile_endpoint_ref
            and bool(canonical_values.get(str(wrong_profile_endpoint_ref or ""), ""))
            and semantic.get("wrongProfileDenied") is True
            and semantic.get("wrongProfileStatus") == 401
            and semantic.get("gatewayReachableHost") == parsed_endpoint.hostname
            and semantic.get("gatewayReachablePort") == parsed_endpoint.port
            and semantic.get("credentialLeak") is False
            and all(
                full_sha256(semantic.get(key))
                for key in ("markerSha256", "toolsListSha256", "resultSha256")
            )
        )

    def c010_audit_row(row: dict) -> dict:
        semantic = _nested(row, "semanticChecks", "runner-toolhive-profile")
        if not isinstance(semantic, dict):
            return {}
        result = {
            key: semantic.get(key)
            for key in (
                "profileRef",
                "bundleId",
                "workloadId",
                "endpointRef",
                "credentialRef",
                "runnerOrigin",
                "initialize",
                "toolsList",
                "toolName",
                "canaryCall",
                "markerSha256",
                "httpStatus",
                "wrongProfileEndpointRef",
                "wrongProfileDenied",
                "wrongProfileStatus",
                "gatewayReachableHost",
                "gatewayReachablePort",
            )
        }
        profile = str(semantic.get("profileRef") or "")
        harness = {
            "coding-daytona-codex": "CODEX",
            "coding-daytona-claude": "CLAUDE",
            "coding-daytona-pi": "PI",
        }.get(profile, "")
        upstream_ref = (
            f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_UPSTREAM" if harness else ""
        )
        upstream = urllib.parse.urlsplit(canonical_values.get(upstream_ref, ""))
        result.update(
            {
                "gatewayUpstreamRef": upstream_ref,
                "gatewayUpstreamHost": upstream.hostname,
                "gatewayUpstreamPort": upstream.port,
            }
        )
        return result

    canonical_values, canonical_findings = dotenv(CANONICAL_ENV)

    def valid_c077(row: dict) -> bool:
        profile = str(row.get("profile") or "")
        proof = _nested(row, "semanticChecks", "server-attributed-router")
        key_ref = _profile_key_ref(profile)
        scoped_key = canonical_values.get(key_ref, "")
        request_ids = proof.get("requestIds") if isinstance(proof, dict) else None
        request_hashes = (
            proof.get("requestFingerprintsSha256") if isinstance(proof, dict) else None
        )
        request_binding = (
            proof.get("requestBinding")
            if isinstance(proof, dict) and isinstance(proof.get("requestBinding"), dict)
            else {}
        )
        correlation_nonce = f"kestra:{_nested(row, 'execution', 'id')}"
        expected_endpoint = {
            "coding-daytona-codex": "/v1/responses",
            "coding-daytona-claude": "/v1/messages",
            "coding-daytona-pi": "/v1/chat/completions",
        }.get(profile)
        return (
            not canonical_findings
            and isinstance(proof, dict)
            and proof == _nested(row, "router", "serverAttribution")
            and proof.get("status") == "passed"
            and proof.get("source") == "9router.sqlite.usageHistory"
            and proof.get("profileRef") == profile
            and proof.get("profileKeyRef") == key_ref
            and bool(scoped_key)
            and proof.get("profileKeyFingerprintSha256")
            == hashlib.sha256(scoped_key.encode()).hexdigest()
            and isinstance(proof.get("historyIdBefore"), int)
            and isinstance(proof.get("historyIdAfter"), int)
            and proof.get("historyIdAfter") > proof.get("historyIdBefore")
            and isinstance(request_ids, list)
            and bool(request_ids)
            and all(
                isinstance(value, int)
                and not isinstance(value, bool)
                and proof.get("historyIdBefore") < value <= proof.get("historyIdAfter")
                for value in request_ids
            )
            and request_ids == sorted(set(request_ids))
            and proof.get("requestCount") == len(request_ids)
            and isinstance(request_hashes, list)
            and len(request_hashes) == len(request_ids)
            and all(full_sha256(value) for value in request_hashes)
            and proof.get("connectionId")
            == canonical_values.get("NINEROUTER_MINIMAX_CONNECTION_ID")
            and proof.get("connectionName") == "mte-minimax-primary"
            and isinstance(proof.get("provider"), str)
            and bool(proof.get("provider"))
            and isinstance(proof.get("model"), str)
            and bool(proof.get("model"))
            and proof.get("expectedEndpoint") == expected_endpoint
            and expected_endpoint in (proof.get("observedEndpoints") or [])
            and proof.get("statuses") == ["ok"]
            and parsed_time(proof.get("firstRequestAt")) is not None
            and parsed_time(proof.get("lastRequestAt")) is not None
            and request_binding.get("status") == "passed"
            and request_binding.get("source") == "9router.sqlite.requestDetails"
            and isinstance(request_binding.get("detailCount"), int)
            and request_binding.get("detailCount") > 0
            and isinstance(request_binding.get("detailDataSha256"), list)
            and len(request_binding.get("detailDataSha256"))
            == request_binding.get("detailCount")
            and all(
                full_sha256(value) for value in request_binding.get("detailDataSha256")
            )
            and request_binding.get("usageRequestIds") == request_ids
            and isinstance(request_binding.get("correlatedUsageHistoryIds"), list)
            and bool(request_binding.get("correlatedUsageHistoryIds"))
            and set(request_binding.get("correlatedUsageHistoryIds"))
            <= set(request_ids)
            and isinstance(request_binding.get("tokenUsages"), list)
            and bool(request_binding.get("tokenUsages"))
            and all(
                isinstance(usage, dict)
                and isinstance(usage.get("inputTokens"), int)
                and usage.get("inputTokens") > 0
                and isinstance(usage.get("outputTokens"), int)
                and usage.get("outputTokens") > 0
                and usage.get("totalTokens")
                == usage.get("inputTokens") + usage.get("outputTokens")
                for usage in request_binding.get("tokenUsages")
            )
            and isinstance(request_binding.get("completionFingerprintsSha256"), list)
            and bool(request_binding.get("completionFingerprintsSha256"))
            and all(
                full_sha256(value)
                for value in request_binding.get("completionFingerprintsSha256")
            )
            and request_binding.get("correlationNonceSha256")
            == hashlib.sha256(correlation_nonce.encode()).hexdigest()
            and isinstance(request_binding.get("correlatedDetailCount"), int)
            and request_binding.get("correlatedDetailCount") > 0
            and isinstance(request_binding.get("correlatedDetailDataSha256"), list)
            and len(request_binding.get("correlatedDetailDataSha256"))
            == request_binding.get("correlatedDetailCount")
            and all(
                full_sha256(value)
                for value in request_binding.get("correlatedDetailDataSha256")
            )
        )

    def harness_artifact(row: dict) -> dict | None:
        artifacts = _nested(row, "paperclip", "artifacts")
        if not isinstance(artifacts, list):
            return None
        matches = [
            item
            for item in artifacts
            if isinstance(item, dict)
            and item.get("name") == "harness-evidence"
            and isinstance(item.get("content"), str)
        ]
        if len(matches) != 1:
            return None
        try:
            value = json.loads(matches[0]["content"])
        except json.JSONDecodeError:
            return None
        return value if isinstance(value, dict) else None

    def valid_github_controller_oracle(row: dict) -> bool:
        proof = _nested(row, "github", "proof")
        if not isinstance(proof, dict):
            return False
        identity = proof.get("controllerArtifactIdentity")
        files = proof.get("files") if isinstance(proof.get("files"), list) else []
        checks = proof.get("checks") if isinstance(proof.get("checks"), list) else []
        required_checks = [
            item
            for item in checks
            if isinstance(item, dict)
            and item.get("name") == "paperclip-e2e"
            and item.get("app")
            == {"id": 15368, "slug": "github-actions", "name": "GitHub Actions"}
        ]
        semantic = {
            "markerFunction": "marker",
            "markerValueSha256": hashlib.sha256(b"PAPERCLIP_DAYTONA_E2E").hexdigest(),
            "workflowName": "paperclip-e2e",
            "jobId": "paperclip-e2e",
            "jobName": "paperclip-e2e",
            "testCommand": "cd paperclip-e2e && python -m unittest test_marker.py",
            "testCallsMarker": True,
        }
        semantic["identitySha256"] = _canonical_json_sha256(semantic)
        return (
            identity == semantic
            and len(files) == 3
            and {item.get("path") for item in files if isinstance(item, dict)}
            == {
                ".github/workflows/paperclip-e2e.yml",
                "paperclip-e2e/marker.py",
                "paperclip-e2e/test_marker.py",
            }
            and all(
                isinstance(item, dict)
                and full_sha256(item.get("contentSha256"))
                and full_sha256(item.get("patchSha256"))
                for item in files
            )
            and checks == _nested(row, "github", "checks")
            and bool(checks)
            and len(required_checks) == 1
            and all(
                isinstance(item, dict)
                and isinstance(item.get("name"), str)
                and bool(item.get("name"))
                and item.get("status") == "completed"
                and item.get("conclusion") == "success"
                and isinstance(item.get("app"), dict)
                and isinstance(item["app"].get("id"), int)
                and item["app"].get("id") > 0
                and bool(item["app"].get("slug"))
                and bool(item["app"].get("name"))
                for item in checks
            )
        )

    def valid_c073(row: dict) -> bool:
        environment = _nested(row, "paperclip", "environment")
        artifact = harness_artifact(row)
        operation = _nested(row, "paperclip", "workspaceOperation")
        projection = (
            operation.get("credentialProjection")
            if isinstance(operation, dict)
            and isinstance(operation.get("credentialProjection"), dict)
            else {}
        )
        if (
            not isinstance(environment, dict)
            or not isinstance(artifact, dict)
            or not isinstance(operation, dict)
        ):
            return False
        return (
            environment.get("provider") == "daytona"
            and all(
                isinstance(environment.get(key), str) and bool(environment.get(key))
                for key in (
                    "sandboxId",
                    "executionWorkspaceId",
                    "environmentLeaseId",
                    "providerLeaseId",
                    "remoteCwd",
                )
            )
            and artifact.get("profileRef") == row.get("profile")
            and _nested(artifact, "daytona", "provider") == "daytona"
            and _nested(artifact, "daytona", "sandboxId")
            == environment.get("sandboxId")
            and bool(_nested(artifact, "localTest", "command"))
            and _nested(artifact, "localTest", "exitCode") == 0
            and operation.get("status") == "passed"
            and operation.get("sandboxId") == environment.get("sandboxId")
            and operation.get("executionWorkspaceId")
            == environment.get("executionWorkspaceId")
            and operation.get("remoteCwd") == environment.get("remoteCwd")
            and operation.get("commitSha") == _nested(row, "github", "commitSha")
            and operation.get("directExecution") is True
            and operation.get("repositoryLauncherAbsent") is True
            and operation.get("operationFingerprintSha256")
            == _canonical_json_sha256(
                {
                    key: value
                    for key, value in operation.items()
                    if key != "operationFingerprintSha256"
                }
            )
            and projection.get("status") == "passed"
            and projection.get("sourceCanonicalSha256") == _canonical_sha256()
            and projection.get("allowlistedKeys")
            == ["DAYTONA_API_KEY", "MTE_DAYTONA_API_URL", "DAYTONA_TARGET"]
            and projection.get("allowlistedKeyCount") == 3
            and full_sha256(projection.get("projectionSha256"))
            and projection.get("projectionMode") == "0600"
            and projection.get("canonicalEnvironmentMounted") is False
            and projection.get("temporaryProjectionRemoved") is True
        )

    def valid_provider_cleanup(value: object) -> bool:
        if not isinstance(value, dict):
            return False
        lease_ids = value.get("leaseIds")
        successful = value.get("successfulLeaseIds")
        duplicates = value.get("duplicateTerminalLeaseIds")
        if not all(isinstance(item, list) for item in (lease_ids, successful, duplicates)):
            return False
        return (
            bool(value.get("providerLeaseId"))
            and bool(lease_ids)
            and bool(successful)
            and value.get("successfulExpiredLeaseObserved") is True
            and value.get("unexpectedLeaseIds") == []
            and not (set(successful) & set(duplicates))
            and (set(successful) | set(duplicates)) == set(lease_ids)
            and value.get("leaseGroupFingerprintSha256")
            == _canonical_json_sha256(
                {
                    key: item
                    for key, item in value.items()
                    if key != "leaseGroupFingerprintSha256"
                }
            )
        )

    def valid_c080_cleanup(row: dict) -> bool:
        profile = str(row.get("profile") or "")
        execution_id = str(row.get("executionId") or "")
        run = next(
            (
                item
                for item in runs
                if item.get("profile") == profile
                and _nested(item, "execution", "id") == execution_id
            ),
            None,
        )
        resources = (
            row.get("resources") if isinstance(row.get("resources"), dict) else {}
        )
        paperclip = (
            resources.get("paperclip")
            if isinstance(resources.get("paperclip"), dict)
            else {}
        )
        filesystem = (
            paperclip.get("filesystemProof")
            if isinstance(paperclip.get("filesystemProof"), dict)
            else {}
        )
        provider_cleanup = (
            paperclip.get("providerLeaseCleanup")
            if isinstance(paperclip.get("providerLeaseCleanup"), dict)
            else {}
        )
        provider_cleanups = (
            paperclip.get("providerLeaseCleanups")
            if isinstance(paperclip.get("providerLeaseCleanups"), list)
            else []
        )
        provider_resources = (
            _nested(resources, "daytona", "providerResources")
            if isinstance(_nested(resources, "daytona", "providerResources"), list)
            else []
        )
        attempts = (
            resources.get("cleanupAttempts")
            if isinstance(resources.get("cleanupAttempts"), dict)
            else {}
        )
        remote_cwd = resources.get("remoteCwd")
        remote_cwd_hash = resources.get("remoteCwdFingerprintSha256")
        worktree_path = resources.get("worktreePath")
        worktree_path_hash = resources.get("worktreePathFingerprintSha256")
        sandbox_id = resources.get("sandboxId")
        fingerprint_parts = (
            "daytona",
            resources.get("environmentLeaseId"),
            resources.get("providerLeaseId"),
            sandbox_id,
            resources.get("executionWorkspaceId"),
            remote_cwd,
            worktree_path,
        )
        return (
            isinstance(run, dict)
            and resources.get("completed") is True
            and resources.get("paperclipIssueId")
            == _nested(run, "paperclip", "issueId")
            and all(isinstance(value, str) and value for value in fingerprint_parts)
            and resources.get("resourceFingerprintSha256")
            == hashlib.sha256("|".join(fingerprint_parts).encode()).hexdigest()
            and isinstance(remote_cwd, str)
            and re.fullmatch(
                r"/home/daytona/paperclip-workspace(?:/[^/]+)*", remote_cwd
            )
            and ".." not in Path(remote_cwd).parts
            and full_sha256(remote_cwd_hash)
            and remote_cwd_hash == hashlib.sha256(remote_cwd.encode()).hexdigest()
            and isinstance(worktree_path, str)
            and re.fullmatch(
                r"/data/instances/default/projects/[^/]+/[^/]+/_default",
                worktree_path,
            )
            and ".." not in Path(worktree_path).parts
            and full_sha256(worktree_path_hash)
            and worktree_path_hash
            == hashlib.sha256(worktree_path.encode()).hexdigest()
            and resources.get("environmentLeaseId")
            == _nested(run, "paperclip", "environment", "environmentLeaseId")
            and resources.get("providerLeaseId")
            == _nested(run, "paperclip", "environment", "providerLeaseId")
            and resources.get("providerLeaseId") == sandbox_id
            and sandbox_id == _nested(run, "paperclip", "environment", "sandboxId")
            and resources.get("executionWorkspaceId")
            == _nested(run, "paperclip", "environment", "executionWorkspaceId")
            and paperclip.get("workspaceStatus") == "archived"
            and paperclip.get("workspaceApiObserved") is True
            and paperclip.get("worktreeAbsent") is True
            and paperclip.get("filesystemAbsenceVerified") is True
            and paperclip.get("environmentLeaseReleased") is True
            and valid_provider_cleanup(provider_cleanup)
            and provider_cleanup.get("providerLeaseId")
            == resources.get("providerLeaseId")
            and provider_cleanup.get("successfulExpiredLeaseObserved") is True
            and bool(provider_cleanups)
            and all(valid_provider_cleanup(group) for group in provider_cleanups)
            and bool(provider_resources)
            and len(provider_resources)
            == len(
                {
                    item.get("providerLeaseId")
                    for item in provider_resources
                    if isinstance(item, dict)
                }
            )
            and {
                group.get("providerLeaseId")
                for group in provider_cleanups
                if isinstance(group, dict)
            }
            == {
                item.get("providerLeaseId")
                for item in provider_resources
                if isinstance(item, dict)
            }
            and all(
                isinstance(item, dict)
                and item.get("sandboxId") == item.get("providerLeaseId")
                and item.get("providerGetStatus") == 404
                and item.get("sandboxAbsent") is True
                and item.get("providerLeaseCleanup") in provider_cleanups
                for item in provider_resources
            )
            and filesystem.get("method")
            == "canonical_paths_bound_to_released_workspace_and_absent_sandbox"
            and filesystem.get("workspaceFilesystemProbe") == "absent"
            and filesystem.get("remoteCwdFingerprintSha256") == remote_cwd_hash
            and filesystem.get("worktreePathFingerprintSha256")
            == worktree_path_hash
            and filesystem.get("sandboxId") == sandbox_id
            and filesystem.get("providerGetStatus") == 404
            and _nested(resources, "daytona", "sandboxAbsent") is True
            and _nested(resources, "daytona", "providerGetStatus") == 404
            and isinstance(attempts.get("paperclipDelete"), int)
            and attempts.get("paperclipDelete") > 0
            and isinstance(attempts.get("paperclipPoll"), int)
            and attempts.get("paperclipPoll") > 0
            and isinstance(attempts.get("daytonaDelete"), int)
            and attempts.get("daytonaDelete") >= 0
            and isinstance(attempts.get("daytonaPoll"), int)
            and attempts.get("daytonaPoll") > 0
        )

    def cleanup_scope_fingerprint(rows: list[dict]) -> str:
        provider_resources = [
            item
            for row in rows
            for item in (_nested(row, "resources", "daytona", "providerResources") or [])
            if isinstance(item, dict)
        ]
        return _canonical_json_sha256(
            {
                "sandboxIds": sorted(
                    str(item.get("sandboxId") or "") for item in provider_resources
                ),
                "providerLeaseIds": sorted(
                    str(item.get("providerLeaseId") or "")
                    for item in provider_resources
                ),
                "refs": sorted(str(row.get("branchRef") or "") for row in rows),
                "pullRequestNumbers": sorted(
                    int(row.get("pullRequestNumber"))
                    for row in rows
                    if isinstance(row.get("pullRequestNumber"), int)
                    and not isinstance(row.get("pullRequestNumber"), bool)
                ),
            }
        )

    for connection_id in ids:
        findings: list[dict] = []
        if connection_id == "C001":
            _expect(
                findings,
                all_runs(
                    lambda row: _nested(row, "execution", "state") == "SUCCESS"
                    and _nested(row, "paperclip", "status") == "succeeded"
                    and bool(_nested(row, "paperclip", "issueId"))
                    and bool(_nested(row, "paperclip", "heartbeatRunId"))
                ),
                "kestra_paperclip_task_canary_incomplete",
            )
        elif connection_id == "C002":
            _expect(
                findings,
                all_runs(
                    lambda row: bool(_nested(row, "paperclip", "claim", "leaseId"))
                    and _nested(row, "paperclip", "claim", "claimantCount") == 1
                    and _nested(row, "paperclip", "claim", "claimant", "type")
                    == "paperclip_agent"
                    and bool(_nested(row, "paperclip", "claim", "claimant", "id"))
                    and _nested(row, "paperclip", "claim", "claimant", "adapterType")
                    == {
                        "coding-daytona-codex": "codex_local",
                        "coding-daytona-claude": "claude_local",
                        "coding-daytona-pi": "pi_local",
                    }.get(str(row.get("profile") or ""))
                    and _nested(row, "paperclip", "claim", "token") is None
                    and parsed_time(_nested(row, "paperclip", "claim", "claimedAt"))
                    is not None
                    and parsed_time(
                        _nested(row, "paperclip", "claim", "firstHeartbeatAt")
                    )
                    is not None
                    and parsed_time(_nested(row, "paperclip", "claim", "claimedAt"))
                    < parsed_time(
                        _nested(row, "paperclip", "claim", "firstHeartbeatAt")
                    )
                ),
                "runner_claim_contract_incomplete",
            )
        elif connection_id == "C003":
            _expect(
                findings,
                all_runs(valid_c003),
                "three_heartbeats_and_final_result_not_proven",
            )
        elif connection_id in {"C008", "C017"}:
            _expect(
                findings,
                all_runs(
                    lambda row: all(
                        _positive_counter(_nested(row, "router", key))
                        for key in (
                            "profileKeyRequestsDelta",
                            "modelRequestsDelta",
                            "totalRequestsDelta",
                        )
                    )
                    and bool(_nested(row, "paperclip", "artifacts"))
                ),
                "scoped_real_llm_completion_not_proven",
            )
        elif connection_id == "C077":
            aggregate = _nested(document, "semanticChecks", "server-attributed-router")
            proofs = [
                _nested(row, "semanticChecks", "server-attributed-router")
                for row in runs
            ]
            request_sets = [
                set(proof.get("requestIds", [])) if isinstance(proof, dict) else set()
                for proof in proofs
            ]
            _expect(
                findings,
                all_runs(valid_c077)
                and isinstance(aggregate, dict)
                and aggregate.get("status") == "passed"
                and aggregate.get("requiredProfiles") == list(R1_E2E_HARNESS_PROFILES)
                and aggregate.get("runs") == proofs
                and all(
                    not (left & right)
                    for index, left in enumerate(request_sets)
                    for right in request_sets[index + 1 :]
                ),
                "server_side_router_attribution_not_proven",
            )
        elif connection_id == "C010":
            aggregate = _nested(document, "semanticChecks", "runner-toolhive-profile")
            gateway_audit = document.get("toolhiveGatewayAudit")
            _expect(
                findings,
                all_runs(valid_c010)
                and isinstance(aggregate, dict)
                and aggregate.get("status") == "passed"
                and aggregate.get("requiredProfiles") == list(R1_E2E_HARNESS_PROFILES)
                and aggregate.get("runs")
                == [
                    _nested(row, "semanticChecks", "runner-toolhive-profile")
                    for row in runs
                ]
                and isinstance(gateway_audit, dict)
                and gateway_audit.get("profiles")
                == [c010_audit_row(row) for row in runs],
                "runner_profile_toolhive_call_not_proven",
            )
        elif connection_id == "C018":
            strict = harness_scoped_router_auth_evidence()
            _expect(
                findings, strict.get("ok") is True, "harness_scoped_router_auth_invalid"
            )
        elif connection_id == "C073":
            _expect(
                findings,
                all_runs(valid_c073),
                "paperclip_workspace_identity_not_proven",
            )
        elif connection_id == "C075":
            _expect(
                findings,
                all_runs(
                    lambda row: _nested(
                        row, "semanticChecks", "harness-scoped-router-auth", "check"
                    )
                    == "harness-scoped-router-auth"
                    and _nested(
                        row,
                        "semanticChecks",
                        "harness-scoped-router-auth",
                        "status",
                    )
                    == "passed"
                    and _nested(
                        row,
                        "semanticChecks",
                        "harness-scoped-router-auth",
                        "evidenceSource",
                    )
                    == "9router-server-side-usage"
                    and _nested(
                        row,
                        "semanticChecks",
                        "harness-scoped-router-auth",
                        "profileRef",
                    )
                    == row.get("profile")
                    and _nested(
                        row,
                        "semanticChecks",
                        "harness-scoped-router-auth",
                        "routerProfileKeyRef",
                    )
                    == _profile_key_ref(str(row.get("profile") or ""))
                    and all(
                        _positive_counter(
                            _nested(
                                row,
                                "semanticChecks",
                                "harness-scoped-router-auth",
                                key,
                            )
                        )
                        for key in (
                            "profileKeyRequestsDelta",
                            "modelRequestsDelta",
                            "totalRequestsDelta",
                        )
                    )
                ),
                "paperclip_harness_profile_routing_not_proven",
            )
        elif connection_id == "C076":
            revisions = [_nested(row, "execution", "flowRevision") for row in runs]
            execution_ids = [_nested(row, "execution", "id") for row in runs]
            _expect(
                findings,
                _nested(document, "flow", "namespace") == "micro_task_engine.e2e"
                and _nested(document, "flow", "id") == "paperclip-github-e2e"
                and bool(_nested(document, "flow", "revision"))
                and all_runs(
                    lambda row: _nested(row, "execution", "state") == "SUCCESS"
                    and _nested(row, "execution", "namespace")
                    == "micro_task_engine.e2e"
                    and _nested(row, "execution", "flowId") == "paperclip-github-e2e"
                )
                and len(set(execution_ids)) == len(R1_E2E_HARNESS_PROFILES)
                and all(
                    revision == _nested(document, "flow", "revision")
                    for revision in revisions
                ),
                "kestra_e2e_flow_not_proven",
            )
        elif connection_id == "C078":
            branches = [_nested(row, "github", "branch") for row in runs]
            commits = [_nested(row, "github", "commitSha") for row in runs]
            pull_numbers = [
                _nested(row, "github", "pullRequest", "number") for row in runs
            ]
            _expect(
                findings,
                all_runs(
                    lambda row: (
                        bool(_nested(row, "github", "branch"))
                        and bool(_nested(row, "github", "commitSha"))
                        and isinstance(
                            _nested(row, "github", "pullRequest", "number"), int
                        )
                        and bool(_nested(row, "github", "pullRequest", "url"))
                        and _nested(row, "github", "pullRequest", "draftAtCapture")
                        is True
                        and _nested(row, "execution", "outputs", "commit_sha")
                        == _nested(row, "github", "commitSha")
                        and _nested(row, "execution", "outputs", "pull_request_url")
                        == _nested(row, "github", "pullRequest", "url")
                        and isinstance(harness_artifact(row), dict)
                        and harness_artifact(row).get("branch")
                        == _nested(row, "github", "branch")
                        and harness_artifact(row).get("commitSha")
                        == _nested(row, "github", "commitSha")
                        and _nested(harness_artifact(row), "pullRequest", "number")
                        == _nested(row, "github", "pullRequest", "number")
                        and valid_github_controller_oracle(row)
                    )
                ),
                # The release gate proves every declared R1 run, then verifies
                # that its GitHub identities are not reused.
                "github_draft_pr_not_proven",
            )
            _expect(
                findings,
                len(set(branches))
                == len(set(commits))
                == len(set(pull_numbers))
                == len(R1_E2E_HARNESS_PROFILES),
                "github_e2e_run_identity_not_distinct",
            )
        elif connection_id == "C079":
            _expect(
                findings,
                all_runs(
                    lambda row: _nested(row, "execution", "state") == "SUCCESS"
                    and isinstance(_nested(row, "github", "checks"), list)
                    and bool(_nested(row, "github", "checks"))
                    and all(
                        isinstance(item, dict)
                        for item in _nested(row, "github", "checks")
                    )
                    and all(
                        item.get("status") == "completed"
                        and item.get("conclusion") == "success"
                        and bool(item.get("name"))
                        and isinstance(item.get("app"), dict)
                        for item in _nested(row, "github", "checks")
                    )
                    and valid_github_controller_oracle(row)
                ),
                "github_checks_to_kestra_terminal_not_proven",
            )
        elif connection_id == "C080":
            global_absence = (
                cleanup.get("globalAbsence")
                if isinstance(cleanup.get("globalAbsence"), dict)
                else {}
            )
            provider_resource_count = sum(
                len(_nested(row, "resources", "daytona", "providerResources") or [])
                for row in cleanup_rows
            )
            _expect(
                findings,
                cleanup.get("completed") is True
                and global_absence.get("status") == "passed"
                and global_absence.get("scope") == "exact-run-owned-identities"
                and global_absence.get("scopeFingerprintSha256")
                == cleanup_scope_fingerprint(cleanup_rows)
                and global_absence.get("ownedResourceCount")
                == provider_resource_count
                and global_absence.get("unrelatedParallelResourcesIgnored") is True
                and full_sha256(global_absence.get("daytonaLabelFingerprintSha256"))
                and global_absence.get("daytonaSandboxIds") == []
                and global_absence.get("paperclipProviderLeaseIds")
                == sorted(
                    str(item.get("providerLeaseId") or "")
                    for row in cleanup_rows
                    for item in (
                        _nested(row, "resources", "daytona", "providerResources")
                        or []
                    )
                    if isinstance(item, dict)
                )
                and global_absence.get("githubRefs") == []
                and global_absence.get("githubOpenPullRequests") == []
                and global_absence.get("githubRefPrefix")
                == "refs/heads/agent/paperclip-e2e-"
                and len(cleanup_rows) == len(R1_E2E_HARNESS_PROFILES)
                and all(
                    row.get("completed") is True
                    and row.get("pullRequestClosed") is True
                    and row.get("branchDeleted") is True
                    and valid_c080_cleanup(row)
                    for row in cleanup_rows
                ),
                "e2e_cleanup_absence_not_proven",
            )
        results[connection_id] = _connection_result(
            connection_id, findings, evidence=E2E_EVIDENCE
        )
    return results


def _integration_connection_proofs(requested: set[str]) -> dict[str, dict]:
    ids = requested & {
        "C012",
        "C023",
        "C024",
        "C027",
        "C029",
        "C030",
    }
    if not ids:
        return {}
    document, envelope = _bound_evidence(
        INTEGRATION_EVIDENCE,
        kind="IntegrationCanaryEvidence",
        status=None,
        time_fields=("generatedAt",),
        canonical_field=("canonicalSourceSha256",),
        producer_field=("producerSha256",),
        producer_path=SERVER_INTEGRATION_SOURCE,
    )
    if document is None or envelope:
        return {
            connection_id: _connection_result(
                connection_id, list(envelope), evidence=INTEGRATION_EVIDENCE
            )
            for connection_id in ids
        }
    rows = [row for row in document.get("canaries", []) if isinstance(row, dict)]
    profile = str(document.get("dataContentProfile") or "")
    results: dict[str, dict] = {}

    def row_for(connection_id: str) -> dict | None:
        matches = [row for row in rows if row.get("id") == connection_id]
        return matches[0] if len(matches) == 1 else None

    for connection_id in ids:
        findings: list[dict] = []
        row = row_for(connection_id)
        if connection_id == "C012":
            c023 = row_for("C023")
            _expect(
                findings,
                isinstance(c023, dict)
                and c023.get("ok") is True
                and _nested(c023, "cleanup", "workloadRemoved") is True,
                "toolhive_managed_workload_not_proven",
            )
        else:
            _expect(
                findings,
                isinstance(row, dict)
                and row.get("ok") is True
                and row.get("state") == "passed",
                "integration_canary_missing_or_failed",
            )
            if isinstance(row, dict) and connection_id == "C023":
                _expect(
                    findings,
                    row.get("controlledMarkerObserved") is True
                    and all(
                        _nested(row, "cleanup", key) is True
                        for key in (
                            "workloadRemoved",
                            "envFileRemoved",
                            "markerServerRemoved",
                        )
                    ),
                    "firecrawl_scrape_semantics_invalid",
                )
            elif isinstance(row, dict) and connection_id == "C024":
                _expect(
                    findings,
                    row.get("httpStatus") == 200
                    and isinstance(row.get("resultCount"), int)
                    and row.get("resultCount") > 0
                    and "results" in (row.get("responseKeys") or []),
                    "searxng_json_search_semantics_invalid",
                )
            elif isinstance(row, dict) and connection_id == "C027":
                findings.extend(_data_content_projection_contract_findings(profile))
                findings.extend(_postgrest_verify_findings(profile))
                _expect(
                    findings,
                    profile == "postgres-notion"
                    and row.get("dataContentProfile") == profile
                    and row.get("tablesApiComponent") == "postgrest"
                    and row.get("source") == "paperclip_process_heartbeat_run"
                    and all(
                        isinstance(row.get(key), str) and bool(row.get(key))
                        for key in (
                            "paperclipTaskId",
                            "paperclipHeartbeatRunId",
                            "paperclipAgentId",
                            "paperclipProjectId",
                            "secretAccessEventId",
                        )
                    )
                    and row.get("bindingType") == "secret_ref"
                    and row.get("secretIdMatchesManaged") is True
                    and row.get("credentialResolvedBy") == "paperclip_runtime"
                    and row.get("secretAccessEventVerified") is True
                    and row.get("createStatus") == 201
                    and row.get("readStatus") == 200
                    and row.get("deleteStatus") in {200, 204}
                    and row.get("markerObserved") is True
                    and row.get("postDeleteAbsent") is True
                    and row.get("cleanup") == "verified_deleted"
                    and row.get("paperclipCleanup")
                    == {"runTerminalOrCancelled": True, "issueDeleted": True}
                    and row.get("dependencyEvidence")
                    == _dependency_ref(
                        POSTGREST_VERIFY_EVIDENCE,
                        "PostgrestVerification",
                        ROOT / "bin/server-postgrest.py",
                    ),
                    "tables_api_paperclip_crud_semantics_invalid",
                )
            elif isinstance(row, dict) and connection_id == "C029":
                split, split_findings = _c029_integration_evidence()
                findings.extend(split_findings)
                split_rows = (
                    split.get("canaries")
                    if isinstance(split, dict)
                    and isinstance(split.get("canaries"), list)
                    else []
                )
                _expect(
                    findings,
                    profile == "postgres-notion"
                    and document.get("dataContentProfile") == "postgres-notion"
                    and len(split_rows) == 1
                    and row == split_rows[0]
                    and _notion_c029_row_valid(row),
                    "data_content_persistence_aggregate_drift",
                )
            elif isinstance(row, dict) and connection_id == "C030":
                _expect(
                    findings,
                    row.get("bindingType") == "secret_ref"
                    and row.get("secretAccessEventVerified") is True
                    and row.get("authorMatchesManagedBot") is True
                    and row.get("contentMatchesTaskAndRun") is True
                    and row.get("postDeleteStatus") == 404
                    and row.get("cleanup") == "verified_deleted"
                    and _nested(row, "paperclipCleanup", "issueDeleted") is True,
                    "mattermost_notification_semantics_invalid",
                )
        results[connection_id] = _connection_result(
            connection_id, findings, evidence=INTEGRATION_EVIDENCE
        )
    return results


def _hermes_connection_proofs(requested: set[str]) -> dict[str, dict]:
    ids = requested & {"C006", "C007", "C009", "C011", "C031", "C033", "C034", "C035"}
    if not ids:
        return {}
    document, envelope = _bound_evidence(
        HERMES_EVIDENCE,
        kind="HermesNativeAcceptance",
        api_version="paperclip-agent-platform/v1alpha1",
        status="passed",
        time_fields=("finishedAt",),
        canonical_field=("canonicalSha256",),
        producer_field=("producerSha256",),
        producer_path=HERMES_ACCEPTANCE_RUNTIME,
    )
    if document is not None:
        _expect(
            envelope,
            document.get("producerPath") == str(HERMES_ACCEPTANCE_RUNTIME),
            "hermes_producer_path_mismatch",
        )
        _expect(
            envelope,
            _sha256_file(HERMES_ACCEPTANCE_SOURCE)
            == _sha256_file(HERMES_ACCEPTANCE_RUNTIME),
            "hermes_runtime_source_drift",
        )
        _expect(
            envelope,
            document.get("nativeHermesCliPath") == str(HERMES_CLI_RUNTIME)
            and _is_full_sha256(document.get("nativeHermesCliSha256"))
            and document.get("nativeHermesCliSha256")
            == _sha256_file(HERMES_CLI_RUNTIME),
            "hermes_native_cli_drift",
        )
        try:
            unit = HERMES_UNIT_RUNTIME.read_text(encoding="utf-8")
        except OSError:
            unit = ""
        exec_starts = [
            line.strip()
            for line in unit.splitlines()
            if line.lstrip().startswith("ExecStart=")
        ]
        _expect(
            envelope,
            exec_starts
            == [
                "ExecStart=/opt/mte-hermes/current/venv/bin/hermes gateway run --replace"
            ],
            "hermes_native_gateway_unit_invalid",
        )
    if document is None or envelope:
        return {
            connection_id: _connection_result(
                connection_id, list(envelope), evidence=HERMES_EVIDENCE
            )
            for connection_id in ids
        }
    connections = (
        document.get("connections")
        if isinstance(document.get("connections"), dict)
        else {}
    )
    native = (
        connections.get("nativeTerminal")
        if isinstance(connections.get("nativeTerminal"), dict)
        else {}
    )
    native_run = native.get("run") if isinstance(native.get("run"), dict) else {}
    router = (
        connections.get("9router")
        if isinstance(connections.get("9router"), dict)
        else {}
    )
    results: dict[str, dict] = {}

    def completed_native_run() -> bool:
        return (
            native.get("ok") is True
            and native.get("nativeHermes") is True
            and native_run.get("status") == "completed"
            and bool(
                re.fullmatch(r"run_[0-9a-f]{32}", str(native_run.get("runId") or ""))
            )
            and "run.completed" in (native_run.get("eventTypes") or [])
        )

    def router_delta_valid() -> bool:
        delta = (
            router.get("usageDelta")
            if isinstance(router.get("usageDelta"), dict)
            else {}
        )
        return (
            router.get("ok") is True
            and router.get("runId") == native_run.get("runId")
            and all(
                _positive_counter(delta.get(key))
                for key in ("hermesKeyRequests", "modelRequests", "totalRequests")
            )
        )

    def messaging_ready(name: str) -> bool:
        row = connections.get(name)
        return (
            isinstance(row, dict)
            and row.get("ok") is True
            and row.get("state") == "ready"
            and row.get("nativeHermesIntegration") is True
        )

    def host_operator_policy_ready() -> bool:
        try:
            unit = HERMES_UNIT_RUNTIME.read_text(encoding="utf-8")
        except OSError:
            return False
        config = _json_object(CONFIG) or {}
        components = _nested(config, "spec", "components")
        hermes = (
            next(
                (
                    row
                    for row in components
                    if isinstance(components, list)
                    and isinstance(row, dict)
                    and row.get("id") == "hermes"
                ),
                None,
            )
            if isinstance(components, list)
            else None
        )
        runtime = hermes.get("runtime") if isinstance(hermes, dict) else None
        if not isinstance(runtime, dict):
            return False
        expected_runtime = {
            "command": "/opt/mte-hermes/current/venv/bin/hermes gateway run --replace",
            "apiExposure": "private-docker-bridge",
            "llmRoute": "9router",
            "messaging": ["telegram", "mattermost"],
            "operatorMode": runtime.get("operatorMode"),
        }
        if runtime != expected_runtime:
            return False
        mode = runtime.get("operatorMode")
        if mode == "unprivileged_service":
            return (
                not HERMES_SUDOERS_RUNTIME.exists()
                and "NoNewPrivileges=true" in unit
            )
        if mode != "unrestricted_host_repair":
            return False
        try:
            sudoers = HERMES_SUDOERS_RUNTIME.read_text(encoding="utf-8")
            sudoers_mode = HERMES_SUDOERS_RUNTIME.stat().st_mode & 0o777
        except OSError:
            return False
        policy = [
            line.strip()
            for line in sudoers.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        return (
            sudoers_mode == 0o440
            and policy
            == [
                "Defaults:mte-hermes !requiretty",
                "mte-hermes ALL=(ALL:ALL) NOPASSWD: ALL",
            ]
            and "NoNewPrivileges=true" not in unit
        )

    for connection_id in ids:
        findings: list[dict] = []
        if connection_id == "C006":
            _expect(
                findings,
                completed_native_run()
                and isinstance(native_run.get("eventTypes"), list),
                "hermes_native_api_semantics_invalid",
            )
        elif connection_id == "C007":
            _expect(
                findings,
                completed_native_run() and router_delta_valid(),
                "hermes_native_turn_semantics_invalid",
            )
        elif connection_id == "C009":
            _expect(
                findings,
                completed_native_run() and router_delta_valid(),
                "hermes_router_usage_invalid",
            )
        elif connection_id == "C011":
            _expect(
                findings,
                completed_native_run()
                and native_run.get("nativeTerminal") is True
                and native_run.get("approvalCount") == 1
                and native_run.get("command")
                == "python3 /opt/mte-platform/bin/server-verify.py status",
                "hermes_native_terminal_semantics_invalid",
            )
        elif connection_id == "C031":
            _expect(
                findings,
                messaging_ready("mattermost"),
                "hermes_mattermost_native_integration_invalid",
            )
        elif connection_id == "C033":
            # Inactive configuration is handled by connection_condition.  This
            # path is reached only when both Telegram refs are configured.
            _expect(
                findings,
                messaging_ready("telegram"),
                "hermes_telegram_native_integration_invalid",
            )
        elif connection_id == "C034":
            _expect(
                findings,
                completed_native_run()
                and native_run.get("nativeTerminal") is True
                and native_run.get("command")
                == "python3 /opt/mte-platform/bin/server-verify.py status",
                "hermes_platform_status_semantics_invalid",
            )
        elif connection_id == "C035":
            _expect(
                findings,
                host_operator_policy_ready(),
                "hermes_host_operator_policy_invalid",
            )
        results[connection_id] = _connection_result(
            connection_id, findings, evidence=HERMES_EVIDENCE
        )
    return results


def _observability_connection_proofs(requested: set[str]) -> dict[str, dict]:
    ids = requested & {
        "C040",
        "C041",
        "C042",
        "C043",
        "C044",
        "C045",
        "C047",
        "C048",
        "C049",
        "C050",
        "C063",
        "C064",
        "C069",
    }
    if not ids:
        return {}
    document, envelope = _bound_evidence(
        OBSERVABILITY_EVIDENCE,
        kind="ObservabilityDataCanaryEvidence",
        status="passed",
        time_fields=("completedAt",),
        canonical_field=("sourceGate", "sourceSha256"),
        producer_field=("producerSha256",),
        producer_path=SERVER_OBSERVABILITY_SOURCE,
    )
    gate = _source_gate()
    if document is not None:
        _expect(
            envelope,
            gate is not None and document.get("sourceGate") == gate,
            "observability_source_gate_mismatch",
        )
    if document is None or envelope:
        return {
            connection_id: _connection_result(
                connection_id, list(envelope), evidence=OBSERVABILITY_EVIDENCE
            )
            for connection_id in ids
        }
    checks = document.get("checks") if isinstance(document.get("checks"), dict) else {}
    expected_checks = {
        "C040",
        "C041",
        "C042",
        "C043",
        "C044",
        "C045",
        "C047",
        "C048",
        "C049",
        "C050",
        "C063",
        "C064",
        "C069",
        "C070",
    }
    shared_findings: list[dict] = []
    _expect(
        shared_findings,
        document.get("schemaVersion") == 2,
        "observability_schema_version_mismatch",
    )
    _expect(
        shared_findings,
        set(checks) == expected_checks,
        "observability_check_set_mismatch",
    )
    results: dict[str, dict] = {}
    for connection_id in ids:
        findings = list(shared_findings)
        row = (
            checks.get(connection_id)
            if isinstance(checks.get(connection_id), dict)
            else {}
        )
        _expect(
            findings,
            row.get("status") == "pass",
            "observability_check_missing_or_failed",
        )
        if connection_id == "C040":
            emitters = (
                row.get("emitters") if isinstance(row.get("emitters"), dict) else {}
            )
            application = (
                emitters.get("application")
                if isinstance(emitters.get("application"), dict)
                else {}
            )
            runner = (
                emitters.get("runner")
                if isinstance(emitters.get("runner"), dict)
                else {}
            )

            def valid_emitter(emitter: dict) -> bool:
                statuses = (
                    emitter.get("otlpHttpStatus")
                    if isinstance(emitter.get("otlpHttpStatus"), dict)
                    else {}
                )
                backend = (
                    emitter.get("backendProof")
                    if isinstance(emitter.get("backendProof"), dict)
                    else {}
                )
                expected_keys = {
                    "container",
                    "service",
                    "image",
                    "otlpHttpStatus",
                    "runId",
                    "traceId",
                    "backendProof",
                    "networkLifecycle",
                }
                network = (
                    emitter.get("networkLifecycle")
                    if isinstance(emitter.get("networkLifecycle"), dict)
                    else {}
                )
                return (
                    set(emitter) == expected_keys
                    and all(
                        bool(emitter.get(key))
                        for key in ("container", "service", "image")
                    )
                    and set(statuses) == {"metrics", "logs", "traces"}
                    and all(value in {200, 202} for value in statuses.values())
                    and bool(emitter.get("runId"))
                    and bool(
                        re.fullmatch(r"[0-9a-f]{32}", str(emitter.get("traceId") or ""))
                    )
                    and set(backend)
                    == {
                        "victoriametricsSeries",
                        "victorialogsRecords",
                        "victoriatracesCount",
                    }
                    and all(_positive_counter(value) for value in backend.values())
                    and set(network)
                    == {
                        "network",
                        "temporaryAttachmentCreated",
                        "temporaryAttachmentCleanupVerified",
                    }
                    and bool(network.get("network"))
                    and network.get("temporaryAttachmentCreated") is True
                    and network.get("temporaryAttachmentCleanupVerified") is True
                )

            _expect(
                findings,
                set(row) == {"status", "emitterCoverage", "emitters"}
                and row.get("emitterCoverage") == {"application": True, "runner": True}
                and set(emitters) == {"application", "runner"}
                and valid_emitter(application)
                and valid_emitter(runner)
                and application.get("runId") != runner.get("runId")
                and application.get("traceId") != runner.get("traceId"),
                "application_runner_telemetry_not_proven",
            )
        elif connection_id == "C041":
            _expect(
                findings,
                all(
                    isinstance(row.get(key), dict)
                    and _positive_counter(row[key].get("series"))
                    and isinstance(row[key].get("freshnessSeconds"), (int, float))
                    and row[key]["freshnessSeconds"] <= 180
                    for key in ("host", "containers")
                ),
                "host_container_metric_freshness_invalid",
            )
        elif connection_id == "C042":
            _expect(
                findings,
                _positive_counter(row.get("metricSeries")),
                "victoria_metric_series_missing",
            )
        elif connection_id == "C043":
            _expect(
                findings,
                _positive_counter(row.get("logRecords")),
                "victoria_log_records_missing",
            )
        elif connection_id == "C044":
            c040_emitters = _nested(checks, "C040", "emitters")
            application = (
                c040_emitters.get("application")
                if isinstance(c040_emitters, dict)
                and isinstance(c040_emitters.get("application"), dict)
                else {}
            )
            runner = (
                c040_emitters.get("runner")
                if isinstance(c040_emitters, dict)
                and isinstance(c040_emitters.get("runner"), dict)
                else {}
            )
            expected_trace_ids = [
                application.get("traceId"),
                runner.get("traceId"),
            ]
            expected_trace_count = sum(
                int(_nested(emitter, "backendProof", "victoriatracesCount") or 0)
                for emitter in (application, runner)
            )
            _expect(
                findings,
                set(row) == {"status", "traceCount", "traceIds"}
                and _positive_counter(row.get("traceCount"))
                and row.get("traceCount") == expected_trace_count
                and row.get("traceIds") == expected_trace_ids
                and all(expected_trace_ids)
                and len(set(expected_trace_ids)) == 2,
                "victoria_trace_correlation_invalid",
            )
        elif connection_id == "C045":
            health = row.get("health") if isinstance(row.get("health"), dict) else {}
            _expect(
                findings,
                set(health) == {"victoriametrics", "victorialogs", "victoriatraces"}
                and all(value == 200 for value in health.values())
                and _positive_counter(row.get("metricSeries"))
                and row.get("logsFound") is True
                and row.get("traceFound") is True,
                "grafana_datasource_query_semantics_invalid",
            )
        elif connection_id == "C047":
            _expect(
                findings,
                all(
                    row.get(key) is True
                    for key in (
                        "mattermostReceiverReady",
                        "sendResolved",
                        "otelLabelSelectorReady",
                        "vmalertFiringObserved",
                        "alertmanagerFiringObserved",
                        "resolvedObserved",
                    )
                ),
                "alertmanager_firing_resolved_semantics_invalid",
            )
        elif connection_id == "C048":
            cleanup = row.get("cleanup") if isinstance(row.get("cleanup"), dict) else {}
            _expect(
                findings,
                row.get("mattermostFiringObserved") is True
                and row.get("mattermostResolvedObserved") is True
                and _positive_counter(row.get("matchingPosts"))
                and row.get("webhookCredentialRef") == "MATTERMOST_ALERT_WEBHOOK_URL"
                and bool(
                    re.fullmatch(
                        r"[0-9a-f]{64}",
                        str(row.get("canonicalWebhookFingerprintSha256") or ""),
                    )
                )
                and bool(
                    re.fullmatch(
                        r"[0-9a-f]{64}",
                        str(row.get("deployedWebhookFingerprintSha256") or ""),
                    )
                )
                and row.get("canonicalWebhookFingerprintSha256")
                != row.get("deployedWebhookFingerprintSha256")
                and row.get("webhookPathPreserved") is True
                and bool(row.get("postAuthor"))
                and row.get("postChannel") == "mte-alerts"
                and row.get("postAuthorIdentityCount") == 1
                and row.get("postChannelIdentityCount") == 1
                and cleanup.get("cleanupVerified") is True
                and cleanup.get("remainingPosts") == 0,
                "alertmanager_mattermost_delivery_contract_not_proven",
            )
        elif connection_id == "C049":
            _expect(
                findings,
                row.get("exactInventory") is True
                and row.get("allSuccessful") is True
                and row.get("allFresh") is True
                and isinstance(row.get("declaredTargets"), list)
                and row.get("observedSeries") == len(row.get("declaredTargets")),
                "blackbox_exact_inventory_invalid",
            )
        elif connection_id == "C050":
            _expect(
                findings,
                row.get("idempotent") is True
                and isinstance(row.get("first"), dict)
                and row.get("first") == row.get("second")
                and _nested(row, "second", "serviceAccountCount") == 1,
                "grafana_provisioning_not_idempotent",
            )
        elif connection_id == "C063":
            paths = (
                row.get("applicationPaths")
                if isinstance(row.get("applicationPaths"), list)
                else []
            )
            expected_path_counts = {
                "postgres-notion": 6,
            }
            canonical_values, canonical_findings = dotenv(CANONICAL_ENV)
            findings.extend(canonical_findings)
            profile = canonical_values.get("DATA_CONTENT_PROFILE", "")
            expected_count = expected_path_counts.get(profile)
            _expect(
                findings,
                set(row)
                == {
                    "status",
                    "dataContentProfile",
                    "expectedPathCount",
                    "applicationPaths",
                }
                and row.get("dataContentProfile") == profile
                and row.get("expectedPathCount") == expected_count
                and isinstance(expected_count, int)
                and len(paths) == expected_count
                and len({item.get("role") for item in paths if isinstance(item, dict)})
                == len(paths)
                and all(
                    isinstance(item, dict)
                    and set(item)
                    == {
                        "role",
                        "networkNamespace",
                        "databaseIdentityRef",
                        "credentialInArgv",
                        "inserted",
                        "read",
                        "deleted",
                        "remaining",
                    }
                    and bool(item.get("role"))
                    and bool(item.get("networkNamespace"))
                    and bool(item.get("databaseIdentityRef"))
                    and item.get("inserted") == 1
                    and item.get("read") == 1
                    and item.get("deleted") == 1
                    and item.get("remaining") == 0
                    and item.get("credentialInArgv") is False
                    for item in paths
                ),
                "postgres_rw_delete_path_coverage_invalid",
            )
        elif connection_id == "C064":
            paths = (
                row.get("applicationPaths")
                if isinstance(row.get("applicationPaths"), list)
                else []
            )
            expected_path_counts = {
                "postgres-notion": 4,
            }
            canonical_values, canonical_findings = dotenv(CANONICAL_ENV)
            findings.extend(canonical_findings)
            profile = canonical_values.get("DATA_CONTENT_PROFILE", "")
            expected_count = expected_path_counts.get(profile)
            _expect(
                findings,
                set(row)
                == {
                    "status",
                    "dataContentProfile",
                    "expectedPathCount",
                    "applicationPaths",
                }
                and row.get("dataContentProfile") == profile
                and row.get("expectedPathCount") == expected_count
                and isinstance(expected_count, int)
                and len(paths) == expected_count
                and len({item.get("role") for item in paths if isinstance(item, dict)})
                == len(paths)
                and all(
                    isinstance(item, dict)
                    and set(item)
                    == {
                        "role",
                        "networkNamespace",
                        "credentialRef",
                        "unauthenticatedRejected",
                        "authenticatedPing",
                    }
                    and bool(item.get("role"))
                    and bool(item.get("networkNamespace"))
                    and bool(item.get("credentialRef"))
                    and item.get("unauthenticatedRejected") is True
                    and item.get("authenticatedPing") == "PONG"
                    for item in paths
                ),
                "redis_authenticated_ping_coverage_invalid",
            )
        elif connection_id == "C069":
            _expect(
                findings,
                row.get("contract") == "direct-docker-compose"
                and row.get("project") == "mte-platform"
                and row.get("noDuplicateResources") is True
                and _positive_counter(row.get("componentCount"))
                and row.get("coverage")
                == ["canonical-aggregate-compose", "live-runtime-labels"]
                and bool(
                    re.fullmatch(
                        r"[0-9a-f]{64}", str(row.get("inventoryIdentitySha256") or "")
                    )
                ),
                "compose_runtime_semantics_invalid",
            )
        results[connection_id] = _connection_result(
            connection_id, findings, evidence=OBSERVABILITY_EVIDENCE
        )
    return results


def _indexed_evidence_context() -> tuple[
    dict | None, dict | None, dict | None, list[dict]
]:
    findings: list[dict] = []
    final = _json_object(INDEXED_IDEMPOTENCY_EVIDENCE)
    first = _json_object(INDEXED_PASS_EVIDENCE[1])
    second = _json_object(INDEXED_PASS_EVIDENCE[2])
    if not all(isinstance(item, dict) for item in (final, first, second)):
        return (
            final,
            first,
            second,
            [{"finding": "indexed_evidence_missing_or_invalid"}],
        )
    assert final is not None and first is not None and second is not None
    gate = _source_gate()
    expected_hashes = {
        "server-observability-canary.py": _sha256_file(SERVER_OBSERVABILITY_SOURCE),
        "server-provision.py": _sha256_file(SERVER_PROVISION_SOURCE),
        "server-toolhive.py": _sha256_file(SERVER_TOOLHIVE_SOURCE),
        "server-profile-reconcile.py": _sha256_file(SERVER_PROFILE_RECONCILE_SOURCE),
        "server-config.py": _sha256_file(SERVER_CONFIG_SOURCE),
    }
    for path, document, expected_kind in (
        (INDEXED_PASS_EVIDENCE[1], first, "IndexedReconcilePass"),
        (INDEXED_PASS_EVIDENCE[2], second, "IndexedReconcilePass"),
        (INDEXED_IDEMPOTENCY_EVIDENCE, final, "IndexedDeployIdempotencyEvidence"),
    ):
        _expect(
            findings,
            _mode_is_0600(path),
            "indexed_evidence_mode_invalid",
            path=str(path),
        )
        _expect(
            findings,
            document.get("apiVersion") == "micro-task-engine/v1alpha1"
            and document.get("kind") == expected_kind
            and document.get("status") == "passed",
            "indexed_evidence_envelope_invalid",
            path=str(path),
        )
        _expect(
            findings,
            _fresh_field(document, ("completedAt",)),
            "indexed_evidence_stale_or_timestamp_missing",
            path=str(path),
        )
        _expect(
            findings,
            gate is not None and document.get("sourceGate") == gate,
            "indexed_source_gate_mismatch",
            path=str(path),
        )
        _expect(
            findings,
            document.get("producerSha256")
            == expected_hashes["server-observability-canary.py"],
            "indexed_primary_producer_hash_mismatch",
            path=str(path),
        )
        _expect(
            findings,
            document.get("producerHashes") == expected_hashes,
            "indexed_dependency_producer_hashes_mismatch",
            path=str(path),
        )
    _expect(
        findings,
        first.get("pass") == 1 and second.get("pass") == 2,
        "indexed_pass_number_mismatch",
    )
    first_after = _nested(first, "after", "identitySha256")
    second_before = _nested(second, "before", "identitySha256")
    second_after = _nested(second, "after", "identitySha256")
    _expect(
        findings,
        bool(first_after)
        and first_after
        == second_before
        == second_after
        == final.get("inventoryIdentitySha256"),
        "indexed_identity_chain_mismatch",
    )
    actions = (
        second.get("composeActions")
        if isinstance(second.get("composeActions"), dict)
        else {}
    )
    _expect(
        findings,
        bool(actions) and set(actions.values()) == {"unchanged"},
        "indexed_second_pass_not_noop",
    )
    _expect(
        findings,
        final.get("stableComposeIdentity") is True
        and final.get("noDuplicateResources") is True
        and final.get("secondPassNoChange") is True
        and final.get("coverage")
        == [
            "direct-compose-all-indexed-components",
            "server-provision-all-adapters",
            "toolhive-provisioning",
            "grafana-provisioning",
            "canonical-aggregate-compose",
            "live-runtime-labels",
        ],
        "indexed_final_semantics_invalid",
    )
    return final, first, second, findings


def _provisioning_connection_proofs(requested: set[str]) -> dict[str, dict]:
    ids = requested & {"C014", "C015", "C016", "C019", "C037", "C039"}
    if not ids:
        return {}
    _final, _first, second, envelope = _indexed_evidence_context()
    if second is None or envelope:
        return {
            connection_id: _connection_result(
                connection_id, list(envelope), evidence=INDEXED_IDEMPOTENCY_EVIDENCE
            )
            for connection_id in ids
        }
    provisioner = _nested(second, "after", "identity", "provisioner")
    toolhive = _nested(second, "after", "identity", "toolhive")
    if not isinstance(provisioner, dict):
        provisioner = {}
    if not isinstance(toolhive, dict):
        toolhive = {}
    components = (
        provisioner.get("components")
        if isinstance(provisioner.get("components"), list)
        else []
    )
    component_map = {
        str(row.get("component")): row
        for row in components
        if isinstance(row, dict) and row.get("component")
    }
    common_ready = (
        provisioner.get("incomplete") == []
        and _nested(provisioner, "security", "findings") == []
    )
    expected_profiles = set(NATIVE_HARNESS_PROFILES)
    results: dict[str, dict] = {}
    for connection_id in ids:
        findings: list[dict] = []
        _expect(findings, common_ready, "provisioner_not_fully_ready")
        paperclip = component_map.get("paperclip", {})
        router = component_map.get("9router", {})
        if connection_id == "C014":
            bindings = (
                paperclip.get("agentBindings")
                if isinstance(paperclip.get("agentBindings"), list)
                else []
            )
            _expect(
                findings,
                set(paperclip.get("managed") or [])
                >= {
                    "company",
                    "default_responsible_user",
                    "operations_project",
                    "local_encrypted_company_secrets",
                    "user_secret_definitions",
                    "profile_runtime_bindings",
                    "task_bridge_agent_key",
                }
                and _nested(paperclip, "runtimeSecurity", "provider")
                == "local_encrypted"
                and _nested(paperclip, "runtimeSecurity", "strictMode") is True
                and _nested(paperclip, "responsibleUser", "configured") is True
                and paperclip.get("unsafeInlineBindings") == []
                and {row.get("profileRef") for row in bindings if isinstance(row, dict)}
                == expected_profiles
                and all(
                    row.get("status") == "ready"
                    for row in bindings
                    if isinstance(row, dict)
                ),
                "paperclip_provisioning_semantics_invalid",
            )
        elif connection_id == "C015":
            profiles = (
                router.get("harnessProfiles")
                if isinstance(router.get("harnessProfiles"), list)
                else []
            )
            canaries = _nested(router, "minimax", "canaries")
            _expect(
                findings,
                {row.get("profileRef") for row in profiles if isinstance(row, dict)}
                == expected_profiles
                and all(
                    row.get("status") == "ready"
                    for row in profiles
                    if isinstance(row, dict)
                )
                and _nested(router, "minimax", "providerTest") == "passed"
                and _nested(router, "minimax", "canary") == "passed"
                and isinstance(canaries, list)
                and {row.get("client") for row in canaries if isinstance(row, dict)}
                >= expected_profiles
                and all(
                    row.get("status") == "passed"
                    for row in canaries
                    if isinstance(row, dict)
                ),
                "ninerouter_provisioning_semantics_invalid",
            )
        elif connection_id == "C016":
            bundles = (
                toolhive.get("profileBundles")
                if isinstance(toolhive.get("profileBundles"), list)
                else []
            )
            _expect(
                findings,
                toolhive.get("binary") == "ready"
                and toolhive.get("canary") == "ready"
                and {row.get("profileRef") for row in bundles if isinstance(row, dict)}
                == expected_profiles
                and all(
                    row.get("status") == "ready"
                    for row in bundles
                    if isinstance(row, dict)
                ),
                "toolhive_profile_bundle_reconcile_not_proven",
            )
        elif connection_id == "C019":
            reconcile = _nested(second, "after", "identity", "profileReconcile")
            rows = (
                reconcile.get("profiles")
                if isinstance(reconcile, dict)
                and isinstance(reconcile.get("profiles"), list)
                else []
            )
            _expect(
                findings,
                {row.get("profileRef") for row in rows if isinstance(row, dict)}
                == expected_profiles
                and all(
                    row.get("paperclip") is True
                    and row.get("toolhive") is True
                    and row.get("kestra") is True
                    for row in rows
                    if isinstance(row, dict)
                ),
                "cross_control_plane_profile_reconcile_not_proven",
            )
        elif connection_id == "C037":
            row = component_map.get("mattermost", {})
            _expect(
                findings,
                set(row.get("managed") or [])
                >= {
                    "system_admin",
                    "team",
                    "bot",
                    "bot_access_token",
                    "alert_channel",
                    "alertmanager_incoming_webhook",
                }
                and bool(_nested(row, "fingerprints", "botToken"))
                and bool(_nested(row, "fingerprints", "alertWebhook")),
                "mattermost_provisioning_semantics_invalid",
            )
        elif connection_id == "C039":
            row = component_map.get("kestra", {})
            _expect(
                findings,
                set(row.get("managed") or [])
                >= {
                    "shared_basic_auth_principal",
                    "mte_namespace_via_flow_catalog",
                    "managed_flows",
                }
                and _nested(row, "names", "namespace") == "mte.platform"
                and _positive_counter(row.get("managedFlowCount"))
                and row.get("credentialVerified") is True,
                "kestra_provisioning_semantics_invalid",
            )
        results[connection_id] = _connection_result(
            connection_id, findings, evidence=INDEXED_IDEMPOTENCY_EVIDENCE
        )
    return results


def _profile_reconcile_connection_proofs(requested: set[str]) -> dict[str, dict]:
    ids = requested & {"C016", "C019"}
    if not ids:
        return {}
    document, findings = _bound_evidence(
        PROFILE_RECONCILE_EVIDENCE,
        kind="ProfileReconcileEvidence",
        status="passed",
        time_fields=("generatedAt",),
        canonical_field=("canonicalSourceSha256",),
        producer_field=("producerSha256",),
        producer_path=SERVER_PROFILE_RECONCILE_SOURCE,
    )
    if document is not None:
        _expect(findings, document.get("ok") is True, "profile_reconcile_not_ok")
        _expect(
            findings,
            document.get("connectionReady") is True
            and document.get("completionBlockers") == [],
            "profile_reconcile_not_connection_ready",
        )
        _expect(
            findings,
            document.get("producerPath") == str(SERVER_PROFILE_RECONCILE_SOURCE),
            "profile_reconcile_producer_path_mismatch",
        )
        profiles = (
            document.get("profiles")
            if isinstance(document.get("profiles"), list)
            else []
        )
        _expect(
            findings,
            [row.get("profileRef") for row in profiles if isinstance(row, dict)]
            == list(NATIVE_HARNESS_PROFILES),
            "profile_reconcile_profile_set_mismatch",
        )
        adapters = {
            "coding-daytona-codex": "codex_local",
            "coding-daytona-claude": "claude_local",
            "coding-daytona-pi": "pi_local",
        }
        harness_names = {
            "coding-daytona-codex": "codex",
            "coding-daytona-claude": "claude",
            "coding-daytona-pi": "pi",
        }
        _expect(
            findings,
            len(profiles) == 3
            and all(isinstance(row, dict) for row in profiles)
            and all(
                row.get("nativeAdapter") == adapters.get(row.get("profileRef"))
                and _nested(row, "paperclip", "status") == "ready"
                and bool(_nested(row, "paperclip", "agentId"))
                and _nested(row, "paperclip", "catalogSha256")
                == document.get("profileCatalogSha256")
                and _nested(row, "toolhive", "status") == "ready"
                and _nested(row, "toolhive", "bundleId")
                == f"mte-profile-{row.get('profileRef')}"
                and _nested(row, "toolhive", "workloadId")
                == f"mte-profile-{harness_names.get(row.get('profileRef'))}"
                and _nested(row, "toolhive", "endpointRef")
                == "MTE_AGENT_GATEWAY_TOOLHIVE_"
                + str(harness_names.get(row.get("profileRef"), "")).upper()
                + "_URL"
                and _nested(row, "toolhive", "credentialRef")
                == "TOOLHIVE_PROFILE_CODING_DAYTONA_"
                + str(harness_names.get(row.get("profileRef"), "")).upper()
                + "_BEARER_TOKEN"
                and _nested(row, "toolhive", "managerInventoryRead") is True
                and _nested(row, "toolhive", "managerReadOnlyCanary") is True
                and _nested(row, "toolhive", "groupProvidesIdentity") is False
                and _nested(row, "toolhive", "runnerAccessVerified") is True
                and all(
                    bool(
                        re.fullmatch(
                            r"[0-9a-f]{64}",
                            str(_nested(row, "toolhive", key) or ""),
                        )
                    )
                    for key in (
                        "bundleSha256",
                        "toolSchemaSha256",
                        "canaryResultSha256",
                    )
                )
                and _nested(row, "kestra", "status") == "ready"
                and _nested(row, "kestra", "gateId") == "mte.profile.catalog"
                and _nested(row, "kestra", "documentSha256")
                == document.get("kestraCatalogPayloadSha256")
                and _nested(row, "kestra", "observedCatalogSha256")
                == document.get("kestraProfileCatalogSha256")
                for row in profiles
            )
            and document.get("profileCatalogSha256")
            == _profile_catalog_semantic_sha256(E2E_PROFILES)
            and _is_full_sha256(document.get("kestraCatalogPayloadSha256"))
            and document.get("secondRunNoOp") is True
            and document.get("mutationCount") == 0
            and document.get("duplicateCount") == 0,
            "profile_reconcile_semantics_invalid",
        )
        _expect(
            findings,
            document.get("extraCount") == 0
            and document.get("accessEvidenceSha256")
            == _sha256_file(PROFILE_ACCESS_EVIDENCE)
            and document.get("kestraEvidenceSha256")
            == _sha256_file(KESTRA_RECONCILE_VERIFY_EVIDENCE)
            and document.get("kestraProfileCatalogSha256")
            == document.get("kestraCatalogPayloadSha256"),
            "profile_reconcile_completion_binding_invalid",
        )
        _expect(
            findings,
            len({_nested(row, "paperclip", "agentId") for row in profiles}) == 3
            and len({_nested(row, "toolhive", "workloadId") for row in profiles}) == 3,
            "profile_reconcile_remote_identity_not_unique",
        )
    return {
        connection_id: _connection_result(
            connection_id, list(findings), evidence=PROFILE_RECONCILE_EVIDENCE
        )
        for connection_id in ids
    }


def _profile_access_connection_proofs(requested: set[str]) -> dict[str, dict]:
    """Require the separate runner-origin C010 attestation and its live E2E subject."""
    if "C010" not in requested:
        return {}
    document, findings = _bound_evidence(
        PROFILE_ACCESS_EVIDENCE,
        kind="ToolHiveProfileAccessVerification",
        status="passed",
        time_fields=("generatedAt",),
        canonical_field=("canonicalSourceSha256",),
        producer_field=("producerSha256",),
        producer_path=SERVER_PROFILE_RECONCILE_SOURCE,
    )
    e2e_result = _e2e_connection_proofs({"C010"}).get("C010", {})
    findings.extend(e2e_result.get("findings") or [])
    if document is not None:
        profiles = (
            document.get("profiles")
            if isinstance(document.get("profiles"), list)
            else []
        )
        expected_rows = []
        for profile in NATIVE_HARNESS_PROFILES:
            harness = profile.rsplit("-", 1)[-1]
            expected_rows.append(
                {
                    "profileRef": profile,
                    "bundleId": f"mte-profile-{profile}",
                    "workloadId": f"mte-profile-{harness}",
                    "endpointRef": f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness.upper()}_URL",
                    "credentialRef": "TOOLHIVE_PROFILE_"
                    + profile.replace("-", "_").upper()
                    + "_BEARER_TOKEN",
                    "wrongProfileEndpointRef": "MTE_AGENT_GATEWAY_TOOLHIVE_"
                    + {
                        "codex": "CLAUDE",
                        "claude": "PI",
                        "pi": "CODEX",
                    }[harness]
                    + "_URL",
                }
            )
        _expect(
            findings,
            document.get("ok") is True
            and document.get("producerPath") == str(SERVER_PROFILE_RECONCILE_SOURCE)
            and document.get("profileCatalogSha256")
            == _profile_catalog_semantic_sha256(E2E_PROFILES)
            and document.get("subjectEvidencePath") == str(E2E_EVIDENCE)
            and document.get("subjectEvidenceSha256") == _sha256_file(E2E_EVIDENCE)
            and document.get("secretValuesPrinted") is False,
            "profile_access_binding_invalid",
        )
        _expect(
            findings,
            _nested(document, "identityModel", "groupProvidesIdentity") is False
            and _nested(
                document,
                "identityModel",
                "boundedAlternative",
                "type",
            )
            == "mte-agent-plane-gateway-profile-bearer"
            and _nested(
                document,
                "identityModel",
                "boundedAlternative",
                "networkExposure",
            )
            == "private-agent-plane-only",
            "profile_access_identity_model_invalid",
        )
        _expect(
            findings,
            len(profiles) == 3
            and [row.get("profileRef") for row in profiles if isinstance(row, dict)]
            == list(NATIVE_HARNESS_PROFILES)
            and all(
                isinstance(row, dict)
                and all(row.get(key) == expected[key] for key in expected)
                and row.get("status") == "passed"
                and row.get("runnerOrigin") == "daytona"
                and row.get("initialize") is True
                and row.get("toolsList") is True
                and row.get("canaryCall") is True
                and row.get("toolName") == "echo"
                and row.get("httpStatus") == 200
                and row.get("unauthorizedStatus") == 401
                and row.get("wrongProfileDenied") is True
                and row.get("wrongProfileStatus") == 401
                and row.get("credentialLeak") is False
                and bool(row.get("runId"))
                and all(
                    _is_full_sha256(row.get(key))
                    for key in ("markerSha256", "toolsListSha256", "resultSha256")
                )
                for row, expected in zip(profiles, expected_rows, strict=True)
            ),
            "profile_access_semantics_invalid",
        )
    return {
        "C010": _connection_result("C010", findings, evidence=PROFILE_ACCESS_EVIDENCE)
    }


def _kestra_reconcile_connection_proofs(requested: set[str]) -> dict[str, dict]:
    """Validate the dedicated, read-back C039 reconciliation attestation."""
    if "C039" not in requested:
        return {}
    document, findings = _bound_evidence(
        KESTRA_RECONCILE_VERIFY_EVIDENCE,
        kind="KestraReconcileEvidence",
        status="passed",
        time_fields=("finishedAt",),
        canonical_field=("canonicalSourceSha256",),
        producer_field=("producerSha256",),
        producer_path=SERVER_KESTRA_RECONCILE_SOURCE,
    )
    if document is not None:
        lock_path = ROOT / "templates/platform.lock.yaml"
        try:
            lock = yaml.safe_load(lock_path.read_text())
        except (OSError, yaml.YAMLError):
            lock = {}
        kestra_version = _nested(lock, "spec", "kestra")
        expected_flows = [
            (
                "control-plane",
                "mte.platform",
                "kestra/flows/control-plane.yaml",
            ),
            (
                "paperclip-runtime",
                "micro_task_engine.prototype",
                "kestra/flows/paperclip-runtime.yaml",
            ),
            (
                "platform-canary",
                "system.health",
                "kestra/flows/platform-canary.yaml",
            ),
            (
                "paperclip-github-e2e",
                "micro_task_engine.e2e",
                "kestra/flows/paperclip-github-e2e.yaml",
            ),
        ]
        expected_source_set = [
            {
                "id": flow_id,
                "namespace": namespace,
                "sourceRef": source_ref,
                "sourceSha256": _sha256_file(ROOT / "manifests" / source_ref),
            }
            for flow_id, namespace, source_ref in expected_flows
        ]
        first = (
            document.get("firstPass")
            if isinstance(document.get("firstPass"), dict)
            else {}
        )
        second = (
            document.get("secondPass")
            if isinstance(document.get("secondPass"), dict)
            else {}
        )
        second_flows = (
            second.get("flows") if isinstance(second.get("flows"), list) else []
        )
        second_kv = second.get("kv") if isinstance(second.get("kv"), list) else []
        subject = (
            document.get("subjectProvisionEvidence")
            if isinstance(document.get("subjectProvisionEvidence"), dict)
            else {}
        )
        provision_path = ROOT / "evidence/kestra-reconcile.json"
        _expect(
            findings,
            document.get("action") == "verify"
            and document.get("producerPath") == str(SERVER_KESTRA_RECONCILE_SOURCE)
            and document.get("controlNamespace") == "mte.platform"
            and document.get("flowCatalogKey") == "mte.flow.catalog"
            and document.get("profileCatalogKey") == "mte.profile.catalog"
            and document.get("profileSourceSha256") == _sha256_file(E2E_PROFILE_SOURCE)
            and document.get("profileRuntimeSha256")
            == _profile_catalog_semantic_sha256(E2E_PROFILES)
            and document.get("profileRefs") == list(NATIVE_HARNESS_PROFILES)
            and document.get("flowSourceSet") == expected_source_set
            and document.get("stableRemoteState") is True
            and document.get("platformLockSha256") == _sha256_file(lock_path)
            and document.get("kestraVersion") == kestra_version,
            "kestra_reconcile_binding_invalid",
        )
        _expect(
            findings,
            document.get("credential")
            == {
                "authType": "basic",
                "usernameRef": "KESTRA_ADMIN_USER",
                "passwordRef": "KESTRA_ADMIN_PASSWORD",
                "resolvedForLiveApi": True,
                "rawSecretIncluded": False,
            }
            and document.get("secretAudit")
            == {
                "canonicalEnvIncluded": False,
                "authorizationHeaderIncluded": False,
                "rawSecretIncluded": False,
            },
            "kestra_reconcile_credential_contract_invalid",
        )
        _expect(
            findings,
            subject
            == {
                "path": str(provision_path),
                "sha256": _sha256_file(provision_path),
            }
            and _mode_is_0600(provision_path),
            "kestra_reconcile_provision_subject_invalid",
        )
        _expect(
            findings,
            first.get("mutationCount") == 0
            and first.get("mutations") == []
            and second.get("mutationCount") == 0
            and second.get("mutations") == []
            and second.get("noOp") is True
            and first.get("flows") == second_flows
            and first.get("kv") == second_kv,
            "kestra_reconcile_not_stable_noop",
        )
        _expect(
            findings,
            len(second_flows) == 4
            and [
                (row.get("id"), row.get("namespace"), row.get("sourceRef"))
                for row in second_flows
                if isinstance(row, dict)
            ]
            == expected_flows
            and all(
                row.get("sourceSha256") == expected_source_set[index]["sourceSha256"]
                and isinstance(row.get("revision"), int)
                and not isinstance(row.get("revision"), bool)
                and row.get("revision") >= 1
                and bool(row.get("updated"))
                for index, row in enumerate(second_flows)
                if isinstance(row, dict)
            ),
            "kestra_reconcile_flow_inventory_invalid",
        )
        _expect(
            findings,
            len(second_kv) == 2
            and [row.get("key") for row in second_kv if isinstance(row, dict)]
            == ["mte.flow.catalog", "mte.profile.catalog"]
            and all(
                row.get("namespace") == "mte.platform"
                and row.get("type") == "JSON"
                and _is_full_sha256(row.get("valueSha256"))
                and isinstance(row.get("revision"), int)
                and not isinstance(row.get("revision"), bool)
                and row.get("revision") >= 1
                and bool(row.get("updated"))
                for row in second_kv
                if isinstance(row, dict)
            ),
            "kestra_reconcile_kv_inventory_invalid",
        )
    return {
        "C039": _connection_result(
            "C039", findings, evidence=KESTRA_RECONCILE_VERIFY_EVIDENCE
        )
    }


def _account_provision_connection_proofs(requested: set[str]) -> dict[str, dict]:
    """Bind C075 to both live harness isolation and Paperclip secret scopes."""
    if "C075" not in requested:
        return {}
    e2e = _e2e_connection_proofs({"C075"})["C075"]
    findings = list(e2e.get("findings") or [])
    document, envelope = _bound_evidence(
        ACCOUNT_PROVISION_VERIFY_EVIDENCE,
        kind="AccountProvisioningVerify",
        status="passed",
        time_fields=("generatedAt",),
        canonical_field=("canonicalSourceSha256",),
        producer_field=("producerSha256",),
        producer_path=SERVER_PROVISION_SOURCE,
    )
    findings.extend(envelope)
    if document is not None and not envelope:
        paperclip = (
            document.get("paperclip")
            if isinstance(document.get("paperclip"), dict)
            else {}
        )
        security = (
            document.get("security")
            if isinstance(document.get("security"), dict)
            else {}
        )
        secrets = (
            paperclip.get("companySecrets")
            if isinstance(paperclip.get("companySecrets"), list)
            else []
        )
        definitions = (
            paperclip.get("userSecretDefinitions")
            if isinstance(paperclip.get("userSecretDefinitions"), list)
            else []
        )
        bindings = (
            paperclip.get("agentBindings")
            if isinstance(paperclip.get("agentBindings"), list)
            else []
        )
        environment_bindings = (
            paperclip.get("agentEnvironmentBindings")
            if isinstance(paperclip.get("agentEnvironmentBindings"), list)
            else []
        )
        project_workspace = (
            paperclip.get("projectWorkspace")
            if isinstance(paperclip.get("projectWorkspace"), dict)
            else {}
        )
        daytona_environment = (
            paperclip.get("daytonaEnvironment")
            if isinstance(paperclip.get("daytonaEnvironment"), dict)
            else {}
        )
        values, dotenv_findings = dotenv(CANONICAL_ENV)
        findings.extend(dotenv_findings)
        expected = {
            "coding-daytona-codex": {
                "adapterType": "codex_local",
                "routerKeyRef": "NINEROUTER_PROFILE_CODING_DAYTONA_CODEX_API_KEY",
                "toolhiveTokenRef": "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN",
                "toolhiveUrlRef": "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
                "envKeys": ACCOUNT_PROFILE_ENV_KEYS["coding-daytona-codex"],
            },
            "coding-daytona-claude": {
                "adapterType": "claude_local",
                "routerKeyRef": "NINEROUTER_PROFILE_CODING_DAYTONA_CLAUDE_API_KEY",
                "toolhiveTokenRef": "TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_BEARER_TOKEN",
                "toolhiveUrlRef": "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_URL",
                "envKeys": ACCOUNT_PROFILE_ENV_KEYS["coding-daytona-claude"],
            },
            "coding-daytona-pi": {
                "adapterType": "pi_local",
                "routerKeyRef": "NINEROUTER_PROFILE_CODING_DAYTONA_PI_API_KEY",
                "toolhiveTokenRef": "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN",
                "toolhiveUrlRef": "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL",
                "envKeys": ACCOUNT_PROFILE_ENV_KEYS["coding-daytona-pi"],
            },
        }
        secret_by_id = {
            str(row.get("id")): row
            for row in secrets
            if isinstance(row, dict) and row.get("id")
        }
        common_company_ids = {
            str(row.get("companyId"))
            for row in secrets
            if isinstance(row, dict) and row.get("companyId")
        }
        _expect(
            findings,
            paperclip.get("status") == "ready"
            and _nested(paperclip, "runtimeSecurity", "provider") == "local_encrypted"
            and _nested(paperclip, "runtimeSecurity", "strictMode") is True
            and _nested(paperclip, "runtimeSecurity", "llmApiKeyConfigured") is False
            and _nested(paperclip, "responsibleUser", "configured") is True
            and paperclip.get("unsafeInlineBindings") == []
            and security.get("ok") is True
            and security.get("findings") == [],
            "paperclip_secret_runtime_security_invalid",
        )
        _expect(
            findings,
            bool(secrets)
            and len(common_company_ids) == 1
            and all(
                isinstance(row, dict)
                and row.get("scope") == "company"
                and row.get("provider") == "local_encrypted"
                and row.get("managedMode") == "paperclip_managed"
                and row.get("status") == "ready"
                and bool(row.get("sourceKey"))
                and bool(row.get("id"))
                and bool(
                    re.fullmatch(r"[0-9a-f]{64}", str(row.get("fingerprint") or ""))
                )
                for row in secrets
            ),
            "paperclip_company_secret_scope_invalid",
        )
        github_definitions = [
            row
            for row in definitions
            if isinstance(row, dict)
            and row.get("key") == "mte.github.personal_access_token"
        ]
        _expect(
            findings,
            len(github_definitions) == 1
            and github_definitions[0].get("status") == "ready"
            and github_definitions[0].get("sourceConfigured") is True
            and github_definitions[0].get("provider") == "local_encrypted"
            and github_definitions[0].get("managedMode") == "paperclip_managed"
            and github_definitions[0].get("scope") == "user"
            and bool(github_definitions[0].get("definitionId"))
            and bool(github_definitions[0].get("userSecretId")),
            "paperclip_github_user_secret_scope_invalid",
        )
        _expect(
            findings,
            [row.get("profileRef") for row in bindings if isinstance(row, dict)]
            == list(NATIVE_HARNESS_PROFILES)
            and len(bindings) == 3
            and all(isinstance(row, dict) for row in bindings),
            "paperclip_agent_binding_profile_set_invalid",
        )
        workspace_id = str(project_workspace.get("workspaceId") or "")
        workspace_policy = (
            project_workspace.get("policy")
            if isinstance(project_workspace.get("policy"), dict)
            else {}
        )
        expected_repo_url = (
            "https://github.com/"
            f"{values.get('E2E_GITHUB_OWNER', '')}/"
            f"{values.get('E2E_GITHUB_REPOSITORY', '')}.git"
        )
        expected_branch = values.get("E2E_GITHUB_BASE_BRANCH", "")
        _expect(
            findings,
            project_workspace.get("status") == "ready"
            and bool(workspace_id)
            and project_workspace.get("sourceType") == "git_repo"
            and project_workspace.get("repoUrl") == expected_repo_url
            and project_workspace.get("defaultRef") == expected_branch
            and project_workspace.get("isPrimary") is True
            and workspace_policy
            == {
                "enabled": True,
                "defaultMode": "isolated_workspace",
                "allowIssueOverride": True,
                "defaultProjectWorkspaceId": workspace_id,
                "workspaceStrategy": {
                    "type": "cloud_sandbox",
                    "baseRef": expected_branch,
                },
            },
            "paperclip_project_workspace_policy_invalid",
        )
        environment_id = str(daytona_environment.get("environmentId") or "")
        _expect(
            findings,
            daytona_environment.get("status") == "ready"
            and bool(environment_id)
            and daytona_environment.get("name")
            == values.get("MTE_DAYTONA_ENVIRONMENT_NAME")
            and daytona_environment.get("driver") == "sandbox"
            and daytona_environment.get("provider") == "daytona",
            "paperclip_daytona_environment_invalid",
        )
        _expect(
            findings,
            [
                row.get("profileRef")
                for row in environment_bindings
                if isinstance(row, dict)
            ]
            == list(NATIVE_HARNESS_PROFILES)
            and len(environment_bindings) == len(NATIVE_HARNESS_PROFILES)
            and all(
                isinstance(row, dict)
                and bool(row.get("agentId"))
                and row.get("status") == "ready"
                and row.get("environmentId") == environment_id
                and row.get("defaultEnvironmentId") == environment_id
                for row in environment_bindings
            ),
            "paperclip_agent_environment_binding_invalid",
        )
        bound_ids: list[str] = []
        for row in bindings:
            if not isinstance(row, dict):
                continue
            contract = expected.get(str(row.get("profileRef")), {})
            router_secret_id = str(row.get("routerSecretId") or "")
            toolhive_secret_id = str(row.get("toolhiveSecretId") or "")
            bound_ids.extend((router_secret_id, toolhive_secret_id))
            _expect(
                findings,
                row.get("adapterType") == contract.get("adapterType")
                and row.get("routerKeyRef") == contract.get("routerKeyRef")
                and row.get("toolhiveTokenRef") == contract.get("toolhiveTokenRef")
                and row.get("toolhiveUrlRef") == contract.get("toolhiveUrlRef")
                and row.get("gatewayHost") == values.get("MTE_AGENT_GATEWAY_HOST")
                and row.get("status") == "ready"
                and row.get("configDrift") is False
                and bool(row.get("cwd"))
                and _exact_string_set(
                    row.get("envKeys"), contract.get("envKeys", set())
                )
                and router_secret_id in secret_by_id
                and secret_by_id.get(router_secret_id, {}).get("sourceKey")
                == contract.get("routerKeyRef")
                and toolhive_secret_id in secret_by_id
                and secret_by_id.get(toolhive_secret_id, {}).get("sourceKey")
                == contract.get("toolhiveTokenRef"),
                "paperclip_profile_secret_binding_invalid",
                profile=row.get("profileRef"),
            )
        _expect(
            findings,
            len(bound_ids) == 6
            and all(bound_ids)
            and len(set(bound_ids)) == len(bound_ids),
            "paperclip_profile_secret_ids_not_unique",
        )
    return {
        "C075": _connection_result(
            "C075",
            findings,
            evidence=ACCOUNT_PROVISION_VERIFY_EVIDENCE,
            details={
                "dependencyEvidence": [
                    {
                        "path": str(E2E_EVIDENCE),
                        "sha256": _sha256_file(E2E_EVIDENCE),
                    }
                ]
            },
        )
    }


def _cloudflare_semantic_projection(row: dict) -> dict:
    return {key: value for key, value in row.items() if key != "dependencyEvidence"}


def _cloudflare_split_connection_evidence(
    connection_id: str, acceptance_row: dict
) -> tuple[dict | None, list[dict]]:
    path = CLOUDFLARE_CONNECTION_EVIDENCE[connection_id]
    document, findings = _bound_evidence(
        path,
        kind="CloudflareConnectionEvidence",
        status="passed",
        time_fields=("generatedAt",),
        canonical_field=("canonicalSourceSha256",),
        producer_field=("producerSha256",),
        producer_path=SERVER_CLOUDFLARE_ACCEPTANCE_SOURCE,
    )
    if document is None:
        return None, findings
    gate = _source_gate()
    subject = _cloudflare_semantic_projection(acceptance_row)
    _cloudflare_security_findings(document, path, findings)
    _expect(findings, document.get("ok") is True, "cloudflare_split_not_ok")
    _expect(
        findings,
        document.get("connectionId") == connection_id,
        "cloudflare_split_connection_id_mismatch",
    )
    _expect(
        findings,
        gate is not None and document.get("sourceGate") == gate,
        "cloudflare_split_source_gate_mismatch",
    )
    _expect(
        findings,
        document.get("producerPath") == str(SERVER_CLOUDFLARE_ACCEPTANCE_SOURCE),
        "cloudflare_split_producer_path_mismatch",
    )
    _expect(
        findings,
        document.get("configSha256") == _sha256_file(CONFIG),
        "cloudflare_split_config_hash_mismatch",
    )
    _expect(
        findings,
        document.get("manifestSha256") == _sha256_file(PROJECTION_MANIFEST),
        "cloudflare_split_manifest_hash_mismatch",
    )
    _expect(
        findings,
        document.get("secretValuesPrinted") is False,
        "cloudflare_split_secret_output_guard_missing",
    )
    _expect(
        findings,
        document.get("connection") == subject
        and document.get("subjectSha256") == _canonical_json_sha256(subject),
        "cloudflare_split_subject_mismatch",
    )
    return document, findings


def _cloudflare_data_content_edge_contract() -> tuple[dict, list[dict]]:
    findings: list[dict] = []
    plane = _json_object(DATA_CONTENT_PLANE)
    apps = _json_object(SECRET_ROOT / "cloudflare/apps.json")
    if plane is None or apps is None:
        return {}, [{"finding": "cloudflare_data_content_projection_missing"}]
    data_content = apps.get("dataContent")
    roles = data_content.get("roles") if isinstance(data_content, dict) else None
    plane_roles = plane.get("roles") if isinstance(plane, dict) else None
    app_rows = apps.get("apps") if isinstance(apps.get("apps"), dict) else {}
    _expect(
        findings,
        isinstance(data_content, dict)
        and set(data_content) == {"profile", "projectionSha256", "roles"}
        and data_content.get("profile") == plane.get("profile")
        and data_content.get("projectionSha256") == _sha256_file(DATA_CONTENT_PLANE)
        and isinstance(roles, dict)
        and set(roles) == {"tablesUi", "documentsUi"}
        and isinstance(plane_roles, dict),
        "cloudflare_data_content_projection_mismatch",
    )
    normalized: dict[str, dict] = {}
    application_ids: list[str] = []
    if isinstance(roles, dict) and isinstance(plane_roles, dict):
        for role_id in ("tablesUi", "documentsUi"):
            role = roles.get(role_id)
            plane_role = plane_roles.get(role_id)
            application_id = (
                str(role.get("applicationId", "")) if isinstance(role, dict) else ""
            )
            app = app_rows.get(application_id)
            valid = (
                isinstance(role, dict)
                and set(role) == {"applicationId", "hostname", "accessClass"}
                and isinstance(plane_role, dict)
                and plane_role.get("componentId") == application_id
                and isinstance(app, dict)
                and app.get("hostname") == role.get("hostname")
                and app.get("accessClass") == "human"
                and role.get("accessClass") == "human"
            )
            _expect(
                findings,
                valid,
                "cloudflare_data_content_role_mismatch",
                role=role_id,
            )
            if valid:
                application_ids.append(application_id)
                normalized[role_id] = dict(role)
    unique_application_ids = list(dict.fromkeys(application_ids))
    return {
        "profile": data_content.get("profile")
        if isinstance(data_content, dict)
        else None,
        "projectionSha256": (
            data_content.get("projectionSha256")
            if isinstance(data_content, dict)
            else None
        ),
        "roles": normalized,
        "applicationIds": unique_application_ids,
    }, findings


def _cloudflare_expected_edge_inventory() -> tuple[dict, list[dict]]:
    """Derive exact Cloudflare inventory from the active hash-bound projection."""

    findings: list[dict] = []
    apps_path = SECRET_ROOT / "cloudflare/apps.json"
    apps_document = _json_object(apps_path)
    plane = _json_object(DATA_CONTENT_PLANE)
    manifest = _json_object(PROJECTION_MANIFEST)
    values, canonical_findings = dotenv(CANONICAL_ENV)
    findings.extend(canonical_findings)
    gate = _source_gate()
    if not all(
        isinstance(item, dict) for item in (apps_document, plane, manifest, gate)
    ):
        return {}, [{"finding": "cloudflare_apps_projection_binding_missing"}]
    assert apps_document is not None
    assert plane is not None
    assert manifest is not None
    assert gate is not None
    rows = (
        manifest.get("projections")
        if isinstance(manifest.get("projections"), list)
        else []
    )
    matching = [
        row
        for row in rows
        if isinstance(row, dict) and row.get("path") == str(apps_path)
    ]
    generated = (
        apps_document.get("_generated")
        if isinstance(apps_document.get("_generated"), dict)
        else {}
    )
    app_rows = (
        apps_document.get("apps") if isinstance(apps_document.get("apps"), dict) else {}
    )
    data_content = (
        apps_document.get("dataContent")
        if isinstance(apps_document.get("dataContent"), dict)
        else {}
    )
    active_profile = values.get("DATA_CONTENT_PROFILE", "").strip()
    _expect(
        findings,
        len(matching) == 1
        and matching[0].get("contentSha256") == _sha256_file(apps_path)
        and matching[0].get("sourceSha256") == gate.get("sourceSha256")
        and matching[0].get("generatorVersion") == gate.get("generatorVersion")
        and generated.get("sourceSha256") == gate.get("sourceSha256")
        and generated.get("generatorVersion") == gate.get("generatorVersion"),
        "cloudflare_apps_projection_hash_binding_invalid",
    )
    _expect(
        findings,
        bool(active_profile)
        and plane.get("profile") == active_profile
        and data_content.get("profile") == active_profile
        and data_content.get("projectionSha256") == _sha256_file(DATA_CONTENT_PLANE),
        "cloudflare_apps_active_profile_mismatch",
    )
    hostnames: list[str] = []
    valid_apps = bool(app_rows)
    for application_id, app in app_rows.items():
        valid = (
            bool(application_id)
            and isinstance(app, dict)
            and bool(app.get("hostname"))
            and bool(app.get("origin"))
            and app.get("accessClass") in {"human", "service"}
        )
        valid_apps = valid_apps and valid
        if valid:
            hostnames.append(str(app["hostname"]))
    _expect(
        findings,
        valid_apps and len(hostnames) == len(set(hostnames)),
        "cloudflare_apps_inventory_invalid",
    )
    return {
        "profile": active_profile,
        "applicationCount": len(app_rows),
        "humanApplicationCount": sum(
            1
            for app in app_rows.values()
            if isinstance(app, dict) and app.get("accessClass") == "human"
        ),
        "serviceApplicationCount": sum(
            1
            for app in app_rows.values()
            if isinstance(app, dict) and app.get("accessClass") == "service"
        ),
    }, findings


def _cloudflare_connection_proofs(requested: set[str]) -> dict[str, dict]:
    plane = _json_object(DATA_CONTENT_PLANE)
    external_data_content = (
        isinstance(plane, dict) and plane.get("profile") == "postgres-notion"
    )
    ids = requested & {
        "C004",
        "C005",
        "C025",
        "C026",
        "C029",
        "C032",
        "C046",
        "C060",
        "C065",
        "C066",
        "C067",
    }
    if external_data_content:
        # Notion is an external workspace connector.  It has no platform edge
        # application and C029 is owned by the connector/integration producer.
        ids.discard("C029")
    if not ids:
        return {}
    document, envelope = _bound_evidence(
        CLOUDFLARE_ACCEPTANCE_EVIDENCE,
        kind="CloudflareAcceptanceEvidence",
        status="passed",
        time_fields=("generatedAt",),
        canonical_field=("canonicalSourceSha256",),
        producer_field=("producerSha256",),
        producer_path=SERVER_CLOUDFLARE_ACCEPTANCE_SOURCE,
    )
    gate = _source_gate()
    if document is not None:
        _cloudflare_security_findings(
            document, CLOUDFLARE_ACCEPTANCE_EVIDENCE, envelope
        )
        _expect(envelope, document.get("ok") is True, "cloudflare_acceptance_not_ok")
        _expect(
            envelope,
            gate is not None and document.get("sourceGate") == gate,
            "cloudflare_source_gate_mismatch",
        )
        _expect(
            envelope,
            document.get("producerPath") == str(SERVER_CLOUDFLARE_ACCEPTANCE_SOURCE),
            "cloudflare_producer_path_mismatch",
        )
        _expect(
            envelope,
            document.get("configSha256") == _sha256_file(CONFIG),
            "cloudflare_config_hash_mismatch",
        )
        _expect(
            envelope,
            document.get("manifestSha256") == _sha256_file(PROJECTION_MANIFEST),
            "cloudflare_manifest_hash_mismatch",
        )
        _expect(
            envelope,
            document.get("secretValuesPrinted") is False,
            "cloudflare_secret_output_guard_missing",
        )
    if document is None or envelope:
        return {
            connection_id: _connection_result(
                connection_id, list(envelope), evidence=CLOUDFLARE_ACCEPTANCE_EVIDENCE
            )
            for connection_id in ids
        }
    raw_rows = document.get("connections")
    if isinstance(raw_rows, dict):
        rows = {
            str(key): value
            for key, value in raw_rows.items()
            if isinstance(value, dict)
        }
    elif isinstance(raw_rows, list):
        rows = {
            str(row.get("id")): row
            for row in raw_rows
            if isinstance(row, dict) and row.get("id")
        }
    else:
        rows = {}
    expected_ids = {
        "C004",
        "C005",
        "C025",
        "C026",
        "C029",
        "C032",
        "C046",
        "C060",
        "C065",
        "C066",
        "C067",
    }
    if external_data_content:
        expected_ids.remove("C029")
    shared: list[dict] = []
    _expect(shared, set(rows) == expected_ids, "cloudflare_connection_set_mismatch")
    results: dict[str, dict] = {}
    human_ids = {"C004", "C005", "C025", "C032", "C046"}
    if not external_data_content:
        human_ids.add("C029")
    data_content, data_content_findings = _cloudflare_data_content_edge_contract()
    for connection_id in ids:
        findings = list(shared)
        row = rows.get(connection_id, {})
        _expect(
            findings,
            row.get("id") == connection_id
            and row.get("ok") is True
            and row.get("state") == "passed",
            "cloudflare_connection_row_invalid",
        )
        if connection_id in CLOUDFLARE_CONNECTION_EVIDENCE:
            _split, split_findings = _cloudflare_split_connection_evidence(
                connection_id, row
            )
            findings.extend(split_findings)
            split_path = CLOUDFLARE_CONNECTION_EVIDENCE[connection_id]
            _expect(
                findings,
                row.get("dependencyEvidence")
                == [
                    {
                        "path": str(split_path),
                        "sha256": _sha256_file(split_path),
                        "kind": "CloudflareConnectionEvidence",
                        "producerSha256": _sha256_file(
                            SERVER_CLOUDFLARE_ACCEPTANCE_SOURCE
                        ),
                    }
                ],
                "cloudflare_split_dependency_reference_mismatch",
            )
        if connection_id in human_ids:
            _expect(
                findings,
                bool(row.get("canonicalHostname"))
                and row.get("expectedAccessClass") == "human"
                and row.get("anonymousStatus") == 302
                and row.get("accessLocationVerified") is True
                and row.get("edgeGateVerified") is True
                and row.get("serviceSemanticVerified") is True
                and _dependency_refs_current(row.get("dependencyEvidence")),
                "cloudflare_human_route_semantics_invalid",
            )
            if connection_id == "C029":
                _c029_document, c029_findings = _c029_integration_evidence()
                findings.extend(c029_findings)
                findings.extend(data_content_findings)
                edge_apps = (
                    row.get("edgeApplications")
                    if isinstance(row.get("edgeApplications"), list)
                    else []
                )
                dependencies = (
                    row.get("dependencyEvidence")
                    if isinstance(row.get("dependencyEvidence"), list)
                    else []
                )
                data_evidence = (
                    row.get("dataContentEvidence")
                    if isinstance(row.get("dataContentEvidence"), dict)
                    else {}
                )
                table_evidence = (
                    data_evidence.get("tables")
                    if isinstance(data_evidence.get("tables"), dict)
                    else {}
                )
                document_evidence = (
                    data_evidence.get("documents")
                    if isinstance(data_evidence.get("documents"), dict)
                    else {}
                )
                expected_dependency_paths = [
                    str(CLOUDFLARE_SEMANTIC_EVIDENCE),
                    str(C029_INTEGRATION_EVIDENCE),
                    table_evidence.get("path"),
                    document_evidence.get("path"),
                ]
                _expect(
                    findings,
                    not _contains_legacy_storage_key(row)
                    and row.get("dataContentProfile") == data_content.get("profile")
                    and row.get("dataContentProjectionSha256")
                    == data_content.get("projectionSha256")
                    and row.get("dataContentApplications")
                    == data_content.get("applicationIds")
                    and row.get("dataContentRoles") == data_content.get("roles")
                    and row.get("canonicalHostnames")
                    == list(
                        dict.fromkeys(
                            [
                                row.get("tablesHostname"),
                                row.get("documentsHostname"),
                            ]
                        )
                    )
                    and len(edge_apps) == len(data_content.get("applicationIds") or [])
                    and [
                        item.get("applicationId")
                        for item in edge_apps
                        if isinstance(item, dict)
                    ]
                    == data_content.get("applicationIds")
                    and all(
                        isinstance(item, dict)
                        and item.get("canonicalHostname")
                        in {row.get("tablesHostname"), row.get("documentsHostname")}
                        and item.get("expectedAccessClass") == "human"
                        and item.get("anonymousStatus") == 302
                        and item.get("accessLocationVerified") is True
                        for item in edge_apps
                    )
                    and row.get("osiLicensesVerified") is True
                    and row.get("tablePersistenceVerified") is True
                    and row.get("documentPersistenceVerified") is True
                    and row.get("applicationRestartObserved") is True
                    and row.get("cleanupCompleted") is True
                    and [
                        dependency.get("path")
                        for dependency in dependencies
                        if isinstance(dependency, dict)
                    ]
                    == expected_dependency_paths
                    and table_evidence
                    == (dependencies[2] if len(dependencies) > 2 else None)
                    and document_evidence
                    == (dependencies[3] if len(dependencies) > 3 else None)
                    and _dependency_refs_current(dependencies),
                    "ose_storage_restart_persistence_not_proven",
                )
            if connection_id == "C046":
                _expect(
                    findings,
                    row.get("dashboardProvisioned") is True
                    and row.get("datasourceQueriesVerified") is True,
                    "grafana_dashboard_edge_semantics_invalid",
                )
        elif connection_id == "C026":
            _expect(
                findings,
                row.get("expectedAccessClass") == "service"
                and row.get("anonymousDenied") is True
                and row.get("serviceTokenStatus") == 200
                and row.get("liveScrapeKnownDocumentObserved") is True
                and row.get("liveScrapeMetadataStatus") == 200
                and row.get("liveScrapeCacheBypassed") is True
                and row.get("edgeGateVerified") is True
                and row.get("serviceSemanticVerified") is True
                and _dependency_refs_current(row.get("dependencyEvidence")),
                "cloudflare_firecrawl_service_semantics_invalid",
            )
        elif connection_id == "C060":
            blocked = (
                row.get("externalPortsBlocked")
                if isinstance(row.get("externalPortsBlocked"), dict)
                else {}
            )
            canonical_values, canonical_findings = dotenv(CANONICAL_ENV)
            findings.extend(canonical_findings)
            ssh_cidrs = canonical_operator_ssh_cidrs(
                canonical_values.get("MTE_OPERATOR_SSH_CIDRS", "")
            )
            ipv4_count = (
                sum(ipaddress.ip_network(item).version == 4 for item in ssh_cidrs)
                if ssh_cidrs
                else 0
            )
            ipv6_count = len(ssh_cidrs or []) - ipv4_count
            ssh_cidrs_sha = (
                hashlib.sha256("\n".join(ssh_cidrs).encode()).hexdigest()
                if ssh_cidrs
                else None
            )
            _expect(
                findings,
                ssh_cidrs is not None
                and row.get("sshReachable") is True
                and row.get("expectedTarget") is True
                and row.get("excludedTargetsRejected") is True
                and all(
                    blocked.get(str(port)) is True or blocked.get(port) is True
                    for port in (80, 443, 2377, 3000, 7946, 20241)
                )
                and all(
                    row.get(key) is True
                    for key in (
                        "firewallV4Input",
                        "firewallV4Docker",
                        "firewallV6Input",
                        "firewallV6Docker",
                    )
                )
                and row.get("firewallPolicyVersion") == "mte-origin-firewall/v2"
                and row.get("firewallServiceActive") is True
                and row.get("firewallServiceEnabled") is True
                and row.get("firewallRecoveryTimerActive") is True
                and row.get("firewallRecoveryTimerEnabled") is True
                and bool(row.get("publicInterface"))
                and all(
                    row.get(key) is True
                    for family in ("V4", "V6")
                    for key in (
                        f"firewall{family}InputTcpDrop",
                        f"firewall{family}InputUdpDrop",
                        f"firewall{family}DockerTcpDrop",
                        f"firewall{family}DockerUdpDrop",
                        f"firewall{family}Established",
                    )
                )
                and row.get("firewallSshCidrsEnforced") is True
                and row.get("firewallSshCidrCount") == len(ssh_cidrs)
                and row.get("firewallSshIpv4CidrCount") == ipv4_count
                and row.get("firewallSshIpv6CidrCount") == ipv6_count
                and row.get("operatorSshCidrsSha256") == ssh_cidrs_sha
                and row.get("udp443Blocked") is True
                and row.get("publicTcpDefaultDenied") is True
                and row.get("publicUdpDefaultDenied") is True,
                "host_preflight_firewall_semantics_invalid",
            )
        elif connection_id == "C065":
            _expect(
                findings,
                row.get("tunnelConnectorHealthy") is True
                and row.get("cloudflaredRunning") is True
                and row.get("restartCount") == 0,
                "cloudflare_tunnel_health_semantics_invalid",
            )
        elif connection_id == "C066":
            expected_inventory, inventory_findings = (
                _cloudflare_expected_edge_inventory()
            )
            findings.extend(inventory_findings)
            expected_count = expected_inventory.get("applicationCount")
            _expect(
                findings,
                isinstance(expected_count, int)
                and expected_count > 0
                and row.get("exactManagedRoutes") == expected_count
                and row.get("exactDnsRecords") == expected_count
                and row.get("exactAccessApplications") == expected_count
                and row.get("exactAccessPolicies") == expected_count
                and row.get("routeOriginsVerified") is True
                and row.get("accessClassesVerified") is True
                and row.get("humanAccessPolicyScoped") is True
                and row.get("serviceAccessTokenScoped") is True
                and row.get("foreignDnsPreserved") is True,
                "cloudflare_tunnel_route_semantics_invalid",
            )
        elif connection_id == "C067":
            changes = row.get("changes") if isinstance(row.get("changes"), dict) else {}
            _expect(
                findings,
                row.get("tofuDetailedExitCode") == 0
                and changes == {"create": 0, "update": 0, "delete": 0}
                and str(row.get("iacDirMode")) == "0700"
                and str(row.get("stateMode")) == "0600"
                and row.get("tfvarsContainsApiToken") is False,
                "cloudflare_empty_plan_semantics_invalid",
            )
        results[connection_id] = _connection_result(
            connection_id, findings, evidence=CLOUDFLARE_ACCEPTANCE_EVIDENCE
        )
    return results


def _secret_store_audit() -> dict:
    findings: list[dict] = []
    if not SECRET_ROOT.is_dir() or SECRET_ROOT.is_symlink():
        return _connection_result(
            "C070", [{"finding": "secret_root_missing_or_symlink"}]
        )
    expected_uid = 0 if str(SECRET_ROOT).startswith("/root/") else os.getuid()
    paths: list[Path] = [SECRET_ROOT, CANONICAL_ENV, PROJECTION_MANIFEST]
    for relative in ("services", "cloudflare", "integrations"):
        base = SECRET_ROOT / relative
        if base.exists():
            paths.append(base)
            paths.extend(sorted(base.rglob("*")))
    for candidate in sorted(SECRET_ROOT.glob("*.lock")):
        paths.append(candidate)
    seen: set[Path] = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        try:
            info = path.lstat()
        except OSError:
            findings.append(
                {"finding": "secret_path_missing_or_unreadable", "path": str(path)}
            )
            continue
        if path.is_symlink():
            findings.append(
                {"finding": "secret_symlink_not_allowed", "path": str(path)}
            )
            continue
        mode = info.st_mode & 0o777
        if info.st_uid != expected_uid:
            findings.append({"finding": "secret_owner_mismatch", "path": str(path)})
        if path.is_dir() and mode & 0o077:
            findings.append(
                {
                    "finding": "secret_directory_permissions_too_open",
                    "path": str(path),
                    "actualMode": oct(mode),
                }
            )
        if path.is_file() and mode & 0o077:
            findings.append(
                {
                    "finding": "secret_file_permissions_too_open",
                    "path": str(path),
                    "actualMode": oct(mode),
                }
            )
    source = config_source_check(include_static=True)
    _expect(
        findings,
        source.get("ok") is True,
        "canonical_config_or_secret_leak_audit_failed",
    )
    return _connection_result(
        "C070",
        findings,
        details={
            "checkedPathCount": len(seen),
            "producerSha256": _sha256_file(Path(__file__)),
            "canonicalSourceSha256": _canonical_sha256(),
        },
    )


def _configuration_connection_proofs(requested: set[str]) -> dict[str, dict]:
    results: dict[str, dict] = {}
    if "C070" in requested:
        results["C070"] = _secret_store_audit()
    if "C071" in requested:
        source = config_source_check(include_static=True)
        findings = (
            []
            if source.get("ok") is True
            else list(
                source.get("findings")
                or [{"finding": "canonical_projection_audit_failed"}]
            )
        )
        gate = _source_gate()
        _expect(findings, gate is not None, "canonical_source_gate_invalid")
        manifest = _json_object(PROJECTION_MANIFEST)
        projections = (
            manifest.get("projections")
            if isinstance(manifest, dict)
            and isinstance(manifest.get("projections"), list)
            else []
        )
        _expect(
            findings,
            len(projections) > 0
            and len(projections) == source.get("projections")
            and all(isinstance(row, dict) and row.get("path") for row in projections),
            "canonical_projection_inventory_invalid",
            actual=len(projections),
            activeProfile=(
                dotenv(CANONICAL_ENV)[0].get("DATA_CONTENT_PROFILE")
                if CANONICAL_ENV.is_file()
                else None
            ),
        )
        results["C071"] = _connection_result(
            "C071",
            findings,
            evidence=PROJECTION_MANIFEST,
            details={"sourceGate": gate, "projectionCount": len(projections)},
        )
    return results


def _daytona_image_contract_valid(images: object, values: dict[str, str]) -> bool:
    """Match the complete schema emitted by ``daytona.sh`` without coercion."""
    if not isinstance(images, dict):
        return False
    snapshots = images.get("snapshots")
    deferred_cleanup = images.get("deferredCleanup")
    if not isinstance(snapshots, list):
        return False
    if not isinstance(deferred_cleanup, list):
        return False
    expected_keys = {
        "apiVersion",
        "kind",
        "status",
        "generatedAt",
        "producerSha256",
        "canonicalSourceSha256",
        "controlPlane",
        "sandboxVersion",
        "snapshotContractHash",
        "generation",
        "sandboxImage",
        "source",
        "snapshots",
        "deferredCleanup",
        "pointerSwitch",
        "resources",
        "harnessVersions",
        "credentialsBakedIntoImage",
    }
    expected_control_plane = {
        "version": values.get("MTE_DAYTONA_CONTROL_PLANE_VERSION"),
        "sourceCommit": values.get("MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT"),
    }
    resources = {
        "coding": {
            "cpu": int(values.get("MTE_DAYTONA_CODING_CPU") or 0),
            "memory": int(values.get("MTE_DAYTONA_CODING_MEMORY_GIB") or 0),
            "disk": int(values.get("MTE_DAYTONA_DISK_GIB") or 0),
        },
        "general": {
            "cpu": int(values.get("MTE_DAYTONA_GENERAL_CPU") or 0),
            "memory": int(values.get("MTE_DAYTONA_GENERAL_MEMORY_GIB") or 0),
            "disk": int(values.get("MTE_DAYTONA_DISK_GIB") or 0),
        },
    }
    generation = str(images.get("generation") or "")
    expected_snapshots = (
        (
            "coding",
            values.get("MTE_DAYTONA_CODING_SNAPSHOT"),
            resources["coding"],
        ),
        (
            "general",
            values.get("MTE_DAYTONA_GENERAL_SNAPSHOT"),
            resources["general"],
        ),
    )
    snapshots_valid = len(snapshots) == 2
    if snapshots_valid:
        for row, (role, name, expected_resources) in zip(snapshots, expected_snapshots):
            snapshots_valid = snapshots_valid and (
                isinstance(row, dict)
                and set(row)
                == {
                    "role",
                    "id",
                    "name",
                    "state",
                    "ref",
                    "cpu",
                    "memoryGiB",
                    "diskGiB",
                }
                and row.get("role") == role
                and row.get("name") == name
                and row.get("state") == "active"
                and bool(row.get("id"))
                and row.get("ref") == values.get("MTE_DAYTONA_SANDBOX_IMAGE")
                and row.get("cpu") == expected_resources["cpu"]
                and row.get("memoryGiB") == expected_resources["memory"]
                and row.get("diskGiB") == expected_resources["disk"]
            )
    snapshot_contract_hash = hashlib.sha256(
        json.dumps(
            {
                "sandboxImage": images.get("sandboxImage"),
                "sandboxImageRevision": values.get(
                    "MTE_DAYTONA_SANDBOX_IMAGE_REVISION"
                ),
                "resources": resources,
                "harnessVersions": images.get("harnessVersions"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    prefixes = (
        values.get("MTE_DAYTONA_CODING_SNAPSHOT_PREFIX"),
        values.get("MTE_DAYTONA_GENERAL_SNAPSHOT_PREFIX"),
    )
    active_names = {
        values.get("MTE_DAYTONA_CODING_SNAPSHOT"),
        values.get("MTE_DAYTONA_GENERAL_SNAPSHOT"),
    }
    return (
        set(images) == expected_keys
        and images.get("apiVersion") == "micro-task-engine/v1alpha1"
        and images.get("kind") == "DaytonaHarnessSnapshots"
        and images.get("status") == "ready"
        and images.get("controlPlane") == expected_control_plane
        and images.get("sandboxVersion") == values.get("MTE_DAYTONA_SANDBOX_VERSION")
        and images.get("resources") == resources
        and images.get("harnessVersions")
        == {
            "codex": values.get("MTE_CODEX_VERSION"),
            "claudeCode": values.get("MTE_CLAUDE_CODE_VERSION"),
            "pi": values.get("MTE_PI_VERSION"),
        }
        and images.get("sandboxImage") == values.get("MTE_DAYTONA_SANDBOX_IMAGE")
        and bool(
            re.fullmatch(
                r"[^\s@]+@sha256:[0-9a-f]{64}",
                str(images.get("sandboxImage") or ""),
            )
        )
        and images.get("source")
        == {
            "url": values.get("MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL"),
            "revision": values.get("MTE_DAYTONA_SANDBOX_IMAGE_REVISION"),
        }
        and images.get("snapshotContractHash") == snapshot_contract_hash
        and generation == snapshot_contract_hash[:12]
        and prefixes[0] != prefixes[1]
        and snapshots_valid
        and len({row.get("id") for row in snapshots}) == 2
        and len({row.get("name") for row in snapshots}) == 2
        and snapshots[0].get("name") == f"{prefixes[0]}-{generation}"
        and snapshots[1].get("name") == f"{prefixes[1]}-{generation}"
        and images.get("pointerSwitch")
        == {
            "coding": values.get("MTE_DAYTONA_CODING_SNAPSHOT"),
            "general": values.get("MTE_DAYTONA_GENERAL_SNAPSHOT"),
            "completed": True,
        }
        and all(
            isinstance(row, dict)
            and set(row) == {"id", "name", "state"}
            and bool(row.get("id"))
            and row.get("name") not in active_names
            and any(
                str(row.get("name") or "").startswith(f"{prefix}-")
                for prefix in prefixes
            )
            for row in deferred_cleanup
        )
        and images.get("credentialsBakedIntoImage") is False
    )


def _daytona_connection_proofs(requested: set[str]) -> dict[str, dict]:
    ids = requested & {"C072", "C074"}
    if not ids:
        return {}
    document, envelope = _bound_evidence(
        PAPERCLIP_DAYTONA_VERIFY_EVIDENCE,
        kind="PaperclipExperimentalReconcile",
        status="ready",
        time_fields=("observedAt",),
        canonical_field=("canonicalSourceSha256",),
        producer_field=("producerSha256",),
        producer_path=SERVER_PAPERCLIP_EXPERIMENTAL_SOURCE,
    )
    if document is not None:
        _expect(
            envelope,
            document.get("feature") == "daytona" and document.get("action") == "verify",
            "paperclip_daytona_not_verify_evidence",
        )
        _expect(
            envelope,
            document.get("producerPath") == str(SERVER_PAPERCLIP_EXPERIMENTAL_SOURCE),
            "paperclip_daytona_producer_path_mismatch",
        )
    if document is None or envelope:
        return {
            connection_id: _connection_result(
                connection_id,
                list(envelope),
                evidence=PAPERCLIP_DAYTONA_VERIFY_EVIDENCE,
            )
            for connection_id in ids
        }
    details = (
        document.get("details") if isinstance(document.get("details"), dict) else {}
    )
    refs = (
        details.get("runtimeEvidence")
        if isinstance(details.get("runtimeEvidence"), dict)
        else {}
    )
    control_plane_ref = (
        refs.get("controlPlane") if isinstance(refs.get("controlPlane"), dict) else {}
    )
    image_ref = refs.get("images") if isinstance(refs.get("images"), dict) else {}
    lifecycle_ref = (
        refs.get("lifecycle") if isinstance(refs.get("lifecycle"), dict) else {}
    )
    common: list[dict] = []
    _control_plane, control_plane_findings = _daytona_control_plane_evidence()
    common.extend(control_plane_findings)
    _expect(
        common,
        set(refs) == {"controlPlane", "images", "lifecycle"}
        and control_plane_ref
        == {
            "path": str(PAPERCLIP_DAYTONA_CONTROL_PLANE_EVIDENCE),
            "kind": "PaperclipDaytonaControlPlaneEvidence",
            "status": "ready",
            "sha256": _sha256_file(PAPERCLIP_DAYTONA_CONTROL_PLANE_EVIDENCE),
        }
        and image_ref
        == {
            "path": str(DAYTONA_IMAGES_EVIDENCE),
            "kind": "DaytonaHarnessSnapshots",
            "status": "ready",
            "sha256": _sha256_file(DAYTONA_IMAGES_EVIDENCE),
        }
        and lifecycle_ref
        == {
            "path": str(DAYTONA_LIFECYCLE_EVIDENCE),
            "kind": "DaytonaSandboxLifecycleEvidence",
            "status": "ready",
            "sha256": _sha256_file(DAYTONA_LIFECYCLE_EVIDENCE),
        },
        "daytona_nested_evidence_hash_mismatch",
    )
    images = _json_object(DAYTONA_IMAGES_EVIDENCE)
    lifecycle = _json_object(DAYTONA_LIFECYCLE_EVIDENCE)
    values, canonical_findings = dotenv(CANONICAL_ENV)
    common.extend(canonical_findings)
    _expect(
        common,
        _daytona_image_contract_valid(images, values),
        "daytona_snapshot_schema_invalid",
    )
    for path, nested, kind in (
        (DAYTONA_IMAGES_EVIDENCE, images, "DaytonaHarnessSnapshots"),
        (DAYTONA_LIFECYCLE_EVIDENCE, lifecycle, "DaytonaSandboxLifecycleEvidence"),
    ):
        _expect(
            common,
            isinstance(nested, dict),
            "daytona_nested_evidence_missing",
            path=str(path),
        )
        if isinstance(nested, dict):
            _expect(
                common,
                _mode_is_0600(path),
                "daytona_nested_evidence_mode_invalid",
                path=str(path),
            )
            _expect(
                common,
                nested.get("kind") == kind and nested.get("status") == "ready",
                "daytona_nested_evidence_envelope_invalid",
                path=str(path),
            )
            _expect(
                common,
                nested.get("canonicalSourceSha256") == _canonical_sha256(),
                "daytona_nested_canonical_hash_mismatch",
                path=str(path),
            )
            _expect(
                common,
                nested.get("producerSha256")
                == _sha256_file(PAPERCLIP_DAYTONA_STEP_SOURCE),
                "daytona_nested_producer_hash_mismatch",
                path=str(path),
            )
            _expect(
                common,
                _fresh_field(
                    nested,
                    ("observedAt", "generatedAt", "finishedAt"),
                    max_age_seconds=(
                        3600
                        if kind == "DaytonaSandboxLifecycleEvidence"
                        else CONNECTION_EVIDENCE_MAX_AGE_SECONDS
                    ),
                ),
                "daytona_nested_evidence_stale_or_timestamp_missing",
                path=str(path),
            )
    if not isinstance(images, dict) or not isinstance(lifecycle, dict):
        return {
            connection_id: _connection_result(
                connection_id,
                list(common),
                evidence=PAPERCLIP_DAYTONA_VERIFY_EVIDENCE,
            )
            for connection_id in ids
        }
    results: dict[str, dict] = {}
    for connection_id in ids:
        findings = list(common)
        if connection_id == "C072":
            agents = (
                details.get("agents") if isinstance(details.get("agents"), list) else []
            )
            probes = (
                details.get("probeResults")
                if isinstance(details.get("probeResults"), list)
                else []
            )
            config = (
                details.get("driverConfig")
                if isinstance(details.get("driverConfig"), dict)
                else {}
            )
            plugin = (
                details.get("plugin") if isinstance(details.get("plugin"), dict) else {}
            )
            expected_driver = {
                "provider": "daytona",
                "apiKeySecretId": details.get("apiKeySecretId"),
                "apiUrl": values.get("PAPERCLIP_DAYTONA_UPSTREAM_URL"),
                "target": values.get("DAYTONA_TARGET"),
                "snapshot": values.get("MTE_DAYTONA_CODING_SNAPSHOT"),
                "image": None,
                "memory": None,
                "disk": None,
                "timeoutMs": int(values.get("MTE_DAYTONA_TIMEOUT_MS") or 0),
                "reuseLease": values.get("MTE_DAYTONA_REUSE_LEASE", "").lower()
                == "true",
            }
            agent_contracts = {
                "coding-daytona-codex": {
                    "adapterType": "codex_local",
                    "versionKey": "PROFILE_CODING_DAYTONA_CODEX_PACKAGE_CODEX_VERSION",
                    "routerKeyRef": "NINEROUTER_PROFILE_CODING_DAYTONA_CODEX_API_KEY",
                    "toolhiveUrlRef": "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
                },
                "coding-daytona-claude": {
                    "adapterType": "claude_local",
                    "versionKey": "PROFILE_CODING_DAYTONA_CLAUDE_PACKAGE_CLAUDECODE_VERSION",
                    "routerKeyRef": "NINEROUTER_PROFILE_CODING_DAYTONA_CLAUDE_API_KEY",
                    "toolhiveUrlRef": "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_URL",
                },
                "coding-daytona-pi": {
                    "adapterType": "pi_local",
                    "versionKey": "PROFILE_CODING_DAYTONA_PI_PACKAGE_PI_VERSION",
                    "routerKeyRef": "NINEROUTER_PROFILE_CODING_DAYTONA_PI_API_KEY",
                    "toolhiveUrlRef": "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL",
                },
            }

            def valid_agent(row: dict, profile: str) -> bool:
                contract = agent_contracts[profile]
                return (
                    row.get("profileRef") == profile
                    and bool(row.get("agentId"))
                    and row.get("adapterType") == contract["adapterType"]
                    and row.get("harnessVersion") == values.get(contract["versionKey"])
                    and row.get("routerKeyRef") == contract["routerKeyRef"]
                    and row.get("cwd") == "/home/daytona/paperclip-workspace"
                    and _exact_string_set(
                        row.get("envKeys"), ACCOUNT_PROFILE_ENV_KEYS[profile]
                    )
                    and row.get("runtimeSecretBinding")
                    == "paperclip_company_secret_ref"
                    and bool(row.get("runtimeSecretId"))
                    and row.get("githubBinding") == "paperclip_user_secret_ref"
                    and row.get("githubDefinitionKey")
                    == "mte.github.personal_access_token"
                    and row.get("toolhiveSecretBinding")
                    == "paperclip_company_secret_ref"
                    and bool(row.get("toolhiveSecretId"))
                    and row.get("toolhiveUrlRef") == contract["toolhiveUrlRef"]
                    and row.get("status") == "ready"
                )

            expected_probe_rows = [
                {
                    "profileRef": profile,
                    "adapterType": agent_contracts[profile]["adapterType"],
                    "status": "passed",
                }
                for profile in NATIVE_HARNESS_PROFILES
            ]

            def valid_probe(row: dict, expected: dict[str, str]) -> bool:
                attempts = row.get("attempts")
                if (
                    not all(row.get(key) == value for key, value in expected.items())
                    or not isinstance(row.get("probeSandboxesDeleted"), int)
                    or row.get("probeSandboxesDeleted") < 0
                    or not isinstance(row.get("attemptCount"), int)
                    or not isinstance(attempts, list)
                    or not 1 <= row.get("attemptCount") <= 3
                    or len(attempts) != row.get("attemptCount")
                    or row.get("upstreamStatus") not in {"pass", "warn"}
                    or not isinstance(row.get("acceptedWarningCodes"), list)
                    or not all(
                        isinstance(code, str)
                        for code in row.get("acceptedWarningCodes", [])
                    )
                    or not isinstance(row.get("optionalUserSecretBindingCount"), int)
                    or row.get("optionalUserSecretBindingCount") < 0
                ):
                    return False
                for index, attempt in enumerate(attempts, 1):
                    if (
                        not isinstance(attempt, dict)
                        or set(attempt)
                        != {
                            "attempt",
                            "status",
                            "accepted",
                            "warningCodes",
                            "requestError",
                            "checks",
                            "probeSandboxesDeleted",
                        }
                        or attempt.get("attempt") != index
                        or not isinstance(attempt.get("status"), str)
                        or not isinstance(attempt.get("accepted"), bool)
                        or not isinstance(attempt.get("warningCodes"), list)
                        or not all(
                            isinstance(code, str)
                            for code in attempt.get("warningCodes", [])
                        )
                        or (
                            attempt.get("requestError") is not None
                            and not re.fullmatch(
                                r"[a-z][a-z0-9_]*",
                                str(attempt.get("requestError")),
                            )
                        )
                        or not isinstance(attempt.get("checks"), list)
                        or not all(
                            isinstance(check, dict)
                            and set(check) == {"code", "level"}
                            and isinstance(check.get("code"), str)
                            and isinstance(check.get("level"), str)
                            for check in attempt.get("checks", [])
                        )
                        or not isinstance(attempt.get("probeSandboxesDeleted"), int)
                        or attempt.get("probeSandboxesDeleted") < 0
                    ):
                        return False
                return (
                    attempts[-1].get("accepted") is True
                    and attempts[-1].get("status") == row.get("upstreamStatus")
                    and attempts[-1].get("warningCodes")
                    == row.get("acceptedWarningCodes")
                    and all(
                        attempt.get("accepted") is False for attempt in attempts[:-1]
                    )
                    and sum(
                        attempt.get("probeSandboxesDeleted", 0) for attempt in attempts
                    )
                    == row.get("probeSandboxesDeleted")
                )

            _expect(
                findings,
                plugin.get("status") == "ready"
                and plugin.get("package") == "@paperclipai/plugin-daytona"
                and plugin.get("manifestVersion")
                == values.get("MTE_DAYTONA_PLUGIN_MANIFEST_VERSION")
                and plugin.get("packageVersion")
                == values.get("MTE_DAYTONA_PLUGIN_MANIFEST_VERSION")
                and plugin.get("installedVersion")
                == values.get("MTE_DAYTONA_PLUGIN_MANIFEST_VERSION")
                and _is_full_sha256(plugin.get("contentSha256"))
                and isinstance(plugin.get("fileCount"), int)
                and plugin.get("fileCount") > 0
                and plugin.get("pluginKey") == "paperclip.daytona-sandbox-provider"
                and details.get("provider") == "daytona"
                and details.get("environmentDriver") == "sandbox"
                and bool(details.get("environmentId"))
                and details.get("probe") == "passed"
                and details.get("snapshot") == values.get("MTE_DAYTONA_CODING_SNAPSHOT")
                and details.get("customImageTemplate") == "active-snapshot"
                and config.get("canonical") == expected_driver
                and config.get("observed") == expected_driver
                and config.get("matchesCanonical") is True
                and config.get("apiKeySecretIdMatches") is True
                and config.get("apiUrlMatches") is True
                and config.get("targetMatches") is True
                and config.get("snapshotMatches") is True
                and config.get("timeoutMatches") is True
                and config.get("reusePolicyMatches") is True
                and len(agents) == 3
                and all(isinstance(row, dict) for row in agents)
                and [row.get("profileRef") for row in agents]
                == list(NATIVE_HARNESS_PROFILES)
                and all(
                    valid_agent(row, profile)
                    for row, profile in zip(agents, NATIVE_HARNESS_PROFILES)
                )
                and len({row.get("agentId") for row in agents}) == 3
                and len({row.get("runtimeSecretId") for row in agents}) == 3
                and len({row.get("toolhiveSecretId") for row in agents}) == 3
                and len(probes) == 3
                and all(isinstance(row, dict) for row in probes)
                and all(
                    valid_probe(row, expected)
                    for row, expected in zip(probes, expected_probe_rows)
                )
                and _nested(details, "probeCleanup", "leakedSandboxCount") == 0
                and _nested(details, "probeCleanup", "baselinePreserved") is True
                and _nested(details, "probeCleanup", "createdSandboxCount")
                == _nested(details, "probeCleanup", "deletedSandboxCount")
                and details.get("probeSandboxIdsAfter")
                == details.get("probeSandboxIdsBefore"),
                "paperclip_daytona_provider_semantics_invalid",
            )
        else:
            snapshots = (
                images.get("snapshots")
                if isinstance(images, dict)
                and isinstance(images.get("snapshots"), list)
                else []
            )
            versions = (
                images.get("harnessVersions")
                if isinstance(images, dict)
                and isinstance(images.get("harnessVersions"), dict)
                else {}
            )
            states = (
                lifecycle.get("states")
                if isinstance(lifecycle, dict)
                and isinstance(lifecycle.get("states"), list)
                else []
            )
            expected_snapshots = [
                {
                    "role": "coding",
                    "name": values.get("MTE_DAYTONA_CODING_SNAPSHOT"),
                    "cpu": int(values.get("MTE_DAYTONA_CODING_CPU") or 0),
                    "memoryGiB": int(values.get("MTE_DAYTONA_CODING_MEMORY_GIB") or 0),
                    "diskGiB": int(values.get("MTE_DAYTONA_DISK_GIB") or 0),
                },
                {
                    "role": "general",
                    "name": values.get("MTE_DAYTONA_GENERAL_SNAPSHOT"),
                    "cpu": int(values.get("MTE_DAYTONA_GENERAL_CPU") or 0),
                    "memoryGiB": int(values.get("MTE_DAYTONA_GENERAL_MEMORY_GIB") or 0),
                    "diskGiB": int(values.get("MTE_DAYTONA_DISK_GIB") or 0),
                },
            ]
            expected_states = [
                ("create", "started"),
                ("execute", "passed"),
                ("delete", "deleted"),
            ]
            expected_resources = {
                "cpu": int(values.get("MTE_DAYTONA_CODING_CPU") or 0),
                "memory": int(values.get("MTE_DAYTONA_CODING_MEMORY_GIB") or 0),
                "disk": int(values.get("MTE_DAYTONA_DISK_GIB") or 0),
            }
            lifecycle_harnesses = lifecycle.get("harnesses")
            expected_lifecycle_versions = (
                ("codex", values.get("MTE_CODEX_VERSION")),
                ("claude", values.get("MTE_CLAUDE_CODE_VERSION")),
                ("pi", values.get("MTE_PI_VERSION")),
            )
            valid_lifecycle_harnesses = (
                isinstance(lifecycle_harnesses, list)
                and len(lifecycle_harnesses) == 3
                and all(
                    isinstance(row, dict)
                    and set(row) == {"name", "commandPath", "realpath", "versionOutput"}
                    and row.get("name") == name
                    and row.get("commandPath") == f"/usr/local/bin/{name}"
                    and str(row.get("realpath") or "").startswith(
                        "/opt/mte-harness/node_modules/"
                    )
                    and normalized_harness_version(
                        name, row.get("versionOutput")
                    )
                    == version
                    for row, (name, version) in zip(
                        lifecycle_harnesses, expected_lifecycle_versions
                    )
                )
            )
            expected_lifecycle_keys = {
                "apiVersion",
                "kind",
                "status",
                "generatedAt",
                "producerSha256",
                "canonicalSourceSha256",
                "controlPlane",
                "sandboxVersion",
                "provider",
                "target",
                "snapshot",
                "sandboxId",
                "workspace",
                "harnesses",
                "credentialFileProbe",
                "credentialEnvProbe",
                "resources",
                "credentialsBakedIntoImage",
                "states",
                "cleanupDeleted",
                "delete",
            }
            expected_image_keys = {
                "apiVersion",
                "kind",
                "status",
                "generatedAt",
                "producerSha256",
                "canonicalSourceSha256",
                "controlPlane",
                "sandboxVersion",
                "snapshotContractHash",
                "generation",
                "sandboxImage",
                "source",
                "snapshots",
                "deferredCleanup",
                "pointerSwitch",
                "resources",
                "harnessVersions",
                "credentialsBakedIntoImage",
            }
            _expect(
                findings,
                set(images) == expected_image_keys
                and len(snapshots) == 2
                and all(isinstance(row, dict) for row in snapshots)
                and all(
                    set(row)
                    == {
                        "role",
                        "id",
                        "name",
                        "state",
                        "ref",
                        "cpu",
                        "memoryGiB",
                        "diskGiB",
                    }
                    and row.get("ref")
                    == values.get("MTE_DAYTONA_SANDBOX_IMAGE")
                    and row.get("role") == expected["role"]
                    and row.get("name") == expected["name"]
                    and row.get("cpu") == expected["cpu"]
                    and row.get("memoryGiB") == expected["memoryGiB"]
                    and row.get("diskGiB") == expected["diskGiB"]
                    and bool(row.get("id"))
                    and row.get("state") == "active"
                    for row, expected in zip(snapshots, expected_snapshots)
                )
                and len({row.get("id") for row in snapshots}) == 2
                and len({row.get("name") for row in snapshots}) == 2
                and values.get("MTE_DAYTONA_CODING_SNAPSHOT_PREFIX")
                != values.get("MTE_DAYTONA_GENERAL_SNAPSHOT_PREFIX")
                and versions
                == {
                    "codex": values.get("MTE_CODEX_VERSION"),
                    "claudeCode": values.get("MTE_CLAUDE_CODE_VERSION"),
                    "pi": values.get("MTE_PI_VERSION"),
                }
                and images.get("resources")
                == {
                    "coding": {
                        "cpu": int(values.get("MTE_DAYTONA_CODING_CPU") or 0),
                        "memory": int(values.get("MTE_DAYTONA_CODING_MEMORY_GIB") or 0),
                        "disk": int(values.get("MTE_DAYTONA_DISK_GIB") or 0),
                    },
                    "general": {
                        "cpu": int(values.get("MTE_DAYTONA_GENERAL_CPU") or 0),
                        "memory": int(
                            values.get("MTE_DAYTONA_GENERAL_MEMORY_GIB") or 0
                        ),
                        "disk": int(values.get("MTE_DAYTONA_DISK_GIB") or 0),
                    },
                }
                and images.get("sandboxImage")
                == values.get("MTE_DAYTONA_SANDBOX_IMAGE")
                and bool(
                    re.fullmatch(
                        r"[^\s@]+@sha256:[0-9a-f]{64}",
                        str(images.get("sandboxImage") or ""),
                    )
                )
                and images.get("source")
                == {
                    "url": values.get("MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL"),
                    "revision": values.get("MTE_DAYTONA_SANDBOX_IMAGE_REVISION"),
                }
                and images.get("snapshotContractHash")
                == hashlib.sha256(
                    json.dumps(
                        {
                            "sandboxImage": images.get("sandboxImage"),
                            "sandboxImageRevision": values.get(
                                "MTE_DAYTONA_SANDBOX_IMAGE_REVISION"
                            ),
                            "resources": images.get("resources"),
                            "harnessVersions": versions,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest()
                and images.get("generation")
                == str(images.get("snapshotContractHash") or "")[:12]
                and snapshots[0].get("name")
                == f'{values.get("MTE_DAYTONA_CODING_SNAPSHOT_PREFIX")}-{images.get("generation")}'
                and snapshots[1].get("name")
                == f'{values.get("MTE_DAYTONA_GENERAL_SNAPSHOT_PREFIX")}-{images.get("generation")}'
                and images.get("pointerSwitch")
                == {
                    "coding": values.get("MTE_DAYTONA_CODING_SNAPSHOT"),
                    "general": values.get("MTE_DAYTONA_GENERAL_SNAPSHOT"),
                    "completed": True,
                }
                and isinstance(images.get("deferredCleanup"), list)
                and all(
                    isinstance(row, dict)
                    and set(row) == {"id", "name", "state"}
                    and bool(row.get("id"))
                    and row.get("name")
                    not in {
                        values.get("MTE_DAYTONA_CODING_SNAPSHOT"),
                        values.get("MTE_DAYTONA_GENERAL_SNAPSHOT"),
                    }
                    and any(
                        str(row.get("name") or "").startswith(f"{prefix}-")
                        for prefix in (
                            values.get("MTE_DAYTONA_CODING_SNAPSHOT_PREFIX"),
                            values.get("MTE_DAYTONA_GENERAL_SNAPSHOT_PREFIX"),
                        )
                    )
                    for row in images.get("deferredCleanup", [])
                )
                and images.get("controlPlane")
                == {
                    "version": values.get("MTE_DAYTONA_CONTROL_PLANE_VERSION"),
                    "sourceCommit": values.get(
                        "MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT"
                    ),
                }
                and images.get("sandboxVersion")
                == values.get("MTE_DAYTONA_SANDBOX_VERSION")
                and images.get("credentialsBakedIntoImage") is False
                and set(lifecycle) == expected_lifecycle_keys
                and lifecycle.get("controlPlane") == images.get("controlPlane")
                and lifecycle.get("sandboxVersion") == images.get("sandboxVersion")
                and lifecycle.get("provider") == "daytona"
                and lifecycle.get("target") == values.get("DAYTONA_TARGET")
                and lifecycle.get("snapshot")
                == values.get("MTE_DAYTONA_CODING_SNAPSHOT")
                and bool(lifecycle.get("sandboxId"))
                and lifecycle.get("workspace") == "/home/daytona/paperclip-workspace"
                and valid_lifecycle_harnesses
                and lifecycle.get("credentialsBakedIntoImage") is False
                and [(row.get("phase"), row.get("state")) for row in states]
                == expected_states
                and _nested(lifecycle, "resources", "expected") == expected_resources
                and _nested(lifecycle, "resources", "actual") == expected_resources
                and _nested(lifecycle, "resources", "equal") is True
                and lifecycle.get("credentialFileProbe")
                == {
                    "checkedPaths": [
                        "/home/daytona/.codex/auth.json",
                        "/home/daytona/.claude/.credentials.json",
                        "/home/daytona/.pi/agent/auth.json",
                        "/home/daytona/.config/gh/hosts.yml",
                    ],
                    "foundPaths": [],
                    "credentialFree": True,
                }
                and lifecycle.get("credentialEnvProbe")
                == {
                    "checkedNames": [
                        "OPENAI_API_KEY",
                        "ANTHROPIC_API_KEY",
                        "GH_TOKEN",
                        "CONTEXT7_API_KEY",
                        "MTE_TOOLHIVE_BEARER_TOKEN",
                    ],
                    "foundNames": [],
                    "credentialFree": True,
                }
                and lifecycle.get("cleanupDeleted") is True
                and _nested(lifecycle, "delete", "requested") is True
                and _nested(lifecycle, "delete", "getAfterDeleteStatus") == 404,
                "daytona_snapshot_lifecycle_semantics_invalid",
            )
        results[connection_id] = _connection_result(
            connection_id,
            findings,
            evidence=PAPERCLIP_DAYTONA_VERIFY_EVIDENCE,
        )
    return results


def connection_evidence_results(requested: set[str]) -> dict[str, dict]:
    """Evaluate every requested registry row against its exact evidence owner."""
    results: dict[str, dict] = {}
    for producer in (
        _e2e_connection_proofs,
        _profile_access_connection_proofs,
        _integration_connection_proofs,
        _hermes_connection_proofs,
        _observability_connection_proofs,
        _provisioning_connection_proofs,
        _kestra_reconcile_connection_proofs,
        _profile_reconcile_connection_proofs,
        _account_provision_connection_proofs,
        _cloudflare_connection_proofs,
        _configuration_connection_proofs,
        _daytona_connection_proofs,
        _ose_provision_connection_proofs,
    ):
        results.update(producer(requested))
    if "C068" in requested:
        results["C068"] = _connection_result(
            "C068",
            [{"finding": "optional_backup_restore_canary_not_implemented"}],
            state="optional_not_implemented",
        )
        results["C068"]["ok"] = None
    for connection_id in sorted(requested - set(results)):
        results[connection_id] = _connection_result(
            connection_id,
            [{"finding": "semantic_evidence_validator_missing"}],
            state="validator_missing",
        )
    return results


def write_evidence(kind: str, value: dict) -> dict:
    EVIDENCE.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        EVIDENCE.chmod(0o700)
    except OSError:
        pass
    stamp = f"{int(time.time())}-{time.time_ns() % 1_000_000_000:09d}"
    path = EVIDENCE / f"{kind}-{stamp}.json"
    latest = EVIDENCE / f"{kind}-latest.json"
    payload = {**value, "evidenceFile": str(path)}
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    for target in (path, latest):
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(serialized)
        temporary.chmod(0o600)
        temporary.replace(target)
        target.chmod(0o600)
    return payload


def load_components() -> list[dict]:
    document = json.loads(CONFIG.read_text())
    rows = document.get("spec", {}).get("components")
    if not isinstance(rows, list):
        raise ValueError("platform config spec.components must be a list")
    data_content_spec = document.get("spec", {}).get("dataContentPlane")
    if data_content_spec is None:
        return rows
    plane = _json_object(ROOT / "config/data-content-plane.json")
    if not isinstance(plane, dict) or not isinstance(plane.get("componentIds"), list):
        raise ValueError("selected data/content projection is missing or invalid")
    lock_path = reviewed_platform_lock(ROOT)
    try:
        lock = yaml.safe_load(lock_path.read_text())
        registry = data_content_contract(ROOT).validate_registry(lock)
    except Exception as exc:
        raise ValueError("reviewed data/content registry is invalid") from exc
    provider_components = {
        str(component_id)
        for bundle in registry.values()
        for component_id in bundle["componentIds"]
    }
    selected = {str(component_id) for component_id in plane["componentIds"]}
    return [
        row
        for row in rows
        if not isinstance(row, dict)
        or row.get("id") not in provider_components
        or row.get("id") in selected
    ]


def verify(selected: list[str], *, persist: bool = True) -> dict:
    rows = load_components()
    catalog: dict[str, dict] = {}
    duplicate_ids: list[str] = []
    for row in rows:
        component_id = str(row.get("id", "")) if isinstance(row, dict) else ""
        if not component_id or component_id in catalog:
            duplicate_ids.append(component_id or "<missing>")
            continue
        catalog[component_id] = row

    requested = list(dict.fromkeys(selected))
    unknown = sorted(set(requested) - set(catalog))
    targets = (
        [catalog[item] for item in requested if item in catalog]
        if requested
        else list(catalog.values())
    )
    checks: list[dict] = [
        {
            "component": component_id,
            "check": "component-selection",
            "ok": False,
            "state": "unknown_component",
        }
        for component_id in unknown
    ]
    checks.append(config_source_check(include_static=True))
    if SERVER_NOTION_PROJECTION_SOURCE.is_file():
        projection_findings = _notion_projection_consumer_findings()
        checks.append(
            {
                "component": "notion-projection",
                "check": "postgres-outbox-to-notion",
                "ok": not projection_findings,
                "state": "passed" if not projection_findings else "failed",
                "findings": projection_findings,
            }
        )
        canary_findings = _notion_projection_canary_findings()
        checks.append(
            {
                "component": "notion-projection",
                "check": "postgres-outbox-to-notion-live-canary",
                "ok": not canary_findings,
                "state": "passed" if not canary_findings else "failed",
                "findings": canary_findings,
            }
        )
    for row in targets:
        component_id = row["id"]
        health = row.get("health")
        if not isinstance(health, dict) or not health:
            checks.append(
                {
                    "component": component_id,
                    "check": "health",
                    "ok": False,
                    "state": "not_configured",
                }
            )
            continue
        if health.get("url"):
            result = probe(str(health["url"]))
            checks.append(
                {
                    "component": component_id,
                    "check": "http-health",
                    "state": "passed" if result.get("ok") else "failed",
                    **result,
                }
            )
        elif health.get("command"):
            command = str(health["command"])
            try:
                completed = subprocess.run(
                    ["/bin/sh", "-c", command],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=False,
                )
                check = {
                    "ok": completed.returncode == 0,
                    "exitCode": completed.returncode,
                }
            except subprocess.TimeoutExpired:
                check = {"ok": False, "error": "command_timeout"}
            checks.append(
                {
                    "component": component_id,
                    "check": "command-health",
                    "state": "passed" if check.get("ok") else "failed",
                    **check,
                }
            )
        else:
            checks.append(
                {
                    "component": component_id,
                    "check": "health",
                    "ok": False,
                    "state": "invalid_configuration",
                }
            )

    if any(row.get("id") == "paperclip" for row in targets):
        result = paperclip_runtime_ports()
        checks.append(
            {
                "component": "paperclip-runtime",
                "check": "canonical-listeners",
                **result,
            }
        )

    if not requested or "toolhive" in requested:
        result = mcp_initialize()
        checks.append(
            {
                "component": "toolhive-mcp",
                "check": "mcp-initialize",
                "state": "passed" if result.get("ok") else "failed",
                **result,
            }
        )

    if not requested or "paperclip" in requested or "9router" in requested:
        result = harness_scoped_router_auth_evidence()
        checks.append(
            {
                "component": "harness-scoped-router-auth",
                "check": "semantic-evidence",
                **result,
            }
        )

    if not checks:
        checks.append(
            {
                "component": "<none>",
                "check": "verification-coverage",
                "ok": False,
                "state": "no_checks_executed",
            }
        )
    passed = sum(item.get("ok") is True for item in checks)
    failed = len(checks) - passed
    result = {
        "timestamp": int(time.time()),
        "ok": bool(checks) and failed == 0 and not duplicate_ids,
        "requested": requested or ["<all>"],
        "unknownComponents": unknown,
        "duplicateComponentIds": sorted(set(duplicate_ids)),
        "summary": {"total": len(checks), "passed": passed, "failed": failed},
        "checks": checks,
    }
    return write_evidence("verify", result) if persist else result


def status() -> dict:
    command = ["docker", "ps", "--format", "{{.Names}}|{{.Status}}|{{.Ports}}"]
    try:
        lines = subprocess.check_output(command, text=True, timeout=30).splitlines()
        docker_error = None
    except (OSError, subprocess.SubprocessError) as exc:
        lines = []
        docker_error = type(exc).__name__
    relevant = [line for line in lines if line.startswith("mte-")]
    live = verify([], persist=False)
    result = {
        "timestamp": int(time.time()),
        "ok": docker_error is None and live.get("ok") is True,
        "dockerError": docker_error,
        "containers": sorted(relevant),
        "verify": live,
    }
    return result


def compose_config() -> dict:
    """Validate every rendered Compose projection with the server engine."""
    rows = load_components()
    results: list[dict] = []
    for row in rows:
        component_id = str(row.get("id", ""))
        compose_ref = row.get("compose")
        if not compose_ref:
            continue
        compose_path = ROOT / str(compose_ref)
        env_path = SERVICE_ROOT / f"{component_id}.env"
        if not compose_path.is_file() or not env_path.is_file():
            results.append(
                {
                    "component": component_id,
                    "ok": False,
                    "state": "projection_or_env_missing",
                }
            )
            continue
        try:
            completed = subprocess.run(
                [
                    "docker",
                    "compose",
                    "--env-file",
                    str(env_path),
                    "-f",
                    str(compose_path),
                    "config",
                    "--quiet",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
            results.append(
                {
                    "component": component_id,
                    "ok": completed.returncode == 0,
                    "state": "passed" if completed.returncode == 0 else "failed",
                    "exitCode": completed.returncode,
                }
            )
        except subprocess.TimeoutExpired:
            results.append({"component": component_id, "ok": False, "state": "timeout"})
        except OSError as exc:
            results.append(
                {
                    "component": component_id,
                    "ok": False,
                    "state": "engine_unavailable",
                    "errorType": type(exc).__name__,
                }
            )
    result = {
        "timestamp": int(time.time()),
        "ok": bool(results) and all(row.get("ok") is True for row in results),
        "summary": {
            "total": len(results),
            "passed": sum(row.get("ok") is True for row in results),
            "failed": sum(row.get("ok") is not True for row in results),
        },
        "results": results,
    }
    return write_evidence("compose-config", result)


def _evidence_is_fresh(value: object, *, max_age_seconds: int = 600) -> bool:
    if not isinstance(value, str):
        return False
    try:
        moment = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if moment.tzinfo is None:
        return False
    age = (datetime.datetime.now(datetime.timezone.utc) - moment).total_seconds()
    return -60 <= age <= max_age_seconds


def telegram_configured_condition() -> dict:
    try:
        values = {
            key: bool(value.strip())
            for key, value in (
                line.split("=", 1)
                for line in CANONICAL_ENV.read_text().splitlines()
                if line and not line.startswith("#") and "=" in line
            )
            if key in {"HERMES_TELEGRAM_BOT_TOKEN", "HERMES_TELEGRAM_ALLOWED_USERS"}
        }
    except OSError:
        return {"active": True, "valid": False, "state": "condition_source_missing"}
    token = values.get("HERMES_TELEGRAM_BOT_TOKEN", False)
    allowed = values.get("HERMES_TELEGRAM_ALLOWED_USERS", False)
    if not token and not allowed:
        return {"active": False, "valid": True, "state": "conditional_disabled"}
    if token != allowed:
        return {
            "active": True,
            "valid": False,
            "state": "conditional_configuration_incomplete",
        }
    return {"active": True, "valid": True, "state": "active_telegram_configured"}


def connection_condition(connection: dict) -> dict:
    name = connection.get("condition")
    if name is None:
        return {"active": True, "valid": True, "state": "unconditional"}
    if name == "telegram-configured" and connection.get("id") == "C033":
        return telegram_configured_condition()
    return {"active": True, "valid": False, "state": "unknown_condition"}


def acceptance_requirement_rows() -> tuple[list[dict], list[dict]]:
    document = yaml.safe_load(ACCEPTANCE_REQUIREMENTS.read_text())
    if not isinstance(document, dict):
        return [], [{"finding": "acceptance_registry_not_an_object"}]
    findings: list[dict] = []
    if document.get("apiVersion") != "micro-task-engine/v1alpha1":
        findings.append({"finding": "acceptance_registry_api_version_invalid"})
    if document.get("kind") != "ReleaseEvidenceRegistry":
        findings.append({"finding": "acceptance_registry_kind_invalid"})
    requirements_value = document.get("requirements")
    if not isinstance(requirements_value, list):
        findings.append({"finding": "acceptance_requirements_not_a_list"})
        return [], findings
    valid: list[dict] = []
    seen: set[str] = set()
    required_fields = {"id", "from", "to", "required", "auth", "exposure", "check"}
    for index, row in enumerate(requirements_value):
        if not isinstance(row, dict):
            findings.append({"index": index, "finding": "requirement_not_an_object"})
            continue
        missing = sorted(required_fields - set(row))
        connection_id = str(row.get("id", ""))
        if missing:
            findings.append(
                {
                    "id": connection_id or None,
                    "finding": "missing_fields",
                    "fields": missing,
                }
            )
        if not connection_id:
            findings.append({"index": index, "finding": "missing_id"})
        elif connection_id in seen:
            findings.append({"id": connection_id, "finding": "duplicate_id"})
        seen.add(connection_id)
        expected = CONNECTION_CONTRACT_EXPECTATIONS.get(connection_id)
        if expected is not None:
            drift = {
                key: {"expected": expected_value, "actual": row.get(key)}
                for key, expected_value in expected.items()
                if row.get(key) != expected_value
            }
            if drift:
                findings.append(
                    {
                        "id": connection_id,
                        "finding": "security_contract_drift",
                        "fields": drift,
                    }
                )
        valid.append(row)
    return valid, findings


def acceptance() -> dict:
    registry, registry_findings = acceptance_requirement_rows()
    evidence_results = connection_evidence_results(
        {str(row.get("id")) for row in registry if row.get("id")}
    )
    component_results = {
        row["component"]: row
        for row in evidence_results.values()
        if row.get("component")
    }
    rows: list[dict] = []
    for connection in registry:
        check_name = str(connection.get("check", ""))
        component = CONNECTION_CHECK_COMPONENTS.get(check_name)
        condition = connection_condition(connection)
        condition_active = condition.get("active") is True
        condition_valid = condition.get("valid") is True
        if not condition_valid:
            ok = False
            state = str(condition.get("state") or "condition_invalid")
        elif not condition_active:
            ok = None
            state = str(condition.get("state") or "conditional_not_run")
        elif component is None:
            ok = False
            state = "not_implemented"
        elif component not in component_results:
            ok = False
            state = "missing_result"
        else:
            ok = component_results[component].get("ok") is True
            state = (
                "passed"
                if ok
                else str(component_results[component].get("state") or "failed")
            )
        rows.append(
            {
                "id": connection.get("id"),
                "check": check_name,
                "required": connection.get("required") is True,
                "condition": connection.get("condition"),
                "conditionActive": condition_active,
                "conditionValid": condition_valid,
                "activeRequired": connection.get("required") is True
                and condition_active,
                "implemented": component is not None,
                "sourceResult": component,
                "sourceEvidence": (
                    component_results.get(component, {}).get("evidence")
                    if component is not None
                    else None
                ),
                "sourceFindings": (
                    component_results.get(component, {}).get("findings", [])
                    if component is not None
                    else []
                ),
                "conditionState": condition.get("state"),
                "passed": ok is True,
                "ok": ok,
                "state": state,
            }
        )
    required_failures = [
        row["id"] for row in rows if row["activeRequired"] and row.get("ok") is not True
    ]
    conditional_not_run = [
        row["id"]
        for row in rows
        if row.get("condition") and row.get("conditionActive") is False
    ]
    declared_unverified = [
        row["id"] for row in rows if row["required"] and row.get("ok") is not True
    ]
    implemented = sum(row["implemented"] for row in rows)
    passed = sum(row.get("ok") is True for row in rows)
    active_required_ok = not registry_findings and not required_failures
    all_declared_verified = not registry_findings and not declared_unverified
    result = {
        "timestamp": int(time.time()),
        "ok": active_required_ok,
        "activeRequiredOk": active_required_ok,
        "allDeclaredVerified": all_declared_verified,
        "registryFindings": registry_findings,
        "requiredFailures": required_failures,
        "conditionalNotRun": conditional_not_run,
        "declaredUnverified": declared_unverified,
        "summary": {
            "total": len(rows),
            "required": sum(row["required"] for row in rows),
            "activeRequired": sum(row["activeRequired"] for row in rows),
            "implemented": implemented,
            "passed": passed,
            "conditionalNotRun": len(conditional_not_run),
            "notImplemented": sum(row["state"] == "not_implemented" for row in rows),
        },
        "requirements": rows,
    }
    return result


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    if action == "verify":
        value = verify(sys.argv[2:])
    elif action == "status" and len(sys.argv) == 2:
        value = status()
    elif action == "acceptance" and len(sys.argv) == 2:
        value = acceptance()
    elif action == "compose-config" and len(sys.argv) == 2:
        value = compose_config()
    else:
        print(
            "usage: server-verify.py verify [components...]|status|acceptance|compose-config",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0 if value.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

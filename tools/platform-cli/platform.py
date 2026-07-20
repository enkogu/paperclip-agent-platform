#!/usr/bin/env python3
"""One entrypoint for the declarative MTE platform deployment."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import uuid
from typing import Any

import yaml


TOOL_ROOT = Path(__file__).resolve().parent
ROOT = TOOL_ROOT.parents[1]
CONFIG_PATH = ROOT / "config/platform.yaml"
LOCK_PATH = ROOT / "config/platform.lock.yaml"
ACCEPTANCE_REQUIREMENTS_PATH = ROOT / "config/acceptance-requirements.yaml"
SERVICES_ROOT = ROOT / "deployment/services"
COMPOSE_SEEDS_PATH = ROOT / "config/compose-seeds.lock.json"
PROFILES_ROOT = ROOT / "config/profiles"
KESTRA_WORKFLOWS_ROOT = ROOT / "workflows/kestra"
KESTRA_SERVICE_ROOT = SERVICES_ROOT / "kestra"
HERMES_SERVICE_ROOT = SERVICES_ROOT / "hermes"
SYSTEM_PLATFORM_SKILL_ROOT = ROOT / "skills/system-platform"
VERIFICATION_PROFILE_SKILL_ROOT = ROOT / "skills/verification-before-completion"
SEARXNG_SERVICE_ROOT = SERVICES_ROOT / "searxng"
CLOUDFLARE_ROOT = ROOT / "deployment/cloudflare"
AGENT_RUNTIME_ROOT = ROOT / "deployment/agent-runtime"
CANONICAL_ENV_EXAMPLE = ROOT / "config/platform.env.example"
RESOURCE_PREFLIGHT_STEP = ROOT / "deployment/steps/resource-preflight.sh"
DAYTONA_HARNESS_MANIFEST = ROOT / "deployment/image-build/daytona-harness/package.json"
PUBLIC_HARNESS_PACKAGES = frozenset(
    {
        "@anthropic-ai/claude-code",
        "@earendil-works/pi-coding-agent",
        "@openai/codex",
    }
)
PROPRIETARY_HARNESS_ENABLEMENT_KEY = (
    "MTE_ENABLE_OPERATOR_PROVIDED_PROPRIETARY_HARNESSES"
)
OPERATOR_ENV_OVERRIDE: Path | None = None
DEFAULT_DATA_CONTENT_PROFILE = "postgres-notion"
NOTION_UPGRADE_IMPORT_KEYS = {
    "NOTION_TOKEN",
    "NOTION_ROOT_PAGE_ID",
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
OPERATOR_ENV_ALIASES = frozenset(
    {
        "GH_TOKEN",
        "MINIMAX_OPENAI_ENDPOINT",
        "PRIN7R_HERMES_TELEGRAM_BOT_TOKEN",
        "PRIN7R_NOTION_PAGE_ID",
        *NOTION_TOKEN_IMPORT_PRIORITY,
    }
)
SSH_TRANSPORT_OPTIONS = (
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=15",
    "-o",
    "ServerAliveInterval=30",
    "-o",
    "ServerAliveCountMax=10",
    "-o",
    "TCPKeepAlive=yes",
)
HOST_BOOTSTRAP_SEED_KEYS = frozenset(
    {
        "MTE_CONTAINERD_IO_VERSION",
        "MTE_DOCKER_ALLOW_PROVIDER_MIGRATION",
        "MTE_DOCKER_APT_KEY_FINGERPRINT",
        "MTE_DOCKER_APT_KEY_SHA256",
        "MTE_DOCKER_APT_KEY_URL",
        "MTE_DOCKER_APT_REPOSITORY_URL",
        "MTE_DOCKER_CE_VERSION",
        "MTE_DOCKER_CLI_VERSION",
        "MTE_DOCKER_COMPOSE_VERSION",
        "MTE_DOCKER_UBUNTU_COMPOSE_VERSION",
        "MTE_DOCKER_UBUNTU_CONTAINERD_VERSION",
        "MTE_DOCKER_UBUNTU_DOCKER_IO_VERSION",
        "MTE_CONTROL_NETWORK_GATEWAY",
        "MTE_CONTROL_NETWORK_SUBNET",
        "MTE_HOST_REQUIRED_TCP_PORTS",
    }
)


class PlatformError(RuntimeError):
    pass


def local_evidence_root() -> Path:
    """Return local-only generated evidence below the ignored runtime tree."""

    return ROOT / ".runtime" / "evidence"


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open() as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise PlatformError(f"{path} must contain a YAML object")
    return value


def operator_env_path(*, required: bool = False) -> Path | None:
    """Return the explicitly selected operator input file.

    Public source must never guess a workstation-specific credential path.  A
    caller may select the file with ``--operator-env`` or ``MTE_OPERATOR_ENV``;
    otherwise already-exported environment variables remain valid inputs.
    """

    override = str(OPERATOR_ENV_OVERRIDE or "").strip()
    environment_override = str(os.environ.get("MTE_OPERATOR_ENV", "")).strip()
    if override and environment_override:
        override_path = Path(override).expanduser().resolve()
        environment_path = Path(environment_override).expanduser().resolve()
        if override_path != environment_path:
            raise PlatformError("multiple operator env files were selected")
    raw = override or environment_override
    if not raw:
        if required:
            raise PlatformError(
                "operator input is required; pass --operator-env or set MTE_OPERATOR_ENV"
            )
        return None
    path = Path(raw).expanduser().resolve()
    if not path.is_file():
        raise PlatformError(f"operator env file does not exist: {path}")
    if path.stat().st_mode & 0o077:
        raise PlatformError(
            f"operator env file must not be group/world accessible: {path}"
        )
    return path


def operator_values(*, required: bool = False) -> dict[str, str]:
    path = operator_env_path(required=required)
    return local_dotenv(path) if path is not None else dict(os.environ)


def activate_operator_environment(path: Path | None) -> None:
    """Make one explicit operator dotenv authoritative for known input keys."""

    if path is None:
        return
    contract = server_config_contract()
    selected = normalized_operator_values(local_dotenv(path))
    governed_keys = (
        set(contract.REQUIRED_OPERATOR_ENV_KEYS)
        | set(contract.OPTIONAL_OPERATOR_INPUT_KEYS)
        | set(OPERATOR_ENV_ALIASES)
        | set(contract.DOMAIN_INPUT_ALIASES)
    )
    for key in governed_keys - set(selected):
        os.environ.pop(key, None)
    for key in selected.keys() & governed_keys:
        os.environ[key] = selected[key]


def server_config_contract(path: Path | None = None):
    path = path or TOOL_ROOT / "server-config.py"
    spec = importlib.util.spec_from_file_location("mte_server_config_contract", path)
    if spec is None or spec.loader is None:
        raise PlatformError("cannot load the canonical environment contract")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normalized_operator_values(values: dict[str, str]) -> dict[str, str]:
    """Return canonical input names without exposing or duplicating values."""

    normalized = normalize_notion_token_import(values)
    aliases = {
        "GH_TOKEN": "GITHUB_TOKEN",
        "PRIN7R_HERMES_TELEGRAM_BOT_TOKEN": "HERMES_TELEGRAM_BOT_TOKEN",
        "MINIMAX_OPENAI_ENDPOINT": "MINIMAX_BASE_URL",
        "PRIN7R_NOTION_PAGE_ID": "NOTION_ROOT_PAGE_ID",
    }
    for legacy, canonical in aliases.items():
        if (
            not str(normalized.get(canonical, "")).strip()
            and str(normalized.get(legacy, "")).strip()
        ):
            normalized[canonical] = normalized[legacy]
    return normalized


def validate_operator_environment(
    values: dict[str, str], *, reject_documentation_values: bool
) -> dict[str, Any]:
    """Validate the private input carrier without returning any values."""

    contract = server_config_contract()
    normalized = normalized_operator_values(values)
    domain_aliases = sorted(set(contract.DOMAIN_INPUT_ALIASES) & set(values))
    if domain_aliases:
        raise PlatformError(
            "legacy domain aliases are not accepted in operator env; use "
            "PLATFORM_BASE_DOMAIN instead: " + ", ".join(domain_aliases)
        )
    required = set(contract.REQUIRED_OPERATOR_ENV_KEYS)
    missing = sorted(
        key for key in required if not str(normalized.get(key, "")).strip()
    )
    if missing:
        raise PlatformError(
            "operator env is missing required keys: " + ", ".join(missing)
        )
    if not re.fullmatch(
        r"[^\s@]+@sha256:[0-9a-f]{64}",
        str(normalized["MTE_PAPERCLIP_IMAGE"]).strip(),
    ):
        raise PlatformError(
            "MTE_PAPERCLIP_IMAGE must be an immutable sha256 digest reference"
        )
    try:
        contract.validate_paperclip_fork_evidence(
            str(normalized["MTE_PAPERCLIP_FORK_SOURCE_URL"]),
            str(normalized["MTE_PAPERCLIP_FORK_REVISION"]),
        )
    except contract.ConfigError as exc:
        raise PlatformError(str(exc)) from exc
    if not re.fullmatch(
        r"[^\s@]+@sha256:[0-9a-f]{64}",
        str(normalized["MTE_DAYTONA_SANDBOX_IMAGE"]).strip(),
    ):
        raise PlatformError(
            "MTE_DAYTONA_SANDBOX_IMAGE must be an immutable sha256 digest reference"
        )
    if not re.fullmatch(
        r"https://[^\s]+",
        str(normalized["MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL"]).strip(),
    ):
        raise PlatformError(
            "MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL must be an HTTPS source URL"
        )
    if not re.fullmatch(
        r"[0-9a-f]{40}",
        str(normalized["MTE_DAYTONA_SANDBOX_IMAGE_REVISION"]).strip(),
    ):
        raise PlatformError(
            "MTE_DAYTONA_SANDBOX_IMAGE_REVISION must be an immutable 40-character commit"
        )

    raw_cidrs = str(normalized["MTE_OPERATOR_SSH_CIDRS"]).strip()
    try:
        canonical_cidrs = contract.normalize_operator_ssh_cidrs(raw_cidrs)
    except contract.ConfigError as exc:
        raise PlatformError(str(exc)) from exc
    if raw_cidrs != canonical_cidrs:
        raise PlatformError(
            "MTE_OPERATOR_SSH_CIDRS must be sorted, unique, normalized and "
            f"comma-separated: {canonical_cidrs}"
        )

    target = str(normalized["MTE_SSH_TARGET"]).strip()
    if target.count("@") != 1 or not all(target.split("@", 1)):
        raise PlatformError("MTE_SSH_TARGET must use user@host syntax")
    domain = str(normalized["PLATFORM_BASE_DOMAIN"]).strip().lower().rstrip(".")
    if not domain or domain.startswith(("http://", "https://")) or "." not in domain:
        raise PlatformError("PLATFORM_BASE_DOMAIN must be a DNS name without scheme")
    if "@" not in str(normalized["CLOUDFLARE_EMAIL"]).strip():
        raise PlatformError("CLOUDFLARE_EMAIL must be an email address")
    try:
        contract.validate_e2e_github_target(normalized)
        contract.resource_preflight_values(normalized)
    except contract.ConfigError as exc:
        raise PlatformError(str(exc)) from exc

    if reject_documentation_values:
        documented = parse_dotenv(CANONICAL_ENV_EXAMPLE)
        unchanged = sorted(
            key
            for key in contract.REQUIRED_OPERATOR_BOOTSTRAP_KEYS
            if documented.get(key) and normalized.get(key) == documented[key]
        )
        if unchanged:
            raise PlatformError(
                "operator env still contains documentation-only values: "
                + ", ".join(unchanged)
            )

    return {
        "ok": True,
        "requiredKeyCount": len(required),
        "optionalKeyCount": len(contract.OPTIONAL_OPERATOR_INPUT_KEYS),
        "canonicalRuntimeSource": "/root/.config/mte-secrets/platform.env",
        "operatorInputs": "reconciled",
        "generatedValues": "fill-only",
    }


def operator_environment_schema() -> dict[str, Any]:
    """Validate and describe the sole checked-in environment template."""

    contract = server_config_contract()
    values = parse_dotenv(CANONICAL_ENV_EXAMPLE)
    expected = set(contract.OPERATOR_ENV_EXAMPLE_KEYS)
    actual = set(values)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        raise PlatformError(
            "canonical environment example key drift; "
            f"missing={','.join(missing) or '-'}; extra={','.join(extra) or '-'}"
        )
    return {
        "ok": True,
        "example": str(CANONICAL_ENV_EXAMPLE.relative_to(ROOT)),
        "requiredKeys": sorted(contract.REQUIRED_OPERATOR_ENV_KEYS),
        "optionalKeys": sorted(contract.OPTIONAL_OPERATOR_INPUT_KEYS),
        "localOnlyBootstrapKeys": sorted(contract.LOCAL_ONLY_OPERATOR_INPUT_KEYS),
        "canonicalRuntimeSource": "/root/.config/mte-secrets/platform.env",
        "operatorInputs": "reconciled",
        "generatedValues": "fill-only safe defaults, pinned runtime values, service secrets and provisioned IDs",
    }


def validate_public_harness_enablement(values: dict[str, str]) -> None:
    """Fail before transport when the shipped all-harness bundle lacks consent.

    Daytona is intentionally the only runtime installer for the Codex, Claude
    Code and Pi harness closure.  Keeping this guard here means the public
    default stops during local preflight, before host bootstrap, sync, Docker,
    or a late Daytona package-install failure can mutate a deployment.
    """

    try:
        manifest = json.loads(DAYTONA_HARNESS_MANIFEST.read_text())
        dependencies = manifest.get("dependencies")
    except (OSError, json.JSONDecodeError) as exc:
        raise PlatformError("daytona harness manifest is unavailable") from exc
    if not isinstance(dependencies, dict):
        raise PlatformError("daytona harness manifest dependencies are invalid")
    manifest_packages = {str(package) for package in dependencies}
    if not PUBLIC_HARNESS_PACKAGES.issubset(manifest_packages):
        raise PlatformError("public release harness manifest is incomplete")
    if str(values.get(PROPRIETARY_HARNESS_ENABLEMENT_KEY, "")).strip() == "true":
        return
    raise PlatformError(
        "public-release preflight blocked proprietary native harness installation; "
        f"set {PROPRIETARY_HARNESS_ENABLEMENT_KEY}=true in the private operator input "
        "to deliberately enable the shipped Codex, Claude Code, and Pi harness bundle"
    )


def locked_image(name: str) -> str:
    value = load_yaml(LOCK_PATH).get("spec", {}).get("images", {}).get(name)
    if not isinstance(value, str) or "@sha256:" not in value:
        raise PlatformError(f"platform lock is missing digest-pinned image {name}")
    return value


def bootstrap_seeds() -> dict[str, str]:
    module = server_config_contract()
    values = getattr(module, "ONE_TIME_MIGRATION_SEEDS", None)
    if not isinstance(values, dict):
        raise PlatformError("canonical bootstrap seed source is invalid")
    return {str(key): str(value) for key, value in values.items()}


def host_bootstrap_seeds(*, contract_source: Path | None = None) -> dict[str, str]:
    """Return the exact non-secret seed set consumed before the first sync."""

    module = server_config_contract(contract_source)
    source = getattr(module, "ONE_TIME_MIGRATION_SEEDS", None)
    if not isinstance(source, dict):
        raise PlatformError("canonical host bootstrap seed source is invalid")
    missing = sorted(HOST_BOOTSTRAP_SEED_KEYS - set(source))
    if missing:
        raise PlatformError(
            "canonical host bootstrap seeds are missing: " + ", ".join(missing)
        )
    forbidden = HOST_BOOTSTRAP_SEED_KEYS & (
        set(getattr(module, "REQUIRED_OPERATOR_ENV_KEYS", set()))
        | set(getattr(module, "OPTIONAL_OPERATOR_INPUT_KEYS", set()))
        | set(getattr(module, "OPTIONAL_EMPTY_KEYS", set()))
    )
    sensitive = sorted(
        key
        for key in HOST_BOOTSTRAP_SEED_KEYS
        if getattr(module, "SENSITIVE_KEY_PATTERN").search(key)
    )
    if forbidden or sensitive:
        raise PlatformError(
            "host bootstrap seed allowlist contains operator or sensitive keys"
        )
    result: dict[str, str] = {}
    for key in sorted(HOST_BOOTSTRAP_SEED_KEYS):
        value = source[key]
        if (
            not isinstance(value, str)
            or not value
            or "\n" in value
            or "\r" in value
            or "\0" in value
        ):
            raise PlatformError(f"host bootstrap seed {key} is not a safe scalar")
        result[key] = value
    return result


def data_content_contract():
    path = TOOL_ROOT / "data_content_plane.py"
    spec = importlib.util.spec_from_file_location("mte_data_content_plane", path)
    if spec is None or spec.loader is None:
        raise PlatformError("cannot load the reviewed data/content contract")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resolved_data_content(cfg: dict[str, Any]) -> dict[str, Any]:
    plane = cfg.get("_resolvedDataContentPlane")
    if not isinstance(plane, dict):
        raise PlatformError("resolved data/content plane is missing")
    return plane


def optional_resolved_data_content(cfg: dict[str, Any]) -> dict[str, Any] | None:
    plane = cfg.get("_resolvedDataContentPlane")
    if isinstance(plane, dict):
        return plane
    declared = cfg.get("spec", {}).get("dataContentPlane")
    if declared is not None:
        raise PlatformError("declared data/content plane was not resolved")
    return None


def config(domain: str | None = None) -> dict[str, Any]:
    raw = load_yaml(CONFIG_PATH)
    spec = raw["spec"]
    seed_values = bootstrap_seeds()
    selected_path = operator_env_path()
    if selected_path is not None:
        contract = server_config_contract()
        selected_governed_keys = set(contract.REQUIRED_OPERATOR_ENV_KEYS) | set(
            contract.OPTIONAL_OPERATOR_INPUT_KEYS
        )
        selected_values = normalized_operator_values(local_dotenv(selected_path))
        selected_values = {
            key: value
            for key, value in selected_values.items()
            if key in selected_governed_keys
        }
    else:
        selected_governed_keys = set()
        selected_values = {}
    host = spec["host"]

    def resolve_ref(name: str) -> str:
        ref = str(host.get(name, ""))
        if selected_path is not None and ref in selected_governed_keys:
            value = selected_values.get(ref, "")
        elif selected_path is not None:
            value = seed_values.get(ref, "")
        else:
            value = os.environ.get(ref) or seed_values.get(ref, "")
        if not value:
            raise PlatformError(f"bootstrap host ref {ref or name} is unresolved")
        return value

    host["ssh"] = resolve_ref("sshRef")
    host["root"] = resolve_ref("rootRef")
    host["secretsRoot"] = resolve_ref("secretsRootRef")
    excluded_refs = host.get("excludedRefs", [])
    host["excluded"] = [
        (
            selected_values.get(str(ref), "")
            if selected_path is not None and str(ref) in selected_governed_keys
            else (
                seed_values.get(str(ref), "")
                if selected_path is not None
                else os.environ.get(str(ref)) or seed_values.get(str(ref), "")
            )
        )
        for ref in excluded_refs
    ]
    if any(not value for value in host["excluded"]):
        raise PlatformError("one or more bootstrap excluded-host refs are unresolved")
    domain_ref = str(spec.get("domainRef", "PLATFORM_BASE_DOMAIN"))
    selected_domain = str(selected_values.get(domain_ref, "")).strip().rstrip(".")
    requested_domain = str(domain or "").strip().rstrip(".")
    if (
        requested_domain
        and selected_path is not None
        and requested_domain != selected_domain
    ):
        raise PlatformError("--domain conflicts with the selected operator env")
    if selected_path is not None:
        resolved = selected_domain
    else:
        resolved = (
            domain or os.environ.get(domain_ref) or seed_values.get(domain_ref) or ""
        )
    resolved = resolved.strip().rstrip(".")
    if resolved.startswith("http://") or resolved.startswith("https://"):
        raise PlatformError("domain must be a DNS name without scheme")
    spec["resolvedDomain"] = resolved
    values = dict(seed_values)
    if selected_path is None:
        values.update(os.environ)
    values.update(selected_values)
    values[domain_ref] = resolved
    for url_key, subdomain_ref in (("POSTGREST_PUBLIC_URL", "POSTGREST_SUBDOMAIN"),):
        subdomain = values.get(subdomain_ref, "").strip().strip(".")
        if subdomain and resolved:
            values[url_key] = f"https://{subdomain}.{resolved}"
    contract = data_content_contract()
    lock = load_yaml(LOCK_PATH)
    try:
        raw["_resolvedDataContentPlane"] = contract.resolve_from_paths(
            raw,
            lock,
            values,
            config_path=CONFIG_PATH,
            lock_path=LOCK_PATH,
            source_sha256="0" * 64,
            generator_version="mte-platform-local-validation",
        )
    except contract.DataContentError as exc:
        raise PlatformError(str(exc)) from exc
    return raw


def host_spec(cfg: dict[str, Any]) -> dict[str, Any]:
    return cfg["spec"]["host"]


def components(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    plane = optional_resolved_data_content(cfg)
    if plane is None:
        return cfg["spec"]["components"]
    profile_id = str(plane.get("profile") or "")
    catalog = provider_profile_catalog(cfg)
    if profile_id not in catalog:
        raise PlatformError(
            f"unknown selected provider profile: {profile_id or '<empty>'}"
        )
    return [
        row
        for row in cfg["spec"]["components"]
        if "enabledForProfiles" not in row or profile_id in row["enabledForProfiles"]
    ]


def _unique_manifest_ids(
    value: Any, label: str, *, allow_empty: bool = False
) -> list[str]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise PlatformError(f"{label} must be a unique non-empty string list")
    return value


def provider_profile_catalog(cfg: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    """Validate the manifest-owned provider availability matrix.

    Immutable provider details live in ``platform.lock.yaml``. The manifest
    must independently and explicitly state which providers and deployable
    components each profile enables. Exact cross-validation makes profile
    selection visible to operators without creating a second permissive source
    of provider wiring.
    """

    spec = cfg.get("spec")
    if not isinstance(spec, dict):
        raise PlatformError("platform manifest spec must be an object")
    declared = spec.get("providerProfiles")
    if not isinstance(declared, dict) or not declared:
        raise PlatformError("spec.providerProfiles must be a non-empty object")

    lock = load_yaml(LOCK_PATH)
    contract = data_content_contract()
    registry = contract.validate_registry(lock)
    known_profiles = set(registry)
    declared_profiles = set(declared)
    if declared_profiles != known_profiles:
        missing = sorted(known_profiles - declared_profiles)
        unknown = sorted(declared_profiles - known_profiles)
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if unknown:
            details.append("unknown=" + ",".join(unknown))
        raise PlatformError(
            "spec.providerProfiles differs from the locked profile registry: "
            + "; ".join(details)
        )

    component_rows = spec.get("components")
    if not isinstance(component_rows, list) or any(
        not isinstance(row, dict) for row in component_rows
    ):
        raise PlatformError("spec.components must be a list of objects")
    component_ids = [str(row.get("id") or "") for row in component_rows]
    if any(not component_id for component_id in component_ids) or len(
        component_ids
    ) != len(set(component_ids)):
        raise PlatformError("component ids must be unique non-empty strings")

    enabled_components: dict[str, set[str]] = {
        profile_id: set() for profile_id in known_profiles
    }
    core_components: set[str] = set()
    for row, component_id in zip(component_rows, component_ids, strict=True):
        if "enabledForProfiles" not in row:
            core_components.add(component_id)
            continue
        profiles = _unique_manifest_ids(
            row["enabledForProfiles"],
            f"component {component_id} enabledForProfiles",
        )
        invalid_profiles = sorted(set(profiles) - known_profiles)
        if invalid_profiles:
            raise PlatformError(
                f"component {component_id} enables unknown profile(s): "
                + ", ".join(invalid_profiles)
            )
        for profile_id in profiles:
            enabled_components[profile_id].add(component_id)

    result: dict[str, dict[str, list[str]]] = {}
    for profile_id in sorted(known_profiles):
        selection = declared[profile_id]
        if not isinstance(selection, dict) or set(selection) != {
            "providerIds",
            "componentIds",
        }:
            raise PlatformError(
                f"provider profile {profile_id} must declare exactly providerIds and componentIds"
            )
        provider_ids = _unique_manifest_ids(
            selection["providerIds"], f"provider profile {profile_id} providerIds"
        )
        selected_component_ids = _unique_manifest_ids(
            selection["componentIds"],
            f"provider profile {profile_id} componentIds",
        )
        bundle = registry[profile_id]
        locked_provider_ids = set(bundle["providers"])
        if set(provider_ids) != locked_provider_ids:
            raise PlatformError(
                f"provider profile {profile_id} provider mapping differs from the lock"
            )
        locked_component_ids = set(str(item) for item in bundle["componentIds"])
        if set(selected_component_ids) != locked_component_ids:
            raise PlatformError(
                f"provider profile {profile_id} component mapping differs from the lock"
            )
        if enabled_components[profile_id] != locked_component_ids:
            raise PlatformError(
                f"provider profile {profile_id} enabledForProfiles mapping is incomplete or ambiguous"
            )

        component_claims: dict[str, str] = {}
        for provider_id in provider_ids:
            provider = bundle["providers"][provider_id]
            if provider["deployment"] != "profile-component":
                continue
            component_id = str(provider["componentId"])
            previous = component_claims.get(component_id)
            if previous is not None:
                raise PlatformError(
                    f"provider profile {profile_id} ambiguously maps component {component_id} "
                    f"to providers {previous} and {provider_id}"
                )
            component_claims[component_id] = provider_id
        if set(component_claims) != locked_component_ids:
            raise PlatformError(
                f"provider profile {profile_id} lacks an exact provider-to-component mapping"
            )

        available = core_components | enabled_components[profile_id]
        for row, component_id in zip(component_rows, component_ids, strict=True):
            if component_id not in available:
                continue
            dependencies = _unique_manifest_ids(
                row.get("dependsOn", []),
                f"component {component_id} dependsOn",
                allow_empty=True,
            )
            unavailable = sorted(set(dependencies) - available)
            if unavailable:
                raise PlatformError(
                    f"provider profile {profile_id} leaves component {component_id} "
                    "with unavailable dependencies: " + ", ".join(unavailable)
                )
        result[profile_id] = {
            "providerIds": list(provider_ids),
            "componentIds": list(selected_component_ids),
        }
    return result


def component_dependencies(cfg: dict[str, Any], row: dict[str, Any]) -> list[str]:
    dependencies = [str(item) for item in row.get("dependsOn", [])]
    if len(dependencies) != len(set(dependencies)):
        raise PlatformError(f"{row.get('id')} has duplicate dependencies")
    role_dependencies = row.get("dependsOnRoles", [])
    if role_dependencies:
        contract = data_content_contract()
        plane = resolved_data_content(cfg)
        dependencies.extend(
            contract.role_component(plane, str(role_id))
            for role_id in role_dependencies
        )
    return list(dict.fromkeys(dependencies))


def component_order(
    cfg: dict[str, Any], selected: list[str] | None
) -> list[dict[str, Any]]:
    rows = {row["id"]: row for row in components(cfg)}
    wanted = set(selected or rows)
    unknown = sorted(wanted - rows.keys())
    if unknown:
        raise PlatformError("unknown component(s): " + ", ".join(unknown))

    def include_deps(component_id: str) -> None:
        for dep in component_dependencies(cfg, rows[component_id]):
            if dep not in rows:
                raise PlatformError(
                    f"{component_id} depends on unknown component {dep}"
                )
            if dep not in wanted:
                wanted.add(dep)
                include_deps(dep)

    for item in list(wanted):
        include_deps(item)

    result: list[dict[str, Any]] = []
    pending = set(wanted)
    while pending:
        ready = sorted(
            (
                item
                for item in pending
                if set(component_dependencies(cfg, rows[item]))
                <= {r["id"] for r in result}
            ),
            key=lambda item: (int(rows[item].get("stage", 0)), item),
        )
        if not ready:
            raise PlatformError("component dependency graph contains a cycle")
        item = ready[0]
        result.append(rows[item])
        pending.remove(item)
    return result


def run(
    command: list[str],
    *,
    check: bool = True,
    input_text: str | None = None,
    capture_output: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        text=True,
        input=input_text,
        capture_output=capture_output,
        env=env,
    )


def ssh_transport_command(program: str = "ssh") -> list[str]:
    return [program, *SSH_TRANSPORT_OPTIONS]


def remote_rsync_command(*arguments: str) -> list[str]:
    return [
        "rsync",
        "-e",
        shlex.join(ssh_transport_command()),
        *arguments,
    ]


def ssh(
    cfg: dict[str, Any],
    remote_command: str,
    *,
    check: bool = True,
    input_text: str | None = None,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    target = host_spec(cfg)["ssh"]
    # SSH invokes the account's login shell.  The platform's remote commands
    # intentionally use Bash features (and must work even when root uses zsh),
    # so select Bash explicitly instead of inheriting the account default.
    remote_script = (
        f"export PYTHONDONTWRITEBYTECODE={shlex.quote('1')};\n{remote_command}"
    )
    remote_command = f"bash -c {shlex.quote(remote_script)}"
    return run(
        [
            *ssh_transport_command(),
            target,
            remote_command,
        ],
        check=check,
        input_text=input_text,
        capture_output=capture_output,
    )


def host_bootstrap_env_command(cfg: dict[str, Any]) -> str:
    """Build the fail-closed clean-host canonical seed merge command."""

    secret_root = str(host_spec(cfg)["secretsRoot"]).rstrip("/")
    if not secret_root.startswith("/") or secret_root == "/":
        raise PlatformError("host secrets root must be an absolute non-root path")
    keys = sorted(HOST_BOOTSTRAP_SEED_KEYS)
    key_words = " ".join(shlex.quote(key) for key in keys)
    return f"""set -eu
umask 077
fail() {{ printf '%s\\n' "host-bootstrap-env: $*" >&2; exit 74; }}
[ "$(id -u)" -eq 0 ] || fail 'root SSH target is required'
secret_root={shlex.quote(secret_root)}
canonical="$secret_root/platform.env"
lock="$secret_root/.platform-env.lock"
if [ -e "$secret_root" ]; then
    [ ! -L "$secret_root" ] && [ -d "$secret_root" ] || fail 'secret root is unsafe'
    [ "$(stat -c %u "$secret_root")" -eq 0 ] || fail 'secret root owner is unsafe'
else
    mkdir -p "$secret_root"
fi
chown root:root "$secret_root"
chmod 0700 "$secret_root"
if [ -e "$canonical" ]; then
    [ ! -L "$canonical" ] && [ -f "$canonical" ] || fail 'canonical env is unsafe'
    [ "$(stat -c %u "$canonical")" -eq 0 ] || fail 'canonical env owner is unsafe'
    [ "$(stat -c %a "$canonical")" = 600 ] || fail 'canonical env mode is unsafe'
fi
if [ -e "$lock" ]; then
    [ ! -L "$lock" ] && [ -f "$lock" ] || fail 'canonical lock is unsafe'
    [ "$(stat -c %u "$lock")" -eq 0 ] || fail 'canonical lock owner is unsafe'
fi
: >>"$lock"
chown root:root "$lock"
chmod 0600 "$lock"
exec 9>"$lock"
flock -x 9
incoming=$(mktemp "$secret_root/.host-bootstrap-incoming.XXXXXX")
merged=$(mktemp "$secret_root/.host-bootstrap-merged.XXXXXX")
empty=$(mktemp "$secret_root/.host-bootstrap-empty.XXXXXX")
cleanup() {{ rm -f "$incoming" "$merged" "$empty"; }}
trap cleanup EXIT HUP INT TERM
cat >"$incoming"
chmod 0600 "$incoming" "$merged" "$empty"
[ "$(wc -l <"$incoming" | tr -d ' ')" -eq {len(keys)} ] || fail 'seed count is invalid'
awk -F= '
    $0 !~ /^[A-Z][A-Z0-9_]*=.+$/ {{ exit 1 }}
    {{ if (++seen[$1] != 1) exit 1 }}
' "$incoming" || fail 'seed payload is invalid'
for key in {key_words}; do
    [ "$(awk -F= -v key="$key" '$1 == key {{ count++ }} END {{ print count + 0 }}' "$incoming")" -eq 1 ] \
        || fail 'seed allowlist is incomplete'
done
existing=$empty
if [ -e "$canonical" ]; then existing=$canonical; fi
awk -F= '
    NR == FNR {{
        key = $1
        incoming[key] = substr($0, index($0, "=") + 1)
        order[++count] = key
        next
    }}
    {{
        key = $1
        if (key in incoming) {{
            if (++seen[key] != 1) exit 72
            current = substr($0, index($0, "=") + 1)
            if (current == "") print key "=" incoming[key]
            else print $0
            consumed[key] = 1
            next
        }}
        print $0
    }}
    END {{
        for (position = 1; position <= count; position++) {{
            key = order[position]
            if (!(key in consumed)) print key "=" incoming[key]
        }}
    }}
' "$incoming" "$existing" >"$merged" || fail 'canonical env contains duplicate host keys'
chown root:root "$merged"
chmod 0600 "$merged"
mv -f "$merged" "$canonical"
chown root:root "$canonical"
chmod 0600 "$canonical"
[ "$(stat -c %a "$secret_root")" = 700 ] || fail 'secret root mode verification failed'
[ "$(stat -c %u "$canonical")" -eq 0 ] || fail 'canonical env owner verification failed'
[ "$(stat -c %a "$canonical")" = 600 ] || fail 'canonical env mode verification failed'
"""


def materialize_host_bootstrap_env(
    cfg: dict[str, Any], *, contract_source: Path | None = None
) -> None:
    """Fill only missing clean-host inputs before the host installer runs."""

    seeds = host_bootstrap_seeds(contract_source=contract_source)
    payload = "".join(f"{key}={seeds[key]}\n" for key in sorted(seeds))
    ssh(cfg, host_bootstrap_env_command(cfg), input_text=payload)


def scp(cfg: dict[str, Any], source: Path, destination: str) -> None:
    target = host_spec(cfg)["ssh"]
    run(
        [
            *ssh_transport_command("scp"),
            "-q",
            str(source),
            f"{target}:{destination}",
        ]
    )


def remote_root(cfg: dict[str, Any]) -> str:
    return str(host_spec(cfg)["root"])


def remote_script(cfg: dict[str, Any], name: str) -> str:
    return f"{remote_root(cfg)}/bin/{name}"


def remote_step(cfg: dict[str, Any], name: str) -> str:
    if Path(name).name != name or not name.endswith(".sh"):
        raise PlatformError("deployment step must be a shell-script basename")
    return f"{remote_root(cfg)}/steps/{name}"


def synchronized_core_scripts(cfg: dict[str, Any]) -> list[str]:
    names = [
        "server-secrets.py",
        "server-verify.py",
        "server-provision.py",
        "server-hermes.py",
        "server-toolhive.py",
        "server-paperclip-experimental.py",
        "server-observability-canary.py",
        "server-integration-canaries.py",
        "server-notion-sync.py",
        "server-cloudflare-acceptance.py",
        "server-kestra-reconcile.py",
        "server-profile-reconcile.py",
        "agent-plane-gateway.py",
        "profile_catalog.py",
        "server-config.py",
        "render-cloudflare.py",
        "cloudflare-preflight.py",
        "server-cloudflare-dns.py",
        "server-cloudflare-access.py",
        "server-cloudflare-runtime.py",
        "render-profiles.py",
        "data_content_plane.py",
    ]
    runner = str(cfg.get("spec", {}).get("e2eCanary", {}).get("runner", ""))
    if runner:
        if Path(runner).name != runner or not runner.endswith(".py"):
            raise PlatformError("e2eCanary.runner must be a Python basename")
        names.append(runner)
    return list(dict.fromkeys(names))


def canonical_compose_sources() -> list[Path]:
    """Return one owner-scoped Compose manifest for every managed service."""
    return sorted(SERVICES_ROOT.glob("*/compose.yaml"))


def parse_dotenv(path: Path) -> dict[str, str]:
    """Parse exactly one dotenv file; never merge ambient process secrets."""

    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def local_dotenv(path: Path) -> dict[str, str]:
    """Backward-compatible name for the strict single-file parser."""

    return parse_dotenv(path)


def normalize_notion_token_import(values: dict[str, str]) -> dict[str, str]:
    """Collapse Notion credential aliases to one deterministic canonical key."""
    normalized = dict(values)
    selected = next(
        (
            str(normalized[key]).strip()
            for key in NOTION_TOKEN_IMPORT_PRIORITY
            if str(normalized.get(key, "")).strip()
        ),
        "",
    )
    for key in NOTION_TOKEN_IMPORT_PRIORITY:
        normalized.pop(key, None)
    if selected:
        normalized["NOTION_TOKEN"] = selected
    return normalized


def ensure_safe_target(cfg: dict[str, Any]) -> None:
    target = host_spec(cfg)["ssh"].split("@")[-1]
    if target in set(host_spec(cfg).get("excluded", [])):
        raise PlatformError(f"deployment target {target} is explicitly excluded")


def render_config(cfg: dict[str, Any]) -> Path:
    output_dir = local_evidence_root()
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "platform.rendered.json"
    structural = load_yaml(CONFIG_PATH)
    path.write_text(json.dumps(structural, indent=2, sort_keys=True) + "\n")
    return path


SYNC_MANIFEST_NAME = ".sync-manifest.sha256"


@contextmanager
def local_sync_lock():
    """Serialize the full local sync lifecycle for one operator checkout."""

    path = local_evidence_root().parent / "sync.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as handle:
        path.chmod(0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _copy_sync_source(source: Path, destination: Path) -> None:
    """Copy one approved source into the bundle without following special files."""

    mode = source.lstat().st_mode
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise PlatformError(f"sync source must be a regular file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(source.read_bytes())


def _copy_sync_tree(source: Path, destination: Path) -> None:
    """Copy an approved tree, rejecting links and non-file filesystem entries."""

    mode = source.lstat().st_mode
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise PlatformError(f"sync source must be a directory: {source}")
    destination.mkdir(parents=True, exist_ok=True)
    for item in sorted(source.iterdir(), key=lambda path: path.name):
        if item.name == "__pycache__" or item.name.endswith((".orig", ".pyc")):
            continue
        item_mode = item.lstat().st_mode
        target = destination / item.name
        if stat.S_ISDIR(item_mode):
            _copy_sync_tree(item, target)
        elif stat.S_ISREG(item_mode):
            _copy_sync_source(item, target)
        else:
            raise PlatformError(f"sync source contains a special file: {item}")


def _write_sync_manifest(bundle: Path) -> None:
    rows: list[str] = []
    for path in sorted(
        bundle.rglob("*"), key=lambda item: item.relative_to(bundle).as_posix()
    ):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise PlatformError(f"sync bundle contains a special file: {path}")
        relative = path.relative_to(bundle).as_posix()
        if "\n" in relative or "\r" in relative:
            raise PlatformError(f"sync bundle path contains a newline: {relative!r}")
        rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n")
    (bundle / SYNC_MANIFEST_NAME).write_text("".join(rows))


def _materialize_sync_bundle(cfg: dict[str, Any], bundle: Path, rendered: Path) -> None:
    tree_projections = (
        (KESTRA_WORKFLOWS_ROOT, "manifests/kestra/flows"),
        (PROFILES_ROOT, "templates/profiles"),
        (PROFILES_ROOT / "instructions", "runtime/paperclip/profiles/instructions"),
        (
            VERIFICATION_PROFILE_SKILL_ROOT,
            "runtime/paperclip/profiles/skills/verification-before-completion",
        ),
        (CLOUDFLARE_ROOT, "manifests/cloudflare"),
        (ROOT / "deployment/steps", "steps"),
        (AGENT_RUNTIME_ROOT, "deployment/agent-runtime"),
        (SERVICES_ROOT, "deployment/services"),
        (
            SYSTEM_PLATFORM_SKILL_ROOT,
            "manifests/hermes/skills/system-platform",
        ),
    )
    for source, relative in tree_projections:
        _copy_sync_tree(source, bundle / relative)

    profile_catalog = bundle / "templates/profiles/catalog.yaml"
    profile_catalog.rename(profile_catalog.with_name("profiles.yaml"))

    file_projections = {
        "manifests/kestra/application.yaml": KESTRA_SERVICE_ROOT / "application.yaml",
        "deployment/compose.yaml": ROOT / "deployment/compose.yaml",
        "deployment/scripts/compose-remote.sh": ROOT
        / "deployment/scripts/compose-remote.sh",
        "config/services/kestra/application.yaml": KESTRA_SERVICE_ROOT
        / "application.yaml",
        "config/services/searxng/settings.yml": SEARXNG_SERVICE_ROOT / "settings.yml",
        "manifests/hermes/hermes.service": HERMES_SERVICE_ROOT / "service.unit",
        "manifests/hermes/acceptance-canary.py": HERMES_SERVICE_ROOT
        / "acceptance-canary.py",
        "manifests/hermes/bootstrap-mattermost.py": HERMES_SERVICE_ROOT
        / "bootstrap-mattermost.py",
        "manifests/hermes/config.yaml.template": HERMES_SERVICE_ROOT
        / "config.yaml.template",
        "manifests/hermes/SOUL.md": HERMES_SERVICE_ROOT / "soul.txt",
        "manifests/hermes/requirements-messaging.lock": HERMES_SERVICE_ROOT
        / "requirements-messaging.lock",
        "manifests/hermes/supply-chain.lock.json": HERMES_SERVICE_ROOT
        / "supply-chain.lock.json",
        "runtime/paperclip/scripts/bootstrap-paperclip.py": TOOL_ROOT
        / "bootstrap-paperclip.py",
        "runtime/paperclip/scripts/profile_catalog.py": TOOL_ROOT
        / "profile_catalog.py",
        "runtime/paperclip/scripts/integration_canary.py": ROOT
        / "tests/fixtures/agents/integration_canary.py",
        "templates/platform.json": rendered,
        "templates/compose-seeds.lock.json": COMPOSE_SEEDS_PATH,
        "templates/platform.lock.yaml": LOCK_PATH,
        "config/acceptance-requirements.yaml": ACCEPTANCE_REQUIREMENTS_PATH,
    }
    core_scripts = synchronized_core_scripts(cfg)
    plane = optional_resolved_data_content(cfg)
    adapter_scripts = (
        sorted({str(row["script"]) for row in plane["adapters"].values()})
        if plane is not None
        else []
    )
    for name in [*core_scripts, *adapter_scripts]:
        file_projections[f"bin/{name}"] = TOOL_ROOT / name
    for relative, source in file_projections.items():
        _copy_sync_source(source, bundle / relative)
    _write_sync_manifest(bundle)


def sync(cfg: dict[str, Any], *, render_projections: bool = True) -> None:
    """Serialize one complete sync from local bundle through remote publish."""

    with local_sync_lock():
        _sync_unlocked(cfg, render_projections=render_projections)


def _sync_unlocked(cfg: dict[str, Any], *, render_projections: bool = True) -> None:
    ensure_safe_target(cfg)
    target = host_spec(cfg)["ssh"]
    remote_root = host_spec(cfg)["root"]
    # A sync may be started again before an earlier upload has published.  Its
    # staging tree must therefore belong to exactly one invocation: publishing
    # the earlier bundle removes only its own stage, never an in-flight rsync.
    staging_root = f"{remote_root}/.sync-staging-{uuid.uuid4().hex}"
    rendered = render_config(cfg)
    try:
        ssh(
            cfg,
            "set -eu; umask 077; mkdir -p " + shlex.quote(staging_root),
        )
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp) / "bundle"
            bundle.mkdir()
            _materialize_sync_bundle(cfg, bundle, rendered)
            run(
                remote_rsync_command(
                    "-rtz",
                    "--delete",
                    str(bundle) + "/",
                    f"{target}:{staging_root}/",
                )
            )
        ssh(
            cfg,
            "set -eu; umask 077; stage="
            + shlex.quote(staging_root)
            + "; root="
            + shlex.quote(remote_root)
            + '; lock="$root/.sync.lock"; : > "$lock"; chown root:root "$lock"; '
            + 'chmod 0600 "$lock"; exec 9>"$lock"; flock -x 9; '
            + 'cd "$stage"; actual="$(find . -type f ! -path '
            + shlex.quote(f"./{SYNC_MANIFEST_NAME}")
            + " -printf '%P\\n' | LC_ALL=C sort)\"; expected=\"$(sed -n "
            + shlex.quote(r"s/^[0-9a-f]\{64\}  //p")
            + " "
            + shlex.quote(SYNC_MANIFEST_NAME)
            + ')"; test "$actual" = "$expected"; sha256sum -c '
            + shlex.quote(SYNC_MANIFEST_NAME)
            + "; rm -f "
            + shlex.quote(SYNC_MANIFEST_NAME)
            + "; "
            + 'chown -R root:root "$stage"; '
            + 'find "$stage" -type d -exec chmod 0755 {} +; '
            + 'find "$stage" -type f -exec chmod 0644 {} +; '
            + 'find "$stage/bin" -type f -exec chmod 0700 {} +; '
            + 'find "$stage/steps" -type f -name "*.sh" -exec chmod 0700 {} +; '
            + 'test -z "$(find "$stage" -type l -print -quit)"; '
            + 'test -z "$(find "$stage" \\( ! -user root -o ! -group root \\) -print -quit)"; '
            + 'test -z "$(find "$stage/bin" -type f ! -perm 0700 -print -quit)"; '
            + 'test -z "$(find "$stage/steps" -type f -name "*.sh" ! -perm 0700 -print -quit)"; '
            + 'test -z "$(find "$stage" -type f ! -path "$stage/bin/*" '
            + '! -path "$stage/steps/*.sh" '
            + '! -perm 0644 -print -quit)"; '
            + 'mkdir -p "$root/config" "$root/runtime"; '
            + "for rel in bin templates manifests runtime/paperclip deployment steps config/services; do "
            + 'mkdir -p "$root/$rel"; '
            + 'test -z "$(find "$root/$rel" -type l -print -quit)"; '
            + 'find "$root/$rel" -type d -exec chown root:root {} + '
            + "-exec chmod 0755 {} +; "
            + 'rsync -rtp --delete --ignore-times "$stage/$rel/" "$root/$rel/"; '
            + "done; "
            + 'install -o root -g root -m 0644 "$stage/config/acceptance-requirements.yaml" '
            + '"$root/config/.acceptance-requirements.yaml.tmp"; '
            + 'mv -f "$root/config/.acceptance-requirements.yaml.tmp" '
            + '"$root/config/acceptance-requirements.yaml"; '
            + 'set -- "$root/bin" "$root/templates" "$root/manifests" '
            + '"$root/runtime/paperclip" "$root/deployment" '
            + '"$root/steps" "$root/config/services"; '
            + 'test -z "$(find "$@" -type l -print -quit)"; '
            + 'test -z "$(find "$@" \\( ! -user root -o ! -group root \\) -print -quit)"; '
            + 'test -z "$(find "$root/bin" -type f ! -perm 0700 -print -quit)"; '
            + 'test -z "$(find "$root/steps" -type f -name "*.sh" ! -perm 0700 -print -quit)"; '
            + 'test -z "$(find "$root/templates" "$root/manifests" '
            + '"$root/runtime/paperclip" "$root/deployment" '
            + '"$root/config/services" '
            + '-type f ! -perm 0644 -print -quit)"; '
            + 'test -z "$(find "$root/steps" -type f ! -name "*.sh" -print -quit)"; '
            + "test \"$(stat -c '%u:%g:%a:%F' "
            + '"$root/config/acceptance-requirements.yaml")" '
            + "= '0:0:644:regular file'; rm -rf \"$stage\"",
        )
    except BaseException:
        try:
            ssh(
                cfg,
                "set -eu; stage=" + shlex.quote(staging_root) + '; rm -rf -- "$stage"',
                check=False,
            )
        except BaseException:
            pass
        raise
    # Source synchronization is deliberately projection-blind.  Only the
    # explicit config-render stage may write runtime/ or the projection
    # manifest; this makes a repeat sync safe after an audited render.
    del render_projections


def compose_validate(row: dict[str, Any], placeholder_env: Path) -> None:
    compose = row.get("compose")
    if not compose:
        return
    path = ROOT / compose
    if not path.is_file():
        raise PlatformError(f"missing compose for {row['id']}: {path}")
    document = load_yaml(path)
    services = document.get("services")
    if not isinstance(services, dict) or not services:
        raise PlatformError(f"compose {row['id']} has no services")
    text = path.read_text()
    if "/var/run/docker.sock:/var/run/docker.sock" in text:
        raise PlatformError(f"compose {row['id']} exposes the host Docker socket")
    for service_name, service in services.items():
        image = str((service or {}).get("image", ""))
        if image.endswith(":latest"):
            raise PlatformError(
                f"compose {row['id']}/{service_name} uses a floating latest image"
            )
        for port in (service or {}).get("ports", []) or []:
            rendered = str(port)
            if rendered.startswith("${"):
                continue
            if rendered.startswith("0.0.0.0:") or (
                rendered.count(":") == 1 and not rendered.startswith("127.0.0.1:")
            ):
                raise PlatformError(
                    f"compose {row['id']}/{service_name} publishes a non-loopback port: {rendered}"
                )


def placeholder_env(cfg: dict[str, Any]) -> Path:
    keys: set[str] = set()
    for row in components(cfg):
        keys.update(row.get("secrets", []))
    handle = tempfile.NamedTemporaryFile("w", prefix="mte-plan-", delete=False)
    os.chmod(handle.name, 0o600)
    for key in sorted(keys):
        handle.write(f"{key}=plan-placeholder-0123456789abcdef0123456789abcdef\n")
    handle.write("MATTERMOST_SITE_URL=http://127.0.0.1:18065\n")
    handle.write("SEARXNG_BASE_URL=http://127.0.0.1:18088/\n")
    handle.close()
    return Path(handle.name)


def cmd_plan(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    ensure_safe_target(cfg)
    ordered = component_order(cfg, args.components or None)
    temp = placeholder_env(cfg)
    try:
        for row in ordered:
            compose_validate(row, temp)
    finally:
        temp.unlink(missing_ok=True)
    seed_values = bootstrap_seeds()

    def exposure_class(row: dict[str, Any]) -> str:
        exposure = row.get("exposure", {})
        if not isinstance(exposure, dict):
            return "none"
        if exposure.get("class"):
            return str(exposure["class"])
        ref = str(exposure.get("accessClassRef", ""))
        return os.environ.get(ref) or seed_values.get(ref) or "none"

    result = {
        "target": host_spec(cfg)["ssh"],
        "domain": cfg["spec"]["resolvedDomain"] or None,
        "components": [
            {
                "id": row["id"],
                "stage": row.get("stage"),
                "management": "compose"
                if row.get("compose")
                else row.get("management"),
                "dependsOn": row.get("dependsOn", []),
                "dependsOnRoles": row.get("dependsOnRoles", []),
                "resolvedDependsOn": component_dependencies(cfg, row),
                "exposure": exposure_class(row),
                "required": bool(row.get("required", False)),
            }
            for row in ordered
        ],
        "valid": True,
    }
    plane = optional_resolved_data_content(cfg)
    if plane is not None:
        profile_id = str(plane["profile"])
        selection = provider_profile_catalog(cfg)[profile_id]
        result["providerProfile"] = {
            "id": profile_id,
            **selection,
        }
    print(json.dumps(result, indent=2))


def cmd_preflight(args: argparse.Namespace) -> None:
    # Keep this entirely local and before ``config``/SSH so the public default
    # cannot reach a host, create files, or defer the consent failure to the
    # Daytona stage.
    values = operator_values(required=True)
    validate_public_harness_enablement(values)
    cfg = config(args.domain)
    ensure_safe_target(cfg)
    result = ssh(
        cfg,
        "test -r /etc/os-release && . /etc/os-release && "
        'test "${ID:-}" = ubuntu && '
        'printf \'{"ssh":"ready","os":"ubuntu"}\\n\'',
        capture_output=True,
    )
    run_resource_preflight(cfg, "deploy", values=values)
    print(result.stdout, end="")


def run_resource_preflight(
    cfg: dict[str, Any],
    mode: str,
    *,
    values: dict[str, str],
    source: Path = RESOURCE_PREFLIGHT_STEP,
) -> None:
    """Stream the read-only admission check with its canonical policy."""

    if mode not in {"deploy", "daytona-e2e"}:
        raise PlatformError("unsupported resource preflight mode")
    contract = server_config_contract()
    try:
        thresholds = contract.resource_preflight_values(
            normalized_operator_values(values)
        )
    except contract.ConfigError as exc:
        raise PlatformError(str(exc)) from exc
    assignments = " ".join(
        f"{key}={shlex.quote(value)}" for key, value in sorted(thresholds.items())
    )
    ssh(
        cfg,
        f"env {assignments} bash -s -- {shlex.quote(mode)}",
        input_text=source.read_text(),
    )


def cmd_sync(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    sync(cfg)
    print(json.dumps({"synced": True, "target": host_spec(cfg)["ssh"]}))


def run_host_bootstrap(
    cfg: dict[str, Any],
    *,
    source: Path | None = None,
    contract_source: Path | None = None,
) -> None:
    ensure_safe_target(cfg)
    source = source or ROOT / "deployment/steps/host.sh"
    remote = "/tmp/mte-platform-host.sh"
    materialize_host_bootstrap_env(cfg, contract_source=contract_source)
    scp(cfg, source, remote)
    ssh(
        cfg,
        "set -eu; "
        + f"trap 'rm -f {shlex.quote(remote)}' EXIT; "
        + f"chmod 0700 {shlex.quote(remote)}; {shlex.quote(remote)}",
    )


def finish_platform_bootstrap(cfg: dict[str, Any]) -> None:
    sync(cfg)
    ssh(
        cfg,
        f"python3 {shlex.quote(remote_script(cfg, 'server-config.py'))} init </dev/null && "
        f"python3 {shlex.quote(remote_script(cfg, 'server-secrets.py'))} init && "
        f"python3 {shlex.quote(remote_script(cfg, 'server-config.py'))} init </dev/null && "
        f"python3 {shlex.quote(remote_script(cfg, 'server-config.py'))} render && "
        f"python3 {shlex.quote(remote_script(cfg, 'server-config.py'))} audit",
    )


def cmd_bootstrap(args: argparse.Namespace) -> None:
    validate_operator_environment(
        operator_values(required=True), reject_documentation_values=True
    )
    cfg = config(args.domain)
    run_host_bootstrap(cfg)
    # Import the explicit operator inputs before the ordinary bootstrap stages.
    # This fixes clean-host bootstrap: remote init must not start from empty
    # stdin when no canonical source exists yet.
    run_config(cfg, "init")
    finish_platform_bootstrap(cfg)
    print(
        json.dumps(
            {
                "bootstrap": "complete",
                "target": host_spec(cfg)["ssh"],
                "platformRoot": remote_root(cfg),
                "runtime": "docker-compose-ready",
            },
            indent=2,
        )
    )


def cmd_secrets(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    sync(cfg)
    remote_root = host_spec(cfg)["root"]
    ssh(
        cfg,
        f"python3 {shlex.quote(remote_root + '/bin/server-secrets.py')} {shlex.quote(args.action)}",
    )
    if args.action == "init":
        ssh(
            cfg,
            f"python3 {shlex.quote(remote_root + '/bin/server-config.py')} render && "
            f"python3 {shlex.quote(remote_root + '/bin/server-config.py')} audit",
        )


def run_config(cfg: dict[str, Any], action: str) -> None:
    script = remote_script(cfg, "server-config.py")
    if action == "init":
        # This is the only path allowed to import the explicit operator input
        # carrier. Server-side init reconciles the reviewed operator set while
        # keeping generated and provisioned values fill-only.
        contract = server_config_contract()
        imported = {
            key: value
            for key, value in normalized_operator_values(
                operator_values(required=True)
            ).items()
            if key not in contract.LOCAL_ONLY_OPERATOR_INPUT_KEYS
        }
        sync(cfg, render_projections=False)
        ssh(
            cfg,
            f"umask 077; python3 {shlex.quote(script)} init",
            input_text=json.dumps(imported),
        )
        ssh(cfg, f"python3 {shlex.quote(remote_script(cfg, 'server-secrets.py'))} init")
        ssh(cfg, f"python3 {shlex.quote(script)} init </dev/null")
        # Cloudflare bootstrap credentials stay in the local operator carrier.
        # Reconcile the least-privilege token only after the canonical source
        # and generated service secrets exist, but before the first render,
        # which intentionally requires the scoped token and zone binding.
        run_cloudflare(cfg, "token-apply")
        ssh(cfg, f"python3 {shlex.quote(script)} render")
        ssh(cfg, f"python3 {shlex.quote(script)} audit")
        return
    if action == "render":
        sync(cfg, render_projections=False)
        ssh(cfg, f"python3 {shlex.quote(script)} render")
        return
    # audit/diff intentionally do not sync or render first: they must observe
    # source hash drift and manual edits rather than silently repairing them.
    ssh(cfg, f"python3 {shlex.quote(script)} {shlex.quote(action)}")


def cmd_config(args: argparse.Namespace) -> None:
    if args.action == "schema":
        print(json.dumps(operator_environment_schema(), indent=2, sort_keys=True))
        return
    if args.action == "check":
        result = validate_operator_environment(
            operator_values(required=True), reject_documentation_values=True
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    if args.action == "init":
        validate_operator_environment(
            operator_values(required=True), reject_documentation_values=True
        )
    cfg = config(args.domain)
    run_config(cfg, args.action)


def ensure_config_initialized(cfg: dict[str, Any]) -> None:
    source = "/root/.config/mte-secrets/platform.env"
    result = ssh(cfg, f"test -s {shlex.quote(source)}", check=False)
    if result.returncode != 0:
        run_config(cfg, "init")
        return
    # Re-import the reviewed operator contract from the same selected file on
    # every post-install pass. Managed Notion identifiers cross this boundary
    # only for fill-only upgrades; server-config reconciles operator-owned keys
    # and preserves generated/provisioned values.
    contract = server_config_contract()
    local_values = normalize_notion_token_import(operator_values(required=True))
    telegram_alias = "PRIN7R_HERMES_TELEGRAM_BOT_TOKEN"
    if (
        not str(local_values.get("HERMES_TELEGRAM_BOT_TOKEN", "")).strip()
        and str(local_values.get(telegram_alias, "")).strip()
    ):
        local_values["HERMES_TELEGRAM_BOT_TOKEN"] = local_values[telegram_alias]
    local_values.pop(telegram_alias, None)
    allowed_upgrade_imports = (
        set(contract.REQUIRED_OPERATOR_ENV_KEYS)
        | set(contract.OPTIONAL_OPERATOR_INPUT_KEYS)
    ) - set(contract.LOCAL_ONLY_OPERATOR_INPUT_KEYS) | NOTION_UPGRADE_IMPORT_KEYS
    upgrade_imports = {
        key: value
        for key, value in local_values.items()
        if key in allowed_upgrade_imports
    }
    sync(cfg, render_projections=False)
    script = remote_script(cfg, "server-config.py")
    ssh(
        cfg,
        f"umask 077; python3 {shlex.quote(script)} init",
        input_text=json.dumps(upgrade_imports),
    )
    ssh(cfg, f"python3 {shlex.quote(remote_script(cfg, 'server-secrets.py'))} init")
    ssh(cfg, f"python3 {shlex.quote(script)} render")
    ssh(cfg, f"python3 {shlex.quote(script)} audit")


def cmd_verify(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    if getattr(args, "all", False) and args.components:
        raise PlatformError("verify --all cannot be combined with component names")
    run_data_content_projections(cfg, "verify")
    sync(cfg)
    command = [
        "python3",
        remote_script(cfg, "server-verify.py"),
        "verify",
        *([] if getattr(args, "all", False) else args.components),
    ]
    ssh(cfg, " ".join(shlex.quote(item) for item in command))


def cmd_status(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    ssh(cfg, f"python3 {shlex.quote(remote_script(cfg, 'server-verify.py'))} status")


def cmd_acceptance(args: argparse.Namespace) -> None:
    registry = load_yaml(ACCEPTANCE_REQUIREMENTS_PATH)
    if args.action == "export":
        print(json.dumps(registry, indent=2))
        return
    cfg = config(args.domain)
    sync(cfg)
    ssh(
        cfg,
        f"python3 {shlex.quote(remote_script(cfg, 'server-verify.py'))} acceptance",
    )


def run_paperclip_runtime(cfg: dict[str, Any], action: str) -> None:
    sync(cfg)
    step = remote_step(cfg, "paperclip.sh")
    ssh(cfg, f"{shlex.quote(step)} {shlex.quote(action)}")


def cmd_runtime(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    if args.runtime != "paperclip":
        raise PlatformError(f"unsupported runtime: {args.runtime}")
    run_paperclip_runtime(cfg, args.action)


def merge_paperclip_experimental_inputs(cfg: dict[str, Any], feature: str) -> None:
    """Assert declared refs exist in the canonical server-side source.

    Normal deploys never re-read the legacy operator dotenv.  That file is a
    one-time migration input for ``platform config init`` only.
    """
    spec = cfg["spec"]
    experimental = spec.get("paperclipExperimental", {})
    daytona = experimental.get("daytona", {}) if isinstance(experimental, dict) else {}
    e2e = spec.get("e2eCanary", {})
    refs: set[str] = set()
    if feature == "secrets":
        secret_spec = (
            experimental.get("secrets", {}) if isinstance(experimental, dict) else {}
        )
        if isinstance(secret_spec, dict) and secret_spec.get("valueRef"):
            refs.add(str(secret_spec["valueRef"]))
    if feature == "daytona":
        refs.update(
            str(daytona[key])
            for key in ("apiKeyRef", "apiUrlRef", "targetRef")
            if isinstance(daytona, dict) and daytona.get(key)
        )
    if feature == "e2e" and isinstance(e2e, dict):
        refs.update(str(item) for item in e2e.get("llmCredentialRefs", []) if item)
        refs.update(str(item) for item in e2e.get("githubCredentialRefs", []) if item)
    code = """
import json
import os
from pathlib import Path
import sys

path = Path('/root/.config/mte-secrets/platform.env')
if not path.is_file() or path.stat().st_uid != 0 or path.stat().st_mode & 0o777 != 0o600:
    raise SystemExit('canonical platform.env is missing or has unsafe permissions')
values = {}
for line in path.read_text().splitlines():
    if line and not line.startswith('#') and '=' in line:
        key, value = line.split('=', 1)
        values[key] = value
required = set(json.load(sys.stdin))
missing = sorted(key for key in required if not values.get(key))
if missing:
    print(json.dumps({'ok': False, 'missingCanonicalRefs': missing}))
    raise SystemExit(1)
print(json.dumps({'ok': True, 'canonicalRefsChecked': len(required)}))
"""
    ssh(
        cfg,
        "umask 077; python3 -c " + shlex.quote(code),
        input_text=json.dumps(sorted(refs)),
    )


def require_daytona_dependencies(cfg: dict[str, Any]) -> None:
    """Fail closed unless account refs and profile tool identities are ready."""
    commands = [
        ["python3", remote_script(cfg, "server-provision.py"), "verify"],
        ["python3", remote_script(cfg, "server-profile-reconcile.py"), "verify"],
    ]
    ssh(
        cfg,
        "set -eu; "
        + "; ".join(
            " ".join(shlex.quote(item) for item in command) for command in commands
        ),
    )


def run_paperclip_experimental(cfg: dict[str, Any], feature: str, action: str) -> None:
    sync(cfg)
    script = remote_script(cfg, "server-paperclip-experimental.py")

    def reconcile(requested_action: str) -> None:
        command = ["python3", script, feature, requested_action]
        ssh(cfg, " ".join(shlex.quote(item) for item in command))

    def render_canonical_source() -> None:
        renderer = remote_script(cfg, "server-config.py")
        ssh(
            cfg,
            f"python3 {shlex.quote(renderer)} render && "
            f"python3 {shlex.quote(renderer)} audit",
        )

    if feature != "daytona":
        merge_paperclip_experimental_inputs(cfg, feature)
        reconcile(action)
        return

    step = remote_step(cfg, "daytona.sh")
    if action == "status":
        ssh(cfg, f"{shlex.quote(step)} status")
        merge_paperclip_experimental_inputs(cfg, feature)
        reconcile("status")
        return

    if action == "apply":
        # Paperclip's native plugin package (and Daytona SDK) is installed by
        # the ordinary Paperclip deployment. Build the named snapshots before
        # reconciling an environment that requires their readiness flags.
        for step_action in ("install", "set-target"):
            ssh(cfg, f"{shlex.quote(step)} {step_action}")
        render_canonical_source()
        ssh(cfg, f"{shlex.quote(step)} images")

        # Snapshot creation atomically merges readiness into canonical config.
        # Render before the first environment reconcile so it cannot observe a
        # missing snapshot or stale projection.
        render_canonical_source()
        merge_paperclip_experimental_inputs(cfg, feature)
        reconcile("apply")
        ssh(cfg, f"{shlex.quote(step)} lifecycle")
        ssh(cfg, f"{shlex.quote(step)} verify")
        reconcile("verify")
        require_daytona_dependencies(cfg)
        run_paperclip_runtime(cfg, "verify")
        return

    if action == "verify":
        merge_paperclip_experimental_inputs(cfg, feature)
        require_daytona_dependencies(cfg)
        ssh(cfg, f"{shlex.quote(step)} acceptance")
        render_canonical_source()
        reconcile("verify")
        require_daytona_dependencies(cfg)
        run_paperclip_runtime(cfg, "verify")
        return

    raise PlatformError(f"unsupported Daytona action: {action}")


def cmd_paperclip_experimental(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    run_paperclip_experimental(cfg, args.feature, args.action)


def run_kestra_canary(cfg: dict[str, Any], action: str) -> None:
    """Invoke the independently implemented E2E runner through a stable hook."""
    e2e = cfg["spec"].get("e2eCanary", {})
    runner_name = str(e2e.get("runner", "server-e2e-canary.py"))
    if Path(runner_name).name != runner_name or not runner_name.endswith(".py"):
        raise PlatformError("e2eCanary.runner must be a Python basename")
    runner = TOOL_ROOT / runner_name
    if not runner.is_file():
        raise PlatformError(
            f"E2E canary runner is not present yet: {runner}; "
            "the dedicated flow implementation must provide it"
        )
    if action == "apply":
        # The canary creates a coding sandbox. Its admission is derived from
        # the deploy policy, so E2E capacity cannot drift into six extra
        # operator-configurable thresholds.
        run_resource_preflight(
            cfg, "daytona-e2e", values=operator_values(required=True)
        )
    sync(cfg)
    merge_paperclip_experimental_inputs(cfg, "e2e")
    target = host_spec(cfg)["ssh"]
    remote = remote_script(cfg, runner_name)
    expected = hashlib.sha256(runner.read_bytes()).hexdigest()
    run(
        remote_rsync_command(
            "-az",
            "--chmod=Fu=rwx,Fgo=",
            str(runner),
            f"{target}:{remote}",
        )
    )
    command = ["python3", remote, action]
    verified_command = (
        "set -eu; "
        f"chown root:root {shlex.quote(remote)}; "
        f"chmod 0700 {shlex.quote(remote)}; "
        f"test \"$(stat -c '%u:%g:%a:%F' {shlex.quote(remote)})\" = "
        "'0:0:700:regular file'; "
        f"actual=$(sha256sum {shlex.quote(remote)} | cut -d' ' -f1); "
        f'test "$actual" = {shlex.quote(expected)}; '
        + " ".join(shlex.quote(item) for item in command)
    )
    ssh(cfg, verified_command)


def refresh_daytona_e2e_runtime(cfg: dict[str, Any]) -> None:
    """Reconcile and prove the runtime evidence consumed by the live canary."""
    run_paperclip_experimental(cfg, "daytona", "apply")
    run_paperclip_experimental(cfg, "daytona", "verify")


def run_kestra_canary_acceptance(cfg: dict[str, Any]) -> None:
    """Refresh Daytona, then produce and independently verify E2E evidence."""
    refresh_daytona_e2e_runtime(cfg)
    run_kestra_canary(cfg, "apply")
    run_kestra_canary(cfg, "verify")


def cmd_kestra_canary(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    run_kestra_canary(cfg, args.action)


def run_kestra_control(cfg: dict[str, Any], action: str) -> None:
    sync(cfg)
    command = [
        "python3",
        remote_script(cfg, "server-kestra-reconcile.py"),
        action,
    ]
    ssh(cfg, " ".join(shlex.quote(item) for item in command))


def cmd_kestra_control(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    run_kestra_control(cfg, args.action)


def run_profile_acceptance(cfg: dict[str, Any]) -> None:
    sync(cfg)
    commands = [
        ["python3", remote_script(cfg, "server-kestra-reconcile.py"), "verify"],
        [
            "python3",
            remote_script(cfg, "server-profile-reconcile.py"),
            "verify-access",
        ],
        [
            "python3",
            remote_script(cfg, "server-profile-reconcile.py"),
            "finalize",
        ],
    ]
    ssh(
        cfg,
        "set -eu; "
        + "; ".join(
            " ".join(shlex.quote(item) for item in command) for command in commands
        ),
    )


def cmd_profile_acceptance(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    run_profile_acceptance(cfg)


def canonical_source_sha256(cfg: dict[str, Any]) -> str:
    path = str(host_spec(cfg)["secretsRoot"]) + "/platform.env"
    result = ssh(
        cfg,
        f"set -eu; test -s {shlex.quote(path)}; sha256sum {shlex.quote(path)} | cut -d' ' -f1",
        capture_output=True,
    )
    value = result.stdout.strip()
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise PlatformError("canonical source hash observation is invalid")
    return value


def run_canonical_hash_bound(cfg: dict[str, Any], command: list[str]) -> None:
    before = canonical_source_sha256(cfg)
    ssh(cfg, " ".join(shlex.quote(item) for item in command))
    after = canonical_source_sha256(cfg)
    if before != after:
        raise PlatformError("canonical source changed during an acceptance producer")


def run_hermes_acceptance(cfg: dict[str, Any]) -> None:
    run_hermes(cfg, "health")
    run_canonical_hash_bound(cfg, ["/opt/mte-hermes/bin/acceptance-canary"])


def run_observability_acceptance(cfg: dict[str, Any]) -> None:
    """Atomically produce fresh, hash-bound live observability evidence."""
    sync(cfg)
    expected = canonical_source_sha256(cfg)
    producer = remote_script(cfg, "server-observability-canary.py")
    lock = f"{remote_root(cfg)}/evidence/.observability-acceptance.lock"
    command = [
        "sh",
        "-c",
        "set -eu; umask 077; mkdir -p "
        + shlex.quote(str(Path(lock).parent))
        + "; lock="
        + shlex.quote(lock)
        + '; : > "$lock"; chmod 0600 "$lock"; exec 9>"$lock"; flock -x 9; '
        + "; ".join(
            " ".join(shlex.quote(item) for item in items)
            for items in (
                [
                    "python3",
                    producer,
                    "reconcile-pass",
                    "--pass-number",
                    "1",
                    "--expected-source-hash",
                    expected,
                ],
                [
                    "python3",
                    producer,
                    "reconcile-pass",
                    "--pass-number",
                    "2",
                    "--expected-source-hash",
                    expected,
                ],
                [
                    "python3",
                    producer,
                    "finalize-idempotency",
                    "--expected-source-hash",
                    expected,
                ],
                ["python3", producer, "apply", "--expected-source-hash", expected],
            )
        ),
    ]
    run_canonical_hash_bound(cfg, command)


def cmd_observability_acceptance(args: argparse.Namespace) -> None:
    run_observability_acceptance(config(args.domain))


def run_final_evidence_rebind(cfg: dict[str, Any]) -> None:
    """Rebind internal evidence if Cloudflare minted canonical runtime refs.

    The sequence is intentionally unconditional: on a stable source every
    reconcile is a proved no-op, while a first install gets fresh evidence for
    the post-Cloudflare canonical hash before external acceptance.
    """
    run_config(cfg, "render")
    run_config(cfg, "audit")
    run_provision(cfg, "verify")
    run_tools(cfg, "verify")
    run_kestra_canary_acceptance(cfg)
    run_profile_acceptance(cfg)
    run_integration_canaries(cfg, "run", [])
    run_hermes_acceptance(cfg)
    run_observability_acceptance(cfg)
    # Keep the create/update/archive proof adjacent to its final consumers. The
    # verifier deliberately rejects evidence older than ten minutes.
    run_notion_projection(cfg, "canary")


def cmd_evidence_rebind(args: argparse.Namespace) -> None:
    run_final_evidence_rebind(config(args.domain))


def run_integration_canaries(
    cfg: dict[str, Any], action: str, canary_ids: list[str]
) -> None:
    """Run only the exact integration-canary producer synchronized by this source."""
    if action == "status" and canary_ids:
        raise PlatformError("integration-canaries status does not accept canary IDs")
    supported = {"C023", "C024", "C027", "C029", "C030"}
    unknown = sorted(set(canary_ids) - supported)
    if unknown:
        raise PlatformError(f"unknown integration canary IDs: {', '.join(unknown)}")
    sync(cfg)
    local = TOOL_ROOT / "server-integration-canaries.py"
    expected = hashlib.sha256(local.read_bytes()).hexdigest()
    remote = remote_script(cfg, local.name)
    command = (
        "set -eu; "
        f"actual=$(sha256sum {shlex.quote(remote)} | cut -d' ' -f1); "
        f'test "$actual" = {shlex.quote(expected)}; '
        + " ".join(
            shlex.quote(item) for item in ["python3", remote, action, *canary_ids]
        )
    )
    ssh(cfg, command)


def cmd_integration_canaries(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    run_integration_canaries(cfg, args.action, args.canary_ids)


def run_provision(cfg: dict[str, Any], action: str) -> None:
    sync(cfg)
    commands: list[str] = []
    contract = data_content_contract()
    plane = resolved_data_content(cfg)

    def command_text(command: list[str]) -> str:
        return " ".join(shlex.quote(item) for item in command)

    def provider_step(command: list[str], *, expect_idempotent: bool) -> str:
        if Path(command[1]).name != "server-notion.py":
            return command_text(command)
        producer = command_text([*command, "--json"])
        consumer = [
            "python3",
            remote_script(cfg, "server-config.py"),
            "merge-notion-provision",
        ]
        if expect_idempotent:
            consumer.append("--expect-idempotent")
        # The provisioned IDs cross processes only over stdin.  The merger
        # emits key names and hashes, never the UUID values.
        return producer + " | " + command_text(consumer)

    if action == "provision":
        provider_commands = [
            ["python3", remote_script(cfg, script), provider_action]
            for script, provider_action in contract.adapter_commands(plane, "provision")
        ]
        commands.extend(
            provider_step(command, expect_idempotent=False)
            for command in provider_commands
        )
        commands.extend(
            (
                command_text(
                    ["python3", remote_script(cfg, "server-config.py"), "render"]
                ),
                command_text(
                    ["python3", remote_script(cfg, "server-config.py"), "audit"]
                ),
            )
        )
        commands.extend(
            provider_step(command, expect_idempotent=True)
            for command in provider_commands
        )
        commands.extend(
            [
                command_text(
                    ["python3", remote_script(cfg, "server-provision.py"), action]
                ),
            ]
        )
    else:
        if action == "verify":
            commands.extend(
                command_text(["python3", remote_script(cfg, script), provider_action])
                for script, provider_action in contract.adapter_commands(
                    plane, "verify"
                )
            )
        commands.extend(
            [
                command_text(
                    ["python3", remote_script(cfg, "server-provision.py"), action]
                ),
            ]
        )
    ssh(cfg, "set -eu; " + "; ".join(commands))


def run_application_databases(cfg: dict[str, Any]) -> None:
    """Create the selected provider bundle's isolated databases before startup."""
    sync(cfg)
    contract = data_content_contract()
    commands = [
        ["python3", remote_script(cfg, script), action]
        for script, action in contract.adapter_commands(
            resolved_data_content(cfg), "database"
        )
    ]
    ssh(
        cfg,
        "set -eu; "
        + "; ".join(
            " ".join(shlex.quote(item) for item in command) for command in commands
        ),
    )


def cmd_provision(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    action = "provision" if args.action == "apply" else args.action
    run_provision(cfg, action)
    run_data_content_projections(cfg, action)


def run_data_content_projections(cfg: dict[str, Any], action: str) -> None:
    """Run connector-specific projection consumers selected by the profile."""

    sync(cfg)
    contract = data_content_contract()
    commands = [
        ["python3", remote_script(cfg, script), projection_action]
        for script, projection_action in contract.projection_consumer_commands(
            resolved_data_content(cfg), action
        )
    ]
    # Provisioning is a deploy reconciliation gate, not merely an installer.
    # Run the consumer's own verification immediately after convergence so a
    # successful deployment step always leaves fresh evidence bound to both
    # the canonical environment and the synchronized producer source.  The
    # final platform verification still repeats this check after all later
    # deployment steps.
    if action == "provision":
        commands.extend(
            ["python3", remote_script(cfg, script), projection_action]
            for script, projection_action in contract.projection_consumer_commands(
                resolved_data_content(cfg), "verify"
            )
        )
    if not commands:
        return
    ssh(
        cfg,
        "set -eu; "
        + "; ".join(
            " ".join(shlex.quote(item) for item in command) for command in commands
        ),
    )


def run_notion_projection(cfg: dict[str, Any], action: str) -> None:
    if action not in {"provision", "drain", "status", "verify", "canary"}:
        raise PlatformError("unsupported Notion projection action")
    sync(cfg)
    command = [
        "python3",
        remote_script(cfg, "server-notion-sync.py"),
        action,
    ]
    if action == "canary":
        run_canonical_hash_bound(cfg, command)
    else:
        ssh(cfg, " ".join(shlex.quote(item) for item in command))


def cmd_notion_projection(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    action = "provision" if args.action == "apply" else args.action
    run_notion_projection(cfg, action)


def run_tools(cfg: dict[str, Any], action: str) -> None:
    sync(cfg)
    commands = [
        ["python3", remote_script(cfg, "server-toolhive.py"), action],
    ]
    if action == "provision":
        commands.extend(
            [
                [
                    "python3",
                    remote_script(cfg, "server-profile-reconcile.py"),
                    "provision",
                ],
                [
                    "python3",
                    remote_script(cfg, "server-profile-reconcile.py"),
                    "provision",
                ],
            ]
        )
    elif action in {"status", "verify"}:
        commands.append(
            [
                "python3",
                remote_script(cfg, "server-profile-reconcile.py"),
                action,
            ]
        )
    ssh(
        cfg,
        "set -eu; "
        + "; ".join(
            " ".join(shlex.quote(item) for item in command) for command in commands
        ),
    )


def cmd_tools(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    run_tools(cfg, args.action)


def run_harness_auth(cfg: dict[str, Any], action: str) -> None:
    # Codex, Claude Code and Pi never receive native subscription credentials.
    # Provisioning verifies a distinct 9Router runtime key for every profile.
    run_provision(cfg, action)


def cmd_harness_auth(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    run_harness_auth(cfg, args.action)


def merge_hermes_inputs(cfg: dict[str, Any]) -> None:
    required = ("HERMES_LLM_API_KEY", "HERMES_LLM_MODEL", "HERMES_LLM_BASE_URL")
    code = """
import json
from pathlib import Path
import sys

root = Path('/root/.config/mte-secrets')
platform = root / 'platform.env'
if not platform.is_file() or platform.stat().st_uid != 0 or platform.stat().st_mode & 0o777 != 0o600:
    raise SystemExit('canonical platform.env is missing or has unsafe permissions')
values = dict(
    line.split('=', 1)
    for line in platform.read_text().splitlines()
    if line and not line.startswith('#') and '=' in line
)
required = set(json.load(sys.stdin))
missing = sorted(key for key in required if not values.get(key))
if missing:
    print(json.dumps({'ok': False, 'missingCanonicalRefs': missing}))
    raise SystemExit(1)
print(json.dumps({'ok': True, 'canonicalRefsChecked': len(required)}))
"""
    ssh(
        cfg,
        "umask 077; python3 -c " + shlex.quote(code),
        input_text=json.dumps(required),
    )


def run_hermes(
    cfg: dict[str, Any],
    action: str,
    *,
    purge_data: bool = False,
    grant_platform_admin: bool = False,
) -> None:
    sync(cfg)
    if action in {"preflight", "install", "health"}:
        merge_hermes_inputs(cfg)
    command = ["python3", remote_script(cfg, "server-hermes.py"), action]
    if action == "install" and grant_platform_admin:
        command.append("--grant-platform-admin")
    if action == "remove" and purge_data:
        command.append("--purge-data")
    ssh(cfg, " ".join(shlex.quote(item) for item in command))


def cmd_hermes(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    if args.grant_platform_admin and args.action != "install":
        raise SystemExit("--grant-platform-admin is valid only with hermes install")
    if args.action == "acceptance":
        run_hermes_acceptance(cfg)
        return
    run_hermes(
        cfg,
        args.action,
        purge_data=args.purge_data,
        grant_platform_admin=args.grant_platform_admin,
    )


def render_cloudflare_remote(cfg: dict[str, Any], output: str) -> None:
    secret_root = str(host_spec(cfg)["secretsRoot"])
    command = [
        "python3",
        remote_script(cfg, "render-cloudflare.py"),
        "--config",
        f"{remote_root(cfg)}/config/platform.json",
        "--env-file",
        f"{secret_root}/platform.env",
        "--apps-projection",
        f"{secret_root}/cloudflare/apps.json",
        "--data-content-projection",
        f"{remote_root(cfg)}/config/data-content-plane.json",
        "--output",
        output,
    ]
    ssh(cfg, " ".join(shlex.quote(item) for item in command))


def render_cloudflare(cfg: dict[str, Any]) -> str:
    sync(cfg)
    secret_root = str(host_spec(cfg)["secretsRoot"])
    output = f"{secret_root}/cloudflare/iac/terraform.tfvars.json"
    ssh(cfg, f"umask 077; mkdir -p {shlex.quote(str(Path(output).parent))}")
    render_cloudflare_remote(cfg, output)
    return output


def cloudflare_preflight(cfg: dict[str, Any], *, require_ready: bool) -> bool:
    evidence = local_evidence_root() / "cloudflare-preflight.json"
    sync(cfg)
    remote_evidence = f"{remote_root(cfg)}/evidence/cloudflare-preflight.json"
    secret_root = str(host_spec(cfg)["secretsRoot"])
    command = [
        "python3",
        remote_script(cfg, "cloudflare-preflight.py"),
        "--config",
        f"{remote_root(cfg)}/config/platform.json",
        "--env-file",
        f"{secret_root}/platform.env",
        "--output",
        remote_evidence,
        "--origins-local",
    ]
    result = ssh(
        cfg,
        " ".join(shlex.quote(item) for item in command),
        check=False,
        capture_output=True,
    )
    if result.stdout:
        print(result.stdout, end="")
    run(
        remote_rsync_command(
            "-az",
            f"{host_spec(cfg)['ssh']}:{remote_evidence}",
            str(evidence),
        ),
        check=False,
    )
    if evidence.is_file():
        evidence.chmod(0o600)
    if result.returncode == 0:
        return True
    if require_ready:
        raise PlatformError(
            "Cloudflare preflight blocked plan/apply; inspect " + str(evidence)
        )
    return False


def prepare_cloudflare_remote(cfg: dict[str, Any]) -> tuple[str, str, str]:
    sync(cfg)
    secret_root = str(host_spec(cfg)["secretsRoot"])
    cloudflare_root = f"{secret_root}/cloudflare"
    iac_root = f"{cloudflare_root}/iac"
    api_env = f"{cloudflare_root}/api.env"
    ssh(
        cfg,
        "umask 077; "
        + "mkdir -p "
        + " ".join(shlex.quote(path) for path in [cloudflare_root, iac_root])
        + "; chmod 0700 "
        + " ".join(shlex.quote(path) for path in [cloudflare_root, iac_root]),
    )
    source_root = f"{remote_root(cfg)}/manifests/cloudflare"
    ssh(
        cfg,
        "set -eu; umask 077; "
        + " ".join(
            f"install -m 0600 {shlex.quote(source_root + '/' + name)} {shlex.quote(iac_root + '/' + name)};"
            for name in ("main.tf", "variables.tf", "outputs.tf")
        ),
    )
    render_cloudflare_remote(cfg, f"{iac_root}/terraform.tfvars.json")
    ssh(
        cfg,
        "set -eu; umask 077; "
        + f"test -s {shlex.quote(api_env)}; "
        + f"test -s {shlex.quote(iac_root + '/terraform.tfvars.json')}; "
        + f"chmod 0600 {shlex.quote(api_env)} {shlex.quote(iac_root + '/terraform.tfvars.json')}",
    )
    return cloudflare_root, iac_root, api_env


def tofu_command(iac_root: str, api_env: str, *arguments: str) -> str:
    command = [
        "docker",
        "run",
        "--rm",
        "--env-file",
        api_env,
        "-e",
        "TF_IN_AUTOMATION=1",
        "-v",
        f"{iac_root}:/workspace",
        "-w",
        "/workspace",
        locked_image("openTofu"),
        *arguments,
    ]
    return " ".join(shlex.quote(item) for item in command)


def cloudflare_dns_command(
    cfg: dict[str, Any], iac_root: str, api_env: str, action: str
) -> str:
    if action not in {"apply", "verify"}:
        raise PlatformError(f"unsupported Cloudflare DNS action: {action}")
    secret_root = str(host_spec(cfg)["secretsRoot"])
    tunnel_id = tofu_command(iac_root, api_env, "output", "-raw", "tunnel_id")
    arguments = [
        "python3",
        remote_script(cfg, "server-cloudflare-dns.py"),
        action,
        "--env-file",
        f"{secret_root}/platform.env",
        "--tfvars",
        f"{iac_root}/terraform.tfvars.json",
        "--tunnel-id",
        '"$tunnel_id"',
        "--output",
        f"{remote_root(cfg)}/evidence/cloudflare-dns-reconcile.json",
    ]
    reconcile = " ".join(
        item if item == '"$tunnel_id"' else shlex.quote(item) for item in arguments
    )
    return f'tunnel_id=$({tunnel_id}); test -n "$tunnel_id"; {reconcile}'


def cloudflare_access_command(
    cfg: dict[str, Any], iac_root: str, api_env: str, action: str
) -> str:
    if action not in {"apply", "verify"}:
        raise PlatformError(f"unsupported Cloudflare Access action: {action}")
    secret_root = str(host_spec(cfg)["secretsRoot"])
    human_policy_id_json = tofu_command(
        iac_root, api_env, "output", "-json", "human_access_policy_id"
    )
    service_policy_ids_json = tofu_command(
        iac_root, api_env, "output", "-json", "service_access_policy_ids"
    )
    arguments = [
        "python3",
        remote_script(cfg, "server-cloudflare-access.py"),
        action,
        "--env-file",
        f"{secret_root}/platform.env",
        "--tfvars",
        f"{iac_root}/terraform.tfvars.json",
        "--human-policy-id-json",
        '"$human_policy_id_json"',
        "--service-policy-ids-json",
        '"$service_policy_ids_json"',
        "--output",
        f"{remote_root(cfg)}/evidence/cloudflare-access-reconcile.json",
    ]
    reconcile = " ".join(
        item
        if item in {'"$human_policy_id_json"', '"$service_policy_ids_json"'}
        else shlex.quote(item)
        for item in arguments
    )
    return (
        f"human_policy_id_json=$({human_policy_id_json}); "
        'test -n "$human_policy_id_json"; '
        f"service_policy_ids_json=$({service_policy_ids_json}); "
        'test -n "$service_policy_ids_json"; ' + reconcile
    )


def cloudflare_access_policy_bootstrap_command(iac_root: str, api_env: str) -> str:
    """Create current Access policies before an app can lose its legacy policy.

    The initial per-route migration may have an existing shared policy in
    OpenTofu state that is still attached to remote Access applications.  A
    full apply would otherwise attempt that deletion before the REST
    application reconciler can bind the current named policies.  Target only
    the replacement policy/token graph, reconcile applications, then perform
    a fresh full plan and apply.  Re-running this is a no-op after the first
    successful migration.
    """
    targets = (
        "-target=cloudflare_zero_trust_access_policy.human",
        "-target=cloudflare_zero_trust_access_service_token.service",
        "-target=cloudflare_zero_trust_access_policy.service",
    )
    return tofu_command(
        iac_root,
        api_env,
        "apply",
        "-input=false",
        "-no-color",
        "-auto-approve",
        *targets,
    )


def cloudflare_edge_command(
    cfg: dict[str, Any], iac_root: str, api_env: str, action: str
) -> str:
    """Apply or verify Access before publishing the matching DNS records."""

    return "; ".join(
        [
            cloudflare_access_command(cfg, iac_root, api_env, action),
            cloudflare_dns_command(cfg, iac_root, api_env, action),
        ]
    )


def run_cloudflare(cfg: dict[str, Any], action: str) -> None:
    if action == "origin-firewall":
        run_origin_firewall(cfg)
        return
    if action == "acceptance":
        sync(cfg)
        local = TOOL_ROOT / "server-cloudflare-acceptance.py"
        remote = remote_script(cfg, local.name)
        expected = hashlib.sha256(local.read_bytes()).hexdigest()
        target_host = host_spec(cfg)["ssh"].rsplit("@", 1)[-1]
        remote_observation = (
            f"{remote_root(cfg)}/evidence/cloudflare-external-observation.json"
        )
        with tempfile.TemporaryDirectory(
            prefix="mte-cloudflare-observer-"
        ) as directory:
            local_observation = Path(directory) / "observation.json"
            run(
                [
                    sys.executable,
                    str(local),
                    "observe",
                    "--host",
                    target_host,
                    "--output",
                    str(local_observation),
                ]
            )
            local_observation.chmod(0o600)
            scp(cfg, local_observation, remote_observation)
        verified = (
            "set -eu; umask 077; "
            f"test $(sha256sum {shlex.quote(remote)} | cut -d' ' -f1) = {shlex.quote(expected)}; "
            f"chown root:root {shlex.quote(remote_observation)}; "
            f"chmod 0600 {shlex.quote(remote_observation)}; "
            + " ".join(
                shlex.quote(item)
                for item in [
                    "python3",
                    remote,
                    "run",
                    "--external-observation",
                    remote_observation,
                ]
            )
        )
        ssh(cfg, verified)
        return
    if action in {"token-plan", "token-status", "token-apply"}:
        if action == "token-apply":
            # The bootstrap imports the synchronized server-config producer and
            # performs canonical write + render + audit + manifest verification
            # while holding the shared canonical lock.
            sync(cfg, render_projections=False)
        run(
            [
                sys.executable,
                str(TOOL_ROOT / "cloudflare-token-bootstrap.py"),
                action.removeprefix("token-"),
                "--env-file",
                str(operator_env_path(required=True)),
                "--output",
                str(local_evidence_root() / "cloudflare-token-plan.json"),
            ]
        )
        return
    if action == "preflight":
        cloudflare_preflight(cfg, require_ready=True)
        return
    if action == "render":
        path = render_cloudflare(cfg)
        print(json.dumps({"cloudflare": "rendered", "tfvars": path}, indent=2))
        return
    if action in {"status", "verify"}:
        sync(cfg)
        step = remote_step(cfg, "cloudflare-tunnel.sh")
        ssh(cfg, f"{shlex.quote(step)} {shlex.quote(action)}")
        if action == "status":
            return
        secret_root = str(host_spec(cfg)["secretsRoot"])
        cloudflare_root = f"{secret_root}/cloudflare"
        iac_root = f"{cloudflare_root}/iac"
        api_env = f"{cloudflare_root}/api.env"
        plan = tofu_command(
            iac_root,
            api_env,
            "plan",
            "-input=false",
            "-no-color",
            "-detailed-exitcode",
        )
        edge_verify = cloudflare_edge_command(cfg, iac_root, api_env, "verify")
        ssh(cfg, f"set -eu; test -s {shlex.quote(api_env)}; {plan}; {edge_verify}")
        return

    cloudflare_preflight(cfg, require_ready=True)
    cloudflare_root, iac_root, api_env = prepare_cloudflare_remote(cfg)
    init = tofu_command(iac_root, api_env, "init", "-input=false", "-no-color")
    ssh(
        cfg,
        f"set -eu; umask 077; {init}; chmod -R go-rwx {shlex.quote(iac_root)}",
    )
    if action == "plan":
        plan = tofu_command(
            iac_root,
            api_env,
            "plan",
            "-input=false",
            "-no-color",
            "-out=/workspace/platform.tfplan",
        )
        ssh(cfg, f"set -eu; umask 077; {plan}; chmod -R go-rwx {shlex.quote(iac_root)}")
        return
    if action != "apply":
        raise PlatformError(f"unsupported Cloudflare action: {action}")

    access_bootstrap = cloudflare_access_policy_bootstrap_command(iac_root, api_env)
    access_reconcile = cloudflare_access_command(cfg, iac_root, api_env, "apply")
    ssh(cfg, f"set -eu; umask 077; {access_bootstrap}; {access_reconcile}")

    plan = tofu_command(
        iac_root,
        api_env,
        "plan",
        "-input=false",
        "-no-color",
        "-out=/workspace/platform.tfplan",
    )
    ssh(cfg, f"set -eu; umask 077; {plan}; chmod -R go-rwx {shlex.quote(iac_root)}")

    apply = tofu_command(
        iac_root,
        api_env,
        "apply",
        "-input=false",
        "-no-color",
        "-auto-approve",
        "/workspace/platform.tfplan",
    )
    tunnel_output = tofu_command(iac_root, api_env, "output", "-raw", "tunnel_token")
    service_output = tofu_command(
        iac_root, api_env, "output", "-json", "service_tokens"
    )
    edge_apply = cloudflare_edge_command(cfg, iac_root, api_env, "apply")
    ssh(
        cfg,
        "set -eu; umask 077; "
        + f"{apply}; "
        + f"{edge_apply}; "
        + f"token_tmp=$(mktemp {shlex.quote(cloudflare_root + '/.tunnel-token.XXXXXX')}); "
        + f"service_tmp=$(mktemp {shlex.quote(cloudflare_root + '/.service-token.XXXXXX')}); "
        + 'trap \'rm -f "$token_tmp" "$service_tmp"\' EXIT; '
        + f'{tunnel_output} >"$token_tmp"; test -s "$token_tmp"; '
        + f'{service_output} >"$service_tmp"; test -s "$service_tmp"; '
        + f"python3 {shlex.quote(remote_script(cfg, 'server-cloudflare-runtime.py'))} upsert "
        + '--tunnel-file "$token_tmp" --service-file "$service_tmp" '
        + f"--tfvars {shlex.quote(iac_root + '/terraform.tfvars.json')}; "
        + f"python3 {shlex.quote(remote_script(cfg, 'server-config.py'))} render; "
        + f"python3 {shlex.quote(remote_script(cfg, 'server-config.py'))} audit; "
        + f"python3 {shlex.quote(remote_script(cfg, 'server-cloudflare-runtime.py'))} status "
        + f"--tfvars {shlex.quote(iac_root + '/terraform.tfvars.json')}; "
        + f"{shlex.quote(remote_step(cfg, 'cloudflare-tunnel.sh'))} install",
    )


ORIGIN_FIREWALL_EVIDENCE_FIELDS = {
    "firewallPolicyVersion",
    "firewallServiceActive",
    "firewallServiceEnabled",
    "firewallRecoveryTimerActive",
    "firewallRecoveryTimerEnabled",
    "publicInterface",
    "publicInterfaceV4",
    "publicInterfaceV6",
    "operatorSshCidrsSha256",
    "firewallSshCidrCount",
    "firewallSshIpv4CidrCount",
    "firewallSshIpv6CidrCount",
    "firewallSshCidrsEnforced",
    "firewallV4Established",
    "firewallV6Established",
    "firewallV4InputTcpDrop",
    "firewallV4InputUdpDrop",
    "firewallV4DockerTcpDrop",
    "firewallV4DockerUdpDrop",
    "firewallV6InputTcpDrop",
    "firewallV6InputUdpDrop",
    "firewallV6DockerTcpDrop",
    "firewallV6DockerUdpDrop",
    "firewallV4Input",
    "firewallV4Docker",
    "firewallV6Input",
    "firewallV6Docker",
    "udp443Blocked",
    "publicTcpDefaultDenied",
    "publicUdpDefaultDenied",
}


def validate_origin_firewall_evidence(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != ORIGIN_FIREWALL_EVIDENCE_FIELDS:
        raise PlatformError("origin firewall returned an unexpected evidence schema")
    if payload["firewallPolicyVersion"] != "mte-origin-firewall/v2":
        raise PlatformError("origin firewall policy version is not current")
    required_true = {
        field
        for field in ORIGIN_FIREWALL_EVIDENCE_FIELDS
        if field.startswith("firewallV")
        or field
        in {
            "firewallServiceActive",
            "firewallServiceEnabled",
            "firewallRecoveryTimerActive",
            "firewallRecoveryTimerEnabled",
            "firewallSshCidrsEnforced",
            "udp443Blocked",
            "publicTcpDefaultDenied",
            "publicUdpDefaultDenied",
        }
    }
    if any(payload[field] is not True for field in required_true):
        raise PlatformError("origin firewall evidence does not prove default deny")
    fingerprint = payload["operatorSshCidrsSha256"]
    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(character not in "0123456789abcdef" for character in fingerprint)
    ):
        raise PlatformError("origin firewall evidence has an invalid CIDR fingerprint")
    counts = (
        payload["firewallSshCidrCount"],
        payload["firewallSshIpv4CidrCount"],
        payload["firewallSshIpv6CidrCount"],
    )
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in counts
    ):
        raise PlatformError("origin firewall evidence has invalid CIDR counts")
    if counts[0] < 1 or counts[0] != counts[1] + counts[2]:
        raise PlatformError("origin firewall evidence has inconsistent CIDR counts")
    return payload


def run_origin_firewall(cfg: dict[str, Any]) -> None:
    """Install the origin default-deny policy and retain its redacted status."""

    sync(cfg)
    step = remote_step(cfg, "origin-firewall.sh")
    remote_evidence = f"{remote_root(cfg)}/evidence/cloudflare-origin-firewall.json"
    ssh(
        cfg,
        "set -eu; umask 077; "
        + f"mkdir -p {shlex.quote(remote_root(cfg) + '/evidence')}; "
        + f"tmp=$(mktemp {shlex.quote(remote_root(cfg) + '/evidence/.origin-firewall.XXXXXX')}); "
        + "trap 'rm -f \"$tmp\"' EXIT; "
        + f"{shlex.quote(step)} apply >/dev/null; "
        + f'{shlex.quote(step)} status >"$tmp"; '
        + 'chmod 0600 "$tmp"; '
        + f'mv -f "$tmp" {shlex.quote(remote_evidence)}; '
        + "trap - EXIT",
    )
    local_evidence = local_evidence_root() / "cloudflare-origin-firewall.json"
    local_evidence.parent.mkdir(parents=True, exist_ok=True)
    run(
        remote_rsync_command(
            "-az",
            f"{host_spec(cfg)['ssh']}:{remote_evidence}",
            str(local_evidence),
        )
    )
    try:
        payload = json.loads(local_evidence.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise PlatformError("origin firewall evidence is not valid JSON") from exc
    validate_origin_firewall_evidence(payload)
    local_evidence.chmod(0o600)


def cmd_cloudflare(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    run_cloudflare(cfg, args.action)


def render_profiles() -> None:
    run(
        [
            sys.executable,
            str(TOOL_ROOT / "render-profiles.py"),
            "--catalog",
            str(PROFILES_ROOT / "catalog.yaml"),
            "--output",
            str(local_evidence_root() / "profiles"),
        ]
    )


def apply_profiles(cfg: dict[str, Any]) -> None:
    render_profiles()
    sync(cfg)
    bootstrap = f"{remote_root(cfg)}/evidence/paperclip-bootstrap.json"
    config_script = remote_script(cfg, "server-config.py")
    remote = (
        f"python3 {shlex.quote(config_script)} render >/dev/null && "
        f"python3 {shlex.quote(config_script)} audit >/dev/null && "
        f"python3 {shlex.quote(remote_root(cfg) + '/runtime/paperclip/scripts/bootstrap-paperclip.py')} "
        "--mode native --workspace-root /home/daytona/paperclip-workspace "
        "--instructions-root /prototype/profiles "
        f"--output {shlex.quote(bootstrap)} && "
        f"docker cp {shlex.quote(bootstrap)} mte-paperclip:/data/bootstrap.json"
    )
    ssh(cfg, remote)


def cmd_profiles(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    if args.action == "render":
        render_profiles()
        return
    apply_profiles(cfg)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="platform")
    result.add_argument("--domain", help="base domain, for example agents.example.com")
    result.add_argument(
        "--operator-env",
        metavar="PATH",
        help="private operator input dotenv (or set MTE_OPERATOR_ENV)",
    )
    subs = result.add_subparsers(dest="command", required=True)

    plan = subs.add_parser("plan")
    plan.add_argument("components", nargs="*")
    plan.set_defaults(func=cmd_plan)

    preflight = subs.add_parser("preflight")
    preflight.set_defaults(func=cmd_preflight)

    synchronize = subs.add_parser("sync")
    synchronize.set_defaults(func=cmd_sync)

    bootstrap = subs.add_parser("bootstrap")
    bootstrap.set_defaults(func=cmd_bootstrap)

    secrets = subs.add_parser("secrets")
    secrets.add_argument("action", choices=["init", "audit"])
    secrets.set_defaults(func=cmd_secrets)

    platform_config = subs.add_parser("config")
    platform_config.add_argument(
        "action", choices=["schema", "check", "init", "render", "audit", "diff"]
    )
    platform_config.set_defaults(func=cmd_config)

    verify = subs.add_parser("verify")
    verify.add_argument("components", nargs="*")
    verify.add_argument(
        "--all", action="store_true", help="run the complete platform acceptance"
    )
    verify.set_defaults(func=cmd_verify)

    status = subs.add_parser("status")
    status.set_defaults(func=cmd_status)

    acceptance = subs.add_parser("acceptance")
    acceptance.add_argument("action", choices=["export", "check"])
    acceptance.set_defaults(func=cmd_acceptance)

    profiles = subs.add_parser("profiles")
    profiles.add_argument("action", choices=["render", "apply"])
    profiles.set_defaults(func=cmd_profiles)

    runtime = subs.add_parser("runtime")
    runtime_subs = runtime.add_subparsers(dest="runtime", required=True)
    paperclip = runtime_subs.add_parser("paperclip")
    paperclip.add_argument(
        "action",
        choices=[
            "preflight",
            "config-migrate",
            "install",
            "status",
            "verify",
            "remove",
        ],
    )
    paperclip.set_defaults(func=cmd_runtime)

    for command_name, feature in (
        ("paperclip-environments", "environments"),
        ("paperclip-secrets", "secrets"),
        ("daytona", "daytona"),
    ):
        experimental = subs.add_parser(command_name)
        experimental.add_argument("action", choices=["apply", "status", "verify"])
        experimental.set_defaults(func=cmd_paperclip_experimental, feature=feature)

    kestra_canary = subs.add_parser("kestra-canary")
    kestra_canary.add_argument("action", choices=["apply", "status", "verify"])
    kestra_canary.set_defaults(func=cmd_kestra_canary)

    kestra_control = subs.add_parser("kestra-control")
    kestra_control.add_argument("action", choices=["provision", "status", "verify"])
    kestra_control.set_defaults(func=cmd_kestra_control)

    profile_acceptance = subs.add_parser("profile-acceptance")
    profile_acceptance.add_argument("action", choices=["verify"])
    profile_acceptance.set_defaults(func=cmd_profile_acceptance)

    observability_acceptance = subs.add_parser("observability-acceptance")
    observability_acceptance.set_defaults(func=cmd_observability_acceptance)

    evidence_rebind = subs.add_parser("evidence-rebind")
    evidence_rebind.set_defaults(func=cmd_evidence_rebind)

    integration_canaries = subs.add_parser("integration-canaries")
    integration_canaries.add_argument("action", choices=["run", "status"])
    integration_canaries.add_argument("canary_ids", nargs="*")
    integration_canaries.set_defaults(func=cmd_integration_canaries)

    provision = subs.add_parser("provision")
    provision.add_argument("action", choices=["apply", "status", "verify"])
    provision.set_defaults(func=cmd_provision)

    notion_projection = subs.add_parser("notion-projection")
    notion_projection.add_argument(
        "action", choices=["apply", "drain", "status", "verify", "canary"]
    )
    notion_projection.set_defaults(func=cmd_notion_projection)

    tools = subs.add_parser("tools")
    tools.add_argument("action", choices=["install", "provision", "status", "verify"])
    tools.set_defaults(func=cmd_tools)

    harness_auth = subs.add_parser("harness-auth")
    harness_auth.add_argument("action", choices=["status", "verify"])
    harness_auth.set_defaults(func=cmd_harness_auth)

    hermes = subs.add_parser("hermes")
    hermes.add_argument(
        "action",
        choices=["preflight", "install", "status", "health", "acceptance", "remove"],
    )
    hermes.add_argument("--purge-data", action="store_true")
    hermes.add_argument(
        "--grant-platform-admin",
        action="store_true",
        help="explicitly enable unrestricted Hermes host repair during install",
    )
    hermes.set_defaults(func=cmd_hermes)

    cloudflare = subs.add_parser("cloudflare")
    cloudflare.add_argument(
        "action",
        choices=[
            "token-plan",
            "token-status",
            "token-apply",
            "preflight",
            "render",
            "plan",
            "apply",
            "origin-firewall",
            "status",
            "verify",
            "acceptance",
        ],
    )
    cloudflare.set_defaults(func=cmd_cloudflare)
    return result


def main() -> None:
    global OPERATOR_ENV_OVERRIDE
    args = parser().parse_args()
    try:
        if args.operator_env:
            OPERATOR_ENV_OVERRIDE = Path(args.operator_env)
        selected_operator_env = operator_env_path()
        activate_operator_environment(selected_operator_env)
        args.func(args)
    except (PlatformError, subprocess.CalledProcessError, OSError, KeyError) as exc:
        print(f"platform: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()

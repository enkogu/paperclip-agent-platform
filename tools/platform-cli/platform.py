#!/usr/bin/env python3
"""One entrypoint for the declarative MTE platform deployment."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any
import uuid

import yaml


TOOL_ROOT = Path(__file__).resolve().parent
ROOT = TOOL_ROOT.parents[1]
CONFIG_PATH = ROOT / "config/platform.yaml"
LOCK_PATH = ROOT / "config/platform.lock.yaml"
CONNECTIONS_PATH = ROOT / "config/connections.yaml"
SERVICES_ROOT = ROOT / "deployment/services"
COMPOSE_SEEDS_PATH = ROOT / "config/compose-seeds.lock.json"
PROFILES_ROOT = ROOT / "config/profiles"
KESTRA_WORKFLOWS_ROOT = ROOT / "workflows/kestra"
KESTRA_SERVICE_ROOT = SERVICES_ROOT / "kestra"
HERMES_SERVICE_ROOT = SERVICES_ROOT / "hermes"
SEARXNG_SERVICE_ROOT = SERVICES_ROOT / "searxng"
CLOUDFLARE_ROOT = ROOT / "deployment/cloudflare"
CANONICAL_ENV_EXAMPLE = ROOT / "config/platform.env.example"
OPERATOR_ENV_OVERRIDE: Path | None = None
FULL_DEPLOY_STEPS = (
    "config-initialize",
    "config-render",
    "config-audit",
    "bootstrap",
    "toolhive-binary",
    "dokploy-foundation",
    "application-databases",
    "dokploy-components",
    "paperclip-runtime-config",
    "paperclip-runtime",
    "profiles",
    "paperclip-environments",
    "paperclip-secrets",
    "provision",
    "provision-idempotency",
    "data-content-projections",
    "kestra-control",
    "tool-bundles",
    "tool-bundles-idempotency",
    # Hermes install may create its native API key in the canonical env. Keep
    # it before Daytona so the hash-bound runtime proof stays current for E2E.
    "hermes",
    "daytona",
    "harness-auth",
    "kestra-e2e-canary",
    "profile-acceptance",
    "integration-canaries",
    "hermes-acceptance",
    "host-dokploy-acceptance",
    "observability-reconcile-pass-1",
    "observability-reconcile-pass-2",
    "observability-idempotency",
    "observability-acceptance",
    "cloudflare-plan",
    "cloudflare-apply",
    "cloudflare-origin-firewall",
    "post-cloudflare-evidence-rebind",
    "cloudflare-acceptance",
    "connections",
    "verify",
)

PROMOTION_PATHS = (
    "bin",
    "templates",
    "manifests",
    "runtime/paperclip",
    "steps",
    "config/services",
    "config/connections.yaml",
)
ACTIVE_DEPLOY_TRANSACTION: "DeployTransaction | None" = None
DEFAULT_DATA_CONTENT_PROFILE = "postgres-notion"
NOCODOCS_LICENSED_PROFILE = "postgres-postgrest-nocodb-nocodocs"
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


class PlatformError(RuntimeError):
    pass


class PreMutationGateError(PlatformError):
    """A read-only deployment gate rejected the requested live mutation."""

    def __init__(self, code: str, result: dict[str, str]):
        super().__init__(code)
        self.code = code
        self.result = dict(result)


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

    raw = str(OPERATOR_ENV_OVERRIDE or os.environ.get("MTE_OPERATOR_ENV", "")).strip()
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
    """Fill missing process inputs from an explicit operator dotenv file."""

    if path is None:
        return
    for key, value in local_dotenv(path).items():
        os.environ.setdefault(key, value)


def server_config_contract():
    path = TOOL_ROOT / "server-config.py"
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
    required = set(contract.REQUIRED_OPERATOR_ENV_KEYS)
    missing = sorted(
        key for key in required if not str(normalized.get(key, "")).strip()
    )
    if missing:
        raise PlatformError(
            "operator env is missing required keys: " + ", ".join(missing)
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
        "fillOnly": True,
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
        "fillOnly": True,
        "generatedValues": "safe defaults, pinned runtime values, service secrets and provisioned IDs",
    }


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
    host = spec["host"]

    def resolve_ref(name: str) -> str:
        ref = str(host.get(name, ""))
        value = os.environ.get(ref) or seed_values.get(ref, "")
        if not value:
            raise PlatformError(f"bootstrap host ref {ref or name} is unresolved")
        return value

    host["ssh"] = resolve_ref("sshRef")
    host["root"] = resolve_ref("rootRef")
    host["secretsRoot"] = resolve_ref("secretsRootRef")
    excluded_refs = host.get("excludedRefs", [])
    host["excluded"] = [
        os.environ.get(str(ref)) or seed_values.get(str(ref), "")
        for ref in excluded_refs
    ]
    if any(not value for value in host["excluded"]):
        raise PlatformError("one or more bootstrap excluded-host refs are unresolved")
    domain_ref = str(spec.get("domainRef", "PLATFORM_BASE_DOMAIN"))
    resolved = domain or os.environ.get(domain_ref) or seed_values.get(domain_ref) or ""
    resolved = resolved.strip().rstrip(".")
    if resolved.startswith("http://") or resolved.startswith("https://"):
        raise PlatformError("domain must be a DNS name without scheme")
    spec["resolvedDomain"] = resolved
    values = dict(seed_values)
    values.update(os.environ)
    values[domain_ref] = resolved
    for url_key, subdomain_ref in (
        ("BASEROW_PUBLIC_URL", "BASEROW_SUBDOMAIN"),
        ("WIKIJS_SITE_URL", "WIKIJS_SUBDOMAIN"),
        ("POSTGREST_PUBLIC_URL", "POSTGREST_SUBDOMAIN"),
        ("NOCODB_PUBLIC_URL", "NOCODB_SUBDOMAIN"),
    ):
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
    remote_command = (
        f"export PYTHONDONTWRITEBYTECODE={shlex.quote('1')};\n{remote_command}"
    )
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


def pre_mutation_license_gate(cfg: dict[str, Any]) -> dict[str, str]:
    """Reject an explicitly selected unlicensed legacy NocoDocs deploy.

    Profiles without NocoDocs do not need a remote credential observer.  The
    legacy-profile observer emits exactly the selected profile and a presence bit;
    no credential value, hash, length, prefix, or exception text crosses SSH.
    A missing canonical source is valid for a clean install, but it cannot prove
    the Business license required by the NocoDocs profile.
    """

    selected_profile = str(resolved_data_content(cfg).get("profile") or "").strip()
    if not selected_profile:
        raise PlatformError("data_content_profile_unresolved")
    if selected_profile != NOCODOCS_LICENSED_PROFILE:
        return {"profile": selected_profile, "licenseKey": "not-required"}
    canonical = str(host_spec(cfg)["secretsRoot"]).rstrip("/") + "/platform.env"
    code = f"""set -u
umask 077
canonical={shlex.quote(canonical)}
expected={shlex.quote(selected_profile)}
target={shlex.quote(NOCODOCS_LICENSED_PROFILE)}
profile="$expected"
presence=missing
exit_code=0
normalize() {{
    awk '{{
        gsub(/^[[:space:]]+|[[:space:]]+$/, "")
        if (length($0) >= 2 && ((substr($0,1,1) == "\\\"" && substr($0,length($0),1) == "\\\"") || (substr($0,1,1) == "\\047" && substr($0,length($0),1) == "\\047"))) {{
            $0 = substr($0, 2, length($0) - 2)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "")
        }}
        print
    }}'
}}
if [ -e "$canonical" ]; then
    if [ -L "$canonical" ] || [ ! -f "$canonical" ] || [ "$(stat -c %u "$canonical" 2>/dev/null || printf invalid)" != "$(id -u)" ] || [ "$(stat -c %a "$canonical" 2>/dev/null || printf invalid)" != 600 ]; then
        exit_code=79
    else
        canonical_profile=$(awk 'index($0,"DATA_CONTENT_PROFILE=")==1 {{print substr($0,index($0,"=")+1); exit}}' "$canonical" | normalize)
        if [ -n "$canonical_profile" ]; then
            profile="$canonical_profile"
        fi
        license_value=$(awk 'index($0,"NOCODB_LICENSE_KEY=")==1 {{print substr($0,index($0,"=")+1); exit}}' "$canonical" | normalize)
        if [ -n "$license_value" ]; then
            presence=present
        fi
        unset license_value
    fi
fi
if ! printf '%s' "$profile" | grep -Eq '^[a-z0-9]+(-[a-z0-9]+)*$'; then
    profile="$expected"
    presence=missing
    exit_code=79
fi
if [ "$exit_code" -eq 0 ] && [ "$profile" != "$expected" ]; then
    exit_code=80
fi
if [ "$exit_code" -eq 0 ] && [ "$profile" = "$target" ] && [ "$presence" = missing ]; then
    exit_code=78
fi
printf '{{"licenseKey":"%s","profile":"%s"}}\n' "$presence" "$profile"
exit "$exit_code"
"""
    observed = ssh(
        cfg,
        "sh -c " + shlex.quote(code),
        check=False,
        capture_output=True,
    )
    try:
        result = json.loads(observed.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PlatformError("license_preflight_invalid_response") from exc
    if (
        not isinstance(result, dict)
        or set(result) != {"profile", "licenseKey"}
        or not isinstance(result["profile"], str)
        or result["licenseKey"] not in {"present", "missing"}
    ):
        raise PlatformError("license_preflight_invalid_response")
    safe_result = {
        "profile": str(result["profile"]),
        "licenseKey": str(result["licenseKey"]),
    }
    if observed.returncode == 78:
        raise PreMutationGateError("business_license_required", safe_result)
    if observed.returncode == 79:
        raise PreMutationGateError("canonical_secret_source_unsafe", safe_result)
    if observed.returncode == 80:
        raise PreMutationGateError("data_content_profile_mismatch", safe_result)
    if observed.returncode != 0:
        raise PlatformError("license_preflight_remote_failure")
    if safe_result["profile"] != selected_profile:
        raise PlatformError("license_preflight_profile_mismatch")
    if (
        selected_profile == NOCODOCS_LICENSED_PROFILE
        and safe_result["licenseKey"] != "present"
    ):
        raise PreMutationGateError("business_license_required", safe_result)
    return safe_result


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


def remove_legacy_patch_projection(cfg: dict[str, Any]) -> None:
    """Remove the pre-steps remote projection after a governed release exists."""

    root = remote_root(cfg)
    ssh(
        cfg,
        "set -eu; "
        + f"test -d {shlex.quote(root + '/steps')}; "
        + f"rm -rf {shlex.quote(root + '/patches')}",
    )


def deployment_transaction_contract():
    path = TOOL_ROOT / "server-deploy-transaction.py"
    spec = importlib.util.spec_from_file_location("mte_deploy_transaction", path)
    if spec is None or spec.loader is None:
        raise PlatformError("cannot load the governed release transaction helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synchronized_core_scripts(cfg: dict[str, Any]) -> list[str]:
    names = [
        "server-secrets.py",
        "server-dokploy.py",
        "server-deploy-transaction.py",
        "server-verify.py",
        "server-provision.py",
        "server-hermes.py",
        "server-toolhive.py",
        "server-paperclip-experimental.py",
        "server-observability-canary.py",
        "server-host-dokploy-acceptance.py",
        "server-integration-canaries.py",
        "server-notion-sync.py",
        "server-cloudflare-acceptance.py",
        "server-kestra-reconcile.py",
        "server-profile-reconcile.py",
        "server-activepieces-provision-verify.py",
        "agent-plane-gateway.py",
        "profile_catalog.py",
        "server-config.py",
        "render-cloudflare.py",
        "cloudflare-preflight.py",
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


def _copy_release_tree(
    source: Path, destination: Path, *, deploy: bool = False
) -> None:
    def ignored(_directory: str, names: list[str]) -> set[str]:
        result = {
            name
            for name in names
            if name == "__pycache__" or name.endswith((".pyc", ".orig"))
        }
        if deploy:
            result.add("compose-seeds.lock.json")
        return result

    if not source.is_dir():
        raise PlatformError(f"governed source directory is missing: {source}")
    shutil.copytree(source, destination, ignore=ignored)


def canonical_compose_sources() -> list[Path]:
    """Return one owner-scoped Compose manifest for every managed service."""
    return sorted(SERVICES_ROOT.glob("*/compose.yaml"))


def compose_projection_name(source: Path) -> str:
    """Keep the established flat remote name for an owner-scoped manifest."""
    if source.name != "compose.yaml" or source.parent.parent != SERVICES_ROOT:
        raise PlatformError(f"invalid canonical Compose source: {source}")
    return f"{source.parent.name}.yaml"


class ReleaseSnapshot:
    def __init__(self, cfg: dict[str, Any], run_id: str):
        self._temporary = tempfile.TemporaryDirectory(prefix="mte-release-")
        self.root = Path(self._temporary.name)
        self.source = self.root / "source"
        for path in (
            self.source / "bin",
            self.source / "templates/deploy",
            self.source / "templates/profiles",
            self.source / "manifests/kestra/flows",
            self.source / "manifests/hermes",
            self.source / "manifests/cloudflare",
            self.source / "runtime/paperclip/scripts",
            self.source / "runtime/paperclip/profiles/instructions",
            self.source / "steps",
            self.source / "config",
        ):
            path.mkdir(parents=True, exist_ok=True)

        for source, destination in (
            (KESTRA_WORKFLOWS_ROOT, self.source / "manifests/kestra/flows"),
            (PROFILES_ROOT, self.source / "templates/profiles"),
            (
                PROFILES_ROOT / "instructions",
                self.source / "runtime/paperclip/profiles/instructions",
            ),
            (CLOUDFLARE_ROOT, self.source / "manifests/cloudflare"),
            (ROOT / "deployment/steps", self.source / "steps"),
        ):
            destination.rmdir()
            _copy_release_tree(source, destination)
        deploy_destination = self.source / "templates/deploy"
        for source in canonical_compose_sources():
            shutil.copy2(source, deploy_destination / compose_projection_name(source))

        # Keep the established remote runtime contract while the local source
        # tree uses purpose-based names. Server consumers still read
        # manifests/kestra/application.yaml and templates/profiles/profiles.yaml.
        shutil.copy2(
            KESTRA_SERVICE_ROOT / "application.yaml",
            self.source / "manifests/kestra/application.yaml",
        )
        kestra_runtime_config = self.source / "config/services/kestra/application.yaml"
        kestra_runtime_config.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(KESTRA_SERVICE_ROOT / "application.yaml", kestra_runtime_config)
        searxng_runtime_config = self.source / "config/services/searxng/settings.yml"
        searxng_runtime_config.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SEARXNG_SERVICE_ROOT / "settings.yml", searxng_runtime_config)
        profile_catalog = self.source / "templates/profiles/catalog.yaml"
        profile_catalog.replace(self.source / "templates/profiles/profiles.yaml")

        hermes_destination = self.source / "manifests/hermes"
        shutil.copy2(
            HERMES_SERVICE_ROOT / "config.yaml.template",
            hermes_destination / "config.yaml.template",
        )
        shutil.copy2(
            HERMES_SERVICE_ROOT / "soul.txt",
            hermes_destination / "SOUL.md",
        )
        shutil.copy2(
            HERMES_SERVICE_ROOT / "service.unit",
            hermes_destination / "hermes.service",
        )
        for name in ("acceptance-canary.py", "bootstrap-mattermost.py"):
            shutil.copy2(HERMES_SERVICE_ROOT / name, hermes_destination / name)
        skill_destination = hermes_destination / "skills/mte-platform/SKILL.md"
        skill_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HERMES_SERVICE_ROOT / "platform-skill.txt", skill_destination)

        plane = optional_resolved_data_content(cfg)
        adapters = (
            sorted({str(row["script"]) for row in plane["adapters"].values()})
            if plane is not None
            else []
        )
        for name in [*synchronized_core_scripts(cfg), *adapters]:
            source = TOOL_ROOT / name
            if not source.is_file():
                raise PlatformError(f"governed server script is missing: {source}")
            shutil.copy2(source, self.source / "bin" / name)
        shutil.copy2(
            TOOL_ROOT / "bootstrap-paperclip.py",
            self.source / "runtime/paperclip/scripts/bootstrap-paperclip.py",
        )
        shutil.copy2(
            TOOL_ROOT / "profile_catalog.py",
            self.source / "runtime/paperclip/scripts/profile_catalog.py",
        )
        # This deterministic process agent exists only as a live-acceptance
        # fixture. It is synchronized beside Paperclip runtime scripts, but is
        # not a platform application or long-lived service.
        shutil.copy2(
            ROOT / "tests/fixtures/agents/integration_canary.py",
            self.source / "runtime/paperclip/scripts/integration_canary.py",
        )

        rendered = render_config(cfg)
        shutil.copy2(rendered, self.source / "templates/platform.json")
        for source, destination in (
            (
                COMPOSE_SEEDS_PATH,
                self.source / "templates/compose-seeds.lock.json",
            ),
            (
                LOCK_PATH,
                self.source / "templates/platform.lock.yaml",
            ),
            (
                CONNECTIONS_PATH,
                self.source / "config/connections.yaml",
            ),
        ):
            shutil.copy2(source, destination)

        for path in self.source.rglob("*"):
            if path.is_symlink():
                raise PlatformError(f"governed source contains a symlink: {path}")
            path.chmod(0o755 if path.is_dir() else 0o644)
        for path in (self.source / "bin").iterdir():
            if path.is_file():
                path.chmod(0o700)
        for path in (self.source / "steps").glob("*.sh"):
            path.chmod(0o700)

        contract = deployment_transaction_contract()
        try:
            self.manifest = contract.build_manifest(self.source, list(PROMOTION_PATHS))
        except contract.TransactionError as exc:
            raise PlatformError(str(exc)) from exc
        self.source_sha256 = str(self.manifest["sourceSha256"])
        self.release_id = f"{run_id}-{self.source_sha256[:16]}"
        self.manifest_path = self.root / "source-manifest.json"
        self.manifest_path.write_text(
            json.dumps(self.manifest, indent=2, sort_keys=True) + "\n"
        )
        self.manifest_path.chmod(0o600)

    def verify(self) -> None:
        contract = deployment_transaction_contract()
        try:
            proof = contract.verify_tree(self.source, self.manifest)
        except contract.TransactionError as exc:
            raise PlatformError("immutable local release snapshot drift") from exc
        if proof.get("sourceSha256") != self.source_sha256:
            raise PlatformError("immutable local release snapshot hash mismatch")

    def close(self) -> None:
        self._temporary.cleanup()


@contextmanager
def remote_deploy_lock(cfg: dict[str, Any]):
    root = remote_root(cfg)
    target = host_spec(cfg)["ssh"]
    command = (
        "set -eu; umask 077; "
        f"mkdir -p {shlex.quote(root + '/.deploy')}; "
        f"exec 9>{shlex.quote(root + '/.deploy/deploy.lock')}; "
        "if ! flock -n 9; then printf 'MTE_DEPLOY_BUSY\\n'; exit 73; fi; "
        "printf 'MTE_DEPLOY_LOCKED\\n'; IFS= read -r _"
    )
    process = subprocess.Popen(
        [
            *ssh_transport_command(),
            target,
            command,
        ],
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    ready = process.stdout.readline().strip()
    if ready != "MTE_DEPLOY_LOCKED":
        process.kill()
        process.wait()
        raise PlatformError("another full-platform deployment holds the remote lock")
    try:
        yield
    finally:
        if process.stdin is not None:
            try:
                process.stdin.write("release\n")
                process.stdin.flush()
                process.stdin.close()
            except BrokenPipeError:
                pass
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


class DeployTransaction:
    def __init__(
        self,
        cfg: dict[str, Any],
        snapshot: ReleaseSnapshot,
        run_id: str,
        *,
        attempt: int,
        release_id: str | None = None,
    ):
        self.cfg = cfg
        self.snapshot = snapshot
        self.run_id = run_id
        self.attempt = attempt
        self.release_id = release_id or snapshot.release_id
        if release_id and release_id != snapshot.release_id:
            raise PlatformError("resume release ID does not match frozen source")
        self.activation_id = f"{run_id}-a{attempt}"
        self.promoted = False
        self.helper = f"/tmp/mte-deploy-transaction-{self.activation_id}.py"

    def _helper_command(self, *arguments: str) -> str:
        local = self.snapshot.source / "bin/server-deploy-transaction.py"
        expected = hashlib.sha256(local.read_bytes()).hexdigest()
        command = [
            "python3",
            self.helper,
            "--root",
            remote_root(self.cfg),
            *arguments,
        ]
        return (
            "set -eu; "
            f"test $(sha256sum {shlex.quote(self.helper)} | cut -d' ' -f1) = {shlex.quote(expected)}; "
            + " ".join(shlex.quote(item) for item in command)
        )

    def _helper_json(self, *arguments: str) -> dict[str, Any]:
        observed = ssh(
            self.cfg,
            self._helper_command(*arguments),
            capture_output=True,
        )
        lines = [line.strip() for line in (observed.stdout or "").splitlines()]
        try:
            payload = json.loads(next(line for line in reversed(lines) if line))
        except (json.JSONDecodeError, StopIteration) as exc:
            raise PlatformError(
                "governed release helper returned invalid JSON"
            ) from exc
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            raise PlatformError("governed release helper rejected the operation")
        if payload.get("activationId") not in {None, self.activation_id}:
            raise PlatformError("governed release helper activation mismatch")
        return payload

    def inspect_activation(self) -> dict[str, Any]:
        payload = self._helper_json(
            "inspect-activation", "--activation-id", self.activation_id
        )
        if payload.get("activationId") != self.activation_id or not isinstance(
            payload.get("current"), bool
        ):
            raise PlatformError("invalid governed source activation inspection")
        if payload["current"] and (
            payload.get("releaseId") != self.release_id
            or payload.get("sourceSha256") != self.snapshot.source_sha256
        ):
            raise PlatformError("current governed source activation identity mismatch")
        return payload

    def promote(self) -> dict[str, Any]:
        promotion_error: Exception | None = None
        try:
            self._helper_json(
                "promote",
                "--release-id",
                self.release_id,
                "--run-id",
                self.run_id,
                "--activation-id",
                self.activation_id,
            )
        except Exception as exc:
            # SSH can lose the acknowledgement after the remote commit.  The
            # durable remote activation pointer, not the client exception, is
            # authoritative in that case.
            promotion_error = exc
        try:
            inspected = self.inspect_activation()
        except Exception:
            if promotion_error is not None:
                raise promotion_error
            raise
        if not inspected["current"]:
            if promotion_error is not None:
                raise promotion_error
            raise PlatformError("governed source promotion is not current")
        self.promoted = True
        self.verify()
        return inspected

    def install_helper(self) -> None:
        local = self.snapshot.source / "bin/server-deploy-transaction.py"
        scp(self.cfg, local, self.helper)
        expected = hashlib.sha256(local.read_bytes()).hexdigest()
        ssh(
            self.cfg,
            "set -eu; "
            f"chown root:root {shlex.quote(self.helper)}; "
            f"chmod 0700 {shlex.quote(self.helper)}; "
            f"test $(sha256sum {shlex.quote(self.helper)} | cut -d' ' -f1) = {shlex.quote(expected)}",
        )

    def ensure_synced(self) -> None:
        self.snapshot.verify()
        if self.promoted:
            self.verify()
            return
        self.install_helper()
        root = remote_root(self.cfg)
        upload = f"{root}/.deploy/uploads/{self.activation_id}"
        ssh(
            self.cfg,
            f"set -eu; umask 077; rm -rf {shlex.quote(upload)}; "
            f"mkdir -p {shlex.quote(upload + '/source')}",
        )
        run(
            remote_rsync_command(
                "-rtz",
                "--delete",
                str(self.snapshot.source) + "/",
                f"{host_spec(self.cfg)['ssh']}:{upload}/source/",
            )
        )
        scp(self.cfg, self.snapshot.manifest_path, upload + "/source-manifest.json")
        ssh(
            self.cfg,
            "set -eu; "
            f"chown -R root:root {shlex.quote(upload)}; "
            f"find {shlex.quote(upload + '/source')} -type d -exec chmod 0755 {{}} +; "
            f"find {shlex.quote(upload + '/source')} -type f -exec chmod 0644 {{}} +; "
            f"find {shlex.quote(upload + '/source/bin')} -type f -exec chmod 0700 {{}} +; "
            f"find {shlex.quote(upload + '/source/steps')} -type f -name '*.sh' -exec chmod 0700 {{}} +; "
            f"chmod 0600 {shlex.quote(upload + '/source-manifest.json')}",
        )
        ssh(
            self.cfg,
            self._helper_command(
                "seal",
                "--upload",
                upload,
                "--release-id",
                self.release_id,
            ),
        )
        self.promote()

    def verify(self) -> None:
        self.snapshot.verify()
        if not self.promoted:
            raise PlatformError("governed source release is not promoted")
        payload = self._helper_json(
            "verify-current",
            "--release-id",
            self.release_id,
            "--activation-id",
            self.activation_id,
        )
        if (
            payload.get("status") != "active"
            or payload.get("sourceSha256") != self.snapshot.source_sha256
        ):
            raise PlatformError("governed source verification identity mismatch")

    def checkpoint(
        self, status: str, *, completed_step: str = "", next_step: str = ""
    ) -> None:
        ssh(
            self.cfg,
            self._helper_command(
                "checkpoint",
                "--run-id",
                self.run_id,
                "--release-id",
                self.release_id,
                "--activation-id",
                self.activation_id,
                "--source-sha256",
                self.snapshot.source_sha256,
                "--status",
                status,
                "--step",
                completed_step,
                "--next-step",
                next_step,
                "--attempt",
                str(self.attempt),
            ),
        )

    def _validated_rollback(self, payload: dict[str, Any]) -> dict[str, Any]:
        action = payload.get("action")
        if payload.get("activationId") != self.activation_id:
            raise PlatformError("governed source rollback activation mismatch")
        if action in {"rolledBack", "alreadyRolledBack"}:
            if (
                payload.get("status") != "rolledBack"
                or payload.get("sourceSha256") != self.snapshot.source_sha256
            ):
                raise PlatformError("governed source rollback proof mismatch")
        elif action == "notCurrent":
            if payload.get("current") is not False:
                raise PlatformError("invalid non-current source rollback proof")
        else:
            raise PlatformError("invalid governed source rollback action")
        self.promoted = False
        return payload

    def _rollback_result_from_inspection(
        self, inspected: dict[str, Any]
    ) -> dict[str, Any] | None:
        if inspected["current"]:
            return None
        journal_status = inspected.get("journalStatus")
        if journal_status == "rolledBack":
            return self._validated_rollback(
                {
                    "action": "alreadyRolledBack",
                    "status": "rolledBack",
                    "activationId": self.activation_id,
                    "sourceSha256": inspected.get("sourceSha256"),
                }
            )
        if journal_status in {"promoting", "committing", "rollingBack"}:
            # The server must finish its write-ahead journal before the client
            # can authoritatively call the activation non-current.
            return None
        return self._validated_rollback({"action": "notCurrent", **inspected})

    def rollback(self) -> dict[str, Any]:
        last_error: Exception | None = None
        for _attempt in range(2):
            try:
                return self._validated_rollback(
                    self._helper_json(
                        "rollback-if-current",
                        "--activation-id",
                        self.activation_id,
                    )
                )
            except Exception as exc:
                last_error = exc
                try:
                    inspected = self.inspect_activation()
                except Exception:
                    continue
                observed = self._rollback_result_from_inspection(inspected)
                if observed is not None:
                    return observed
        try:
            inspected = self.inspect_activation()
            observed = self._rollback_result_from_inspection(inspected)
            if observed is not None:
                return observed
        except Exception:
            pass
        assert last_error is not None
        raise last_error

    def cleanup(self) -> None:
        ssh(self.cfg, f"rm -f {shlex.quote(self.helper)}", check=False)


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


def sync(cfg: dict[str, Any], *, render_projections: bool = True) -> None:
    if ACTIVE_DEPLOY_TRANSACTION is not None:
        ACTIVE_DEPLOY_TRANSACTION.ensure_synced()
        return
    ensure_safe_target(cfg)
    target = host_spec(cfg)["ssh"]
    remote_root = host_spec(cfg)["root"]
    staging_root = f"{remote_root}/.sync-staging"
    rendered = render_config(cfg)
    ssh(
        cfg,
        "set -eu; umask 077; rm -rf "
        + shlex.quote(staging_root)
        + "; mkdir -p "
        + " ".join(
            shlex.quote(path)
            for path in [
                f"{staging_root}/bin",
                f"{staging_root}/config",
                f"{staging_root}/config/services/kestra",
                f"{staging_root}/config/services/searxng",
                f"{staging_root}/templates/deploy",
                f"{staging_root}/templates/profiles",
                f"{staging_root}/manifests/kestra/flows",
                f"{staging_root}/manifests/hermes/skills/mte-platform",
                f"{staging_root}/manifests/cloudflare",
                f"{staging_root}/runtime/paperclip/scripts",
                f"{staging_root}/runtime/paperclip/profiles/instructions",
                f"{staging_root}/steps",
            ]
        ),
    )
    transfers = [
        (
            str(KESTRA_WORKFLOWS_ROOT) + "/",
            f"{target}:{staging_root}/manifests/kestra/flows/",
        ),
        (str(PROFILES_ROOT) + "/", f"{target}:{staging_root}/templates/profiles/"),
        (
            str(PROFILES_ROOT / "instructions") + "/",
            f"{target}:{staging_root}/runtime/paperclip/profiles/instructions/",
        ),
        (
            str(CLOUDFLARE_ROOT) + "/",
            f"{target}:{staging_root}/manifests/cloudflare/",
        ),
        (
            str(ROOT / "deployment/steps") + "/",
            f"{target}:{staging_root}/steps/",
        ),
    ]
    # Canonical Compose sources are grouped by owner, while the server keeps
    # the established flat templates/deploy/<service>.yaml projection.
    for source in canonical_compose_sources():
        run(
            remote_rsync_command(
                "-rtz",
                str(source),
                f"{target}:{staging_root}/templates/deploy/"
                f"{compose_projection_name(source)}",
            )
        )
    for source, destination in transfers:
        run(
            remote_rsync_command(
                "-rtz",
                "--delete",
                "--exclude=*.orig",
                "--exclude=__pycache__",
                "--exclude=*.pyc",
                source,
                destination,
            )
        )
    static_files = {
        "manifests/kestra/application.yaml": KESTRA_SERVICE_ROOT / "application.yaml",
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
        "manifests/hermes/skills/mte-platform/SKILL.md": HERMES_SERVICE_ROOT
        / "platform-skill.txt",
    }
    for destination, source in static_files.items():
        run(
            remote_rsync_command(
                "-rtz",
                str(source),
                f"{target}:{staging_root}/{destination}",
            )
        )
    core_scripts = synchronized_core_scripts(cfg)
    plane = optional_resolved_data_content(cfg)
    adapter_scripts = (
        sorted({str(row["script"]) for row in plane["adapters"].values()})
        if plane is not None
        else []
    )
    for name in [*core_scripts, *adapter_scripts]:
        run(
            remote_rsync_command(
                "-rtz",
            str(TOOL_ROOT / name),
                f"{target}:{staging_root}/bin/{name}",
            )
        )
    runtime_scripts = {
        "bootstrap-paperclip.py": TOOL_ROOT / "bootstrap-paperclip.py",
        "profile_catalog.py": TOOL_ROOT / "profile_catalog.py",
        "integration_canary.py": ROOT / "tests/fixtures/agents/integration_canary.py",
    }
    for name, source in runtime_scripts.items():
        run(
            remote_rsync_command(
                "-rtz",
                str(source),
                f"{target}:{staging_root}/runtime/paperclip/scripts/{name}",
            )
        )
    run(
        remote_rsync_command(
            "-rtz",
            str(rendered),
            f"{target}:{staging_root}/templates/platform.json",
        )
    )
    run(
        remote_rsync_command(
            "-rtz",
            str(COMPOSE_SEEDS_PATH),
            f"{target}:{staging_root}/templates/compose-seeds.lock.json",
        )
    )
    run(
        remote_rsync_command(
            "-rtz",
            str(LOCK_PATH),
            f"{target}:{staging_root}/templates/platform.lock.yaml",
        )
    )
    run(
        remote_rsync_command(
            "-rtz",
            str(CONNECTIONS_PATH),
            f"{target}:{staging_root}/config/connections.yaml",
        )
    )
    ssh(
        cfg,
        "set -eu; umask 077; stage="
        + shlex.quote(staging_root)
        + "; root="
        + shlex.quote(remote_root)
        + '; mv "$stage/templates/profiles/catalog.yaml" '
        + '"$stage/templates/profiles/profiles.yaml"; '
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
        + '! -path "$stage/steps/*.sh" ! -perm 0644 -print -quit)"; '
        + 'mkdir -p "$root/config" "$root/runtime"; '
        + "for rel in bin templates manifests runtime/paperclip steps config/services; do "
        + 'mkdir -p "$root/$rel"; '
        + 'test -z "$(find "$root/$rel" -type l -print -quit)"; '
        + 'find "$root/$rel" -type d -exec chown root:root {} + '
        + "-exec chmod 0755 {} +; "
        + 'rsync -rtp --delete --ignore-times "$stage/$rel/" "$root/$rel/"; '
        + "done; "
        + 'install -o root -g root -m 0644 "$stage/config/connections.yaml" '
        + '"$root/config/.connections.yaml.tmp"; '
        + 'mv -f "$root/config/.connections.yaml.tmp" "$root/config/connections.yaml"; '
        + 'set -- "$root/bin" "$root/templates" "$root/manifests" '
        + '"$root/runtime/paperclip" "$root/steps" "$root/config/services"; '
        + 'test -z "$(find "$@" -type l -print -quit)"; '
        + 'test -z "$(find "$@" \\( ! -user root -o ! -group root \\) -print -quit)"; '
        + 'test -z "$(find "$root/bin" -type f ! -perm 0700 -print -quit)"; '
        + 'test -z "$(find "$root/steps" -type f -name "*.sh" ! -perm 0700 -print -quit)"; '
        + 'test -z "$(find "$root/templates" "$root/manifests" '
        + '"$root/runtime/paperclip" "$root/config/services" '
        + '-type f ! -perm 0644 -print -quit)"; '
        + 'test -z "$(find "$root/steps" -type f ! -name "*.sh" -print -quit)"; '
        + 'rm -rf "$root/patches"; '
        + 'test "$(stat -c \'%u:%g:%a:%F\' "$root/config/connections.yaml")" '
        + "= '0:0:644:regular file'; rm -rf \"$stage\"",
    )
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
    handle.write("BASEROW_PUBLIC_URL=http://127.0.0.1:18085\n")
    handle.write("WIKIJS_SITE_URL=http://127.0.0.1:18086\n")
    handle.write("MATTERMOST_SITE_URL=http://127.0.0.1:18065\n")
    handle.write("AP_FRONTEND_URL=http://127.0.0.1:18090\n")
    handle.write("SEARXNG_BASE_URL=http://127.0.0.1:18088/\n")
    handle.close()
    return Path(handle.name)


def cmd_plan(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    ensure_safe_target(cfg)
    if args.all and args.components:
        raise PlatformError("plan --all does not accept component names")
    ordered = component_order(cfg, None if args.all else (args.components or None))
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
                "management": "dokploy"
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
    if args.all:
        result["fullDeploySteps"] = [
            {"index": index, "id": step}
            for index, step in enumerate(FULL_DEPLOY_STEPS, start=1)
        ]
    print(json.dumps(result, indent=2))


def cmd_preflight(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    ensure_safe_target(cfg)
    result = ssh(
        cfg,
        "test -r /etc/os-release && . /etc/os-release && "
        'test "${ID:-}" = ubuntu && '
        'printf \'{"ssh":"ready","os":"ubuntu"}\\n\'',
        capture_output=True,
    )
    print(result.stdout, end="")


def cmd_sync(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    sync(cfg)
    print(json.dumps({"synced": True, "target": host_spec(cfg)["ssh"]}))


def run_host_bootstrap(cfg: dict[str, Any], *, source: Path | None = None) -> None:
    ensure_safe_target(cfg)
    source = source or ROOT / "deployment/steps/10-host.sh"
    remote = "/tmp/mte-platform-10-host.sh"
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
    ssh(
        cfg,
        "set -eu; "
        "for attempt in $(seq 1 90); do "
        "if curl -sS -o /dev/null http://127.0.0.1:3000/api/settings.isCloud; then exit 0; fi; "
        "sleep 2; done; exit 1",
    )
    ssh(
        cfg, f"python3 {shlex.quote(remote_script(cfg, 'server-dokploy.py'))} bootstrap"
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
                "dokploy": "owner-and-api-ready",
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
        # carrier. Server-side init filters known keys and remains fill-only.
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
    # Schema upgrades may add a new operator-owned key after the canonical
    # source was first created. Re-import the reviewed operator contract plus
    # managed Notion identifiers; server-config filters them again and applies
    # them fill-only, so existing credentials and generated values always win.
    contract = server_config_contract()
    local_values = normalize_notion_token_import(operator_values())
    allowed_upgrade_imports = (
        set(contract.REQUIRED_OPERATOR_ENV_KEYS)
        - set(contract.LOCAL_ONLY_OPERATOR_INPUT_KEYS)
    ) | NOTION_UPGRADE_IMPORT_KEYS
    upgrade_imports = {
        key: value
        for key, value in local_values.items()
        if key in allowed_upgrade_imports and value
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


def deploy_components(
    cfg: dict[str, Any],
    selected: list[str] | None,
    *,
    no_wait: bool = False,
) -> None:
    ordered = component_order(cfg, selected)
    managed = [row["id"] for row in ordered if row.get("compose")]
    if not managed:
        raise PlatformError("no Dokploy-managed components selected")
    sync(cfg)
    ssh(cfg, f"python3 {shlex.quote(remote_script(cfg, 'server-secrets.py'))} init")
    ssh(cfg, f"python3 {shlex.quote(remote_script(cfg, 'server-config.py'))} render")
    ssh(cfg, f"python3 {shlex.quote(remote_script(cfg, 'server-config.py'))} audit")
    command = ["python3", remote_script(cfg, "server-dokploy.py"), "deploy", *managed]
    if no_wait:
        command.append("--no-wait")
    ssh(cfg, " ".join(shlex.quote(item) for item in command))


def write_index_evidence(payload: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def source_rollback_evidence(
    status: str,
    *,
    error_type: str = "",
    live_mutation_possible: bool,
) -> dict[str, str]:
    """Describe source restoration without overstating live-service recovery."""

    result = {
        "status": status,
        "scope": "governed-source-tree",
    }
    if error_type:
        result["errorType"] = error_type
    if live_mutation_possible:
        result.update(
            {
                "coverage": "source-only",
                "serviceRollback": "not-performed",
                "liveServiceState": "may-have-mutated",
                "recovery": "roll-forward-required",
            }
        )
    return result


def authoritative_source_rollback_evidence(
    result: dict[str, Any], *, live_mutation_possible: bool
) -> dict[str, str]:
    """Translate a validated remote result without overstating recovery."""

    action = result.get("action")
    if action in {"rolledBack", "alreadyRolledBack"}:
        evidence = source_rollback_evidence(
            "completed", live_mutation_possible=live_mutation_possible
        )
        evidence.update(
            {
                "authoritativeState": "rolled-back",
                "remoteAction": str(action),
            }
        )
        return evidence
    if action == "notCurrent" and result.get("current") is False:
        evidence = source_rollback_evidence(
            "not-required", live_mutation_possible=live_mutation_possible
        )
        evidence.update(
            {
                "authoritativeState": "not-current",
                "remoteAction": "notCurrent",
            }
        )
        return evidence
    raise PlatformError("remote rollback result is not authoritative")


def best_effort_transaction_failure(
    transaction: DeployTransaction,
    *,
    failed_step: str,
    live_mutation_possible: bool,
) -> tuple[dict[str, str], dict[str, str]]:
    """Attempt the failure checkpoint and rollback as independent phases."""

    try:
        transaction.checkpoint("failed", completed_step="", next_step=failed_step)
        checkpoint_evidence = {"status": "completed"}
    except BaseException as exc:
        checkpoint_evidence = {
            "status": "failed",
            "errorType": type(exc).__name__,
        }

    try:
        rollback_result = transaction.rollback()
        rollback_evidence = authoritative_source_rollback_evidence(
            rollback_result,
            live_mutation_possible=live_mutation_possible,
        )
    except BaseException as exc:
        rollback_evidence = source_rollback_evidence(
            "failed",
            error_type=type(exc).__name__,
            live_mutation_possible=live_mutation_possible,
        )
    return checkpoint_evidence, rollback_evidence


def no_mutation_rollback_evidence() -> dict[str, str]:
    return {
        "status": "not-required",
        "scope": "none",
        "releaseMutation": "none",
        "serviceMutation": "none",
        "recovery": "safe-after-gate-remediation",
    }


def _resume_evidence(value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = local_evidence_root() / f"deploy-all-{value}.json"
    candidate = candidate.resolve()
    allowed = local_evidence_root().resolve()
    if allowed not in candidate.parents or not candidate.is_file():
        raise PlatformError("resume evidence is missing or outside .runtime/evidence")
    return candidate


def deploy_all(args: argparse.Namespace) -> None:
    global ACTIVE_DEPLOY_TRANSACTION
    if args.components:
        raise PlatformError("deploy --all does not accept component names")
    if args.no_wait:
        raise PlatformError(
            "deploy --all requires health-gated waits between indexed steps"
        )
    cfg = config(args.domain)
    ensure_safe_target(cfg)
    started = datetime.now(timezone.utc)
    preliminary_run_id = started.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:12]
    try:
        license_gate = pre_mutation_license_gate(cfg)
    except PreMutationGateError as exc:
        # This is the only artifact permitted on a failed pre-mutation gate.
        # No source normalization, release snapshot, lock, sync, promotion, or
        # remote mutation has happened at this point.
        evidence_path = local_evidence_root() / f"deploy-all-{preliminary_run_id}.json"
        write_index_evidence(
            {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "PlatformDeployRun",
                "runId": preliminary_run_id,
                "attempt": 1,
                "target": host_spec(cfg)["ssh"],
                "domain": cfg["spec"]["resolvedDomain"] or None,
                "startedAt": started.isoformat(),
                "finishedAt": datetime.now(timezone.utc).isoformat(),
                "status": "failed",
                "failedStep": "license-preflight",
                "errorType": type(exc).__name__,
                "failureCode": exc.code,
                "licenseGate": exc.result,
                "steps": [],
                "rollback": no_mutation_rollback_evidence(),
            },
            evidence_path,
        )
        raise

    resume_value = str(getattr(args, "resume", "") or "")
    if resume_value:
        evidence_path = _resume_evidence(resume_value)
        evidence = json.loads(evidence_path.read_text())
        if (
            evidence.get("kind") != "PlatformDeployRun"
            or evidence.get("status") not in {"failed", "interrupted"}
            or evidence.get("target") != host_spec(cfg)["ssh"]
            or evidence.get("domain") != (cfg["spec"]["resolvedDomain"] or None)
            or not (
                evidence.get("rollback", {}).get("status") == "completed"
                or (
                    evidence.get("rollback", {}).get("status") == "not-required"
                    and evidence.get("rollback", {}).get("authoritativeState")
                    == "not-current"
                )
            )
        ):
            raise PlatformError("deploy evidence is not safe to resume")
        run_id = str(evidence.get("runId") or "")
        attempt = int(evidence.get("attempt") or 1) + 1
        evidence["steps"] = [
            row for row in evidence.get("steps", []) if row.get("status") == "completed"
        ]
        evidence.update(
            {
                "attempt": attempt,
                "resumedAt": started.isoformat(),
                "status": "running",
                "licenseGate": license_gate,
            }
        )
        evidence.pop("failedStep", None)
        evidence.pop("finishedAt", None)
        evidence.pop("rollback", None)
    else:
        run_id = preliminary_run_id
        attempt = 1
        evidence_path = local_evidence_root() / f"deploy-all-{run_id}.json"
        evidence = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "PlatformDeployRun",
            "runId": run_id,
            "attempt": attempt,
            "target": host_spec(cfg)["ssh"],
            "domain": cfg["spec"]["resolvedDomain"] or None,
            "startedAt": started.isoformat(),
            "status": "running",
            "licenseGate": license_gate,
            "steps": [],
        }

    snapshot = ReleaseSnapshot(cfg, run_id)
    transaction = DeployTransaction(
        cfg,
        snapshot,
        run_id,
        attempt=attempt,
        release_id=str(evidence.get("releaseId") or "") or None,
    )
    if evidence.get("sourceSha256") not in {None, snapshot.source_sha256}:
        snapshot.close()
        raise PlatformError("resume source differs from the frozen release")
    evidence.update(
        {
            "releaseId": transaction.release_id,
            "activationId": transaction.activation_id,
            "sourceSha256": snapshot.source_sha256,
            "sourceManifestSha256": hashlib.sha256(
                snapshot.manifest_path.read_bytes()
            ).hexdigest(),
            "remoteCheckpoint": f"{remote_root(cfg)}/.deploy/runs/{run_id}.json",
            "rollbackScope": "governed-source-tree",
        }
    )
    write_index_evidence(evidence, evidence_path)

    def step_args(**values: Any) -> argparse.Namespace:
        return argparse.Namespace(domain=args.domain, **values)

    actions = {
        "config-initialize": lambda: ensure_config_initialized(cfg),
        "config-render": lambda: run_config(cfg, "render"),
        "config-audit": lambda: run_config(cfg, "audit"),
        "bootstrap": lambda: finish_platform_bootstrap(cfg),
        "toolhive-binary": lambda: run_tools(cfg, "install"),
        "dokploy-foundation": lambda: deploy_components(cfg, ["postgres"]),
        "application-databases": lambda: run_application_databases(cfg),
        "dokploy-components": lambda: deploy_components(cfg, None),
        "paperclip-runtime-config": lambda: run_paperclip_runtime(
            cfg, "config-migrate"
        ),
        "paperclip-runtime": lambda: run_paperclip_runtime(cfg, "install"),
        "profiles": lambda: apply_profiles(cfg),
        "paperclip-environments": lambda: run_paperclip_experimental(
            cfg, "environments", "apply"
        ),
        "paperclip-secrets": lambda: run_paperclip_experimental(
            cfg, "secrets", "apply"
        ),
        "provision": lambda: run_provision(cfg, "provision"),
        "provision-idempotency": lambda: run_provision(cfg, "verify"),
        "data-content-projections": lambda: run_data_content_projections(
            cfg, "provision"
        ),
        "kestra-control": lambda: run_kestra_control(cfg, "provision"),
        "tool-bundles": lambda: run_tools(cfg, "provision"),
        "tool-bundles-idempotency": lambda: run_tools(cfg, "verify"),
        "daytona": lambda: run_paperclip_experimental(cfg, "daytona", "apply"),
        "harness-auth": lambda: run_harness_auth(cfg, "status"),
        "hermes": lambda: run_hermes(cfg, "install"),
        "kestra-e2e-canary": lambda: run_kestra_canary(cfg, "apply"),
        "profile-acceptance": lambda: run_profile_acceptance(cfg),
        "integration-canaries": lambda: run_integration_canaries(cfg, "run", []),
        "hermes-acceptance": lambda: run_hermes_acceptance(cfg),
        "host-dokploy-acceptance": lambda: run_host_dokploy_acceptance(cfg),
        "observability-reconcile-pass-1": lambda: run_observability_producer(
            cfg, "reconcile-pass-1"
        ),
        "observability-reconcile-pass-2": lambda: run_observability_producer(
            cfg, "reconcile-pass-2"
        ),
        "observability-idempotency": lambda: run_observability_producer(
            cfg, "idempotency"
        ),
        "observability-acceptance": lambda: run_observability_producer(
            cfg, "acceptance"
        ),
        "cloudflare-plan": lambda: run_cloudflare(cfg, "plan"),
        "cloudflare-apply": lambda: run_cloudflare(cfg, "apply"),
        "cloudflare-origin-firewall": lambda: run_origin_firewall(cfg),
        "post-cloudflare-evidence-rebind": lambda: run_final_evidence_rebind(cfg),
        "cloudflare-acceptance": lambda: run_cloudflare(cfg, "acceptance"),
        "connections": lambda: cmd_connections(step_args(action="check")),
        "verify": lambda: cmd_verify(step_args(components=[])),
    }
    completed = {
        str(row.get("id"))
        for row in evidence["steps"]
        if row.get("status") == "completed"
    }
    ACTIVE_DEPLOY_TRANSACTION = transaction
    remote_mutation_started = False
    try:
        with remote_deploy_lock(cfg):
            locked_license_gate = pre_mutation_license_gate(cfg)
            if locked_license_gate != license_gate:
                raise PreMutationGateError(
                    "license_preflight_changed_during_lock", locked_license_gate
                )
            evidence["licenseGate"] = locked_license_gate
            write_index_evidence(evidence, evidence_path)
            remote_mutation_started = True
            # The host step is the sole prerequisite for rsync, Python, and
            # the immutable release helper on a clean Ubuntu server.
            run_host_bootstrap(
                cfg,
                source=snapshot.source / "steps/10-host.sh",
            )
            transaction.ensure_synced()
            remove_legacy_patch_projection(cfg)
            pending = [step for step in FULL_DEPLOY_STEPS if step not in completed]
            transaction.checkpoint("running", next_step=pending[0] if pending else "")
            for index, step in enumerate(FULL_DEPLOY_STEPS, start=1):
                if step in completed:
                    continue
                transaction.verify()
                row: dict[str, Any] = {
                    "index": index,
                    "attempt": attempt,
                    "id": step,
                    "status": "running",
                    "startedAt": datetime.now(timezone.utc).isoformat(),
                }
                evidence["steps"].append(row)
                write_index_evidence(evidence, evidence_path)
                tick = time.monotonic()
                try:
                    actions[step]()
                    transaction.verify()
                except BaseException as exc:
                    row.update(
                        {
                            "status": "failed",
                            "finishedAt": datetime.now(timezone.utc).isoformat(),
                            "durationSeconds": round(time.monotonic() - tick, 3),
                            "errorType": type(exc).__name__,
                        }
                    )
                    evidence["status"] = "failed"
                    evidence["failedStep"] = step
                    evidence["finishedAt"] = datetime.now(timezone.utc).isoformat()
                    (
                        evidence["failureCheckpoint"],
                        evidence["rollback"],
                    ) = best_effort_transaction_failure(
                        transaction,
                        failed_step=step,
                        live_mutation_possible=True,
                    )
                    write_index_evidence(evidence, evidence_path)
                    raise
                row.update(
                    {
                        "status": "completed",
                        "finishedAt": datetime.now(timezone.utc).isoformat(),
                        "durationSeconds": round(time.monotonic() - tick, 3),
                    }
                )
                completed.add(step)
                remaining = [
                    item for item in FULL_DEPLOY_STEPS if item not in completed
                ]
                transaction.checkpoint(
                    "running",
                    completed_step=step,
                    next_step=remaining[0] if remaining else "",
                )
                write_index_evidence(evidence, evidence_path)

            transaction.checkpoint("completed", completed_step=FULL_DEPLOY_STEPS[-1])
            evidence["status"] = "completed"
            evidence["finishedAt"] = datetime.now(timezone.utc).isoformat()
            evidence["rollback"] = {
                "status": "not-required",
                "scope": "governed-source-tree",
            }
            write_index_evidence(evidence, evidence_path)
    except BaseException as exc:
        if evidence.get("status") != "failed":
            gate_failure = isinstance(exc, PreMutationGateError)
            evidence.update(
                {
                    "status": "failed",
                    "failedStep": (
                        "license-preflight"
                        if gate_failure
                        else "transaction-preparation"
                    ),
                    "finishedAt": datetime.now(timezone.utc).isoformat(),
                    "errorType": type(exc).__name__,
                }
            )
            if gate_failure:
                evidence["failureCode"] = exc.code
                evidence["licenseGate"] = exc.result
                evidence["rollback"] = no_mutation_rollback_evidence()
            else:
                (
                    evidence["failureCheckpoint"],
                    evidence["rollback"],
                ) = best_effort_transaction_failure(
                    transaction,
                    failed_step=str(evidence["failedStep"]),
                    live_mutation_possible=remote_mutation_started,
                )
            write_index_evidence(evidence, evidence_path)
        raise
    finally:
        ACTIVE_DEPLOY_TRANSACTION = None
        if remote_mutation_started:
            transaction.cleanup()
        snapshot.close()
    print(
        json.dumps({"deployAll": "completed", "evidence": str(evidence_path)}, indent=2)
    )


def cmd_deploy(args: argparse.Namespace) -> None:
    if args.all:
        deploy_all(args)
        return
    if getattr(args, "resume", None):
        raise PlatformError("deploy --resume requires --all")
    cfg = config(args.domain)
    deploy_components(cfg, args.components or None, no_wait=args.no_wait)


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


def cmd_connections(args: argparse.Namespace) -> None:
    registry = load_yaml(CONNECTIONS_PATH)
    if args.action == "export":
        print(json.dumps(registry, indent=2))
        return
    cfg = config(args.domain)
    sync(cfg)
    ssh(
        cfg,
        f"python3 {shlex.quote(remote_script(cfg, 'server-verify.py'))} connections",
    )


def run_paperclip_runtime(cfg: dict[str, Any], action: str) -> None:
    sync(cfg)
    step = remote_step(cfg, "50-paperclip.sh")
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

    step = remote_step(cfg, "60-daytona.sh")
    if action == "status":
        ssh(cfg, f"{shlex.quote(step)} status")
        merge_paperclip_experimental_inputs(cfg, feature)
        reconcile("status")
        return

    if action == "apply":
        # The Daytona SDK used to build snapshots is installed by Paperclip's
        # official Daytona plugin.  Establish the control plane and its key
        # first, install/enable the plugin second, and only then build and
        # exercise the custom snapshots.  This ordering is intentionally
        # explicit: ``60-daytona.sh all`` is control-plane-only and cannot
        # accidentally reintroduce the former bootstrap cycle.
        for step_action in ("install", "provision-key", "set-target"):
            ssh(cfg, f"{shlex.quote(step)} {step_action}")
        render_canonical_source()
        merge_paperclip_experimental_inputs(cfg, feature)

        # First apply installs/enables the native plugin and creates the
        # environment with the pinned base image. Runtime probes are reserved
        # for the explicit verify after the snapshot is available.
        reconcile("apply")
        ssh(cfg, f"{shlex.quote(step)} acceptance")

        # Snapshot readiness is merged into canonical platform.env by the
        # acceptance step. Re-render, bind Paperclip to that exact snapshot,
        # then run the real per-harness environment probes.
        render_canonical_source()
        reconcile("apply")
        reconcile("verify")
        require_daytona_dependencies(cfg)
        return

    if action == "verify":
        merge_paperclip_experimental_inputs(cfg, feature)
        require_daytona_dependencies(cfg)
        ssh(cfg, f"{shlex.quote(step)} acceptance")
        render_canonical_source()
        reconcile("verify")
        require_daytona_dependencies(cfg)
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
    runner = (
        ACTIVE_DEPLOY_TRANSACTION.snapshot.source / "bin" / runner_name
        if ACTIVE_DEPLOY_TRANSACTION is not None
        else TOOL_ROOT / runner_name
    )
    if not runner.is_file():
        raise PlatformError(
            f"E2E canary runner is not present yet: {runner}; "
            "the dedicated flow implementation must provide it"
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


def run_host_dokploy_acceptance(cfg: dict[str, Any]) -> None:
    expected = canonical_source_sha256(cfg)
    run_canonical_hash_bound(
        cfg,
        [
            "python3",
            remote_script(cfg, "server-host-dokploy-acceptance.py"),
            "apply",
            "--expected-source-hash",
            expected,
        ],
    )


def run_observability_producer(cfg: dict[str, Any], action: str) -> None:
    expected = canonical_source_sha256(cfg)
    command = [
        "python3",
        remote_script(cfg, "server-observability-canary.py"),
    ]
    if action.startswith("reconcile-pass-"):
        command.extend(
            [
                "reconcile-pass",
                "--expected-source-hash",
                expected,
                "--pass-number",
                action.rsplit("-", 1)[-1],
            ]
        )
    elif action == "idempotency":
        command.extend(["finalize-idempotency", "--expected-source-hash", expected])
    elif action == "acceptance":
        command.extend(["apply", "--expected-source-hash", expected])
    else:
        raise PlatformError(f"unknown observability producer action: {action}")
    run_canonical_hash_bound(cfg, command)


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
    run_kestra_canary(cfg, "apply")
    run_profile_acceptance(cfg)
    run_integration_canaries(cfg, "run", [])
    run_hermes_acceptance(cfg)
    run_host_dokploy_acceptance(cfg)
    for action in (
        "reconcile-pass-1",
        "reconcile-pass-2",
        "idempotency",
        "acceptance",
    ):
        run_observability_producer(cfg, action)


def run_integration_canaries(
    cfg: dict[str, Any], action: str, canary_ids: list[str]
) -> None:
    """Run only the exact integration-canary producer synchronized by this source."""
    if action == "status" and canary_ids:
        raise PlatformError("integration-canaries status does not accept canary IDs")
    supported = {"C013", "C023", "C024", "C027", "C028", "C029", "C030"}
    unknown = sorted(set(canary_ids) - supported)
    if unknown:
        raise PlatformError(f"unknown integration canary IDs: {', '.join(unknown)}")
    sync(cfg)
    local = (
        ACTIVE_DEPLOY_TRANSACTION.snapshot.source / "bin/server-integration-canaries.py"
        if ACTIVE_DEPLOY_TRANSACTION is not None
        else TOOL_ROOT / "server-integration-canaries.py"
    )
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
                command_text(
                    [
                        "python3",
                        remote_script(cfg, "server-activepieces-provision-verify.py"),
                        "provision",
                    ]
                ),
                command_text(
                    [
                        "python3",
                        remote_script(cfg, "server-activepieces-provision-verify.py"),
                        "provision",
                    ]
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
                command_text(
                    [
                        "python3",
                        remote_script(cfg, "server-activepieces-provision-verify.py"),
                        action,
                    ]
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
    if action not in {"provision", "drain", "status", "verify"}:
        raise PlatformError("unsupported Notion projection action")
    sync(cfg)
    command = [
        "python3",
        remote_script(cfg, "server-notion-sync.py"),
        action,
    ]
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


def run_hermes(cfg: dict[str, Any], action: str, *, purge_data: bool = False) -> None:
    sync(cfg)
    if action in {"preflight", "install", "health"}:
        merge_hermes_inputs(cfg)
    command = ["python3", remote_script(cfg, "server-hermes.py"), action]
    if action == "install":
        command.append("--grant-platform-admin")
    if action == "remove" and purge_data:
        command.append("--purge-data")
    ssh(cfg, " ".join(shlex.quote(item) for item in command))


def cmd_hermes(args: argparse.Namespace) -> None:
    cfg = config(args.domain)
    run_hermes(cfg, args.action, purge_data=args.purge_data)


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


def run_cloudflare(cfg: dict[str, Any], action: str) -> None:
    if action == "origin-firewall":
        run_origin_firewall(cfg)
        return
    if action == "acceptance":
        sync(cfg)
        local = (
            ACTIVE_DEPLOY_TRANSACTION.snapshot.source
            / "bin/server-cloudflare-acceptance.py"
            if ACTIVE_DEPLOY_TRANSACTION is not None
            else TOOL_ROOT / "server-cloudflare-acceptance.py"
        )
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
        step = remote_step(cfg, "90-cloudflare-tunnel.sh")
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
        ssh(cfg, f"test -s {shlex.quote(api_env)}; {plan}")
        return

    cloudflare_preflight(cfg, require_ready=True)
    cloudflare_root, iac_root, api_env = prepare_cloudflare_remote(cfg)
    init = tofu_command(iac_root, api_env, "init", "-input=false", "-no-color")
    plan = tofu_command(
        iac_root,
        api_env,
        "plan",
        "-input=false",
        "-no-color",
        "-out=/workspace/platform.tfplan",
    )
    ssh(
        cfg,
        f"set -eu; umask 077; {init}; {plan}; chmod -R go-rwx {shlex.quote(iac_root)}",
    )
    if action == "plan":
        return
    if action != "apply":
        raise PlatformError(f"unsupported Cloudflare action: {action}")

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
    service_output = tofu_command(iac_root, api_env, "output", "-json", "service_token")
    ssh(
        cfg,
        "set -eu; umask 077; "
        + f"{apply}; "
        + f"token_tmp=$(mktemp {shlex.quote(cloudflare_root + '/.tunnel-token.XXXXXX')}); "
        + f"service_tmp=$(mktemp {shlex.quote(cloudflare_root + '/.service-token.XXXXXX')}); "
        + 'trap \'rm -f "$token_tmp" "$service_tmp"\' EXIT; '
        + f'{tunnel_output} >"$token_tmp"; test -s "$token_tmp"; '
        + f'{service_output} >"$service_tmp"; test -s "$service_tmp"; '
        + f"python3 {shlex.quote(remote_script(cfg, 'server-cloudflare-runtime.py'))} upsert "
        + '--tunnel-file "$token_tmp" --service-file "$service_tmp"; '
        + f"python3 {shlex.quote(remote_script(cfg, 'server-config.py'))} render; "
        + f"python3 {shlex.quote(remote_script(cfg, 'server-config.py'))} audit; "
        + f"python3 {shlex.quote(remote_script(cfg, 'server-cloudflare-runtime.py'))} status; "
        + f"{shlex.quote(remote_step(cfg, '90-cloudflare-tunnel.sh'))} install",
    )


ORIGIN_FIREWALL_EVIDENCE_FIELDS = {
    "firewallPolicyVersion",
    "firewallServiceActive",
    "firewallServiceEnabled",
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
    step = remote_step(cfg, "91-origin-firewall.sh")
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
    remote = (
        f"python3 {shlex.quote(remote_root(cfg) + '/runtime/paperclip/scripts/bootstrap-paperclip.py')} "
        "--mode native --workspace-root /home/daytona/workspaces --instructions-root /prototype/profiles "
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
    plan.add_argument(
        "--all", action="store_true", help="show the indexed full-platform sequence"
    )
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

    deploy = subs.add_parser("deploy")
    deploy.add_argument("components", nargs="*")
    deploy.add_argument("--no-wait", action="store_true")
    deploy.add_argument(
        "--all", action="store_true", help="run the indexed full-platform sequence"
    )
    deploy.add_argument(
        "--resume",
        metavar="RUN_ID_OR_EVIDENCE",
        help="resume a failed, source-rolled-back full deployment",
    )
    deploy.set_defaults(func=cmd_deploy)

    verify = subs.add_parser("verify")
    verify.add_argument("components", nargs="*")
    verify.add_argument(
        "--all", action="store_true", help="run the complete platform acceptance"
    )
    verify.set_defaults(func=cmd_verify)

    status = subs.add_parser("status")
    status.set_defaults(func=cmd_status)

    connections = subs.add_parser("connections")
    connections.add_argument("action", choices=["export", "check"])
    connections.set_defaults(func=cmd_connections)

    profiles = subs.add_parser("profiles")
    profiles.add_argument("action", choices=["render", "apply"])
    profiles.set_defaults(func=cmd_profiles)

    runtime = subs.add_parser("runtime")
    runtime_subs = runtime.add_subparsers(dest="runtime", required=True)
    paperclip = runtime_subs.add_parser("paperclip")
    paperclip.add_argument(
        "action",
        choices=[
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

    integration_canaries = subs.add_parser("integration-canaries")
    integration_canaries.add_argument("action", choices=["run", "status"])
    integration_canaries.add_argument("canary_ids", nargs="*")
    integration_canaries.set_defaults(func=cmd_integration_canaries)

    provision = subs.add_parser("provision")
    provision.add_argument("action", choices=["apply", "status", "verify"])
    provision.set_defaults(func=cmd_provision)

    notion_projection = subs.add_parser("notion-projection")
    notion_projection.add_argument(
        "action", choices=["apply", "drain", "status", "verify"]
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
        "action", choices=["preflight", "install", "status", "health", "remove"]
    )
    hermes.add_argument("--purge-data", action="store_true")
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

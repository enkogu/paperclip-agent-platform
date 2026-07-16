#!/usr/bin/env python3
"""Fail-closed loader for the declarative Paperclip profile catalog.

Both the reviewed source and its rendered runtime projection are real YAML.
Every profile consumer imports this module; profile membership, runtime shape,
probe policy, and cross-profile topology therefore come from one data contract
instead of parallel Python maps.  Catalog identity is format-independent: its
semantic hash is always calculated from canonical JSON after YAML parsing.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any

import yaml


CATALOG_SCHEMA_ID = "micro-task-engine/v1alpha1"
KIND = "PaperclipProfileCatalog"
REF_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{1,62}")
ENV_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*")
PLACEHOLDER_PATTERN = re.compile(r"\$\{[^}]+\}")
RUNTIME_KEYS = frozenset(
    {
        "harnessKind",
        "adapterType",
        "protocol",
        "packageKey",
        "runtimeSecretEnv",
        "envAllowlist",
        "providerManagedEnv",
        "probe",
    }
)
TOPOLOGY_KEYS = frozenset(
    {
        "wrongProfileRef",
        "toolhiveUpstreamRef",
        "toolhiveGatewayPortRef",
        "toolhiveProxyPortRef",
        "toolhiveIdentityPortRef",
        "toolhiveNotionPortRef",
    }
)


class CatalogError(RuntimeError):
    """The catalog is missing, malformed, ambiguous, or references drift."""


@dataclass(frozen=True)
class ProfileCatalog:
    document: dict[str, Any]
    profiles: tuple[dict[str, Any], ...]
    refs: tuple[str, ...]
    by_ref: dict[str, dict[str, Any]]
    semantic_sha256: str

    def require(self, ref: str) -> dict[str, Any]:
        try:
            return self.by_ref[ref]
        except KeyError as exc:
            raise CatalogError(f"profile_unknown:{ref}") from exc


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def semantic_sha256(document: dict[str, Any]) -> str:
    semantic = {key: value for key, value in document.items() if key != "_generated"}
    return hashlib.sha256(canonical_json(semantic)).hexdigest()


def repository_root() -> Path:
    script_parent = Path(__file__).resolve().parent
    if script_parent.name == "bin":
        return script_parent.parent
    if script_parent.name == "platform-cli" and script_parent.parent.name == "tools":
        return script_parent.parents[1]
    return script_parent


def catalog_candidates(*, runtime_first: bool = True) -> tuple[Path, ...]:
    root = repository_root()
    runtime = root / "runtime/profiles/profiles.yaml"
    sources = (
        root / "config/profiles/catalog.yaml",
        root / "templates/profiles/profiles.yaml",
    )
    return (runtime, *sources) if runtime_first else (*sources, runtime)


def default_catalog_path(*, runtime_first: bool = True) -> Path:
    candidates = catalog_candidates(runtime_first=runtime_first)
    return next((path for path in candidates if path.is_file()), candidates[0])


def _object(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogError(code)
    return value


def _required_string(
    value: Any, code: str, pattern: re.Pattern[str] | None = None
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or (pattern and not pattern.fullmatch(value))
    ):
        raise CatalogError(code)
    return value


def _string_list(value: Any, code: str, *, env: bool = False) -> list[str]:
    if not isinstance(value, list) or not value:
        raise CatalogError(code)
    rows = [
        _required_string(item, code, ENV_PATTERN if env else None) for item in value
    ]
    if len(rows) != len(set(rows)):
        raise CatalogError(code + "_duplicate")
    return rows


def _validate_profile(profile: dict[str, Any]) -> None:
    ref = _required_string(profile.get("ref"), "profile_ref_invalid", REF_PATTERN)
    for key in ("title", "role", "defaultEnvironment", "workspaceMode", "instructions"):
        _required_string(profile.get(key), f"profile_{key}_invalid:{ref}")
    native_adapter = _required_string(
        profile.get("nativeAdapter"), f"profile_native_adapter_invalid:{ref}"
    )
    _object(profile.get("nativeAdapterConfig"), f"profile_adapter_config_invalid:{ref}")
    runtime_packages = _object(
        profile.get("runtimePackages"), f"profile_runtime_packages_invalid:{ref}"
    )
    runtime = _object(
        profile.get("runtimeContract"), f"profile_runtime_contract_invalid:{ref}"
    )
    if set(runtime) != RUNTIME_KEYS:
        raise CatalogError(f"profile_runtime_contract_keys_invalid:{ref}")
    _required_string(
        runtime.get("harnessKind"), f"profile_harness_kind_invalid:{ref}", REF_PATTERN
    )
    adapter_type = _required_string(
        runtime.get("adapterType"), f"profile_adapter_type_invalid:{ref}"
    )
    if adapter_type != native_adapter:
        raise CatalogError(f"profile_adapter_type_mirror_drift:{ref}")
    _required_string(
        runtime.get("protocol"), f"profile_protocol_invalid:{ref}", REF_PATTERN
    )
    package_key = _required_string(
        runtime.get("packageKey"), f"profile_package_key_invalid:{ref}"
    )
    if package_key not in runtime_packages or not isinstance(
        runtime_packages[package_key], (str, int, float)
    ):
        raise CatalogError(f"profile_package_binding_invalid:{ref}")
    runtime_secret_env = _required_string(
        runtime.get("runtimeSecretEnv"),
        f"profile_runtime_secret_env_invalid:{ref}",
        ENV_PATTERN,
    )
    env_allowlist = _string_list(
        runtime.get("envAllowlist"), f"profile_env_allowlist_invalid:{ref}", env=True
    )
    provider_managed = _object(
        runtime.get("providerManagedEnv"), f"profile_provider_env_invalid:{ref}"
    )
    if not all(
        ENV_PATTERN.fullmatch(key)
        and key in env_allowlist
        and isinstance(binding, dict)
        and set(binding) == {"kind", "pathSuffix"}
        and binding.get("kind") == "paperclip-agent-home"
        and isinstance(binding.get("pathSuffix"), str)
        and binding["pathSuffix"]
        for key, binding in provider_managed.items()
    ):
        raise CatalogError(f"profile_provider_env_invalid:{ref}")
    if runtime_secret_env not in env_allowlist or "GITHUB_TOKEN" not in env_allowlist:
        raise CatalogError(f"profile_env_allowlist_incomplete:{ref}")
    probe = _object(runtime.get("probe"), f"profile_probe_invalid:{ref}")
    if set(probe) != {"helloCode", "acceptedWarnings"}:
        raise CatalogError(f"profile_probe_keys_invalid:{ref}")
    _required_string(probe.get("helloCode"), f"profile_probe_hello_invalid:{ref}")
    warnings = probe.get("acceptedWarnings")
    if (
        not isinstance(warnings, list)
        or any(not isinstance(item, str) or not item for item in warnings)
        or len(warnings) != len(set(warnings))
    ):
        raise CatalogError(f"profile_probe_warnings_invalid:{ref}")

    topology = _object(profile.get("topology"), f"profile_topology_invalid:{ref}")
    if set(topology) != TOPOLOGY_KEYS:
        raise CatalogError(f"profile_topology_keys_invalid:{ref}")
    _required_string(
        topology.get("wrongProfileRef"),
        f"profile_wrong_profile_ref_invalid:{ref}",
        REF_PATTERN,
    )
    for key in TOPOLOGY_KEYS - {"wrongProfileRef"}:
        _required_string(
            topology.get(key), f"profile_topology_ref_invalid:{ref}", ENV_PATTERN
        )

    llm = _object(profile.get("llmRouting"), f"profile_llm_routing_invalid:{ref}")
    tools = _object(profile.get("toolRouting"), f"profile_tool_routing_invalid:{ref}")
    access = _object(profile.get("toolAccess"), f"profile_tool_access_invalid:{ref}")
    for container, key in (
        (llm, "provider"),
        (llm, "apiKeyRef"),
        (tools, "provider"),
        (tools, "mcpUrlRef"),
        (tools, "bearerTokenRef"),
        (access, "bundleId"),
        (access, "workloadId"),
        (access, "endpointRef"),
        (access, "credentialRef"),
        (access, "wrongProfileEndpointRef"),
    ):
        _required_string(container.get(key), f"profile_binding_invalid:{ref}:{key}")
    if (
        access.get("paperclipProfileRef") != ref
        or access.get("endpointRef") != tools.get("mcpUrlRef")
        or access.get("credentialRef") != tools.get("bearerTokenRef")
        or access["endpointRef"] not in env_allowlist
    ):
        raise CatalogError(f"profile_control_plane_binding_drift:{ref}")


def _validate_topology(profiles: tuple[dict[str, Any], ...]) -> None:
    refs = tuple(str(profile["ref"]) for profile in profiles)
    ref_set = set(refs)
    targets = {
        str(profile["ref"]): str(profile["topology"]["wrongProfileRef"])
        for profile in profiles
    }
    if any(target not in ref_set or target == ref for ref, target in targets.items()):
        raise CatalogError("profile_topology_target_invalid")
    if len(set(targets.values())) != len(refs):
        raise CatalogError("profile_topology_target_duplicate")
    visited: list[str] = []
    current = refs[0]
    while current not in visited:
        visited.append(current)
        current = targets[current]
    if current != refs[0] or set(visited) != ref_set:
        raise CatalogError("profile_topology_not_single_cycle")
    by_ref = {str(profile["ref"]): profile for profile in profiles}
    for ref, target in targets.items():
        current_access = by_ref[ref]["toolAccess"]
        target_access = by_ref[target]["toolAccess"]
        if current_access.get("wrongProfileEndpointRef") != target_access.get(
            "endpointRef"
        ):
            raise CatalogError(f"profile_wrong_endpoint_binding_drift:{ref}")


def load_profile_catalog(
    path: Path | str | None = None, *, require_rendered: bool = False
) -> ProfileCatalog:
    source = Path(path) if path is not None else default_catalog_path()
    try:
        document = yaml.safe_load(source.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise CatalogError(f"profile_catalog_unreadable:{source}") from exc
    if not isinstance(document, dict):
        raise CatalogError("profile_catalog_not_object")
    if document.get("apiVersion") != CATALOG_SCHEMA_ID or document.get("kind") != KIND:
        raise CatalogError("profile_catalog_identity_invalid")
    rows = document.get("profiles")
    if (
        not isinstance(rows, list)
        or not rows
        or any(not isinstance(profile, dict) for profile in rows)
    ):
        raise CatalogError("profile_catalog_profiles_invalid")
    profiles = tuple(rows)
    for profile in profiles:
        _validate_profile(profile)
    refs = tuple(str(profile["ref"]) for profile in profiles)
    if len(refs) != len(set(refs)):
        raise CatalogError("profile_catalog_ref_duplicate")
    harness_kinds = tuple(
        str(profile["runtimeContract"]["harnessKind"]) for profile in profiles
    )
    if len(harness_kinds) != len(set(harness_kinds)):
        raise CatalogError("profile_catalog_harness_duplicate")
    _validate_topology(profiles)
    if require_rendered and PLACEHOLDER_PATTERN.search(
        canonical_json({"profiles": profiles}).decode()
    ):
        raise CatalogError("profile_catalog_runtime_not_rendered")
    return ProfileCatalog(
        document=document,
        profiles=profiles,
        refs=refs,
        by_ref={str(profile["ref"]): profile for profile in profiles},
        semantic_sha256=semantic_sha256(document),
    )

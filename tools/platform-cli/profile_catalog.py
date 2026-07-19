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
DELIVERY_KEY_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9]*")
LOCAL_PACKAGE_REF_PATTERN = re.compile(r"(?:[A-Za-z0-9._-]+/)+[A-Za-z0-9._-]+")
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
    extensions: tuple[dict[str, Any], ...]
    by_extension_ref: dict[str, dict[str, Any]]
    skill_packages: dict[str, dict[str, Any]]
    semantic_sha256: str

    def require(self, ref: str) -> dict[str, Any]:
        try:
            return self.by_ref[ref]
        except KeyError as exc:
            raise CatalogError(f"profile_unknown:{ref}") from exc

    def require_extension(self, ref: str) -> dict[str, Any]:
        try:
            return self.by_extension_ref[ref]
        except KeyError as exc:
            raise CatalogError(f"extension_unknown:{ref}") from exc

    def extensions_for(self, profile_ref: str) -> tuple[dict[str, Any], ...]:
        profile = self.require(profile_ref)
        return tuple(
            self.require_extension(extension_ref)
            for extension_ref in profile["extensions"]
        )

    def require_skill_package(self, ref: str) -> dict[str, Any]:
        try:
            return self.skill_packages[ref]
        except KeyError as exc:
            raise CatalogError(f"skill_package_unknown:{ref}") from exc


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


def _string_list(
    value: Any, code: str, *, env: bool = False, allow_empty: bool = False
) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
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
    native_adapter_config = _object(
        profile.get("nativeAdapterConfig"), f"profile_adapter_config_invalid:{ref}"
    )
    paperclip_runtime_config = _object(
        profile.get("paperclipRuntimeConfig"),
        f"profile_paperclip_runtime_config_invalid:{ref}",
    )
    if set(paperclip_runtime_config) != {"modelProfiles"}:
        raise CatalogError(f"profile_paperclip_runtime_config_keys_invalid:{ref}")
    model_profiles = _object(
        paperclip_runtime_config.get("modelProfiles"),
        f"profile_model_profiles_invalid:{ref}",
    )
    if set(model_profiles) - {"cheap"}:
        raise CatalogError(f"profile_model_profile_unknown:{ref}")
    cheap = model_profiles.get("cheap")
    if cheap is not None:
        cheap = _object(cheap, f"profile_cheap_model_profile_invalid:{ref}")
        if set(cheap) != {"enabled", "label", "adapterConfig"}:
            raise CatalogError(f"profile_cheap_model_profile_keys_invalid:{ref}")
        if cheap.get("enabled") is not True:
            raise CatalogError(f"profile_cheap_model_profile_disabled:{ref}")
        _required_string(
            cheap.get("label"), f"profile_cheap_model_profile_label_invalid:{ref}"
        )
        cheap_adapter_config = _object(
            cheap.get("adapterConfig"),
            f"profile_cheap_model_profile_adapter_config_invalid:{ref}",
        )
        if set(cheap_adapter_config) != {"model"}:
            raise CatalogError(
                f"profile_cheap_model_profile_adapter_config_keys_invalid:{ref}"
            )
        if cheap_adapter_config.get("model") != native_adapter_config.get("model"):
            raise CatalogError(f"profile_cheap_model_profile_route_drift:{ref}")
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

    _string_list(
        profile.get("extensions"),
        f"profile_extensions_invalid:{ref}",
        allow_empty=True,
    )
    mcp_policy = _object(profile.get("mcpPolicy"), f"profile_mcp_policy_invalid:{ref}")
    if set(mcp_policy) != {"allow", "deny"}:
        raise CatalogError(f"profile_mcp_policy_keys_invalid:{ref}")
    allowed_capabilities = _string_list(
        mcp_policy.get("allow"), f"profile_mcp_allow_invalid:{ref}"
    )
    denied_capabilities = _string_list(
        mcp_policy.get("deny"), f"profile_mcp_deny_invalid:{ref}"
    )
    if set(allowed_capabilities) & set(denied_capabilities):
        raise CatalogError(f"profile_mcp_policy_overlap:{ref}")
    _object(profile.get("toolDelivery"), f"profile_tool_delivery_invalid:{ref}")

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


def _config_refs(value: Any, *, credential_only: bool = False) -> set[str]:
    """Collect declarative environment references without interpreting config.

    The profile catalog declares delivery metadata; each native harness adapter
    still owns how that metadata is rendered.  This walker only makes reference
    use fail closed, and deliberately does not become a generic runtime loop.
    """
    refs: set[str] = set()
    credential_suffixes = (
        "credentialref",
        "bearertokenref",
        "tokenref",
        "apikeyref",
        "secretref",
    )

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, nested in node.items():
                lowered = str(key).lower()
                is_credential = lowered.endswith(credential_suffixes)
                is_ref = lowered.endswith("ref")
                if is_ref and isinstance(nested, str):
                    if not credential_only or is_credential:
                        refs.add(nested)
                walk(nested)
        elif isinstance(node, list):
            for nested in node:
                walk(nested)

    walk(value)
    return refs


def _unsafe_credential_config_keys(value: Any) -> set[str]:
    unsafe: set[str] = set()
    sensitive_fragments = ("credential", "token", "secret", "apikey", "api_key")

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, nested in node.items():
                lowered = str(key).lower()
                if (
                    any(fragment in lowered for fragment in sensitive_fragments)
                    and not lowered.endswith(("ref", "refs"))
                    and lowered != "credentialrequired"
                ):
                    unsafe.add(str(key))
                walk(nested)
        elif isinstance(node, list):
            for nested in node:
                walk(nested)

    walk(value)
    return unsafe


def _validate_extensions(
    value: Any, profiles: tuple[dict[str, Any], ...]
) -> tuple[dict[str, Any], ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(row, dict) for row in value)
    ):
        raise CatalogError("extension_catalog_invalid")
    rows = tuple(value)
    profile_by_ref = {str(profile["ref"]): profile for profile in profiles}
    refs: list[str] = []
    for row in rows:
        ref = _required_string(row.get("ref"), "extension_ref_invalid", REF_PATTERN)
        refs.append(ref)
        if set(row) != {
            "ref",
            "kind",
            "mcpCapability",
            "deliveryKey",
            "enabledProfiles",
            "package",
            "config",
            "credentialRefs",
        }:
            raise CatalogError(f"extension_keys_invalid:{ref}")
        if row.get("kind") not in {"extension", "plugin"}:
            raise CatalogError(f"extension_kind_invalid:{ref}")
        _required_string(
            row.get("mcpCapability"),
            f"extension_mcp_capability_invalid:{ref}",
            REF_PATTERN,
        )
        _required_string(
            row.get("deliveryKey"),
            f"extension_delivery_key_invalid:{ref}",
            DELIVERY_KEY_PATTERN,
        )
        enabled_profiles = _string_list(
            row.get("enabledProfiles"),
            f"extension_profiles_invalid:{ref}",
        )
        if any(profile_ref not in profile_by_ref for profile_ref in enabled_profiles):
            raise CatalogError(f"extension_profile_unknown:{ref}")

        package = _object(row.get("package"), f"extension_package_invalid:{ref}")
        kind = package.get("kind")
        package_ref = _required_string(
            package.get("ref"), f"extension_package_unpinned:{ref}"
        )
        if kind == "runtime":
            versions = [
                profile_by_ref[profile_ref]
                .get("runtimePackages", {})
                .get(package_ref)
                for profile_ref in enabled_profiles
            ]
            if set(package) != {"kind", "ref"} or any(
                not _runtime_package_is_pinned(version) for version in versions
            ):
                raise CatalogError(f"extension_package_unpinned:{ref}")
        elif kind == "npm":
            if (
                set(package) != {"kind", "ref", "versionRef", "integrityRef"}
                or not re.fullmatch(r"@?[a-z0-9][a-z0-9._/-]*", package_ref)
                or not ENV_PATTERN.fullmatch(str(package.get("versionRef", "")))
                or not ENV_PATTERN.fullmatch(str(package.get("integrityRef", "")))
            ):
                raise CatalogError(f"extension_package_unpinned:{ref}")
        elif kind == "local":
            if (
                set(package) != {"kind", "ref", "integrityRef"}
                or package_ref.startswith(("/", "."))
                or ".." in Path(package_ref).parts
                or not LOCAL_PACKAGE_REF_PATTERN.fullmatch(package_ref)
                or not ENV_PATTERN.fullmatch(str(package.get("integrityRef", "")))
            ):
                raise CatalogError(f"extension_package_unpinned:{ref}")
        else:
            raise CatalogError(f"extension_package_kind_invalid:{ref}")

        config = _object(row.get("config"), f"extension_config_invalid:{ref}")
        _required_string(config.get("mode"), f"extension_config_mode_invalid:{ref}")
        if _unsafe_credential_config_keys(config):
            raise CatalogError(f"extension_credential_literal_forbidden:{ref}")
        config_refs = _config_refs(config)
        if any(not ENV_PATTERN.fullmatch(item) for item in config_refs):
            raise CatalogError(f"extension_config_ref_invalid:{ref}")
        credential_refs = _string_list(
            row.get("credentialRefs"),
            f"extension_credentials_invalid:{ref}",
            env=True,
            allow_empty=True,
        )
        used_credential_refs = _config_refs(config, credential_only=True)
        if not used_credential_refs.issubset(set(credential_refs)):
            raise CatalogError(f"extension_credential_undeclared:{ref}")
        if set(credential_refs) != used_credential_refs:
            raise CatalogError(f"extension_credential_unused:{ref}")
        for profile_ref in enabled_profiles:
            env_allowlist = set(
                profile_by_ref[profile_ref]["runtimeContract"]["envAllowlist"]
            )
            if not set(credential_refs).issubset(env_allowlist):
                raise CatalogError(f"extension_credential_not_allowed:{ref}")

    if len(refs) != len(set(refs)):
        raise CatalogError("extension_ref_duplicate")
    return rows


def _runtime_package_is_pinned(value: Any) -> bool:
    version = str(value or "")
    return bool(
        version
        and version.lower() not in {"latest", "next", "*"}
        and not version.startswith(("^", "~", ">", "<", "="))
        and " " not in version
        and "||" not in version
        and not version.endswith((".*", ".x"))
    )


def _validate_profile_extension_bindings(
    profiles: tuple[dict[str, Any]], extensions: tuple[dict[str, Any], ...]
) -> None:
    """Bind each profile's declared MCP delivery to the extension registry.

    Selection belongs to the profile; the registry's ``enabledProfiles`` is a
    checked reverse index retained for deployment-time configuration rendering.
    Requiring both directions to agree keeps the R1 Codex, Claude, and Pi
    profiles legible while preventing a profile from silently acquiring an MCP
    extension through a distant allow-list.
    """
    extension_by_ref = {str(row["ref"]): row for row in extensions}
    consumers: dict[str, list[str]] = {ref: [] for ref in extension_by_ref}
    for profile in profiles:
        profile_ref = str(profile["ref"])
        selected_refs = _string_list(
            profile.get("extensions"),
            f"profile_extensions_invalid:{profile_ref}",
            allow_empty=True,
        )
        if any(extension_ref not in extension_by_ref for extension_ref in selected_refs):
            raise CatalogError(f"profile_extension_unknown:{profile_ref}")
        for extension_ref in selected_refs:
            consumers[extension_ref].append(profile_ref)

        policy = _object(
            profile.get("mcpPolicy"), f"profile_mcp_policy_invalid:{profile_ref}"
        )
        allowed_capabilities = set(
            _string_list(policy.get("allow"), f"profile_mcp_allow_invalid:{profile_ref}")
        )
        expected_delivery_keys = {
            str(extension_by_ref[extension_ref]["deliveryKey"])
            for extension_ref in selected_refs
        }
        selected_capabilities = {
            str(extension_by_ref[extension_ref]["mcpCapability"])
            for extension_ref in selected_refs
        }
        if not selected_capabilities.issubset(allowed_capabilities):
            raise CatalogError(f"profile_extension_capability_not_allowed:{profile_ref}")
        delivery = _object(
            profile.get("toolDelivery"),
            f"profile_tool_delivery_invalid:{profile_ref}",
        )
        if set(delivery) != expected_delivery_keys:
            raise CatalogError(f"profile_extension_delivery_drift:{profile_ref}")

    for extension_ref, profile_refs in consumers.items():
        extension = extension_by_ref[extension_ref]
        declared_profiles = set(extension["enabledProfiles"])
        if declared_profiles != set(profile_refs):
            raise CatalogError(f"profile_extension_scope_drift:{extension_ref}")


def _validate_skill_packages(
    value: Any, profiles: tuple[dict[str, Any], ...]
) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or not value:
        raise CatalogError("skill_package_catalog_invalid")
    packages: dict[str, dict[str, Any]] = {}
    required_keys = {
        "source",
        "projection",
        "manifest",
        "manifestSha256",
        "metadata",
        "metadataSha256",
        "contractId",
        "nativeDestinations",
    }

    def relative_path(raw: Any, code: str) -> Path:
        value = _required_string(raw, code)
        path = Path(value)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
            raise CatalogError(code)
        return path

    for ref, raw in value.items():
        _required_string(ref, "skill_package_ref_invalid", REF_PATTERN)
        package = _object(raw, f"skill_package_invalid:{ref}")
        if set(package) != required_keys:
            raise CatalogError(f"skill_package_keys_invalid:{ref}")
        source = relative_path(
            package.get("source"), f"skill_package_source_invalid:{ref}"
        )
        projection = relative_path(
            package.get("projection"), f"skill_package_projection_invalid:{ref}"
        )
        manifest = relative_path(
            package.get("manifest"), f"skill_package_manifest_invalid:{ref}"
        )
        metadata = relative_path(
            package.get("metadata"), f"skill_package_metadata_invalid:{ref}"
        )
        if (
            source.parts[:1] != ("skills",)
            or source.name != ref
            or projection.parts[:4] != ("runtime", "paperclip", "profiles", "skills")
            or projection.name != ref
            or manifest.as_posix() != "SKILL.md"
            or metadata.as_posix() != "agents/openai.yaml"
        ):
            raise CatalogError(f"skill_package_layout_invalid:{ref}")
        for key in ("manifestSha256", "metadataSha256"):
            if not re.fullmatch(r"[a-f0-9]{64}", str(package.get(key, ""))):
                raise CatalogError(f"skill_package_hash_invalid:{ref}:{key}")
        if not re.fullmatch(
            r"[a-z0-9][a-z0-9._-]{2,127}", str(package.get("contractId", ""))
        ):
            raise CatalogError(f"skill_package_contract_invalid:{ref}")
        destinations = _object(
            package.get("nativeDestinations"),
            f"skill_package_destinations_invalid:{ref}",
        )
        for harness, destination_raw in destinations.items():
            _required_string(
                harness, f"skill_package_harness_invalid:{ref}", REF_PATTERN
            )
            destination = Path(
                _required_string(
                    destination_raw, f"skill_package_destination_invalid:{ref}"
                )
            )
            if (
                not destination.is_absolute()
                or ".." in destination.parts
                or destination.name != ref
                or destination.as_posix() != destination_raw
            ):
                raise CatalogError(f"skill_package_destination_invalid:{ref}")
        if len(destinations) != len(set(destinations.values())):
            raise CatalogError(f"skill_package_destination_duplicate:{ref}")
        packages[ref] = package

    for profile in profiles:
        profile_ref = str(profile["ref"])
        skills = _string_list(
            profile.get("skills"), f"profile_skills_invalid:{profile_ref}"
        )
        harness = str(profile["runtimeContract"]["harnessKind"])
        for skill_ref in skills:
            package = packages.get(skill_ref)
            if package is None:
                raise CatalogError(f"profile_skill_unknown:{profile_ref}:{skill_ref}")
            if harness not in package["nativeDestinations"]:
                raise CatalogError(
                    f"profile_skill_destination_missing:{profile_ref}:{skill_ref}"
                )
    return packages


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
    extensions = _validate_extensions(document.get("extensions"), profiles)
    _validate_profile_extension_bindings(profiles, extensions)
    skill_packages = _validate_skill_packages(document.get("skillPackages"), profiles)
    if require_rendered and PLACEHOLDER_PATTERN.search(
        canonical_json({"profiles": profiles}).decode()
    ):
        raise CatalogError("profile_catalog_runtime_not_rendered")
    return ProfileCatalog(
        document=document,
        profiles=profiles,
        refs=refs,
        by_ref={str(profile["ref"]): profile for profile in profiles},
        extensions=extensions,
        by_extension_ref={str(row["ref"]): row for row in extensions},
        skill_packages=skill_packages,
        semantic_sha256=semantic_sha256(document),
    )

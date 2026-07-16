#!/usr/bin/env python3
"""Reviewed provider-bundle contract for the platform data/docs plane.

The canonical environment selects only a bundle id.  All component, role and
adapter wiring is loaded from the checked-in platform lock; no environment
value is ever interpreted as a path or executable.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
from typing import Any


CONTRACT_REVISION = 2
PROFILE_REF = "DATA_CONTENT_PROFILE"
REGISTRY_SECTION = "dataContentProfiles"
PROJECTION_RELATIVE_PATH = "config/data-content-plane.json"
REQUIRED_ROLES = (
    "tablesUi",
    "tablesApi",
    "documentsUi",
    "documentsApi",
)
NOTION_PROJECTION_CONSUMER_REFS = {
    "batchSizeRef": "NOTION_SYNC_BATCH_SIZE",
    "maxAttemptsRef": "NOTION_SYNC_MAX_ATTEMPTS",
    "leaseSecondsRef": "NOTION_SYNC_LEASE_SECONDS",
    "retryBaseSecondsRef": "NOTION_SYNC_RETRY_BASE_SECONDS",
    "intervalSecondsRef": "NOTION_SYNC_INTERVAL_SECONDS",
}
REVIEWED_PROFILE_IDS = (
    "postgres-notion",
    "baserow-wikijs",
    "postgres-postgrest-nocodb-nocodocs",
)
REVIEWED_ADAPTER_ROWS = (
    (
        "notion",
        "server-notion.py",
        "notion",
        None,
        ("tables", "documents"),
        ("provision", "verify"),
    ),
    (
        "baserow",
        "server-baserow.py",
        "baserow",
        "baserow",
        ("tables",),
        ("database", "provision", "verify"),
    ),
    (
        "wikijs",
        "server-wikijs.py",
        "wikijs",
        "wikijs",
        ("documents",),
        ("database", "provision", "verify"),
    ),
    (
        "postgrest",
        "server-postgrest.py",
        "postgrest",
        "postgrest",
        ("data",),
        ("database", "provision", "verify"),
    ),
    (
        "nocodb",
        "server-nocodb.py",
        "nocodb",
        "nocodb",
        ("tables", "documents"),
        ("database", "provision", "verify"),
    ),
)
REVIEWED_PROJECTION_CONSUMERS = {
    "notion": {
        "script": "server-notion-sync.py",
        "actions": ("provision", "drain", "status", "verify"),
    },
}
OSI_LICENSES = {
    "AGPL-3.0-only",
    "Apache-2.0",
    "BSD-3-Clause",
    "GPL-3.0-only",
    "MIT",
}
REVIEWED_LICENSE_EXCEPTIONS = {
    "LicenseRef-NocoDB-Sustainable-Use-1.0": {
        "component": "nocodb",
        "scope": "internal-self-hosted-tables-ui-and-nocodocs",
        "approval": "user-approved-2026-07-15",
        "source": "https://github.com/nocodb/nocodb/blob/2026.06.2/LICENSE.md",
    }
}
PROFILE_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
ENV_KEY_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
PREFIX_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*_$")
SCRIPT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*\.py$")
IMAGE_PATTERN = re.compile(r"^[^\s@]+(?::[^\s@]+)?@sha256:[0-9a-f]{64}$")
CAPABILITY_INTERFACES = {"sql", "ui", "api", "mcp"}
PROVIDER_KINDS = {
    "system-of-record",
    "internal-scoped-api",
    "external-workspace",
    "self-hosted-workspace",
}
PROVIDER_DEPLOYMENTS = {"core", "profile-component", "external"}
ROLE_CONTRACT = {
    "tablesUi": ("tables", "ui"),
    "tablesApi": ("tables", "api"),
    "documentsUi": ("documents", "ui"),
    "documentsApi": ("documents", "api"),
}
STALE_CREDENTIAL_PATTERN = re.compile(
    r"(?:(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|WEBHOOK|_PAT)"
    r"(?!_(?:NAME|EXPIRATION|EXPIRES|ENABLED)(?:_|$))|_ID$)",
    re.IGNORECASE,
)


class DataContentError(RuntimeError):
    """The reviewed data/content contract is missing, stale, or unsafe."""


def _exact_keys(value: Any, expected: set[str], location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DataContentError(f"{location} must be an object")
    actual = set(value)
    if actual != expected:
        missing = ",".join(sorted(expected - actual)) or "-"
        extra = ",".join(sorted(actual - expected)) or "-"
        raise DataContentError(
            f"{location} schema mismatch; missing={missing}; extra={extra}"
        )
    return value


def _canonical_json_sha(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _path_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_platform_contract(config: dict[str, Any]) -> dict[str, Any]:
    spec = config.get("spec")
    if not isinstance(spec, dict):
        raise DataContentError("platform config spec must be an object")
    contract = _exact_keys(
        spec.get("dataContentPlane"),
        {
            "profileRef",
            "registrySection",
            "requiredRoles",
            "projectionPath",
            "notionProjectionConsumer",
        },
        "spec.dataContentPlane",
    )
    if contract["profileRef"] != PROFILE_REF:
        raise DataContentError(
            f"spec.dataContentPlane.profileRef must be {PROFILE_REF}"
        )
    if contract["registrySection"] != REGISTRY_SECTION:
        raise DataContentError(
            f"spec.dataContentPlane.registrySection must be {REGISTRY_SECTION}"
        )
    if contract["projectionPath"] != PROJECTION_RELATIVE_PATH:
        raise DataContentError(
            "spec.dataContentPlane.projectionPath must use the reviewed config path"
        )
    roles = contract["requiredRoles"]
    if not isinstance(roles, list) or tuple(roles) != REQUIRED_ROLES:
        raise DataContentError(
            "spec.dataContentPlane.requiredRoles must match the exact logical-role contract"
        )
    consumer = _exact_keys(
        contract["notionProjectionConsumer"],
        set(NOTION_PROJECTION_CONSUMER_REFS),
        "spec.dataContentPlane.notionProjectionConsumer",
    )
    if consumer != NOTION_PROJECTION_CONSUMER_REFS:
        raise DataContentError(
            "spec.dataContentPlane.notionProjectionConsumer refs are not canonical"
        )
    return contract


def _reviewed_adapters() -> dict[str, dict[str, Any]]:
    return {
        adapter_id: {
            "script": script,
            "providerId": provider_id,
            "componentId": component_id,
            "capabilities": list(capabilities),
            "actions": list(actions),
        }
        for (
            adapter_id,
            script,
            provider_id,
            component_id,
            capabilities,
            actions,
        ) in REVIEWED_ADAPTER_ROWS
    }


def _validate_role(
    profile_id: str,
    role_id: str,
    row: Any,
    providers: dict[str, dict[str, Any]],
    adapters: dict[str, dict[str, Any]],
) -> None:
    role = _exact_keys(
        row,
        {"providerId", "capability", "interface", "endpointRef", "adapterId"},
        f"spec.{REGISTRY_SECTION}.{profile_id}.roles.{role_id}",
    )
    expected_capability, expected_interface = ROLE_CONTRACT[role_id]
    if (
        role["capability"] != expected_capability
        or role["interface"] != expected_interface
    ):
        raise DataContentError(
            f"{profile_id}/{role_id} capability/interface differs from the logical-role contract"
        )
    provider = providers.get(str(role["providerId"]))
    if not provider:
        raise DataContentError(
            f"{profile_id}/{role_id} references an undeclared provider"
        )
    adapter = adapters.get(str(role["adapterId"]))
    if not adapter:
        raise DataContentError(
            f"{profile_id}/{role_id} references an undeclared adapter"
        )
    provider_capability = provider["capabilities"].get(str(role["capability"]), {})
    provider_interfaces = (
        provider_capability.get("interfaces")
        if isinstance(provider_capability, dict)
        else []
    )
    if role["interface"] not in provider_interfaces:
        raise DataContentError(
            f"{profile_id}/{role_id} is not provided by its declared provider capability"
        )
    if (
        adapter["providerId"] != role["providerId"]
        or role["capability"] not in adapter["capabilities"]
    ):
        raise DataContentError(
            f"{profile_id}/{role_id} adapter/provider capability mismatch"
        )
    if not isinstance(role["endpointRef"], str) or not ENV_KEY_PATTERN.fullmatch(
        role["endpointRef"]
    ):
        raise DataContentError(f"{profile_id}/{role_id} has an invalid endpoint ref")


def _validate_provider(
    profile_id: str,
    provider_id: str,
    row: Any,
    component_ids: set[str],
) -> dict[str, Any]:
    provider = _exact_keys(
        row,
        {"kind", "deployment", "componentId", "capabilities", "adapterIds"},
        f"spec.{REGISTRY_SECTION}.{profile_id}.providers.{provider_id}",
    )
    if not PROFILE_PATTERN.fullmatch(provider_id):
        raise DataContentError(f"{profile_id} has invalid provider id {provider_id}")
    if provider["kind"] not in PROVIDER_KINDS:
        raise DataContentError(f"{profile_id}/{provider_id} has invalid provider kind")
    if provider["deployment"] not in PROVIDER_DEPLOYMENTS:
        raise DataContentError(
            f"{profile_id}/{provider_id} has invalid provider deployment"
        )
    component_id = provider["componentId"]
    if provider["deployment"] == "external":
        if component_id is not None:
            raise DataContentError(
                f"{profile_id}/{provider_id} external provider cannot claim a platform component"
            )
    elif not isinstance(component_id, str) or not PROFILE_PATTERN.fullmatch(
        component_id
    ):
        raise DataContentError(
            f"{profile_id}/{provider_id} requires a valid platform component"
        )
    elif (
        provider["deployment"] == "profile-component"
        and component_id not in component_ids
    ):
        raise DataContentError(
            f"{profile_id}/{provider_id} references an undeclared profile component"
        )
    elif provider["deployment"] == "core" and component_id in component_ids:
        raise DataContentError(
            f"{profile_id}/{provider_id} core component cannot be profile-filtered"
        )
    capabilities = provider["capabilities"]
    if not isinstance(capabilities, dict) or not capabilities:
        raise DataContentError(f"{profile_id}/{provider_id} capabilities are invalid")
    for capability_id, capability_row in capabilities.items():
        capability = _exact_keys(
            capability_row,
            {"interfaces", "configurationRefs"},
            f"spec.{REGISTRY_SECTION}.{profile_id}.providers.{provider_id}.capabilities.{capability_id}",
        )
        interfaces = capability["interfaces"]
        if (
            not PROFILE_PATTERN.fullmatch(str(capability_id))
            or not isinstance(interfaces, list)
            or not interfaces
            or len(interfaces) != len(set(interfaces))
            or any(interface not in CAPABILITY_INTERFACES for interface in interfaces)
        ):
            raise DataContentError(
                f"{profile_id}/{provider_id}/{capability_id} capability interfaces are invalid"
            )
        configuration_refs = capability["configurationRefs"]
        if (
            not isinstance(configuration_refs, list)
            or len(configuration_refs) != len(set(configuration_refs))
            or any(
                not isinstance(item, str) or not ENV_KEY_PATTERN.fullmatch(item)
                for item in configuration_refs
            )
        ):
            raise DataContentError(
                f"{profile_id}/{provider_id}/{capability_id} capability configurationRefs are invalid"
            )
    adapter_ids = provider["adapterIds"]
    if (
        not isinstance(adapter_ids, list)
        or len(adapter_ids) != len(set(adapter_ids))
        or any(not PROFILE_PATTERN.fullmatch(str(item)) for item in adapter_ids)
    ):
        raise DataContentError(f"{profile_id}/{provider_id} adapterIds are invalid")
    return provider


def validate_registry(lock: dict[str, Any]) -> dict[str, dict[str, Any]]:
    spec = lock.get("spec")
    if not isinstance(spec, dict):
        raise DataContentError("platform lock spec must be an object")
    registry = spec.get(REGISTRY_SECTION)
    if not isinstance(registry, dict):
        raise DataContentError(f"platform lock is missing spec.{REGISTRY_SECTION}")
    if tuple(sorted(registry)) != tuple(sorted(REVIEWED_PROFILE_IDS)):
        raise DataContentError(
            "data/content registry profile set differs from the reviewed allowlist"
        )

    reviewed_adapters = _reviewed_adapters()
    for profile_id in REVIEWED_PROFILE_IDS:
        if not PROFILE_PATTERN.fullmatch(profile_id):
            raise DataContentError(f"invalid reviewed profile id {profile_id}")
        bundle = _exact_keys(
            registry.get(profile_id),
            {
                "contractVersion",
                "selectable",
                "contractComplete",
                "componentIds",
                "canonicalKeyPrefixes",
                "systemOfRecord",
                "providers",
                "internalApis",
                "images",
                "licenses",
                "licenseExceptions",
                "roles",
                "adapters",
                "activationBlockers",
            },
            f"spec.{REGISTRY_SECTION}.{profile_id}",
        )
        if bundle["contractVersion"] != CONTRACT_REVISION:
            raise DataContentError(f"{profile_id} contract version is unsupported")
        if not isinstance(bundle["selectable"], bool) or not isinstance(
            bundle["contractComplete"], bool
        ):
            raise DataContentError(f"{profile_id} lifecycle flags must be booleans")
        component_rows = bundle["componentIds"]
        if (
            not isinstance(component_rows, list)
            or not component_rows
            or len(component_rows) != len(set(component_rows))
            or any(not PROFILE_PATTERN.fullmatch(str(item)) for item in component_rows)
        ):
            raise DataContentError(f"{profile_id} componentIds are invalid")
        prefixes = bundle["canonicalKeyPrefixes"]
        if (
            not isinstance(prefixes, list)
            or not prefixes
            or len(prefixes) != len(set(prefixes))
            or any(not PREFIX_PATTERN.fullmatch(str(item)) for item in prefixes)
        ):
            raise DataContentError(f"{profile_id} canonical key prefixes are invalid")
        blockers = bundle["activationBlockers"]
        if not isinstance(blockers, list) or any(
            not isinstance(item, str) or not item for item in blockers
        ):
            raise DataContentError(f"{profile_id} activation blockers are invalid")
        roles = bundle["roles"]
        adapters = bundle["adapters"]
        providers = bundle["providers"]
        internal_apis = bundle["internalApis"]
        images = bundle["images"]
        licenses = bundle["licenses"]
        license_exceptions = bundle["licenseExceptions"]
        if (
            not isinstance(roles, dict)
            or not isinstance(adapters, dict)
            or not isinstance(providers, dict)
            or not isinstance(internal_apis, dict)
        ):
            raise DataContentError(
                f"{profile_id} roles, providers, adapters and internalApis must be objects"
            )
        if (
            not isinstance(images, dict)
            or not images
            or any(
                not PROFILE_PATTERN.fullmatch(str(component_id))
                or not isinstance(image, str)
                or not IMAGE_PATTERN.fullmatch(image)
                for component_id, image in images.items()
            )
        ):
            raise DataContentError(f"{profile_id} image pins are invalid")
        if not isinstance(license_exceptions, dict):
            raise DataContentError(f"{profile_id} licenseExceptions must be an object")
        non_osi = {
            str(component_id): str(license_id)
            for component_id, license_id in licenses.items()
            if license_id not in OSI_LICENSES
        }
        reviewed_exceptions = {
            str(row.get("component")): license_id
            for license_id, row in REVIEWED_LICENSE_EXCEPTIONS.items()
            if isinstance(row, dict)
        }
        if (
            not isinstance(licenses, dict)
            or set(licenses) != set(images)
            or non_osi
            != {
                component_id: license_id
                for component_id, license_id in reviewed_exceptions.items()
                if license_exceptions.get(component_id)
                == REVIEWED_LICENSE_EXCEPTIONS[license_id]
            }
            or set(license_exceptions) != set(non_osi)
        ):
            raise DataContentError(
                f"{profile_id} licenses must be OSI or an exact reviewed exception"
            )

        if bundle["selectable"]:
            if not bundle["contractComplete"] or blockers:
                raise DataContentError(
                    f"selectable profile {profile_id} is not contract-complete"
                )
            if set(roles) != set(REQUIRED_ROLES):
                raise DataContentError(
                    f"selectable profile {profile_id} lacks the exact logical-role set"
                )
            if not adapters:
                raise DataContentError(
                    f"selectable profile {profile_id} has no adapters"
                )
        else:
            if bundle["contractComplete"] or not blockers:
                raise DataContentError(
                    f"inactive profile {profile_id} must be explicitly contract-incomplete"
                )

        component_ids = set(component_rows)
        validated_providers = {
            str(provider_id): _validate_provider(
                profile_id, str(provider_id), row, component_ids
            )
            for provider_id, row in providers.items()
        }
        system_of_record = _exact_keys(
            bundle["systemOfRecord"],
            {"providerId", "componentId", "ownership"},
            f"spec.{REGISTRY_SECTION}.{profile_id}.systemOfRecord",
        )
        owner = validated_providers.get(str(system_of_record["providerId"]))
        if (
            system_of_record["providerId"] != "postgres"
            or system_of_record["componentId"] != "postgres"
            or not owner
            or owner["kind"] != "system-of-record"
            or owner["componentId"] != system_of_record["componentId"]
            or owner["deployment"] != "core"
            or "sql"
            not in owner.get("capabilities", {}).get("data", {}).get("interfaces", [])
            or system_of_record["ownership"] != "authoritative"
        ):
            raise DataContentError(
                f"{profile_id} must declare PostgreSQL-compatible authoritative system-of-record ownership"
            )

        for adapter_id, adapter_row in adapters.items():
            adapter = _exact_keys(
                adapter_row,
                {
                    "script",
                    "providerId",
                    "componentId",
                    "capabilities",
                    "actions",
                },
                f"spec.{REGISTRY_SECTION}.{profile_id}.adapters.{adapter_id}",
            )
            if (
                adapter_id not in reviewed_adapters
                or adapter != reviewed_adapters[adapter_id]
            ):
                raise DataContentError(
                    f"{profile_id}/{adapter_id} is not an allowlisted provider adapter"
                )
            if not SCRIPT_PATTERN.fullmatch(str(adapter["script"])):
                raise DataContentError(f"{profile_id}/{adapter_id} script is unsafe")
            provider = validated_providers.get(str(adapter["providerId"]))
            if not provider:
                raise DataContentError(
                    f"{profile_id}/{adapter_id} references an undeclared provider"
                )
            if adapter["componentId"] != provider["componentId"]:
                raise DataContentError(
                    f"{profile_id}/{adapter_id} provider/component mismatch"
                )
            if adapter_id not in provider["adapterIds"]:
                raise DataContentError(
                    f"{profile_id}/{adapter_id} is not claimed by its provider"
                )
            if any(
                capability not in provider["capabilities"]
                for capability in adapter["capabilities"]
            ):
                raise DataContentError(
                    f"{profile_id}/{adapter_id} declares unsupported provider capabilities"
                )
        claimed_adapters = {
            str(adapter_id)
            for provider in validated_providers.values()
            for adapter_id in provider["adapterIds"]
        }
        if claimed_adapters != set(adapters):
            raise DataContentError(
                f"{profile_id} provider adapter claims differ from declared adapters"
            )
        for role_id in REQUIRED_ROLES:
            _validate_role(
                profile_id,
                role_id,
                roles[role_id],
                validated_providers,
                adapters,
            )
        for api_id, api_row in internal_apis.items():
            if not PROFILE_PATTERN.fullmatch(str(api_id)):
                raise DataContentError(f"{profile_id} has invalid internal API id")
            api = _exact_keys(
                api_row,
                {"providerId", "capability", "interface", "endpointRef", "adapterId"},
                f"spec.{REGISTRY_SECTION}.{profile_id}.internalApis.{api_id}",
            )
            provider = validated_providers.get(str(api["providerId"]))
            adapter = adapters.get(str(api["adapterId"]))
            if (
                not provider
                or provider["kind"] != "internal-scoped-api"
                or provider["deployment"] != "profile-component"
                or api["interface"] != "api"
                or api["capability"] not in provider["capabilities"]
                or "api"
                not in provider["capabilities"][api["capability"]]["interfaces"]
                or not adapter
                or adapter["providerId"] != api["providerId"]
                or api["capability"] not in adapter["capabilities"]
                or not ENV_KEY_PATTERN.fullmatch(str(api["endpointRef"]))
            ):
                raise DataContentError(
                    f"{profile_id}/{api_id} internal scoped API contract is invalid"
                )
    return registry


def selectable_profiles(lock: dict[str, Any]) -> tuple[str, ...]:
    registry = validate_registry(lock)
    return tuple(
        profile_id
        for profile_id in REVIEWED_PROFILE_IDS
        if registry[profile_id]["selectable"] is True
    )


def selected_bundle(
    lock: dict[str, Any], values: dict[str, str]
) -> tuple[str, dict[str, Any], dict[str, dict[str, Any]]]:
    registry = validate_registry(lock)
    profile_id = str(values.get(PROFILE_REF, "")).strip()
    if profile_id not in registry:
        allowed = ",".join(selectable_profiles(lock))
        raise DataContentError(
            f"canonical {PROFILE_REF} is outside the exact allowlist: {allowed}"
        )
    bundle = registry[profile_id]
    if bundle["selectable"] is not True or bundle["contractComplete"] is not True:
        raise DataContentError(
            f"canonical {PROFILE_REF} selects inactive contract-incomplete profile {profile_id}"
        )
    stale_keys: list[str] = []
    selected_prefixes = set(bundle["canonicalKeyPrefixes"])
    for other_id, other in registry.items():
        if other_id == profile_id or other["selectable"] is not True:
            continue
        for prefix in other["canonicalKeyPrefixes"]:
            if prefix in selected_prefixes:
                continue
            stale_keys.extend(
                key
                for key, value in values.items()
                if key.startswith(prefix)
                and value
                and STALE_CREDENTIAL_PATTERN.search(key)
            )
    if stale_keys:
        raise DataContentError(
            "canonical platform.env contains stale keys for an unselected provider: "
            + ",".join(sorted(set(stale_keys)))
        )
    return profile_id, bundle, registry


def _unique_manifest_ids(
    value: Any, label: str, *, allow_empty: bool = False
) -> list[str]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise DataContentError(f"{label} must be a unique non-empty string list")
    return value


def provider_profile_catalog(
    config: dict[str, Any], lock: dict[str, Any]
) -> dict[str, dict[str, list[str]]]:
    """Validate the manifest-owned provider availability matrix.

    The lock owns immutable provider contracts.  The deployment manifest must
    independently and exactly declare both the provider set and deployable
    component set for every reviewed profile.  Components with
    ``enabledForProfiles`` are therefore selected from the manifest rather than
    inferred from the lock's component union.
    """

    spec = config.get("spec")
    if not isinstance(spec, dict):
        raise DataContentError("platform manifest spec must be an object")
    declared = spec.get("providerProfiles")
    if not isinstance(declared, dict) or not declared:
        raise DataContentError("spec.providerProfiles must be a non-empty object")

    registry = validate_registry(lock)
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
        raise DataContentError(
            "spec.providerProfiles differs from the locked profile registry: "
            + "; ".join(details)
        )

    component_rows = spec.get("components")
    if not isinstance(component_rows, list) or any(
        not isinstance(row, dict) for row in component_rows
    ):
        raise DataContentError("spec.components must be a list of objects")
    component_ids = [str(row.get("id") or "") for row in component_rows]
    if any(not component_id for component_id in component_ids) or len(
        component_ids
    ) != len(set(component_ids)):
        raise DataContentError("component ids must be unique non-empty strings")

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
            raise DataContentError(
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
            raise DataContentError(
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
            raise DataContentError(
                f"provider profile {profile_id} provider mapping differs from the lock"
            )
        locked_component_ids = {str(item) for item in bundle["componentIds"]}
        if set(selected_component_ids) != locked_component_ids:
            raise DataContentError(
                f"provider profile {profile_id} component mapping differs from the lock"
            )
        if enabled_components[profile_id] != locked_component_ids:
            raise DataContentError(
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
                raise DataContentError(
                    f"provider profile {profile_id} ambiguously maps component {component_id} "
                    f"to providers {previous} and {provider_id}"
                )
            component_claims[component_id] = provider_id
        if set(component_claims) != locked_component_ids:
            raise DataContentError(
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
                raise DataContentError(
                    f"provider profile {profile_id} leaves component {component_id} "
                    "with unavailable dependencies: " + ", ".join(unavailable)
                )
        result[profile_id] = {
            "providerIds": list(provider_ids),
            "componentIds": list(selected_component_ids),
        }
    return result


def _component_rows_for_profile(
    config: dict[str, Any], profile_id: str
) -> list[dict[str, Any]]:
    spec = config["spec"]
    components = spec["components"]
    return [
        row
        for row in components
        if "enabledForProfiles" not in row or profile_id in row["enabledForProfiles"]
    ]


def filter_platform_config(
    config: dict[str, Any], lock: dict[str, Any], values: dict[str, str]
) -> dict[str, Any]:
    validate_platform_contract(config)
    profile_id, bundle, _registry = selected_bundle(lock, values)
    catalog = provider_profile_catalog(config, lock)
    if profile_id not in catalog:
        raise DataContentError(
            f"unknown selected provider profile: {profile_id or '<empty>'}"
        )
    result = copy.deepcopy(config)
    result["spec"]["components"] = _component_rows_for_profile(result, profile_id)
    selected_components = set(catalog[profile_id]["componentIds"])
    if selected_components != set(bundle["componentIds"]):
        raise DataContentError(
            f"selected profile {profile_id} manifest and lock component mappings differ"
        )
    declared = {
        str(row.get("id")) for row in result["spec"]["components"] if row.get("id")
    }
    missing = sorted(selected_components - declared)
    if missing:
        raise DataContentError(
            "selected data/content components are missing from platform config: "
            + ",".join(missing)
        )
    return result


def resolve_bundle(
    config: dict[str, Any],
    lock: dict[str, Any],
    values: dict[str, str],
    *,
    source_sha256: str,
    config_sha256: str,
    lock_sha256: str,
    generator_version: str,
) -> dict[str, Any]:
    contract = validate_platform_contract(config)
    profile_id, bundle, registry = selected_bundle(lock, values)

    components = config.get("spec", {}).get("components", [])
    declared_components = {
        str(row.get("id"))
        for row in components
        if isinstance(row, dict) and row.get("id")
    }
    missing_components = sorted(set(bundle["componentIds"]) - declared_components)
    if missing_components:
        raise DataContentError(
            f"selected profile {profile_id} components are missing from "
            "config/platform.yaml: "
            + ",".join(missing_components)
        )
    missing_refs = sorted(
        {
            str(role["endpointRef"])
            for role in bundle["roles"].values()
            if not values.get(str(role["endpointRef"]), "").strip()
        }
    )
    if missing_refs:
        raise DataContentError(
            f"selected profile {profile_id} endpoint refs are unresolved: "
            + ",".join(missing_refs)
        )

    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "DataContentPlane",
        "contractVersion": CONTRACT_REVISION,
        "profile": profile_id,
        "selectableProfiles": list(selectable_profiles(lock)),
        "componentIds": list(bundle["componentIds"]),
        "systemOfRecord": bundle["systemOfRecord"],
        "providers": bundle["providers"],
        "internalApis": bundle["internalApis"],
        "roles": bundle["roles"],
        "adapters": bundle["adapters"],
        "images": bundle["images"],
        "licenses": bundle["licenses"],
        "licenseExceptions": bundle["licenseExceptions"],
        "canonicalKeyPrefixes": list(bundle["canonicalKeyPrefixes"]),
        "binding": {
            "sourceSha256": source_sha256,
            "platformConfigSha256": config_sha256,
            "platformLockSha256": lock_sha256,
            "contractSha256": _canonical_json_sha(contract),
            "registrySha256": _canonical_json_sha(registry),
            "bundleSha256": _canonical_json_sha(bundle),
        },
        "_generated": {
            "doNotEdit": True,
            "sourceSha256": source_sha256,
            "generatorVersion": generator_version,
        },
    }
    return payload


def resolve_from_paths(
    config: dict[str, Any],
    lock: dict[str, Any],
    values: dict[str, str],
    *,
    config_path: Path,
    lock_path: Path,
    source_sha256: str,
    generator_version: str,
) -> dict[str, Any]:
    return resolve_bundle(
        config,
        lock,
        values,
        source_sha256=source_sha256,
        config_sha256=_path_sha(config_path),
        lock_sha256=_path_sha(lock_path),
        generator_version=generator_version,
    )


def adapter_commands(plane: dict[str, Any], action: str) -> list[tuple[str, str]]:
    if action not in {"database", "provision", "verify"}:
        raise DataContentError(f"unknown data/content adapter action {action}")
    adapters = plane.get("adapters")
    if not isinstance(adapters, dict):
        raise DataContentError("data/content projection adapters are invalid")
    commands: list[tuple[str, str]] = []
    reviewed = _reviewed_adapters()
    for adapter_id, row in adapters.items():
        if adapter_id not in reviewed or row != reviewed[adapter_id]:
            raise DataContentError(
                f"projection adapter {adapter_id} is not allowlisted"
            )
        if action in row["actions"]:
            commands.append((str(row["script"]), action))
    return commands


def projection_consumer_commands(
    plane: dict[str, Any], action: str
) -> list[tuple[str, str]]:
    """Resolve background projection consumers from active connector adapters.

    PostgreSQL ownership is independent of the selected table/document frontend.
    A connector can therefore add its own outbox consumer without teaching the
    top-level deployment index about a concrete provider profile.
    """

    if action not in {"provision", "drain", "status", "verify"}:
        raise DataContentError(f"unknown data/content projection action {action}")
    adapters = plane.get("adapters")
    if not isinstance(adapters, dict):
        raise DataContentError("data/content projection adapters are invalid")
    reviewed = _reviewed_adapters()
    commands: list[tuple[str, str]] = []
    for adapter_id, row in adapters.items():
        if adapter_id not in reviewed or row != reviewed[adapter_id]:
            raise DataContentError(
                f"projection adapter {adapter_id} is not allowlisted"
            )
        consumer = REVIEWED_PROJECTION_CONSUMERS.get(adapter_id)
        if consumer and action in consumer["actions"]:
            commands.append((str(consumer["script"]), action))
    return commands


def role_component(plane: dict[str, Any], role_id: str) -> str:
    if role_id not in REQUIRED_ROLES:
        raise DataContentError(f"unknown logical data/content role {role_id}")
    roles = plane.get("roles")
    row = roles.get(role_id) if isinstance(roles, dict) else None
    if not isinstance(row, dict) or not isinstance(row.get("providerId"), str):
        raise DataContentError(f"projection is missing logical role {role_id}")
    providers = plane.get("providers")
    provider = (
        providers.get(str(row["providerId"])) if isinstance(providers, dict) else None
    )
    component_id = provider.get("componentId") if isinstance(provider, dict) else None
    if not isinstance(component_id, str) or not component_id:
        raise DataContentError(
            f"logical role {role_id} is external and has no platform component dependency"
        )
    return component_id

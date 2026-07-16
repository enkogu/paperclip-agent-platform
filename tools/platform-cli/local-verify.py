#!/usr/bin/env python3
"""Audit local platform reproducibility and write fail-closed JSON evidence."""

from __future__ import annotations

import argparse
from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any
from unittest import mock

import yaml


TOOL_ROOT = Path(__file__).resolve().parent
ROOT = TOOL_ROOT.parents[1]
if str(TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOL_ROOT))

from profile_catalog import CatalogError, load_profile_catalog  # noqa: E402


EVIDENCE_ROOT = ROOT / ".runtime" / "evidence"
PLATFORM_SOURCE = ROOT / "config/platform.yaml"
PLATFORM_LOCK_SOURCE = ROOT / "config/platform.lock.yaml"
CONNECTIONS_SOURCE = ROOT / "config/connections.yaml"
COMPOSE_SEED_SOURCE = ROOT / "config/compose-seeds.lock.json"
PROFILE_CATALOG_SOURCE = ROOT / "config/profiles/catalog.yaml"
PROFILE_SOURCE_ROOT = ROOT / "config/profiles"
SERVICES_SOURCE_ROOT = ROOT / "deployment/services"
PUBLIC_ENV_KEYS = {
    "BASEROW_PUBLIC_URL",
    "WIKIJS_SITE_URL",
    "MATTERMOST_SITE_URL",
    "AP_FRONTEND_URL",
    "SEARXNG_BASE_URL",
}
# External networks created by host bootstrap rather than by a Compose project.
# The mapping names the canonical env ref and its platform dependency owner;
# mutable network names remain in platform.env.
EXTERNAL_NETWORK_PROVISIONER_REFS = {
    "MTE_AGENT_PLANE_NETWORK": "dokploy",
}
IMAGE_PATTERN = re.compile(r"@sha256:[0-9a-f]{64}$")
ENV_REQUIRED_PATTERN = re.compile(r"\$\{([A-Z][A-Z0-9_]*):\?")
ENV_EXACT_REQUIRED_PATTERN = re.compile(r"\$\{([A-Z][A-Z0-9_]*):\?[^}]*\}")


def canonical_compose_sources() -> list[Path]:
    return sorted(SERVICES_SOURCE_ROOT.glob("*/compose.yaml"))


def compose_projection_name(source: Path) -> str:
    return f"{source.parent.name}.yaml"


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_source_binding() -> dict[str, Any]:
    """Bind local evidence to its producer and reviewed source contracts."""
    sources = {
        path.relative_to(ROOT).as_posix(): sha256_path(path)
        for path in (
            PLATFORM_SOURCE,
            PLATFORM_LOCK_SOURCE,
            CONNECTIONS_SOURCE,
            COMPOSE_SEED_SOURCE,
            PROFILE_CATALOG_SOURCE,
        )
    }
    contract = json.dumps(
        sources, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    producer = Path(__file__).resolve()
    return {
        "producer": {
            "path": producer.relative_to(ROOT).as_posix(),
            "sha256": sha256_path(producer),
        },
        "canonicalSources": sources,
        "canonicalSourcesSha256": hashlib.sha256(contract).hexdigest(),
    }


def command(argv: list[str], timeout: int = 60) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        return {
            "ok": completed.returncode == 0,
            "state": "passed" if completed.returncode == 0 else "failed",
            "exitCode": completed.returncode,
            "durationSeconds": round(time.monotonic() - started, 3),
            "outputTail": completed.stdout[-4000:],
        }
    except subprocess.TimeoutExpired as exc:
        output = (
            exc.stdout.decode(errors="replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or "")
        )
        return {
            "ok": False,
            "state": "timeout",
            "durationSeconds": round(time.monotonic() - started, 3),
            "outputTail": output[-4000:],
        }
    except OSError as exc:
        return {
            "ok": False,
            "state": "unavailable",
            "errorType": type(exc).__name__,
            "durationSeconds": round(time.monotonic() - started, 3),
        }


def record(name: str, ok: bool, **details: Any) -> dict[str, Any]:
    return {
        "name": name,
        "ok": ok,
        "state": "passed" if ok else details.pop("state", "failed"),
        **details,
    }


def yaml_documents() -> tuple[dict[Path, Any], list[dict[str, Any]]]:
    documents: dict[Path, Any] = {}
    findings: list[dict[str, Any]] = []
    paths = sorted(
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and path.suffix in {".yaml", ".yml"}
        and ".orig" not in path.name
        and ".runtime" not in path.parts
    )
    for path in paths:
        try:
            documents[path] = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            findings.append(
                {
                    "path": str(path.relative_to(ROOT)),
                    "finding": "yaml_parse_error",
                    "error": str(exc)[:300],
                }
            )
    return documents, findings


def platform_consistency(documents: dict[Path, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    platform_path = PLATFORM_SOURCE
    platform = documents.get(platform_path)
    components = (
        platform.get("spec", {}).get("components", [])
        if isinstance(platform, dict)
        else []
    )
    if not isinstance(components, list):
        return record(
            "platform-consistency",
            False,
            findings=[{"finding": "components_not_a_list"}],
        )
    ids: set[str] = set()
    rows: dict[str, dict] = {}
    for component in components:
        if not isinstance(component, dict):
            findings.append({"finding": "component_not_an_object"})
            continue
        component_id = str(component.get("id", ""))
        if not component_id or component_id in ids:
            findings.append(
                {
                    "component": component_id or None,
                    "finding": "missing_or_duplicate_id",
                }
            )
        ids.add(component_id)
        rows[component_id] = component
        if component.get("required") is not True:
            findings.append(
                {"component": component_id, "finding": "required_not_explicitly_true"}
            )
        if not component.get("compose") and not component.get("management"):
            findings.append(
                {"component": component_id, "finding": "no_management_method"}
            )
        if not isinstance(component.get("health"), dict) or not component.get("health"):
            findings.append(
                {"component": component_id, "finding": "health_not_configured"}
            )
        for dependency in component.get("dependsOn", []):
            if dependency not in {
                str(item.get("id", "")) for item in components if isinstance(item, dict)
            }:
                findings.append(
                    {
                        "component": component_id,
                        "finding": "unknown_dependency",
                        "dependency": dependency,
                    }
                )

    compose_paths = {
        path.relative_to(ROOT).as_posix()
        for path in canonical_compose_sources()
    }
    declared_paths = {
        str(row["compose"])
        for row in components
        if isinstance(row, dict) and row.get("compose")
    }
    for missing in sorted(declared_paths - compose_paths):
        findings.append({"path": missing, "finding": "declared_compose_missing"})
    for undeclared in sorted(compose_paths - declared_paths):
        findings.append({"path": undeclared, "finding": "compose_not_declared"})

    # Every external Compose network must be created by a component that is in
    # the consumer's transitive dependency closure.
    producers: dict[str, set[str]] = {}
    external: dict[str, set[str]] = {}
    for component_id, component in rows.items():
        compose_ref = component.get("compose")
        if not compose_ref:
            continue
        document = documents.get(ROOT / str(compose_ref), {})
        networks = document.get("networks", {}) if isinstance(document, dict) else {}
        for logical, definition in (networks or {}).items():
            definition = definition or {}
            name = (
                str(definition.get("name", logical))
                if isinstance(definition, dict)
                else str(logical)
            )
            target = (
                external
                if isinstance(definition, dict) and definition.get("external") is True
                else producers
            )
            target.setdefault(name, set()).add(component_id)

    def closure(component_id: str) -> set[str]:
        result: set[str] = set()
        pending = list(rows[component_id].get("dependsOn", []))
        while pending:
            item = pending.pop()
            if item in result or item not in rows:
                continue
            result.add(item)
            pending.extend(rows[item].get("dependsOn", []))
        return result

    for network, consumers in external.items():
        owners = producers.get(network, set())
        network_ref = ENV_EXACT_REQUIRED_PATTERN.fullmatch(network)
        if not owners and network_ref:
            provisioner = EXTERNAL_NETWORK_PROVISIONER_REFS.get(network_ref.group(1))
            if provisioner:
                owners = {provisioner}
        if not owners:
            findings.append(
                {
                    "network": network,
                    "finding": "external_network_has_no_declared_owner",
                }
            )
            continue
        for consumer in consumers:
            if not (owners & closure(consumer)):
                findings.append(
                    {
                        "component": consumer,
                        "network": network,
                        "finding": "external_network_owner_not_a_dependency",
                        "owners": sorted(owners),
                    }
                )

    return record(
        "platform-consistency",
        not findings,
        componentCount=len(rows),
        composeCount=len(declared_paths),
        findings=findings,
    )


def compose_static(documents: dict[Path, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    platform = documents[PLATFORM_SOURCE]
    rows = {row["id"]: row for row in platform["spec"]["components"]}
    seed_catalog = json.loads(COMPOSE_SEED_SOURCE.read_text())
    catalog_values = (
        seed_catalog.get("seeds", {}) if isinstance(seed_catalog, dict) else {}
    )
    os.environ["MTE_PLATFORM_ROOT"] = str(ROOT)
    try:
        spec = importlib.util.spec_from_file_location(
            "mte_compose_static_config", TOOL_ROOT / "server-config.py"
        )
        server_config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(server_config)
    finally:
        os.environ.pop("MTE_PLATFORM_ROOT", None)
    declared_runtime_refs = (
        set(catalog_values)
        | set(server_config.ONE_TIME_MIGRATION_SEEDS)
        | set(server_config.DERIVED_VALUE_KEYS)
    )
    for component_id, row in rows.items():
        if not row.get("compose"):
            continue
        path = ROOT / row["compose"]
        document = documents.get(path)
        services = document.get("services") if isinstance(document, dict) else None
        if not isinstance(services, dict) or not services:
            findings.append(
                {"component": component_id, "finding": "compose_services_missing"}
            )
            continue
        required_refs = set(ENV_REQUIRED_PATTERN.findall(path.read_text()))
        declared_refs = (
            set(row.get("secrets", [])) | PUBLIC_ENV_KEYS | declared_runtime_refs
        )
        for missing in sorted(required_refs - declared_refs):
            findings.append(
                {
                    "component": component_id,
                    "finding": "required_env_not_declared",
                    "key": missing,
                }
            )
        for service_name, service in services.items():
            service = service or {}
            image = str(service.get("image", ""))
            image_match = ENV_EXACT_REQUIRED_PATTERN.fullmatch(image)
            if image_match:
                image = str(catalog_values.get(image_match.group(1), ""))
            if not IMAGE_PATTERN.search(image):
                findings.append(
                    {
                        "component": component_id,
                        "service": service_name,
                        "finding": "image_not_digest_pinned",
                        "image": image,
                    }
                )
            for port in service.get("ports", []) or []:
                rendered = str(port)
                port_match = ENV_EXACT_REQUIRED_PATTERN.fullmatch(rendered)
                if port_match:
                    rendered = str(catalog_values.get(port_match.group(1), ""))
                if not rendered.startswith("127.0.0.1:"):
                    findings.append(
                        {
                            "component": component_id,
                            "service": service_name,
                            "finding": "port_not_loopback",
                            "port": rendered,
                        }
                    )
            for volume in service.get("volumes", []) or []:
                source = None
                if isinstance(volume, str):
                    source = volume.split(":", 1)[0]
                elif isinstance(volume, dict) and volume.get("type") == "bind":
                    source = volume.get("source") or volume.get("src")
                if source in {"/run/docker.sock", "/var/run/docker.sock"}:
                    findings.append(
                        {
                            "component": component_id,
                            "service": service_name,
                            "finding": "host_docker_socket_present",
                        }
                    )
    return record("compose-static", not findings, findings=findings)


def configuration_source_static() -> dict[str, Any]:
    os.environ["MTE_PLATFORM_ROOT"] = str(ROOT)
    try:
        spec = importlib.util.spec_from_file_location(
            "mte_config_source_verify", TOOL_ROOT / "server-verify.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        os.environ.pop("MTE_PLATFORM_ROOT", None)
    findings = module.static_config_findings(ROOT)
    return record(
        "configuration-source-static",
        not findings,
        canonicalServerSource="/root/.config/mte-secrets/platform.env",
        projectionManifest="/root/.config/mte-secrets/projections-manifest.json",
        findings=findings,
    )


def connection_coverage() -> dict[str, Any]:
    registry = yaml.safe_load(CONNECTIONS_SOURCE.read_text())
    rows = registry.get("connections", []) if isinstance(registry, dict) else []
    findings: list[dict[str, Any]] = []
    ids: set[str] = set()
    required_fields = {"id", "from", "to", "required", "auth", "exposure", "check"}
    for row in rows:
        if not isinstance(row, dict):
            findings.append({"finding": "connection_not_an_object"})
            continue
        missing = sorted(required_fields - set(row))
        if missing:
            findings.append(
                {"id": row.get("id"), "finding": "missing_fields", "fields": missing}
            )
        if row.get("id") in ids:
            findings.append({"id": row.get("id"), "finding": "duplicate_id"})
        ids.add(row.get("id"))

    os.environ["MTE_PLATFORM_ROOT"] = str(ROOT)
    try:
        spec = importlib.util.spec_from_file_location(
            "mte_local_server_verify", TOOL_ROOT / "server-verify.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        os.environ.pop("MTE_PLATFORM_ROOT", None)
    implemented = set(module.CONNECTION_CHECK_COMPONENTS)
    required_checks = {
        str(row.get("check"))
        for row in rows
        if isinstance(row, dict) and row.get("required") is True
    }
    for missing in sorted(required_checks - implemented):
        findings.append(
            {"check": missing, "finding": "required_connection_check_not_implemented"}
        )
    return record(
        "connection-coverage",
        not findings,
        total=len(rows),
        required=sum(
            isinstance(row, dict) and row.get("required") is True for row in rows
        ),
        implemented=len(required_checks & implemented),
        findings=findings,
    )


def profile_coverage() -> dict[str, Any]:
    lock = yaml.safe_load(PLATFORM_LOCK_SOURCE.read_text())
    required_harnesses = set(lock.get("spec", {}).get("harnesses", {}))
    try:
        catalog = load_profile_catalog(PROFILE_CATALOG_SOURCE)
    except CatalogError as exc:
        return record(
            "profile-coverage",
            False,
            profiles=0,
            requiredHarnesses=sorted(required_harnesses),
            representedHarnesses=[],
            findings=[
                {
                    "finding": "profile_catalog_invalid",
                    "error": str(exc),
                }
            ],
        )
    profiles = list(catalog.profiles)
    spec = importlib.util.spec_from_file_location(
        "mte_profile_seed_source", TOOL_ROOT / "server-config.py"
    )
    server_config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(server_config)
    expected_profiles = {
        "coding-daytona-codex": ("codex", "codex_local"),
        "coding-daytona-claude": ("claudeCode", "claude_local"),
        "coding-daytona-pi": ("pi", "pi_local"),
    }
    represented = set()
    profile_refs = {str(profile.get("ref", "")) for profile in profiles}
    findings = [
        {"profile": ref, "finding": "required_profile_missing"}
        for ref in sorted(set(expected_profiles) - profile_refs)
    ]
    findings.extend(
        {"profile": ref, "finding": "unexpected_profile"}
        for ref in sorted(profile_refs - set(expected_profiles))
    )
    for profile in profiles:
        profile_ref = str(profile.get("ref", ""))
        if profile_ref not in expected_profiles:
            continue
        harness, expected_adapter = expected_profiles[profile_ref]
        raw_adapter = str(profile.get("nativeAdapter", ""))
        match = server_config.ENV_PATTERN.fullmatch(raw_adapter)
        adapter = (
            server_config.ONE_TIME_MIGRATION_SEEDS.get(match.group(1), "")
            if match
            else raw_adapter
        )
        if adapter != expected_adapter:
            findings.append(
                {
                    "profile": profile_ref,
                    "finding": "native_adapter_mismatch",
                    "expected": expected_adapter,
                    "actual": adapter,
                }
            )
        else:
            represented.add(harness)
    findings.extend(
        {"harness": harness, "finding": "locked_harness_has_no_profile"}
        for harness in sorted(required_harnesses - represented)
    )
    for profile in profiles:
        instruction = PROFILE_SOURCE_ROOT / str(profile.get("instructions", ""))
        if not instruction.is_file():
            findings.append(
                {"profile": profile.get("ref"), "finding": "instructions_missing"}
            )
    return record(
        "profile-coverage",
        not findings,
        profiles=len(profiles),
        requiredHarnesses=sorted(required_harnesses),
        representedHarnesses=sorted(represented),
        findings=findings,
    )


def fresh_install_render() -> dict[str, Any]:
    """Exercise the real init -> secrets -> render path in an empty root."""
    findings: list[dict[str, Any]] = []
    rendered_compose = 0
    projection_count = 0
    canonical_mode: int | None = None
    post_provisioned_notion_ids_absent: list[str] = []
    # These values exist only inside the temporary fresh-install root.  They
    # classify inputs which production bootstrap must receive from an operator;
    # neither server-config nor server-secrets is allowed to fabricate them.
    FRESH_INSTALL_EXTERNAL_SECRET_FIXTURES = {
        "CLOUDFLARE_API_TOKEN": "test-token",
        "GITHUB_TOKEN": "synthetic-github-token-for-test-only",
        "MINIMAX_API_KEY": "synthetic-minimax-key-for-test-only",
        "NOTION_TOKEN": "synthetic-notion-token-for-test-only",
    }
    FRESH_INSTALL_OPERATOR_CONFIG_FIXTURES = {
        "CLOUDFLARE_ACCESS_ALLOWED_EMAILS": "operator@example.test",
        "CLOUDFLARE_ACCOUNT_ID": "external-test-value",
        "CLOUDFLARE_ZONE_ID": "external-test-value",
        "MTE_EXCLUDED_HOST_1": "192.0.2.10",
        "MTE_EXCLUDED_HOST_2": "192.0.2.11",
        "MTE_OPERATOR_SSH_CIDRS": "198.51.100.0/24",
        "MTE_SSH_TARGET": "root@198.51.100.10",
        "MINIMAX_BASE_URL": "https://llm.example.test/v1",
        "MINIMAX_MODEL": "test-model",
        "NOTION_ROOT_PAGE_ID": "00000000-0000-4000-8000-000000000001",
        "PLATFORM_BASE_DOMAIN": "example.test",
    }
    FRESH_INSTALL_EXTERNAL_FIXTURES = {
        **FRESH_INSTALL_EXTERNAL_SECRET_FIXTURES,
        **FRESH_INSTALL_OPERATOR_CONFIG_FIXTURES,
    }
    expected_external = set(FRESH_INSTALL_EXTERNAL_FIXTURES)

    def load(name: str, path: Path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    try:
        with tempfile.TemporaryDirectory(prefix="mte-fresh-install-") as temp:
            temporary = Path(temp)
            platform_root = temporary / "platform"
            secret_root = temporary / "secrets"
            compose_root = platform_root / "templates/deploy"
            profile_root = platform_root / "templates/profiles"
            compose_root.mkdir(parents=True)
            profile_root.mkdir(parents=True)
            for source in canonical_compose_sources():
                shutil.copy2(source, compose_root / compose_projection_name(source))
            shutil.copy2(PROFILE_CATALOG_SOURCE, profile_root / "profiles.yaml")
            shutil.copy2(
                COMPOSE_SEED_SOURCE,
                platform_root / "templates/compose-seeds.lock.json",
            )
            platform_lock_source = platform_root / "templates/platform.lock.yaml"
            shutil.copy2(PLATFORM_LOCK_SOURCE, platform_lock_source)
            structural = yaml.safe_load(PLATFORM_SOURCE.read_text())
            config_source = platform_root / "templates/platform.json"
            config_source.write_text(json.dumps(structural, sort_keys=True) + "\n")

            server_config = load(
                "mte_fresh_server_config", TOOL_ROOT / "server-config.py"
            )
            server_secrets = load(
                "mte_fresh_server_secrets", TOOL_ROOT / "server-secrets.py"
            )
            canonical = secret_root / "platform.env"
            FRESH_INSTALL_PATH_REPLACEMENTS = {
                "ROOT": platform_root,
                "SECRET_ROOT": secret_root,
                "SOURCE": canonical,
                "MANIFEST": secret_root / "projections-manifest.json",
                "LOCK": secret_root / ".platform-env.lock",
                "CONFIG_SOURCE": config_source,
                "CONFIG": platform_root / "config/platform.json",
                "SERVICE_ROOT": secret_root / "services",
                "PROFILE_SOURCE": profile_root / "profiles.yaml",
                "PROFILE_RUNTIME": platform_root / "runtime/profiles/profiles.yaml",
                "COMPOSE_SEED_SOURCE": platform_root
                / "templates/compose-seeds.lock.json",
                "PLATFORM_LOCK_SOURCE": platform_lock_source,
                "PUBLIC_URLS": platform_root / "config/public-urls.json",
                "DATA_CONTENT_PLANE": platform_root / "config/data-content-plane.json",
                "CLOUDFLARE_APPS": secret_root / "cloudflare/apps.json",
                "CLOUDFLARE_API_ENV": secret_root / "cloudflare/api.env",
                "CLOUDFLARE_TUNNEL_TOKEN": secret_root / "cloudflare/tunnel-token",
                "CLOUDFLARE_ACCESS_TOKEN": secret_root
                / "cloudflare/access-service-token.json",
            }
            secret_replacements = {
                "ROOT": platform_root,
                "SECRET_ROOT": secret_root,
                "PLATFORM_ENV": canonical,
                "SERVICE_ROOT": secret_root / "services",
                "INTEGRATION_ROOT": secret_root / "integrations",
                "DOKPLOY_ADMIN_ENV": secret_root / "dokploy-admin.env",
                "CONFIG": platform_root / "config/platform.json",
                "CONFIG_TEMPLATE": config_source,
                "LOCK": secret_root / ".platform-env.lock",
            }
            original_stat = Path.stat

            def root_owned_stat(path: Path, *args: Any, **kwargs: Any):
                value = original_stat(path, *args, **kwargs)
                fields = list(value)
                fields[4] = 0
                return os.stat_result(fields)

            with ExitStack() as stack:
                for name, value in FRESH_INSTALL_PATH_REPLACEMENTS.items():
                    stack.enter_context(mock.patch.object(server_config, name, value))
                for name, value in secret_replacements.items():
                    if hasattr(server_secrets, name):
                        stack.enter_context(
                            mock.patch.object(server_secrets, name, value)
                        )
                stack.enter_context(mock.patch.object(Path, "stat", root_owned_stat))
                config = server_config.active_config_object(
                    server_config.config_object(),
                    {
                        **server_config.ONE_TIME_MIGRATION_SEEDS,
                        **FRESH_INSTALL_EXTERNAL_FIXTURES,
                    },
                )
                required, _, base_seeds = server_config.declared_keys(config)
                compose_seeds = server_config.compose_seed_catalog(config)
                generated = server_secrets.generated_defaults(
                    server_config.ONE_TIME_MIGRATION_SEEDS["DATA_CONTENT_PROFILE"]
                )
                generated_ready = {
                    key
                    for key, value in generated.items()
                    if value or key in server_config.OPTIONAL_EMPTY_KEYS
                }
                categories = {
                    "generalSeed": set(base_seeds)
                    - set(server_config.OPTIONAL_EMPTY_KEYS),
                    "composeSeed": set(compose_seeds),
                    "generatedSecret": generated_ready
                    - set(server_config.OPTIONAL_EMPTY_KEYS),
                    "optionalEmpty": set(server_config.OPTIONAL_EMPTY_KEYS),
                    "externalSecret": set(FRESH_INSTALL_EXTERNAL_SECRET_FIXTURES),
                    "operatorConfig": set(FRESH_INSTALL_OPERATOR_CONFIG_FIXTURES),
                }
                memberships = {
                    key: sorted(
                        category for category, keys in categories.items() if key in keys
                    )
                    for key in required
                }
                ambiguous = {
                    key: assigned
                    for key, assigned in memberships.items()
                    if len(assigned) != 1
                }
                if ambiguous:
                    findings.append(
                        {
                            "finding": "required_key_classification_not_exact",
                            "keys": ambiguous,
                        }
                    )
                actual_external = (
                    required - set(base_seeds) - set(compose_seeds) - generated_ready
                )
                if actual_external != expected_external:
                    findings.append(
                        {
                            "finding": "external_input_classification_mismatch",
                            "missing": sorted(expected_external - actual_external),
                            "unexpected": sorted(actual_external - expected_external),
                        }
                    )
                first = server_config.init_source(FRESH_INSTALL_EXTERNAL_FIXTURES)
                with redirect_stdout(io.StringIO()):
                    server_secrets.init()
                second = server_config.init_source({})
                if second["missingKeys"]:
                    findings.append(
                        {
                            "finding": "missing_after_secrets_init",
                            "keys": second["missingKeys"],
                        }
                    )

                values = server_config.parse_env(canonical)
                canonical_mode = canonical.stat().st_mode & 0o777
                if canonical_mode != 0o600:
                    findings.append(
                        {
                            "finding": "canonical_env_mode_not_0600",
                            "actualMode": oct(canonical_mode),
                        }
                    )
                for key, fixture in FRESH_INSTALL_EXTERNAL_FIXTURES.items():
                    if values.get(key) != fixture:
                        findings.append(
                            {
                                "finding": "external_input_not_preserved",
                                "key": key,
                            }
                        )
                post_provisioned_notion_ids_absent = sorted(
                    key
                    for key in server_config.NOTION_BOOTSTRAP_ID_KEYS
                    if key not in values
                )
                if post_provisioned_notion_ids_absent != sorted(
                    server_config.NOTION_BOOTSTRAP_ID_KEYS
                ):
                    findings.append(
                        {
                            "finding": "notion_child_id_fabricated_before_provision",
                            "present": sorted(
                                set(server_config.NOTION_BOOTSTRAP_ID_KEYS)
                                - set(post_provisioned_notion_ids_absent)
                            ),
                        }
                    )
                mutation_key = "POSTGRES_ADMIN_DB"
                values[mutation_key] = "operator_mutation"
                with server_config.LOCK.open("a+") as config_lock:
                    fcntl.flock(config_lock.fileno(), fcntl.LOCK_EX)
                    server_config.write_env(canonical, values)
                catalog_path = FRESH_INSTALL_PATH_REPLACEMENTS["COMPOSE_SEED_SOURCE"]
                catalog_text = catalog_path.read_text()
                catalog_path.write_text("{}\n")
                repeated = server_config.init_source({})
                catalog_path.write_text(catalog_text)
                if (
                    server_config.parse_env(canonical).get(mutation_key)
                    != "operator_mutation"
                ):
                    findings.append(
                        {"finding": "repeated_init_overwrote_canonical_mutation"}
                    )
                if mutation_key in repeated["createdKeys"]:
                    findings.append({"finding": "bootstrap_catalog_reapplied"})

                rendered = server_config.render()
                projection_count = int(rendered["projectionCount"])
                audited = server_config.audit()
                if not audited.get("ok"):
                    findings.append(
                        {
                            "finding": "fresh_projection_audit_failed",
                            "details": audited.get("findings", []),
                        }
                    )

                for component_id, source_path in server_config.compose_paths(config):
                    runtime_path = server_config.runtime_compose_path(source_path)
                    env_values = server_config.parse_env(
                        secret_root / f"services/{component_id}.env"
                    )
                    content = server_config.strip_generated_header(
                        runtime_path.read_text()
                    )
                    resolved = server_config.ENV_PATTERN.sub(
                        lambda match: env_values.get(match.group(1), match.group(0)),
                        content,
                    )
                    if server_config.ENV_PATTERN.search(resolved):
                        findings.append(
                            {
                                "component": component_id,
                                "finding": "runtime_compose_ref_unresolved",
                            }
                        )
                        continue
                    document = yaml.safe_load(resolved)
                    for service_name, service in document.get("services", {}).items():
                        image = str((service or {}).get("image", ""))
                        if not IMAGE_PATTERN.search(image):
                            findings.append(
                                {
                                    "component": component_id,
                                    "service": service_name,
                                    "finding": "runtime_image_not_digest_pinned",
                                }
                            )
                        for port in (service or {}).get("ports", []) or []:
                            if not str(port).startswith("127.0.0.1:"):
                                findings.append(
                                    {
                                        "component": component_id,
                                        "service": service_name,
                                        "finding": "runtime_port_not_loopback",
                                    }
                                )
                    rendered_compose += 1
                if first["missingKeys"] and not set(first["missingKeys"]) <= set(
                    generated
                ):
                    findings.append(
                        {
                            "finding": "unexpected_missing_before_secrets",
                            "keys": first["missingKeys"],
                        }
                    )
    except BaseException as exc:
        findings.append(
            {"finding": "fresh_install_exception", "errorType": type(exc).__name__}
        )
    return record(
        "fresh-install-render",
        not findings,
        requiredExternalInputs=sorted(expected_external),
        externalSecretInputs=sorted(FRESH_INSTALL_EXTERNAL_SECRET_FIXTURES),
        operatorConfigInputs=sorted(FRESH_INSTALL_OPERATOR_CONFIG_FIXTURES),
        postProvisionedNotionInputs=post_provisioned_notion_ids_absent,
        canonicalEnvMode=oct(canonical_mode) if canonical_mode is not None else None,
        classificationCounts={
            category: len(keys & required) for category, keys in categories.items()
        }
        if "categories" in locals()
        else {},
        composeFilesRendered=rendered_compose,
        projectionCount=projection_count,
        findings=findings,
    )


def smoke_evidence(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return record(
            "smoke-evidence",
            False,
            state="missing",
            path=str(path),
            findings=[{"finding": "smoke_evidence_missing"}],
        )
    try:
        value = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return record(
            "smoke-evidence",
            False,
            state="invalid",
            path=str(path),
            findings=[{"finding": "invalid_json", "error": str(exc)}],
        )
    findings = []
    expected = {
        "coding": "succeeded",
        "research": "succeeded",
    }
    for key, state in expected.items():
        actual = value.get(key, {}).get("run", {}).get("status")
        if actual != state:
            findings.append(
                {
                    "scenario": key,
                    "finding": "unexpected_status",
                    "expected": state,
                    "actual": actual,
                }
            )
    content = value.get("content", {})
    if (
        content.get("waitingState", {}).get("status") != "waiting_input"
        or content.get("finalState", {}).get("status") != "succeeded"
    ):
        findings.append({"scenario": "content", "finding": "approval_flow_not_passed"})
    if value.get("cancel", {}).get("status") != "cancelled":
        findings.append({"scenario": "cancel", "finding": "cancel_flow_not_passed"})
    age = max(0, time.time() - path.stat().st_mtime)
    if age > 7200:
        findings.append({"finding": "smoke_evidence_stale", "ageSeconds": round(age)})
    return record(
        "smoke-evidence",
        not findings,
        path=str(path.relative_to(ROOT)),
        ageSeconds=round(age),
        findings=findings,
    )


def local_capacity() -> dict[str, Any]:
    usage = shutil.disk_usage(ROOT)
    # The reproducibility path now uses the Python renderer and bounded temp
    # copies rather than materializing an npx runtime on the workstation.
    minimum_free = 64 * 1024 * 1024
    ok = usage.free >= minimum_free
    return record(
        "local-capacity",
        ok,
        state="blocked" if not ok else "passed",
        totalBytes=usage.total,
        usedBytes=usage.used,
        freeBytes=usage.free,
        minimumFreeBytes=minimum_free,
        reason=None if ok else "insufficient_disk_headroom_for_smoke_runtime",
    )


def docker_compose_check() -> dict[str, Any]:
    version = command(["docker", "compose", "version"], timeout=10)
    if not version["ok"]:
        spec = importlib.util.spec_from_file_location(
            "mte_compose_remote_target", TOOL_ROOT / "server-config.py"
        )
        server_config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(server_config)
        target = os.environ.get("MTE_SSH_TARGET", "").strip()
        if not target:
            return record(
                "docker-compose-engine",
                False,
                state="not_tested",
                executionMode="remote-server",
                reason="local_engine_unavailable_and_remote_target_not_configured",
                versionCheck=version,
                remoteCheck=None,
                composeFilesTested=0,
            )
        remote = command(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=15",
                target,
                "python3 /opt/mte-platform/bin/server-verify.py compose-config",
            ],
            timeout=180,
        )
        remote_ok = False
        remote_summary: dict[str, Any] = {}
        if remote["ok"]:
            try:
                payload = json.loads(remote.get("outputTail", ""))
                remote_ok = payload.get("ok") is True
                remote_summary = payload.get("summary", {})
            except json.JSONDecodeError:
                remote_ok = False
        return record(
            "docker-compose-engine",
            remote_ok,
            state="passed" if remote_ok else "not_tested",
            executionMode="remote-server",
            reason=None
            if remote_ok
            else "local_engine_unavailable_and_remote_check_failed",
            versionCheck=version,
            remoteCheck={
                "ok": remote.get("ok"),
                "state": remote.get("state"),
                "exitCode": remote.get("exitCode"),
                "summary": remote_summary,
            },
            composeFilesTested=int(remote_summary.get("total", 0)),
        )
    platform = yaml.safe_load(PLATFORM_SOURCE.read_text())
    seed_catalog = json.loads(COMPOSE_SEED_SOURCE.read_text())
    spec = importlib.util.spec_from_file_location(
        "mte_compose_local_config", TOOL_ROOT / "server-config.py"
    )
    server_config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(server_config)
    env_values = {
        **server_config.ONE_TIME_MIGRATION_SEEDS,
        **seed_catalog.get("seeds", {}),
    }
    required_refs: set[str] = set(PUBLIC_ENV_KEYS)
    for row in platform["spec"]["components"]:
        required_refs.update(row.get("secrets", []))
        compose_ref = row.get("compose")
        if compose_ref:
            required_refs.update(
                ENV_REQUIRED_PATTERN.findall((ROOT / str(compose_ref)).read_text())
            )
    for key in required_refs:
        env_values.setdefault(key, "audit-placeholder-0123456789abcdef0123456789")
    with tempfile.NamedTemporaryFile(
        "w", prefix="mte-compose-audit-", delete=False
    ) as handle:
        env_path = Path(handle.name)
        for key, value in sorted(env_values.items()):
            handle.write(f"{key}={value}\n")
    try:
        results = []
        for path in canonical_compose_sources():
            result = command(
                [
                    "docker",
                    "compose",
                    "--env-file",
                    str(env_path),
                    "-f",
                    str(path),
                    "config",
                    "--quiet",
                ],
                timeout=30,
            )
            results.append({"path": str(path.relative_to(ROOT)), **result})
    finally:
        env_path.unlink(missing_ok=True)
    return record(
        "docker-compose-engine",
        all(result["ok"] for result in results),
        versionCheck=version,
        composeFilesTested=len(results),
        results=results,
    )


def write_evidence(value: dict[str, Any]) -> Path:
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    path = EVIDENCE_ROOT / f"local-reproducibility-{stamp}.json"
    latest = EVIDENCE_ROOT / "local-reproducibility-latest.json"
    serialized = (
        json.dumps({**value, "evidenceFile": str(path)}, indent=2, sort_keys=True)
        + "\n"
    )
    for target in (path, latest):
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(serialized)
        temporary.chmod(0o600)
        temporary.replace(target)
        target.chmod(0o600)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--smoke-evidence", type=Path, default=ROOT / "evidence/smoke-results.json"
    )
    args = parser.parse_args()
    started = datetime.now(timezone.utc)
    documents, yaml_findings = yaml_documents()
    checks = [
        record(
            "yaml-parse",
            not yaml_findings,
            files=len(documents),
            findings=yaml_findings,
        ),
        platform_consistency(documents),
        compose_static(documents),
        configuration_source_static(),
        fresh_install_render(),
        connection_coverage(),
        profile_coverage(),
        {
            "name": "python-compile",
            **command(
                [
                    sys.executable,
                    "-m",
                    "compileall",
                    "-q",
                    "tools/platform-cli",
                    "tests",
                ],
                timeout=60,
            ),
        },
        {
            "name": "unit-tests",
            **command(
                [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                timeout=120,
            ),
        },
        local_capacity(),
        smoke_evidence(args.smoke_evidence),
        docker_compose_check(),
    ]
    result = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "LocalReproducibilityAudit",
        **canonical_source_binding(),
        "startedAt": started.isoformat(),
        "finishedAt": datetime.now(timezone.utc).isoformat(),
        "ok": all(check.get("ok") is True for check in checks),
        "summary": {
            "total": len(checks),
            "passed": sum(check.get("ok") is True for check in checks),
            "failedOrNotTested": sum(check.get("ok") is not True for check in checks),
        },
        "checks": checks,
    }
    path = write_evidence(result)
    print(
        json.dumps(
            {"ok": result["ok"], "summary": result["summary"], "evidence": str(path)},
            indent=2,
        )
    )
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

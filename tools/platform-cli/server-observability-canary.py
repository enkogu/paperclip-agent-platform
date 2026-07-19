#!/usr/bin/env python3
"""Hash-gated live observability and data-plane acceptance canary."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
from typing import Any, Callable, NamedTuple
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(os.environ.get("MTE_PLATFORM_ROOT", "/opt/mte-platform"))
SECRET_ROOT = Path(os.environ.get("MTE_SECRET_ROOT", "/root/.config/mte-secrets"))
SERVER_BIN = ROOT / "bin"
CONFIG = ROOT / "config/platform.json"
DATA_CONTENT_PLANE = ROOT / "config/data-content-plane.json"
MANIFEST = SECRET_ROOT / "projections-manifest.json"
PLATFORM_ENV = SECRET_ROOT / "platform.env"
SERVICE_ENV_DIR = SECRET_ROOT / "services"
EVIDENCE = ROOT / "evidence/observability-data-canary.json"
INDEX_PASS = {
    1: ROOT / "evidence/indexed-reconcile-pass-1.json",
    2: ROOT / "evidence/indexed-reconcile-pass-2.json",
}
INDEX_FINAL = ROOT / "evidence/indexed-reconcile-idempotency.json"
COMPOSE = ROOT / "deployment/compose.yaml"
COMPOSE_ENV = SECRET_ROOT / "compose.env"
OTLP_EMITTER_CONTAINER = "mte-paperclip"
OTLP_EMITTER_SERVICE = "paperclip"
OTLP_RUNNER_CONTAINER = "mte-daytona-runner"
OTLP_RUNNER_SERVICE = "daytona-runner"
GENERATOR_VERSION = "mte-config-renderer/v1"
OBSERVABILITY_EVIDENCE_SCHEMA_VERSION = 2

POSTGRES_VOLUMES = {
    "application-data": "mte-postgres-data",
    "mattermost": "mte-mattermost-db-data",
    "firecrawl": "mte-firecrawl-postgres",
    "kestra": "mte-kestra-postgres",
}
CRITERIA = [
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
]
COMPOSE_PROJECT = "mte-platform"
OBSERVABILITY_COMPOSE_SERVICES = (
    "alertmanager",
    "blackbox-exporter",
    "cadvisor",
    "grafana",
    "node-exporter",
    "otel-collector",
    "victorialogs",
    "victoriametrics",
    "victoriatraces",
    "vmalert",
)
ONE_SHOT_COMPOSE_SERVICES = frozenset(
    {"config-init", "kestra-storage-init", "searxng-config-init"}
)
POSTGRES_NOTION_PROFILE = "postgres-notion"
POSTGRES_NOTION_COMPONENTS = ("postgrest",)
PROFILE_RUNTIME_CONTRACTS = {
    "postgres-notion": {
        "componentIds": ("postgrest",),
        "externalProviders": ("notion",),
    },
}
PROFILE_COMPONENT_IDS = frozenset(
    component
    for contract in PROFILE_RUNTIME_CONTRACTS.values()
    for component in contract["componentIds"]
)
CORE_APPLICATION_COMPONENTS = (
    "mattermost",
    "firecrawl",
    "kestra",
    "searxng",
)
SENSITIVE_EVIDENCE_KEY_RE = re.compile(
    r"password|secret|credential|api.?key|token|webhook|connection.?string",
    re.IGNORECASE,
)


class CanaryError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ObservabilityRuntime(NamedTuple):
    """Validated, canonical runtime inputs derived only from platform.env."""

    host_otlp_url: str
    container_otlp_url: str
    victoriametrics_url: str
    victorialogs_url: str
    victoriatraces_url: str
    vmalert_url: str
    alertmanager_url: str
    grafana_url: str
    query_timeout_seconds: int
    poll_interval_seconds: int
    series_max_age_seconds: int
    alert_fire_timeout_seconds: int
    alert_resolve_timeout_seconds: int
    alert_poll_interval_seconds: int
    http_timeout_seconds: int
    command_timeout_seconds: int
    datasources: dict[str, dict[str, Any]]


def required_positive_int(values: dict[str, str], key: str) -> int:
    raw = values.get(key, "").strip()
    if not raw:
        raise CanaryError("missing_observability_runtime", key)
    try:
        value = int(raw)
    except ValueError as exc:
        raise CanaryError("invalid_observability_runtime", key) from exc
    if value <= 0:
        raise CanaryError("invalid_observability_runtime", key)
    return value


def required_http_base(values: dict[str, str], key: str) -> str:
    raw = values.get(key, "").strip()
    if not raw:
        raise CanaryError("missing_observability_runtime", key)
    try:
        parsed = urllib.parse.urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise CanaryError("invalid_observability_runtime", key) from exc
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or port is None
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise CanaryError("invalid_observability_runtime", key)
    return raw.rstrip("/")


def mapped_endpoint(
    values: dict[str, str],
    key: str,
    *,
    path: str = "",
) -> tuple[str, int]:
    raw = values.get(key, "").strip()
    if not raw:
        raise CanaryError("missing_observability_runtime", key)
    try:
        host, published_raw, container_raw = raw.rsplit(":", 2)
        published, container = int(published_raw), int(container_raw)
    except (ValueError, TypeError) as exc:
        raise CanaryError("invalid_observability_runtime", key) from exc
    host = host.strip("[]")
    if (
        not host
        or not (1 <= published <= 65535)
        or not (1 <= container <= 65535)
        or (path and not path.startswith("/"))
    ):
        raise CanaryError("invalid_observability_runtime", key)
    authority = f"[{host}]" if ":" in host else host
    return f"http://{authority}:{published}{path}", container


def observability_runtime(values: dict[str, str]) -> ObservabilityRuntime:
    """Resolve endpoints and timings from the one canonical environment."""
    host_otlp = required_http_base(values, "OBSERVABILITY_OTLP_HTTP_URL")
    container_otlp = required_http_base(values, "OBSERVABILITY_CONTAINER_OTLP_HTTP_URL")
    vm, vm_container_port = mapped_endpoint(
        values, "MTE_OBSERVABILITY_VICTORIAMETRICS_PORT_1_MAPPING"
    )
    vl, vl_container_port = mapped_endpoint(
        values, "MTE_OBSERVABILITY_VICTORIALOGS_PORT_1_MAPPING"
    )
    vt, vt_container_port = mapped_endpoint(
        values,
        "MTE_OBSERVABILITY_VICTORIATRACES_PORT_1_MAPPING",
        path="/select/jaeger",
    )
    vmalert, _ = mapped_endpoint(values, "MTE_OBSERVABILITY_VMALERT_PORT_1_MAPPING")
    alertmanager, _ = mapped_endpoint(
        values, "MTE_OBSERVABILITY_ALERTMANAGER_PORT_1_MAPPING"
    )
    grafana_health = values.get("OBSERVABILITY_HEALTH_URL", "").strip()
    try:
        parsed_grafana = urllib.parse.urlsplit(grafana_health)
        grafana_port = parsed_grafana.port
    except ValueError as exc:
        raise CanaryError(
            "invalid_observability_runtime", "OBSERVABILITY_HEALTH_URL"
        ) from exc
    if (
        parsed_grafana.scheme not in {"http", "https"}
        or not parsed_grafana.hostname
        or grafana_port is None
        or parsed_grafana.username
        or parsed_grafana.password
        or parsed_grafana.query
        or parsed_grafana.fragment
    ):
        code = (
            "missing_observability_runtime"
            if not grafana_health
            else "invalid_observability_runtime"
        )
        raise CanaryError(code, "OBSERVABILITY_HEALTH_URL")
    grafana = urllib.parse.urlunsplit(
        (parsed_grafana.scheme, parsed_grafana.netloc, "", "", "")
    )
    datasources = {
        "victoriametrics": {
            "name": "VictoriaMetrics",
            "type": "prometheus",
            "url": f"http://victoriametrics:{vm_container_port}",
            "access": "proxy",
            "isDefault": True,
            "editable": False,
        },
        "victorialogs": {
            "name": "VictoriaLogs",
            "type": "victoriametrics-logs-datasource",
            "url": f"http://victorialogs:{vl_container_port}",
            "access": "proxy",
            "editable": False,
        },
        "victoriatraces": {
            "name": "VictoriaTraces",
            "type": "jaeger",
            "url": f"http://victoriatraces:{vt_container_port}/select/jaeger",
            "access": "proxy",
            "editable": False,
        },
    }
    return ObservabilityRuntime(
        host_otlp_url=host_otlp,
        container_otlp_url=container_otlp,
        victoriametrics_url=vm,
        victorialogs_url=vl,
        victoriatraces_url=vt,
        vmalert_url=vmalert,
        alertmanager_url=alertmanager,
        grafana_url=grafana,
        query_timeout_seconds=required_positive_int(
            values, "OBSERVABILITY_QUERY_TIMEOUT_SECONDS"
        ),
        poll_interval_seconds=required_positive_int(
            values, "OBSERVABILITY_POLL_INTERVAL_SECONDS"
        ),
        series_max_age_seconds=required_positive_int(
            values, "OBSERVABILITY_SERIES_MAX_AGE_SECONDS"
        ),
        alert_fire_timeout_seconds=required_positive_int(
            values, "OBSERVABILITY_ALERT_FIRE_TIMEOUT_SECONDS"
        ),
        alert_resolve_timeout_seconds=required_positive_int(
            values, "OBSERVABILITY_ALERT_RESOLVE_TIMEOUT_SECONDS"
        ),
        alert_poll_interval_seconds=required_positive_int(
            values, "OBSERVABILITY_ALERT_POLL_INTERVAL_SECONDS"
        ),
        http_timeout_seconds=required_positive_int(
            values, "OBSERVABILITY_HTTP_TIMEOUT_SECONDS"
        ),
        command_timeout_seconds=required_positive_int(
            values, "OBSERVABILITY_COMMAND_TIMEOUT_SECONDS"
        ),
        datasources=datasources,
    )


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def producer_sha256() -> str:
    path = Path(__file__)
    if not path.is_file():
        raise CanaryError(
            "producer_not_installed",
            "mutating canary must run from its installed source file",
        )
    return hashlib.sha256(path.read_bytes()).hexdigest()


def installed_producer_hashes(names: tuple[str, ...]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in names:
        if name == Path(__file__).name:
            path = Path(__file__)
        else:
            installed = SERVER_BIN / name
            sibling = Path(__file__).parent / name
            path = installed if installed.is_file() else sibling
        if not path.is_file():
            raise CanaryError("producer_not_installed", name)
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def producer_hashes() -> dict[str, str]:
    """Bind indexed evidence to its producer and reconciler dependencies."""
    return installed_producer_hashes(
        (
            Path(__file__).name,
            "server-provision.py",
            "server-toolhive.py",
            "server-profile-reconcile.py",
            "server-config.py",
        )
    )


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise CanaryError("invalid_local_state", f"cannot read {path}") from exc
    if not isinstance(value, dict):
        raise CanaryError("invalid_local_state", f"{path} is not an object")
    return value


def dotenv(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        raise CanaryError("missing_secret_projection", f"cannot read {path}") from exc
    values: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def declared_component_ids(config: dict[str, Any]) -> set[str]:
    components = config.get("spec", {}).get("components", [])
    if not isinstance(components, list):
        raise CanaryError("runtime_profile_invalid", "components are not a list")
    ids = [
        str(row.get("id"))
        for row in components
        if isinstance(row, dict) and row.get("id")
    ]
    if len(ids) != len(set(ids)):
        raise CanaryError("runtime_profile_invalid", "duplicate component id")
    return set(ids)


def runtime_profile(config: dict[str, Any], values: dict[str, str]) -> dict[str, Any]:
    """Resolve and validate the selected data/content runtime fail-closed."""
    profile = values.get("DATA_CONTENT_PROFILE", "").strip()
    contract = PROFILE_RUNTIME_CONTRACTS.get(profile)
    if not contract:
        raise CanaryError(
            "unsupported_data_content_profile", profile or "missing-profile"
        )
    plane = load_json(DATA_CONTENT_PLANE)
    active_ids = declared_component_ids(config)
    expected_components = set(contract["componentIds"])
    external = sorted(
        str(provider_id)
        for provider_id, row in (
            plane.get("providers", {}).items()
            if isinstance(plane.get("providers"), dict)
            else []
        )
        if isinstance(row, dict) and row.get("deployment") == "external"
    )
    required_core = {"postgres", *CORE_APPLICATION_COMPONENTS}
    active_profile_components = active_ids & PROFILE_COMPONENT_IDS
    if (
        plane.get("profile") != profile
        or plane.get("componentIds") != list(contract["componentIds"])
        or plane.get("systemOfRecord", {}).get("providerId") != "postgres"
        or external != list(contract["externalProviders"])
        or not required_core <= active_ids
        or active_profile_components != expected_components
    ):
        raise CanaryError("runtime_profile_invalid", profile)
    return {
        "profile": profile,
        "componentIds": list(contract["componentIds"]),
        "externalProviders": list(contract["externalProviders"]),
        "activeComponentIds": sorted(active_ids),
    }


def runtime_values(
    canonical: dict[str, str],
    config: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, str]:
    """Overlay only selected, hash-governed service projections."""
    source_sha = hashlib.sha256(PLATFORM_ENV.read_bytes()).hexdigest()
    if (
        manifest.get("sourceSha256") != source_sha
        or manifest.get("generatorVersion") != GENERATOR_VERSION
    ):
        raise CanaryError("service_projection_drift", "manifest-source")
    rows = manifest.get("projections")
    if not isinstance(rows, list):
        raise CanaryError("service_projection_drift", "manifest-schema")
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise CanaryError("service_projection_drift", "manifest-row")
        path = str(row["path"])
        if path in indexed:
            raise CanaryError("service_projection_drift", f"duplicate:{path}")
        indexed[path] = row
    plane_row = indexed.get(str(DATA_CONTENT_PLANE))
    if (
        plane_row is None
        or plane_row.get("sourceSha256") != source_sha
        or plane_row.get("generatorVersion") != GENERATOR_VERSION
        or not DATA_CONTENT_PLANE.is_file()
        or plane_row.get("contentSha256")
        != hashlib.sha256(DATA_CONTENT_PLANE.read_bytes()).hexdigest()
    ):
        raise CanaryError("service_projection_drift", "data-content-plane")
    profile = runtime_profile(config, canonical)
    values = dict(canonical)
    projection_components = {
        *profile["activeComponentIds"],
        *profile["externalProviders"],
    }
    for component in sorted(projection_components):
        path = SERVICE_ENV_DIR / f"{component}.env"
        row = indexed.get(str(path))
        if (
            row is None
            or row.get("sourceSha256") != source_sha
            or row.get("generatorVersion") != GENERATOR_VERSION
            or not path.is_file()
            or row.get("contentSha256") != hashlib.sha256(path.read_bytes()).hexdigest()
        ):
            raise CanaryError("service_projection_drift", component)
        projected = dotenv(path)
        for key, value in projected.items():
            if key in values and values[key] != value:
                raise CanaryError(
                    "service_projection_drift",
                    f"{component}:{key}",
                )
            values[key] = value
    return values


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        temporary.replace(path)
        path.chmod(0o600)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def request_json(
    method: str,
    url: str,
    *,
    body: Any | None = None,
    headers: dict[str, str] | None = None,
    allow_status: set[int] | None = None,
    timeout: int,
) -> tuple[int, Any]:
    request_headers = {"Accept": "application/json", **(headers or {})}
    data = None
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(
        url, data=data, method=method, headers=request_headers
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status, content = response.status, response.read()
    except urllib.error.HTTPError as exc:
        if allow_status and exc.code in allow_status:
            return exc.code, None
        raise CanaryError(
            "remote_http_error", f"{method} returned HTTP {exc.code}"
        ) from exc
    except urllib.error.URLError as exc:
        raise CanaryError(
            "remote_unavailable", f"{method} endpoint unavailable"
        ) from exc
    if not content:
        return status, None
    try:
        return status, json.loads(content)
    except json.JSONDecodeError:
        return status, content.decode(errors="replace")


def run(
    argv: list[str],
    *,
    stdin: str | None = None,
    timeout: int,
    allow_failure: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        input=stdin,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env=env,
    )
    if result.returncode and not allow_failure:
        raise CanaryError("command_failed", f"{argv[0]} exited {result.returncode}")
    return result


def exact_hash_gate(
    expected: str,
    config: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, str]:
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise CanaryError("invalid_hash_gate", "expected hash must be lowercase sha256")
    generated = config.get("_generated")
    if not isinstance(generated, dict):
        raise CanaryError("missing_hash_gate", "rendered metadata missing")
    versions = {generated.get("generatorVersion"), manifest.get("generatorVersion")}
    if versions != {GENERATOR_VERSION}:
        raise CanaryError("generator_version_drift", "generator version drifted")
    if (
        generated.get("sourceSha256") != expected
        or manifest.get("sourceSha256") != expected
    ):
        raise CanaryError(
            "final_hash_not_stable", "exact FINAL-STABLE hash gate failed"
        )
    return {"sourceSha256": expected, "generatorVersion": GENERATOR_VERSION}


def docker_inventory(
    runtime: ObservabilityRuntime,
    *,
    all_containers: bool = False,
) -> list[dict[str, Any]]:
    names = run(
        ["docker", "ps", *(["-a"] if all_containers else []), "--format", "{{.Names}}"],
        timeout=runtime.command_timeout_seconds,
    ).stdout.splitlines()
    if not names:
        raise CanaryError("docker_inventory_empty", "no running containers")
    # Restrict the one inspect snapshot to runtime identity and state; full
    # Docker inspect would unnecessarily read container environments/secrets.
    output = run(
        [
            "docker",
            "inspect",
            "--format",
            "{{json .Name}}\t{{json .Mounts}}\t{{json .NetworkSettings.Ports}}"
            "\t{{json .Config.Labels}}\t{{json .Config.Image}}\t{{json .State}}",
            *names,
        ],
        timeout=runtime.command_timeout_seconds,
    ).stdout
    items: list[dict[str, Any]] = []
    try:
        for line in output.splitlines():
            raw_name, raw_mounts, raw_ports, raw_labels, raw_image, raw_state = (
                line.split("\t", 5)
            )
            items.append(
                {
                    "Name": json.loads(raw_name),
                    "Mounts": json.loads(raw_mounts),
                    "Ports": json.loads(raw_ports),
                    "Labels": json.loads(raw_labels) or {},
                    "Image": json.loads(raw_image),
                    "State": json.loads(raw_state) or {},
                }
            )
    except (ValueError, json.JSONDecodeError) as exc:
        raise CanaryError(
            "docker_inventory_invalid",
            "restricted Docker inspect invalid",
        ) from exc
    return items


def direct_compose_proof(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Prove the canonical aggregate Compose project owns the live stack."""
    observed: dict[str, dict[str, Any]] = {}
    for item in items:
        labels = item.get("Labels") or {}
        if labels.get("com.docker.compose.project") != COMPOSE_PROJECT:
            continue
        service = str(labels.get("com.docker.compose.service") or "")
        if service not in OBSERVABILITY_COMPOSE_SERVICES:
            continue
        if service in observed:
            raise CanaryError("compose_runtime_duplicate", service)
        config_hash = str(labels.get("com.docker.compose.config-hash") or "")
        if not config_hash:
            raise CanaryError("compose_runtime_invalid", f"{service}:config-hash")
        observed[service] = {
            "container": str(item.get("Name") or "").lstrip("/"),
            "configHash": config_hash,
        }
    missing = sorted(set(OBSERVABILITY_COMPOSE_SERVICES) - set(observed))
    if missing:
        raise CanaryError("compose_runtime_missing", ",".join(missing))
    identity = {
        "project": COMPOSE_PROJECT,
        "services": {key: observed[key] for key in sorted(observed)},
    }
    return {
        "contract": "direct-docker-compose",
        "project": COMPOSE_PROJECT,
        "serviceCount": len(observed),
        "services": sorted(observed),
        "runtimeIdentitySha256": hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "allContainersRunning": True,
        "noDuplicateServices": True,
    }


def stable_projection(value: Any) -> Any:
    """Remove volatile and secret-shaped fields from an identity snapshot."""
    volatile = {
        "timestamp",
        "startedat",
        "finishedat",
        "generatedat",
        "completedat",
        "durationseconds",
        "health",
        "reason",
        "error",
        "errortype",
    }
    if isinstance(value, dict):
        projected: dict[str, Any] = {}
        for key in sorted(value):
            lower = key.lower()
            redacted_fingerprint = (
                lower in {"bottoken", "alertwebhook"}
                and isinstance(value[key], str)
                and re.fullmatch(r"[0-9a-f]{12}", value[key]) is not None
            )
            if lower in volatile or (
                SENSITIVE_EVIDENCE_KEY_RE.search(key)
                and "fingerprint" not in lower
                and not redacted_fingerprint
            ):
                continue
            projected[key] = stable_projection(value[key])
        return projected
    if isinstance(value, list):
        projected = [stable_projection(item) for item in value]
        if all(isinstance(item, dict) for item in projected):
            return sorted(projected, key=lambda item: json.dumps(item, sort_keys=True))
        return projected
    return value


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def assert_no_list_duplicates(value: Any, path: str = "root") -> None:
    if isinstance(value, list):
        rows = [row for row in value if isinstance(row, dict)]
        for field in ("id", "uid", "name", "component", "profileRef"):
            identities = [str(row[field]) for row in rows if row.get(field)]
            if len(identities) != len(set(identities)):
                raise CanaryError("indexed_inventory_duplicate", f"{path}.{field}")
        for index, item in enumerate(value):
            assert_no_list_duplicates(item, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            assert_no_list_duplicates(item, f"{path}.{key}")


def require_containers(items: list[dict[str, Any]]) -> dict[str, str]:
    volumes: dict[str, str] = {}
    for item in items:
        name = str(item.get("Name", "")).lstrip("/")
        for mount in item.get("Mounts", []) or []:
            if mount.get("Type") == "volume" and mount.get("Name"):
                volumes[str(mount["Name"])] = name
    required = dict(POSTGRES_VOLUMES)
    missing = sorted(key for key, volume in required.items() if volume not in volumes)
    if missing:
        raise CanaryError(
            "required_container_missing", "missing roles: " + ",".join(missing)
        )
    return {key: volumes[volume] for key, volume in required.items()}


def require_otlp_emitters(items: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    proof: dict[str, dict[str, str]] = {}
    for role, container, service in (
        ("application", OTLP_EMITTER_CONTAINER, OTLP_EMITTER_SERVICE),
        ("runner", OTLP_RUNNER_CONTAINER, OTLP_RUNNER_SERVICE),
    ):
        exact = [
            item for item in items if str(item.get("Name", "")).lstrip("/") == container
        ]
        if len(exact) != 1:
            raise CanaryError(
                "otlp_emitter_missing",
                f"expected one running {container} container",
            )
        image = str(exact[0].get("Image") or "")
        if not image:
            raise CanaryError("otlp_emitter_invalid", f"{role} image missing")
        proof[role] = {"container": container, "service": service, "image": image}
    return proof


def container_host_ports(item: dict[str, Any]) -> set[int]:
    result: set[int] = set()
    for bindings in (item.get("Ports") or {}).values():
        for binding in bindings or []:
            try:
                result.add(int(binding.get("HostPort", "")))
            except (TypeError, ValueError):
                continue
    return result


def application_paths(
    config: dict[str, Any],
    items: list[dict[str, Any]],
    values: dict[str, str],
) -> dict[str, str]:
    profile = runtime_profile(config, values)
    by_port: dict[int, str] = {}
    by_name = {str(item.get("Name", "")).lstrip("/"): item for item in items}
    for name, item in by_name.items():
        for port in container_host_ports(item):
            if port in by_port:
                raise CanaryError("application_path_duplicate", f"host port {port}")
            by_port[port] = name
    components = {
        str(row.get("id")): row
        for row in config.get("spec", {}).get("components", [])
        if isinstance(row, dict)
    }
    required_components = [
        *CORE_APPLICATION_COMPONENTS,
        *profile["componentIds"],
    ]
    primary: dict[str, str] = {}
    for component in required_components:
        health = components.get(component, {}).get("health", {})
        parsed = urllib.parse.urlsplit(str(health.get("url", "")))
        if not parsed.port or parsed.port not in by_port:
            raise CanaryError("application_path_missing", component)
        primary[component] = by_port[parsed.port]

    paths = {
        "mattermost": primary["mattermost"],
        "firecrawl-api": primary["firecrawl"],
        "kestra": primary["kestra"],
        "searxng": primary["searxng"],
    }
    for component in profile["componentIds"]:
        paths[component] = primary[component]
    return paths


def attr(key: str, value: str) -> dict[str, Any]:
    return {"key": key, "value": {"stringValue": value}}


def otlp_payloads(
    run_id: str,
    trace_id: str,
    span_id: str,
    now_ns: int,
    *,
    service_name: str = OTLP_EMITTER_SERVICE,
    container_name: str = OTLP_EMITTER_CONTAINER,
) -> dict[str, dict[str, Any]]:
    resource = {
        "attributes": [
            attr("service.name", service_name),
            attr("container.name", container_name),
            attr("run_id", run_id),
        ]
    }
    attrs = [attr("run_id", run_id), attr("trace_id", trace_id)]
    return {
        "metrics": {
            "resourceMetrics": [
                {
                    "resource": resource,
                    "scopeMetrics": [
                        {
                            "scope": {"name": "mte.observability.canary"},
                            "metrics": [
                                {
                                    "name": "mte_observability_canary",
                                    "unit": "1",
                                    "gauge": {
                                        "dataPoints": [
                                            {
                                                "attributes": attrs,
                                                "timeUnixNano": str(now_ns),
                                                "asDouble": 1.0,
                                            }
                                        ]
                                    },
                                }
                            ],
                        }
                    ],
                }
            ]
        },
        "logs": {
            "resourceLogs": [
                {
                    "resource": resource,
                    "scopeLogs": [
                        {
                            "scope": {"name": "mte.observability.canary"},
                            "logRecords": [
                                {
                                    "timeUnixNano": str(now_ns),
                                    "observedTimeUnixNano": str(now_ns),
                                    "severityNumber": 9,
                                    "severityText": "INFO",
                                    "traceId": trace_id,
                                    "spanId": span_id,
                                    "body": {
                                        "stringValue": "mte correlated observability canary"
                                    },
                                    "attributes": attrs,
                                }
                            ],
                        }
                    ],
                }
            ]
        },
        "traces": {
            "resourceSpans": [
                {
                    "resource": resource,
                    "scopeSpans": [
                        {
                            "scope": {"name": "mte.observability.canary"},
                            "spans": [
                                {
                                    "traceId": trace_id,
                                    "spanId": span_id,
                                    "name": "mte-observability-canary",
                                    "kind": 2,
                                    "startTimeUnixNano": str(now_ns - 1_000_000),
                                    "endTimeUnixNano": str(now_ns),
                                    "attributes": attrs,
                                    "status": {"code": 1},
                                }
                            ],
                        }
                    ],
                }
            ]
        },
    }


def probe_metric_payload(run_id: str, value: int) -> dict[str, Any]:
    return {
        "resourceMetrics": [
            {
                "resource": {
                    "attributes": [attr("service.name", "mte-observability-canary")]
                },
                "scopeMetrics": [
                    {
                        "scope": {"name": "mte.observability.alert-canary"},
                        "metrics": [
                            {
                                "name": "probe_success",
                                "gauge": {
                                    "dataPoints": [
                                        {
                                            "attributes": [
                                                attr("job", "platform_health"),
                                                attr("service.name", "platform_health"),
                                                attr("service", "observability-canary"),
                                                attr(
                                                    "instance", f"mte-canary:{run_id}"
                                                ),
                                                attr("run_id", run_id),
                                            ],
                                            "timeUnixNano": str(time.time_ns()),
                                            "asInt": str(value),
                                        }
                                    ]
                                },
                            }
                        ],
                    }
                ],
            }
        ]
    }


def send_otlp(
    kind: str,
    payload: dict[str, Any],
    runtime: ObservabilityRuntime,
) -> int:
    status, _ = request_json(
        "POST",
        f"{runtime.host_otlp_url}/v1/{kind}",
        body=payload,
        timeout=runtime.http_timeout_seconds,
    )
    if status not in {200, 202}:
        raise CanaryError("otlp_rejected", f"OTLP {kind} returned {status}")
    return status


def send_otlp_from_container(
    container: str,
    kind: str,
    payload: dict[str, Any],
    runtime: ObservabilityRuntime,
) -> int:
    if container != OTLP_EMITTER_CONTAINER:
        raise CanaryError("otlp_emitter_invalid", container)
    helper = (
        "const http=require('node:http');let b=[];"
        "process.stdin.on('data',x=>b.push(x));process.stdin.on('end',()=>{"
        "const u=new URL(process.argv[1]);const r=http.request({hostname:u.hostname,"
        "port:u.port,path:u.pathname,method:'POST',headers:{'content-type':"
        "'application/json'}},x=>{process.stdout.write(String(x.statusCode));"
        "x.resume();});r.on('error',e=>{console.error(e.message);process.exit(2)});"
        "r.end(Buffer.concat(b));});"
    )
    result = run(
        [
            "docker",
            "exec",
            "-i",
            container,
            "node",
            "-e",
            helper,
            f"{runtime.container_otlp_url}/v1/{kind}",
        ],
        stdin=json.dumps(payload, separators=(",", ":")),
        timeout=runtime.command_timeout_seconds,
    )
    try:
        status = int(result.stdout.strip())
    except ValueError as exc:
        raise CanaryError("otlp_emitter_invalid", f"{kind} status") from exc
    if status not in {200, 202}:
        raise CanaryError("otlp_rejected", f"OTLP {kind} returned {status}")
    return status


def otel_collector_network(runtime: ObservabilityRuntime) -> str:
    names = run(
        [
            "docker",
            "ps",
            "--filter",
            "label=com.docker.compose.service=otel-collector",
            "--format",
            "{{.Names}}",
        ],
        timeout=runtime.command_timeout_seconds,
    ).stdout.splitlines()
    if len(names) != 1:
        raise CanaryError(
            "otel_network_missing", "collector container count is not one"
        )
    raw = run(
        [
            "docker",
            "inspect",
            "--format",
            "{{json .NetworkSettings.Networks}}",
            names[0],
        ],
        timeout=runtime.command_timeout_seconds,
    ).stdout.strip()
    try:
        networks = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CanaryError("otel_network_missing", "collector network invalid") from exc
    candidates = (
        sorted(name for name in networks if name != "host" and isinstance(name, str))
        if isinstance(networks, dict)
        else []
    )
    if len(candidates) != 1:
        raise CanaryError("otel_network_missing", "collector network is ambiguous")
    return candidates[0]


def send_otlp_from_runner(
    container: str,
    kind: str,
    payload: dict[str, Any],
    runtime: ObservabilityRuntime,
) -> int:
    if container != OTLP_RUNNER_CONTAINER:
        raise CanaryError("otlp_emitter_invalid", container)
    result = run(
        [
            "docker",
            "exec",
            "-i",
            container,
            "curl",
            "-fsS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            str(runtime.http_timeout_seconds),
            "-H",
            "Content-Type: application/json",
            "-X",
            "POST",
            "--data-binary",
            "@-",
            f"{runtime.container_otlp_url}/v1/{kind}",
        ],
        stdin=json.dumps(payload, separators=(",", ":")),
        timeout=runtime.command_timeout_seconds,
    )
    try:
        status = int(result.stdout.strip())
    except ValueError as exc:
        raise CanaryError("otlp_emitter_invalid", f"runner {kind} status") from exc
    if status not in {200, 202}:
        raise CanaryError("otlp_rejected", f"runner OTLP {kind} returned {status}")
    return status


def container_otlp_bundle(
    container: str,
    payloads: dict[str, dict[str, Any]],
    runtime: ObservabilityRuntime,
) -> tuple[dict[str, int], dict[str, Any]]:
    if container not in {OTLP_EMITTER_CONTAINER, OTLP_RUNNER_CONTAINER}:
        raise CanaryError("otlp_emitter_invalid", container)
    network = otel_collector_network(runtime)
    connected = False
    statuses: dict[str, int] = {}
    try:
        result = run(
            [
                "docker",
                "network",
                "connect",
                network,
                container,
            ],
            timeout=runtime.command_timeout_seconds,
            allow_failure=True,
        )
        if result.returncode:
            raise CanaryError("otel_runner_attach_failed", "network connect failed")
        connected = True
        sender = (
            send_otlp_from_container
            if container == OTLP_EMITTER_CONTAINER
            else send_otlp_from_runner
        )
        statuses = {
            kind: sender(container, kind, payload, runtime)
            for kind, payload in payloads.items()
        }
    finally:
        if connected:
            detached = run(
                [
                    "docker",
                    "network",
                    "disconnect",
                    network,
                    container,
                ],
                timeout=runtime.command_timeout_seconds,
                allow_failure=True,
            )
            if detached.returncode:
                raise CanaryError(
                    "otel_runner_detach_failed", "network disconnect failed"
                )
    networks_raw = run(
        [
            "docker",
            "inspect",
            "--format",
            "{{json .NetworkSettings.Networks}}",
            container,
        ],
        timeout=runtime.command_timeout_seconds,
    ).stdout.strip()
    try:
        remaining = json.loads(networks_raw)
    except json.JSONDecodeError as exc:
        raise CanaryError("otel_runner_detach_failed", "network state invalid") from exc
    if isinstance(remaining, dict) and network in remaining:
        raise CanaryError("otel_runner_detach_failed", "temporary network remains")
    return statuses, {
        "network": network,
        "temporaryAttachmentCreated": True,
        "temporaryAttachmentCleanupVerified": True,
    }


def runner_otlp_bundle(
    container: str,
    payloads: dict[str, dict[str, Any]],
    runtime: ObservabilityRuntime,
) -> tuple[dict[str, int], dict[str, Any]]:
    if container != OTLP_RUNNER_CONTAINER:
        raise CanaryError("otlp_emitter_invalid", container)
    return container_otlp_bundle(container, payloads, runtime)


def prom_query(
    query: str,
    runtime: ObservabilityRuntime,
    *,
    base: str | None = None,
) -> list[dict[str, Any]]:
    base = base or runtime.victoriametrics_url
    url = base + "/api/v1/query?" + urllib.parse.urlencode({"query": query})
    status, body = request_json("GET", url, timeout=runtime.http_timeout_seconds)
    if status != 200 or not isinstance(body, dict) or body.get("status") != "success":
        raise CanaryError("prom_query_failed", "Prometheus query failed")
    result = body.get("data", {}).get("result", [])
    if not isinstance(result, list):
        raise CanaryError("prom_query_invalid", "Prometheus result invalid")
    return result


def wait_for(predicate: Callable[[], Any], *, timeout: int, interval: int) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise CanaryError("canary_timeout", f"condition timed out after {timeout}s")


def query_correlated_data(
    run_id: str,
    trace_id: str,
    runtime: ObservabilityRuntime,
) -> dict[str, Any]:
    metric = wait_for(
        lambda: prom_query(
            f'mte_observability_canary{{run_id="{run_id}",trace_id="{trace_id}"}}',
            runtime,
        ),
        timeout=runtime.query_timeout_seconds,
        interval=runtime.poll_interval_seconds,
    )
    query = f'run_id:="{run_id}" AND trace_id:="{trace_id}"'

    def logs() -> list[str] | bool:
        url = (
            runtime.victorialogs_url
            + "/select/logsql/query?"
            + urllib.parse.urlencode({"query": query})
        )
        status, body = request_json("GET", url, timeout=runtime.http_timeout_seconds)
        if status != 200:
            return False
        # VictoriaLogs returns newline-delimited JSON.  A query matching one
        # record is also valid JSON by itself, so request_json() decodes it to
        # a dict instead of leaving it as an NDJSON string.  Both canary
        # emitters intentionally produce one correlated record each.
        if isinstance(body, dict):
            return [body] if body else False
        if isinstance(body, list):
            return body or False
        if isinstance(body, str):
            return [line for line in body.splitlines() if line.strip()] or False
        return False

    def trace() -> dict[str, Any] | bool:
        status, body = request_json(
            "GET",
            f"{runtime.victoriatraces_url}/api/traces/{trace_id}",
            allow_status={404},
            timeout=runtime.http_timeout_seconds,
        )
        return (
            body
            if status == 200 and isinstance(body, dict) and body.get("data")
            else False
        )

    log_rows = wait_for(
        logs,
        timeout=runtime.query_timeout_seconds,
        interval=runtime.poll_interval_seconds,
    )
    trace_body = wait_for(
        trace,
        timeout=runtime.query_timeout_seconds,
        interval=runtime.poll_interval_seconds,
    )
    return {
        "metricSeries": len(metric),
        "logRecords": len(log_rows),
        "traceCount": len(trace_body["data"]),
        "runId": run_id,
        "traceId": trace_id,
    }


def series_freshness(
    query: str,
    runtime: ObservabilityRuntime,
) -> dict[str, Any]:
    rows = prom_query(query, runtime)
    timestamps = [
        float(row["value"][0])
        for row in rows
        if isinstance(row.get("value"), list) and row["value"]
    ]
    if not timestamps:
        raise CanaryError("series_missing", "required metric series missing")
    age = max(0.0, time.time() - max(timestamps))
    if age > runtime.series_max_age_seconds:
        raise CanaryError(
            "series_stale",
            f"metric series older than {runtime.series_max_age_seconds}s",
        )
    return {"series": len(rows), "freshnessSeconds": round(age, 3)}


def declared_http_targets(config: dict[str, Any]) -> dict[str, str]:
    targets: dict[str, str] = {}
    components = config.get("spec", {}).get("components", [])
    for component in components if isinstance(components, list) else []:
        if not isinstance(component, dict) or not component.get("required"):
            continue
        health = component.get("health")
        url = health.get("url") if isinstance(health, dict) else None
        if not isinstance(url, str):
            continue
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise CanaryError("declared_health_invalid", str(component.get("id")))
        targets[str(component["id"])] = url.rstrip("/") or url
    if not targets:
        raise CanaryError("declared_health_missing", "no required URL health targets")
    return targets


def blackbox_proof(
    config: dict[str, Any],
    runtime: ObservabilityRuntime,
) -> dict[str, Any]:
    expected = declared_http_targets(config)
    rows = prom_query('probe_success{service.name="platform_health"}', runtime)
    values: dict[str, float] = {}
    ages: dict[str, float] = {}
    addresses: dict[str, str] = {}
    for row in rows:
        metric = row.get("metric", {})
        service = metric.get("service")
        value = row.get("value")
        address = metric.get("server.address")
        # Synthetic alert series intentionally have no server.address and must
        # not inflate the declared blackbox inventory.
        if service and address and isinstance(value, list) and len(value) == 2:
            values[str(service)] = float(value[1])
            ages[str(service)] = max(0.0, time.time() - float(value[0]))
            addresses[str(service)] = str(address).rstrip("/") or str(address)
    expected_ids, observed_ids = set(expected), set(values)
    missing = sorted(expected_ids - observed_ids)
    extra = sorted(observed_ids - expected_ids)
    mismatched = sorted(
        service
        for service in expected_ids & observed_ids
        if addresses.get(service) != expected.get(service)
    )
    failing = sorted(service for service in expected_ids if values.get(service) != 1.0)
    stale = sorted(
        service
        for service in expected_ids
        if ages.get(service, 10**9) > runtime.series_max_age_seconds
    )
    if missing or extra or mismatched or failing or stale:
        detail = {
            "missing": missing,
            "extra": extra,
            "addressMismatch": mismatched,
            "failing": failing,
            "stale": stale,
        }
        raise CanaryError("blackbox_targets_failed", json.dumps(detail, sort_keys=True))
    return {
        "declaredTargets": [
            {"component": component, "url": expected[component]}
            for component in sorted(expected)
        ],
        "observedSeries": len(values),
        "exactInventory": True,
        "allSuccessful": True,
        "allFresh": True,
    }


def basic_auth(values: dict[str, str]) -> dict[str, str]:
    user = values.get("GRAFANA_ADMIN_USER", "")
    password = values.get("GRAFANA_ADMIN_PASSWORD", "")
    if not user or not password:
        raise CanaryError("missing_grafana_auth", "Grafana credential refs missing")
    encoded = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def grafana_call(
    method: str,
    path: str,
    auth: dict[str, str],
    runtime: ObservabilityRuntime,
    *,
    body: Any | None = None,
    allow_status: set[int] | None = None,
) -> tuple[int, Any]:
    return request_json(
        method,
        runtime.grafana_url + path,
        body=body,
        headers=auth,
        allow_status=allow_status,
        timeout=runtime.http_timeout_seconds,
    )


def reconcile_grafana_once(
    auth: dict[str, str],
    runtime: ObservabilityRuntime,
) -> dict[str, Any]:
    datasource_ids: dict[str, int] = {}
    for uid, expected in runtime.datasources.items():
        status, existing = grafana_call(
            "GET",
            f"/api/datasources/uid/{uid}",
            auth,
            runtime,
            allow_status={404},
        )
        if status == 404:
            status, _ = grafana_call(
                "POST",
                "/api/datasources",
                auth,
                runtime,
                body={"uid": uid, **expected},
            )
            if status not in {200, 201}:
                raise CanaryError("grafana_reconcile_failed", f"create {uid} failed")
            _, existing = grafana_call(
                "GET", f"/api/datasources/uid/{uid}", auth, runtime
            )
        if not isinstance(existing, dict):
            raise CanaryError("grafana_datasource_invalid", f"{uid} invalid")
        drift = [
            key
            for key in ("name", "type", "url", "access")
            if existing.get(key) != expected.get(key)
        ]
        if drift:
            raise CanaryError("grafana_datasource_drift", f"{uid}: {','.join(drift)}")
        datasource_ids[uid] = int(existing.get("id", 0))

    folder_uid = "mte-platform"
    status, folder = grafana_call(
        "GET",
        f"/api/folders/{folder_uid}",
        auth,
        runtime,
        allow_status={404},
    )
    if status == 404:
        _, folders = grafana_call("GET", "/api/folders?limit=1000", auth, runtime)
        exact_folders = (
            [item for item in folders if item.get("title") == "MTE Platform"]
            if isinstance(folders, list)
            else []
        )
        if len(exact_folders) > 1:
            raise CanaryError("grafana_reconcile_duplicate", "folder count exceeds one")
        if exact_folders:
            folder = exact_folders[0]
        else:
            status, _ = grafana_call(
                "POST",
                "/api/folders",
                auth,
                runtime,
                body={"uid": folder_uid, "title": "MTE Platform"},
            )
            if status not in {200, 201, 409}:
                raise CanaryError("grafana_reconcile_failed", "folder create failed")
            _, folder = grafana_call("GET", f"/api/folders/{folder_uid}", auth, runtime)
    if not isinstance(folder, dict) or folder.get("title") != "MTE Platform":
        raise CanaryError("grafana_folder_drift", "MTE Platform folder drifted")

    account_name = "mte-observability-prober"
    search_path = "/api/serviceaccounts/search?" + urllib.parse.urlencode(
        {"query": account_name, "perpage": 100},
    )
    _, search = grafana_call("GET", search_path, auth, runtime)
    accounts = search.get("serviceAccounts", []) if isinstance(search, dict) else []
    exact = [item for item in accounts if item.get("name") == account_name]
    if not exact:
        status, _ = grafana_call(
            "POST",
            "/api/serviceaccounts",
            auth,
            runtime,
            body={"name": account_name, "role": "Viewer", "isDisabled": False},
        )
        if status not in {200, 201}:
            raise CanaryError(
                "grafana_reconcile_failed", "service account create failed"
            )
        _, search = grafana_call("GET", search_path, auth, runtime)
        accounts = search.get("serviceAccounts", []) if isinstance(search, dict) else []
        exact = [item for item in accounts if item.get("name") == account_name]
    if len(exact) != 1:
        raise CanaryError(
            "grafana_reconcile_duplicate", "service account count is not one"
        )
    fingerprint = {
        "datasourceIds": datasource_ids,
        "folderId": folder.get("id"),
        "folderUid": folder.get("uid"),
        "serviceAccountId": exact[0].get("id"),
        "serviceAccountCount": len(exact),
    }
    fingerprint["sha256"] = hashlib.sha256(
        json.dumps(
            fingerprint,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return fingerprint


def grafana_reconcile_twice(
    auth: dict[str, str],
    runtime: ObservabilityRuntime,
) -> dict[str, Any]:
    first = reconcile_grafana_once(auth, runtime)
    second = reconcile_grafana_once(auth, runtime)
    if first != second or second.get("serviceAccountCount") != 1:
        raise CanaryError(
            "reconcile_not_idempotent", "second reconcile changed identity"
        )
    return {"first": first, "second": second, "idempotent": True}


def run_json_command(argv: list[str], runtime: ObservabilityRuntime) -> Any:
    completed = run(argv, timeout=runtime.command_timeout_seconds)
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CanaryError("command_json_invalid", Path(argv[1]).name) from exc


def canonical_compose_command(*arguments: str) -> list[str]:
    return [
        "docker",
        "compose",
        "--env-file",
        str(COMPOSE_ENV),
        "-f",
        str(COMPOSE),
        *arguments,
    ]


def canonical_compose_environment() -> dict[str, str]:
    allowed = {
        key: value
        for key, value in os.environ.items()
        if key
        in {
            "HOME",
            "PATH",
            "DOCKER_CONFIG",
            "DOCKER_CONTEXT",
            "DOCKER_HOST",
            "XDG_CONFIG_HOME",
            "XDG_RUNTIME_DIR",
        }
    }
    allowed.setdefault("HOME", "/root")
    allowed.setdefault(
        "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    )
    return allowed


def compose_inventory(runtime: ObservabilityRuntime) -> dict[str, Any]:
    expected = {
        row.strip()
        for row in run(
            canonical_compose_command("config", "--services"),
            timeout=runtime.command_timeout_seconds,
            env=canonical_compose_environment(),
        ).stdout.splitlines()
        if row.strip()
    }
    observed: dict[str, dict[str, Any]] = {}
    for item in docker_inventory(runtime, all_containers=True):
        labels = item.get("Labels") or {}
        if labels.get("com.docker.compose.project") != COMPOSE_PROJECT:
            continue
        service = str(labels.get("com.docker.compose.service") or "")
        if not service or service in observed:
            raise CanaryError("indexed_inventory_duplicate", service or "compose")
        state = item.get("State") if isinstance(item.get("State"), dict) else {}
        status = str(state.get("Status") or "")
        running = state.get("Running") is True
        health_document = (
            state.get("Health") if isinstance(state.get("Health"), dict) else {}
        )
        health = str(health_document.get("Status") or "not-configured")
        if service in ONE_SHOT_COMPOSE_SERVICES:
            if running or status != "exited" or state.get("ExitCode") != 0:
                raise CanaryError("indexed_compose_runtime_not_ready", service)
        elif not running or status != "running" or health not in {
            "healthy",
            "not-configured",
        }:
            raise CanaryError("indexed_compose_runtime_not_ready", service)
        observed[service] = {
            "container": str(item.get("Name") or "").lstrip("/"),
            "configHash": str(labels.get("com.docker.compose.config-hash") or ""),
            "image": str(item.get("Image") or ""),
            "state": status,
            "running": running,
            "health": health,
        }
        if service in ONE_SHOT_COMPOSE_SERVICES:
            observed[service]["exitCode"] = state.get("ExitCode")
    if (
        not expected
        or set(observed) != expected
        or any(
            not row["container"] or not row["configHash"] or not row["image"]
            for row in observed.values()
        )
    ):
        raise CanaryError("indexed_compose_inventory_invalid", "aggregate-compose")
    identity = {key: observed[key] for key in sorted(observed)}
    return {
        "project": COMPOSE_PROJECT,
        "services": identity,
        "componentCount": len(identity),
        "identitySha256": canonical_json_sha256(identity),
    }


def indexed_inventory(
    expected_hash: str,
    runtime: ObservabilityRuntime,
    values: dict[str, str],
) -> dict[str, Any]:
    gate = exact_hash_gate(expected_hash, load_json(CONFIG), load_json(MANIFEST))
    provisioner = run_json_command(
        ["python3", str(SERVER_BIN / "server-provision.py"), "status"], runtime
    )
    toolhive = run_json_command(
        ["python3", str(SERVER_BIN / "server-toolhive.py"), "status"], runtime
    )
    profile = run_json_command(
        ["python3", str(SERVER_BIN / "server-profile-reconcile.py"), "status"],
        runtime,
    )
    if provisioner.get("ok") is not True or provisioner.get("incomplete") != []:
        raise CanaryError("indexed_provisioner_not_ready", "status")
    if toolhive.get("binary") != "ready" or toolhive.get("canary") != "ready":
        raise CanaryError("indexed_toolhive_not_ready", "status")
    if profile.get("status") != "passed" or profile.get("ok") is not True:
        raise CanaryError("indexed_profile_not_finalized", "status")
    for name, document in (
        ("provisioner", provisioner),
        ("toolhive", toolhive),
        ("profileReconcile", profile),
    ):
        assert_no_list_duplicates(document, name)
    profile_rows = (
        profile.get("profiles") if isinstance(profile.get("profiles"), list) else []
    )
    profile_summary = [
        {
            "profileRef": row.get("profileRef"),
            "paperclip": (row.get("paperclip") or {}).get("status") == "ready",
            "toolhive": (row.get("toolhive") or {}).get("status") == "ready",
            "kestra": (row.get("kestra") or {}).get("status") == "ready",
        }
        for row in profile_rows
        if isinstance(row, dict)
    ]
    toolhive_identity = {
        **stable_projection(toolhive),
        "profileBundles": [
            {"profileRef": row["profileRef"], "status": "ready"}
            for row in profile_summary
            if row.get("toolhive") is True
        ],
    }
    identity = {
        "compose": compose_inventory(runtime),
        "provisioner": stable_projection(provisioner),
        "toolhive": toolhive_identity,
        "profileReconcile": {"profiles": profile_summary},
    }
    scan_for_secrets(identity, values)
    return {
        "sourceGate": gate,
        "identity": identity,
        "identitySha256": canonical_json_sha256(identity),
        "noDuplicates": True,
    }


def indexed_reconcile_pass(
    expected_hash: str,
    pass_number: int,
) -> dict[str, Any]:
    if pass_number not in INDEX_PASS:
        raise CanaryError("invalid_reconcile_pass", str(pass_number))
    config, manifest = load_json(CONFIG), load_json(MANIFEST)
    values = runtime_values(dotenv(PLATFORM_ENV), config, manifest)
    runtime = observability_runtime(values)
    before = indexed_inventory(expected_hash, runtime, values)
    run(
        canonical_compose_command("up", "-d", "--wait"),
        timeout=runtime.command_timeout_seconds,
        env=canonical_compose_environment(),
    )
    provisioner = run_json_command(
        ["python3", str(SERVER_BIN / "server-provision.py"), "provision"], runtime
    )
    if (
        provisioner.get("ok") is not True
        or provisioner.get("incomplete") != []
        or (provisioner.get("canonicalMutationGuard") or {}).get("changedKeys") != []
    ):
        raise CanaryError("indexed_provisioner_not_idempotent", str(pass_number))
    run_json_command(
        ["python3", str(SERVER_BIN / "server-toolhive.py"), "provision"], runtime
    )
    grafana = reconcile_grafana_once(basic_auth(values), runtime)
    after = indexed_inventory(expected_hash, runtime, values)
    before_services = before["identity"]["compose"]["services"]
    after_services = after["identity"]["compose"]["services"]
    actions = {
        service: (
            "unchanged"
            if before_services.get(service) == after_services.get(service)
            else "changed"
        )
        for service in sorted(after_services)
    }
    if pass_number == 2 and set(actions.values()) != {"unchanged"}:
        raise CanaryError("indexed_second_pass_changed", "aggregate-compose")
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "IndexedReconcilePass",
        "pass": pass_number,
        "status": "passed",
        "completedAt": utcnow(),
        "producerSha256": producer_sha256(),
        "producerHashes": producer_hashes(),
        "sourceGate": after["sourceGate"],
        "before": before,
        "after": after,
        "composeActions": actions,
        "provisionerIdentitySha256": canonical_json_sha256(
            after["identity"]["provisioner"]
        ),
        "toolhiveIdentitySha256": canonical_json_sha256(after["identity"]["toolhive"]),
        "grafanaFingerprint": grafana["sha256"],
    }
    scan_for_secrets(payload, values)
    atomic_json(INDEX_PASS[pass_number], payload)
    return payload


def finalize_indexed_idempotency(expected_hash: str) -> dict[str, Any]:
    gate = exact_hash_gate(expected_hash, load_json(CONFIG), load_json(MANIFEST))
    first, second = load_json(INDEX_PASS[1]), load_json(INDEX_PASS[2])
    current_hashes = producer_hashes()
    if first.get("sourceGate") != gate or second.get("sourceGate") != gate:
        raise CanaryError("indexed_source_gate_drift", "reconcile passes")
    if (
        first.get("producerHashes") != current_hashes
        or second.get("producerHashes") != current_hashes
    ):
        raise CanaryError("indexed_producer_drift", "reconcile passes")
    first_after = (first.get("after") or {}).get("identitySha256")
    second_before = (second.get("before") or {}).get("identitySha256")
    second_after = (second.get("after") or {}).get("identitySha256")
    if not first_after or first_after != second_before or second_before != second_after:
        raise CanaryError("indexed_identity_changed", "reconcile passes")
    actions = second.get("composeActions") or {}
    if not actions or set(actions.values()) != {"unchanged"}:
        raise CanaryError("indexed_second_pass_changed", "aggregate-compose")
    if (
        first.get("provisionerIdentitySha256")
        != second.get("provisionerIdentitySha256")
        or first.get("toolhiveIdentitySha256") != second.get("toolhiveIdentitySha256")
        or first.get("grafanaFingerprint") != second.get("grafanaFingerprint")
    ):
        raise CanaryError("indexed_identity_changed", "reconciler identities")
    if not (first.get("after") or {}).get("noDuplicates") or not (
        second.get("after") or {}
    ).get("noDuplicates"):
        raise CanaryError("indexed_inventory_duplicate", "reconcile passes")
    identity = (second.get("after") or {}).get("identity") or {}
    compose = identity.get("compose") or {}
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "IndexedDeployIdempotencyEvidence",
        "status": "passed",
        "completedAt": utcnow(),
        "producerSha256": producer_sha256(),
        "producerHashes": current_hashes,
        "sourceGate": gate,
        "componentCount": compose.get("componentCount"),
        "stableComposeIdentity": True,
        "noDuplicateResources": True,
        "secondPassNoChange": True,
        "inventoryIdentitySha256": second_after,
        "passes": [str(INDEX_PASS[1]), str(INDEX_PASS[2])],
        "coverage": [
            "direct-compose-all-indexed-components",
            "server-provision-all-adapters",
            "toolhive-provisioning",
            "grafana-provisioning",
            "canonical-aggregate-compose",
            "live-runtime-labels",
        ],
    }
    atomic_json(INDEX_FINAL, payload)
    return payload


def secret_permissions_proof(manifest: dict[str, Any]) -> dict[str, Any]:
    if not SECRET_ROOT.is_dir():
        raise CanaryError("secret_permissions_invalid", "secret root missing")
    directories = [path for path in SECRET_ROOT.rglob("*") if path.is_dir()]
    directories.append(SECRET_ROOT)
    # Provider executables are supply-chain artifacts, not secret projections;
    # their execute bit must remain intact. Everything else in the secret store
    # is root-readable only.
    files = [
        path
        for path in SECRET_ROOT.rglob("*")
        if path.is_file() and ".terraform/providers" not in str(path)
    ]
    manifest_files = {
        Path(str(row.get("path")))
        for row in manifest.get("projections", [])
        if isinstance(row, dict)
        and row.get("path")
        and (
            Path(str(row.get("path"))) == SECRET_ROOT
            or SECRET_ROOT in Path(str(row.get("path"))).parents
        )
    }
    required = {
        PLATFORM_ENV,
        MANIFEST,
        SECRET_ROOT / ".platform-env.lock",
        *manifest_files,
    }
    missing = [path for path in required if not path.is_file()]
    bad_dirs = [
        path
        for path in directories
        if path.stat().st_uid != 0
        or path.stat().st_gid != 0
        or path.stat().st_mode & 0o777 != 0o700
    ]
    bad_files = [
        path
        for path in files
        if path.stat().st_uid != 0
        or path.stat().st_gid != 0
        or path.stat().st_mode & 0o777 != 0o600
    ]
    if missing or bad_dirs or bad_files:
        raise CanaryError(
            "secret_permissions_invalid",
            f"missing={len(missing)},dirs={len(bad_dirs)},files={len(bad_files)}",
        )
    aliases = sorted(
        path.name
        for path in (
            SECRET_ROOT / ".platform-env.lock",
            SECRET_ROOT / ".platform.env.lock",
            SECRET_ROOT / "platform.env.lock",
        )
        if path.exists()
    )
    return {
        "secretRoot": str(SECRET_ROOT),
        "directoryCount": len(directories),
        "fileCount": len(files),
        "registeredProjectionCount": len(manifest_files),
        "lockAliasesAudited": aliases,
        "owner": "root:root",
        "directoryMode": "0700",
        "fileMode": "0600",
        "valuesReadIntoEvidence": False,
    }


def grafana_queries(
    auth: dict[str, str],
    run_id: str,
    trace_id: str,
    runtime: ObservabilityRuntime,
) -> dict[str, Any]:
    health: dict[str, str] = {}
    for uid in runtime.datasources:
        status, body = grafana_call(
            "GET",
            f"/api/datasources/uid/{uid}/health",
            auth,
            runtime,
        )
        if status != 200:
            raise CanaryError("grafana_datasource_unhealthy", uid)
        health[uid] = (
            str(body.get("status", "unknown")) if isinstance(body, dict) else "http-200"
        )
    metric_path = (
        "/api/datasources/proxy/uid/victoriametrics/api/v1/query?"
        + urllib.parse.urlencode(
            {
                "query": f'mte_observability_canary{{run_id="{run_id}"}}',
            }
        )
    )
    _, metric = grafana_call("GET", metric_path, auth, runtime)
    log_path = (
        "/api/datasources/proxy/uid/victorialogs/select/logsql/query?"
        + urllib.parse.urlencode({"query": f'run_id:="{run_id}"'})
    )
    log_status, logs = grafana_call("GET", log_path, auth, runtime)
    trace_status, trace = grafana_call(
        "GET",
        f"/api/datasources/proxy/uid/victoriatraces/api/traces/{trace_id}",
        auth,
        runtime,
    )
    metric_rows = (
        metric.get("data", {}).get("result", []) if isinstance(metric, dict) else []
    )
    if not metric_rows or log_status != 200 or not logs:
        raise CanaryError("grafana_query_failed", "metric or log query empty")
    if trace_status != 200 or not isinstance(trace, dict) or not trace.get("data"):
        raise CanaryError("grafana_query_failed", "trace query empty")
    return {
        "health": health,
        "metricSeries": len(metric_rows),
        "logsFound": True,
        "traceFound": True,
    }


def postgres_path_specs(
    values: dict[str, str],
    apps: dict[str, str],
) -> list[dict[str, str]]:
    profile = values.get("DATA_CONTENT_PROFILE", "").strip()
    contract = PROFILE_RUNTIME_CONTRACTS.get(profile)
    if not contract:
        raise CanaryError(
            "unsupported_data_content_profile", profile or "missing-profile"
        )
    expected_apps = {
        "mattermost",
        "firecrawl-api",
        "kestra",
        "searxng",
        *contract["componentIds"],
    }
    if set(apps) != expected_apps:
        raise CanaryError("application_path_profile_mismatch", profile)
    common = [
        (
            "postgrest",
            "POSTGREST_DB_HOST",
            "POSTGREST_DB_PORT",
            "POSTGREST_DB_LOGIN_ROLE",
            "POSTGREST_DATA_DB_NAME",
            "POSTGREST_AUTHENTICATOR_PASSWORD",
        ),
        (
            "mattermost",
            "MATTERMOST_DB_HOST",
            "MATTERMOST_DB_PORT",
            "MATTERMOST_DB_USER",
            "MATTERMOST_DB_NAME",
            "MATTERMOST_DB_PASSWORD",
        ),
        (
            "firecrawl-api",
            "MTE_FIRECRAWL_API_ENV_POSTGRES_HOST",
            "MTE_FIRECRAWL_API_ENV_POSTGRES_PORT",
            "FIRECRAWL_DB_USER",
            "FIRECRAWL_DB_NAME",
            "FIRECRAWL_DB_PASSWORD",
        ),
        (
            "kestra",
            "KESTRA_DB_HOST",
            "KESTRA_DB_PORT",
            "KESTRA_DB_USER",
            "KESTRA_DB_NAME",
            "KESTRA_DB_PASSWORD",
        ),
    ]
    raw = common
    specs: list[dict[str, str]] = []
    for role, host_ref, port_ref, user_ref, db_ref, password_ref in raw:
        host = values.get(host_ref, "")
        port = values.get(port_ref, "")
        user = values.get(user_ref, "")
        database = values.get(db_ref, "")
        password = values.get(password_ref, "")
        if (
            not all((apps.get(role), host, port, user, database, password))
            or not port.isdigit()
            or not (1 <= int(port) <= 65535)
        ):
            raise CanaryError("postgres_path_config_missing", role)
        specs.append(
            {
                "role": role,
                "container": apps[role],
                "host": host,
                "port": port,
                "user": user,
                "database": database,
                "password": password,
                "passwordRef": password_ref,
            }
        )
    return specs


def postgres_rw_delete(
    values: dict[str, str],
    apps: dict[str, str],
    marker: str,
    runtime: ObservabilityRuntime,
) -> list[dict[str, Any]]:
    if not re.fullmatch(r"[a-z0-9-]+", marker):
        raise CanaryError("invalid_run_id", "unsafe PostgreSQL marker")
    sql = (
        "BEGIN;\n"
        "CREATE TEMP TABLE mte_observability_canary(marker text primary key);\n"
        f"INSERT INTO mte_observability_canary VALUES ('{marker}');\n"
        "SELECT count(*) FROM mte_observability_canary;\n"
        f"DELETE FROM mte_observability_canary WHERE marker = '{marker}' RETURNING 1;\n"
        "SELECT count(*) FROM mte_observability_canary;\n"
        "ROLLBACK;\n"
    )
    image = values.get("MTE_POSTGRES_POSTGRES_IMAGE", "")
    if not image:
        raise CanaryError("postgres_client_image_missing", "image ref missing")
    proof: list[dict[str, Any]] = []
    for spec in postgres_path_specs(values, apps):
        child_env = {
            **os.environ,
            "PGPASSWORD": spec["password"],
            "PGCONNECT_TIMEOUT": str(runtime.http_timeout_seconds),
        }
        result = run(
            [
                "docker",
                "run",
                "-i",
                "--rm",
                "--pull=never",
                "--network",
                f"container:{spec['container']}",
                "-e",
                "PGPASSWORD",
                "-e",
                "PGCONNECT_TIMEOUT",
                image,
                "psql",
                "-X",
                "-qAt",
                "-v",
                "ON_ERROR_STOP=1",
                "-h",
                spec["host"],
                "-p",
                spec["port"],
                "-U",
                spec["user"],
                "-d",
                spec["database"],
            ],
            stdin=sql,
            env=child_env,
            timeout=runtime.command_timeout_seconds,
        )
        rows = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip().isdigit()
        ]
        if rows[-3:] != ["1", "1", "0"]:
            raise CanaryError("postgres_canary_failed", spec["role"])
        proof.append(
            {
                "role": spec["role"],
                "networkNamespace": spec["role"],
                "databaseIdentityRef": spec["passwordRef"],
                "credentialInArgv": False,
                "inserted": 1,
                "read": 1,
                "deleted": 1,
                "remaining": 0,
            }
        )
    return proof


def redis_path_specs(
    values: dict[str, str],
    apps: dict[str, str],
) -> list[dict[str, str]]:
    profile = values.get("DATA_CONTENT_PROFILE", "").strip()
    contract = PROFILE_RUNTIME_CONTRACTS.get(profile)
    if not contract:
        raise CanaryError(
            "unsupported_data_content_profile", profile or "missing-profile"
        )
    expected_apps = {
        "mattermost",
        "firecrawl-api",
        "kestra",
        "searxng",
        *contract["componentIds"],
    }
    if set(apps) != expected_apps:
        raise CanaryError("application_path_profile_mismatch", profile)
    raw = [
        ("firecrawl-api", "FIRECRAWL_REDIS_URL"),
        ("searxng", "SEARXNG_VALKEY_URL"),
    ]
    specs: list[dict[str, str]] = []
    for role, url_ref in raw:
        url = values.get(url_ref, "")
        parsed = urllib.parse.urlsplit(url)
        try:
            port = parsed.port
        except ValueError as exc:
            raise CanaryError("redis_path_auth_missing", role) from exc
        if (
            not apps.get(role)
            or parsed.scheme not in {"redis", "rediss"}
            or not parsed.hostname
            or not parsed.password
            or port is None
        ):
            raise CanaryError("redis_path_auth_missing", role)
        specs.append(
            {
                "role": role,
                "container": apps[role],
                "urlRef": url_ref,
                "host": parsed.hostname,
                "port": str(port),
                "password": urllib.parse.unquote(parsed.password),
            }
        )
    return specs


def redis_authenticated_paths(
    values: dict[str, str],
    apps: dict[str, str],
    runtime: ObservabilityRuntime,
) -> list[dict[str, Any]]:
    image = values.get("MTE_SEARXNG_VALKEY_IMAGE", "")
    if not image:
        raise CanaryError("redis_client_image_missing", "image ref missing")
    proof: list[dict[str, Any]] = []
    for spec in redis_path_specs(values, apps):
        unauth = run(
            [
                "docker",
                "run",
                "--rm",
                "--pull=never",
                "--network",
                f"container:{spec['container']}",
                image,
                "redis-cli",
                "-h",
                spec["host"],
                "-p",
                spec["port"],
                "PING",
            ],
            timeout=runtime.command_timeout_seconds,
            allow_failure=True,
        )
        if "NOAUTH" not in (unauth.stdout + unauth.stderr).upper():
            raise CanaryError("redis_auth_not_enforced", spec["role"])
        child_env = {**os.environ, "REDISCLI_AUTH": spec["password"]}
        authenticated = run(
            [
                "docker",
                "run",
                "--rm",
                "--pull=never",
                "--network",
                f"container:{spec['container']}",
                "-e",
                "REDISCLI_AUTH",
                image,
                "redis-cli",
                "--no-auth-warning",
                "-h",
                spec["host"],
                "-p",
                spec["port"],
                "PING",
            ],
            env=child_env,
            timeout=runtime.command_timeout_seconds,
        )
        if authenticated.stdout.strip() != "PONG":
            raise CanaryError("redis_authenticated_ping_failed", spec["role"])
        proof.append(
            {
                "role": spec["role"],
                "networkNamespace": spec["role"],
                "credentialRef": spec["urlRef"],
                "unauthenticatedRejected": True,
                "authenticatedPing": "PONG",
            }
        )
    return proof


def runtime_alert_config(
    values: dict[str, str],
    runtime: ObservabilityRuntime,
    config_root: Path | None = None,
) -> dict[str, Any]:
    if config_root is None:
        mountpoint = run(
            [
                "docker",
                "volume",
                "inspect",
                "mte-observability-config",
                "--format",
                "{{.Mountpoint}}",
            ],
            timeout=runtime.command_timeout_seconds,
        ).stdout.strip()
        config_root = Path(mountpoint)
    try:
        alertmanager = (config_root / "alertmanager.yml").read_text()
        rules = (config_root / "rules.yml").read_text()
    except OSError as exc:
        raise CanaryError(
            "alert_runtime_config_missing", "alert config unreadable"
        ) from exc
    canonical_webhook = values.get("MATTERMOST_ALERT_WEBHOOK_URL", "").strip()
    try:
        parsed_webhook = urllib.parse.urlsplit(canonical_webhook)
    except ValueError as exc:
        raise CanaryError(
            "mattermost_receiver_not_deployed", "canonical webhook is invalid"
        ) from exc
    if (
        parsed_webhook.scheme not in {"http", "https"}
        or not parsed_webhook.hostname
        or parsed_webhook.username
        or parsed_webhook.password
        or parsed_webhook.query
        or parsed_webhook.fragment
        or not parsed_webhook.path.startswith("/hooks/")
    ):
        raise CanaryError(
            "mattermost_receiver_not_deployed", "canonical webhook is invalid"
        )
    deployed_webhook = f"http://mattermost:8065{parsed_webhook.path}"
    receiver_ready = (
        deployed_webhook in alertmanager
        and "receiver: mattermost" in alertmanager
        and "send_resolved: true" in alertmanager
    )
    selector_ready = (
        'probe_success{service.name="platform_health"}' in rules
        or 'probe_success{"service.name"="platform_health"}' in rules
    )
    if not receiver_ready:
        raise CanaryError(
            "mattermost_receiver_not_deployed",
            "runtime Alertmanager receiver is not the canonical webhook",
        )
    if not selector_ready:
        raise CanaryError(
            "vmalert_selector_not_deployed",
            "runtime rule does not select OTel service.name label",
        )
    canonical_fingerprint = hashlib.sha256(canonical_webhook.encode()).hexdigest()
    deployed_fingerprint = hashlib.sha256(deployed_webhook.encode()).hexdigest()
    return {
        "mattermostReceiverReady": True,
        "webhookCredentialRef": "MATTERMOST_ALERT_WEBHOOK_URL",
        "canonicalWebhookFingerprintSha256": canonical_fingerprint,
        "deployedWebhookFingerprintSha256": deployed_fingerprint,
        "webhookPathPreserved": (
            urllib.parse.urlsplit(deployed_webhook).path == parsed_webhook.path
        ),
        "sendResolved": True,
        "otelLabelSelectorReady": True,
    }


def alertmanager_matches(
    run_id: str,
    runtime: ObservabilityRuntime,
) -> list[dict[str, Any]]:
    _, body = request_json(
        "GET",
        runtime.alertmanager_url + "/api/v2/alerts",
        timeout=runtime.http_timeout_seconds,
    )
    if not isinstance(body, list):
        raise CanaryError("alertmanager_invalid", "alerts response invalid")
    instance = f"mte-canary:{run_id}"
    return [item for item in body if item.get("labels", {}).get("instance") == instance]


def vmalert_matches(
    run_id: str,
    runtime: ObservabilityRuntime,
) -> list[dict[str, Any]]:
    _, body = request_json(
        "GET",
        runtime.vmalert_url + "/api/v1/alerts",
        timeout=runtime.http_timeout_seconds,
    )
    alerts = body.get("data", {}).get("alerts", []) if isinstance(body, dict) else []
    instance = f"mte-canary:{run_id}"
    return [
        item for item in alerts if item.get("labels", {}).get("instance") == instance
    ]


def mattermost_post_state(
    container: str,
    run_id: str,
    runtime: ObservabilityRuntime,
) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9-]+", run_id):
        raise CanaryError("invalid_run_id", "unsafe Mattermost marker")
    sql = (
        "SELECT count(*),"
        "coalesce(bool_or(lower(p.message || ' ' || p.props::text) "
        "LIKE '%firing%'),false),"
        "coalesce(bool_or(lower(p.message || ' ' || p.props::text) "
        "LIKE '%resolved%'),false),"
        "coalesce(min(nullif(u.username,'')),"
        "min(nullif(p.props::jsonb->>'override_username','')),'incoming-webhook'),"
        "coalesce(min(c.name),''),"
        "count(distinct p.userid),count(distinct p.channelid) "
        "FROM public.posts p "
        "LEFT JOIN public.users u ON u.id=p.userid "
        "LEFT JOIN public.channels c ON c.id=p.channelid "
        "WHERE lower(p.message || ' ' || p.props::text) "
        f"LIKE '%{run_id}%';"
    )
    result = run(
        [
            "docker",
            "exec",
            "-i",
            container,
            "sh",
            "-ec",
            'psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
        ],
        stdin=sql,
        timeout=runtime.command_timeout_seconds,
    )
    fields = result.stdout.strip().split("|")
    if len(fields) != 7:
        raise CanaryError("mattermost_proof_invalid", "post query invalid")
    return {
        "matchingPosts": int(fields[0]),
        "firing": fields[1] == "t",
        "resolved": fields[2] == "t",
        "author": fields[3],
        "channel": fields[4],
        "distinctAuthors": int(fields[5]),
        "distinctChannels": int(fields[6]),
    }


def mattermost_cleanup_posts(
    container: str,
    run_id: str,
    runtime: ObservabilityRuntime,
) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9-]+", run_id):
        raise CanaryError("invalid_run_id", "unsafe Mattermost marker")
    sql = (
        "WITH deleted AS (DELETE FROM public.posts "
        "WHERE lower(message || ' ' || props::text) "
        f"LIKE '%{run_id}%' RETURNING 1) SELECT count(*) FROM deleted;"
        "SELECT count(*) FROM public.posts "
        "WHERE lower(message || ' ' || props::text) "
        f"LIKE '%{run_id}%';"
    )
    result = run(
        [
            "docker",
            "exec",
            "-i",
            container,
            "sh",
            "-ec",
            'psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
        ],
        stdin=sql,
        timeout=runtime.command_timeout_seconds,
    )
    fields = result.stdout.strip().splitlines()
    if len(fields) != 2 or not all(field.isdigit() for field in fields):
        raise CanaryError("mattermost_cleanup_invalid", "cleanup query invalid")
    deleted, remaining = map(int, fields)
    if remaining != 0:
        raise CanaryError("mattermost_cleanup_failed", "canary posts remain")
    return {
        "deletedPosts": deleted,
        "remainingPosts": remaining,
        "cleanupVerified": True,
    }


def fire_and_resolve_alert(
    run_id: str,
    mattermost_db: str,
    runtime: ObservabilityRuntime,
) -> dict[str, Any]:
    def emit(value: int) -> None:
        send_otlp("metrics", probe_metric_payload(run_id, value), runtime)

    emit(0)
    started = time.monotonic()

    def firing() -> dict[str, Any] | bool:
        emit(0)
        vm = vmalert_matches(run_id, runtime)
        am = alertmanager_matches(run_id, runtime)
        mm = mattermost_post_state(mattermost_db, run_id, runtime)
        if vm and am and mm["firing"]:
            return {"vmalert": len(vm), "alertmanager": len(am), "mattermost": mm}
        return False

    def resolved() -> dict[str, Any] | bool:
        emit(1)
        vm = vmalert_matches(run_id, runtime)
        am = alertmanager_matches(run_id, runtime)
        mm = mattermost_post_state(mattermost_db, run_id, runtime)
        if not vm and not am and mm["resolved"]:
            return {"vmalert": 0, "alertmanager": 0, "mattermost": mm}
        return False

    # Always clear the injected zero and delete the exact canary posts,
    # including timeout/error paths.
    try:
        try:
            fired = wait_for(
                firing,
                timeout=runtime.alert_fire_timeout_seconds,
                interval=runtime.alert_poll_interval_seconds,
            )
        finally:
            emit(1)
        cleared = wait_for(
            resolved,
            timeout=runtime.alert_resolve_timeout_seconds,
            interval=runtime.alert_poll_interval_seconds,
        )
        if (
            cleared["mattermost"].get("channel") != "mte-alerts"
            or not cleared["mattermost"].get("author")
            or cleared["mattermost"].get("distinctChannels") != 1
        ):
            raise CanaryError(
                "mattermost_post_identity_invalid", "author/channel mismatch"
            )
        cleanup = mattermost_cleanup_posts(mattermost_db, run_id, runtime)
        return {
            "firing": fired,
            "resolved": cleared,
            "cleanup": cleanup,
            "transitionSeconds": round(time.monotonic() - started, 3),
            "rulePath": "probe_success -> vmalert -> Alertmanager -> Mattermost",
        }
    except BaseException:
        # The zero is already cleared in the inner finally. Remove any canary
        # posts even when the semantic acceptance later fails.
        mattermost_cleanup_posts(mattermost_db, run_id, runtime)
        raise


def scan_for_secrets(payload: dict[str, Any], values: dict[str, str]) -> None:
    rendered = json.dumps(payload, sort_keys=True)
    for key, value in values.items():
        if (
            SENSITIVE_EVIDENCE_KEY_RE.search(key)
            and len(value) >= 8
            and value in rendered
        ):
            raise CanaryError("evidence_secret_leak", f"exact value for {key}")
    patterns = (
        r"github_pat_[A-Za-z0-9_]+",
        r"Bearer\s+[A-Za-z0-9._~-]+",
        r"postgres(?:ql)?://[^\s\"']+",
        r"redis://[^\s\"']+",
        r"https?://[^\s\"']+/hooks/[A-Za-z0-9]+",
    )
    if any(re.search(pattern, rendered, re.IGNORECASE) for pattern in patterns):
        raise CanaryError("evidence_secret_pattern", "credential-shaped evidence")


def preflight(expected_hash: str | None = None) -> dict[str, Any]:
    config, manifest = load_json(CONFIG), load_json(MANIFEST)
    values = runtime_values(dotenv(PLATFORM_ENV), config, manifest)
    runtime = observability_runtime(values)
    profile = runtime_profile(config, values)
    refs = {
        "GRAFANA_ADMIN_USER",
        "GRAFANA_ADMIN_PASSWORD",
        "MATTERMOST_ALERT_WEBHOOK_URL",
    }
    missing = sorted(key for key in refs if not values.get(key))
    if missing:
        raise CanaryError("missing_runtime_refs", ",".join(missing))
    generated = config.get("_generated", {})
    state: dict[str, Any] = {
        "configSourceSha256": generated.get("sourceSha256"),
        "manifestSourceSha256": manifest.get("sourceSha256"),
        "generatorVersion": generated.get("generatorVersion"),
    }
    if expected_hash:
        state = exact_hash_gate(expected_hash, config, manifest)
    inventory = docker_inventory(runtime)
    containers = require_containers(inventory)
    emitters = require_otlp_emitters(inventory)
    apps = application_paths(config, inventory, values)
    postgres_specs = postgres_path_specs(values, apps)
    redis_specs = redis_path_specs(values, apps)
    alert_config = runtime_alert_config(values, runtime)
    return {
        "status": "ready",
        "mutationPerformed": False,
        "hashState": state,
        "runtimeAlertConfig": alert_config,
        "otlpEmitters": emitters,
        "requiredContainerRoles": sorted(containers),
        "applicationPaths": sorted(apps),
        "requiredCredentialRefs": sorted(refs),
        "dataContentProfile": profile["profile"],
        "postgresPathCount": len(postgres_specs),
        "redisPathCount": len(redis_specs),
        "criteria": CRITERIA,
    }


def telemetry_evidence_checks(
    *,
    emitters: dict[str, dict[str, str]],
    app_statuses: dict[str, int],
    runner_statuses: dict[str, int],
    app_run_id: str,
    runner_run_id: str,
    app_trace_id: str,
    runner_trace_id: str,
    app_network: dict[str, Any],
    runner_network: dict[str, Any],
    app_correlated: dict[str, Any],
    runner_correlated: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Build the version-2, dual-emitter telemetry evidence contract."""
    backend_keys = {
        "victoriametricsSeries": "metricSeries",
        "victorialogsRecords": "logRecords",
        "victoriatracesCount": "traceCount",
    }

    def backend(proof: dict[str, Any]) -> dict[str, Any]:
        return {target: proof[source] for target, source in backend_keys.items()}

    return {
        "C040": {
            "status": "pass",
            "emitterCoverage": {"application": True, "runner": True},
            "emitters": {
                "application": {
                    **emitters["application"],
                    "otlpHttpStatus": app_statuses,
                    "runId": app_run_id,
                    "traceId": app_trace_id,
                    "networkLifecycle": app_network,
                    "backendProof": backend(app_correlated),
                },
                "runner": {
                    **emitters["runner"],
                    "otlpHttpStatus": runner_statuses,
                    "runId": runner_run_id,
                    "traceId": runner_trace_id,
                    "networkLifecycle": runner_network,
                    "backendProof": backend(runner_correlated),
                },
            },
        },
        "C044": {
            "status": "pass",
            "traceCount": app_correlated["traceCount"]
            + runner_correlated["traceCount"],
            "traceIds": [app_trace_id, runner_trace_id],
        },
    }


def apply(expected_hash: str) -> dict[str, Any]:
    started = utcnow()
    producer_hash = producer_sha256()
    config, manifest = load_json(CONFIG), load_json(MANIFEST)
    values = runtime_values(dotenv(PLATFORM_ENV), config, manifest)
    runtime = observability_runtime(values)
    profile = runtime_profile(config, values)
    gate = exact_hash_gate(expected_hash, config, manifest)
    inventory = docker_inventory(runtime)
    compose = direct_compose_proof(inventory)
    containers = require_containers(inventory)
    emitters = require_otlp_emitters(inventory)
    apps = application_paths(config, inventory, values)
    alert_config = runtime_alert_config(values, runtime)
    app_run_id = "otel-app-" + secrets.token_hex(6)
    runner_run_id = "otel-runner-" + secrets.token_hex(6)
    app_trace_id, app_span_id = secrets.token_hex(16), secrets.token_hex(8)
    runner_trace_id, runner_span_id = secrets.token_hex(16), secrets.token_hex(8)
    app_payloads = otlp_payloads(
        app_run_id,
        app_trace_id,
        app_span_id,
        time.time_ns(),
        service_name=emitters["application"]["service"],
        container_name=emitters["application"]["container"],
    )
    runner_payloads = otlp_payloads(
        runner_run_id,
        runner_trace_id,
        runner_span_id,
        time.time_ns(),
        service_name=emitters["runner"]["service"],
        container_name=emitters["runner"]["container"],
    )
    app_statuses, app_network = container_otlp_bundle(
        emitters["application"]["container"],
        app_payloads,
        runtime,
    )
    runner_statuses, runner_network = runner_otlp_bundle(
        emitters["runner"]["container"],
        runner_payloads,
        runtime,
    )
    app_correlated = query_correlated_data(app_run_id, app_trace_id, runtime)
    runner_correlated = query_correlated_data(runner_run_id, runner_trace_id, runtime)
    run_id, trace_id = app_run_id, app_trace_id
    checks: dict[str, Any] = {
        **telemetry_evidence_checks(
            emitters=emitters,
            app_statuses=app_statuses,
            runner_statuses=runner_statuses,
            app_run_id=app_run_id,
            runner_run_id=runner_run_id,
            app_trace_id=app_trace_id,
            runner_trace_id=runner_trace_id,
            app_network=app_network,
            runner_network=runner_network,
            app_correlated=app_correlated,
            runner_correlated=runner_correlated,
        ),
        "C041": {
            "status": "pass",
            "host": series_freshness('node_uname_info{service.name="node"}', runtime),
            "containers": series_freshness(
                'container_cpu_usage_seconds_total{service.name="containers"}',
                runtime,
            ),
        },
        "C042": {
            "status": "pass",
            "metricSeries": app_correlated["metricSeries"]
            + runner_correlated["metricSeries"],
        },
        "C043": {
            "status": "pass",
            "logRecords": app_correlated["logRecords"]
            + runner_correlated["logRecords"],
        },
    }
    auth = basic_auth(values)
    checks["C050"] = {
        "status": "pass",
        **grafana_reconcile_twice(auth, runtime),
    }
    checks["C045"] = {
        "status": "pass",
        **grafana_queries(auth, run_id, trace_id, runtime),
    }
    alert = fire_and_resolve_alert(run_id, containers["mattermost"], runtime)
    checks["C047"] = {
        "status": "pass",
        **alert_config,
        "vmalertFiringObserved": bool(alert["firing"]["vmalert"]),
        "alertmanagerFiringObserved": bool(alert["firing"]["alertmanager"]),
        "resolvedObserved": alert["resolved"]["alertmanager"] == 0,
    }
    checks["C048"] = {
        "status": "pass",
        "webhookCredentialRef": alert_config["webhookCredentialRef"],
        "canonicalWebhookFingerprintSha256": alert_config[
            "canonicalWebhookFingerprintSha256"
        ],
        "deployedWebhookFingerprintSha256": alert_config[
            "deployedWebhookFingerprintSha256"
        ],
        "webhookPathPreserved": alert_config["webhookPathPreserved"],
        "mattermostFiringObserved": alert["firing"]["mattermost"]["firing"],
        "mattermostResolvedObserved": alert["resolved"]["mattermost"]["resolved"],
        "matchingPosts": alert["resolved"]["mattermost"]["matchingPosts"],
        "postAuthor": alert["resolved"]["mattermost"]["author"],
        "postChannel": alert["resolved"]["mattermost"]["channel"],
        "postAuthorIdentityCount": alert["resolved"]["mattermost"]["distinctAuthors"],
        "postChannelIdentityCount": alert["resolved"]["mattermost"]["distinctChannels"],
        "cleanup": alert["cleanup"],
    }
    checks["C049"] = {"status": "pass", **blackbox_proof(config, runtime)}
    postgres_paths = postgres_rw_delete(values, apps, run_id, runtime)
    checks["C063"] = {
        "status": "pass",
        "dataContentProfile": profile["profile"],
        "expectedPathCount": len(postgres_paths),
        "applicationPaths": postgres_paths,
    }
    redis_paths = redis_authenticated_paths(values, apps, runtime)
    checks["C064"] = {
        "status": "pass",
        "dataContentProfile": profile["profile"],
        "expectedPathCount": len(redis_paths),
        "applicationPaths": redis_paths,
    }
    checks["C069"] = {
        "status": "pass",
        "contract": compose["contract"],
        "project": compose["project"],
        "noDuplicateResources": compose["noDuplicateServices"],
        "componentCount": compose["serviceCount"],
        "inventoryIdentitySha256": compose["runtimeIdentitySha256"],
        "coverage": ["canonical-aggregate-compose", "live-runtime-labels"],
    }
    checks["C070"] = {"status": "pass", **secret_permissions_proof(manifest)}
    evidence = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "ObservabilityDataCanaryEvidence",
        "schemaVersion": OBSERVABILITY_EVIDENCE_SCHEMA_VERSION,
        "status": "passed",
        "startedAt": started,
        "completedAt": utcnow(),
        "sourceGate": gate,
        "producerSha256": producer_hash,
        "producerHashes": producer_hashes(),
        "runId": run_id,
        "checks": checks,
    }
    scan_for_secrets(evidence, values)
    atomic_json(EVIDENCE, evidence)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=["preflight", "reconcile-pass", "finalize-idempotency", "apply"],
    )
    parser.add_argument("--expected-source-hash")
    parser.add_argument("--pass-number", type=int, choices=(1, 2))
    args = parser.parse_args()
    try:
        if args.command in {"apply", "reconcile-pass", "finalize-idempotency"}:
            if not args.expected_source_hash:
                raise CanaryError("hash_gate_required", "mutation requires final hash")
        if args.command == "reconcile-pass":
            if args.pass_number is None:
                raise CanaryError(
                    "reconcile_pass_required", "--pass-number is required"
                )
            result = indexed_reconcile_pass(
                args.expected_source_hash,
                args.pass_number,
            )
            output = {
                "status": result["status"],
                "evidence": str(INDEX_PASS[args.pass_number]),
            }
        elif args.command == "finalize-idempotency":
            result = finalize_indexed_idempotency(args.expected_source_hash)
            output = {"status": result["status"], "evidence": str(INDEX_FINAL)}
        elif args.command == "apply":
            result = apply(args.expected_source_hash)
            output = {"status": result["status"], "evidence": str(EVIDENCE)}
        else:
            output = preflight(args.expected_source_hash)
        print(json.dumps(output, sort_keys=True))
        return 0
    except CanaryError as exc:
        print(json.dumps({"status": "failed", "reason": exc.code, "message": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

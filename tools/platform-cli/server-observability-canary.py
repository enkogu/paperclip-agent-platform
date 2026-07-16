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
import time
from typing import Any, Callable
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
POSTGREST_VERIFY_EVIDENCE = ROOT / "evidence/postgrest-verify.json"
NOTION_VERIFY_EVIDENCE = ROOT / "evidence/notion-connector-verify.json"
ACTIVEPIECES_PROVISION_EVIDENCE = ROOT / "evidence/provision-activepieces.json"
INDEX_PASS = {
    1: ROOT / "evidence/indexed-reconcile-pass-1.json",
    2: ROOT / "evidence/indexed-reconcile-pass-2.json",
}
INDEX_FINAL = ROOT / "evidence/indexed-reconcile-idempotency.json"
HOST_DOKPLOY_EVIDENCE = ROOT / "evidence/host-dokploy-acceptance.json"
OTLP = "http://127.0.0.1:4318"
OTLP_EMITTER_CONTAINER = "mte-paperclip"
OTLP_EMITTER_SERVICE = "paperclip"
OTLP_RUNNER_CONTAINER = "mte-daytona-runner"
OTLP_RUNNER_SERVICE = "daytona-runner"
VM = "http://127.0.0.1:18428"
VL = "http://127.0.0.1:19428"
VT = "http://127.0.0.1:10428/select/jaeger"
VMALERT = "http://127.0.0.1:18881"
ALERTMANAGER = "http://127.0.0.1:19093"
GRAFANA = "http://127.0.0.1:13000"
GENERATOR_VERSION = "mte-config-renderer/v1"
OBSERVABILITY_EVIDENCE_SCHEMA_VERSION = 2

POSTGRES_VOLUMES = {
    "application-data": "mte-postgres-data",
    "mattermost": "mte-mattermost-db-data",
    "activepieces": "mte-activepieces-postgres",
    "firecrawl": "mte-firecrawl-postgres",
    "kestra": "mte-kestra-postgres",
}
REDIS_VOLUME = "mte-activepieces-redis"
DATASOURCES = {
    "victoriametrics": {
        "name": "VictoriaMetrics",
        "type": "prometheus",
        "url": "http://victoriametrics:8428",
        "access": "proxy",
        "isDefault": True,
        "editable": False,
    },
    "victorialogs": {
        "name": "VictoriaLogs",
        "type": "victoriametrics-logs-datasource",
        "url": "http://victorialogs:9428",
        "access": "proxy",
        "editable": False,
    },
    "victoriatraces": {
        "name": "VictoriaTraces",
        "type": "jaeger",
        "url": "http://victoriatraces:10428/select/jaeger",
        "access": "proxy",
        "editable": False,
    },
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
    "C061",
    "C062",
    "C063",
    "C064",
    "C069",
    "C070",
]
INDEX_PRODUCERS = (
    "server-observability-canary.py",
    "server-dokploy.py",
    "server-provision.py",
    "server-toolhive.py",
    "server-config.py",
)
HOST_DOKPLOY_PRODUCERS = (
    "server-host-dokploy-acceptance.py",
    "server-dokploy.py",
)
POSTGRES_NOTION_PROFILE = "postgres-notion"
POSTGRES_NOTION_COMPONENTS = ("postgrest",)
POSTGRES_NOTION_DORMANT_COMPONENTS = frozenset({"baserow", "wikijs", "nocodb"})
PROFILE_RUNTIME_CONTRACTS = {
    "postgres-notion": {
        "componentIds": ("postgrest",),
        "externalProviders": ("notion",),
    },
    "baserow-wikijs": {
        "componentIds": ("postgrest", "baserow", "wikijs"),
        "externalProviders": (),
    },
    "postgres-postgrest-nocodb-nocodocs": {
        "componentIds": ("postgrest", "nocodb"),
        "externalProviders": (),
    },
}
PROFILE_COMPONENT_IDS = frozenset(
    component
    for contract in PROFILE_RUNTIME_CONTRACTS.values()
    for component in contract["componentIds"]
)
CORE_APPLICATION_COMPONENTS = (
    "mattermost",
    "activepieces",
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
    """Return the stable, profile-independent indexed control-plane producers."""
    return installed_producer_hashes(INDEX_PRODUCERS)


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
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def request_json(
    method: str,
    url: str,
    *,
    body: Any | None = None,
    headers: dict[str, str] | None = None,
    allow_status: set[int] | None = None,
    timeout: int = 30,
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
    timeout: int = 60,
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


def docker_inventory() -> list[dict[str, Any]]:
    names = run(
        ["docker", "ps", "--format", "{{.Names}}"], timeout=30
    ).stdout.splitlines()
    if not names:
        raise CanaryError("docker_inventory_empty", "no running containers")
    # Restrict inspect output to names and mounts; full Docker inspect would
    # unnecessarily read every container's environment and secret values.
    output = run(
        [
            "docker",
            "inspect",
            "--format",
            "{{json .Name}}\t{{json .Mounts}}\t{{json .NetworkSettings.Ports}}"
            "\t{{json .Config.Labels}}\t{{json .Config.Image}}",
            *names,
        ],
        timeout=60,
    ).stdout
    items: list[dict[str, Any]] = []
    try:
        for line in output.splitlines():
            raw_name, raw_mounts, raw_ports, raw_labels, raw_image = line.split("\t", 4)
            items.append(
                {
                    "Name": json.loads(raw_name),
                    "Mounts": json.loads(raw_mounts),
                    "Ports": json.loads(raw_ports),
                    "Labels": json.loads(raw_labels) or {},
                    "Image": json.loads(raw_image),
                }
            )
    except (ValueError, json.JSONDecodeError) as exc:
        raise CanaryError(
            "docker_inventory_invalid",
            "restricted Docker inspect invalid",
        ) from exc
    return items


def require_containers(items: list[dict[str, Any]]) -> dict[str, str]:
    volumes: dict[str, str] = {}
    for item in items:
        name = str(item.get("Name", "")).lstrip("/")
        for mount in item.get("Mounts", []) or []:
            if mount.get("Type") == "volume" and mount.get("Name"):
                volumes[str(mount["Name"])] = name
    required = {**POSTGRES_VOLUMES, "activepieces-redis": REDIS_VOLUME}
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

    def sibling(component: str, service: str) -> str:
        source = by_name[primary[component]]
        project = source.get("Labels", {}).get("com.docker.compose.project")
        matches = [
            name
            for name, item in by_name.items()
            if item.get("Labels", {}).get("com.docker.compose.project") == project
            and item.get("Labels", {}).get("com.docker.compose.service") == service
        ]
        if len(matches) != 1:
            raise CanaryError("application_path_missing", f"{component}-{service}")
        return matches[0]

    paths = {
        "mattermost": primary["mattermost"],
        "activepieces-app": primary["activepieces"],
        "activepieces-worker": sibling("activepieces", "worker"),
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


def send_otlp(kind: str, payload: dict[str, Any]) -> int:
    status, _ = request_json("POST", f"{OTLP}/v1/{kind}", body=payload)
    if status not in {200, 202}:
        raise CanaryError("otlp_rejected", f"OTLP {kind} returned {status}")
    return status


def send_otlp_from_container(
    container: str,
    kind: str,
    payload: dict[str, Any],
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
            f"{OTLP}/v1/{kind}",
        ],
        stdin=json.dumps(payload, separators=(",", ":")),
        timeout=45,
    )
    try:
        status = int(result.stdout.strip())
    except ValueError as exc:
        raise CanaryError("otlp_emitter_invalid", f"{kind} status") from exc
    if status not in {200, 202}:
        raise CanaryError("otlp_rejected", f"OTLP {kind} returned {status}")
    return status


def otel_collector_network() -> str:
    names = run(
        [
            "docker",
            "ps",
            "--filter",
            "label=com.docker.compose.service=otel-collector",
            "--format",
            "{{.Names}}",
        ]
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
        ]
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
            "30",
            "-H",
            "Content-Type: application/json",
            "-X",
            "POST",
            "--data-binary",
            "@-",
            f"http://otel-collector:4318/v1/{kind}",
        ],
        stdin=json.dumps(payload, separators=(",", ":")),
        timeout=45,
    )
    try:
        status = int(result.stdout.strip())
    except ValueError as exc:
        raise CanaryError("otlp_emitter_invalid", f"runner {kind} status") from exc
    if status not in {200, 202}:
        raise CanaryError("otlp_rejected", f"runner OTLP {kind} returned {status}")
    return status


def runner_otlp_bundle(
    container: str,
    payloads: dict[str, dict[str, Any]],
) -> tuple[dict[str, int], dict[str, Any]]:
    network = otel_collector_network()
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
            allow_failure=True,
        )
        if result.returncode:
            raise CanaryError("otel_runner_attach_failed", "network connect failed")
        connected = True
        statuses = {
            kind: send_otlp_from_runner(container, kind, payload)
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
        ]
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


def prom_query(query: str, base: str = VM) -> list[dict[str, Any]]:
    url = base + "/api/v1/query?" + urllib.parse.urlencode({"query": query})
    status, body = request_json("GET", url)
    if status != 200 or not isinstance(body, dict) or body.get("status") != "success":
        raise CanaryError("prom_query_failed", "Prometheus query failed")
    result = body.get("data", {}).get("result", [])
    if not isinstance(result, list):
        raise CanaryError("prom_query_invalid", "Prometheus result invalid")
    return result


def wait_for(predicate: Callable[[], Any], *, timeout: int, interval: int = 5) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise CanaryError("canary_timeout", f"condition timed out after {timeout}s")


def query_correlated_data(run_id: str, trace_id: str) -> dict[str, Any]:
    metric = wait_for(
        lambda: prom_query(
            f'mte_observability_canary{{run_id="{run_id}",trace_id="{trace_id}"}}'
        ),
        timeout=90,
    )
    query = f'run_id:="{run_id}" AND trace_id:="{trace_id}"'

    def logs() -> list[str] | bool:
        url = VL + "/select/logsql/query?" + urllib.parse.urlencode({"query": query})
        status, body = request_json("GET", url)
        if status != 200:
            return False
        if isinstance(body, list):
            return body or False
        if isinstance(body, str):
            return [line for line in body.splitlines() if line.strip()] or False
        return False

    def trace() -> dict[str, Any] | bool:
        status, body = request_json(
            "GET",
            f"{VT}/api/traces/{trace_id}",
            allow_status={404},
        )
        return (
            body
            if status == 200 and isinstance(body, dict) and body.get("data")
            else False
        )

    log_rows = wait_for(logs, timeout=90)
    trace_body = wait_for(trace, timeout=90)
    return {
        "metricSeries": len(metric),
        "logRecords": len(log_rows),
        "traceCount": len(trace_body["data"]),
        "runId": run_id,
        "traceId": trace_id,
    }


def series_freshness(query: str, *, max_age: int = 180) -> dict[str, Any]:
    rows = prom_query(query)
    timestamps = [
        float(row["value"][0])
        for row in rows
        if isinstance(row.get("value"), list) and row["value"]
    ]
    if not timestamps:
        raise CanaryError("series_missing", "required metric series missing")
    age = max(0.0, time.time() - max(timestamps))
    if age > max_age:
        raise CanaryError("series_stale", f"metric series older than {max_age}s")
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


def blackbox_proof(config: dict[str, Any]) -> dict[str, Any]:
    expected = declared_http_targets(config)
    rows = prom_query('probe_success{service.name="platform_health"}')
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
        service for service in expected_ids if ages.get(service, 10**9) > 180
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
    *,
    body: Any | None = None,
    allow_status: set[int] | None = None,
) -> tuple[int, Any]:
    return request_json(
        method,
        GRAFANA + path,
        body=body,
        headers=auth,
        allow_status=allow_status,
    )


def reconcile_grafana_once(auth: dict[str, str]) -> dict[str, Any]:
    datasource_ids: dict[str, int] = {}
    for uid, expected in DATASOURCES.items():
        status, existing = grafana_call(
            "GET",
            f"/api/datasources/uid/{uid}",
            auth,
            allow_status={404},
        )
        if status == 404:
            status, _ = grafana_call(
                "POST",
                "/api/datasources",
                auth,
                body={"uid": uid, **expected},
            )
            if status not in {200, 201}:
                raise CanaryError("grafana_reconcile_failed", f"create {uid} failed")
            _, existing = grafana_call("GET", f"/api/datasources/uid/{uid}", auth)
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
        allow_status={404},
    )
    if status == 404:
        _, folders = grafana_call("GET", "/api/folders?limit=1000", auth)
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
                body={"uid": folder_uid, "title": "MTE Platform"},
            )
            if status not in {200, 201, 409}:
                raise CanaryError("grafana_reconcile_failed", "folder create failed")
            _, folder = grafana_call("GET", f"/api/folders/{folder_uid}", auth)
    if not isinstance(folder, dict) or folder.get("title") != "MTE Platform":
        raise CanaryError("grafana_folder_drift", "MTE Platform folder drifted")

    account_name = "mte-observability-prober"
    search_path = "/api/serviceaccounts/search?" + urllib.parse.urlencode(
        {"query": account_name, "perpage": 100},
    )
    _, search = grafana_call("GET", search_path, auth)
    accounts = search.get("serviceAccounts", []) if isinstance(search, dict) else []
    exact = [item for item in accounts if item.get("name") == account_name]
    if not exact:
        status, _ = grafana_call(
            "POST",
            "/api/serviceaccounts",
            auth,
            body={"name": account_name, "role": "Viewer", "isDisabled": False},
        )
        if status not in {200, 201}:
            raise CanaryError(
                "grafana_reconcile_failed", "service account create failed"
            )
        _, search = grafana_call("GET", search_path, auth)
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


def grafana_reconcile_twice(auth: dict[str, str]) -> dict[str, Any]:
    first = reconcile_grafana_once(auth)
    second = reconcile_grafana_once(auth)
    if first != second or second.get("serviceAccountCount") != 1:
        raise CanaryError(
            "reconcile_not_idempotent", "second reconcile changed identity"
        )
    return {"first": first, "second": second, "idempotent": True}


def run_json_command(argv: list[str], *, timeout: int = 1800) -> Any:
    completed = run(argv, timeout=timeout)
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CanaryError("command_json_invalid", Path(argv[1]).name) from exc


def validate_host_dokploy_acceptance(gate: dict[str, str]) -> dict[str, Any]:
    evidence = load_json(HOST_DOKPLOY_EVIDENCE)
    current = installed_producer_hashes(HOST_DOKPLOY_PRODUCERS)
    expected_producers = {
        "server-host-dokploy-acceptance.py": current[
            "server-host-dokploy-acceptance.py"
        ],
        "server-dokploy.py": current["server-dokploy.py"],
    }
    c061 = evidence.get("C061", {})
    c062 = evidence.get("C062", {})
    first = c062.get("firstRevision", {}) if isinstance(c062, dict) else {}
    second = c062.get("secondRevision", {}) if isinstance(c062, dict) else {}
    cleanup = c062.get("cleanup", {}) if isinstance(c062, dict) else {}
    remaining = cleanup.get("remaining", {}) if isinstance(cleanup, dict) else {}
    created = c062.get("engineResourcesCreated", {}) if isinstance(c062, dict) else {}
    expected_operations = [
        "list",
        "create",
        "update",
        "status",
        "update",
        "status",
        "delete",
    ]
    invalid = (
        evidence.get("status") != "passed"
        or evidence.get("sourceGate") != gate
        or evidence.get("producerHashes") != expected_producers
        or c061.get("status") != "pass"
        or c061.get("apiKeyAuthenticated") is not True
        or c061.get("operations") != expected_operations
        or not all(
            c061.get(key) is True
            for key in (
                "resourceCreated",
                "resourceUpdated",
                "statusObserved",
                "resourceDeleted",
            )
        )
        or c062.get("status") != "pass"
        or c062.get("configHashChanged") is not True
        or first.get("containerStates") != ["running"]
        or second.get("containerStates") != ["running"]
        or not first.get("configHashes")
        or not second.get("configHashes")
        or set(first.get("configHashes", [])) == set(second.get("configHashes", []))
        or any(
            int(created.get(key) or 0) < 1
            for key in (
                "containers",
                "volumes",
                "networks",
            )
        )
        or cleanup.get("noResidualResources") is not True
        or any(
            int(remaining.get(key, -1)) != 0
            for key in (
                "containers",
                "volumes",
                "networks",
            )
        )
    )
    if invalid:
        raise CanaryError(
            "host_dokploy_acceptance_invalid",
            "ephemeral Dokploy and Docker lifecycle evidence is incomplete",
        )
    return evidence


def host_dokploy_acceptance(
    expected_hash: str,
    gate: dict[str, str],
    *,
    execute: bool,
) -> dict[str, Any]:
    if execute:
        result = run_json_command(
            [
                "python3",
                str(SERVER_BIN / "server-host-dokploy-acceptance.py"),
                "apply",
                "--expected-source-hash",
                expected_hash,
            ]
        )
        if not isinstance(result, dict) or result.get("status") != "passed":
            raise CanaryError(
                "host_dokploy_acceptance_failed",
                "producer did not pass",
            )
    return validate_host_dokploy_acceptance(gate)


def dokploy_control_plane_proof(expected_components: list[str]) -> dict[str, Any]:
    proof = run_json_command(
        [
            "python3",
            str(SERVER_BIN / "server-dokploy.py"),
            "proof",
        ]
    )
    if not isinstance(proof, dict):
        raise CanaryError("dokploy_api_proof_invalid", "proof is not an object")
    fingerprint = str(proof.get("credentialFingerprintSha256") or "")
    resources = proof.get("resources")
    if (
        proof.get("apiKeyAuthenticated") is not True
        or proof.get("credentialRef") != "DOKPLOY_API_TOKEN"
        or proof.get("credentialSource") != str(PLATFORM_ENV)
        or not re.fullmatch(r"[0-9a-f]{64}", fingerprint)
        or not isinstance(resources, list)
    ):
        raise CanaryError(
            "dokploy_api_proof_invalid", "dedicated credential proof failed"
        )
    observed = sorted(str(row.get("component")) for row in resources)
    if observed != sorted(expected_components):
        raise CanaryError("dokploy_api_proof_invalid", "resource inventory mismatch")
    if any(row.get("status") not in {"done", "idle"} for row in resources):
        raise CanaryError(
            "dokploy_api_resource_unready", "compose resource is not ready"
        )
    return {
        "apiKeyAuthenticated": True,
        "credentialRef": proof["credentialRef"],
        "credentialSource": proof["credentialSource"],
        "credentialFingerprintSha256": fingerprint,
        "projectCount": int(proof.get("projectCount") or 0),
        "resources": resources,
    }


def docker_engine_proof(resources: list[dict[str, Any]]) -> dict[str, Any]:
    version_raw = run(
        [
            "docker",
            "version",
            "--format",
            "{{json .Server}}",
        ]
    ).stdout.strip()
    try:
        version = json.loads(version_raw)
    except json.JSONDecodeError as exc:
        raise CanaryError("docker_engine_invalid", "server version invalid") from exc
    if not isinstance(version, dict) or not version.get("Version"):
        raise CanaryError("docker_engine_invalid", "server version missing")
    names = run(
        [
            "docker",
            "ps",
            "--format",
            "{{.Names}}",
        ]
    ).stdout.splitlines()
    if not names:
        raise CanaryError("docker_engine_invalid", "no running containers")
    raw = run(
        [
            "docker",
            "inspect",
            "--format",
            "{{json .Name}}\t{{json .State.Status}}\t{{json .Config.Labels}}",
            *names,
        ]
    ).stdout
    containers: list[dict[str, Any]] = []
    for line in raw.splitlines():
        try:
            raw_name, raw_state, raw_labels = line.split("\t", 2)
            containers.append(
                {
                    "name": str(json.loads(raw_name)).lstrip("/"),
                    "state": json.loads(raw_state),
                    "labels": json.loads(raw_labels) or {},
                }
            )
        except (ValueError, json.JSONDecodeError) as exc:
            raise CanaryError(
                "docker_engine_invalid", "inspect output invalid"
            ) from exc
    projects: list[dict[str, Any]] = []
    for resource in resources:
        app_name = str(resource.get("appName") or "")
        if (
            not app_name
            or resource.get("composeType") != "docker-compose"
            or resource.get("sourceType") != "raw"
        ):
            raise CanaryError(
                "dokploy_engine_binding_invalid", str(resource.get("component"))
            )
        matches = [
            row
            for row in containers
            if row["labels"].get("com.docker.compose.project") == app_name
        ]
        if not matches or any(row["state"] != "running" for row in matches):
            raise CanaryError(
                "dokploy_engine_binding_invalid", str(resource.get("component"))
            )
        services = sorted(
            {
                str(row["labels"].get("com.docker.compose.service") or "")
                for row in matches
            }
        )
        config_hashes = sorted(
            {
                str(row["labels"].get("com.docker.compose.config-hash") or "")
                for row in matches
            }
        )
        if "" in services or "" in config_hashes:
            raise CanaryError(
                "dokploy_engine_binding_invalid", str(resource.get("component"))
            )
        projects.append(
            {
                "component": resource.get("component"),
                "composeId": resource.get("composeId"),
                "appName": app_name,
                "runningContainers": len(matches),
                "services": services,
                "configHashes": config_hashes,
            }
        )
    return {
        "serverVersion": str(version["Version"]),
        "apiVersion": str(version.get("ApiVersion") or ""),
        "projects": projects,
        "allContainersRunning": True,
    }


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


def stable_projection(value: Any) -> Any:
    volatile = {
        "timestamp",
        "startedat",
        "finishedat",
        "generatedat",
        "completedat",
        "updatedat",
        "durationseconds",
        "status",
        "action",
        "ok",
        "health",
        "reason",
        "error",
        "errortype",
    }
    if isinstance(value, dict):
        projected: dict[str, Any] = {}
        for key in sorted(value):
            lower = key.lower()
            if lower in volatile or (
                SENSITIVE_EVIDENCE_KEY_RE.search(key) and "fingerprint" not in lower
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


def indexed_evidence_reference(
    path: Path,
    *,
    kind: str,
    producer: str,
    profile_field: str,
    profile: str,
    canonical_source_sha256: str,
) -> dict[str, str]:
    """Bind indexed proof to a redacted producer artifact without copying it."""
    document = load_json(path)
    producer_hash = installed_producer_hashes((producer,))[producer]
    if path.stat().st_mode & 0o777 != 0o600:
        raise CanaryError("indexed_evidence_mode_invalid", str(path))
    if (
        document.get("apiVersion") != "micro-task-engine/v1alpha1"
        or document.get("kind") != kind
        or document.get("status") != "passed"
        or document.get("ok") is not True
        or document.get(profile_field) != profile
        or document.get("canonicalSourceSha256") != canonical_source_sha256
        or document.get("producerSha256") != producer_hash
    ):
        raise CanaryError("indexed_profile_evidence_invalid", kind)
    return {
        "path": str(path),
        "kind": kind,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "semanticSha256": canonical_json_sha256(stable_projection(document)),
        "producerSha256": producer_hash,
    }


def postgres_notion_contract(
    config: dict[str, Any], values: dict[str, str]
) -> dict[str, Any]:
    profile = values.get("DATA_CONTENT_PROFILE", "")
    plane = load_json(DATA_CONTENT_PLANE)
    source_sha = hashlib.sha256(PLATFORM_ENV.read_bytes()).hexdigest()
    components = {
        str(row.get("id"))
        for row in config.get("spec", {}).get("components", [])
        if isinstance(row, dict) and row.get("compose")
    }
    provider_components = plane.get("componentIds")
    providers = plane.get("providers")
    external = sorted(
        str(name)
        for name, row in (providers.items() if isinstance(providers, dict) else [])
        if isinstance(row, dict) and row.get("deployment") == "external"
    )
    if (
        profile != POSTGRES_NOTION_PROFILE
        or plane.get("profile") != profile
        or provider_components != list(POSTGRES_NOTION_COMPONENTS)
        or plane.get("systemOfRecord", {}).get("providerId") != "postgres"
        or plane.get("binding", {}).get("sourceSha256") != source_sha
        or plane.get("_generated", {}).get("sourceSha256") != source_sha
        or not set(POSTGRES_NOTION_COMPONENTS) <= components
        or components & POSTGRES_NOTION_DORMANT_COMPONENTS
        or external != ["notion"]
    ):
        raise CanaryError(
            "indexed_data_content_profile_invalid",
            profile or "missing-profile",
        )
    return {
        "profile": profile,
        "systemOfRecord": "postgres",
        "providerComponents": list(POSTGRES_NOTION_COMPONENTS),
        "externalProviders": external,
    }


def profile_declarative_reconcile(
    config: dict[str, Any], values: dict[str, str]
) -> dict[str, Any]:
    """Reconcile only the selected profile's declarative provider resources."""
    contract = postgres_notion_contract(config, values)
    canonical_source_sha = hashlib.sha256(PLATFORM_ENV.read_bytes()).hexdigest()
    postgrest = run_json_command(
        ["python3", str(SERVER_BIN / "server-postgrest.py"), "provision"]
    )
    notion = run_json_command(
        ["python3", str(SERVER_BIN / "server-notion.py"), "provision", "--json"]
    )
    activepieces = run_json_command(
        [
            "python3",
            str(SERVER_BIN / "server-activepieces-provision-verify.py"),
            "provision",
        ]
    )
    postgrest_canonical = (
        postgrest.get("canonical") if isinstance(postgrest, dict) else None
    )
    role_bindings = (
        postgrest.get("roleBindings") if isinstance(postgrest, dict) else None
    )
    notion_created = notion.get("created") if isinstance(notion, dict) else None
    notion_schema = notion.get("schema") if isinstance(notion, dict) else None
    flows = (
        activepieces.get("managedFlows")
        if isinstance(activepieces, dict)
        and isinstance(activepieces.get("managedFlows"), list)
        else []
    )
    slots = (
        activepieces.get("credentialSlots")
        if isinstance(activepieces, dict)
        and isinstance(activepieces.get("credentialSlots"), list)
        else []
    )
    if (
        not isinstance(postgrest, dict)
        or postgrest.get("ok") is not True
        or postgrest.get("status") != "converged"
        or not isinstance(postgrest_canonical, dict)
        or postgrest_canonical.get("changedKeys") != []
        or not isinstance(role_bindings, dict)
        or role_bindings.get("distinct") is not True
    ):
        raise CanaryError(
            "indexed_final_not_stable", "PostgREST provisioning was not a no-op"
        )
    if (
        not isinstance(notion, dict)
        or notion.get("apiVersion") != "micro-task-engine/v1alpha1"
        or notion.get("kind") != "NotionConnectorProvision"
        or notion.get("status") != "converged"
        or notion.get("ok") is not True
        or notion.get("dataContentProfile") != POSTGRES_NOTION_PROFILE
        or notion.get("changedKeys") != []
        or notion.get("redacted") is not True
        or not isinstance(notion_created, dict)
        or any(value is not False for value in notion_created.values())
        or not isinstance(notion_schema, dict)
        or notion_schema.get("exact") is not True
        or notion_schema.get("changed") is not False
    ):
        raise CanaryError(
            "indexed_final_not_stable", "Notion provisioning was not a no-op"
        )
    if (
        not isinstance(activepieces, dict)
        or activepieces.get("apiVersion") != "micro-task-engine/v1alpha1"
        or activepieces.get("kind") != "ActivepiecesProvisionEvidence"
        or activepieces.get("dataContentProfile") != POSTGRES_NOTION_PROFILE
        or activepieces.get("status") != "passed"
        or activepieces.get("ok") is not True
        or activepieces.get("secondRunNoOp") is not True
        or activepieces.get("mutationCount") != 0
        or activepieces.get("duplicateCount") != 0
        or activepieces.get("mcpTokenIssuable") is not True
        or activepieces.get("mcpTokenPersisted") is not False
        or len(flows) != 3
        or any(
            not isinstance(row, dict) or row.get("status") != "ready" for row in flows
        )
        or len(slots) != 1
        or any(
            not isinstance(row, dict)
            or row.get("status") != "ready"
            or row.get("type") != "project-variable"
            or row.get("valueRedacted") is not True
            for row in slots
        )
    ):
        raise CanaryError(
            "indexed_final_not_stable",
            "Activepieces declarative provisioning was not a no-op",
        )
    evidence = {
        "postgrest": indexed_evidence_reference(
            POSTGREST_VERIFY_EVIDENCE,
            kind="PostgrestVerification",
            producer="server-postgrest.py",
            profile_field="profile",
            profile=POSTGRES_NOTION_PROFILE,
            canonical_source_sha256=canonical_source_sha,
        ),
        "notion": indexed_evidence_reference(
            NOTION_VERIFY_EVIDENCE,
            kind="NotionConnectorVerification",
            producer="server-notion.py",
            profile_field="dataContentProfile",
            profile=POSTGRES_NOTION_PROFILE,
            canonical_source_sha256=canonical_source_sha,
        ),
        "activepieces": indexed_evidence_reference(
            ACTIVEPIECES_PROVISION_EVIDENCE,
            kind="ActivepiecesProvisionEvidence",
            producer="server-activepieces-provision-verify.py",
            profile_field="dataContentProfile",
            profile=POSTGRES_NOTION_PROFILE,
            canonical_source_sha256=canonical_source_sha,
        ),
    }
    summary = {
        **contract,
        "postgrest": {
            "status": "converged",
            "canonicalChangedKeys": [],
            "roleBindingsDistinct": True,
            "evidence": evidence["postgrest"],
        },
        "notion": {
            "status": "converged",
            "createdResourceCount": 0,
            "schemaExact": True,
            "schemaChanged": False,
            "canonicalChangedKeys": [],
            "evidence": evidence["notion"],
        },
        "activepieces": {
            "status": "passed",
            "managedFlowCount": len(flows),
            "credentialSlotCount": len(slots),
            "credentialKinds": sorted(
                str(row["type"]) for row in slots if isinstance(row, dict)
            ),
            "secondRunNoOp": True,
            "mutationCount": 0,
            "duplicateCount": 0,
            "mcpTokenPersisted": False,
            "evidence": evidence["activepieces"],
        },
    }
    scan_for_secrets(summary, values)
    identity = json.loads(json.dumps(summary))
    for row in identity.values():
        if not isinstance(row, dict) or not isinstance(row.get("evidence"), dict):
            continue
        row["evidence"].pop("sha256", None)
    return {
        "summary": summary,
        "identitySha256": canonical_json_sha256(identity),
    }


def assert_no_list_duplicates(value: Any, path: str = "root") -> None:
    if isinstance(value, list):
        rows = [row for row in value if isinstance(row, dict)]
        for field in ("id", "uid", "name", "component", "profile"):
            identities = [str(row[field]) for row in rows if row.get(field)]
            if len(identities) != len(set(identities)):
                raise CanaryError(
                    "indexed_inventory_duplicate",
                    f"{path}.{field}",
                )
        for index, item in enumerate(value):
            assert_no_list_duplicates(item, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            assert_no_list_duplicates(item, f"{path}.{key}")


def grafana_inventory(auth: dict[str, str]) -> dict[str, Any]:
    datasources: dict[str, Any] = {}
    for uid in DATASOURCES:
        status, row = grafana_call(
            "GET",
            f"/api/datasources/uid/{uid}",
            auth,
            allow_status={404},
        )
        datasources[uid] = (
            None
            if status == 404
            else {
                "id": row.get("id"),
                "uid": row.get("uid"),
                "name": row.get("name"),
            }
        )
    _, folders = grafana_call("GET", "/api/folders?limit=1000", auth)
    exact_folders = (
        [
            {"id": row.get("id"), "uid": row.get("uid"), "title": row.get("title")}
            for row in folders
            if row.get("title") == "MTE Platform"
        ]
        if isinstance(folders, list)
        else []
    )
    search_path = "/api/serviceaccounts/search?" + urllib.parse.urlencode(
        {
            "query": "mte-observability-prober",
            "perpage": 100,
        }
    )
    _, accounts = grafana_call("GET", search_path, auth)
    exact_accounts = (
        [
            {"id": row.get("id"), "name": row.get("name"), "role": row.get("role")}
            for row in accounts.get("serviceAccounts", [])
            if row.get("name") == "mte-observability-prober"
        ]
        if isinstance(accounts, dict)
        else []
    )
    if len(exact_folders) > 1 or len(exact_accounts) > 1:
        raise CanaryError("indexed_inventory_duplicate", "Grafana identity duplicated")
    return {
        "datasources": datasources,
        "folders": exact_folders,
        "serviceAccounts": exact_accounts,
    }


def indexed_inventory(
    config: dict[str, Any],
    values: dict[str, str],
    expected_hash: str,
) -> dict[str, Any]:
    gate = exact_hash_gate(expected_hash, config, load_json(MANIFEST))
    data_content_contract = postgres_notion_contract(config, values)
    components = sorted(
        str(row["id"])
        for row in config.get("spec", {}).get("components", [])
        if isinstance(row, dict) and row.get("compose")
    )
    ids = load_json(SECRET_ROOT / "dokploy-mte-ids.json")
    state = load_json(SECRET_ROOT / "dokploy-mte-state.json")
    if set(ids) != set(components) or len(set(ids.values())) != len(ids):
        raise CanaryError(
            "indexed_inventory_duplicate", "Dokploy IDs missing or duplicated"
        )
    dokploy_status = run_json_command(
        [
            "python3",
            str(SERVER_BIN / "server-dokploy.py"),
            "status",
        ]
    )
    status_ids = [row.get("composeId") for row in dokploy_status]
    if len(dokploy_status) != len(components) or len(set(status_ids)) != len(
        status_ids
    ):
        raise CanaryError(
            "indexed_inventory_duplicate", "Dokploy runtime inventory drift"
        )
    provisioner = run_json_command(
        [
            "python3",
            str(SERVER_BIN / "server-provision.py"),
            "status",
        ]
    )
    toolhive = run_json_command(
        [
            "python3",
            str(SERVER_BIN / "server-toolhive.py"),
            "status",
        ]
    )
    assert_no_list_duplicates(dokploy_status, "dokploy")
    assert_no_list_duplicates(provisioner, "provisioner")
    assert_no_list_duplicates(toolhive, "toolhive")
    identity = {
        "componentIds": components,
        "dokployIds": ids,
        "dokployState": stable_projection(state),
        "dokployRuntime": stable_projection(dokploy_status),
        "provisioner": stable_projection(provisioner),
        "toolhive": stable_projection(toolhive),
        "grafana": grafana_inventory(basic_auth(values)),
        "dataContentContract": data_content_contract,
    }
    identity_sha = hashlib.sha256(
        json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return {
        "sourceGate": gate,
        "identity": identity,
        "identitySha256": identity_sha,
        "noDuplicates": True,
    }


def indexed_reconcile_pass(expected_hash: str, pass_number: int) -> dict[str, Any]:
    if pass_number not in INDEX_PASS:
        raise CanaryError("invalid_reconcile_pass", str(pass_number))
    config, values = load_json(CONFIG), dotenv(PLATFORM_ENV)
    before = indexed_inventory(config, values, expected_hash)
    components = before["identity"]["componentIds"]
    dokploy = run_json_command(
        [
            "python3",
            str(SERVER_BIN / "server-dokploy.py"),
            "deploy",
            *components,
        ]
    )
    provisioner = run_json_command(
        [
            "python3",
            str(SERVER_BIN / "server-provision.py"),
            "provision",
        ]
    )
    declarative = profile_declarative_reconcile(config, values)
    toolhive = run_json_command(
        [
            "python3",
            str(SERVER_BIN / "server-toolhive.py"),
            "provision",
        ]
    )
    grafana = reconcile_grafana_once(basic_auth(values))
    # A provisioner that adds a new canonical value invalidates FINAL-STABLE.
    config = load_json(CONFIG)
    after = indexed_inventory(config, dotenv(PLATFORM_ENV), expected_hash)
    actions = {str(row.get("component")): row.get("action") for row in dokploy}
    if set(actions) != set(components):
        raise CanaryError("indexed_reconcile_incomplete", "Dokploy result incomplete")
    if pass_number == 2 and set(actions.values()) != {"unchanged"}:
        raise CanaryError(
            "indexed_second_pass_changed", json.dumps(actions, sort_keys=True)
        )
    control_plane = dokploy_control_plane_proof(components)
    engine = docker_engine_proof(control_plane["resources"])
    host_acceptance = host_dokploy_acceptance(
        expected_hash,
        after["sourceGate"],
        execute=pass_number == 1,
    )
    host_evidence_sha = hashlib.sha256(
        HOST_DOKPLOY_EVIDENCE.read_bytes(),
    ).hexdigest()
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
        "dokployActions": actions,
        "hostDokployEvidence": str(HOST_DOKPLOY_EVIDENCE),
        "hostDokployEvidenceSha256": host_evidence_sha,
        "C061": {
            "status": "pass",
            **control_plane,
            **host_acceptance["C061"],
            "managedInventory": control_plane,
        },
        "C062": {
            "status": "pass",
            "dokployActions": actions,
            **engine,
            **host_acceptance["C062"],
            "managedRuntime": engine,
        },
        "provisionerIdentitySha256": hashlib.sha256(
            json.dumps(
                stable_projection(provisioner),
                sort_keys=True,
            ).encode()
        ).hexdigest(),
        "toolhiveIdentitySha256": hashlib.sha256(
            json.dumps(
                stable_projection(toolhive),
                sort_keys=True,
            ).encode()
        ).hexdigest(),
        "dataContentProfile": POSTGRES_NOTION_PROFILE,
        "dataContentDeclarativeEvidence": declarative["summary"],
        "dataContentIdentitySha256": declarative["identitySha256"],
        "grafanaFingerprint": grafana["sha256"],
    }
    scan_for_secrets(payload, values)
    atomic_json(INDEX_PASS[pass_number], payload)
    return payload


def finalize_indexed_idempotency(expected_hash: str) -> dict[str, Any]:
    gate = exact_hash_gate(expected_hash, load_json(CONFIG), load_json(MANIFEST))
    first, second = load_json(INDEX_PASS[1]), load_json(INDEX_PASS[2])
    if first.get("sourceGate") != gate or second.get("sourceGate") != gate:
        raise CanaryError("indexed_source_gate_drift", "reconcile pass hash differs")
    current_producers = producer_hashes()
    if (
        first.get("producerHashes") != current_producers
        or second.get("producerHashes") != current_producers
    ):
        raise CanaryError("indexed_producer_drift", "reconcile producer hash differs")
    validate_host_dokploy_acceptance(gate)
    host_evidence_sha = hashlib.sha256(
        HOST_DOKPLOY_EVIDENCE.read_bytes(),
    ).hexdigest()
    if (
        first.get("hostDokployEvidenceSha256") != host_evidence_sha
        or second.get("hostDokployEvidenceSha256") != host_evidence_sha
    ):
        raise CanaryError(
            "host_dokploy_acceptance_drift",
            "host lifecycle evidence changed",
        )
    first_after = first.get("after", {})
    second_before = second.get("before", {})
    second_after = second.get("after", {})
    if first_after.get("identitySha256") != second_before.get("identitySha256"):
        raise CanaryError(
            "indexed_between_pass_drift", "identity changed between passes"
        )
    if second_before.get("identitySha256") != second_after.get("identitySha256"):
        raise CanaryError(
            "indexed_second_pass_changed", "second pass changed inventory"
        )
    if set(second.get("dokployActions", {}).values()) != {"unchanged"}:
        raise CanaryError("indexed_second_pass_changed", "Dokploy was not no-op")
    before_ids = first.get("before", {}).get("identity", {}).get("dokployIds")
    after_ids = second_after.get("identity", {}).get("dokployIds")
    if before_ids != after_ids:
        raise CanaryError("indexed_identity_changed", "Dokploy IDs changed")
    if first.get("provisionerIdentitySha256") != second.get(
        "provisionerIdentitySha256"
    ):
        raise CanaryError("indexed_identity_changed", "provisioner identities changed")
    if first.get("toolhiveIdentitySha256") != second.get("toolhiveIdentitySha256"):
        raise CanaryError("indexed_identity_changed", "ToolHive identities changed")
    if (
        first.get("dataContentProfile") != POSTGRES_NOTION_PROFILE
        or second.get("dataContentProfile") != POSTGRES_NOTION_PROFILE
        or first.get("dataContentIdentitySha256")
        != second.get("dataContentIdentitySha256")
    ):
        raise CanaryError("indexed_identity_changed", "data/content identities changed")
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "IndexedDeployIdempotencyEvidence",
        "status": "passed",
        "completedAt": utcnow(),
        "producerSha256": producer_sha256(),
        "producerHashes": current_producers,
        "sourceGate": gate,
        "componentCount": len(after_ids),
        "stableDokployIds": True,
        "noDuplicateResources": True,
        "secondPassNoChange": True,
        "inventoryIdentitySha256": second_after["identitySha256"],
        "dataContentProfile": POSTGRES_NOTION_PROFILE,
        "dataContentIdentitySha256": second["dataContentIdentitySha256"],
        "dataContentDeclarativeEvidence": second["dataContentDeclarativeEvidence"],
        "passes": [str(INDEX_PASS[1]), str(INDEX_PASS[2])],
        "hostDokployEvidence": str(HOST_DOKPLOY_EVIDENCE),
        "hostDokployEvidenceSha256": host_evidence_sha,
        "checks": {"C061": second["C061"], "C062": second["C062"]},
        "coverage": [
            "dokploy-all-indexed-components",
            "server-provision-all-adapters",
            "toolhive-provisioning",
            "grafana-provisioning",
            "dedicated-dokploy-api-key",
            "dokploy-docker-engine-binding",
        ],
        "profileCoverage": [
            "postgres-ssot-postgrest-provisioning",
            "notion-external-connector-provisioning",
            "activepieces-declarative-resources",
        ],
    }
    atomic_json(INDEX_FINAL, payload)
    return payload


def grafana_queries(
    auth: dict[str, str],
    run_id: str,
    trace_id: str,
) -> dict[str, Any]:
    health: dict[str, str] = {}
    for uid in DATASOURCES:
        status, body = grafana_call(
            "GET",
            f"/api/datasources/uid/{uid}/health",
            auth,
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
    _, metric = grafana_call("GET", metric_path, auth)
    log_path = (
        "/api/datasources/proxy/uid/victorialogs/select/logsql/query?"
        + urllib.parse.urlencode({"query": f'run_id:="{run_id}"'})
    )
    log_status, logs = grafana_call("GET", log_path, auth)
    trace_status, trace = grafana_call(
        "GET",
        f"/api/datasources/proxy/uid/victoriatraces/api/traces/{trace_id}",
        auth,
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
        "activepieces-app",
        "activepieces-worker",
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
            None,
            None,
            "MATTERMOST_DB_USER",
            "MATTERMOST_DB_NAME",
            "MATTERMOST_DB_PASSWORD",
        ),
        (
            "activepieces-app",
            "MTE_ACTIVEPIECES_APP_ENV_AP_POSTGRES_HOST",
            "MTE_ACTIVEPIECES_APP_ENV_AP_POSTGRES_PORT",
            "AP_POSTGRES_USERNAME",
            "AP_POSTGRES_DATABASE",
            "AP_POSTGRES_PASSWORD",
        ),
        (
            "activepieces-worker",
            "MTE_ACTIVEPIECES_WORKER_ENV_AP_POSTGRES_HOST",
            "MTE_ACTIVEPIECES_WORKER_ENV_AP_POSTGRES_PORT",
            "AP_POSTGRES_USERNAME",
            "AP_POSTGRES_DATABASE",
            "AP_POSTGRES_PASSWORD",
        ),
        (
            "firecrawl-api",
            "MTE_FIRECRAWL_API_ENV_POSTGRES_HOST",
            "MTE_FIRECRAWL_API_ENV_POSTGRES_PORT",
            "FIRECRAWL_DB_USER",
            "FIRECRAWL_DB_NAME",
            "FIRECRAWL_DB_PASSWORD",
        ),
        ("kestra", None, None, None, None, "KESTRA_DB_PASSWORD"),
    ]
    provider = {
        "baserow": (
            "baserow",
            "BASEROW_DB_HOST",
            "BASEROW_DB_PORT",
            "BASEROW_DB_USER",
            "BASEROW_DB_NAME",
            "BASEROW_DB_PASSWORD",
        ),
        "wikijs": (
            "wikijs",
            "WIKIJS_DB_HOST",
            "WIKIJS_DB_PORT",
            "WIKIJS_DB_USER",
            "WIKIJS_DB_NAME",
            "WIKIJS_DB_PASSWORD",
        ),
        "nocodb": (
            "nocodb",
            "NOCODB_DB_HOST",
            "NOCODB_DB_PORT",
            "NOCODB_META_DB_USER",
            "NOCODB_META_DB_NAME",
            "NOCODB_META_DB_PASSWORD",
        ),
    }
    raw = [
        *common,
        *(
            provider[component]
            for component in contract["componentIds"]
            if component in provider
        ),
    ]
    specs: list[dict[str, str]] = []
    for role, host_ref, port_ref, user_ref, db_ref, password_ref in raw:
        host = (
            values.get(host_ref, "")
            if host_ref
            else {
                "mattermost": "mte-mattermost-postgres",
                "kestra": "mte-kestra-postgres",
            }[role]
        )
        port = values.get(port_ref, "") if port_ref else "5432"
        user = values.get(user_ref, "") if user_ref else "kestra"
        database = values.get(db_ref, "") if db_ref else "kestra"
        password = values.get(password_ref, "")
        if not all((apps.get(role), host, port, user, database, password)):
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
            "PGCONNECT_TIMEOUT": "10",
        }
        result = run(
            [
                "docker",
                "run",
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
        "activepieces-app",
        "activepieces-worker",
        "firecrawl-api",
        "kestra",
        "searxng",
        *contract["componentIds"],
    }
    if set(apps) != expected_apps:
        raise CanaryError("application_path_profile_mismatch", profile)
    raw = [
        ("activepieces-app", "AP_REDIS_URL"),
        ("activepieces-worker", "AP_REDIS_URL"),
        ("firecrawl-api", "FIRECRAWL_REDIS_URL"),
        ("searxng", "SEARXNG_VALKEY_URL"),
    ]
    specs: list[dict[str, str]] = []
    for role, url_ref in raw:
        url = values.get(url_ref, "")
        parsed = urllib.parse.urlsplit(url)
        if (
            not apps.get(role)
            or parsed.scheme not in {"redis", "rediss"}
            or not parsed.hostname
            or not parsed.password
        ):
            raise CanaryError("redis_path_auth_missing", role)
        specs.append(
            {
                "role": role,
                "container": apps[role],
                "url": url,
                "urlRef": url_ref,
                "host": parsed.hostname,
                "port": str(parsed.port or 6379),
            }
        )
    if "baserow" in contract["componentIds"]:
        password = values.get("BASEROW_REDIS_PASSWORD", "")
        host = values.get("BASEROW_REDIS_HOST", "")
        port = values.get("BASEROW_REDIS_PORT", "")
        database = values.get("BASEROW_REDIS_DB", "")
        if (
            not apps.get("baserow")
            or not password
            or not host
            or not port.isdigit()
            or not database.isdigit()
        ):
            raise CanaryError("redis_path_auth_missing", "baserow")
        specs.append(
            {
                "role": "baserow",
                "container": apps["baserow"],
                "url": "redis://:"
                + urllib.parse.quote(password, safe="")
                + f"@{host}:{port}/{database}",
                "urlRef": "BASEROW_REDIS_PASSWORD",
                "host": host,
                "port": port,
            }
        )
    return specs


def redis_authenticated_paths(
    values: dict[str, str],
    apps: dict[str, str],
) -> list[dict[str, Any]]:
    image = values.get("MTE_ACTIVEPIECES_DATA_REDIS_IMAGE", "")
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
            allow_failure=True,
        )
        if "NOAUTH" not in (unauth.stdout + unauth.stderr).upper():
            raise CanaryError("redis_auth_not_enforced", spec["role"])
        child_env = {**os.environ, "MTE_CANARY_REDIS_URL": spec["url"]}
        authenticated = run(
            [
                "docker",
                "run",
                "--rm",
                "--pull=never",
                "--network",
                f"container:{spec['container']}",
                "-e",
                "MTE_CANARY_REDIS_URL",
                image,
                "sh",
                "-ec",
                'redis-cli --no-auth-warning -u "$MTE_CANARY_REDIS_URL" PING',
            ],
            env=child_env,
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
            ]
        ).stdout.strip()
        config_root = Path(mountpoint)
    try:
        alertmanager = (config_root / "alertmanager.yml").read_text()
        rules = (config_root / "rules.yml").read_text()
    except OSError as exc:
        raise CanaryError(
            "alert_runtime_config_missing", "alert config unreadable"
        ) from exc
    webhook = values.get("MATTERMOST_ALERT_WEBHOOK_URL", "")
    receiver_ready = (
        bool(webhook)
        and webhook in alertmanager
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
    fingerprint = hashlib.sha256(webhook.encode()).hexdigest()
    return {
        "mattermostReceiverReady": True,
        "webhookCredentialRef": "MATTERMOST_ALERT_WEBHOOK_URL",
        "canonicalWebhookFingerprintSha256": fingerprint,
        "deployedWebhookFingerprintSha256": fingerprint,
        "webhookFingerprintMatch": True,
        "sendResolved": True,
        "otelLabelSelectorReady": True,
    }


def alertmanager_matches(run_id: str) -> list[dict[str, Any]]:
    _, body = request_json("GET", ALERTMANAGER + "/api/v2/alerts")
    if not isinstance(body, list):
        raise CanaryError("alertmanager_invalid", "alerts response invalid")
    instance = f"mte-canary:{run_id}"
    return [item for item in body if item.get("labels", {}).get("instance") == instance]


def vmalert_matches(run_id: str) -> list[dict[str, Any]]:
    _, body = request_json("GET", VMALERT + "/api/v1/alerts")
    alerts = body.get("data", {}).get("alerts", []) if isinstance(body, dict) else []
    instance = f"mte-canary:{run_id}"
    return [
        item for item in alerts if item.get("labels", {}).get("instance") == instance
    ]


def mattermost_post_state(container: str, run_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9-]+", run_id):
        raise CanaryError("invalid_run_id", "unsafe Mattermost marker")
    sql = (
        "SELECT count(*),"
        'coalesce(bool_or(lower("Message" || \' \' || "Props"::text) '
        "LIKE '%firing%'),false),"
        'coalesce(bool_or(lower("Message" || \' \' || "Props"::text) '
        "LIKE '%resolved%'),false),"
        "coalesce(min(nullif(u.\"Username\",'')),"
        "min(nullif(p.\"Props\"::jsonb->>'override_username','')),'incoming-webhook'),"
        "coalesce(min(c.\"Name\"),''),"
        'count(distinct p."UserId"),count(distinct p."ChannelId") '
        'FROM "Posts" p '
        'LEFT JOIN "Users" u ON u."Id"=p."UserId" '
        'LEFT JOIN "Channels" c ON c."Id"=p."ChannelId" '
        'WHERE lower(p."Message" || \' \' || p."Props"::text) '
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


def mattermost_cleanup_posts(container: str, run_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9-]+", run_id):
        raise CanaryError("invalid_run_id", "unsafe Mattermost marker")
    sql = (
        'WITH deleted AS (DELETE FROM "Posts" '
        'WHERE lower("Message" || \' \' || "Props"::text) '
        f"LIKE '%{run_id}%' RETURNING 1) SELECT count(*) FROM deleted;"
        'SELECT count(*) FROM "Posts" '
        'WHERE lower("Message" || \' \' || "Props"::text) '
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
) -> dict[str, Any]:
    def emit(value: int) -> None:
        send_otlp("metrics", probe_metric_payload(run_id, value))

    emit(0)
    started = time.monotonic()

    def firing() -> dict[str, Any] | bool:
        emit(0)
        vm = vmalert_matches(run_id)
        am = alertmanager_matches(run_id)
        mm = mattermost_post_state(mattermost_db, run_id)
        if vm and am and mm["firing"]:
            return {"vmalert": len(vm), "alertmanager": len(am), "mattermost": mm}
        return False

    def resolved() -> dict[str, Any] | bool:
        emit(1)
        vm = vmalert_matches(run_id)
        am = alertmanager_matches(run_id)
        mm = mattermost_post_state(mattermost_db, run_id)
        if not vm and not am and mm["resolved"]:
            return {"vmalert": 0, "alertmanager": 0, "mattermost": mm}
        return False

    # Always clear the injected zero and delete the exact canary posts,
    # including timeout/error paths.
    try:
        try:
            fired = wait_for(firing, timeout=300, interval=20)
        finally:
            emit(1)
        cleared = wait_for(resolved, timeout=420, interval=20)
        if (
            cleared["mattermost"].get("channel") != "mte-alerts"
            or not cleared["mattermost"].get("author")
            or cleared["mattermost"].get("distinctChannels") != 1
        ):
            raise CanaryError(
                "mattermost_post_identity_invalid", "author/channel mismatch"
            )
        cleanup = mattermost_cleanup_posts(mattermost_db, run_id)
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
        mattermost_cleanup_posts(mattermost_db, run_id)
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
    profile = runtime_profile(config, values)
    refs = {
        "GRAFANA_ADMIN_USER",
        "GRAFANA_ADMIN_PASSWORD",
        "AP_REDIS_PASSWORD",
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
    inventory = docker_inventory()
    containers = require_containers(inventory)
    emitters = require_otlp_emitters(inventory)
    apps = application_paths(config, inventory, values)
    postgres_specs = postgres_path_specs(values, apps)
    redis_specs = redis_path_specs(values, apps)
    alert_config = runtime_alert_config(values)
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
    profile = runtime_profile(config, values)
    gate = exact_hash_gate(expected_hash, config, manifest)
    indexed = load_json(INDEX_FINAL)
    if indexed.get("status") != "passed" or indexed.get("sourceGate") != gate:
        raise CanaryError(
            "indexed_idempotency_missing",
            "C069 final evidence is missing or belongs to another source hash",
        )
    inventory = docker_inventory()
    containers = require_containers(inventory)
    emitters = require_otlp_emitters(inventory)
    apps = application_paths(config, inventory, values)
    alert_config = runtime_alert_config(values)
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
    app_statuses = {
        kind: send_otlp_from_container(
            emitters["application"]["container"],
            kind,
            payload,
        )
        for kind, payload in app_payloads.items()
    }
    runner_statuses, runner_network = runner_otlp_bundle(
        emitters["runner"]["container"],
        runner_payloads,
    )
    app_correlated = query_correlated_data(app_run_id, app_trace_id)
    runner_correlated = query_correlated_data(runner_run_id, runner_trace_id)
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
            runner_network=runner_network,
            app_correlated=app_correlated,
            runner_correlated=runner_correlated,
        ),
        "C041": {
            "status": "pass",
            "host": series_freshness('node_uname_info{service.name="node"}'),
            "containers": series_freshness(
                'container_cpu_usage_seconds_total{service.name="containers"}'
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
    checks["C050"] = {"status": "pass", **grafana_reconcile_twice(auth)}
    checks["C045"] = {
        "status": "pass",
        **grafana_queries(auth, run_id, trace_id),
    }
    alert = fire_and_resolve_alert(run_id, containers["mattermost"])
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
        "webhookFingerprintMatch": alert_config["webhookFingerprintMatch"],
        "mattermostFiringObserved": alert["firing"]["mattermost"]["firing"],
        "mattermostResolvedObserved": alert["resolved"]["mattermost"]["resolved"],
        "matchingPosts": alert["resolved"]["mattermost"]["matchingPosts"],
        "postAuthor": alert["resolved"]["mattermost"]["author"],
        "postChannel": alert["resolved"]["mattermost"]["channel"],
        "postAuthorIdentityCount": alert["resolved"]["mattermost"]["distinctAuthors"],
        "postChannelIdentityCount": alert["resolved"]["mattermost"]["distinctChannels"],
        "cleanup": alert["cleanup"],
    }
    checks["C049"] = {"status": "pass", **blackbox_proof(config)}
    postgres_paths = postgres_rw_delete(values, apps, run_id)
    checks["C063"] = {
        "status": "pass",
        "dataContentProfile": profile["profile"],
        "expectedPathCount": len(postgres_paths),
        "applicationPaths": postgres_paths,
    }
    redis_paths = redis_authenticated_paths(values, apps)
    checks["C064"] = {
        "status": "pass",
        "dataContentProfile": profile["profile"],
        "expectedPathCount": len(redis_paths),
        "applicationPaths": redis_paths,
    }
    checks["C061"] = {"status": "pass", **indexed["checks"]["C061"]}
    checks["C062"] = {"status": "pass", **indexed["checks"]["C062"]}
    checks["C069"] = {
        "status": "pass",
        "stableDokployIds": indexed["stableDokployIds"],
        "noDuplicateResources": indexed["noDuplicateResources"],
        "secondPassNoChange": indexed["secondPassNoChange"],
        "componentCount": indexed["componentCount"],
        "inventoryIdentitySha256": indexed["inventoryIdentitySha256"],
        "coverage": indexed["coverage"],
        "evidence": str(INDEX_FINAL),
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
    parser.add_argument("--pass-number", type=int, choices=[1, 2])
    args = parser.parse_args()
    try:
        if args.command in {"apply", "reconcile-pass", "finalize-idempotency"}:
            if not args.expected_source_hash:
                raise CanaryError("hash_gate_required", "mutation requires final hash")
        if args.command == "apply":
            result = apply(args.expected_source_hash)
            output = {"status": result["status"], "evidence": str(EVIDENCE)}
        elif args.command == "reconcile-pass":
            if not args.pass_number:
                raise CanaryError(
                    "reconcile_pass_required", "--pass-number is required"
                )
            result = indexed_reconcile_pass(
                args.expected_source_hash,
                args.pass_number,
            )
            output = {
                "status": result["status"],
                "pass": args.pass_number,
                "evidence": str(INDEX_PASS[args.pass_number]),
            }
        elif args.command == "finalize-idempotency":
            result = finalize_indexed_idempotency(args.expected_source_hash)
            output = {"status": result["status"], "evidence": str(INDEX_FINAL)}
        else:
            output = preflight(args.expected_source_hash)
        print(json.dumps(output, sort_keys=True))
        return 0
    except CanaryError as exc:
        print(json.dumps({"status": "failed", "reason": exc.code, "message": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

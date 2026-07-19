#!/usr/bin/env python3
"""Hash-gated, secret-safe Cloudflare edge acceptance producer.

The ``observe`` action is intentionally executed from the operator machine so
that direct-origin reachability is measured outside the target host.  The
``run`` action executes on the target as root, validates that fresh observer
artifact, performs the Cloudflare and application checks, and atomically emits
root-only evidence.  Neither action changes the canonical platform source.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

import yaml


root = Path(os.environ.get("MTE_PLATFORM_ROOT", "/opt/mte-platform"))
secret_root = Path(os.environ.get("MTE_SECRET_ROOT", "/root/.config/mte-secrets"))
canonical = secret_root / "platform.env"
config_path = root / "config/platform.json"
data_content_path = root / "config/data-content-plane.json"
manifest_path = secret_root / "projections-manifest.json"
apps_path = secret_root / "cloudflare/apps.json"
iac_root = secret_root / "cloudflare/iac"
api_env_path = secret_root / "cloudflare/api.env"
lock_path = root / "templates/platform.lock.yaml"
evidence_path = root / "evidence/cloudflare-acceptance.json"
observer_path = root / "evidence/cloudflare-external-observation.json"
semantic_evidence_path = root / "evidence/cloudflare-app-semantics.json"
dns_reconcile_evidence_path = root / "evidence/cloudflare-dns-reconcile.json"
c029_integration_evidence_path = root / "evidence/integration-canary-C029.json"
observability_evidence_path = root / "evidence/observability-data-canary.json"
postgrest_evidence_path = root / "evidence/postgrest-verify.json"
notion_projection_canary_evidence_path = (
    root / "evidence/notion-projection-live-canary.json"
)
notion_consumer_verification_evidence_path = (
    root / "evidence/notion-projection-consumer-verify.json"
)
producer_path_expected = root / "bin/server-cloudflare-acceptance.py"
cloudflared_step_path = root / "steps/cloudflare-tunnel.sh"
origin_firewall_step_path = root / "steps/origin-firewall.sh"
generator_contract = "mte-config-renderer/v1"
searxng_canary_query = "OpenAI"
searxng_canary_attempts = 3
searxng_canary_retry_seconds = 1
opentofu_null_metadata_contracts = frozenset({("1.2", "1.12.1")})
semantic_connection_ids = ("C004", "C005", "C025", "C026", "C032")
connection_evidence_ids = (
    "C004",
    "C005",
    "C025",
    "C026",
    "C029",
    "C032",
    "C046",
    "C065",
    "C066",
    "C067",
)
connection_ids = (
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
)
human_connections = {
    "C004": "paperclip",
    "C005": "kestra",
    "C025": "searxng",
    "C032": "mattermost",
    "C046": "observability",
}

SERVICE_TOKEN_FIELDS = ("ID", "CLIENT_ID", "CLIENT_SECRET", "EXPIRES_AT")

# SSH must stay reachable for governed operation. Every other port is a direct
# origin or control-plane exposure that must be unreachable from the operator
# machine, including Docker Swarm and cloudflared metrics ports observed during
# the production pre-release audit.
external_ssh_port = 22
external_blocked_tcp_ports = (80, 443, 2377, 3000, 7946, 20241)

origin_firewall_status_fields = frozenset(
    {
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
)
origin_firewall_true_fields = frozenset(
    {
        "firewallServiceActive",
        "firewallServiceEnabled",
        "firewallRecoveryTimerActive",
        "firewallRecoveryTimerEnabled",
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
)


class AcceptanceError(RuntimeError):
    """A fail-closed error whose message is safe to persist and print."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


no_redirect = urllib.request.build_opener(NoRedirect)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise AcceptanceError("required_file_missing", str(path)) from exc
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise AcceptanceError("invalid_json", str(path)) from exc
    if not isinstance(value, dict):
        raise AcceptanceError("invalid_json_object", str(path))
    return value


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        raise AcceptanceError("canonical_source_missing", str(path)) from exc
    for number, raw in enumerate(lines, 1):
        if not raw or raw.startswith("#"):
            continue
        if "=" not in raw:
            raise AcceptanceError("canonical_source_invalid", f"line:{number}")
        key, value = raw.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise AcceptanceError("canonical_source_invalid", f"line:{number}")
        values[key] = value
    return values


def require_values(values: dict[str, str], *names: str) -> None:
    missing = sorted(name for name in names if not values.get(name))
    if missing:
        raise AcceptanceError("canonical_refs_missing", ",".join(missing))


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def exact_mode(path: Path, mode: int, *, root_owned: bool = True) -> None:
    if path.is_symlink():
        raise AcceptanceError("unsafe_file_symlink", str(path))
    try:
        info = path.stat()
    except OSError as exc:
        raise AcceptanceError("required_file_missing", str(path)) from exc
    if stat.S_IMODE(info.st_mode) != mode:
        raise AcceptanceError("unsafe_file_mode", str(path))
    if root_owned and (info.st_uid != 0 or info.st_gid != 0):
        raise AcceptanceError("unsafe_file_owner", str(path))


def file_security_contract(path: Path, mode: int) -> dict[str, Any]:
    """Return a public, exact root-owned file contract after checking it."""
    exact_mode(path, mode)
    if not path.is_file():
        raise AcceptanceError("unsafe_file_type", str(path))
    return {
        "path": str(path),
        "ownerUid": 0,
        "ownerGid": 0,
        "mode": f"{mode:04o}",
        "regularFile": True,
        "symlink": False,
    }


def expected_file_security(path: Path, mode: int) -> dict[str, Any]:
    """Describe the post-write security gate embedded into an evidence file."""
    return {
        "path": str(path),
        "ownerUid": 0,
        "ownerGid": 0,
        "mode": f"{mode:04o}",
        "regularFile": True,
        "symlink": False,
    }


def canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def exact_hash_gate() -> tuple[dict[str, str], dict[str, Any], dict[str, Any]]:
    exact_mode(canonical, 0o600)
    exact_mode(manifest_path, 0o600)
    exact_mode(config_path, 0o600)
    exact_mode(apps_path, 0o600)
    source_hash = sha256_file(canonical)
    config = load_json(config_path)
    manifest = load_json(manifest_path)
    apps = load_json(apps_path)
    generated = config.get("_generated")
    app_generated = apps.get("_generated")
    versions = {
        manifest.get("generatorVersion"),
        generated.get("generatorVersion") if isinstance(generated, dict) else None,
        app_generated.get("generatorVersion")
        if isinstance(app_generated, dict)
        else None,
    }
    hashes = {
        manifest.get("sourceSha256"),
        generated.get("sourceSha256") if isinstance(generated, dict) else None,
        app_generated.get("sourceSha256") if isinstance(app_generated, dict) else None,
    }
    if versions != {generator_contract}:
        raise AcceptanceError("generator_version_drift")
    if hashes != {source_hash}:
        raise AcceptanceError("final_stable_hash_gate_failed")
    rows = manifest.get("projections")
    if not isinstance(rows, list):
        raise AcceptanceError("projection_manifest_invalid")
    registered = {str(row.get("path")): row for row in rows if isinstance(row, dict)}
    for path in (config_path, data_content_path, apps_path):
        row = registered.get(str(path))
        if not isinstance(row, dict):
            raise AcceptanceError("projection_not_registered", str(path))
        if (
            row.get("sourceSha256") != source_hash
            or row.get("contentSha256") != sha256_file(path)
            or row.get("generatorVersion") != generator_contract
        ):
            raise AcceptanceError("projection_hash_drift", str(path))
    data_content = load_json(data_content_path)
    data_generated = data_content.get("_generated")
    if not (
        data_content.get("kind") == "DataContentPlane"
        and isinstance(data_generated, dict)
        and data_generated.get("sourceSha256") == source_hash
        and data_generated.get("generatorVersion") == generator_contract
    ):
        raise AcceptanceError("data_content_projection_invalid")
    data_content_edge_contract(apps, app_rows(apps, read_env(canonical), config))
    return (
        {"sourceSha256": source_hash, "generatorVersion": generator_contract},
        config,
        apps,
    )


def parse_iso(value: Any) -> datetime:
    if not isinstance(value, str):
        raise AcceptanceError("timestamp_missing")
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AcceptanceError("timestamp_invalid") from exc
    if moment.tzinfo is None:
        raise AcceptanceError("timestamp_invalid")
    return moment.astimezone(timezone.utc)


def request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: Any | None = None,
    allowed: set[int] | None = None,
    follow_redirects: bool = True,
    timeout: int = 30,
) -> tuple[int, Any, dict[str, str]]:
    request_headers = {
        "Accept": "application/json",
        "User-Agent": "mte-cloudflare-acceptance/1",
        **(headers or {}),
    }
    data = None
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        request_headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    opener = urllib.request.urlopen if follow_redirects else no_redirect.open
    try:
        response = opener(req, timeout=timeout)
        with response:
            status_code = response.status
            raw = response.read(8_000_000)
            response_headers = {
                key.lower(): value for key, value in response.headers.items()
            }
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        raw = exc.read(8_000_000)
        response_headers = {key.lower(): value for key, value in exc.headers.items()}
        if allowed is None or status_code not in allowed:
            raise AcceptanceError(
                "http_status_unexpected", f"{method}:{status_code}"
            ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AcceptanceError("http_endpoint_unavailable", method) from exc
    if allowed is not None and status_code not in allowed:
        raise AcceptanceError("http_status_unexpected", f"{method}:{status_code}")
    if not raw:
        value: Any = None
    else:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            value = raw.decode(errors="replace")
    return status_code, value, response_headers


class CloudflareApi:
    def __init__(self, token: str) -> None:
        self.token = token

    def get(self, path: str, query: dict[str, str] | None = None) -> Any:
        endpoint = "https://api.cloudflare.com/client/v4" + path
        if query:
            endpoint += "?" + urllib.parse.urlencode(query)
        status_code, payload, _ = request(
            "GET", endpoint, headers={"Authorization": "Bearer " + self.token}
        )
        if (
            status_code != 200
            or not isinstance(payload, dict)
            or payload.get("success") is not True
        ):
            raise AcceptanceError("cloudflare_api_failed", path.rsplit("/", 1)[-1])
        return payload.get("result")

    def pages(
        self, path: str, query: dict[str, str] | None = None
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        page = 1
        while True:
            params = {**(query or {}), "page": str(page), "per_page": "100"}
            endpoint = (
                "https://api.cloudflare.com/client/v4"
                + path
                + "?"
                + urllib.parse.urlencode(params)
            )
            status_code, payload, _ = request(
                "GET", endpoint, headers={"Authorization": "Bearer " + self.token}
            )
            if (
                status_code != 200
                or not isinstance(payload, dict)
                or payload.get("success") is not True
                or not isinstance(payload.get("result"), list)
            ):
                raise AcceptanceError("cloudflare_api_failed", path.rsplit("/", 1)[-1])
            rows.extend(row for row in payload["result"] if isinstance(row, dict))
            info = payload.get("result_info")
            pages = (
                int(info.get("total_pages", page)) if isinstance(info, dict) else page
            )
            if page >= pages or not payload["result"]:
                return rows
            page += 1


def declared_managed_app_ids(config: dict[str, Any]) -> set[str]:
    """Return the exact edge application set from the active Platform config."""
    spec = config.get("spec")
    if not isinstance(spec, dict) or not isinstance(spec.get("components"), list):
        raise AcceptanceError("platform_app_declarations_invalid")
    declarations: list[Any] = [
        component
        for component in spec["components"]
        if isinstance(component, dict) and isinstance(component.get("exposure"), dict)
    ]
    cloudflare = spec.get("cloudflare")
    if not isinstance(cloudflare, dict):
        raise AcceptanceError("platform_app_declarations_invalid")
    additional = cloudflare.get("additionalApps")
    if not isinstance(additional, list):
        raise AcceptanceError("platform_app_declarations_invalid")
    declarations.extend(additional)
    identifiers: set[str] = set()
    for declaration in declarations:
        if not isinstance(declaration, dict):
            raise AcceptanceError("platform_app_declarations_invalid")
        app_id = str(declaration.get("id", ""))
        if (
            not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", app_id)
            or app_id in identifiers
        ):
            raise AcceptanceError("platform_app_declarations_invalid", app_id)
        identifiers.add(app_id)
    if not identifiers:
        raise AcceptanceError("platform_app_declarations_invalid")
    return identifiers


def app_rows(
    apps: dict[str, Any], values: dict[str, str], config: dict[str, Any]
) -> dict[str, dict[str, str]]:
    base_domain = values.get("PLATFORM_BASE_DOMAIN", "").strip().lower().rstrip(".")
    raw = apps.get("apps")
    if not base_domain or not isinstance(raw, dict):
        raise AcceptanceError("cloudflare_apps_projection_invalid")
    normalized: dict[str, dict[str, str]] = {}
    for app_id, row in raw.items():
        if not isinstance(row, dict):
            raise AcceptanceError("cloudflare_apps_projection_invalid")
        hostname = str(row.get("hostname", "")).lower().rstrip(".")
        origin = str(row.get("origin", ""))
        access_class = str(row.get("accessClass", ""))
        if (
            not hostname.endswith("." + base_domain)
            or not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", origin)
            or access_class not in {"human", "service"}
        ):
            raise AcceptanceError("cloudflare_apps_projection_invalid", str(app_id))
        normalized[str(app_id)] = {
            "hostname": hostname,
            "origin": origin,
            "accessClass": access_class,
        }
    declared = declared_managed_app_ids(config)
    if set(normalized) != declared:
        missing = ",".join(sorted(declared - set(normalized))) or "none"
        unexpected = ",".join(sorted(set(normalized) - declared)) or "none"
        raise AcceptanceError(
            "managed_app_declaration_mismatch",
            f"missing={missing};unexpected={unexpected}",
        )
    return normalized


def service_route_credentials(values: dict[str, str], app_id: str) -> dict[str, str]:
    prefix = "CLOUDFLARE_ACCESS_ROUTE_" + app_id.upper().replace("-", "_")
    names = {field: prefix + "_" + field for field in SERVICE_TOKEN_FIELDS}
    require_values(values, *names.values())
    expires_at = parse_iso(values[names["EXPIRES_AT"]])
    if (expires_at - datetime.now(timezone.utc)).total_seconds() <= 300:
        raise AcceptanceError("cloudflare_service_token_expired_or_near_expiry", app_id)
    return {
        "id": values[names["ID"]],
        "client_id": values[names["CLIENT_ID"]],
        "client_secret": values[names["CLIENT_SECRET"]],
        "expires_at": values[names["EXPIRES_AT"]],
    }


def service_probe_paths(
    config: dict[str, Any], apps: dict[str, dict[str, str]]
) -> dict[str, str]:
    components = config.get("spec", {}).get("components", [])
    by_id = {
        str(row.get("id")): row
        for row in components
        if isinstance(row, dict) and row.get("id")
    }
    result: dict[str, str] = {}
    for app_id, app in apps.items():
        if app["accessClass"] != "service":
            continue
        component = by_id.get(app_id)
        health = component.get("health") if isinstance(component, dict) else None
        health_url = str(health.get("url", "")) if isinstance(health, dict) else ""
        parsed = urllib.parse.urlsplit(health_url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
            raise AcceptanceError("service_route_health_url_invalid", app_id)
        result[app_id] = parsed.path or "/"
    return result


def service_edge_checks(
    values: dict[str, str],
    apps: dict[str, dict[str, str]],
    config: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    service_apps = {
        app_id: app for app_id, app in apps.items() if app["accessClass"] == "service"
    }
    if not service_apps:
        return {}
    credentials = {
        app_id: service_route_credentials(values, app_id) for app_id in service_apps
    }
    paths = service_probe_paths(config, apps)
    app_ids = sorted(service_apps)
    if len(app_ids) < 2:
        raise AcceptanceError("cross_route_service_token_unavailable")
    checks: dict[str, dict[str, Any]] = {}
    for index, app_id in enumerate(app_ids):
        app = service_apps[app_id]
        cross_id = app_ids[(index + 1) % len(app_ids)]
        endpoint = "https://" + app["hostname"] + paths[app_id]
        anonymous_status, _payload, _headers = request(
            "GET", endpoint, allowed={401}, follow_redirects=False
        )
        intended = credentials[app_id]
        intended_status, _payload, _headers = request(
            "GET",
            endpoint,
            headers={
                "CF-Access-Client-Id": intended["client_id"],
                "CF-Access-Client-Secret": intended["client_secret"],
            },
            allowed={200},
        )
        cross = credentials[cross_id]
        cross_status, _payload, _headers = request(
            "GET",
            endpoint,
            headers={
                "CF-Access-Client-Id": cross["client_id"],
                "CF-Access-Client-Secret": cross["client_secret"],
            },
            allowed={401},
            follow_redirects=False,
        )
        checks[app_id] = {
            "hostname": app["hostname"],
            "healthPath": paths[app_id],
            "anonymousDenied": anonymous_status == 401,
            "intendedTokenStatus": intended_status,
            "crossTokenDenied": cross_status == 401,
            "crossTokenRoute": cross_id,
            "credentialValuesEmitted": False,
        }
    return checks


def data_content_edge_contract(
    apps_projection: dict[str, Any], apps: dict[str, dict[str, str]]
) -> dict[str, Any]:
    """Resolve C029 from the hash-governed data/content projection.

    Self-hosted workspace providers must resolve to managed Cloudflare apps.
    The default Notion provider is external SaaS, so its UI roles deliberately
    have no DNS, tunnel route, or Access application in this contract.
    """
    value = apps_projection.get("dataContent")
    if not isinstance(value, dict) or set(value) != {
        "profile",
        "projectionSha256",
        "roles",
    }:
        raise AcceptanceError("data_content_edge_contract_invalid")
    profile = value.get("profile")
    projection_sha = value.get("projectionSha256")
    roles = value.get("roles")
    if not (
        isinstance(profile, str)
        and bool(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", profile))
        and isinstance(projection_sha, str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", projection_sha))
        and projection_sha == sha256_file(data_content_path)
        and isinstance(roles, dict)
    ):
        raise AcceptanceError("data_content_edge_contract_invalid")

    plane = load_json(data_content_path)
    plane_roles = plane.get("roles") if isinstance(plane.get("roles"), dict) else {}
    providers = (
        plane.get("providers") if isinstance(plane.get("providers"), dict) else {}
    )
    if profile == "postgres-notion":
        notion = providers.get("notion")
        expected_role_contract = {
            "tablesUi": ("tables", "ui"),
            "tablesApi": ("tables", "api"),
            "documentsUi": ("documents", "ui"),
            "documentsApi": ("documents", "api"),
        }
        if not (
            roles == {}
            and plane.get("profile") == profile
            and isinstance(notion, dict)
            and notion.get("kind") == "external-workspace"
            and notion.get("deployment") == "external"
            and notion.get("componentId") is None
            and set(plane_roles) == set(expected_role_contract)
            and all(
                isinstance(plane_roles.get(role_id), dict)
                and plane_roles[role_id].get("providerId") == "notion"
                and plane_roles[role_id].get("capability") == capability
                and plane_roles[role_id].get("interface") == interface
                and plane_roles[role_id].get("adapterId") == "notion"
                for role_id, (capability, interface) in expected_role_contract.items()
            )
        ):
            raise AcceptanceError("external_data_content_contract_invalid")
        return {
            "profile": profile,
            "projectionSha256": projection_sha,
            "edgeManaged": False,
            "providerId": "notion",
            "roles": {},
            "roleBindings": {
                role_id: {
                    "providerId": "notion",
                    "capability": capability,
                    "interface": interface,
                    "adapterId": "notion",
                }
                for role_id, (capability, interface) in expected_role_contract.items()
            },
            "applicationIds": [],
        }

    if set(roles) != {"tablesUi", "documentsUi"}:
        raise AcceptanceError("data_content_edge_contract_invalid")
    normalized_roles: dict[str, dict[str, str]] = {}
    application_ids: list[str] = []
    for role_id in ("tablesUi", "documentsUi"):
        row = roles.get(role_id)
        if not isinstance(row, dict) or set(row) != {
            "applicationId",
            "hostname",
            "accessClass",
        }:
            raise AcceptanceError("data_content_edge_role_invalid", role_id)
        application_id = str(row.get("applicationId", ""))
        app = apps.get(application_id)
        if not (
            isinstance(app, dict)
            and row.get("hostname") == app.get("hostname")
            and row.get("accessClass") == "human"
            and app.get("accessClass") == "human"
        ):
            raise AcceptanceError("data_content_edge_role_invalid", role_id)
        application_ids.append(application_id)
        normalized_roles[role_id] = {
            "applicationId": application_id,
            "hostname": str(row["hostname"]),
            "accessClass": "human",
        }
    return {
        "profile": profile,
        "projectionSha256": projection_sha,
        "edgeManaged": True,
        "roles": normalized_roles,
        "roleBindings": normalized_roles,
        "applicationIds": list(dict.fromkeys(application_ids)),
    }


def human_connection_contract(
    data_content: dict[str, Any],
) -> dict[str, tuple[str, ...]]:
    result = {
        connection_id: (app_id,) for connection_id, app_id in human_connections.items()
    }
    if data_content.get("edgeManaged") is True:
        roles = data_content["roles"]
        result["C029"] = tuple(
            dict.fromkeys(
                (
                    roles["tablesUi"]["applicationId"],
                    roles["documentsUi"]["applicationId"],
                )
            )
        )
    return result


def one(rows: list[dict[str, Any]], code: str) -> dict[str, Any]:
    if len(rows) != 1:
        raise AcceptanceError(code, str(len(rows)))
    return rows[0]


def dns_reconcile_status(
    source_gate: dict[str, str],
    apps: dict[str, dict[str, str]],
    tunnel_id: str,
) -> dict[str, Any]:
    exact_mode(dns_reconcile_evidence_path, 0o600)
    payload = load_json(dns_reconcile_evidence_path)
    producer = root / "bin/server-cloudflare-dns.py"
    exact_mode(producer, 0o700)
    tfvars = iac_root / "terraform.tfvars.json"
    exact_mode(tfvars, 0o600)
    access_classes = {
        app_id: row["accessClass"] for app_id, row in sorted(apps.items())
    }
    expected_target = tunnel_id + ".cfargotunnel.com"
    expected_official_contracts = [
        "https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/batch/",
        "https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/",
    ]
    fingerprints = (
        payload.get("foreignRecordSetBeforeSha256"),
        payload.get("foreignRecordSetAfterSha256"),
    )
    if not (
        payload.get("apiVersion") == "micro-task-engine/v1alpha1"
        and payload.get("kind") == "CloudflareDnsReconcileEvidence"
        and payload.get("status") == "passed"
        and payload.get("ok") is True
        and payload.get("action") in {"apply", "verify"}
        and payload.get("canonicalSourceSha256") == source_gate["sourceSha256"]
        and payload.get("tfvarsSha256") == sha256_file(tfvars)
        and payload.get("producerPath") == str(producer)
        and payload.get("producerSha256") == sha256_file(producer)
        and payload.get("desiredHostnameCount") == len(apps)
        and payload.get("accessClassBindingSha256")
        == canonical_json_sha256(access_classes)
        and payload.get("tunnelTargetSha256") == canonical_json_sha256(expected_target)
        and isinstance(payload.get("plannedDeleteCount"), int)
        and not isinstance(payload.get("plannedDeleteCount"), bool)
        and payload["plannedDeleteCount"] >= 0
        and isinstance(payload.get("plannedCreateCount"), int)
        and not isinstance(payload.get("plannedCreateCount"), bool)
        and payload["plannedCreateCount"] >= 0
        and isinstance(payload.get("batchApplied"), bool)
        and payload.get("batchDatabaseTransactionAtomic") is True
        and payload.get("edgePropagationAtomic") is False
        and payload.get("batchOperationOrder")
        == ["deletes", "patches", "puts", "posts"]
        and payload.get("desiredHostnamesReserved") is True
        and payload.get("desiredRecordsExact") is True
        and payload.get("proxiedDnsOnly") is True
        and payload.get("originAddressRecordCount") == 0
        and isinstance(payload.get("foreignRecordCount"), int)
        and not isinstance(payload.get("foreignRecordCount"), bool)
        and payload["foreignRecordCount"] >= 0
        and all(
            isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))
            for value in fingerprints
        )
        and fingerprints[0] == fingerprints[1]
        and payload.get("foreignRecordsPreserved") is True
        and payload.get("officialContracts") == expected_official_contracts
        and payload.get("secretValuesPrinted") is False
    ):
        raise AcceptanceError("cloudflare_dns_reconcile_evidence_invalid")
    return {
        "dependencyEvidence": {
            "path": str(dns_reconcile_evidence_path),
            "sha256": sha256_file(dns_reconcile_evidence_path),
        },
        "batchApplied": payload.get("batchApplied") is True,
        "batchDatabaseTransactionAtomic": True,
        "edgePropagationAtomic": False,
        "desiredHostnamesReserved": True,
        "desiredRecordsExact": True,
        "proxiedDnsOnly": True,
        "originAddressRecordCount": 0,
        "foreignRecordCount": payload["foreignRecordCount"],
        "foreignRecordsPreserved": True,
        "foreignRecordSetSha256": fingerprints[1],
    }


def cloudflare_inventory(
    values: dict[str, str], apps: dict[str, dict[str, str]]
) -> dict[str, Any]:
    require_values(
        values,
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_ACCOUNT_ID",
        "CLOUDFLARE_ZONE_ID",
        "CLOUDFLARE_TUNNEL_NAME",
    )
    api = CloudflareApi(values["CLOUDFLARE_API_TOKEN"])
    account = values["CLOUDFLARE_ACCOUNT_ID"]
    zone = values["CLOUDFLARE_ZONE_ID"]
    tunnels = api.pages(f"/accounts/{account}/cfd_tunnel")
    tunnel = one(
        [row for row in tunnels if row.get("name") == values["CLOUDFLARE_TUNNEL_NAME"]],
        "named_tunnel_count_mismatch",
    )
    tunnel_id = str(tunnel.get("id", ""))
    if tunnel.get("status") != "healthy" or not tunnel_id:
        raise AcceptanceError("named_tunnel_unhealthy")
    connections = tunnel.get("connections")
    if not isinstance(connections, list) or not connections:
        raise AcceptanceError("named_tunnel_has_no_connections")
    if any(
        row.get("is_pending_reconnect") is True
        for row in connections
        if isinstance(row, dict)
    ):
        raise AcceptanceError("named_tunnel_pending_reconnect")

    dns = api.pages(f"/zones/{zone}/dns_records")
    access = api.pages(f"/accounts/{account}/access/apps")
    expected_target = tunnel_id + ".cfargotunnel.com"
    dns_ids: list[str] = []
    access_ids: list[str] = []
    policy_cache: dict[str, dict[str, Any]] = {}
    human_apps_present = any(row["accessClass"] == "human" for row in apps.values())
    expected_human_emails = sorted(
        value.strip().lower()
        for value in values.get("CLOUDFLARE_ACCESS_ALLOWED_EMAILS", "").split(",")
        if value.strip()
    )
    if human_apps_present and (
        not expected_human_emails
        or len(expected_human_emails) != len(set(expected_human_emails))
        or any(
            not re.fullmatch(r"[^@\s,]+@[^@\s,]+", value)
            for value in expected_human_emails
        )
    ):
        raise AcceptanceError("human_access_email_scope_invalid")
    for app_id, expected in apps.items():
        record = one(
            [
                row
                for row in dns
                if str(row.get("name", "")).lower().rstrip(".") == expected["hostname"]
            ],
            "managed_dns_count_mismatch",
        )
        if not (
            record.get("type") == "CNAME"
            and bool(record.get("id"))
            and str(record.get("content", "")).lower().rstrip(".") == expected_target
            and record.get("proxied") is True
            and record.get("ttl") == 1
            and record.get("comment") == "Managed by MTE platform IaC for " + app_id
        ):
            raise AcceptanceError("managed_dns_contract_drift", app_id)
        dns_ids.append(str(record.get("id", "")))
        access_app = one(
            [
                row
                for row in access
                if str(row.get("domain", "")).lower().rstrip(".")
                == expected["hostname"]
            ],
            "managed_access_app_count_mismatch",
        )
        human = expected["accessClass"] == "human"
        policies = access_app.get("policies")
        if not (
            access_app.get("type") == "self_hosted"
            and bool(access_app.get("id"))
            and isinstance(policies, list)
            and len(policies) == 1
            and isinstance(policies[0], dict)
            and bool(policies[0].get("id"))
            and access_app.get("app_launcher_visible") is human
            and (human or access_app.get("service_auth_401_redirect") is True)
        ):
            raise AcceptanceError("managed_access_contract_drift", app_id)
        policy_id = str(policies[0]["id"])
        if policy_id not in policy_cache:
            policy_cache[policy_id] = api.get(
                f"/accounts/{account}/access/policies/{policy_id}"
            )
        policy = policy_cache[policy_id]
        include = (
            policy.get("include") if isinstance(policy.get("include"), list) else []
        )
        if human:
            observed_emails = sorted(
                str(item.get("email", {}).get("email", "")).strip().lower()
                for item in include
                if isinstance(item, dict) and isinstance(item.get("email"), dict)
            )
            policy_valid = (
                policy.get("decision") == "allow"
                and observed_emails == expected_human_emails
                and len(include) == len(observed_emails)
            )
        else:
            route_token = service_route_credentials(values, app_id)
            policy_valid = policy.get("decision") == "non_identity" and include == [
                {"service_token": {"token_id": route_token["id"]}}
            ]
        if (
            not policy_valid
            or policy.get("exclude") not in (None, [])
            or policy.get("require") not in (None, [])
        ):
            raise AcceptanceError("managed_access_policy_scope_drift", app_id)
        access_ids.append(str(access_app.get("id", "")))

    remote = api.get(f"/accounts/{account}/cfd_tunnel/{tunnel_id}/configurations")
    ingress = (
        remote.get("config", {}).get("ingress") if isinstance(remote, dict) else None
    )
    if not isinstance(ingress, list) or len(ingress) != len(apps) + 1:
        raise AcceptanceError("tunnel_ingress_count_mismatch")
    actual_routes = {
        str(row.get("hostname", "")).lower().rstrip("."): str(row.get("service", ""))
        for row in ingress
        if isinstance(row, dict) and row.get("hostname")
    }
    expected_routes = {row["hostname"]: row["origin"] for row in apps.values()}
    catchall = [
        row for row in ingress if isinstance(row, dict) and not row.get("hostname")
    ]
    if actual_routes != expected_routes or catchall != [{"service": "http_status:404"}]:
        raise AcceptanceError("tunnel_ingress_contract_drift")

    desired_hostnames = {row["hostname"] for row in apps.values()}
    foreign: list[dict[str, Any]] = []
    for row in dns:
        hostname = str(row.get("name", "")).lower().rstrip(".")
        if hostname in desired_hostnames:
            continue
        if str(row.get("comment", "")).startswith("Managed by MTE platform IaC for "):
            raise AcceptanceError("retired_managed_dns_remains")
        foreign.append(
            {
                "recordFingerprint": canonical_json_sha256(
                    {
                        "id": str(row.get("id", "")),
                        "name": hostname,
                        "type": str(row.get("type", "")),
                        "content": str(row.get("content", "")),
                        "proxied": row.get("proxied"),
                        "ttl": row.get("ttl"),
                        "comment": str(row.get("comment", "")),
                    }
                ),
            }
        )
    return {
        "tunnelId": tunnel_id,
        "tunnelName": str(tunnel.get("name")),
        "tunnelHealthy": True,
        "connectorCount": len(connections),
        "dnsRecordCount": len(dns_ids),
        "accessApplicationCount": len(access_ids),
        "accessPolicyCount": len(policy_cache),
        "humanAccessPolicyScoped": True,
        "serviceAccessTokenScoped": True,
        "desiredHostnamesReserved": True,
        "dnsTargetTunnelBound": True,
        "proxiedDnsOnly": True,
        "originAddressRecordCount": 0,
        "routes": expected_routes,
        "foreign": foreign,
        "foreignRecordSetSha256": canonical_json_sha256(
            sorted(row["recordFingerprint"] for row in foreign)
        ),
    }


def edge_redirect(hostname: str) -> dict[str, Any]:
    status_code, _payload, headers = request(
        "GET",
        "https://" + hostname + "/",
        allowed={302},
        follow_redirects=False,
    )
    location = headers.get("location", "")
    parsed = urllib.parse.urlsplit(location)
    access_location = parsed.scheme == "https" and (
        parsed.netloc.endswith(".cloudflareaccess.com")
        or parsed.path.startswith("/cdn-cgi/access/")
    )
    if status_code != 302 or not access_location:
        raise AcceptanceError("human_access_redirect_invalid", hostname)
    return {"anonymousStatus": status_code, "accessLocationVerified": True}


def basic(user: str, password: str) -> dict[str, str]:
    encoded = base64.b64encode((user + ":" + password).encode()).decode()
    return {"Authorization": "Basic " + encoded}


def list_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    if isinstance(value, dict):
        for key in ("results", "data", "list", "items", "content"):
            if isinstance(value.get(key), list):
                return [row for row in value[key] if isinstance(row, dict)]
    return []


def semantic_paperclip(values: dict[str, str], origin: str) -> dict[str, Any]:
    require_values(
        values,
        "PAPERCLIP_AGENT_API_KEY",
        "PAPERCLIP_SERVICE_AGENT_ID",
        "PAPERCLIP_COMPANY_ID",
    )
    status_code, payload, _ = request(
        "GET",
        origin + "/api/agents/me",
        headers={"Authorization": "Bearer " + values["PAPERCLIP_AGENT_API_KEY"]},
    )
    if not (
        status_code == 200
        and isinstance(payload, dict)
        and payload.get("id") == values["PAPERCLIP_SERVICE_AGENT_ID"]
        and payload.get("companyId") == values["PAPERCLIP_COMPANY_ID"]
    ):
        raise AcceptanceError("paperclip_authenticated_identity_invalid")
    return {
        "semantic": "authenticated-agent-identity",
        "httpStatus": 200,
        "originAuthenticationRequired": True,
        "originAuthenticationVerified": True,
    }


def semantic_kestra(values: dict[str, str], origin: str) -> dict[str, Any]:
    require_values(values, "KESTRA_ADMIN_USER", "KESTRA_ADMIN_PASSWORD")
    status_code, payload, _ = request(
        "GET",
        origin + "/api/v1/main/flows/search?size=100",
        headers=basic(values["KESTRA_ADMIN_USER"], values["KESTRA_ADMIN_PASSWORD"]),
    )
    flows = list_rows(payload)
    expected = [
        row
        for row in flows
        if row.get("namespace") == "micro_task_engine.e2e"
        and row.get("id") == "paperclip-github-e2e"
    ]
    if status_code != 200 or len(expected) != 1:
        raise AcceptanceError("kestra_authenticated_flow_missing")
    return {
        "semantic": "authenticated-e2e-flow-catalog",
        "flowCount": len(flows),
        "originAuthenticationRequired": True,
        "originAuthenticationVerified": True,
    }


def semantic_searxng(_values: dict[str, str], origin: str) -> dict[str, Any]:
    query = urllib.parse.urlencode(
        {"q": searxng_canary_query, "format": "json", "language": "en"}
    )
    endpoint = origin + "/search?" + query
    for attempt in range(1, searxng_canary_attempts + 1):
        status_code, payload, _ = request("GET", endpoint, timeout=60)
        if status_code != 200 or not isinstance(payload, dict):
            raise AcceptanceError("searxng_live_search_contract_invalid")
        if payload.get("query") != searxng_canary_query:
            raise AcceptanceError("searxng_live_search_contract_invalid")
        results = payload.get("results")
        if not isinstance(results, list) or any(
            not isinstance(row, dict) for row in results
        ):
            raise AcceptanceError("searxng_live_search_contract_invalid")
        valid_results = [
            row
            for row in results
            if isinstance(row.get("title"), str)
            and row["title"].strip()
            and isinstance(row.get("url"), str)
            and urllib.parse.urlsplit(row["url"]).scheme in {"http", "https"}
            and bool(urllib.parse.urlsplit(row["url"]).netloc)
        ]
        if valid_results:
            return {
                "semantic": "live-json-search",
                "canaryQuerySha256": hashlib.sha256(
                    searxng_canary_query.encode()
                ).hexdigest(),
                "attemptCount": attempt,
                "resultCount": len(results),
                "validResultCount": len(valid_results),
                "originAuthenticationRequired": False,
                "originAuthenticationVerified": True,
            }
        if results:
            raise AcceptanceError("searxng_live_search_contract_invalid")
        if attempt < searxng_canary_attempts:
            time.sleep(searxng_canary_retry_seconds)
    raise AcceptanceError("searxng_live_search_empty")


def semantic_mattermost(values: dict[str, str], origin: str) -> dict[str, Any]:
    require_values(values, "MATTERMOST_BOT_TOKEN", "MATTERMOST_BOT_USER_ID")
    status_code, payload, _ = request(
        "GET",
        origin + "/api/v4/users/me",
        headers={"Authorization": "Bearer " + values["MATTERMOST_BOT_TOKEN"]},
    )
    if not (
        status_code == 200
        and isinstance(payload, dict)
        and payload.get("id") == values["MATTERMOST_BOT_USER_ID"]
    ):
        raise AcceptanceError("mattermost_authenticated_bot_invalid")
    return {
        "semantic": "authenticated-bot-identity",
        "botIdentityVerified": True,
        "originAuthenticationRequired": True,
        "originAuthenticationVerified": True,
    }


def semantic_grafana(values: dict[str, str], origin: str) -> dict[str, Any]:
    require_values(values, "GRAFANA_ADMIN_USER", "GRAFANA_ADMIN_PASSWORD")
    auth = basic(values["GRAFANA_ADMIN_USER"], values["GRAFANA_ADMIN_PASSWORD"])
    status_code, payload, _ = request(
        "GET",
        origin + "/api/datasources",
        headers=auth,
    )
    rows = list_rows(payload)
    expected = {"victoriametrics", "victorialogs", "victoriatraces"}
    observed = {str(row.get("uid", "")) for row in rows}
    if status_code != 200 or observed != expected:
        raise AcceptanceError("grafana_authenticated_datasources_missing")
    read_status, saved, _ = request(
        "GET",
        origin + "/api/dashboards/uid/mte-platform-overview",
        headers=auth,
    )
    dashboard = saved.get("dashboard") if isinstance(saved, dict) else None
    meta = saved.get("meta") if isinstance(saved, dict) else None
    panels = dashboard.get("panels") if isinstance(dashboard, dict) else None
    observed_panels = {
        (
            str(panel.get("title", "")),
            str(panel.get("type", "")),
            str(panel.get("datasource", {}).get("uid", "")),
        )
        for panel in panels or []
        if isinstance(panel, dict) and isinstance(panel.get("datasource"), dict)
    }
    expected_panels = {
        ("Platform endpoints up", "stat", "victoriametrics"),
        ("Endpoint availability", "timeseries", "victoriametrics"),
        ("Task and run log search", "logs", "victorialogs"),
    }
    if not (
        read_status == 200
        and isinstance(dashboard, dict)
        and dashboard.get("uid") == "mte-platform-overview"
        and dashboard.get("title") == "MTE Platform: Agents and Services"
        and set(dashboard.get("tags") or []) == {"mte", "agents", "task_id", "run_id"}
        and dashboard.get("editable") is False
        and isinstance(panels, list)
        and len(panels) == len(expected_panels)
        and observed_panels == expected_panels
        and isinstance(meta, dict)
        and isinstance(meta.get("folderUid"), str)
        and bool(meta.get("folderUid"))
    ):
        raise AcceptanceError("grafana_managed_dashboard_invalid")
    return {
        "semantic": "authenticated-declarative-dashboard-and-datasource-catalog",
        "requiredDatasources": 3,
        "requiredPanels": 3,
        "dashboardProvisioned": True,
        "originAuthenticationRequired": True,
        "originAuthenticationVerified": True,
    }


semantic_checks = {
    "paperclip": semantic_paperclip,
    "kestra": semantic_kestra,
    "searxng": semantic_searxng,
    "mattermost": semantic_mattermost,
    "observability": semantic_grafana,
}


def human_rows(
    values: dict[str, str],
    apps: dict[str, dict[str, str]],
    connection_apps: dict[str, tuple[str, ...]],
    data_content: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    expected_connections = set(human_connections)
    if data_content.get("edgeManaged") is True:
        expected_connections.add("C029")
    if set(connection_apps) != expected_connections:
        raise AcceptanceError("human_connection_set_invalid")
    for connection_id, app_ids in connection_apps.items():
        if not app_ids:
            raise AcceptanceError("human_app_contract_missing", connection_id)
        application_rows: list[dict[str, Any]] = []
        for app_id in app_ids:
            app = apps.get(app_id)
            if not isinstance(app, dict) or app.get("accessClass") != "human":
                raise AcceptanceError("human_app_contract_missing", app_id)
            edge = edge_redirect(app["hostname"])
            checker = semantic_checks.get(app_id)
            if checker is None:
                raise AcceptanceError("human_semantic_checker_missing", app_id)
            semantic = checker(values, app["origin"])
            if not (
                semantic.get("originAuthenticationVerified") is True
                and isinstance(semantic.get("originAuthenticationRequired"), bool)
            ):
                raise AcceptanceError("origin_authentication_evidence_missing", app_id)
            application_rows.append(
                {
                    "applicationId": app_id,
                    "canonicalHostname": app["hostname"],
                    "expectedAccessClass": "human",
                    **edge,
                    **semantic,
                }
            )
        primary = application_rows[0]
        result[connection_id] = {
            "id": connection_id,
            "ok": True,
            "state": "passed",
            "canonicalHostname": primary["canonicalHostname"],
            "canonicalHostnames": [
                row["canonicalHostname"] for row in application_rows
            ],
            "expectedAccessClass": "human",
            "edgeGateVerified": True,
            "serviceSemanticVerified": True,
            "originSemanticVerified": True,
            "originAuthenticationVerified": all(
                row.get("originAuthenticationVerified") is True
                for row in application_rows
            ),
            "authenticatedCloudflareSessionTested": False,
            "dependencyEvidence": [],
            "edgeApplications": application_rows,
            "anonymousStatus": primary["anonymousStatus"],
            "accessLocationVerified": all(
                row.get("accessLocationVerified") is True for row in application_rows
            ),
            "semantic": primary["semantic"],
        }
        if connection_id == "C029":
            result[connection_id].update(
                {
                    "cloudflareManaged": True,
                    "edgeGateApplicable": True,
                    "dataContentProfile": data_content["profile"],
                    "dataContentProjectionSha256": data_content["projectionSha256"],
                    "tablesHostname": data_content["roles"]["tablesUi"]["hostname"],
                    "documentsHostname": data_content["roles"]["documentsUi"][
                        "hostname"
                    ],
                    "dataContentApplications": [
                        row["applicationId"] for row in application_rows
                    ],
                    "dataContentRoles": data_content["roles"],
                }
            )
    if data_content.get("edgeManaged") is False:
        if data_content.get("profile") != "postgres-notion":
            raise AcceptanceError("external_data_content_profile_invalid")
        result["C029"] = {
            "id": "C029",
            "ok": True,
            "state": "passed",
            "canonicalHostname": "api.notion.com",
            "canonicalHostnames": [],
            "expectedAccessClass": "external-saas",
            "cloudflareManaged": False,
            "edgeGateApplicable": False,
            "edgeGateVerified": False,
            "serviceSemanticVerified": False,
            "originSemanticVerified": False,
            "originAuthenticationVerified": False,
            "authenticatedCloudflareSessionTested": False,
            "dependencyEvidence": [],
            "edgeApplications": [],
            "externalProvider": "notion",
            "externalProviderAuthentication": "notion-workspace-integration",
            "dataContentProfile": data_content["profile"],
            "dataContentProjectionSha256": data_content["projectionSha256"],
            "dataContentApplications": [],
            "dataContentRoles": data_content["roleBindings"],
        }
    return result


def fresh_dependency(
    path: Path,
    *,
    source_gate: dict[str, str],
    kind: str,
    time_field: str,
    producer: Path,
) -> dict[str, Any]:
    exact_mode(path, 0o600)
    if not producer.is_file() or producer.is_symlink():
        raise AcceptanceError("dependency_producer_missing", str(producer))
    exact_mode(producer, 0o700)
    document = load_json(path)
    moment = parse_iso(document.get(time_field))
    age = (datetime.now(timezone.utc) - moment).total_seconds()
    canonical_hash = document.get("canonicalSourceSha256")
    if canonical_hash is None and isinstance(document.get("sourceGate"), dict):
        canonical_hash = document["sourceGate"].get("sourceSha256")
    if not (
        document.get("apiVersion") == "micro-task-engine/v1alpha1"
        and document.get("kind") == kind
        and document.get("status", "passed") == "passed"
        and canonical_hash == source_gate["sourceSha256"]
        and document.get("producerSha256") == sha256_file(producer)
        and -30 <= age <= 600
    ):
        raise AcceptanceError("dependency_evidence_invalid", path.name)
    return document


def fresh_component_dependency(
    path: Path,
    *,
    source_gate: dict[str, str],
    api_version: str,
    kind: str,
    producer: Path,
) -> dict[str, Any]:
    exact_mode(path, 0o600)
    if not producer.is_file() or producer.is_symlink():
        raise AcceptanceError("dependency_producer_missing", str(producer))
    exact_mode(producer, 0o700)
    document = load_json(path)
    age = (
        datetime.now(timezone.utc) - parse_iso(document.get("generatedAt"))
    ).total_seconds()
    if not (
        document.get("apiVersion") == api_version
        and document.get("kind") == kind
        and document.get("status") == "passed"
        and document.get("ok") is True
        and document.get("canonicalSourceSha256") == source_gate["sourceSha256"]
        and document.get("producerSha256") == sha256_file(producer)
        and -30 <= age <= 900
    ):
        raise AcceptanceError("component_dependency_evidence_invalid", path.name)
    return document


def c029_persistence_dependencies(
    source_gate: dict[str, str], base_domain: str
) -> list[dict[str, str]]:
    _ = base_domain
    document = fresh_dependency(
        c029_integration_evidence_path,
        source_gate=source_gate,
        kind="IntegrationCanaryEvidence",
        time_field="generatedAt",
        producer=root / "bin/server-integration-canaries.py",
    )
    rows = (
        document.get("canaries") if isinstance(document.get("canaries"), list) else []
    )
    matching = [
        row for row in rows if isinstance(row, dict) and row.get("id") == "C029"
    ]
    if document.get("selected") != ["C029"] or len(rows) != 1 or len(matching) != 1:
        raise AcceptanceError("ose_storage_persistence_dependency_missing")
    row = matching[0]
    dependency_evidence = (
        row.get("dependencyEvidence")
        if isinstance(row.get("dependencyEvidence"), dict)
        else {}
    )

    def sha256(value: Any) -> bool:
        return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))

    profile = str(row.get("dataContentProfile") or "")
    if profile == "postgres-notion":
        postgres = (
            row.get("postgresSsot") if isinstance(row.get("postgresSsot"), dict) else {}
        )
        notion = row.get("notion") if isinstance(row.get("notion"), dict) else {}
        table = notion.get("table") if isinstance(notion.get("table"), dict) else {}
        notion_document = (
            notion.get("document") if isinstance(notion.get("document"), dict) else {}
        )
        cleanup = row.get("cleanup") if isinstance(row.get("cleanup"), dict) else {}
        postgres_required = (
            "created",
            "readBackVerified",
            "updated",
            "projectionIntentVerified",
            "postDeleteAbsent",
            "cleanupVerified",
        )
        table_required = (
            "created",
            "queryVerified",
            "updated",
            "archived",
            "cleanupVerified",
            "linkageVerified",
        )
        document_required = (
            "created",
            "appendVerified",
            "readBackVerified",
            "archived",
            "cleanupVerified",
            "linkageVerified",
        )
        notion_producer = root / "bin/server-notion-sync.py"
        expected_canary_reference = {
            "path": str(notion_projection_canary_evidence_path),
            "sha256": sha256_file(notion_projection_canary_evidence_path),
            "kind": "NotionProjectionLiveCanary",
            "producerSha256": sha256_file(notion_producer),
        }
        expected_verification_reference = {
            "path": str(notion_consumer_verification_evidence_path),
            "sha256": sha256_file(notion_consumer_verification_evidence_path),
            "kind": "NotionProjectionConsumerVerification",
            "producerSha256": sha256_file(notion_producer),
        }
        consumer_evidence = (
            row.get("consumerVerificationEvidence")
            if isinstance(row.get("consumerVerificationEvidence"), dict)
            else {}
        )
        if not (
            row.get("ok") is True
            and row.get("state") == "passed"
            and row.get("source") == "server_notion_projection_consumer_canary"
            and row.get("roles")
            == {
                "tablesUi": "notion",
                "tablesApi": "notion",
                "documentsUi": "notion",
                "documentsApi": "notion",
            }
            and set(postgres) == {"record", "document"}
            and all(
                isinstance(item, dict)
                and sha256(item.get("objectIdSha256"))
                and sha256(item.get("initialContentSha256"))
                and sha256(item.get("finalContentSha256"))
                and item.get("initialRevision") == 1
                and item.get("finalRevision") == 2
                and all(item.get(key) is True for key in postgres_required)
                for item in postgres.values()
            )
            and sha256(table.get("pageIdSha256"))
            and all(table.get(key) is True for key in table_required)
            and sha256(notion_document.get("pageIdSha256"))
            and all(notion_document.get(key) is True for key in document_required)
            and all(
                cleanup.get(key) is True
                for key in (
                    "postgresRecordDeleted",
                    "postgresDocumentDeleted",
                    "postgresProjectionRowsDeleted",
                    "notionTableRowArchived",
                    "notionDocumentArchived",
                    "verified",
                )
            )
            and row.get("tablePersistenceVerified") is True
            and row.get("documentPersistenceVerified") is True
            and row.get("crossProviderLinkageVerified") is True
            and row.get("cleanupCompleted") is True
            and row.get("redacted") is True
            and dependency_evidence == expected_canary_reference
            and consumer_evidence == expected_verification_reference
        ):
            raise AcceptanceError("notion_projection_canary_dependency_invalid")

        notion_canary = fresh_component_dependency(
            notion_projection_canary_evidence_path,
            source_gate=source_gate,
            api_version="micro-task-engine/v1alpha1",
            kind="NotionProjectionLiveCanary",
            producer=notion_producer,
        )
        notion_verification = fresh_component_dependency(
            notion_consumer_verification_evidence_path,
            source_gate=source_gate,
            api_version="micro-task-engine/v1alpha1",
            kind="NotionProjectionConsumerVerification",
            producer=notion_producer,
        )
        canary_linkage = (
            notion_canary.get("linkage")
            if isinstance(notion_canary.get("linkage"), dict)
            else {}
        )
        canary_cleanup = (
            notion_canary.get("cleanup")
            if isinstance(notion_canary.get("cleanup"), dict)
            else {}
        )
        delivery = (
            notion_verification.get("delivery")
            if isinstance(notion_verification.get("delivery"), dict)
            else {}
        )
        systemd = (
            notion_verification.get("systemd")
            if isinstance(notion_verification.get("systemd"), dict)
            else {}
        )
        evidence_contracts = (
            notion_canary.get("evidence"),
            notion_verification.get("evidence"),
        )
        linkage_pairs = (
            ("entity", "record", table),
            ("document", "document", notion_document),
        )
        if not (
            notion_canary.get("dataContentProfile") == profile
            and notion_verification.get("dataContentProfile") == profile
            and notion_canary.get("provider") == "notion"
            and notion_verification.get("provider") == "notion"
            and notion_canary.get("redacted") is True
            and notion_verification.get("redacted") is True
            and evidence_contracts
            == (
                {
                    "path": str(notion_projection_canary_evidence_path),
                    "mode": "0600",
                },
                {
                    "path": str(notion_consumer_verification_evidence_path),
                    "mode": "0600",
                },
            )
            and set(canary_linkage) == {"entity", "document"}
            and all(
                isinstance(canary_linkage.get(canary_kind), dict)
                and canary_linkage[canary_kind].get("canonicalObjectIdSha256")
                == postgres[row_kind].get("objectIdSha256")
                and canary_linkage[canary_kind].get("providerObjectIdSha256")
                == projected.get("pageIdSha256")
                and all(
                    canary_linkage[canary_kind].get(key) == postgres[row_kind].get(key)
                    for key in (
                        "initialRevision",
                        "finalRevision",
                        "initialContentSha256",
                        "finalContentSha256",
                    )
                )
                for canary_kind, row_kind, projected in linkage_pairs
            )
            and canary_cleanup.get("verified") is True
            and all(
                delivery.get(key) == 0
                for key in (
                    "pending",
                    "processing",
                    "failed",
                    "eligible",
                    "exhausted",
                    "expiredLeases",
                )
            )
            and delivery.get("schemaReady") is True
            and systemd
            and all(value is True for value in systemd.values())
        ):
            raise AcceptanceError("notion_projection_consumer_evidence_invalid")
        return [
            {
                "path": str(c029_integration_evidence_path),
                "sha256": sha256_file(c029_integration_evidence_path),
                "kind": "IntegrationCanaryEvidence",
                "producerSha256": sha256_file(
                    root / "bin/server-integration-canaries.py"
                ),
            },
            expected_canary_reference,
            expected_verification_reference,
        ]

    raise AcceptanceError("data_content_profile_unsupported", profile)


def c046_datasource_dependency(source_gate: dict[str, str]) -> dict[str, str]:
    document = fresh_dependency(
        observability_evidence_path,
        source_gate=source_gate,
        kind="ObservabilityDataCanaryEvidence",
        time_field="completedAt",
        producer=root / "bin/server-observability-canary.py",
    )
    checks = document.get("checks") if isinstance(document.get("checks"), dict) else {}
    row = checks.get("C045") if isinstance(checks.get("C045"), dict) else {}
    health = row.get("health") if isinstance(row.get("health"), dict) else {}
    if not (
        row.get("status") == "pass"
        and set(health) == {"victoriametrics", "victorialogs", "victoriatraces"}
        and all(value == 200 for value in health.values())
        and isinstance(row.get("metricSeries"), int)
        and not isinstance(row.get("metricSeries"), bool)
        and row.get("metricSeries") > 0
        and row.get("logsFound") is True
        and row.get("traceFound") is True
    ):
        raise AcceptanceError("grafana_datasource_dependency_invalid")
    return {
        "path": str(observability_evidence_path),
        "sha256": sha256_file(observability_evidence_path),
    }


def write_semantic_evidence(
    source_gate: dict[str, str], producer_hash: str, rows: dict[str, dict[str, Any]]
) -> dict[str, str]:
    safe_rows: dict[str, dict[str, Any]] = {}
    connection_ids_to_write = [*human_connections, "C026"]
    if rows.get("C029", {}).get("cloudflareManaged") is True:
        connection_ids_to_write.append("C029")
    for connection_id in connection_ids_to_write:
        row = rows.get(connection_id)
        if not isinstance(row, dict) or row.get("ok") is not True:
            raise AcceptanceError("semantic_evidence_incomplete", connection_id)
        safe_rows[connection_id] = {
            key: value for key, value in row.items() if key != "dependencyEvidence"
        }
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "CloudflareApplicationSemanticEvidence",
        "status": "passed",
        "ok": True,
        "generatedAt": utcnow(),
        "canonicalSourceSha256": source_gate["sourceSha256"],
        "sourceGate": source_gate,
        "producerPath": str(Path(__file__).resolve()),
        "producerSha256": producer_hash,
        "configSha256": sha256_file(config_path),
        "manifestSha256": sha256_file(manifest_path),
        "fileSecurity": {
            "producer": file_security_contract(Path(__file__).resolve(), 0o700),
            "evidence": expected_file_security(semantic_evidence_path, 0o600),
        },
        "secretValuesPrinted": False,
        "connections": safe_rows,
    }
    atomic_json(semantic_evidence_path, payload)
    exact_mode(semantic_evidence_path, 0o600)
    return {
        "path": str(semantic_evidence_path),
        "sha256": sha256_file(semantic_evidence_path),
    }


def connection_evidence_path(connection_id: str) -> Path:
    if connection_id not in connection_evidence_ids:
        raise AcceptanceError(
            "split_connection_evidence_not_allowlisted", connection_id
        )
    return root / f"evidence/cloudflare-connection-{connection_id}.json"


def semantic_row_projection(row: dict[str, Any]) -> dict[str, Any]:
    """Strip only parent-artifact references before hashing the semantic subject."""
    return {
        key: value
        for key, value in row.items()
        if key not in {"dependencyEvidence", "connectionEvidence"}
    }


def write_connection_evidence(
    source_gate: dict[str, str],
    producer_hash: str,
    rows: dict[str, dict[str, Any]],
) -> dict[str, dict[str, str]]:
    """Emit one root-only, hash-bound attestation per audited edge connection."""
    references: dict[str, dict[str, str]] = {}
    producer = Path(__file__).resolve()
    producer_security = file_security_contract(producer, 0o700)
    for connection_id in connection_evidence_ids:
        row = rows.get(connection_id)
        if not isinstance(row, dict) or row.get("ok") is not True:
            raise AcceptanceError("split_connection_evidence_incomplete", connection_id)
        path = connection_evidence_path(connection_id)
        subject = semantic_row_projection(row)
        upstream = (
            row.get("dependencyEvidence")
            if isinstance(row.get("dependencyEvidence"), list)
            else []
        )
        payload = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "CloudflareConnectionEvidence",
            "status": "passed",
            "ok": True,
            "generatedAt": utcnow(),
            "freshnessMaxAgeSeconds": 600,
            "futureSkewSeconds": 30,
            "connectionId": connection_id,
            "canonicalSourceSha256": source_gate["sourceSha256"],
            "sourceGate": source_gate,
            "configSha256": sha256_file(config_path),
            "manifestSha256": sha256_file(manifest_path),
            "appsProjectionSha256": sha256_file(apps_path),
            "dataContentProjectionSha256": sha256_file(data_content_path),
            "producerPath": str(producer),
            "producerSha256": producer_hash,
            "fileSecurity": {
                "producer": producer_security,
                "evidence": expected_file_security(path, 0o600),
            },
            "secretValuesPrinted": False,
            "subjectSha256": canonical_json_sha256(subject),
            "connection": subject,
            "upstreamEvidenceSha256": canonical_json_sha256(upstream),
            "upstreamEvidence": upstream,
        }
        atomic_json(path, payload)
        exact_mode(path, 0o600)
        references[connection_id] = {
            "path": str(path),
            "sha256": sha256_file(path),
            "kind": "CloudflareConnectionEvidence",
            "producerSha256": producer_hash,
        }
    return references


def docker_run(
    args: list[str], *, timeout: int = 120, allow_failure: bool = False
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        args, text=True, capture_output=True, timeout=timeout, check=False
    )
    if completed.returncode and not allow_failure:
        raise AcceptanceError("command_failed", Path(args[0]).name)
    return completed


def firecrawl_row(values: dict[str, str], app: dict[str, str]) -> dict[str, Any]:
    if app.get("accessClass") != "service":
        raise AcceptanceError("firecrawl_access_class_invalid")
    require_values(
        values,
        "FIRECRAWL_API_KEY",
        "FIRECRAWL_HEALTH_URL",
    )
    route_token = service_route_credentials(values, "firecrawl")
    base = "https://" + app["hostname"]
    health = urllib.parse.urlsplit(values["FIRECRAWL_HEALTH_URL"])
    if not (
        health.scheme == "http"
        and health.hostname == "127.0.0.1"
        and health.port is not None
        and health.username is None
        and health.password is None
        and not health.query
        and not health.fragment
    ):
        raise AcceptanceError("firecrawl_health_url_invalid")
    health_path = health.path or "/"
    anonymous_status, _payload, _headers = request(
        "GET", base + health_path, allowed={401}, follow_redirects=False
    )
    service_headers = {
        "CF-Access-Client-Id": route_token["client_id"],
        "CF-Access-Client-Secret": route_token["client_secret"],
    }
    service_status, _payload, _headers = request(
        "GET", base + health_path, headers=service_headers, allowed={200}
    )
    scrape_headers = {
        **service_headers,
        "Authorization": "Bearer " + values["FIRECRAWL_API_KEY"],
    }
    scrape_status, scrape, _ = request(
        "POST",
        base + "/v1/scrape",
        headers=scrape_headers,
        body={
            "url": "https://example.com/",
            "formats": ["markdown"],
            "onlyMainContent": False,
            "maxAge": 0,
        },
        allowed={200},
        timeout=180,
    )
    data = scrape.get("data") if isinstance(scrape, dict) else None
    markdown = data.get("markdown") if isinstance(data, dict) else None
    metadata = data.get("metadata") if isinstance(data, dict) else None
    if not (
        scrape_status == 200
        and scrape.get("success") is True
        and isinstance(markdown, str)
        and "Example Domain" in markdown
        and isinstance(metadata, dict)
        and metadata.get("statusCode") == 200
    ):
        raise AcceptanceError("firecrawl_live_scrape_invalid")
    return {
        "id": "C026",
        "ok": True,
        "state": "passed",
        "canonicalHostname": app["hostname"],
        "expectedAccessClass": "service",
        "edgeGateVerified": True,
        "serviceSemanticVerified": True,
        "originAuthenticationRequired": True,
        "originAuthenticationVerified": True,
        "dependencyEvidence": [],
        "anonymousDenied": anonymous_status == 401,
        "anonymousStatus": anonymous_status,
        "serviceTokenStatus": service_status,
        "healthPath": health_path,
        "serviceTokenExpiryVerified": True,
        "serviceTokenCredentialsPresent": True,
        "serviceTokenCredentialValuesEmitted": False,
        "liveScrapeKnownDocumentObserved": True,
        "liveScrapeResultSha256": hashlib.sha256(markdown.encode()).hexdigest(),
        "liveScrapeMetadataStatus": 200,
        "liveScrapeCacheBypassed": True,
    }


def socket_observation(host: str, timeout: float) -> dict[str, Any]:
    parsed = host.rsplit("@", 1)[-1].strip()
    if not parsed or parsed in {"localhost", "127.0.0.1", "::1"}:
        raise AcceptanceError("observer_target_invalid")
    ports: dict[str, dict[str, Any]] = {}
    for port in (external_ssh_port, *external_blocked_tcp_ports):
        started = time.monotonic()
        try:
            connection = socket.create_connection((parsed, port), timeout=timeout)
        except OSError as exc:
            ports[str(port)] = {
                "open": False,
                "failureType": type(exc).__name__,
                "elapsedMs": round((time.monotonic() - started) * 1000, 3),
            }
        else:
            connection.close()
            ports[str(port)] = {
                "open": True,
                "elapsedMs": round((time.monotonic() - started) * 1000, 3),
            }
    return {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "CloudflareExternalPortObservation",
        "generatedAt": utcnow(),
        "freshnessMaxAgeSeconds": 300,
        "futureSkewSeconds": 30,
        "targetHost": parsed,
        "producerSha256": sha256_file(Path(__file__).resolve()),
        "ports": ports,
        "ok": (
            ports[str(external_ssh_port)]["open"] is True
            and all(
                ports[str(port)]["open"] is False for port in external_blocked_tcp_ports
            )
        ),
    }


def resolved_addresses(host: str) -> set[str]:
    try:
        return {
            str(row[4][0]).split("%", 1)[0]
            for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            if row[4] and row[4][0]
        }
    except socket.gaierror as exc:
        raise AcceptanceError("host_identity_resolution_failed", host) from exc


def current_host_identity(expected: str, excluded: set[str]) -> dict[str, Any]:
    completed = docker_run(
        ["ip", "-o", "addr", "show", "scope", "global"], allow_failure=True
    )
    if completed.returncode != 0:
        raise AcceptanceError("host_identity_inventory_failed")
    observed = {
        match.group(1).split("/", 1)[0].split("%", 1)[0]
        for match in re.finditer(r"\sinet6?\s+([^\s]+)", completed.stdout)
    }
    expected_addresses = resolved_addresses(expected)
    excluded_addresses = (
        set().union(*(resolved_addresses(host) for host in excluded))
        if excluded
        else set()
    )
    if not observed or not (observed & expected_addresses):
        raise AcceptanceError("executing_host_target_mismatch")
    if observed & excluded_addresses:
        raise AcceptanceError("executing_host_is_excluded")
    return {
        "localAddressCount": len(observed),
        "expectedAddressMatched": True,
        "excludedAddressMatched": False,
    }


def validate_observation(
    path: Path, values: dict[str, str], producer_hash: str
) -> dict[str, Any]:
    exact_mode(path, 0o600)
    payload = load_json(path)
    expected = values.get("MTE_SSH_TARGET", "").rsplit("@", 1)[-1]
    excluded = {
        values.get("MTE_EXCLUDED_HOST_1", ""),
        values.get("MTE_EXCLUDED_HOST_2", ""),
    } - {""}
    if len(excluded) != 2 or expected in excluded:
        raise AcceptanceError("excluded_target_contract_invalid")
    identity = current_host_identity(expected, excluded)
    moment = parse_iso(payload.get("generatedAt"))
    age = (datetime.now(timezone.utc) - moment).total_seconds()
    ports = payload.get("ports")
    if not (
        payload.get("apiVersion") == "micro-task-engine/v1alpha1"
        and payload.get("kind") == "CloudflareExternalPortObservation"
        and payload.get("producerSha256") == producer_hash
        and payload.get("freshnessMaxAgeSeconds") == 300
        and payload.get("futureSkewSeconds") == 30
        and payload.get("targetHost") == expected
        and expected not in excluded
        and -30 <= age <= 300
        and isinstance(ports, dict)
        and set(ports)
        == {str(external_ssh_port), *(str(port) for port in external_blocked_tcp_ports)}
        and ports[str(external_ssh_port)].get("open") is True
        and all(
            ports[str(port)].get("open") is False for port in external_blocked_tcp_ports
        )
        and payload.get("ok") is True
    ):
        raise AcceptanceError("external_port_observation_invalid")
    return {
        "expectedHost": expected,
        "excludedHosts": sorted(excluded),
        "sshReachable": True,
        "externalPortsBlocked": {
            str(port): True for port in external_blocked_tcp_ports
        },
        "evidenceSha256": sha256_file(path),
        "ageSeconds": round(age, 3),
        **identity,
    }


def firewall_status() -> dict[str, Any]:
    """Validate the v2 origin-firewall producer rather than stale rule shapes."""
    if (
        not origin_firewall_step_path.is_file()
        or origin_firewall_step_path.is_symlink()
    ):
        raise AcceptanceError("origin_firewall_producer_missing")
    exact_mode(origin_firewall_step_path, 0o700)
    completed = docker_run(
        [str(origin_firewall_step_path), "status"], allow_failure=True
    )
    if completed.returncode != 0:
        raise AcceptanceError("origin_firewall_contract_failed")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AcceptanceError("origin_firewall_status_invalid") from exc
    if not isinstance(payload, dict) or set(payload) != origin_firewall_status_fields:
        raise AcceptanceError("origin_firewall_status_invalid")
    counts = (
        payload.get("firewallSshCidrCount"),
        payload.get("firewallSshIpv4CidrCount"),
        payload.get("firewallSshIpv6CidrCount"),
    )
    fingerprint = payload.get("operatorSshCidrsSha256")
    interfaces = (
        payload.get("publicInterface"),
        payload.get("publicInterfaceV4"),
        payload.get("publicInterfaceV6"),
    )
    if not (
        payload.get("firewallPolicyVersion") == "mte-origin-firewall/v2"
        and all(payload.get(field) is True for field in origin_firewall_true_fields)
        and all(isinstance(value, str) and value for value in interfaces)
        and isinstance(fingerprint, str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", fingerprint))
        and all(
            isinstance(value, int) and not isinstance(value, bool) for value in counts
        )
        and counts[0] >= 1
        and counts[0] == counts[1] + counts[2]
    ):
        raise AcceptanceError("origin_firewall_contract_failed")
    return payload


def cloudflared_status(values: dict[str, str]) -> dict[str, Any]:
    """Prove the live connector matches the canonical runtime contract."""
    require_values(values, "CLOUDFLARED_CONTAINER_NAME")
    name = values["CLOUDFLARED_CONTAINER_NAME"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
        raise AcceptanceError("cloudflared_container_name_invalid")
    if not cloudflared_step_path.is_file() or cloudflared_step_path.is_symlink():
        raise AcceptanceError("cloudflared_runtime_producer_missing")
    exact_mode(cloudflared_step_path, 0o700)
    verified = docker_run([str(cloudflared_step_path), "verify"], allow_failure=True)
    if verified.returncode != 0:
        raise AcceptanceError("cloudflared_runtime_contract_failed")
    state = docker_run(["docker", "inspect", "--format", "{{json .State}}", name])
    restarts = docker_run(["docker", "inspect", "--format", "{{.RestartCount}}", name])
    try:
        payload = json.loads(state.stdout)
        restart_count = int(restarts.stdout.strip())
    except (json.JSONDecodeError, ValueError) as exc:
        raise AcceptanceError("cloudflared_state_invalid") from exc
    if payload.get("Running") is not True or restart_count != 0:
        raise AcceptanceError("cloudflared_runtime_unhealthy")
    return {
        "cloudflaredRunning": True,
        "restartCount": restart_count,
        "cloudflaredRuntimeConfigVerified": True,
    }


def lock_image() -> str:
    try:
        document = yaml.safe_load(lock_path.read_text())
        image = document["spec"]["images"]["openTofu"]
    except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
        raise AcceptanceError("opentofu_lock_missing") from exc
    if not isinstance(image, str) or not re.fullmatch(
        r"[^\s]+@sha256:[0-9a-f]{64}", image
    ):
        raise AcceptanceError("opentofu_lock_invalid")
    return image


def plan_action_summary(document: dict[str, Any]) -> dict[str, int]:
    """Reject every apply mutation in the machine-readable saved plan."""
    counts = {
        "create": 0,
        "update": 0,
        "delete": 0,
        "forget": 0,
        "import": 0,
        "read": 0,
        "no-op": 0,
    }

    def rows(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, list):
            if any(not isinstance(row, dict) for row in value):
                raise AcceptanceError("opentofu_saved_plan_schema_invalid")
            return value
        if isinstance(value, dict):
            if any(not isinstance(row, dict) for row in value.values()):
                raise AcceptanceError("opentofu_saved_plan_schema_invalid")
            return list(value.values())
        raise AcceptanceError("opentofu_saved_plan_schema_invalid")

    for section in ("resource_changes", "resource_drift", "output_changes"):
        value = document.get(section, [] if section != "output_changes" else {})
        if not isinstance(value, (list, dict)):
            raise AcceptanceError("opentofu_saved_plan_schema_invalid", section)
        for row in rows(value):
            change = row.get("change")
            actions = change.get("actions") if isinstance(change, dict) else None
            if not (
                isinstance(actions, list)
                and actions
                and all(
                    isinstance(action, str) and action in counts for action in actions
                )
            ):
                raise AcceptanceError("opentofu_saved_plan_actions_invalid", section)
            for action in actions:
                counts[action] += 1
    if any(
        counts[action] for action in ("create", "update", "delete", "forget", "import")
    ):
        raise AcceptanceError("opentofu_saved_plan_not_empty")
    return counts


def saved_plan_metadata(
    document: dict[str, Any], action_counts: dict[str, int]
) -> dict[str, Any]:
    """Validate explicit metadata or OpenTofu's null empty-plan metadata."""
    applyable = document.get("applyable")
    complete = document.get("complete")
    errored = document.get("errored")
    if errored is not False:
        raise AcceptanceError("opentofu_saved_plan_metadata_invalid")
    if applyable is False and complete is True:
        mode = "explicit"
    elif applyable is None and complete is None:
        if (
            document.get("format_version"),
            document.get("terraform_version"),
        ) not in opentofu_null_metadata_contracts or any(
            section not in document
            for section in (
                "resource_changes",
                "resource_drift",
                "output_changes",
            )
        ):
            raise AcceptanceError("opentofu_saved_plan_metadata_invalid")
        if any(
            action_counts[action]
            for action in ("create", "update", "delete", "forget", "import")
        ):
            raise AcceptanceError("opentofu_saved_plan_not_empty")
        mode = "opentofu-null-empty"
    else:
        raise AcceptanceError("opentofu_saved_plan_metadata_invalid")
    return {
        "applyable": applyable,
        "complete": complete,
        "errored": False,
        "mode": mode,
    }


def tofu_status(values: dict[str, str]) -> dict[str, Any]:
    exact_mode(iac_root, 0o700)
    state = iac_root / "terraform.tfstate"
    tfvars = iac_root / "terraform.tfvars.json"
    exact_mode(state, 0o600)
    exact_mode(tfvars, 0o600)
    exact_mode(api_env_path, 0o600)
    require_values(values, "CLOUDFLARE_API_TOKEN")
    raw = tfvars.read_bytes()
    token = values["CLOUDFLARE_API_TOKEN"].encode()
    try:
        tfvars_payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AcceptanceError("cloudflare_tfvars_invalid") from exc

    def secret_key_present(value: Any) -> bool:
        if isinstance(value, dict):
            for key, nested in value.items():
                if re.search(
                    r"(?:api[_-]?token|secret|credential|password)", str(key), re.I
                ):
                    return True
                if secret_key_present(nested):
                    return True
        elif isinstance(value, list):
            return any(secret_key_present(row) for row in value)
        return False

    contains = bool(token and token in raw) or secret_key_present(tfvars_payload)
    if contains:
        raise AcceptanceError("cloudflare_tfvars_contains_secret")
    image = lock_image()
    started = time.time()
    temporary_plan = iac_root / (
        ".acceptance-empty-" + str(os.getpid()) + "-" + secrets.token_hex(8) + ".tfplan"
    )
    saved_plan = iac_root / "acceptance-empty.tfplan"
    command = [
        "docker",
        "run",
        "--rm",
        "--env-file",
        str(api_env_path),
        "-e",
        "TF_IN_AUTOMATION=1",
        "-v",
        str(iac_root) + ":/workspace",
        "-w",
        "/workspace",
        image,
        "plan",
        "-input=false",
        "-no-color",
        "-lock-timeout=60s",
        "-detailed-exitcode",
        "-out=/workspace/" + temporary_plan.name,
    ]
    try:
        completed = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AcceptanceError("opentofu_plan_unavailable", type(exc).__name__) from exc
    try:
        # Detailed exit 0 is the only accepted state. stdout/stderr are never
        # persisted because provider diagnostics may contain remote metadata.
        if completed.returncode != 0:
            raise AcceptanceError("opentofu_plan_not_empty", str(completed.returncode))
        if not temporary_plan.is_file() or temporary_plan.is_symlink():
            raise AcceptanceError("opentofu_saved_plan_missing")
        plan_stat = temporary_plan.stat()
        if (
            plan_stat.st_uid != os.geteuid()
            or plan_stat.st_gid != os.getegid()
            or plan_stat.st_mtime < started - 1
        ):
            raise AcceptanceError("opentofu_saved_plan_owner_or_freshness_invalid")
        temporary_plan.chmod(0o600)
        exact_mode(temporary_plan, 0o600)
        show = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-e",
                "TF_IN_AUTOMATION=1",
                "-v",
                str(iac_root) + ":/workspace",
                "-w",
                "/workspace",
                image,
                "show",
                "-json",
                "/workspace/" + temporary_plan.name,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
        if show.returncode != 0:
            raise AcceptanceError("opentofu_saved_plan_unreadable")
        try:
            plan_document = json.loads(show.stdout)
        except json.JSONDecodeError as exc:
            raise AcceptanceError("opentofu_saved_plan_json_invalid") from exc
        if not isinstance(plan_document, dict):
            raise AcceptanceError("opentofu_saved_plan_schema_invalid")
        plan_timestamp = parse_iso(plan_document.get("timestamp"))
        plan_age = (datetime.now(timezone.utc) - plan_timestamp).total_seconds()
        if not -30 <= plan_age <= 300:
            raise AcceptanceError("opentofu_saved_plan_metadata_invalid")
        action_counts = plan_action_summary(plan_document)
        metadata = saved_plan_metadata(plan_document, action_counts)
        os.replace(temporary_plan, saved_plan)
        saved_plan.chmod(0o600)
        exact_mode(saved_plan, 0o600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AcceptanceError(
            "opentofu_saved_plan_unavailable", type(exc).__name__
        ) from exc
    finally:
        if temporary_plan.exists():
            temporary_plan.unlink()
    return {
        "tofuDetailedExitCode": 0,
        "changes": {"create": 0, "update": 0, "delete": 0},
        "create": 0,
        "update": 0,
        "delete": 0,
        "iacDirMode": "0700",
        "stateMode": "0600",
        "savedPlanPath": str(saved_plan),
        "savedPlanSha256": sha256_file(saved_plan),
        "savedPlanGeneratedAt": datetime.fromtimestamp(
            saved_plan.stat().st_mtime, timezone.utc
        ).isoformat(timespec="microseconds"),
        "savedPlanAgeSeconds": round(time.time() - saved_plan.stat().st_mtime, 3),
        "savedPlanMode": "0600",
        "savedPlanOwner": "root:root",
        "savedPlanApplyable": metadata["applyable"],
        "savedPlanComplete": metadata["complete"],
        "savedPlanErrored": metadata["errored"],
        "savedPlanMetadataMode": metadata["mode"],
        "savedPlanActionCounts": action_counts,
        "tfvarsContainsApiToken": False,
    }


def failure_payload(
    code: str, detail: str, producer_hash: str | None = None
) -> dict[str, Any]:
    rows = {
        connection_id: {
            "id": connection_id,
            "ok": False,
            "state": "failed" if index == 0 else "not_run",
            **({"errorCode": code, "errorDetail": detail} if index == 0 else {}),
        }
        for index, connection_id in enumerate(connection_ids)
    }
    return {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "CloudflareAcceptanceEvidence",
        "status": "failed",
        "ok": False,
        "generatedAt": utcnow(),
        "producerPath": str(Path(__file__).resolve()),
        "producerSha256": producer_hash,
        "fileSecurity": {
            "producer": expected_file_security(Path(__file__).resolve(), 0o700),
            "evidence": expected_file_security(evidence_path, 0o600),
        },
        "secretValuesPrinted": False,
        "connections": rows,
    }


def run_acceptance(external_observation: Path) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise AcceptanceError("root_required")
    installed = Path(__file__).resolve()
    if installed != producer_path_expected:
        raise AcceptanceError("producer_path_invalid", str(installed))
    exact_mode(installed, 0o700)
    producer_hash = sha256_file(installed)
    source_gate, config, apps_projection = exact_hash_gate()
    values = read_env(canonical)
    require_values(values, "PLATFORM_BASE_DOMAIN", "MTE_SSH_TARGET")
    apps = app_rows(apps_projection, values, config)
    data_content = data_content_edge_contract(apps_projection, apps)
    connection_apps = human_connection_contract(data_content)
    inventory = cloudflare_inventory(values, apps)
    service_routes = service_edge_checks(values, apps, config)
    dns_reconcile = dns_reconcile_status(source_gate, apps, inventory["tunnelId"])
    if inventory["foreignRecordSetSha256"] != dns_reconcile["foreignRecordSetSha256"]:
        raise AcceptanceError("cloudflare_dns_foreign_inventory_drift")
    rows = human_rows(values, apps, connection_apps, data_content)
    firecrawl = apps.get("firecrawl")
    if not isinstance(firecrawl, dict):
        raise AcceptanceError("firecrawl_app_missing")
    rows["C026"] = firecrawl_row(values, firecrawl)
    rows["C026"]["serviceTokenPolicyScoped"] = inventory["serviceAccessTokenScoped"]
    semantic_dependency = write_semantic_evidence(source_gate, producer_hash, rows)
    rows["C046"]["dependencyEvidence"] = [semantic_dependency]
    if data_content["edgeManaged"] is True:
        rows["C029"]["dependencyEvidence"] = [semantic_dependency]
    storage_dependencies = c029_persistence_dependencies(
        source_gate, values["PLATFORM_BASE_DOMAIN"]
    )
    rows["C029"]["dependencyEvidence"].extend(storage_dependencies)
    c029_common = {
        "dataContentProfile": data_content["profile"],
        "dataContentProjectionSha256": data_content["projectionSha256"],
        "dataContentApplications": data_content["applicationIds"],
        "tablePersistenceVerified": True,
        "documentPersistenceVerified": True,
        "cleanupCompleted": True,
    }
    if data_content["edgeManaged"] is False:
        rows["C029"].update(
            {
                **c029_common,
                "serviceSemanticVerified": True,
                "originSemanticVerified": True,
                "originAuthenticationVerified": True,
                "notionProjectionConsumerVerified": True,
                "postgresSystemOfRecordVerified": True,
                "crossProviderLinkageVerified": True,
                "applicationRestartApplicable": False,
                "dataContentEvidence": {
                    "integrationCanary": storage_dependencies[0],
                    "notionProjectionCanary": storage_dependencies[1],
                    "notionConsumerVerification": storage_dependencies[2],
                },
            }
        )
    else:
        rows["C029"].update(
            {
                **c029_common,
                "dataContentEvidence": {
                    "tables": storage_dependencies[1],
                    "documents": storage_dependencies[2],
                },
                "osiLicensesVerified": True,
                "applicationRestartObserved": True,
            }
        )
    datasource_dependency = c046_datasource_dependency(source_gate)
    rows["C046"]["dependencyEvidence"].append(datasource_dependency)
    rows["C046"].update(
        {"dashboardProvisioned": True, "datasourceQueriesVerified": True}
    )
    external = validate_observation(external_observation, values, producer_hash)
    firewall = firewall_status()
    rows["C060"] = {
        "id": "C060",
        "ok": True,
        "state": "passed",
        "canonicalHostname": external["expectedHost"],
        "expectedAccessClass": "restricted",
        "edgeGateVerified": True,
        "serviceSemanticVerified": True,
        "dependencyEvidence": [
            {"path": str(external_observation), "sha256": external["evidenceSha256"]}
        ],
        "sshReachable": True,
        "expectedTarget": True,
        "excludedTargetsRejected": True,
        "externalPortsBlocked": external["externalPortsBlocked"],
        **firewall,
    }
    runtime = cloudflared_status(values)
    rows["C065"] = {
        "id": "C065",
        "ok": True,
        "state": "passed",
        "canonicalHostname": inventory["tunnelName"],
        "expectedAccessClass": "egress",
        "edgeGateVerified": True,
        "serviceSemanticVerified": True,
        "dependencyEvidence": [],
        "tunnelConnectorHealthy": inventory["tunnelHealthy"],
        "connectorCount": inventory["connectorCount"],
        **runtime,
    }
    rows["C066"] = {
        "id": "C066",
        "ok": True,
        "state": "passed",
        "canonicalHostname": values["PLATFORM_BASE_DOMAIN"],
        "expectedAccessClass": "edge",
        "edgeGateVerified": True,
        "serviceSemanticVerified": True,
        "dependencyEvidence": [dns_reconcile["dependencyEvidence"]],
        "exactManagedRoutes": len(inventory["routes"]),
        "exactDnsRecords": inventory["dnsRecordCount"],
        "exactAccessApplications": inventory["accessApplicationCount"],
        "exactAccessPolicies": inventory["accessPolicyCount"],
        "routeOriginsVerified": True,
        "accessClassesVerified": True,
        "humanAccessPolicyScoped": inventory["humanAccessPolicyScoped"],
        "serviceAccessTokenScoped": inventory["serviceAccessTokenScoped"],
        "serviceRouteChecks": service_routes,
        "serviceRouteCheckCount": len(service_routes),
        "crossRouteTokensDenied": all(
            row["crossTokenDenied"] for row in service_routes.values()
        ),
        "desiredHostnamesReserved": inventory["desiredHostnamesReserved"],
        "desiredRecordsExact": dns_reconcile["desiredRecordsExact"],
        "dnsTargetTunnelBound": inventory["dnsTargetTunnelBound"],
        "proxiedDnsOnly": inventory["proxiedDnsOnly"],
        "originAddressRecordCount": inventory["originAddressRecordCount"],
        "batchApplied": dns_reconcile["batchApplied"],
        "batchDatabaseTransactionAtomic": dns_reconcile[
            "batchDatabaseTransactionAtomic"
        ],
        "edgePropagationAtomic": dns_reconcile["edgePropagationAtomic"],
        "foreignDnsPreserved": dns_reconcile["foreignRecordsPreserved"],
        "foreignRecordCount": dns_reconcile["foreignRecordCount"],
        "foreignRecordSetSha256": inventory["foreignRecordSetSha256"],
    }
    tofu = tofu_status(values)
    rows["C067"] = {
        "id": "C067",
        "ok": True,
        "state": "passed",
        "canonicalHostname": "api.cloudflare.com",
        "expectedAccessClass": "egress",
        "edgeGateVerified": True,
        "serviceSemanticVerified": True,
        "dependencyEvidence": [],
        **tofu,
    }
    split_dependencies = write_connection_evidence(source_gate, producer_hash, rows)
    for connection_id in semantic_connection_ids:
        if connection_id == "C029" and data_content["edgeManaged"] is False:
            rows[connection_id]["connectionEvidence"] = split_dependencies[
                connection_id
            ]
            continue
        rows[connection_id]["dependencyEvidence"] = [split_dependencies[connection_id]]
    for connection_id in connection_evidence_ids:
        if connection_id not in semantic_connection_ids:
            rows[connection_id]["connectionEvidence"] = split_dependencies[
                connection_id
            ]
    if set(rows) != set(connection_ids) or any(
        row.get("ok") is not True for row in rows.values()
    ):
        raise AcceptanceError("connection_evidence_incomplete")
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "CloudflareAcceptanceEvidence",
        "status": "passed",
        "ok": True,
        "generatedAt": utcnow(),
        "freshnessMaxAgeSeconds": 600,
        "futureSkewSeconds": 30,
        "canonicalSourceSha256": source_gate["sourceSha256"],
        "sourceGate": source_gate,
        "configSha256": sha256_file(config_path),
        "manifestSha256": sha256_file(manifest_path),
        "appsProjectionSha256": sha256_file(apps_path),
        "dataContentProjectionSha256": sha256_file(data_content_path),
        "producerPath": str(installed),
        "producerSha256": producer_hash,
        "fileSecurity": {
            "producer": file_security_contract(installed, 0o700),
            "evidence": expected_file_security(evidence_path, 0o600),
        },
        "secretValuesPrinted": False,
        "configKind": config.get("kind"),
        "connectionEvidence": {
            connection_id: split_dependencies[connection_id]
            for connection_id in connection_evidence_ids
        },
        "connections": {key: rows[key] for key in connection_ids},
    }
    atomic_json(evidence_path, payload)
    exact_mode(evidence_path, 0o600)
    return payload


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    actions = result.add_subparsers(dest="action", required=True)
    observe = actions.add_parser("observe")
    observe.add_argument("--host", required=True)
    observe.add_argument("--output", type=Path, required=True)
    observe.add_argument("--timeout", type=float, default=4.0)
    run_action = actions.add_parser("run")
    run_action.add_argument("--external-observation", type=Path, default=observer_path)
    return result


def main() -> int:
    args = parser().parse_args()
    if args.action == "observe":
        try:
            payload = socket_observation(args.host, args.timeout)
            atomic_json(args.output.expanduser().resolve(), payload)
        except AcceptanceError as exc:
            payload = {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "CloudflareExternalPortObservation",
                "generatedAt": utcnow(),
                "ok": False,
                "errorCode": exc.code,
            }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if payload.get("ok") else 1
    producer_hash = None
    try:
        producer_hash = sha256_file(Path(__file__).resolve())
        payload = run_acceptance(args.external_observation.expanduser().resolve())
    except AcceptanceError as exc:
        payload = failure_payload(exc.code, exc.detail, producer_hash)
        if os.geteuid() == 0:
            atomic_json(evidence_path, payload)
            exact_mode(evidence_path, 0o600)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

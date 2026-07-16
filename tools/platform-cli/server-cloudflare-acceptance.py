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
c029_integration_evidence_path = root / "evidence/integration-canary-C029.json"
observability_evidence_path = root / "evidence/observability-data-canary.json"
baserow_evidence_path = root / "evidence/baserow-verify.json"
wikijs_evidence_path = root / "evidence/wikijs-verify.json"
postgrest_evidence_path = root / "evidence/postgrest-verify.json"
nocodb_evidence_path = root / "evidence/nocodb-verify.json"
notion_evidence_path = root / "evidence/notion-connector-verify.json"
producer_path_expected = root / "bin/server-cloudflare-acceptance.py"
generator_contract = "mte-config-renderer/v1"
protected_foreign_labels = ("paperclip", "chat")
semantic_connection_ids = ("C004", "C005", "C020", "C025", "C026", "C032")
connection_evidence_ids = (
    "C004",
    "C005",
    "C020",
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
    "C020",
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
    "C020": "activepieces",
    "C025": "searxng",
    "C032": "mattermost",
    "C046": "observability",
}


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


def cloudflare_inventory(
    values: dict[str, str], apps: dict[str, dict[str, str]]
) -> dict[str, Any]:
    require_values(
        values,
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_ACCOUNT_ID",
        "CLOUDFLARE_ZONE_ID",
        "CLOUDFLARE_TUNNEL_NAME",
        "CLOUDFLARE_ACCESS_ALLOWED_EMAILS",
        "CLOUDFLARE_ACCESS_SERVICE_TOKEN_ID",
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
    expected_human_emails = sorted(
        value.strip().lower()
        for value in values["CLOUDFLARE_ACCESS_ALLOWED_EMAILS"].split(",")
        if value.strip()
    )
    if (
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
            and str(record.get("comment", "")).startswith(
                "Managed by MTE platform IaC for "
            )
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
            policy_valid = policy.get("decision") == "non_identity" and include == [
                {
                    "service_token": {
                        "token_id": values["CLOUDFLARE_ACCESS_SERVICE_TOKEN_ID"]
                    }
                }
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

    base_domain = values["PLATFORM_BASE_DOMAIN"].strip().lower().rstrip(".")
    foreign: list[dict[str, Any]] = []
    for label in protected_foreign_labels:
        hostname = label + "." + base_domain
        row = one(
            [
                item
                for item in dns
                if str(item.get("name", "")).lower().rstrip(".") == hostname
            ],
            "protected_foreign_dns_missing",
        )
        if str(row.get("content", "")).lower().rstrip(".") == expected_target or str(
            row.get("comment", "")
        ).startswith("Managed by MTE platform IaC for "):
            raise AcceptanceError("protected_foreign_dns_taken_over", label)
        foreign.append(
            {
                "hostname": hostname,
                "recordType": str(row.get("type", "")),
                "recordFingerprint": hashlib.sha256(
                    (
                        str(row.get("type", "")) + "\0" + str(row.get("content", ""))
                    ).encode()
                ).hexdigest(),
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
        "routes": expected_routes,
        "foreign": foreign,
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


def semantic_activepieces(values: dict[str, str], origin: str) -> dict[str, Any]:
    require_values(
        values,
        "ACTIVEPIECES_ADMIN_EMAIL",
        "ACTIVEPIECES_ADMIN_PASSWORD",
        "ACTIVEPIECES_PROJECT_ID",
    )
    status_code, payload, _ = request(
        "POST",
        origin + "/api/v1/authentication/sign-in",
        body={
            "email": values["ACTIVEPIECES_ADMIN_EMAIL"],
            "password": values["ACTIVEPIECES_ADMIN_PASSWORD"],
        },
    )
    if not (
        status_code == 200
        and isinstance(payload, dict)
        and payload.get("projectId") == values["ACTIVEPIECES_PROJECT_ID"]
        and isinstance(payload.get("token"), str)
        and payload.get("token")
    ):
        raise AcceptanceError("activepieces_authenticated_project_invalid")
    return {
        "semantic": "authenticated-project-session",
        "projectIdentityVerified": True,
        "originAuthenticationRequired": True,
        "originAuthenticationVerified": True,
    }


def semantic_searxng(_values: dict[str, str], origin: str) -> dict[str, Any]:
    query = urllib.parse.urlencode({"q": "OpenAI", "format": "json"})
    status_code, payload, _ = request("GET", origin + "/search?" + query, timeout=60)
    results = payload.get("results") if isinstance(payload, dict) else None
    if status_code != 200 or not isinstance(results, list) or not results:
        raise AcceptanceError("searxng_live_search_empty")
    return {
        "semantic": "live-json-search",
        "resultCount": len(results),
        "originAuthenticationRequired": False,
        "originAuthenticationVerified": True,
    }


def semantic_baserow(values: dict[str, str], origin: str) -> dict[str, Any]:
    require_values(values, "BASEROW_PAPERCLIP_TOKEN", "BASEROW_TABLE_ID")
    query = urllib.parse.urlencode({"user_field_names": "true", "size": "1"})
    status_code, payload, _ = request(
        "GET",
        origin
        + "/api/database/rows/table/"
        + urllib.parse.quote(values["BASEROW_TABLE_ID"])
        + "/?"
        + query,
        headers={"Authorization": "Token " + values["BASEROW_PAPERCLIP_TOKEN"]},
    )
    if not (
        status_code == 200
        and isinstance(payload, dict)
        and isinstance(payload.get("count"), int)
        and not isinstance(payload.get("count"), bool)
        and isinstance(payload.get("results"), list)
    ):
        raise AcceptanceError("baserow_authenticated_table_read_invalid")
    return {
        "semantic": "authenticated-baserow-table-read",
        "rowCount": payload["count"],
        "originAuthenticationRequired": True,
        "originAuthenticationVerified": True,
    }


def semantic_wikijs(values: dict[str, str], origin: str) -> dict[str, Any]:
    require_values(values, "WIKIJS_API_TOKEN")
    status_code, payload, _ = request(
        "POST",
        origin + "/graphql",
        headers={"Authorization": "Bearer " + values["WIKIJS_API_TOKEN"]},
        body={
            "query": (
                "query MteSystemInfo { system { info { currentVersion dbType dbHost } } }"
            )
        },
    )
    info = (
        payload.get("data", {}).get("system", {}).get("info")
        if isinstance(payload, dict)
        and isinstance(payload.get("data"), dict)
        and isinstance(payload["data"].get("system"), dict)
        else None
    )
    if not (
        status_code == 200
        and isinstance(info, dict)
        and info.get("currentVersion") == "2.5.314"
        and info.get("dbType") == "postgres"
        and info.get("dbHost") == "mte-postgres"
        and not payload.get("errors")
    ):
        raise AcceptanceError("wikijs_authenticated_system_info_invalid")
    return {
        "semantic": "authenticated-wikijs-system-info",
        "version": "2.5.314",
        "databaseType": "postgres",
        "originAuthenticationRequired": True,
        "originAuthenticationVerified": True,
    }


def semantic_nocodb(values: dict[str, str], origin: str) -> dict[str, Any]:
    require_values(values, "NOCODB_ADMIN_EMAIL", "NOCODB_ADMIN_PASSWORD")
    status, signed_in, _headers = request(
        "POST",
        origin + "/api/v1/auth/user/signin",
        body={
            "email": values["NOCODB_ADMIN_EMAIL"],
            "password": values["NOCODB_ADMIN_PASSWORD"],
        },
    )
    token = str((signed_in or {}).get("token") or "")
    if status != 200 or not token:
        raise AcceptanceError("nocodb_admin_auth_invalid")
    authenticated_status, bases, _headers = request(
        "GET",
        origin + "/api/v2/meta/bases",
        headers={"xc-auth": token},
    )
    denied_status, _denied, _headers = request(
        "GET",
        origin + "/api/v2/meta/bases",
        headers={"xc-auth": "invalid"},
        allowed={401, 403},
    )
    if authenticated_status != 200 or not isinstance(bases, (dict, list)):
        raise AcceptanceError("nocodb_authenticated_bases_read_invalid")
    return {
        "semantic": "authenticated-nocodb-base-read",
        "originAuthenticationRequired": True,
        "originAuthenticationVerified": denied_status in {401, 403},
        "authenticatedStatus": authenticated_status,
    }


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
    "activepieces": semantic_activepieces,
    "searxng": semantic_searxng,
    "baserow": semantic_baserow,
    "wikijs": semantic_wikijs,
    "nocodb": semantic_nocodb,
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
    component_api_prefix = "mte." + base_domain.strip().lower().rstrip(".")
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
    baserow = (
        row.get("baserowPersistence")
        if isinstance(row.get("baserowPersistence"), dict)
        else {}
    )
    wikijs = (
        row.get("wikijsPersistence")
        if isinstance(row.get("wikijsPersistence"), dict)
        else {}
    )
    licenses = (
        row.get("osiLicenses") if isinstance(row.get("osiLicenses"), list) else []
    )
    dependency_evidence = (
        row.get("dependencyEvidence")
        if isinstance(row.get("dependencyEvidence"), dict)
        else {}
    )

    def sha256(value: Any) -> bool:
        return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))

    def old_storage_key_present(value: Any) -> bool:
        if isinstance(value, dict):
            return any(
                re.search(r"noco(?:db|docs)", str(key), re.I)
                or old_storage_key_present(nested)
                for key, nested in value.items()
            )
        if isinstance(value, list):
            return any(old_storage_key_present(nested) for nested in value)
        return False

    def numeric_identifier(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value > 0

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
        notion_producer = root / "bin/server-notion.py"
        if not (
            row.get("ok") is True
            and row.get("state") == "passed"
            and row.get("source") == "server_notion_connector_canary"
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
            and dependency_evidence
            == {
                "path": str(notion_evidence_path),
                "sha256": sha256_file(notion_evidence_path),
                "kind": "NotionConnectorVerification",
                "producerSha256": sha256_file(notion_producer),
            }
        ):
            raise AcceptanceError("notion_connector_canary_dependency_invalid")

        notion_verification = fresh_component_dependency(
            notion_evidence_path,
            source_gate=source_gate,
            api_version="micro-task-engine/v1alpha1",
            kind="NotionConnectorVerification",
            producer=notion_producer,
        )
        identity = (
            notion_verification.get("identity")
            if isinstance(notion_verification.get("identity"), dict)
            else {}
        )
        canary = (
            notion_verification.get("canary")
            if isinstance(notion_verification.get("canary"), dict)
            else {}
        )
        verified_notion = (
            canary.get("notion") if isinstance(canary.get("notion"), dict) else {}
        )
        verified_table = (
            verified_notion.get("table")
            if isinstance(verified_notion.get("table"), dict)
            else {}
        )
        verified_document = (
            verified_notion.get("document")
            if isinstance(verified_notion.get("document"), dict)
            else {}
        )
        verified_cleanup = (
            notion_verification.get("cleanup")
            if isinstance(notion_verification.get("cleanup"), dict)
            else {}
        )
        secret_audit = (
            notion_verification.get("secretAudit")
            if isinstance(notion_verification.get("secretAudit"), dict)
            else {}
        )
        resources = (
            notion_verification.get("resources")
            if isinstance(notion_verification.get("resources"), dict)
            else {}
        )
        schema = (
            notion_verification.get("schema")
            if isinstance(notion_verification.get("schema"), dict)
            else {}
        )
        canary_linkage = (
            canary.get("linkage") if isinstance(canary.get("linkage"), dict) else {}
        )
        if not (
            notion_verification.get("dataContentProfile") == profile
            and notion_verification.get("notionApiVersion") == "2025-09-03"
            and isinstance(identity.get("botId"), str)
            and bool(identity.get("botId"))
            and isinstance(identity.get("workspaceId"), str)
            and bool(identity.get("workspaceId"))
            and identity.get("botExact") is True
            and identity.get("workspaceExact") is True
            and set(resources) == {"root", "documents", "database", "dataSource"}
            and all(
                isinstance(resource, dict) and resource.get("exact") is True
                for resource in resources.values()
            )
            and schema.get("exact") is True
            and isinstance(schema.get("properties"), dict)
            and bool(schema.get("properties"))
            and canary.get("kind") == "NotionConnectorCanary"
            and canary.get("status") == "passed"
            and canary.get("ok") is True
            and canary.get("dataContentProfile") == profile
            and canary.get("canonicalSourceSha256") == source_gate["sourceSha256"]
            and canary.get("producerSha256") == sha256_file(notion_producer)
            and canary.get("redacted") is True
            and set(canary_linkage) == {"record", "document"}
            and all(
                isinstance(canary_linkage.get(kind), dict)
                and all(
                    canary_linkage[kind].get(key) == postgres[kind].get(key)
                    for key in (
                        "objectIdSha256",
                        "initialRevision",
                        "finalRevision",
                        "initialContentSha256",
                        "finalContentSha256",
                    )
                )
                for kind in ("record", "document")
            )
            and isinstance(verified_table.get("pageId"), str)
            and sha256(table.get("pageIdSha256"))
            and hashlib.sha256(verified_table["pageId"].encode()).hexdigest()
            == table.get("pageIdSha256")
            and isinstance(verified_document.get("pageId"), str)
            and sha256(notion_document.get("pageIdSha256"))
            and hashlib.sha256(verified_document["pageId"].encode()).hexdigest()
            == notion_document.get("pageIdSha256")
            and all(verified_table.get(key) is True for key in table_required[:-1])
            and all(
                verified_document.get(key) is True for key in document_required[:-1]
            )
            and verified_cleanup.get("verified") is True
            and notion_verification.get("redacted") is True
            and secret_audit.get("tokenPresent") is False
            and secret_audit.get("rawMarkerPresent") is False
        ):
            raise AcceptanceError("notion_connector_verification_invalid")
        return [
            {
                "path": str(c029_integration_evidence_path),
                "sha256": sha256_file(c029_integration_evidence_path),
                "kind": "IntegrationCanaryEvidence",
                "producerSha256": sha256_file(
                    root / "bin/server-integration-canaries.py"
                ),
            },
            {
                "path": str(notion_evidence_path),
                "sha256": sha256_file(notion_evidence_path),
                "kind": "NotionConnectorVerification",
                "producerSha256": sha256_file(notion_producer),
            },
        ]

    if profile == "postgres-postgrest-nocodb-nocodocs":
        tables = (
            row.get("tablesPersistence")
            if isinstance(row.get("tablesPersistence"), dict)
            else {}
        )
        documents = (
            row.get("documentsPersistence")
            if isinstance(row.get("documentsPersistence"), dict)
            else {}
        )
        if not (
            row.get("ok") is True
            and row.get("state") == "passed"
            and row.get("source") == "controlled_data_content_application_restarts"
            and row.get("roles")
            == {
                "tablesUi": "nocodb",
                "tablesApi": "postgrest",
                "documentsUi": "nocodb",
                "documentsApi": "nocodb",
            }
            and all(
                item.get("restartObserved") is True
                and item.get("persistenceVerified") is True
                and item.get("postDeleteAbsent") is True
                and item.get("cleanupCompleted") is True
                and sha256(item.get("markerSha256"))
                for item in (tables, documents)
            )
            and tables.get("nocodbVisibilityVerified") is True
            and tables.get("singlePostgresStateVerified") is True
            and documents.get("endpoint") == "/api/v3/docs"
            and documents.get("requiredPlan")
            == "licensed-self-hosted-business-or-higher"
            and row.get("applicationRestartObserved") is True
            and row.get("tablePersistenceVerified") is True
            and row.get("documentPersistenceVerified") is True
            and row.get("cleanupCompleted") is True
        ):
            raise AcceptanceError("data_content_persistence_dependency_invalid")

        postgrest_document = fresh_component_dependency(
            postgrest_evidence_path,
            source_gate=source_gate,
            api_version="micro-task-engine/v1alpha1",
            kind="PostgrestVerification",
            producer=root / "bin/server-postgrest.py",
        )
        nocodb_document = fresh_component_dependency(
            nocodb_evidence_path,
            source_gate=source_gate,
            api_version="micro-task-engine/v1alpha1",
            kind="NocoDbNocoDocsVerification",
            producer=root / "bin/server-nocodb.py",
        )
        if not (
            postgrest_document.get("profile") == profile
            and postgrest_document.get("persistence")
            and all(
                postgrest_document["persistence"].get(key) is True
                for key in (
                    "restartObserved",
                    "persistenceVerified",
                    "postDeleteAbsent",
                    "cleanupCompleted",
                )
            )
            and nocodb_document.get("profile") == profile
            and nocodb_document.get("dataState", {}).get("owner")
            == "postgres-postgrest"
            and nocodb_document.get("dataState", {}).get("nocodbUniqueTableState")
            is False
            and nocodb_document.get("documentsApi", {}).get("endpoint")
            == "/api/v3/docs"
            and nocodb_document.get("documentsApi", {}).get("requiredPlan")
            == "licensed-self-hosted-business-or-higher"
            and nocodb_document.get("release", {}).get("license")
            == "LicenseRef-NocoDB-Sustainable-Use-1.0"
            and nocodb_document.get("release", {}).get("exception", {}).get("approval")
            == "user-approved-2026-07-15"
        ):
            raise AcceptanceError("data_content_component_dependency_invalid")
        expected_refs = {
            "postgrest": {
                "path": str(postgrest_evidence_path),
                "sha256": sha256_file(postgrest_evidence_path),
                "kind": "PostgrestVerification",
                "producerSha256": sha256_file(root / "bin/server-postgrest.py"),
            },
            "nocodb": {
                "path": str(nocodb_evidence_path),
                "sha256": sha256_file(nocodb_evidence_path),
                "kind": "NocoDbNocoDocsVerification",
                "producerSha256": sha256_file(root / "bin/server-nocodb.py"),
            },
        }
        if dependency_evidence != expected_refs:
            raise AcceptanceError("data_content_dependency_reference_invalid")
        return [
            {
                "path": str(c029_integration_evidence_path),
                "sha256": sha256_file(c029_integration_evidence_path),
            },
            {
                "path": str(postgrest_evidence_path),
                "sha256": sha256_file(postgrest_evidence_path),
            },
            {
                "path": str(nocodb_evidence_path),
                "sha256": sha256_file(nocodb_evidence_path),
            },
        ]

    expected_row_keys = {
        "id",
        "ok",
        "state",
        "source",
        "dataContentProfile",
        "roles",
        "tablesPersistence",
        "documentsPersistence",
        "baserowPersistence",
        "wikijsPersistence",
        "osiLicenses",
        "applicationRestartObserved",
        "tablePersistenceVerified",
        "documentPersistenceVerified",
        "cleanupCompleted",
        "dependencyEvidence",
    }
    if not (
        set(row) == expected_row_keys
        and row.get("ok") is True
        and row.get("state") == "passed"
        and row.get("source") == "controlled_ose_application_restarts"
        and row.get("dataContentProfile") == "baserow-wikijs"
        and row.get("roles")
        == {
            "tablesUi": "baserow",
            "tablesApi": "baserow",
            "documentsUi": "wikijs",
            "documentsApi": "wikijs",
        }
        and not old_storage_key_present(row)
        and set(baserow)
        == {
            "databaseId",
            "tableId",
            "rowId",
            "markerSha256",
            "restartObserved",
            "persistenceVerified",
            "postDeleteStatus",
            "cleanupCompleted",
        }
        and all(
            numeric_identifier(baserow.get(key))
            for key in ("databaseId", "tableId", "rowId")
        )
        and sha256(baserow.get("markerSha256"))
        and baserow.get("restartObserved") is True
        and baserow.get("persistenceVerified") is True
        and baserow.get("postDeleteStatus") == 404
        and baserow.get("cleanupCompleted") is True
        and set(wikijs)
        == {
            "pageId",
            "pathHashSha256",
            "markerSha256",
            "restartObserved",
            "persistenceVerified",
            "postDeleteStatus",
            "cleanupCompleted",
        }
        and numeric_identifier(wikijs.get("pageId"))
        and sha256(wikijs.get("pathHashSha256"))
        and sha256(wikijs.get("markerSha256"))
        and wikijs.get("restartObserved") is True
        and wikijs.get("persistenceVerified") is True
        and wikijs.get("postDeleteStatus") == 404
        and wikijs.get("cleanupCompleted") is True
        and licenses
        == [
            {
                "component": "baserow",
                "version": "2.3.1",
                "spdx": "MIT",
                "imageDigest": "sha256:496889c4fe22ee6b632698c3c74f7ccaee734c8002b5ebc8d194c5fcacffc98a",
                "verified": True,
            },
            {
                "component": "wikijs",
                "version": "2.5.314",
                "spdx": "AGPL-3.0-only",
                "imageDigest": "sha256:68f0d1848261ae76492ba358e30a96a76fed5d97a3fff381656082bf90f70d7e",
                "verified": True,
            },
        ]
        and row.get("tablePersistenceVerified") is True
        and row.get("documentPersistenceVerified") is True
        and row.get("applicationRestartObserved") is True
        and row.get("cleanupCompleted") is True
    ):
        raise AcceptanceError("ose_storage_persistence_dependency_invalid")

    baserow_document = fresh_component_dependency(
        baserow_evidence_path,
        source_gate=source_gate,
        api_version=component_api_prefix + "/v1",
        kind="BaserowAcceptance",
        producer=root / "bin/server-baserow.py",
    )
    distribution = (
        baserow_document.get("distribution")
        if isinstance(baserow_document.get("distribution"), dict)
        else {}
    )
    rest_api = (
        baserow_document.get("restApi")
        if isinstance(baserow_document.get("restApi"), dict)
        else {}
    )
    mcp = (
        baserow_document.get("mcp")
        if isinstance(baserow_document.get("mcp"), dict)
        else {}
    )
    baserow_component_persistence = (
        baserow_document.get("baserowPersistence")
        if isinstance(baserow_document.get("baserowPersistence"), dict)
        else {}
    )
    if not (
        distribution.get("name") == "Baserow OSE"
        and distribution.get("version") == "2.3.1"
        and distribution.get("image")
        == "baserow/baserow:2.3.1@sha256:496889c4fe22ee6b632698c3c74f7ccaee734c8002b5ebc8d194c5fcacffc98a"
        and distribution.get("platformDigest")
        == "sha256:16d9dd21b3f282c9300d876da66c8036e217143cae0af8f1dd2da5b45af0e30b"
        and distribution.get("license") == "MIT"
        and distribution.get("licenseSource")
        == "https://github.com/baserow/baserow/blob/2.3.1/LICENSE"
        and distribution.get("licenseSourceSha256")
        == "1c1fa26d7bb6fddee61c4120803a7190ee3199ac29062bcc1ff0f00a0de08e2b"
        and distribution.get("enterpriseLicenseConfigured") is False
        and distribution.get("premiumFeaturesUsed") is False
        and rest_api.get("ok") is True
        and rest_api.get("tokenCheckStatus") == 200
        and rest_api.get("rowsStatus") == 200
        and mcp.get("ok") is True
        and mcp.get("initializeOk") is True
        and mcp.get("toolsListOk") is True
        and isinstance(mcp.get("toolNames"), list)
        and bool(mcp.get("toolNames"))
        and all(
            baserow_component_persistence.get(key) == value
            for key, value in baserow.items()
        )
    ):
        raise AcceptanceError("baserow_component_dependency_invalid")

    wikijs_document = fresh_component_dependency(
        wikijs_evidence_path,
        source_gate=source_gate,
        api_version="micro-task-engine/v1alpha1",
        kind="WikiJsVerification",
        producer=root / "bin/server-wikijs.py",
    )
    wiki_image = (
        wikijs_document.get("image")
        if isinstance(wikijs_document.get("image"), dict)
        else {}
    )
    graphql = (
        wikijs_document.get("graphql")
        if isinstance(wikijs_document.get("graphql"), dict)
        else {}
    )
    secret_audit = (
        wikijs_document.get("secretAudit")
        if isinstance(wikijs_document.get("secretAudit"), dict)
        else {}
    )
    wiki_component_projection = {
        "pageId": graphql.get("pageId"),
        "pathHashSha256": graphql.get("pathHashSha256"),
        "markerSha256": graphql.get("markerSha256"),
        "restartObserved": graphql.get("restartObserved"),
        "persistenceVerified": graphql.get("persistenceVerified"),
        "postDeleteStatus": graphql.get("postDeleteStatus404"),
        "cleanupCompleted": graphql.get("cleanupCompleted"),
    }
    if not (
        wiki_image.get("license")
        == {
            "spdx": "AGPL-3.0-only",
            "source": "https://github.com/requarks/wiki/blob/v2.5.314/LICENSE",
        }
        and wiki_image.get("ref")
        == "ghcr.io/requarks/wiki:2.5.314@sha256:68f0d1848261ae76492ba358e30a96a76fed5d97a3fff381656082bf90f70d7e"
        and wiki_image.get("version") == "2.5.314"
        and wiki_image.get("digest")
        == "sha256:68f0d1848261ae76492ba358e30a96a76fed5d97a3fff381656082bf90f70d7e"
        and wiki_image.get("upstreamCommit")
        == "6f042e97cc2d3acda6b6ff611de8e0faacce91c1"
        and graphql.get("bearerAuthenticated") is True
        and graphql.get("restartObserved") is True
        and graphql.get("persistenceVerified") is True
        and graphql.get("cleanupCompleted") is True
        and graphql.get("postDeleteGraphqlMissing") is True
        and graphql.get("postDeleteStatus404") == 404
        and sha256(graphql.get("pathHashSha256"))
        and sha256(graphql.get("markerSha256"))
        and wiki_component_projection == wikijs
        and secret_audit.get("rawSecretsPresent") is False
        and secret_audit.get("contentMarkerPresent") is False
    ):
        raise AcceptanceError("wikijs_component_dependency_invalid")

    expected_refs = {
        "baserow": {
            "path": str(baserow_evidence_path),
            "sha256": sha256_file(baserow_evidence_path),
            "kind": "BaserowAcceptance",
            "producerSha256": sha256_file(root / "bin/server-baserow.py"),
        },
        "wikijs": {
            "path": str(wikijs_evidence_path),
            "sha256": sha256_file(wikijs_evidence_path),
            "kind": "WikiJsVerification",
            "producerSha256": sha256_file(root / "bin/server-wikijs.py"),
        },
    }
    if dependency_evidence != expected_refs:
        raise AcceptanceError("ose_storage_dependency_reference_invalid")

    return [
        {
            "path": str(c029_integration_evidence_path),
            "sha256": sha256_file(c029_integration_evidence_path),
        },
        {
            "path": str(baserow_evidence_path),
            "sha256": sha256_file(baserow_evidence_path),
        },
        {
            "path": str(wikijs_evidence_path),
            "sha256": sha256_file(wikijs_evidence_path),
        },
    ]


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
        "CLOUDFLARE_ACCESS_CLIENT_ID",
        "CLOUDFLARE_ACCESS_CLIENT_SECRET",
        "CLOUDFLARE_ACCESS_SERVICE_TOKEN_ID",
        "CLOUDFLARE_ACCESS_EXPIRES_AT",
        "FIRECRAWL_API_KEY",
        "FIRECRAWL_HEALTH_URL",
    )
    expires_at = parse_iso(values["CLOUDFLARE_ACCESS_EXPIRES_AT"])
    if (expires_at - datetime.now(timezone.utc)).total_seconds() <= 300:
        raise AcceptanceError("cloudflare_service_token_expired_or_near_expiry")
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
        "CF-Access-Client-Id": values["CLOUDFLARE_ACCESS_CLIENT_ID"],
        "CF-Access-Client-Secret": values["CLOUDFLARE_ACCESS_CLIENT_SECRET"],
    }
    service_status, _payload, _headers = request(
        "GET", base + health_path, headers=service_headers, allowed={200}
    )
    marker = "MTE-C026-" + secrets.token_hex(12)
    suffix = hashlib.sha256(marker.encode()).hexdigest()[:12]
    container = "mte-cf-marker-" + suffix
    code = (
        "import os;from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer;"
        "m=os.environ['MARKER'].encode();"
        "H=type('H',(BaseHTTPRequestHandler,),{"
        "'do_GET':lambda s:(s.send_response(200),s.send_header('Content-Type','text/plain'),"
        "s.end_headers(),s.wfile.write(m))[-1],"
        "'log_message':lambda *a:None});"
        "ThreadingHTTPServer(('0.0.0.0',8080),H).serve_forever()"
    )
    cleanup = False
    try:
        docker_run(["docker", "rm", "-f", container], allow_failure=True)
        docker_run(
            [
                "docker",
                "run",
                "--rm",
                "-d",
                "--name",
                container,
                "--network",
                "mte-firecrawl",
                "-e",
                "MARKER=" + marker,
                "python:3.13-slim",
                "python",
                "-c",
                code,
            ],
            timeout=120,
        )
        time.sleep(1)
        scrape_headers = {
            **service_headers,
            "Authorization": "Bearer " + values["FIRECRAWL_API_KEY"],
        }
        scrape_status, scrape, _ = request(
            "POST",
            base + "/v1/scrape",
            headers=scrape_headers,
            body={
                "url": "http://" + container + ":8080/",
                "formats": ["markdown"],
                "onlyMainContent": False,
            },
            allowed={200},
            timeout=180,
        )
        markdown = ""
        if isinstance(scrape, dict) and isinstance(scrape.get("data"), dict):
            markdown = str(scrape["data"].get("markdown", ""))
        if scrape_status != 200 or marker not in markdown:
            raise AcceptanceError("firecrawl_controlled_marker_missing")
    finally:
        removed = docker_run(["docker", "rm", "-f", container], allow_failure=True)
        cleanup = removed.returncode == 0
    if not cleanup:
        raise AcceptanceError("firecrawl_marker_cleanup_failed")
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
        "controlledScrapeMarkerObserved": True,
        "markerResultSha256": hashlib.sha256(markdown.encode()).hexdigest(),
        "markerContainerRemoved": True,
    }


def socket_observation(host: str, timeout: float) -> dict[str, Any]:
    parsed = host.rsplit("@", 1)[-1].strip()
    if not parsed or parsed in {"localhost", "127.0.0.1", "::1"}:
        raise AcceptanceError("observer_target_invalid")
    ports: dict[str, dict[str, Any]] = {}
    for port in (22, 80, 443, 3000):
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
            ports["22"]["open"] is True
            and all(ports[str(port)]["open"] is False for port in (80, 443, 3000))
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
        and set(ports) == {"22", "80", "443", "3000"}
        and ports["22"].get("open") is True
        and all(ports[str(port)].get("open") is False for port in (80, 443, 3000))
        and payload.get("ok") is True
    ):
        raise AcceptanceError("external_port_observation_invalid")
    return {
        "expectedHost": expected,
        "excludedHosts": sorted(excluded),
        "sshReachable": True,
        "externalPortsBlocked": {"80": True, "443": True, "3000": True},
        "evidenceSha256": sha256_file(path),
        "ageSeconds": round(age, 3),
        **identity,
    }


def firewall_status() -> dict[str, Any]:
    active = docker_run(
        ["systemctl", "is-active", "mte-cloudflare-origin-firewall.service"],
        allow_failure=True,
    )
    enabled = docker_run(
        ["systemctl", "is-enabled", "mte-cloudflare-origin-firewall.service"],
        allow_failure=True,
    )
    interface = docker_run(
        ["sh", "-c", "ip -4 route show default | awk 'NR==1{print $5}'"]
    ).stdout.strip()
    if not interface:
        raise AcceptanceError("public_interface_missing")
    rule = [
        "-i",
        interface,
        "-p",
        "tcp",
        "-m",
        "multiport",
        "--dports",
        "80,443,3000",
        "-m",
        "comment",
        "--comment",
        "mte-cloudflare-origin-block",
        "-j",
        "DROP",
    ]
    checks: dict[str, bool] = {}
    for tool, family in (("iptables", "V4"), ("ip6tables", "V6")):
        for chain, suffix in (("INPUT", "Input"), ("DOCKER-USER", "Docker")):
            result = docker_run([tool, "-w", "-C", chain, *rule], allow_failure=True)
            checks["firewall" + family + suffix] = result.returncode == 0
    if active.returncode != 0 or enabled.returncode != 0 or not all(checks.values()):
        raise AcceptanceError("origin_firewall_contract_failed")
    return {
        "firewallServiceActive": True,
        "firewallServiceEnabled": True,
        "publicInterface": interface,
        **checks,
    }


def cloudflared_status() -> dict[str, Any]:
    state = docker_run(
        ["docker", "inspect", "--format", "{{json .State}}", "mte-cloudflared"]
    )
    restarts = docker_run(
        ["docker", "inspect", "--format", "{{.RestartCount}}", "mte-cloudflared"]
    )
    try:
        payload = json.loads(state.stdout)
        restart_count = int(restarts.stdout.strip())
    except (json.JSONDecodeError, ValueError) as exc:
        raise AcceptanceError("cloudflared_state_invalid") from exc
    if payload.get("Running") is not True or restart_count != 0:
        raise AcceptanceError("cloudflared_runtime_unhealthy")
    return {"cloudflaredRunning": True, "restartCount": restart_count}


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
        if not (
            plan_document.get("applyable") is False
            and plan_document.get("complete") is True
            and plan_document.get("errored") is False
            and -30 <= plan_age <= 300
        ):
            raise AcceptanceError("opentofu_saved_plan_metadata_invalid")
        action_counts = plan_action_summary(plan_document)
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
        "savedPlanApplyable": False,
        "savedPlanComplete": True,
        "savedPlanErrored": False,
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
                "notionConnectorVerified": True,
                "postgresSystemOfRecordVerified": True,
                "crossProviderLinkageVerified": True,
                "applicationRestartApplicable": False,
                "dataContentEvidence": {
                    "integrationCanary": storage_dependencies[0],
                    "notionConnector": storage_dependencies[1],
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
    runtime = cloudflared_status()
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
        "dependencyEvidence": [],
        "exactManagedRoutes": len(inventory["routes"]),
        "exactDnsRecords": inventory["dnsRecordCount"],
        "exactAccessApplications": inventory["accessApplicationCount"],
        "exactAccessPolicies": inventory["accessPolicyCount"],
        "routeOriginsVerified": True,
        "accessClassesVerified": True,
        "humanAccessPolicyScoped": inventory["humanAccessPolicyScoped"],
        "serviceAccessTokenScoped": inventory["serviceAccessTokenScoped"],
        "foreignDnsPreserved": len(inventory["foreign"])
        == len(protected_foreign_labels),
        "protectedForeignRecords": inventory["foreign"],
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

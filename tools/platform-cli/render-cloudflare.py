#!/usr/bin/env python3
"""Render secret-free Cloudflare tfvars from the platform deployment config."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RENDERED = ROOT / ".runtime" / "evidence" / "platform.rendered.json"
DEFAULT_CONFIG = ROOT / "config" / "platform.yaml"
DEFAULT_OUTPUT = ROOT / ".runtime" / "cloudflare" / "terraform.tfvars.json"
DEFAULT_APPS_PROJECTION = Path("/root/.config/mte-secrets/cloudflare/apps.json")
DEFAULT_DATA_CONTENT_PROJECTION = Path(
    "/opt/mte-platform/config/data-content-plane.json"
)
ID_PATTERN = re.compile(r"^[0-9a-fA-F]{32}$")
LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
ENV_REF_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
UI_ROLE_CONTRACT = {
    "tablesUi": "tables",
    "documentsUi": "documents",
}
ROLE_KEYS = {"providerId", "capability", "interface", "endpointRef", "adapterId"}
PROVIDER_KEYS = {
    "kind",
    "deployment",
    "componentId",
    "capabilities",
    "adapterIds",
}
CAPABILITY_KEYS = {"interfaces", "configurationRefs"}
NOTION_CONFIGURATION_REFS = {
    "tables": {"NOTION_TABLE_DATABASE_ID", "NOTION_TABLE_DATA_SOURCE_ID"},
    "documents": {"NOTION_DOCUMENTS_PAGE_ID"},
}


class RenderError(RuntimeError):
    """A safe, user-facing configuration error."""


def read_document(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise RenderError(f"configuration file does not exist: {path}")
    try:
        if path.suffix.lower() == ".json":
            value = json.loads(path.read_text())
        else:
            value = yaml.safe_load(path.read_text())
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise RenderError(f"cannot parse configuration file {path}: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("spec"), dict):
        raise RenderError(f"configuration file must contain a spec object: {path}")
    return value


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for number, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise RenderError(f"invalid environment assignment at {path}:{number}")
        name, value = line.split("=", 1)
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise RenderError(f"invalid environment name at {path}:{number}")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[name] = value
    return values


def combined_environment(env_file: Path) -> dict[str, str]:
    # platform.env is the authoritative, hash-governed input. In particular,
    # do not let a stale operator shell override it or fill a missing governed
    # provider reference from ambient process state.
    return parse_env_file(env_file)


def env_ref(section: dict[str, Any], key: str, environment: dict[str, str]) -> str:
    ref = str(section.get(key, "")).strip()
    return environment.get(ref, "").strip() if ref else ""


def validate_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if "://" in domain or "/" in domain or len(domain) > 253:
        raise RenderError(
            "domain must be a DNS name without a scheme, path, or trailing dot"
        )
    labels = domain.split(".")
    if len(labels) < 2 or not all(LABEL_PATTERN.fullmatch(label) for label in labels):
        raise RenderError("domain must be a valid DNS name with at least two labels")
    return domain


def required_ref(
    section: dict[str, Any], key: str, environment: dict[str, str]
) -> tuple[str, str]:
    ref = str(section.get(key, "")).strip()
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", ref):
        raise RenderError(f"cloudflare.{key} must be a canonical environment reference")
    value = environment.get(ref, "").strip()
    if not value:
        raise RenderError(f"canonical environment is missing {ref}")
    return ref, value


def resolve_domain(cloudflare: dict[str, Any], environment: dict[str, str]) -> str:
    ref, value = required_ref(cloudflare, "baseDomainRef", environment)
    if ref != "PLATFORM_BASE_DOMAIN":
        raise RenderError("cloudflare.baseDomainRef must be PLATFORM_BASE_DOMAIN")
    return validate_domain(value)


def api_get(
    path: str, token: str, query: dict[str, str] | None = None
) -> dict[str, Any]:
    url = "https://api.cloudflare.com/client/v4" + path
    if query:
        url += "?" + urlencode(query)
    request = Request(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urlopen(request, timeout=20) as response:
            payload = json.loads(response.read())
    except HTTPError as exc:
        raise RenderError(
            f"Cloudflare API request failed with HTTP {exc.code}"
        ) from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RenderError(
            f"Cloudflare API request failed: {type(exc).__name__}"
        ) from exc
    if not isinstance(payload, dict) or not payload.get("success"):
        errors = payload.get("errors", []) if isinstance(payload, dict) else []
        codes = [
            str(item.get("code"))
            for item in errors
            if isinstance(item, dict) and item.get("code")
        ]
        suffix = f" (codes: {', '.join(codes)})" if codes else ""
        raise RenderError("Cloudflare API returned an unsuccessful response" + suffix)
    return payload


def zone_candidates(domain: str) -> list[str]:
    labels = domain.split(".")
    return [".".join(labels[index:]) for index in range(0, len(labels) - 1)]


def discover_zone(domain: str, account_id: str, token: str) -> tuple[str, str]:
    for candidate in zone_candidates(domain):
        payload = api_get(
            "/zones",
            token,
            {
                "name": candidate,
                "account.id": account_id,
                "status": "active",
                "per_page": "50",
            },
        )
        rows = payload.get("result", [])
        if not isinstance(rows, list):
            continue
        exact = [
            row
            for row in rows
            if isinstance(row, dict) and row.get("name") == candidate
        ]
        if len(exact) == 1 and ID_PATTERN.fullmatch(str(exact[0].get("id", ""))):
            return str(exact[0]["id"]), candidate
        if len(exact) > 1:
            raise RenderError(f"Cloudflare returned multiple zones named {candidate}")
    raise RenderError(
        "no active Cloudflare zone belonging to the configured account contains the configured domain"
    )


def resolve_zone(
    domain: str,
    cloudflare: dict[str, Any],
    environment: dict[str, str],
    account_id: str,
    token: str,
) -> tuple[str, str]:
    zone_id = env_ref(cloudflare, "zoneIdRef", environment)
    if zone_id:
        if not ID_PATTERN.fullmatch(zone_id):
            raise RenderError(
                "the configured Cloudflare zone ID is not a 32-character identifier"
            )
        payload = api_get(f"/zones/{zone_id}", token)
        result = payload.get("result", {})
        zone_name = (
            validate_domain(str(result.get("name", "")))
            if isinstance(result, dict)
            else ""
        )
        if domain != zone_name and not domain.endswith("." + zone_name):
            raise RenderError(
                "the configured domain is not contained by the configured Cloudflare zone"
            )
        result_account = result.get("account", {}) if isinstance(result, dict) else {}
        if isinstance(result_account, dict) and result_account.get("id") not in {
            None,
            account_id,
        }:
            raise RenderError(
                "the configured Cloudflare zone belongs to a different account"
            )
        return zone_id, zone_name
    return discover_zone(domain, account_id, token)


def parse_allowed_emails(
    cloudflare: dict[str, Any], environment: dict[str, str]
) -> list[str]:
    _, value = required_ref(cloudflare, "accessAllowedEmailsRef", environment)
    emails = [email.strip().lower() for email in value.split(",") if email.strip()]
    invalid = [
        email
        for email in emails
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
    ]
    if invalid:
        raise RenderError(
            "one or more Cloudflare Access allowed-email values are invalid"
        )
    return sorted(set(emails))


def full_hostname(label: str, domain: str) -> str:
    value = label.strip().lower().rstrip(".")
    if not LABEL_PATTERN.fullmatch(value):
        raise RenderError(
            "an application subdomain must be exactly one valid DNS label"
        )
    return validate_domain(f"{value}.{domain}")


def render_apps(
    spec: dict[str, Any],
    cloudflare: dict[str, Any],
    environment: dict[str, str],
    domain: str,
) -> dict[str, dict[str, str]]:
    components = spec.get("components", [])
    if not isinstance(components, list):
        raise RenderError("spec.components must be a list")
    declarations: list[dict[str, Any]] = []
    for component in components:
        if not isinstance(component, dict) or not isinstance(
            component.get("exposure"), dict
        ):
            continue
        declarations.append({"id": component.get("id"), **component["exposure"]})
    additional = cloudflare.get("additionalApps", [])
    if not isinstance(additional, list):
        raise RenderError("cloudflare.additionalApps must be a list")
    declarations.extend(row for row in additional if isinstance(row, dict))

    apps: dict[str, dict[str, str]] = {}
    hostnames: set[str] = set()
    for declaration in declarations:
        component_id = str(declaration.get("id", "")).strip()
        if not component_id or component_id in apps:
            raise RenderError("every exposed component must have a unique non-empty id")
        _, label = required_ref(declaration, "subdomainRef", environment)
        _, port_value = required_ref(declaration, "originPortRef", environment)
        _, access_class = required_ref(declaration, "accessClassRef", environment)
        access_class = access_class.lower()
        if access_class not in {"human", "service"}:
            raise RenderError(
                f"{component_id} has unsupported exposure class {access_class!r}"
            )
        if not port_value.isdigit() or not 1 <= int(port_value) <= 65535:
            raise RenderError(f"{component_id} has an invalid canonical origin port")
        hostname = full_hostname(label, domain)
        if hostname in hostnames:
            raise RenderError(
                f"{component_id} resolves to a duplicate exposure hostname"
            )
        apps[component_id] = {
            "hostname": hostname,
            "origin": f"http://127.0.0.1:{int(port_value)}",
            "access_class": access_class,
        }
        hostnames.add(hostname)
    if not apps:
        raise RenderError("the platform configuration contains no Cloudflare exposures")
    return dict(sorted(apps.items()))


def validate_ui_role_provider(
    plane_roles: dict[str, Any],
    providers: dict[str, Any],
    role_id: str,
) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """Return a validated UI role/provider pair and whether it is external Notion."""

    role = plane_roles.get(role_id)
    if not isinstance(role, dict) or set(role) != ROLE_KEYS:
        raise RenderError(f"data/content logical role {role_id} is malformed")
    capability_id = UI_ROLE_CONTRACT[role_id]
    if (
        role.get("capability") != capability_id
        or role.get("interface") != "ui"
        or not isinstance(role.get("adapterId"), str)
        or not ENV_REF_PATTERN.fullmatch(str(role.get("endpointRef", "")))
    ):
        raise RenderError(
            f"data/content logical role {role_id} capability is malformed"
        )
    provider_id = role.get("providerId")
    provider = providers.get(provider_id) if isinstance(provider_id, str) else None
    if not isinstance(provider, dict) or set(provider) != PROVIDER_KEYS:
        raise RenderError(
            f"data/content logical role {role_id} provider metadata is malformed"
        )
    capabilities = provider.get("capabilities")
    capability = (
        capabilities.get(capability_id) if isinstance(capabilities, dict) else None
    )
    if not isinstance(capability, dict) or set(capability) != CAPABILITY_KEYS:
        raise RenderError(
            f"data/content logical role {role_id} provider capability is malformed"
        )
    interfaces = capability.get("interfaces")
    configuration_refs = capability.get("configurationRefs")
    adapter_ids = provider.get("adapterIds")
    if (
        not isinstance(interfaces, list)
        or any(not isinstance(item, str) for item in interfaces)
        or "ui" not in interfaces
        or len(interfaces) != len(set(interfaces))
        or not isinstance(configuration_refs, list)
        or any(
            not isinstance(item, str) or not ENV_REF_PATTERN.fullmatch(item)
            for item in configuration_refs
        )
        or len(configuration_refs) != len(set(configuration_refs))
        or not isinstance(adapter_ids, list)
        or not adapter_ids
        or any(not isinstance(item, str) or not item for item in adapter_ids)
        or len(adapter_ids) != len(set(adapter_ids))
        or role.get("adapterId") not in adapter_ids
    ):
        raise RenderError(
            f"data/content logical role {role_id} provider capability is malformed"
        )

    deployment = provider.get("deployment")
    if deployment == "external":
        if (
            provider_id != "notion"
            or provider.get("kind") != "external-workspace"
            or provider.get("componentId") is not None
            or role.get("adapterId") != "notion"
            or role.get("endpointRef") != "NOTION_API_BASE_URL"
            or set(interfaces) != {"ui", "api"}
            or len(interfaces) != 2
            or set(configuration_refs) != NOTION_CONFIGURATION_REFS[capability_id]
            or set(adapter_ids) != {"notion"}
        ):
            raise RenderError(
                f"data/content logical role {role_id} external Notion metadata is malformed"
            )
        return role, provider, True
    if (
        deployment != "profile-component"
        or provider.get("kind") != "self-hosted-workspace"
    ):
        raise RenderError(
            f"data/content logical role {role_id} provider deployment is malformed"
        )
    component_id = provider.get("componentId")
    if not isinstance(component_id, str) or not component_id:
        raise RenderError(
            f"data/content logical role {role_id} provider component is malformed"
        )
    return role, provider, False


def read_apps_projection(
    path: Path,
    env_file: Path,
    domain: str,
    data_content_projection: Path | None = None,
) -> dict[str, dict[str, str]]:
    if not path.is_file():
        raise RenderError("manifest-registered Cloudflare apps projection is missing")
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RenderError("Cloudflare apps projection is invalid") from exc
    if not isinstance(payload, dict):
        raise RenderError("Cloudflare apps projection must be an object")
    generated = payload.get("_generated", {})
    expected_sha = hashlib.sha256(env_file.read_bytes()).hexdigest()
    if generated.get("sourceSha256") != expected_sha:
        raise RenderError("Cloudflare apps projection has canonical source hash drift")
    if payload.get("baseDomain") != domain:
        raise RenderError(
            "Cloudflare apps projection base domain differs from canonical domain"
        )
    rows = payload.get("apps", {})
    if not isinstance(rows, dict) or not rows:
        raise RenderError("Cloudflare apps projection is empty")
    apps: dict[str, dict[str, str]] = {}
    for app_id, row in rows.items():
        if not isinstance(row, dict):
            raise RenderError(
                "Cloudflare apps projection contains an invalid application"
            )
        hostname = validate_domain(str(row.get("hostname", "")))
        origin = str(row.get("origin", ""))
        access_class = str(row.get("accessClass", "")).lower()
        if not hostname.endswith("." + domain):
            raise RenderError(
                "Cloudflare apps projection contains an out-of-zone hostname"
            )
        if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", origin):
            raise RenderError(
                "Cloudflare apps projection contains an invalid loopback origin"
            )
        if access_class not in {"human", "service"}:
            raise RenderError(
                "Cloudflare apps projection contains an invalid access class"
            )
        apps[str(app_id)] = {
            "hostname": hostname,
            "origin": origin,
            "access_class": access_class,
        }
    apps = dict(sorted(apps.items()))
    if data_content_projection is not None:
        try:
            data_content = json.loads(data_content_projection.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise RenderError("data/content plane projection is invalid") from exc
        binding = payload.get("dataContent")
        if not isinstance(binding, dict) or set(binding) != {
            "profile",
            "projectionSha256",
            "roles",
        }:
            raise RenderError(
                "Cloudflare apps projection lacks an exact data/content binding"
            )
        if not isinstance(data_content, dict):
            raise RenderError("data/content plane projection must be an object")
        data_generated = data_content.get("_generated")
        if (
            not isinstance(data_generated, dict)
            or data_generated.get("sourceSha256") != expected_sha
        ):
            raise RenderError("data/content plane has canonical source hash drift")
        content_sha = hashlib.sha256(data_content_projection.read_bytes()).hexdigest()
        if binding.get("projectionSha256") != content_sha:
            raise RenderError(
                "Cloudflare data/content projection hash binding has drift"
            )
        if binding.get("profile") != data_content.get("profile"):
            raise RenderError("Cloudflare data/content profile binding has drift")
        plane_roles = data_content.get("roles")
        providers = data_content.get("providers")
        projected_roles = binding.get("roles")
        if (
            not isinstance(plane_roles, dict)
            or not isinstance(providers, dict)
            or not isinstance(projected_roles, dict)
        ):
            raise RenderError("data/content logical roles are invalid")
        validated_roles = {
            role_id: validate_ui_role_provider(plane_roles, providers, role_id)
            for role_id in UI_ROLE_CONTRACT
        }
        if not projected_roles:
            if not all(row[2] for row in validated_roles.values()):
                raise RenderError(
                    "empty Cloudflare data/content UI roles require both roles to use external Notion"
                )
            return apps
        if set(projected_roles) != set(UI_ROLE_CONTRACT):
            raise RenderError("Cloudflare data/content UI role set is not exact")
        for role_id, role_binding in projected_roles.items():
            _, provider, external = validated_roles[role_id]
            if external:
                raise RenderError(
                    f"external Notion logical role {role_id} cannot be a Cloudflare application"
                )
            if not isinstance(role_binding, dict) or set(role_binding) != {
                "applicationId",
                "hostname",
                "accessClass",
            }:
                raise RenderError(
                    f"Cloudflare logical role {role_id} binding is invalid"
                )
            app_id = str(role_binding["applicationId"])
            if (
                provider.get("componentId") != app_id
                or app_id not in apps
                or role_binding.get("hostname") != apps[app_id]["hostname"]
                or role_binding.get("accessClass") != apps[app_id]["access_class"]
            ):
                raise RenderError(
                    f"Cloudflare logical role {role_id} binding has drift"
                )
    return apps


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="platform YAML or rendered JSON")
    parser.add_argument(
        "--env-file",
        type=Path,
        required=True,
        help="explicit operator or canonical environment file",
    )
    parser.add_argument("--apps-projection", type=Path, default=DEFAULT_APPS_PROJECTION)
    parser.add_argument(
        "--data-content-projection",
        type=Path,
        default=DEFAULT_DATA_CONTENT_PROJECTION,
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = args.config or (
        DEFAULT_RENDERED if DEFAULT_RENDERED.is_file() else DEFAULT_CONFIG
    )
    document = read_document(config_path.resolve())
    spec = document["spec"]
    cloudflare = spec.get("cloudflare", {})
    if not isinstance(cloudflare, dict) or not cloudflare.get("enabled", False):
        raise RenderError("Cloudflare is not enabled in the platform configuration")

    environment = combined_environment(args.env_file.expanduser())
    domain = resolve_domain(cloudflare, environment)
    account_id = env_ref(cloudflare, "accountIdRef", environment)
    token = env_ref(cloudflare, "apiTokenRef", environment)
    if not ID_PATTERN.fullmatch(account_id):
        raise RenderError("the configured Cloudflare account ID is missing or invalid")
    if not token:
        raise RenderError(
            "the Cloudflare API token is missing from the configured environment reference"
        )

    zone_id, zone_name = resolve_zone(
        domain, cloudflare, environment, account_id, token
    )
    apps = read_apps_projection(
        args.apps_projection.expanduser().resolve(),
        args.env_file.expanduser().resolve(),
        domain,
        args.data_content_projection.expanduser().resolve(),
    )
    human_apps_present = any(app["access_class"] == "human" for app in apps.values())
    allowed_emails = (
        parse_allowed_emails(cloudflare, environment) if human_apps_present else []
    )
    if human_apps_present and not allowed_emails:
        raise RenderError(
            "human-facing apps require canonical Cloudflare allowed emails"
        )
    _, tunnel_name = required_ref(cloudflare, "tunnelNameRef", environment)
    _, human_session_duration = required_ref(
        cloudflare, "humanSessionDurationRef", environment
    )
    _, service_token_duration = required_ref(
        cloudflare, "serviceTokenDurationRef", environment
    )

    tfvars = {
        "account_id": account_id,
        "zone_id": zone_id,
        "base_domain": domain,
        "tunnel_name": tunnel_name,
        "apps": apps,
        "human_allowed_emails": allowed_emails,
        "human_session_duration": human_session_duration,
        "service_token_duration": service_token_duration,
    }
    output = args.output.expanduser().resolve()
    atomic_write_json(output, tfvars)
    print(
        json.dumps(
            {
                "output": str(output),
                "base_domain_present": True,
                "zone_resolved": bool(zone_name),
                "apps": len(apps),
                "human_apps": sum(
                    app["access_class"] == "human" for app in apps.values()
                ),
                "service_apps": sum(
                    app["access_class"] == "service" for app in apps.values()
                ),
                "contains_api_token": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RenderError as exc:
        print(f"render-cloudflare: {exc}", file=sys.stderr)
        raise SystemExit(2)

#!/usr/bin/env python3
"""Fail-closed, secret-safe preflight for the MTE Cloudflare edge."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / "config" / "platform.yaml"
DEFAULT_OUTPUT = ROOT / ".runtime" / "evidence" / "cloudflare-preflight.json"
ID_PATTERN = re.compile(r"^[0-9a-fA-F]{32}$")
LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class PreflightError(RuntimeError):
    """An operational error whose message never contains credentials."""


def read_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise PreflightError(f"configuration file does not exist: {path}")
    try:
        value = (
            json.loads(path.read_text())
            if path.suffix == ".json"
            else yaml.safe_load(path.read_text())
        )
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise PreflightError(
            f"cannot parse configuration: {type(exc).__name__}"
        ) from exc
    if not isinstance(value, dict) or not isinstance(value.get("spec"), dict):
        raise PreflightError("configuration must contain a spec object")
    return value


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if path.is_file():
        for number, raw in enumerate(path.read_text().splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            if "=" not in line:
                raise PreflightError(f"invalid environment assignment at line {number}")
            name, value = line.split("=", 1)
            name = name.strip()
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise PreflightError(f"invalid environment name at line {number}")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            values[name] = value
    values.update(os.environ)
    return values


def ref_value(
    section: dict[str, Any], key: str, environment: dict[str, str], default: str
) -> tuple[str, str]:
    ref = str(section.get(key, default)).strip() or default
    return ref, environment.get(ref, "").strip()


def validate_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    labels = domain.split(".")
    if (
        not domain
        or "://" in domain
        or "/" in domain
        or len(domain) > 253
        or len(labels) < 2
        or not all(LABEL_PATTERN.fullmatch(label) for label in labels)
    ):
        raise PreflightError("configured domain is not a valid DNS name")
    return domain


def resolve_domain(
    cloudflare: dict[str, Any], environment: dict[str, str]
) -> tuple[str, str, bool]:
    ref = str(cloudflare.get("baseDomainRef", "")).strip()
    if ref != "PLATFORM_BASE_DOMAIN":
        return ref or "PLATFORM_BASE_DOMAIN", "", True
    value = environment.get(ref, "")
    if not value:
        return ref, "", False
    try:
        return ref, validate_domain(value), False
    except PreflightError:
        return ref, "", True


def blocker(code: str, **details: Any) -> dict[str, Any]:
    return {"code": code, **details}


def api_get(
    path: str, token: str, query: dict[str, str] | None = None
) -> tuple[bool, int, dict[str, Any]]:
    url = "https://api.cloudflare.com/client/v4" + path
    if query:
        url += "?" + urlencode(query)
    request = Request(
        url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
    )
    try:
        with urlopen(request, timeout=20) as response:
            status = response.status
            payload = json.loads(response.read())
    except HTTPError as exc:
        status = exc.code
        try:
            payload = json.loads(exc.read())
        except (json.JSONDecodeError, OSError):
            payload = {}
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        return False, 0, {"errorType": type(exc).__name__}
    success = bool(
        isinstance(payload, dict) and payload.get("success") and 200 <= status < 300
    )
    return success, status, payload if isinstance(payload, dict) else {}


def safe_api_check(
    path: str, token: str, query: dict[str, str] | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    success, status, payload = api_get(path, token, query)
    codes = sorted(
        {
            str(row.get("code"))
            for row in payload.get("errors", [])
            if isinstance(row, dict) and row.get("code") is not None
        }
    )
    check = {"ready": success, "httpStatus": status or None}
    if codes:
        check["errorCodes"] = codes
    return check, payload


def zone_candidates(domain: str) -> list[str]:
    labels = domain.split(".")
    return [".".join(labels[index:]) for index in range(len(labels) - 1)]


def discover_zone(
    domain: str, account_id: str, token: str
) -> tuple[str, dict[str, Any]]:
    last_check: dict[str, Any] = {"ready": False, "httpStatus": None}
    for candidate in zone_candidates(domain):
        last_check, payload = safe_api_check(
            "/zones",
            token,
            {
                "name": candidate,
                "account.id": account_id,
                "status": "active",
                "per_page": "50",
            },
        )
        if not last_check["ready"]:
            return "", last_check
        rows = payload.get("result", [])
        exact = [
            row
            for row in rows
            if isinstance(row, dict) and row.get("name") == candidate
        ]
        if len(exact) == 1 and ID_PATTERN.fullmatch(str(exact[0].get("id", ""))):
            return str(exact[0]["id"]), {
                "ready": True,
                "httpStatus": last_check["httpStatus"],
            }
    return "", {
        "ready": False,
        "httpStatus": last_check.get("httpStatus"),
        "reason": "notFound",
    }


def internal_checks(
    spec: dict[str, Any], *, local: bool = False
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    host = spec.get("host", {})
    target = str(host.get("ssh", "")).strip() if isinstance(host, dict) else ""
    checks: dict[str, str] = {}
    for row in spec.get("components", []):
        if not isinstance(row, dict) or not isinstance(row.get("exposure"), dict):
            continue
        component_id = str(row.get("id", "")).strip()
        health = row.get("health", {})
        url = str(health.get("url", "")).strip() if isinstance(health, dict) else ""
        if not url:
            url = str(row["exposure"].get("origin", "")).strip()
        if not re.fullmatch(
            r"https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::[0-9]{1,5})?(?:/.*)?", url
        ):
            return {}, [blocker("invalid_internal_origin", component=component_id)]
        checks[component_id] = url
    if not target:
        return {}, [blocker("missing_origin_host")]

    checks_json = json.dumps(checks, sort_keys=True)
    remote = (
        """import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen
checks = json.loads("""
        + repr(checks_json)
        + """)
result = {}
for name, url in checks.items():
    request = Request(url, headers={"User-Agent": "mte-cloudflare-preflight/1"})
    try:
        with urlopen(request, timeout=8) as response:
            status = response.status
            result[name] = {"ready": 200 <= status < 400, "httpStatus": status}
    except HTTPError as exc:
        result[name] = {"ready": False, "httpStatus": exc.code}
    except Exception as exc:
        result[name] = {"ready": False, "httpStatus": None, "errorType": type(exc).__name__}
print(json.dumps(result, sort_keys=True))
"""
    )
    command = (
        ["python3", "-"]
        if local
        else [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
            target,
            "python3 -",
        ]
    )
    try:
        process = subprocess.run(
            command,
            input=remote,
            text=True,
            capture_output=True,
            timeout=max(30, len(checks) * 9),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {}, [blocker("origin_host_unreachable", errorType=type(exc).__name__)]
    if process.returncode != 0:
        return {}, [blocker("origin_host_unreachable", sshExitCode=process.returncode)]
    try:
        result = json.loads(process.stdout)
    except json.JSONDecodeError:
        return {}, [blocker("origin_health_invalid_response")]
    blockers = [
        blocker("internal_origin_unhealthy", component=name)
        for name, check in sorted(result.items())
        if not isinstance(check, dict) or not check.get("ready")
    ]
    return result, blockers


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument(
        "--env-file",
        type=Path,
        required=True,
        help="explicit operator or canonical environment file",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--origins-local", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    document = read_config(args.config.expanduser().resolve())
    spec = document["spec"]
    cloudflare = spec.get("cloudflare", {})
    if not isinstance(cloudflare, dict) or not cloudflare.get("enabled", False):
        raise PreflightError("Cloudflare is not enabled in the platform configuration")
    environment = read_env(args.env_file.expanduser())

    domain_ref, domain, invalid_domain = resolve_domain(cloudflare, environment)
    account_ref, account_id = ref_value(
        cloudflare, "accountIdRef", environment, "CLOUDFLARE_ACCOUNT_ID"
    )
    zone_ref, configured_zone_id = ref_value(
        cloudflare, "zoneIdRef", environment, "CLOUDFLARE_ZONE_ID"
    )
    token_ref, token = ref_value(
        cloudflare, "apiTokenRef", environment, "CLOUDFLARE_API_TOKEN"
    )
    allowed_email_ref = str(cloudflare.get("accessAllowedEmailsRef", "")).strip()
    email_present = bool(
        allowed_email_ref and environment.get(allowed_email_ref, "").strip()
    )

    result: dict[str, Any] = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "CloudflarePreflight",
        "ready": False,
        "checks": {
            "refs": {
                "domain": {"name": domain_ref, "present": bool(domain)},
                "accountId": {"name": account_ref, "present": bool(account_id)},
                "zoneId": {
                    "name": zone_ref,
                    "present": bool(configured_zone_id),
                    "required": False,
                },
                "apiToken": {"name": token_ref, "present": bool(token)},
                "humanAllowedEmail": {"present": email_present},
            },
            "internalOrigins": {},
            "cloudflareApi": {},
        },
        "blockers": [],
    }
    blockers: list[dict[str, Any]] = result["blockers"]
    if invalid_domain:
        blockers.append(blocker("invalid_domain_candidate", ref=domain_ref))
    elif not domain:
        blockers.append(blocker("missing_domain", ref=domain_ref))
    if not ID_PATTERN.fullmatch(account_id):
        blockers.append(blocker("missing_or_invalid_account_id", ref=account_ref))
    if not token:
        blockers.append(blocker("missing_api_token", ref=token_ref))
    app_declarations = [
        row["exposure"]
        for row in spec.get("components", [])
        if isinstance(row, dict) and isinstance(row.get("exposure"), dict)
    ]
    additional_apps = cloudflare.get("additionalApps", [])
    if isinstance(additional_apps, list):
        app_declarations.extend(row for row in additional_apps if isinstance(row, dict))
    human_apps = [
        row
        for row in app_declarations
        if environment.get(str(row.get("accessClassRef", "")), "").strip().lower()
        == "human"
    ]
    if human_apps and not email_present:
        blockers.append(blocker("missing_human_allowed_email"))

    origins, origin_blockers = internal_checks(spec, local=args.origins_local)
    result["checks"]["internalOrigins"] = origins
    blockers.extend(origin_blockers)

    if token:
        verify_path = (
            f"/accounts/{account_id}/tokens/verify"
            if ID_PATTERN.fullmatch(account_id)
            else "/user/tokens/verify"
        )
        token_check, _ = safe_api_check(verify_path, token)
        result["checks"]["cloudflareApi"]["token"] = token_check
        if not token_check["ready"]:
            blockers.append(blocker("api_token_invalid_or_unverifiable"))
    if token and ID_PATTERN.fullmatch(account_id):
        capability_paths = {
            "tunnel": (
                f"/accounts/{account_id}/cfd_tunnel",
                {"is_deleted": "false", "per_page": "1"},
            ),
            "accessApplications": (
                f"/accounts/{account_id}/access/apps",
                {"per_page": "1"},
            ),
            "accessServiceTokens": (
                f"/accounts/{account_id}/access/service_tokens",
                {"per_page": "1"},
            ),
        }
        for capability, (path, query) in capability_paths.items():
            check, _ = safe_api_check(path, token, query)
            result["checks"]["cloudflareApi"][capability] = check
            if not check["ready"]:
                blockers.append(
                    blocker(
                        "cloudflare_api_capability_unavailable", capability=capability
                    )
                )

        idp_mode = environment.get("CLOUDFLARE_ACCESS_IDP_MODE", "").strip()
        idp_present = idp_mode in {"onetimepin", "external"}
        result["checks"]["cloudflareApi"]["identityProvider"] = {
            "ready": idp_present,
            "present": idp_present,
            "mode": idp_mode or None,
            "source": "canonical_bootstrap_inventory",
        }
        if human_apps and not idp_present:
            blockers.append(blocker("zero_trust_identity_provider_missing"))

        if domain:
            if configured_zone_id:
                if ID_PATTERN.fullmatch(configured_zone_id):
                    zone_check, zone_payload = safe_api_check(
                        f"/zones/{configured_zone_id}", token
                    )
                    zone_id = configured_zone_id if zone_check["ready"] else ""
                    zone_result = (
                        zone_payload.get("result", {}) if zone_check["ready"] else {}
                    )
                    zone_name = (
                        str(zone_result.get("name", ""))
                        if isinstance(zone_result, dict)
                        else ""
                    )
                    contained = bool(
                        zone_name
                        and (domain == zone_name or domain.endswith("." + zone_name))
                    )
                    zone_check["containsDomain"] = contained
                    if zone_check["ready"] and not contained:
                        zone_id = ""
                        blockers.append(
                            blocker("configured_zone_does_not_contain_domain")
                        )
                else:
                    zone_id = ""
                    zone_check = {
                        "ready": False,
                        "httpStatus": None,
                        "reason": "invalidIdentifier",
                    }
            else:
                zone_id, zone_check = discover_zone(domain, account_id, token)
            result["checks"]["cloudflareApi"]["zone"] = zone_check
            if not zone_id:
                blockers.append(blocker("cloudflare_zone_unavailable"))
            else:
                dns_check, _ = safe_api_check(
                    f"/zones/{zone_id}/dns_records", token, {"per_page": "1"}
                )
                result["checks"]["cloudflareApi"]["dns"] = dns_check
                if not dns_check["ready"]:
                    blockers.append(
                        blocker(
                            "cloudflare_api_capability_unavailable", capability="dns"
                        )
                    )

    result["blockers"] = sorted(
        blockers,
        key=lambda row: (
            str(row.get("code")),
            str(row.get("component", "")),
            str(row.get("capability", "")),
        ),
    )
    result["ready"] = not result["blockers"]
    output = args.output.expanduser().resolve()
    try:
        write_json(output, result)
    except OSError as exc:
        result["blockers"].append(
            blocker("local_evidence_write_failed", errorType=type(exc).__name__)
        )
        result["blockers"] = sorted(
            result["blockers"],
            key=lambda row: (
                str(row.get("code")),
                str(row.get("component", "")),
                str(row.get("capability", "")),
            ),
        )
        result["ready"] = False
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ready"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PreflightError as exc:
        failure = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "CloudflarePreflight",
            "ready": False,
            "blockers": [{"code": "preflight_error", "errorType": type(exc).__name__}],
        }
        print(json.dumps(failure, indent=2, sort_keys=True))
        raise SystemExit(3)

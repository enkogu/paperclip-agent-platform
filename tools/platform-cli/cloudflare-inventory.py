#!/usr/bin/env python3
"""Read-only Cloudflare inventory using legacy global-key authentication."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / ".runtime" / "evidence" / "cloudflare-inventory.json"
LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
REQUIRED_GROUPS = {
    "tunnel": (
        "Cloudflare Tunnel Write",
        "Cloudflare One Connector: cloudflared Write",
        "Cloudflare One Connectors Write",
    ),
    "dns": ("DNS Write",),
    "zoneRead": ("Zone Read",),
    "accessApplications": ("Access: Apps and Policies Write",),
    "accessServiceTokens": ("Access: Service Tokens Write",),
}


class InventoryError(RuntimeError):
    """An inventory failure whose text contains no credential values."""


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        raise InventoryError("credential environment file is missing")
    for number, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise InventoryError(f"invalid environment assignment at line {number}")
        name, value = line.split("=", 1)
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise InventoryError(f"invalid environment name at line {number}")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[name] = value
    values.update(os.environ)
    return values


def valid_hostname(value: str) -> bool:
    hostname = value.strip().lower().rstrip(".")
    labels = hostname.split(".")
    return bool(
        hostname
        and len(hostname) <= 253
        and len(labels) >= 2
        and all(LABEL_PATTERN.fullmatch(label) for label in labels)
    )


def api_get(
    path: str,
    email: str,
    global_key: str,
    query: dict[str, str] | None = None,
) -> tuple[bool, int, dict[str, Any]]:
    url = "https://api.cloudflare.com/client/v4" + path
    if query:
        url += "?" + urlencode(query)
    request = Request(
        url,
        headers={
            "X-Auth-Email": email,
            "X-Auth-Key": global_key,
            "Accept": "application/json",
            "User-Agent": "mte-cloudflare-readonly-inventory/1",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
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


def error_codes(payload: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(row.get("code"))
            for row in payload.get("errors", [])
            if isinstance(row, dict) and row.get("code") is not None
        }
    )


def paginated(
    path: str,
    email: str,
    global_key: str,
    query: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    page = 1
    while True:
        params = dict(query or {})
        params.update({"page": str(page), "per_page": "50"})
        success, status, payload = api_get(path, email, global_key, params)
        if not success:
            check = {"ready": False, "httpStatus": status or None}
            codes = error_codes(payload)
            if codes:
                check["errorCodes"] = codes
            return [], check
        result = payload.get("result", [])
        if not isinstance(result, list):
            return [], {
                "ready": False,
                "httpStatus": status,
                "reason": "invalidResponse",
            }
        rows.extend(row for row in result if isinstance(row, dict))
        info = payload.get("result_info", {})
        total_pages = (
            int(info.get("total_pages", page)) if isinstance(info, dict) else page
        )
        if page >= total_pages or not result:
            return rows, {"ready": True, "httpStatus": status}
        page += 1


def single_page(
    path: str,
    email: str,
    global_key: str,
    query: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    success, status, payload = api_get(path, email, global_key, query)
    check: dict[str, Any] = {"ready": success, "httpStatus": status or None}
    codes = error_codes(payload)
    if codes:
        check["errorCodes"] = codes
    result = payload.get("result", []) if success else []
    return (
        [row for row in result if isinstance(row, dict)]
        if isinstance(result, list)
        else [],
        check,
    )


def account_refs(accounts: list[dict[str, Any]], configured_id: str) -> dict[str, str]:
    identifiers = sorted(str(row.get("id", "")) for row in accounts if row.get("id"))
    refs: dict[str, str] = {}
    counter = 1
    for identifier in identifiers:
        if configured_id and identifier == configured_id:
            refs[identifier] = "configured"
        else:
            refs[identifier] = f"account-{counter}"
            counter += 1
    return refs


def find_permission_groups(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_name = {str(row.get("name", "")): row for row in rows if row.get("name")}
    result: dict[str, dict[str, Any]] = {}
    for capability, alternatives in REQUIRED_GROUPS.items():
        matched = next((name for name in alternatives if name in by_name), "")
        scopes = sorted(
            str(value) for value in by_name.get(matched, {}).get("scopes", []) if value
        )
        result[capability] = {
            "present": bool(matched),
            "permissionGroup": matched or alternatives[0],
            "scopes": scopes,
        }
    return result


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
    parser.add_argument(
        "--env-file",
        type=Path,
        required=True,
        help="explicit operator bootstrap environment file",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    environment = read_env(args.env_file.expanduser())
    email = environment.get("CLOUDFLARE_EMAIL", "").strip()
    global_key = environment.get("CLOUDFLARE_GLOBAL_API_KEY", "").strip()
    candidate = environment.get("PLATFORM_BASE_DOMAIN", "").strip()
    configured_account = environment.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
    if not email or not global_key:
        raise InventoryError("global-key authentication references are missing")

    accounts, accounts_check = paginated("/accounts", email, global_key)
    zones, zones_check = paginated("/zones", email, global_key, {"status": "active"})
    refs = account_refs(accounts, configured_account)
    configured_present = bool(configured_account and configured_account in refs)

    zone_rows: list[dict[str, Any]] = []
    for zone in sorted(zones, key=lambda row: str(row.get("name", ""))):
        account = zone.get("account", {})
        account_id = str(account.get("id", "")) if isinstance(account, dict) else ""
        name = str(zone.get("name", "")).strip().lower()
        if name:
            zone_rows.append(
                {"name": name, "accountRef": refs.get(account_id, "unlisted")}
            )

    normalized_candidate = candidate.strip().lower().rstrip(".")
    candidate_valid = (
        valid_hostname(normalized_candidate) if normalized_candidate else False
    )
    containing = [
        row
        for row in zone_rows
        if candidate_valid
        and (
            normalized_candidate == row["name"]
            or normalized_candidate.endswith("." + row["name"])
        )
    ]
    containing.sort(key=lambda row: len(row["name"]), reverse=True)
    resolved = containing[0] if containing else None
    exact = bool(resolved and resolved["name"] == normalized_candidate)

    if not normalized_candidate:
        not_found_reason = "candidate_missing"
    elif not candidate_valid:
        not_found_reason = "candidate_not_a_valid_hostname"
    elif not resolved:
        not_found_reason = "candidate_not_contained_by_any_visible_active_zone"
    elif resolved["accountRef"] != "configured":
        not_found_reason = "candidate_zone_belongs_to_a_different_account"
    else:
        not_found_reason = "scoped_api_token_lacks_zone_visibility"

    user_groups, user_groups_check = single_page(
        "/user/tokens/permission_groups", email, global_key
    )
    user_tokens, user_tokens_check = paginated(
        "/user/tokens", email, global_key, {"direction": "desc"}
    )
    # Inventory only: token values, IDs, names, and policies are deliberately discarded.
    del user_tokens
    user_permissions = find_permission_groups(user_groups)

    account_groups: list[dict[str, Any]] = []
    account_groups_check: dict[str, Any] = {
        "ready": False,
        "httpStatus": None,
        "reason": "configuredAccountUnavailable",
    }
    account_tokens_check: dict[str, Any] = dict(account_groups_check)
    members_check: dict[str, Any] = dict(account_groups_check)
    current_member_roles: list[str] = []
    if configured_present:
        account_groups, account_groups_check = single_page(
            f"/accounts/{configured_account}/tokens/permission_groups",
            email,
            global_key,
        )
        account_tokens, account_tokens_check = paginated(
            f"/accounts/{configured_account}/tokens", email, global_key
        )
        del account_tokens
        members, members_check = paginated(
            f"/accounts/{configured_account}/members",
            email,
            global_key,
            {"status": "accepted"},
        )
        current_member = next(
            (
                row
                for row in members
                if str(row.get("email", "")).lower() == email.lower()
                or (
                    isinstance(row.get("user"), dict)
                    and str(row["user"].get("email", "")).lower() == email.lower()
                )
            ),
            None,
        )
        if isinstance(current_member, dict):
            current_member_roles = sorted(
                str(role.get("name", ""))
                for role in current_member.get("roles", [])
                if isinstance(role, dict) and role.get("name")
            )
    account_permissions = find_permission_groups(account_groups)

    user_groups_complete = all(row["present"] for row in user_permissions.values())
    account_groups_complete = all(
        row["present"] for row in account_permissions.values()
    )
    target_ready = bool(resolved and resolved["accountRef"] == "configured")
    administrative_role = any(
        "administrator" in role.lower() or "super admin" in role.lower()
        for role in current_member_roles
    )
    account_create_authorization_inferred = bool(
        members_check.get("ready") and administrative_role
    )
    account_token_automatable = bool(
        target_ready
        and account_groups_check.get("ready")
        and account_tokens_check.get("ready")
        and account_groups_complete
        and account_create_authorization_inferred
    )
    user_token_automatable = bool(
        target_ready
        and user_groups_check.get("ready")
        and user_tokens_check.get("ready")
        and user_groups_complete
    )
    preferred_method = (
        "account_owned_api_token"
        if account_token_automatable
        else "user_api_token"
        if user_token_automatable
        else None
    )

    result: dict[str, Any] = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "CloudflareReadOnlyInventory",
        "readOnly": True,
        "authentication": {
            "emailRefPresent": True,
            "globalApiKeyRefPresent": True,
            "valuesEmitted": False,
        },
        "accounts": {
            "check": accounts_check,
            "count": len(accounts),
            "configuredAccountPresent": configured_present,
            "items": [
                {
                    "ref": ref,
                    "configured": ref == "configured",
                    "activeZoneCount": sum(
                        row["accountRef"] == ref for row in zone_rows
                    ),
                }
                for ref in sorted(set(refs.values()))
            ],
        },
        "zones": {
            "check": zones_check,
            "count": len(zone_rows),
            "items": zone_rows,
        },
        "candidateResolution": {
            "present": bool(normalized_candidate),
            "validHostname": candidate_valid,
            "resolved": bool(resolved),
            "exactZone": exact,
            "containingActiveZone": resolved["name"] if resolved else None,
            "accountRef": resolved["accountRef"] if resolved else None,
            "scopedTokenNotFoundReason": not_found_reason,
        },
        "tokenAutomation": {
            "mutationPerformed": False,
            "createAuthorizationProvenByMutation": False,
            "createAuthorizationInferredFromAdministrativeMembership": account_create_authorization_inferred,
            "globalKeyCarriesCurrentUserPermissions": True,
            "preferredMethod": preferred_method,
            "accountOwnedToken": {
                "automatable": account_token_automatable,
                "currentUserMembershipCheck": members_check,
                "currentUserAdministrativeRole": administrative_role,
                "currentUserRoleNames": current_member_roles,
                "permissionGroupsCheck": account_groups_check,
                "tokenManagementReadCheck": account_tokens_check,
                "requiredPermissions": account_permissions,
            },
            "userToken": {
                "automatable": user_token_automatable,
                "permissionGroupsCheck": user_groups_check,
                "tokenManagementReadCheck": user_tokens_check,
                "requiredPermissions": user_permissions,
            },
            "recommendation": {
                "status": "blocked_until_origins_and_target_zone_are_ready",
                "useGlobalKeyAtRuntime": False,
                "storeCreatedTokenOnlyInRootSecretStore": True,
                "scopeToConfiguredAccountAndResolvedZoneOnly": True,
                "accountPolicy": {
                    "resources": ["com.cloudflare.api.account.<configured-account-id>"],
                    "permissions": [
                        "Cloudflare Tunnel Write",
                        "Access: Apps and Policies Write",
                        "Access: Service Tokens Write",
                    ],
                },
                "zonePolicy": {
                    "resources": ["com.cloudflare.api.account.zone.<resolved-zone-id>"],
                    "permissions": ["Zone Read", "DNS Write"],
                },
            },
        },
    }
    output = args.output.expanduser().resolve()
    write_json(output, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if accounts_check.get("ready") and zones_check.get("ready") else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InventoryError as exc:
        print(
            json.dumps(
                {
                    "apiVersion": "micro-task-engine/v1alpha1",
                    "kind": "CloudflareReadOnlyInventory",
                    "readOnly": True,
                    "ready": False,
                    "blockers": [
                        {"code": "inventory_error", "errorType": type(exc).__name__}
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
        raise SystemExit(3)

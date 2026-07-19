#!/usr/bin/env python3
"""Reconcile the platform's Cloudflare Access applications through its API.

This owns only the Access application records.  The Cloudflare provider keeps
ownership of the tunnel, account-level policies, and service token.  The split
exists because provider v5 can create an Access application but then stall
before persisting its Terraform state; the documented REST endpoint is the
smallest reliable reconciliation surface for this fixed application set.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


API_BASE = "https://api.cloudflare.com/client/v4"
ACCESS_APPS_DOC = (
    "https://developers.cloudflare.com/api/resources/zero_trust/subresources/"
    "access/subresources/applications/methods/create/"
)
UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
APP_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


class AccessReconcileError(RuntimeError):
    """Safe failure code; API bodies and credentials never leave the host."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def secure_file(path: Path, mode: int) -> None:
    try:
        info = path.stat()
    except OSError as exc:
        raise AccessReconcileError("protected_file_missing") from exc
    if (
        not path.is_file()
        or path.is_symlink()
        or stat.S_IMODE(info.st_mode) != mode
        or (os.geteuid() == 0 and (info.st_uid != 0 or info.st_gid != 0))
    ):
        raise AccessReconcileError("protected_file_unsafe")


def read_env(path: Path) -> dict[str, str]:
    secure_file(path, 0o600)
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        if not raw or raw.startswith("#"):
            continue
        if "=" not in raw:
            raise AccessReconcileError("canonical_environment_invalid")
        key, value = raw.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise AccessReconcileError("canonical_environment_invalid")
        values[key] = value
    if not values.get("CLOUDFLARE_API_TOKEN"):
        raise AccessReconcileError("cloudflare_api_token_missing")
    return values


def read_tfvars(path: Path) -> dict[str, Any]:
    secure_file(path, 0o600)
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise AccessReconcileError("cloudflare_tfvars_invalid") from exc
    if not isinstance(payload, dict):
        raise AccessReconcileError("cloudflare_tfvars_invalid")
    return payload


def normalized(value: Any) -> str:
    return str(value).strip().lower().rstrip(".")


def desired_contract(
    tfvars: dict[str, Any],
    human_policy_id: str | None,
    service_policy_ids: dict[str, str],
) -> dict[str, Any]:
    account_id = str(tfvars.get("account_id", ""))
    apps = tfvars.get("apps")
    human_duration = str(tfvars.get("human_session_duration", ""))
    if (
        not re.fullmatch(r"[0-9a-fA-F]{32}", account_id)
        or not isinstance(apps, dict)
        or not apps
        or not re.fullmatch(r"[1-9][0-9]*(?:ms|s|m|h)", human_duration)
        or not isinstance(service_policy_ids, dict)
    ):
        raise AccessReconcileError("cloudflare_access_desired_contract_invalid")
    desired: dict[str, dict[str, Any]] = {}
    hostnames: set[str] = set()
    for app_id, row in sorted(apps.items()):
        if not APP_ID.fullmatch(str(app_id)) or not isinstance(row, dict):
            raise AccessReconcileError("cloudflare_access_desired_contract_invalid")
        hostname = normalized(row.get("hostname"))
        access_class = str(row.get("access_class", ""))
        if (
            not hostname
            or hostname in hostnames
            or access_class not in {"human", "service"}
        ):
            raise AccessReconcileError("cloudflare_access_desired_contract_invalid")
        policy_id = (
            human_policy_id
            if access_class == "human"
            else service_policy_ids.get(str(app_id))
        )
        if not isinstance(policy_id, str) or not UUID.fullmatch(policy_id):
            raise AccessReconcileError("cloudflare_access_policy_binding_missing")
        payload: dict[str, Any] = {
            "name": f"MTE {app_id}" + (" service" if access_class == "service" else ""),
            "domain": hostname,
            "type": "self_hosted",
            "destinations": [{"type": "public", "uri": hostname}],
            "app_launcher_visible": access_class == "human",
            "enable_binding_cookie": True,
            "http_only_cookie_attribute": True,
            "same_site_cookie_attribute": "strict",
            "policies": [{"id": policy_id, "precedence": 1}],
        }
        if access_class == "human":
            payload["session_duration"] = human_duration
        else:
            payload["service_auth_401_redirect"] = True
        desired[str(app_id)] = {"accessClass": access_class, "payload": payload}
        hostnames.add(hostname)
    service_app_ids = {
        app_id for app_id, row in desired.items() if row["accessClass"] == "service"
    }
    if set(service_policy_ids) != service_app_ids:
        raise AccessReconcileError("cloudflare_access_policy_binding_mismatch")
    return {"accountId": account_id.lower(), "apps": desired}


def relevant_shape(row: dict[str, Any]) -> dict[str, Any]:
    destinations = row.get("destinations")
    policies = row.get("policies")
    app_launcher_visible = bool(row.get("app_launcher_visible", False))
    return {
        "name": str(row.get("name", "")),
        "domain": normalized(row.get("domain")),
        "type": str(row.get("type", "")),
        "destinations": sorted(
            [
                {"type": str(item.get("type", "")), "uri": normalized(item.get("uri"))}
                for item in destinations
                if isinstance(item, dict)
            ],
            key=lambda item: (item["type"], item["uri"]),
        )
        if isinstance(destinations, list)
        else [],
        "app_launcher_visible": app_launcher_visible,
        "enable_binding_cookie": bool(row.get("enable_binding_cookie", False)),
        "http_only_cookie_attribute": bool(
            row.get("http_only_cookie_attribute", False)
        ),
        "same_site_cookie_attribute": str(row.get("same_site_cookie_attribute", "")),
        # Cloudflare returns its default session duration on non-human apps
        # even though it has no authorization effect for a service-token
        # policy.  Keep the human session explicit and ignore that API-only
        # default for service applications.
        "session_duration": (
            str(row.get("session_duration", "")) if app_launcher_visible else ""
        ),
        "service_auth_401_redirect": bool(row.get("service_auth_401_redirect", False)),
        "policies": sorted(
            [
                {"id": str(item.get("id", "")), "precedence": item.get("precedence")}
                for item in policies
                if isinstance(item, dict)
            ],
            key=lambda item: (item["id"], str(item["precedence"])),
        )
        if isinstance(policies, list)
        else [],
    }


def expected_shape(payload: dict[str, Any]) -> dict[str, Any]:
    return relevant_shape(payload)


def matches_identity(row: dict[str, Any], payload: dict[str, Any]) -> bool:
    return (
        str(row.get("name", "")) == payload["name"]
        and normalized(row.get("domain")) == payload["domain"]
        and bool(row.get("id"))
    )


def access_plan(rows: list[dict[str, Any]], contract: dict[str, Any]) -> dict[str, Any]:
    creates: list[dict[str, Any]] = []
    updates: list[tuple[str, dict[str, Any]]] = []
    deletes: list[str] = []
    for app_id, desired in contract["apps"].items():
        payload = desired["payload"]
        matched = sorted(
            (row for row in rows if matches_identity(row, payload)),
            key=lambda row: str(row["id"]),
        )
        if not matched:
            creates.append(payload)
            continue
        primary, *duplicates = matched
        if relevant_shape(primary) != expected_shape(payload):
            updates.append((str(primary["id"]), payload))
        deletes.extend(str(row["id"]) for row in duplicates)
    return {"creates": creates, "updates": updates, "deletes": sorted(deletes)}


def verify_inventory(rows: list[dict[str, Any]], contract: dict[str, Any]) -> None:
    for desired in contract["apps"].values():
        payload = desired["payload"]
        matched = [row for row in rows if matches_identity(row, payload)]
        if len(matched) != 1 or relevant_shape(matched[0]) != expected_shape(payload):
            raise AccessReconcileError("cloudflare_access_postcondition_drift")


class CloudflareAccessApi:
    def __init__(self, token: str) -> None:
        self.token = token

    def request(
        self, method: str, path: str, payload: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            API_BASE + path,
            data=data,
            method=method,
            headers={
                "Authorization": "Bearer " + self.token,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = json.loads(response.read().decode())
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise AccessReconcileError("cloudflare_access_api_failed") from exc
        if not isinstance(body, dict) or body.get("success") is not True:
            raise AccessReconcileError("cloudflare_access_api_failed")
        return body

    def applications(self, account_id: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        page = 1
        while True:
            query = urllib.parse.urlencode({"page": page, "per_page": 100})
            payload = self.request("GET", f"/accounts/{account_id}/access/apps?{query}")
            result = payload.get("result")
            if not isinstance(result, list):
                raise AccessReconcileError("cloudflare_access_inventory_invalid")
            rows.extend(row for row in result if isinstance(row, dict))
            info = payload.get("result_info")
            pages = (
                int(info.get("total_pages", page)) if isinstance(info, dict) else page
            )
            if page >= pages or not result:
                return rows
            page += 1

    def create(self, account_id: str, payload: dict[str, Any]) -> None:
        self.request("POST", f"/accounts/{account_id}/access/apps", payload)

    def update(self, account_id: str, app_id: str, payload: dict[str, Any]) -> None:
        self.request("PUT", f"/accounts/{account_id}/access/apps/{app_id}", payload)

    def delete(self, account_id: str, app_id: str) -> None:
        self.request("DELETE", f"/accounts/{account_id}/access/apps/{app_id}")


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


def reconcile(
    action: str,
    env_file: Path,
    tfvars_file: Path,
    human_policy_id: str | None,
    service_policy_ids: dict[str, str],
    output: Path,
    *,
    api_class: type[CloudflareAccessApi] = CloudflareAccessApi,
) -> dict[str, Any]:
    values = read_env(env_file)
    contract = desired_contract(
        read_tfvars(tfvars_file), human_policy_id, service_policy_ids
    )
    api = api_class(values["CLOUDFLARE_API_TOKEN"])
    before = api.applications(contract["accountId"])
    plan = access_plan(before, contract)
    change_count = len(plan["creates"]) + len(plan["updates"]) + len(plan["deletes"])
    if action == "verify" and change_count:
        raise AccessReconcileError("cloudflare_access_drift_detected")
    if action == "apply":
        for payload in plan["creates"]:
            api.create(contract["accountId"], payload)
        for app_id, payload in plan["updates"]:
            api.update(contract["accountId"], app_id, payload)
        for app_id in plan["deletes"]:
            api.delete(contract["accountId"], app_id)
    after = api.applications(contract["accountId"]) if action == "apply" else before
    if action != "plan":
        verify_inventory(after, contract)
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "CloudflareAccessReconcileEvidence",
        "status": "planned" if action == "plan" else "passed",
        "ok": True,
        "generatedAt": utcnow(),
        "action": action,
        "canonicalSourceSha256": sha256_file(env_file),
        "tfvarsSha256": sha256_file(tfvars_file),
        "producerPath": str(Path(__file__).resolve()),
        "producerSha256": sha256_file(Path(__file__).resolve()),
        "desiredApplicationCount": len(contract["apps"]),
        "accessClassBindingSha256": canonical_sha256(
            {key: value["accessClass"] for key, value in contract["apps"].items()}
        ),
        "plannedCreateCount": len(plan["creates"]),
        "plannedUpdateCount": len(plan["updates"]),
        "plannedDuplicateDeleteCount": len(plan["deletes"]),
        "reconciledExactly": action != "plan",
        "officialContracts": [ACCESS_APPS_DOC],
        "secretValuesPrinted": False,
    }
    atomic_json(output, payload)
    return payload


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("action", choices=("plan", "apply", "verify"))
    result.add_argument("--env-file", type=Path, required=True)
    result.add_argument("--tfvars", type=Path, required=True)
    result.add_argument("--human-policy-id-json", required=True)
    result.add_argument("--service-policy-ids-json", required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        try:
            human_policy_id = json.loads(args.human_policy_id_json)
            service_policy_ids = json.loads(args.service_policy_ids_json)
        except json.JSONDecodeError as exc:
            raise AccessReconcileError(
                "cloudflare_access_policy_outputs_invalid"
            ) from exc
        if human_policy_id is not None and not isinstance(human_policy_id, str):
            raise AccessReconcileError("cloudflare_access_policy_outputs_invalid")
        if not isinstance(service_policy_ids, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in service_policy_ids.items()
        ):
            raise AccessReconcileError("cloudflare_access_policy_outputs_invalid")
        payload = reconcile(
            args.action,
            args.env_file.expanduser().resolve(),
            args.tfvars.expanduser().resolve(),
            human_policy_id,
            service_policy_ids,
            args.output.expanduser().resolve(),
        )
    except AccessReconcileError as exc:
        payload = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "CloudflareAccessReconcileEvidence",
            "status": "failed",
            "ok": False,
            "errorCode": exc.code,
            "secretValuesPrinted": False,
        }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

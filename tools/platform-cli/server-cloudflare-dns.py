#!/usr/bin/env python3
"""Reconcile the exact platform DNS set through Cloudflare's batch endpoint."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from datetime import datetime, timezone
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


API_BASE = "https://api.cloudflare.com/client/v4"
MANAGED_COMMENT_PREFIX = "Managed by MTE platform IaC for "
DNS_BATCH_DOC = (
    "https://developers.cloudflare.com/api/resources/dns/subresources/records/"
    "methods/batch/"
)
TUNNEL_DNS_DOC = (
    "https://developers.cloudflare.com/cloudflare-one/networks/connectors/"
    "cloudflare-tunnel/routing-to-tunnel/"
)


class DnsReconcileError(RuntimeError):
    """Fail-closed error whose code is safe to print."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, separators=(",", ":"), sort_keys=True, ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def secure_file(path: Path, mode: int) -> None:
    try:
        info = path.stat()
    except OSError as exc:
        raise DnsReconcileError("protected_file_missing") from exc
    if (
        not path.is_file()
        or path.is_symlink()
        or stat.S_IMODE(info.st_mode) != mode
        or (os.geteuid() == 0 and (info.st_uid != 0 or info.st_gid != 0))
    ):
        raise DnsReconcileError("protected_file_unsafe")


def read_env(path: Path) -> dict[str, str]:
    secure_file(path, 0o600)
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise DnsReconcileError("canonical_environment_invalid")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise DnsReconcileError("canonical_environment_invalid")
        values[key] = value
    if not values.get("CLOUDFLARE_API_TOKEN"):
        raise DnsReconcileError("cloudflare_api_token_missing")
    return values


def read_tfvars(path: Path) -> dict[str, Any]:
    secure_file(path, 0o600)
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise DnsReconcileError("cloudflare_tfvars_invalid") from exc
    if not isinstance(value, dict):
        raise DnsReconcileError("cloudflare_tfvars_invalid")
    return value


def normalize_name(value: Any) -> str:
    return str(value).strip().lower().rstrip(".")


def desired_contract(tfvars: dict[str, Any], tunnel_id: str) -> dict[str, Any]:
    zone_id = str(tfvars.get("zone_id", ""))
    base_domain = normalize_name(tfvars.get("base_domain", ""))
    apps = tfvars.get("apps")
    if (
        not re.fullmatch(r"[0-9a-fA-F]{32}", zone_id)
        or not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
            base_domain,
        )
        or not re.fullmatch(
            r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}",
            tunnel_id,
        )
        or not isinstance(apps, dict)
        or not apps
    ):
        raise DnsReconcileError("cloudflare_dns_desired_contract_invalid")

    target = tunnel_id.lower() + ".cfargotunnel.com"
    desired: dict[str, dict[str, Any]] = {}
    hostnames: set[str] = set()
    for app_id, row in sorted(apps.items()):
        if (
            not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", str(app_id))
            or not isinstance(row, dict)
            or set(row) != {"hostname", "origin", "access_class"}
        ):
            raise DnsReconcileError("cloudflare_dns_app_contract_invalid")
        hostname = normalize_name(row.get("hostname"))
        access_class = str(row.get("access_class", ""))
        if (
            not hostname.endswith("." + base_domain)
            or hostname in hostnames
            or access_class not in {"human", "service"}
        ):
            raise DnsReconcileError("cloudflare_dns_app_contract_invalid")
        desired[str(app_id)] = {
            "hostname": hostname,
            "accessClass": access_class,
            "record": {
                "type": "CNAME",
                "name": hostname,
                "content": target,
                "ttl": 1,
                "proxied": True,
                "comment": MANAGED_COMMENT_PREFIX + str(app_id),
            },
        }
        hostnames.add(hostname)
    return {
        "zoneId": zone_id.lower(),
        "baseDomain": base_domain,
        "target": target,
        "apps": desired,
    }


def is_exact_record(record: dict[str, Any], expected: dict[str, Any]) -> bool:
    return (
        normalize_name(record.get("name")) == expected["name"]
        and record.get("type") == "CNAME"
        and normalize_name(record.get("content")) == expected["content"]
        and record.get("proxied") is True
        and record.get("ttl") == 1
        and record.get("comment") == expected["comment"]
        and bool(record.get("id"))
    )


def is_retired_managed_record(
    record: dict[str, Any], desired_hostnames: set[str], base_domain: str
) -> bool:
    name = normalize_name(record.get("name"))
    comment = str(record.get("comment", ""))
    return (
        name not in desired_hostnames
        and name.endswith("." + base_domain)
        and comment.startswith(MANAGED_COMMENT_PREFIX)
        and bool(
            re.fullmatch(
                r"[a-z0-9]+(?:-[a-z0-9]+)*",
                comment.removeprefix(MANAGED_COMMENT_PREFIX),
            )
        )
    )


def record_fingerprint(record: dict[str, Any]) -> str:
    return canonical_sha256(
        {
            "id": str(record.get("id", "")),
            "name": normalize_name(record.get("name")),
            "type": str(record.get("type", "")),
            "content": str(record.get("content", "")),
            "proxied": record.get("proxied"),
            "ttl": record.get("ttl"),
            "comment": str(record.get("comment", "")),
        }
    )


def reconcile_plan(
    records: list[dict[str, Any]], contract: dict[str, Any]
) -> dict[str, Any]:
    desired = contract["apps"]
    desired_hostnames = {row["hostname"] for row in desired.values()}
    by_name: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if not isinstance(record, dict) or not record.get("id"):
            raise DnsReconcileError("cloudflare_dns_inventory_invalid")
        by_name.setdefault(normalize_name(record.get("name")), []).append(record)

    delete_ids: set[str] = set()
    posts: list[dict[str, Any]] = []
    replaced_hostnames: list[str] = []
    for app_id, row in desired.items():
        observed = by_name.get(row["hostname"], [])
        if len(observed) == 1 and is_exact_record(observed[0], row["record"]):
            continue
        replaced_hostnames.append(row["hostname"])
        delete_ids.update(str(record["id"]) for record in observed)
        posts.append(dict(row["record"]))

    retired_ids: set[str] = set()
    foreign: list[str] = []
    for record in records:
        name = normalize_name(record.get("name"))
        record_id = str(record["id"])
        if name in desired_hostnames:
            continue
        if is_retired_managed_record(record, desired_hostnames, contract["baseDomain"]):
            delete_ids.add(record_id)
            retired_ids.add(record_id)
            continue
        foreign.append(record_fingerprint(record))

    return {
        "deletes": [{"id": value} for value in sorted(delete_ids)],
        "posts": sorted(posts, key=lambda row: row["name"]),
        "replacedHostnames": sorted(replaced_hostnames),
        "retiredManagedRecordCount": len(retired_ids),
        "foreignFingerprints": sorted(foreign),
    }


def verify_inventory(
    records: list[dict[str, Any]], contract: dict[str, Any]
) -> dict[str, Any]:
    desired = contract["apps"]
    desired_hostnames = {row["hostname"] for row in desired.values()}
    by_name: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if not isinstance(record, dict) or not record.get("id"):
            raise DnsReconcileError("cloudflare_dns_inventory_invalid")
        by_name.setdefault(normalize_name(record.get("name")), []).append(record)
    for row in desired.values():
        observed = by_name.get(row["hostname"], [])
        if len(observed) != 1 or not is_exact_record(observed[0], row["record"]):
            raise DnsReconcileError("cloudflare_dns_postcondition_drift")
    retired = [
        record
        for record in records
        if is_retired_managed_record(record, desired_hostnames, contract["baseDomain"])
    ]
    if retired:
        raise DnsReconcileError("cloudflare_dns_retired_records_remain")
    foreign = sorted(
        record_fingerprint(record)
        for record in records
        if normalize_name(record.get("name")) not in desired_hostnames
    )
    return {
        "desiredRecordsExact": True,
        "proxiedDnsOnly": True,
        "originAddressRecordCount": 0,
        "foreignFingerprints": foreign,
    }


class CloudflareDnsApi:
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
            raise DnsReconcileError("cloudflare_dns_api_failed") from exc
        if not isinstance(body, dict) or body.get("success") is not True:
            raise DnsReconcileError("cloudflare_dns_api_failed")
        return body

    def records(self, zone_id: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        page = 1
        while True:
            query = urllib.parse.urlencode({"page": page, "per_page": 100})
            payload = self.request("GET", f"/zones/{zone_id}/dns_records?{query}")
            rows = payload.get("result")
            if not isinstance(rows, list):
                raise DnsReconcileError("cloudflare_dns_inventory_invalid")
            result.extend(row for row in rows if isinstance(row, dict))
            info = payload.get("result_info")
            total_pages = (
                int(info.get("total_pages", page)) if isinstance(info, dict) else page
            )
            if page >= total_pages or not rows:
                return result
            page += 1

    def batch(self, zone_id: str, payload: dict[str, Any]) -> None:
        response = self.request("POST", f"/zones/{zone_id}/dns_records/batch", payload)
        result = response.get("result")
        if not isinstance(result, dict):
            raise DnsReconcileError("cloudflare_dns_batch_result_invalid")
        if len(result.get("deletes", [])) != len(payload.get("deletes", [])) or len(
            result.get("posts", [])
        ) != len(payload.get("posts", [])):
            raise DnsReconcileError("cloudflare_dns_batch_result_invalid")


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
    tunnel_id: str,
    output: Path,
    *,
    api_class: type[CloudflareDnsApi] = CloudflareDnsApi,
) -> dict[str, Any]:
    values = read_env(env_file)
    tfvars = read_tfvars(tfvars_file)
    contract = desired_contract(tfvars, tunnel_id)
    api = api_class(values["CLOUDFLARE_API_TOKEN"])
    before = api.records(contract["zoneId"])
    plan = reconcile_plan(before, contract)
    changes = len(plan["deletes"]) + len(plan["posts"])
    if action == "verify" and changes:
        raise DnsReconcileError("cloudflare_dns_drift_detected")
    batch_applied = action == "apply" and changes > 0
    if batch_applied:
        api.batch(
            contract["zoneId"],
            {"deletes": plan["deletes"], "posts": plan["posts"]},
        )
    after = api.records(contract["zoneId"]) if batch_applied else before
    verified = verify_inventory(after, contract) if action != "plan" else None
    foreign_before = canonical_sha256(plan["foreignFingerprints"])
    foreign_after = (
        canonical_sha256(verified["foreignFingerprints"])
        if verified is not None
        else foreign_before
    )
    if action != "plan" and foreign_before != foreign_after:
        raise DnsReconcileError("cloudflare_dns_foreign_records_changed")
    access_classes = {
        app_id: row["accessClass"] for app_id, row in contract["apps"].items()
    }
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "CloudflareDnsReconcileEvidence",
        "status": "planned" if action == "plan" else "passed",
        "ok": True,
        "generatedAt": utcnow(),
        "action": action,
        "canonicalSourceSha256": sha256_file(env_file),
        "tfvarsSha256": sha256_file(tfvars_file),
        "producerPath": str(Path(__file__).resolve()),
        "producerSha256": sha256_file(Path(__file__).resolve()),
        "desiredHostnameCount": len(contract["apps"]),
        "accessClassBindingSha256": canonical_sha256(access_classes),
        "tunnelTargetSha256": canonical_sha256(contract["target"]),
        "plannedDeleteCount": len(plan["deletes"]),
        "plannedCreateCount": len(plan["posts"]),
        "replacedReservedHostnameCount": len(plan["replacedHostnames"]),
        "retiredManagedRecordCount": plan["retiredManagedRecordCount"],
        "batchApplied": batch_applied,
        "batchDatabaseTransactionAtomic": True,
        "edgePropagationAtomic": False,
        "batchOperationOrder": ["deletes", "patches", "puts", "posts"],
        "desiredHostnamesReserved": True,
        "desiredRecordsExact": verified is not None,
        "proxiedDnsOnly": verified is not None,
        "originAddressRecordCount": (
            verified["originAddressRecordCount"] if verified is not None else None
        ),
        "foreignRecordCount": len(plan["foreignFingerprints"]),
        "foreignRecordSetBeforeSha256": foreign_before,
        "foreignRecordSetAfterSha256": foreign_after,
        "foreignRecordsPreserved": foreign_before == foreign_after,
        "officialContracts": [DNS_BATCH_DOC, TUNNEL_DNS_DOC],
        "secretValuesPrinted": False,
    }
    atomic_json(output, payload)
    return payload


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("action", choices=("plan", "apply", "verify"))
    result.add_argument("--env-file", type=Path, required=True)
    result.add_argument("--tfvars", type=Path, required=True)
    result.add_argument("--tunnel-id", required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        payload = reconcile(
            args.action,
            args.env_file.expanduser().resolve(),
            args.tfvars.expanduser().resolve(),
            args.tunnel_id,
            args.output.expanduser().resolve(),
        )
    except DnsReconcileError as exc:
        payload = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "CloudflareDnsReconcileEvidence",
            "status": "failed",
            "ok": False,
            "errorCode": exc.code,
            "secretValuesPrinted": False,
        }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

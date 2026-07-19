#!/usr/bin/env python3
"""Atomically reconcile Terraform-issued Cloudflare runtime credentials."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from datetime import datetime, timezone
import stat
from typing import Iterator


SECRET_ROOT = Path("/root/.config/mte-secrets")
SOURCE = SECRET_ROOT / "platform.env"
LOCK = SECRET_ROOT / ".platform-env.lock"
TUNNEL_KEY = "CLOUDFLARE_TUNNEL_TOKEN"
LEGACY_SERVICE_KEYS = (
    "CLOUDFLARE_ACCESS_SERVICE_TOKEN_ID",
    "CLOUDFLARE_ACCESS_CLIENT_ID",
    "CLOUDFLARE_ACCESS_CLIENT_SECRET",
    "CLOUDFLARE_ACCESS_EXPIRES_AT",
)
SERVICE_FIELDS = ("id", "client_id", "client_secret", "expires_at")
SERVICE_KEY = re.compile(
    r"^CLOUDFLARE_ACCESS_ROUTE_([A-Z0-9_]+?)_(CLIENT_SECRET|CLIENT_ID|EXPIRES_AT|ID)$"
)


class RuntimeErrorSafe(RuntimeError):
    pass


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def secure_root_file(path: Path, mode: int) -> None:
    try:
        info = path.stat()
    except OSError as exc:
        raise RuntimeErrorSafe(f"required protected file is missing: {path}") from exc
    if (
        not path.is_file()
        or path.is_symlink()
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise RuntimeErrorSafe(f"protected file ownership or mode is unsafe: {path}")


def producer_metadata() -> dict[str, object]:
    path = Path(__file__).resolve()
    secure_root_file(path, 0o700)
    return {
        "producerPath": str(path),
        "producerSha256": sha256_file(path),
        "producerOwner": "root:root",
        "producerMode": "0700",
    }


def parse_expiry(value: str) -> datetime:
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeErrorSafe("Cloudflare service token expiry is invalid") from exc
    if moment.tzinfo is None:
        raise RuntimeErrorSafe("Cloudflare service token expiry is not timezone-aware")
    return moment.astimezone(timezone.utc)


def route_prefix(app_id: str) -> str:
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", app_id):
        raise RuntimeErrorSafe("Cloudflare service route ID is invalid")
    return "CLOUDFLARE_ACCESS_ROUTE_" + app_id.upper().replace("-", "_")


def service_fields(service: dict[str, object]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for app_id, raw in sorted(service.items()):
        if not isinstance(raw, dict) or set(raw) != set(SERVICE_FIELDS):
            raise RuntimeErrorSafe("Cloudflare Access service token output is missing")
        prefix = route_prefix(app_id)
        for field in SERVICE_FIELDS:
            key = prefix + "_" + field.upper()
            fields[key] = str(raw.get(field, "")).strip()
    return fields


def runtime_contract(
    values: dict[str, str], required_service_ids: set[str] | None = None
) -> dict[str, object]:
    route_keys = sorted(key for key in values if SERVICE_KEY.fullmatch(key))
    grouped: dict[str, dict[str, str]] = {}
    for key in route_keys:
        match = SERVICE_KEY.fullmatch(key)
        assert match is not None
        grouped.setdefault(match.group(1), {})[match.group(2)] = values[key]
    if not values.get(TUNNEL_KEY) or any(
        set(fields) != {"ID", "CLIENT_ID", "CLIENT_SECRET", "EXPIRES_AT"}
        for fields in grouped.values()
    ):
        raise RuntimeErrorSafe("Cloudflare runtime credential set is incomplete")
    if len(values[TUNNEL_KEY]) < 40 or any(
        "\n" in values[key] or "\r" in values[key] for key in [TUNNEL_KEY, *route_keys]
    ):
        raise RuntimeErrorSafe("Cloudflare runtime credential shape is invalid")
    for fields in grouped.values():
        if (
            len(fields["ID"]) < 16
            or len(fields["CLIENT_ID"]) < 16
            or len(fields["CLIENT_SECRET"]) < 32
            or (
                parse_expiry(fields["EXPIRES_AT"]) - datetime.now(timezone.utc)
            ).total_seconds()
            <= 300
        ):
            raise RuntimeErrorSafe("Cloudflare service token is invalid or near expiry")
    if required_service_ids is not None:
        expected_prefixes = {
            route_prefix(app_id).removeprefix("CLOUDFLARE_ACCESS_ROUTE_")
            for app_id in required_service_ids
        }
        if set(grouped) != expected_prefixes:
            raise RuntimeErrorSafe("required Cloudflare service route token is absent")
    return {
        "ready": True,
        "presentKeyCount": 1 + len(route_keys),
        "tunnelCredentialPresent": True,
        "serviceRouteCredentialCount": len(grouped),
        "serviceTokenExpiryVerified": True,
        "secretValuesPrinted": False,
    }


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    secure_root_file(path, 0o600)
    for raw in path.read_text().splitlines():
        if not raw or raw.startswith("#"):
            continue
        if "=" not in raw:
            raise RuntimeErrorSafe(
                "canonical platform.env contains an invalid assignment"
            )
        key, value = raw.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise RuntimeErrorSafe("canonical platform.env contains an invalid key")
        values[key] = value
    return values


@contextmanager
def locked() -> Iterator[None]:
    SECRET_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    root_stat = SECRET_ROOT.stat()
    if (
        SECRET_ROOT.is_symlink()
        or root_stat.st_uid != 0
        or root_stat.st_gid != 0
        or stat.S_IMODE(root_stat.st_mode) != 0o700
    ):
        raise RuntimeErrorSafe("Cloudflare secret root ownership or mode is unsafe")
    descriptor = os.open(
        LOCK,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        lock_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lock_stat.st_mode)
            or lock_stat.st_uid != 0
            or lock_stat.st_gid != 0
        ):
            raise RuntimeErrorSafe("Cloudflare runtime lock owner is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def atomic_env(values: dict[str, str]) -> str:
    descriptor, temporary = tempfile.mkstemp(prefix="platform.env.", dir=SECRET_ROOT)
    try:
        with os.fdopen(descriptor, "w") as handle:
            for key in sorted(values):
                handle.write(f"{key}={values[key]}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, SOURCE)
        SOURCE.chmod(0o600)
        secure_root_file(SOURCE, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return hashlib.sha256(SOURCE.read_bytes()).hexdigest()


def required_routes(tfvars_file: Path) -> set[str]:
    secure_root_file(tfvars_file, 0o600)
    try:
        payload = json.loads(tfvars_file.read_text())
    except json.JSONDecodeError as exc:
        raise RuntimeErrorSafe("Cloudflare tfvars are invalid") from exc
    apps = payload.get("apps") if isinstance(payload, dict) else None
    if not isinstance(apps, dict) or not apps:
        raise RuntimeErrorSafe("Cloudflare tfvars app set is invalid")
    return {
        str(app_id)
        for app_id, row in apps.items()
        if isinstance(row, dict) and row.get("access_class") == "service"
    }


def reconcile(
    tunnel_file: Path, service_file: Path, tfvars_file: Path | None = None
) -> dict[str, object]:
    secure_root_file(tunnel_file, 0o600)
    secure_root_file(service_file, 0o600)
    tunnel = tunnel_file.read_text().strip()
    try:
        service = json.loads(service_file.read_text())
    except json.JSONDecodeError as exc:
        raise RuntimeErrorSafe(
            "Cloudflare Access service token output is invalid"
        ) from exc
    if len(tunnel) < 40 or "\n" in tunnel or "\r" in tunnel:
        raise RuntimeErrorSafe("Cloudflare tunnel token output is invalid")
    if not isinstance(service, dict):
        raise RuntimeErrorSafe("Cloudflare Access service token output is missing")
    required = required_routes(tfvars_file) if tfvars_file is not None else set(service)
    if set(service) != required:
        raise RuntimeErrorSafe("required Cloudflare service route token is absent")
    fields = {TUNNEL_KEY: tunnel, **service_fields(service)}
    if any(not value or "\n" in value or "\r" in value for value in fields.values()):
        raise RuntimeErrorSafe("Cloudflare runtime credential output is incomplete")
    contract = runtime_contract(fields, required)
    with locked():
        values = parse_env(SOURCE)
        for key in [
            *LEGACY_SERVICE_KEYS,
            *(key for key in values if SERVICE_KEY.fullmatch(key)),
        ]:
            values.pop(key, None)
        values.update(fields)
        digest = atomic_env(values)
    return {
        "updated": True,
        "generatedAt": utcnow(),
        "canonicalSourceSha256": digest,
        "updatedKeyCount": len(fields),
        **contract,
        **producer_metadata(),
    }


def status(tfvars_file: Path | None = None) -> dict[str, object]:
    with locked():
        values = parse_env(SOURCE)
        digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    return {
        "generatedAt": utcnow(),
        "canonicalSourceSha256": digest,
        **runtime_contract(
            values,
            required_routes(tfvars_file) if tfvars_file is not None else None,
        ),
        **producer_metadata(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("upsert", "status"))
    parser.add_argument("--tunnel-file", type=Path)
    parser.add_argument("--service-file", type=Path)
    parser.add_argument("--tfvars", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "upsert":
            if args.tunnel_file is None or args.service_file is None:
                raise RuntimeErrorSafe(
                    "upsert requires protected Terraform output files"
                )
            result = reconcile(args.tunnel_file, args.service_file, args.tfvars)
        else:
            result = status(args.tfvars)
    except (OSError, RuntimeErrorSafe) as exc:
        print(
            json.dumps({"ok": False, "errorType": type(exc).__name__}, sort_keys=True)
        )
        raise SystemExit(1) from exc
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

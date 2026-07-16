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
RUNTIME_KEYS = (
    "CLOUDFLARE_TUNNEL_TOKEN",
    "CLOUDFLARE_ACCESS_SERVICE_TOKEN_ID",
    "CLOUDFLARE_ACCESS_CLIENT_ID",
    "CLOUDFLARE_ACCESS_CLIENT_SECRET",
    "CLOUDFLARE_ACCESS_EXPIRES_AT",
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


def runtime_contract(values: dict[str, str]) -> dict[str, object]:
    missing = sorted(key for key in RUNTIME_KEYS if not values.get(key))
    if missing:
        raise RuntimeErrorSafe("Cloudflare runtime credential set is incomplete")
    if (
        len(values["CLOUDFLARE_TUNNEL_TOKEN"]) < 40
        or len(values["CLOUDFLARE_ACCESS_SERVICE_TOKEN_ID"]) < 16
        or len(values["CLOUDFLARE_ACCESS_CLIENT_ID"]) < 16
        or len(values["CLOUDFLARE_ACCESS_CLIENT_SECRET"]) < 32
        or any("\n" in values[key] or "\r" in values[key] for key in RUNTIME_KEYS)
    ):
        raise RuntimeErrorSafe("Cloudflare runtime credential shape is invalid")
    expires_at = parse_expiry(values["CLOUDFLARE_ACCESS_EXPIRES_AT"])
    if (expires_at - datetime.now(timezone.utc)).total_seconds() <= 300:
        raise RuntimeErrorSafe("Cloudflare service token is expired or near expiry")
    return {
        "ready": True,
        "presentKeys": sorted(RUNTIME_KEYS),
        "tunnelCredentialPresent": True,
        "serviceTokenCredentialPresent": True,
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


def reconcile(tunnel_file: Path, service_file: Path) -> dict[str, object]:
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
    if not isinstance(service, dict) or set(service) != {
        "id",
        "client_id",
        "client_secret",
        "expires_at",
    }:
        raise RuntimeErrorSafe("Cloudflare Access service token output is missing")
    fields = {
        "CLOUDFLARE_TUNNEL_TOKEN": tunnel,
        "CLOUDFLARE_ACCESS_SERVICE_TOKEN_ID": str(service.get("id", "")).strip(),
        "CLOUDFLARE_ACCESS_CLIENT_ID": str(service.get("client_id", "")).strip(),
        "CLOUDFLARE_ACCESS_CLIENT_SECRET": str(
            service.get("client_secret", "")
        ).strip(),
        "CLOUDFLARE_ACCESS_EXPIRES_AT": str(service.get("expires_at", "")).strip(),
    }
    if any(not value or "\n" in value or "\r" in value for value in fields.values()):
        raise RuntimeErrorSafe("Cloudflare runtime credential output is incomplete")
    contract = runtime_contract(fields)
    with locked():
        values = parse_env(SOURCE)
        values.update(fields)
        digest = atomic_env(values)
    return {
        "updated": True,
        "generatedAt": utcnow(),
        "canonicalSourceSha256": digest,
        "updatedKeys": sorted(fields),
        **contract,
        **producer_metadata(),
    }


def status() -> dict[str, object]:
    with locked():
        values = parse_env(SOURCE)
        digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    return {
        "generatedAt": utcnow(),
        "canonicalSourceSha256": digest,
        **runtime_contract(values),
        **producer_metadata(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("upsert", "status"))
    parser.add_argument("--tunnel-file", type=Path)
    parser.add_argument("--service-file", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "upsert":
            if args.tunnel_file is None or args.service_file is None:
                raise RuntimeErrorSafe(
                    "upsert requires protected Terraform output files"
                )
            result = reconcile(args.tunnel_file, args.service_file)
        else:
            result = status()
    except (OSError, RuntimeErrorSafe) as exc:
        print(
            json.dumps({"ok": False, "errorType": type(exc).__name__}, sort_keys=True)
        )
        raise SystemExit(1) from exc
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

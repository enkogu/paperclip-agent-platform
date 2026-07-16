#!/usr/bin/env python3
"""Generate and split server-side secrets without printing values."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys


ROOT = Path(os.environ.get("MTE_PLATFORM_ROOT", "/opt/mte-platform"))
SECRET_ROOT = Path(os.environ.get("MTE_SECRET_ROOT", "/root/.config/mte-secrets"))
PLATFORM_ENV = SECRET_ROOT / "platform.env"
INTEGRATION_ROOT = SECRET_ROOT / "integrations"
LOCK = SECRET_ROOT / ".platform-env.lock"
CONFIG_RENDERER = ROOT / "bin/server-config.py"
SENSITIVE_KEY_RE = re.compile(
    r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ENCRYPT|JWT|SALT|"
    r"COOKIE|CREDENTIAL|AUTH|WEBHOOK|CONNECTION_STRING)",
    re.IGNORECASE,
)
# One-time bootstrap identity seeds. They are copied into the canonical env
# only when a key is absent; every later run preserves the canonical value.
# Keeping this literal-only group named and separate lets the strict verifier
# distinguish bootstrap seeds from parallel runtime configuration.
BOOTSTRAP_ONLY_DEFAULTS = {
    "DOKPLOY_ADMIN_NAME": "MTE Platform Admin",
    "DOKPLOY_ADMIN_EMAIL": "admin@mte.local",
    "MATTERMOST_ADMIN_EMAIL": "admin@mte.local",
    "MATTERMOST_ADMIN_USERNAME": "mte-admin",
    "MATTERMOST_BOT_USERNAME": "mte-agent-bot",
    "AP_ADMIN_EMAIL": "admin@mte.local",
    "GRAFANA_ADMIN_USER": "admin",
    "MATTERMOST_ALERT_WEBHOOK_URL": "",
    "KESTRA_ADMIN_USER": "admin@mte.local",
    "HERMES_TELEGRAM_BOT_TOKEN": "",
    "HERMES_TELEGRAM_ALLOWED_USERS": "",
    "HERMES_LLM_API_KEY": "",
}


@contextmanager
def config_lock():
    SECRET_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    secure_path(SECRET_ROOT, 0o700)
    with LOCK.open("a+") as handle:
        secure_path(LOCK, 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield


def dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key] = value
    return values


def write_env(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    secure_path(path.parent, 0o700)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text("".join(f"{key}={values[key]}\n" for key in sorted(values)))
    secure_path(temp, 0o600)
    temp.replace(path)
    secure_path(path, 0o600)


def secure_path(path: Path, mode: int) -> None:
    path.chmod(mode)
    if os.geteuid() == 0:
        os.chown(path, 0, 0)


def token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def generated_defaults(profile: str = "postgres-notion") -> dict[str, str]:
    shared = {
        **BOOTSTRAP_ONLY_DEFAULTS,
        "DOKPLOY_ADMIN_PASSWORD": token(),
        "POSTGRES_ADMIN_PASSWORD": token(),
        "MATTERMOST_DB_PASSWORD": token(),
        "MATTERMOST_ADMIN_PASSWORD": token(),
        "FIRECRAWL_DB_PASSWORD": token(),
        "FIRECRAWL_REDIS_PASSWORD": token(),
        "FIRECRAWL_API_KEY": token(36),
        "SEARXNG_SECRET": token(32),
        "SEARXNG_VALKEY_PASSWORD": token(),
        "AP_ENCRYPTION_KEY": secrets.token_hex(16),
        "AP_JWT_SECRET": secrets.token_hex(32),
        "AP_POSTGRES_PASSWORD": token(),
        "AP_REDIS_PASSWORD": token(),
        "AP_ADMIN_PASSWORD": token(),
        "GRAFANA_ADMIN_PASSWORD": token(),
        "KESTRA_DB_PASSWORD": token(),
        "KESTRA_ADMIN_PASSWORD": token(),
        "NINEROUTER_INITIAL_PASSWORD": token(),
        "NINEROUTER_JWT_SECRET": secrets.token_hex(32),
        "NINEROUTER_API_KEY_SECRET": secrets.token_hex(32),
        "NINEROUTER_MACHINE_ID_SALT": secrets.token_hex(24),
        "PAPERCLIP_SERVICE_TOKEN": token(36),
        "KESTRA_SERVICE_TOKEN": token(36),
        "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN": token(36),
        "TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_BEARER_TOKEN": token(36),
        "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN": token(36),
    }
    providers = {
        "postgres-notion": {
            "POSTGREST_DATA_DB_PASSWORD": token(),
            "POSTGREST_AUTHENTICATOR_PASSWORD": token(),
            "POSTGREST_JWT_SECRET": secrets.token_hex(48),
        },
        "baserow-wikijs": {
            "BASEROW_SECRET_KEY": token(48),
            "BASEROW_DB_PASSWORD": token(),
            "BASEROW_REDIS_PASSWORD": token(),
            "BASEROW_ADMIN_PASSWORD": token(),
            "WIKIJS_DB_PASSWORD": token(),
            "WIKIJS_ADMIN_PASSWORD": token(),
        },
        "postgres-postgrest-nocodb-nocodocs": {
            "POSTGREST_DATA_DB_PASSWORD": token(),
            "POSTGREST_AUTHENTICATOR_PASSWORD": token(),
            "POSTGREST_JWT_SECRET": secrets.token_hex(48),
            "NOCODB_META_DB_PASSWORD": token(),
            "NOCODB_DATA_DB_PASSWORD": token(),
            "NOCODB_ADMIN_PASSWORD": token(),
            "NOCODB_JWT_SECRET": secrets.token_hex(48),
        },
    }
    if profile not in providers:
        raise RuntimeError("data_content_profile_unsupported")
    return {**shared, **providers[profile]}


def init() -> dict[str, object]:
    values = dotenv(PLATFORM_ENV)
    created: list[str] = []
    for key, value in generated_defaults(
        values.get("DATA_CONTENT_PROFILE", "postgres-notion") or "postgres-notion"
    ).items():
        if key not in values:
            values[key] = value
            created.append(key)
    write_env(PLATFORM_ENV, values)
    # Remove the pre-SSOT bootstrap sidecar without importing from it. Owner
    # credentials have always been generated into the canonical source first.
    legacy_admin = SECRET_ROOT / "dokploy-admin.env"
    if legacy_admin.exists():
        legacy_admin.unlink()

    # Provisioners add system-generated API tokens to these files. Creating
    # the directory here establishes the ownership/mode before any API call.
    INTEGRATION_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    secure_path(INTEGRATION_ROOT, 0o700)

    manifest = {
        "keys": sorted(values),
        "created": sorted(created),
        "fingerprints": {
            key: hashlib.sha256(value.encode()).hexdigest()[:12]
            for key, value in values.items()
            if value
        },
    }
    path = SECRET_ROOT / "generated-manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    secure_path(path, 0o600)
    return {
        "initialized": True,
        "createdKeys": sorted(created),
        "canonicalSourceSha256": hashlib.sha256(PLATFORM_ENV.read_bytes()).hexdigest(),
        "projectionRenderRequired": True,
        "secretRoot": str(SECRET_ROOT),
    }


def reconcile() -> dict[str, object]:
    with config_lock():
        result = init()
    for action in ("render", "audit"):
        subprocess.run(
            [sys.executable, str(CONFIG_RENDERER), action],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    result["projectionRenderRequired"] = False
    result["projectionAuditPassed"] = True
    return result


def audit() -> None:
    values = dotenv(PLATFORM_ENV)
    sensitive = {
        key: value
        for key, value in values.items()
        if value and len(value) >= 12 and SENSITIVE_KEY_RE.search(key)
    }
    findings: list[dict[str, str]] = []
    scan_roots = [ROOT / "manifests", ROOT / "config", ROOT / "evidence"]
    for base in scan_roots:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.stat().st_size > 5_000_000:
                continue
            try:
                content = path.read_text(errors="ignore")
            except OSError:
                continue
            for key, value in sensitive.items():
                if value in content:
                    findings.append({"key": key, "path": str(path)})
    print(
        json.dumps(
            {
                "ok": not findings,
                "sensitiveKeysScanned": len(sensitive),
                "publicKeysExcluded": len(values) - len(sensitive),
                "findings": findings,
            },
            indent=2,
        )
    )
    if findings:
        raise SystemExit(1)


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    if action == "init":
        print(json.dumps(reconcile()))
    elif action == "audit":
        audit()
    else:
        raise SystemExit("usage: server-secrets.py init|audit")

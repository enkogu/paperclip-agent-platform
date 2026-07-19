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
import stat
import subprocess
import sys
import tempfile


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
NON_SECRET_METADATA_SUFFIXES = (
    "_ENABLED",
    "_MODE",
    "_ROOT",
    "_DURATION",
    "_ID",
    "_SOURCE_FINGERPRINT",
)
ENV_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]*")
# One-time bootstrap identity seeds. They are copied into the canonical env
# only when a key is absent; every later run preserves the canonical value.
# Keeping this literal-only group named and separate lets the strict verifier
# distinguish bootstrap seeds from parallel runtime configuration.
BOOTSTRAP_ONLY_DEFAULTS = {
    "MATTERMOST_ADMIN_EMAIL": "admin@mte.local",
    "MATTERMOST_ADMIN_USERNAME": "mte-admin",
    "MATTERMOST_BOT_USERNAME": "mte-agent-bot",
    "GRAFANA_ADMIN_USER": "admin",
    "MATTERMOST_ALERT_WEBHOOK_URL": "",
    "KESTRA_ADMIN_USER": "admin@mte.local",
    "HERMES_TELEGRAM_BOT_TOKEN": "",
    "HERMES_TELEGRAM_ALLOWED_USERS": "",
    "HERMES_LLM_API_KEY": "",
}


class SecretConfigurationError(RuntimeError):
    """Raised when a secret artifact cannot be handled safely."""


def ensure_secure_directory(path: Path) -> None:
    """Create a root-only directory without traversing a symlink."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.mkdir(parents=True, exist_ok=False, mode=0o700)
        info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise SecretConfigurationError(f"secret path is not a directory: {path}")
    secure_path(path, 0o700)


def require_regular_file(path: Path, *, missing_ok: bool = False) -> bool:
    """Return whether a non-symlink regular file exists at ``path``."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return False
        raise SecretConfigurationError(f"secret artifact is missing: {path}") from None
    if not stat.S_ISREG(info.st_mode):
        raise SecretConfigurationError(f"secret artifact is not a regular file: {path}")
    return True


def validate_env_values(values: dict[str, str]) -> str:
    lines: list[str] = []
    for key in sorted(values):
        value = values[key]
        if not ENV_KEY_RE.fullmatch(key):
            raise SecretConfigurationError(f"invalid canonical key: {key!r}")
        if not isinstance(value, str) or any(char in value for char in "\r\n\0"):
            raise SecretConfigurationError(f"canonical value for {key} must be single-line")
        lines.append(f"{key}={value}\n")
    return "".join(lines)


def atomic_text(path: Path, content: str, *, mode: int) -> None:
    """Atomically replace a secret file without a permissive write window."""
    ensure_secure_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        if os.geteuid() == 0:
            os.fchown(descriptor, 0, 0)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        secure_path(path, mode)
    finally:
        if descriptor != -1:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


@contextmanager
def config_lock():
    ensure_secure_directory(SECRET_ROOT)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(LOCK, flags, 0o600)
    except OSError as error:
        raise SecretConfigurationError("cannot open secret configuration lock") from error
    try:
        os.fchmod(descriptor, 0o600)
        if os.geteuid() == 0:
            os.fchown(descriptor, 0, 0)
        with os.fdopen(descriptor, "a+", encoding="utf-8") as handle:
            descriptor = -1
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
    finally:
        if descriptor != -1:
            os.close(descriptor)


def dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not require_regular_file(path, missing_ok=True):
        return values
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in line:
            raise SecretConfigurationError(
                f"canonical environment line {line_number} is malformed"
            )
        key, value = stripped.split("=", 1)
        if not ENV_KEY_RE.fullmatch(key):
            raise SecretConfigurationError(f"invalid canonical key: {key!r}")
        if key in values:
            raise SecretConfigurationError(f"canonical key is duplicated: {key}")
        values[key] = value
    return values


def write_env(path: Path, values: dict[str, str]) -> None:
    atomic_text(path, validate_env_values(values), mode=0o600)


def secure_path(path: Path, mode: int) -> None:
    if path.is_symlink():
        raise SecretConfigurationError(f"secret path must not be a symlink: {path}")
    path.chmod(mode)
    if os.geteuid() == 0:
        os.chown(path, 0, 0)


def token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def daytona_generated_defaults() -> dict[str, str]:
    """Return fresh, strongly random credentials for Daytona's internal services."""
    return {
        "DAYTONA_ADMIN_API_KEY": "dtn_" + secrets.token_hex(32),
        "DAYTONA_DB_PASSWORD": secrets.token_hex(24),
        "DAYTONA_ENCRYPTION_KEY": secrets.token_hex(16),
        "DAYTONA_ENCRYPTION_SALT": secrets.token_hex(16),
        "DAYTONA_HEALTH_CHECK_API_KEY": secrets.token_hex(24),
        "DAYTONA_MINIO_PASSWORD": secrets.token_hex(24),
        "DAYTONA_OTEL_COLLECTOR_API_KEY": secrets.token_hex(24),
        "DAYTONA_PROXY_API_KEY": secrets.token_hex(24),
        "DAYTONA_REGISTRY_PASSWORD": secrets.token_hex(24),
        "DAYTONA_RUNNER_API_KEY": secrets.token_hex(24),
        "DAYTONA_SSH_GATEWAY_API_KEY": secrets.token_hex(24),
    }


def generated_defaults(profile: str = "postgres-notion") -> dict[str, str]:
    shared = {
        **BOOTSTRAP_ONLY_DEFAULTS,
        **daytona_generated_defaults(),
        "POSTGRES_ADMIN_PASSWORD": token(),
        "MATTERMOST_DB_PASSWORD": token(),
        "MATTERMOST_ADMIN_PASSWORD": token(),
        "FIRECRAWL_DB_PASSWORD": token(),
        "FIRECRAWL_REDIS_PASSWORD": token(),
        "FIRECRAWL_API_KEY": token(36),
        "SEARXNG_SECRET": token(32),
        "SEARXNG_VALKEY_PASSWORD": token(),
        "GRAFANA_ADMIN_PASSWORD": token(),
        "KESTRA_DB_PASSWORD": token(),
        "KESTRA_ADMIN_PASSWORD": token(),
        "NINEROUTER_INITIAL_PASSWORD": token(),
        "NINEROUTER_JWT_SECRET": secrets.token_hex(32),
        "NINEROUTER_API_KEY_SECRET": secrets.token_hex(32),
        "NINEROUTER_MACHINE_ID_SALT": secrets.token_hex(24),
        "HERMES_API_SERVER_KEY": token(36),
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
    }
    if profile not in providers:
        raise RuntimeError("data_content_profile_unsupported")
    return {**shared, **providers[profile]}


def init() -> dict[str, object]:
    ensure_secure_directory(SECRET_ROOT)
    values = dotenv(PLATFORM_ENV)
    created: list[str] = []
    for key, value in generated_defaults(
        values.get("DATA_CONTENT_PROFILE", "postgres-notion") or "postgres-notion"
    ).items():
        if key not in values:
            values[key] = value
            created.append(key)
    write_env(PLATFORM_ENV, values)
    # Provisioners add system-generated API tokens to these files. Creating
    # the directory here establishes the ownership/mode before any API call.
    ensure_secure_directory(INTEGRATION_ROOT)

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
    atomic_text(path, json.dumps(manifest, indent=2) + "\n", mode=0o600)
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


def is_sensitive_key(key: str) -> bool:
    """Return whether ``key`` holds a raw secret that audit must scan for."""
    return not key.endswith(NON_SECRET_METADATA_SUFFIXES) and bool(
        SENSITIVE_KEY_RE.search(key)
    )


def audit() -> None:
    ensure_secure_directory(SECRET_ROOT)
    values = dotenv(PLATFORM_ENV)
    sensitive = {
        key: value
        for key, value in values.items()
        if value and is_sensitive_key(key)
    }
    findings: list[dict[str, str]] = []
    scan_roots = [ROOT / "manifests", ROOT / "config", ROOT / "evidence"]
    for base in scan_roots:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            try:
                info = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_size > 5_000_000:
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

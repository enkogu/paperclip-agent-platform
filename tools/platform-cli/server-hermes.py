#!/usr/bin/env python3
"""Install and operate the pinned native Hermes runtime on a VPS.

This script is intentionally server-local and uses only the standard library.
It never prints secret values and never imports credentials from unrelated
projects. The only credential source is the configured platform EnvironmentFile.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any
import urllib.error
import urllib.request


VERSION = "0.18.2"
REPOSITORY = "https://github.com/NousResearch/hermes-agent.git"
TAG = "v2026.7.7.2"
COMMIT = "9de9c25f620ff7f1ce0fd5457d596052d5159596"

SERVICE = "mte-hermes.service"
LEGACY_SERVICE = "mte-hermes-operator.service"
SERVICE_USER = "mte-hermes"
INSTALL_ROOT = Path("/opt/mte-hermes")
RELEASE = INSTALL_ROOT / "releases" / VERSION
SOURCE = RELEASE / "source"
VENV = RELEASE / "venv"
CURRENT = INSTALL_ROOT / "current"
BIN_ROOT = INSTALL_ROOT / "bin"
SHARE_ROOT = INSTALL_ROOT / "share"
STATE_ROOT = Path("/var/lib/mte-hermes")
UNIT_PATH = Path("/etc/systemd/system") / SERVICE
LEGACY_UNIT_PATH = Path("/etc/systemd/system") / LEGACY_SERVICE
SUDOERS_PATH = Path("/etc/sudoers.d/mte-hermes-platform-admin")
DEFAULT_ENV_FILE = Path("/root/.config/mte-secrets/platform.env")
PROJECTION_HASH_PATH = Path("/root/.config/mte-secrets/platform.env.sha256")
HERMES_RUNTIME_ENV_FILE = Path("/root/.config/mte-secrets/hermes-runtime.env")
HERMES_RUNTIME_ENV_HASH_PATH = Path(
    "/root/.config/mte-secrets/hermes-runtime.env.sha256"
)
PLATFORM_ROOT = Path("/opt/mte-platform")
CONFIG_RENDERER = PLATFORM_ROOT / "bin/server-config.py"
PROJECTIONS_MANIFEST = DEFAULT_ENV_FILE.parent / "projections-manifest.json"
PLATFORM_ENV_LOCK = DEFAULT_ENV_FILE.parent / ".platform-env.lock"

REQUIRED_KEYS = (
    "HERMES_LLM_API_KEY",
    "HERMES_LLM_BASE_URL",
    "HERMES_LLM_MODEL",
    "HERMES_LLM_PROVIDER",
    "HERMES_LLM_API_MODE",
    "HERMES_PAPERCLIP_URL",
    "HERMES_KESTRA_URL",
    "HERMES_TERMINAL_CWD",
    "HERMES_TERMINAL_BACKEND",
    "HERMES_TERMINAL_HOME_MODE",
    "HERMES_TERMINAL_TIMEOUT",
    "HERMES_TERMINAL_LIFETIME_SECONDS",
    "HERMES_APPROVALS_MODE",
    "HERMES_APPROVALS_TIMEOUT",
    "HERMES_APPROVALS_CRON_MODE",
    "HERMES_APPROVALS_MCP_RELOAD_CONFIRM",
    "HERMES_APPROVALS_DESTRUCTIVE_SLASH_CONFIRM",
    "HERMES_GATEWAY_STREAMING_ENABLED",
    "HERMES_GATEWAY_STREAMING_TRANSPORT",
    "HERMES_TELEGRAM_REQUIRE_MENTION",
    "HERMES_TELEGRAM_EXCLUSIVE_BOT_MENTIONS",
    "HERMES_TELEGRAM_GUEST_MODE",
    "HERMES_EXEC_ASK",
    "HERMES_API_SERVER_ENABLED",
    "HERMES_API_SERVER_KEY",
    "HERMES_API_SERVER_HOST",
    "HERMES_API_SERVER_PORT",
    "HERMES_API_SERVER_MODEL_NAME",
    "HERMES_PAPERCLIP_API_KEY",
    "HERMES_DISPLAY_TOOL_PROGRESS",
    "HERMES_TELEGRAM_NOTIFICATIONS",
)

# The native Hermes process receives only this explicit projection. It never
# receives the complete platform credential file.
HERMES_RUNTIME_REQUIRED_KEYS = REQUIRED_KEYS
HERMES_RUNTIME_KEYS = frozenset(
    {
        *HERMES_RUNTIME_REQUIRED_KEYS,
        "HERMES_TELEGRAM_BOT_TOKEN",
        "HERMES_TELEGRAM_ALLOWED_USERS",
        "HERMES_KESTRA_USERNAME",
        "HERMES_KESTRA_PASSWORD",
        "MATTERMOST_URL",
        "MATTERMOST_TOKEN",
        "MATTERMOST_ALLOWED_USERS",
        "MATTERMOST_HOME_CHANNEL",
        "MATTERMOST_REPLY_MODE",
        "MATTERMOST_REQUIRE_MENTION",
    }
)

# Canonical platform names stay stable for the deployment layer. The generated
# EnvironmentFile uses the variable names understood by upstream Hermes.
HERMES_NATIVE_ENV_NAMES = {
    "HERMES_LLM_API_KEY": "OPENAI_API_KEY",
    "HERMES_LLM_BASE_URL": "OPENAI_BASE_URL",
    "HERMES_TELEGRAM_BOT_TOKEN": "TELEGRAM_BOT_TOKEN",
    "HERMES_TELEGRAM_ALLOWED_USERS": "TELEGRAM_ALLOWED_USERS",
    "HERMES_API_SERVER_ENABLED": "API_SERVER_ENABLED",
    "HERMES_API_SERVER_KEY": "API_SERVER_KEY",
    "HERMES_API_SERVER_HOST": "API_SERVER_HOST",
    "HERMES_API_SERVER_PORT": "API_SERVER_PORT",
    "HERMES_API_SERVER_MODEL_NAME": "API_SERVER_MODEL_NAME",
}


class HermesInstallError(RuntimeError):
    pass


def emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def command(
    argv: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    cwd: Path | None = None,
    timeout: int = 1800,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=check,
        text=True,
        capture_output=capture,
        cwd=str(cwd) if cwd else None,
        timeout=timeout,
    )


def require_root() -> None:
    if os.geteuid() != 0:
        raise HermesInstallError("this action must run as root")


def hermes_asset_paths() -> dict[str, Path]:
    """Resolve the canonical checkout or its compatible server projection."""
    installed = Path(__file__).resolve()
    root = (
        installed.parents[2]
        if installed.parent.name == "platform-cli"
        and installed.parent.parent.name == "tools"
        else installed.parents[1]
    )
    projected = root / "manifests/hermes"
    candidates = (
        {
            "acceptance": root
            / "deployment/services/hermes/acceptance-canary.py",
            "mattermostBootstrap": root
            / "deployment/services/hermes/bootstrap-mattermost.py",
            "configTemplate": root
            / "deployment/services/hermes/config.yaml.template",
            "soul": root / "deployment/services/hermes/soul.txt",
            "platformSkill": root
            / "deployment/services/hermes/platform-skill.txt",
            "serviceUnit": root / "deployment/services/hermes/service.unit",
        },
        {
            "acceptance": projected / "acceptance-canary.py",
            "mattermostBootstrap": projected / "bootstrap-mattermost.py",
            "configTemplate": projected / "config.yaml.template",
            "soul": projected / "SOUL.md",
            "platformSkill": projected / "skills/mte-platform/SKILL.md",
            "serviceUnit": projected / "hermes.service",
        },
    )
    for assets in candidates:
        if all(path.is_file() for path in assets.values()):
            return assets
    raise HermesInstallError(
        "Hermes runtime assets are missing from the synchronized platform"
    )


def parse_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        raise HermesInstallError(f"credential source does not exist: {path}")
    for number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            raise HermesInstallError(f"invalid dotenv syntax at line {number}")
        name, value = stripped.split("=", 1)
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise HermesInstallError(f"invalid dotenv key at line {number}")
        values[name] = value.strip()
    return values


def source_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@contextmanager
def platform_env_lock():
    """Use the canonical writer lock for source-derived Hermes artifacts."""
    DEFAULT_ENV_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with PLATFORM_ENV_LOCK.open("a+") as handle:
        PLATFORM_ENV_LOCK.chmod(0o600)
        if os.geteuid() == 0:
            os.chown(PLATFORM_ENV_LOCK, 0, 0)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def projection_hash_matches(path: Path) -> bool:
    if not PROJECTION_HASH_PATH.is_file():
        return False
    expected = PROJECTION_HASH_PATH.read_text(encoding="ascii").strip()
    return bool(
        re.fullmatch(r"[0-9a-f]{64}", expected) and source_hash(path) == expected
    )


def write_projection_hash(path: Path, expected_source_sha: str) -> None:
    with platform_env_lock():
        if source_hash(path) != expected_source_sha:
            raise HermesInstallError(
                "canonical platform credential changed before Hermes hash projection"
            )
        temporary = PROJECTION_HASH_PATH.with_name(PROJECTION_HASH_PATH.name + ".tmp")
        temporary.write_text(expected_source_sha + "\n", encoding="ascii")
        os.chown(temporary, 0, 0)
        temporary.chmod(0o600)
        temporary.replace(PROJECTION_HASH_PATH)


def render_runtime_credential_projection(
    path: Path, expected_source_sha: str
) -> dict[str, Any]:
    """Project only Hermes-owned values for the unprivileged systemd service."""
    with platform_env_lock():
        if source_hash(path) != expected_source_sha:
            raise HermesInstallError(
                "canonical platform credential changed before Hermes credential projection"
            )
        values = parse_dotenv(path)
        selected = {
            HERMES_NATIVE_ENV_NAMES.get(key, key): values[key]
            for key in sorted(HERMES_RUNTIME_KEYS)
            if values.get(key, "").strip()
        }
        missing = sorted(
            key
            for key in HERMES_RUNTIME_REQUIRED_KEYS
            if not values.get(key, "").strip()
        )
        if missing:
            raise HermesInstallError(
                "Hermes runtime credential projection is missing: " + ", ".join(missing)
            )
        content = (
            "# Generated from canonical platform.env; do not edit.\n"
            f"# sourceSha256={expected_source_sha}\n"
            + "".join(f"{key}={selected[key]}\n" for key in sorted(selected))
        )
        runtime_sha = hashlib.sha256(content.encode()).hexdigest()
        HERMES_RUNTIME_ENV_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        HERMES_RUNTIME_ENV_FILE.parent.chmod(0o700)
        if os.geteuid() == 0:
            os.chown(HERMES_RUNTIME_ENV_FILE.parent, 0, 0)
        env_temporary = HERMES_RUNTIME_ENV_FILE.with_name(
            HERMES_RUNTIME_ENV_FILE.name + ".tmp"
        )
        hash_temporary = HERMES_RUNTIME_ENV_HASH_PATH.with_name(
            HERMES_RUNTIME_ENV_HASH_PATH.name + ".tmp"
        )
        env_temporary.write_text(content, encoding="utf-8")
        hash_temporary.write_text(runtime_sha + "\n", encoding="ascii")
        for temporary in (env_temporary, hash_temporary):
            os.chown(temporary, 0, 0)
            temporary.chmod(0o600)
        env_temporary.replace(HERMES_RUNTIME_ENV_FILE)
        hash_temporary.replace(HERMES_RUNTIME_ENV_HASH_PATH)
        return {
            "keyCount": len(selected),
            "runtimeSha256": runtime_sha,
            "sourceSha256": expected_source_sha,
        }


def runtime_credential_projection_matches(path: Path) -> bool:
    if (
        not HERMES_RUNTIME_ENV_FILE.is_file()
        or not HERMES_RUNTIME_ENV_HASH_PATH.is_file()
    ):
        return False
    for projection in (HERMES_RUNTIME_ENV_FILE, HERMES_RUNTIME_ENV_HASH_PATH):
        info = projection.stat()
        if stat.S_IMODE(info.st_mode) != 0o600:
            return False
        if os.geteuid() == 0 and info.st_uid != 0:
            return False
    expected = HERMES_RUNTIME_ENV_HASH_PATH.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        return False
    if source_hash(HERMES_RUNTIME_ENV_FILE) != expected:
        return False
    try:
        values = parse_dotenv(HERMES_RUNTIME_ENV_FILE)
        canonical = parse_dotenv(path)
    except (HermesInstallError, OSError):
        return False
    return values == {
        HERMES_NATIVE_ENV_NAMES.get(key, key): canonical[key]
        for key in sorted(HERMES_RUNTIME_KEYS)
        if canonical.get(key, "").strip()
    }


def require_bool(values: dict[str, str], name: str) -> bool:
    value = values[name].strip().lower()
    if value not in {"true", "false"}:
        raise HermesInstallError(f"{name} must be true or false")
    return value == "true"


def require_int(values: dict[str, str], name: str, minimum: int, maximum: int) -> int:
    value = values[name].strip()
    if not value.isdigit() or not minimum <= int(value) <= maximum:
        raise HermesInstallError(f"{name} must be an integer in {minimum}..{maximum}")
    return int(value)


def validate_env_file(path: Path) -> dict[str, Any]:
    file_stat = path.stat() if path.exists() else None
    if file_stat is None:
        raise HermesInstallError(f"credential source does not exist: {path}")
    if file_stat.st_uid != 0:
        raise HermesInstallError("platform credential source must be owned by root")
    if stat.S_IMODE(file_stat.st_mode) & 0o077:
        raise HermesInstallError(
            "platform credential source must not be accessible by group/other"
        )

    values = parse_dotenv(path)
    missing = [name for name in REQUIRED_KEYS if not values.get(name, "").strip()]
    if missing:
        raise HermesInstallError(
            "empty required credential references: " + ", ".join(missing)
        )

    token = values.get("HERMES_TELEGRAM_BOT_TOKEN", "").strip()
    telegram_allowed_raw = values.get("HERMES_TELEGRAM_ALLOWED_USERS", "").strip()
    if bool(token) != bool(telegram_allowed_raw):
        raise HermesInstallError(
            "Telegram token and allowlist must be configured together"
        )
    telegram_users: list[str] = []
    if token:
        if not re.fullmatch(r"[0-9]{6,15}:[A-Za-z0-9_-]{20,}", token):
            raise HermesInstallError("HERMES_TELEGRAM_BOT_TOKEN has an invalid shape")
        telegram_users = [
            item.strip() for item in telegram_allowed_raw.split(",") if item.strip()
        ]
        if not telegram_users or "*" in telegram_users:
            raise HermesInstallError(
                "Telegram authorization requires a non-wildcard allowlist"
            )
        if any(not re.fullmatch(r"[1-9][0-9]{4,19}", item) for item in telegram_users):
            raise HermesInstallError(
                "HERMES_TELEGRAM_ALLOWED_USERS must contain numeric user IDs"
            )

    mattermost_url = values.get("MATTERMOST_URL", "").strip()
    mattermost_token = values.get("MATTERMOST_TOKEN", "").strip()
    mattermost_allowed_raw = values.get("MATTERMOST_ALLOWED_USERS", "").strip()
    if any((mattermost_url, mattermost_token, mattermost_allowed_raw)) and not all(
        (mattermost_url, mattermost_token, mattermost_allowed_raw)
    ):
        raise HermesInstallError(
            "Mattermost URL, token, and allowlist must be configured together"
        )
    mattermost_users: list[str] = []
    if mattermost_url:
        if not re.fullmatch(r"https?://[^\s]+", mattermost_url):
            raise HermesInstallError("MATTERMOST_URL must be an HTTP(S) URL")
        mattermost_users = [
            item.strip() for item in mattermost_allowed_raw.split(",") if item.strip()
        ]
        if not mattermost_users or "*" in mattermost_users:
            raise HermesInstallError(
                "Mattermost authorization requires a non-wildcard allowlist"
            )
        if any(not re.fullmatch(r"[a-z0-9]{26}", item) for item in mattermost_users):
            raise HermesInstallError(
                "MATTERMOST_ALLOWED_USERS must contain Mattermost user IDs"
            )
        for name in (
            "MATTERMOST_HOME_CHANNEL",
            "MATTERMOST_REPLY_MODE",
            "MATTERMOST_REQUIRE_MENTION",
        ):
            if not values.get(name, "").strip():
                raise HermesInstallError(f"{name} is required for Mattermost")
        if not re.fullmatch(r"[a-z0-9]{26}", values["MATTERMOST_HOME_CHANNEL"].strip()):
            raise HermesInstallError("MATTERMOST_HOME_CHANNEL is invalid")
        if values["MATTERMOST_REPLY_MODE"].strip() not in {"thread", "off"}:
            raise HermesInstallError("MATTERMOST_REPLY_MODE is invalid")
        if values["MATTERMOST_REQUIRE_MENTION"].strip().lower() not in {
            "true",
            "false",
        }:
            raise HermesInstallError("MATTERMOST_REQUIRE_MENTION must be boolean")
    if not token and not mattermost_url:
        raise HermesInstallError("no authenticated messaging platform is configured")

    base_url = values["HERMES_LLM_BASE_URL"].strip()
    if not re.fullmatch(r"https?://[^\s]+", base_url):
        raise HermesInstallError("HERMES_LLM_BASE_URL must be an HTTP(S) URL")

    model = values["HERMES_LLM_MODEL"].strip()
    if not model or any(char in model for char in "\r\n\0"):
        raise HermesInstallError("HERMES_LLM_MODEL is invalid")

    if not Path(values["HERMES_TERMINAL_CWD"].strip()).is_absolute():
        raise HermesInstallError("HERMES_TERMINAL_CWD must be absolute")
    if values["HERMES_TERMINAL_BACKEND"].strip() != "local":
        raise HermesInstallError(
            "HERMES_TERMINAL_BACKEND must be local for host repair"
        )
    if values["HERMES_TERMINAL_HOME_MODE"].strip() not in {
        "auto",
        "real",
        "profile",
    }:
        raise HermesInstallError("HERMES_TERMINAL_HOME_MODE is invalid")
    if values["HERMES_LLM_PROVIDER"].strip() != "custom":
        raise HermesInstallError("HERMES_LLM_PROVIDER must be custom for 9Router")
    if values["HERMES_LLM_API_MODE"].strip() not in {
        "chat_completions",
        "codex_responses",
        "anthropic_messages",
    }:
        raise HermesInstallError("HERMES_LLM_API_MODE is invalid")
    require_int(values, "HERMES_TERMINAL_TIMEOUT", 1, 86400)
    require_int(values, "HERMES_TERMINAL_LIFETIME_SECONDS", 1, 604800)
    require_int(values, "HERMES_APPROVALS_TIMEOUT", 1, 86400)
    for name in (
        "HERMES_APPROVALS_MCP_RELOAD_CONFIRM",
        "HERMES_APPROVALS_DESTRUCTIVE_SLASH_CONFIRM",
        "HERMES_GATEWAY_STREAMING_ENABLED",
        "HERMES_TELEGRAM_REQUIRE_MENTION",
        "HERMES_TELEGRAM_EXCLUSIVE_BOT_MENTIONS",
        "HERMES_TELEGRAM_GUEST_MODE",
    ):
        require_bool(values, name)
    if values["HERMES_APPROVALS_MODE"].strip() not in {"manual", "smart", "off"}:
        raise HermesInstallError("HERMES_APPROVALS_MODE is invalid")
    if values["HERMES_APPROVALS_CRON_MODE"].strip() not in {
        "deny",
        "approve",
    }:
        raise HermesInstallError("HERMES_APPROVALS_CRON_MODE is invalid")
    if values["HERMES_GATEWAY_STREAMING_TRANSPORT"].strip() not in {
        "edit",
        "off",
    }:
        raise HermesInstallError("HERMES_GATEWAY_STREAMING_TRANSPORT is invalid")
    if values["HERMES_EXEC_ASK"].strip() not in {"0", "1"}:
        raise HermesInstallError("HERMES_EXEC_ASK must be 0 or 1")
    if not require_bool(values, "HERMES_API_SERVER_ENABLED"):
        raise HermesInstallError("HERMES_API_SERVER_ENABLED must be true")
    api_server_key = values["HERMES_API_SERVER_KEY"].strip()
    if len(api_server_key) < 32 or any(char.isspace() for char in api_server_key):
        raise HermesInstallError("HERMES_API_SERVER_KEY is too weak or malformed")
    if values["HERMES_API_SERVER_HOST"].strip() not in {"127.0.0.1", "::1"}:
        raise HermesInstallError("HERMES_API_SERVER_HOST must be loopback")
    require_int(values, "HERMES_API_SERVER_PORT", 1024, 65535)
    if not re.fullmatch(
        r"[A-Za-z0-9._-]{1,80}", values["HERMES_API_SERVER_MODEL_NAME"].strip()
    ):
        raise HermesInstallError("HERMES_API_SERVER_MODEL_NAME is invalid")
    if values["HERMES_DISPLAY_TOOL_PROGRESS"].strip() not in {
        "off",
        "new",
        "all",
        "verbose",
        "log",
    }:
        raise HermesInstallError("HERMES_DISPLAY_TOOL_PROGRESS is invalid")
    if values["HERMES_TELEGRAM_NOTIFICATIONS"].strip() not in {
        "off",
        "important",
        "all",
    }:
        raise HermesInstallError("HERMES_TELEGRAM_NOTIFICATIONS is invalid")

    return {
        "credentialSource": str(path),
        "owner": "root",
        "mode": format(stat.S_IMODE(file_stat.st_mode), "04o"),
        "requiredKeys": list(REQUIRED_KEYS),
        "telegram": {
            "configured": bool(token),
            "failClosed": not bool(token),
            "allowedUserCount": len(telegram_users),
        },
        "mattermost": {
            "configured": bool(mattermost_url),
            "failClosed": not bool(mattermost_url),
            "allowedUserCount": len(mattermost_users),
        },
        "llmBaseUrlConfigured": bool(values.get("HERMES_LLM_BASE_URL", "").strip()),
        "llmModelConfigured": True,
    }


def json_request(
    url: str,
    *,
    bearer: str | None = None,
    basic: tuple[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: int = 10,
) -> Any:
    headers = {
        "Accept": "application/json",
        "User-Agent": f"mte-hermes-health/{VERSION}",
    }
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if basic:
        encoded = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(url, headers=headers, data=data)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise HermesInstallError("remote health endpoint returned a non-200 status")
        payload = response.read(5_000_001)
    if len(payload) > 5_000_000:
        raise HermesInstallError("remote health response exceeded the size limit")
    return json.loads(payload)


def hermes_api_server_ready(values: dict[str, str]) -> bool:
    host = values["HERMES_API_SERVER_HOST"].strip()
    rendered_host = "[::1]" if host == "::1" else host
    url = (
        "http://"
        + rendered_host
        + ":"
        + values["HERMES_API_SERVER_PORT"].strip()
        + "/health"
    )
    try:
        payload = json_request(
            url,
            bearer=values["HERMES_API_SERVER_KEY"].strip(),
        )
    except (OSError, ValueError, json.JSONDecodeError, HermesInstallError):
        return False
    return isinstance(payload, dict)


def wait_hermes_api_server(
    values: dict[str, str], *, timeout_seconds: int = 60
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if hermes_api_server_ready(values):
            return True
        time.sleep(1)
    return False


def external_readiness(path: Path) -> tuple[dict[str, bool], dict[str, str]]:
    values = parse_dotenv(path)
    checks = {"llmRoute": False, "llmCompletion": False}
    states: dict[str, str] = {}

    checks["hermesApiServer"] = False
    checks["hermesApiServer"] = hermes_api_server_ready(values)
    states["hermesApiServer"] = (
        "ready" if checks["hermesApiServer"] else "unreachable-or-rejected"
    )

    telegram_token = values.get("HERMES_TELEGRAM_BOT_TOKEN", "").strip()
    if telegram_token:
        checks["telegramBot"] = False
        try:
            telegram = json_request(
                "https://api.telegram.org/bot" + telegram_token + "/getMe"
            )
            checks["telegramBot"] = bool(
                isinstance(telegram, dict)
                and telegram.get("ok") is True
                and isinstance(telegram.get("result"), dict)
                and telegram["result"].get("is_bot") is True
            )
            states["telegramBot"] = (
                "ready" if checks["telegramBot"] else "invalid-response"
            )
        except (
            OSError,
            KeyError,
            ValueError,
            json.JSONDecodeError,
            HermesInstallError,
        ):
            states["telegramBot"] = "unreachable-or-rejected"
    else:
        states["telegramBot"] = "disabled-fail-closed"

    mattermost_url = values.get("MATTERMOST_URL", "").strip().rstrip("/")
    if mattermost_url:
        checks["mattermostBot"] = False
        try:
            me = json_request(
                mattermost_url + "/api/v4/users/me",
                bearer=values["MATTERMOST_TOKEN"].strip(),
            )
            checks["mattermostBot"] = bool(
                isinstance(me, dict) and me.get("id") and me.get("is_bot") is True
            )
            states["mattermostBot"] = (
                "ready" if checks["mattermostBot"] else "invalid-response"
            )
        except (
            OSError,
            KeyError,
            ValueError,
            json.JSONDecodeError,
            HermesInstallError,
        ):
            states["mattermostBot"] = "unreachable-or-rejected"
    else:
        states["mattermostBot"] = "disabled-fail-closed"

    for label, url, basic_auth, bearer_auth in (
        (
            "paperclipApi",
            values["HERMES_PAPERCLIP_URL"].rstrip("/") + "/health",
            None,
            values["HERMES_PAPERCLIP_API_KEY"].strip(),
        ),
        (
            "kestraApi",
            values["HERMES_KESTRA_URL"].rstrip("/") + "/health",
            (
                values.get("HERMES_KESTRA_USERNAME", ""),
                values.get("HERMES_KESTRA_PASSWORD", ""),
            )
            if values.get("HERMES_KESTRA_USERNAME")
            else None,
            None,
        ),
    ):
        checks[label] = False
        try:
            response = json_request(url, basic=basic_auth, bearer=bearer_auth)
            checks[label] = isinstance(response, dict)
            states[label] = "ready" if checks[label] else "invalid-response"
        except (
            OSError,
            KeyError,
            ValueError,
            json.JSONDecodeError,
            HermesInstallError,
        ):
            states[label] = "unreachable-or-rejected"

    try:
        base_url = values["HERMES_LLM_BASE_URL"].strip()
        models = json_request(
            base_url.rstrip("/") + "/models",
            bearer=values["HERMES_LLM_API_KEY"].strip(),
        )
        listed = {
            str(item.get("id"))
            for item in models.get("data", [])
            if isinstance(item, dict) and item.get("id")
        }
        checks["llmRoute"] = values["HERMES_LLM_MODEL"].strip() in listed
        states["llmRoute"] = "ready" if checks["llmRoute"] else "model-not-listed"
        if checks["llmRoute"]:
            completion = json_request(
                base_url.rstrip("/") + "/chat/completions",
                bearer=values["HERMES_LLM_API_KEY"].strip(),
                body={
                    "model": values["HERMES_LLM_MODEL"].strip(),
                    "messages": [{"role": "user", "content": "Reply with OK."}],
                    "max_tokens": 8,
                    "stream": False,
                },
                timeout=60,
            )
            choices = completion.get("choices", [])
            checks["llmCompletion"] = bool(
                isinstance(choices, list)
                and choices
                and isinstance(choices[0], dict)
                and isinstance(choices[0].get("message"), dict)
                and str(choices[0]["message"].get("content", "")).strip()
            )
            states["llmCompletion"] = (
                "ready" if checks["llmCompletion"] else "invalid-response"
            )
        else:
            states["llmCompletion"] = "not-attempted"
    except (
        OSError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        HermesInstallError,
    ):
        states["llmRoute"] = "unreachable-or-rejected"
        states["llmCompletion"] = "unreachable-or-rejected"

    return checks, states


def ensure_packages() -> None:
    binaries = {
        "curl": "curl",
        "ffmpeg": "ffmpeg",
        "git": "git",
        "python3": "python3",
        "rg": "ripgrep",
        "sudo": "sudo",
        "visudo": "sudo",
        "xz": "xz-utils",
    }
    missing_packages = sorted(
        {
            package
            for binary, package in binaries.items()
            if shutil.which(binary) is None
        }
    )
    venv_probe = (
        command(["python3", "-c", "import venv"], check=False, capture=True)
        if shutil.which("python3")
        else None
    )
    if venv_probe is None or venv_probe.returncode != 0:
        missing_packages.append("python3-venv")
    if shutil.which("dpkg-query"):
        ca_probe = command(
            ["dpkg-query", "-W", "-f=${Status}", "ca-certificates"],
            check=False,
            capture=True,
            timeout=30,
        )
        if ca_probe.returncode != 0 or "install ok installed" not in ca_probe.stdout:
            missing_packages.append("ca-certificates")
    missing_packages = sorted(set(missing_packages))
    if not missing_packages:
        return
    if shutil.which("apt-get") is None:
        raise HermesInstallError(
            "missing packages and apt-get is unavailable: "
            + ", ".join(missing_packages)
        )
    command(["apt-get", "update"], timeout=600)
    command(
        ["apt-get", "install", "-y", "--no-install-recommends", *missing_packages],
        timeout=1200,
    )


def bootstrap_mattermost() -> None:
    result = command(
        ["python3", str(hermes_asset_paths()["mattermostBootstrap"])],
        check=False,
        capture=True,
        timeout=180,
    )
    if result.returncode != 0:
        raise HermesInstallError("Mattermost operator bootstrap failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise HermesInstallError(
            "Mattermost operator bootstrap returned invalid status"
        ) from error
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise HermesInstallError("Mattermost operator bootstrap did not become ready")


def _json_command(argv: list[str], *, label: str) -> dict[str, Any]:
    result = command(argv, check=False, capture=True, timeout=300)
    if result.returncode != 0:
        raise HermesInstallError(f"{label} failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise HermesInstallError(f"{label} returned invalid status") from error
    if not isinstance(payload, dict):
        raise HermesInstallError(f"{label} returned invalid status")
    return payload


def reconcile_platform_projections(env_file: Path) -> dict[str, Any]:
    """Render, audit and independently verify the canonical projection manifest."""
    if not CONFIG_RENDERER.is_file():
        raise HermesInstallError("platform configuration renderer is missing")
    expected_source_sha = source_hash(env_file)
    render = _json_command(
        ["python3", str(CONFIG_RENDERER), "render"],
        label="platform configuration render",
    )
    if (
        render.get("rendered") is not True
        or render.get("sourceSha256") != expected_source_sha
        or render.get("manifest") != str(PROJECTIONS_MANIFEST)
    ):
        raise HermesInstallError("platform configuration render evidence is invalid")

    audit = _json_command(
        ["python3", str(CONFIG_RENDERER), "audit"],
        label="platform configuration audit",
    )
    if (
        audit.get("ok") is not True
        or audit.get("sourceSha256") != expected_source_sha
        or audit.get("findings") != []
    ):
        raise HermesInstallError("platform configuration audit evidence is invalid")

    if not PROJECTIONS_MANIFEST.is_file():
        raise HermesInstallError("platform projection manifest is missing")
    manifest_stat = PROJECTIONS_MANIFEST.stat()
    if stat.S_IMODE(manifest_stat.st_mode) != 0o600:
        raise HermesInstallError("platform projection manifest permissions are unsafe")
    if os.geteuid() == 0 and manifest_stat.st_uid != 0:
        raise HermesInstallError("platform projection manifest must be owned by root")
    try:
        manifest = json.loads(PROJECTIONS_MANIFEST.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise HermesInstallError("platform projection manifest is invalid") from error
    projections = manifest.get("projections") if isinstance(manifest, dict) else None
    if (
        not isinstance(projections, list)
        or not projections
        or manifest.get("sourceSha256") != expected_source_sha
        or manifest.get("generatorVersion") != render.get("generatorVersion")
        or len(projections) != render.get("projectionCount")
    ):
        raise HermesInstallError("platform projection manifest evidence is invalid")
    for row in projections:
        if not isinstance(row, dict) or row.get("sourceSha256") != expected_source_sha:
            raise HermesInstallError("platform projection manifest row is invalid")
        path = Path(str(row.get("path", "")))
        if not path.is_file() or row.get("contentSha256") != source_hash(path):
            raise HermesInstallError("platform projection manifest content drifted")
    if source_hash(env_file) != expected_source_sha:
        raise HermesInstallError(
            "canonical platform credential changed during projection reconciliation"
        )
    return {
        "sourceSha256": expected_source_sha,
        "projectionCount": len(projections),
        "generatorVersion": manifest["generatorVersion"],
    }


def ensure_supported_python() -> None:
    probe = command(
        [
            "python3",
            "-c",
            "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
        ],
        capture=True,
        timeout=30,
    ).stdout.strip()
    if probe not in {"3.11", "3.12", "3.13"}:
        raise HermesInstallError(
            f"Hermes {VERSION} requires Python 3.11-3.13; server python3 is {probe or 'unknown'}"
        )


def ensure_user() -> None:
    try:
        account = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        command(
            [
                "useradd",
                "--system",
                "--create-home",
                "--home-dir",
                str(STATE_ROOT),
                "--shell",
                "/bin/bash",
                SERVICE_USER,
            ]
        )
        account = pwd.getpwnam(SERVICE_USER)
    if Path(account.pw_dir) != STATE_ROOT:
        raise HermesInstallError(
            f"existing {SERVICE_USER} account has an unexpected home directory"
        )

    STATE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    (STATE_ROOT / ".hermes").mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chown(STATE_ROOT, account.pw_uid, account.pw_gid)
    os.chown(STATE_ROOT / ".hermes", account.pw_uid, account.pw_gid)
    STATE_ROOT.chmod(0o700)
    (STATE_ROOT / ".hermes").chmod(0o700)


def checked_source_commit() -> str | None:
    if not (SOURCE / ".git").is_dir():
        return None
    result = command(
        ["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
        check=False,
        capture=True,
        timeout=30,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def install_source() -> None:
    RELEASE.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    current_commit = checked_source_commit()
    if current_commit and current_commit != COMMIT:
        raise HermesInstallError(
            f"existing release source does not match pinned Hermes {VERSION}"
        )
    if current_commit == COMMIT:
        RELEASE.chmod(0o755)

    if current_commit is None:
        staging = Path(tempfile.mkdtemp(prefix=f".{VERSION}-", dir=str(RELEASE.parent)))
        try:
            checkout = staging / "source"
            command(
                [
                    "git",
                    "clone",
                    "--quiet",
                    "--depth",
                    "1",
                    "--branch",
                    TAG,
                    REPOSITORY,
                    str(checkout),
                ]
            )
            actual = command(
                ["git", "-C", str(checkout), "rev-parse", "HEAD"], capture=True
            ).stdout.strip()
            if actual != COMMIT:
                raise HermesInstallError(
                    "downloaded Hermes tag does not match the pinned commit"
                )
            version_text = (checkout / "pyproject.toml").read_text(encoding="utf-8")
            if not re.search(
                rf'^version\s*=\s*"{re.escape(VERSION)}"\s*$',
                version_text,
                re.MULTILINE,
            ):
                raise HermesInstallError(
                    "downloaded source does not declare the pinned package version"
                )
            if RELEASE.exists():
                shutil.rmtree(RELEASE)
            staging.replace(RELEASE)
            RELEASE.chmod(0o755)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise


def installed_version() -> str | None:
    python = VENV / "bin" / "python"
    if not python.is_file():
        return None
    probe = command(
        [str(python), "-c", "import hermes_cli; print(hermes_cli.__version__)"],
        check=False,
        capture=True,
        timeout=60,
    )
    if probe.returncode != 0:
        return None
    return probe.stdout.strip()


def install_venv() -> None:
    if installed_version() == VERSION:
        return
    if VENV.exists():
        shutil.rmtree(VENV)
    command(["python3", "-m", "venv", str(VENV)], timeout=180)
    pip = VENV / "bin" / "pip"
    # The package and all direct Hermes dependencies come from the exact tagged
    # source. --no-cache-dir avoids retaining a second executable copy.
    command(
        [str(pip), "install", "--no-input", "--no-cache-dir", f"{SOURCE}[messaging]"],
        cwd=SOURCE,
        timeout=1800,
    )
    if installed_version() != VERSION:
        raise HermesInstallError(
            "Hermes virtual environment version verification failed"
        )


def atomic_copy(source: Path, destination: Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    temporary = destination.with_name(destination.name + ".tmp")
    shutil.copyfile(source, temporary)
    temporary.chmod(mode)
    temporary.replace(destination)


def render_native_config(values: dict[str, str]) -> dict[str, str]:
    """Render upstream Hermes configuration before the native service starts."""
    assets = hermes_asset_paths()
    template = assets["configTemplate"].read_text(encoding="utf-8")
    replacements = {
        "@@HERMES_LLM_MODEL@@": json.dumps(values["HERMES_LLM_MODEL"].strip()),
        "@@HERMES_LLM_PROVIDER@@": json.dumps(values["HERMES_LLM_PROVIDER"].strip()),
        "@@HERMES_LLM_BASE_URL@@": json.dumps(
            values["HERMES_LLM_BASE_URL"].strip().rstrip("/")
        ),
        "@@HERMES_LLM_API_MODE@@": json.dumps(values["HERMES_LLM_API_MODE"].strip()),
        "@@HERMES_TERMINAL_BACKEND@@": json.dumps(
            values["HERMES_TERMINAL_BACKEND"].strip()
        ),
        "@@HERMES_TERMINAL_CWD@@": json.dumps(values["HERMES_TERMINAL_CWD"].strip()),
        "@@HERMES_TERMINAL_TIMEOUT@@": values["HERMES_TERMINAL_TIMEOUT"].strip(),
        "@@HERMES_TERMINAL_LIFETIME_SECONDS@@": values[
            "HERMES_TERMINAL_LIFETIME_SECONDS"
        ].strip(),
        "@@HERMES_TERMINAL_HOME_MODE@@": json.dumps(
            values["HERMES_TERMINAL_HOME_MODE"].strip()
        ),
        "@@HERMES_APPROVALS_MODE@@": json.dumps(
            values["HERMES_APPROVALS_MODE"].strip()
        ),
        "@@HERMES_APPROVALS_TIMEOUT@@": values["HERMES_APPROVALS_TIMEOUT"].strip(),
        "@@HERMES_APPROVALS_CRON_MODE@@": json.dumps(
            values["HERMES_APPROVALS_CRON_MODE"].strip()
        ),
        "@@HERMES_APPROVALS_MCP_RELOAD_CONFIRM@@": values[
            "HERMES_APPROVALS_MCP_RELOAD_CONFIRM"
        ]
        .strip()
        .lower(),
        "@@HERMES_APPROVALS_DESTRUCTIVE_SLASH_CONFIRM@@": values[
            "HERMES_APPROVALS_DESTRUCTIVE_SLASH_CONFIRM"
        ]
        .strip()
        .lower(),
        "@@HERMES_GATEWAY_STREAMING_ENABLED@@": values[
            "HERMES_GATEWAY_STREAMING_ENABLED"
        ]
        .strip()
        .lower(),
        "@@HERMES_GATEWAY_STREAMING_TRANSPORT@@": json.dumps(
            values["HERMES_GATEWAY_STREAMING_TRANSPORT"].strip()
        ),
        "@@HERMES_TELEGRAM_REQUIRE_MENTION@@": values["HERMES_TELEGRAM_REQUIRE_MENTION"]
        .strip()
        .lower(),
        "@@HERMES_TELEGRAM_EXCLUSIVE_BOT_MENTIONS@@": values[
            "HERMES_TELEGRAM_EXCLUSIVE_BOT_MENTIONS"
        ]
        .strip()
        .lower(),
        "@@HERMES_TELEGRAM_GUEST_MODE@@": values["HERMES_TELEGRAM_GUEST_MODE"]
        .strip()
        .lower(),
        "@@HERMES_DISPLAY_TOOL_PROGRESS@@": json.dumps(
            values["HERMES_DISPLAY_TOOL_PROGRESS"].strip()
        ),
        "@@HERMES_TELEGRAM_NOTIFICATIONS@@": json.dumps(
            values["HERMES_TELEGRAM_NOTIFICATIONS"].strip()
        ),
    }
    for placeholder, replacement in replacements.items():
        template = template.replace(placeholder, replacement)
    if "@@" in template:
        raise HermesInstallError("unresolved placeholder in Hermes configuration")

    try:
        account = pwd.getpwnam(SERVICE_USER)
    except KeyError as error:
        raise HermesInstallError(
            "Hermes service account is missing; run install before reconcile"
        ) from error
    destination = STATE_ROOT / ".hermes" / "config.yaml"
    soul = STATE_ROOT / ".hermes" / "SOUL.md"
    for path, content in (
        (destination, template),
        (soul, assets["soul"].read_text(encoding="utf-8")),
    ):
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(content, encoding="utf-8")
        os.chown(temporary, account.pw_uid, account.pw_gid)
        temporary.chmod(0o600)
        temporary.replace(path)
    return {
        "configSha256": source_hash(destination),
        "soulSha256": source_hash(soul),
    }


def render_service_unit(*, grant_platform_admin: bool) -> str:
    unit = hermes_asset_paths()["serviceUnit"].read_text(encoding="utf-8")
    return unit.replace(
        "@@HERMES_PRIVILEGE_HARDENING@@",
        (
            "# Explicit host-admin mode: systemd sandboxing that blocks sudo children is omitted."
            if grant_platform_admin
            else "\n".join(
                (
                    "NoNewPrivileges=true",
                    "PrivateDevices=true",
                    "PrivateTmp=true",
                    "ProtectControlGroups=true",
                    "ProtectHome=true",
                    "ProtectKernelLogs=true",
                    "ProtectKernelModules=true",
                    "ProtectKernelTunables=true",
                    "ProtectSystem=strict",
                    "ReadWritePaths=/var/lib/mte-hermes",
                    "RestrictRealtime=true",
                    "RestrictSUIDSGID=true",
                    "LockPersonality=true",
                )
            )
        ),
    )


def install_runtime_files(*, grant_platform_admin: bool) -> None:
    assets = hermes_asset_paths()
    atomic_copy(assets["acceptance"], BIN_ROOT / "acceptance-canary", 0o755)
    atomic_copy(
        assets["configTemplate"], SHARE_ROOT / "config.yaml.template", 0o644
    )
    atomic_copy(assets["soul"], SHARE_ROOT / "SOUL.md", 0o644)
    for obsolete in (BIN_ROOT / "launch-gateway", BIN_ROOT / "platform-api"):
        obsolete.unlink(missing_ok=True)

    unit = render_service_unit(grant_platform_admin=grant_platform_admin)
    temporary = UNIT_PATH.with_name(UNIT_PATH.name + ".tmp")
    temporary.write_text(unit, encoding="utf-8")
    temporary.chmod(0o644)
    temporary.replace(UNIT_PATH)

    if CURRENT.is_symlink() or CURRENT.exists():
        if CURRENT.is_symlink() and CURRENT.resolve() == RELEASE.resolve():
            return
        if CURRENT.is_dir() and not CURRENT.is_symlink():
            raise HermesInstallError(f"refusing to replace non-symlink {CURRENT}")
        CURRENT.unlink()
    CURRENT.symlink_to(RELEASE)


def install_platform_skill() -> None:
    source = hermes_asset_paths()["platformSkill"]
    destination = STATE_ROOT / ".hermes" / "skills" / "mte-platform"
    if not source.is_file():
        raise HermesInstallError("MTE platform skill asset is missing")
    shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True, mode=0o755)
    atomic_copy(source, destination / "SKILL.md", 0o644)
    account = pwd.getpwnam(SERVICE_USER)
    for path in [destination, *destination.rglob("*")]:
        os.chown(path, account.pw_uid, account.pw_gid)
        path.chmod(0o755 if path.is_dir() else 0o644)


def install_admin_policy() -> None:
    policy = (
        "# Managed by the platform; grants native Hermes explicit host repair access.\n"
        f"Defaults:{SERVICE_USER} !requiretty\n"
        f"{SERVICE_USER} ALL=(ALL:ALL) NOPASSWD: ALL\n"
    )
    temporary = SUDOERS_PATH.with_name(SUDOERS_PATH.name + ".tmp")
    temporary.write_text(policy, encoding="utf-8")
    temporary.chmod(0o440)
    validation = command(
        ["visudo", "-cf", str(temporary)], check=False, capture=True, timeout=30
    )
    if validation.returncode != 0:
        temporary.unlink(missing_ok=True)
        raise HermesInstallError(
            "generated Hermes sudoers policy failed visudo validation"
        )
    temporary.replace(SUDOERS_PATH)


def reconcile_admin_policy(enabled: bool) -> None:
    """Make unrestricted host repair an explicit, reversible installation mode."""
    if enabled:
        install_admin_policy()
    else:
        SUDOERS_PATH.unlink(missing_ok=True)


def systemctl(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return command(["systemctl", *args], check=check, capture=True, timeout=90)


def service_property(name: str) -> str:
    result = systemctl("show", SERVICE, f"--property={name}", "--value", check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def sudoers_valid() -> bool:
    if not SUDOERS_PATH.is_file() or stat.S_IMODE(SUDOERS_PATH.stat().st_mode) != 0o440:
        return False
    result = command(
        ["visudo", "-cf", str(SUDOERS_PATH)], check=False, capture=True, timeout=30
    )
    return result.returncode == 0


def native_runtime_files_ready() -> bool:
    try:
        account = pwd.getpwnam(SERVICE_USER)
        unit = UNIT_PATH.read_text(encoding="utf-8")
    except (KeyError, OSError):
        return False
    if (
        "ExecStart=/opt/mte-hermes/current/venv/bin/hermes gateway run --replace"
        not in unit
        or "launch-gateway" in unit
        or "platform-api" in unit
    ):
        return False
    for path in (
        STATE_ROOT / ".hermes" / "config.yaml",
        STATE_ROOT / ".hermes" / "SOUL.md",
    ):
        try:
            info = path.stat()
        except OSError:
            return False
        if info.st_uid != account.pw_uid or stat.S_IMODE(info.st_mode) != 0o600:
            return False
    return True


def status_payload(env_file: Path, *, verify_external: bool = False) -> dict[str, Any]:
    try:
        account = pwd.getpwnam(SERVICE_USER)
        account_ok = Path(account.pw_dir) == STATE_ROOT
    except KeyError:
        account_ok = False

    try:
        credential_state: dict[str, Any] = validate_env_file(env_file)
        credential_ok = True
    except (HermesInstallError, OSError) as error:
        credential_state = {"ready": False, "error": str(error)}
        credential_ok = False

    active = systemctl("is-active", SERVICE, check=False).stdout.strip()
    enabled = systemctl("is-enabled", SERVICE, check=False).stdout.strip()
    commit = checked_source_commit()
    version = installed_version()
    admin_policy_installed = SUDOERS_PATH.exists()
    admin_policy_valid = sudoers_valid() if admin_policy_installed else True
    checks = {
        "account": account_ok,
        "credentialSource": credential_ok,
        "credentialProjectionHash": credential_ok and projection_hash_matches(env_file),
        "sourceCommit": commit == COMMIT,
        "runtimeVersion": version == VERSION,
        "unitInstalled": UNIT_PATH.is_file(),
        "nativeGateway": native_runtime_files_ready(),
        "serviceEnabled": enabled == "enabled",
        "serviceActive": active == "active",
        "platformAdminPolicy": admin_policy_valid,
        "runtimeCredentialProjection": credential_ok
        and runtime_credential_projection_matches(env_file),
    }
    external_states: dict[str, str] = {}
    if credential_ok and verify_external:
        external_checks, external_states = external_readiness(env_file)
        checks.update(external_checks)
    elif credential_ok:
        external_states = {"verification": "not-requested"}
    return {
        "ok": all(checks.values()),
        "service": SERVICE,
        "version": version,
        "pinnedVersion": VERSION,
        "pinnedCommit": COMMIT,
        "serviceState": active or "not-installed",
        "enabledState": enabled or "not-installed",
        "mainPid": service_property("MainPID") or "0",
        "restartCount": service_property("NRestarts") or "0",
        "checks": checks,
        "externalReadiness": external_states,
        "privilegeMode": (
            "unrestricted_host_repair"
            if admin_policy_installed and admin_policy_valid
            else "unprivileged_service"
        ),
        "platformAdminPolicyInstalled": admin_policy_installed,
        "credentials": credential_state,
    }


def preflight(args: argparse.Namespace) -> None:
    state = validate_env_file(args.env_file)
    emit(
        {
            "ok": True,
            "hermesVersion": VERSION,
            "authorization": "authenticated-messaging-allowlists",
            **state,
        }
    )


def install(args: argparse.Namespace) -> None:
    require_root()
    if args.env_file != DEFAULT_ENV_FILE:
        raise HermesInstallError(
            f"installation only accepts the canonical credential source {DEFAULT_ENV_FILE}"
        )
    bootstrap_mattermost()
    projection_evidence = reconcile_platform_projections(args.env_file)
    credential_state = validate_env_file(args.env_file)
    canonical_hash = projection_evidence["sourceSha256"]
    if source_hash(args.env_file) != canonical_hash:
        raise HermesInstallError(
            "canonical platform credential changed after projection reconciliation"
        )
    ensure_packages()
    ensure_supported_python()
    ensure_user()
    PLATFORM_ROOT.mkdir(parents=True, exist_ok=True, mode=0o755)
    install_source()
    install_venv()
    runtime_projection = render_runtime_credential_projection(
        args.env_file, canonical_hash
    )
    native_config = render_native_config(parse_dotenv(args.env_file))
    install_runtime_files(grant_platform_admin=args.grant_platform_admin)
    install_platform_skill()
    reconcile_admin_policy(args.grant_platform_admin)
    if source_hash(args.env_file) != canonical_hash:
        raise HermesInstallError(
            "canonical platform credential changed during Hermes installation"
        )
    write_projection_hash(args.env_file, canonical_hash)
    systemctl("disable", "--now", LEGACY_SERVICE, check=False)
    LEGACY_UNIT_PATH.unlink(missing_ok=True)
    systemctl("daemon-reload")
    systemctl("enable", SERVICE)
    if not args.no_start:
        systemctl("restart", SERVICE)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if systemctl("is-active", SERVICE, check=False).stdout.strip() == "active":
                break
            time.sleep(1)
        # systemd reports the gateway process active before the authenticated
        # Hermes API finishes binding.  Gate the installation result on the
        # real API surface instead of racing a one-shot external health probe.
        if not wait_hermes_api_server(parse_dotenv(args.env_file), timeout_seconds=60):
            raise HermesInstallError("native Hermes API did not become ready")

    payload = status_payload(args.env_file, verify_external=not args.no_start)
    payload["installed"] = True
    payload["credentials"] = credential_state
    payload["runtimeCredentialProjection"] = runtime_projection
    payload["nativeConfig"] = native_config
    if args.no_start:
        payload["ok"] = all(
            value
            for name, value in payload["checks"].items()
            if name != "serviceActive"
        )
    emit(payload)
    if not payload["ok"]:
        raise HermesInstallError(
            "Hermes installation completed but health checks did not pass"
        )


def reconcile(args: argparse.Namespace) -> None:
    """Re-render native Hermes state from the canonical platform env."""
    require_root()
    if args.env_file != DEFAULT_ENV_FILE:
        raise HermesInstallError(
            f"reconciliation only accepts the canonical credential source {DEFAULT_ENV_FILE}"
        )
    projection_evidence = reconcile_platform_projections(args.env_file)
    validate_env_file(args.env_file)
    canonical_hash = projection_evidence["sourceSha256"]
    runtime_projection = render_runtime_credential_projection(
        args.env_file, canonical_hash
    )
    native_config = render_native_config(parse_dotenv(args.env_file))
    write_projection_hash(args.env_file, canonical_hash)
    restarted = False
    if not args.no_restart and UNIT_PATH.is_file():
        systemctl("restart", SERVICE)
        if not wait_hermes_api_server(parse_dotenv(args.env_file), timeout_seconds=60):
            raise HermesInstallError("native Hermes API did not become ready")
        restarted = True
    emit(
        {
            "ok": True,
            "reconciled": True,
            "service": SERVICE,
            "restarted": restarted,
            "platformProjections": projection_evidence,
            "runtimeCredentialProjection": runtime_projection,
            "nativeConfig": native_config,
        }
    )


def status(args: argparse.Namespace) -> None:
    emit(status_payload(args.env_file))


def health(args: argparse.Namespace) -> None:
    payload = status_payload(args.env_file, verify_external=True)
    emit(payload)
    if not payload["ok"]:
        raise SystemExit(1)


def remove(args: argparse.Namespace) -> None:
    require_root()
    systemctl("disable", "--now", SERVICE, check=False)
    systemctl("disable", "--now", LEGACY_SERVICE, check=False)
    UNIT_PATH.unlink(missing_ok=True)
    LEGACY_UNIT_PATH.unlink(missing_ok=True)
    SUDOERS_PATH.unlink(missing_ok=True)
    PROJECTION_HASH_PATH.unlink(missing_ok=True)
    HERMES_RUNTIME_ENV_FILE.unlink(missing_ok=True)
    HERMES_RUNTIME_ENV_HASH_PATH.unlink(missing_ok=True)
    systemctl("daemon-reload", check=False)
    systemctl("reset-failed", SERVICE, check=False)
    if INSTALL_ROOT.exists():
        shutil.rmtree(INSTALL_ROOT)
    purged = False
    if args.purge_data:
        if STATE_ROOT.exists():
            shutil.rmtree(STATE_ROOT)
        try:
            pwd.getpwnam(SERVICE_USER)
        except KeyError:
            pass
        else:
            command(["userdel", SERVICE_USER], check=False, capture=True, timeout=30)
        purged = True
    emit(
        {"ok": True, "removed": True, "statePreserved": not purged, "service": SERVICE}
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument(
        "--env-file",
        type=Path,
        default=DEFAULT_ENV_FILE,
        help="root-owned platform EnvironmentFile (default: %(default)s)",
    )
    commands = root.add_subparsers(dest="action", required=True)

    preflight_parser = commands.add_parser(
        "preflight", help="validate credentials and authorization without values"
    )
    preflight_parser.set_defaults(handler=preflight)

    install_parser = commands.add_parser(
        "install", help="idempotently install and start the pinned runtime"
    )
    install_parser.add_argument(
        "--grant-platform-admin",
        action="store_true",
        help="explicitly enable unrestricted NOPASSWD host repair (disabled by default)",
    )
    install_parser.add_argument(
        "--no-start",
        action="store_true",
        help="install and enable the unit without starting it",
    )
    install_parser.set_defaults(handler=install)

    reconcile_parser = commands.add_parser(
        "reconcile", help="re-render native runtime state from canonical config"
    )
    reconcile_parser.add_argument(
        "--no-restart",
        action="store_true",
        help="re-render state without restarting an installed service",
    )
    reconcile_parser.set_defaults(handler=reconcile)

    status_parser = commands.add_parser("status", help="return redacted runtime status")
    status_parser.set_defaults(handler=status)

    health_parser = commands.add_parser(
        "health", help="fail unless the configured runtime is healthy"
    )
    health_parser.set_defaults(handler=health)

    remove_parser = commands.add_parser(
        "remove", help="remove runtime and policy; preserve state by default"
    )
    remove_parser.add_argument(
        "--purge-data",
        action="store_true",
        help="also delete Hermes state and service account",
    )
    remove_parser.set_defaults(handler=remove)
    return root


def main() -> None:
    args = parser().parse_args()
    try:
        args.handler(args)
    except (HermesInstallError, OSError, subprocess.SubprocessError) as error:
        print(f"server-hermes: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()

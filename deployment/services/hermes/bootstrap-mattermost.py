#!/usr/bin/env python3
"""Provision the private Mattermost control surface for Hermes.

The script is intended to run as root on the platform host. It captures all
credential-bearing command output in memory, updates only the protected
platform dotenv file, and emits redacted identifiers/readiness information.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
from typing import Any, NamedTuple
import urllib.error
import urllib.parse
import urllib.request


ENV_FILE = Path("/root/.config/mte-secrets/platform.env")
ENV_LOCK = ENV_FILE.parent / ".platform-env.lock"

CANONICAL_RUNTIME_KEYS = (
    "HERMES_APPROVALS_CRON_MODE",
    "HERMES_APPROVALS_DESTRUCTIVE_SLASH_CONFIRM",
    "HERMES_APPROVALS_MCP_RELOAD_CONFIRM",
    "HERMES_APPROVALS_MODE",
    "HERMES_APPROVALS_TIMEOUT",
    "HERMES_API_SERVER_ENABLED",
    "HERMES_API_SERVER_HOST",
    "HERMES_API_SERVER_KEY",
    "HERMES_API_SERVER_MODEL_NAME",
    "HERMES_API_SERVER_PORT",
    "HERMES_DISPLAY_TOOL_PROGRESS",
    "HERMES_EXEC_ASK",
    "HERMES_GATEWAY_STREAMING_ENABLED",
    "HERMES_GATEWAY_STREAMING_TRANSPORT",
    "HERMES_KESTRA_URL",
    "HERMES_LLM_API_MODE",
    "HERMES_LLM_BASE_URL",
    "HERMES_LLM_PROVIDER",
    "HERMES_PAPERCLIP_URL",
    "HERMES_TELEGRAM_EXCLUSIVE_BOT_MENTIONS",
    "HERMES_TELEGRAM_GUEST_MODE",
    "HERMES_TELEGRAM_NOTIFICATIONS",
    "HERMES_TELEGRAM_REQUIRE_MENTION",
    "HERMES_TERMINAL_BACKEND",
    "HERMES_TERMINAL_CWD",
    "HERMES_TERMINAL_HOME_MODE",
    "HERMES_TERMINAL_LIFETIME_SECONDS",
    "HERMES_TERMINAL_TIMEOUT",
    "MATTERMOST_REPLY_MODE",
    "MATTERMOST_REQUIRE_MENTION",
    "MATTERMOST_URL",
)


class BootstrapSettings(NamedTuple):
    mattermost_url: str
    http_timeout_seconds: int
    command_timeout_seconds: int
    container_name_suffix: str
    bot_name: str
    operator_name: str
    operator_email: str
    team_name: str
    channel_name: str


class BootstrapError(RuntimeError):
    pass


def required(values: dict[str, str], key: str) -> str:
    value = values.get(key, "").strip()
    if not value:
        raise BootstrapError(f"canonical {key} is required")
    if any(character in value for character in "\r\n\0"):
        raise BootstrapError(f"canonical {key} is malformed")
    return value


def required_int(
    values: dict[str, str], key: str, *, minimum: int, maximum: int
) -> int:
    raw = required(values, key)
    try:
        value = int(raw)
    except ValueError as error:
        raise BootstrapError(f"canonical {key} must be an integer") from error
    if not minimum <= value <= maximum:
        raise BootstrapError(
            f"canonical {key} must be between {minimum} and {maximum}"
        )
    return value


def required_slug(values: dict[str, str], key: str) -> str:
    value = required(values, key)
    if not re.fullmatch(r"[a-z][a-z0-9._-]{0,62}", value):
        raise BootstrapError(f"canonical {key} is not a valid Mattermost slug")
    return value


def required_email(values: dict[str, str], key: str) -> str:
    value = required(values, key)
    if not re.fullmatch(r"[^\s@]+@[^\s@]+", value):
        raise BootstrapError(f"canonical {key} is not a valid email address")
    return value


def required_base_url(values: dict[str, str], key: str) -> str:
    value = required(values, key).rstrip("/")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise BootstrapError(f"canonical {key} must be a credential-free HTTP(S) URL")
    return value


def bootstrap_settings(values: dict[str, str]) -> BootstrapSettings:
    """Validate every bootstrap-owned setting before any external mutation."""
    for key in CANONICAL_RUNTIME_KEYS:
        required(values, key)
    for key in (
        "HERMES_PAPERCLIP_URL",
        "HERMES_KESTRA_URL",
        "HERMES_LLM_BASE_URL",
    ):
        required_base_url(values, key)
    return BootstrapSettings(
        mattermost_url=required_base_url(values, "MATTERMOST_URL"),
        http_timeout_seconds=required_int(
            values,
            "MATTERMOST_BOOTSTRAP_HTTP_TIMEOUT_SECONDS",
            minimum=1,
            maximum=300,
        ),
        command_timeout_seconds=required_int(
            values,
            "MATTERMOST_BOOTSTRAP_COMMAND_TIMEOUT_SECONDS",
            minimum=1,
            maximum=900,
        ),
        container_name_suffix=required_slug(
            values, "MATTERMOST_CONTAINER_NAME_SUFFIX"
        ),
        bot_name=required_slug(values, "MATTERMOST_HERMES_BOT_USERNAME"),
        operator_name=required_slug(values, "MATTERMOST_OPERATOR_USERNAME"),
        operator_email=required_email(values, "MATTERMOST_OPERATOR_EMAIL"),
        team_name=required_slug(values, "MATTERMOST_PLATFORM_TEAM_NAME"),
        channel_name=required_slug(values, "MATTERMOST_OPERATOR_CHANNEL_NAME"),
    )


@contextmanager
def platform_env_lock():
    """Serialize canonical updates with every other platform.env writer."""
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    ENV_FILE.parent.chmod(0o700)
    if os.geteuid() == 0:
        os.chown(ENV_FILE.parent, 0, 0)
    with ENV_LOCK.open("a+") as handle:
        handle.flush()
        ENV_LOCK.chmod(0o600)
        if os.geteuid() == 0:
            os.chown(ENV_LOCK, 0, 0)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def command(
    argv: list[str], *, check: bool = True, timeout: int
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise BootstrapError("Mattermost bootstrap command timed out") from error
    if check and result.returncode:
        raise BootstrapError("Mattermost bootstrap command failed")
    return result


def mattermost_container(settings: BootstrapSettings) -> str:
    result = command(
        ["docker", "ps", "--format", "{{.Names}}"],
        timeout=settings.command_timeout_seconds,
    )
    matches = [
        line
        for line in result.stdout.splitlines()
        if line.endswith(settings.container_name_suffix)
    ]
    if len(matches) != 1:
        raise BootstrapError("expected exactly one running Mattermost container")
    return matches[0]


def mmctl(
    settings: BootstrapSettings,
    container: str,
    *args: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return command(
        [
            "docker",
            "exec",
            container,
            "mmctl",
            "--local",
            "--json",
            "--suppress-warnings",
            *args,
        ],
        check=check,
        timeout=settings.command_timeout_seconds,
    )


def payload(result: subprocess.CompletedProcess[str]) -> Any:
    if not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise BootstrapError("Mattermost returned non-JSON command output") from error


def records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def first_named(items: Any, name: str) -> dict[str, Any] | None:
    for item in records(items):
        if item.get("name") == name or item.get("username") == name:
            return item
    return None


def secret_from(value: Any) -> str | None:
    """Find a token field without accepting arbitrary 26-character IDs."""
    if isinstance(value, dict):
        for key, item in value.items():
            if "token" in key.lower() and isinstance(item, str) and len(item) >= 20:
                return item
        for item in value.values():
            found = secret_from(item)
            if found:
                return found
    if isinstance(value, list):
        for item in value:
            found = secret_from(item)
            if found:
                return found
    return None


def api_request(
    settings: BootstrapSettings,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    bearer: str | None = None,
    method: str = "POST",
) -> tuple[Any, dict[str, str]]:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    request = urllib.request.Request(
        settings.mattermost_url + path,
        data=(
            json.dumps(body, separators=(",", ":")).encode()
            if body is not None
            else None
        ),
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(
            request, timeout=settings.http_timeout_seconds
        ) as response:
            raw = response.read(1_000_001)
            response_headers = dict(response.headers.items())
    except urllib.error.HTTPError as error:
        error_id = "unknown"
        try:
            error_payload = json.loads(error.read(100_001))
            if isinstance(error_payload, dict):
                candidate = error_payload.get("id")
                if isinstance(candidate, str) and re.fullmatch(
                    r"[A-Za-z0-9_.-]{1,160}", candidate
                ):
                    error_id = candidate
        except (ValueError, json.JSONDecodeError):
            pass
        raise BootstrapError(
            f"Mattermost API rejected {path}: HTTP {error.code} ({error_id})"
        ) from error
    if len(raw) > 1_000_000:
        raise BootstrapError("Mattermost API response exceeded the size limit")
    try:
        return json.loads(raw), response_headers
    except json.JSONDecodeError as error:
        raise BootstrapError("Mattermost API returned non-JSON output") from error


def admin_login(settings: BootstrapSettings, login_id: str, password: str) -> str:
    actor, headers = api_request(
        settings,
        "/api/v4/users/login",
        body={"login_id": login_id, "password": password},
    )
    roles = (
        set(str(actor.get("roles") or "").split()) if isinstance(actor, dict) else set()
    )
    if "system_admin" not in roles:
        raise BootstrapError("Mattermost bootstrap principal is not a system admin")
    token = headers.get("Token") or headers.get("token")
    if not token:
        raise BootstrapError("Mattermost login did not return a session token")
    return token


def read_env() -> tuple[list[str], dict[str, str]]:
    if not ENV_FILE.is_file():
        raise BootstrapError("protected platform credential file is missing")
    info = ENV_FILE.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        raise BootstrapError(
            "platform credential file must be root-owned and mode 0600"
        )
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
    values: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip()
    return lines, values


def update_env(updates: dict[str, str]) -> None:
    with platform_env_lock():
        lines, _ = read_env()
        pending = dict(updates)
        rendered: list[str] = []
        for line in lines:
            match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", line.strip())
            if match and match.group(1) in pending:
                key = match.group(1)
                rendered.append(f"{key}={pending.pop(key)}")
            else:
                rendered.append(line)
        if pending:
            if rendered and rendered[-1].strip():
                rendered.append("")
            rendered.append("# Native Hermes integration (server-generated)")
            rendered.extend(f"{key}={value}" for key, value in sorted(pending.items()))

        fd, temporary = tempfile.mkstemp(
            prefix="platform.env.", dir=str(ENV_FILE.parent)
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("\n".join(rendered) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chown(temporary, 0, 0)
            os.replace(temporary, ENV_FILE)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def ensure_user(
    settings: BootstrapSettings,
    container: str,
    admin_token: str,
    existing_password: str | None,
) -> tuple[dict[str, Any], str]:
    found = mmctl(
        settings,
        container,
        "user",
        "search",
        settings.operator_name,
        check=False,
    )
    if found.returncode == 0:
        user = first_named(payload(found), settings.operator_name)
        if user:
            if existing_password:
                password = existing_password
            else:
                password = secrets.token_urlsafe(36)
                api_request(
                    settings,
                    f"/api/v4/users/{user['id']}/password",
                    bearer=admin_token,
                    method="PUT",
                    body={"new_password": password},
                )
            api_request(
                settings,
                f"/api/v4/users/{user['id']}/roles",
                bearer=admin_token,
                method="PUT",
                body={"roles": "system_user system_admin"},
            )
            return user, password
    password = secrets.token_urlsafe(36)
    created, _ = api_request(
        settings,
        "/api/v4/users",
        bearer=admin_token,
        body={
            "email": settings.operator_email,
            "username": settings.operator_name,
            "password": password,
            "email_verified": True,
        },
    )
    user = created if isinstance(created, dict) else None
    if not user:
        found = mmctl(
            settings, container, "user", "search", settings.operator_name
        )
        user = first_named(payload(found), settings.operator_name)
    if not user:
        raise BootstrapError("operator account could not be resolved after creation")
    api_request(
        settings,
        f"/api/v4/users/{user['id']}/roles",
        bearer=admin_token,
        method="PUT",
        body={"roles": "system_user system_admin"},
    )
    return user, password


def ensure_bot(
    settings: BootstrapSettings,
    container: str,
    admin_token: str,
    existing_token: str | None,
) -> tuple[dict[str, Any], str]:
    bot = first_named(
        payload(mmctl(settings, container, "bot", "list")), settings.bot_name
    )
    if not bot:
        created, _ = api_request(
            settings,
            "/api/v4/bots",
            bearer=admin_token,
            body={
                "username": settings.bot_name,
                "display_name": "Hermes",
                "description": "Native Hermes Agent",
            },
        )
        bot = created if isinstance(created, dict) else None
    if not bot or not (bot.get("user_id") or bot.get("id")):
        bot = first_named(
            payload(mmctl(settings, container, "bot", "list")), settings.bot_name
        )
    if not bot:
        raise BootstrapError("Hermes bot could not be resolved after creation")
    if existing_token:
        return bot, existing_token
    bot_user_id = str(bot.get("user_id") or bot.get("id"))
    generated, _ = api_request(
        settings,
        f"/api/v4/users/{bot_user_id}/tokens",
        bearer=admin_token,
        body={"description": "mte-hermes-native"},
    )
    token = secret_from(generated)
    if not token:
        if isinstance(generated, dict):
            token = generated.get("token")
        if not token:
            raise BootstrapError("Mattermost bot token was not returned")
    return bot, token


def ensure_team(settings: BootstrapSettings, container: str) -> dict[str, Any]:
    team = first_named(
        payload(mmctl(settings, container, "team", "list")), settings.team_name
    )
    if team:
        return team
    created = payload(
        mmctl(
            settings,
            container,
            "team",
            "create",
            "--name",
            settings.team_name,
            "--display-name",
            "MTE Platform",
            "--private",
        )
    )
    team = first_named(created, settings.team_name)
    if not team:
        team = first_named(
            payload(mmctl(settings, container, "team", "list")), settings.team_name
        )
    if not team:
        raise BootstrapError("Mattermost team could not be resolved after creation")
    return team


def ensure_channel(settings: BootstrapSettings, container: str) -> dict[str, Any]:
    channel = first_named(
        payload(
            mmctl(settings, container, "channel", "list", settings.team_name)
        ),
        settings.channel_name,
    )
    if channel:
        return channel
    created = payload(
        mmctl(
            settings,
            container,
            "channel",
            "create",
            "--team",
            settings.team_name,
            "--name",
            settings.channel_name,
            "--display-name",
            "Hermes",
            "--private",
        )
    )
    channel = first_named(created, settings.channel_name)
    if not channel:
        channel = first_named(
            payload(
                mmctl(settings, container, "channel", "list", settings.team_name)
            ),
            settings.channel_name,
        )
    if not channel:
        raise BootstrapError("Mattermost channel could not be resolved after creation")
    return channel


def main() -> int:
    if os.geteuid() != 0:
        raise BootstrapError("run as root")
    _, old_values = read_env()
    settings = bootstrap_settings(old_values)
    admin_username = required(old_values, "MATTERMOST_ADMIN_USERNAME")
    admin_password = required(old_values, "MATTERMOST_ADMIN_PASSWORD")

    # Everything above this point is validation-only. No Mattermost or
    # credential mutation is allowed until the full canonical contract passes.
    container = mattermost_container(settings)
    bot_setting = mmctl(
        settings,
        container,
        "config",
        "get",
        "ServiceSettings.EnableBotAccountCreation",
        check=False,
    )
    if bot_setting.returncode == 0:
        mmctl(
            settings,
            container,
            "config",
            "set",
            "ServiceSettings.EnableBotAccountCreation",
            "true",
        )
    mmctl(
        settings,
        container,
        "config",
        "set",
        "ServiceSettings.EnableUserAccessTokens",
        "true",
    )
    admin_token = admin_login(settings, admin_username, admin_password)
    operator, operator_password = ensure_user(
        settings,
        container,
        admin_token,
        old_values.get("MATTERMOST_OPERATOR_PASSWORD"),
    )
    session_token = admin_login(settings, settings.operator_name, operator_password)
    bot, bot_token = ensure_bot(
        settings, container, session_token, old_values.get("MATTERMOST_TOKEN")
    )
    team = ensure_team(settings, container)
    channel = ensure_channel(settings, container)

    for username in (settings.operator_name, settings.bot_name):
        mmctl(
            settings,
            container,
            "team",
            "users",
            "add",
            settings.team_name,
            username,
        )
        mmctl(
            settings,
            container,
            "channel",
            "users",
            "add",
            f"{settings.team_name}:{settings.channel_name}",
            username,
        )

    updates = {
        "MATTERMOST_ALLOWED_USERS": str(operator["id"]),
        "MATTERMOST_HOME_CHANNEL": str(channel["id"]),
        "MATTERMOST_OPERATOR_PASSWORD": operator_password,
        "MATTERMOST_TOKEN": bot_token,
    }
    update_env(updates)

    print(
        json.dumps(
            {
                "ok": True,
                "botId": bot.get("user_id") or bot.get("id"),
                "channelId": channel["id"],
                "operatorId": operator["id"],
                "teamId": team["id"],
                "credentials": "stored-server-side-redacted",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BootstrapError, KeyError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        raise SystemExit(1)

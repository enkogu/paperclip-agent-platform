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
from typing import Any
import urllib.error
import urllib.request


ENV_FILE = Path("/root/.config/mte-secrets/platform.env")
ENV_LOCK = ENV_FILE.parent / ".platform-env.lock"
BOT_NAME = "hermes-operator"
OPERATOR_NAME = "mte-operator"
TEAM_NAME = "mte-platform"
CHANNEL_NAME = "operator"
MATTERMOST_URL = "http://127.0.0.1:18065"


class BootstrapError(RuntimeError):
    pass


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


def command(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, text=True, capture_output=True, check=False)
    if check and result.returncode:
        raise BootstrapError("Mattermost bootstrap command failed")
    return result


def mattermost_container() -> str:
    result = command(["docker", "ps", "--format", "{{.Names}}"])
    matches = [
        line for line in result.stdout.splitlines() if line.endswith("mattermost-1")
    ]
    if len(matches) != 1:
        raise BootstrapError("expected exactly one running Mattermost container")
    return matches[0]


def mmctl(
    container: str, *args: str, check: bool = True
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
        MATTERMOST_URL + path,
        data=(
            json.dumps(body, separators=(",", ":")).encode()
            if body is not None
            else None
        ),
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
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


def admin_login(login_id: str, password: str) -> str:
    actor, headers = api_request(
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
    container: str, admin_token: str, existing_password: str | None
) -> tuple[dict[str, Any], str]:
    found = mmctl(container, "user", "search", OPERATOR_NAME, check=False)
    if found.returncode == 0:
        user = first_named(payload(found), OPERATOR_NAME)
        if user:
            if existing_password:
                password = existing_password
            else:
                password = secrets.token_urlsafe(36)
                api_request(
                    f"/api/v4/users/{user['id']}/password",
                    bearer=admin_token,
                    method="PUT",
                    body={"new_password": password},
                )
            api_request(
                f"/api/v4/users/{user['id']}/roles",
                bearer=admin_token,
                method="PUT",
                body={"roles": "system_user system_admin"},
            )
            return user, password
    password = secrets.token_urlsafe(36)
    created, _ = api_request(
        "/api/v4/users",
        bearer=admin_token,
        body={
            "email": "operator@mte.local",
            "username": OPERATOR_NAME,
            "password": password,
            "email_verified": True,
        },
    )
    user = created if isinstance(created, dict) else None
    if not user:
        found = mmctl(container, "user", "search", OPERATOR_NAME)
        user = first_named(payload(found), OPERATOR_NAME)
    if not user:
        raise BootstrapError("operator account could not be resolved after creation")
    api_request(
        f"/api/v4/users/{user['id']}/roles",
        bearer=admin_token,
        method="PUT",
        body={"roles": "system_user system_admin"},
    )
    return user, password


def ensure_bot(
    container: str, admin_token: str, existing_token: str | None
) -> tuple[dict[str, Any], str]:
    bot = first_named(payload(mmctl(container, "bot", "list")), BOT_NAME)
    if not bot:
        created, _ = api_request(
            "/api/v4/bots",
            bearer=admin_token,
            body={
                "username": BOT_NAME,
                "display_name": "Hermes",
                "description": "Native Hermes Agent",
            },
        )
        bot = created if isinstance(created, dict) else None
    if not bot or not (bot.get("user_id") or bot.get("id")):
        bot = first_named(payload(mmctl(container, "bot", "list")), BOT_NAME)
    if not bot:
        raise BootstrapError("Hermes bot could not be resolved after creation")
    if existing_token:
        return bot, existing_token
    bot_user_id = str(bot.get("user_id") or bot.get("id"))
    generated, _ = api_request(
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


def ensure_team(container: str) -> dict[str, Any]:
    team = first_named(payload(mmctl(container, "team", "list")), TEAM_NAME)
    if team:
        return team
    created = payload(
        mmctl(
            container,
            "team",
            "create",
            "--name",
            TEAM_NAME,
            "--display-name",
            "MTE Platform",
            "--private",
        )
    )
    team = first_named(created, TEAM_NAME)
    if not team:
        team = first_named(payload(mmctl(container, "team", "list")), TEAM_NAME)
    if not team:
        raise BootstrapError("Mattermost team could not be resolved after creation")
    return team


def ensure_channel(container: str) -> dict[str, Any]:
    channel = first_named(
        payload(mmctl(container, "channel", "list", TEAM_NAME)), CHANNEL_NAME
    )
    if channel:
        return channel
    created = payload(
        mmctl(
            container,
            "channel",
            "create",
            "--team",
            TEAM_NAME,
            "--name",
            CHANNEL_NAME,
            "--display-name",
            "Hermes",
            "--private",
        )
    )
    channel = first_named(created, CHANNEL_NAME)
    if not channel:
        channel = first_named(
            payload(mmctl(container, "channel", "list", TEAM_NAME)), CHANNEL_NAME
        )
    if not channel:
        raise BootstrapError("Mattermost channel could not be resolved after creation")
    return channel


def main() -> int:
    if os.geteuid() != 0:
        raise BootstrapError("run as root")
    container = mattermost_container()
    bot_setting = mmctl(
        container,
        "config",
        "get",
        "ServiceSettings.EnableBotAccountCreation",
        check=False,
    )
    if bot_setting.returncode == 0:
        mmctl(
            container,
            "config",
            "set",
            "ServiceSettings.EnableBotAccountCreation",
            "true",
        )
    mmctl(
        container,
        "config",
        "set",
        "ServiceSettings.EnableUserAccessTokens",
        "true",
    )
    _, old_values = read_env()
    admin_username = old_values.get("MATTERMOST_ADMIN_USERNAME") or "mte-admin"
    admin_password = old_values.get("MATTERMOST_ADMIN_PASSWORD", "")
    if not admin_password:
        raise BootstrapError(
            "Mattermost admin credential is required before Hermes bootstrap"
        )
    admin_token = admin_login(admin_username, admin_password)
    operator, operator_password = ensure_user(
        container, admin_token, old_values.get("MATTERMOST_OPERATOR_PASSWORD")
    )
    session_token = admin_login(OPERATOR_NAME, operator_password)
    bot, bot_token = ensure_bot(
        container, session_token, old_values.get("MATTERMOST_TOKEN")
    )
    team = ensure_team(container)
    channel = ensure_channel(container)

    for username in (OPERATOR_NAME, BOT_NAME):
        mmctl(container, "team", "users", "add", TEAM_NAME, username)
        mmctl(
            container,
            "channel",
            "users",
            "add",
            f"{TEAM_NAME}:{CHANNEL_NAME}",
            username,
        )

    updates = {
        "HERMES_APPROVALS_CRON_MODE": "deny",
        "HERMES_APPROVALS_DESTRUCTIVE_SLASH_CONFIRM": "true",
        "HERMES_APPROVALS_MCP_RELOAD_CONFIRM": "true",
        "HERMES_APPROVALS_MODE": "manual",
        "HERMES_APPROVALS_TIMEOUT": "600",
        "HERMES_API_SERVER_ENABLED": "true",
        "HERMES_API_SERVER_HOST": "127.0.0.1",
        "HERMES_API_SERVER_MODEL_NAME": "mte-hermes",
        "HERMES_API_SERVER_PORT": "8642",
        "HERMES_EXEC_ASK": "1",
        "HERMES_DISPLAY_TOOL_PROGRESS": "new",
        "HERMES_GATEWAY_STREAMING_ENABLED": "true",
        "HERMES_GATEWAY_STREAMING_TRANSPORT": "edit",
        "HERMES_PAPERCLIP_URL": "http://127.0.0.1:3100/api",
        "HERMES_KESTRA_URL": "http://127.0.0.1:18081",
        "HERMES_LLM_BASE_URL": "http://127.0.0.1:20128/v1",
        "HERMES_LLM_API_MODE": "chat_completions",
        "HERMES_LLM_PROVIDER": "custom",
        "HERMES_TELEGRAM_EXCLUSIVE_BOT_MENTIONS": "true",
        "HERMES_TELEGRAM_GUEST_MODE": "false",
        "HERMES_TELEGRAM_NOTIFICATIONS": "important",
        "HERMES_TELEGRAM_REQUIRE_MENTION": "true",
        "HERMES_TERMINAL_BACKEND": "local",
        "HERMES_TERMINAL_CWD": "/opt/mte-platform",
        "HERMES_TERMINAL_HOME_MODE": "real",
        "HERMES_TERMINAL_LIFETIME_SECONDS": "1800",
        "HERMES_TERMINAL_TIMEOUT": "600",
        "MATTERMOST_URL": MATTERMOST_URL,
        "MATTERMOST_ALLOWED_USERS": str(operator["id"]),
        "MATTERMOST_HOME_CHANNEL": str(channel["id"]),
        "MATTERMOST_REQUIRE_MENTION": "true",
        "MATTERMOST_REPLY_MODE": "thread",
    }
    updates["MATTERMOST_TOKEN"] = bot_token
    updates["MATTERMOST_OPERATOR_PASSWORD"] = operator_password
    updates["HERMES_API_SERVER_KEY"] = old_values.get(
        "HERMES_API_SERVER_KEY"
    ) or secrets.token_urlsafe(48)
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

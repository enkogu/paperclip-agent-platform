#!/usr/bin/env python3
"""Idempotent post-deploy account, workspace and service-token provisioning.

This script is intended to run on the deployment host after the Compose
applications are healthy.  It never prints credential values.  Automatically
created credentials live only in canonical ``$MTE_SECRET_ROOT/platform.env``
with mode 0600. Runtime projections are owned exclusively by ``server-config``;
this script stores encrypted Paperclip bindings instead of editable copies.
All native harnesses use profile-scoped 9Router runtime keys. Native
subscription credentials and auth homes are not created or supported.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import fcntl
import hashlib
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request
import uuid

import yaml


ROOT = Path(os.environ.get("MTE_PLATFORM_ROOT", "/opt/mte-platform"))
SECRET_ROOT = Path(os.environ.get("MTE_SECRET_ROOT", "/root/.config/mte-secrets"))
CONFIG = ROOT / "config/platform.json"
PLATFORM_ENV = SECRET_ROOT / "platform.env"
PLATFORM_LOCK = SECRET_ROOT / ".platform-env.lock"
INTEGRATIONS = SECRET_ROOT / "integrations"
SERVICES = SECRET_ROOT / "services"
REFS = INTEGRATIONS / "agent-access-refs.json"
CONFIG_RENDERER = ROOT / "bin/server-config.py"
PROJECTION_MANIFEST = SECRET_ROOT / "projections-manifest.json"
PROVISION_VERIFY_EVIDENCE = ROOT / "evidence/account-provisioning-verify.json"

PAPERCLIP_CONTAINER = "mte-paperclip"
PAPERCLIP_CONFIG_PATH = "/data/instances/default/config.json"
PAPERCLIP_DEFAULT_KEY_PATH = "/data/instances/default/secrets/master.key"
SENSITIVE_ENV_KEY_RE = re.compile(
    r"(^token$|[-_]?token$|api[-_]?key|access[-_]?token|auth(?:_?token)?|"
    r"authorization|bearer|secret|passwd|password|credential|jwt|"
    r"private[-_]?key|cookie|connectionstring)",
    re.IGNORECASE,
)

DEFAULT_USER_SECRET_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {
        "key": "mte.github.personal_access_token",
        "name": "GitHub personal access token",
        "description": "Per-user GitHub token used only by profiles whose tool policy allows GitHub.",
        "usageGuidance": "Use a fine-grained token restricted to the repositories and operations this user authorizes.",
        "sourceComponent": "canonical",
        "sourceKey": "GITHUB_TOKEN",
        "toolSelectors": ["github"],
    },
)

INTEGRATION_PREFIXES = {
    "mattermost": ("MATTERMOST_",),
    "9router": ("NINEROUTER_",),
    "paperclip": ("PAPERCLIP_",),
}

# These Paperclip keys are idempotency markers owned by the secret reconcilers.
# They must never enter the component snapshot: saving that older snapshot at
# the end of a provision pass would otherwise undo a rotation performed during
# the same pass.
PAPERCLIP_RECONCILER_STATE_PREFIXES = (
    "PAPERCLIP_SECRET_",
    "PAPERCLIP_USER_SECRET_",
)
PAPERCLIP_UNATTENDED_OWNER_BOOTSTRAP_KEY = (
    "MTE_ALLOW_UNATTENDED_PAPERCLIP_OWNER_BOOTSTRAP"
)
PAPERCLIP_OWNER_INVITE_ID_KEY = "PAPERCLIP_OWNER_INVITE_ID"
PAPERCLIP_OWNER_BOOTSTRAP_REQUEST_TYPE_KEY = (
    "PAPERCLIP_OWNER_BOOTSTRAP_REQUEST_TYPE"
)
PAPERCLIP_OWNER_BOOTSTRAP_STATE_KEYS = frozenset(
    {
        PAPERCLIP_OWNER_INVITE_ID_KEY,
        PAPERCLIP_OWNER_BOOTSTRAP_REQUEST_TYPE_KEY,
    }
)

# Host-side provisioning endpoints are assembled exclusively from the rendered
# platform config and canonical platform.env. The ports below are references,
# not defaults: server-config owns their values in the single runtime SSOT.
SERVICE_ENDPOINT_REFS: dict[str, tuple[str, str]] = {
    "postgrest": ("POSTGREST_HEALTH_URL", "POSTGREST_ORIGIN_PORT"),
    "mattermost": ("MATTERMOST_HEALTH_URL", "MATTERMOST_ORIGIN_PORT"),
    "kestra": ("KESTRA_HEALTH_URL", "KESTRA_ORIGIN_PORT"),
    "9router": ("NINEROUTER_HEALTH_URL", "NINEROUTER_ORIGIN_PORT"),
    "paperclip": ("PAPERCLIP_HEALTH_URL", "PAPERCLIP_ORIGIN_PORT"),
}

TERMINAL_READY = {"ready", "configured", "not_applicable", "unsupported"}
REQUIRED_COMPONENTS = {
    "mattermost",
    "kestra",
    "9router",
    "paperclip",
}

E2E_GITHUB_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
E2E_GITHUB_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
PAPERCLIP_E2E_WORKSPACE_NAME = "MTE GitHub E2E primary"
PAPERCLIP_E2E_WORKSPACE_PURPOSE = "github-e2e-primary"
PAPERCLIP_E2E_WORKSPACE_MANAGER = "mte-server-provision"
PAPERCLIP_DAYTONA_ENVIRONMENT_PURPOSE = "coding-daytona"
PAPERCLIP_DAYTONA_ENVIRONMENT_MANAGER = "mte-platform"


class ApiError(RuntimeError):
    """HTTP failure retaining only status and a non-secret operation label."""

    def __init__(
        self,
        status: int,
        reason: str = "http_error",
        *,
        operation: str = "",
        response_error_sha256: str = "",
        response_error_length: int = 0,
    ) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.operation = operation
        self.response_error_sha256 = response_error_sha256
        self.response_error_length = response_error_length


def now() -> int:
    return int(time.time())


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def password() -> str:
    """Generate a password that also satisfies common mixed-class policies."""
    return f"Mte1!{token(28)}"


def safe_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    if not slug:
        raise RuntimeError("invalid_empty_slug")
    return slug


def profile_catalog() -> list[dict[str, Any]]:
    candidates = (
        ROOT / "runtime/profiles/profiles.yaml",
        ROOT / "config/profiles/catalog.yaml",
        ROOT / "templates/profiles/profiles.yaml",
    )
    for path in candidates:
        if not path.is_file():
            continue
        try:
            payload = yaml.safe_load(path.read_text())
        except (OSError, yaml.YAMLError):
            continue
        rows = payload.get("profiles", []) if isinstance(payload, dict) else []
        return [row for row in rows if isinstance(row, dict) and row.get("ref")]
    return []


def canonical_mutation_plan(values: dict[str, str]) -> frozenset[str]:
    """Return the exact key-name envelope a provision action may mutate.

    A component function is deliberately unable to authorize itself.  The
    top-level provision action computes this envelope before contacting any
    remote API and passes it into ``Context``.  This makes one-time remote
    credentials fail closed instead of silently changing the canonical SSOT
    when a component is called ad hoc.
    """

    planned = {
        key
        for key in values
        if key.startswith(
            (
                "POSTGREST_",
                "MATTERMOST_",
                "NINEROUTER_",
                "PAPERCLIP_",
            )
        )
        or key
        in {
            "HERMES_LLM_API_KEY",
            "HERMES_LLM_BASE_URL",
            "HERMES_LLM_MODEL",
            "HERMES_PAPERCLIP_API_KEY",
        }
    }
    planned.update(
        {
            "MATTERMOST_ADMIN_USERNAME",
            "MATTERMOST_ADMIN_EMAIL",
            "MATTERMOST_ADMIN_PASSWORD",
            "MATTERMOST_BOT_TOKEN",
            "MATTERMOST_BOT_USER_ID",
            "MATTERMOST_TEAM_ID",
            "MATTERMOST_ALERT_WEBHOOK_URL",
            "NINEROUTER_AGENT_API_KEY",
            "NINEROUTER_AGENT_API_KEY_ID",
            "NINEROUTER_OPENAI_BASE_URL",
            "NINEROUTER_ANTHROPIC_BASE_URL",
            "NINEROUTER_MINIMAX_PROVIDER_NODE_ID",
            "NINEROUTER_MINIMAX_CONNECTION_ID",
            "NINEROUTER_MINIMAX_SOURCE_FINGERPRINT",
            "NINEROUTER_MINIMAX_CANARY_AT",
            "HERMES_LLM_API_KEY",
            "HERMES_LLM_BASE_URL",
            "HERMES_LLM_MODEL",
            "PAPERCLIP_COMPANY_ID",
            "PAPERCLIP_BOARD_API_KEY",
            "PAPERCLIP_BOARD_EMAIL",
            "PAPERCLIP_BOARD_PASSWORD",
            "PAPERCLIP_PROJECT_ID",
            "PAPERCLIP_SERVICE_AGENT_ID",
            "PAPERCLIP_AGENT_API_KEY",
            "PAPERCLIP_AGENT_API_KEY_ID",
            "PAPERCLIP_AGENT_KEY_STATE",
            *PAPERCLIP_OWNER_BOOTSTRAP_STATE_KEYS,
            "HERMES_PAPERCLIP_API_KEY",
        }
    )
    for client in ("CLAUDE", "CODEX", "PI", "HERMES"):
        planned.update(
            {
                f"NINEROUTER_CLIENT_{client}_API_KEY",
                f"NINEROUTER_CLIENT_{client}_API_KEY_ID",
            }
        )
    for profile in profile_catalog():
        ref = safe_slug(str(profile["ref"])).upper()
        planned.update(
            {
                f"NINEROUTER_PROFILE_{ref}_API_KEY",
                f"NINEROUTER_PROFILE_{ref}_API_KEY_ID",
            }
        )
    for canary in (
        "CODING_DAYTONA_CLAUDE",
        "CODING_DAYTONA_CODEX",
        "CODING_DAYTONA_PI",
        "HERMES",
    ):
        planned.add(f"NINEROUTER_MINIMAX_CANARY_{canary}_FINGERPRINT")
    paperclip_source_keys = dict(
        [
            ("POSTGREST_PAPERCLIP_TOKEN", "mte.postgrest.paperclip"),
            ("MATTERMOST_BOT_TOKEN", "mte.mattermost.bot"),
            ("HERMES_API_SERVER_KEY", "mte.hermes.api-server"),
            ("KESTRA_ADMIN_PASSWORD", "mte.kestra.shared-password"),
            ("CONTEXT7_API_KEY", "mte.context7.api-key"),
        ]
    )
    if values.get("DATA_CONTENT_PROFILE", "") == "postgres-notion":
        paperclip_source_keys["NOTION_TOKEN"] = "mte.notion.connector"
    for source_key in values:
        if re.fullmatch(
            r"NINEROUTER_(?:AGENT|CLIENT_[A-Z0-9_]+|PROFILE_[A-Z0-9_]+)_API_KEY",
            source_key,
        ):
            suffix = (
                source_key.lower()
                .removeprefix("ninerouter_")
                .removesuffix("_api_key")
                .replace("_", ".")
            )
            paperclip_source_keys[source_key] = f"mte.9router.{suffix}"
        elif re.fullmatch(
            r"TOOLHIVE_PROFILE_CODING_DAYTONA_(?:CODEX|CLAUDE|PI)_BEARER_TOKEN",
            source_key,
        ):
            suffix = (
                source_key.lower()
                .removeprefix("toolhive_profile_")
                .removesuffix("_bearer_token")
                .replace("_", ".")
            )
            paperclip_source_keys[source_key] = f"mte.toolhive.profile.{suffix}.bearer"
    for source_key, secret_key in paperclip_source_keys.items():
        if not canonical_secret_value(values, source_key):
            continue
        prefix = f"PAPERCLIP_SECRET_{safe_slug(secret_key).upper()}"
        planned.update({f"{prefix}_ID", f"{prefix}_SOURCE_FINGERPRINT"})
    for definition in DEFAULT_USER_SECRET_DEFINITIONS:
        source_key = str(definition["sourceKey"])
        if not canonical_secret_value(values, source_key):
            continue
        prefix = f"PAPERCLIP_USER_SECRET_{safe_slug(str(definition['key'])).upper()}"
        planned.update({f"{prefix}_ID", f"{prefix}_SOURCE_FINGERPRINT"})
    return frozenset(planned)


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


def secure_directory(path: Path) -> None:
    if path.exists() and (path.is_symlink() or not path.is_dir()):
        raise RuntimeError("unsafe_secret_directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def write_env(path: Path, values: dict[str, str]) -> None:
    secure_directory(path.parent)
    for key, value in values.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or "\n" in value or "\r" in value:
            raise RuntimeError("unsafe_env_value")
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text("".join(f"{key}={values[key]}\n" for key in sorted(values)))
    temp.chmod(0o600)
    temp.replace(path)
    path.chmod(0o600)


def write_json(path: Path, value: Any) -> None:
    secure_directory(path.parent)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temp.chmod(0o600)
    temp.replace(path)
    path.chmod(0o600)


def canonical_source_hash() -> str:
    if not PLATFORM_ENV.is_file():
        return "missing"
    return hashlib.sha256(PLATFORM_ENV.read_bytes()).hexdigest()


def safe_secret_reference_value(path_value: str) -> str:
    path = Path(path_value)
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("unsafe_secret_reference_type")
    if info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError("unsafe_secret_reference_permissions")
    value = path.read_text().strip()
    if not value or "\n" in value or "\r" in value:
        raise RuntimeError("invalid_secret_reference_value")
    return value


def canonical_secret_value(values: dict[str, str], key: str) -> str:
    direct = values.get(key, "").strip()
    if direct:
        return direct
    reference = values.get(f"{key}_REF", "").strip()
    return safe_secret_reference_value(reference) if reference else ""


def json_from_mixed_output(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for marker in ("[", "{"):
        offset = raw.find(marker)
        if offset >= 0:
            try:
                return decoder.raw_decode(raw[offset:])[0]
            except json.JSONDecodeError:
                pass
    raise RuntimeError("invalid_json_output")


def find_secret(value: Any, prefixes: tuple[str, ...] = ()) -> str | None:
    """Find a one-time token in a response without ever logging the response."""
    if isinstance(value, str) and (not prefixes or value.startswith(prefixes)):
        return value
    if isinstance(value, dict):
        preferred = ("token", "value", "key", "access_token", "accessToken")
        for key in preferred:
            candidate = value.get(key)
            if isinstance(candidate, str) and (
                not prefixes or candidate.startswith(prefixes)
            ):
                return candidate
        for nested in value.values():
            found = find_secret(nested, prefixes)
            if found:
                return found
    if isinstance(value, list):
        for nested in value:
            found = find_secret(nested, prefixes)
            if found:
                return found
    return None


def list_value(payload: Any, *keys: str) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        for key in keys + ("list", "data", "items", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
    return []


def request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: Any | None = None,
    opener: urllib.request.OpenerDirector | None = None,
    timeout: int = 15,
) -> Any:
    parsed_url = urllib.parse.urlsplit(url)
    operation = f"{method.upper()} {parsed_url.path}"
    request_headers = {"User-Agent": "mte-server-provision/1", **(headers or {})}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(
        url, data=data, headers=request_headers, method=method
    )
    client = opener or urllib.request.build_opener()
    try:
        with client.open(request, timeout=timeout) as response:
            raw = response.read(4_000_000)
            if not raw:
                return {}
            try:
                return json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ApiError(
                    response.status, "invalid_json", operation=operation
                ) from exc
    except urllib.error.HTTPError as exc:
        # Never retain response bodies: some APIs return a token in an error
        # payload.  A hash of the top-level error string is sufficient to map
        # a failure back to an audited upstream literal without exposing it.
        error_sha256 = ""
        error_length = 0
        try:
            error_payload = json.loads(exc.read(65_536))
            error_text = (
                error_payload.get("error") if isinstance(error_payload, dict) else None
            )
            if isinstance(error_text, str):
                error_sha256 = hashlib.sha256(error_text.encode()).hexdigest()
                error_length = len(error_text)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            pass
        raise ApiError(
            exc.code,
            operation=operation,
            response_error_sha256=error_sha256,
            response_error_length=error_length,
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ApiError(0, type(exc).__name__, operation=operation) from None


def basic_auth(username: str, password: str) -> dict[str, str]:
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


@dataclass
class Context:
    config: dict[str, Any]
    platform_env: dict[str, str]
    mutate: bool
    strict: bool
    canonical_mutation_keys: frozenset[str] = frozenset()
    canonical_mutations: set[str] = field(default_factory=set)

    @property
    def components(self) -> dict[str, dict[str, Any]]:
        return {row["id"]: row for row in self.config["spec"].get("components", [])}

    def url(self, component: str) -> str:
        row = self.components.get(component, {})
        exposure = row.get("exposure", {})
        if exposure.get("origin"):
            return self._validated_origin(str(exposure["origin"]), component)

        try:
            health_ref, default_port_ref = SERVICE_ENDPOINT_REFS[component]
        except KeyError as exc:
            raise RuntimeError(
                f"service_endpoint_contract_missing:{component}"
            ) from exc

        health = str(row.get("health", {}).get("url", "")).strip()
        if not health or health.startswith("${"):
            health = self.platform_env.get(health_ref, "").strip()
        port_ref = str(exposure.get("originPortRef") or default_port_ref)
        port = self.platform_env.get(port_ref, "").strip()
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise RuntimeError(f"service_origin_port_invalid:{component}:{port_ref}")

        parsed = urllib.parse.urlsplit(health)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise RuntimeError(f"service_health_url_invalid:{component}:{health_ref}")
        host = parsed.hostname
        if ":" in host:
            host = f"[{host}]"
        return f"{parsed.scheme}://{host}:{int(port)}"

    @staticmethod
    def _validated_origin(value: str, component: str) -> str:
        parsed = urllib.parse.urlsplit(value.rstrip("/"))
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise RuntimeError(f"service_origin_invalid:{component}")
        return value.rstrip("/")

    def integration(self, name: str) -> tuple[Path, dict[str, str]]:
        path = INTEGRATIONS / f"{name}.env"
        prefixes = INTEGRATION_PREFIXES.get(name, ())
        return path, {
            key: value
            for key, value in self.platform_env.items()
            if any(key.startswith(prefix) for prefix in prefixes)
            and not (
                name == "paperclip"
                and key.startswith(PAPERCLIP_RECONCILER_STATE_PREFIXES)
            )
        }

    def persist_canonical(self, values: dict[str, str]) -> None:
        if not self.mutate:
            raise RuntimeError("canonical_write_in_read_only_mode")
        clean = {
            key: value
            for key, value in values.items()
            if key != "MTE_PROJECTION_SOURCE_SHA256"
        }
        secure_directory(PLATFORM_ENV.parent)
        lock_path = PLATFORM_LOCK
        with lock_path.open("a+") as lock:
            lock_path.chmod(0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            current = dotenv(PLATFORM_ENV)
            changed = {key for key, value in clean.items() if current.get(key) != value}
            if not changed:
                self.platform_env.clear()
                self.platform_env.update(current)
                return
            unauthorized = changed - self.canonical_mutation_keys
            if unauthorized:
                raise RuntimeError(
                    "canonical_mutation_not_authorized:"
                    + ",".join(sorted(unauthorized))
                )
            current.update({key: clean[key] for key in changed})
            write_env(PLATFORM_ENV, current)
            self.platform_env.clear()
            self.platform_env.update(current)
            self.canonical_mutations.update(changed)

    def save_integration(self, name: str, values: dict[str, str]) -> None:
        """Persist only to canonical state; server-config is the sole projection owner."""
        self.persist_canonical(values)

    def operator_email(self, service: str) -> str:
        specific = self.platform_env.get(f"{service.upper()}_ADMIN_EMAIL", "")
        return (
            specific
            or self.platform_env.get("MTE_OPERATOR_EMAIL", "")
            or f"admin@{service}.mte.local"
        )


def result(component: str, status: str, **fields: Any) -> dict[str, Any]:
    return {"component": component, "status": status, **fields}


def component_error(component: str, exc: BaseException) -> dict[str, Any]:
    details = result(
        component,
        "unavailable" if isinstance(exc, ApiError) and exc.status == 0 else "error",
        errorType=type(exc).__name__,
        httpStatus=getattr(exc, "status", None),
    )
    if isinstance(exc, ApiError) and exc.operation:
        details["operation"] = exc.operation
    if isinstance(exc, ApiError) and exc.response_error_sha256:
        details["responseErrorSha256"] = exc.response_error_sha256
        details["responseErrorLength"] = exc.response_error_length
    return details


def mattermost_container() -> str:
    completed = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}|{{.Image}}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("docker_ps_failed")
    for line in completed.stdout.splitlines():
        name, _, image = line.partition("|")
        if image.startswith("mattermost/mattermost-team-edition:"):
            return name
    raise RuntimeError("mattermost_container_not_found")


def mmctl(container: str, *args: str) -> Any:
    completed = subprocess.run(
        [
            "docker",
            "exec",
            container,
            "/mattermost/bin/mmctl",
            "--local",
            "--json",
            *args,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("mmctl_failed")
    if not completed.stdout.strip():
        return {}
    return json_from_mixed_output(completed.stdout)


def mmctl_optional(container: str, *args: str) -> Any:
    try:
        return mmctl(container, *args)
    except RuntimeError:
        return []


def mmctl_config_set(container: str, key: str, value: str) -> None:
    completed = subprocess.run(
        [
            "docker",
            "exec",
            container,
            "/mattermost/bin/mmctl",
            "--local",
            "config",
            "set",
            key,
            value,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("mmctl_config_set_failed")


def mattermost_admin_session(
    ctx: Context, saved: dict[str, str]
) -> tuple[dict[str, str], dict[str, Any]]:
    request = urllib.request.Request(
        f"{ctx.url('mattermost')}/api/v4/users/login",
        data=json.dumps(
            {
                "login_id": saved["MATTERMOST_ADMIN_USERNAME"],
                "password": saved["MATTERMOST_ADMIN_PASSWORD"],
            }
        ).encode(),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "mte-server-provision/1",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            actor = json.loads(response.read(1_000_000))
            access_token = response.headers.get("Token", "")
    except urllib.error.HTTPError as exc:
        raise ApiError(exc.code) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ApiError(0, type(exc).__name__) from None
    if not access_token or not isinstance(actor, dict):
        raise RuntimeError("mattermost_admin_login_missing_token")
    return {"Authorization": f"Bearer {access_token}"}, actor


def ensure_mattermost_alert_webhook(
    ctx: Context,
    saved: dict[str, str],
    *,
    container: str,
    team_id: str,
) -> dict[str, str]:
    if not team_id:
        raise RuntimeError("mattermost_alert_team_missing")
    if ctx.mutate:
        mmctl_config_set(container, "ServiceSettings.EnableIncomingWebhooks", "true")
    admin_headers, _ = mattermost_admin_session(ctx, saved)
    try:
        channel = request_json(
            "GET",
            f"{ctx.url('mattermost')}/api/v4/teams/{team_id}/channels/name/mte-alerts",
            headers=admin_headers,
        )
    except ApiError as exc:
        if exc.status != 404 or not ctx.mutate:
            raise
        channel = request_json(
            "POST",
            f"{ctx.url('mattermost')}/api/v4/channels",
            headers=admin_headers,
            body={
                "team_id": team_id,
                "name": "mte-alerts",
                "display_name": "MTE Alerts",
                "purpose": "Managed platform and agent alerts",
                "type": "O",
            },
        )
    channel_id = str(channel.get("id") or "")
    if not channel_id:
        raise RuntimeError("mattermost_alert_channel_missing")
    hooks = list_value(
        request_json(
            "GET",
            f"{ctx.url('mattermost')}/api/v4/hooks/incoming?team_id={team_id}&page=0&per_page=200",
            headers=admin_headers,
        )
    )
    hook = next(
        (
            row
            for row in hooks
            if row.get("display_name") == "MTE Alertmanager"
            and row.get("channel_id") == channel_id
        ),
        None,
    )
    if hook is None and ctx.mutate:
        hook = request_json(
            "POST",
            f"{ctx.url('mattermost')}/api/v4/hooks/incoming",
            headers=admin_headers,
            body={
                "channel_id": channel_id,
                "display_name": "MTE Alertmanager",
                "description": "Managed Alertmanager receiver",
            },
        )
    hook_id = str((hook or {}).get("id") or "")
    if not hook_id:
        raise RuntimeError("mattermost_alert_webhook_missing")
    return {"MATTERMOST_ALERT_WEBHOOK_URL": f"{ctx.url('mattermost')}/hooks/{hook_id}"}


def mattermost(ctx: Context) -> dict[str, Any]:
    component = "mattermost"
    path, saved = ctx.integration(component)
    try:
        container = mattermost_container()
        users = list_value(mmctl(container, "user", "list"))
        admin = next((row for row in users if row.get("username") == "mte-admin"), None)
        if admin is None and ctx.mutate:
            saved.setdefault("MATTERMOST_ADMIN_USERNAME", "mte-admin")
            saved.setdefault("MATTERMOST_ADMIN_EMAIL", ctx.operator_email(component))
            saved.setdefault("MATTERMOST_ADMIN_PASSWORD", password())
            ctx.save_integration(component, saved)
            admin = request_json(
                "POST",
                f"{ctx.url(component)}/api/v4/users",
                body={
                    "username": saved["MATTERMOST_ADMIN_USERNAME"],
                    "email": saved["MATTERMOST_ADMIN_EMAIL"],
                    "password": saved["MATTERMOST_ADMIN_PASSWORD"],
                    "first_name": "MTE",
                    "last_name": "Operator",
                    "email_verified": True,
                },
            )
            if not isinstance(admin, dict) or not admin.get("id"):
                raise RuntimeError("mattermost_admin_create_invalid")
            _, actor = mattermost_admin_session(ctx, saved)
            roles = set(str(actor.get("roles") or "").split())
            if "system_admin" not in roles:
                raise RuntimeError("mattermost_first_user_not_system_admin")

        teams = list_value(mmctl(container, "team", "list"))
        team = next((row for row in teams if row.get("name") == "mte"), None)
        if team is None and ctx.mutate:
            team = mmctl(
                container,
                "team",
                "create",
                "--name",
                "mte",
                "--display-name",
                "MTE Agents",
                "--private",
            )
            if not isinstance(team, dict):
                team = {"name": "mte"}
        bots = list_value(mmctl(container, "bot", "list", "--all"), "bots")
        bot = next((row for row in bots if row.get("username") == "mte-agent"), None)
        if bot is None and ctx.mutate:
            # Mattermost keeps bot-account creation disabled by default. This
            # is the single prerequisite for the ordinary admin REST API;
            # without it a valid system-admin session receives HTTP 403.
            mmctl_config_set(container, "ServiceSettings.EnableBotAccountCreation", "true")
            admin_headers, actor = mattermost_admin_session(ctx, saved)
            bot = request_json(
                "POST",
                f"{ctx.url(component)}/api/v4/bots",
                headers=admin_headers,
                body={
                    "username": "mte-agent",
                    "display_name": "MTE Agent",
                    "description": "Managed platform agent identity",
                    "owner_id": actor.get("id"),
                },
            )
            if not isinstance(bot, dict) or not bot.get("username"):
                bot = {"username": "mte-agent"}
            created_token = request_json(
                "POST",
                f"{ctx.url(component)}/api/v4/users/{bot['user_id']}/tokens",
                headers=admin_headers,
                body={"description": "mte-agents"},
            )
            raw = find_secret(created_token)
            if not raw:
                raise RuntimeError("mattermost_bot_token_missing")
            saved["MATTERMOST_BOT_TOKEN"] = raw
            if isinstance(bot, dict) and bot.get("user_id"):
                saved["MATTERMOST_BOT_USER_ID"] = str(bot["user_id"])
            ctx.save_integration(component, saved)
        if bot is not None and not saved.get("MATTERMOST_BOT_TOKEN") and ctx.mutate:
            admin_headers, _ = mattermost_admin_session(ctx, saved)
            existing_tokens = list_value(
                request_json(
                    "GET",
                    f"{ctx.url(component)}/api/v4/users/{bot['user_id']}/tokens",
                    headers=admin_headers,
                )
            )
            managed_token = next(
                (
                    row
                    for row in existing_tokens
                    if row.get("description") in {"autogenerated", "mte-agents"}
                    and row.get("is_active", True)
                ),
                None,
            )
            if managed_token and managed_token.get("id"):
                request_json(
                    "DELETE",
                    f"{ctx.url(component)}/api/v4/users/tokens/{managed_token['id']}",
                    headers=admin_headers,
                )
            generated = request_json(
                "POST",
                f"{ctx.url(component)}/api/v4/users/{bot['user_id']}/tokens",
                headers=admin_headers,
                body={"description": "mte-agents"},
            )
            raw = find_secret(generated)
            if not raw:
                raise RuntimeError("mattermost_bot_token_recovery_failed")
            saved["MATTERMOST_BOT_TOKEN"] = raw
            ctx.save_integration(component, saved)
        if team and ctx.mutate:
            mmctl(container, "team", "users", "add", "mte", "mte-admin")
            mmctl(container, "team", "users", "add", "mte", "mte-agent")
        if team and team.get("id"):
            saved["MATTERMOST_TEAM_ID"] = str(team["id"])
        alert_webhook_ready = False
        if (
            team
            and saved.get("MATTERMOST_ADMIN_USERNAME")
            and saved.get("MATTERMOST_ADMIN_PASSWORD")
        ):
            alert_updates = ensure_mattermost_alert_webhook(
                ctx,
                saved,
                container=container,
                team_id=str(team.get("id") or ""),
            )
            saved.update(alert_updates)
            alert_webhook_ready = bool(saved.get("MATTERMOST_ALERT_WEBHOOK_URL"))
        if ctx.mutate:
            ctx.save_integration(component, saved)

        token_ready = False
        if saved.get("MATTERMOST_BOT_TOKEN"):
            try:
                me = request_json(
                    "GET",
                    f"{ctx.url(component)}/api/v4/users/me",
                    headers={
                        "Authorization": f"Bearer {saved['MATTERMOST_BOT_TOKEN']}"
                    },
                )
                token_ready = bool(me.get("id"))
            except ApiError:
                token_ready = False
        ready = bool(admin and team and bot and token_ready and alert_webhook_ready)
        return result(
            component,
            "ready"
            if ready
            else (
                "pending_bootstrap"
                if not ctx.mutate and (not admin or not team or not bot)
                else "needs_rotation"
            ),
            managed=[
                "system_admin",
                "team",
                "bot",
                "bot_access_token",
                "alert_channel",
                "alertmanager_incoming_webhook",
            ],
            names={
                "admin": "mte-admin",
                "team": "mte",
                "bot": "mte-agent",
                "alertChannel": "mte-alerts",
                "alertWebhook": "MTE Alertmanager",
            },
            fingerprints={
                "botToken": fingerprint(saved["MATTERMOST_BOT_TOKEN"]),
                "alertWebhook": fingerprint(saved["MATTERMOST_ALERT_WEBHOOK_URL"]),
            }
            if saved.get("MATTERMOST_BOT_TOKEN")
            and saved.get("MATTERMOST_ALERT_WEBHOOK_URL")
            else {},
        )
    except BaseException as exc:
        return component_error(component, exc)


def kestra(ctx: Context) -> dict[str, Any]:
    component = "kestra"
    username = ctx.platform_env.get("KESTRA_ADMIN_USER", "")
    password = ctx.platform_env.get("KESTRA_ADMIN_PASSWORD", "")
    if not username or not password:
        return result(
            component, "needs_configuration", reason="missing_basic_auth_refs"
        )
    try:
        request_json(
            "GET",
            f"{ctx.url(component)}/api/v1/main/flows/search",
            headers=basic_auth(username, password),
        )
        return result(
            component,
            "ready",
            managed=["shared_basic_auth_principal", "mte_namespace_via_flow_catalog"],
            names={"principal": username, "namespace": "mte.platform"},
            fingerprints={"basicAuthPassword": fingerprint(password)},
            limitations=[
                "Kestra Open Source supports one server Basic Auth principal; users, service accounts and API tokens are Enterprise features."
            ],
        )
    except BaseException as exc:
        return component_error(component, exc)


def ninerouter_session(
    ctx: Context,
) -> tuple[urllib.request.OpenerDirector, dict[str, str]]:
    path, saved = ctx.integration("9router")
    password = ctx.platform_env.get("NINEROUTER_INITIAL_PASSWORD", "")
    if not password:
        raise RuntimeError("missing_9router_password")
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    request_json(
        "POST",
        f"{ctx.url('9router')}/api/auth/login",
        body={"password": password},
        opener=opener,
    )
    return opener, saved


def bootstrap_ninerouter_keys(ctx: Context) -> dict[str, Any]:
    """Break the render/key bootstrap cycle without touching providers or canaries."""
    opener, _ = ninerouter_session(ctx)
    keys = list_value(
        request_json("GET", f"{ctx.url('9router')}/api/keys", opener=opener),
        "keys",
    )
    specs = (
        ("mte-client-hermes", "NINEROUTER_CLIENT_HERMES_API_KEY"),
        (
            "mte-profile-coding-daytona-codex",
            "NINEROUTER_PROFILE_CODING_DAYTONA_CODEX_API_KEY",
        ),
        (
            "mte-profile-coding-daytona-claude",
            "NINEROUTER_PROFILE_CODING_DAYTONA_CLAUDE_API_KEY",
        ),
        (
            "mte-profile-coding-daytona-pi",
            "NINEROUTER_PROFILE_CODING_DAYTONA_PI_API_KEY",
        ),
    )
    updates: dict[str, str] = {}
    evidence: list[dict[str, Any]] = []
    for name, token_key in specs:
        remote = next(
            (
                row
                for row in keys
                if row.get("name") == name and row.get("isActive", True)
            ),
            None,
        )
        current_token = ctx.platform_env.get(token_key, "")
        if remote:
            current_token = current_token or find_secret(remote, ("sk-",)) or ""
        if remote is None or not current_token:
            if remote and remote.get("id"):
                request_json(
                    "DELETE",
                    f"{ctx.url('9router')}/api/keys/{remote['id']}",
                    opener=opener,
                )
                keys.remove(remote)
            remote = request_json(
                "POST",
                f"{ctx.url('9router')}/api/keys",
                opener=opener,
                body={"name": name},
            )
            current_token = find_secret(remote, ("sk-",)) or ""
            if isinstance(remote, dict):
                keys.append(remote)
        if not current_token or not remote or not remote.get("id"):
            raise RuntimeError("9router_scoped_key_material_missing")
        request_json(
            "GET",
            f"{ctx.url('9router')}/v1/models",
            headers={"Authorization": f"Bearer {current_token}"},
        )
        updates[token_key] = current_token
        updates[f"{token_key}_ID"] = str(remote["id"])
        evidence.append(
            {
                "name": name,
                "tokenKey": token_key,
                "status": "ready",
                "fingerprint": fingerprint(current_token),
            }
        )
    model = ctx.platform_env.get("MINIMAX_MODEL", "").strip()
    if not model:
        raise RuntimeError("missing_minimax_model")
    updates.update(
        {
            "HERMES_LLM_API_KEY": updates["NINEROUTER_CLIENT_HERMES_API_KEY"],
            "HERMES_LLM_BASE_URL": f"{ctx.url('9router')}/v1",
            "HERMES_LLM_MODEL": f"mte-minimax/{model}",
        }
    )
    ctx.persist_canonical(updates)
    return {
        "action": "bootstrap-router-keys",
        "timestamp": now(),
        "ok": True,
        "keys": evidence,
        "canonicalKeys": sorted(updates),
        "canonicalSourceHash": canonical_source_hash()[:16],
        "providersChanged": False,
        "canariesRun": False,
        "paperclipChanged": False,
    }


def ensure_ninerouter_key(
    ctx: Context,
    opener: urllib.request.OpenerDirector,
    keys: list[dict[str, Any]],
    *,
    name: str,
    token_key: str,
    projection_path: Path,
) -> dict[str, Any]:
    persisted_token = bool(ctx.platform_env.get(token_key))
    remote = next(
        (row for row in keys if row.get("name") == name and row.get("isActive", True)),
        None,
    )
    if remote is None and ctx.mutate:
        remote = request_json(
            "POST", f"{ctx.url('9router')}/api/keys", opener=opener, body={"name": name}
        )
        if isinstance(remote, dict):
            keys.append(remote)
    updates: dict[str, str] = {}
    if remote:
        raw = find_secret(remote, ("sk-",))
        if raw and ctx.mutate:
            updates[token_key] = raw
        if remote.get("id"):
            updates[f"{token_key}_ID"] = str(remote["id"])
    updates.setdefault("NINEROUTER_OPENAI_BASE_URL", f"{ctx.url('9router')}/v1")
    updates.setdefault("NINEROUTER_ANTHROPIC_BASE_URL", ctx.url("9router"))
    if ctx.mutate and updates:
        ctx.persist_canonical(updates)
    current_token = ctx.platform_env.get(token_key, "")
    token_ready = False
    if current_token and (ctx.mutate or persisted_token):
        try:
            request_json(
                "GET",
                f"{ctx.url('9router')}/v1/models",
                headers={"Authorization": f"Bearer {current_token}"},
            )
            token_ready = True
        except ApiError:
            token_ready = False
    return {
        "name": name,
        "status": "ready"
        if token_ready
        else ("pending_bootstrap" if remote is None else "needs_rotation"),
        "credentialFile": str(projection_path),
        "tokenKey": token_key,
        "fingerprint": fingerprint(current_token) if current_token else None,
    }


def ensure_ninerouter_custom_model(
    ctx: Context,
    opener: urllib.request.OpenerDirector,
    *,
    provider_alias: str,
    model_id: str,
    client_token: str,
) -> dict[str, Any]:
    """Reconcile one exact 9Router custom-model record and prove its route.

    Compatible provider nodes are routed by their declared prefix, but 9Router
    does not derive the public ``/v1/models`` catalog from a provider
    connection's ``defaultModel``.  The official custom-model API is therefore
    the declarative source for this catalog entry.

    A read-only status is intentionally not green from the catalog response
    alone: the exact scoped client credential must also complete a minimal
    request on the exact published model.
    """

    base = ctx.url("9router")
    route_model = f"{provider_alias}/{model_id}"

    def inventory() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        rows = list_value(
            request_json("GET", f"{base}/api/models/custom", opener=opener),
            "models",
        )
        matching = [
            row
            for row in rows
            if str(row.get("providerAlias") or "") == provider_alias
            and str(row.get("id") or "") == model_id
        ]
        exact = [row for row in matching if str(row.get("type") or "llm") == "llm"]
        return matching, exact

    matching, exact = inventory()
    if ctx.mutate and (len(matching) != 1 or len(exact) != 1):
        # Remove every conflicting type first.  Re-adding one exact record makes
        # the second run a true no-op and prevents ambiguous catalog entries.
        for model_type in sorted(
            {str(row.get("type") or "llm") for row in matching} | {"llm"}
        ):
            query = urllib.parse.urlencode(
                {
                    "providerAlias": provider_alias,
                    "id": model_id,
                    "type": model_type,
                }
            )
            request_json(
                "DELETE",
                f"{base}/api/models/custom?{query}",
                opener=opener,
            )
        request_json(
            "POST",
            f"{base}/api/models/custom",
            opener=opener,
            body={
                "providerAlias": provider_alias,
                "id": model_id,
                "type": "llm",
            },
        )
        matching, exact = inventory()

    exact_record = len(matching) == 1 and len(exact) == 1
    catalog_count = 0
    completion_ok = False
    if client_token:
        models = request_json(
            "GET",
            f"{base}/v1/models",
            headers={"Authorization": f"Bearer {client_token}"},
        )
        catalog_count = sum(
            1
            for row in list_value(models, "data")
            if str(row.get("id") or "") == route_model
        )
        if exact_record and catalog_count == 1:
            completion = request_json(
                "POST",
                f"{base}/v1/chat/completions",
                headers={"Authorization": f"Bearer {client_token}"},
                body={
                    "model": route_model,
                    "messages": [{"role": "user", "content": "Reply with OK."}],
                    "max_tokens": 4,
                    "stream": False,
                },
                timeout=75,
            )
            completion_ok = bool(list_value(completion, "choices"))

    ready = exact_record and catalog_count == 1 and completion_ok
    return {
        "status": "ready" if ready else "needs_configuration",
        "providerAlias": provider_alias,
        "modelId": model_id,
        "routeModel": route_model,
        "exactRecordCount": len(exact),
        "conflictingRecordCount": len(matching) - len(exact),
        "catalogExactCount": catalog_count,
        "completion": "passed" if completion_ok else "failed_or_not_attempted",
    }


def ensure_minimax_upstream(
    ctx: Context,
    opener: urllib.request.OpenerDirector,
    providers: list[dict[str, Any]],
) -> dict[str, Any]:
    base_url = ctx.platform_env.get("MINIMAX_BASE_URL", "").strip().rstrip("/")
    api_key = canonical_secret_value(ctx.platform_env, "MINIMAX_API_KEY")
    model = ctx.platform_env.get("MINIMAX_MODEL", "").strip()
    if not base_url or not api_key or not model:
        missing = [
            key
            for key, value in (
                ("MINIMAX_BASE_URL", base_url),
                ("MINIMAX_API_KEY_or_REF", api_key),
                ("MINIMAX_MODEL", model),
            )
            if not value
        ]
        return {
            "status": "needs_configuration",
            "missing": missing,
            "canary": "not_run",
        }

    source_fingerprint = fingerprint(api_key)
    nodes = list_value(
        request_json("GET", f"{ctx.url('9router')}/api/provider-nodes", opener=opener),
        "nodes",
    )
    node = next(
        (
            row
            for row in nodes
            if row.get("prefix") == "mte-minimax" or row.get("name") == "MTE MiniMax"
        ),
        None,
    )
    node_payload = {
        "name": "MTE MiniMax",
        "prefix": "mte-minimax",
        "apiType": "chat",
        "baseUrl": base_url,
        "type": "openai-compatible",
    }
    if node is None and ctx.mutate:
        created_node = request_json(
            "POST",
            f"{ctx.url('9router')}/api/provider-nodes",
            opener=opener,
            body=node_payload,
        )
        node = (
            created_node.get("node", created_node)
            if isinstance(created_node, dict)
            else None
        )
    elif (
        node
        and ctx.mutate
        and any(
            str(node.get(key, "")) != str(value) for key, value in node_payload.items()
        )
    ):
        updated_node = request_json(
            "PUT",
            f"{ctx.url('9router')}/api/provider-nodes/{node['id']}",
            opener=opener,
            body=node_payload,
        )
        node = (
            updated_node.get("node", updated_node)
            if isinstance(updated_node, dict)
            else node
        )
    if not node or not node.get("id"):
        return {"status": "pending_bootstrap", "canary": "not_run"}

    node_id = str(node["id"])
    connection = next(
        (
            row
            for row in providers
            if str(row.get("provider")) == node_id
            and row.get("name") == "mte-minimax-primary"
        ),
        None,
    )
    connection_payload = {
        "provider": node_id,
        "name": "mte-minimax-primary",
        "apiKey": api_key,
        "defaultModel": model,
        "priority": 1,
        "isActive": True,
    }
    stored_fingerprint = ctx.platform_env.get(
        "NINEROUTER_MINIMAX_SOURCE_FINGERPRINT", ""
    )
    connection_drift = (
        connection is None
        or stored_fingerprint != source_fingerprint
        or str(connection.get("defaultModel") or "") != model
        or not connection.get("isActive", True)
    )
    if ctx.mutate and connection_drift:
        if connection and connection.get("id"):
            updated_connection = request_json(
                "PUT",
                f"{ctx.url('9router')}/api/providers/{connection['id']}",
                opener=opener,
                body=connection_payload,
            )
            connection = (
                updated_connection.get("connection", updated_connection)
                if isinstance(updated_connection, dict)
                else connection
            )
        else:
            created_connection = request_json(
                "POST",
                f"{ctx.url('9router')}/api/providers",
                opener=opener,
                body=connection_payload,
            )
            connection = (
                created_connection.get("connection", created_connection)
                if isinstance(created_connection, dict)
                else None
            )
            if isinstance(connection, dict):
                providers.append(connection)
        if connection and connection.get("id"):
            ctx.persist_canonical(
                {
                    "NINEROUTER_MINIMAX_PROVIDER_NODE_ID": node_id,
                    "NINEROUTER_MINIMAX_CONNECTION_ID": str(connection["id"]),
                    "NINEROUTER_MINIMAX_SOURCE_FINGERPRINT": source_fingerprint,
                }
            )
    if not connection or not connection.get("id"):
        return {"status": "pending_bootstrap", "canary": "not_run"}

    connection_valid = connection.get("testStatus") == "active"
    if ctx.mutate or ctx.strict:
        try:
            tested = request_json(
                "POST",
                f"{ctx.url('9router')}/api/providers/{connection['id']}/test",
                opener=opener,
            )
            connection_valid = (
                tested.get("valid") is True or tested.get("success") is True
            )
        except ApiError:
            connection_valid = False

    route_model = f"mte-minimax/{model}"
    model_registration = ensure_ninerouter_custom_model(
        ctx,
        opener,
        provider_alias="mte-minimax",
        model_id=model,
        client_token=ctx.platform_env.get("NINEROUTER_CLIENT_HERMES_API_KEY", ""),
    )
    canary_specs = (
        (
            "coding_daytona_claude",
            "NINEROUTER_PROFILE_CODING_DAYTONA_CLAUDE_API_KEY",
            "anthropic",
        ),
        (
            "coding_daytona_codex",
            "NINEROUTER_PROFILE_CODING_DAYTONA_CODEX_API_KEY",
            "responses",
        ),
        (
            "coding_daytona_pi",
            "NINEROUTER_PROFILE_CODING_DAYTONA_PI_API_KEY",
            "chat",
        ),
        ("hermes", "NINEROUTER_CLIENT_HERMES_API_KEY", "chat"),
    )
    canaries: list[dict[str, str]] = []
    canary_updates: dict[str, str] = {}
    for canary_name, token_key, protocol in canary_specs:
        client_token = ctx.platform_env.get(token_key, "")
        marker = hashlib.sha256(
            f"{base_url}|{model}|{source_fingerprint}|{fingerprint(client_token) if client_token else 'missing'}|{protocol}".encode()
        ).hexdigest()[:16]
        marker_key = f"NINEROUTER_MINIMAX_CANARY_{canary_name.upper()}_FINGERPRINT"
        canary_ok = bool(client_token) and ctx.platform_env.get(marker_key) == marker
        if connection_valid and client_token and (ctx.mutate or ctx.strict):
            try:
                if protocol == "anthropic":
                    completion = request_json(
                        "POST",
                        f"{ctx.url('9router')}/v1/messages",
                        headers={
                            "x-api-key": client_token,
                            "anthropic-version": "2023-06-01",
                        },
                        body={
                            "model": route_model,
                            "messages": [{"role": "user", "content": "Reply with OK."}],
                            "max_tokens": 4,
                            "stream": False,
                        },
                        timeout=75,
                    )
                    canary_ok = bool(list_value(completion, "content"))
                elif protocol == "responses":
                    completion = request_json(
                        "POST",
                        f"{ctx.url('9router')}/v1/responses",
                        headers={"Authorization": f"Bearer {client_token}"},
                        body={
                            "model": route_model,
                            "input": "Reply with OK.",
                            "max_output_tokens": 4,
                            "stream": False,
                        },
                        timeout=75,
                    )
                    canary_ok = (
                        bool(list_value(completion, "output"))
                        or bool(completion.get("output_text"))
                        or bool(list_value(completion, "choices"))
                    )
                else:
                    completion = request_json(
                        "POST",
                        f"{ctx.url('9router')}/v1/chat/completions",
                        headers={"Authorization": f"Bearer {client_token}"},
                        body={
                            "model": route_model,
                            "messages": [{"role": "user", "content": "Reply with OK."}],
                            "max_tokens": 4,
                            "stream": False,
                        },
                        timeout=75,
                    )
                    canary_ok = bool(list_value(completion, "choices"))
            except ApiError:
                canary_ok = False
            if canary_ok and ctx.mutate:
                canary_updates[marker_key] = marker
        canaries.append(
            {
                "client": canary_name.replace("_", "-"),
                "protocol": protocol,
                "status": "passed" if canary_ok else "failed_or_stale",
            }
        )
    canary_ok = all(row["status"] == "passed" for row in canaries)
    if canary_updates and ctx.mutate:
        canary_updates["NINEROUTER_MINIMAX_CANARY_AT"] = str(now())
        ctx.persist_canonical(canary_updates)
    return {
        "status": "ready"
        if connection_valid and model_registration["status"] == "ready" and canary_ok
        else "needs_configuration",
        "providerNode": "MTE MiniMax",
        "connection": "mte-minimax-primary",
        "routeModel": route_model,
        "sourceFingerprint": source_fingerprint,
        "providerTest": "passed" if connection_valid else "failed",
        "modelRegistration": model_registration,
        "canary": "passed" if canary_ok else "failed_or_stale",
        "canaries": canaries,
    }


def harness_router_auth_status(ctx: Context, harness: str) -> dict[str, Any]:
    key_ref = f"NINEROUTER_PROFILE_CODING_DAYTONA_{harness.upper()}_API_KEY"
    api_key = ctx.platform_env.get(key_ref, "")
    model = ctx.platform_env.get("HERMES_LLM_MODEL", "")
    ready = bool(api_key and model)
    return {
        "harness": harness,
        "status": "ready" if ready else "needs_configuration",
        "method": "profile_scoped_9router_runtime_key",
        "keyRef": key_ref,
        "baseUrl": f"{ctx.url('9router')}/v1",
        "model": model or None,
        "fingerprint": fingerprint(api_key) if api_key else None,
        "nativeSubscriptionCredential": False,
    }


def ninerouter(ctx: Context) -> dict[str, Any]:
    component = "9router"
    path, saved = ctx.integration(component)
    try:
        opener, saved = ninerouter_session(ctx)
        keys = list_value(
            request_json("GET", f"{ctx.url(component)}/api/keys", opener=opener), "keys"
        )
        generic = ensure_ninerouter_key(
            ctx,
            opener,
            keys,
            name="mte-agents",
            token_key="NINEROUTER_AGENT_API_KEY",
            projection_path=path,
        )
        clients = []
        for ref in ("claude", "codex", "pi", "hermes"):
            token_key = f"NINEROUTER_CLIENT_{safe_slug(ref).upper()}_API_KEY"
            clients.append(
                {
                    "client": ref,
                    **ensure_ninerouter_key(
                        ctx,
                        opener,
                        keys,
                        name=f"mte-client-{ref}",
                        token_key=token_key,
                        projection_path=INTEGRATIONS
                        / "9router"
                        / "clients"
                        / f"{safe_slug(ref)}.env",
                    ),
                }
            )
        hermes_key = ctx.platform_env.get("NINEROUTER_CLIENT_HERMES_API_KEY", "")
        minimax_model = ctx.platform_env.get("MINIMAX_MODEL", "").strip()
        if ctx.mutate and hermes_key and minimax_model:
            ctx.persist_canonical(
                {
                    "HERMES_LLM_API_KEY": hermes_key,
                    "HERMES_LLM_BASE_URL": f"{ctx.url(component)}/v1",
                    "HERMES_LLM_MODEL": f"mte-minimax/{minimax_model}",
                }
            )
        profile_keys = []
        catalog_refs = {str(profile["ref"]) for profile in profile_catalog()}
        profile_refs = sorted(
            (catalog_refs - {"coding-daytona"})
            | {
                "coding-daytona-codex",
                "coding-daytona-claude",
                "coding-daytona-pi",
            }
        )
        for ref in profile_refs:
            profile_keys.append(
                {
                    "profile": ref,
                    **ensure_ninerouter_key(
                        ctx,
                        opener,
                        keys,
                        name=f"mte-profile-{ref}",
                        token_key=f"NINEROUTER_PROFILE_{safe_slug(ref).upper()}_API_KEY",
                        projection_path=INTEGRATIONS
                        / "9router"
                        / "profiles"
                        / f"{safe_slug(ref)}.env",
                    ),
                }
            )

        providers = list_value(
            request_json("GET", f"{ctx.url(component)}/api/providers", opener=opener),
            "connections",
        )
        minimax = ensure_minimax_upstream(ctx, opener, providers)
        harness_routes = [
            harness_router_auth_status(ctx, harness)
            for harness in ("claude", "codex", "pi")
        ]
        key_ready = (
            generic["status"] == "ready"
            and all(row["status"] == "ready" for row in clients)
            and all(row["status"] == "ready" for row in profile_keys)
            and minimax["status"] == "ready"
        )
        harness_routes_ready = all(row["status"] == "ready" for row in harness_routes)
        status = "ready" if key_ready and harness_routes_ready else "needs_rotation"
        daytona_harness_profiles = [
            {
                "profileRef": f"coding-daytona-{harness}",
                "clientKeyRef": f"NINEROUTER_PROFILE_CODING_DAYTONA_{harness.upper()}_API_KEY",
                "routeModel": minimax.get("routeModel"),
                "protocol": protocol,
                "status": next(
                    (
                        row["status"]
                        for row in profile_keys
                        if row["profile"] == f"coding-daytona-{harness}"
                    ),
                    "needs_configuration",
                ),
            }
            for harness, protocol in (
                ("codex", "openai_responses"),
                ("claude", "anthropic_messages"),
                ("pi", "openai_chat_completions"),
            )
        ]
        return result(
            component,
            status,
            managed=[
                "dashboard_principal",
                "agent_api_key",
                "scoped_client_keys",
                "profile_client_keys",
                "minimax_upstream",
                "openai_route",
                "anthropic_route",
            ],
            names={
                "apiKey": "mte-agents",
                "clients": [row["name"] for row in clients],
                "profileKeys": [row["name"] for row in profile_keys],
            },
            fingerprints={
                "agentApiKey": fingerprint(ctx.platform_env["NINEROUTER_AGENT_API_KEY"])
            }
            if ctx.platform_env.get("NINEROUTER_AGENT_API_KEY")
            else {},
            clientKeys=[
                {
                    key: value
                    for key, value in row.items()
                    if key not in {"credentialFile", "tokenKey"}
                }
                for row in clients
            ],
            profileKeys=[
                {
                    key: value
                    for key, value in row.items()
                    if key not in {"credentialFile", "tokenKey"}
                }
                for row in profile_keys
            ],
            harnessProfiles=daytona_harness_profiles,
            minimax=minimax,
            harnessRouting=harness_routes,
            limitations=[
                "Native harness subscription credentials are intentionally unsupported; Claude, Codex and Pi all receive profile-scoped 9Router runtime keys."
            ],
        )
    except BaseException as exc:
        return component_error(component, exc)


def command_json(args: list[str]) -> Any:
    completed = subprocess.run(
        args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("command_failed")
    return json.loads(completed.stdout or "{}")


def paperclip_container_env() -> dict[str, str]:
    payload = command_json(
        ["docker", "inspect", "--format", "{{json .Config.Env}}", PAPERCLIP_CONTAINER]
    )
    if not isinstance(payload, list):
        raise RuntimeError("paperclip_container_env_invalid")
    result: dict[str, str] = {}
    for row in payload:
        if not isinstance(row, str) or "=" not in row:
            continue
        key, value = row.split("=", 1)
        result[key] = value
    return result


def paperclip_runtime_snapshot(key_path_override: str = "") -> dict[str, Any]:
    script = r"""
const fs = require('fs');
const p = '/data/instances/default/config.json';
if (!fs.existsSync(p)) { console.log(JSON.stringify({configExists:false})); process.exit(0); }
const d = JSON.parse(fs.readFileSync(p, 'utf8'));
const keyPath = process.argv[1] || d.secrets?.localEncrypted?.keyFilePath || '/data/instances/default/secrets/master.key';
let key = {exists:false, mode:null, valid:false};
if (fs.existsSync(keyPath)) {
  const raw = fs.readFileSync(keyPath, 'utf8').trim();
  let valid = /^[A-Fa-f0-9]{64}$/.test(raw) || Buffer.byteLength(raw, 'utf8') === 32;
  if (!valid) { try { valid = Buffer.from(raw, 'base64').length === 32; } catch (_) {} }
  key = {exists:true, mode:(fs.statSync(keyPath).mode & 0o777).toString(8), valid};
}
console.log(JSON.stringify({
  configExists:true,
  provider:d.secrets?.provider || null,
  strictMode:d.secrets?.strictMode === true,
  keyFilePath:keyPath,
  key,
  configMode:(fs.statSync(p).mode & 0o777).toString(8),
  deploymentMode:d.server?.deploymentMode || null,
  port:d.server?.port || null,
  llmApiKeyConfigured:Boolean(d.llm?.apiKey)
}));
"""
    completed = subprocess.run(
        [
            "docker",
            "exec",
            PAPERCLIP_CONTAINER,
            "node",
            "-e",
            script,
            key_path_override,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("paperclip_runtime_snapshot_failed")
    return json.loads(completed.stdout or "{}")


def configure_paperclip_runtime(key_path: str) -> None:
    script = r"""
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const configPath = '/data/instances/default/config.json';
if (!fs.existsSync(configPath)) process.exit(2);
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
config.secrets = config.secrets || {};
config.secrets.provider = 'local_encrypted';
config.secrets.strictMode = true;
config.secrets.localEncrypted = config.secrets.localEncrypted || {};
config.secrets.localEncrypted.keyFilePath = process.argv[1];
fs.mkdirSync(path.dirname(process.argv[1]), {recursive:true, mode:0o700});
if (!fs.existsSync(process.argv[1])) {
  const keyTmp = process.argv[1] + '.tmp';
  fs.writeFileSync(keyTmp, crypto.randomBytes(32).toString('base64'), {encoding:'utf8', mode:0o600});
  fs.renameSync(keyTmp, process.argv[1]);
}
fs.chmodSync(process.argv[1], 0o600);
const tmp = configPath + '.tmp';
fs.writeFileSync(tmp, JSON.stringify(config, null, 2) + '\n', {encoding:'utf8', mode:0o600});
fs.renameSync(tmp, configPath);
fs.chmodSync(configPath, 0o600);
"""
    completed = subprocess.run(
        ["docker", "exec", PAPERCLIP_CONTAINER, "node", "-e", script, key_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("paperclip_runtime_configure_failed")


def wait_json_endpoint(url: str, timeout: int = 75) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            request_json("GET", url, timeout=4)
            return
        except ApiError:
            time.sleep(1)
    raise RuntimeError("paperclip_restart_timeout")


def paperclip_runtime_security(ctx: Context) -> dict[str, Any]:
    env = paperclip_container_env()
    if env.get("PAPERCLIP_SECRETS_MASTER_KEY", "").strip():
        return {
            "status": "error",
            "reason": "inline_master_key_env_forbidden",
            "masterKeySource": "inline_env_rejected",
        }
    key_override = env.get("PAPERCLIP_SECRETS_MASTER_KEY_FILE", "").strip()
    strict_override = env.get("PAPERCLIP_SECRETS_STRICT_MODE", "").strip().lower()
    if strict_override in {"0", "false", "no", "off"}:
        return {
            "status": "error",
            "reason": "strict_mode_disabled_by_container_env",
            "masterKeySource": "env_file" if key_override else "config_file",
        }
    snapshot = paperclip_runtime_snapshot(key_override)
    if not snapshot.get("configExists"):
        return {
            "status": "needs_configuration",
            "reason": "paperclip_instance_config_missing",
        }
    if snapshot.get("llmApiKeyConfigured"):
        return {
            "status": "error",
            "reason": "instance_llm_api_key_must_be_removed_after_9router_migration",
            "masterKeySource": "env_file" if key_override else "config_file",
        }
    effective_key_path = key_override or str(
        snapshot.get("keyFilePath") or PAPERCLIP_DEFAULT_KEY_PATH
    )
    effective_strict = (
        strict_override in {"1", "true", "yes", "on"}
        or snapshot.get("strictMode") is True
    )
    needs_change = (
        snapshot.get("provider") != "local_encrypted"
        or not snapshot.get("strictMode")
        or not snapshot.get("key", {}).get("exists")
        or not snapshot.get("key", {}).get("valid")
        or snapshot.get("key", {}).get("mode") != "600"
    )
    if needs_change and ctx.mutate:
        configure_paperclip_runtime(effective_key_path)
        completed = subprocess.run(
            ["docker", "restart", PAPERCLIP_CONTAINER],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("paperclip_restart_failed")
        wait_json_endpoint(f"{ctx.url('paperclip')}/api/health")
        snapshot = paperclip_runtime_snapshot(key_override)
        effective_strict = (
            strict_override in {"1", "true", "yes", "on"}
            or snapshot.get("strictMode") is True
        )
    ready = (
        snapshot.get("provider") == "local_encrypted"
        and effective_strict
        and snapshot.get("key", {}).get("exists") is True
        and snapshot.get("key", {}).get("valid") is True
        and snapshot.get("key", {}).get("mode") == "600"
        and snapshot.get("configMode") == "600"
    )
    return {
        "status": "ready" if ready else "needs_configuration",
        "provider": snapshot.get("provider"),
        "strictMode": effective_strict,
        "masterKeySource": "env_file" if key_override else "config_file",
        "masterKeyFile": {
            "configured": bool(effective_key_path),
            "exists": snapshot.get("key", {}).get("exists") is True,
            "valid": snapshot.get("key", {}).get("valid") is True,
            "mode": snapshot.get("key", {}).get("mode"),
        },
        "configMode": snapshot.get("configMode"),
        "llmApiKeyConfigured": snapshot.get("llmApiKeyConfigured") is True,
    }


def paperclip_headers(
    saved: dict[str, str], platform_env: dict[str, str]
) -> dict[str, str]:
    key = saved.get("PAPERCLIP_BOARD_API_KEY", "") or platform_env.get(
        "PAPERCLIP_BOARD_API_KEY", ""
    )
    return {"Authorization": f"Bearer {key}"} if key else {}


def paperclip_bootstrap_request(
    opener: urllib.request.OpenerDirector,
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Accept": "application/json", "Origin": url.split("/api/", 1)[0]}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with opener.open(request, timeout=30) as response:
            payload = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        raise ApiError(
            exc.code,
            "paperclip_bootstrap_http_error",
            operation=f"paperclip_bootstrap_{method.lower()}",
            response_error_sha256=hashlib.sha256(raw).hexdigest(),
            response_error_length=len(raw),
        ) from None
    if not isinstance(payload, dict):
        raise RuntimeError("paperclip_bootstrap_response_invalid")
    return payload


def paperclip_public_url(ctx: Context) -> str:
    return (
        "https://"
        + ctx.platform_env.get("PAPERCLIP_SUBDOMAIN", "paperclip")
        + "."
        + ctx.platform_env["PLATFORM_BASE_DOMAIN"]
    )


def paperclip_machine_invite_request_type(health: dict[str, Any]) -> str | None:
    """Return an upstream-declared non-human invite type, if one exists.

    Absence is intentionally not guessed.  A server that only exposes the
    historical human request type must remain a human-approved bootstrap even
    when an operator has opted into unattended setup.
    """

    candidates = health.get("supportedInviteRequestTypes")
    if not isinstance(candidates, list):
        return None
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip().lower() == "machine":
            return "machine"
    return None


def paperclip_owner_authorization_handoff(
    ctx: Context,
    *,
    invite_id: str = "",
    reason: str,
) -> dict[str, Any]:
    """Give operators a resumable but non-secret-bearing browser handoff."""

    return {
        "status": "needs_authorization",
        "reason": reason,
        "browserHandoff": {
            "url": paperclip_public_url(ctx).rstrip("/") + "/invite/[redacted]",
            "inviteFingerprint": fingerprint(invite_id) if invite_id else None,
            "redacted": True,
            "resumeCommand": "./install.sh",
        },
    }


def ensure_paperclip_board_identity(ctx: Context) -> dict[str, Any]:
    """Reconcile a board key without ever passing a machine off as a human.

    The public path creates at most the upstream bootstrap invite and then
    stops.  It returns only a redacted handoff, so the invite bearer is neither
    printed nor included in the provisioning evidence.  A repeated install
    reuses the stored private invite identifier and resumes once a human has
    accepted it.  The legacy fully unattended sequence is available solely
    behind an explicit high-risk flag and only for an upstream-declared
    ``machine`` invite request type.
    """

    _, saved = ctx.integration("paperclip")
    if saved.get("PAPERCLIP_BOARD_API_KEY") or ctx.platform_env.get(
        "PAPERCLIP_BOARD_API_KEY", ""
    ):
        return {"status": "ready"}
    if not ctx.mutate:
        return paperclip_owner_authorization_handoff(
            ctx, reason="paperclip_board_identity_missing"
        )

    base = ctx.url("paperclip")
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    health = paperclip_bootstrap_request(opener, "GET", f"{base}/api/health")
    if health.get("bootstrapStatus") == "bootstrap_pending":
        invite_id = saved.get(PAPERCLIP_OWNER_INVITE_ID_KEY, "")
        if not invite_id:
            completed = subprocess.run(
                [
                    "docker",
                    "exec",
                    "--user",
                    "node",
                    PAPERCLIP_CONTAINER,
                    "/tools/node_modules/.bin/paperclipai",
                    "auth",
                    "bootstrap-ceo",
                    "-c",
                    PAPERCLIP_CONFIG_PATH,
                    "-d",
                    "/data",
                    "--base-url",
                    paperclip_public_url(ctx),
                    "--expires-hours",
                    "24",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError("paperclip_bootstrap_invite_create_failed")
            match = re.search(
                r"/invite/(pcp_(?:invite|bootstrap)_[A-Za-z0-9_-]+)",
                completed.stdout + "\n" + completed.stderr,
            )
            if not match:
                raise RuntimeError("paperclip_bootstrap_invite_missing")
            invite_id = match.group(1)
            saved[PAPERCLIP_OWNER_INVITE_ID_KEY] = invite_id
            ctx.save_integration("paperclip", saved)

        request_type = paperclip_machine_invite_request_type(health)
        if (
            ctx.platform_env.get(PAPERCLIP_UNATTENDED_OWNER_BOOTSTRAP_KEY) != "true"
        ):
            return paperclip_owner_authorization_handoff(
                ctx,
                invite_id=invite_id,
                reason="paperclip_first_owner_human_authorization_required",
            )
        if request_type is None:
            return paperclip_owner_authorization_handoff(
                ctx,
                invite_id=invite_id,
                reason="paperclip_unattended_owner_bootstrap_requires_upstream_machine_type",
            )

        email = (
            saved.get("PAPERCLIP_BOARD_EMAIL")
            or ctx.platform_env.get("PAPERCLIP_BOARD_EMAIL", "")
            or f"platform-admin@{ctx.platform_env['PLATFORM_BASE_DOMAIN']}"
        )
        operator_password = (
            saved.get("PAPERCLIP_BOARD_PASSWORD")
            or ctx.platform_env.get("PAPERCLIP_BOARD_PASSWORD", "")
            or password()
        )
        # Persist the explicitly machine-only resumable state before the
        # upstream accept call. If a later board-key request fails, a replay
        # can sign in as that same machine identity without inventing a human
        # request type or issuing another owner invite.
        saved.update(
            {
                "PAPERCLIP_BOARD_EMAIL": email,
                "PAPERCLIP_BOARD_PASSWORD": operator_password,
                PAPERCLIP_OWNER_BOOTSTRAP_REQUEST_TYPE_KEY: request_type,
            }
        )
        ctx.save_integration("paperclip", saved)
        paperclip_bootstrap_request(
            opener,
            "POST",
            f"{base}/api/auth/sign-up/email",
            {
                "name": "MTE Platform Admin",
                "email": email,
                "password": operator_password,
            },
        )
        accepted = paperclip_bootstrap_request(
            opener,
            "POST",
            f"{base}/api/invites/{invite_id}/accept",
            {"requestType": request_type},
        )
        if accepted.get("bootstrapAccepted") is not True:
            raise RuntimeError("paperclip_bootstrap_accept_failed")
    else:
        if (
            ctx.platform_env.get(PAPERCLIP_UNATTENDED_OWNER_BOOTSTRAP_KEY) != "true"
            or saved.get(PAPERCLIP_OWNER_BOOTSTRAP_REQUEST_TYPE_KEY) != "machine"
            or not saved.get("PAPERCLIP_BOARD_EMAIL")
            or not saved.get("PAPERCLIP_BOARD_PASSWORD")
        ):
            return paperclip_owner_authorization_handoff(
                ctx,
                reason="paperclip_board_api_key_requires_owner_authorization",
            )
        email = saved["PAPERCLIP_BOARD_EMAIL"]
        operator_password = saved["PAPERCLIP_BOARD_PASSWORD"]
        paperclip_bootstrap_request(
            opener,
            "POST",
            f"{base}/api/auth/sign-in/email",
            {
                "email": email,
                "password": operator_password,
            },
        )

    created = paperclip_bootstrap_request(
        opener,
        "POST",
        f"{base}/api/board-api-keys",
        {"name": "mte-platform-provisioner"},
    )
    board_key = str(created.get("token") or "")
    if not board_key.startswith("pcp_board_"):
        raise RuntimeError("paperclip_board_key_create_failed")
    saved.update(
        {
            "PAPERCLIP_BOARD_EMAIL": email,
            "PAPERCLIP_BOARD_PASSWORD": operator_password,
            "PAPERCLIP_BOARD_API_KEY": board_key,
        }
    )
    ctx.save_integration("paperclip", saved)
    return {"status": "ready"}


def paperclip_secret_specs(ctx: Context) -> list[dict[str, str]]:
    specs: list[dict[str, str]] = []
    candidates = {
        "POSTGREST_PAPERCLIP_TOKEN": (
            "mte.postgrest.paperclip",
            "PostgREST Paperclip scoped writer JWT",
        ),
        "MATTERMOST_BOT_TOKEN": ("mte.mattermost.bot", "Mattermost agent bot token"),
        "HERMES_API_SERVER_KEY": (
            "mte.hermes.api-server",
            "Hermes native API server key",
        ),
        "KESTRA_ADMIN_PASSWORD": (
            "mte.kestra.shared-password",
            "Kestra shared Basic Auth password",
        ),
        "CONTEXT7_API_KEY": (
            "mte.context7.api-key",
            "Optional Context7 API key for native harness tools",
        ),
    }
    if ctx.platform_env.get("DATA_CONTENT_PROFILE", "") == "postgres-notion":
        candidates["NOTION_TOKEN"] = (
            "mte.notion.connector",
            "Notion external tables and documents connector token",
        )
    for source_key in sorted(ctx.platform_env):
        if re.fullmatch(
            r"NINEROUTER_(?:AGENT|CLIENT_[A-Z0-9_]+|PROFILE_[A-Z0-9_]+)_API_KEY",
            source_key,
        ):
            suffix = (
                source_key.lower()
                .removeprefix("ninerouter_")
                .removesuffix("_api_key")
                .replace("_", ".")
            )
            candidates[source_key] = (
                f"mte.9router.{suffix}",
                f"9Router {suffix} scoped API key",
            )
        elif re.fullmatch(
            r"TOOLHIVE_PROFILE_CODING_DAYTONA_(?:CODEX|CLAUDE|PI)_BEARER_TOKEN",
            source_key,
        ):
            suffix = (
                source_key.lower()
                .removeprefix("toolhive_profile_")
                .removesuffix("_bearer_token")
                .replace("_", ".")
            )
            candidates[source_key] = (
                f"mte.toolhive.profile.{suffix}.bearer",
                f"ToolHive {suffix} scoped bearer token",
            )
    for source_key, (secret_key, name) in candidates.items():
        value = canonical_secret_value(ctx.platform_env, source_key)
        if value:
            specs.append(
                {
                    "sourceKey": source_key,
                    "key": secret_key,
                    "name": name,
                    "value": value,
                    "description": "Managed by the MTE provisioner from canonical platform.env state.",
                }
            )
    return specs


def data_content_paperclip_bindings(ctx: Context) -> tuple[tuple[str, str], ...]:
    """Return profile-scoped Paperclip env bindings without credential values.

    PostgreSQL remains authoritative in the ``postgres-notion`` profile, so
    agents retain the scoped PostgREST writer credential.  The external
    Notion credential belongs to the dedicated ``mte.notion.connector``
    identity and is deliberately never projected into an agent environment;
    agents consume only the ToolHive-enforced read-only Notion MCP surface.
    """

    profile = ctx.platform_env.get("DATA_CONTENT_PROFILE", "")
    if profile == "postgres-notion":
        return (("POSTGREST_PAPERCLIP_TOKEN", "POSTGREST_API_TOKEN"),)
    raise RuntimeError("data_content_profile_unsupported")


def data_content_paperclip_binding(ctx: Context) -> tuple[str, str]:
    """Compatibility accessor for the profile's canonical data API binding."""

    return data_content_paperclip_bindings(ctx)[0]


def reconcile_data_content_paperclip_env(
    ctx: Context,
    existing: dict[str, Any],
    secret_ids: dict[str, str],
) -> dict[str, Any]:
    """Replace data/content credentials with Paperclip-managed references."""

    desired = dict(existing)
    for stale_key in ("POSTGREST_API_TOKEN", "NOTION_TOKEN"):
        desired.pop(stale_key, None)
    for source_key, env_key in data_content_paperclip_bindings(ctx):
        secret_id = secret_ids.get(source_key, "")
        if secret_id:
            desired[env_key] = paperclip_ref(secret_id)
    return desired


def ensure_paperclip_company_secret(
    ctx: Context,
    url: str,
    headers: dict[str, str],
    company_id: str,
    secrets_list: list[dict[str, Any]],
    spec: dict[str, str],
) -> dict[str, Any]:
    remote = next((row for row in secrets_list if row.get("key") == spec["key"]), None)
    state_prefix = f"PAPERCLIP_SECRET_{safe_slug(spec['key']).upper()}"
    value_fingerprint = fingerprint(spec["value"])
    stored_fingerprint = ctx.platform_env.get(f"{state_prefix}_SOURCE_FINGERPRINT", "")
    if remote is None and ctx.mutate:
        remote = request_json(
            "POST",
            f"{url}/api/companies/{company_id}/secrets",
            headers=headers,
            body={
                "name": spec["name"],
                "key": spec["key"],
                "provider": "local_encrypted",
                "managedMode": "paperclip_managed",
                "value": spec["value"],
                "description": spec["description"],
            },
        )
        if isinstance(remote, dict):
            secrets_list.append(remote)
    elif remote and ctx.mutate and stored_fingerprint != value_fingerprint:
        request_json(
            "POST",
            f"{url}/api/secrets/{remote['id']}/rotate",
            headers=headers,
            body={"value": spec["value"]},
        )
    if remote and remote.get("id") and ctx.mutate:
        ctx.persist_canonical(
            {
                f"{state_prefix}_ID": str(remote["id"]),
                f"{state_prefix}_SOURCE_FINGERPRINT": value_fingerprint,
            }
        )
    ready = bool(
        remote
        and remote.get("id")
        and (ctx.mutate or stored_fingerprint == value_fingerprint)
    )
    evidence = {
        "sourceKey": spec["sourceKey"],
        "key": spec["key"],
        "id": str(remote.get("id")) if remote and remote.get("id") else "",
        "provider": str((remote or {}).get("provider") or "local_encrypted"),
        "managedMode": str((remote or {}).get("managedMode") or "paperclip_managed"),
        "scope": "company",
        "companyId": company_id,
        "status": "ready"
        if ready
        else ("pending_bootstrap" if remote is None else "needs_rotation"),
    }
    # Context7 is optional and its credential evidence is deliberately
    # boolean/ref-only. The root-only source fingerprint remains an internal
    # idempotent rotation marker, never part of result/evidence payloads.
    if spec["sourceKey"] != "CONTEXT7_API_KEY":
        evidence["fingerprint"] = value_fingerprint
    return evidence


def paperclip_profile_ref(
    agent: dict[str, Any], catalog: dict[str, dict[str, Any]]
) -> str:
    metadata = agent.get("metadata") if isinstance(agent.get("metadata"), dict) else {}
    explicit = str(metadata.get("profileRef") or "")
    if explicit in catalog:
        return explicit
    name = str(agent.get("name") or "").lower()
    for ref in catalog:
        if ref.lower() in name:
            return ref
    return ""


def paperclip_ref(secret_id: str) -> dict[str, Any]:
    return {"type": "secret_ref", "secretId": secret_id, "version": "latest"}


def hermes_gateway_agent_payload(
    ctx: Context,
    *,
    gateway_secret_id: str,
) -> dict[str, Any]:
    """Return the official Paperclip hermes_gateway agent declaration.

    Hermes is a native host service, while Paperclip is isolated in the
    ``mte-control`` Docker network.  Paperclip therefore calls the host through
    that network's private gateway; Hermes calls Paperclip through its
    loopback-published API.  The gateway credential is always a Paperclip
    secret reference, never an inline value.
    """

    host = ctx.platform_env.get("HERMES_API_SERVER_HOST", "").strip()
    port = ctx.platform_env.get("HERMES_API_SERVER_PORT", "").strip()
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise RuntimeError("hermes_gateway_host_invalid") from exc
    if (
        not gateway_secret_id
        or not port.isdigit()
        or not 1 <= int(port) <= 65535
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or not (address.is_loopback or address.is_private)
    ):
        raise RuntimeError("hermes_gateway_contract_invalid")
    adapter_config: dict[str, Any] = {
        "apiBaseUrl": f"http://{host}:{int(port)}",
        "apiKey": paperclip_ref(gateway_secret_id),
        "paperclipApiUrl": ctx.url("paperclip"),
        "sessionKeyStrategy": "issue",
        "timeoutSec": 1800,
    }
    if not address.is_loopback:
        # Upstream Paperclip requires this explicit opt-in for trusted private
        # HTTP networks. The API remains authenticated by API_SERVER_KEY and
        # is bound only to the private Docker bridge address.
        adapter_config["dangerouslyAllowInsecureRemoteHttp"] = True
    return {
        "name": "MTE Hermes Gateway",
        "title": "Platform Operator",
        "role": "devops",
        "capabilities": (
            "Operate and repair the MTE platform; create, inspect, comment on, "
            "and update Paperclip tasks through a project-scoped bridge key."
        ),
        "adapterType": "hermes_gateway",
        "adapterConfig": adapter_config,
        "runtimeConfig": {
            "heartbeat": {
                "enabled": False,
                "wakeOnDemand": True,
                "maxConcurrentRuns": 1,
            }
        },
        "budgetMonthlyCents": 0,
        "metadata": {
            "systemRef": "hermes-operator",
            "managedBy": "mte-server-provision",
        },
    }


def context7_binding_evidence(
    ctx: Context, secret_id: str, adapter_type: str = ""
) -> dict[str, Any]:
    configured = bool(canonical_secret_value(ctx.platform_env, "CONTEXT7_API_KEY"))
    native_config_binding = {
        "codex_local": "codex_bearer_token_env_var",
        "claude_local": "claude_managed_mcp_headers_ref",
        "pi_local": "pi_extension_optional_env",
    }.get(adapter_type, "company_secret_ref")
    return {
        "configured": configured,
        "authMode": "paperclip_company_secret_ref" if configured else "anonymous",
        "bindingRef": "CONTEXT7_API_KEY" if configured else None,
        "secretId": secret_id or None,
        "nativeConfigBinding": native_config_binding if configured else "none",
    }


def paperclip_user_ref(key: str) -> dict[str, Any]:
    return {
        "type": "user_secret_ref",
        "key": key,
        "version": "latest",
        "required": True,
        "allowMissingOverride": False,
    }


def paperclip_user_secret_id(row: dict[str, Any] | None) -> str:
    if not row:
        return ""
    secret = row.get("secret") if isinstance(row.get("secret"), dict) else row
    return str(secret.get("id") or "")


def unsafe_paperclip_env(env: Any) -> list[str]:
    findings: list[str] = []
    if not isinstance(env, dict):
        return findings
    for key, value in env.items():
        if not SENSITIVE_ENV_KEY_RE.search(str(key)):
            continue
        if isinstance(value, str) and value:
            findings.append(str(key))
        elif (
            isinstance(value, dict)
            and value.get("type") == "plain"
            and value.get("value")
        ):
            findings.append(str(key))
    return findings


def reconcile_codex_context7_args(
    raw_args: Any, *, secret_ref_configured: bool
) -> list[str]:
    args = [str(value) for value in raw_args] if isinstance(raw_args, list) else []
    binding_prefix = "mcp_servers.context7.bearer_token_env_var="
    desired: list[str] = []
    index = 0
    while index < len(args):
        if (
            args[index] == "-c"
            and index + 1 < len(args)
            and args[index + 1].startswith(binding_prefix)
        ):
            index += 2
            continue
        if args[index].startswith(binding_prefix):
            index += 1
            continue
        desired.append(args[index])
        index += 1
    if secret_ref_configured:
        desired.extend(
            ["-c", 'mcp_servers.context7.bearer_token_env_var="CONTEXT7_API_KEY"']
        )
    return desired


def paperclip_agent_gateway_contract(
    ctx: Context, profile: dict[str, Any]
) -> dict[str, str]:
    """Resolve and validate the private Daytona agent-plane endpoints.

    These URLs are deliberately distinct from the host-loopback control-plane
    origins returned by ``Context.url``.  A nested Daytona sandbox can only
    use the canonical inner bridge gateway; public Cloudflare origins and
    host loopback are both rejected.
    """

    host = ctx.platform_env.get("MTE_AGENT_GATEWAY_HOST", "").strip()
    router_url = ctx.platform_env.get(
        "MTE_AGENT_GATEWAY_NINEROUTER_BASE_URL", ""
    ).rstrip("/")
    tool_routing = profile.get("toolRouting")
    if not isinstance(tool_routing, dict):
        raise RuntimeError("paperclip_tool_routing_missing")
    tool_url_ref = str(tool_routing.get("mcpUrlRef") or "")
    token_ref = str(tool_routing.get("bearerTokenRef") or "")
    tool_access = profile.get("toolAccess")
    if not isinstance(tool_access, dict):
        raise RuntimeError("paperclip_tool_access_missing")
    if not re.fullmatch(
        r"MTE_AGENT_GATEWAY_TOOLHIVE_(?:CODEX|CLAUDE|PI)_URL", tool_url_ref
    ):
        raise RuntimeError("paperclip_toolhive_url_ref_invalid")
    if not re.fullmatch(
        r"TOOLHIVE_PROFILE_CODING_DAYTONA_(?:CODEX|CLAUDE|PI)_BEARER_TOKEN",
        token_ref,
    ):
        raise RuntimeError("paperclip_toolhive_token_ref_invalid")
    tool_url = ctx.platform_env.get(tool_url_ref, "").rstrip("/")
    if not host or not router_url or not tool_url:
        raise RuntimeError("paperclip_agent_gateway_contract_missing")
    if (
        tool_access.get("endpointRef") != tool_url_ref
        or tool_access.get("credentialRef") != token_ref
        or not all(
            isinstance(tool_access.get(key), str) and tool_access.get(key)
            for key in ("bundleId", "workloadId", "canaryTool")
        )
    ):
        raise RuntimeError("paperclip_tool_access_contract_invalid")

    def validate_url(value: str, *, port: int, path: str) -> None:
        parsed = urllib.parse.urlparse(value)
        if (
            parsed.scheme != "http"
            or parsed.hostname != host
            or parsed.port != port
            or (parsed.path or "") != path
            or parsed.params
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise RuntimeError("paperclip_agent_gateway_contract_invalid")

    router_port = int(ctx.platform_env.get("MTE_AGENT_GATEWAY_NINEROUTER_PORT") or 0)
    harness = tool_url_ref.removeprefix("MTE_AGENT_GATEWAY_TOOLHIVE_").removesuffix(
        "_URL"
    )
    harnesses = ("CODEX", "CLAUDE", "PI")
    if harness not in harnesses:
        raise RuntimeError("paperclip_agent_gateway_contract_invalid")
    tool_port = int(
        ctx.platform_env.get(f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_PORT") or 0
    )
    wrong_harness = harnesses[(harnesses.index(harness) + 1) % len(harnesses)]
    wrong_tool_url_ref = f"MTE_AGENT_GATEWAY_TOOLHIVE_{wrong_harness}_URL"
    wrong_tool_url = ctx.platform_env.get(wrong_tool_url_ref, "").rstrip("/")
    wrong_tool_port = int(
        ctx.platform_env.get(f"MTE_AGENT_GATEWAY_TOOLHIVE_{wrong_harness}_PORT") or 0
    )
    if not wrong_tool_url:
        raise RuntimeError("paperclip_agent_gateway_contract_missing")
    validate_url(router_url, port=router_port, path="")
    validate_url(tool_url, port=tool_port, path="/mcp")
    validate_url(wrong_tool_url, port=wrong_tool_port, path="/mcp")
    if wrong_tool_url == tool_url:
        raise RuntimeError("paperclip_agent_gateway_contract_invalid")
    return {
        "host": host,
        "routerBaseUrl": router_url,
        "toolhiveMcpUrl": tool_url,
        "toolhiveUrlRef": tool_url_ref,
        "toolhiveTokenRef": token_ref,
        "toolhiveBundleId": str(tool_access["bundleId"]),
        "toolhiveWorkloadId": str(tool_access["workloadId"]),
        "toolhiveCanaryTool": str(tool_access["canaryTool"]),
        "wrongProfileToolhiveMcpUrl": wrong_tool_url,
    }


def paperclip_desired_adapter_config(
    ctx: Context,
    *,
    company_id: str,
    agent_id: str,
    profile: dict[str, Any],
    adapter_type: str,
    router_secret_id: str,
    toolhive_secret_id: str,
    existing: dict[str, Any],
    context7_secret_id: str = "",
) -> dict[str, Any]:
    desired = dict(existing)
    desired.update(dict(profile.get("nativeAdapterConfig") or {}))
    gateway = paperclip_agent_gateway_contract(ctx, profile)
    env: dict[str, Any] = {}
    existing_env = existing.get("env") if isinstance(existing.get("env"), dict) else {}
    if adapter_type == "codex_local":
        binding = existing_env.get("CODEX_HOME")
        value = (
            binding.get("value")
            if isinstance(binding, dict) and binding.get("type") == "plain"
            else binding
            if isinstance(binding, str)
            else ""
        )
        expected_suffix = f"/companies/{company_id}/agents/{agent_id}/codex-home"
        if (
            isinstance(value, str)
            and value.startswith("/")
            and value.endswith(expected_suffix)
        ):
            # Paperclip injects this per-agent auth-home isolation whenever a
            # codex_local profile uses an API-key ref. Preserve only the exact
            # Paperclip-owned path so reconciliation is idempotent without
            # accepting arbitrary operator-supplied CODEX_HOME overrides.
            env["CODEX_HOME"] = {"type": "plain", "value": value}
    if router_secret_id:
        if adapter_type == "claude_local":
            env["ANTHROPIC_API_KEY"] = paperclip_ref(router_secret_id)
            env["ANTHROPIC_BASE_URL"] = {
                "type": "plain",
                "value": gateway["routerBaseUrl"],
            }
        else:
            env["OPENAI_API_KEY"] = paperclip_ref(router_secret_id)
            env["OPENAI_BASE_URL"] = {
                "type": "plain",
                "value": f"{gateway['routerBaseUrl']}/v1",
            }
        if adapter_type == "codex_local":
            env["PAPERCLIP_CODEX_PROVIDERS"] = {
                "type": "plain",
                "value": json.dumps(
                    {
                        "providers": {
                            "mte9router": {
                                "name": "MTE 9Router",
                                "base_url": f"{gateway['routerBaseUrl']}/v1",
                                "env_key": "OPENAI_API_KEY",
                                "wire_api": "responses",
                            }
                        },
                        "model_provider": "mte9router",
                    },
                    separators=(",", ":"),
                ),
            }
        elif adapter_type == "pi_local":
            model_id = ctx.platform_env.get("HERMES_LLM_MODEL", "")
            env["PAPERCLIP_PI_PROVIDERS"] = {
                "type": "plain",
                "value": json.dumps(
                    {
                        "mte9router": {
                            "baseUrl": f"{gateway['routerBaseUrl']}/v1",
                            "apiKey": "{env:OPENAI_API_KEY}",
                            "api": "openai-completions",
                            "models": [
                                {
                                    "id": model_id,
                                    "name": "MTE MiniMax",
                                    "reasoning": False,
                                    "input": ["text"],
                                    "cost": {
                                        "input": 0,
                                        "output": 0,
                                        "cacheRead": 0,
                                        "cacheWrite": 0,
                                    },
                                    "contextWindow": 200000,
                                    "maxTokens": 32768,
                                }
                            ],
                        }
                    },
                    separators=(",", ":"),
                ),
            }
            env["PI_CODING_AGENT_DIR"] = {
                "type": "plain",
                "value": ctx.platform_env.get("MTE_PI_CODING_AGENT_DIR", ""),
            }
    if toolhive_secret_id:
        env["MTE_TOOLHIVE_BEARER_TOKEN"] = paperclip_ref(toolhive_secret_id)
        env[gateway["toolhiveUrlRef"]] = {
            "type": "plain",
            "value": gateway["toolhiveMcpUrl"],
        }
        env["MTE_TOOLHIVE_WRONG_PROFILE_MCP_URL"] = {
            "type": "plain",
            "value": gateway["wrongProfileToolhiveMcpUrl"],
        }
        for key, value in (
            ("MTE_TOOLHIVE_BUNDLE_ID", gateway["toolhiveBundleId"]),
            ("MTE_TOOLHIVE_WORKLOAD_ID", gateway["toolhiveWorkloadId"]),
            ("MTE_TOOLHIVE_ENDPOINT_REF", gateway["toolhiveUrlRef"]),
            ("MTE_TOOLHIVE_BINDING_REF", gateway["toolhiveTokenRef"]),
            ("MTE_TOOLHIVE_CANARY_TOOL", gateway["toolhiveCanaryTool"]),
        ):
            env[key] = {"type": "plain", "value": value}
    if context7_secret_id:
        env["CONTEXT7_API_KEY"] = paperclip_ref(context7_secret_id)
    if adapter_type == "codex_local" and ("extraArgs" in desired or context7_secret_id):
        desired["extraArgs"] = reconcile_codex_context7_args(
            desired.get("extraArgs"),
            secret_ref_configured=bool(context7_secret_id),
        )
    if "github" in set((profile.get("mcpPolicy") or {}).get("allow", [])):
        github_ref = paperclip_user_ref("mte.github.personal_access_token")
        # Official GitHub CLI consumes GH_TOKEN while GitHub API/MCP clients
        # conventionally consume GITHUB_TOKEN. Keep both names bound to the
        # same Paperclip user-secret definition; no value is copied or written
        # into a workspace credential file.
        env["GH_TOKEN"] = dict(github_ref)
        env["GITHUB_TOKEN"] = dict(github_ref)
    desired["env"] = env
    return desired


def paperclip_adapter_binding_ready(
    adapter_config: dict[str, Any],
    desired_adapter_config: dict[str, Any],
    *,
    router_secret_id: str,
    toolhive_secret_id: str,
    context7_required: bool = False,
    context7_secret_id: str = "",
) -> bool:
    """Return readiness from the post-mutation adapter representation."""
    return (
        bool(router_secret_id)
        and bool(toolhive_secret_id)
        and (not context7_required or bool(context7_secret_id))
        and adapter_config == desired_adapter_config
    )


def paperclip_e2e_workspace_contract(ctx: Context) -> dict[str, Any]:
    """Return the supported Paperclip project workspace for the E2E target."""

    e2e = ctx.config.get("spec", {}).get("e2eCanary", {})
    refs = {
        "owner": str(e2e.get("githubOwnerRef") or ""),
        "repository": str(e2e.get("githubRepositoryRef") or ""),
        "baseBranch": str(e2e.get("baseBranchRef") or ""),
    }
    missing_refs = sorted(key for key, ref in refs.items() if not ref)
    if missing_refs:
        raise RuntimeError(
            "paperclip_e2e_workspace_refs_missing:" + ",".join(missing_refs)
        )
    values = {
        key: str(ctx.platform_env.get(ref, "")).strip() for key, ref in refs.items()
    }
    missing_values = sorted(key for key, value in values.items() if not value)
    if missing_values:
        raise RuntimeError(
            "paperclip_e2e_workspace_values_missing:" + ",".join(missing_values)
        )
    owner = values["owner"]
    repository = values["repository"]
    base_branch = values["baseBranch"]
    if (
        not E2E_GITHUB_SLUG_RE.fullmatch(owner)
        or not E2E_GITHUB_SLUG_RE.fullmatch(repository)
        or repository in {".", ".."}
    ):
        raise RuntimeError("paperclip_e2e_workspace_repository_invalid")
    invalid_branch = (
        not E2E_GITHUB_BRANCH_RE.fullmatch(base_branch)
        or base_branch == "HEAD"
        or base_branch.startswith(("-", ".", "/"))
        or base_branch.endswith((".", "/", ".lock"))
        or ".." in base_branch
        or "@{" in base_branch
        or "//" in base_branch
        or any(
            not segment
            or segment.startswith((".", "-"))
            or segment.endswith((".", ".lock"))
            for segment in base_branch.split("/")
        )
    )
    if invalid_branch:
        raise RuntimeError("paperclip_e2e_workspace_base_branch_invalid")
    return {
        "name": PAPERCLIP_E2E_WORKSPACE_NAME,
        "sourceType": "git_repo",
        "repoUrl": f"https://github.com/{owner}/{repository}.git",
        "repoRef": base_branch,
        "defaultRef": base_branch,
        "visibility": "default",
        "metadata": {
            "managedBy": PAPERCLIP_E2E_WORKSPACE_MANAGER,
            "purpose": PAPERCLIP_E2E_WORKSPACE_PURPOSE,
        },
        "isPrimary": True,
    }


def reconcile_paperclip_e2e_project_workspace(
    ctx: Context,
    url: str,
    headers: dict[str, str],
    project: dict[str, Any] | None,
) -> dict[str, Any]:
    """Read-before-write reconciliation for the E2E project's primary codebase."""

    project_id = str((project or {}).get("id") or "")
    if not project_id:
        return {"status": "needs_configuration", "reason": "project_missing"}
    desired = paperclip_e2e_workspace_contract(ctx)
    workspaces = list_value(
        request_json(
            "GET", f"{url}/api/projects/{project_id}/workspaces", headers=headers
        )
    )
    managed_workspaces = [
        row
        for row in workspaces
        if isinstance(row.get("metadata"), dict)
        and row["metadata"].get("managedBy") == PAPERCLIP_E2E_WORKSPACE_MANAGER
        and row["metadata"].get("purpose") == PAPERCLIP_E2E_WORKSPACE_PURPOSE
    ]
    unmanaged_collisions = [
        row
        for row in workspaces
        if row not in managed_workspaces
        and (
            row.get("name") == PAPERCLIP_E2E_WORKSPACE_NAME
            or row.get("repoUrl") == desired["repoUrl"]
        )
    ]
    if unmanaged_collisions:
        return {
            "status": "needs_configuration",
            "reason": "unmanaged_project_workspace_collision",
            "workspaceId": None,
            "sourceType": desired["sourceType"],
            "repoUrl": desired["repoUrl"],
            "defaultRef": desired["defaultRef"],
            "isPrimary": False,
            "policy": None,
        }
    if len(managed_workspaces) > 1:
        return {
            "status": "needs_configuration",
            "reason": "duplicate_managed_project_workspaces",
            "workspaceId": None,
            "sourceType": desired["sourceType"],
            "repoUrl": desired["repoUrl"],
            "defaultRef": desired["defaultRef"],
            "isPrimary": False,
            "policy": None,
        }
    workspace = managed_workspaces[0] if managed_workspaces else None
    if workspace is None and ctx.mutate:
        workspace = request_json(
            "POST",
            f"{url}/api/projects/{project_id}/workspaces",
            headers=headers,
            body=desired,
        )
    elif workspace is not None and ctx.mutate:
        drifted = any(workspace.get(key) != value for key, value in desired.items())
        if drifted:
            workspace = request_json(
                "PATCH",
                f"{url}/api/projects/{project_id}/workspaces/{workspace['id']}",
                headers=headers,
                body=desired,
            )
    workspace_id = str((workspace or {}).get("id") or "")
    desired_policy = {
        "enabled": True,
        "defaultMode": "isolated_workspace",
        "allowIssueOverride": True,
        "defaultProjectWorkspaceId": workspace_id or None,
        "workspaceStrategy": {
            "type": "cloud_sandbox",
            "baseRef": desired["defaultRef"],
        },
    }
    if (
        workspace_id
        and (project or {}).get("executionWorkspacePolicy") != desired_policy
    ):
        if ctx.mutate:
            updated = request_json(
                "PATCH",
                f"{url}/api/projects/{project_id}",
                headers=headers,
                body={"executionWorkspacePolicy": desired_policy},
            )
            if isinstance(updated, dict) and project is not None:
                project.update(updated)
        else:
            return {
                "status": "needs_configuration",
                "reason": "execution_workspace_policy_drift",
                "workspaceId": workspace_id,
                "repoUrl": desired["repoUrl"],
                "defaultRef": desired["defaultRef"],
            }
    ready = (
        bool(workspace_id)
        and all((workspace or {}).get(key) == value for key, value in desired.items())
        and (project or {}).get("executionWorkspacePolicy") == desired_policy
    )
    return {
        "status": "ready" if ready else "needs_configuration",
        "reason": None if ready else "primary_git_workspace_missing_or_drifted",
        "workspaceId": workspace_id or None,
        "sourceType": desired["sourceType"],
        "repoUrl": desired["repoUrl"],
        "defaultRef": desired["defaultRef"],
        "isPrimary": bool((workspace or {}).get("isPrimary")),
        "policy": desired_policy,
    }


def paperclip_daytona_environment(
    ctx: Context,
    url: str,
    headers: dict[str, str],
    company_id: str,
) -> dict[str, Any]:
    """Resolve the existing environment owned by the Daytona reconciler."""

    environment_name = str(
        ctx.platform_env.get("MTE_DAYTONA_ENVIRONMENT_NAME") or ""
    ).strip()
    if not environment_name:
        return {
            "status": "needs_configuration",
            "reason": "daytona_environment_name_missing",
            "environmentId": None,
        }
    environments = list_value(
        request_json(
            "GET",
            f"{url}/api/companies/{company_id}/environments",
            headers=headers,
        ),
        "environments",
    )
    managed = [
        row
        for row in environments
        if isinstance(row.get("metadata"), dict)
        and row["metadata"].get("managedBy") == PAPERCLIP_DAYTONA_ENVIRONMENT_MANAGER
        and row["metadata"].get("purpose") == PAPERCLIP_DAYTONA_ENVIRONMENT_PURPOSE
    ]
    if len(managed) != 1:
        return {
            "status": "needs_configuration",
            "reason": (
                "daytona_environment_missing"
                if not managed
                else "duplicate_managed_daytona_environments"
            ),
            "environmentId": None,
            "name": environment_name,
        }
    environment = managed[0]
    config = (
        environment.get("config") if isinstance(environment.get("config"), dict) else {}
    )
    ready = (
        environment.get("name") == environment_name
        and environment.get("driver") == "sandbox"
        and environment.get("status") == "active"
        and config.get("provider") == "daytona"
        and bool(environment.get("id"))
    )
    return {
        "status": "ready" if ready else "needs_configuration",
        "reason": None if ready else "daytona_environment_drift",
        "environmentId": str(environment.get("id") or "") or None,
        "name": environment_name,
        "driver": environment.get("driver"),
        "provider": config.get("provider"),
    }


def reconcile_paperclip_agent_environment(
    ctx: Context,
    url: str,
    headers: dict[str, str],
    agent: dict[str, Any],
    environment: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Bind a native agent through Paperclip's supported environment field."""

    environment_id = str(environment.get("environmentId") or "")
    agent_id = str(agent.get("id") or "")
    if (
        ctx.mutate
        and agent_id
        and environment.get("status") == "ready"
        and str(agent.get("defaultEnvironmentId") or "") != environment_id
    ):
        updated = request_json(
            "PATCH",
            f"{url}/api/agents/{agent_id}",
            headers=headers,
            body={"defaultEnvironmentId": environment_id},
        )
        if isinstance(updated, dict):
            agent.update(updated.get("agent", updated))
    default_environment_id = str(agent.get("defaultEnvironmentId") or "")
    ready = (
        environment.get("status") == "ready"
        and bool(agent_id)
        and default_environment_id == environment_id
    )
    return agent, {
        "agentId": agent_id or None,
        "defaultEnvironmentId": default_environment_id or None,
        "environmentId": environment_id or None,
        "status": "ready" if ready else "needs_configuration",
    }


def paperclip(ctx: Context) -> dict[str, Any]:
    component = "paperclip"
    board_identity = ensure_paperclip_board_identity(ctx)
    if board_identity["status"] != "ready":
        return result(
            component,
            "needs_authorization",
            reason=board_identity["reason"],
            browserHandoff=board_identity["browserHandoff"],
        )
    _, saved = ctx.integration(component)
    url = ctx.url(component)
    headers = paperclip_headers(saved, ctx.platform_env)
    try:
        runtime_security = paperclip_runtime_security(ctx)
        if runtime_security["status"] != "ready":
            return result(
                component, runtime_security["status"], runtimeSecurity=runtime_security
            )
        me = request_json("GET", f"{url}/api/cli-auth/me", headers=headers)
        current_user_id = str(
            me.get("userId") or (me.get("user") or {}).get("id") or ""
        )
        companies = list_value(
            request_json("GET", f"{url}/api/companies", headers=headers)
        )
        configured_company_id = ctx.platform_env.get("PAPERCLIP_COMPANY_ID", "")
        company = next(
            (row for row in companies if str(row.get("id")) == configured_company_id),
            None,
        )
        if company is None:
            company = next(
                (
                    row
                    for row in companies
                    if row.get("name")
                    in {"MTE Platform", "Micro Task Engine Prototype"}
                ),
                None,
            )
        if company is None and ctx.mutate:
            company = request_json(
                "POST",
                f"{url}/api/companies",
                headers=headers,
                body={
                    "name": "MTE Platform",
                    "description": "Managed multi-agent platform",
                    "budgetMonthlyCents": 0,
                },
            )
        if not company:
            return result(component, "pending_bootstrap", managed=[])
        company_id = str(company.get("id") or "")
        saved["PAPERCLIP_COMPANY_ID"] = company_id
        if ctx.mutate:
            ctx.save_integration(component, saved)

        members_payload = request_json(
            "GET", f"{url}/api/companies/{company_id}/members", headers=headers
        )
        members = list_value(members_payload, "members")
        current_member = next(
            (
                row
                for row in members
                if str(row.get("principalId")) == current_user_id
                and row.get("principalType") == "user"
                and row.get("status") == "active"
                and row.get("membershipRole") != "viewer"
            ),
            None,
        )
        responsible_user_id = str(company.get("defaultResponsibleUserId") or "")
        responsible_member = next(
            (
                row
                for row in members
                if str(row.get("principalId")) == responsible_user_id
                and row.get("principalType") == "user"
                and row.get("status") == "active"
                and row.get("membershipRole") != "viewer"
            ),
            None,
        )
        if responsible_member is None and current_member and ctx.mutate:
            company = request_json(
                "PATCH",
                f"{url}/api/companies/{company_id}",
                headers=headers,
                body={
                    "name": "MTE Platform",
                    "defaultResponsibleUserId": current_user_id,
                },
            )
            responsible_user_id = current_user_id
            responsible_member = current_member

        projects = list_value(
            request_json(
                "GET", f"{url}/api/companies/{company_id}/projects", headers=headers
            )
        )
        project = next(
            (row for row in projects if row.get("name") == "MTE Platform Operations"),
            None,
        )
        if project is None and ctx.mutate:
            project = request_json(
                "POST",
                f"{url}/api/companies/{company_id}/projects",
                headers=headers,
                body={
                    "name": "MTE Platform Operations",
                    "description": "Managed agent runs, platform maintenance and cross-service workflows.",
                    "status": "in_progress",
                },
            )
        if project and project.get("id") and ctx.mutate:
            ctx.persist_canonical({"PAPERCLIP_PROJECT_ID": str(project["id"])})
        project_workspace = reconcile_paperclip_e2e_project_workspace(
            ctx, url, headers, project
        )

        remote_secrets = list_value(
            request_json(
                "GET", f"{url}/api/companies/{company_id}/secrets", headers=headers
            )
        )
        secret_rows = [
            ensure_paperclip_company_secret(
                ctx, url, headers, company_id, remote_secrets, spec
            )
            for spec in paperclip_secret_specs(ctx)
        ]
        secret_ids = {row["sourceKey"]: row["id"] for row in secret_rows if row["id"]}

        definitions = list_value(
            request_json(
                "GET",
                f"{url}/api/companies/{company_id}/user-secret-definitions",
                headers=headers,
            )
        )
        user_values = list_value(
            request_json(
                "GET",
                f"{url}/api/companies/{company_id}/me/user-secrets",
                headers=headers,
            )
        )
        definition_rows: list[dict[str, Any]] = []
        for definition_spec in DEFAULT_USER_SECRET_DEFINITIONS:
            definition = next(
                (
                    row
                    for row in definitions
                    if row.get("key") == definition_spec["key"]
                ),
                None,
            )
            if definition is None and ctx.mutate:
                definition = request_json(
                    "POST",
                    f"{url}/api/companies/{company_id}/user-secret-definitions",
                    headers=headers,
                    body={
                        "key": definition_spec["key"],
                        "name": definition_spec["name"],
                        "description": definition_spec["description"],
                        "provider": "local_encrypted",
                        "managedMode": "paperclip_managed",
                        "usageGuidance": definition_spec["usageGuidance"],
                    },
                )
                if isinstance(definition, dict):
                    definitions.append(definition)
            source_value = canonical_secret_value(
                ctx.platform_env, definition_spec["sourceKey"]
            )
            user_value = next(
                (
                    row
                    for row in user_values
                    if str(
                        row.get("definitionId")
                        or (
                            row.get("definition", {}).get("id")
                            if isinstance(row.get("definition"), dict)
                            else ""
                        )
                    )
                    == str((definition or {}).get("id"))
                    or row.get("definitionKey") == definition_spec["key"]
                    or (
                        row.get("definition", {}).get("key")
                        if isinstance(row.get("definition"), dict)
                        else ""
                    )
                    == definition_spec["key"]
                ),
                None,
            )
            state_prefix = (
                f"PAPERCLIP_USER_SECRET_{safe_slug(definition_spec['key']).upper()}"
            )
            source_fingerprint = fingerprint(source_value) if source_value else ""
            stored_fingerprint = ctx.platform_env.get(
                f"{state_prefix}_SOURCE_FINGERPRINT", ""
            )
            if definition and source_value and current_member and ctx.mutate:
                user_secret_id = paperclip_user_secret_id(user_value)
                if user_secret_id and stored_fingerprint != source_fingerprint:
                    request_json(
                        "POST",
                        f"{url}/api/companies/{company_id}/me/user-secrets/{user_secret_id}/rotate",
                        headers=headers,
                        body={"value": source_value},
                    )
                elif user_value is None:
                    user_value = request_json(
                        "POST",
                        f"{url}/api/companies/{company_id}/me/user-secrets",
                        headers=headers,
                        body={"definitionId": definition["id"], "value": source_value},
                    )
                    if isinstance(user_value, dict):
                        user_values.append(user_value)
                user_secret_id = paperclip_user_secret_id(user_value)
                if user_secret_id:
                    ctx.persist_canonical(
                        {
                            f"{state_prefix}_ID": user_secret_id,
                            f"{state_prefix}_SOURCE_FINGERPRINT": source_fingerprint,
                        }
                    )
            definition_rows.append(
                {
                    "key": definition_spec["key"],
                    "status": "ready"
                    if definition and user_value and source_value
                    else "needs_authorization",
                    "sourceConfigured": bool(source_value),
                    "definitionId": str((definition or {}).get("id") or ""),
                    "userSecretId": paperclip_user_secret_id(user_value),
                    "provider": str(
                        (definition or {}).get("provider") or "local_encrypted"
                    ),
                    "managedMode": str(
                        (definition or {}).get("managedMode") or "paperclip_managed"
                    ),
                    "scope": "user",
                }
            )

        agents = list_value(
            request_json(
                "GET", f"{url}/api/companies/{company_id}/agents", headers=headers
            )
        )
        daytona_environment = paperclip_daytona_environment(
            ctx, url, headers, company_id
        )
        catalog = {str(row["ref"]): row for row in profile_catalog()}
        company_skills = list_value(
            request_json(
                "GET",
                f"{url}/api/companies/{company_id}/skills",
                headers=headers,
            )
        )
        for skill_key in sorted(
            {
                str(skill)
                for profile in catalog.values()
                for skill in profile.get("skills", [])
            }
        ):
            skill = next(
                (
                    row
                    for row in company_skills
                    if row.get("slug") == skill_key or row.get("name") == skill_key
                ),
                None,
            )
            if skill is None and ctx.mutate:
                created_skill = request_json(
                    "POST",
                    f"{url}/api/companies/{company_id}/skills",
                    headers=headers,
                    body={
                        "name": skill_key,
                        "slug": skill_key,
                        "description": "Declarative MTE profile skill requirement.",
                        "markdown": f"# {skill_key}\n\nApply this skill as required by the selected MTE agent profile.",
                        "sharingScope": "company",
                        "categories": ["mte-profile"],
                    },
                )
                if isinstance(created_skill, dict):
                    company_skills.append(created_skill.get("skill", created_skill))
        for profile_ref, profile in catalog.items():
            profile_agent = next(
                (
                    row
                    for row in agents
                    if paperclip_profile_ref(row, catalog) == profile_ref
                ),
                None,
            )
            if profile_agent is not None or not ctx.mutate:
                continue
            instruction_ref = str(profile.get("instructions") or "")
            instruction_path = (
                ROOT / "runtime/paperclip/profiles" / instruction_ref
                if instruction_ref
                else None
            )
            instructions_bundle = None
            if instruction_path and instruction_path.is_file():
                instructions_bundle = {
                    "entryFile": instruction_ref,
                    "files": {instruction_ref: instruction_path.read_text()},
                }
            body: dict[str, Any] = {
                "name": f"MTE {profile_ref} (native)",
                "title": str(profile.get("title") or profile_ref),
                "role": str(profile.get("role") or "general"),
                "adapterType": str(profile.get("nativeAdapter") or "process"),
                "adapterConfig": dict(profile.get("nativeAdapterConfig") or {}),
                "desiredSkills": [str(skill) for skill in profile.get("skills", [])],
                "budgetMonthlyCents": 0,
                "metadata": {
                    "profileRef": profile_ref,
                    "managedBy": "mte-server-provision",
                    "workspaceMode": profile.get("workspaceMode"),
                    "defaultEnvironment": profile.get("defaultEnvironment"),
                    "mcpPolicy": profile.get("mcpPolicy", {}),
                    "runtimePackages": profile.get("runtimePackages", {}),
                    "llmRouting": profile.get("llmRouting", {}),
                    "toolRouting": profile.get("toolRouting", {}),
                },
            }
            if instructions_bundle:
                body["instructionsBundle"] = instructions_bundle
            created_agent = request_json(
                "POST",
                f"{url}/api/companies/{company_id}/agents",
                headers=headers,
                body=body,
            )
            if isinstance(created_agent, dict):
                agents.append(created_agent.get("agent", created_agent))
        unsafe_inline: list[dict[str, Any]] = []
        bound_agents: list[dict[str, Any]] = []
        agent_environment_bindings: list[dict[str, Any]] = []
        for agent_row in agents:
            adapter_config = dict(agent_row.get("adapterConfig") or {})
            existing_env = dict(adapter_config.get("env") or {})
            for finding in unsafe_paperclip_env(existing_env):
                unsafe_inline.append(
                    {"agentId": str(agent_row.get("id")), "key": finding}
                )
            profile_ref = paperclip_profile_ref(agent_row, catalog)
            profile = catalog.get(profile_ref, {})
            adapter_type = str(
                agent_row.get("adapterType") or profile.get("nativeAdapter") or ""
            )
            if not profile_ref:
                continue
            source_key = f"NINEROUTER_PROFILE_{safe_slug(profile_ref).upper()}_API_KEY"
            if source_key not in secret_ids:
                source_key = {
                    "claude_local": "NINEROUTER_CLIENT_CLAUDE_API_KEY",
                    "codex_local": "NINEROUTER_CLIENT_CODEX_API_KEY",
                    "pi_local": "NINEROUTER_CLIENT_PI_API_KEY",
                }.get(adapter_type, "NINEROUTER_AGENT_API_KEY")
            router_secret_id = secret_ids.get(source_key, "")
            tool_routing = profile.get("toolRouting") or {}
            toolhive_source_key = str(tool_routing.get("bearerTokenRef") or "")
            toolhive_secret_id = secret_ids.get(toolhive_source_key, "")
            context7_configured = bool(
                canonical_secret_value(ctx.platform_env, "CONTEXT7_API_KEY")
            )
            context7_secret_id = secret_ids.get("CONTEXT7_API_KEY", "")
            # The profile owns the complete runtime credential envelope.  Do
            # not retain stale plain values or auth-home overrides from an old
            # bootstrap; strict-mode refs are rebuilt declaratively each run.
            desired_adapter_config = paperclip_desired_adapter_config(
                ctx,
                company_id=company_id,
                agent_id=str(agent_row.get("id") or ""),
                profile=profile,
                adapter_type=adapter_type,
                router_secret_id=router_secret_id,
                toolhive_secret_id=toolhive_secret_id,
                context7_secret_id=context7_secret_id,
                existing=adapter_config,
            )
            config_drift = desired_adapter_config != adapter_config
            if ctx.mutate and agent_row.get("id") and config_drift:
                updated_agent = request_json(
                    "PATCH",
                    f"{url}/api/agents/{agent_row['id']}",
                    headers=headers,
                    body={
                        "adapterConfig": desired_adapter_config,
                        "replaceAdapterConfig": True,
                    },
                )
                if isinstance(updated_agent, dict):
                    agent_row.update(updated_agent.get("agent", updated_agent))
                adapter_config = dict(agent_row.get("adapterConfig") or {})
                desired_adapter_config = paperclip_desired_adapter_config(
                    ctx,
                    company_id=company_id,
                    agent_id=str(agent_row.get("id") or ""),
                    profile=profile,
                    adapter_type=adapter_type,
                    router_secret_id=router_secret_id,
                    toolhive_secret_id=toolhive_secret_id,
                    context7_secret_id=context7_secret_id,
                    existing=adapter_config,
                )
                config_drift = adapter_config != desired_adapter_config
            elif not ctx.mutate:
                config_drift = adapter_config != desired_adapter_config
            agent_row, environment_binding = reconcile_paperclip_agent_environment(
                ctx,
                url,
                headers,
                agent_row,
                daytona_environment,
            )
            environment_binding["profileRef"] = profile_ref
            agent_environment_bindings.append(environment_binding)
            # Paperclip may inject its managed per-agent CODEX_HOME while
            # applying a codex_local adapter.  Readiness must use the desired
            # envelope recomputed from that response, never the pre-PATCH one.
            binding_ready = (
                paperclip_adapter_binding_ready(
                    adapter_config,
                    desired_adapter_config,
                    router_secret_id=router_secret_id,
                    toolhive_secret_id=toolhive_secret_id,
                    context7_required=context7_configured,
                    context7_secret_id=context7_secret_id,
                )
                and environment_binding["status"] == "ready"
            )
            bound_agents.append(
                {
                    "agentId": str(agent_row.get("id") or "") or None,
                    "profileRef": profile_ref,
                    "adapterType": adapter_type,
                    "routerKeyRef": source_key,
                    "routerSecretId": router_secret_id,
                    "toolhiveTokenRef": toolhive_source_key,
                    "toolhiveSecretId": toolhive_secret_id,
                    "toolhiveUrlRef": str(tool_routing.get("mcpUrlRef") or ""),
                    "gatewayHost": ctx.platform_env.get("MTE_AGENT_GATEWAY_HOST", ""),
                    "context7": context7_binding_evidence(
                        ctx, context7_secret_id, adapter_type
                    ),
                    "status": "ready" if binding_ready else "needs_configuration",
                    "cwd": str(adapter_config.get("cwd") or ""),
                    "envKeys": sorted((adapter_config.get("env") or {}).keys()),
                    "configDrift": config_drift,
                    "defaultEnvironmentId": environment_binding["defaultEnvironmentId"],
                    "environmentId": environment_binding["environmentId"],
                }
            )

        project_env = dict((project or {}).get("env") or {})
        for finding in unsafe_paperclip_env(project_env):
            unsafe_inline.append(
                {"projectId": str((project or {}).get("id") or ""), "key": finding}
            )
        project_env = reconcile_data_content_paperclip_env(ctx, project_env, secret_ids)
        for source_key, env_key in (
            ("MATTERMOST_BOT_TOKEN", "MATTERMOST_BOT_TOKEN"),
            ("KESTRA_ADMIN_PASSWORD", "KESTRA_PASSWORD"),
        ):
            if secret_ids.get(source_key):
                project_env[env_key] = paperclip_ref(secret_ids[source_key])
        project_env["KESTRA_USERNAME"] = {
            "type": "plain",
            "value": ctx.platform_env.get("KESTRA_ADMIN_USER", ""),
        }
        project_env["NINEROUTER_BASE_URL"] = {
            "type": "plain",
            "value": f"{ctx.url('9router')}/v1",
        }
        if (
            project
            and project.get("id")
            and ctx.mutate
            and project_env != (project.get("env") or {})
        ):
            request_json(
                "PATCH",
                f"{url}/api/projects/{project['id']}",
                headers=headers,
                body={"env": project_env},
            )

        for definition_row in definition_rows:
            definition_id = definition_row.get("definitionId", "")
            if not definition_id:
                definition_row["coverage"] = "not_available"
                continue
            try:
                request_json(
                    "GET",
                    f"{url}/api/companies/{company_id}/user-secret-definitions/{definition_id}/coverage",
                    headers=headers,
                )
                definition_row["coverage"] = "checked"
            except ApiError:
                definition_row["coverage"] = "check_failed"

        configured_id = (
            saved.get("PAPERCLIP_SERVICE_AGENT_ID")
            or ctx.platform_env.get("PAPERCLIP_SERVICE_AGENT_ID", "")
            or ctx.platform_env.get("HERMES_PAPERCLIP_AGENT_ID", "")
        )
        agent = (
            next((row for row in agents if str(row.get("id")) == configured_id), None)
            if configured_id
            else None
        )
        if agent is None:
            agent = next(
                (
                    row
                    for row in agents
                    if (
                        (
                            isinstance(row.get("metadata"), dict)
                            and row["metadata"].get("systemRef")
                            == "hermes-operator"
                        )
                        or (
                            "gateway" in str(row.get("name", "")).lower()
                            and any(
                                token in str(row.get("name", "")).lower()
                                for token in ("hermes", "platform")
                            )
                        )
                    )
                ),
                None,
            )
        gateway_secret_id = secret_ids.get("HERMES_API_SERVER_KEY", "")
        gateway_payload = (
            hermes_gateway_agent_payload(
                ctx,
                gateway_secret_id=gateway_secret_id,
            )
            if gateway_secret_id
            else None
        )
        if agent is None and gateway_payload and ctx.mutate:
            created_agent = request_json(
                "POST",
                f"{url}/api/companies/{company_id}/agents",
                headers=headers,
                body=gateway_payload,
            )
            if isinstance(created_agent, dict):
                agent = created_agent.get("agent", created_agent)
                if isinstance(agent, dict):
                    agents.append(agent)
        if agent and agent.get("id"):
            gateway_config = dict(agent.get("adapterConfig") or {})
            if gateway_payload:
                desired_gateway_config = dict(gateway_payload["adapterConfig"])
                desired_gateway_config["env"] = dict(gateway_config.get("env") or {})
                gateway_identity_drift = (
                    agent.get("adapterType") != "hermes_gateway"
                    or gateway_config != desired_gateway_config
                    or (agent.get("metadata") or {}).get("systemRef")
                    != "hermes-operator"
                )
                if ctx.mutate and gateway_identity_drift:
                    updated_agent = request_json(
                        "PATCH",
                        f"{url}/api/agents/{agent['id']}",
                        headers=headers,
                        body={
                            "adapterType": "hermes_gateway",
                            "adapterConfig": desired_gateway_config,
                            "replaceAdapterConfig": True,
                            "metadata": gateway_payload["metadata"],
                        },
                    )
                    if isinstance(updated_agent, dict):
                        agent.update(updated_agent.get("agent", updated_agent))
                    gateway_config = dict(agent.get("adapterConfig") or {})
            gateway_env = dict(gateway_config.get("env") or {})
            for finding in unsafe_paperclip_env(gateway_env):
                unsafe_inline.append({"agentId": str(agent["id"]), "key": finding})
            gateway_env = reconcile_data_content_paperclip_env(
                ctx, gateway_env, secret_ids
            )
            gateway_sources = (
                (
                    "NINEROUTER_CLIENT_HERMES_API_KEY",
                    "HERMES_LLM_API_KEY",
                ),
                ("MATTERMOST_BOT_TOKEN", "MATTERMOST_BOT_TOKEN"),
                ("KESTRA_ADMIN_PASSWORD", "KESTRA_PASSWORD"),
                ("HERMES_API_SERVER_KEY", "HERMES_API_SERVER_KEY"),
            )
            for source_key, env_key in gateway_sources:
                if secret_ids.get(source_key):
                    gateway_env[env_key] = paperclip_ref(secret_ids[source_key])
            gateway_env["HERMES_LLM_BASE_URL"] = {
                "type": "plain",
                "value": f"{ctx.url('9router')}/v1",
            }
            gateway_env["HERMES_LLM_MODEL"] = {
                "type": "plain",
                "value": ctx.platform_env.get("HERMES_LLM_MODEL", ""),
            }
            gateway_env["KESTRA_USERNAME"] = {
                "type": "plain",
                "value": ctx.platform_env.get("KESTRA_ADMIN_USER", ""),
            }
            gateway_config["env"] = gateway_env
            if ctx.mutate and gateway_env != (agent.get("adapterConfig") or {}).get(
                "env", {}
            ):
                agent = request_json(
                    "PATCH",
                    f"{url}/api/agents/{agent['id']}",
                    headers=headers,
                    body={
                        "adapterConfig": gateway_config,
                        "replaceAdapterConfig": True,
                    },
                )
            saved["PAPERCLIP_SERVICE_AGENT_ID"] = str(agent["id"])
            existing_keys = list_value(
                request_json(
                    "GET", f"{url}/api/agents/{agent['id']}/keys", headers=headers
                )
            )
            named = next(
                (
                    row
                    for row in existing_keys
                    if row.get("name") == "mte-tools" and not row.get("revokedAt")
                ),
                None,
            )
            if saved.get("PAPERCLIP_AGENT_API_KEY"):
                try:
                    me = request_json(
                        "GET",
                        f"{url}/api/agents/me",
                        headers={
                            "Authorization": f"Bearer {saved['PAPERCLIP_AGENT_API_KEY']}"
                        },
                    )
                    if str(me.get("id")) != str(agent["id"]):
                        saved.pop("PAPERCLIP_AGENT_API_KEY", None)
                except ApiError:
                    saved.pop("PAPERCLIP_AGENT_API_KEY", None)
            if named is None and ctx.mutate:
                created = request_json(
                    "POST",
                    f"{url}/api/agents/{agent['id']}/keys",
                    headers=headers,
                    body={
                        "name": "mte-tools",
                        "scope": {
                            "kind": "task_bridge",
                            "projectIds": [str(project["id"])]
                            if project and project.get("id")
                            else [],
                            "allowedAssigneeAgentIds": [
                                str(row["id"]) for row in agents if row.get("id")
                            ],
                        },
                    },
                )
                raw = find_secret(created, ("pcp_",))
                if not raw:
                    raise RuntimeError("paperclip_agent_key_missing")
                saved["PAPERCLIP_AGENT_API_KEY"] = raw
                saved["HERMES_PAPERCLIP_API_KEY"] = raw
                if created.get("id"):
                    saved["PAPERCLIP_AGENT_API_KEY_ID"] = str(created["id"])
            elif named is not None and not saved.get("PAPERCLIP_AGENT_API_KEY"):
                if ctx.mutate and named.get("id"):
                    # This is our reserved managed-key name.  If its one-time
                    # value was lost, revoke it before minting the replacement;
                    # never leave a duplicate unknown credential active.
                    request_json(
                        "DELETE",
                        f"{url}/api/agents/{agent['id']}/keys/{named['id']}",
                        headers=headers,
                    )
                    created = request_json(
                        "POST",
                        f"{url}/api/agents/{agent['id']}/keys",
                        headers=headers,
                        body={
                            "name": "mte-tools",
                            "scope": {
                                "kind": "task_bridge",
                                "projectIds": [str(project["id"])]
                                if project and project.get("id")
                                else [],
                                "allowedAssigneeAgentIds": [
                                    str(row["id"]) for row in agents if row.get("id")
                                ],
                            },
                        },
                    )
                    raw = find_secret(created, ("pcp_",))
                    if not raw:
                        raise RuntimeError("paperclip_agent_key_rotation_missing")
                    saved["PAPERCLIP_AGENT_API_KEY"] = raw
                    saved["HERMES_PAPERCLIP_API_KEY"] = raw
                    saved["PAPERCLIP_AGENT_API_KEY_ID"] = str(created.get("id") or "")
                    saved["PAPERCLIP_AGENT_KEY_STATE"] = "ready"
                elif ctx.mutate:
                    saved["PAPERCLIP_AGENT_KEY_STATE"] = "needs_rotation"
        if ctx.mutate:
            if saved.get("PAPERCLIP_AGENT_API_KEY"):
                saved["HERMES_PAPERCLIP_API_KEY"] = saved["PAPERCLIP_AGENT_API_KEY"]
            ctx.save_integration(component, saved)
        required_definition_keys = {
            "mte.github.personal_access_token"
            for row in bound_agents
            if row["profileRef"] in catalog
            and "github"
            in set((catalog[row["profileRef"]].get("mcpPolicy") or {}).get("allow", []))
        }
        user_bindings_ready = all(
            row["status"] == "ready"
            for row in definition_rows
            if row["key"] in required_definition_keys
        )
        required_data_content_secrets = {
            source_key for source_key, _ in data_content_paperclip_bindings(ctx)
        }
        company_secrets_ready = (
            bool(secret_rows)
            and required_data_content_secrets.issubset(secret_ids)
            and all(row["status"] == "ready" for row in secret_rows)
        )
        bound_profile_refs = [str(row.get("profileRef") or "") for row in bound_agents]
        agent_bindings_ready = (
            len(bound_agents) == len(catalog)
            and set(bound_profile_refs) == set(catalog)
            and len(bound_profile_refs) == len(set(bound_profile_refs))
            and all(row["status"] == "ready" for row in bound_agents)
        )
        if not agent:
            status = "needs_configuration"
            reason = "service_agent_profile_must_be_created_by_profile_renderer"
        elif not saved.get("PAPERCLIP_AGENT_API_KEY"):
            status = "needs_rotation"
            reason = "existing_one_time_agent_key_not_recoverable"
        else:
            status = "ready"
            reason = None
        if not responsible_member:
            status = "needs_authorization"
            reason = "active_responsible_user_required_for_dispatch"
        elif unsafe_inline:
            status = "error"
            reason = "strict_mode_rejects_inline_sensitive_agent_env"
        elif daytona_environment["status"] != "ready":
            status = "needs_configuration"
            reason = str(
                daytona_environment.get("reason") or "daytona_environment_incomplete"
            )
        elif not company_secrets_ready or not agent_bindings_ready:
            status = "needs_configuration"
            reason = "company_secret_or_agent_bindings_incomplete"
        elif project_workspace["status"] != "ready":
            status = "needs_configuration"
            reason = str(
                project_workspace.get("reason") or "project_workspace_incomplete"
            )
        elif not user_bindings_ready:
            status = "needs_authorization"
            reason = "required_user_secret_value_missing"
        return result(
            component,
            status,
            reason=reason,
            managed=[
                "company",
                "default_responsible_user",
                "operations_project",
                "e2e_primary_git_workspace",
                "local_encrypted_company_secrets",
                "user_secret_definitions",
                "profile_runtime_bindings",
                "task_bridge_agent_key",
            ],
            names={
                "company": "MTE Platform",
                "project": "MTE Platform Operations",
                "agentKey": "mte-tools",
            },
            fingerprints={"agentApiKey": fingerprint(saved["PAPERCLIP_AGENT_API_KEY"])}
            if saved.get("PAPERCLIP_AGENT_API_KEY")
            else {},
            runtimeSecurity=runtime_security,
            responsibleUser={
                "configured": bool(responsible_member),
                "userId": responsible_user_id or None,
            },
            projectWorkspace=project_workspace,
            daytonaEnvironment=daytona_environment,
            companySecrets=[dict(row) for row in secret_rows],
            userSecretDefinitions=definition_rows,
            agentBindings=bound_agents,
            agentEnvironmentBindings=agent_environment_bindings,
            unsafeInlineBindings=unsafe_inline,
            limitations=[
                "The provisioner creates the official Hermes gateway agent and scoped task-bridge key; the native Hermes runtime is installed separately by the deployment stage."
            ],
        )
    except ApiError as exc:
        if exc.status in {401, 403} and not saved.get("PAPERCLIP_BOARD_API_KEY"):
            return result(
                component,
                "needs_authorization",
                reason="authenticated_mode_requires_board_cli_key",
            )
        return component_error(component, exc)
    except BaseException as exc:
        return component_error(component, exc)


ADAPTERS: tuple[Callable[[Context], dict[str, Any]], ...] = (
    mattermost,
    kestra,
    ninerouter,
    paperclip,
)


def build_refs(ctx: Context, rows: list[dict[str, Any]]) -> dict[str, Any]:
    status = {row["component"]: row["status"] for row in rows}
    profile = ctx.platform_env.get("DATA_CONTENT_PROFILE", "")
    if profile != "postgres-notion":
        raise RuntimeError("data_content_profile_unsupported")
    data_content_services = {
        "postgrest": {
            "url": ctx.url("postgrest"),
            "role": "internal_ssot_api",
            "authority": "postgres",
            "credentialFile": str(SERVICES / "postgrest.env"),
            "agentCredentialBinding": "paperclip_secret_ref",
            "managedSecretProvider": "local_encrypted",
            "tokenKey": "POSTGREST_PAPERCLIP_TOKEN",
            "capabilities": {
                "records": {
                    "id": "mte.postgres.records",
                    "sourceOfTruth": True,
                }
            },
            "status": "managed_by_server_postgrest",
        },
        "notion": {
            "url": ctx.platform_env.get("NOTION_API_BASE_URL", ""),
            "role": "external_presentation_provider",
            "authority": "postgres",
            "sourceOfTruth": False,
            "canonicalCredentialSource": str(PLATFORM_ENV),
            "agentCredentialBinding": "toolhive_readonly_tools_only",
            "agentRawCredential": False,
            "connectorCredentialBinding": "paperclip_secret_ref",
            "connectorIdentity": "mte.notion.connector",
            "connectorExecutable": "server-notion.py",
            "connectorAgentReachable": False,
            "managedSecretProvider": "local_encrypted",
            "connectorTokenKey": "NOTION_TOKEN",
            "apiVersionKey": "NOTION_API_VERSION",
            "rootPageIdKey": "NOTION_ROOT_PAGE_ID",
            "capabilities": {
                "tables": {
                    "id": "mte.notion.tables",
                    "databaseIdKey": "NOTION_TABLE_DATABASE_ID",
                    "dataSourceIdKey": "NOTION_TABLE_DATA_SOURCE_ID",
                },
                "documents": {
                    "id": "mte.notion.documents",
                    "parentPageIdKey": "NOTION_DOCUMENTS_PAGE_ID",
                },
            },
            "status": "managed_external_connector",
        },
    }
    return {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "AgentAccessReferenceCatalog",
        "generatedAt": now(),
        "services": {
            **data_content_services,
            "mattermost": {
                "url": ctx.url("mattermost"),
                "credentialFile": str(SERVICES / "mattermost.env"),
                "agentCredentialBinding": "paperclip_secret_ref",
                "tokenKey": "MATTERMOST_BOT_TOKEN",
                "teamIdKey": "MATTERMOST_TEAM_ID",
                "status": status.get("mattermost"),
            },
            "kestra": {
                "url": ctx.url("kestra"),
                "credentialFile": str(PLATFORM_ENV),
                "usernameKey": "KESTRA_ADMIN_USER",
                "passwordKey": "KESTRA_ADMIN_PASSWORD",
                "serviceToken": "unsupported_in_open_source_edition",
                "status": status.get("kestra"),
            },
            "9router": {
                "url": ctx.url("9router"),
                "openaiBaseUrl": f"{ctx.url('9router')}/v1",
                "credentialFile": str(SERVICES / "9router.env"),
                "agentCredentialBinding": "paperclip_secret_ref",
                "tokenKey": "NINEROUTER_AGENT_API_KEY",
                "canonicalCredentialSource": str(PLATFORM_ENV),
                "projectionSourceHash": canonical_source_hash(),
                "harnessProfiles": {
                    "claude": {
                        "profileRef": "claude",
                        "profileCatalog": str(ROOT / "runtime/profiles/profiles.yaml"),
                        "tokenKey": "NINEROUTER_CLIENT_CLAUDE_API_KEY",
                        "runtimeTokenKey": "ANTHROPIC_API_KEY",
                        "baseUrlKey": "ANTHROPIC_BASE_URL",
                        "endpoint": "/v1/messages",
                        "protocol": "anthropic_messages",
                        "modelKey": "HERMES_LLM_MODEL",
                    },
                    "codex": {
                        "profileRef": "codex",
                        "profileCatalog": str(ROOT / "runtime/profiles/profiles.yaml"),
                        "tokenKey": "NINEROUTER_CLIENT_CODEX_API_KEY",
                        "runtimeTokenKey": "OPENAI_API_KEY",
                        "baseUrlKey": "OPENAI_BASE_URL",
                        "endpoint": "/v1/responses",
                        "protocol": "openai_responses",
                        "modelKey": "HERMES_LLM_MODEL",
                    },
                    "pi": {
                        "profileRef": "pi",
                        "profileCatalog": str(ROOT / "runtime/profiles/profiles.yaml"),
                        "tokenKey": "NINEROUTER_CLIENT_PI_API_KEY",
                        "runtimeTokenKey": "OPENAI_API_KEY",
                        "baseUrlKey": "OPENAI_BASE_URL",
                        "endpoint": "/v1/chat/completions",
                        "protocol": "openai_chat_completions",
                        "modelKey": "HERMES_LLM_MODEL",
                    },
                },
                "daytonaProfileRefs": {
                    "coding-daytona-codex": {
                        "clientKeyRef": "NINEROUTER_PROFILE_CODING_DAYTONA_CODEX_API_KEY",
                        "modelKey": "HERMES_LLM_MODEL",
                        "protocol": "openai_responses",
                    },
                    "coding-daytona-claude": {
                        "clientKeyRef": "NINEROUTER_PROFILE_CODING_DAYTONA_CLAUDE_API_KEY",
                        "modelKey": "HERMES_LLM_MODEL",
                        "protocol": "anthropic_messages",
                    },
                    "coding-daytona-pi": {
                        "clientKeyRef": "NINEROUTER_PROFILE_CODING_DAYTONA_PI_API_KEY",
                        "modelKey": "HERMES_LLM_MODEL",
                        "protocol": "openai_chat_completions",
                    },
                },
                "status": status.get("9router"),
            },
            "paperclip": {
                "url": ctx.url("paperclip"),
                "credentialFile": str(SERVICES / "paperclip.env"),
                "tokenKey": "PAPERCLIP_AGENT_API_KEY",
                "companyIdKey": "PAPERCLIP_COMPANY_ID",
                "status": status.get("paperclip"),
            },
        },
        "codingAuth": {
            harness: harness_router_auth_status(ctx, harness)
            for harness in ("codex", "claude", "pi")
        },
    }


def validate_secret_tree() -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    paths: list[Path] = [SECRET_ROOT, PLATFORM_ENV]
    if INTEGRATIONS.exists():
        paths.extend([INTEGRATIONS, *INTEGRATIONS.rglob("*")])
    for path in paths:
        if not path.exists():
            findings.append({"path": str(path), "finding": "missing"})
            continue
        try:
            info = path.lstat()
        except OSError:
            findings.append({"path": str(path), "finding": "unreadable"})
            continue
        mode = stat.S_IMODE(info.st_mode)
        if path.is_symlink():
            findings.append({"path": str(path), "finding": "symlink_not_allowed"})
        elif path.is_dir() and mode & 0o077:
            findings.append(
                {"path": str(path), "finding": "directory_permissions_too_open"}
            )
        elif path.is_file() and mode & 0o077:
            findings.append({"path": str(path), "finding": "file_permissions_too_open"})
        elif path.is_file() and path.suffix == ".env" and path != PLATFORM_ENV:
            projection_hash = dotenv(path).get("MTE_PROJECTION_SOURCE_SHA256", "")
            if projection_hash != canonical_source_hash():
                findings.append(
                    {
                        "path": str(path),
                        "finding": "projection_source_hash_missing_or_stale",
                    }
                )
    return findings


def reconcile_canonical_projections() -> dict[str, Any]:
    if not CONFIG_RENDERER.is_file():
        return {"status": "error", "reason": "server_config_renderer_missing"}
    for action in ("render", "audit"):
        completed = subprocess.run(
            [sys.executable, str(CONFIG_RENDERER), action],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if completed.returncode != 0:
            return {
                "status": "error",
                "reason": f"canonical_projection_{action}_failed",
            }
    try:
        manifest = json.loads(PROJECTION_MANIFEST.read_text())
    except (OSError, json.JSONDecodeError):
        return {"status": "error", "reason": "projection_manifest_missing_or_invalid"}
    return {
        "status": "ready",
        "sourceHash": str(manifest.get("sourceSha256") or "")[:16],
        "generatorVersion": manifest.get("generatorVersion"),
        "projectionCount": len(manifest.get("projections", [])),
    }


def write_provision_verify_evidence(value: dict[str, Any]) -> dict[str, Any]:
    """Persist a redacted, source-bound proof of the Paperclip secret model."""

    components = value.get("components")
    paperclip_row = (
        next(
            (
                row
                for row in components
                if isinstance(row, dict) and row.get("component") == "paperclip"
            ),
            {},
        )
        if isinstance(components, list)
        else {}
    )
    runtime_security = (
        paperclip_row.get("runtimeSecurity")
        if isinstance(paperclip_row.get("runtimeSecurity"), dict)
        else {}
    )
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "AccountProvisioningVerify",
        "status": "passed" if value.get("ok") is True else "failed",
        "runId": str(uuid.uuid4()),
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "canonicalSourceSha256": canonical_source_hash(),
        "producerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "paperclip": {
            "status": paperclip_row.get("status"),
            "runtimeSecurity": {
                "provider": runtime_security.get("provider"),
                "strictMode": runtime_security.get("strictMode") is True,
                "configMode": runtime_security.get("configMode"),
                "masterKeyFile": runtime_security.get("masterKeyFile"),
                "llmApiKeyConfigured": runtime_security.get("llmApiKeyConfigured")
                is True,
            },
            "responsibleUser": paperclip_row.get("responsibleUser"),
            "projectWorkspace": paperclip_row.get("projectWorkspace"),
            "daytonaEnvironment": paperclip_row.get("daytonaEnvironment"),
            "companySecrets": paperclip_row.get("companySecrets", []),
            "userSecretDefinitions": paperclip_row.get("userSecretDefinitions", []),
            "agentBindings": paperclip_row.get("agentBindings", []),
            "agentEnvironmentBindings": paperclip_row.get(
                "agentEnvironmentBindings", []
            ),
            "unsafeInlineBindings": paperclip_row.get("unsafeInlineBindings", []),
        },
        "security": value.get("security", {}),
    }
    write_json(PROVISION_VERIFY_EVIDENCE, payload)
    return {
        "path": str(PROVISION_VERIFY_EVIDENCE),
        "sha256": hashlib.sha256(PROVISION_VERIFY_EVIDENCE.read_bytes()).hexdigest(),
        "mode": oct(stat.S_IMODE(PROVISION_VERIFY_EVIDENCE.stat().st_mode)),
    }


def execute(action: str) -> dict[str, Any]:
    if not CONFIG.exists() or not PLATFORM_ENV.exists():
        missing = [str(path) for path in (CONFIG, PLATFORM_ENV) if not path.exists()]
        return {
            "action": action,
            "timestamp": now(),
            "ok": False,
            "error": "missing_required_files",
            "missing": missing,
        }
    config = json.loads(CONFIG.read_text())
    mutate = action == "provision"
    platform_values = dotenv(PLATFORM_ENV)
    ctx = Context(
        config=config,
        platform_env=platform_values,
        mutate=mutate,
        strict=action == "verify",
        canonical_mutation_keys=(
            canonical_mutation_plan(platform_values) if mutate else frozenset()
        ),
    )
    if mutate:
        secure_directory(INTEGRATIONS)
    rows = [adapter(ctx) for adapter in ADAPTERS]
    projection_reconcile = (
        reconcile_canonical_projections()
        if mutate
        else {"status": "not_run", "reason": "read_only_action"}
    )
    refs = build_refs(ctx, rows)
    if mutate:
        write_json(REFS, refs)
    findings = validate_secret_tree()
    incomplete = [
        row["component"]
        for row in rows
        if row["component"] in REQUIRED_COMPONENTS
        and row["status"] not in TERMINAL_READY
    ]
    if mutate and projection_reconcile["status"] != "ready":
        incomplete.append("canonical-projections")
    value = {
        "action": action,
        "timestamp": now(),
        "ok": not incomplete and not findings,
        "components": rows,
        "incomplete": incomplete,
        "security": {"ok": not findings, "findings": findings},
        "canonicalProjections": projection_reconcile,
        "canonicalMutationGuard": {
            "authorizedBeforeRemoteWrites": mutate,
            "changedKeys": sorted(ctx.canonical_mutations),
        },
        "referenceCatalog": str(REFS),
    }
    if action == "verify":
        value["verifyEvidence"] = write_provision_verify_evidence(value)
    return value


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    if (
        action
        not in {
            "bootstrap-router-keys",
            "provision",
            "status",
            "verify",
        }
        or len(sys.argv) != 2
    ):
        print(
            "usage: server-provision.py bootstrap-router-keys|provision|status|verify",
            file=sys.stderr,
        )
        return 2
    try:
        if action == "bootstrap-router-keys":
            if not CONFIG.exists() or not PLATFORM_ENV.exists():
                missing = [
                    str(path) for path in (CONFIG, PLATFORM_ENV) if not path.exists()
                ]
                value = {
                    "action": action,
                    "timestamp": now(),
                    "ok": False,
                    "error": "missing_required_files",
                    "missing": missing,
                }
            else:
                platform_values = dotenv(PLATFORM_ENV)
                ctx = Context(
                    config=json.loads(CONFIG.read_text()),
                    platform_env=platform_values,
                    mutate=True,
                    strict=True,
                    canonical_mutation_keys=canonical_mutation_plan(platform_values),
                )
                value = bootstrap_ninerouter_keys(ctx)
        else:
            value = execute(action)
    except BaseException as exc:
        value = {
            "action": action,
            "timestamp": now(),
            "ok": False,
            "error": "provisioner_failure",
            "errorType": type(exc).__name__,
        }
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0 if action == "status" or value.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

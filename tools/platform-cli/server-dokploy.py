#!/usr/bin/env python3
"""Idempotently reconcile raw Compose applications through the local Dokploy API."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path("/opt/mte-platform")
SECRET_ROOT = Path("/root/.config/mte-secrets")
CONFIG_PATH = ROOT / "config/platform.json"
IDS_PATH = SECRET_ROOT / "dokploy-mte-ids.json"
STATE_PATH = SECRET_ROOT / "dokploy-mte-state.json"
COOKIE_PATH = SECRET_ROOT / "dokploy.cookies"
PLATFORM_ENV = SECRET_ROOT / "platform.env"
PLATFORM_LOCK = SECRET_ROOT / ".platform-env.lock"
PROJECTIONS_MANIFEST = SECRET_ROOT / "projections-manifest.json"
CONFIG_RENDERER = ROOT / "bin/server-config.py"
CONFIG_GENERATOR_VERSION = "mte-config-renderer/v1"
API_KEY_NAME = "mte-platform-cli"
API_KEY_REF = "DOKPLOY_API_TOKEN"


def dotenv(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.exists():
        return result
    for line in path.read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def load_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text())


def save_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    secure_path(temp, 0o600)
    temp.replace(path)


def ensure_agent_plane() -> str:
    name = dotenv(PLATFORM_ENV).get("MTE_AGENT_PLANE_NETWORK", "")
    if not name or not all(
        character.isalnum() or character in "_.-" for character in name
    ):
        raise RuntimeError("canonical agent-plane network name is missing or invalid")
    inspected = subprocess.run(
        ["docker", "network", "inspect", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if inspected.returncode != 0:
        subprocess.run(
            ["docker", "network", "create", "--driver", "bridge", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    return name


@contextmanager
def canonical_writer_guard():
    SECRET_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    secure_path(SECRET_ROOT, 0o700)
    descriptor = os.open(PLATFORM_LOCK, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        if os.geteuid() == 0:
            os.fchown(descriptor, 0, 0)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def persist_canonical_api_token(token: str) -> str:
    if not re.fullmatch(r"[^\s]{24,}", token):
        raise RuntimeError("refusing to persist an invalid Dokploy API credential")
    with canonical_writer_guard():
        verify_canonical_permissions()
        values = dotenv(PLATFORM_ENV)
        values[API_KEY_REF] = token
        descriptor, temporary = tempfile.mkstemp(
            prefix="platform.env.",
            dir=SECRET_ROOT,
        )
        try:
            with os.fdopen(descriptor, "w") as handle:
                for key in sorted(values):
                    handle.write(f"{key}={values[key]}\n")
                handle.flush()
                os.fsync(handle.fileno())
            secure_path(Path(temporary), 0o600)
            os.replace(temporary, PLATFORM_ENV)
            secure_path(PLATFORM_ENV, 0o600)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        source_sha = hashlib.sha256(PLATFORM_ENV.read_bytes()).hexdigest()
    for action in ("render", "audit"):
        subprocess.run(
            [sys.executable, str(CONFIG_RENDERER), action],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    verify_canonical_projection_state()
    return source_sha


def secure_path(path: Path, mode: int) -> None:
    path.chmod(mode)
    if os.geteuid() == 0:
        os.chown(path, 0, 0)


def verify_canonical_permissions() -> None:
    if (
        not PLATFORM_ENV.is_file()
        or PLATFORM_ENV.stat().st_uid != 0
        or PLATFORM_ENV.stat().st_gid != 0
        or PLATFORM_ENV.stat().st_mode & 0o777 != 0o600
    ):
        raise RuntimeError("canonical platform.env is missing or not root:root 0600")


def verify_canonical_projection_state() -> None:
    verify_canonical_permissions()
    source_sha = hashlib.sha256(PLATFORM_ENV.read_bytes()).hexdigest()
    manifest = load_json(PROJECTIONS_MANIFEST, {})
    if (
        manifest.get("sourceSha256") != source_sha
        or manifest.get("generatorVersion") != CONFIG_GENERATOR_VERSION
    ):
        raise RuntimeError(
            "configuration projection manifest source hash mismatch; run config render"
        )


def verify_projection(path: Path) -> None:
    if (
        not PLATFORM_ENV.is_file()
        or PLATFORM_ENV.stat().st_uid != 0
        or PLATFORM_ENV.stat().st_mode & 0o777 != 0o600
    ):
        raise RuntimeError("canonical platform.env is missing or not mode 0600")
    source_sha = hashlib.sha256(PLATFORM_ENV.read_bytes()).hexdigest()
    manifest = load_json(PROJECTIONS_MANIFEST, {})
    if manifest.get("sourceSha256") != source_sha:
        raise RuntimeError(
            "configuration projection manifest source hash mismatch; run config render"
        )
    if manifest.get("generatorVersion") != CONFIG_GENERATOR_VERSION:
        raise RuntimeError(
            "configuration projection generator mismatch; run config render"
        )
    projections = {
        str(row.get("path")): row
        for row in manifest.get("projections", [])
        if isinstance(row, dict)
    }
    row = projections.get(str(path))
    if not row:
        raise RuntimeError(f"unregistered derived projection: {path}")
    if (
        row.get("sourceSha256") != source_sha
        or row.get("generatorVersion") != CONFIG_GENERATOR_VERSION
    ):
        raise RuntimeError(f"stale derived projection metadata: {path}")
    if (
        not path.is_file()
        or path.stat().st_uid != 0
        or path.stat().st_mode & 0o777 != 0o600
        or row.get("contentSha256") != hashlib.sha256(path.read_bytes()).hexdigest()
    ):
        raise RuntimeError(f"manual or stale derived projection detected: {path}")


class Dokploy:
    def __init__(
        self,
        base: str,
        *,
        api_key_only: bool = False,
        session_only: bool = False,
    ):
        if api_key_only and session_only:
            raise RuntimeError("Dokploy client auth mode is ambiguous")
        self.base = base.rstrip("/")
        parsed_base = urllib.parse.urlsplit(self.base)
        if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc:
            raise RuntimeError("Dokploy base URL is invalid")
        self.auth_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
        self.api_key_only = api_key_only
        self.session_only = session_only
        self.api_key = "" if session_only else dotenv(PLATFORM_ENV).get(API_KEY_REF, "")
        if api_key_only and not self.api_key:
            raise RuntimeError(f"missing dedicated Dokploy API ref in {PLATFORM_ENV}")
        self.jar = http.cookiejar.MozillaCookieJar(str(COOKIE_PATH))
        if not api_key_only and COOKIE_PATH.exists():
            try:
                self.jar.load(ignore_discard=True, ignore_expires=True)
            except (OSError, http.cookiejar.LoadError):
                pass
        self.opener = (
            urllib.request.build_opener()
            if api_key_only
            else urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(self.jar)
            )
        )

    def auth_headers(self, *, json_body: bool = False) -> dict[str, str]:
        """Return Better Auth headers without weakening its origin checks."""
        headers = {
            "Accept": "application/json",
            "Origin": self.auth_origin,
        }
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    def request(self, method: str, path: str, body=None, *, retry_login: bool = True):
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["x-api-key"] = self.api_key
        elif not self.api_key_only and method not in {"GET", "HEAD", "OPTIONS"}:
            headers["Origin"] = self.auth_origin
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        request = urllib.request.Request(
            f"{self.base}/{path.lstrip('/')}", data=data, headers=headers, method=method
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            if (
                exc.code in (401, 403)
                and retry_login
                and not self.api_key
                and not self.api_key_only
            ):
                self.login()
                return self.request(method, path, body, retry_login=False)
            detail = exc.read().decode(errors="replace")[:500]
            raise RuntimeError(
                f"Dokploy {method} {path}: HTTP {exc.code}: {detail}"
            ) from exc

    def login(self) -> None:
        admin = dotenv(PLATFORM_ENV)
        email = admin.get("DOKPLOY_ADMIN_EMAIL") or admin.get("EMAIL")
        password = admin.get("DOKPLOY_ADMIN_PASSWORD") or admin.get("PASSWORD")
        if not email or not password:
            raise RuntimeError(f"missing Dokploy admin refs in {PLATFORM_ENV}")
        request = urllib.request.Request(
            self.base + "/auth/sign-in/email",
            data=json.dumps({"email": email, "password": password}).encode(),
            headers=self.auth_headers(json_body=True),
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                response.read()
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Dokploy login failed with HTTP {exc.code}") from exc
        self.jar.save(ignore_discard=True, ignore_expires=True)
        secure_path(COOKIE_PATH, 0o600)

    def auth_request(
        self,
        method: str,
        path: str,
        body=None,
        *,
        query: dict | None = None,
    ):
        if self.api_key_only:
            raise RuntimeError("session auth endpoint is unavailable in API-only mode")
        suffix = path.lstrip("/")
        if query:
            suffix += "?" + urllib.parse.urlencode(query)
        data = None
        headers = self.auth_headers(json_body=body is not None)
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(
            f"{self.base}/auth/{suffix}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"Dokploy auth {method} {path}: HTTP {exc.code}"
            ) from exc

    def session(self) -> dict | None:
        try:
            value = self.auth_request("GET", "get-session")
        except RuntimeError:
            return None
        return value if isinstance(value, dict) and value.get("user") else None

    def bootstrap_owner(self) -> str:
        """Create the first owner only when normal login is not yet possible."""
        if self.session():
            return "existing"
        try:
            self.login()
            return "existing"
        except RuntimeError:
            admin = dotenv(PLATFORM_ENV)
            name = admin.get("DOKPLOY_ADMIN_NAME") or "MTE Platform Admin"
            email = admin.get("DOKPLOY_ADMIN_EMAIL")
            password = admin.get("DOKPLOY_ADMIN_PASSWORD")
            if not email or not password:
                raise RuntimeError(f"missing Dokploy owner refs in {PLATFORM_ENV}")
            request = urllib.request.Request(
                self.base + "/auth/sign-up/email",
                data=json.dumps(
                    {"name": name, "email": email, "password": password}
                ).encode(),
                headers={
                    **self.auth_headers(json_body=True),
                },
                method="POST",
            )
            try:
                with self.opener.open(request, timeout=30) as response:
                    response.read()
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode(errors="replace")[:300]
                raise RuntimeError(
                    "Dokploy owner login failed and first-owner creation was rejected: "
                    f"HTTP {exc.code}: {detail}"
                ) from exc
            self.jar.save(ignore_discard=True, ignore_expires=True)
            secure_path(COOKIE_PATH, 0o600)
            return "created"


def api_key_proof(base_url: str) -> dict:
    verify_canonical_projection_state()
    token = dotenv(PLATFORM_ENV).get(API_KEY_REF, "")
    if not token or not re.fullmatch(r"[^\s]{24,}", token):
        raise RuntimeError("dedicated Dokploy API credential is missing or invalid")
    api = Dokploy(base_url, api_key_only=True)
    projects = api.request("GET", "project.all", retry_login=False)
    if not isinstance(projects, list):
        raise RuntimeError("dedicated Dokploy API key did not list projects")
    return {
        "apiKeyAuthenticated": True,
        "credentialRef": API_KEY_REF,
        "credentialSource": str(PLATFORM_ENV),
        "credentialFingerprintSha256": hashlib.sha256(token.encode()).hexdigest(),
        "projectCount": len(projects),
    }


def ensure_api_key(base_url: str) -> dict:
    existing_token = dotenv(PLATFORM_ENV).get(API_KEY_REF, "")
    if existing_token:
        try:
            return {"action": "existing", **api_key_proof(base_url)}
        except RuntimeError:
            # A revoked or exhausted credential is rotated through the owner
            # session.  Never expose its material or the remote error body.
            pass
    session_api = Dokploy(base_url, session_only=True)
    if not session_api.session():
        session_api.login()
    organizations = session_api.auth_request("GET", "organization/list")
    if not isinstance(organizations, list) or len(organizations) != 1:
        raise RuntimeError("Dokploy API key requires exactly one managed organization")
    organization_id = str(organizations[0].get("id") or "")
    if not organization_id:
        raise RuntimeError("Dokploy managed organization ID is missing")
    listed = session_api.auth_request("GET", "api-key/list", query={"limit": 100})
    rows = listed.get("apiKeys", []) if isinstance(listed, dict) else []
    exact = [row for row in rows if row.get("name") == API_KEY_NAME]
    # Use Dokploy's own protected procedure, not the lower-level Better Auth
    # browser endpoint.  The former is how the v0.29 UI creates operational
    # keys and can explicitly disable Better Auth's 10 requests/day default.
    created = session_api.request(
        "POST",
        "user.createApiKey",
        body={
            "name": API_KEY_NAME,
            "prefix": "mte",
            "metadata": {"organizationId": organization_id},
            "rateLimitEnabled": False,
        },
    )
    raw = created.get("key", "") if isinstance(created, dict) else ""
    if not isinstance(raw, str) or not re.fullmatch(r"[^\s]{24,}", raw):
        raise RuntimeError("Dokploy API key creation returned no recoverable secret")
    created_id = str(created.get("id") or "")
    if not created_id:
        raise RuntimeError("Dokploy API key creation returned no credential ID")
    persist_canonical_api_token(raw)
    proof = api_key_proof(base_url)
    for row in exact:
        key_id = str(row.get("id") or "")
        if key_id and key_id != created_id:
            session_api.request(
                "POST",
                "user.deleteApiKey",
                body={"apiKeyId": key_id},
            )
    return {"action": "rotated" if existing_token else "created", **proof}


def all_dicts(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from all_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from all_dicts(child)


def find_environment(project: dict, name: str) -> dict | None:
    for item in all_dicts(project):
        if item.get("environmentId") and item.get("name") == name:
            return item
    return None


def find_compose(project: dict, *, compose_id: str | None, name: str) -> dict | None:
    for item in all_dicts(project):
        if not item.get("composeId"):
            continue
        if compose_id and item.get("composeId") == compose_id:
            return item
        if item.get("name") == name:
            return item
    return None


def deployment_marker(value) -> str:
    fields: list[tuple[str, str]] = []
    accepted = {
        "deploymentId",
        "composeDeploymentId",
        "revisionId",
        "currentRevisionId",
        "latestRevisionId",
        "deployedAt",
        "updatedAt",
    }
    for item in all_dicts(value):
        for key in sorted(accepted):
            raw = item.get(key)
            if isinstance(raw, (str, int)) and str(raw):
                fields.append((key, str(raw)))
    if not fields:
        return ""
    return hashlib.sha256(
        json.dumps(sorted(set(fields)), separators=(",", ":")).encode()
    ).hexdigest()


def wait_terminal(
    api: Dokploy,
    compose_id: str,
    *,
    baseline_marker: str,
    requested_marker: str,
    timeout: int = 1800,
) -> dict:
    deadline = time.monotonic() + timeout
    last = "unknown"
    last_marker = requested_marker or baseline_marker
    observed_new = bool(requested_marker)
    while time.monotonic() < deadline:
        item = api.request(
            "GET", "compose.one?" + urllib.parse.urlencode({"composeId": compose_id})
        )
        last = item.get("composeStatus", "unknown")
        marker = deployment_marker(item)
        if marker and marker != baseline_marker:
            observed_new = True
            last_marker = marker
        if last == "idle":
            raise RuntimeError(
                f"Dokploy compose {compose_id} became idle before a successful deployment"
            )
        if last == "error":
            raise RuntimeError(f"Dokploy compose {compose_id} deployment failed")
        if last not in {"done", "unknown"}:
            observed_new = True
        if last == "done" and observed_new:
            return {
                "status": "done",
                "deploymentMarker": last_marker or requested_marker,
            }
        time.sleep(5)
    raise RuntimeError(
        f"Dokploy compose {compose_id} did not reach a new done deployment; last={last}"
    )


def wait_declared_health(
    row: dict,
    timeout: int = 300,
    *,
    app_name: str = "",
) -> dict:
    health = row.get("health")
    if not isinstance(health, dict):
        raise RuntimeError(f"component {row.get('id')} has no declared health gate")
    url = str(health.get("url") or "")
    command = str(health.get("command") or "")
    if bool(url) == bool(command):
        raise RuntimeError(
            f"component {row.get('id')} must declare exactly one health gate"
        )
    deadline = time.monotonic() + timeout
    command_env = None
    if command:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", app_name):
            raise RuntimeError(
                f"component {row.get('id')} has no safe Dokploy appName for health"
            )
        command_env = {**os.environ, "DOKPLOY_APP_NAME": app_name}
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        healthy = False
        if url:
            try:
                request = urllib.request.Request(url, headers={"Accept": "*/*"})
                with urllib.request.urlopen(request, timeout=15) as response:
                    healthy = 200 <= response.status < 300
            except (OSError, urllib.error.URLError):
                healthy = False
        else:
            try:
                result = subprocess.run(
                    ["/bin/sh", "-c", command],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=command_env,
                    timeout=30,
                    check=False,
                )
                healthy = result.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                healthy = False
        if healthy:
            return {
                "status": "passed",
                "kind": "url" if url else "command",
                "attempts": attempts,
            }
        time.sleep(3)
    raise RuntimeError(f"declared health gate failed for {row.get('id')}")


def reconcile(selected: list[str], no_wait: bool) -> None:
    if no_wait:
        raise RuntimeError("Dokploy reconcile requires terminal and health-gated waits")
    verify_projection(CONFIG_PATH)
    ensure_agent_plane()
    cfg = load_json(CONFIG_PATH, {})
    spec = cfg["spec"]
    rows = {row["id"]: row for row in spec["components"] if row.get("compose")}
    unknown = sorted(set(selected) - rows.keys())
    if unknown:
        raise RuntimeError("unknown Dokploy component(s): " + ", ".join(unknown))
    api = Dokploy(spec["dokploy"]["baseUrl"], api_key_only=True)
    projects = api.request("GET", "project.all")
    project = next(
        (row for row in projects if row.get("name") == spec["dokploy"]["project"]), None
    )
    if not project:
        project = api.request(
            "POST",
            "project.create",
            {
                "name": spec["dokploy"]["project"],
                "description": "Declarative MTE platform",
            },
        )
    project_id = project["projectId"]
    project = api.request(
        "GET", "project.one?" + urllib.parse.urlencode({"projectId": project_id})
    )
    environment = find_environment(project, spec["dokploy"]["environment"])
    if not environment:
        environment = api.request(
            "POST",
            "environment.create",
            {
                "name": spec["dokploy"]["environment"],
                "projectId": project_id,
                "description": "MTE production",
            },
        )
    environment_id = environment["environmentId"]

    ids = load_json(IDS_PATH, {})
    state = load_json(STATE_PATH, {})
    result = []
    for component_id in selected:
        row = rows[component_id]
        project = api.request(
            "GET", "project.one?" + urllib.parse.urlencode({"projectId": project_id})
        )
        app = find_compose(project, compose_id=ids.get(component_id), name=row["name"])
        if not app:
            app = api.request(
                "POST",
                "compose.create",
                {
                    "name": row["name"],
                    "environmentId": environment_id,
                    "composeType": "docker-compose",
                    "appName": f"mte-{component_id}",
                },
            )
        compose_id = app["composeId"]
        ids[component_id] = compose_id
        save_json(IDS_PATH, ids)

        compose_path = ROOT / row["compose"]
        compose_text = compose_path.read_text()
        env_path = SECRET_ROOT / "services" / f"{component_id}.env"
        verify_projection(compose_path)
        verify_projection(env_path)
        env_text = env_path.read_text() if env_path.exists() else ""
        validation = subprocess.run(
            [
                "docker",
                "compose",
                "--env-file",
                str(env_path),
                "-f",
                str(compose_path),
                "config",
                "--quiet",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        if validation.returncode:
            raise RuntimeError(
                f"compose validation failed for {component_id}: {validation.stderr.strip()[:500]}"
            )
        digest = hashlib.sha256((compose_text + "\0" + env_text).encode()).hexdigest()
        current = api.request(
            "GET", "compose.one?" + urllib.parse.urlencode({"composeId": compose_id})
        )
        if state.get(component_id, {}).get("digest") == digest:
            if current.get("composeStatus") != "done":
                raise RuntimeError(
                    f"unchanged Dokploy component {component_id} is not done"
                )
            health = wait_declared_health(
                row,
                app_name=str(current.get("appName") or ""),
            )
            result.append(
                {
                    "component": component_id,
                    "composeId": compose_id,
                    "action": "unchanged",
                    "status": current.get("composeStatus"),
                    "health": health,
                    "appName": current.get("appName"),
                    "composeType": current.get("composeType"),
                    "sourceType": current.get("sourceType"),
                }
            )
            continue

        api.request(
            "POST",
            "compose.update",
            {"composeId": compose_id, "composeFile": compose_text, "sourceType": "raw"},
        )
        api.request(
            "POST",
            "compose.saveEnvironment",
            {"composeId": compose_id, "env": env_text},
        )
        baseline = api.request(
            "GET", "compose.one?" + urllib.parse.urlencode({"composeId": compose_id})
        )
        deploy_result = api.request(
            "POST",
            "compose.deploy",
            {"composeId": compose_id, "title": "platform reconcile"},
        )
        terminal = wait_terminal(
            api,
            compose_id,
            baseline_marker=deployment_marker(baseline),
            requested_marker=deployment_marker(deploy_result),
        )
        health = wait_declared_health(
            row,
            app_name=str(current.get("appName") or app.get("appName") or ""),
        )
        status = terminal["status"]
        state[component_id] = {
            "digest": digest,
            "composeId": compose_id,
            "status": status,
            "deploymentMarker": terminal["deploymentMarker"],
            "health": health["status"],
            "updatedAt": int(time.time()),
        }
        save_json(STATE_PATH, state)
        current = api.request(
            "GET", "compose.one?" + urllib.parse.urlencode({"composeId": compose_id})
        )
        result.append(
            {
                "component": component_id,
                "composeId": compose_id,
                "action": "deployed",
                "status": status,
                "deploymentMarker": terminal["deploymentMarker"],
                "health": health,
                "appName": current.get("appName"),
                "composeType": current.get("composeType"),
                "sourceType": current.get("sourceType"),
            }
        )
    print(json.dumps(result, indent=2))


def status() -> None:
    cfg = load_json(CONFIG_PATH, {})
    api = Dokploy(cfg["spec"]["dokploy"]["baseUrl"], api_key_only=True)
    ids = load_json(IDS_PATH, {})
    result = []
    for component_id, compose_id in sorted(ids.items()):
        try:
            item = api.request(
                "GET",
                "compose.one?" + urllib.parse.urlencode({"composeId": compose_id}),
            )
            result.append(
                {
                    "component": component_id,
                    "composeId": compose_id,
                    "status": item.get("composeStatus"),
                    "appName": item.get("appName"),
                    "composeType": item.get("composeType"),
                    "sourceType": item.get("sourceType"),
                }
            )
        except RuntimeError as exc:
            result.append(
                {
                    "component": component_id,
                    "composeId": compose_id,
                    "status": "api-error",
                    "error": str(exc),
                }
            )
    print(json.dumps(result, indent=2))


def bootstrap() -> None:
    cfg = load_json(CONFIG_PATH, {})
    base_url = cfg["spec"]["dokploy"]["baseUrl"]
    if dotenv(PLATFORM_ENV).get(API_KEY_REF):
        action = "existing-via-dedicated-api-key"
        credential = ensure_api_key(base_url)
    else:
        api = Dokploy(base_url)
        action = api.bootstrap_owner()
        credential = ensure_api_key(base_url)
    print(
        json.dumps(
            {
                "owner": action,
                "api": "ready",
                "projectCount": credential["projectCount"],
                "dedicatedApiCredential": credential,
            }
        )
    )


def proof() -> None:
    cfg = load_json(CONFIG_PATH, {})
    base_url = cfg["spec"]["dokploy"]["baseUrl"]
    result = api_key_proof(base_url)
    result["resources"] = json.loads(
        subprocess.check_output(
            ["python3", str(Path(__file__)), "status"],
            text=True,
        )
    )
    print(json.dumps(result, indent=2, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest="command", required=True)
    deploy = subs.add_parser("deploy")
    deploy.add_argument("components", nargs="+")
    deploy.add_argument("--no-wait", action="store_true")
    subs.add_parser("status")
    subs.add_parser("bootstrap")
    subs.add_parser("proof")
    args = parser.parse_args()
    if args.command == "deploy":
        reconcile(args.components, args.no_wait)
    elif args.command == "bootstrap":
        bootstrap()
    elif args.command == "proof":
        proof()
    else:
        status()


if __name__ == "__main__":
    main()

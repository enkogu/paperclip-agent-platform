#!/usr/bin/env python3
"""Plan or reconcile the MTE least-privilege Cloudflare account token."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shlex
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import yaml

TOOL_ROOT = Path(__file__).resolve().parent
ROOT = TOOL_ROOT.parents[1]
CONFIG = ROOT / "config" / "platform.yaml"
DEFAULT_OUTPUT = ROOT / ".runtime" / "evidence" / "cloudflare-token-plan.json"
LOCAL_METADATA = ROOT / ".runtime" / "cloudflare" / "platform-api-token.meta.json"
CANONICAL_ENV = Path("/root/.config/mte-secrets/platform.env")
DEFAULT_PLATFORM_ROOT = Path("/opt/mte-platform")
DEFAULT_SECRET_ROOT = CANONICAL_ENV.parent
SHARED_LOCK_NAME = ".platform-env.lock"
TOKEN_NAME = "mte-platform-cloudflare"
REQUIRED_GROUPS = {
    "Cloudflare Tunnel Write": "account",
    "Access: Apps and Policies Write": "account",
    "Access: Service Tokens Write": "account",
    "Zone Read": "zone",
    "DNS Write": "zone",
}


class BootstrapError(RuntimeError):
    """A safe failure that never includes credential values."""


def load_script(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise BootstrapError(f"cannot load helper {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inventory = load_script(
    TOOL_ROOT / "cloudflare-inventory.py", "mte_cf_inventory"
)
preflight = load_script(
    TOOL_ROOT / "cloudflare-preflight.py", "mte_cf_preflight"
)


def read_platform() -> dict[str, Any]:
    value = yaml.safe_load(CONFIG.read_text())
    if not isinstance(value, dict) or not isinstance(value.get("spec"), dict):
        raise BootstrapError("platform configuration must contain a spec object")
    return value


def request_json(
    method: str,
    path: str,
    email: str,
    global_key: str,
    *,
    query: dict[str, str] | None = None,
    body: Any | None = None,
) -> dict[str, Any]:
    url = "https://api.cloudflare.com/client/v4" + path
    if query:
        url += "?" + urlencode(query)
    encoded = json.dumps(body).encode() if body is not None else None
    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": global_key,
        "Accept": "application/json",
        "User-Agent": "mte-cloudflare-token-bootstrap/1",
    }
    if encoded is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=encoded, headers=headers, method=method)
    try:
        with urlopen(request, timeout=30) as response:
            payload = json.loads(response.read())
    except HTTPError as exc:
        try:
            payload = json.loads(exc.read())
        except (json.JSONDecodeError, OSError):
            payload = {}
        codes = sorted(
            str(row.get("code"))
            for row in payload.get("errors", [])
            if isinstance(row, dict) and row.get("code") is not None
        )
        suffix = f" codes={','.join(codes)}" if codes else ""
        raise BootstrapError(
            f"Cloudflare mutation API returned HTTP {exc.code}{suffix}"
        ) from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise BootstrapError(
            f"Cloudflare mutation API failed: {type(exc).__name__}"
        ) from exc
    if not isinstance(payload, dict) or not payload.get("success"):
        raise BootstrapError(
            "Cloudflare mutation API returned an unsuccessful response"
        )
    return payload


def bearer_verified_token_id(account_id: str, token: str) -> str | None:
    """Return the active account-token ID without exposing its value.

    A valid token alone is insufficient: the canonical runtime credential must
    be the managed least-privilege token, not another active token belonging to
    the account.  Cloudflare's verification response includes that token ID.
    """
    request = Request(
        f"https://api.cloudflare.com/client/v4/accounts/{account_id}/tokens/verify",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    for attempt in range(5):
        try:
            with urlopen(request, timeout=20) as response:
                payload = json.loads(response.read())
            result = payload.get("result", {}) if isinstance(payload, dict) else {}
            token_id = result.get("id") if isinstance(result, dict) else None
            if (
                payload.get("success")
                and result.get("status") == "active"
                and isinstance(token_id, str)
                and token_id
            ):
                return token_id
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
            pass
        if attempt < 4:
            time.sleep(1)
    return None


def exact_zone(
    candidate: str,
    configured_account: str,
    zones: list[dict[str, Any]],
) -> dict[str, Any]:
    matches = [
        row
        for row in zones
        if str(row.get("name", "")).lower() == candidate.lower()
        and isinstance(row.get("account"), dict)
        and str(row["account"].get("id", "")) == configured_account
    ]
    if len(matches) != 1 or not matches[0].get("id"):
        raise BootstrapError(
            "canonical base-domain candidate is not one exact active zone in the configured account"
        )
    return matches[0]


def permission_map(rows: list[dict[str, Any]]) -> dict[str, str]:
    by_name = {str(row.get("name", "")): str(row.get("id", "")) for row in rows}
    missing = sorted(name for name in REQUIRED_GROUPS if not by_name.get(name))
    if missing:
        raise BootstrapError(
            "required Cloudflare permission groups are unavailable: "
            + ", ".join(missing)
        )
    return {name: by_name[name] for name in REQUIRED_GROUPS}


def desired_policies(
    account_id: str, zone_id: str, groups: dict[str, str]
) -> list[dict[str, Any]]:
    account_groups = sorted(
        groups[name] for name, scope in REQUIRED_GROUPS.items() if scope == "account"
    )
    zone_groups = sorted(
        groups[name] for name, scope in REQUIRED_GROUPS.items() if scope == "zone"
    )
    return [
        {
            "effect": "allow",
            "permission_groups": [{"id": value} for value in account_groups],
            "resources": {f"com.cloudflare.api.account.{account_id}": "*"},
        },
        {
            "effect": "allow",
            "permission_groups": [{"id": value} for value in zone_groups],
            "resources": {f"com.cloudflare.api.account.zone.{zone_id}": "*"},
        },
    ]


def normalized_policies(policies: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for policy in policies or []:
        if not isinstance(policy, dict):
            continue
        groups = sorted(
            str(row.get("id", ""))
            for row in policy.get("permission_groups", [])
            if isinstance(row, dict) and row.get("id")
        )
        resources = policy.get("resources", {})
        if not isinstance(resources, dict):
            resources = {}
        result.append(
            {
                "effect": str(policy.get("effect", "")),
                "permission_groups": groups,
                "resources": json.loads(json.dumps(resources, sort_keys=True)),
            }
        )
    return sorted(result, key=lambda row: json.dumps(row, sort_keys=True))


def ssh_command(
    target: str, command: str, *, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", target, command],
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BootstrapError(
            f"canonical secret host is unavailable: {type(exc).__name__}"
        ) from exc


def canonical_snapshot(target: str, canonical: Path = CANONICAL_ENV) -> dict[str, Any]:
    script = f"""import hashlib, json
from pathlib import Path
path=Path({str(canonical)!r})
values={{}}
if path.is_file():
    for raw in path.read_text().splitlines():
        line=raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key,value=line.split("=",1); values[key]=value
keys=["PLATFORM_BASE_DOMAIN","CLOUDFLARE_ACCOUNT_ID","CLOUDFLARE_ZONE_ID","CLOUDFLARE_API_TOKEN","CLOUDFLARE_ACCESS_ALLOWED_EMAILS","CLOUDFLARE_ACCESS_IDP_MODE"]
print(json.dumps({{"exists":path.is_file(),"keys":{{key:{{"present":bool(values.get(key)),"sha256":hashlib.sha256(values.get(key,"").encode()).hexdigest() if values.get(key) else None}} for key in keys}}}}))
"""
    result = ssh_command(target, "python3 -", input_text=script)
    if result.returncode != 0:
        raise BootstrapError("cannot inspect canonical platform.env")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise BootstrapError(
            "canonical platform.env inspection returned invalid JSON"
        ) from exc


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def canonical_conflicts(snapshot: dict[str, Any], desired: dict[str, str]) -> list[str]:
    keys = snapshot.get("keys", {})
    conflicts: list[str] = []
    for key, value in desired.items():
        if key == "CLOUDFLARE_API_TOKEN":
            continue
        row = keys.get(key, {}) if isinstance(keys, dict) else {}
        if row.get("present") and row.get("sha256") != hash_value(value):
            conflicts.append(key)
    return sorted(conflicts)


def read_server_token(target: str, canonical: Path = CANONICAL_ENV) -> str:
    script = f"""from pathlib import Path
path=Path({str(canonical)!r})
value=""
if path.is_file():
    for raw in path.read_text().splitlines():
        if raw.startswith("CLOUDFLARE_API_TOKEN="):
            value=raw.split("=",1)[1]; break
print(value, end="")
"""
    result = ssh_command(target, "python3 -", input_text=script)
    if result.returncode != 0:
        raise BootstrapError("cannot read canonical Cloudflare token projection")
    return result.stdout.strip()


def read_canonical_domain(target: str, canonical: Path = CANONICAL_ENV) -> str:
    """Read the sole runtime base-domain key from canonical platform.env."""
    script = f"""import json
from pathlib import Path
path=Path({str(canonical)!r})
values={{}}
if path.is_file():
    for raw in path.read_text().splitlines():
        if raw and not raw.startswith("#") and "=" in raw:
            key,value=raw.split("=",1); values[key]=value
print(json.dumps({{"domain":values.get("PLATFORM_BASE_DOMAIN","").strip()}}))
"""
    result = ssh_command(target, "python3 -", input_text=script)
    if result.returncode != 0:
        raise BootstrapError("cannot read canonical platform base domain")
    try:
        payload = json.loads(result.stdout)
        domain = str(payload.get("domain", "")).strip()
    except (json.JSONDecodeError, AttributeError) as exc:
        raise BootstrapError(
            "canonical platform base-domain inspection returned invalid JSON"
        ) from exc
    if not domain:
        raise BootstrapError("canonical platform.env is missing PLATFORM_BASE_DOMAIN")
    return domain


def canonical_reconcile_script(platform_root: Path, secret_root: Path) -> str:
    """Build the secret-safe remote writer used under the shared config lock."""
    return """import fcntl, hashlib, importlib.util, json, os, re, stat, sys, tempfile
from pathlib import Path
platform_root=Path(%r)
secret_root=Path(%r)
canonical=secret_root/"platform.env"
lock=secret_root/".platform-env.lock"
manifest_path=secret_root/"projections-manifest.json"
config_script=platform_root/"bin/server-config.py"
incoming=json.loads(sys.stdin.read())
if not isinstance(incoming,dict) or not incoming:
    raise SystemExit("invalid canonical update")
if any(not re.fullmatch(r"[A-Z][A-Z0-9_]*",str(key)) for key in incoming):
    raise SystemExit("invalid canonical update key")
if any(not isinstance(value,str) or "\\n" in value or "\\r" in value for value in incoming.values()):
    raise SystemExit("invalid canonical update value")
secret_root.mkdir(parents=True,exist_ok=True,mode=0o700)
os.chmod(secret_root,0o700)
os.chown(secret_root,0,0)
descriptor=os.open(lock,os.O_CREAT|os.O_RDWR,0o600)
try:
    os.fchmod(descriptor,0o600)
    os.fchown(descriptor,0,0)
    fcntl.flock(descriptor,fcntl.LOCK_EX)
    current={}
    if canonical.is_file():
        info=canonical.stat()
        if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:
            raise SystemExit("unsafe canonical source")
        for raw in canonical.read_text().splitlines():
            if not raw or raw.startswith("#"):
                continue
            if "=" not in raw:
                raise SystemExit("invalid canonical source")
            key,value=raw.split("=",1)
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*",key):
                raise SystemExit("invalid canonical source key")
            current[key]=value
    current.update(incoming)
    fd,temporary=tempfile.mkstemp(prefix="platform.env.",dir=secret_root)
    try:
        with os.fdopen(fd,"w") as handle:
            for key in sorted(current):
                handle.write(key+"="+current[key]+"\\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary,0o600)
        os.replace(temporary,canonical)
        os.chmod(canonical,0o600)
        os.chown(canonical,0,0)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    digest=hashlib.sha256(canonical.read_bytes()).hexdigest()
    if not config_script.is_file() or config_script.is_symlink():
        raise SystemExit("server config producer missing")
    os.environ["MTE_PLATFORM_ROOT"]=str(platform_root)
    os.environ["MTE_SECRET_ROOT"]=str(secret_root)
    spec=importlib.util.spec_from_file_location("mte_server_config_locked",config_script)
    if spec is None or spec.loader is None:
        raise SystemExit("server config producer invalid")
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.render(lock_fd=descriptor)
    audited=module.audit()
    if audited.get("ok") is not True or audited.get("sourceSha256")!=digest:
        raise SystemExit("server config render audit failed")
    manifest=json.loads(manifest_path.read_text())
    rows=manifest.get("projections")
    if (manifest.get("sourceSha256")!=digest
        or manifest.get("generatorVersion")!=module.GENERATOR_VERSION
        or not isinstance(rows,list) or not rows):
        raise SystemExit("projection manifest source gate failed")
    for row in rows:
        path=Path(str(row.get("path") or "")) if isinstance(row,dict) else Path("")
        if (not path.is_file() or path.is_symlink()
            or row.get("sourceSha256")!=digest
            or row.get("generatorVersion")!=module.GENERATOR_VERSION
            or row.get("contentSha256")!=hashlib.sha256(path.read_bytes()).hexdigest()):
            raise SystemExit("projection manifest content gate failed")
        info=path.stat()
        if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:
            raise SystemExit("projection permissions gate failed")
    print(json.dumps({
        "canonicalSourceSha256":digest,
        "manifestSha256":hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "projectionCount":len(rows),
        "generatorVersion":module.GENERATOR_VERSION,
        "renderAuditVerified":True,
        "sharedLockPath":str(lock),
        "serverConfigSha256":hashlib.sha256(config_script.read_bytes()).hexdigest(),
    },sort_keys=True))
finally:
    fcntl.flock(descriptor,fcntl.LOCK_UN)
    os.close(descriptor)
""" % (str(platform_root), str(secret_root))


def validate_canonical_update_evidence(
    payload: Any, *, secret_root: Path
) -> dict[str, Any]:
    expected_lock = str(secret_root / SHARED_LOCK_NAME)
    hash_fields = ("canonicalSourceSha256", "manifestSha256", "serverConfigSha256")
    if not (
        isinstance(payload, dict)
        and all(
            isinstance(payload.get(key), str)
            and len(payload[key]) == 64
            and all(char in "0123456789abcdef" for char in payload[key])
            for key in hash_fields
        )
        and isinstance(payload.get("projectionCount"), int)
        and not isinstance(payload.get("projectionCount"), bool)
        and payload["projectionCount"] > 0
        and isinstance(payload.get("generatorVersion"), str)
        and bool(payload["generatorVersion"])
        and payload.get("renderAuditVerified") is True
        and payload.get("sharedLockPath") == expected_lock
    ):
        raise BootstrapError("canonical platform.env update evidence is invalid")
    return payload


def write_canonical(
    target: str,
    values: dict[str, str],
    *,
    platform_root: Path = DEFAULT_PLATFORM_ROOT,
    secret_root: Path = DEFAULT_SECRET_ROOT,
) -> dict[str, Any]:
    script = canonical_reconcile_script(platform_root, secret_root)
    command = "python3 -c " + shlex.quote(script)
    result = ssh_command(target, command, input_text=json.dumps(values))
    if result.returncode != 0:
        raise BootstrapError("locked canonical render and audit failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise BootstrapError(
            "canonical platform.env update returned invalid evidence"
        ) from exc
    return validate_canonical_update_evidence(payload, secret_root=secret_root)


def atomic_local_metadata(
    canonical_evidence: dict[str, Any], canonical: Path = CANONICAL_ENV
) -> None:
    """Persist only non-secret source/manifest fingerprints on the operator host."""
    path = LOCAL_METADATA
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    content = (
        json.dumps(
            {
                "kind": "CanonicalSecretProjectionMetadata",
                "canonical": str(canonical),
                "canonicalSourceSha256": canonical_evidence["canonicalSourceSha256"],
                "manifestSha256": canonical_evidence["manifestSha256"],
                "serverConfigSha256": canonical_evidence["serverConfigSha256"],
                "projectionCount": canonical_evidence["projectionCount"],
                "generatorVersion": canonical_evidence["generatorVersion"],
                "renderAuditVerified": True,
                "containsSecretValue": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_evidence(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def extract_token_value(payload: dict[str, Any]) -> str:
    result = payload.get("result")
    if isinstance(result, str):
        value = result
    elif isinstance(result, dict):
        raw = result.get("value", "")
        value = str(raw.get("value", "")) if isinstance(raw, dict) else str(raw)
    else:
        value = ""
    if len(value) < 40 or "\n" in value or "\r" in value:
        raise BootstrapError("Cloudflare did not return a valid token value")
    return value


def build_context(env_file: Path) -> dict[str, Any]:
    environment = inventory.read_env(env_file)
    email = environment.get("CLOUDFLARE_EMAIL", "").strip()
    global_key = environment.get("CLOUDFLARE_GLOBAL_API_KEY", "").strip()
    account_id = environment.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
    if not email or not global_key or not account_id:
        raise BootstrapError("Cloudflare bootstrap references are incomplete")

    platform = read_platform()
    host = platform["spec"].get("host", {})
    if not isinstance(host, dict):
        raise BootstrapError("canonical secret host is invalid")

    def host_value(field: str, ref_field: str, fallback: str = "") -> str:
        literal = str(host.get(field, "")).strip()
        reference = str(host.get(ref_field, "")).strip()
        return literal or str(environment.get(reference, "")).strip() or fallback

    target = host_value("ssh", "sshRef")
    platform_root = Path(host_value("root", "rootRef", str(DEFAULT_PLATFORM_ROOT)))
    secret_root = Path(
        host_value("secretsRoot", "secretsRootRef", str(DEFAULT_SECRET_ROOT))
    )
    if not target or not platform_root.is_absolute() or not secret_root.is_absolute():
        raise BootstrapError("canonical secret host is missing")
    canonical_path = secret_root / "platform.env"
    candidate = read_canonical_domain(target, canonical_path)
    if not inventory.valid_hostname(candidate):
        raise BootstrapError("Cloudflare base-domain candidate is invalid")

    zones, zones_check = inventory.paginated(
        "/zones", email, global_key, {"status": "active"}
    )
    if not zones_check.get("ready"):
        raise BootstrapError("active Cloudflare zone inventory is unavailable")
    zone = exact_zone(candidate, account_id, zones)
    zone_id = str(zone["id"])

    groups, groups_check = inventory.single_page(
        f"/accounts/{account_id}/tokens/permission_groups", email, global_key
    )
    if not groups_check.get("ready"):
        raise BootstrapError("account token permission groups are unavailable")
    group_ids = permission_map(groups)
    policies = desired_policies(account_id, zone_id, group_ids)

    tokens, tokens_check = inventory.paginated(
        f"/accounts/{account_id}/tokens", email, global_key
    )
    if not tokens_check.get("ready"):
        raise BootstrapError("account token inventory is unavailable")
    matches = [row for row in tokens if str(row.get("name", "")) == TOKEN_NAME]
    if len(matches) > 1:
        raise BootstrapError(
            "multiple managed Cloudflare tokens have the canonical name"
        )
    token = matches[0] if matches else None
    if token and token.get("id"):
        success, _, detail = inventory.api_get(
            f"/accounts/{account_id}/tokens/{token['id']}", email, global_key
        )
        if not success or not isinstance(detail.get("result"), dict):
            raise BootstrapError("managed Cloudflare token details are unavailable")
        token = detail["result"]

    idps, idps_check = inventory.single_page(
        f"/accounts/{account_id}/access/identity_providers",
        email,
        global_key,
        {"per_page": "50"},
    )
    if not idps_check.get("ready"):
        raise BootstrapError(
            "Cloudflare Access identity-provider inventory is unavailable"
        )
    external_idps = [row for row in idps if str(row.get("type", "")) != "onetimepin"]
    idp_mode = "external" if external_idps else "onetimepin"

    origins, origin_blockers = preflight.internal_checks(platform["spec"])
    snapshot = canonical_snapshot(target, canonical_path)
    desired_canonical = {
        "PLATFORM_BASE_DOMAIN": candidate.lower().rstrip("."),
        "CLOUDFLARE_ACCOUNT_ID": account_id,
        "CLOUDFLARE_ZONE_ID": zone_id,
        "CLOUDFLARE_ACCESS_ALLOWED_EMAILS": email.lower(),
        "CLOUDFLARE_ACCESS_IDP_MODE": idp_mode,
    }
    conflicts = canonical_conflicts(snapshot, desired_canonical)
    return {
        "email": email,
        "globalKey": global_key,
        "accountId": account_id,
        "zoneId": zone_id,
        "zoneName": candidate.lower().rstrip("."),
        "target": target,
        "platformRoot": platform_root,
        "secretRoot": secret_root,
        "canonicalPath": canonical_path,
        "policies": policies,
        "token": token,
        "origins": origins,
        "originBlockers": origin_blockers,
        "snapshot": snapshot,
        "canonicalDesired": desired_canonical,
        "canonicalConflicts": conflicts,
        "idpMode": idp_mode,
    }


def safe_plan(context: dict[str, Any], action: str) -> dict[str, Any]:
    token = context["token"]
    token_exists = bool(token)
    policy_exact = bool(
        token
        and normalized_policies(token.get("policies"))
        == normalized_policies(context["policies"])
        and token.get("status") == "active"
    )
    snapshot_keys = context["snapshot"].get("keys", {})
    server_present = bool(snapshot_keys.get("CLOUDFLARE_API_TOKEN", {}).get("present"))
    planned: list[str] = []
    if not token_exists:
        planned.append("create_account_owned_token")
    elif not policy_exact:
        planned.append("reconcile_exact_token_policies")
    if token_exists and not server_present:
        planned.append("roll_unrecoverable_token_value")
    planned.extend(
        [
            "locked_atomic_upsert_canonical_platform_env",
            "render_audit_verify_manifest_under_shared_lock",
            "write_nonsecret_local_metadata",
        ]
    )
    origins_green = not context["originBlockers"]
    # Origin health belongs to the later edge/app preflight. Token bootstrap
    # must be able to establish the credential needed to render and start
    # those origins on a clean host, while retaining the observation in its
    # evidence for operators.
    ready = not context["canonicalConflicts"]
    return {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "CloudflareTokenBootstrap",
        "action": action,
        "readyForApply": ready,
        "mutationPerformed": False,
        "baseDomain": context["zoneName"],
        "origins": {
            "green": origins_green,
            "blockers": context["originBlockers"],
        },
        "token": {
            "canonicalName": TOKEN_NAME,
            "exists": token_exists,
            "policyExact": policy_exact,
            "localSecretProjectionPresent": False,
            "canonicalServerValuePresent": server_present,
            "requiredPermissions": sorted(REQUIRED_GROUPS),
        },
        "canonical": {
            "path": str(context.get("canonicalPath", CANONICAL_ENV)),
            "sharedLockPath": str(
                Path(context.get("secretRoot", DEFAULT_SECRET_ROOT)) / SHARED_LOCK_NAME
            ),
            "conflictingKeys": context["canonicalConflicts"],
            "upsertKeys": sorted(
                [*context["canonicalDesired"], "CLOUDFLARE_API_TOKEN"]
            ),
            "accessIdpMode": context["idpMode"],
            "allowedEmailSeededFromOperator": True,
        },
        "plannedActions": planned,
    }


def reconcile(context: dict[str, Any]) -> dict[str, Any]:
    plan = safe_plan(context, "apply")
    if context["canonicalConflicts"]:
        plan["blockers"] = [
            {"code": "canonical_config_conflict", "keys": context["canonicalConflicts"]}
        ]
        return plan

    account_id = context["accountId"]
    email = context["email"]
    global_key = context["globalKey"]
    token_row = context["token"]
    actions: list[str] = []
    token_value = ""

    if token_row is None:
        created = request_json(
            "POST",
            f"/accounts/{account_id}/tokens",
            email,
            global_key,
            body={"name": TOKEN_NAME, "policies": context["policies"]},
        )
        token_row = created.get("result", {})
        token_value = extract_token_value(created)
        actions.append("created_account_owned_token")
    else:
        token_id = str(token_row.get("id", ""))
        if not token_id:
            raise BootstrapError("managed token identifier is unavailable")
        policy_exact = (
            normalized_policies(token_row.get("policies"))
            == normalized_policies(context["policies"])
            and token_row.get("status") == "active"
        )
        if not policy_exact:
            request_json(
                "PUT",
                f"/accounts/{account_id}/tokens/{token_id}",
                email,
                global_key,
                body={
                    "name": TOKEN_NAME,
                    "policies": context["policies"],
                    "status": "active",
                },
            )
            actions.append("reconciled_exact_token_policies")
        candidate = read_server_token(
            context["target"],
            Path(context.get("canonicalPath", CANONICAL_ENV)),
        )
        if candidate and bearer_verified_token_id(account_id, candidate) == token_id:
            token_value = candidate
        if not token_value:
            rolled = request_json(
                "PUT",
                f"/accounts/{account_id}/tokens/{token_id}/value",
                email,
                global_key,
                body={},
            )
            token_value = extract_token_value(rolled)
            actions.append("rolled_unrecoverable_token_value")

    if bearer_verified_token_id(account_id, token_value) != str(token_row.get("id", "")):
        raise BootstrapError(
            "reconciled Cloudflare token does not match the managed token"
        )
    canonical_values = dict(context["canonicalDesired"])
    canonical_values["CLOUDFLARE_API_TOKEN"] = token_value
    canonical_evidence = write_canonical(
        context["target"],
        canonical_values,
        platform_root=Path(context.get("platformRoot", DEFAULT_PLATFORM_ROOT)),
        secret_root=Path(context.get("secretRoot", DEFAULT_SECRET_ROOT)),
    )
    atomic_local_metadata(
        canonical_evidence,
        Path(context.get("canonicalPath", CANONICAL_ENV)),
    )
    actions.extend(
        [
            "updated_canonical_platform_env_under_shared_lock",
            "rendered_audited_and_verified_projection_manifest",
            "wrote_nonsecret_local_metadata",
        ]
    )

    plan["readyForApply"] = True
    plan["mutationPerformed"] = True
    plan["performedActions"] = actions
    plan["canonical"]["sourceHashRecorded"] = True
    plan["canonical"]["sourceSha256"] = canonical_evidence["canonicalSourceSha256"]
    plan["canonical"]["manifestSha256"] = canonical_evidence["manifestSha256"]
    plan["canonical"]["serverConfigSha256"] = canonical_evidence["serverConfigSha256"]
    plan["canonical"]["projectionCount"] = canonical_evidence["projectionCount"]
    plan["canonical"]["generatorVersion"] = canonical_evidence["generatorVersion"]
    plan["canonical"]["renderAuditVerified"] = True
    plan["token"]["localSecretProjectionPresent"] = False
    plan["token"]["canonicalServerValuePresent"] = True
    plan.pop("plannedActions", None)
    return plan


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["plan", "status", "apply"])
    parser.add_argument(
        "--env-file",
        type=Path,
        required=True,
        help="explicit operator bootstrap environment file",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    context = build_context(args.env_file.expanduser())
    result = (
        reconcile(context)
        if args.action == "apply"
        else safe_plan(context, args.action)
    )
    write_evidence(args.output.expanduser().resolve(), result)
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.action == "apply" and not result.get("mutationPerformed"):
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BootstrapError as exc:
        print(
            json.dumps(
                {
                    "apiVersion": "micro-task-engine/v1alpha1",
                    "kind": "CloudflareTokenBootstrap",
                    "readyForApply": False,
                    "mutationPerformed": False,
                    "blockers": [
                        {"code": "bootstrap_error", "errorType": type(exc).__name__}
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
        raise SystemExit(3)

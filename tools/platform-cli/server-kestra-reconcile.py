#!/usr/bin/env python3
"""Declaratively reconcile and attest the Kestra C039 control-plane contract.

The producer owns only Kestra flow/KV resources. It never writes canonical
configuration and never persists the Basic Auth secret used for live API calls.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

import yaml


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from profile_catalog import (  # noqa: E402
    CatalogError,
    default_catalog_path,
    load_profile_catalog,
    semantic_sha256,
)


ROOT = Path(os.environ.get("MTE_PLATFORM_ROOT", "/opt/mte-platform"))
SECRET_ROOT = Path(os.environ.get("MTE_SECRET_ROOT", "/root/.config/mte-secrets"))
CANONICAL_ENV = SECRET_ROOT / "platform.env"
PLATFORM_LOCK = ROOT / "templates/platform.lock.yaml"
PROVISION_EVIDENCE = ROOT / "evidence/kestra-reconcile.json"
VERIFY_EVIDENCE = ROOT / "evidence/kestra-reconcile-verify.json"

API_VERSION = "micro-task-engine/v1alpha1"
EVIDENCE_KIND = "KestraReconcileEvidence"
YAML_MEDIA_TYPE = "application/x-yaml"
KV_MEDIA_TYPE = "text/plain"
CONTROL_NAMESPACE = "mte.platform"
PROFILE_CATALOG_KEY = "mte.profile.catalog"
FLOW_CATALOG_KEY = "mte.flow.catalog"
EXPECTED_PROFILE_REFS = load_profile_catalog(
    default_catalog_path(runtime_first=False)
).refs
EXPECTED_FLOW_FILES = (
    "control-plane.yaml",
    "paperclip-runtime.yaml",
    "platform-canary.yaml",
    "paperclip-github-e2e.yaml",
)
SECRET_KEY = re.compile(
    r"(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|PRIVATE_KEY|CREDENTIAL|AUTH)",
    re.IGNORECASE,
)
NON_SECRET_LITERALS = frozenset(
    {"true", "false", "none", "null", "enabled", "disabled", "required"}
)
UNEXPANDED = re.compile(r"\$\{[^}]+\}")


class ReconcileError(RuntimeError):
    pass


def utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_json_sha256(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode())


def profile_catalog_semantic_sha256(document: dict[str, Any]) -> str:
    return semantic_sha256(document)


def dotenv(path: Path | None = None) -> dict[str, str]:
    path = CANONICAL_ENV if path is None else path
    if not path.is_file():
        raise ReconcileError("canonical_env_missing")
    values: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ReconcileError(f"canonical_env_invalid_line:{line_number}")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in values:
            raise ReconcileError(f"canonical_env_invalid_key:{line_number}")
        values[key] = value
    return values


def producer_path() -> Path:
    return Path(__file__).resolve()


def platform_contract() -> dict[str, str]:
    if not PLATFORM_LOCK.is_file():
        raise ReconcileError("platform_lock_missing")
    payload = yaml.safe_load(PLATFORM_LOCK.read_text())
    if not isinstance(payload, dict):
        raise ReconcileError("platform_lock_invalid")
    if (
        payload.get("apiVersion") != API_VERSION
        or payload.get("kind") != "PlatformLock"
    ):
        raise ReconcileError("platform_lock_contract_invalid")
    version = payload.get("spec", {}).get("kestra")
    if not isinstance(version, str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+", version
    ):
        raise ReconcileError("kestra_version_lock_missing")
    return {"version": version, "sha256": sha256_path(PLATFORM_LOCK)}


def flow_directory() -> Path:
    candidates = (
        ROOT / "workflows/kestra",
        ROOT / "manifests/kestra/flows",
    )
    return next((path for path in candidates if path.is_dir()), candidates[0])


def profile_source_paths() -> tuple[Path, Path]:
    source_candidates = (
        ROOT / "config/profiles/catalog.yaml",
        ROOT / "templates/profiles/profiles.yaml",
    )
    source = next(
        (path for path in source_candidates if path.is_file()), source_candidates[0]
    )
    runtime = ROOT / "runtime/profiles/profiles.yaml"
    return source, runtime


def read_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ReconcileError(f"required_source_missing:{path}")
    try:
        value = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise ReconcileError(f"source_invalid:{path}") from exc
    if not isinstance(value, dict):
        raise ReconcileError(f"source_not_object:{path}")
    return value


def load_flows() -> list[dict[str, Any]]:
    directory = flow_directory()
    if not directory.is_dir():
        raise ReconcileError("kestra_flow_directory_missing")
    actual = sorted(path.name for path in directory.glob("*.yaml"))
    if actual != sorted(EXPECTED_FLOW_FILES):
        raise ReconcileError("kestra_flow_source_set_mismatch")
    flows: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    for filename in EXPECTED_FLOW_FILES:
        path = directory / filename
        source = path.read_text()
        try:
            parsed = yaml.safe_load(source)
        except yaml.YAMLError as exc:
            raise ReconcileError(f"kestra_flow_source_invalid:{filename}") from exc
        if not isinstance(parsed, dict):
            raise ReconcileError(f"kestra_flow_source_invalid:{filename}")
        flow_id = parsed.get("id")
        namespace = parsed.get("namespace")
        if not isinstance(flow_id, str) or not isinstance(namespace, str):
            raise ReconcileError(f"kestra_flow_identity_missing:{filename}")
        identity = (namespace, flow_id)
        if identity in identities:
            raise ReconcileError("kestra_flow_identity_duplicate")
        identities.add(identity)
        flows.append(
            {
                "id": flow_id,
                "namespace": namespace,
                "sourceRef": f"workflows/kestra/{filename}",
                "sourcePath": path,
                "source": source,
                "sourceSha256": sha256_bytes(source.encode()),
            }
        )
    return flows


def _profile_summary(row: dict[str, Any]) -> dict[str, Any]:
    llm = row.get("llmRouting") if isinstance(row.get("llmRouting"), dict) else {}
    tools = row.get("toolRouting") if isinstance(row.get("toolRouting"), dict) else {}
    access = row.get("toolAccess") if isinstance(row.get("toolAccess"), dict) else {}
    runtime = (
        row.get("runtimeContract")
        if isinstance(row.get("runtimeContract"), dict)
        else {}
    )
    summary = {
        "profileRef": row.get("ref"),
        "harnessKind": runtime.get("harnessKind"),
        "nativeAdapter": runtime.get("adapterType"),
        "protocol": runtime.get("protocol"),
        "defaultEnvironment": row.get("defaultEnvironment"),
        "llmProvider": llm.get("provider"),
        "llmApiKeyRef": llm.get("apiKeyRef"),
        "toolProvider": tools.get("provider"),
        "toolEndpointRef": tools.get("mcpUrlRef"),
        "toolCredentialRef": tools.get("bearerTokenRef"),
        "bundleId": access.get("bundleId"),
        "workloadId": access.get("workloadId"),
    }
    if any(not isinstance(value, str) or not value for value in summary.values()):
        raise ReconcileError(f"profile_contract_incomplete:{row.get('ref')}")
    if UNEXPANDED.search(canonical_json(summary)):
        raise ReconcileError(f"profile_runtime_not_rendered:{row.get('ref')}")
    return summary


def load_profile_contract() -> dict[str, Any]:
    source_path, runtime_path = profile_source_paths()
    try:
        source = load_profile_catalog(source_path)
        runtime = load_profile_catalog(runtime_path, require_rendered=True)
    except CatalogError as exc:
        raise ReconcileError(str(exc)) from exc
    if source.refs != runtime.refs:
        raise ReconcileError("profile_catalog_source_runtime_set_mismatch")
    summaries = [_profile_summary(row) for row in runtime.profiles]
    spec = {
        "apiVersion": API_VERSION,
        "kind": "KestraProfileCatalogBinding",
        "namespace": CONTROL_NAMESPACE,
        "key": PROFILE_CATALOG_KEY,
        "profileSourceSha256": sha256_path(source_path),
        "profileRuntimeSha256": runtime.semantic_sha256,
        "profiles": summaries,
    }
    spec["specSha256"] = canonical_json_sha256(spec)
    return {
        "sourcePath": source_path,
        "runtimePath": runtime_path,
        "refs": runtime.refs,
        "value": spec,
    }


def _required_value(values: dict[str, str], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value:
        raise ReconcileError(f"canonical_env_ref_missing:{key}")
    return value


def basic_auth(values: dict[str, str]) -> tuple[str, dict[str, str], int]:
    username = _required_value(values, "KESTRA_ADMIN_USER")
    password = _required_value(values, "KESTRA_ADMIN_PASSWORD")
    host = _required_value(values, "KESTRA_LOOPBACK_HOST")
    port = _required_value(values, "KESTRA_ORIGIN_PORT")
    timeout = _required_value(values, "KESTRA_RECONCILE_HTTP_TIMEOUT_SECONDS")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ReconcileError("kestra_origin_not_loopback")
    if not port.isdigit() or not 1024 <= int(port) <= 65535:
        raise ReconcileError("kestra_origin_port_invalid")
    if not timeout.isdigit() or not 1 <= int(timeout) <= 300:
        raise ReconcileError("kestra_reconcile_http_timeout_invalid")
    credential = base64.b64encode(f"{username}:{password}".encode()).decode()
    url_host = f"[{host}]" if host == "::1" else host
    return (
        f"http://{url_host}:{port}",
        {"Authorization": f"Basic {credential}"},
        int(timeout),
    )


def request(
    base: str,
    headers: dict[str, str],
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    content_type: str | None = None,
    allow_status: set[int] | None = None,
    timeout_seconds: int,
) -> tuple[int, Any]:
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or not 1 <= timeout_seconds <= 300
    ):
        raise ReconcileError("kestra_reconcile_http_timeout_invalid")
    request_headers = {"Accept": "application/json", **headers}
    if content_type:
        request_headers["Content-Type"] = content_type
    req = urllib.request.Request(
        base + path, data=body, method=method, headers=request_headers
    )
    try:
        response = urllib.request.urlopen(req, timeout=timeout_seconds)
        with response:
            status_code = response.status
            raw = response.read(8_000_000)
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        raw = exc.read(8_000_000)
        if allow_status is None or status_code not in allow_status:
            raise ReconcileError(f"kestra_http_status:{method}:{status_code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ReconcileError(f"kestra_unavailable:{method}") from exc
    if allow_status is None and not 200 <= status_code < 300:
        raise ReconcileError(f"kestra_http_status:{method}:{status_code}")
    if allow_status is not None and status_code not in allow_status:
        raise ReconcileError(f"kestra_http_status:{method}:{status_code}")
    if not raw:
        return status_code, None
    try:
        return status_code, json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReconcileError(f"kestra_response_not_json:{method}") from exc


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _flow_snapshot(document: Any, desired: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ReconcileError("kestra_flow_response_invalid")
    source = document.get("source")
    revision = document.get("revision")
    updated = document.get("updated")
    if (
        document.get("id") != desired["id"]
        or document.get("namespace") != desired["namespace"]
        or not isinstance(revision, int)
        or isinstance(revision, bool)
        or revision < 1
        or not _valid_timestamp(updated)
        or not isinstance(source, str)
        or sha256_bytes(source.encode()) != desired["sourceSha256"]
        or document.get("deleted") is True
        or document.get("draft") is True
    ):
        raise ReconcileError(
            f"kestra_flow_observed_drift:{desired['namespace']}/{desired['id']}"
        )
    return {
        "id": desired["id"],
        "namespace": desired["namespace"],
        "sourceRef": desired["sourceRef"],
        "sourceSha256": desired["sourceSha256"],
        "revision": revision,
        "updated": updated,
    }


def reconcile_flow(
    base: str,
    headers: dict[str, str],
    desired: dict[str, Any],
    *,
    mutate: bool,
    timeout_seconds: int,
) -> tuple[dict[str, Any], dict[str, str] | None]:
    namespace = urllib.parse.quote(desired["namespace"], safe="")
    flow_id = urllib.parse.quote(desired["id"], safe="")
    flow_path = f"/api/v1/main/flows/{namespace}/{flow_id}"
    status_code, current = request(
        base,
        headers,
        "GET",
        flow_path + "?source=true",
        allow_status={200, 404},
        timeout_seconds=timeout_seconds,
    )
    current_matches = False
    if status_code == 200 and isinstance(current, dict):
        current_matches = (
            current.get("id") == desired["id"]
            and current.get("namespace") == desired["namespace"]
            and isinstance(current.get("source"), str)
            and sha256_bytes(current["source"].encode()) == desired["sourceSha256"]
            and current.get("deleted") is not True
            and current.get("draft") is not True
        )
    mutation: dict[str, str] | None = None
    if not current_matches:
        if not mutate:
            raise ReconcileError(
                f"kestra_flow_requires_reconcile:{desired['namespace']}/{desired['id']}"
            )
        method = "POST" if status_code == 404 else "PUT"
        path = "/api/v1/main/flows" if method == "POST" else flow_path
        request(
            base,
            headers,
            method,
            path,
            body=desired["source"].encode(),
            content_type=YAML_MEDIA_TYPE,
            timeout_seconds=timeout_seconds,
        )
        mutation = {
            "resource": "flow",
            "action": "created" if method == "POST" else "updated",
            "ref": f"{desired['namespace']}/{desired['id']}",
        }
    _status, observed = request(
        base,
        headers,
        "GET",
        flow_path + "?source=true",
        allow_status={200},
        timeout_seconds=timeout_seconds,
    )
    return _flow_snapshot(observed, desired), mutation


def _kv_snapshot(document: Any, key: str, expected: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ReconcileError(f"kestra_kv_response_invalid:{key}")
    value = document.get("value")
    revision = document.get("revision")
    updated = document.get("updated")
    if (
        document.get("type") != "JSON"
        or value != expected
        or not isinstance(revision, int)
        or isinstance(revision, bool)
        or revision < 1
        or not _valid_timestamp(updated)
    ):
        raise ReconcileError(f"kestra_kv_observed_drift:{key}")
    return {
        "namespace": CONTROL_NAMESPACE,
        "key": key,
        "type": "JSON",
        "valueSha256": canonical_json_sha256(value),
        "revision": revision,
        "updated": updated,
    }


def reconcile_kv(
    base: str,
    headers: dict[str, str],
    key: str,
    expected: dict[str, Any],
    *,
    mutate: bool,
    timeout_seconds: int,
) -> tuple[dict[str, Any], dict[str, str] | None]:
    namespace = urllib.parse.quote(CONTROL_NAMESPACE, safe="")
    encoded_key = urllib.parse.quote(key, safe="")
    path = f"/api/v1/main/namespaces/{namespace}/kv/{encoded_key}"
    status_code, current = request(
        base,
        headers,
        "GET",
        path,
        allow_status={200, 404},
        timeout_seconds=timeout_seconds,
    )
    current_matches = (
        status_code == 200
        and isinstance(current, dict)
        and current.get("type") == "JSON"
        and current.get("value") == expected
    )
    mutation: dict[str, str] | None = None
    if not current_matches:
        if not mutate:
            raise ReconcileError(f"kestra_kv_requires_reconcile:{key}")
        request(
            base,
            headers,
            "PUT",
            path,
            body=canonical_json(expected).encode(),
            content_type=KV_MEDIA_TYPE,
            allow_status={200, 204},
            timeout_seconds=timeout_seconds,
        )
        mutation = {
            "resource": "kv",
            "action": "created" if status_code == 404 else "updated",
            "ref": f"{CONTROL_NAMESPACE}/{key}",
        }
    _status, observed = request(
        base,
        headers,
        "GET",
        path,
        allow_status={200},
        timeout_seconds=timeout_seconds,
    )
    return _kv_snapshot(observed, key, expected), mutation


def flow_catalog_value(observed_flows: list[dict[str, Any]]) -> dict[str, Any]:
    value = {
        "apiVersion": API_VERSION,
        "kind": "KestraManagedFlowCatalog",
        "namespace": CONTROL_NAMESPACE,
        "key": FLOW_CATALOG_KEY,
        "flows": observed_flows,
    }
    value["specSha256"] = canonical_json_sha256(value)
    return value


def reconcile_pass(
    base: str,
    headers: dict[str, str],
    flows: list[dict[str, Any]],
    profile_contract: dict[str, Any],
    *,
    mutate: bool,
    timeout_seconds: int,
) -> dict[str, Any]:
    mutations: list[dict[str, str]] = []
    observed_flows: list[dict[str, Any]] = []
    for desired in flows:
        observed, mutation = reconcile_flow(
            base,
            headers,
            desired,
            mutate=mutate,
            timeout_seconds=timeout_seconds,
        )
        observed_flows.append(observed)
        if mutation:
            mutations.append(mutation)
    kv_rows: list[dict[str, Any]] = []
    for key, expected in (
        (FLOW_CATALOG_KEY, flow_catalog_value(observed_flows)),
        (PROFILE_CATALOG_KEY, profile_contract["value"]),
    ):
        observed, mutation = reconcile_kv(
            base,
            headers,
            key,
            expected,
            mutate=mutate,
            timeout_seconds=timeout_seconds,
        )
        kv_rows.append(observed)
        if mutation:
            mutations.append(mutation)
    return {
        "mutationCount": len(mutations),
        "mutations": mutations,
        "flows": observed_flows,
        "kv": kv_rows,
    }


def _stable_state(first: dict[str, Any], second: dict[str, Any]) -> bool:
    return first.get("flows") == second.get("flows") and first.get("kv") == second.get(
        "kv"
    )


def evidence_mode(path: Path) -> bool:
    try:
        info = path.stat()
    except OSError:
        return False
    owner_valid = os.geteuid() != 0 or (info.st_uid == 0 and info.st_gid == 0)
    return not path.is_symlink() and stat.S_IMODE(info.st_mode) == 0o600 and owner_valid


def _fresh_timestamp(value: Any, max_age_seconds: int = 3600) -> bool:
    if not _valid_timestamp(value):
        return False
    parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    age = (datetime.datetime.now(datetime.timezone.utc) - parsed).total_seconds()
    return -60 <= age <= max_age_seconds


def read_provision_subject(
    canonical_sha: str,
    producer_sha: str,
    lock_sha: str,
    flows: list[dict[str, Any]],
    profiles: dict[str, Any],
) -> dict[str, Any]:
    if not PROVISION_EVIDENCE.is_file() or not evidence_mode(PROVISION_EVIDENCE):
        raise ReconcileError("kestra_provision_evidence_missing_or_insecure")
    try:
        document = json.loads(PROVISION_EVIDENCE.read_text())
    except json.JSONDecodeError as exc:
        raise ReconcileError("kestra_provision_evidence_invalid") from exc
    expected_flow_sources = [
        {
            "id": row["id"],
            "namespace": row["namespace"],
            "sourceRef": row["sourceRef"],
            "sourceSha256": row["sourceSha256"],
        }
        for row in flows
    ]
    if (
        not isinstance(document, dict)
        or document.get("apiVersion") != API_VERSION
        or document.get("kind") != EVIDENCE_KIND
        or document.get("status") != "passed"
        or document.get("action") != "provision"
        or not _fresh_timestamp(document.get("finishedAt"))
        or document.get("canonicalSourceSha256") != canonical_sha
        or document.get("producerPath") != str(producer_path())
        or document.get("producerSha256") != producer_sha
        or document.get("platformLockSha256") != lock_sha
        or document.get("flowSourceSet") != expected_flow_sources
        or document.get("profileSourceSha256") != sha256_path(profiles["sourcePath"])
        or document.get("profileRuntimeSha256")
        != profile_catalog_semantic_sha256(read_object(profiles["runtimePath"]))
        or document.get("profileRefs") != list(profiles["refs"])
        or document.get("stableRemoteState") is not True
        or document.get("secondPass", {}).get("mutationCount") != 0
        or document.get("secondPass", {}).get("noOp") is not True
    ):
        raise ReconcileError("kestra_provision_evidence_binding_invalid")
    return document


def _atomic_evidence(
    path: Path, document: dict[str, Any], values: dict[str, str]
) -> None:
    serialized = json.dumps(document, indent=2, sort_keys=True) + "\n"
    forbidden = [
        value
        for key, value in values.items()
        if SECRET_KEY.search(key)
        and len(value) >= 8
        and value.lower() not in NON_SECRET_LITERALS
    ]
    if any(value in serialized for value in forbidden):
        raise ReconcileError("kestra_evidence_contains_secret")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(serialized)
    temporary.chmod(0o600)
    temporary.replace(path)
    if not evidence_mode(path):
        raise ReconcileError("kestra_evidence_mode_invalid")


def execute(action: str) -> dict[str, Any]:
    if action not in {"provision", "verify"}:
        raise ReconcileError("unsupported_action")
    started = utcnow()
    values = dotenv()
    canonical_sha = sha256_path(CANONICAL_ENV)
    producer_sha = sha256_path(producer_path())
    lock = platform_contract()
    base, headers, timeout_seconds = basic_auth(values)
    flows = load_flows()
    profiles = load_profile_contract()
    mutate = action == "provision"
    subject: dict[str, str] | None = None
    if action == "verify":
        read_provision_subject(
            canonical_sha,
            producer_sha,
            lock["sha256"],
            flows,
            profiles,
        )
        subject = {
            "path": str(PROVISION_EVIDENCE),
            "sha256": sha256_path(PROVISION_EVIDENCE),
        }
    first = reconcile_pass(
        base,
        headers,
        flows,
        profiles,
        mutate=mutate,
        timeout_seconds=timeout_seconds,
    )
    try:
        second = reconcile_pass(
            base,
            headers,
            flows,
            profiles,
            mutate=False,
            timeout_seconds=timeout_seconds,
        )
    except ReconcileError as exc:
        raise ReconcileError("kestra_second_reconcile_not_noop") from exc
    stable = _stable_state(first, second)
    if second["mutationCount"] != 0 or not stable:
        raise ReconcileError("kestra_second_reconcile_not_noop")
    second["noOp"] = True
    document: dict[str, Any] = {
        "apiVersion": API_VERSION,
        "kind": EVIDENCE_KIND,
        "status": "passed",
        "action": action,
        "startedAt": started,
        "finishedAt": utcnow(),
        "canonicalSourceSha256": canonical_sha,
        "producerPath": str(producer_path()),
        "producerSha256": producer_sha,
        "platformLockSha256": lock["sha256"],
        "kestraVersion": lock["version"],
        "controlNamespace": CONTROL_NAMESPACE,
        "credential": {
            "authType": "basic",
            "usernameRef": "KESTRA_ADMIN_USER",
            "passwordRef": "KESTRA_ADMIN_PASSWORD",
            "resolvedForLiveApi": True,
            "rawSecretIncluded": False,
        },
        "connection": {
            "scheme": "http",
            "hostRef": "KESTRA_LOOPBACK_HOST",
            "portRef": "KESTRA_ORIGIN_PORT",
            "timeoutSecondsRef": "KESTRA_RECONCILE_HTTP_TIMEOUT_SECONDS",
            "loopbackOnly": True,
        },
        "flowCatalogKey": FLOW_CATALOG_KEY,
        "profileCatalogKey": PROFILE_CATALOG_KEY,
        "profileSourceSha256": sha256_path(profiles["sourcePath"]),
        "profileRuntimeSha256": profile_catalog_semantic_sha256(
            read_object(profiles["runtimePath"])
        ),
        "profileRefs": list(profiles["refs"]),
        "flowSourceSet": [
            {
                "id": row["id"],
                "namespace": row["namespace"],
                "sourceRef": row["sourceRef"],
                "sourceSha256": row["sourceSha256"],
            }
            for row in flows
        ],
        "firstPass": first,
        "secondPass": second,
        "stableRemoteState": stable,
        "secretAudit": {
            "canonicalEnvIncluded": False,
            "authorizationHeaderIncluded": False,
            "rawSecretIncluded": False,
        },
    }
    if subject is not None:
        document["subjectProvisionEvidence"] = subject
    output = PROVISION_EVIDENCE if action == "provision" else VERIFY_EVIDENCE
    _atomic_evidence(output, document, values)
    return document


def status() -> dict[str, Any]:
    path = VERIFY_EVIDENCE if VERIFY_EVIDENCE.is_file() else PROVISION_EVIDENCE
    if not path.is_file():
        return {"ok": False, "status": "evidence_missing"}
    try:
        value = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"ok": False, "status": "evidence_invalid"}
    return {
        "ok": value.get("status") == "passed",
        "status": value.get("status"),
        "action": value.get("action"),
        "evidencePath": str(path),
        "canonicalSourceSha256": value.get("canonicalSourceSha256"),
        "producerSha256": value.get("producerSha256"),
    }


def main() -> int:
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    try:
        if action in {"provision", "verify"}:
            result = execute(action)
        elif action == "status":
            result = status()
        else:
            print(
                "usage: server-kestra-reconcile.py provision|verify|status",
                file=sys.stderr,
            )
            return 2
    except ReconcileError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "passed" or result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

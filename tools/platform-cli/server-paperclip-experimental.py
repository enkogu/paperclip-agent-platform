#!/usr/bin/env python3
"""Reconcile Paperclip experimental environments, Daytona, and secret bindings.

The controller runs on the target host.  It emits only identifiers, states, and
short fingerprints; secret values and provider connection payloads never enter
stdout or evidence files.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any
import uuid
import urllib.error
import urllib.parse
import urllib.request


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from profile_catalog import (  # noqa: E402
    default_catalog_path,
    load_profile_catalog,
)


ROOT = Path("/opt/mte-platform")
CONFIG = ROOT / "config/platform.json"
BOOTSTRAP = ROOT / "evidence/paperclip-bootstrap.json"
PLATFORM_ENV = Path("/root/.config/mte-secrets/platform.env")
EVIDENCE_ROOT = ROOT / "evidence"
DAYTONA_STEP_SOURCE = ROOT / "steps/60-daytona.sh"
API_VERSION = "micro-task-engine/v1alpha1"
DEFAULT_PROFILE_CATALOG = load_profile_catalog(default_catalog_path())
DAYTONA_PROFILE_REFS = DEFAULT_PROFILE_CATALOG.refs
DAYTONA_IMAGE_CONTRACT_KEYS = (
    "DAYTONA_TARGET",
    "MTE_DAYTONA_SANDBOX_BASE_IMAGE",
    "MTE_CODEX_VERSION",
    "MTE_CLAUDE_CODE_VERSION",
    "MTE_PI_VERSION",
    "MTE_CODEX_NPM_INTEGRITY",
    "MTE_CLAUDE_CODE_NPM_INTEGRITY",
    "MTE_PI_NPM_INTEGRITY",
    "MTE_TOOLHIVE_VERSION",
    "MTE_TOOLHIVE_ARCHIVE_SHA256",
    "MTE_GITHUB_CLI_VERSION",
    "MTE_GITHUB_CLI_ARCHIVE_SHA256",
    "MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL",
    "HERMES_LLM_MODEL",
    "MTE_PI_CODING_AGENT_DIR",
    "MTE_DAYTONA_CODING_SNAPSHOT",
    "MTE_DAYTONA_GENERAL_SNAPSHOT",
    "MTE_DAYTONA_CODING_CPU",
    "MTE_DAYTONA_CODING_MEMORY_GIB",
    "MTE_DAYTONA_GENERAL_CPU",
    "MTE_DAYTONA_GENERAL_MEMORY_GIB",
    "MTE_DAYTONA_DISK_GIB",
)
DAYTONA_LIFECYCLE_STATES = (
    ("created", "started"),
    ("file-roundtrip", "started"),
    ("stopped", "stopped"),
    ("restarted", "started"),
    ("stopped-before-archive", "stopped"),
    ("archive-requested", "archiving"),
    ("archived", "archived"),
    ("restored-from-archive", "restored"),
    ("refreshed", "started"),
    ("final-stop", "stopped"),
    ("cleanup", "deleted"),
)
EXPECTED_ENVIRONMENT_PROBE_WARNINGS = {
    ref: frozenset(profile["runtimeContract"]["probe"]["acceptedWarnings"])
    for ref, profile in DEFAULT_PROFILE_CATALOG.by_ref.items()
}
ENVIRONMENT_PROBE_HELLO_CODES = {
    ref: str(profile["runtimeContract"]["probe"]["helloCode"])
    for ref, profile in DEFAULT_PROFILE_CATALOG.by_ref.items()
}
ENVIRONMENT_PROBE_ATTEMPTS = 3
ENVIRONMENT_PROBE_RETRY_SECONDS = 2
FULL_SHA256 = re.compile(r"[a-f0-9]{64}")
FULL_IMAGE_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
EXACT_ENV_PLACEHOLDER = re.compile(r"\$\{([A-Z][A-Z0-9_]*):\?required\}")


class ControlError(RuntimeError):
    def __init__(self, code: str, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ControlError("invalid_local_state", f"cannot read {path}") from exc
    if not isinstance(value, dict):
        raise ControlError("invalid_local_state", f"{path} must contain an object")
    return value


def dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def settings() -> tuple[dict[str, Any], dict[str, Any]]:
    cfg = load_json(CONFIG)
    experimental = cfg.get("spec", {}).get("paperclipExperimental")
    if not isinstance(experimental, dict):
        raise ControlError("invalid_config", "spec.paperclipExperimental is required")
    return cfg, experimental


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def catalog_value(value: Any, values: dict[str, str]) -> str:
    """Resolve a source-catalog placeholder or return an already rendered value."""
    if isinstance(value, str):
        match = EXACT_ENV_PLACEHOLDER.fullmatch(value)
        if match:
            return values.get(match.group(1), "")
        return value
    return ""


def expected_harness_versions(values: dict[str, str]) -> dict[str, str]:
    result = {
        str(profile["runtimeContract"]["packageKey"]): catalog_value(
            profile["runtimePackages"][profile["runtimeContract"]["packageKey"]],
            values,
        )
        for profile in DEFAULT_PROFILE_CATALOG.profiles
    }
    result["toolhive"] = values.get("MTE_TOOLHIVE_VERSION", "")
    result["githubCli"] = values.get("MTE_GITHUB_CLI_VERSION", "")
    if any(not value for value in result.values()):
        raise ControlError(
            "missing_canonical_config", "profile harness version is missing"
        )
    return result


def expected_package_integrity(values: dict[str, str]) -> dict[str, str]:
    result = {
        "codex": values.get("MTE_CODEX_NPM_INTEGRITY", ""),
        "claudeCode": values.get("MTE_CLAUDE_CODE_NPM_INTEGRITY", ""),
        "pi": values.get("MTE_PI_NPM_INTEGRITY", ""),
        "githubCliSha256": values.get("MTE_GITHUB_CLI_ARCHIVE_SHA256", ""),
    }
    if any(not value for value in result.values()):
        raise ControlError(
            "missing_canonical_config", "sandbox package integrity is missing"
        )
    return result


def normalized_driver_config(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": value.get("provider"),
        "apiKeySecretId": value.get("apiKey"),
        "apiUrl": value.get("apiUrl"),
        "target": value.get("target"),
        "snapshot": value.get("snapshot"),
        "image": value.get("image"),
        "memory": value.get("memory"),
        "disk": value.get("disk"),
        "timeoutMs": value.get("timeoutMs"),
        "reuseLease": value.get("reuseLease"),
    }


def adapter_environment_probe_config(
    adapter_config: dict[str, Any],
) -> tuple[dict[str, Any], int]:
    """Return a probe-only config that can resolve without a responsible user.

    Paperclip's adapter environment test endpoint has no responsible-user
    context.  Required ``user_secret_ref`` bindings therefore cannot be
    resolved there, even though normal task execution resolves them against
    the responsible user.  Make only those bindings optional in the deep copy
    sent to the probe; the persisted agent config remains strict and unchanged.
    """
    probe_config = copy.deepcopy(adapter_config)
    env = probe_config.get("env")
    if env is None:
        return probe_config, 0
    if not isinstance(env, dict):
        raise ControlError(
            "coding_profile_env_drift", "adapterConfig.env must be an object"
        )
    optional_user_secret_count = 0
    for binding in env.values():
        if isinstance(binding, dict) and binding.get("type") == "user_secret_ref":
            binding["required"] = False
            binding["allowMissingOverride"] = True
            optional_user_secret_count += 1
    return probe_config, optional_user_secret_count


def accepted_environment_probe(
    profile_ref: str, payload: Any
) -> tuple[bool, list[str]]:
    """Accept a native probe or one precisely allowlisted upstream warning.

    Paperclip aggregates any adapter warning into a top-level ``warn`` status.
    We remain fail-closed: a warning result is accepted only when its complete
    warning-code set exactly matches the profile allowlist, no error exists,
    and the native harness hello check passed.
    """
    if not isinstance(payload, dict):
        return False, []
    status = payload.get("status")
    if status == "pass":
        return True, []
    if status != "warn":
        return False, []
    checks = payload.get("checks")
    if not isinstance(checks, list) or not checks:
        return False, []
    normalized = [row for row in checks if isinstance(row, dict)]
    if len(normalized) != len(checks) or any(
        row.get("level") == "error" for row in normalized
    ):
        return False, []
    warning_codes = sorted(
        str(row.get("code", "")) for row in normalized if row.get("level") == "warn"
    )
    allowed = EXPECTED_ENVIRONMENT_PROBE_WARNINGS.get(profile_ref, frozenset())
    hello_code = ENVIRONMENT_PROBE_HELLO_CODES.get(profile_ref)
    hello_passed = any(
        row.get("code") == hello_code and row.get("level") == "info"
        for row in normalized
    )
    return set(warning_codes) == set(allowed) and bool(
        allowed
    ) and hello_passed, warning_codes


def environment_probe_observation(
    payload: Any,
    *,
    attempt: int,
    accepted: bool,
    warning_codes: list[str],
    request_error: str | None,
    deleted_sandbox_count: int,
) -> dict[str, Any]:
    """Return a secret-free, deterministic adapter-probe observation."""
    checks = payload.get("checks") if isinstance(payload, dict) else None
    safe_checks = []
    if isinstance(checks, list):
        safe_checks = [
            {
                "code": str(row.get("code", "")),
                "level": str(row.get("level", "")),
            }
            for row in checks
            if isinstance(row, dict)
        ]
    return {
        "attempt": attempt,
        "status": str(payload.get("status", ""))
        if isinstance(payload, dict)
        else "",
        "accepted": accepted,
        "warningCodes": warning_codes,
        "requestError": request_error,
        "checks": safe_checks,
        "probeSandboxesDeleted": deleted_sandbox_count,
    }


def validate_profile_env_contract(
    *,
    profile_ref: str,
    company_id: str,
    agent_id: str,
    env: Any,
    required_keys: set[str],
    provider_managed_env: dict[str, dict[str, str]] | None = None,
) -> None:
    """Validate the catalog-owned env allowlist and provider-managed homes."""
    if provider_managed_env is None:
        profile = DEFAULT_PROFILE_CATALOG.require(profile_ref)
        provider_managed_env = profile["runtimeContract"]["providerManagedEnv"]
    expected_keys = set(required_keys) | set(provider_managed_env)
    if not isinstance(env, dict) or set(env) != expected_keys:
        raise ControlError(
            "coding_profile_env_drift",
            f"{profile_ref} env keys do not match the profile",
        )
    for key, contract in provider_managed_env.items():
        binding = env.get(key)
        value = binding.get("value") if isinstance(binding, dict) else None
        expected_suffix = f"/companies/{company_id}/agents/{agent_id}/" + str(
            contract["pathSuffix"]
        )
        if (
            contract.get("kind") != "paperclip-agent-home"
            or not isinstance(binding, dict)
            or set(binding) != {"type", "value"}
            or binding.get("type") != "plain"
            or not isinstance(value, str)
            or not value.startswith("/")
            or not value.endswith(expected_suffix)
        ):
            raise ControlError(
                "coding_profile_env_drift",
                f"{profile_ref} managed {key} binding is invalid",
            )


def validate_daytona_runtime_evidence(
    payload: dict[str, Any], expected_kind: str, values: dict[str, str]
) -> None:
    """Fail closed before binding nested Daytona evidence into C072/C074/C075."""
    if expected_kind == "PaperclipDaytonaControlPlaneEvidence":
        gateway = payload.get("agentGateway")
        profiles = gateway.get("profiles") if isinstance(gateway, dict) else None
        runner_id = (
            str(gateway.get("runnerContainerId", ""))
            if isinstance(gateway, dict)
            else ""
        )
        gateway_id = (
            str(gateway.get("gatewayContainerId", ""))
            if isinstance(gateway, dict)
            else ""
        )
        expected_networks = ["mte-agent-plane", "mte-daytona-net", "mte-tool-runtime"]
        expected_profiles = tuple(
            {
                "profileRef": str(profile["ref"]),
                "upstreamRef": str(profile["topology"]["toolhiveUpstreamRef"]),
                "host": "toolhive",
                "port": int(values[profile["topology"]["toolhiveProxyPortRef"]]),
                "gatewayPort": int(
                    values[profile["topology"]["toolhiveGatewayPortRef"]]
                ),
                "httpStatus": 200,
                "initialize": True,
            }
            for profile in DEFAULT_PROFILE_CATALOG.profiles
        )
        if (
            payload.get("action") != "verify"
            or payload.get("secretValuesPrinted") is not False
            or not isinstance(gateway, dict)
            or set(gateway)
            != {
                "status",
                "profileCount",
                "runnerContainerId",
                "gatewayContainerId",
                "gatewayNetworkMode",
                "runnerNetworks",
                "expectedRunnerNetworks",
                "privateToolRuntimeNetwork",
                "noPublishedPorts",
                "profiles",
            }
            or gateway.get("status") != "passed"
            or gateway.get("profileCount") != len(expected_profiles)
            or not FULL_SHA256.fullmatch(runner_id)
            or not FULL_SHA256.fullmatch(gateway_id)
            or gateway.get("gatewayNetworkMode") != "container:" + runner_id
            or gateway.get("noPublishedPorts") is not True
            or gateway.get("privateToolRuntimeNetwork") != "mte-tool-runtime"
            or gateway.get("runnerNetworks") != expected_networks
            or gateway.get("expectedRunnerNetworks") != expected_networks
            or not isinstance(profiles, list)
            or len(profiles) != len(expected_profiles)
        ):
            raise ControlError(
                "runtime_evidence_failed", "Daytona control-plane proof is incomplete"
            )
        for row, expected in zip(profiles, expected_profiles, strict=True):
            if not isinstance(row, dict) or row != expected:
                raise ControlError(
                    "runtime_evidence_failed",
                    f"{expected['profileRef']} control-plane gateway proof drifted",
                )
        return

    if expected_kind == "DaytonaHarnessSnapshots":
        snapshots = payload.get("snapshots")
        expected_snapshots = (
            (
                values["MTE_DAYTONA_CODING_SNAPSHOT"],
                int(values["MTE_DAYTONA_CODING_CPU"]),
                int(values["MTE_DAYTONA_CODING_MEMORY_GIB"]),
            ),
            (
                values["MTE_DAYTONA_GENERAL_SNAPSHOT"],
                int(values["MTE_DAYTONA_GENERAL_CPU"]),
                int(values["MTE_DAYTONA_GENERAL_MEMORY_GIB"]),
            ),
        )
        if not isinstance(snapshots, list) or len(snapshots) != 2:
            raise ControlError(
                "runtime_evidence_failed", "Daytona snapshot proof is incomplete"
            )
        ids: set[str] = set()
        for row, (name, cpu, memory) in zip(snapshots, expected_snapshots, strict=True):
            if (
                not isinstance(row, dict)
                or not row.get("id")
                or row.get("name") != name
                or row.get("state") != "active"
                or row.get("cpu") != cpu
                or row.get("memoryGiB") != memory
                or row.get("diskGiB") != int(values["MTE_DAYTONA_DISK_GIB"])
                or not FULL_IMAGE_DIGEST.fullmatch(str(row.get("digest", "")))
            ):
                raise ControlError(
                    "runtime_evidence_failed", f"snapshot {name} proof drifted"
                )
            ids.add(str(row["id"]))
        expected_contract = {
            key: values.get(key, "") for key in sorted(DAYTONA_IMAGE_CONTRACT_KEYS)
        }
        if (
            len(ids) != 2
            or payload.get("harnessVersions") != expected_harness_versions(values)
            or payload.get("packageIntegrity") != expected_package_integrity(values)
            or payload.get("imageContract") != expected_contract
            or payload.get("imageContractHash")
            != canonical_json_sha256(expected_contract)
            or payload.get("credentialsBakedIntoImage") is not False
            or (payload.get("canonicalBinding") or {}).get("imageContractUnchanged")
            is not True
            or (payload.get("canonicalBinding") or {}).get(
                "fullCanonicalHashAfterReadinessMerge"
            )
            != file_sha256(PLATFORM_ENV)
        ):
            raise ControlError(
                "runtime_evidence_failed", "Daytona image contract proof drifted"
            )
        return

    if expected_kind == "DaytonaSandboxLifecycleEvidence":
        states = payload.get("states")
        expected_resources = {
            "cpu": int(values["MTE_DAYTONA_CODING_CPU"]),
            "memory": int(values["MTE_DAYTONA_CODING_MEMORY_GIB"]),
            "disk": int(values["MTE_DAYTONA_DISK_GIB"]),
        }
        version_output = payload.get("harnessVersionOutput")
        joined_versions = (
            "\n".join(str(row) for row in version_output)
            if isinstance(version_output, list)
            else ""
        )
        credential_probe = payload.get("credentialFileProbe")
        workspace_probe = payload.get("workspaceDirectoryProbe")
        pi_config_probe = payload.get("piProbeConfig")
        github_probe = payload.get("github")
        expected_workspace_paths = [
            str(profile["nativeAdapterConfig"]["cwd"])
            for profile in DEFAULT_PROFILE_CATALOG.profiles
        ]
        if (
            not isinstance(states, list)
            or [(row.get("phase"), row.get("state")) for row in states]
            != list(DAYTONA_LIFECYCLE_STATES)
            or payload.get("provider") != "daytona"
            or payload.get("target") != values["DAYTONA_TARGET"]
            or payload.get("snapshot") != values["MTE_DAYTONA_CODING_SNAPSHOT"]
            or payload.get("credentialsBakedIntoImage") is not False
            or (payload.get("fileRoundTrip") or {}).get("verified") is not True
            or not FULL_SHA256.fullmatch(
                str((payload.get("fileRoundTrip") or {}).get("markerSha256", ""))
            )
            or (payload.get("fileRoundTrip") or {}).get("markerSha256")
            != payload.get("markerSha256")
            or payload.get("persistence")
            != {"verified": True, "afterRestart": True, "afterArchiveRestore": True}
            or payload.get("resources")
            != {
                "expected": expected_resources,
                "actual": expected_resources,
                "equal": True,
            }
            or payload.get("agentGateway")
            != {
                "expectedHost": values["MTE_AGENT_GATEWAY_HOST"],
                "observedDefaultGateway": values["MTE_AGENT_GATEWAY_HOST"],
                "matchesCanonical": True,
            }
            or not all(
                version in joined_versions
                for version in expected_harness_versions(values).values()
            )
            or github_probe
            != {
                "cliVersion": values["MTE_GITHUB_CLI_VERSION"],
                "authentication": "GH_TOKEN-runtime-env",
                "gitCredentialHelper": "gh auth git-credential",
                "gitIdentity": {
                    "name": "Paperclip Agent",
                    "email": "paperclip-agent@users.noreply.github.com",
                },
                "tokenInRemoteUrl": False,
                "credentialFilePersisted": False,
            }
            or payload.get("cleanupDeleted") is not True
            or payload.get("delete") != {"requested": True, "getAfterDeleteStatus": 404}
            or not isinstance(credential_probe, dict)
            or credential_probe.get("credentialFree") is not True
            or credential_probe.get("foundPaths") != []
            or not isinstance(credential_probe.get("checkedPaths"), list)
            or not credential_probe["checkedPaths"]
            or workspace_probe
            != {
                "checkedPaths": expected_workspace_paths,
                "missingPaths": [],
                "allPresent": True,
            }
            or not isinstance(pi_config_probe, dict)
            or pi_config_probe.get("path")
            != values["MTE_PI_CODING_AGENT_DIR"] + "/models.json"
            or pi_config_probe.get("apiKeyReference") != "$OPENAI_API_KEY"
            or pi_config_probe.get("secretEmbedded") is not False
            or not FULL_SHA256.fullmatch(str(pi_config_probe.get("sha256", "")))
        ):
            raise ControlError(
                "runtime_evidence_failed", "Daytona lifecycle proof drifted"
            )
        return

    raise ControlError(
        "runtime_evidence_failed", f"unsupported evidence kind {expected_kind}"
    )


def evidence_reference(
    path: Path,
    expected_kind: str,
    *,
    values: dict[str, str] | None = None,
) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ControlError(
            "runtime_evidence_failed", f"{path.name} is not a regular file"
        )
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ControlError("runtime_evidence_failed", f"{path.name} mode is not 0600")
    payload = load_json(path)
    timestamp = str(payload.get("generatedAt", ""))
    try:
        generated_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ControlError(
            "runtime_evidence_failed", f"{path.name} timestamp is invalid"
        ) from exc
    now = datetime.now(timezone.utc)
    max_age_seconds = (
        3600 if expected_kind == "DaytonaSandboxLifecycleEvidence" else 600
    )
    if (
        payload.get("apiVersion") != API_VERSION
        or payload.get("kind") != expected_kind
        or payload.get("status") != "ready"
        or payload.get("canonicalSourceSha256") != file_sha256(PLATFORM_ENV)
        or not FULL_SHA256.fullmatch(str(payload.get("producerSha256", "")))
        or generated_at.tzinfo is None
        or generated_at > now + timedelta(seconds=60)
        or (now - generated_at).total_seconds() > max_age_seconds
    ):
        raise ControlError("runtime_evidence_failed", f"{path.name} is not ready")
    if values is not None:
        if (
            not DAYTONA_STEP_SOURCE.is_file()
            or payload.get("producerSha256") != file_sha256(DAYTONA_STEP_SOURCE)
            or (
                expected_kind == "PaperclipDaytonaControlPlaneEvidence"
                and payload.get("producerPath") != str(DAYTONA_STEP_SOURCE)
            )
        ):
            raise ControlError(
                "runtime_evidence_failed", f"{path.name} producer binding drifted"
            )
        validate_daytona_runtime_evidence(payload, expected_kind, values)
    return {
        "path": str(path),
        "kind": expected_kind,
        "status": "ready",
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def json_request(
    base: str,
    method: str,
    path: str,
    body: Any | None = None,
    *,
    timeout: int = 30,
) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        base.rstrip("/") + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        # Do not include response bodies: plugin/provider errors may echo a
        # submitted credential or a temporary sandbox connection payload.
        raise ControlError(
            "remote_api_error",
            f"Paperclip {method} {path} returned HTTP {exc.code}",
            status=exc.code,
        ) from exc
    except urllib.error.URLError as exc:
        raise ControlError(
            "remote_unavailable", f"Paperclip {method} {path} is unavailable"
        ) from exc
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ControlError(
            "invalid_remote_response", f"Paperclip {method} {path} returned non-JSON"
        ) from exc


def daytona_json_request(
    values: dict[str, str],
    method: str,
    path: str,
    body: Any | None = None,
    *,
    allow_not_found: bool = False,
) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        values["MTE_DAYTONA_API_URL"].rstrip("/") + path,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {values['DAYTONA_API_KEY']}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        if allow_not_found and exc.code == 404:
            return None
        raise ControlError(
            "daytona_api_error",
            f"Daytona {method} {path.split('?', 1)[0]} returned HTTP {exc.code}",
            status=exc.code,
        ) from exc
    except urllib.error.URLError as exc:
        raise ControlError(
            "remote_unavailable", f"Daytona {method} API is unavailable"
        ) from exc
    return json.loads(raw) if raw else None


def daytona_environment_sandbox_ids(
    values: dict[str, str], environment_id: str
) -> set[str]:
    labels = json.dumps(
        {"paperclip-environment-id": environment_id}, separators=(",", ":")
    )
    query = urllib.parse.urlencode({"page": 1, "limit": 100, "labels": labels})
    response = daytona_json_request(values, "GET", f"/sandbox/paginated?{query}")
    return {
        str(item["id"]) for item in rows(response, "items", "data") if item.get("id")
    }


def destroy_daytona_probe_sandbox(values: dict[str, str], sandbox_id: str) -> None:
    encoded = urllib.parse.quote(sandbox_id)
    deadline = time.monotonic() + 180
    while True:
        try:
            daytona_json_request(values, "DELETE", f"/sandbox/{encoded}")
            break
        except ControlError as exc:
            if exc.status not in {409, 423} or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    for _ in range(90):
        if (
            daytona_json_request(
                values,
                "GET",
                f"/sandbox/{encoded}",
                allow_not_found=True,
            )
            is None
        ):
            return
        time.sleep(1)
    raise ControlError(
        "probe_cleanup_failed", "Daytona probe sandbox cleanup timed out"
    )


def rows(value: Any, *keys: str) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in keys:
            nested = value.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
    return []


def paperclip_context() -> tuple[str, str]:
    _, experimental = settings()
    base = str(experimental.get("apiBase", "http://127.0.0.1:3100")).rstrip("/")
    bootstrap = load_json(BOOTSTRAP)
    company_id = str(bootstrap.get("companyId", "")).strip()
    if not company_id:
        raise ControlError(
            "bootstrap_required", "Paperclip profiles/bootstrap must run first"
        )
    companies = rows(json_request(base, "GET", "/api/companies"), "companies", "items")
    if not any(str(item.get("id")) == company_id for item in companies):
        raise ControlError(
            "bootstrap_stale", "Paperclip bootstrap company no longer exists"
        )
    return base, company_id


def atomic_evidence(feature: str, action: str, payload: dict[str, Any]) -> Path:
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o755)
    path = EVIDENCE_ROOT / f"paperclip-{feature}-{action}.json"
    temp = path.with_suffix(".json.tmp")
    temp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temp.chmod(0o600)
    temp.replace(path)
    path.chmod(0o600)
    return path


def emit(feature: str, action: str, status: str, details: dict[str, Any]) -> None:
    observed_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "PaperclipExperimentalReconcile",
        "runId": str(uuid.uuid4()),
        "feature": feature,
        "action": action,
        "status": status,
        "observedAt": observed_at,
        "generatedAt": observed_at,
        "canonicalSourceSha256": file_sha256(PLATFORM_ENV),
        "producerSha256": file_sha256(Path(__file__)),
        "producerPath": str(Path(__file__)),
        "sources": {
            "platformConfigSha256": file_sha256(CONFIG),
            "bootstrapSha256": file_sha256(BOOTSTRAP) if BOOTSTRAP.is_file() else None,
        },
        "details": details,
    }
    path = atomic_evidence(feature, action, payload)
    print(json.dumps({**payload, "evidence": str(path)}, indent=2, sort_keys=True))


def find_named(items: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    return next((item for item in items if str(item.get("name")) == name), None)


def ensure_local_repository(path: str) -> None:
    script = """
set -eu
root=$1
mkdir -p "$root"
if [ ! -d "$root/.git" ]; then
  git -C "$root" init -q
  git -C "$root" config user.name "MTE Canary"
  git -C "$root" config user.email "mte-canary@localhost"
  printf '%s\n' '# MTE isolated workspace canary' >"$root/README.md"
  git -C "$root" add README.md
  git -C "$root" commit -qm "Initialize isolated workspace canary"
fi
git -C "$root" rev-parse --verify HEAD >/dev/null
"""
    try:
        subprocess.run(
            [
                "docker",
                "exec",
                "mte-paperclip",
                "sh",
                "-ceu",
                script,
                "mte-workspace",
                path,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ControlError(
            "workspace_init_failed", "cannot initialize Paperclip canary repository"
        ) from exc


def environment_capabilities(base: str, company_id: str) -> Any:
    path = f"/api/companies/{urllib.parse.quote(company_id)}/environments/capabilities"
    try:
        return json_request(base, "GET", path)
    except ControlError as exc:
        if exc.status == 404:
            raise ControlError(
                "runtime_upgrade_required",
                "installed Paperclip does not expose experimental environments",
                status=404,
            ) from exc
        raise


def environment_list(base: str, company_id: str) -> list[dict[str, Any]]:
    value = json_request(
        base,
        "GET",
        f"/api/companies/{urllib.parse.quote(company_id)}/environments",
    )
    return rows(value, "environments", "items", "data")


def project_list(base: str, company_id: str) -> list[dict[str, Any]]:
    value = json_request(
        base,
        "GET",
        f"/api/companies/{urllib.parse.quote(company_id)}/projects",
    )
    return rows(value, "projects", "items", "data")


def agent_list(base: str, company_id: str) -> list[dict[str, Any]]:
    value = json_request(
        base,
        "GET",
        f"/api/companies/{urllib.parse.quote(company_id)}/agents",
    )
    return rows(value, "agents", "items", "data")


def select_local_environment(
    environments: list[dict[str, Any]], name: str
) -> tuple[dict[str, Any] | None, bool]:
    named = find_named(environments, name)
    if named is not None:
        return named, False
    local_environments = [
        item for item in environments if str(item.get("driver")) == "local"
    ]
    if len(local_environments) > 1:
        raise ControlError(
            "environment_duplicate",
            "Paperclip exposes multiple unnamed local environments",
        )
    if local_environments:
        # Paperclip creates one built-in local environment per company and
        # rejects a second local driver with HTTP 409. Reuse it without
        # overwriting Paperclip-owned name/metadata.
        return local_environments[0], True
    return None, False


def environment_mutation_path(environment_id: str, company_id: str) -> str:
    """Bind instance-scoped environment mutations to one company context.

    Paperclip environments are instance resources, while their secret refs are
    company-scoped.  Current Paperclip therefore requires ``companyId`` on any
    environment mutation that carries config or envVars.
    """
    return (
        f"/api/environments/{urllib.parse.quote(environment_id, safe='')}"
        f"?companyId={urllib.parse.quote(company_id, safe='')}"
    )


def reconcile_local_environment(*, mutate: bool) -> dict[str, Any]:
    _, experimental = settings()
    spec = experimental.get("localEnvironment", {})
    if not isinstance(spec, dict):
        raise ControlError("invalid_config", "localEnvironment must be an object")
    name = str(spec.get("name", "MTE Local Isolated Workspaces"))
    workspace_root = str(spec.get("workspaceRoot", "/workspaces/mte-isolated-canary"))
    project_name = str(spec.get("projectName", "MTE Isolated Workspace Canary"))
    branch_template = str(spec.get("branchTemplate", "{{issue.identifier}}"))
    if not workspace_root.startswith("/workspaces/"):
        raise ControlError(
            "unsafe_workspace_root", "local workspace must be below /workspaces"
        )

    base, company_id = paperclip_context()
    capabilities = environment_capabilities(base, company_id)
    if mutate:
        ensure_local_repository(workspace_root)

    environment, adopted_builtin = select_local_environment(
        environment_list(base, company_id), name
    )
    environment_payload = {
        "name": name,
        "description": "Local Paperclip environment for isolated git worktree execution.",
        "driver": "local",
        "status": "active",
        "config": {},
        "metadata": {"managedBy": "mte-platform", "purpose": "isolated-workspaces"},
    }
    if mutate:
        if environment and not adopted_builtin:
            environment = json_request(
                base,
                "PATCH",
                environment_mutation_path(str(environment["id"]), company_id),
                environment_payload,
            )
        elif environment is None:
            try:
                environment = json_request(
                    base,
                    "POST",
                    f"/api/companies/{urllib.parse.quote(company_id)}/environments",
                    environment_payload,
                )
            except ControlError as exc:
                if exc.status != 409:
                    raise
                environment, adopted_builtin = select_local_environment(
                    environment_list(base, company_id), name
                )
    if not isinstance(environment, dict) or not environment.get("id"):
        raise ControlError(
            "environment_missing", "managed local Paperclip environment is missing"
        )

    environment_id = str(environment["id"])
    policy = {
        "enabled": True,
        "defaultMode": "isolated_workspace",
        "allowIssueOverride": False,
        "workspaceStrategy": {
            "type": "git_worktree",
            "branchTemplate": branch_template,
            "worktreeParentDir": "/workspaces/.paperclip-worktrees",
        },
    }
    project = find_named(project_list(base, company_id), project_name)
    if mutate:
        if project:
            project = json_request(
                base,
                "PATCH",
                f"/api/projects/{urllib.parse.quote(str(project['id']))}",
                {"executionWorkspacePolicy": policy},
            )
        else:
            try:
                project = json_request(
                    base,
                    "POST",
                    f"/api/companies/{urllib.parse.quote(company_id)}/projects",
                    {
                        "name": project_name,
                        "description": "Idempotent canary project for Paperclip isolated workspaces.",
                        "workspace": {
                            "name": "MTE isolated canary primary",
                            "sourceType": "local_path",
                            "cwd": workspace_root,
                            "isPrimary": True,
                        },
                        "executionWorkspacePolicy": policy,
                    },
                )
            except ControlError as exc:
                if exc.status != 409:
                    raise
                project = find_named(project_list(base, company_id), project_name)
    if not isinstance(project, dict) or not project.get("id"):
        raise ControlError(
            "project_missing", "managed isolated-workspace project is missing"
        )

    observed_policy = project.get("executionWorkspacePolicy")
    if not isinstance(observed_policy, dict):
        raise ControlError("policy_missing", "project has no executionWorkspacePolicy")
    observed_strategy = observed_policy.get("workspaceStrategy")
    if observed_policy != policy:
        raise ControlError(
            "policy_drift", "isolated workspace policy does not match the manifest"
        )

    return {
        "companyId": company_id,
        "environmentId": environment_id,
        "environmentDriver": environment.get("driver"),
        "adoptedPaperclipDefault": adopted_builtin,
        "projectId": str(project["id"]),
        "workspaceMode": observed_policy.get("defaultMode"),
        "workspaceStrategy": observed_strategy.get("type"),
        "capabilitiesAvailable": bool(capabilities),
    }


def strict_mode_state() -> dict[str, bool]:
    try:
        result = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{range .Config.Env}}{{println .}}{{end}}",
                "mte-paperclip",
            ],
            check=True,
            text=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ControlError(
            "runtime_unavailable", "cannot inspect mte-paperclip runtime"
        ) from exc
    environment_enabled = (
        "PAPERCLIP_SECRETS_STRICT_MODE=true" in result.stdout.splitlines()
    )
    config_script = """
const fs = require('node:fs');
const path = '/data/instances/default/config.json';
if (!fs.existsSync(path)) process.exit(3);
const value = JSON.parse(fs.readFileSync(path, 'utf8'));
process.stdout.write(String(value?.secrets?.strictMode === true));
"""
    try:
        persisted = subprocess.run(
            ["docker", "exec", "mte-paperclip", "node", "-e", config_script],
            check=True,
            text=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ControlError(
            "runtime_config_unavailable", "cannot read Paperclip persisted strict mode"
        ) from exc
    return {
        "environment": environment_enabled,
        "persistedConfig": persisted.stdout.strip() == "true",
    }


def ensure_company_secret(
    base: str,
    company_id: str,
    *,
    name: str,
    value: str,
    provider: str = "local_encrypted",
) -> tuple[dict[str, Any], str]:
    if not value:
        raise ControlError(
            "needs_authorization", f"credential reference for {name} is empty"
        )
    digest = fingerprint(value)
    description = f"Managed by mte-platform; sha256:{digest}"
    secrets = rows(
        json_request(
            base, "GET", f"/api/companies/{urllib.parse.quote(company_id)}/secrets"
        ),
        "secrets",
        "items",
        "data",
    )
    secret = find_named(secrets, name)
    if secret:
        if str(secret.get("description", "")) != description:
            secret = json_request(
                base,
                "POST",
                f"/api/secrets/{urllib.parse.quote(str(secret['id']))}/rotate",
                {"value": value},
            )
            secret = json_request(
                base,
                "PATCH",
                f"/api/secrets/{urllib.parse.quote(str(secret['id']))}",
                {"description": description},
            )
    else:
        secret = json_request(
            base,
            "POST",
            f"/api/companies/{urllib.parse.quote(company_id)}/secrets",
            {
                "name": name,
                "provider": provider,
                "value": value,
                "description": description,
            },
        )
    if not isinstance(secret, dict) or not secret.get("id"):
        raise ControlError(
            "secret_create_failed", f"Paperclip did not return metadata for {name}"
        )
    return secret, digest


def validate_company_secret_scopes(
    secrets: list[dict[str, Any]],
    *,
    company_id: str,
    daytona_secret_id: str,
    profile_bindings: list[dict[str, str]],
) -> dict[str, Any]:
    """Prove C075 scope/provider/uniqueness without exposing secret values."""
    by_id: dict[str, list[dict[str, Any]]] = {}
    for row in secrets:
        secret_id = str(row.get("id", ""))
        if secret_id:
            by_id.setdefault(secret_id, []).append(row)
    expected_ids = [daytona_secret_id]
    for row in profile_bindings:
        expected_ids.extend((row["runtimeSecretId"], row["toolhiveSecretId"]))
    if len(expected_ids) != 7 or len(set(expected_ids)) != 7:
        raise ControlError(
            "secret_scope_mismatch",
            "Daytona and harness company secret IDs must be distinct",
        )

    sanitized: dict[str, dict[str, str]] = {}
    for secret_id in expected_ids:
        matches = by_id.get(secret_id, [])
        if len(matches) != 1:
            raise ControlError(
                "secret_scope_mismatch",
                "managed company secret is missing or duplicated",
            )
        secret = matches[0]
        provider = str(secret.get("provider") or secret.get("providerId") or "")
        observed_company_id = str(secret.get("companyId") or "")
        if (
            observed_company_id and observed_company_id != company_id
        ) or provider != "local_encrypted":
            raise ControlError(
                "secret_scope_mismatch",
                "managed secret provider or company scope drifted",
            )
        sanitized[secret_id] = {
            "secretId": secret_id,
            "provider": provider,
            "scopeType": "company",
            "scopeId": company_id,
        }

    profiles = []
    for row in profile_bindings:
        profiles.append(
            {
                "profileRef": row["profileRef"],
                "runtime": sanitized[row["runtimeSecretId"]],
                "toolhive": sanitized[row["toolhiveSecretId"]],
                "github": {
                    "binding": "paperclip_user_secret_ref",
                    "definitionKey": "mte.github.personal_access_token",
                },
                "envAllowlist": row["envKeys"],
                "inlineSensitiveValues": [],
            }
        )
    return {
        "provider": "local_encrypted",
        "scope": {"type": "company", "id": company_id},
        "daytonaApiKey": sanitized[daytona_secret_id],
        "profiles": profiles,
        "distinctCompanySecretIdCount": len(expected_ids),
        "unsafeInlineBindings": [],
        "rawValuesIncluded": False,
    }


def reconcile_secrets(*, mutate: bool) -> dict[str, Any]:
    _, experimental = settings()
    spec = experimental.get("secrets", {})
    if not isinstance(spec, dict):
        raise ControlError(
            "invalid_config", "paperclipExperimental.secrets must be an object"
        )
    if spec.get("strictMode") is not True:
        raise ControlError("unsafe_config", "Paperclip secrets strictMode must be true")
    strict_mode = strict_mode_state()
    if not all(strict_mode.values()):
        raise ControlError(
            "strict_mode_disabled", "Paperclip runtime strict secret mode is disabled"
        )

    base, company_id = paperclip_context()
    providers = rows(
        json_request(
            base,
            "GET",
            f"/api/companies/{urllib.parse.quote(company_id)}/secret-providers",
        ),
        "providers",
        "items",
        "data",
    )
    provider = str(spec.get("provider", "local_encrypted"))
    if not any(str(item.get("id")) == provider for item in providers):
        raise ControlError(
            "secret_provider_unavailable",
            f"Paperclip secret provider {provider} is unavailable",
        )

    environment_spec = experimental.get("localEnvironment", {})
    environment_name = str(
        environment_spec.get("name", "MTE Local Isolated Workspaces")
    )
    environment, adopted_builtin = select_local_environment(
        environment_list(base, company_id), environment_name
    )
    if not environment:
        raise ControlError(
            "environment_required",
            "local Paperclip environment must be reconciled first",
        )

    value_ref = str(spec.get("valueRef", "PAPERCLIP_SERVICE_TOKEN"))
    value = dotenv(PLATFORM_ENV).get(value_ref, "")
    secret_name = str(spec.get("secretName", "mte-platform-service-token"))
    digest = fingerprint(value) if value else ""
    secret = find_named(
        rows(
            json_request(
                base, "GET", f"/api/companies/{urllib.parse.quote(company_id)}/secrets"
            ),
            "secrets",
            "items",
            "data",
        ),
        secret_name,
    )
    if mutate:
        secret, digest = ensure_company_secret(
            base,
            company_id,
            name=secret_name,
            value=value,
            provider=provider,
        )
        env_vars = environment.get("envVars")
        if not isinstance(env_vars, dict):
            env_vars = {}
        env_vars[str(spec.get("bindingName", "MTE_PLATFORM_SERVICE_TOKEN"))] = {
            "type": "secret_ref",
            "secretId": str(secret["id"]),
            "version": "latest",
        }
        environment = json_request(
            base,
            "PATCH",
            environment_mutation_path(str(environment["id"]), company_id),
            {"envVars": env_vars},
        )
    if not isinstance(secret, dict) or not secret.get("id"):
        raise ControlError(
            "secret_missing", "managed Paperclip service secret is missing"
        )
    binding_name = str(spec.get("bindingName", "MTE_PLATFORM_SERVICE_TOKEN"))
    env_vars = environment.get("envVars") if isinstance(environment, dict) else None
    binding = env_vars.get(binding_name) if isinstance(env_vars, dict) else None
    if not isinstance(binding, dict) or str(binding.get("secretId")) != str(
        secret["id"]
    ):
        raise ControlError(
            "secret_binding_missing",
            "managed environment secret_ref binding is missing",
        )
    if str(secret.get("companyId", company_id)) != company_id:
        raise ControlError(
            "secret_scope_mismatch", "managed secret is outside the bootstrap company"
        )

    return {
        "companyId": company_id,
        "strictMode": strict_mode,
        "provider": provider,
        "secretId": str(secret["id"]),
        "secretFingerprint": digest or "stored",
        "scope": {"type": "company", "id": company_id},
        "binding": {
            "targetType": "environment",
            "targetId": str(environment["id"]),
            "name": binding_name,
            "type": "secret_ref",
        },
        "adoptedPaperclipDefault": adopted_builtin,
    }


def plugin_rows(base: str) -> list[dict[str, Any]]:
    return rows(json_request(base, "GET", "/api/plugins"), "plugins", "items", "data")


def plugin_match(
    items: list[dict[str, Any]], package_name: str
) -> dict[str, Any] | None:
    return next(
        (
            item
            for item in items
            if package_name
            in {
                str(item.get("packageName", "")),
                str(item.get("npmPackage", "")),
                str(item.get("source", "")),
            }
            or str(item.get("pluginKey", "")) == "paperclip.daytona-sandbox-provider"
        ),
        None,
    )


def installed_plugin_package_proof(package_name: str) -> dict[str, Any]:
    if not re.fullmatch(r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+", package_name):
        raise ControlError("invalid_config", "unsafe Daytona plugin package name")
    script = r"""
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const root = '/home/node/.paperclip/plugins/node_modules';
const packageName = process.argv[1];
const packageRoot = path.resolve(root, packageName);
if (!packageRoot.startsWith(root + path.sep)) process.exit(3);
const manifestBytes = fs.readFileSync(path.join(packageRoot, 'package.json'));
const manifest = JSON.parse(manifestBytes.toString('utf8'));
const files = [];
function walk(current) {
  for (const entry of fs.readdirSync(current, {withFileTypes: true})) {
    const absolute = path.join(current, entry.name);
    if (entry.isDirectory()) walk(absolute);
    else if (entry.isFile()) files.push(path.relative(packageRoot, absolute));
  }
}
walk(packageRoot);
files.sort();
const digest = crypto.createHash('sha256');
for (const relative of files) {
  digest.update(relative); digest.update('\0');
  digest.update(fs.readFileSync(path.join(packageRoot, relative))); digest.update('\0');
}
process.stdout.write(JSON.stringify({
  name: manifest.name,
  version: manifest.version,
  manifestSha256: crypto.createHash('sha256').update(manifestBytes).digest('hex'),
  contentSha256: digest.digest('hex'),
  fileCount: files.length,
}));
"""
    try:
        completed = subprocess.run(
            ["docker", "exec", "mte-paperclip", "node", "-e", script, package_name],
            check=True,
            text=True,
            capture_output=True,
        )
        value = json.loads(completed.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise ControlError(
            "plugin_package_unverifiable", "cannot hash installed Daytona plugin"
        ) from exc
    if (
        not isinstance(value, dict)
        or value.get("name") != package_name
        or not re.fullmatch(r"[a-f0-9]{64}", str(value.get("manifestSha256", "")))
        or not re.fullmatch(r"[a-f0-9]{64}", str(value.get("contentSha256", "")))
        or int(value.get("fileCount", 0)) < 1
    ):
        raise ControlError(
            "plugin_package_unverifiable", "installed Daytona plugin proof is invalid"
        )
    return value


def ensure_daytona_plugin(
    base: str,
    package_name: str,
    manifest_version: str,
    package_version: str,
) -> dict[str, Any]:
    plugin = plugin_match(plugin_rows(base), package_name)
    observed_version = str((plugin or {}).get("version", ""))
    state = str((plugin or {}).get("status", "")).lower()
    installed_package_version = ""
    if plugin:
        try:
            installed_package_version = str(
                installed_plugin_package_proof(package_name).get("version", "")
            )
        except ControlError as exc:
            if exc.code != "plugin_package_unverifiable":
                raise
    package_current = (
        bool(plugin)
        and observed_version == manifest_version
        and (installed_package_version == package_version)
    )
    if plugin and package_current and state in {"error", "failed", "disabled"}:
        plugin_key = str(plugin.get("pluginKey", ""))
        if not plugin_key:
            raise ControlError(
                "plugin_identity_invalid", "Paperclip Daytona plugin key is missing"
            )
        json_request(
            base,
            "POST",
            "/api/plugins/" + urllib.parse.quote(plugin_key, safe="") + "/enable",
            {},
            timeout=180,
        )
    elif plugin and not package_current:
        plugin_key = str(plugin.get("pluginKey", ""))
        if not plugin_key:
            raise ControlError(
                "plugin_identity_invalid", "Paperclip Daytona plugin key is missing"
            )
        json_request(
            base,
            "DELETE",
            "/api/plugins/" + urllib.parse.quote(plugin_key, safe="") + "?purge=true",
            timeout=180,
        )
        plugin = None
    if not plugin:
        json_request(
            base,
            "POST",
            "/api/plugins/install",
            {
                "packageName": package_name,
                "version": package_version,
                "isLocalPath": False,
            },
            timeout=180,
        )
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        plugin = plugin_match(plugin_rows(base), package_name)
        state = str((plugin or {}).get("status", "")).lower()
        if plugin and state not in {
            "installing",
            "pending",
            "error",
            "failed",
            "disabled",
        }:
            return plugin
        if state in {"error", "failed"}:
            break
        time.sleep(2)
    raise ControlError(
        "plugin_not_ready", "Paperclip Daytona plugin did not become ready"
    )


def reconcile_daytona(*, mutate: bool, probe: bool) -> dict[str, Any]:
    _, experimental = settings()
    spec = experimental.get("daytona", {})
    if not isinstance(spec, dict) or spec.get("enabled") is not True:
        raise ControlError(
            "feature_disabled", "Daytona is not enabled in the platform manifest"
        )
    base, company_id = paperclip_context()
    environment_capabilities(base, company_id)
    strict_mode = strict_mode_state()
    if not all(strict_mode.values()):
        raise ControlError(
            "strict_mode_disabled", "Paperclip runtime strict secret mode is disabled"
        )
    providers = rows(
        json_request(
            base,
            "GET",
            f"/api/companies/{urllib.parse.quote(company_id)}/secret-providers",
        ),
        "providers",
        "items",
        "data",
    )
    if not any(str(row.get("id")) == "local_encrypted" for row in providers):
        raise ControlError(
            "secret_provider_unavailable",
            "Paperclip local_encrypted secret provider is unavailable",
        )
    company_secrets = rows(
        json_request(
            base,
            "GET",
            f"/api/companies/{urllib.parse.quote(company_id)}/secrets",
        ),
        "secrets",
        "items",
        "data",
    )

    values = dotenv(PLATFORM_ENV)
    package_name = values.get(
        "MTE_DAYTONA_PLUGIN_PACKAGE",
        str(spec.get("pluginPackage", "@paperclipai/plugin-daytona")),
    )
    manifest_version = values.get(
        "MTE_DAYTONA_PLUGIN_MANIFEST_VERSION",
        str(spec.get("pluginVersion", "0.1.0")),
    )
    package_version = values.get("MTE_DAYTONA_PLUGIN_NPM_VERSION", "")
    if not package_version:
        raise ControlError(
            "missing_canonical_config",
            "MTE_DAYTONA_PLUGIN_NPM_VERSION is required",
        )
    plugin = plugin_match(plugin_rows(base), package_name)
    if mutate:
        plugin = ensure_daytona_plugin(
            base,
            package_name,
            manifest_version,
            package_version,
        )
    if not plugin:
        raise ControlError(
            "plugin_missing", "Paperclip Daytona plugin is not installed"
        )
    package_proof = installed_plugin_package_proof(package_name)
    if (
        str(plugin.get("version", "")) != manifest_version
        or package_proof.get("version") != package_version
    ):
        raise ControlError(
            "plugin_version_drift", "Daytona plugin package or manifest version drifted"
        )

    api_key_ref = str(spec.get("apiKeyRef", "DAYTONA_API_KEY"))
    api_key = values.get(api_key_ref, "")
    secret_name = str(spec.get("secretName", "mte-daytona-api-key"))
    daytona_secret = find_named(company_secrets, secret_name)
    key_fingerprint = fingerprint(api_key) if api_key else ""
    if mutate:
        daytona_secret, key_fingerprint = ensure_company_secret(
            base,
            company_id,
            name=secret_name,
            value=api_key,
        )
    if not daytona_secret:
        raise ControlError(
            "needs_authorization",
            f"credential reference {api_key_ref} is not provisioned",
        )
    # Refresh after a mutating create/rotate so the scope proof is based on the
    # observed company inventory rather than the mutation response.
    if mutate:
        company_secrets = rows(
            json_request(
                base,
                "GET",
                f"/api/companies/{urllib.parse.quote(company_id)}/secrets",
            ),
            "secrets",
            "items",
            "data",
        )
        daytona_secret = find_named(company_secrets, secret_name)
        if not daytona_secret:
            raise ControlError(
                "secret_missing", "Daytona API key secret disappeared after reconcile"
            )

    environment_name = values.get(
        "MTE_DAYTONA_ENVIRONMENT_NAME",
        str(spec.get("environmentName", "MTE Daytona Coding")),
    )
    image = values.get("MTE_DAYTONA_CODING_IMAGE") or values.get(
        "MTE_DAYTONA_SANDBOX_BASE_IMAGE", ""
    )
    if not image:
        raise ControlError(
            "missing_canonical_config",
            "canonical Daytona coding image is not configured",
        )
    memory_gib = int(values.get("MTE_DAYTONA_CODING_MEMORY_GIB", ""))
    disk_gib = int(values.get("MTE_DAYTONA_DISK_GIB", ""))
    timeout_ms = int(values.get("MTE_DAYTONA_TIMEOUT_MS", ""))
    reuse_lease = values.get("MTE_DAYTONA_REUSE_LEASE", "").lower() == "true"
    snapshot_name = values.get("MTE_DAYTONA_CODING_SNAPSHOT", "")
    snapshot_ready = values.get(
        "MTE_DAYTONA_CODING_SNAPSHOT_READY", ""
    ).lower() == "true" and bool(snapshot_name)
    environment = find_named(environment_list(base, company_id), environment_name)
    driver_config: dict[str, Any] = {
        "provider": "daytona",
        # Paperclip sandbox-provider secret-ref fields persist the existing
        # company secret UUID as a string. Object refs are only used by SSH's
        # dedicated privateKeySecretRef envelope.
        "apiKey": str(daytona_secret["id"]),
        "timeoutMs": timeout_ms,
        "reuseLease": reuse_lease,
    }
    if snapshot_ready:
        driver_config["snapshot"] = snapshot_name
    else:
        driver_config.update({"image": image, "memory": memory_gib, "disk": disk_gib})
    for config_key, ref_key in (("apiUrl", "apiUrlRef"), ("target", "targetRef")):
        ref = str(spec.get(ref_key, ""))
        if ref and values.get(ref):
            driver_config[config_key] = values[ref]
    payload = {
        "name": environment_name,
        "description": "Managed Daytona sandbox environment for coding agents.",
        "driver": "sandbox",
        "status": "active",
        "config": driver_config,
        "metadata": {"managedBy": "mte-platform", "purpose": "coding-daytona"},
    }
    if mutate:
        if environment:
            environment = json_request(
                base,
                "PATCH",
                environment_mutation_path(str(environment["id"]), company_id),
                payload,
            )
        else:
            environment = json_request(
                base,
                "POST",
                f"/api/companies/{urllib.parse.quote(company_id)}/environments",
                payload,
            )
    if not isinstance(environment, dict) or not environment.get("id"):
        raise ControlError(
            "environment_missing", "managed Daytona environment is missing"
        )
    environment_id = str(environment["id"])
    observed_config = environment.get("config")
    if (
        not isinstance(observed_config, dict)
        or observed_config.get("provider") != "daytona"
    ):
        raise ControlError(
            "environment_drift", "Daytona environment driver config has drifted"
        )
    # The sandbox provider persists its own lifecycle defaults and nullable
    # resource fields alongside the submitted config.  Compare the complete
    # MTE-owned driver contract instead of rejecting those provider-owned
    # fields as drift.
    canonical_driver = normalized_driver_config(driver_config)
    observed_driver = normalized_driver_config(observed_config)
    if observed_driver != canonical_driver:
        raise ControlError(
            "environment_drift",
            "Daytona driver config does not exactly match canonical config",
        )

    profile_catalog = DEFAULT_PROFILE_CATALOG
    required_profiles = profile_catalog.refs
    managed_agents = [
        agent
        for agent in agent_list(base, company_id)
        if isinstance(agent.get("metadata"), dict)
        and str(agent["metadata"].get("profileRef")) in required_profiles
    ]
    profile_counts = {
        profile_ref: sum(
            str(agent["metadata"].get("profileRef")) == profile_ref
            for agent in managed_agents
        )
        for profile_ref in required_profiles
    }
    if any(count != 1 for count in profile_counts.values()):
        raise ControlError(
            "coding_profile_duplicate",
            "Paperclip must expose exactly one agent for each Daytona profile",
        )
    agents_by_profile = {
        str(agent.get("metadata", {}).get("profileRef")): agent
        for agent in managed_agents
    }
    missing_profiles = [
        ref for ref in required_profiles if ref not in agents_by_profile
    ]
    if missing_profiles:
        raise ControlError(
            "coding_profile_missing",
            "Paperclip profiles are not bootstrapped: " + ", ".join(missing_profiles),
        )
    reconciled_agents: list[dict[str, Any]] = []
    for profile_ref in required_profiles:
        profile = profile_catalog.require(profile_ref)
        runtime = profile["runtimeContract"]
        access = profile["toolAccess"]
        topology = profile["topology"]
        wrong_profile = profile_catalog.require(str(topology["wrongProfileRef"]))
        package_key = str(runtime["packageKey"])
        harness_version = catalog_value(profile["runtimePackages"][package_key], values)
        agent = agents_by_profile[profile_ref]
        if mutate and str(agent.get("defaultEnvironmentId", "")) != environment_id:
            agent = json_request(
                base,
                "PATCH",
                f"/api/agents/{urllib.parse.quote(str(agent['id']))}",
                {"defaultEnvironmentId": environment_id},
            )
        if not isinstance(agent, dict) or not agent.get("id"):
            raise ControlError(
                "coding_profile_missing", f"{profile_ref} Paperclip agent is missing"
            )
        if str(agent.get("defaultEnvironmentId", "")) != environment_id:
            raise ControlError(
                "coding_profile_drift", f"{profile_ref} is not bound to Daytona"
            )
        if str(agent.get("adapterType", "")) != catalog_value(
            runtime["adapterType"], values
        ):
            raise ControlError(
                "coding_profile_drift", f"{profile_ref} native adapter type drifted"
            )
        if not harness_version:
            raise ControlError(
                "missing_canonical_config", f"{profile_ref} harness version is missing"
            )
        adapter_config = agent.get("adapterConfig")
        if not isinstance(adapter_config, dict):
            raise ControlError(
                "coding_profile_drift", f"{profile_ref} has no adapter config"
            )
        if str(adapter_config.get("cwd", "")) != str(
            profile["nativeAdapterConfig"]["cwd"]
        ):
            raise ControlError(
                "coding_profile_drift", f"{profile_ref} has a non-Daytona workspace cwd"
            )
        env = adapter_config.get("env")
        validate_profile_env_contract(
            profile_ref=profile_ref,
            company_id=company_id,
            agent_id=str(agent["id"]),
            env=env,
            required_keys=set(runtime["envAllowlist"]),
            provider_managed_env=runtime["providerManagedEnv"],
        )
        runtime_ref = env.get(runtime["runtimeSecretEnv"])
        gh_ref = env.get("GH_TOKEN")
        github_ref = env.get("GITHUB_TOKEN")
        toolhive_ref = env.get("MTE_TOOLHIVE_BEARER_TOKEN")
        toolhive_url_ref = str(access["endpointRef"])
        toolhive_url = env.get(toolhive_url_ref)
        wrong_toolhive_url_ref = str(wrong_profile["toolAccess"]["endpointRef"])
        wrong_toolhive_url = env.get("MTE_TOOLHIVE_WRONG_PROFILE_MCP_URL")
        suffix = profile_ref.upper().replace("-", "_")
        expected_router_secret_id = values.get(
            f"PAPERCLIP_SECRET_MTE_9ROUTER_PROFILE_{suffix}_ID", ""
        )
        expected_toolhive_secret_id = values.get(
            f"PAPERCLIP_SECRET_MTE_TOOLHIVE_PROFILE_{suffix}_BEARER_ID", ""
        )
        if (
            not isinstance(runtime_ref, dict)
            or runtime_ref.get("type") != "secret_ref"
            or not runtime_ref.get("secretId")
            or runtime_ref.get("secretId") != expected_router_secret_id
            or not isinstance(github_ref, dict)
            or github_ref.get("type") != "user_secret_ref"
            or github_ref.get("key") != "mte.github.personal_access_token"
            or not isinstance(gh_ref, dict)
            or gh_ref.get("type") != "user_secret_ref"
            or gh_ref.get("key") != "mte.github.personal_access_token"
            or gh_ref != github_ref
            or not isinstance(toolhive_ref, dict)
            or toolhive_ref.get("type") != "secret_ref"
            or not toolhive_ref.get("secretId")
            or toolhive_ref.get("secretId") != expected_toolhive_secret_id
            or not isinstance(toolhive_url, dict)
            or toolhive_url.get("type") != "plain"
            or toolhive_url.get("value") != values.get(toolhive_url_ref)
            or not isinstance(wrong_toolhive_url, dict)
            or wrong_toolhive_url.get("type") != "plain"
            or wrong_toolhive_url.get("value") != values.get(wrong_toolhive_url_ref)
            or (env.get("MTE_TOOLHIVE_ENDPOINT_REF") or {}).get("value")
            != toolhive_url_ref
            or (env.get("MTE_TOOLHIVE_BINDING_REF") or {}).get("value")
            != access["credentialRef"]
            or (env.get("MTE_TOOLHIVE_BUNDLE_ID") or {}).get("value")
            != access["bundleId"]
            or (env.get("MTE_TOOLHIVE_WORKLOAD_ID") or {}).get("value")
            != access["workloadId"]
            or (env.get("MTE_TOOLHIVE_CANARY_TOOL") or {}).get("value")
            != access["canaryTool"]
        ):
            raise ControlError(
                "coding_profile_env_drift", f"{profile_ref} secret refs are invalid"
            )
        reconciled_agents.append(
            {
                "profileRef": profile_ref,
                "agentId": str(agent["id"]),
                "harnessKind": runtime["harnessKind"],
                "adapterType": str(agent.get("adapterType", "")),
                "protocol": runtime["protocol"],
                "harnessVersion": harness_version,
                "routerKeyRef": profile["llmRouting"]["apiKeyRef"],
                "cwd": str(adapter_config["cwd"]),
                "envKeys": sorted(env),
                "runtimeSecretBinding": "paperclip_company_secret_ref",
                "runtimeSecretId": str(runtime_ref["secretId"]),
                "githubBinding": "paperclip_user_secret_ref",
                "githubDefinitionKey": "mte.github.personal_access_token",
                "githubCliEnv": "GH_TOKEN",
                "toolhiveSecretBinding": "paperclip_company_secret_ref",
                "toolhiveSecretId": str(toolhive_ref["secretId"]),
                "toolhiveUrlRef": toolhive_url_ref,
                "status": "ready",
            }
        )

    if len({row["agentId"] for row in reconciled_agents}) != len(required_profiles):
        raise ControlError(
            "coding_profile_duplicate", "Daytona profile agent IDs must be distinct"
        )

    secret_scope = validate_company_secret_scopes(
        company_secrets,
        company_id=company_id,
        daytona_secret_id=str(daytona_secret["id"]),
        profile_bindings=reconciled_agents,
    )
    secret_scope["strictMode"] = strict_mode
    secret_scope["nativeAuthHomesCredentialFree"] = None
    secret_scope["credentialFileProbe"] = None

    template_state = "disabled"
    if spec.get("customImageLifecycle") is True:
        # Daytona's native Snapshot API builds the pinned image. Finishing an
        # empty Paperclip interactive setup session would capture a sandbox
        # without the required harness CLIs, so that route is not used here.
        template_state = (
            "active-snapshot" if snapshot_ready else "pending-snapshot-build"
        )

    probe_results: list[dict[str, Any]] = []
    runtime_evidence: dict[str, dict[str, str]] = {}
    probe_cleanup: dict[str, Any] = {
        "baselineSandboxCount": 0,
        "createdSandboxCount": 0,
        "deletedSandboxCount": 0,
        "leakedSandboxCount": 0,
    }
    if probe:
        probe_baseline_ids = daytona_environment_sandbox_ids(values, environment_id)
        probe_cleanup["baselineSandboxCount"] = len(probe_baseline_ids)
        # Environment validation is adapter-specific in Paperclip. Probe each
        # harness binding instead of calling a generic environment endpoint.
        for agent in reconciled_agents:
            adapter_type = str(agent.get("adapterType", ""))
            if not adapter_type:
                raise ControlError(
                    "coding_profile_drift",
                    f"{agent['profileRef']} has no adapter type",
                )
            probe_config, optional_user_secret_count = adapter_environment_probe_config(
                agents_by_profile[str(agent["profileRef"])].get("adapterConfig", {})
            )
            probe_response: Any = None
            probe_accepted = False
            accepted_warning_codes: list[str] = []
            probe_attempts: list[dict[str, Any]] = []
            profile_created_sandbox_ids: set[str] = set()
            for attempt in range(1, ENVIRONMENT_PROBE_ATTEMPTS + 1):
                before_sandbox_ids = daytona_environment_sandbox_ids(
                    values, environment_id
                )
                probe_response = None
                request_error: str | None = None
                try:
                    probe_response = json_request(
                        base,
                        "POST",
                        "/api/companies/"
                        + urllib.parse.quote(company_id)
                        + "/adapters/"
                        + urllib.parse.quote(adapter_type)
                        + "/test-environment",
                        {
                            "adapterConfig": probe_config,
                            "environmentId": environment_id,
                        },
                        timeout=max(360, timeout_ms // 1000 + 60),
                    )
                    (
                        probe_accepted,
                        accepted_warning_codes,
                    ) = accepted_environment_probe(
                        str(agent["profileRef"]), probe_response
                    )
                except ControlError as exc:
                    request_error = exc.code
                    probe_accepted = False
                    accepted_warning_codes = []

                after_sandbox_ids = daytona_environment_sandbox_ids(
                    values, environment_id
                )
                created_sandbox_ids = sorted(
                    after_sandbox_ids - before_sandbox_ids
                )
                profile_created_sandbox_ids.update(created_sandbox_ids)
                # Paperclip marks ad-hoc test leases ephemeral, but a provider
                # with reuseLease=true stops rather than destroys them. Delete
                # only IDs created by this exact attempt, including failed
                # attempts, so retries cannot leak stopped or archived leases.
                for sandbox_id in created_sandbox_ids:
                    destroy_daytona_probe_sandbox(values, sandbox_id)
                probe_attempts.append(
                    environment_probe_observation(
                        probe_response,
                        attempt=attempt,
                        accepted=probe_accepted,
                        warning_codes=accepted_warning_codes,
                        request_error=request_error,
                        deleted_sandbox_count=len(created_sandbox_ids),
                    )
                )
                if probe_accepted:
                    break
                if attempt < ENVIRONMENT_PROBE_ATTEMPTS:
                    time.sleep(ENVIRONMENT_PROBE_RETRY_SECONDS)

            if not probe_accepted:
                observed_codes = sorted(
                    {
                        str(check.get("code", ""))
                        for row in probe_attempts
                        for check in row["checks"]
                        if check.get("code")
                    }
                )
                raise ControlError(
                    "environment_probe_failed",
                    f"{agent['profileRef']} environment probe did not pass; "
                    + "observed codes: "
                    + (",".join(observed_codes) or "none"),
                )
            probe_cleanup["createdSandboxCount"] += len(
                profile_created_sandbox_ids
            )
            probe_cleanup["deletedSandboxCount"] += len(
                profile_created_sandbox_ids
            )
            probe_results.append(
                {
                    "profileRef": str(agent["profileRef"]),
                    "adapterType": adapter_type,
                    "status": "passed",
                    "upstreamStatus": str(probe_response.get("status", "")),
                    "acceptedWarningCodes": accepted_warning_codes,
                    "attemptCount": len(probe_attempts),
                    "attempts": probe_attempts,
                    "probeSandboxesDeleted": len(profile_created_sandbox_ids),
                    "optionalUserSecretBindingCount": optional_user_secret_count,
                }
            )
        runtime_evidence = {
            "controlPlane": evidence_reference(
                EVIDENCE_ROOT / "paperclip-daytona-control-plane.json",
                "PaperclipDaytonaControlPlaneEvidence",
                values=values,
            ),
            "images": evidence_reference(
                EVIDENCE_ROOT / "daytona-images.json",
                "DaytonaHarnessSnapshots",
                values=values,
            ),
            "lifecycle": evidence_reference(
                EVIDENCE_ROOT / "daytona-lifecycle.json",
                "DaytonaSandboxLifecycleEvidence",
                values=values,
            ),
        }
        lifecycle_payload = load_json(EVIDENCE_ROOT / "daytona-lifecycle.json")
        credential_probe = lifecycle_payload["credentialFileProbe"]
        secret_scope["nativeAuthHomesCredentialFree"] = True
        secret_scope["credentialFileProbe"] = credential_probe
        remaining_ids = daytona_environment_sandbox_ids(values, environment_id)
        leaked_ids = remaining_ids - probe_baseline_ids
        probe_cleanup["leakedSandboxCount"] = len(leaked_ids)
        probe_cleanup["baselinePreserved"] = remaining_ids == probe_baseline_ids
        if leaked_ids or remaining_ids != probe_baseline_ids:
            raise ControlError(
                "probe_cleanup_failed", "adapter probes left Daytona sandbox drift"
            )
    else:
        probe_baseline_ids = set()
        remaining_ids = set()

    plugin_record = {
        "package": package_name,
        "manifestVersion": manifest_version,
        "manifestSha256": package_proof["manifestSha256"],
        "packageVersion": package_proof["version"],
        "contentSha256": package_proof["contentSha256"],
        "fileCount": package_proof["fileCount"],
        "pluginKey": str(plugin.get("pluginKey", "paperclip.daytona-sandbox-provider")),
        "status": str(plugin.get("status", "ready")),
    }
    return {
        "companyId": company_id,
        "plugin": {
            **plugin_record,
            "installedVersion": package_proof["version"],
            "recordSha256": canonical_json_sha256(plugin_record),
        },
        "environmentId": environment_id,
        "environmentDriver": "sandbox",
        "profileRefs": list(required_profiles),
        "agents": reconciled_agents,
        "provider": "daytona",
        "image": image,
        "snapshot": snapshot_name if snapshot_ready else None,
        "apiKeySecretId": str(daytona_secret["id"]),
        "apiKeyFingerprint": key_fingerprint or "stored",
        "driverConfig": {
            "canonical": canonical_driver,
            "observed": observed_driver,
            "matchesCanonical": observed_driver == canonical_driver,
            "apiKeySecretIdMatches": observed_config.get("apiKey")
            == str(daytona_secret["id"]),
            "apiUrlMatches": observed_config.get("apiUrl")
            == driver_config.get("apiUrl"),
            "targetMatches": observed_config.get("target")
            == driver_config.get("target"),
            "snapshotMatches": observed_config.get("snapshot")
            == driver_config.get("snapshot"),
            "timeoutMatches": observed_config.get("timeoutMs") == timeout_ms,
            "reusePolicyMatches": observed_config.get("reuseLease") == reuse_lease,
            "provider": observed_config["provider"],
            "apiKeySecretId": observed_config["apiKey"],
            "apiUrl": observed_config.get("apiUrl"),
            "target": observed_config.get("target"),
            "snapshot": observed_config.get("snapshot"),
            "image": observed_config.get("image"),
            "memory": observed_config.get("memory"),
            "disk": observed_config.get("disk"),
            "timeoutMs": observed_config.get("timeoutMs"),
            "reuseLease": observed_config.get("reuseLease"),
            "canonicalSha256": canonical_json_sha256(canonical_driver),
            "observedSha256": canonical_json_sha256(observed_driver),
        },
        "secretScope": secret_scope,
        "customImageTemplate": template_state,
        "probe": "passed" if probe_results else "not-run",
        "probeResults": probe_results,
        "probeCleanup": probe_cleanup,
        "probeSandboxIdsBefore": sorted(probe_baseline_ids),
        "probeSandboxIdsAfter": sorted(remaining_ids),
        "runtimeEvidence": runtime_evidence,
        "canonicalConfigHash": hashlib.sha256(PLATFORM_ENV.read_bytes()).hexdigest(),
    }


def run_feature(feature: str, action: str) -> dict[str, Any]:
    mutate = action == "apply"
    if feature == "environments":
        return reconcile_local_environment(mutate=mutate)
    if feature == "secrets":
        return reconcile_secrets(mutate=mutate)
    if feature == "daytona":
        return reconcile_daytona(mutate=mutate, probe=action == "verify")
    raise ControlError("unknown_feature", f"unknown feature {feature}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("feature", choices=("environments", "secrets", "daytona"))
    parser.add_argument("action", choices=("apply", "status", "verify"))
    args = parser.parse_args()
    try:
        details = run_feature(args.feature, args.action)
    except ControlError as exc:
        state = (
            "blocked"
            if exc.code in {"needs_authorization", "runtime_upgrade_required"}
            else "failed"
        )
        emit(
            args.feature, args.action, state, {"reason": exc.code, "message": str(exc)}
        )
        raise SystemExit(2 if state == "blocked" else 1) from exc
    emit(args.feature, args.action, "ready", details)


if __name__ == "__main__":
    main()

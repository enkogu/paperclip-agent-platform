#!/usr/bin/env python3
"""Produce fail-closed C019 state and validate runner-origin C010 evidence.

ToolHive runtime groups are bundles, not identities. The pinned single-host
Docker/CLI deployment has no reviewed incoming OIDC configuration. Profile
identity is therefore enforced by the private MTE agent-plane gateway with one
runtime bearer ref per profile. C010 is never marked passed from a root-side
ToolHive call: it requires a Daytona-origin E2E subject proving initialize,
tools/list, a read-only echo call, and denial with the same credential at a
different profile endpoint.

The profile catalog also owns the Notion tool boundary. Coding harnesses get a
ToolHive-enforced read-only allow-list; Notion mutations remain exclusive to
the separate ``mte.notion.connector`` executable. PostgreSQL/PostgREST writes
remain available to agents and do not traverse Notion.

The Kestra portion is deliberately a payload builder only. Until a separate
owner applies and reads back that KV payload, C019 evidence remains
``prepared`` rather than pretending that the cross-plane reconcile passed.
"""

from __future__ import annotations

from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any
import urllib.request


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
CANONICAL = SECRET_ROOT / "platform.env"
PROFILES_SOURCE = ROOT / "templates/profiles/profiles.yaml"
PROFILES = ROOT / "runtime/profiles/profiles.yaml"
EVIDENCE = ROOT / "evidence/profile-reconcile.json"
ACCESS_EVIDENCE = ROOT / "evidence/profile-access.json"
RUNNER_E2E_EVIDENCE = ROOT / "evidence/kestra-paperclip-github-e2e.json"
KESTRA_VERIFY_EVIDENCE = ROOT / "evidence/kestra-reconcile-verify.json"
DEFAULT_CATALOG = load_profile_catalog(default_catalog_path(runtime_first=False))
REQUIRED = DEFAULT_CATALOG.refs
HARNESS = {
    ref: str(profile["runtimeContract"]["harnessKind"]).upper()
    for ref, profile in DEFAULT_CATALOG.by_ref.items()
}
WRONG_PROFILE = {
    ref: str(profile["topology"]["wrongProfileRef"])
    for ref, profile in DEFAULT_CATALOG.by_ref.items()
}
MANAGED_BY = "profile-reconciler"
GROUP_PREFIX = "mte-profile-"
KESTRA_NAMESPACE = "mte.platform"
KESTRA_CATALOG_KEY = "mte.profile.catalog"
SHA_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SENSITIVE_KEY_PATTERN = re.compile(
    r"PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIAL|AUTH|WEBHOOK",
    re.IGNORECASE,
)
_POLICY_REFS = {
    str(profile["toolAccess"]["toolPolicyRef"]) for profile in DEFAULT_CATALOG.profiles
}
if len(_POLICY_REFS) != 1:
    raise CatalogError("profile_tool_policy_ref_set_invalid")
TOOL_POLICY_REF = next(iter(_POLICY_REFS))
_DEFAULT_POLICY = DEFAULT_CATALOG.document.get("toolPolicies", {}).get(TOOL_POLICY_REF)
if not isinstance(_DEFAULT_POLICY, dict):
    raise CatalogError("profile_tool_policy_missing")
_NOTION_ACCESS = _DEFAULT_POLICY.get("notionAgentAccess")
if not isinstance(_NOTION_ACCESS, dict):
    raise CatalogError("profile_notion_policy_missing")
_NOTION_REGISTRY = _NOTION_ACCESS.get("registry")
if not isinstance(_NOTION_REGISTRY, dict):
    raise CatalogError("profile_notion_registry_missing")
NOTION_REGISTRY_PACKAGE = str(_NOTION_REGISTRY.get("package") or "")
NOTION_REGISTRY_IMAGE = str(_NOTION_REGISTRY.get("registryImage") or "")
NOTION_REPOSITORY_URL = str(_NOTION_REGISTRY.get("repositoryUrl") or "")
NOTION_API_VERSION = str(_NOTION_REGISTRY.get("apiVersion") or "")
NOTION_SECRET_REF = str(_NOTION_REGISTRY.get("secretRef") or "")
NOTION_IMAGE = str(_NOTION_REGISTRY.get("pinnedImage") or "")
NOTION_AGENT_READ_TOOLS = tuple(_NOTION_ACCESS.get("allowedTools") or ())
NOTION_WRITE_TOOLS = tuple(_NOTION_ACCESS.get("deniedTools") or ())
NOTION_TOOLS = tuple((*NOTION_AGENT_READ_TOOLS, *NOTION_WRITE_TOOLS))
TOOLHIVE_RUNTIME_HOST = "127.0.0.1"
TOOLHIVE_RUNTIME_ROOT = "/opt/mte-platform/toolhive/tmp/profile-reconcile"
NOTION_PERMISSION_PROFILE_PATH = TOOLHIVE_RUNTIME_ROOT + "/notion-egress.json"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def dotenv(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise RuntimeError("canonical_platform_env_missing")
    return dict(
        line.split("=", 1)
        for line in path.read_text().splitlines()
        if line and not line.startswith("#") and "=" in line
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def profile_catalog_semantic_sha256(document: dict[str, Any]) -> str:
    return semantic_sha256(document)


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def secure_evidence(path: Path) -> bool:
    try:
        info = path.stat()
    except OSError:
        return False
    owner_valid = os.geteuid() != 0 or (info.st_uid == 0 and info.st_gid == 0)
    return not path.is_symlink() and stat.S_IMODE(info.st_mode) == 0o600 and owner_valid


def fresh_timestamp(value: Any, max_age_seconds: int = 3600) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        return False
    age = (datetime.now(timezone.utc) - parsed).total_seconds()
    return -60 <= age <= max_age_seconds


def run(
    argv: list[str],
    *,
    check: bool = True,
    input_text: str | None = None,
    timeout: int = 240,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError("profile_reconcile_command_failed")
    return result


def request_json(url: str, *, headers: dict[str, str] | None = None) -> Any:
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", **(headers or {})}
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        raw = response.read(4_000_000)
        return json.loads(raw) if raw else None


def service_container(service: str) -> str:
    rows = run(
        [
            "docker",
            "ps",
            "-q",
            "--filter",
            f"label=com.docker.compose.service={service}",
        ]
    ).stdout.splitlines()
    if len(rows) != 1:
        raise RuntimeError(f"toolhive_{service}_not_unique")
    return rows[0]


def manager() -> str:
    return service_container("toolhive")


def assert_manager_not_oom_killed(target: str) -> None:
    result = run(
        ["docker", "inspect", target, "--format", "{{.State.OOMKilled}}"],
        check=False,
    )
    state = result.stdout.strip().lower()
    if result.returncode != 0 or state not in {"true", "false"}:
        raise RuntimeError("toolhive_manager_state_unreadable")
    if state == "true":
        raise RuntimeError("toolhive_manager_oom_killed")


def toolhive_runtime() -> str:
    return service_container("tool-runtime")


def thv(target: str, *args: str, **kwargs) -> subprocess.CompletedProcess[str]:
    return run(["docker", "exec", "-i", target, "thv", *args], **kwargs)


def expected_tool_policy() -> dict[str, Any]:
    """Return the source catalog policy, including its locked registry contract."""
    source = (
        PROFILES_SOURCE
        if PROFILES_SOURCE.is_file()
        else default_catalog_path(runtime_first=False)
    )
    loaded = load_profile_catalog(source)
    policies = loaded.document.get("toolPolicies")
    policy = policies.get(TOOL_POLICY_REF) if isinstance(policies, dict) else None
    if not isinstance(policy, dict):
        raise RuntimeError("profile_tool_policy_missing")
    return copy.deepcopy(policy)


def tool_policy(document: dict[str, Any]) -> dict[str, Any]:
    policies = document.get("toolPolicies")
    if not isinstance(policies, dict) or set(policies) != {TOOL_POLICY_REF}:
        raise RuntimeError("profile_tool_policy_set_invalid")
    policy = policies.get(TOOL_POLICY_REF)
    if not isinstance(policy, dict) or policy != expected_tool_policy():
        raise RuntimeError("profile_tool_policy_drift")
    if set(NOTION_AGENT_READ_TOOLS) & set(NOTION_WRITE_TOOLS):
        raise RuntimeError("profile_notion_tool_policy_overlap")
    if set(NOTION_AGENT_READ_TOOLS) | set(NOTION_WRITE_TOOLS) != set(NOTION_TOOLS):
        raise RuntimeError("profile_notion_tool_policy_incomplete")
    return policy


def catalog() -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    try:
        loaded = load_profile_catalog(PROFILES, require_rendered=True)
    except CatalogError as exc:
        raise RuntimeError(str(exc)) from exc
    policy = tool_policy(loaded.document)
    rows = list(loaded.profiles)
    if any(
        not isinstance(row.get("toolAccess"), dict)
        or row["toolAccess"].get("toolPolicyRef") != TOOL_POLICY_REF
        for row in rows
    ):
        raise RuntimeError("profile_tool_policy_ref_invalid")
    return rows, loaded.semantic_sha256, policy


def valid_port(values: dict[str, str], key: str) -> int:
    value = values.get(key, "")
    if not value.isdigit() or not 1024 <= int(value) <= 65535:
        raise RuntimeError("profile_toolhive_port_invalid")
    return int(value)


def desired(
    rows: list[dict[str, Any]],
    values: dict[str, str],
    policy: dict[str, Any],
) -> list[dict[str, Any]]:
    if policy != expected_tool_policy():
        raise RuntimeError("profile_tool_policy_drift")
    agent_tools = list(policy["notionAgentAccess"]["allowedTools"])
    denied_tools = list(policy["notionAgentAccess"]["deniedTools"])
    connector = policy["notionWriteConnector"]
    canary_image = values.get("TOOLHIVE_CANARY_IMAGE", "")
    notion_image = values.get("TOOLHIVE_NOTION_IMAGE", "")
    notion_token = values.get(NOTION_SECRET_REF, "")
    if "@sha256:" not in canary_image:
        raise RuntimeError("profile_toolhive_image_not_pinned")
    if notion_image != NOTION_IMAGE:
        raise RuntimeError("profile_notion_image_not_pinned")
    if not notion_token or notion_token != notion_token.strip() or "\n" in notion_token:
        raise RuntimeError("profile_notion_token_missing_or_invalid")

    specs: list[dict[str, Any]] = []
    all_ports: list[int] = []
    profiles_by_ref = {str(profile["ref"]): profile for profile in rows}
    for profile in rows:
        ref = str(profile["ref"])
        runtime = profile["runtimeContract"]
        topology = profile["topology"]
        wrong_profile = profiles_by_ref[str(topology["wrongProfileRef"])]
        access = profile.get("toolAccess")
        routing = profile.get("toolRouting")
        if not isinstance(access, dict) or not isinstance(routing, dict):
            raise RuntimeError("profile_tool_access_missing")
        bundle_id = str(access["bundleId"])
        identity_workload_id = str(access["workloadId"])
        notion_workload_id = str(access["notionWorkloadId"])
        endpoint_ref = str(access["endpointRef"])
        credential_ref = str(access["credentialRef"])
        expected = {
            "toolPolicyRef": TOOL_POLICY_REF,
            "bundleId": bundle_id,
            "workloadId": identity_workload_id,
            "endpointRef": endpoint_ref,
            "credentialRef": credential_ref,
            "canaryTool": "echo",
            "paperclipProfileRef": ref,
            "kestraCatalogKey": KESTRA_CATALOG_KEY,
            "identityMode": "mte_gateway_profile_bearer",
            "identityEnforcer": "mte-agent-plane-gateway",
            "wrongProfileEndpointRef": wrong_profile["toolAccess"]["endpointRef"],
            "nativeToolHiveOidcConfigured": False,
            "groupActsAsIdentity": False,
            "aggregateMode": "toolhive-vmcp",
            "aggregateWorkloadIds": [identity_workload_id, notion_workload_id],
            "notionWorkloadId": notion_workload_id,
            "notionRegistryPackage": NOTION_REGISTRY_PACKAGE,
            "notionSecretRef": NOTION_SECRET_REF,
            "notionApiVersion": NOTION_API_VERSION,
            "notionToolCount": len(agent_tools),
            "notionRegistryToolCount": len(NOTION_TOOLS),
            "notionAccessMode": "read_only",
            "notionRawCredentialInHarness": False,
            "notionWriteConnectorIdentity": connector["identity"],
            "capabilities": [
                "canary.echo",
                "notion.tables.read",
                "notion.documents.read",
            ],
        }
        if any(access.get(key) != value for key, value in expected.items()):
            raise RuntimeError("profile_tool_access_contract_drift")
        expected_server = {
            "id": f"{ref}-tools",
            "endpointRef": endpoint_ref,
            "credentialRef": credential_ref,
            "transport": "streamable-http",
            "aggregation": "toolhive-vmcp",
            "workloadRefs": [identity_workload_id, notion_workload_id],
            "capabilities": [
                "canary.echo",
                "notion.tables.read",
                "notion.documents.read",
            ],
        }
        if (
            routing.get("provider") != "toolhive"
            or routing.get("mcpUrlRef") != endpoint_ref
            or routing.get("bearerTokenRef") != credential_ref
            or routing.get("servers") != [expected_server]
        ):
            raise RuntimeError("profile_tool_routing_contract_drift")

        aggregate_port = valid_port(values, str(topology["toolhiveProxyPortRef"]))
        identity_port = valid_port(values, str(topology["toolhiveIdentityPortRef"]))
        notion_port = valid_port(values, str(topology["toolhiveNotionPortRef"]))
        all_ports.extend((aggregate_port, identity_port, notion_port))
        identity_workload = {
            "role": "identity-canary",
            "workloadId": identity_workload_id,
            "proxyPort": identity_port,
            "image": canary_image,
            "tools": ["echo"],
            "secretRef": "",
        }
        notion_workload = {
            "role": "notion-readonly",
            "workloadId": notion_workload_id,
            "proxyPort": notion_port,
            "image": notion_image,
            "tools": agent_tools,
            "deniedTools": denied_tools,
            "secretRef": NOTION_SECRET_REF,
            "registryPackage": NOTION_REGISTRY_PACKAGE,
            "apiVersion": NOTION_API_VERSION,
            "egress": {"allowHost": ["api.notion.com"], "allowPort": [443]},
        }
        identity = {
            "profileRef": ref,
            "harnessKind": runtime["harnessKind"],
            "adapterType": runtime["adapterType"],
            "protocol": runtime["protocol"],
            **expected,
            "aggregatePort": aggregate_port,
            "proxyPort": identity_port,
            "image": canary_image,
            "tools": ["echo"],
            "identityWorkload": identity_workload,
            "notionWorkload": notion_workload,
            "aggregateTools": sorted(("echo", *agent_tools)),
            "toolPolicy": {
                "ref": TOOL_POLICY_REF,
                "notionAgentAccess": "read_only",
                "notionWriteConnectorIdentity": connector["identity"],
                "notionWriteConnectorAgentReachable": connector["agentReachable"],
                "postgresWriteAllowed": policy["agentCanonicalWrite"]["allowed"],
            },
            "notionCredentialSha256": sha256_bytes(notion_token.encode()),
        }
        specs.append(
            {
                **identity,
                "bundleSha256": sha256_bytes(canonical_json(identity)),
            }
        )
    if len(set(all_ports)) != len(all_ports):
        raise RuntimeError("profile_toolhive_port_duplicate")
    return specs


def workload_inventory(target: str) -> list[dict[str, Any]]:
    value = json.loads(thv(target, "list", "--all", "--format", "json").stdout or "[]")
    if not isinstance(value, list):
        raise RuntimeError("toolhive_inventory_invalid")
    return [row for row in value if isinstance(row, dict)]


def group_names(target: str) -> set[str]:
    structured = thv(target, "group", "list", "--format", "json", check=False)
    if structured.returncode == 0:
        try:
            value = json.loads(structured.stdout or "[]")
        except json.JSONDecodeError:
            value = None
        if isinstance(value, list):
            return {
                str(row.get("name") if isinstance(row, dict) else row)
                for row in value
                if (isinstance(row, str) and row)
                or (isinstance(row, dict) and row.get("name"))
            }
    rows = thv(target, "group", "list").stdout.splitlines()
    return {row.strip().split()[0] for row in rows[1:] if row.strip()}


def safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def toolhive_label_sha(value: str) -> str:
    if not SHA_PATTERN.fullmatch(value):
        raise RuntimeError("toolhive_label_sha_invalid")
    return value[:63]


def workload_tools_sha(workload: dict[str, Any]) -> str:
    return toolhive_label_sha(sha256_bytes(canonical_json(workload["tools"])))


def docker_exec(
    target: str,
    *args: str,
    check: bool = True,
    input_text: str | None = None,
    timeout: int = 240,
) -> subprocess.CompletedProcess[str]:
    return run(
        ["docker", "exec", "-i", target, *args],
        check=check,
        input_text=input_text,
        timeout=timeout,
    )


def container_file_state(target: str, path: str) -> tuple[str, str] | None:
    result = docker_exec(
        target,
        "sh",
        "-c",
        'test -f "$1" && printf "%s %s" "$(stat -c %a "$1")" '
        '"$(sha256sum "$1" | cut -d" " -f1)"',
        "sh",
        path,
        check=False,
    )
    if result.returncode != 0:
        return None
    parts = result.stdout.strip().split()
    return (parts[0], parts[1]) if len(parts) == 2 else None


def write_container_file(target: str, path: str, value: str, mode: str) -> None:
    docker_exec(
        target,
        "sh",
        "-c",
        'set -eu; path=$1; mode=$2; dir=${path%/*}; mkdir -p "$dir"; '
        'tmp="$path.tmp.$$"; trap \'rm -f "$tmp"\' EXIT; cat >"$tmp"; '
        'chmod "$mode" "$tmp"; mv "$tmp" "$path"; trap - EXIT',
        "sh",
        path,
        mode,
        input_text=value,
    )


def notion_permission_profile() -> bytes:
    return canonical_json(
        {
            "name": "mte-notion-api-only",
            "network": {
                "inbound": {"allow_host": ["localhost", "127.0.0.1"]},
                "outbound": {
                    "insecure_allow_all": False,
                    "allow_host": ["api.notion.com"],
                    "allow_port": [443],
                },
            },
        }
    )


def ensure_notion_permission_profile(target: str, *, mutate: bool) -> tuple[int, str]:
    content = notion_permission_profile()
    expected_sha = sha256_bytes(content)
    state = container_file_state(target, NOTION_PERMISSION_PROFILE_PATH)
    if state == ("600", expected_sha):
        return 0, expected_sha
    if not mutate:
        raise RuntimeError("profile_notion_permission_profile_drift")
    write_container_file(
        target,
        NOTION_PERMISSION_PROFILE_PATH,
        content.decode(),
        "600",
    )
    if container_file_state(target, NOTION_PERMISSION_PROFILE_PATH) != (
        "600",
        expected_sha,
    ):
        raise RuntimeError("profile_notion_permission_profile_write_failed")
    return 1, expected_sha


def notion_registry_contract(target: str, notion_image: str) -> dict[str, Any]:
    result = thv(
        target,
        "registry",
        "info",
        NOTION_REGISTRY_PACKAGE,
        "--format",
        "json",
    )
    try:
        entry = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("profile_notion_registry_contract_invalid") from exc
    if (
        not isinstance(entry, dict)
        or entry.get("name") != NOTION_REGISTRY_PACKAGE
        or entry.get("tier") != "Official"
        or entry.get("status") != "Active"
        or entry.get("transport") != "stdio"
        or entry.get("repository_url") != NOTION_REPOSITORY_URL
        or entry.get("image") != NOTION_REGISTRY_IMAGE
        or tuple(entry.get("tools") or ()) != NOTION_TOOLS
        or notion_image != NOTION_IMAGE
    ):
        raise RuntimeError("profile_notion_registry_contract_drift")
    contract = {
        "package": NOTION_REGISTRY_PACKAGE,
        "tier": "Official",
        "status": "Active",
        "transport": "stdio",
        "repositoryUrl": NOTION_REPOSITORY_URL,
        "registryImage": NOTION_REGISTRY_IMAGE,
        "image": notion_image,
        "imagePinned": True,
        "apiVersion": NOTION_API_VERSION,
        "toolCount": len(NOTION_TOOLS),
        "toolsSha256": sha256_bytes(canonical_json(list(NOTION_TOOLS))),
        "egress": {"allowHost": ["api.notion.com"], "allowPort": [443]},
    }
    return {**contract, "contractSha256": sha256_bytes(canonical_json(contract))}


def ensure_notion_image_cache(
    values: dict[str, str], contract: dict[str, Any], *, mutate: bool
) -> tuple[int, dict[str, Any]]:
    registry_image = str(contract.get("registryImage") or "")
    pinned_image = values.get("TOOLHIVE_NOTION_IMAGE", "")
    if registry_image != NOTION_REGISTRY_IMAGE or pinned_image != NOTION_IMAGE:
        raise RuntimeError("profile_notion_image_cache_contract_drift")
    target = toolhive_runtime()

    def inspect() -> list[str]:
        result = run(
            [
                "docker",
                "exec",
                target,
                "docker",
                "image",
                "inspect",
                registry_image,
                "--format",
                "{{json .RepoDigests}}",
            ],
            check=False,
            timeout=60,
        )
        if result.returncode != 0:
            return []
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        return sorted(str(row) for row in value) if isinstance(value, list) else []

    digests = inspect()
    mutations = 0
    if pinned_image not in digests:
        if not mutate:
            raise RuntimeError("profile_notion_pinned_image_cache_missing")
        run(
            ["docker", "exec", target, "docker", "pull", registry_image],
            timeout=300,
        )
        mutations = 1
        digests = inspect()
    if pinned_image not in digests:
        raise RuntimeError("profile_notion_registry_tag_digest_mismatch")
    evidence = {
        "registryImage": registry_image,
        "pinnedImage": pinned_image,
        "pinnedDigestVerified": True,
        "repoDigestsSha256": sha256_bytes(canonical_json(digests)),
    }
    return mutations, evidence


def workload_specs(spec: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    return spec["identityWorkload"], spec["notionWorkload"]


def all_workloads(
    specs: list[dict[str, Any]],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    return [(spec, workload) for spec in specs for workload in workload_specs(spec)]


def is_current(
    row: dict[str, Any],
    spec: dict[str, Any],
    workload: dict[str, Any] | None = None,
) -> bool:
    workload = workload or spec["identityWorkload"]
    labels = row.get("labels") if isinstance(row.get("labels"), dict) else {}
    return (
        row.get("name") == workload["workloadId"]
        and row.get("group") == spec["bundleId"]
        and safe_int(row.get("port")) == workload["proxyPort"]
        and row.get("status") == "running"
        and labels.get("mte.managed-by") == MANAGED_BY
        and labels.get("mte.profile-ref") == spec["profileRef"]
        and labels.get("mte.bundle-sha256") == toolhive_label_sha(spec["bundleSha256"])
        and labels.get("mte.workload-role") == workload["role"]
        and labels.get("mte.image-ref-sha256")
        == toolhive_label_sha(sha256_bytes(workload["image"].encode()))
        and labels.get("mte.tools-sha256") == workload_tools_sha(workload)
    )


def tool_names(value: Any) -> list[str]:
    return sorted(
        str(row.get("name"))
        for row in (value.get("tools") if isinstance(value, dict) else []) or []
        if isinstance(row, dict) and row.get("name")
    )


def wait_workload_ready(
    target: str, spec: dict[str, Any], workload: dict[str, Any]
) -> dict[str, Any]:
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            listed = thv(
                target,
                "mcp",
                "list",
                "tools",
                "--server",
                workload["workloadId"],
                "--format",
                "json",
                check=False,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            time.sleep(1)
            continue
        if listed.returncode == 0:
            try:
                schema = json.loads(listed.stdout)
            except json.JSONDecodeError:
                schema = {}
            names = tool_names(schema)
            if names == sorted(workload["tools"]):
                tool_name = (
                    "echo" if workload["role"] == "identity-canary" else "API-get-self"
                )
                marker = "mte-c019-" + spec["bundleSha256"][:16]
                try:
                    called_result = thv(
                        target,
                        "mcp",
                        "call",
                        tool_name,
                        "--server",
                        workload["workloadId"],
                        "--args-file",
                        "-",
                        "--format",
                        "json",
                        input_text=json.dumps(
                            {"message": marker}
                            if workload["role"] == "identity-canary"
                            else {}
                        ),
                        check=False,
                        timeout=60,
                    )
                except subprocess.TimeoutExpired:
                    time.sleep(1)
                    continue
                called = called_result.stdout
                if called_result.returncode != 0 or not called:
                    time.sleep(1)
                    continue
                if workload["role"] == "identity-canary" and marker not in called:
                    time.sleep(1)
                    continue
                return {
                    "role": workload["role"],
                    "workloadId": workload["workloadId"],
                    "proxyPort": workload["proxyPort"],
                    "toolCount": len(names),
                    "toolSchemaSha256": sha256_bytes(canonical_json(schema)),
                    "readOnlyCanaryTool": tool_name,
                    "readOnlyCanaryResultSha256": sha256_bytes(called.encode()),
                }
        time.sleep(1)
    raise RuntimeError("toolhive_profile_workload_not_ready")


def run_workload(
    target: str,
    spec: dict[str, Any],
    workload: dict[str, Any],
    notion_token: str,
) -> dict[str, Any]:
    tool_flags = [flag for name in workload["tools"] for flag in ("--tools", name)]
    common = [
        "run",
        "--name",
        workload["workloadId"],
        "--transport",
        "stdio",
        "--proxy-port",
        str(workload["proxyPort"]),
        "--host",
        "0.0.0.0",
        "--group",
        spec["bundleId"],
        *tool_flags,
        "--label",
        f"mte.managed-by={MANAGED_BY}",
        "--label",
        f"mte.profile-ref={spec['profileRef']}",
        "--label",
        f"mte.bundle-sha256={toolhive_label_sha(spec['bundleSha256'])}",
        "--label",
        f"mte.workload-role={workload['role']}",
        "--label",
        "mte.image-ref-sha256="
        + toolhive_label_sha(sha256_bytes(workload["image"].encode())),
        "--label",
        f"mte.tools-sha256={workload_tools_sha(workload)}",
    ]
    if workload["role"] == "identity-canary":
        thv(target, *common, workload["image"])
        return {
            "used": False,
            "mode": "not-created",
            "deleted": True,
            "secretRef": "",
        }

    projection = (
        TOOLHIVE_RUNTIME_ROOT
        + "/secrets/"
        + sha256_bytes(workload["workloadId"].encode())[:16]
        + ".token"
    )
    write_container_file(target, projection, notion_token, "600")
    if container_file_state(target, projection) is None:
        raise RuntimeError("profile_notion_secret_projection_missing")
    try:
        docker_exec(
            target,
            "sh",
            "-c",
            "set -eu; projection=$1; shift; "
            '[ "$(stat -c %a "$projection")" = 600 ]; '
            'token=$(cat "$projection"); [ -n "$token" ]; '
            "export TOOLHIVE_SECRETS_PROVIDER=environment; "
            'export TOOLHIVE_SECRET_NOTION_TOKEN="$token"; unset token; '
            'exec thv "$@"',
            "sh",
            projection,
            *common,
            "--permission-profile",
            NOTION_PERMISSION_PROFILE_PATH,
            "--isolate-network",
            "--secret",
            "NOTION_TOKEN,target=NOTION_TOKEN",
            workload["image"],
            timeout=300,
        )
    finally:
        docker_exec(target, "rm", "-f", projection, check=False)
    if container_file_state(target, projection) is not None:
        raise RuntimeError("profile_notion_secret_projection_cleanup_failed")
    return {
        "used": True,
        "mode": "0600",
        "deleted": True,
        "secretRef": NOTION_SECRET_REF,
        "valueInArgv": False,
        "valueInEvidence": False,
    }


def vmcp_document(spec: dict[str, Any]) -> dict[str, Any]:
    identity, notion = workload_specs(spec)
    return {
        "name": spec["bundleId"] + "-" + spec["bundleSha256"][:12],
        "groupRef": spec["bundleId"],
        "incomingAuth": {"type": "anonymous"},
        "outgoingAuth": {
            "source": "inline",
            "default": {"type": "unauthenticated"},
        },
        "aggregation": {
            "conflictResolution": "priority",
            "conflictResolutionConfig": {
                "priorityOrder": [identity["workloadId"], notion["workloadId"]]
            },
        },
        "backends": [
            {
                "name": workload["workloadId"],
                "url": (f"http://{TOOLHIVE_RUNTIME_HOST}:{workload['proxyPort']}/mcp"),
                "transport": "streamable-http",
            }
            for workload in (identity, notion)
        ],
    }


def vmcp_paths(spec: dict[str, Any]) -> tuple[str, str, str]:
    base = TOOLHIVE_RUNTIME_ROOT + "/vmcp/" + spec["profileRef"]
    return base + ".json", base + ".pid", base + ".log"


def vmcp_process_command(target: str, pid_path: str) -> str:
    result = docker_exec(
        target,
        "sh",
        "-c",
        'p=$(cat "$1" 2>/dev/null || true); [ -n "$p" ] && '
        '[ -r "/proc/$p/cmdline" ] && tr "\\000" " " <"/proc/$p/cmdline"',
        "sh",
        pid_path,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def stop_vmcp(target: str, config_path: str, pid_path: str) -> None:
    docker_exec(
        target,
        "sh",
        "-c",
        'set -eu; p=$(cat "$1" 2>/dev/null || true); '
        'if [ -n "$p" ] && [ -r "/proc/$p/cmdline" ] && '
        'tr "\\000" " " <"/proc/$p/cmdline" | grep -F -- "$2" >/dev/null; then '
        'kill "$p" 2>/dev/null || true; n=0; while kill -0 "$p" 2>/dev/null && '
        '[ "$n" -lt 50 ]; do sleep .1; n=$((n+1)); done; '
        'kill -9 "$p" 2>/dev/null || true; fi; rm -f "$1"',
        "sh",
        pid_path,
        config_path,
    )


def start_vmcp(
    target: str, config_path: str, pid_path: str, log_path: str, port: int
) -> None:
    run(
        [
            "docker",
            "exec",
            "-d",
            target,
            "sh",
            "-c",
            "set -eu; config=$1; pid=$2; log=$3; port=$4; umask 077; "
            'nohup thv vmcp serve --config "$config" --host 0.0.0.0 '
            '--port "$port" >"$log" 2>&1 & printf "%s" "$!" >"$pid"',
            "sh",
            config_path,
            pid_path,
            log_path,
            str(port),
        ]
    )


def ensure_vmcp(target: str, spec: dict[str, Any], *, mutate: bool) -> tuple[int, str]:
    config_path, pid_path, log_path = vmcp_paths(spec)
    content = canonical_json(vmcp_document(spec))
    expected_sha = sha256_bytes(content)
    file_current = container_file_state(target, config_path) == ("600", expected_sha)
    command = vmcp_process_command(target, pid_path)
    process_current = all(
        marker in command
        for marker in (
            "thv vmcp serve",
            config_path,
            "--host 0.0.0.0",
            f"--port {spec['aggregatePort']}",
        )
    )
    if file_current and process_current:
        return 0, expected_sha
    if not mutate:
        raise RuntimeError("profile_vmcp_aggregate_drift")
    mutations = 0
    if not file_current:
        write_container_file(target, config_path, content.decode(), "600")
        thv(target, "vmcp", "validate", "--config", config_path)
        mutations += 1
    if process_current:
        stop_vmcp(target, config_path, pid_path)
        process_current = False
    if not process_current:
        stop_vmcp(target, config_path, pid_path)
        start_vmcp(target, config_path, pid_path, log_path, spec["aggregatePort"])
        mutations += 1
    return mutations, expected_sha


def wait_aggregate_ready(target: str, spec: dict[str, Any]) -> dict[str, Any]:
    url = f"http://127.0.0.1:{spec['aggregatePort']}/mcp"
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            listed = thv(
                target,
                "mcp",
                "list",
                "tools",
                "--server",
                url,
                "--format",
                "json",
                check=False,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            time.sleep(1)
            continue
        if listed.returncode == 0:
            try:
                schema = json.loads(listed.stdout)
            except json.JSONDecodeError:
                schema = {}
            if tool_names(schema) == spec["aggregateTools"]:
                marker = "mte-c019-aggregate-" + spec["bundleSha256"][:12]
                try:
                    echo_result = thv(
                        target,
                        "mcp",
                        "call",
                        "echo",
                        "--server",
                        url,
                        "--args-file",
                        "-",
                        "--format",
                        "json",
                        input_text=json.dumps({"message": marker}),
                        check=False,
                        timeout=60,
                    )
                    notion_result = thv(
                        target,
                        "mcp",
                        "call",
                        "API-get-self",
                        "--server",
                        url,
                        "--args-file",
                        "-",
                        "--format",
                        "json",
                        input_text="{}",
                        check=False,
                        timeout=60,
                    )
                except subprocess.TimeoutExpired:
                    time.sleep(1)
                    continue
                echo = echo_result.stdout
                notion = notion_result.stdout
                if (
                    echo_result.returncode != 0
                    or notion_result.returncode != 0
                    or marker not in echo
                    or not notion
                ):
                    time.sleep(1)
                    continue
                return {
                    "mode": "toolhive-vmcp",
                    "port": spec["aggregatePort"],
                    "endpointPath": "/mcp",
                    "toolCount": len(spec["aggregateTools"]),
                    "notionAccessMode": "read_only",
                    "notionDeniedToolCount": len(spec["notionWorkload"]["deniedTools"]),
                    "notionWriteConnectorIdentity": spec["toolPolicy"][
                        "notionWriteConnectorIdentity"
                    ],
                    "toolSchemaSha256": sha256_bytes(canonical_json(schema)),
                    "canaryResultSha256": sha256_bytes(echo.encode()),
                    "notionGetSelfResultSha256": sha256_bytes(notion.encode()),
                }
        time.sleep(1)
    raise RuntimeError("profile_vmcp_aggregate_not_ready")


def reserved_workload(row: dict[str, Any]) -> bool:
    labels = row.get("labels") if isinstance(row.get("labels"), dict) else {}
    return (
        str(row.get("name") or "").startswith(GROUP_PREFIX)
        or labels.get("mte.managed-by") == MANAGED_BY
    )


def audit_toolhive(
    specs: list[dict[str, Any]],
    inventory: list[dict[str, Any]],
    groups: set[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[str] = []
    desired_names = {workload["workloadId"] for _spec, workload in all_workloads(specs)}
    desired_groups = {row["bundleId"] for row in specs}
    counts = Counter(str(row.get("name") or "") for row in inventory)
    if any(counts[name] != 1 for name in desired_names):
        findings.append("toolhive_profile_workload_missing_or_duplicate")
    extras = [
        str(row.get("name") or "")
        for row in inventory
        if reserved_workload(row) and row.get("name") not in desired_names
    ]
    if extras:
        findings.append("toolhive_profile_workload_extra")
    reserved_groups = {name for name in groups if name.startswith(GROUP_PREFIX)}
    if reserved_groups != desired_groups:
        findings.append("toolhive_profile_group_set_invalid")
    identities: list[dict[str, Any]] = []
    for spec in specs:
        workload_identities: list[dict[str, Any]] = []
        for workload in workload_specs(spec):
            matches = [
                row for row in inventory if row.get("name") == workload["workloadId"]
            ]
            if len(matches) != 1 or not is_current(matches[0], spec, workload):
                findings.append("toolhive_profile_workload_drift")
                continue
            workload_identities.append(
                {
                    "role": workload["role"],
                    "workloadId": workload["workloadId"],
                    "proxyPort": workload["proxyPort"],
                    "imageSha256": sha256_bytes(workload["image"].encode()),
                }
            )
        identities.append(
            {
                "profileRef": spec["profileRef"],
                "bundleId": spec["bundleId"],
                "workloadId": spec["workloadId"],
                "proxyPort": spec["proxyPort"],
                "aggregatePort": spec["aggregatePort"],
                "bundleSha256": spec["bundleSha256"],
                "workloads": workload_identities,
            }
        )
    return identities, sorted(set(findings))


def stable_readiness_identity(
    readiness: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    workload_keys = (
        "role",
        "workloadId",
        "proxyPort",
        "toolCount",
        "toolSchemaSha256",
        "readOnlyCanaryTool",
    )
    aggregate_keys = (
        "mode",
        "port",
        "endpointPath",
        "toolCount",
        "notionAccessMode",
        "notionDeniedToolCount",
        "notionWriteConnectorIdentity",
        "toolSchemaSha256",
        "configSha256",
    )
    return [
        {
            "profileRef": profile_ref,
            "workloads": [
                {key: row.get(key) for key in workload_keys}
                for row in value.get("workloads", [])
                if isinstance(row, dict)
            ],
            "aggregate": {
                key: value.get("aggregate", {}).get(key) for key in aggregate_keys
            },
        }
        for profile_ref, value in sorted(readiness.items())
    ]


def reconcile_toolhive_pass(
    specs: list[dict[str, Any]], *, mutate: bool, pass_number: int
) -> dict[str, Any]:
    target = manager()
    inventory = workload_inventory(target)
    groups = group_names(target)
    desired_names = {workload["workloadId"] for _spec, workload in all_workloads(specs)}
    desired_groups = {row["bundleId"] for row in specs}
    counts = Counter(str(row.get("name") or "") for row in inventory)
    if any(counts[name] > 1 for name in desired_names):
        raise RuntimeError("toolhive_profile_workload_duplicate")
    assert_manager_not_oom_killed(target)
    values = dotenv(CANONICAL)
    notion_token = values.get(NOTION_SECRET_REF, "")
    notion_image = values.get("TOOLHIVE_NOTION_IMAGE", "")
    if not notion_token or notion_token != notion_token.strip() or "\n" in notion_token:
        raise RuntimeError("profile_notion_token_missing_or_invalid")
    registry_contract = notion_registry_contract(target, notion_image)
    image_cache_mutations, image_cache = ensure_notion_image_cache(
        values, registry_contract, mutate=mutate
    )
    permission_mutations, permission_sha = ensure_notion_permission_profile(
        target, mutate=mutate
    )
    mutations = image_cache_mutations + permission_mutations
    if mutate:
        for row in inventory:
            name = str(row.get("name") or "")
            match = next(
                (
                    (spec, workload)
                    for spec, workload in all_workloads(specs)
                    if workload["workloadId"] == name
                ),
                None,
            )
            if reserved_workload(row) and (
                match is None or not is_current(row, match[0], match[1])
            ):
                if thv(target, "rm", name, check=False, timeout=60).returncode != 0:
                    raise RuntimeError("toolhive_profile_workload_remove_failed")
                mutations += 1
        for group in sorted(
            name
            for name in groups
            if name.startswith(GROUP_PREFIX) and name not in desired_groups
        ):
            if thv(target, "group", "rm", group, check=False).returncode != 0:
                raise RuntimeError("toolhive_profile_group_remove_failed")
            mutations += 1
        for spec in specs:
            if spec["bundleId"] not in groups:
                thv(target, "group", "create", spec["bundleId"])
                mutations += 1
            for workload in workload_specs(spec):
                current = next(
                    (
                        row
                        for row in inventory
                        if row.get("name") == workload["workloadId"]
                    ),
                    None,
                )
                if not is_current(current or {}, spec, workload):
                    run_workload(
                        target,
                        spec,
                        workload,
                        notion_token,
                    )
                    mutations += 1
    readiness: dict[str, dict[str, Any]] = {}
    for spec in specs:
        workload_rows = [
            wait_workload_ready(target, spec, workload)
            for workload in workload_specs(spec)
        ]
        vmcp_mutations, vmcp_sha = ensure_vmcp(target, spec, mutate=mutate)
        mutations += vmcp_mutations
        aggregate = wait_aggregate_ready(target, spec)
        aggregate["configSha256"] = vmcp_sha
        readiness[spec["profileRef"]] = {
            "workloads": workload_rows,
            "aggregate": aggregate,
            "toolSchemaSha256": aggregate["toolSchemaSha256"],
            "canaryResultSha256": aggregate["canaryResultSha256"],
        }
    final_inventory = workload_inventory(target)
    final_groups = group_names(target)
    identities, findings = audit_toolhive(specs, final_inventory, final_groups)
    if findings:
        raise RuntimeError(findings[0])
    identity_sha = sha256_bytes(
        canonical_json(
            {
                "profiles": identities,
                "registryContractSha256": registry_contract["contractSha256"],
                "imageCacheSha256": image_cache["repoDigestsSha256"],
                "permissionProfileSha256": permission_sha,
                "aggregates": stable_readiness_identity(readiness),
            }
        )
    )
    return {
        "pass": pass_number,
        "mutationCount": mutations,
        "duplicateCount": 0,
        "extraCount": 0,
        "registryContract": registry_contract,
        "imageCache": image_cache,
        "permissionProfileSha256": permission_sha,
        "inventoryIdentitySha256": identity_sha,
        "profiles": [
            {**identity, **readiness[identity["profileRef"]]} for identity in identities
        ],
    }


def reconcile_toolhive_two_pass(
    specs: list[dict[str, Any]], *, mutate: bool
) -> tuple[dict[str, Any], dict[str, Any]]:
    first = reconcile_toolhive_pass(specs, mutate=mutate, pass_number=1)
    second = reconcile_toolhive_pass(specs, mutate=False, pass_number=2)
    if (
        second["mutationCount"] != 0
        or first["inventoryIdentitySha256"] != second["inventoryIdentitySha256"]
    ):
        raise RuntimeError("toolhive_profile_second_pass_not_noop")
    return first, second


def paperclip_inventory(
    values: dict[str, str], specs: list[dict[str, Any]], catalog_sha: str
) -> list[dict[str, str]]:
    required_refs = tuple(str(spec["profileRef"]) for spec in specs)
    key = values.get("PAPERCLIP_BOARD_API_KEY", "")
    headers = {"Authorization": "Bearer " + key} if key else {}
    agents = request_json(
        "http://127.0.0.1:"
        + values["PAPERCLIP_PORT"]
        + "/api/companies/"
        + values["PAPERCLIP_COMPANY_ID"]
        + "/agents",
        headers=headers,
    )
    rows = agents if isinstance(agents, list) else (agents or {}).get("data", [])
    expected_refs = set(required_refs)
    unexpected = [
        row
        for row in rows
        if isinstance(row, dict)
        and isinstance(row.get("metadata"), dict)
        and row["metadata"].get("managedBy") == "mte-profile-reconciler"
        and row["metadata"].get("profileRef") not in expected_refs
    ]
    if unexpected:
        raise RuntimeError("paperclip_profile_agent_extra")
    result: list[dict[str, str]] = []
    for spec in specs:
        matches = [
            row
            for row in rows
            if isinstance(row, dict)
            and isinstance(row.get("metadata"), dict)
            and row["metadata"].get("profileRef") == spec["profileRef"]
        ]
        if len(matches) != 1:
            raise RuntimeError("paperclip_profile_agent_missing_or_duplicate")
        metadata = matches[0]["metadata"]
        if (
            metadata.get("managedBy") != "mte-profile-reconciler"
            or metadata.get("catalogSha256") != catalog_sha
            or metadata.get("toolBundleRef") != spec["bundleId"]
            or metadata.get("toolWorkloadRef") != spec["workloadId"]
            or metadata.get("kestraCatalogKey") != KESTRA_CATALOG_KEY
        ):
            raise RuntimeError("paperclip_profile_catalog_ref_drift")
        identity = str(matches[0].get("id") or "")
        if not identity:
            raise RuntimeError("paperclip_profile_agent_id_missing")
        result.append({"profileRef": spec["profileRef"], "agentId": identity})
    if len({row["agentId"] for row in result}) != len(required_refs):
        raise RuntimeError("paperclip_profile_agent_identity_not_unique")
    return result


def kestra_catalog_payload(
    rows: list[dict[str, Any]],
    specs: list[dict[str, Any]],
    catalog_sha: str,
) -> dict[str, Any]:
    document = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "KestraProfileCatalogBinding",
        "namespace": KESTRA_NAMESPACE,
        "key": KESTRA_CATALOG_KEY,
        "profileSourceSha256": sha256_path(PROFILES_SOURCE),
        "profileRuntimeSha256": catalog_sha,
        "profiles": [
            {
                "profileRef": spec["profileRef"],
                "harnessKind": source.get("runtimeContract", {}).get("harnessKind"),
                "nativeAdapter": source.get("runtimeContract", {}).get("adapterType"),
                "protocol": source.get("runtimeContract", {}).get("protocol"),
                "defaultEnvironment": source.get("defaultEnvironment"),
                "llmProvider": source.get("llmRouting", {}).get("provider"),
                "llmApiKeyRef": source.get("llmRouting", {}).get("apiKeyRef"),
                "toolProvider": source.get("toolRouting", {}).get("provider"),
                "toolEndpointRef": source.get("toolRouting", {}).get("mcpUrlRef"),
                "toolCredentialRef": source.get("toolRouting", {}).get(
                    "bearerTokenRef"
                ),
                "bundleId": spec["bundleId"],
                "workloadId": spec["workloadId"],
            }
            for source, spec in zip(rows, specs, strict=True)
        ],
    }
    if any(
        not isinstance(value, str) or not value
        for profile in document["profiles"]
        for value in profile.values()
    ):
        raise RuntimeError("kestra_profile_catalog_incomplete")
    document["specSha256"] = sha256_bytes(canonical_json(document))
    return {
        "namespace": KESTRA_NAMESPACE,
        "key": KESTRA_CATALOG_KEY,
        "method": "PUT",
        "path": (
            "/api/v1/main/namespaces/" + KESTRA_NAMESPACE + "/kv/" + KESTRA_CATALOG_KEY
        ),
        "contentType": "application/json",
        "document": document,
        "documentSha256": sha256_bytes(canonical_json(document)),
        "status": "payload-ready",
        "applied": False,
    }


def identity_model() -> dict[str, Any]:
    return {
        "toolHiveNativeIncomingOidc": {
            "configured": False,
            "scope": "pinned-single-host-docker-cli-deployment",
            "reason": "no-reviewed-incoming-oidc-config",
        },
        "groupProvidesIdentity": False,
        "boundedAlternative": {
            "type": "mte-agent-plane-gateway-profile-bearer",
            "enforcer": "mte-agent-plane-gateway",
            "networkExposure": "private-agent-plane-only",
            "credentialTransport": "paperclip-runtime-secret-ref",
            "requiredNegativeProof": "same-credential-wrong-profile-endpoint-401",
        },
    }


def sensitive_values(values: dict[str, str]) -> set[str]:
    return {
        value
        for key, value in values.items()
        if len(value) >= 12 and SENSITIVE_KEY_PATTERN.search(key)
    }


def assert_secret_free(value: Any, values: dict[str, str]) -> None:
    encoded = json.dumps(value, sort_keys=True)
    if any(secret in encoded for secret in sensitive_values(values)):
        raise RuntimeError("secret_value_in_evidence")


def profile_access_from_subject(
    subject: dict[str, Any], rows: list[dict[str, Any]], values: dict[str, str]
) -> list[dict[str, Any]]:
    if (
        subject.get("kind") != "KestraPaperclipGitHubE2E"
        or subject.get("status") != "passed"
    ):
        raise RuntimeError("c010_subject_not_passed")
    runs = subject.get("runs") if isinstance(subject.get("runs"), list) else []
    if [row.get("profile") for row in runs if isinstance(row, dict)] != list(REQUIRED):
        raise RuntimeError("c010_subject_profile_set_invalid")
    result: list[dict[str, Any]] = []
    for source, run_row in zip(rows, runs, strict=True):
        access = source["toolAccess"]
        semantic = (
            run_row.get("semanticChecks", {}).get("runner-toolhive-profile", {})
            if isinstance(run_row, dict)
            else {}
        )
        expected = {
            "status": "passed",
            "profileRef": source["ref"],
            "bundleId": access["bundleId"],
            "workloadId": access["workloadId"],
            "endpointRef": access["endpointRef"],
            "credentialRef": access["credentialRef"],
            "runnerOrigin": "daytona",
            "initialize": True,
            "toolsList": True,
            "canaryCall": True,
            "toolName": "echo",
            "httpStatus": 200,
            "wrongProfileEndpointRef": access["wrongProfileEndpointRef"],
            "wrongProfileDenied": True,
            "wrongProfileStatus": 401,
            "credentialLeak": False,
        }
        if any(
            semantic.get(key) != expected_value
            for key, expected_value in expected.items()
        ):
            raise RuntimeError("c010_runner_profile_semantics_invalid")
        if not isinstance(semantic.get("runId"), str) or not semantic["runId"]:
            raise RuntimeError("c010_runner_profile_run_id_invalid")
        if semantic.get("unauthorizedStatus") != 401:
            raise RuntimeError("c010_unauthorized_probe_invalid")
        for key in ("markerSha256", "toolsListSha256", "resultSha256"):
            if not SHA_PATTERN.fullmatch(str(semantic.get(key) or "")):
                raise RuntimeError("c010_runner_profile_hash_invalid")
        result.append(
            {
                **expected,
                "runId": semantic.get("runId"),
                "unauthorizedStatus": 401,
                "markerSha256": semantic["markerSha256"],
                "toolsListSha256": semantic["toolsListSha256"],
                "resultSha256": semantic["resultSha256"],
            }
        )
    assert_secret_free(subject, values)
    return result


def verify_runner_access(subject_path: Path = RUNNER_E2E_EVIDENCE) -> dict[str, Any]:
    values = dotenv(CANONICAL)
    rows, catalog_sha, _policy = catalog()
    subject = json.loads(subject_path.read_text())
    profiles = profile_access_from_subject(subject, rows, values)
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "ToolHiveProfileAccessVerification",
        "status": "passed",
        "ok": True,
        "generatedAt": utcnow(),
        "canonicalSourceSha256": sha256_path(CANONICAL),
        "producerPath": str(Path(__file__)),
        "producerSha256": sha256_path(Path(__file__)),
        "profileCatalogSha256": catalog_sha,
        "subjectEvidencePath": str(subject_path),
        "subjectEvidenceSha256": sha256_path(subject_path),
        "identityModel": identity_model(),
        "profiles": profiles,
        "secretValuesPrinted": False,
    }
    assert_secret_free(payload, values)
    atomic_json(ACCESS_EVIDENCE, payload)
    return payload


def completion_subjects(
    catalog_sha: str, expected_kestra_catalog_sha: str
) -> dict[str, Any]:
    canonical_sha = sha256_path(CANONICAL)
    producer_sha = sha256_path(Path(__file__))
    for path in (ACCESS_EVIDENCE, KESTRA_VERIFY_EVIDENCE):
        if not secure_evidence(path):
            raise RuntimeError("profile_completion_evidence_missing_or_insecure")
    try:
        access = json.loads(ACCESS_EVIDENCE.read_text())
        kestra = json.loads(KESTRA_VERIFY_EVIDENCE.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("profile_completion_evidence_invalid") from exc

    access_profiles = access.get("profiles") if isinstance(access, dict) else None
    access_refs = [
        row.get("profileRef") for row in access_profiles or [] if isinstance(row, dict)
    ]
    subject_path = Path(str(access.get("subjectEvidencePath") or ""))
    if (
        access.get("apiVersion") != "micro-task-engine/v1alpha1"
        or access.get("kind") != "ToolHiveProfileAccessVerification"
        or access.get("status") != "passed"
        or access.get("ok") is not True
        or not fresh_timestamp(access.get("generatedAt"), 600)
        or access.get("canonicalSourceSha256") != canonical_sha
        or access.get("producerPath") != str(Path(__file__))
        or access.get("producerSha256") != producer_sha
        or access.get("profileCatalogSha256") != catalog_sha
        or access_refs != list(REQUIRED)
        or not subject_path.is_file()
        or access.get("subjectEvidenceSha256") != sha256_path(subject_path)
        or any(
            row.get("runnerOrigin") != "daytona"
            or row.get("initialize") is not True
            or row.get("toolsList") is not True
            or row.get("canaryCall") is not True
            or row.get("wrongProfileDenied") is not True
            or row.get("wrongProfileStatus") != 401
            for row in access_profiles or []
        )
    ):
        raise RuntimeError("profile_access_evidence_binding_invalid")

    second_pass = kestra.get("secondPass") if isinstance(kestra, dict) else None
    kv_rows = second_pass.get("kv") if isinstance(second_pass, dict) else None
    profile_kv = [
        row
        for row in kv_rows or []
        if isinstance(row, dict) and row.get("key") == KESTRA_CATALOG_KEY
    ]
    if (
        kestra.get("apiVersion") != "micro-task-engine/v1alpha1"
        or kestra.get("kind") != "KestraReconcileEvidence"
        or kestra.get("status") != "passed"
        or kestra.get("action") != "verify"
        or not fresh_timestamp(kestra.get("finishedAt"), 600)
        or kestra.get("canonicalSourceSha256") != canonical_sha
        or kestra.get("controlNamespace") != KESTRA_NAMESPACE
        or kestra.get("profileCatalogKey") != KESTRA_CATALOG_KEY
        or kestra.get("profileRuntimeSha256") != catalog_sha
        or kestra.get("profileRefs") != list(REQUIRED)
        or kestra.get("stableRemoteState") is not True
        or not isinstance(second_pass, dict)
        or second_pass.get("mutationCount") != 0
        or second_pass.get("noOp") is not True
        or len(profile_kv) != 1
        or profile_kv[0].get("namespace") != KESTRA_NAMESPACE
        or profile_kv[0].get("type") != "JSON"
        or profile_kv[0].get("valueSha256") != expected_kestra_catalog_sha
    ):
        raise RuntimeError("profile_kestra_evidence_binding_invalid")

    return {
        "accessEvidenceSha256": sha256_path(ACCESS_EVIDENCE),
        "kestraEvidenceSha256": sha256_path(KESTRA_VERIFY_EVIDENCE),
        "kestraProfileCatalogSha256": profile_kv[0]["valueSha256"],
    }


def execute(*, mutate: bool, finalize: bool = False) -> dict[str, Any]:
    values = dotenv(CANONICAL)
    rows, catalog_sha, policy = catalog()
    specs = desired(rows, values, policy)
    first, second = reconcile_toolhive_two_pass(specs, mutate=mutate)
    paperclip_rows = paperclip_inventory(values, specs, catalog_sha)
    paperclip = {row["profileRef"]: row["agentId"] for row in paperclip_rows}
    kestra = kestra_catalog_payload(rows, specs, catalog_sha)
    readiness = {row["profileRef"]: row for row in second.get("profiles", [])}
    profiles = []
    for source, spec in zip(rows, specs, strict=True):
        ready = readiness[spec["profileRef"]]
        profiles.append(
            {
                "profileRef": spec["profileRef"],
                "nativeAdapter": source.get("nativeAdapter"),
                "paperclip": {
                    "agentId": paperclip[spec["profileRef"]],
                    "catalogRef": "runtime/profiles/profiles.yaml",
                    "catalogSha256": catalog_sha,
                    "status": "ready",
                },
                "toolhive": {
                    "toolPolicyRef": TOOL_POLICY_REF,
                    "bundleId": spec["bundleId"],
                    "workloadId": spec["workloadId"],
                    "bundleSha256": spec["bundleSha256"],
                    "endpointRef": spec["endpointRef"],
                    "credentialRef": spec["credentialRef"],
                    "status": "ready",
                    "managerInventoryRead": True,
                    "managerReadOnlyCanary": True,
                    "notionAccessMode": "read_only",
                    "notionAllowedToolCount": len(spec["notionWorkload"]["tools"]),
                    "notionDeniedToolCount": len(spec["notionWorkload"]["deniedTools"]),
                    "notionRawCredentialInHarness": False,
                    "notionWriteConnectorIdentity": spec["toolPolicy"][
                        "notionWriteConnectorIdentity"
                    ],
                    "postgresWriteAllowed": spec["toolPolicy"]["postgresWriteAllowed"],
                    "toolSchemaSha256": ready["toolSchemaSha256"],
                    "canaryResultSha256": ready["canaryResultSha256"],
                    "groupProvidesIdentity": False,
                },
                "kestra": {
                    "gateId": KESTRA_CATALOG_KEY,
                    "status": "payload-ready",
                    "documentSha256": kestra["documentSha256"],
                },
            }
        )
    completion = (
        completion_subjects(catalog_sha, kestra["documentSha256"]) if finalize else None
    )
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "ProfileReconcileEvidence",
        "status": "passed" if completion else "prepared",
        "ok": bool(completion),
        "producerReady": True,
        "connectionReady": bool(completion),
        "generatedAt": utcnow(),
        "canonicalSourceSha256": sha256_path(CANONICAL),
        "producerPath": str(Path(__file__)),
        "producerSha256": sha256_path(Path(__file__)),
        "profileCatalogSha256": catalog_sha,
        "kestraCatalogPayloadSha256": kestra["documentSha256"],
        "kestraCatalog": kestra,
        "identityModel": identity_model(),
        "profiles": profiles,
        "passes": [first, second],
        "mutationCount": second["mutationCount"],
        "secondRunNoOp": True,
        "duplicateCount": 0,
        "extraCount": 0,
        "completionBlockers": []
        if completion
        else [
            "kestra-catalog-apply-and-readback-not-integrated",
            "runner-origin-c010-evidence-required",
        ],
        "secretValuesPrinted": False,
    }
    if completion:
        payload.update(completion)
        for row in payload["profiles"]:
            row["kestra"]["status"] = "ready"
            row["kestra"]["observedCatalogSha256"] = completion[
                "kestraProfileCatalogSha256"
            ]
            row["toolhive"]["runnerAccessVerified"] = True
    assert_secret_free(payload, values)
    atomic_json(EVIDENCE, payload)
    return payload


def failed_payload(kind: str, exc: BaseException) -> dict[str, Any]:
    payload = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": kind,
        "status": "failed",
        "ok": False,
        "generatedAt": utcnow(),
        "canonicalSourceSha256": (
            sha256_path(CANONICAL) if CANONICAL.is_file() else ""
        ),
        "producerPath": str(Path(__file__)),
        "producerSha256": sha256_path(Path(__file__)),
        "errorType": type(exc).__name__,
        "secretValuesPrinted": False,
    }
    return payload


def main() -> int:
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    if action not in {
        "plan",
        "provision",
        "verify",
        "verify-access",
        "finalize",
        "status",
    }:
        print(
            "usage: server-profile-reconcile.py "
            "plan|provision|verify|verify-access|finalize|status",
            file=sys.stderr,
        )
        return 2
    if action == "status":
        if not EVIDENCE.is_file():
            return 1
        print(EVIDENCE.read_text(), end="")
        return 0
    try:
        if action == "plan":
            values = dotenv(CANONICAL)
            rows, catalog_sha, policy = catalog()
            specs = desired(rows, values, policy)
            payload = {
                "status": "payload-ready",
                "identityModel": identity_model(),
                "toolPolicy": {
                    "ref": TOOL_POLICY_REF,
                    "notionAgentAccess": "read_only",
                    "notionAllowedToolCount": len(NOTION_AGENT_READ_TOOLS),
                    "notionDeniedToolCount": len(NOTION_WRITE_TOOLS),
                    "notionWriteConnectorIdentity": policy["notionWriteConnector"][
                        "identity"
                    ],
                    "notionWriteConnectorAgentReachable": False,
                    "postgresWriteAllowed": True,
                },
                "kestraCatalog": kestra_catalog_payload(rows, specs, catalog_sha),
                "profiles": [
                    {
                        key: spec[key]
                        for key in (
                            "profileRef",
                            "bundleId",
                            "workloadId",
                            "endpointRef",
                            "credentialRef",
                        )
                    }
                    for spec in specs
                ],
                "secretValuesPrinted": False,
            }
            assert_secret_free(payload, values)
        elif action == "verify-access":
            payload = verify_runner_access()
        else:
            payload = execute(
                mutate=action == "provision",
                finalize=action == "finalize",
            )
    except BaseException as exc:
        kind = (
            "ToolHiveProfileAccessVerification"
            if action == "verify-access"
            else "ProfileReconcileEvidence"
        )
        payload = failed_payload(kind, exc)
        atomic_json(ACCESS_EVIDENCE if action == "verify-access" else EVIDENCE, payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 1
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

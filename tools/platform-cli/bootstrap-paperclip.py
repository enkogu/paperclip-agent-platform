#!/usr/bin/env python3
"""Reconcile the exact Paperclip profile catalog without exposing secrets.

This is the single owner for profile agents. Agents are identified only by
``metadata.profileRef``; display names are never used as identity. Bootstrap
always provisions Paperclip's native harness adapter; acceptance fixtures are
kept outside the product profile catalog.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from profile_catalog import (  # noqa: E402
    default_catalog_path,
    load_profile_catalog,
    semantic_sha256,
)


_SCRIPT_PATH = Path(__file__).resolve()
ROOT = (
    _SCRIPT_PATH.parents[2]
    if _SCRIPT_PATH.parent.name == "platform-cli"
    and _SCRIPT_PATH.parent.parent.name == "tools"
    else _SCRIPT_PATH.parents[1]
)
CANONICAL_ENV = Path("/root/.config/mte-secrets/platform.env")
PROFILE_SOURCE = next(
    (
        path
        for path in (
            Path(os.environ.get("MTE_PROFILES_FILE", "")),
            Path("/opt/mte-platform/runtime/profiles/profiles.yaml"),
            default_catalog_path(),
        )
        if str(path) and path.is_file()
    ),
    default_catalog_path(),
)
REQUIRED_PROFILE_REFS = load_profile_catalog(PROFILE_SOURCE).refs
MANAGED_BY = "mte-profile-reconciler"
CATALOG_REF = "runtime/profiles/profiles.yaml"
KESTRA_CATALOG_KEY = "mte.profile.catalog"


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def profile_catalog_semantic_sha256(document: dict) -> str:
    return semantic_sha256(document)


def canonical_paperclip_url() -> str | None:
    if not CANONICAL_ENV.is_file():
        return None
    values = dict(
        line.split("=", 1)
        for line in CANONICAL_ENV.read_text().splitlines()
        if line and not line.startswith("#") and "=" in line
    )
    return values.get("PAPERCLIP_API_BASE")


def request(base: str, token: str, method: str, path: str, body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        # The upstream body may contain operator-supplied values. Keep the
        # failure bounded to method/path/status and never echo the response.
        exc.read()
        raise RuntimeError(f"Paperclip {method} {path}: HTTP {exc.code}") from exc


def profile_catalog(path: Path = PROFILE_SOURCE) -> tuple[list[dict], str]:
    loaded = load_profile_catalog(path)
    rows = list(loaded.profiles)
    for row in rows:
        access = row.get("toolAccess")
        if (
            not isinstance(access, dict)
            or access.get("paperclipProfileRef") != row["ref"]
            or access.get("kestraCatalogKey") != KESTRA_CATALOG_KEY
            or access.get("identityMode") != "mte_gateway_profile_bearer"
            or access.get("identityEnforcer") != "mte-agent-plane-gateway"
            or access.get("nativeToolHiveOidcConfigured") is not False
            or access.get("groupActsAsIdentity") is not False
        ):
            raise RuntimeError("profile_catalog_control_plane_refs_invalid")
    return rows, loaded.semantic_sha256


def index_agents_by_profile(
    agents: list[dict], expected_refs: tuple[str, ...] | None = None
) -> dict[str, dict]:
    expected_refs = REQUIRED_PROFILE_REFS if expected_refs is None else expected_refs
    indexed: dict[str, list[dict]] = {ref: [] for ref in expected_refs}
    unexpected_managed: list[str] = []
    for agent in agents:
        if not isinstance(agent, dict):
            continue
        metadata = agent.get("metadata")
        if not isinstance(metadata, dict):
            continue
        ref = str(metadata.get("profileRef") or "")
        if ref in indexed:
            indexed[ref].append(agent)
        elif metadata.get("managedBy") == MANAGED_BY:
            unexpected_managed.append(ref or "<missing>")
    duplicates = [ref for ref, rows in indexed.items() if len(rows) > 1]
    if duplicates:
        raise RuntimeError("paperclip_profile_agent_duplicate")
    if unexpected_managed:
        raise RuntimeError("paperclip_profile_agent_extra")
    return {ref: rows[0] for ref, rows in indexed.items() if rows}


def desired_agent(
    profile: dict,
    *,
    mode: str,
    workspace_root: Path,
    instructions_root: Path,
    max_concurrency: int | None,
    catalog_sha256: str,
) -> dict:
    access = profile["toolAccess"]
    if mode != "native":
        raise ValueError("only native Paperclip harness profiles are supported")
    adapter_type = profile["runtimeContract"]["adapterType"]
    workspace = workspace_root / profile["ref"]
    adapter_config = {
        key: (str(workspace) if value == "${WORKSPACE}" else value)
        for key, value in profile["nativeAdapterConfig"].items()
    }
    adapter_config["instructionsFilePath"] = str(
        instructions_root / profile["instructions"]
    )
    return {
        "name": f"MTE {profile['ref']}",
        "role": profile["role"],
        "title": profile["title"],
        "capabilities": (
            f"profileRef={profile['ref']}; catalogRef={CATALOG_REF}; "
            "normalized runtime contract"
        ),
        "adapterType": adapter_type,
        "adapterConfig": adapter_config,
        "runtimeConfig": {
            "heartbeat": {
                "enabled": False,
                "wakeOnDemand": True,
                "maxConcurrentRuns": (
                    max_concurrency
                    if max_concurrency is not None
                    else profile["limits"]["maxConcurrentRuns"]
                ),
            }
        },
        "budgetMonthlyCents": 0,
        "metadata": {
            "profileRef": profile["ref"],
            "managedBy": MANAGED_BY,
            "bootstrapMode": mode,
            "catalogRef": CATALOG_REF,
            "catalogSha256": catalog_sha256,
            "toolBundleRef": access["bundleId"],
            "toolWorkloadRef": access["workloadId"],
            "kestraCatalogKey": access["kestraCatalogKey"],
        },
    }


def agent_has_drift(agent: dict, desired: dict) -> bool:
    return any(agent.get(key) != value for key, value in desired.items())


def preserve_provisioned_adapter_env(current: dict, desired: dict) -> dict:
    """Keep the provisioning-owned runtime credential envelope intact.

    Bootstrap owns the native adapter shape, while ``server-provision.py`` owns
    ``adapterConfig.env`` and its Paperclip secret references.  Re-applying the
    profile catalog must therefore compare and patch against a desired object
    containing the existing env instead of deleting that second-layer state via
    ``replaceAdapterConfig``.
    """

    current_config = current.get("adapterConfig")
    if not isinstance(current_config, dict):
        return desired
    current_env = current_config.get("env")
    if not isinstance(current_env, dict):
        return desired
    preserved = copy.deepcopy(desired)
    preserved["adapterConfig"]["env"] = copy.deepcopy(current_env)
    return preserved


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def reconcile(args: argparse.Namespace) -> dict:
    profiles, catalog_sha = profile_catalog()
    required_refs = tuple(str(profile["ref"]) for profile in profiles)
    companies = request(args.url, args.token, "GET", "/api/companies")
    company = next(
        (row for row in companies if row["name"] == "Micro Task Engine Prototype"),
        None,
    )
    if not company:
        company = request(
            args.url,
            args.token,
            "POST",
            "/api/companies",
            {
                "name": "Micro Task Engine Prototype",
                "description": (
                    "Disposable Paperclip runtime evaluation; Kestra remains "
                    "workflow owner."
                ),
                "budgetMonthlyCents": 0,
            },
        )
    existing = request(
        args.url,
        args.token,
        "GET",
        f"/api/companies/{company['id']}/agents",
    )
    by_profile = index_agents_by_profile(existing, required_refs)
    identities: dict[str, str] = {}
    actions: dict[str, str] = {}
    for profile in profiles:
        desired = desired_agent(
            profile,
            mode=args.mode,
            workspace_root=Path(args.workspace_root),
            instructions_root=Path(args.instructions_root),
            max_concurrency=args.max_concurrency,
            catalog_sha256=catalog_sha,
        )
        current = by_profile.get(profile["ref"])
        if current is None:
            current = request(
                args.url,
                args.token,
                "POST",
                f"/api/companies/{company['id']}/agents",
                desired,
            )
            actions[profile["ref"]] = "created"
        else:
            desired = preserve_provisioned_adapter_env(current, desired)
            if agent_has_drift(current, desired):
                current = request(
                    args.url,
                    args.token,
                    "PATCH",
                    f"/api/agents/{current['id']}",
                    {**desired, "replaceAdapterConfig": True},
                )
                actions[profile["ref"]] = "updated"
            else:
                actions[profile["ref"]] = "unchanged"
        identity = str(current.get("id") or "")
        if not identity:
            raise RuntimeError("paperclip_profile_agent_id_missing")
        identities[profile["ref"]] = identity
    if len(set(identities.values())) != len(required_refs):
        raise RuntimeError("paperclip_profile_agent_identity_not_unique")
    output = {
        "paperclipUrl": args.url,
        "companyId": company["id"],
        "mode": args.mode,
        "catalogRef": CATALOG_REF,
        "catalogSha256": catalog_sha,
        "profileRefs": list(required_refs),
        "agents": identities,
        "actions": actions,
        "duplicateCount": 0,
        "extraManagedCount": 0,
        "secretValuesPrinted": False,
    }
    atomic_json(args.output, output)
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--url",
        default=os.environ.get("PAPERCLIP_URL") or canonical_paperclip_url(),
    )
    parser.add_argument("--token", default=os.environ.get("PAPERCLIP_TOKEN", ""))
    parser.add_argument("--mode", choices=("native",), default="native")
    parser.add_argument(
        "--workspace-root",
        default=os.environ.get(
            "PAPERCLIP_AGENT_WORKSPACE_ROOT", str(ROOT / "state/workspaces")
        ),
    )
    parser.add_argument(
        "--instructions-root",
        default=os.environ.get(
            "PAPERCLIP_AGENT_INSTRUCTIONS_ROOT", str(ROOT / "profiles")
        ),
    )
    parser.add_argument("--max-concurrency", type=int, default=None)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "state/bootstrap.json",
    )
    args = parser.parse_args()
    if not args.url:
        parser.error("--url or canonical PAPERCLIP_API_BASE is required")
    if args.max_concurrency is not None and args.max_concurrency < 1:
        parser.error("--max-concurrency must be at least 1")
    print(json.dumps(reconcile(args), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

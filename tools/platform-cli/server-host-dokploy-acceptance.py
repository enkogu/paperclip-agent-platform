#!/usr/bin/env python3
"""Ephemeral, hash-gated Dokploy API -> Docker Engine acceptance lifecycle."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
from typing import Any


ROOT = Path(os.environ.get("MTE_PLATFORM_ROOT", "/opt/mte-platform"))
SECRET_ROOT = Path(os.environ.get("MTE_SECRET_ROOT", "/root/.config/mte-secrets"))
CONFIG = ROOT / "config/platform.json"
MANIFEST = SECRET_ROOT / "projections-manifest.json"
PLATFORM_ENV = SECRET_ROOT / "platform.env"
DOKPLOY_SCRIPT = ROOT / "bin/server-dokploy.py"
EVIDENCE = ROOT / "evidence/host-dokploy-acceptance.json"
GENERATOR_VERSION = "mte-config-renderer/v1"
NAME_PREFIX = "MTE Host Acceptance "
APP_PREFIX = "mte-host-acceptance-"


class AcceptanceError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise AcceptanceError("state_invalid", str(path)) from exc
    if not isinstance(value, dict):
        raise AcceptanceError("state_invalid", str(path))
    return value


def dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        raise AcceptanceError("state_invalid", str(path)) from exc
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, value = stripped.split("=", 1)
            values[key] = value
    return values


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)
    if os.geteuid() == 0:
        os.chown(path.parent, 0, 0)
        os.chown(path, 0, 0)


def exact_hash_gate(expected: str) -> dict[str, str]:
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise AcceptanceError("hash_gate_invalid", "expected source SHA is invalid")
    config, manifest = load_json(CONFIG), load_json(MANIFEST)
    generated = config.get("_generated", {})
    source_hash = hashlib.sha256(PLATFORM_ENV.read_bytes()).hexdigest()
    if (
        source_hash != expected
        or generated.get("sourceSha256") != expected
        or manifest.get("sourceSha256") != expected
        or generated.get("generatorVersion") != GENERATOR_VERSION
        or manifest.get("generatorVersion") != GENERATOR_VERSION
    ):
        raise AcceptanceError("hash_gate_drift", "FINAL-STABLE gate failed")
    return {"sourceSha256": expected, "generatorVersion": GENERATOR_VERSION}


def load_dokploy():
    if not DOKPLOY_SCRIPT.is_file():
        raise AcceptanceError("producer_missing", str(DOKPLOY_SCRIPT))
    spec = importlib.util.spec_from_file_location("mte_server_dokploy", DOKPLOY_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def run(
    argv: list[str], *, allow_failure: bool = False
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, text=True, capture_output=True, timeout=120)
    if result.returncode and not allow_failure:
        raise AcceptanceError(
            "engine_command_failed", argv[1] if len(argv) > 1 else argv[0]
        )
    return result


def compose_document(image: str, run_id: str, revision: str) -> str:
    if not re.fullmatch(r"[a-z0-9-]+", run_id):
        raise AcceptanceError("run_id_invalid", "unsafe run ID")
    if not re.search(r"@sha256:[0-9a-f]{64}$", image):
        raise AcceptanceError("image_unpinned", "canary image is not digest-pinned")
    return (
        "services:\n"
        "  canary:\n"
        f"    image: {image}\n"
        '    command: ["sh", "-ec", "echo '
        + revision
        + ' > /data/revision; sleep 600"]\n'
        '    restart: "no"\n'
        "    labels:\n"
        f"      com.mte.acceptance.run-id: {run_id}\n"
        f"      com.mte.acceptance.revision: {revision}\n"
        "    volumes:\n"
        "      - canary-data:/data\n"
        "volumes:\n"
        "  canary-data:\n"
        "    labels:\n"
        f"      com.mte.acceptance.run-id: {run_id}\n"
        "networks:\n"
        "  default:\n"
        "    labels:\n"
        f"      com.mte.acceptance.run-id: {run_id}\n"
    )


def engine_resources(app_name: str) -> dict[str, Any]:
    filters = ["label=com.docker.compose.project=" + app_name]
    containers = run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            filters[0],
            "--format",
            "{{.Names}}",
        ]
    ).stdout.splitlines()
    volumes = run(
        [
            "docker",
            "volume",
            "ls",
            "--filter",
            filters[0],
            "--format",
            "{{.Name}}",
        ]
    ).stdout.splitlines()
    networks = run(
        [
            "docker",
            "network",
            "ls",
            "--filter",
            filters[0],
            "--format",
            "{{.Name}}",
        ]
    ).stdout.splitlines()
    hashes: list[str] = []
    states: list[str] = []
    if containers:
        raw = run(
            [
                "docker",
                "inspect",
                "--format",
                "{{json .State.Status}}\t{{json .Config.Labels}}",
                *containers,
            ]
        ).stdout
        for line in raw.splitlines():
            try:
                state_raw, labels_raw = line.split("\t", 1)
                states.append(str(json.loads(state_raw)))
                labels = json.loads(labels_raw) or {}
                value = str(labels.get("com.docker.compose.config-hash") or "")
                if value:
                    hashes.append(value)
            except (ValueError, json.JSONDecodeError) as exc:
                raise AcceptanceError(
                    "engine_state_invalid", "inspect output invalid"
                ) from exc
    return {
        "containers": sorted(containers),
        "volumes": sorted(volumes),
        "networks": sorted(networks),
        "containerStates": sorted(states),
        "configHashes": sorted(set(hashes)),
    }


def wait_for(predicate, timeout: int = 180, interval: int = 3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AcceptanceError("acceptance_timeout", "condition timed out")


def engine_revision(
    app_name: str, previous: set[str] | None = None
) -> dict[str, Any] | bool:
    value = engine_resources(app_name)
    if (
        len(value["containers"]) == 1
        and value["containerStates"] == ["running"]
        and len(value["volumes"]) == 1
        and len(value["networks"]) == 1
        and value["configHashes"]
        and (previous is None or set(value["configHashes"]) != previous)
    ):
        return value
    return False


def cleanup_engine(app_name: str) -> dict[str, Any]:
    before = engine_resources(app_name)
    actions: list[str] = []
    if before["containers"]:
        run(["docker", "rm", "-f", *before["containers"]], allow_failure=True)
        actions.append("container-rm")
    if before["volumes"]:
        run(["docker", "volume", "rm", "-f", *before["volumes"]], allow_failure=True)
        actions.append("volume-rm")
    if before["networks"]:
        run(["docker", "network", "rm", *before["networks"]], allow_failure=True)
        actions.append("network-rm")
    remaining = wait_for(
        lambda: (
            value
            if not any(value[k] for k in ("containers", "volumes", "networks"))
            else False
        )
        if (value := engine_resources(app_name))
        else False,
        timeout=90,
    )
    return {
        "residualBeforeSafetyCleanup": {
            key: len(before[key]) for key in ("containers", "volumes", "networks")
        },
        "safetyCleanupActions": actions,
        "remaining": {
            key: len(remaining[key]) for key in ("containers", "volumes", "networks")
        },
        "noResidualResources": True,
    }


def apply(expected_hash: str) -> dict[str, Any]:
    started = utcnow()
    gate = exact_hash_gate(expected_hash)
    config, values = load_json(CONFIG), dotenv(PLATFORM_ENV)
    image = values.get("MTE_ACTIVEPIECES_DATA_REDIS_IMAGE", "")
    dokploy = load_dokploy()
    base_url = config["spec"]["dokploy"]["baseUrl"]
    credential = dokploy.api_key_proof(base_url)
    api = dokploy.Dokploy(base_url, api_key_only=True)
    projects = api.request("GET", "project.all", retry_login=False)
    project = next(
        (
            row
            for row in projects
            if row.get("name") == config["spec"]["dokploy"]["project"]
        ),
        None,
    )
    if not project:
        raise AcceptanceError("dokploy_project_missing", "managed project missing")
    project_id = project["projectId"]
    project = api.request(
        "GET", "project.one?projectId=" + project_id, retry_login=False
    )
    environment = dokploy.find_environment(
        project, config["spec"]["dokploy"]["environment"]
    )
    if not environment:
        raise AcceptanceError(
            "dokploy_environment_missing", "managed environment missing"
        )
    run_id = secrets.token_hex(6)
    name, app_name = NAME_PREFIX + run_id, APP_PREFIX + run_id
    compose_id = ""
    deleted = False
    lifecycle: list[str] = ["list"]
    first: dict[str, Any] = {}
    second: dict[str, Any] = {}
    cleanup: dict[str, Any] = {}
    try:
        created = api.request(
            "POST",
            "compose.create",
            {
                "name": name,
                "environmentId": environment["environmentId"],
                "composeType": "docker-compose",
                "appName": app_name,
            },
            retry_login=False,
        )
        compose_id = str(created.get("composeId") or "")
        if not compose_id:
            raise AcceptanceError("dokploy_create_failed", "compose ID missing")
        lifecycle.append("create")
        for revision in ("v1", "v2"):
            api.request(
                "POST",
                "compose.update",
                {
                    "composeId": compose_id,
                    "composeFile": compose_document(image, run_id, revision),
                    "sourceType": "raw",
                },
                retry_login=False,
            )
            api.request(
                "POST",
                "compose.saveEnvironment",
                {
                    "composeId": compose_id,
                    "env": "",
                },
                retry_login=False,
            )
            api.request(
                "POST",
                "compose.deploy",
                {
                    "composeId": compose_id,
                    "title": "host acceptance " + revision,
                },
                retry_login=False,
            )
            lifecycle.extend(["update", "status"])
            status = dokploy.wait_terminal(api, compose_id, timeout=600)
            if status not in {"done", "idle"}:
                raise AcceptanceError("dokploy_deploy_failed", revision)
            observed = wait_for(
                lambda: engine_revision(
                    app_name,
                    set(first.get("configHashes", [])) if revision == "v2" else None,
                ),
                timeout=300,
            )
            if revision == "v1":
                first = observed
            else:
                second = observed
        resource = api.request(
            "GET",
            "compose.one?composeId=" + compose_id,
            retry_login=False,
        )
        if resource.get("composeStatus") not in {"done", "idle"}:
            raise AcceptanceError("dokploy_status_failed", "terminal status missing")
        api.request(
            "POST", "compose.delete", {"composeId": compose_id}, retry_login=False
        )
        lifecycle.append("delete")
        deleted = True
        project = api.request(
            "GET", "project.one?projectId=" + project_id, retry_login=False
        )
        if any(
            row.get("composeId") == compose_id for row in dokploy.all_dicts(project)
        ):
            raise AcceptanceError("dokploy_delete_failed", "resource remains in API")
    finally:
        if compose_id and not deleted:
            try:
                api.request(
                    "POST",
                    "compose.delete",
                    {"composeId": compose_id},
                    retry_login=False,
                )
                deleted = True
            except BaseException:
                pass
        cleanup = cleanup_engine(app_name)
    producer_hashes = {
        Path(__file__).name: hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        DOKPLOY_SCRIPT.name: hashlib.sha256(DOKPLOY_SCRIPT.read_bytes()).hexdigest(),
    }
    evidence = {
        "apiVersion": "micro-task-engine/v1alpha1",
        "kind": "HostDokployAcceptanceEvidence",
        "status": "passed",
        "startedAt": started,
        "completedAt": utcnow(),
        "sourceGate": gate,
        "producerHashes": producer_hashes,
        "runId": run_id,
        "C061": {
            "status": "pass",
            "credentialRef": credential["credentialRef"],
            "credentialFingerprintSha256": credential["credentialFingerprintSha256"],
            "apiKeyAuthenticated": credential["apiKeyAuthenticated"],
            "operations": lifecycle,
            "resourceCreated": True,
            "resourceUpdated": True,
            "statusObserved": True,
            "resourceDeleted": deleted,
        },
        "C062": {
            "status": "pass",
            "composeId": compose_id,
            "firstRevision": {
                key: first[key] for key in ("containerStates", "configHashes")
            },
            "secondRevision": {
                key: second[key] for key in ("containerStates", "configHashes")
            },
            "configHashChanged": set(first["configHashes"])
            != set(second["configHashes"]),
            "engineResourcesCreated": {
                key: len(first[key]) for key in ("containers", "volumes", "networks")
            },
            "cleanup": cleanup,
        },
    }
    rendered = json.dumps(evidence, sort_keys=True)
    token = dotenv(PLATFORM_ENV).get("DOKPLOY_API_TOKEN", "")
    if token and token in rendered:
        raise AcceptanceError("evidence_secret_leak", "API token leaked")
    atomic_json(EVIDENCE, evidence)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("apply", "status"))
    parser.add_argument("--expected-source-hash")
    args = parser.parse_args()
    try:
        if args.command == "apply":
            if not args.expected_source_hash:
                raise AcceptanceError("hash_gate_required", "expected hash is required")
            result = apply(args.expected_source_hash)
        else:
            result = load_json(EVIDENCE)
        print(json.dumps({"status": result.get("status"), "evidence": str(EVIDENCE)}))
        return 0
    except AcceptanceError as exc:
        print(json.dumps({"status": "failed", "reason": exc.code}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

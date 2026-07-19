#!/usr/bin/env python3
"""Install ToolHive and reconcile only the shared MCP canary workload.

The exact per-profile groups and workloads belong to
``server-profile-reconcile.py``. A ToolHive group is an inventory bundle, not
an authentication identity; profile identity is enforced by the private MTE
agent-plane gateway.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request


CANONICAL_ENV = Path("/root/.config/mte-secrets/platform.env")
INSTALL_ROOT = Path("/opt/mte-platform/toolhive")
BINARY = INSTALL_ROOT / "bin/thv"
PROFILE_WORKLOAD_OWNER = "server-profile-reconcile.py"
CONTROL_NETWORK = "mte-toolhive-control"
DATA_NETWORK = "mte-tool-runtime"
DOCKER_RUN_VOLUME = "mte-toolhive-docker-run"
DOCKER_UNIX_ARGUMENT = "--host=unix:///var/run/docker.sock"
DOCKER_TCP_PING_PROBE = "http://tool-runtime:2375/_ping"
NEGATIVE_PING_TIMEOUT_SECONDS = 15
PINNED_IMAGE_REF = re.compile(
    r"^(?:[a-z0-9][a-z0-9._-]*(?::[0-9]+)?/)?"
    r"[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*"
    r"@sha256:[a-f0-9]{64}$"
)


def pinned_image_ref(value: str) -> str:
    """Return a Docker image reference only when it is content-addressed."""
    if not PINNED_IMAGE_REF.fullmatch(value):
        raise RuntimeError("ToolHive canary image must be digest pinned")
    return value


def local_image_id(value: str) -> str:
    """Use a pulled image by immutable local ID, never trigger a probe pull."""
    pinned_image_ref(value)
    return "sha256:" + value.rsplit("@sha256:", 1)[1]


def canonical() -> dict[str, str]:
    values = dict(
        line.split("=", 1)
        for line in CANONICAL_ENV.read_text().splitlines()
        if line and not line.startswith("#") and "=" in line
    )
    required = {
        "TOOLHIVE_VERSION",
        "TOOLHIVE_ARCHIVE_URL",
        "TOOLHIVE_ARCHIVE_SHA256",
        "TOOLHIVE_CANARY_IMAGE",
    }
    missing = sorted(key for key in required if not values.get(key))
    if missing:
        raise RuntimeError("missing canonical ToolHive refs: " + ", ".join(missing))
    pinned_image_ref(values["TOOLHIVE_CANARY_IMAGE"])
    return values


def run(
    argv: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    input_text: str | None = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=check,
        text=True,
        capture_output=capture,
        input=input_text,
        timeout=timeout,
    )


def container(service: str = "toolhive") -> str:
    query = (
        run(
            [
                "docker",
                "ps",
                "--no-trunc",
                "-q",
                "--filter",
                f"label=com.docker.compose.service={service}",
            ],
            capture=True,
        )
        .stdout.strip()
        .splitlines()
    )
    if len(query) != 1:
        raise RuntimeError(
            f"expected one running ToolHive {service} container, found {len(query)}"
        )
    return query[0]


def docker_inspect(*targets: str) -> list[dict[str, object]]:
    if not targets:
        return []
    result = run(["docker", "inspect", *targets], capture=True, timeout=30)
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Docker inspect returned invalid JSON") from error
    if not isinstance(payload, list) or any(not isinstance(row, dict) for row in payload):
        raise RuntimeError("Docker inspect returned an invalid container inventory")
    return payload


def network_members(name: str) -> set[str]:
    result = run(
        ["docker", "network", "inspect", name],
        capture=True,
        timeout=30,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"Docker network {name} returned invalid JSON") from error
    if len(payload) != 1 or not isinstance(payload[0], dict):
        raise RuntimeError(f"Docker network {name} inventory is invalid")
    members = payload[0].get("Containers") or {}
    if not isinstance(members, dict):
        raise RuntimeError(f"Docker network {name} member inventory is invalid")
    return set(members)


def _container_name(row: dict[str, object]) -> str:
    return str(row.get("Name") or "").lstrip("/")


def _consumer_kind(row: dict[str, object]) -> str | None:
    config = row.get("Config") if isinstance(row.get("Config"), dict) else {}
    labels = config.get("Labels") if isinstance(config.get("Labels"), dict) else {}
    service = str(labels.get("com.docker.compose.service") or "")
    environment = config.get("Env") if isinstance(config.get("Env"), list) else []
    env_keys = {str(item).partition("=")[0] for item in environment}
    identity = " ".join(
        (
            _container_name(row),
            str(labels.get("com.docker.compose.project") or ""),
        )
    ).lower()
    if _container_name(row) == "mte-daytona-runner":
        return "daytona"
    if service == "api" and (
        {"HARNESS_STARTUP_TIMEOUT_MS", "EXTRACT_WORKER_PORT", "NUQ_RABBITMQ_URL"}
        <= env_keys
        or "firecrawl" in identity
    ):
        return "firecrawl"
    return None


def _assert_ping_unreachable(target: str, probe_image: str) -> None:
    script = (
        "const http=require('node:http');"
        f"const req=http.get({json.dumps(DOCKER_TCP_PING_PROBE)},res=>{{"
        "res.resume();process.exit(42)});"
        "req.setTimeout(1500,()=>{req.destroy();process.exit(0)});"
        "req.on('error',()=>process.exit(0));"
        # DNS/connect phases do not always trigger ClientRequest#setTimeout.
        # Keep this negative-isolation probe bounded even on a black-holed
        # network, rather than letting the verifier consume a worker slot.
        "setTimeout(()=>{req.destroy();process.exit(0)},2000);"
    )
    result = run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            f"container:{target}",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--entrypoint",
            "node",
            probe_image,
            "-e",
            script,
        ],
        check=False,
        capture=True,
        # The canary image itself is immutable and local by this point, but
        # Docker's sandbox/network setup can exceed five seconds on a busy
        # host. The Node request remains capped at two seconds.
        timeout=NEGATIVE_PING_TIMEOUT_SECONDS,
    )
    if result.returncode == 42:
        raise RuntimeError(
            f"Docker API {DOCKER_TCP_PING_PROBE} is reachable from {_container_name(docker_inspect(target)[0])}"
        )
    if result.returncode != 0:
        raise RuntimeError(
            f"cannot prove Docker API isolation from container {target[:12]}"
        )


def control_plane_isolation() -> dict[str, object]:
    manager_id = container()
    runtime_id = container("tool-runtime")
    rows = docker_inspect(runtime_id, manager_id)
    by_id = {str(row.get("Id") or ""): row for row in rows}
    if set(by_id) != {runtime_id, manager_id}:
        raise RuntimeError("ToolHive inspect identities do not match running containers")

    runtime = by_id[runtime_id]
    manager = by_id[manager_id]
    runtime_config = (
        runtime.get("Config") if isinstance(runtime.get("Config"), dict) else {}
    )
    runtime_command = runtime_config.get("Cmd") or []
    if not isinstance(runtime_command, list):
        raise RuntimeError("ToolHive Docker runtime command is invalid")
    command_text = " ".join(str(item) for item in runtime_command)
    if DOCKER_UNIX_ARGUMENT not in runtime_command or "tcp://" in command_text or "2375" in command_text:
        raise RuntimeError("ToolHive Docker runtime must expose only its Unix socket")

    def networks(row: dict[str, object]) -> set[str]:
        settings = (
            row.get("NetworkSettings")
            if isinstance(row.get("NetworkSettings"), dict)
            else {}
        )
        attached = settings.get("Networks") or {}
        if not isinstance(attached, dict):
            raise RuntimeError("ToolHive container network inventory is invalid")
        return set(attached)

    runtime_networks = networks(runtime)
    manager_networks = networks(manager)
    if runtime_networks != {CONTROL_NETWORK}:
        raise RuntimeError("ToolHive Docker runtime escaped its private control network")
    if not {CONTROL_NETWORK, DATA_NETWORK}.issubset(manager_networks):
        raise RuntimeError("ToolHive controller lacks its control/data network split")

    control_members = network_members(CONTROL_NETWORK)
    if control_members != {runtime_id, manager_id}:
        raise RuntimeError("ToolHive control network contains an unauthorized container")
    data_members = network_members(DATA_NETWORK)
    if runtime_id in data_members or manager_id not in data_members:
        raise RuntimeError("ToolHive Docker runtime is exposed on the data network")

    running = (
        run(["docker", "ps", "--no-trunc", "-q"], capture=True, timeout=30)
        .stdout.strip()
        .splitlines()
    )
    inventory = docker_inspect(*running)
    socket_holders: dict[str, bool] = {}
    for row in inventory:
        target_id = str(row.get("Id") or "")
        mounts = row.get("Mounts") or []
        if not isinstance(mounts, list):
            raise RuntimeError("Docker mount inventory is invalid")
        for mount in mounts:
            if isinstance(mount, dict) and mount.get("Name") == DOCKER_RUN_VOLUME:
                socket_holders[target_id] = bool(mount.get("RW"))
    if socket_holders != {runtime_id: True, manager_id: False}:
        raise RuntimeError("ToolHive Docker socket volume has unauthorized holders or modes")

    probe_image = local_image_id(canonical()["TOOLHIVE_CANARY_IMAGE"])
    probed: list[str] = []
    for row in inventory:
        target_id = str(row.get("Id") or "")
        if target_id not in data_members or target_id == manager_id:
            continue
        _assert_ping_unreachable(target_id, probe_image)
        probed.append(_consumer_kind(row) or f"container:{_container_name(row)}")

    return {
        "transport": "unix",
        "controlNetwork": CONTROL_NETWORK,
        "dataNetwork": DATA_NETWORK,
        "controlMembers": 2,
        "socketHolders": 2,
        "tcp2375Reachable": False,
        "negativePingTargets": sorted(probed),
    }


CANARY_NAME = "everything"
CANARY_MARKER = "mte-toolhive-shared-canary"


def workload_status(target: str, name: str = CANARY_NAME) -> dict[str, object]:
    result = run(
        ["docker", "exec", target, "thv", "status", name, "--format", "json"],
        check=False,
        capture=True,
        timeout=30,
    )
    if result.returncode != 0:
        return {}
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def probe_canary(target: str, marker: str = CANARY_MARKER) -> dict[str, object] | None:
    observed = workload_status(target)
    if observed.get("status") != "running":
        return None
    listed = run(
        [
            "docker",
            "exec",
            "-i",
            target,
            "thv",
            "mcp",
            "list",
            "tools",
            "--server",
            CANARY_NAME,
            "--format",
            "json",
        ],
        check=False,
        capture=True,
        timeout=30,
    )
    if listed.returncode != 0:
        return None
    try:
        schema = json.loads(listed.stdout)
    except json.JSONDecodeError:
        return None
    tools = schema.get("tools") if isinstance(schema, dict) else None
    names = sorted(
        str(row.get("name"))
        for row in (tools if isinstance(tools, list) else [])
        if isinstance(row, dict) and row.get("name")
    )
    if "echo" not in names:
        return None
    called = run(
        [
            "docker",
            "exec",
            "-i",
            target,
            "thv",
            "mcp",
            "call",
            "echo",
            "--server",
            CANARY_NAME,
            "--args-file",
            "-",
            "--format",
            "json",
        ],
        check=False,
        capture=True,
        input_text=json.dumps({"message": marker}),
        timeout=60,
    )
    if called.returncode != 0 or marker not in called.stdout:
        return None
    return {"status": "running", "toolCount": len(names), "echoVerified": True}


def wait_canary(target: str, timeout_seconds: int = 180) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        proof = probe_canary(target)
        if proof is not None:
            return proof
        time.sleep(1)
    raise RuntimeError("ToolHive canary workload failed semantic readiness")


def prepare_binary_destination() -> None:
    """Repair only Docker's empty bind-mount placeholder at the binary path."""
    BINARY.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    if not BINARY.exists() or BINARY.is_file():
        return
    if BINARY.is_dir() and not any(BINARY.iterdir()):
        BINARY.rmdir()
        return
    raise RuntimeError("ToolHive binary destination is not a replaceable file")


def install() -> None:
    values = canonical()
    version = values["TOOLHIVE_VERSION"]
    INSTALL_ROOT.mkdir(parents=True, exist_ok=True, mode=0o755)
    prepare_binary_destination()
    current = (
        run([str(BINARY), "version"], check=False, capture=True)
        if BINARY.is_file()
        else None
    )
    if current and current.returncode == 0 and f"v{version}" in current.stdout:
        print(json.dumps({"toolhive": version, "action": "unchanged"}))
        return
    with tempfile.TemporaryDirectory(prefix="mte-toolhive-") as directory:
        archive = Path(directory) / "toolhive.tar.gz"
        urllib.request.urlretrieve(values["TOOLHIVE_ARCHIVE_URL"], archive)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != values["TOOLHIVE_ARCHIVE_SHA256"]:
            raise RuntimeError("ToolHive archive checksum mismatch")
        with tarfile.open(archive, "r:gz") as source:
            members = [
                member
                for member in source.getmembers()
                if Path(member.name).name == "thv" and member.isfile()
            ]
            if len(members) != 1:
                raise RuntimeError(
                    "ToolHive archive does not contain exactly one thv binary"
                )
            extracted = source.extractfile(members[0])
            if extracted is None:
                raise RuntimeError("cannot extract ToolHive binary")
            temp = BINARY.with_suffix(".tmp")
            with temp.open("wb") as target:
                shutil.copyfileobj(extracted, target)
            temp.chmod(0o755)
            temp.replace(BINARY)
    print(json.dumps({"toolhive": version, "action": "installed"}))


def provision() -> None:
    values = canonical()
    target = container()
    proof = probe_canary(target)
    if proof is None:
        observed = workload_status(target)
        if observed:
            run(
                ["docker", "exec", target, "thv", "rm", CANARY_NAME],
                check=False,
            )
        runtime = container("tool-runtime")
        # The isolation probe uses the same immutable canary image. Pull it
        # through the sole Docker-capable runtime before probing, so a first
        # provision cannot time out while Docker is downloading an image.
        run(
            [
                "docker",
                "exec",
                runtime,
                "docker",
                "pull",
                values["TOOLHIVE_CANARY_IMAGE"],
            ]
        )
    isolation = control_plane_isolation()
    if proof is None:
        run(
            [
                "docker",
                "exec",
                target,
                "thv",
                "run",
                "--name",
                CANARY_NAME,
                "--transport",
                "stdio",
                "--proxy-port",
                "19001",
                "--host",
                "0.0.0.0",
                values["TOOLHIVE_CANARY_IMAGE"],
            ]
        )
        proof = wait_canary(target)
    print(
        json.dumps(
            {
                "workload": CANARY_NAME,
                "action": "ready",
                "canaryStatus": proof["status"],
                "toolCount": proof["toolCount"],
                "echoVerified": proof["echoVerified"],
                "profileWorkloadOwner": PROFILE_WORKLOAD_OWNER,
                "groupProvidesIdentity": False,
                "dockerControlPlane": isolation,
            }
        )
    )


def status() -> None:
    version = run([str(BINARY), "version"], check=False, capture=True)
    target = container()
    observed = workload_status(target)
    print(
        json.dumps(
            {
                "binary": "ready" if version.returncode == 0 else "missing",
                "container": target[:12],
                "canary": (
                    "ready" if observed.get("status") == "running" else "not-ready"
                ),
                "workloadStatus": observed.get("status", "missing"),
                "profileWorkloadOwner": PROFILE_WORKLOAD_OWNER,
                "groupProvidesIdentity": False,
            },
            indent=2,
        )
    )


def verify() -> None:
    if run([str(BINARY), "version"], check=False).returncode != 0:
        raise RuntimeError("ToolHive binary is not executable")
    target = container()
    isolation = control_plane_isolation()
    proof = wait_canary(target, timeout_seconds=45)
    print(
        json.dumps(
            {
                "toolhive": "ready",
                "canary": "ready",
                "workloadStatus": proof["status"],
                "toolCount": proof["toolCount"],
                "echoVerified": proof["echoVerified"],
                "profileWorkloadOwner": PROFILE_WORKLOAD_OWNER,
                "groupProvidesIdentity": False,
                "dockerControlPlane": isolation,
            }
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["install", "provision", "status", "verify"])
    args = parser.parse_args()
    {"install": install, "provision": provision, "status": status, "verify": verify}[
        args.action
    ]()


if __name__ == "__main__":
    main()

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


def install() -> None:
    values = canonical()
    version = values["TOOLHIVE_VERSION"]
    INSTALL_ROOT.mkdir(parents=True, exist_ok=True, mode=0o755)
    BINARY.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    current = (
        run([str(BINARY), "version"], check=False, capture=True)
        if BINARY.exists()
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

#!/usr/bin/env python3
"""Install and operate the pinned native Hermes runtime on a VPS.

This script is intentionally server-local and uses only the standard library.
It never prints secret values and never imports credentials from unrelated
projects. The only credential source is the configured platform EnvironmentFile.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request


VERSION = "0.18.2"
REPOSITORY = "https://github.com/NousResearch/hermes-agent.git"
TAG = "v2026.7.7.2"
COMMIT = "9de9c25f620ff7f1ce0fd5457d596052d5159596"
HERMES_WHEEL_FILENAME = "hermes_agent-0.18.2-py3-none-any.whl"
HERMES_WHEEL_URL = (
    "https://files.pythonhosted.org/packages/0c/4c/"
    "91652c61450763bfe165c65b83026503de0ac9ddad2c11ee522490bf4c2d/"
    + HERMES_WHEEL_FILENAME
)
HERMES_WHEEL_SHA256 = (
    "8f02155cfc84b28bd98551cd18dffec0efa9ec070dd08f90f1a850f1c779492f"
)
HERMES_PYPI_PROVENANCE_URL = (
    "https://pypi.org/integrity/hermes-agent/0.18.2/"
    + HERMES_WHEEL_FILENAME
    + "/provenance"
)
HERMES_SIGSTORE_BUNDLE_URL = (
    "https://github.com/NousResearch/hermes-agent/releases/download/"
    f"{TAG}/{HERMES_WHEEL_FILENAME}.sigstore.json"
)
HERMES_SIGSTORE_BUNDLE_SHA256 = (
    "20cea7962a0773b21c75652845742ae5d414632864cd08684993f286f486c0ad"
)
HERMES_SIGNER_REPOSITORY = "NousResearch/hermes-agent"
HERMES_SIGNER_WORKFLOW = "release.yml"
HERMES_SIGNER_IDENTITY = "https://github.com/NousResearch/hermes-agent/.github/workflows/release.yml@refs/tags/v2026.7.7.2"
HERMES_SIGNER_TAG_REF = "refs/tags/v2026.7.7.2"
HERMES_SIGNER_ISSUER = "https://token.actions.githubusercontent.com"
PYPI_PUBLISH_ATTESTATION_TYPE = "https://docs.pypi.org/attestations/publish/v1"
SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
SUPPLY_CHAIN_MANIFEST_SHA256 = (
    "df6813bc80d4ee3a3716ea15dde9551de658a60a8e7499ea4e447eb7a52469c1"
)
OPERATOR_MODES = frozenset({"unprivileged_service", "unrestricted_host_repair"})

SERVICE = "mte-hermes.service"
LEGACY_SERVICE = "mte-hermes-operator.service"
SERVICE_USER = "mte-hermes"
INSTALL_ROOT = Path("/opt/mte-hermes")
RELEASE = INSTALL_ROOT / "releases" / VERSION
VENV = RELEASE / "venv"
LEGACY_SOURCE = RELEASE / "source"
SUPPLY_CHAIN_RECEIPT = RELEASE / "supply-chain-receipt.json"
CURRENT = INSTALL_ROOT / "current"
BIN_ROOT = INSTALL_ROOT / "bin"
SHARE_ROOT = INSTALL_ROOT / "share"
STATE_ROOT = Path("/var/lib/mte-hermes")
UNIT_PATH = Path("/etc/systemd/system") / SERVICE
LEGACY_UNIT_PATH = Path("/etc/systemd/system") / LEGACY_SERVICE
SUDOERS_PATH = Path("/etc/sudoers.d/mte-hermes-platform-admin")
DEFAULT_ENV_FILE = Path("/root/.config/mte-secrets/platform.env")
HERMES_RUNTIME_ENV_FILE = Path("/root/.config/mte-secrets/services/hermes.env")
PLATFORM_ROOT = Path("/opt/mte-platform")
CONFIG_RENDERER = PLATFORM_ROOT / "bin/server-config.py"
PROJECTIONS_MANIFEST = DEFAULT_ENV_FILE.parent / "projections-manifest.json"
PLATFORM_ENV_LOCK = DEFAULT_ENV_FILE.parent / ".platform-env.lock"

REQUIRED_KEYS = (
    "HERMES_LLM_API_KEY",
    "HERMES_LLM_BASE_URL",
    "HERMES_LLM_MODEL",
    "HERMES_LLM_PROVIDER",
    "HERMES_LLM_API_MODE",
    "HERMES_PAPERCLIP_URL",
    "HERMES_KESTRA_URL",
    "KESTRA_HEALTH_URL",
    "HERMES_TERMINAL_CWD",
    "HERMES_TERMINAL_BACKEND",
    "HERMES_TERMINAL_HOME_MODE",
    "HERMES_TERMINAL_TIMEOUT",
    "HERMES_TERMINAL_LIFETIME_SECONDS",
    "HERMES_APPROVALS_MODE",
    "HERMES_APPROVALS_TIMEOUT",
    "HERMES_APPROVALS_CRON_MODE",
    "HERMES_APPROVALS_MCP_RELOAD_CONFIRM",
    "HERMES_APPROVALS_DESTRUCTIVE_SLASH_CONFIRM",
    "HERMES_GATEWAY_STREAMING_ENABLED",
    "HERMES_GATEWAY_STREAMING_TRANSPORT",
    "HERMES_TELEGRAM_REQUIRE_MENTION",
    "HERMES_TELEGRAM_EXCLUSIVE_BOT_MENTIONS",
    "HERMES_TELEGRAM_GUEST_MODE",
    "HERMES_EXEC_ASK",
    "HERMES_API_SERVER_ENABLED",
    "HERMES_API_SERVER_KEY",
    "HERMES_API_SERVER_HOST",
    "HERMES_API_SERVER_PORT",
    "HERMES_API_SERVER_MODEL_NAME",
    "HERMES_PAPERCLIP_API_KEY",
    "HERMES_DISPLAY_TOOL_PROGRESS",
    "HERMES_TELEGRAM_NOTIFICATIONS",
    "HERMES_OPERATOR_MODE",
)
INSTALL_ONLY_KEYS = (
    "HERMES_APT_PACKAGES",
    "HERMES_SIGSTORE_PACKAGE_VERSION",
    "HERMES_SIGSTORE_VERIFIER_IMAGE",
)

# The native Hermes process receives only this explicit projection. It never
# receives the complete platform credential file.
HERMES_RUNTIME_REQUIRED_KEYS = REQUIRED_KEYS
HERMES_RUNTIME_KEYS = frozenset(
    {
        *HERMES_RUNTIME_REQUIRED_KEYS,
        "CONTEXT7_API_KEY",
        "HERMES_TELEGRAM_BOT_TOKEN",
        "HERMES_TELEGRAM_ALLOWED_USERS",
        "HERMES_KESTRA_USERNAME",
        "HERMES_KESTRA_PASSWORD",
        "MATTERMOST_URL",
        "MATTERMOST_TOKEN",
        "MATTERMOST_ALLOWED_USERS",
        "MATTERMOST_HOME_CHANNEL",
        "MATTERMOST_REPLY_MODE",
        "MATTERMOST_REQUIRE_MENTION",
    }
)

# Canonical platform names stay stable for the deployment layer. The generated
# EnvironmentFile uses the variable names understood by upstream Hermes.
HERMES_NATIVE_ENV_NAMES = {
    "HERMES_LLM_API_KEY": "OPENAI_API_KEY",
    "HERMES_LLM_BASE_URL": "OPENAI_BASE_URL",
    "HERMES_TELEGRAM_BOT_TOKEN": "TELEGRAM_BOT_TOKEN",
    "HERMES_TELEGRAM_ALLOWED_USERS": "TELEGRAM_ALLOWED_USERS",
    "HERMES_API_SERVER_ENABLED": "API_SERVER_ENABLED",
    "HERMES_API_SERVER_KEY": "API_SERVER_KEY",
    "HERMES_API_SERVER_HOST": "API_SERVER_HOST",
    "HERMES_API_SERVER_PORT": "API_SERVER_PORT",
    "HERMES_API_SERVER_MODEL_NAME": "API_SERVER_MODEL_NAME",
    "HERMES_PAPERCLIP_URL": "PAPERCLIP_API_URL",
    "HERMES_PAPERCLIP_API_KEY": "PAPERCLIP_BRIDGE_API_KEY",
}

CONTEXT7_MCP_URL = "https://mcp.context7.com/mcp"
CONTEXT7_MCP_PROTOCOL_VERSION = "2025-03-26"
CONTEXT7_MCP_TOOLS = ("resolve-library-id", "query-docs")
PLATFORM_SKILL_NAME = "system-platform"
LEGACY_PLATFORM_SKILL_NAME = "mte-platform"


class HermesInstallError(RuntimeError):
    pass


def emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def command(
    argv: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    cwd: Path | None = None,
    timeout: int = 1800,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=check,
        text=True,
        capture_output=capture,
        cwd=str(cwd) if cwd else None,
        timeout=timeout,
    )


def require_root() -> None:
    if os.geteuid() != 0:
        raise HermesInstallError("this action must run as root")


def hermes_asset_paths() -> dict[str, Path]:
    """Resolve the canonical checkout or its compatible server projection."""
    installed = Path(__file__).resolve()
    root = (
        installed.parents[2]
        if installed.parent.name == "platform-cli"
        and installed.parent.parent.name == "tools"
        else installed.parents[1]
    )
    projected = root / "manifests/hermes"
    candidates = (
        {
            "acceptance": root / "deployment/services/hermes/acceptance-canary.py",
            "mattermostBootstrap": root
            / "deployment/services/hermes/bootstrap-mattermost.py",
            "configTemplate": root / "deployment/services/hermes/config.yaml.template",
            "soul": root / "deployment/services/hermes/soul.txt",
            "platformSkill": root / "skills/system-platform",
            "requirementsLock": root
            / "deployment/services/hermes/requirements-messaging.lock",
            "serviceUnit": root / "deployment/services/hermes/service.unit",
            "supplyChainLock": root
            / "deployment/services/hermes/supply-chain.lock.json",
        },
        {
            "acceptance": projected / "acceptance-canary.py",
            "mattermostBootstrap": projected / "bootstrap-mattermost.py",
            "configTemplate": projected / "config.yaml.template",
            "soul": projected / "SOUL.md",
            "platformSkill": projected / "skills/system-platform",
            "requirementsLock": projected / "requirements-messaging.lock",
            "serviceUnit": projected / "hermes.service",
            "supplyChainLock": projected / "supply-chain.lock.json",
        },
    )
    for assets in candidates:
        if all(
            path.is_dir() if name == "platformSkill" else path.is_file()
            for name, path in assets.items()
        ):
            return assets
    raise HermesInstallError(
        "Hermes runtime assets are missing from the synchronized platform"
    )


def parse_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        raise HermesInstallError(f"credential source does not exist: {path}")
    for number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            raise HermesInstallError(f"invalid dotenv syntax at line {number}")
        name, value = stripped.split("=", 1)
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise HermesInstallError(f"invalid dotenv key at line {number}")
        values[name] = value.strip()
    return values


def public_mode_requested(path: Path) -> bool:
    """Fail toward immediate privilege revocation before strict validation."""
    try:
        values = parse_dotenv(path)
    except (HermesInstallError, OSError, UnicodeError):
        return True
    return values.get("HERMES_OPERATOR_MODE", "").strip() != (
        "unrestricted_host_repair"
    )


def source_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_atomic_output_path(destination: Path) -> None:
    """Reject destinations or direct parents that could redirect privileged writes."""
    if not destination.is_absolute():
        raise HermesInstallError(
            f"refusing a relative atomic-write destination: {destination}"
        )
    try:
        parent_info = destination.parent.lstat()
    except FileNotFoundError:
        parent_info = None
    if parent_info is not None and stat.S_ISLNK(parent_info.st_mode):
        raise HermesInstallError(
            f"refusing an unsafe atomic-write path: {destination.parent}"
        )
    if parent_info is not None and not stat.S_ISDIR(parent_info.st_mode):
        raise HermesInstallError(
            f"refusing an unsafe atomic-write path: {destination.parent}"
        )
    try:
        destination_info = destination.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(destination_info.st_mode):
        raise HermesInstallError(
            f"refusing an unsafe atomic-write path: {destination}"
        )


def atomic_write_bytes(
    destination: Path,
    content: bytes,
    *,
    mode: int,
    owner: tuple[int, int] | None = None,
    validator: Callable[[Path], None] | None = None,
) -> None:
    """Atomically replace a file without exposing its content through a guessed path."""
    validate_atomic_output_path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    # Re-check after creation so no symlink is followed before the private
    # temporary receives owner-controlled content.
    validate_atomic_output_path(destination)
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".new", dir=str(destination.parent)
    )
    temporary = Path(raw_temporary)
    handle = None
    try:
        # mkstemp creates 0600, and the requested final mode/owner are applied
        # before content is written. This is required for rendered credential
        # references and protected Hermes state.
        os.fchmod(descriptor, mode)
        if owner is not None:
            os.fchown(descriptor, *owner)
        handle = os.fdopen(descriptor, "wb")
        descriptor = -1
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        handle = None
        if validator is not None:
            validator(temporary)
        os.replace(temporary, destination)
    finally:
        if handle is not None:
            handle.close()
        elif descriptor != -1:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def atomic_write_text(
    destination: Path,
    content: str,
    *,
    mode: int,
    owner: tuple[int, int] | None = None,
    validator: Callable[[Path], None] | None = None,
) -> None:
    atomic_write_bytes(
        destination,
        content.encode("utf-8"),
        mode=mode,
        owner=owner,
        validator=validator,
    )


def normalize_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def download_private_artifact(url: str, destination: Path, *, limit: int) -> None:
    """Download one locked artifact without exposing partial bytes to other users."""
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json, application/octet-stream"},
        )
        with urllib.request.urlopen(request, timeout=120) as response:
            written = 0
            with os.fdopen(descriptor, "wb") as output:
                descriptor = -1
                while chunk := response.read(1024 * 1024):
                    written += len(chunk)
                    if written > limit:
                        raise HermesInstallError(
                            "Hermes supply-chain artifact is too large"
                        )
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
    except (OSError, urllib.error.URLError) as error:
        raise HermesInstallError(
            f"failed to download locked Hermes artifact from {url}"
        ) from error
    finally:
        if descriptor != -1:
            os.close(descriptor)


SIGSTORE_VERIFY_PROGRAM = r"""
const fs = require("fs");
const moduleRoot = "/usr/local/lib/node_modules/npm/node_modules";
const packageMetadata = require(moduleRoot + "/sigstore/package.json");
if (packageMetadata.version !== process.argv[5]) {
  throw new Error(`locked sigstore package ${process.argv[5]} required`);
}
const { verify } = require(moduleRoot + "/sigstore");
const bundle = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const artifact = fs.readFileSync(process.argv[1]);
verify(bundle, artifact, {
  certificateIdentityURI: process.argv[3],
  certificateIssuer: process.argv[4],
  ctLogThreshold: 1,
  tlogThreshold: 1,
}).catch((error) => {
  console.error(error instanceof Error ? error.message : "verification failed");
  process.exitCode = 1;
});
""".strip()


def sigstore_verifier_config(values: dict[str, str]) -> tuple[str, str]:
    """Read the immutable verifier pair from the canonical configuration."""
    image = values.get("HERMES_SIGSTORE_VERIFIER_IMAGE", "").strip()
    package_version = values.get("HERMES_SIGSTORE_PACKAGE_VERSION", "").strip()
    if not re.fullmatch(r"node:[^@\s]+@sha256:[0-9a-f]{64}", image):
        raise HermesInstallError("HERMES_SIGSTORE_VERIFIER_IMAGE must be digest-pinned Node")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", package_version):
        raise HermesInstallError("HERMES_SIGSTORE_PACKAGE_VERSION is invalid")
    return image, package_version


def run_sigstore_verifier(
    wheel: Path, bundle_path: Path, workspace: Path, values: dict[str, str]
) -> None:
    """Verify with the official Sigstore library in an immutable runtime."""
    verifier_image, package_version = sigstore_verifier_config(values)
    if shutil.which("docker") is None:
        raise HermesInstallError("Docker is required for Sigstore verification")
    result = command(
        [
            "docker",
            "run",
            "--rm",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--mount",
            f"type=bind,src={workspace},dst=/verify,readonly",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--tmpfs",
            "/root/.sigstore:rw,noexec,nosuid,size=16m",
            verifier_image,
            "node",
            "-e",
            SIGSTORE_VERIFY_PROGRAM,
            f"/verify/{wheel.name}",
            f"/verify/{bundle_path.name}",
            HERMES_SIGNER_IDENTITY,
            HERMES_SIGNER_ISSUER,
            package_version,
        ],
        check=False,
        capture=True,
        timeout=180,
    )
    if result.returncode != 0:
        raise HermesInstallError("Hermes Sigstore verification failed")


def verify_sigstore_bundle(
    wheel: Path, bundle_path: Path, workspace: Path, values: dict[str, str]
) -> None:
    if source_hash(bundle_path) != HERMES_SIGSTORE_BUNDLE_SHA256:
        raise HermesInstallError("Hermes Sigstore bundle hash drifted")
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HermesInstallError("Hermes Sigstore bundle is invalid") from error
    if not isinstance(bundle, dict):
        raise HermesInstallError("Hermes Sigstore bundle contract is invalid")
    if bundle.get("mediaType") != SIGSTORE_BUNDLE_MEDIA_TYPE:
        raise HermesInstallError("Hermes Sigstore bundle contract is invalid")
    run_sigstore_verifier(wheel, bundle_path, workspace, values)


def decode_base64(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise HermesInstallError(f"invalid {label}")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise HermesInstallError(f"invalid {label}") from error


def verify_pypi_provenance(wheel: Path, provenance_path: Path, workspace: Path) -> None:
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HermesInstallError("Hermes PyPI provenance is invalid") from error
    bundles = (
        provenance.get("attestation_bundles")
        if isinstance(provenance, dict)
        else None
    )
    if (
        not isinstance(provenance, dict)
        or provenance.get("version") != 1
        or not isinstance(bundles, list)
    ):
        raise HermesInstallError("Hermes PyPI provenance contract is invalid")
    for bundle in bundles:
        publisher = bundle.get("publisher") if isinstance(bundle, dict) else None
        attestations = bundle.get("attestations") if isinstance(bundle, dict) else None
        if (
            not isinstance(publisher, dict)
            or publisher.get("kind") != "GitHub"
            or publisher.get("repository") != HERMES_SIGNER_REPOSITORY
            or publisher.get("workflow") != HERMES_SIGNER_WORKFLOW
            or not isinstance(attestations, list)
        ):
            continue
        for attestation in attestations:
            if not isinstance(attestation, dict):
                continue
            envelope = attestation.get("envelope")
            material = attestation.get("verification_material")
            if (
                attestation.get("version") != 1
                or not isinstance(envelope, dict)
                or not isinstance(material, dict)
                or not material.get("transparency_entries")
            ):
                continue
            statement_bytes = decode_base64(
                envelope.get("statement"), "PyPI attestation statement"
            )
            try:
                statement = json.loads(statement_bytes)
            except json.JSONDecodeError:
                continue
            if not isinstance(statement, dict):
                continue
            subjects = statement.get("subject")
            if (
                statement.get("predicateType") != PYPI_PUBLISH_ATTESTATION_TYPE
                or not isinstance(subjects, list)
                or not any(
                    isinstance(subject, dict)
                    and subject.get("name") == HERMES_WHEEL_FILENAME
                    and isinstance(subject.get("digest"), dict)
                    and subject["digest"].get("sha256") == HERMES_WHEEL_SHA256
                    for subject in subjects
                )
            ):
                continue
            return
    raise HermesInstallError(
        "Hermes PyPI provenance has no valid locked-wheel publish attestation"
    )


def fetch_and_verify_hermes_artifacts(
    supply: dict[str, Any], workspace: Path, values: dict[str, str]
) -> Path:
    workspace.chmod(0o700)
    wheel = workspace / HERMES_WHEEL_FILENAME
    provenance = workspace / "pypi-provenance.json"
    bundle = workspace / f"{HERMES_WHEEL_FILENAME}.sigstore.json"
    download_private_artifact(HERMES_WHEEL_URL, wheel, limit=16 * 1024 * 1024)
    download_private_artifact(
        HERMES_PYPI_PROVENANCE_URL, provenance, limit=4 * 1024 * 1024
    )
    download_private_artifact(HERMES_SIGSTORE_BUNDLE_URL, bundle, limit=4 * 1024 * 1024)
    if (
        wheel.stat().st_size != supply["wheelSize"]
        or source_hash(wheel) != HERMES_WHEEL_SHA256
    ):
        raise HermesInstallError("downloaded Hermes wheel hash or size drifted")
    verify_sigstore_bundle(wheel, bundle, workspace, values)
    verify_pypi_provenance(wheel, provenance, workspace)
    return wheel


def validate_supply_chain_assets(
    values: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Validate the committed Hermes/Python closure before any network access."""
    assets = hermes_asset_paths()
    manifest_path = assets["supplyChainLock"]
    requirements_path = assets["requirementsLock"]
    for path in (manifest_path, requirements_path):
        if not path.is_file() or path.is_symlink():
            raise HermesInstallError(f"Hermes supply-chain asset is unsafe: {path}")
    manifest_sha = source_hash(manifest_path)
    if manifest_sha != SUPPLY_CHAIN_MANIFEST_SHA256:
        raise HermesInstallError("Hermes supply-chain manifest hash drifted")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise HermesInstallError("Hermes supply-chain manifest is invalid") from error
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
        raise HermesInstallError("Hermes supply-chain schema is unsupported")
    provenance = manifest.get("hermes", {}).get("provenance", {})
    if values is None:
        verifier_image = provenance.get("sigstoreVerifierImage")
        package_version = provenance.get("sigstoreVerifierPackageVersion")
    else:
        verifier_image, package_version = sigstore_verifier_config(values)
    if manifest.get("hermes") != {
        "distribution": "hermes-agent",
        "extras": ["messaging", "mcp"],
        "version": VERSION,
        "wheel": {
            "filename": HERMES_WHEEL_FILENAME,
            "url": HERMES_WHEEL_URL,
            "sha256": HERMES_WHEEL_SHA256,
            "size": 9569078,
        },
        "provenance": {
            "pypi": HERMES_PYPI_PROVENANCE_URL,
            "signerIdentity": HERMES_SIGNER_IDENTITY,
            "signerIssuer": HERMES_SIGNER_ISSUER,
            "signerRepository": HERMES_SIGNER_REPOSITORY,
            "signerTagRef": HERMES_SIGNER_TAG_REF,
            "sigstoreBundleUrl": HERMES_SIGSTORE_BUNDLE_URL,
            "sigstoreBundleSha256": HERMES_SIGSTORE_BUNDLE_SHA256,
            "sigstoreVerifierImage": verifier_image,
            "sigstoreVerifierPackageVersion": package_version,
        },
        "upstream": {
            "repository": REPOSITORY,
            "tag": TAG,
            "commit": COMMIT,
        },
    }:
        raise HermesInstallError("Hermes wheel identity does not match its lock")

    os_lock = manifest.get("osPackages")
    expected_os_names = (
        "ca-certificates",
        "curl",
        "ffmpeg",
        "python3",
        "python3-venv",
        "ripgrep",
        "sudo",
    )
    if (
        not isinstance(os_lock, dict)
        or os_lock.get("canonicalEnvironmentKey") != "HERMES_APT_PACKAGES"
        or tuple(os_lock.get("names", ())) != expected_os_names
    ):
        raise HermesInstallError("Hermes OS package lock is invalid")

    packages: dict[str, str] = {}
    extras: dict[str, tuple[str, ...]] = {}
    lock_pattern = re.compile(
        r"([a-z0-9][a-z0-9-]*)(?:\[([a-z0-9,-]+)\])?=="
        r"([A-Za-z0-9][A-Za-z0-9.!+_-]*) "
        r"--hash=sha256:([0-9a-f]{64})"
    )
    for number, raw in enumerate(
        requirements_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        matched = lock_pattern.fullmatch(line)
        if matched is None:
            raise HermesInstallError(
                f"invalid Hermes requirement lock syntax at line {number}"
            )
        name = normalize_distribution_name(matched.group(1))
        if name in packages:
            raise HermesInstallError(f"duplicate Hermes requirement lock entry: {name}")
        packages[name] = matched.group(3)
        extras[name] = (
            tuple(sorted(matched.group(2).split(","))) if matched.group(2) else ()
        )
    python_lock = manifest.get("python")
    if not isinstance(python_lock, dict) or python_lock != {
        "abi": "cp312",
        "allowDependencySourceBuilds": False,
        "implementation": "cp",
        "packageCount": len(packages),
        "platform": "manylinux2014_x86_64",
        "requirementsFile": requirements_path.name,
        "requirementsSha256": source_hash(requirements_path),
        "resolvedAt": "2026-07-20",
        "version": "3.12",
    }:
        raise HermesInstallError("Hermes Python dependency lock is invalid")
    if (
        packages.get("hermes-agent") != VERSION
        or extras.get("hermes-agent") != ("mcp", "messaging")
        or packages.get("mcp") != "1.26.0"
    ):
        raise HermesInstallError("Hermes wheel extras closure is incomplete")
    return {
        "manifestSha256": manifest_sha,
        "requirementsPath": requirements_path,
        "requirementsSha256": source_hash(requirements_path),
        "pythonPackages": packages,
        "osPackageNames": expected_os_names,
        "wheelSha256": HERMES_WHEEL_SHA256,
        "wheelSize": 9569078,
        "wheelUrl": HERMES_WHEEL_URL,
    }


def parse_pinned_apt_packages(values: dict[str, str]) -> dict[str, str]:
    supply = validate_supply_chain_assets()
    raw = values.get("HERMES_APT_PACKAGES", "").strip()
    packages: dict[str, str] = {}
    for item in raw.split(",") if raw else ():
        if item.count("=") != 1:
            raise HermesInstallError("HERMES_APT_PACKAGES must pin package=version")
        name, version = (part.strip() for part in item.split("=", 1))
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name) or not re.fullmatch(
            r"[A-Za-z0-9.+:~_-]+", version
        ):
            raise HermesInstallError("HERMES_APT_PACKAGES contains an invalid pin")
        if name in packages:
            raise HermesInstallError(f"duplicate Hermes OS package pin: {name}")
        packages[name] = version
    if tuple(sorted(packages)) != tuple(supply["osPackageNames"]):
        raise HermesInstallError(
            "HERMES_APT_PACKAGES does not match the governed Hermes OS package set"
        )
    return packages


@contextmanager
def platform_env_lock():
    """Use the canonical writer lock for source-derived Hermes artifacts."""
    DEFAULT_ENV_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with PLATFORM_ENV_LOCK.open("a+") as handle:
        PLATFORM_ENV_LOCK.chmod(0o600)
        if os.geteuid() == 0:
            os.chown(PLATFORM_ENV_LOCK, 0, 0)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def runtime_credential_projection_evidence(
    path: Path, expected_source_sha: str
) -> dict[str, Any]:
    """Verify the renderer-owned Hermes service projection without mutating it."""
    if source_hash(path) != expected_source_sha:
        raise HermesInstallError(
            "canonical platform credential changed after projection reconciliation"
        )
    for projection, expected_mode in (
        (PROJECTIONS_MANIFEST, 0o600),
        (HERMES_RUNTIME_ENV_FILE.parent, 0o700),
        (HERMES_RUNTIME_ENV_FILE, 0o600),
    ):
        if not projection.exists() or projection.is_symlink():
            raise HermesInstallError(
                f"Hermes credential projection artifact is missing or unsafe: {projection}"
            )
        info = projection.stat()
        if stat.S_IMODE(info.st_mode) != expected_mode:
            raise HermesInstallError(
                f"Hermes credential projection artifact has unsafe mode: {projection}"
            )
        if os.geteuid() == 0 and (info.st_uid != 0 or info.st_gid != 0):
            raise HermesInstallError(
                f"Hermes credential projection artifact is not root-owned: {projection}"
            )
    try:
        manifest = json.loads(PROJECTIONS_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HermesInstallError("projection manifest is unreadable") from exc
    if not isinstance(manifest, dict):
        raise HermesInstallError("projection manifest is not an object")
    if manifest.get("sourceSha256") != expected_source_sha:
        raise HermesInstallError("projection manifest source hash does not match")
    rows = manifest.get("projections")
    if not isinstance(rows, list):
        raise HermesInstallError("projection manifest rows are invalid")
    matching_rows = [
        row
        for row in rows
        if isinstance(row, dict) and row.get("path") == str(HERMES_RUNTIME_ENV_FILE)
    ]
    if len(matching_rows) != 1:
        raise HermesInstallError(
            "Hermes credential projection is not uniquely registered"
        )
    row = matching_rows[0]
    if row.get("sourceSha256") != expected_source_sha or not row.get(
        "generatorVersion"
    ):
        raise HermesInstallError("Hermes credential projection metadata is stale")
    runtime_sha = source_hash(HERMES_RUNTIME_ENV_FILE)
    if row.get("contentSha256") != runtime_sha:
        raise HermesInstallError("Hermes credential projection content hash drifted")
    canonical = parse_dotenv(path)
    missing = sorted(
        key
        for key in HERMES_RUNTIME_REQUIRED_KEYS
        if not canonical.get(key, "").strip()
    )
    if missing:
        raise HermesInstallError(
            "Hermes runtime credential projection is missing: " + ", ".join(missing)
        )
    expected_values = {
        HERMES_NATIVE_ENV_NAMES.get(key, key): canonical[key]
        for key in sorted(HERMES_RUNTIME_KEYS)
        if canonical.get(key, "").strip()
    }
    if parse_dotenv(HERMES_RUNTIME_ENV_FILE) != expected_values:
        raise HermesInstallError(
            "Hermes credential projection does not match its canonical allowlist"
        )
    if source_hash(path) != expected_source_sha:
        raise HermesInstallError(
            "canonical platform credential changed during projection verification"
        )
    return {
        "keyCount": len(expected_values),
        "runtimeSha256": runtime_sha,
        "sourceSha256": expected_source_sha,
        "manifestBound": True,
        "path": str(HERMES_RUNTIME_ENV_FILE),
    }


def runtime_credential_projection_matches(path: Path) -> bool:
    try:
        runtime_credential_projection_evidence(path, source_hash(path))
    except (HermesInstallError, OSError):
        return False
    return True


def require_bool(values: dict[str, str], name: str) -> bool:
    value = values[name].strip().lower()
    if value not in {"true", "false"}:
        raise HermesInstallError(f"{name} must be true or false")
    return value == "true"


def require_int(values: dict[str, str], name: str, minimum: int, maximum: int) -> int:
    value = values[name].strip()
    if not value.isdigit() or not minimum <= int(value) <= maximum:
        raise HermesInstallError(f"{name} must be an integer in {minimum}..{maximum}")
    return int(value)


def validate_api_server_host(value: str) -> str:
    host = value.strip()
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise HermesInstallError(
            "HERMES_API_SERVER_HOST must be an IP address"
        ) from exc
    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or not (address.is_loopback or address.is_private)
    ):
        raise HermesInstallError(
            "HERMES_API_SERVER_HOST must be loopback or a private Docker bridge address"
        )
    return host


def require_loopback_http_url(
    values: dict[str, str], name: str, *, expected_path: str
) -> str:
    raw = values.get(name, "").strip()
    try:
        parsed = urllib.parse.urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise HermesInstallError(f"{name} is not a valid URL") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or port is None
        or parsed.path != expected_path
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise HermesInstallError(
            f"{name} must use exact HTTP loopback URL path {expected_path or '/'}"
        )
    return raw


def dependency_health_endpoints(values: dict[str, str]) -> dict[str, str]:
    paperclip_api = require_loopback_http_url(
        values, "HERMES_PAPERCLIP_URL", expected_path="/api"
    )
    require_loopback_http_url(values, "HERMES_KESTRA_URL", expected_path="")
    kestra_health = require_loopback_http_url(
        values, "KESTRA_HEALTH_URL", expected_path="/health"
    )
    return {
        "paperclipApi": paperclip_api + "/health",
        "kestraApi": kestra_health,
    }


def validate_env_file(path: Path) -> dict[str, Any]:
    file_stat = path.stat() if path.exists() else None
    if file_stat is None:
        raise HermesInstallError(f"credential source does not exist: {path}")
    if file_stat.st_uid != 0:
        raise HermesInstallError("platform credential source must be owned by root")
    if stat.S_IMODE(file_stat.st_mode) & 0o077:
        raise HermesInstallError(
            "platform credential source must not be accessible by group/other"
        )

    values = parse_dotenv(path)
    missing = [
        name
        for name in (*REQUIRED_KEYS, *INSTALL_ONLY_KEYS)
        if not values.get(name, "").strip()
    ]
    if missing:
        raise HermesInstallError(
            "empty required credential references: " + ", ".join(missing)
        )
    apt_packages = parse_pinned_apt_packages(values)
    supply = validate_supply_chain_assets(values)

    token = values.get("HERMES_TELEGRAM_BOT_TOKEN", "").strip()
    telegram_allowed_raw = values.get("HERMES_TELEGRAM_ALLOWED_USERS", "").strip()
    if bool(token) != bool(telegram_allowed_raw):
        raise HermesInstallError(
            "Telegram token and allowlist must be configured together"
        )
    telegram_users: list[str] = []
    if token:
        if not re.fullmatch(r"[0-9]{6,15}:[A-Za-z0-9_-]{20,}", token):
            raise HermesInstallError("HERMES_TELEGRAM_BOT_TOKEN has an invalid shape")
        telegram_users = [
            item.strip() for item in telegram_allowed_raw.split(",") if item.strip()
        ]
        if not telegram_users or "*" in telegram_users:
            raise HermesInstallError(
                "Telegram authorization requires a non-wildcard allowlist"
            )
        if any(not re.fullmatch(r"[1-9][0-9]{4,19}", item) for item in telegram_users):
            raise HermesInstallError(
                "HERMES_TELEGRAM_ALLOWED_USERS must contain numeric user IDs"
            )

    mattermost_url = values.get("MATTERMOST_URL", "").strip()
    mattermost_token = values.get("MATTERMOST_TOKEN", "").strip()
    mattermost_allowed_raw = values.get("MATTERMOST_ALLOWED_USERS", "").strip()
    if any((mattermost_url, mattermost_token, mattermost_allowed_raw)) and not all(
        (mattermost_url, mattermost_token, mattermost_allowed_raw)
    ):
        raise HermesInstallError(
            "Mattermost URL, token, and allowlist must be configured together"
        )
    mattermost_users: list[str] = []
    if mattermost_url:
        if not re.fullmatch(r"https?://[^\s]+", mattermost_url):
            raise HermesInstallError("MATTERMOST_URL must be an HTTP(S) URL")
        mattermost_users = [
            item.strip() for item in mattermost_allowed_raw.split(",") if item.strip()
        ]
        if not mattermost_users or "*" in mattermost_users:
            raise HermesInstallError(
                "Mattermost authorization requires a non-wildcard allowlist"
            )
        if any(not re.fullmatch(r"[a-z0-9]{26}", item) for item in mattermost_users):
            raise HermesInstallError(
                "MATTERMOST_ALLOWED_USERS must contain Mattermost user IDs"
            )
        for name in (
            "MATTERMOST_HOME_CHANNEL",
            "MATTERMOST_REPLY_MODE",
            "MATTERMOST_REQUIRE_MENTION",
        ):
            if not values.get(name, "").strip():
                raise HermesInstallError(f"{name} is required for Mattermost")
        if not re.fullmatch(r"[a-z0-9]{26}", values["MATTERMOST_HOME_CHANNEL"].strip()):
            raise HermesInstallError("MATTERMOST_HOME_CHANNEL is invalid")
        if values["MATTERMOST_REPLY_MODE"].strip() not in {"thread", "off"}:
            raise HermesInstallError("MATTERMOST_REPLY_MODE is invalid")
        if values["MATTERMOST_REQUIRE_MENTION"].strip().lower() not in {
            "true",
            "false",
        }:
            raise HermesInstallError("MATTERMOST_REQUIRE_MENTION must be boolean")
    if not token and not mattermost_url:
        raise HermesInstallError("no authenticated messaging platform is configured")

    base_url = values["HERMES_LLM_BASE_URL"].strip()
    if not re.fullmatch(r"https?://[^\s]+", base_url):
        raise HermesInstallError("HERMES_LLM_BASE_URL must be an HTTP(S) URL")
    dependency_health_endpoints(values)

    model = values["HERMES_LLM_MODEL"].strip()
    if not model or any(char in model for char in "\r\n\0"):
        raise HermesInstallError("HERMES_LLM_MODEL is invalid")

    if not Path(values["HERMES_TERMINAL_CWD"].strip()).is_absolute():
        raise HermesInstallError("HERMES_TERMINAL_CWD must be absolute")
    if values["HERMES_TERMINAL_BACKEND"].strip() != "local":
        raise HermesInstallError(
            "HERMES_TERMINAL_BACKEND must be local for host repair"
        )
    operator_mode = values["HERMES_OPERATOR_MODE"].strip()
    if operator_mode not in OPERATOR_MODES:
        raise HermesInstallError(
            "HERMES_OPERATOR_MODE must be unprivileged_service or "
            "unrestricted_host_repair"
        )
    if values["HERMES_TERMINAL_HOME_MODE"].strip() not in {
        "auto",
        "real",
        "profile",
    }:
        raise HermesInstallError("HERMES_TERMINAL_HOME_MODE is invalid")
    if values["HERMES_LLM_PROVIDER"].strip() != "custom:mte9router":
        raise HermesInstallError(
            "HERMES_LLM_PROVIDER must be custom:mte9router for authenticated 9Router routing"
        )
    if values["HERMES_LLM_API_MODE"].strip() not in {
        "chat_completions",
        "codex_responses",
        "anthropic_messages",
    }:
        raise HermesInstallError("HERMES_LLM_API_MODE is invalid")
    require_int(values, "HERMES_TERMINAL_TIMEOUT", 1, 86400)
    require_int(values, "HERMES_TERMINAL_LIFETIME_SECONDS", 1, 604800)
    require_int(values, "HERMES_APPROVALS_TIMEOUT", 1, 86400)
    for name in (
        "HERMES_APPROVALS_MCP_RELOAD_CONFIRM",
        "HERMES_APPROVALS_DESTRUCTIVE_SLASH_CONFIRM",
        "HERMES_GATEWAY_STREAMING_ENABLED",
        "HERMES_TELEGRAM_REQUIRE_MENTION",
        "HERMES_TELEGRAM_EXCLUSIVE_BOT_MENTIONS",
        "HERMES_TELEGRAM_GUEST_MODE",
    ):
        require_bool(values, name)
    if values["HERMES_APPROVALS_MODE"].strip() not in {"manual", "smart", "off"}:
        raise HermesInstallError("HERMES_APPROVALS_MODE is invalid")
    if values["HERMES_APPROVALS_CRON_MODE"].strip() not in {
        "deny",
        "approve",
    }:
        raise HermesInstallError("HERMES_APPROVALS_CRON_MODE is invalid")
    if values["HERMES_GATEWAY_STREAMING_TRANSPORT"].strip() not in {
        "edit",
        "off",
    }:
        raise HermesInstallError("HERMES_GATEWAY_STREAMING_TRANSPORT is invalid")
    if values["HERMES_EXEC_ASK"].strip() not in {"0", "1"}:
        raise HermesInstallError("HERMES_EXEC_ASK must be 0 or 1")
    if not require_bool(values, "HERMES_API_SERVER_ENABLED"):
        raise HermesInstallError("HERMES_API_SERVER_ENABLED must be true")
    api_server_key = values["HERMES_API_SERVER_KEY"].strip()
    if len(api_server_key) < 32 or any(char.isspace() for char in api_server_key):
        raise HermesInstallError("HERMES_API_SERVER_KEY is too weak or malformed")
    validate_api_server_host(values["HERMES_API_SERVER_HOST"])
    require_int(values, "HERMES_API_SERVER_PORT", 1024, 65535)
    if not re.fullmatch(
        r"[A-Za-z0-9._-]{1,80}", values["HERMES_API_SERVER_MODEL_NAME"].strip()
    ):
        raise HermesInstallError("HERMES_API_SERVER_MODEL_NAME is invalid")
    if values["HERMES_DISPLAY_TOOL_PROGRESS"].strip() not in {
        "off",
        "new",
        "all",
        "verbose",
        "log",
    }:
        raise HermesInstallError("HERMES_DISPLAY_TOOL_PROGRESS is invalid")
    if values["HERMES_TELEGRAM_NOTIFICATIONS"].strip() not in {
        "off",
        "important",
        "all",
    }:
        raise HermesInstallError("HERMES_TELEGRAM_NOTIFICATIONS is invalid")

    context7_api_key = values.get("CONTEXT7_API_KEY", "").strip()
    if context7_api_key and any(char.isspace() for char in context7_api_key):
        raise HermesInstallError("CONTEXT7_API_KEY is malformed")

    return {
        "credentialSource": str(path),
        "owner": "root",
        "mode": format(stat.S_IMODE(file_stat.st_mode), "04o"),
        "requiredKeys": [*REQUIRED_KEYS, *INSTALL_ONLY_KEYS],
        "supplyChain": {
            "aptPackageCount": len(apt_packages),
            "pinned": True,
            "pythonPackageCount": len(supply["pythonPackages"]),
        },
        "telegram": {
            "configured": bool(token),
            "failClosed": not bool(token),
            "allowedUserCount": len(telegram_users),
        },
        "mattermost": {
            "configured": bool(mattermost_url),
            "failClosed": not bool(mattermost_url),
            "allowedUserCount": len(mattermost_users),
        },
        "llmBaseUrlConfigured": bool(values.get("HERMES_LLM_BASE_URL", "").strip()),
        "llmModelConfigured": True,
        "operatorMode": operator_mode,
        "context7": {
            "configured": True,
            "authMode": "api-key" if context7_api_key else "anonymous",
            "secretProjected": bool(context7_api_key),
        },
    }


def json_request(
    url: str,
    *,
    bearer: str | None = None,
    basic: tuple[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: int = 10,
) -> Any:
    headers = {
        "Accept": "application/json",
        "User-Agent": f"mte-hermes-health/{VERSION}",
    }
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if basic:
        encoded = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(url, headers=headers, data=data)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise HermesInstallError("remote health endpoint returned a non-200 status")
        payload = response.read(5_000_001)
    if len(payload) > 5_000_000:
        raise HermesInstallError("remote health response exceeded the size limit")
    return json.loads(payload)


def _mcp_response_message(payload: bytes, request_id: int | None) -> dict[str, Any]:
    """Decode one bounded JSON or SSE response without retaining tool content."""
    if not payload.strip():
        return {}
    text = payload.decode("utf-8")
    messages: list[dict[str, Any]] = []
    data_lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
        elif not line and data_lines:
            messages.append(json.loads("\n".join(data_lines)))
            data_lines = []
    if data_lines:
        messages.append(json.loads("\n".join(data_lines)))
    if not messages:
        decoded = json.loads(text)
        if isinstance(decoded, dict):
            messages.append(decoded)
    for message in messages:
        if request_id is None or message.get("id") == request_id:
            if "error" in message:
                raise HermesInstallError("Context7 MCP returned an error")
            return message
    raise HermesInstallError("Context7 MCP response did not match the request")


def context7_mcp_request(
    method: str,
    params: dict[str, Any],
    *,
    request_id: int | None,
    session_id: str | None,
    api_key: str | None,
    timeout: int = 20,
) -> tuple[dict[str, Any], str | None]:
    """Send a redaction-safe Streamable HTTP request to the native MCP."""
    body: dict[str, Any] = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    }
    if request_id is not None:
        body["id"] = request_id
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": CONTEXT7_MCP_PROTOCOL_VERSION,
        "User-Agent": f"mte-hermes-health/{VERSION}",
    }
    if session_id:
        headers["MCP-Session-ID"] = session_id
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(
        CONTEXT7_MCP_URL,
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status not in {200, 202}:
            raise HermesInstallError("Context7 MCP returned a non-success status")
        payload = response.read(2_000_001)
        next_session_id = response.headers.get("MCP-Session-ID") or session_id
    if len(payload) > 2_000_000:
        raise HermesInstallError("Context7 MCP response exceeded the size limit")
    return _mcp_response_message(payload, request_id), next_session_id


def close_context7_mcp_session(session_id: str | None, *, api_key: str | None) -> None:
    if not session_id:
        return
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": CONTEXT7_MCP_PROTOCOL_VERSION,
        "MCP-Session-ID": session_id,
        "User-Agent": f"mte-hermes-health/{VERSION}",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(CONTEXT7_MCP_URL, headers=headers, method="DELETE")
    try:
        with urllib.request.urlopen(request, timeout=10):
            pass
    except (OSError, urllib.error.URLError):
        pass


def _mcp_tool_text(message: dict[str, Any]) -> str:
    result = message.get("result")
    if not isinstance(result, dict) or result.get("isError") is True:
        return ""
    content = result.get("content")
    if not isinstance(content, list):
        return ""
    return "\n".join(
        str(item.get("text", ""))
        for item in content
        if isinstance(item, dict) and item.get("type") == "text"
    )


def context7_readiness(
    values: dict[str, str],
) -> tuple[dict[str, bool], dict[str, str]]:
    """Prove anonymous/keyed discovery plus a real resolve/query tool chain."""
    api_key = values.get("CONTEXT7_API_KEY", "").strip() or None
    auth_mode = "api-key" if api_key else "anonymous"
    checks = {"context7Discovery": False, "context7Query": False}
    states = {
        "context7AuthMode": auth_mode,
        "context7Discovery": "not-attempted",
        "context7Query": "not-attempted",
    }
    session_id: str | None = None
    try:
        _, session_id = context7_mcp_request(
            "initialize",
            {
                "protocolVersion": CONTEXT7_MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mte-hermes-health", "version": VERSION},
            },
            request_id=1,
            session_id=None,
            api_key=api_key,
        )
        context7_mcp_request(
            "notifications/initialized",
            {},
            request_id=None,
            session_id=session_id,
            api_key=api_key,
        )
        discovered, session_id = context7_mcp_request(
            "tools/list",
            {},
            request_id=2,
            session_id=session_id,
            api_key=api_key,
        )
        result = discovered.get("result")
        tools = result.get("tools") if isinstance(result, dict) else None
        names = {
            str(item.get("name"))
            for item in tools or []
            if isinstance(item, dict) and item.get("name")
        }
        checks["context7Discovery"] = set(CONTEXT7_MCP_TOOLS) <= names
        states["context7Discovery"] = (
            "ready" if checks["context7Discovery"] else "unexpected-tool-surface"
        )
        if not checks["context7Discovery"]:
            return checks, states

        resolved, session_id = context7_mcp_request(
            "tools/call",
            {
                "name": "resolve-library-id",
                "arguments": {
                    "libraryName": "Context7",
                    "query": "Context7 remote MCP server configuration",
                },
            },
            request_id=3,
            session_id=session_id,
            api_key=api_key,
        )
        library_ids = re.findall(
            r"Context7-compatible library ID:\s*(/[^\s]+)",
            _mcp_tool_text(resolved),
        )
        library_id = (
            "/upstash/context7"
            if "/upstash/context7" in library_ids
            else (library_ids[0] if library_ids else "")
        )
        if not library_id:
            states["context7Query"] = "library-resolution-failed"
            return checks, states
        queried, session_id = context7_mcp_request(
            "tools/call",
            {
                "name": "query-docs",
                "arguments": {
                    "libraryId": library_id,
                    "query": "remote MCP server URL and optional API key header",
                },
            },
            request_id=4,
            session_id=session_id,
            api_key=api_key,
        )
        checks["context7Query"] = bool(_mcp_tool_text(queried).strip())
        states["context7Query"] = "ready" if checks["context7Query"] else "empty-result"
    except (
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        HermesInstallError,
    ):
        if states["context7Discovery"] == "not-attempted":
            states["context7Discovery"] = "unreachable-or-rejected"
        if states["context7Query"] == "not-attempted":
            states["context7Query"] = "unreachable-or-rejected"
    finally:
        close_context7_mcp_session(session_id, api_key=api_key)
    return checks, states


def hermes_api_server_ready(values: dict[str, str]) -> bool:
    host = values["HERMES_API_SERVER_HOST"].strip()
    rendered_host = "[::1]" if host == "::1" else host
    url = (
        "http://"
        + rendered_host
        + ":"
        + values["HERMES_API_SERVER_PORT"].strip()
        + "/health"
    )
    try:
        payload = json_request(
            url,
            bearer=values["HERMES_API_SERVER_KEY"].strip(),
        )
    except (OSError, ValueError, json.JSONDecodeError, HermesInstallError):
        return False
    return isinstance(payload, dict)


def wait_hermes_api_server(
    values: dict[str, str], *, timeout_seconds: int = 60
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if hermes_api_server_ready(values):
            return True
        time.sleep(1)
    return False


def external_readiness(path: Path) -> tuple[dict[str, bool], dict[str, str]]:
    values = parse_dotenv(path)
    checks = {"llmRoute": False, "llmCompletion": False}
    states: dict[str, str] = {}

    checks["hermesApiServer"] = False
    checks["hermesApiServer"] = hermes_api_server_ready(values)
    states["hermesApiServer"] = (
        "ready" if checks["hermesApiServer"] else "unreachable-or-rejected"
    )

    telegram_token = values.get("HERMES_TELEGRAM_BOT_TOKEN", "").strip()
    if telegram_token:
        checks["telegramBot"] = False
        try:
            telegram = json_request(
                "https://api.telegram.org/bot" + telegram_token + "/getMe"
            )
            checks["telegramBot"] = bool(
                isinstance(telegram, dict)
                and telegram.get("ok") is True
                and isinstance(telegram.get("result"), dict)
                and telegram["result"].get("is_bot") is True
            )
            states["telegramBot"] = (
                "ready" if checks["telegramBot"] else "invalid-response"
            )
        except (
            OSError,
            KeyError,
            ValueError,
            json.JSONDecodeError,
            HermesInstallError,
        ):
            states["telegramBot"] = "unreachable-or-rejected"
    else:
        states["telegramBot"] = "disabled-fail-closed"

    mattermost_url = values.get("MATTERMOST_URL", "").strip().rstrip("/")
    if mattermost_url:
        checks["mattermostBot"] = False
        try:
            me = json_request(
                mattermost_url + "/api/v4/users/me",
                bearer=values["MATTERMOST_TOKEN"].strip(),
            )
            checks["mattermostBot"] = bool(
                isinstance(me, dict) and me.get("id") and me.get("is_bot") is True
            )
            states["mattermostBot"] = (
                "ready" if checks["mattermostBot"] else "invalid-response"
            )
        except (
            OSError,
            KeyError,
            ValueError,
            json.JSONDecodeError,
            HermesInstallError,
        ):
            states["mattermostBot"] = "unreachable-or-rejected"
    else:
        states["mattermostBot"] = "disabled-fail-closed"

    for label, url_resolver, basic_auth, bearer_auth in (
        (
            "paperclipApi",
            lambda: dependency_health_endpoints(values)["paperclipApi"],
            None,
            values["HERMES_PAPERCLIP_API_KEY"].strip(),
        ),
        (
            "kestraApi",
            lambda: dependency_health_endpoints(values)["kestraApi"],
            (
                values.get("HERMES_KESTRA_USERNAME", ""),
                values.get("HERMES_KESTRA_PASSWORD", ""),
            )
            if values.get("HERMES_KESTRA_USERNAME")
            else None,
            None,
        ),
    ):
        checks[label] = False
        try:
            url = url_resolver()
            response = json_request(url, basic=basic_auth, bearer=bearer_auth)
            checks[label] = isinstance(response, dict)
            states[label] = "ready" if checks[label] else "invalid-response"
        except (
            OSError,
            KeyError,
            ValueError,
            json.JSONDecodeError,
            HermesInstallError,
        ):
            states[label] = "unreachable-or-rejected"

    try:
        base_url = values["HERMES_LLM_BASE_URL"].strip()
        models = json_request(
            base_url.rstrip("/") + "/models",
            bearer=values["HERMES_LLM_API_KEY"].strip(),
        )
        listed = {
            str(item.get("id"))
            for item in models.get("data", [])
            if isinstance(item, dict) and item.get("id")
        }
        checks["llmRoute"] = values["HERMES_LLM_MODEL"].strip() in listed
        states["llmRoute"] = "ready" if checks["llmRoute"] else "model-not-listed"
        if checks["llmRoute"]:
            completion = json_request(
                base_url.rstrip("/") + "/chat/completions",
                bearer=values["HERMES_LLM_API_KEY"].strip(),
                body={
                    "model": values["HERMES_LLM_MODEL"].strip(),
                    "messages": [{"role": "user", "content": "Reply with OK."}],
                    "max_tokens": 8,
                    "stream": False,
                },
                timeout=60,
            )
            choices = completion.get("choices", [])
            checks["llmCompletion"] = bool(
                isinstance(choices, list)
                and choices
                and isinstance(choices[0], dict)
                and isinstance(choices[0].get("message"), dict)
                and str(choices[0]["message"].get("content", "")).strip()
            )
            states["llmCompletion"] = (
                "ready" if checks["llmCompletion"] else "invalid-response"
            )
        else:
            states["llmCompletion"] = "not-attempted"
    except (
        OSError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        HermesInstallError,
    ):
        states["llmRoute"] = "unreachable-or-rejected"
        states["llmCompletion"] = "unreachable-or-rejected"

    return checks, states


def installed_apt_versions(package_names: tuple[str, ...]) -> dict[str, str]:
    if shutil.which("dpkg-query") is None:
        raise HermesInstallError("dpkg-query is required for pinned Hermes packages")
    installed: dict[str, str] = {}
    for name in package_names:
        probe = command(
            ["dpkg-query", "-W", "-f=${Status}\t${Version}", name],
            check=False,
            capture=True,
            timeout=30,
        )
        if probe.returncode != 0:
            continue
        status, separator, version = probe.stdout.strip().partition("\t")
        if separator and status == "install ok installed" and version:
            installed[name] = version
    return installed


def ensure_packages(env_file: Path) -> dict[str, str]:
    """Install only canonical package=version pins and verify dpkg afterwards."""
    expected = parse_pinned_apt_packages(parse_dotenv(env_file))
    names = tuple(sorted(expected))
    installed = installed_apt_versions(names)
    if installed != expected:
        if shutil.which("apt-get") is None:
            raise HermesInstallError("apt-get is required for pinned Hermes packages")
        command(["apt-get", "update"], timeout=600)
        command(
            [
                "apt-get",
                "install",
                "-y",
                "--no-install-recommends",
                *[f"{name}={expected[name]}" for name in names],
            ],
            timeout=1200,
        )
        installed = installed_apt_versions(names)
    if installed != expected:
        drift = sorted(
            name for name in names if installed.get(name) != expected.get(name)
        )
        raise HermesInstallError(
            "Hermes OS package versions drifted: " + ", ".join(drift)
        )
    for binary in (
        "curl",
        "ffmpeg",
        "openssl",
        "python3",
        "rg",
        "sudo",
        "visudo",
    ):
        if shutil.which(binary) is None:
            raise HermesInstallError(f"pinned Hermes binary is missing: {binary}")
    return installed


def bootstrap_mattermost() -> None:
    result = command(
        ["python3", str(hermes_asset_paths()["mattermostBootstrap"])],
        check=False,
        capture=True,
        timeout=180,
    )
    if result.returncode != 0:
        raise HermesInstallError("Mattermost operator bootstrap failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise HermesInstallError(
            "Mattermost operator bootstrap returned invalid status"
        ) from error
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise HermesInstallError("Mattermost operator bootstrap did not become ready")


def _json_command(argv: list[str], *, label: str) -> dict[str, Any]:
    result = command(argv, check=False, capture=True, timeout=300)
    if result.returncode != 0:
        raise HermesInstallError(f"{label} failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise HermesInstallError(f"{label} returned invalid status") from error
    if not isinstance(payload, dict):
        raise HermesInstallError(f"{label} returned invalid status")
    return payload


def reconcile_platform_projections(env_file: Path) -> dict[str, Any]:
    """Render, audit and independently verify the canonical projection manifest."""
    if not CONFIG_RENDERER.is_file():
        raise HermesInstallError("platform configuration renderer is missing")
    expected_source_sha = source_hash(env_file)
    render = _json_command(
        ["python3", str(CONFIG_RENDERER), "render"],
        label="platform configuration render",
    )
    if (
        render.get("rendered") is not True
        or render.get("sourceSha256") != expected_source_sha
        or render.get("manifest") != str(PROJECTIONS_MANIFEST)
    ):
        raise HermesInstallError("platform configuration render evidence is invalid")

    audit = _json_command(
        ["python3", str(CONFIG_RENDERER), "audit"],
        label="platform configuration audit",
    )
    if (
        audit.get("ok") is not True
        or audit.get("sourceSha256") != expected_source_sha
        or audit.get("findings") != []
    ):
        raise HermesInstallError("platform configuration audit evidence is invalid")

    if not PROJECTIONS_MANIFEST.is_file():
        raise HermesInstallError("platform projection manifest is missing")
    manifest_stat = PROJECTIONS_MANIFEST.stat()
    if stat.S_IMODE(manifest_stat.st_mode) != 0o600:
        raise HermesInstallError("platform projection manifest permissions are unsafe")
    if os.geteuid() == 0 and manifest_stat.st_uid != 0:
        raise HermesInstallError("platform projection manifest must be owned by root")
    try:
        manifest = json.loads(PROJECTIONS_MANIFEST.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise HermesInstallError("platform projection manifest is invalid") from error
    projections = manifest.get("projections") if isinstance(manifest, dict) else None
    if (
        not isinstance(projections, list)
        or not projections
        or manifest.get("sourceSha256") != expected_source_sha
        or manifest.get("generatorVersion") != render.get("generatorVersion")
        or len(projections) != render.get("projectionCount")
    ):
        raise HermesInstallError("platform projection manifest evidence is invalid")
    for row in projections:
        if not isinstance(row, dict) or row.get("sourceSha256") != expected_source_sha:
            raise HermesInstallError("platform projection manifest row is invalid")
        path = Path(str(row.get("path", "")))
        if not path.is_file() or row.get("contentSha256") != source_hash(path):
            raise HermesInstallError("platform projection manifest content drifted")
    if source_hash(env_file) != expected_source_sha:
        raise HermesInstallError(
            "canonical platform credential changed during projection reconciliation"
        )
    return {
        "sourceSha256": expected_source_sha,
        "projectionCount": len(projections),
        "generatorVersion": manifest["generatorVersion"],
    }


def ensure_supported_python() -> None:
    probe = command(
        [
            "python3",
            "-c",
            "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
        ],
        capture=True,
        timeout=30,
    ).stdout.strip()
    if probe != "3.12":
        raise HermesInstallError(
            f"Hermes {VERSION} lock requires Python 3.12; server python3 is {probe or 'unknown'}"
        )


def ensure_user() -> None:
    try:
        account = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        command(
            [
                "useradd",
                "--system",
                "--create-home",
                "--home-dir",
                str(STATE_ROOT),
                "--shell",
                "/bin/bash",
                SERVICE_USER,
            ]
        )
        account = pwd.getpwnam(SERVICE_USER)
    if Path(account.pw_dir) != STATE_ROOT:
        raise HermesInstallError(
            f"existing {SERVICE_USER} account has an unexpected home directory"
        )

    STATE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    (STATE_ROOT / ".hermes").mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chown(STATE_ROOT, account.pw_uid, account.pw_gid)
    os.chown(STATE_ROOT / ".hermes", account.pw_uid, account.pw_gid)
    STATE_ROOT.chmod(0o700)
    (STATE_ROOT / ".hermes").chmod(0o700)


def installed_version() -> str | None:
    python = VENV / "bin" / "python"
    if not python.is_file():
        return None
    probe = command(
        [str(python), "-c", "import hermes_cli; print(hermes_cli.__version__)"],
        check=False,
        capture=True,
        timeout=60,
    )
    if probe.returncode != 0:
        return None
    return probe.stdout.strip()


def python_distribution_versions() -> dict[str, str]:
    python = VENV / "bin" / "python"
    if not python.is_file():
        return {}
    probe = command(
        [
            str(python),
            "-c",
            (
                "import importlib.metadata as m,json,re; "
                "print(json.dumps({re.sub(r'[-_.]+','-',d.metadata['Name']).lower():"
                "d.version for d in m.distributions()}))"
            ),
        ],
        check=False,
        capture=True,
        timeout=60,
    )
    if probe.returncode != 0:
        return {}
    try:
        payload = json.loads(probe.stdout)
    except json.JSONDecodeError:
        return {}
    return (
        {str(name): str(version) for name, version in payload.items()}
        if isinstance(payload, dict)
        else {}
    )


def venv_supply_chain_evidence() -> dict[str, Any]:
    supply = validate_supply_chain_assets()
    expected = supply["pythonPackages"]
    installed = python_distribution_versions()
    if installed != expected:
        raise HermesInstallError(
            "Hermes virtual environment dependency closure drifted"
        )
    pip_check = command(
        [str(VENV / "bin/python"), "-m", "pip", "check"],
        check=False,
        capture=True,
        timeout=120,
    )
    if pip_check.returncode != 0:
        raise HermesInstallError("Hermes virtual environment dependency check failed")
    try:
        receipt = json.loads(SUPPLY_CHAIN_RECEIPT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HermesInstallError("Hermes supply-chain receipt is missing") from error
    if not isinstance(receipt, dict) or any(
        (
            receipt.get("hermesVersion") != VERSION,
            receipt.get("manifestSha256") != supply["manifestSha256"],
            receipt.get("requirementsSha256") != supply["requirementsSha256"],
            receipt.get("pythonPackages") != expected,
            receipt.get("wheelSha256") != HERMES_WHEEL_SHA256,
            receipt.get("wheelUrl") != HERMES_WHEEL_URL,
            receipt.get("pypiProvenanceUrl") != HERMES_PYPI_PROVENANCE_URL,
            receipt.get("sigstoreBundleSha256")
            != HERMES_SIGSTORE_BUNDLE_SHA256,
            receipt.get("signerRepository") != HERMES_SIGNER_REPOSITORY,
            receipt.get("signerTagRef") != HERMES_SIGNER_TAG_REF,
        )
    ):
        raise HermesInstallError("Hermes supply-chain receipt drifted")
    return {
        "manifestSha256": supply["manifestSha256"],
        "packageCount": len(installed),
        "requirementsSha256": supply["requirementsSha256"],
        "receiptSha256": source_hash(SUPPLY_CHAIN_RECEIPT),
    }


def write_supply_chain_receipt(
    supply: dict[str, Any], os_packages: dict[str, str]
) -> None:
    payload = {
        "hermesVersion": VERSION,
        "manifestSha256": supply["manifestSha256"],
        "osPackages": os_packages,
        "pythonPackages": supply["pythonPackages"],
        "pypiProvenanceUrl": HERMES_PYPI_PROVENANCE_URL,
        "requirementsSha256": supply["requirementsSha256"],
        "signerRepository": HERMES_SIGNER_REPOSITORY,
        "signerTagRef": HERMES_SIGNER_TAG_REF,
        "sigstoreBundleSha256": HERMES_SIGSTORE_BUNDLE_SHA256,
        "wheelSha256": HERMES_WHEEL_SHA256,
        "wheelUrl": HERMES_WHEEL_URL,
    }
    atomic_write_text(
        SUPPLY_CHAIN_RECEIPT,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        mode=0o644,
    )


def install_venv(
    values: dict[str, str], os_packages: dict[str, str] | None = None
) -> None:
    supply = validate_supply_chain_assets(values)
    # The former installer cloned and built Hermes in this release directory.
    # Remove that managed artifact even when the locked wheel environment is
    # already current, so an in-place upgrade converges to a wheel-only runtime.
    if LEGACY_SOURCE.is_symlink() or LEGACY_SOURCE.is_file():
        LEGACY_SOURCE.unlink()
    elif LEGACY_SOURCE.is_dir():
        shutil.rmtree(LEGACY_SOURCE)
    try:
        current_supply = venv_supply_chain_evidence()
    except HermesInstallError:
        current_supply = {}
    if installed_version() == VERSION and current_supply:
        return
    RELEASE.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    RELEASE.mkdir(parents=True, exist_ok=True, mode=0o755)
    with tempfile.TemporaryDirectory(prefix="mte-hermes-supply-chain-") as directory:
        workspace = Path(directory)
        wheel = fetch_and_verify_hermes_artifacts(supply, workspace, values)
        requirements = workspace / "requirements-local-wheel.lock"
        locked = supply["requirementsPath"].read_text(encoding="utf-8")
        remote_requirement = (
            f"hermes-agent[messaging,mcp]=={VERSION} "
            f"--hash=sha256:{HERMES_WHEEL_SHA256}"
        )
        local_requirement = (
            "hermes-agent[messaging,mcp] @ "
            + wheel.resolve().as_uri()
            + f" --hash=sha256:{HERMES_WHEEL_SHA256}"
        )
        if locked.count(remote_requirement) != 1:
            raise HermesInstallError("Hermes wheel requirement is not uniquely locked")
        requirements.write_text(
            locked.replace(remote_requirement, local_requirement), encoding="utf-8"
        )
        requirements.chmod(0o600)
        if VENV.exists():
            shutil.rmtree(VENV)
        command(["python3", "-m", "venv", str(VENV)], timeout=180)
        python = VENV / "bin" / "python"
        command(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "--no-cache-dir",
                "--require-hashes",
                "--only-binary=:all:",
                "-r",
                str(requirements),
            ],
            timeout=1800,
        )
    if installed_version() != VERSION:
        raise HermesInstallError(
            "Hermes virtual environment version verification failed"
        )
    write_supply_chain_receipt(supply, os_packages or {})
    venv_supply_chain_evidence()


def atomic_copy(source: Path, destination: Path, mode: int) -> None:
    atomic_write_bytes(destination, source.read_bytes(), mode=mode)


def render_context7_mcp_config(values: dict[str, str]) -> str:
    lines = [
        "mcp_servers:",
        "  context7:",
        f"    url: {json.dumps(CONTEXT7_MCP_URL)}",
        "    tools:",
        "      include:",
        *[f"        - {json.dumps(name)}" for name in CONTEXT7_MCP_TOOLS],
        "      resources: false",
        "      prompts: false",
    ]
    if values.get("CONTEXT7_API_KEY", "").strip():
        lines.extend(
            (
                "    headers:",
                '      Authorization: "Bearer ${CONTEXT7_API_KEY}"',
            )
        )
    return "\n".join(lines)


def render_mattermost_native_config(values: dict[str, str]) -> str:
    """Pin native Mattermost commands to the provisioned operator channel.

    The upstream Mattermost plugin reads its URL, token, and operator allowlist
    from the service environment. Its channel allowlist is a regular Hermes
    config setting, so render it here instead of creating a second messaging
    bridge or an unmanaged runtime environment variable.
    """
    if not values.get("MATTERMOST_URL", "").strip():
        return ""
    channel = values.get("MATTERMOST_HOME_CHANNEL", "").strip()
    if not re.fullmatch(r"[a-z0-9]{26}", channel):
        raise HermesInstallError("MATTERMOST_HOME_CHANNEL is invalid")
    return "\n".join(
        (
            "mattermost:",
            "  allowed_channels:",
            f"    - {json.dumps(channel)}",
        )
    )


def mattermost_native_config_ready(values: dict[str, str]) -> bool:
    """Check the rendered native channel boundary without making a network call."""
    expected = render_mattermost_native_config(values)
    if not expected:
        return True
    try:
        config = (STATE_ROOT / ".hermes" / "config.yaml").read_text(encoding="utf-8")
    except OSError:
        return False
    return expected in config


def context7_mcp_config_ready(values: dict[str, str]) -> bool:
    config_path = STATE_ROOT / ".hermes" / "config.yaml"
    try:
        config = config_path.read_text(encoding="utf-8")
    except OSError:
        return False
    expected = render_context7_mcp_config(values)
    api_key = values.get("CONTEXT7_API_KEY", "").strip()
    return bool(
        config.count("mcp_servers:") == 1
        and config.count(CONTEXT7_MCP_URL) == 1
        and expected in config
        and (not api_key or api_key not in config)
    )


def render_native_config(values: dict[str, str]) -> dict[str, str]:
    """Render upstream Hermes configuration before the native service starts."""
    assets = hermes_asset_paths()
    template = assets["configTemplate"].read_text(encoding="utf-8")
    replacements = {
        "@@HERMES_LLM_MODEL@@": json.dumps(values["HERMES_LLM_MODEL"].strip()),
        "@@HERMES_LLM_PROVIDER@@": json.dumps(values["HERMES_LLM_PROVIDER"].strip()),
        "@@HERMES_LLM_BASE_URL@@": json.dumps(
            values["HERMES_LLM_BASE_URL"].strip().rstrip("/")
        ),
        "@@HERMES_LLM_API_MODE@@": json.dumps(values["HERMES_LLM_API_MODE"].strip()),
        "@@HERMES_TERMINAL_BACKEND@@": json.dumps(
            values["HERMES_TERMINAL_BACKEND"].strip()
        ),
        "@@HERMES_TERMINAL_CWD@@": json.dumps(values["HERMES_TERMINAL_CWD"].strip()),
        "@@HERMES_TERMINAL_TIMEOUT@@": values["HERMES_TERMINAL_TIMEOUT"].strip(),
        "@@HERMES_TERMINAL_LIFETIME_SECONDS@@": values[
            "HERMES_TERMINAL_LIFETIME_SECONDS"
        ].strip(),
        "@@HERMES_TERMINAL_HOME_MODE@@": json.dumps(
            values["HERMES_TERMINAL_HOME_MODE"].strip()
        ),
        "@@HERMES_APPROVALS_MODE@@": json.dumps(
            values["HERMES_APPROVALS_MODE"].strip()
        ),
        "@@HERMES_APPROVALS_TIMEOUT@@": values["HERMES_APPROVALS_TIMEOUT"].strip(),
        "@@HERMES_APPROVALS_CRON_MODE@@": json.dumps(
            values["HERMES_APPROVALS_CRON_MODE"].strip()
        ),
        "@@HERMES_APPROVALS_MCP_RELOAD_CONFIRM@@": values[
            "HERMES_APPROVALS_MCP_RELOAD_CONFIRM"
        ]
        .strip()
        .lower(),
        "@@HERMES_APPROVALS_DESTRUCTIVE_SLASH_CONFIRM@@": values[
            "HERMES_APPROVALS_DESTRUCTIVE_SLASH_CONFIRM"
        ]
        .strip()
        .lower(),
        "@@HERMES_GATEWAY_STREAMING_ENABLED@@": values[
            "HERMES_GATEWAY_STREAMING_ENABLED"
        ]
        .strip()
        .lower(),
        "@@HERMES_GATEWAY_STREAMING_TRANSPORT@@": json.dumps(
            values["HERMES_GATEWAY_STREAMING_TRANSPORT"].strip()
        ),
        "@@HERMES_TELEGRAM_REQUIRE_MENTION@@": values["HERMES_TELEGRAM_REQUIRE_MENTION"]
        .strip()
        .lower(),
        "@@HERMES_TELEGRAM_EXCLUSIVE_BOT_MENTIONS@@": values[
            "HERMES_TELEGRAM_EXCLUSIVE_BOT_MENTIONS"
        ]
        .strip()
        .lower(),
        "@@HERMES_TELEGRAM_GUEST_MODE@@": values["HERMES_TELEGRAM_GUEST_MODE"]
        .strip()
        .lower(),
        "@@HERMES_DISPLAY_TOOL_PROGRESS@@": json.dumps(
            values["HERMES_DISPLAY_TOOL_PROGRESS"].strip()
        ),
        "@@HERMES_TELEGRAM_NOTIFICATIONS@@": json.dumps(
            values["HERMES_TELEGRAM_NOTIFICATIONS"].strip()
        ),
        "@@HERMES_MATTERMOST_CONFIG@@": render_mattermost_native_config(values),
        "@@HERMES_CONTEXT7_MCP@@": render_context7_mcp_config(values),
    }
    for placeholder, replacement in replacements.items():
        template = template.replace(placeholder, replacement)
    if "@@" in template:
        raise HermesInstallError("unresolved placeholder in Hermes configuration")

    try:
        account = pwd.getpwnam(SERVICE_USER)
    except KeyError as error:
        raise HermesInstallError(
            "Hermes service account is missing; run install before reconcile"
        ) from error
    destination = STATE_ROOT / ".hermes" / "config.yaml"
    soul = STATE_ROOT / ".hermes" / "SOUL.md"
    for path, content in (
        (destination, template),
        (soul, assets["soul"].read_text(encoding="utf-8")),
    ):
        atomic_write_text(
            path,
            content,
            mode=0o600,
            owner=(account.pw_uid, account.pw_gid),
        )
    return {
        "configSha256": source_hash(destination),
        "soulSha256": source_hash(soul),
    }


def render_service_unit(*, grant_platform_admin: bool) -> str:
    unit = hermes_asset_paths()["serviceUnit"].read_text(encoding="utf-8")
    return unit.replace(
        "@@HERMES_PRIVILEGE_HARDENING@@",
        (
            "# Explicit host-admin mode: systemd sandboxing that blocks sudo children is omitted."
            if grant_platform_admin
            else "\n".join(
                (
                    "NoNewPrivileges=true",
                    "PrivateDevices=true",
                    "PrivateTmp=true",
                    "ProtectControlGroups=true",
                    "ProtectHome=true",
                    "ProtectKernelLogs=true",
                    "ProtectKernelModules=true",
                    "ProtectKernelTunables=true",
                    "ProtectSystem=strict",
                    "ReadWritePaths=/var/lib/mte-hermes",
                    "RestrictRealtime=true",
                    "RestrictSUIDSGID=true",
                    "LockPersonality=true",
                )
            )
        ),
    )


def install_runtime_files(*, grant_platform_admin: bool) -> None:
    assets = hermes_asset_paths()
    atomic_copy(assets["acceptance"], BIN_ROOT / "acceptance-canary", 0o755)
    atomic_copy(assets["configTemplate"], SHARE_ROOT / "config.yaml.template", 0o644)
    atomic_copy(assets["soul"], SHARE_ROOT / "SOUL.md", 0o644)
    for obsolete in (BIN_ROOT / "launch-gateway", BIN_ROOT / "platform-api"):
        obsolete.unlink(missing_ok=True)

    unit = render_service_unit(grant_platform_admin=grant_platform_admin)
    atomic_write_text(UNIT_PATH, unit, mode=0o644)

    if CURRENT.is_symlink() or CURRENT.exists():
        if CURRENT.is_symlink() and CURRENT.resolve() == RELEASE.resolve():
            return
        if CURRENT.is_dir() and not CURRENT.is_symlink():
            raise HermesInstallError(f"refusing to replace non-symlink {CURRENT}")
        CURRENT.unlink()
    CURRENT.symlink_to(RELEASE)


def skill_tree_evidence(root: Path) -> dict[str, Any]:
    if not root.is_dir() or root.is_symlink():
        raise HermesInstallError("system-platform skill root is missing or unsafe")
    files: list[Path] = []
    directories: list[Path] = []
    for path in sorted(
        root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()
    ):
        if path.is_symlink():
            raise HermesInstallError("system-platform skill must not contain symlinks")
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            directories.append(path)
        else:
            raise HermesInstallError("system-platform skill contains a special file")
    relative_files = {path.relative_to(root).as_posix() for path in files}
    required_files = {"SKILL.md", "agents/openai.yaml", "assets/architecture.html"}
    if not required_files <= relative_files or not any(
        name.startswith("references/") for name in relative_files
    ):
        raise HermesInstallError("system-platform skill tree is incomplete")
    digest = hashlib.sha256()
    entries = [(path, b"directory") for path in directories]
    entries.extend((path, b"file") for path in files)
    for path, kind in sorted(
        entries, key=lambda item: item[0].relative_to(root).as_posix()
    ):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes() if kind == b"file" else b""
        digest.update(kind)
        digest.update(b"\0")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(str(len(content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return {
        "path": str(root),
        "fileCount": len(files),
        "directoryCount": len(directories),
        "treeSha256": digest.hexdigest(),
    }


def _remove_tree(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def install_platform_skill() -> dict[str, Any]:
    """Stage, verify and replace the complete canonical skill tree."""
    source = hermes_asset_paths()["platformSkill"]
    source_evidence = skill_tree_evidence(source)
    skills_root = STATE_ROOT / ".hermes" / "skills"
    destination = skills_root / PLATFORM_SKILL_NAME
    legacy_destination = skills_root / LEGACY_PLATFORM_SKILL_NAME
    skills_root.mkdir(parents=True, exist_ok=True, mode=0o755)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{PLATFORM_SKILL_NAME}.staging-", dir=skills_root)
    )
    backup = skills_root / f".{PLATFORM_SKILL_NAME}.previous-{os.getpid()}"
    if backup.exists() or backup.is_symlink():
        _remove_tree(staging)
        raise HermesInstallError("stale system-platform skill backup exists")
    account = pwd.getpwnam(SERVICE_USER)
    try:
        shutil.copytree(source, staging, dirs_exist_ok=True)
        for path in [staging, *staging.rglob("*")]:
            os.chown(path, account.pw_uid, account.pw_gid)
            path.chmod(0o755 if path.is_dir() else 0o644)
        staged_evidence = skill_tree_evidence(staging)
        if (
            staged_evidence["fileCount"] != source_evidence["fileCount"]
            or staged_evidence["directoryCount"] != source_evidence["directoryCount"]
            or staged_evidence["treeSha256"] != source_evidence["treeSha256"]
        ):
            raise HermesInstallError("staged system-platform skill hash drifted")
        if destination.exists() or destination.is_symlink():
            if not destination.is_dir() or destination.is_symlink():
                raise HermesInstallError(
                    "refusing to replace unsafe system-platform skill destination"
                )
            destination.replace(backup)
        try:
            staging.replace(destination)
        except Exception:
            if backup.exists() and not destination.exists():
                backup.replace(destination)
            raise
        _remove_tree(backup)
        _remove_tree(legacy_destination)
    finally:
        _remove_tree(staging)
    installed_evidence = skill_tree_evidence(destination)
    if installed_evidence["treeSha256"] != source_evidence["treeSha256"]:
        raise HermesInstallError("installed system-platform skill hash drifted")
    return installed_evidence


def platform_skill_status() -> dict[str, Any]:
    destination = STATE_ROOT / ".hermes" / "skills" / PLATFORM_SKILL_NAME
    legacy = STATE_ROOT / ".hermes" / "skills" / LEGACY_PLATFORM_SKILL_NAME
    try:
        source = hermes_asset_paths()["platformSkill"]
        account = pwd.getpwnam(SERVICE_USER)
        source_evidence = skill_tree_evidence(source)
        installed_evidence = skill_tree_evidence(destination)
        permissions_ready = all(
            path.stat().st_uid == account.pw_uid
            and stat.S_IMODE(path.stat().st_mode) == (0o755 if path.is_dir() else 0o644)
            for path in [destination, *destination.rglob("*")]
        )
    except (HermesInstallError, KeyError, OSError):
        return {
            "ready": False,
            "path": str(destination),
            "legacySkillAbsent": not (legacy.exists() or legacy.is_symlink()),
        }
    hashes_match = bool(
        source_evidence["fileCount"] == installed_evidence["fileCount"]
        and source_evidence["directoryCount"] == installed_evidence["directoryCount"]
        and source_evidence["treeSha256"] == installed_evidence["treeSha256"]
    )
    legacy_absent = not (legacy.exists() or legacy.is_symlink())
    return {
        "ready": hashes_match and permissions_ready and legacy_absent,
        "path": str(destination),
        "fileCount": installed_evidence["fileCount"],
        "directoryCount": installed_evidence["directoryCount"],
        "sourceTreeSha256": source_evidence["treeSha256"],
        "installedTreeSha256": installed_evidence["treeSha256"],
        "hashesMatch": hashes_match,
        "ownershipAndModes": permissions_ready,
        "legacySkillAbsent": legacy_absent,
    }


def install_admin_policy() -> None:
    policy = (
        "# Managed by the platform; grants native Hermes explicit host repair access.\n"
        f"Defaults:{SERVICE_USER} !requiretty\n"
        f"{SERVICE_USER} ALL=(ALL:ALL) NOPASSWD: ALL\n"
    )
    def validate(temporary: Path) -> None:
        validation = command(
            ["visudo", "-cf", str(temporary)], check=False, capture=True, timeout=30
        )
        if validation.returncode != 0:
            raise HermesInstallError(
                "generated Hermes sudoers policy failed visudo validation"
            )

    atomic_write_text(SUDOERS_PATH, policy, mode=0o440, validator=validate)


def reconcile_admin_policy(enabled: bool) -> None:
    """Make unrestricted host repair an explicit, reversible installation mode."""
    if enabled:
        install_admin_policy()
    else:
        SUDOERS_PATH.unlink(missing_ok=True)


def authorize_operator_mode(configured_mode: str, grant_platform_admin: bool) -> str:
    explicit_admin = bool(grant_platform_admin)
    if configured_mode not in OPERATOR_MODES or explicit_admin != (
        configured_mode == "unrestricted_host_repair"
    ):
        raise HermesInstallError(
            "--grant-platform-admin must be supplied exactly when "
            "HERMES_OPERATOR_MODE=unrestricted_host_repair"
        )
    return configured_mode


def systemctl(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return command(["systemctl", *args], check=check, capture=True, timeout=90)


def service_property(name: str) -> str:
    result = systemctl("show", SERVICE, f"--property={name}", "--value", check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def sudoers_valid() -> bool:
    if not SUDOERS_PATH.is_file() or stat.S_IMODE(SUDOERS_PATH.stat().st_mode) != 0o440:
        return False
    result = command(
        ["visudo", "-cf", str(SUDOERS_PATH)], check=False, capture=True, timeout=30
    )
    return result.returncode == 0


def operator_mode_ready(configured_mode: str) -> bool:
    try:
        unit = UNIT_PATH.read_text(encoding="utf-8")
    except OSError:
        return False
    if configured_mode == "unprivileged_service":
        return not SUDOERS_PATH.exists() and "NoNewPrivileges=true" in unit
    if configured_mode == "unrestricted_host_repair":
        return (
            SUDOERS_PATH.exists()
            and sudoers_valid()
            and "NoNewPrivileges=true" not in unit
        )
    return False


def native_runtime_files_ready() -> bool:
    try:
        account = pwd.getpwnam(SERVICE_USER)
        unit = UNIT_PATH.read_text(encoding="utf-8")
    except (KeyError, OSError):
        return False
    if (
        "ExecStart=/opt/mte-hermes/current/venv/bin/hermes gateway run --replace"
        not in unit
        or "launch-gateway" in unit
        or "platform-api" in unit
    ):
        return False
    for path in (
        STATE_ROOT / ".hermes" / "config.yaml",
        STATE_ROOT / ".hermes" / "SOUL.md",
    ):
        try:
            info = path.stat()
        except OSError:
            return False
        if info.st_uid != account.pw_uid or stat.S_IMODE(info.st_mode) != 0o600:
            return False
    return True


def status_payload(env_file: Path, *, verify_external: bool = False) -> dict[str, Any]:
    credential_values: dict[str, str] = {}
    try:
        account = pwd.getpwnam(SERVICE_USER)
        account_ok = Path(account.pw_dir) == STATE_ROOT
    except KeyError:
        account_ok = False

    try:
        credential_state: dict[str, Any] = validate_env_file(env_file)
        credential_values = parse_dotenv(env_file)
        credential_ok = True
    except (HermesInstallError, OSError) as error:
        credential_state = {"ready": False, "error": str(error)}
        credential_ok = False

    active = systemctl("is-active", SERVICE, check=False).stdout.strip()
    enabled = systemctl("is-enabled", SERVICE, check=False).stdout.strip()
    version = installed_version()
    configured_mode = credential_values.get("HERMES_OPERATOR_MODE", "").strip()
    admin_policy_installed = SUDOERS_PATH.exists()
    admin_policy_valid = sudoers_valid() if admin_policy_installed else True
    skill_state = platform_skill_status()
    try:
        supply_state = venv_supply_chain_evidence()
        expected_apt = parse_pinned_apt_packages(credential_values)
        installed_apt = installed_apt_versions(tuple(sorted(expected_apt)))
        if installed_apt != expected_apt:
            raise HermesInstallError("Hermes OS package closure drifted")
        supply_state["aptPackageCount"] = len(installed_apt)
        supply_state["ready"] = True
        supply_chain_ok = True
    except (HermesInstallError, OSError) as error:
        supply_state = {"ready": False, "error": str(error)}
        supply_chain_ok = False
    context7_config_ok = credential_ok and context7_mcp_config_ready(credential_values)
    mattermost_channel_scope_ok = credential_ok and mattermost_native_config_ready(
        credential_values
    )
    checks = {
        "account": account_ok,
        "credentialSource": credential_ok,
        "runtimeVersion": version == VERSION,
        "immutableSupplyChain": supply_chain_ok,
        "unitInstalled": UNIT_PATH.is_file(),
        "nativeGateway": native_runtime_files_ready(),
        "serviceEnabled": enabled == "enabled",
        "serviceActive": active == "active",
        "operatorMode": credential_ok and operator_mode_ready(configured_mode),
        "platformAdminPolicy": admin_policy_valid,
        "runtimeCredentialProjection": credential_ok
        and runtime_credential_projection_matches(env_file),
        "platformSkill": skill_state.get("ready") is True,
        "context7McpConfig": context7_config_ok,
        "mattermostChannelScope": mattermost_channel_scope_ok,
    }
    external_states: dict[str, str] = {}
    if credential_ok and verify_external:
        context7_checks, context7_states = context7_readiness(credential_values)
        checks.update(context7_checks)
        external_states.update(context7_states)
    elif credential_ok:
        external_states.update(
            {
                "context7AuthMode": (
                    "api-key"
                    if credential_values.get("CONTEXT7_API_KEY", "").strip()
                    else "anonymous"
                ),
                "context7Discovery": "not-requested",
                "context7Query": "not-requested",
            }
        )
    else:
        external_states.update(
            {
                "context7AuthMode": "not-evaluated",
                "context7Discovery": "credential-source-invalid",
                "context7Query": "credential-source-invalid",
            }
        )
    if credential_ok and verify_external:
        external_checks, other_external_states = external_readiness(env_file)
        checks.update(external_checks)
        external_states.update(other_external_states)
    elif credential_ok:
        external_states["otherVerification"] = "not-requested"
    return {
        "ok": all(checks.values()),
        "service": SERVICE,
        "version": version,
        "pinnedVersion": VERSION,
        "wheelSha256": HERMES_WHEEL_SHA256,
        "serviceState": active or "not-installed",
        "enabledState": enabled or "not-installed",
        "mainPid": service_property("MainPID") or "0",
        "restartCount": service_property("NRestarts") or "0",
        "checks": checks,
        "externalReadiness": external_states,
        "platformSkill": skill_state,
        "supplyChain": supply_state,
        "context7Mcp": {
            "url": CONTEXT7_MCP_URL,
            "allowedTools": list(CONTEXT7_MCP_TOOLS),
            "authMode": (
                "api-key"
                if credential_values.get("CONTEXT7_API_KEY", "").strip()
                else "anonymous"
            ),
            "configReady": context7_config_ok,
        },
        "privilegeMode": (
            configured_mode if configured_mode in OPERATOR_MODES else "invalid"
        ),
        "platformAdminPolicyInstalled": admin_policy_installed,
        "credentials": credential_state,
    }


def preflight(args: argparse.Namespace) -> None:
    state = validate_env_file(args.env_file)
    emit(
        {
            "ok": True,
            "hermesVersion": VERSION,
            "authorization": "authenticated-messaging-allowlists",
            **state,
        }
    )


def install(args: argparse.Namespace) -> None:
    require_root()
    if args.env_file != DEFAULT_ENV_FILE:
        raise HermesInstallError(
            f"installation only accepts the canonical credential source {DEFAULT_ENV_FILE}"
        )
    explicit_admin = bool(args.grant_platform_admin)
    if not explicit_admin:
        # The CLI grant is the public/private decision for install. Revoke
        # before credential parsing, projection, or Mattermost bootstrap.
        reconcile_admin_policy(False)
    bootstrap_mattermost()
    projection_evidence = reconcile_platform_projections(args.env_file)
    credential_state = validate_env_file(args.env_file)
    authorize_operator_mode(credential_state["operatorMode"], args.grant_platform_admin)
    canonical_hash = projection_evidence["sourceSha256"]
    if source_hash(args.env_file) != canonical_hash:
        raise HermesInstallError(
            "canonical platform credential changed after projection reconciliation"
        )
    installed_os_packages = ensure_packages(args.env_file)
    ensure_supported_python()
    ensure_user()
    PLATFORM_ROOT.mkdir(parents=True, exist_ok=True, mode=0o755)
    install_venv(parse_dotenv(args.env_file), installed_os_packages)
    runtime_projection = runtime_credential_projection_evidence(
        args.env_file, canonical_hash
    )
    native_config = render_native_config(parse_dotenv(args.env_file))
    install_runtime_files(grant_platform_admin=explicit_admin)
    installed_skill = install_platform_skill()
    reconcile_admin_policy(explicit_admin)
    if source_hash(args.env_file) != canonical_hash:
        raise HermesInstallError(
            "canonical platform credential changed during Hermes installation"
        )
    systemctl("disable", "--now", LEGACY_SERVICE, check=False)
    LEGACY_UNIT_PATH.unlink(missing_ok=True)
    systemctl("daemon-reload")
    systemctl("enable", SERVICE)
    if not args.no_start:
        systemctl("restart", SERVICE)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if systemctl("is-active", SERVICE, check=False).stdout.strip() == "active":
                break
            time.sleep(1)
        # systemd reports the gateway process active before the authenticated
        # Hermes API finishes binding.  Gate the installation result on the
        # real API surface instead of racing a one-shot external health probe.
        if not wait_hermes_api_server(parse_dotenv(args.env_file), timeout_seconds=60):
            raise HermesInstallError("native Hermes API did not become ready")

    payload = status_payload(args.env_file, verify_external=not args.no_start)
    payload["installed"] = True
    payload["credentials"] = credential_state
    payload["runtimeCredentialProjection"] = runtime_projection
    payload["nativeConfig"] = native_config
    payload["skillInstallation"] = installed_skill
    if args.no_start:
        payload["ok"] = all(
            value
            for name, value in payload["checks"].items()
            if name != "serviceActive"
        )
    emit(payload)
    if not payload["ok"]:
        raise HermesInstallError(
            "Hermes installation completed but health checks did not pass"
        )


def reconcile(args: argparse.Namespace) -> None:
    """Re-render native Hermes state from the canonical platform env."""
    require_root()
    if args.env_file != DEFAULT_ENV_FILE:
        raise HermesInstallError(
            f"reconciliation only accepts the canonical credential source {DEFAULT_ENV_FILE}"
        )
    if public_mode_requested(args.env_file):
        # This mode peek fails toward public mode, so malformed credentials
        # cannot preserve a stale unrestricted sudo overlay.
        reconcile_admin_policy(False)
    credential_state = validate_env_file(args.env_file)
    operator_mode = credential_state["operatorMode"]
    projection_evidence = reconcile_platform_projections(args.env_file)
    canonical_hash = projection_evidence["sourceSha256"]
    runtime_projection = runtime_credential_projection_evidence(
        args.env_file, canonical_hash
    )
    native_config = render_native_config(parse_dotenv(args.env_file))
    installed_skill = install_platform_skill()
    if operator_mode == "unprivileged_service":
        install_runtime_files(grant_platform_admin=False)
    elif not operator_mode_ready(operator_mode):
        raise HermesInstallError(
            "unrestricted_host_repair is not already authorized; run install "
            "with --grant-platform-admin"
        )
    restarted = False
    if not args.no_restart and UNIT_PATH.is_file():
        systemctl("restart", SERVICE)
        if not wait_hermes_api_server(parse_dotenv(args.env_file), timeout_seconds=60):
            raise HermesInstallError("native Hermes API did not become ready")
        restarted = True
    emit(
        {
            "ok": True,
            "reconciled": True,
            "service": SERVICE,
            "restarted": restarted,
            "platformProjections": projection_evidence,
            "runtimeCredentialProjection": runtime_projection,
            "nativeConfig": native_config,
            "skillInstallation": installed_skill,
        }
    )


def status(args: argparse.Namespace) -> None:
    emit(status_payload(args.env_file))


def health(args: argparse.Namespace) -> None:
    payload = status_payload(args.env_file, verify_external=True)
    emit(payload)
    if not payload["ok"]:
        raise SystemExit(1)


def remove(args: argparse.Namespace) -> None:
    require_root()
    systemctl("disable", "--now", SERVICE, check=False)
    systemctl("disable", "--now", LEGACY_SERVICE, check=False)
    UNIT_PATH.unlink(missing_ok=True)
    LEGACY_UNIT_PATH.unlink(missing_ok=True)
    SUDOERS_PATH.unlink(missing_ok=True)
    systemctl("daemon-reload", check=False)
    systemctl("reset-failed", SERVICE, check=False)
    if INSTALL_ROOT.exists():
        shutil.rmtree(INSTALL_ROOT)
    purged = False
    if args.purge_data:
        if STATE_ROOT.exists():
            shutil.rmtree(STATE_ROOT)
        try:
            pwd.getpwnam(SERVICE_USER)
        except KeyError:
            pass
        else:
            command(["userdel", SERVICE_USER], check=False, capture=True, timeout=30)
        purged = True
    emit(
        {"ok": True, "removed": True, "statePreserved": not purged, "service": SERVICE}
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument(
        "--env-file",
        type=Path,
        default=DEFAULT_ENV_FILE,
        help="root-owned platform EnvironmentFile (default: %(default)s)",
    )
    commands = root.add_subparsers(dest="action", required=True)

    preflight_parser = commands.add_parser(
        "preflight", help="validate credentials and authorization without values"
    )
    preflight_parser.set_defaults(handler=preflight)

    install_parser = commands.add_parser(
        "install", help="idempotently install and start the pinned runtime"
    )
    install_parser.add_argument(
        "--grant-platform-admin",
        action="store_true",
        help="explicitly enable unrestricted NOPASSWD host repair (disabled by default)",
    )
    install_parser.add_argument(
        "--no-start",
        action="store_true",
        help="install and enable the unit without starting it",
    )
    install_parser.set_defaults(handler=install)

    reconcile_parser = commands.add_parser(
        "reconcile", help="re-render native runtime state from canonical config"
    )
    reconcile_parser.add_argument(
        "--no-restart",
        action="store_true",
        help="re-render state without restarting an installed service",
    )
    reconcile_parser.set_defaults(handler=reconcile)

    status_parser = commands.add_parser("status", help="return redacted runtime status")
    status_parser.set_defaults(handler=status)

    health_parser = commands.add_parser(
        "health", help="fail unless the configured runtime is healthy"
    )
    health_parser.set_defaults(handler=health)

    remove_parser = commands.add_parser(
        "remove", help="remove runtime and policy; preserve state by default"
    )
    remove_parser.add_argument(
        "--purge-data",
        action="store_true",
        help="also delete Hermes state and service account",
    )
    remove_parser.set_defaults(handler=remove)
    return root


def main() -> None:
    args = parser().parse_args()
    try:
        args.handler(args)
    except (HermesInstallError, OSError, subprocess.SubprocessError) as error:
        print(f"server-hermes: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()

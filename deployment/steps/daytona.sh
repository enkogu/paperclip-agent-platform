#!/usr/bin/env bash
set -Eeuo pipefail

ACTION=${1:-all}
ROOT=/opt/mte-platform/runtime/paperclip-daytona
ENV_FILE=/root/.config/mte-secrets/platform.env
DAYTONA_ENV_FILE=/root/.config/mte-secrets/services/daytona.env
ENV_LOCK=/root/.config/mte-secrets/.platform-env.lock
COMPOSE_BIN=/usr/libexec/docker/cli-plugins/docker-compose
RUNTIME_ENV=$ROOT/platform.env.projection
RUNTIME_ENV_HASH=$ROOT/platform.env.projection.sha256
RUNNER_DAEMON_CONFIG=$ROOT/runner-daemon.json
RENDERED_COMPOSE=$ROOT/daytona-compose.rendered.json
EVIDENCE_ROOT=/opt/mte-platform/evidence
EVIDENCE=$EVIDENCE_ROOT/paperclip-daytona-control-plane.json
SCRIPT_PATH=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")
PAPERCLIP_STEP=$SCRIPT_DIR/paperclip.sh
RELEASE_ROOT=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$SCRIPT_DIR/..")
COMPOSE=$RELEASE_ROOT/deployment/services/daytona/compose.yaml
PROFILE_CATALOG=$RELEASE_ROOT/templates/profiles/profiles.yaml
PROFILE_SKILL_ROOT=$RELEASE_ROOT/runtime/paperclip/profiles/skills/verification-before-completion
PROFILE_SKILL_CONTRACT=$ROOT/profile-skill-contract.json
PRODUCER_SHA256=$(sha256sum "$SCRIPT_PATH" | awk '{print $1}')

log() { printf 'paperclip-daytona: %s\n' "$*"; }
die() { printf 'paperclip-daytona: %s\n' "$*" >&2; exit 2; }

prepare_profile_skill_contract() {
  python3 - "$PROFILE_CATALOG" "$PROFILE_SKILL_ROOT" "$PROFILE_SKILL_CONTRACT" <<'PY'
from pathlib import Path
import hashlib
import json
import os
import sys

import yaml

catalog_path, skill_root, output = map(Path, sys.argv[1:])
catalog = yaml.safe_load(catalog_path.read_text())
ref = "verification-before-completion"
package = (catalog.get("skillPackages") or {}).get(ref)
if not isinstance(package, dict):
    raise SystemExit("paperclip-daytona: verification skill package is missing")
profiles = {
    str(profile.get("ref")): profile
    for profile in catalog.get("profiles") or []
    if str(profile.get("ref", "")).startswith("coding-daytona-")
}
expected_profiles = {
    "coding-daytona-codex": "codex",
    "coding-daytona-claude": "claude",
    "coding-daytona-pi": "pi",
}
if set(profiles) != set(expected_profiles) or any(
    ref not in profile.get("skills", [])
    for profile in profiles.values()
):
    raise SystemExit("paperclip-daytona: a configured coding profile lacks the verification skill")
manifest = skill_root / package["manifest"]
metadata = skill_root / package["metadata"]
sha256 = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
if sha256(manifest) != package["manifestSha256"] or sha256(metadata) != package["metadataSha256"]:
    raise SystemExit("paperclip-daytona: projected verification skill hash drifted")
if package["contractId"] not in manifest.read_text():
    raise SystemExit("paperclip-daytona: projected verification skill contract drifted")
payload = {
    "ref": ref,
    "contractId": package["contractId"],
    "manifestSha256": package["manifestSha256"],
    "metadataSha256": package["metadataSha256"],
    "nativeDestinations": {
        harness: package["nativeDestinations"][harness]
        for harness in expected_profiles.values()
    },
    # Keep this explicit rather than alphabetical: controller evidence and the
    # three-run E2E attestation use the same stable Codex → Claude → Pi order.
    "installedProfiles": [
        "coding-daytona-codex",
        "coding-daytona-claude",
        "coding-daytona-pi",
    ],
}
temporary = output.with_suffix(".tmp")
temporary.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
temporary.chmod(0o600)
os.replace(temporary, output)
PY
}

env_value() {
  python3 - "$1" "$2" <<'PY'
from pathlib import Path
import sys
for line in Path(sys.argv[1]).read_text().splitlines():
    if line.startswith(sys.argv[2]+"="):
        print(line.split("=",1)[1]); raise SystemExit(0)
raise SystemExit(2)
PY
}

canonical_lock_run() {
  local operation=$1 timeout=${2:-300} timeout_message=${3:-timeout waiting for canonical platform.env lock}
  local shell_state name
  shell_state=$(
    for name in \
      ROOT ENV_FILE DAYTONA_ENV_FILE ENV_LOCK COMPOSE_BIN RUNTIME_ENV \
      RUNTIME_ENV_HASH RUNNER_DAEMON_CONFIG RENDERED_COMPOSE EVIDENCE_ROOT \
      EVIDENCE SCRIPT_PATH SCRIPT_DIR RELEASE_ROOT COMPOSE \
      PAPERCLIP_STEP PROFILE_CATALOG PROFILE_SKILL_ROOT PROFILE_SKILL_CONTRACT \
      PRODUCER_SHA256 TRACE RUN_ID DAYTONA_API_KEY_RESULT; do
      declare -p "$name" 2>/dev/null || true
    done
    declare -f
  )
  python3 - "$ENV_LOCK" "$timeout" "$operation" "$timeout_message" "$shell_state" <<'PY'
import errno
import fcntl
import os
import stat
import struct
import sys
import time

path, timeout_raw, operation, timeout_message, shell_state = sys.argv[1:]
timeout = float(timeout_raw)
expected_uid = os.geteuid()
expected_gid = os.getegid()
parent, name = os.path.split(path)
if not parent or not name or name in (".", ".."):
    raise SystemExit("canonical lock path is unsafe")
nofollow = getattr(os, "O_NOFOLLOW", None)
cloexec = getattr(os, "O_CLOEXEC", None)
directory = getattr(os, "O_DIRECTORY", None)
if nofollow is None or cloexec is None or directory is None:
    raise SystemExit("canonical lock requires O_NOFOLLOW, O_CLOEXEC and O_DIRECTORY")

created_parent = False
try:
    os.mkdir(parent, 0o700)
    created_parent = True
except FileExistsError:
    pass
try:
    parent_fd = os.open(parent, os.O_RDONLY | directory | nofollow | cloexec)
except OSError as exc:
    raise SystemExit("canonical lock parent cannot be safely opened") from exc
try:
    if created_parent:
        os.fchmod(parent_fd, 0o700)
    parent_path_stat = os.stat(parent, follow_symlinks=False)
    parent_fd_stat = os.fstat(parent_fd)
    if (
        not stat.S_ISDIR(parent_path_stat.st_mode)
        or not stat.S_ISDIR(parent_fd_stat.st_mode)
        or parent_path_stat.st_uid != expected_uid
        or parent_fd_stat.st_uid != expected_uid
        or parent_path_stat.st_gid != expected_gid
        or parent_fd_stat.st_gid != expected_gid
        or stat.S_IMODE(parent_path_stat.st_mode) != 0o700
        or stat.S_IMODE(parent_fd_stat.st_mode) != 0o700
        or parent_path_stat.st_nlink < 2
        or parent_fd_stat.st_nlink < 2
        or (parent_path_stat.st_dev, parent_path_stat.st_ino)
        != (parent_fd_stat.st_dev, parent_fd_stat.st_ino)
    ):
        raise SystemExit("canonical lock parent ownership, type or mode is unsafe")

    flags = os.O_RDWR | nofollow | cloexec
    created = False
    try:
        descriptor = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd)
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise SystemExit("canonical lock cannot be safely opened") from exc
    try:
        if created:
            os.fchmod(descriptor, 0o600)

        def verify_identity():
            path_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            fd_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(path_stat.st_mode)
                or not stat.S_ISREG(fd_stat.st_mode)
                or path_stat.st_uid != expected_uid
                or fd_stat.st_uid != expected_uid
                or path_stat.st_gid != expected_gid
                or fd_stat.st_gid != expected_gid
                or stat.S_IMODE(path_stat.st_mode) != 0o600
                or stat.S_IMODE(fd_stat.st_mode) != 0o600
                or path_stat.st_nlink != 1
                or fd_stat.st_nlink != 1
                or (path_stat.st_dev, path_stat.st_ino)
                != (fd_stat.st_dev, fd_stat.st_ino)
            ):
                raise SystemExit("canonical lock inode ownership, type, mode, link count or identity is unsafe")

        verify_identity()
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise SystemExit(timeout_message)
                time.sleep(0.1)
        required = ("F_OFD_SETLK", "F_WRLCK")
        if not sys.platform.startswith("linux") or any(
            not hasattr(fcntl, item) for item in required
        ):
            raise SystemExit("Linux OFD lock support is required")
        request = struct.pack("hhqqi4x", fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0)
        while True:
            try:
                fcntl.fcntl(descriptor, fcntl.F_OFD_SETLK, request)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                if time.monotonic() >= deadline:
                    raise SystemExit(timeout_message)
                time.sleep(0.1)
        # Reject replacement between safe open and either lock acquisition.
        verify_identity()
        if descriptor != 9:
            os.dup2(descriptor, 9, inheritable=True)
            os.close(descriptor)
        else:
            os.set_inheritable(9, True)
        command = (
            "set -Eeuo pipefail\n"
            + shell_state
            + "\nDAYTONA_ENV_LOCK_HELD=1\n"
            + '"$1"\n'
        )
        os.execve("/bin/bash", ["bash", "-c", command, "daytona-lock", operation], os.environ)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
finally:
    os.close(parent_fd)
PY
}

canonical_lock_ofd() {
  local operation=$1 timeout=${2:-0}
  python3 - "$operation" "$ENV_LOCK" 9 "$timeout" <<'PY'
import errno
import fcntl
import os
import stat
import struct
import sys
import time

operation, path, descriptor_raw, timeout_raw = sys.argv[1:]
descriptor = int(descriptor_raw)
timeout = float(timeout_raw)
required = ("F_OFD_GETLK", "F_OFD_SETLK", "F_WRLCK", "F_UNLCK")
if not sys.platform.startswith("linux") or any(not hasattr(fcntl, name) for name in required):
    raise SystemExit("Linux OFD lock support is required")

path_stat = os.stat(path, follow_symlinks=False)
fd_stat = os.fstat(descriptor)
if (
    not stat.S_ISREG(path_stat.st_mode)
    or not stat.S_ISREG(fd_stat.st_mode)
    or path_stat.st_nlink != 1
    or fd_stat.st_nlink != 1
    or (path_stat.st_dev, path_stat.st_ino) != (fd_stat.st_dev, fd_stat.st_ino)
):
    raise SystemExit("fd9 does not reference the sole canonical regular lock inode")

request = struct.pack("hhqqi4x", fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0)
if operation == "acquire":
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.fcntl(descriptor, fcntl.F_OFD_SETLK, request)
            break
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                raise
            if time.monotonic() >= deadline:
                raise SystemExit("timeout waiting for canonical platform.env lock")
            time.sleep(0.1)
elif operation == "assert":
    flags = os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    contender = os.open(path, flags)
    try:
        observed = fcntl.fcntl(contender, fcntl.F_OFD_GETLK, request)
        lock_type = struct.unpack("hhqqi4x", observed)[0]
        if lock_type == fcntl.F_UNLCK:
            raise SystemExit("fd9 was not locked before already-locked validation")
        try:
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(contender, fcntl.LOCK_UN)
            raise SystemExit("fd9 was not flock-locked before already-locked validation")
    finally:
        os.close(contender)
    try:
        # Idempotent only for the same open-file description. If another OFD
        # owns the observed lock, this fails without changing either lock.
        fcntl.fcntl(descriptor, fcntl.F_OFD_SETLK, request)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            raise SystemExit("fd9 does not own the observed canonical OFD lock")
        raise
else:
    raise SystemExit("invalid canonical OFD lock operation")
PY
}

assert_canonical_lock_held() {
  [[ ${DAYTONA_ENV_LOCK_HELD:-} == 1 ]] \
    || die "already-locked path requires the canonical platform.env lock"
  python3 - "$ENV_LOCK" 9 <<'PY' \
    || die "already-locked path requires fd9 to reference the canonical platform.env lock"
import os
import sys

path_stat = os.stat(sys.argv[1])
fd_stat = os.fstat(int(sys.argv[2]))
if (fd_stat.st_dev, fd_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
    raise SystemExit(1)
PY
  canonical_lock_ofd assert \
    || die "already-locked path requires the canonical platform.env lock"
}

init_config_while_locked() {
  assert_canonical_lock_held
  install -d -m 0700 "$(dirname "$ENV_FILE")" "$ROOT" "$ROOT/keys"
  install -d -m 0755 "$EVIDENCE_ROOT"
  python3 - "$ENV_FILE" <<'PY'
from pathlib import Path
import os
import re
import secrets
import sys

path = Path(sys.argv[1])
if not path.is_file():
    raise SystemExit(
        "paperclip-daytona: canonical platform.env is missing; "
        "run server-config.py init before Daytona"
    )
source_stat = path.stat()
if source_stat.st_uid != 0 or source_stat.st_mode & 0o777 != 0o600:
    raise SystemExit(
        "paperclip-daytona: canonical platform.env must be root-owned with mode 0600"
    )

values = {}
for line_number, line in enumerate(path.read_text().splitlines(), 1):
    if not line or line.startswith("#"):
        continue
    if "=" not in line:
        raise SystemExit(
            f"paperclip-daytona: invalid canonical platform.env line {line_number}"
        )
    key, value = line.split("=", 1)
    if key in values:
        raise SystemExit(
            f"paperclip-daytona: duplicate canonical platform.env key {key}"
        )
    values[key] = value

required = {
    "DAYTONA_API_URL",
    "DAYTONA_BOOTSTRAP_EMAIL",
    "DAYTONA_DB_USER",
    "DAYTONA_MINIO_USER",
    "DAYTONA_REGISTRY_USER",
    "DAYTONA_TARGET",
    "HERMES_LLM_MODEL",
    "MTE_AGENT_GATEWAY_HOST",
    "MTE_AGENT_GATEWAY_IMAGE",
    "MTE_AGENT_GATEWAY_NINEROUTER_BASE_URL",
    "MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL",
    "MTE_AGENT_GATEWAY_NINEROUTER_PORT",
    "MTE_AGENT_GATEWAY_NINEROUTER_UPSTREAM",
    "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_PORT",
    "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_UPSTREAM",
    "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_URL",
    "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_PORT",
    "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM",
    "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
    "MTE_AGENT_GATEWAY_TOOLHIVE_PI_PORT",
    "MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM",
    "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL",
    "MTE_AGENT_PLANE_NETWORK",
    "MTE_CONTEXT7_MCP_URL",
    "MTE_CONTEXT7_PI_NPM_INTEGRITY",
    "MTE_CONTEXT7_PI_PACKAGE",
    "MTE_CONTEXT7_PI_VERSION",
    "MTE_CLAUDE_CODE_NPM_INTEGRITY",
    "MTE_CLAUDE_CODE_VERSION",
    "MTE_CODEX_NPM_INTEGRITY",
    "MTE_CODEX_VERSION",
    "MTE_DOCKER_LOG_MAX_FILES",
    "MTE_DOCKER_LOG_DRIVER",
    "MTE_DOCKER_LOG_MAX_SIZE",
    "MTE_DAYTONA_API_IMAGE",
    "MTE_DAYTONA_API_INTERNAL_PORT",
    "MTE_DAYTONA_API_PORT",
    "MTE_DAYTONA_API_URL",
    "MTE_DAYTONA_CODING_CPU",
    "MTE_DAYTONA_CODING_MEMORY_GIB",
    "MTE_DAYTONA_CODING_SNAPSHOT",
    "MTE_DAYTONA_CODING_SNAPSHOT_PREFIX",
    "MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT",
    "MTE_DAYTONA_CONTROL_PLANE_VERSION",
    "MTE_DAYTONA_DEX_IMAGE",
    "MTE_DAYTONA_DEX_INTERNAL_PORT",
    "MTE_DAYTONA_DEX_PORT",
    "MTE_DAYTONA_DEFAULT_ORG_MAX_CPU_PER_SANDBOX",
    "MTE_DAYTONA_DEFAULT_ORG_MAX_DISK_GIB_PER_SANDBOX",
    "MTE_DAYTONA_DEFAULT_ORG_MAX_MEMORY_GIB_PER_SANDBOX",
    "MTE_DAYTONA_DEFAULT_ORG_MAX_SNAPSHOT_SIZE_GIB",
    "MTE_DAYTONA_DEFAULT_ORG_SNAPSHOT_QUOTA",
    "MTE_DAYTONA_DEFAULT_ORG_TOTAL_CPU",
    "MTE_DAYTONA_DEFAULT_ORG_TOTAL_DISK_GIB",
    "MTE_DAYTONA_DEFAULT_ORG_TOTAL_MEMORY_GIB",
    "MTE_DAYTONA_DEFAULT_ORG_VOLUME_QUOTA",
    "MTE_DAYTONA_DEFAULT_RUNNER_CPU",
    "MTE_DAYTONA_DEFAULT_RUNNER_DISK_GIB",
    "MTE_DAYTONA_DEFAULT_RUNNER_MEMORY_GIB",
    "MTE_DAYTONA_DISK_GIB",
    "MTE_DAYTONA_GENERAL_CPU",
    "MTE_DAYTONA_GENERAL_MEMORY_GIB",
    "MTE_DAYTONA_GENERAL_SNAPSHOT",
    "MTE_DAYTONA_GENERAL_SNAPSHOT_PREFIX",
    "MTE_DAYTONA_MINIO_IMAGE",
    "MTE_DAYTONA_MINIO_CONSOLE_INTERNAL_PORT",
    "MTE_DAYTONA_MINIO_INTERNAL_PORT",
    "MTE_DAYTONA_NETWORK",
    "MTE_DAYTONA_SANDBOX_SUBNET",
    "MTE_DAYTONA_SANDBOX_VERSION",
    "MTE_DAYTONA_PAPERCLIP_NETWORK",
    "MTE_DAYTONA_POSTGRES_IMAGE",
    "MTE_DAYTONA_POSTGRES_INTERNAL_PORT",
    "MTE_DAYTONA_PROXY_IMAGE",
    "MTE_DAYTONA_PROXY_INTERNAL_PORT",
    "MTE_DAYTONA_PROXY_PORT",
    "MTE_DAYTONA_VALKEY_IMAGE",
    "MTE_DAYTONA_REDIS_INTERNAL_PORT",
    "MTE_DAYTONA_REGISTRY_IMAGE",
    "MTE_DAYTONA_REGISTRY_INTERNAL_PORT",
    "MTE_DAYTONA_RUNNER_AVAILABILITY_SCORE_THRESHOLD",
    "MTE_DAYTONA_RUNNER_DECLARATIVE_BUILD_SCORE_THRESHOLD",
    "MTE_DAYTONA_RUNNER_IMAGE",
    "MTE_DAYTONA_RUNNER_INTERNAL_PORT",
    "MTE_DAYTONA_RUNNER_START_SCORE_THRESHOLD",
    "MTE_DAYTONA_INSTALLER_SHA256",
    "MTE_DAYTONA_SANDBOX_IMAGE",
    "MTE_DAYTONA_SANDBOX_IMAGE_REVISION",
    "MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL",
    "MTE_DAYTONA_SSH_IMAGE",
    "MTE_DAYTONA_SSH_INTERNAL_PORT",
    "MTE_DAYTONA_SSH_PORT",
    "MTE_GITHUB_CLI_ARCHIVE_SHA256",
    "MTE_GITHUB_CLI_VERSION",
    "MTE_HEALTHCHECK_STANDARD_INTERVAL",
    "MTE_HEALTHCHECK_STANDARD_RETRIES",
    "MTE_HEALTHCHECK_STANDARD_START_PERIOD",
    "MTE_HEALTHCHECK_STANDARD_TIMEOUT",
    "MTE_JQ_LINUX_AMD64_SHA256",
    "MTE_JQ_VERSION",
    "MTE_PAPERCLIP_API_BASE",
    "MTE_PAPERCLIP_IMAGE",
    "MTE_PI_CODING_AGENT_DIR",
    "MTE_PI_NPM_INTEGRITY",
    "MTE_PI_TOOLHIVE_EXTENSION_SHA256",
    "MTE_PI_VERSION",
    "MTE_TOOLHIVE_ARCHIVE_SHA256",
    "MTE_TOOLHIVE_VERSION",
    "MTE_TOOL_RUNTIME_NETWORK",
    "NINEROUTER_PROFILE_CODING_DAYTONA_CLAUDE_API_KEY",
    "NINEROUTER_PROFILE_CODING_DAYTONA_CODEX_API_KEY",
    "NINEROUTER_PROFILE_CODING_DAYTONA_PI_API_KEY",
    "TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_BEARER_TOKEN",
    "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN",
    "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN",
}
missing = sorted(key for key in required if not values.get(key, "").strip())
if missing:
    raise SystemExit(
        "paperclip-daytona: canonical platform.env is incomplete: "
        + ",".join(missing)
    )
if not re.fullmatch(
    r"[^\s@]+@sha256:[0-9a-f]{64}", values["MTE_DAYTONA_SANDBOX_IMAGE"]
):
    raise SystemExit(
        "paperclip-daytona: MTE_DAYTONA_SANDBOX_IMAGE must be digest-pinned"
    )
if not re.fullmatch(
    r"https://[^\s]+", values["MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL"]
):
    raise SystemExit(
        "paperclip-daytona: MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL must use HTTPS"
    )
if not re.fullmatch(
    r"[0-9a-f]{40}", values["MTE_DAYTONA_SANDBOX_IMAGE_REVISION"]
):
    raise SystemExit(
        "paperclip-daytona: MTE_DAYTONA_SANDBOX_IMAGE_REVISION must be a commit"
    )
if values.get("MTE_ENABLE_OPERATOR_PROVIDED_PROPRIETARY_HARNESSES") != "true":
    raise SystemExit(
        "paperclip-daytona: operator-provided proprietary harnesses are not enabled; "
        "set MTE_ENABLE_OPERATOR_PROVIDED_PROPRIETARY_HARNESSES=true in the private operator input"
    )
generated = {
    "DAYTONA_ADMIN_API_KEY": lambda: "dtn_" + secrets.token_hex(32),
    "DAYTONA_BOOTSTRAP_PASSWORD": lambda: secrets.token_urlsafe(32),
    "DAYTONA_DB_PASSWORD": lambda: secrets.token_hex(24),
    "DAYTONA_ENCRYPTION_KEY": lambda: secrets.token_hex(16),
    "DAYTONA_ENCRYPTION_SALT": lambda: secrets.token_hex(16),
    "DAYTONA_HEALTH_CHECK_API_KEY": lambda: secrets.token_hex(24),
    "DAYTONA_MINIO_PASSWORD": lambda: secrets.token_hex(24),
    "DAYTONA_OTEL_COLLECTOR_API_KEY": lambda: secrets.token_hex(24),
    "DAYTONA_PROXY_API_KEY": lambda: secrets.token_hex(24),
    "DAYTONA_REGISTRY_PASSWORD": lambda: secrets.token_hex(24),
    "DAYTONA_RUNNER_API_KEY": lambda: secrets.token_hex(24),
    "DAYTONA_SSH_GATEWAY_API_KEY": lambda: secrets.token_hex(24),
}
changed = []
for key, factory in generated.items():
    if not values.get(key, "").strip():
        values[key] = factory()
        changed.append(key)

if changed:
    temporary = path.with_name(path.name + ".daytona.tmp")
    temporary.write_text(
        "".join(f"{key}={values[key]}\n" for key in sorted(values))
    )
    temporary.chmod(0o600)
    os.replace(temporary, path)
PY
  [[ "$(env_value "$ENV_FILE" MTE_DAYTONA_INSTALLER_SHA256)" == "$PRODUCER_SHA256" ]] \
    || die "daytona.sh does not match canonical MTE_DAYTONA_INSTALLER_SHA256"
  if [[ ! -s $ROOT/keys/ssh ]]; then
    ssh-keygen -q -t ed25519 -N '' -f "$ROOT/keys/ssh"
    ssh-keygen -q -t ed25519 -N '' -f "$ROOT/keys/host"
  fi
  chmod 0600 "$ENV_FILE" "$ROOT/keys/ssh" "$ROOT/keys/host"
}

init_config() {
  local lock_contract=${1:-acquire}
  case $lock_contract in
    acquire)
      canonical_lock_run init_config_while_locked
      ;;
    already-locked)
      init_config_while_locked
      ;;
    *) die "invalid init_config lock contract: $lock_contract" ;;
  esac
}

config_hash() {
  python3 - "$@" <<'PY'
from pathlib import Path
import hashlib,sys
values = {}
for source in sys.argv[1:] or ["/root/.config/mte-secrets/platform.env"]:
    for line in Path(source).read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
rows=[]
for k, x in values.items():
    if k.startswith(("MTE_PAPERCLIP_","MTE_DAYTONA_","MTE_AGENT_","MTE_CODEX_","MTE_CLAUDE_","MTE_PI_","MTE_TOOLHIVE_","MTE_GITHUB_","MTE_CONTEXT7_","PROFILE_CODING_DAYTONA_")): rows.append(k+"="+x)
    elif k == "CONTEXT7_API_KEY": rows.append("CONTEXT7_API_KEY_CONFIGURED="+str(bool(x)).lower())
for k in ("DAYTONA_API_KEY","DAYTONA_DB_PASSWORD","DAYTONA_PROXY_API_KEY","DAYTONA_RUNNER_API_KEY","DAYTONA_SSH_GATEWAY_API_KEY","TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN","TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_BEARER_TOKEN","TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN"): rows.append("secret-ref:"+k)
print(hashlib.sha256(("\n".join(sorted(rows))+"\n").encode()).hexdigest())
PY
}

snapshot_runtime_config_while_locked() {
  assert_canonical_lock_held
  python3 - "$ENV_FILE" "$DAYTONA_ENV_FILE" "$RUNTIME_ENV" <<'PY'
from pathlib import Path
import sys
canonical, projection, target = map(Path, sys.argv[1:])
values = {}
for source in (canonical, projection):
    for line in source.read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
tmp = target.with_suffix(".tmp")
tmp.write_text("".join(f"{key}={values[key]}\n" for key in sorted(values)))
tmp.chmod(0o600)
tmp.replace(target)
PY
  config_hash "$ENV_FILE" "$DAYTONA_ENV_FILE" >"$RUNTIME_ENV_HASH"
  chmod 0600 "$RUNTIME_ENV_HASH"
}

snapshot_runtime_config() {
  local lock_contract=${1:-acquire}
  case $lock_contract in
    acquire)
      canonical_lock_run snapshot_runtime_config_while_locked
      ;;
    already-locked)
      snapshot_runtime_config_while_locked
      ;;
    *) die "invalid snapshot_runtime_config lock contract: $lock_contract" ;;
  esac
}

assert_runtime_config_current() {
  canonical_lock_run assert_runtime_config_current_while_locked
}

assert_runtime_config_current_while_locked() {
  local expected actual
  expected=$(cat "$RUNTIME_ENV_HASH")
  actual=$(config_hash "$ENV_FILE" "$DAYTONA_ENV_FILE")
  [[ "$actual" == "$expected" ]] || die "rendered Daytona config changed during deployment; rerun install"
}

render_daytona_projection_while_locked() {
  assert_canonical_lock_held
  # Daytona consumes canonical values plus the rendered service projection:
  # the latter supplies derived endpoints such as Dex's OIDC URL.
  # Pass the inherited canonical descriptor so the renderer can prove this
  # transaction owns the lock without taking a second flock.
  python3 - "$RELEASE_ROOT/bin/server-config.py" <<'PY'
from pathlib import Path
import importlib.util
import sys

path = Path(sys.argv[1])
sys.path.insert(0, str(path.parent))
spec = importlib.util.spec_from_file_location("mte_server_config", path)
if spec is None or spec.loader is None:
    raise SystemExit("paperclip-daytona: cannot load server-config renderer")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.render(lock_fd=9)
PY
}

render_daytona_projection() {
  local lock_contract=${1:-acquire}
  case $lock_contract in
    acquire)
      canonical_lock_run render_daytona_projection_while_locked
      ;;
    already-locked)
      render_daytona_projection_while_locked
      ;;
    *) die "invalid render_daytona_projection lock contract: $lock_contract" ;;
  esac
}

render() {
  init_config
  render_daytona_projection
  snapshot_runtime_config
  local pub priv host
  pub=$(base64 -w0 "$ROOT/keys/ssh.pub")
  priv=$(base64 -w0 "$ROOT/keys/ssh")
  host=$(base64 -w0 "$ROOT/keys/host")
  printf 'SSH_PUBLIC_KEY=%s\nSSH_PRIVATE_KEY=%s\nSSH_HOST_KEY=%s\n' \
    "$pub" "$priv" "$host" >"$ROOT/ssh.env"
  printf 'SSH_GATEWAY_PUBLIC_KEY=%s\n' "$(cat "$ROOT/keys/ssh.pub")" >"$ROOT/api-ssh.env"
  chmod 0600 "$ROOT/ssh.env" "$ROOT/api-ssh.env"
  python3 - "$RUNTIME_ENV" "$ROOT/dex.yaml" "$RUNNER_DAEMON_CONFIG" "$COMPOSE" <<'PY'
from pathlib import Path
import crypt
import ipaddress
import json
import sys
import yaml

env_path, dex_path, daemon_path, compose_path = map(Path, sys.argv[1:])
values = dict(line.split("=", 1) for line in env_path.read_text().splitlines() if "=" in line)
subnet = ipaddress.ip_network(values["MTE_DAYTONA_SANDBOX_SUBNET"], strict=True)
gateway = ipaddress.ip_address(values["MTE_AGENT_GATEWAY_HOST"])
if subnet.version != 4 or subnet.prefixlen > 29 or gateway != subnet.network_address + 1:
    raise SystemExit(
        "paperclip-daytona: sandbox subnet/gateway contract must use the first "
        "usable address of an IPv4 /0-/29 network"
    )
compose_document = yaml.safe_load(compose_path.read_text())
services = compose_document.get("services") or {}
runner = services.get("runner") or {}
agent_gateway = services.get("agent-gateway") or {}
if agent_gateway.get("network_mode") != "service:runner":
    raise SystemExit("paperclip-daytona: agent gateway must share the runner network namespace")
if set(runner.get("networks") or []) != {"daytona", "agent-plane", "tool-runtime"}:
    raise SystemExit("paperclip-daytona: runner private network membership drifted")
if "./runner-daemon.json:/etc/docker/daemon.json:ro" not in (runner.get("volumes") or []):
    raise SystemExit("paperclip-daytona: runner daemon network contract is not mounted read-only")
bcrypt = crypt.crypt(values["DAYTONA_BOOTSTRAP_PASSWORD"], crypt.mksalt(crypt.METHOD_BLOWFISH))
dex_path.write_text(f'''issuer: http://127.0.0.1:{values["MTE_DAYTONA_DEX_PORT"]}/dex
storage:
  type: sqlite3
  config: {{file: /var/dex/dex.db}}
web:
  http: 0.0.0.0:{values["MTE_DAYTONA_DEX_INTERNAL_PORT"]}
oauth2:
  passwordConnector: local
staticClients:
  - id: daytona
    redirectURIs:
      - http://127.0.0.1:{values["MTE_DAYTONA_API_PORT"]}
      - http://127.0.0.1:{values["MTE_DAYTONA_API_PORT"]}/dashboard
      - http://127.0.0.1:{values["MTE_DAYTONA_PROXY_PORT"]}/callback
    name: Daytona
    public: true
enablePasswordDB: true
staticPasswords:
  - email: {values["DAYTONA_BOOTSTRAP_EMAIL"]!r}
    hash: {bcrypt!r}
    username: admin
    userID: mte-daytona-admin
''')
# Dex runs as its upstream unprivileged UID (1001), so the bind-mounted
# configuration must be readable by that process. It contains only the bcrypt
# verifier, never the bootstrap password itself.
dex_path.chmod(0o644)
daemon_path.write_text(json.dumps({
    "bip": f"{gateway}/{subnet.prefixlen}",
    "insecure-registries": [f'registry:{values["MTE_DAYTONA_REGISTRY_INTERNAL_PORT"]}'],
    "log-driver": values["MTE_DOCKER_LOG_DRIVER"],
    "log-opts": {
        "max-size": values["MTE_DOCKER_LOG_MAX_SIZE"],
        "max-file": values["MTE_DOCKER_LOG_MAX_FILES"],
    },
}, sort_keys=True) + "\n")
daemon_path.chmod(0o644)
PY
  compose config --quiet
  compose config --format json >"$RENDERED_COMPOSE"
  chmod 0600 "$RENDERED_COMPOSE"
  python3 - "$RUNTIME_ENV" "$RUNNER_DAEMON_CONFIG" "$RENDERED_COMPOSE" <<'PY'
from pathlib import Path
import ipaddress
import json
import sys

env_path, daemon_path, rendered_path = map(Path, sys.argv[1:])
values = dict(line.split("=", 1) for line in env_path.read_text().splitlines() if "=" in line)
rendered = json.loads(rendered_path.read_text())
subnet = ipaddress.ip_network(values["MTE_DAYTONA_SANDBOX_SUBNET"], strict=True)
gateway = ipaddress.ip_address(values["MTE_AGENT_GATEWAY_HOST"])
daemon = json.loads(daemon_path.read_text())
services = rendered.get("services") or {}
runner = services.get("runner") or {}
agent_gateway = services.get("agent-gateway") or {}
if gateway != subnet.network_address + 1 or daemon.get("bip") != f"{gateway}/{subnet.prefixlen}":
    raise SystemExit("paperclip-daytona: rendered sandbox bridge gateway drifted")
if agent_gateway.get("network_mode") != "service:runner":
    raise SystemExit("paperclip-daytona: rendered gateway namespace drifted")
if set(runner.get("networks") or {}) != {"daytona", "agent-plane", "tool-runtime"}:
    raise SystemExit("paperclip-daytona: rendered runner network membership drifted")
mounts = runner.get("volumes") or []
if not any(
    row.get("target") == "/etc/docker/daemon.json" and row.get("read_only") is True
    for row in mounts if isinstance(row, dict)
):
    raise SystemExit("paperclip-daytona: rendered runner daemon mount drifted")
PY
}

compose() {
  "$COMPOSE_BIN" --project-directory "$ROOT" --env-file "$RUNTIME_ENV" -f "$COMPOSE" "$@"
}

wait_url() {
  local url=$1
  for _ in $(seq 1 180); do
    curl -fsS --max-time 3 "$url" >/dev/null 2>&1 && return 0
    sleep 2
  done
  die "timeout waiting for $url"
}

assert_bridge_network() {
  local network=$1 contract
  contract=$(docker network inspect "$network" --format '{{.Driver}} {{.Scope}} {{.Internal}}' 2>/dev/null) \
    || die "required Docker network is missing: $network"
  [[ "$contract" == "bridge local false" ]] \
    || die "incompatible Docker network $network: expected bridge local false"
}

ensure_private_network() {
  local network=$1
  docker network inspect "$network" >/dev/null 2>&1 \
    || docker network create --driver bridge --label mte.owner=daytona "$network" >/dev/null
  assert_bridge_network "$network"
}

preflight() {
  command -v docker >/dev/null
  [[ -x "$COMPOSE_BIN" ]] || die "Docker Compose plugin is missing"
  "$COMPOSE_BIN" version >/dev/null
  command -v python3 >/dev/null
  "$PAPERCLIP_STEP" preflight
  init_config
  printf '{"preflight":"passed","canonicalConfigHash":"%s"}\n' "$(config_hash)"
}

install_daytona() {
  preflight
  local agent_plane daytona_network paperclip_network tool_runtime
  agent_plane=$(env_value "$ENV_FILE" MTE_AGENT_PLANE_NETWORK)
  daytona_network=$(env_value "$ENV_FILE" MTE_DAYTONA_NETWORK)
  paperclip_network=$(env_value "$ENV_FILE" MTE_DAYTONA_PAPERCLIP_NETWORK)
  tool_runtime=$(env_value "$ENV_FILE" MTE_TOOL_RUNTIME_NETWORK)
  ensure_private_network "$daytona_network"
  ensure_private_network "$paperclip_network"
  assert_bridge_network "$agent_plane"
  assert_bridge_network "$tool_runtime"
  render
  compose up -d
  local dex_port api_port
  dex_port=$(env_value "$RUNTIME_ENV" MTE_DAYTONA_DEX_PORT)
  api_port=$(env_value "$RUNTIME_ENV" MTE_DAYTONA_API_PORT)
  wait_url "http://127.0.0.1:${dex_port}/dex/.well-known/openid-configuration"
  wait_url "http://127.0.0.1:${api_port}/api/config"
  assert_runtime_config_current
  # Daytona caches the resolved toolbox proxy URL per region. Clear only that
  # derived entry after applying configuration so upgrades cannot retain a
  # previous host-only endpoint. A cache miss is repopulated from PROXY_DOMAIN.
  docker exec mte-daytona-redis \
    valkey-cli DEL "toolbox-proxy-url:region:$(env_value "$RUNTIME_ENV" DAYTONA_TARGET)" \
    >/dev/null
  log "control plane ready"
}

provision_key() {
  init_config
  render_daytona_projection
  snapshot_runtime_config
  local result=$ROOT/daytona-api-key.result.json
  python3 - "$RUNTIME_ENV" "$result" <<'PY'
from pathlib import Path
import hashlib,json,sys,urllib.parse,urllib.request
p,out=map(Path,sys.argv[1:]); v=dict(line.split("=",1) for line in p.read_text().splitlines() if "=" in line); api=v["MTE_DAYTONA_API_URL"]
def req(method,path,data=None,headers=None):
    body=None if data is None else json.dumps(data).encode()
    with urllib.request.urlopen(urllib.request.Request(api+path,data=body,headers={"Content-Type":"application/json",**(headers or {})},method=method),timeout=60) as r:
        raw=r.read(); return json.loads(raw) if raw else None
form=urllib.parse.urlencode({"grant_type":"password","client_id":"daytona","scope":"openid profile email","username":v["DAYTONA_BOOTSTRAP_EMAIL"],"password":v["DAYTONA_BOOTSTRAP_PASSWORD"]}).encode()
url="http://127.0.0.1:"+v["MTE_DAYTONA_DEX_PORT"]+"/dex/token"
with urllib.request.urlopen(urllib.request.Request(url,data=form,headers={"Content-Type":"application/x-www-form-urlencoded"}),timeout=30) as r: token=json.load(r)["access_token"]
jwt={"Authorization":"Bearer "+token}; orgs=req("GET","/organizations",headers=jwt)
if not orgs: orgs=[req("POST","/organizations",{"name":"MTE Paperclip Daytona"},jwt)]
org=orgs[0]; jwt_org={**jwt,"X-Daytona-Organization-ID":org["id"]}
if org.get("defaultRegionId") != v["DAYTONA_TARGET"]:
    req("PATCH",f"/organizations/{org['id']}/default-region",{"defaultRegionId":v["DAYTONA_TARGET"]},jwt_org)
    org={**org,"defaultRegionId":v["DAYTONA_TARGET"]}
key=v.get("DAYTONA_API_KEY","")
if key:
    try: req("GET","/api-keys/current",headers={"Authorization":"Bearer "+key})
    except Exception: key=""
if not key:
    rows=req("GET","/api-keys",headers=jwt_org) or []
    if any(x.get("name")=="paperclip-selfhost" for x in rows): req("DELETE","/api-keys/paperclip-selfhost",headers=jwt_org)
    created=req("POST","/api-keys",{"name":"paperclip-selfhost","permissions":["write:sandboxes","delete:sandboxes","write:snapshots","delete:snapshots"]},jwt_org)
    key=next((created.get(name) for name in ("key","token","apiKey","value") if created.get(name)),"")
    if not key: raise RuntimeError("unexpected API-key response fields: "+",".join(sorted(created)))
payload={"DAYTONA_API_KEY":key,"DAYTONA_ORGANIZATION_ID":org["id"]}
tmp=out.with_suffix(".tmp"); tmp.write_text(json.dumps(payload)+"\n"); tmp.chmod(0o600); tmp.replace(out)
print(json.dumps({"organizationId":org["id"],"defaultRegionId":org["defaultRegionId"],"apiKeyFingerprint":hashlib.sha256(key.encode()).hexdigest()[:16],"storedInCanonicalEnv":True}))
PY
  DAYTONA_API_KEY_RESULT=$result canonical_lock_run persist_provisioned_key_while_locked
  rm -f "$result"
}

persist_provisioned_key_while_locked() {
  [[ "$(config_hash "$ENV_FILE" "$DAYTONA_ENV_FILE")" == "$(cat "$RUNTIME_ENV_HASH")" ]] || die "canonical Daytona config changed while API key was provisioned"
  python3 - "$ENV_FILE" "$DAYTONA_API_KEY_RESULT" <<'PY'
from pathlib import Path
import json,sys
envp,resultp=map(Path,sys.argv[1:]); v=dict(line.split("=",1) for line in envp.read_text().splitlines() if "=" in line)
v.update({str(k):str(x) for k,x in json.loads(resultp.read_text()).items()})
tmp=envp.with_suffix(".tmp"); tmp.write_text("".join(f"{k}={v[k]}\n" for k in sorted(v))); tmp.chmod(0o600); tmp.replace(envp)
PY
}

set_target() {
  # Provisioning owns the organization default-region mutation. Reusing the
  # idempotent path keeps `set-target` independently safe for the orchestrator.
  provision_key
}

build_images_while_locked() {
  local paperclip_image daytona_network coding_prefix general_prefix
    assert_canonical_lock_held
    # This function is callable only from build_images after it holds ENV_LOCK.
    # The immutable image, Daytona activation, and pointer
    # switch remain one serialized transaction and one canonical generation.
    init_config already-locked
    prepare_profile_skill_contract
    paperclip_image=$(env_value "$ENV_FILE" MTE_PAPERCLIP_IMAGE)
    daytona_network=$(env_value "$RUNTIME_ENV" MTE_DAYTONA_NETWORK)
    coding_prefix=$(env_value "$RUNTIME_ENV" MTE_DAYTONA_CODING_SNAPSHOT_PREFIX)
    general_prefix=$(env_value "$RUNTIME_ENV" MTE_DAYTONA_GENERAL_SNAPSHOT_PREFIX)
    [[ "$coding_prefix" != "$general_prefix" ]] \
      || die "coding and general Daytona snapshot prefixes must be distinct"
    docker run --rm -i --network "$daytona_network" --user 0:0 \
    -e MTE_EVIDENCE_PRODUCER_SHA256="$PRODUCER_SHA256" \
    -v "$RUNTIME_ENV:/run/secrets/platform.env:ro" \
    -v "$EVIDENCE_ROOT:/evidence" \
    "$paperclip_image" node --input-type=module <<'NODE'
import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";

const canonicalSource = fs.readFileSync("/run/secrets/platform.env", "utf8");
const values = Object.fromEntries(
  canonicalSource.split(/\n/)
    .filter((line) => line && !line.startsWith("#") && line.includes("="))
    .map((line) => { const i=line.indexOf("="); return [line.slice(0,i),line.slice(i+1)]; })
);
const safe = (key, pattern=/^[A-Za-z0-9._+:/@-]+$/) => {
  const value=values[key] || "";
  if (!pattern.test(value)) throw new Error(`unsafe or missing canonical ${key}`);
  return value;
};
if (!values.DAYTONA_API_KEY) throw new Error("missing DAYTONA_API_KEY");

const require = createRequire(import.meta.url);
const { CreateBucketCommand, HeadBucketCommand, S3Client } = require("@aws-sdk/client-s3");
const objectStorage = new S3Client({
  endpoint: safe("MTE_DAYTONA_MINIO_ENDPOINT_URL"),
  region: "us-east-1",
  credentials: { accessKeyId: values.DAYTONA_MINIO_USER, secretAccessKey: values.DAYTONA_MINIO_PASSWORD },
  forcePathStyle: true,
});
try {
  await objectStorage.send(new HeadBucketCommand({ Bucket: "daytona" }));
} catch (error) {
  if (error?.$metadata?.httpStatusCode !== 404) throw error;
  await objectStorage.send(new CreateBucketCommand({ Bucket: "daytona" }));
}

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value==="object") return `{${Object.keys(value).sort().map((key)=>`${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};
const { Daytona, Image } = await import("@daytonaio/sdk");
const daytona = new Daytona({
  apiKey: values.DAYTONA_API_KEY,
  apiUrl: safe("MTE_DAYTONA_INTERNAL_API_URL"),
});
const codingPrefix=safe("MTE_DAYTONA_CODING_SNAPSHOT_PREFIX");
const generalPrefix=safe("MTE_DAYTONA_GENERAL_SNAPSHOT_PREFIX");
if (codingPrefix===generalPrefix) throw new Error("coding and general snapshot prefixes must be distinct");
const sandboxImage=safe("MTE_DAYTONA_SANDBOX_IMAGE",/^[^\s@]+@sha256:[0-9a-f]{64}$/);
const sandboxImageSourceUrl=safe("MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL",/^https:\/\/[^\s]+$/);
const sandboxImageRevision=safe("MTE_DAYTONA_SANDBOX_IMAGE_REVISION",/^[0-9a-f]{40}$/);
// The self-hosted control plane cannot reliably pull an OCI digest supplied in
// imageName.  Use the SDK's documented Image path instead: it sends buildInfo
// with this exact, context-free Dockerfile, and BuildKit resolves the immutable
// carrier reference itself.  The canonical environment remains the sole source
// of that reference; no digest is converted to a tag.
const snapshotBuildDockerfile=`FROM ${sandboxImage}\n`;
const snapshotBuildImage=Image.base(sandboxImage);
if (snapshotBuildImage.dockerfile!==snapshotBuildDockerfile || snapshotBuildImage.contextList.length!==0) {
  throw new Error("Daytona SDK did not create the expected context-free digest build request");
}
const codingResources={
  cpu:Number(safe("MTE_DAYTONA_CODING_CPU",/^\d+$/)),
  memory:Number(safe("MTE_DAYTONA_CODING_MEMORY_GIB",/^\d+$/)),
  disk:Number(safe("MTE_DAYTONA_DISK_GIB",/^\d+$/)),
};
const generalResources={
  cpu:Number(safe("MTE_DAYTONA_GENERAL_CPU",/^\d+$/)),
  memory:Number(safe("MTE_DAYTONA_GENERAL_MEMORY_GIB",/^\d+$/)),
  disk:codingResources.disk,
};
const resources={coding:codingResources,general:generalResources};
const harnessVersions={
  codex:safe("MTE_CODEX_VERSION"),
  claudeCode:safe("MTE_CLAUDE_CODE_VERSION"),
  pi:safe("MTE_PI_VERSION"),
};
const snapshotContractHash=sha256(canonicalJson({sandboxImage,sandboxImageRevision,resources,harnessVersions}));
const generation=snapshotContractHash.slice(0,12);
const codingName=`${codingPrefix}-${generation}`;
const generalName=`${generalPrefix}-${generation}`;
if (codingName===generalName) throw new Error("coding and general snapshot names must be distinct");
const ownedNames=new Set([codingName,generalName]);
const sleep=(milliseconds)=>new Promise((resolve)=>setTimeout(resolve,milliseconds));
let list=await daytona.snapshot.list(1,100);
const terminalStates=new Set(["build_failed","error"]);
async function deleteSnapshot(snapshot) {
  if (!ownedNames.has(snapshot.name)) throw new Error(`refusing to delete unowned snapshot ${snapshot.name}`);
  await daytona.snapshot.delete(snapshot);
  for (let attempt=0; attempt<90; attempt+=1) {
    const remaining=(await daytona.snapshot.list(1,100)).items.find((row)=>row.name===snapshot.name);
    if (!remaining) return;
    await sleep(2000);
  }
  throw new Error(`timed out deleting terminal snapshot ${snapshot.name}`);
}
const snapshotBuildProvenance=(snapshot)=>snapshot.buildInfo?.dockerfileContent;
const snapshotMatchesContract=(snapshot,expectedDockerfile,expectedResources)=>
  snapshotBuildProvenance(snapshot)===expectedDockerfile &&
  Number(snapshot.cpu)===expectedResources.cpu &&
  Number(snapshot.mem ?? snapshot.memory)===expectedResources.memory &&
  Number(snapshot.disk)===expectedResources.disk;
async function ensureSnapshot(name,buildImage,expectedDockerfile,resources) {
  for (let cycle=0; cycle<2; cycle+=1) {
    let snapshot=(await daytona.snapshot.list(1,100)).items.find((row)=>row.name===name);
    if (snapshot && terminalStates.has(snapshot.state)) {
      await deleteSnapshot(snapshot);
      snapshot=undefined;
    }
    if (snapshot && !snapshotMatchesContract(snapshot,expectedDockerfile,resources)) {
      // The exact generation name is owned by this deployment contract. A
      // reused row whose image or resources cannot be inspected exactly is
      // unsafe, so delete only that owned row and recreate it.
      await deleteSnapshot(snapshot);
      snapshot=undefined;
    }
    if (!snapshot) snapshot=await daytona.snapshot.create(
      {name,image:buildImage,resources},
      {timeout:1800},
    );
    if (terminalStates.has(snapshot.state)) {
      await deleteSnapshot(snapshot);
      continue;
    }
    if (snapshot.state!=="active") await daytona.snapshot.activate(snapshot);
    for (let attempt=0; attempt<900; attempt+=1) {
      snapshot=(await daytona.snapshot.list(1,100)).items.find((row)=>row.name===name);
      if (!snapshot) throw new Error(`snapshot ${name} disappeared while activating`);
      if (snapshot.state==="active") break;
      if (terminalStates.has(snapshot.state)) break;
      await sleep(2000);
    }
    if (terminalStates.has(snapshot.state)) {
      await deleteSnapshot(snapshot);
      continue;
    }
    if (snapshot.state!=="active") throw new Error(`timed out waiting for active snapshot ${name}`);
    if (!snapshotMatchesContract(snapshot,expectedDockerfile,resources)) {
      await deleteSnapshot(snapshot);
      continue;
    }
    return snapshot;
  }
  throw new Error(`snapshot ${name} entered a terminal build state twice`);
}
const codingSnapshot=await ensureSnapshot(codingName,snapshotBuildImage,snapshotBuildDockerfile,codingResources);
const generalSnapshot=await ensureSnapshot(generalName,snapshotBuildImage,snapshotBuildDockerfile,generalResources);
list=await daytona.snapshot.list(1,100);
const deferredCleanup=list.items
  .filter((snapshot)=>
    !ownedNames.has(snapshot.name) &&
    [codingPrefix,generalPrefix].some((prefix)=>snapshot.name.startsWith(`${prefix}-`))
  )
  .map((snapshot)=>({id:snapshot.id,name:snapshot.name,state:snapshot.state}));
const snapshotRows=[["coding",codingSnapshot],["general",generalSnapshot]].map(([role,snapshot])=>({
  role,
  id:snapshot.id,name:snapshot.name,state:snapshot.state,
  // ref is the immutable source-carrier provenance. Daytona assigns a separate
  // internal registry ref to the build artifact.
  ref:sandboxImage,buildDockerfile:snapshotBuildProvenance(snapshot),
  cpu:snapshot.cpu,memoryGiB:snapshot.mem,diskGiB:snapshot.disk,
}));
const evidence={
  apiVersion:"micro-task-engine/v1alpha1",
  kind:"DaytonaHarnessSnapshots",
  status:"ready",
  generatedAt:new Date().toISOString(),
  producerSha256:process.env.MTE_EVIDENCE_PRODUCER_SHA256,
  canonicalSourceSha256:sha256(canonicalSource),
  controlPlane:{
    version:safe("MTE_DAYTONA_CONTROL_PLANE_VERSION"),
    sourceCommit:safe("MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT",/^[0-9a-f]{40}$/),
  },
  sandboxVersion:safe("MTE_DAYTONA_SANDBOX_VERSION"),
  snapshotContractHash,
  generation,
  sandboxImage,
  source:{url:sandboxImageSourceUrl,revision:sandboxImageRevision},
  snapshots:snapshotRows,
  deferredCleanup,
  resources,
  harnessVersions,
  credentialsBakedIntoImage:false,
};
const output="/evidence/daytona-images.json";
fs.writeFileSync(output+".tmp",JSON.stringify(evidence,null,2)+"\n",{mode:0o600});
fs.renameSync(output+".tmp",output);
console.log(JSON.stringify({status:"ready",snapshots:snapshotRows,sandboxImage}));
NODE
    python3 - "$ENV_FILE" "$EVIDENCE_ROOT/daytona-images.json" <<'PY'
from pathlib import Path
import hashlib
import json
import sys

path, evidence_path = map(Path, sys.argv[1:])
values = dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)
evidence = json.loads(evidence_path.read_text())
snapshots = {
    str(row.get("role")): row
    for row in evidence.get("snapshots") or []
    if isinstance(row, dict)
}
for role in ("coding", "general"):
    row = snapshots.get(role) or {}
    if row.get("state") != "active" or not row.get("name"):
        raise SystemExit(f"paperclip-daytona: {role} snapshot is not active")
values["MTE_DAYTONA_CODING_SNAPSHOT"] = snapshots["coding"]["name"]
values["MTE_DAYTONA_GENERAL_SNAPSHOT"] = snapshots["general"]["name"]
values["MTE_DAYTONA_CODING_SNAPSHOT_READY"] = "true"
values["MTE_DAYTONA_GENERAL_SNAPSHOT_READY"] = "true"
temporary = path.with_suffix(".tmp")
temporary.write_text("".join(f"{key}={values[key]}\n" for key in sorted(values)))
temporary.chmod(0o600)
temporary.replace(path)
canonical_sha = hashlib.sha256(path.read_bytes()).hexdigest()
evidence["canonicalSourceSha256"] = canonical_sha
evidence["pointerSwitch"] = {
    "coding": values["MTE_DAYTONA_CODING_SNAPSHOT"],
    "general": values["MTE_DAYTONA_GENERAL_SNAPSHOT"],
    "completed": True,
}
evidence_temporary = evidence_path.with_suffix(".tmp")
evidence_temporary.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
evidence_temporary.chmod(0o600)
evidence_temporary.replace(evidence_path)
PY
}

build_images() {
  "$PAPERCLIP_STEP" preflight
  [[ -n "$(env_value "$ENV_FILE" DAYTONA_API_KEY 2>/dev/null || true)" ]] \
    || die "DAYTONA_API_KEY is not provisioned"
  canonical_lock_run build_images_transaction_while_locked 300 \
    "timeout waiting for Daytona snapshot apply lock"
}

build_images_transaction_while_locked() {
  build_images_while_locked
  render_daytona_projection already-locked
  snapshot_runtime_config already-locked
}
lifecycle() {
  "$PAPERCLIP_STEP" preflight
  init_config
  [[ "$(env_value "$ENV_FILE" MTE_DAYTONA_CODING_SNAPSHOT_READY 2>/dev/null || true)" == "true" ]] \
    || die "coding snapshot is not ready"
  local paperclip_image daytona_network
  paperclip_image=$(env_value "$ENV_FILE" MTE_PAPERCLIP_IMAGE)
  daytona_network=$(env_value "$RUNTIME_ENV" MTE_DAYTONA_NETWORK)
  docker run --rm -i --network "$daytona_network" --user 0:0 \
    -e MTE_EVIDENCE_PRODUCER_SHA256="$PRODUCER_SHA256" \
    -e MTE_CANONICAL_SOURCE_SHA256="$(sha256sum "$ENV_FILE" | awk '{print $1}')" \
    -v "$RUNTIME_ENV:/run/secrets/platform.env:ro" \
    -v "$EVIDENCE_ROOT:/evidence" \
    "$paperclip_image" node --input-type=module <<'NODE'
import fs from "node:fs";

const source=fs.readFileSync("/run/secrets/platform.env","utf8");
const values=Object.fromEntries(source.split(/\n/).filter((line)=>line.includes("=")).map((line)=>{
  const index=line.indexOf("="); return [line.slice(0,index),line.slice(index+1)];
}));
const canonicalSourceSha256=String(process.env.MTE_CANONICAL_SOURCE_SHA256||"");
if (!/^[0-9a-f]{64}$/.test(canonicalSourceSha256)) throw new Error("missing canonical source hash");
const {Daytona}=await import("@daytonaio/sdk");
// Self-hosted Daytona resolves an omitted SDK target through the organization's
// configured default region.  Passing the region explicitly bypasses that
// default-resolution path in the current control plane and rejects an otherwise
// healthy runner, so keep the region declarative at organization/snapshot level.
const daytona=new Daytona({apiKey:values.DAYTONA_API_KEY,apiUrl:values.MTE_DAYTONA_INTERNAL_API_URL});
const proxyPort=String(values.MTE_DAYTONA_PROXY_INTERNAL_PORT||"");
if (!/^\d{2,5}$/.test(proxyPort)) throw new Error("invalid internal Daytona proxy port");
const internalToolboxProxyUrl=`http://proxy:${proxyPort}/toolbox`;
const useInternalToolboxProxy=(targetSandbox)=>{
  const baseUrl=`${internalToolboxProxyUrl}/${targetSandbox.id}`;
  targetSandbox.toolboxProxyUrl=internalToolboxProxyUrl;
  targetSandbox.axiosInstance.defaults.baseURL=baseUrl;
  targetSandbox.clientConfig.basePath=baseUrl;
};
const labels={"mte.canary":"paperclip-daytona"};
for (const stale of (await daytona.list(labels,1,100)).items) await daytona.delete(stale);
let sandbox;
let deleted=false;
const states=[];
try {
  sandbox=await daytona.create({
    name:`mte-paperclip-canary-${Date.now()}`,
    snapshot:values.MTE_DAYTONA_CODING_SNAPSHOT,
    language:"typescript",
    labels,
    autoStopInterval:15,
    autoArchiveInterval:60,
  },{timeout:900});
  useInternalToolboxProxy(sandbox);
  states.push({phase:"create",state:"started",at:new Date().toISOString()});
  const probeScript=`
    const cp=require("node:child_process"),fs=require("node:fs");
    const exec=(command)=>cp.execFileSync("/bin/sh",["-c",command],{encoding:"utf8"}).trim();
    const harnesses=["codex","claude","pi"].map((name)=>({
      name,
      commandPath:exec("command -v "+name),
      realpath:exec("readlink -f $(command -v "+name+")"),
      versionOutput:exec(name+" --version"),
    }));
    const checkedPaths=[
      "/home/daytona/.codex/auth.json",
      "/home/daytona/.claude/.credentials.json",
      "/home/daytona/.pi/agent/auth.json",
      "/home/daytona/.config/gh/hosts.yml",
    ];
    const checkedEnvNames=["OPENAI_API_KEY","ANTHROPIC_API_KEY","GH_TOKEN","CONTEXT7_API_KEY","MTE_TOOLHIVE_BEARER_TOKEN"];
    console.log(JSON.stringify({
      cwd:process.cwd(),harnesses,
      credentialFileProbe:{checkedPaths,foundPaths:checkedPaths.filter(fs.existsSync)},
      credentialEnvProbe:{checkedNames:checkedEnvNames,foundNames:checkedEnvNames.filter((name)=>Boolean(process.env[name]))},
    }));`;
  const command=`printf '%s' '${Buffer.from(probeScript).toString("base64")}' | base64 -d | node`;
  const result=await sandbox.process.executeCommand(
    command,"/home/daytona/paperclip-workspace",undefined,120,
  );
  if (result.exitCode!==0) throw new Error(`sandbox smoke failed: ${result.result}`);
  const probe=JSON.parse(String(result.result||"").trim());
  if (probe.cwd!=="/home/daytona/paperclip-workspace") throw new Error("provider workspace cwd drifted");
  const expectedVersions={codex:values.MTE_CODEX_VERSION,claude:values.MTE_CLAUDE_CODE_VERSION,pi:values.MTE_PI_VERSION};
  const versionPatterns={
    codex:/^(?:codex(?:-cli)?\s+)?v?([0-9]+\.[0-9]+\.[0-9]+)$/,
    claude:/^(?:claude\s+)?v?([0-9]+\.[0-9]+\.[0-9]+)(?: \(Claude Code\))?$/,
    pi:/^(?:pi\s+)?v?([0-9]+\.[0-9]+\.[0-9]+)$/,
  };
  const normalizedVersion=(name,output)=>String(output||"").trim().match(versionPatterns[name])?.[1];
  for (const harness of probe.harnesses) {
    if (!harness.realpath.startsWith("/opt/mte-harness/node_modules/")) throw new Error(`${harness.name} is not from locked npm closure`);
    if (normalizedVersion(harness.name,harness.versionOutput)!==expectedVersions[harness.name]) throw new Error(`${harness.name} version drifted`);
  }
  if (probe.credentialFileProbe.foundPaths.length || probe.credentialEnvProbe.foundNames.length) throw new Error("sandbox snapshot contains credentials");
  states.push({phase:"execute",state:"passed",at:new Date().toISOString()});
  const expectedResources={cpu:Number(values.MTE_DAYTONA_CODING_CPU),memory:Number(values.MTE_DAYTONA_CODING_MEMORY_GIB),disk:Number(values.MTE_DAYTONA_DISK_GIB)};
  const actualResources={cpu:Number(sandbox.cpu),memory:Number(sandbox.memory),disk:Number(sandbox.disk)};
  if (JSON.stringify(expectedResources)!==JSON.stringify(actualResources)) throw new Error("sandbox resources drifted");
  const evidence={
    apiVersion:"micro-task-engine/v1alpha1",
    kind:"DaytonaSandboxLifecycleEvidence",
    status:"ready",
    generatedAt:new Date().toISOString(),
    producerSha256:process.env.MTE_EVIDENCE_PRODUCER_SHA256,
    canonicalSourceSha256,
    provider:"daytona",
    controlPlane:{
      version:values.MTE_DAYTONA_CONTROL_PLANE_VERSION,
      sourceCommit:values.MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT,
    },
    sandboxVersion:values.MTE_DAYTONA_SANDBOX_VERSION,
    target:values.DAYTONA_TARGET,
    snapshot:values.MTE_DAYTONA_CODING_SNAPSHOT,
    sandboxId:sandbox.id,
    workspace:"/home/daytona/paperclip-workspace",
    harnesses:probe.harnesses,
    credentialFileProbe:{...probe.credentialFileProbe,credentialFree:true},
    credentialEnvProbe:{...probe.credentialEnvProbe,credentialFree:true},
    resources:{expected:expectedResources,actual:actualResources,equal:true},
    credentialsBakedIntoImage:false,
    states,
  };
  const path="/evidence/daytona-lifecycle.json";
  fs.writeFileSync(path+".tmp",JSON.stringify(evidence,null,2)+"\n",{mode:0o600});
  fs.renameSync(path+".tmp",path);
} finally {
  if (sandbox) {
    await daytona.delete(sandbox);
    deleted=true;
  }
}
if (!deleted) throw new Error("sandbox cleanup did not complete");
let getAfterDeleteStatus=0;
for (let attempt=0; attempt<90; attempt+=1) {
  try { await daytona.get(sandbox.id); }
  catch (error) {
    const status=Number(error?.status||error?.statusCode||error?.response?.status||0);
    if (status===404 || /(?:^|\D)404(?:\D|$)/.test(String(error?.message||error))) { getAfterDeleteStatus=404; break; }
    throw error;
  }
  await new Promise((resolve)=>setTimeout(resolve,2000));
}
if (getAfterDeleteStatus!==404) throw new Error("sandbox still exists after delete");
const path="/evidence/daytona-lifecycle.json";
const evidence=JSON.parse(fs.readFileSync(path,"utf8"));
evidence.states.push({phase:"delete",state:"deleted",at:new Date().toISOString()});
evidence.cleanupDeleted=true;
evidence.delete={requested:true,getAfterDeleteStatus};
fs.writeFileSync(path+".tmp",JSON.stringify(evidence,null,2)+"\n",{mode:0o600});
fs.renameSync(path+".tmp",path);
console.log(JSON.stringify({status:"ready",sandboxId:evidence.sandboxId,cleanupDeleted:true}));
NODE
}

status() {
  compose ps --format json
  [[ -s $EVIDENCE ]] && cat "$EVIDENCE" || true
}

verify() {
  local api_port paperclip_api canonical_sha running
  api_port=$(env_value "$ENV_FILE" MTE_DAYTONA_API_PORT)
  paperclip_api=$(env_value "$ENV_FILE" MTE_PAPERCLIP_API_BASE)
  wait_url "http://127.0.0.1:${api_port}/api/config"
  wait_url "${paperclip_api}/health"
  running=$(compose ps --status running --services | sort | tr '\n' ' ')
  for service in db redis registry minio dex runner agent-gateway api proxy ssh-gateway; do
    [[ " $running " == *" $service "* ]] || die "Daytona service is not running: $service"
  done
  canonical_sha=$(sha256sum "$ENV_FILE" | awk '{print $1}')
  python3 - "$ENV_FILE" "$EVIDENCE_ROOT/daytona-images.json" "$EVIDENCE_ROOT/daytona-lifecycle.json" "$EVIDENCE" "$canonical_sha" "$PRODUCER_SHA256" "$running" <<'PY'
from pathlib import Path
import datetime
import json
import sys

env_path, images_path, lifecycle_path, output = map(Path, sys.argv[1:5])
canonical_sha, producer_sha, running = sys.argv[5:]
values = dict(
    line.split("=", 1)
    for line in env_path.read_text().splitlines()
    if "=" in line
)
expected_control_plane = {
    "version": values["MTE_DAYTONA_CONTROL_PLANE_VERSION"],
    "sourceCommit": values["MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT"],
}
for path, kind in (
    (images_path, "DaytonaHarnessSnapshots"),
    (lifecycle_path, "DaytonaSandboxLifecycleEvidence"),
):
    document = json.loads(path.read_text())
    if document.get("kind") != kind or document.get("status") != "ready":
        raise SystemExit(f"paperclip-daytona: invalid {path.name}")
    if document.get("canonicalSourceSha256") != canonical_sha:
        raise SystemExit(f"paperclip-daytona: stale {path.name}")
    if document.get("controlPlane") != expected_control_plane:
        raise SystemExit(f"paperclip-daytona: control-plane provenance drifted in {path.name}")
    if document.get("sandboxVersion") != values["MTE_DAYTONA_SANDBOX_VERSION"]:
        raise SystemExit(f"paperclip-daytona: sandbox version drifted in {path.name}")
payload = {
    "apiVersion": "micro-task-engine/v1alpha1",
    "kind": "PaperclipDaytonaControlPlaneEvidence",
    "status": "ready",
    "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "producerSha256": producer_sha,
    "canonicalSourceSha256": canonical_sha,
    "controlPlane": expected_control_plane,
    "sandboxVersion": values["MTE_DAYTONA_SANDBOX_VERSION"],
    "composeServices": running.split(),
    "runtimeEvidence": {
        "images": str(images_path),
        "lifecycle": str(lifecycle_path),
    },
    "secretValuesPrinted": False,
}
temporary = output.with_suffix(".tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.chmod(0o600)
temporary.replace(output)
print(json.dumps({"status": "ready", "composeServices": payload["composeServices"]}))
PY
}

remove() {
  # Compose down is already idempotent when the project is absent. Any other
  # failure must abort decommission instead of reporting a false success.
  compose down || die "container removal failed"
  log "containers removed; data preserved"
}
acceptance() { build_images; lifecycle; verify; }
all() {
  install_daytona
  provision_key
}

case $ACTION in
preflight) preflight;; install) install_daytona;; provision-key) provision_key;; set-target) set_target;; verify) verify;; status) status;;
images) build_images;;
lifecycle) lifecycle;;
acceptance) acceptance;;
remove) remove;; all) all;;
*) die "usage: daytona.sh preflight|install|provision-key|set-target|images|lifecycle|acceptance|verify|status|remove|all";;
esac

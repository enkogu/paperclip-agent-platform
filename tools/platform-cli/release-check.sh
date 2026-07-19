#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL_ROOT="$ROOT/tools/platform-cli"
PYTHON=python3
CHECK_TIMEOUT="300"
LOCAL_VERIFY_TIMEOUT="300"
LOCKED_INSTALL_COMMAND="python3 -m pip install --require-hashes --only-binary=:all: --requirement $TOOL_ROOT/requirements-release-check.txt"
gitleaks_version="$(awk -F '"' '/^[[:space:]]*GITLEAKS_VERSION:/{print $2; exit}' \
  "$ROOT/.github/workflows/ci.yml")"

cd "$ROOT"

section() {
  printf '\n==> %s\n' "$1"
}

section "Release tree completeness"
if [[ "$(git rev-parse --is-inside-work-tree 2>/dev/null || true)" != "true" ]]; then
  printf '%s\n' "release-check: must run from a Git worktree" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  printf '%s\n' "release-check: a clean, index-complete release worktree is required" >&2
  exit 1
fi
if ! git diff --quiet --ignore-submodules --; then
  printf '%s\n' "release-check: unstaged source changes are not a release tree" >&2
  exit 1
fi
if ! git diff --cached --quiet --ignore-submodules --; then
  printf '%s\n' "release-check: staged source changes are not a release tree" >&2
  exit 1
fi
HEAD_TREE="$(git rev-parse --verify 'HEAD^{tree}' 2>/dev/null || true)"
INDEX_TREE="$(git write-tree 2>/dev/null || true)"
if [[ -z "$HEAD_TREE" || -z "$INDEX_TREE" || "$HEAD_TREE" != "$INDEX_TREE" ]]; then
  printf '%s\n' "release-check: index must exactly match the checked-out release commit" >&2
  exit 1
fi

section "Python dependency preflight"
if ! command -v "$PYTHON" >/dev/null 2>&1 || ! command -v ruff >/dev/null 2>&1; then
  printf '%s\n' \
    'release-check: Python 3.11+ and the locked Python dependencies are required.' \
    'release-check: install them for python3 with:' \
    "  $LOCKED_INSTALL_COMMAND" \
  >&2
  exit 1
fi

if ! "$PYTHON" - "$TOOL_ROOT/requirements-release-check.txt" "$LOCKED_INSTALL_COMMAND" <<'PY'
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import re
import sys


REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+)==(?P<version>[^\s;\\]+)"
    r"(?:\s*;\s*(?P<marker>.*?))?\s*(?:\\)?$"
)


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def marker_applies(marker: str | None) -> bool:
    # The universal lock currently uses only the platform marker below.  An
    # unrecognised marker is treated as applicable so a new locked dependency
    # cannot silently escape this preflight.
    if marker is None:
        return True
    return marker.strip() != "sys_platform == 'win32'" or sys.platform == "win32"


mismatches: list[str] = []
for line in Path(sys.argv[1]).read_text().splitlines():
    if not line or line[0].isspace() or line.startswith("#"):
        continue
    match = REQUIREMENT.match(line)
    if match is None:
        continue
    if not marker_applies(match.group("marker")):
        continue
    name = match.group("name")
    expected = match.group("version")
    try:
        installed = version(name)
    except PackageNotFoundError:
        installed = "not installed"
    if installed != expected:
        mismatches.append(
            f"  {normalized(name)}: expected {expected}, installed {installed}"
        )

if sys.version_info < (3, 11):
    mismatches.insert(0, "  python: expected 3.11+, installed " + sys.version.split()[0])

if mismatches:
    print(
        "release-check: installed distributions do not exactly match "
        "requirements-release-check.txt:",
        *mismatches,
        "release-check: installed metadata cannot attest wheel hashes; install "
        "the exact hash-locked artifacts with:",
        "  " + sys.argv[2],
        sep="\n",
        file=sys.stderr,
    )
    raise SystemExit(1)
PY
then
  exit 1
fi

if ! "$PYTHON" -c \
  'import sys, pytest, yaml; raise SystemExit(sys.version_info < (3, 11))' \
  >/dev/null 2>&1; then
  printf '%s\n' \
    'release-check: Python 3.11+ and the locked Python dependencies are required.' \
    'release-check: install them for python3 with:' \
    "  $LOCKED_INSTALL_COMMAND" \
  >&2
  exit 1
fi

run_bounded() {
  local seconds="$1"
  shift
  "$PYTHON" -c '
import os
import signal
import subprocess
import sys

timeout = float(sys.argv[1])
command = sys.argv[2:]
if not command:
    raise SystemExit("run_bounded requires a command")

process = subprocess.Popen(command, start_new_session=True)
try:
    raise SystemExit(process.wait(timeout=timeout))
except subprocess.TimeoutExpired:
    print(
        "release-check: timed out after {:g}s: {}".format(
            timeout, " ".join(command)
        ),
        file=sys.stderr,
    )
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    raise SystemExit(124)
' "$seconds" "$@"
}

run_bounded 30 "$PYTHON" -m pip check

section "Patch hygiene"
run_bounded 30 git diff --check
run_bounded 30 git diff --cached --check

section "Pinned tracked-source secret scan"
if [[ "${MTE_RELEASE_SECRET_SCAN:-}" == "ci-action" && "${CI:-}" == "true" ]]; then
  printf '%s\n' "release-check: source scan completed by the pinned CI action"
elif ! command -v gitleaks >/dev/null 2>&1; then
  printf '%s\n' "release-check: gitleaks $gitleaks_version is required" >&2
  exit 1
elif [[ "$(gitleaks version)" != "$gitleaks_version" ]]; then
  printf '%s\n' "release-check: expected gitleaks $gitleaks_version" >&2
  exit 1
else
  SOURCE_SNAPSHOT="$(mktemp -d "${TMPDIR:-/tmp}/paperclip-release-check-source.XXXXXX")"
  cleanup_source_snapshot() {
    rm -rf "$SOURCE_SNAPSHOT"
  }
  trap cleanup_source_snapshot EXIT
  run_bounded 30 bash -c 'git archive --format=tar "$(git write-tree)" | tar -xf - -C "$1"' _ "$SOURCE_SNAPSHOT"
  run_bounded 45 gitleaks detect \
    --config "$ROOT/.gitleaks.toml" \
    --no-git \
    --source "$SOURCE_SNAPSHOT" \
    --redact=100 \
    --no-banner \
    --no-color \
    --log-level warn \
    --timeout 30 \
    --max-target-megabytes 2
fi

section "Runtime evidence redaction audit"
run_bounded 60 "$PYTHON" -m pytest \
  -c "$TOOL_ROOT/pyproject.toml" -q \
  tests/test_server_secrets.py::SecretAuditTests::test_sensitive_value_match_fails_without_printing_value \
  tests/test_server_provision.py::PaperclipDeclarativeBindingTests::test_verify_evidence_is_redacted_and_mode_0600 \
  tests/test_server_e2e_canary.py::ServerE2ECanaryTests::test_portable_bundle_embeds_redacted_documents_and_hashes

section "Python tests"
PYTEST_PATH="$PATH"
if [[ "$(uname -s)" == "Darwin" ]]; then
  # Homebrew Bash 5.3 can deadlock while preparing here-documents on macOS.
  # Keep the caller's PATH intact, but prefer Apple's system shell for test
  # subprocesses that resolve `bash` through /usr/bin/env.
  PYTEST_PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PYTEST_PATH"
fi
run_bounded "$CHECK_TIMEOUT" env PATH="$PYTEST_PATH" "$PYTHON" -m pytest \
  -c "$TOOL_ROOT/pyproject.toml" -q tests

section "Python lint"
run_bounded 120 ruff check \
  --config "$TOOL_ROOT/pyproject.toml" .

section "Pinned dependency contract"
run_bounded 120 "$PYTHON" tools/platform-cli/validate-dependencies.py \
  --source-contract-only

section "Shell syntax"
shell_files=("platform")
while IFS= read -r -d '' file; do
  shell_files+=("$file")
done < <(
  find deployment/steps tools/platform-cli \
    -type f -name '*.sh' -print0 2>/dev/null
)
run_bounded 90 bash -n "${shell_files[@]}"

section "Docker Compose availability"
run_bounded 20 docker compose version

section "Offline local reproducibility checks"
run_bounded "$LOCAL_VERIFY_TIMEOUT" "$PYTHON" -c '
from pathlib import Path
import importlib.util
import json

root = Path.cwd()
spec = importlib.util.spec_from_file_location(
    "release_local_verify", root / "tools/platform-cli/local-verify.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
documents, yaml_findings = module.yaml_documents()
fresh_install = module.fresh_install_render()
checks = [
    module.record(
        "yaml-parse",
        not yaml_findings,
        files=len(documents),
        findings=yaml_findings,
    ),
    module.platform_consistency(documents),
    module.compose_static(documents),
    module.configuration_source_static(),
    module.release_check_fresh_install_contract(fresh_install),
    module.acceptance_requirement_coverage(),
    module.profile_coverage(),
    module.local_capacity(),
    module.docker_compose_check(),
]
result = {
    "kind": "OfflineReleaseChecks",
    "ok": all(check.get("ok") is True for check in checks),
    "checks": checks,
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if result["ok"] else 1)
'

printf '\nrelease-check: PASS\n'

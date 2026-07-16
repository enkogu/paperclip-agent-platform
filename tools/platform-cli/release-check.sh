#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL_ROOT="$ROOT/tools/platform-cli"
RUNTIME_DIR="$ROOT/.runtime/release-check"
VENV_DIR="$ROOT/.venv"
HOST_PYTHON="python3"
INSTALL_TIMEOUT="300"
CHECK_TIMEOUT="300"
LOCAL_VERIFY_TIMEOUT="300"

cd "$ROOT"
mkdir -p "$RUNTIME_DIR"

run_bounded() {
  local seconds="$1"
  shift
  "$HOST_PYTHON" - "$seconds" "$@" <<'PY'
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
        f"release-check: timed out after {timeout:g}s: {' '.join(command)}",
        file=sys.stderr,
    )
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    raise SystemExit(124)
PY
}

section() {
  printf '\n==> %s\n' "$1"
}

section "Create isolated Python environment"
if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  run_bounded 60 "$HOST_PYTHON" -m venv "$VENV_DIR"
fi
run_bounded "$INSTALL_TIMEOUT" \
  "$VENV_DIR/bin/python" -m pip install --disable-pip-version-check 'pip==26.0'
run_bounded "$INSTALL_TIMEOUT" \
  "$VENV_DIR/bin/python" -m pip install --disable-pip-version-check \
  --group "$TOOL_ROOT/pyproject.toml:release-check"
PYTHON="$VENV_DIR/bin/python"

section "Python tests"
run_bounded "$CHECK_TIMEOUT" "$PYTHON" -m pytest \
  -c "$TOOL_ROOT/pyproject.toml" -q tests

section "Python lint"
run_bounded 120 "$PYTHON" -m ruff check \
  --config "$TOOL_ROOT/pyproject.toml" .

section "Pinned dependency contract"
run_bounded 120 "$PYTHON" tools/platform-cli/validate-dependencies.py

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
LOCAL_CHECK_RUNNER="$RUNTIME_DIR/offline-local-checks.py"
"$PYTHON" - "$LOCAL_CHECK_RUNNER" <<'PY'
from pathlib import Path
import json
import importlib.util
import sys

path = Path(sys.argv[1])
path.write_text(
    '''from pathlib import Path
import importlib.util
import json

root = Path.cwd()
spec = importlib.util.spec_from_file_location(
    "release_local_verify", root / "tools/platform-cli/local-verify.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
documents, yaml_findings = module.yaml_documents()
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
    module.fresh_install_render(),
    module.connection_coverage(),
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
'''
)
PY
run_bounded "$LOCAL_VERIFY_TIMEOUT" \
  "$PYTHON" "$LOCAL_CHECK_RUNNER"

printf '\nrelease-check: PASS\n'

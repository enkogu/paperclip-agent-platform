#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON=python3

usage() {
  cat <<'EOF'
Usage: ./deployment/scripts/verify.sh [component]
       ./test.sh quick
       ./test.sh smoke [component]
       ./test.sh e2e [kestra]

quick is offline. smoke and e2e contact the configured live host.
The Kestra E2E canary atomically exercises every configured native harness.
EOF
}

fail() {
  printf 'test: %s\n' "$*" >&2
  exit 2
}

section() {
  printf '\n==> %s\n' "$1"
}

require_no_extra_args() {
  (( $# == 0 )) || fail "unexpected argument: $1"
}

run_quick() {
  local -a shell_files

  require_no_extra_args "$@"
  cd "$ROOT"
  if ! command -v "$PYTHON" >/dev/null 2>&1 || \
    ! "$PYTHON" -c \
      'import sys, pytest, yaml; raise SystemExit(sys.version_info < (3, 11))' \
      >/dev/null 2>&1; then
    printf '%s\n' \
      'quick: Python 3.11+ and the locked Python dependencies are required.' \
      'quick: install them for python3 with:' \
      "  python3 -m pip install --require-hashes --only-binary=:all: --requirement $ROOT/tools/platform-cli/requirements-release-check.txt" \
      >&2
    exit 1
  fi

  section "Shell syntax"
  shell_files=(platform install.sh test.sh)
  while IFS= read -r -d '' file; do
    shell_files+=("$file")
  done < <(
    find deployment/scripts -type f -name '*.sh' -print0
  )
  while IFS= read -r -d '' file; do
    shell_files+=("$file")
  done < <(
    find deployment/steps tools/platform-cli -type f -name '*.sh' -print0
  )
  bash -n "${shell_files[@]}"

  if command -v shellcheck >/dev/null 2>&1; then
    section "Shell lint"
    shellcheck --severity=warning "${shell_files[@]}"
  else
    printf 'quick: shellcheck not installed; syntax check completed\n' >&2
  fi

  section "Offline configuration contracts"
  "$PYTHON" -c '
from pathlib import Path
import importlib.util
import json

root = Path.cwd()
spec = importlib.util.spec_from_file_location(
    "quick_local_verify", root / "tools/platform-cli/local-verify.py"
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
    module.acceptance_requirement_coverage(),
    module.profile_coverage(),
]
result = {
    "ok": all(row.get("ok") is True for row in checks),
    "checks": [
        {
            "name": row.get("name"),
            "ok": row.get("ok") is True,
            **({"findings": row.get("findings", [])} if row.get("ok") is not True else {}),
        }
        for row in checks
    ],
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if result["ok"] else 1)
'

  section "Focused unit tests"
  "$PYTHON" -m pytest -c tools/platform-cli/pyproject.toml -q \
    tests/test_test_modes.py \
    tests/test_dependency_contract.py

  printf '\nquick: PASS (offline; no live host checks were run)\n'
}

run_smoke() {
  local component="${1:-}"
  (( $# <= 1 )) || fail "smoke accepts at most one component"
  cd "$ROOT"
  section "Live smoke verification${component:+: $component}"
  if [[ -n "$component" ]]; then
    "$ROOT/platform" verify "$component"
  else
    "$ROOT/platform" verify
  fi
  printf '\nsmoke: PASS (live verifier completed; full E2E was not run)\n'
}

validate_e2e_harness() {
  local harness="${1:-kestra}"
  [[ "$harness" == "kestra" ]] || fail \
    "unsupported E2E harness '$harness'; the current canary entrypoint is 'kestra' and covers codex, claude, and pi atomically"
}

run_e2e() {
  local harness="${1:-kestra}"
  (( $# <= 1 )) || fail "e2e accepts at most one harness"
  validate_e2e_harness "$harness"
  cd "$ROOT"
  # The canary deliberately rejects stale Daytona proof. Refresh the managed
  # runtime through its idempotent lifecycle before producing new E2E evidence;
  # do not bypass that guard or hand-edit its evidence.
  section "Refresh Daytona runtime evidence"
  "$ROOT/platform" daytona apply
  "$ROOT/platform" daytona verify
  section "Live Kestra E2E canary producer"
  "$ROOT/platform" kestra-canary apply
  section "Live Kestra E2E evidence verification"
  "$ROOT/platform" kestra-canary verify
  printf '\ne2e: PASS (fresh live canary evidence produced and verified)\n'
}

run_release_acceptance() {
  local component="${1:-}"
  (( $# <= 1 )) || fail "release verification accepts at most one component"
  cd "$ROOT"
  if [[ -n "$component" ]]; then
    section "Live component acceptance: $component"
    "$ROOT/platform" verify "$component"
    return
  fi

  section "Post-Cloudflare canonical evidence rebind"
  "$ROOT/platform" evidence-rebind
  section "Cloudflare external acceptance"
  "$ROOT/platform" cloudflare acceptance
  section "Release evidence acceptance"
  "$ROOT/platform" acceptance check
  "$ROOT/platform" verify --all
  printf '\nverify: PASS (full live acceptance completed)\n'
}

mode="${1:-}"
if [[ -z "$mode" ]]; then
  run_release_acceptance
  exit 0
fi
shift

case "$mode" in
  quick) run_quick "$@" ;;
  smoke) run_smoke "$@" ;;
  e2e) run_e2e "$@" ;;
  -h|--help|help) usage ;;
  *) run_release_acceptance "$mode" "$@" ;;
esac

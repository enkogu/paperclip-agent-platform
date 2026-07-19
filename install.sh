#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS="$ROOT/deployment/scripts"
STAGES=(preflight host compose provision cloudflare verify)

usage() {
  cat <<'EOF'
Usage: ./install.sh [step [argument ...]]

Install steps: preflight, host, compose, provision, cloudflare, verify, all
Recovery steps:
  backup BACKUP_ID
  restore BACKUP_ID --confirm-restore
  decommission --confirm-decommission

With no step, runs every step in the order shown above.
Components are accepted only by compose, provision, and verify.
Recovery steps are never included in all.
EOF
}

fail() {
  echo "install: $*" >&2
  exit 1
}

step=${1:-all}
(( $# == 0 )) || shift
args=("$@")

case "$step" in
  -h|--help|help)
    usage
    exit 0
    ;;
  all|preflight|host|compose|provision|cloudflare|verify|backup|restore|decommission) ;;
  *) fail "unknown step: $step" ;;
esac

if (( ${#args[@]} )); then
  case "$step" in
    compose|provision|verify)
      (( ${#args[@]} == 1 )) || fail "$step accepts at most one component"
      ;;
    backup|restore|decommission) ;;
    *) fail "the $step step does not accept a component" ;;
  esac
fi
if [[ $step == all && ${#args[@]} -ne 0 ]]; then
  fail "all does not accept arguments"
fi

: "${MTE_OPERATOR_ENV:=$ROOT/config/platform.env}"
export MTE_OPERATOR_ENV

run_stage() {
  local stage=$1 script="$SCRIPTS/$1.sh"
  shift
  [[ -x $script ]] || fail "stage is unavailable or not executable: $stage"
  echo "==> $stage"
  "$script" "$@"
}

if [[ $step == all ]]; then
  for stage in "${STAGES[@]}"; do
    run_stage "$stage"
  done
else
  run_stage "$step" "${args[@]}"
fi

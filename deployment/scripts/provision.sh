#!/usr/bin/env bash
# Operator-side, stateless post-health provisioning index. The existing
# platform CLI owns atomic sync, SSH transport, canonical secret handling, API
# reconciliation, and Daytona lifecycle sequencing.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
SOURCE_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
readonly SOURCE_ROOT
readonly PLATFORM_CLI="${MTE_PLATFORM_CLI:-${SOURCE_ROOT}/platform}"
readonly COMPOSE_RECONCILER="${MTE_COMPOSE_RECONCILER:-${SOURCE_ROOT}/deployment/scripts/compose.sh}"

readonly -a ORDERED_GROUPS=(
  paperclip
  kestra
  toolhive-profiles
  mattermost-hermes
  notion-postgres
  daytona-harness-auth
)

declare -a PLATFORM_GLOBAL_ARGS=()
base_provisioned=0

usage() {
  cat <<'EOF'
usage: provision.sh [--domain DOMAIN] [all|GROUP]

Secrets are accepted only through MTE_OPERATOR_ENV and the server-side
canonical platform.env. Secret values are never command-line arguments.

Groups (ordered):
  paperclip
  kestra
  toolhive-profiles       (alias: toolhive/profiles)
  mattermost-hermes       (alias: mattermost/hermes)
  notion-postgres         (alias: notion/postgres)
  daytona-harness-auth    (alias: daytona/harness-auth)
EOF
}

platform() {
  [[ -x "${PLATFORM_CLI}" ]] || {
    printf 'provision: platform CLI is not executable: %s\n' "${PLATFORM_CLI}" >&2
    return 1
  }
  printf 'provision: run platform' >&2
  if (( ${#PLATFORM_GLOBAL_ARGS[@]} )); then
    printf ' %q' "${PLATFORM_GLOBAL_ARGS[@]}" >&2
  fi
  printf ' %q' "$@" >&2
  printf '\n' >&2
  if (( ${#PLATFORM_GLOBAL_ARGS[@]} )); then
    "${PLATFORM_CLI}" "${PLATFORM_GLOBAL_ARGS[@]}" "$@"
  else
    "${PLATFORM_CLI}" "$@"
  fi
}

prepare_remote() {
  # `platform config render` performs the governed atomic source sync before
  # invoking the remote renderer. Audit then verifies the canonical result.
  platform config render
  platform config audit
}

ensure_base_provisioned() {
  if (( base_provisioned == 0 )); then
    platform provision apply
    # PostgREST is intentionally deferred from the bootstrap Compose stage:
    # its authenticator role is created by the preceding canonical provision.
    "${COMPOSE_RECONCILER}" postgrest
    "${COMPOSE_RECONCILER}" observability
    base_provisioned=1
  fi
}

run_group() {
  local group="$1"
  printf 'provision: group %s\n' "${group}" >&2
  case "${group}" in
    paperclip)
      platform runtime paperclip preflight
      platform runtime paperclip config-migrate
      platform runtime paperclip install
      platform profiles apply
      platform paperclip-environments apply
      platform paperclip-secrets apply
      ensure_base_provisioned
      ;;
    kestra)
      ensure_base_provisioned
      # The Paperclip group issues the board service key after the bootstrap
      # Compose pass. Reconcile Kestra now so the key reaches only its runtime
      # environment before any private Paperclip flow is deployed.
      "${COMPOSE_RECONCILER}" kestra
      platform kestra-control provision
      ;;
    toolhive-profiles)
      ensure_base_provisioned
      platform tools provision
      ;;
    mattermost-hermes)
      ensure_base_provisioned
      platform hermes install
      ;;
    notion-postgres)
      # `platform provision apply` owns PostgreSQL/Notion API resource creation
      # and its fill-only canonical merge, including projection reconciliation.
      ensure_base_provisioned
      ;;
    daytona-harness-auth)
      ensure_base_provisioned
      # This command owns install/provision-key/set-target, plugin reconciliation,
      # snapshot acceptance, probes, and the final private Paperclip verify.
      platform daytona apply
      platform harness-auth verify
      ;;
    *)
      printf 'provision: unknown group: %s\n' "${group}" >&2
      usage >&2
      return 2
      ;;
  esac
}

normalize_group() {
  case "$1" in
    toolhive/profiles) printf '%s\n' toolhive-profiles ;;
    mattermost/hermes) printf '%s\n' mattermost-hermes ;;
    notion/postgres) printf '%s\n' notion-postgres ;;
    daytona/harness-auth) printf '%s\n' daytona-harness-auth ;;
    *) printf '%s\n' "$1" ;;
  esac
}

known_group() {
  local candidate="$1"
  local group
  for group in "${ORDERED_GROUPS[@]}"; do
    [[ "${candidate}" == "${group}" ]] && return 0
  done
  return 1
}

main() {
  local selected=all
  local selected_set=0
  local domain=""
  while (( $# )); do
    case "$1" in
      --domain)
        (( $# >= 2 )) || { usage >&2; return 2; }
        domain="$2"
        shift 2
        ;;
      -h|--help)
        usage
        return 0
        ;;
      -* )
        usage >&2
        return 2
        ;;
      *)
        (( selected_set == 0 )) || { usage >&2; return 2; }
        selected="$(normalize_group "$1")"
        selected_set=1
        shift
        ;;
    esac
  done

  if [[ -n "${domain}" ]]; then
    PLATFORM_GLOBAL_ARGS=(--domain "${domain}")
  fi

  if [[ "${selected}" != all ]] && ! known_group "${selected}"; then
    printf 'provision: unknown group: %s\n' "${selected}" >&2
    usage >&2
    return 2
  fi

  prepare_remote
  if [[ "${selected}" == all ]]; then
    local group
    for group in "${ORDERED_GROUPS[@]}"; do
      run_group "${group}"
    done
  else
    run_group "${selected}"
  fi
}

main "$@"

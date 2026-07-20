#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
component=${1:-}
[[ $# -le 1 ]] || { echo "compose: expected at most one component" >&2; exit 1; }

: "${MTE_OPERATOR_ENV:=$ROOT/config/platform.env}"
export MTE_OPERATOR_ENV

[[ -f $MTE_OPERATOR_ENV ]] \
  || { echo "compose: operator env not found: $MTE_OPERATOR_ENV" >&2; exit 1; }

env_value() {
  local key=$1
  awk -F= -v key="$key" '
    $0 !~ /^[[:space:]]*#/ && $1 == key {
      count++
      value = substr($0, index($0, "=") + 1)
    }
    END {
      if (count != 1 || value == "") exit 1
      print value
    }
  ' "$MTE_OPERATOR_ENV"
}

target=$(env_value MTE_SSH_TARGET) \
  || { echo "compose: MTE_SSH_TARGET must occur exactly once" >&2; exit 1; }
platform_root=$(env_value MTE_PLATFORM_ROOT 2>/dev/null || printf '%s\n' /opt/mte-platform)
secrets_root=$(env_value MTE_SECRETS_ROOT 2>/dev/null || printf '%s\n' /root/.config/mte-secrets)

services=()
post_up_action=none
case "$component" in
  # A clean host cannot start PostgREST until `platform provision apply`
  # creates its database role. The normal compose stage therefore starts the
  # complete runtime except that one dependent service; provision starts it as
  # soon as the database contract exists.
  ""|bootstrap) component=bootstrap ;;
  firecrawl) services=(api playwright-service redis rabbitmq nuq-postgres) ;;
  observability)
    services=(victoriametrics victorialogs victoriatraces blackbox-exporter node-exporter cadvisor otel-collector alertmanager vmalert grafana)
    post_up_action=restart-alertmanager
    ;;
  kestra-data) services=(kestra-postgres) ;;
  mattermost-db) services=(mattermost-postgres) ;;
  *) services=("$component") ;;
esac

# Re-render only canonical projections. Compose itself performs the incremental
# reconciliation and leaves unchanged containers running.
"$ROOT/platform" config render >/dev/null

ssh_options=(
  -o BatchMode=yes
  -o ConnectTimeout=15
  -o ServerAliveInterval=30
  -o ServerAliveCountMax=10
  -o TCPKeepAlive=yes
)

temp_root=${TMPDIR:-/tmp}
remote_script=$(umask 077; mktemp "$temp_root/paperclip-compose.XXXXXX")
cleanup_remote_script() {
  rm -f -- "$remote_script"
}
trap cleanup_remote_script EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Feed SSH from a regular file. macOS/Homebrew Bash can block while preparing a
# sufficiently large heredoc pipe before ssh starts reading it.
cat >"$remote_script" <<'REMOTE'
set -euo pipefail
platform_root=$1
secrets_root=$2
post_up_action=${3:-none}
component=${4:-}
if (( $# >= 4 )); then
  shift 4
else
  shift $#
fi
compose="$platform_root/deployment/compose.yaml"
env_file="$secrets_root/compose.env"
config_renderer="$platform_root/bin/server-config.py"
[[ -r $compose ]] || { echo "compose: missing aggregate: $compose" >&2; exit 1; }
[[ -r $env_file ]] || { echo "compose: missing aggregate environment projection: $env_file" >&2; exit 1; }
[[ -r $config_renderer ]] \
  || { echo "compose: missing config projection auditor: $config_renderer" >&2; exit 1; }
python3 "$config_renderer" audit >/dev/null

# Compose gives the invoking process environment precedence over --env-file.
# Keep only the host settings needed to locate Docker, so stale SSH/session
# variables cannot override the canonical platform environment during
# interpolation.
compose_process_environment=(
  "HOME=${HOME:-/root}"
  "PATH=${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"
)
for system_variable in \
  DOCKER_CONFIG DOCKER_CONTEXT DOCKER_HOST \
  XDG_CONFIG_HOME XDG_RUNTIME_DIR; do
  if [[ -n ${!system_variable-} ]]; then
    compose_process_environment+=("$system_variable=${!system_variable}")
  fi
done
canonical_compose() {
  env -i "${compose_process_environment[@]}" \
    docker compose --env-file "$env_file" -f "$compose" "$@"
}

canonical_compose config --quiet

if [[ $component == bootstrap ]]; then
  mapfile -t services < <(
    canonical_compose config --services | awk '$1 != "postgrest"'
  )
  (( ${#services[@]} )) || {
    echo "compose: bootstrap service set is empty" >&2
    exit 1
  }
  canonical_compose up -d --wait "${services[@]}"
elif [[ $post_up_action == restart-alertmanager ]]; then
  canonical_compose up -d --wait config-init "$@"
elif (( $# )); then
  canonical_compose up -d --wait "$@"
else
  canonical_compose up -d --wait
fi

if [[ $post_up_action == restart-alertmanager ]]; then
  canonical_compose restart alertmanager
  canonical_compose up -d --wait alertmanager
fi

REMOTE

ssh "${ssh_options[@]}" "$target" bash -s -- \
  "$platform_root" "$secrets_root" "$post_up_action" "$component" "${services[@]}" \
  <"$remote_script"

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

remote_script="$ROOT/deployment/scripts/compose-remote.sh"
[[ -r $remote_script ]] \
  || { echo "compose: missing remote helper: $remote_script" >&2; exit 1; }

ssh "${ssh_options[@]}" "$target" bash -s -- \
  "$platform_root" "$secrets_root" "$post_up_action" "$component" "${services[@]}" \
  <"$remote_script"

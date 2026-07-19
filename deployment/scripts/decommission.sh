#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fail() { printf 'decommission: %s\n' "$*" >&2; exit 2; }
[[ $# == 1 && $1 == --confirm-decommission ]] \
  || fail "container decommission requires --confirm-decommission"

: "${MTE_OPERATOR_ENV:=$ROOT/config/platform.env}"
[[ -f $MTE_OPERATOR_ENV ]] || fail "operator env not found: $MTE_OPERATOR_ENV"
env_value() {
  local key=$1
  awk -F= -v key="$key" '
    $0 !~ /^[[:space:]]*#/ && $1 == key {
      count++; value = substr($0, index($0, "=") + 1)
    }
    END { if (count != 1 || value == "") exit 1; print value }
  ' "$MTE_OPERATOR_ENV"
}
target=$(env_value MTE_SSH_TARGET) || fail "MTE_SSH_TARGET must occur exactly once"
platform_root=$(env_value MTE_PLATFORM_ROOT 2>/dev/null || printf '%s\n' /opt/mte-platform)
secrets_root=$(env_value MTE_SECRETS_ROOT 2>/dev/null || printf '%s\n' /root/.config/mte-secrets)

ssh -o BatchMode=yes -o ConnectTimeout=15 "$target" bash -s -- \
  "$platform_root" "$secrets_root" <<'REMOTE'
set -euo pipefail
platform_root=$1
secrets_root=$2
compose=$platform_root/deployment/compose.yaml
env_file=$secrets_root/compose.env
daytona_step=$platform_root/deployment/steps/daytona.sh
paperclip_step=$platform_root/deployment/steps/paperclip.sh
fail() { printf 'decommission: %s\n' "$*" >&2; exit 2; }
for path in "$compose" "$env_file" "$daytona_step" "$paperclip_step"; do
  [[ -r $path ]] || fail "decommission preflight file is unavailable: $path"
done
docker compose --env-file "$env_file" -f "$compose" config --quiet

# These existing remove actions and Compose down omit --volumes by contract.
bash "$paperclip_step" remove
bash "$daytona_step" remove
docker compose --env-file "$env_file" -f "$compose" down --remove-orphans
printf 'decommission: containers removed; all named volumes and host-local backups preserved\n'
printf 'decommission: Cloudflare resources and credentials were not changed\n'
REMOTE

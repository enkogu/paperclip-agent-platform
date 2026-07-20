#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fail() { printf 'backup: %s\n' "$*" >&2; exit 2; }
usage() { printf 'Usage: ./install.sh backup BACKUP_ID\n' >&2; }

case " $* " in
  *' --pitr '*|*' --target '*|*' --off-host '*)
    fail "PITR and off-host targets are unsupported in the public MVP"
    ;;
esac
(( $# == 1 )) || { usage; fail "exactly one backup ID is required"; }
backup_id=$1
[[ $backup_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] \
  || fail "backup ID must be 1-64 safe filename characters"

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
  "$platform_root" "$secrets_root" "$backup_id" <<'REMOTE'
set -euo pipefail
umask 077
platform_root=$1
secrets_root=$2
backup_id=$3
backup_root=/var/backups/mte-platform
final=$backup_root/$backup_id
lock=$backup_root/.recovery.lock
compose=$platform_root/deployment/compose.yaml
env_file=$secrets_root/compose.env
daytona_compose_file=$platform_root/deployment/services/daytona/compose.yaml
daytona_root=$platform_root/runtime/paperclip-daytona
daytona_env=$daytona_root/platform.env.projection
fail() { printf 'backup: %s\n' "$*" >&2; exit 2; }
retention_days=30
minimum_free_reserve_bytes=$((1024 * 1024 * 1024))

for path in "$compose" "$env_file" "$daytona_compose_file" "$daytona_env"; do
  [[ -r $path ]] || fail "required runtime file is unavailable: $path"
done
mkdir -p -m 0700 "$backup_root"
if [[ -d $final ]]; then
  (cd "$final" && sha256sum -c SHA256SUMS >/dev/null) \
    || fail "existing backup failed checksum validation: $backup_id"
  printf 'backup: existing backup is valid: %s\n' "$final"
  exit 0
fi
stage=
clients_quiesced=0
declare -a aggregate_running=() daytona_running=() aggregate_clients=() daytona_clients=()
restart_clients() {
  local status=0
  if (( clients_quiesced )); then
    ((${#aggregate_clients[@]} == 0)) \
      || aggregate_compose up -d --wait "${aggregate_clients[@]}" || status=$?
    ((${#daytona_clients[@]} == 0)) \
      || daytona_compose up -d --wait "${daytona_clients[@]}" || status=$?
    (( status != 0 )) || clients_quiesced=0
  fi
  return "$status"
}
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  restart_clients
  local restart_status=$?
  [[ -z $stage ]] || rm -rf -- "$stage"
  rmdir "$lock"
  if (( status == 0 && restart_status != 0 )); then
    printf 'backup: failed to restart every previously running database client\n' >&2
    status=$restart_status
  fi
  exit "$status"
}
mkdir "$lock" 2>/dev/null || fail "another backup or restore is already in progress"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
stage=$(mktemp -d "$backup_root/.$backup_id.tmp.XXXXXX")

clean_env=(
  "HOME=${HOME:-/root}"
  "PATH=${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"
)
aggregate_compose() {
  env -i "${clean_env[@]}" docker compose --env-file "$env_file" -f "$compose" "$@"
}
daytona_compose() {
  env -i "${clean_env[@]}" docker compose --project-directory "$daytona_root" \
    --env-file "$daytona_env" -f "$daytona_compose_file" "$@"
}
dump_database() {
  local family=$1 service=$2 output=$3
  if [[ $family == aggregate ]]; then
    aggregate_compose exec -T "$service" sh -ceu '
      command -v pg_dump >/dev/null
      : "${POSTGRES_USER:?}" "${POSTGRES_DB:?}"
      exec pg_dump --format=custom --no-owner --no-privileges \
        --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"
    ' >"$output"
  else
    daytona_compose exec -T "$service" sh -ceu '
      command -v pg_dump >/dev/null
      : "${POSTGRES_USER:?}" "${POSTGRES_DB:?}"
      exec pg_dump --format=custom --no-owner --no-privileges \
        --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"
    ' >"$output"
  fi
  [[ -s $output ]] || fail "empty PostgreSQL dump: $(basename "$output")"
}
database_info() {
  local family=$1 service=$2
  local command='command -v psql >/dev/null; command -v pg_dump >/dev/null; : "${POSTGRES_USER:?}" "${POSTGRES_DB:?}"; size=$(psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --tuples-only --no-align --command="SELECT pg_database_size(current_database())"); server=$(psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --tuples-only --no-align --command="SHOW server_version_num"); dump_version=$(pg_dump --version); dump_version=${dump_version##* }; printf "%s %s %s\\n" "$size" "$((server / 10000))" "${dump_version%%.*}"'
  if [[ $family == aggregate ]]; then
    aggregate_compose exec -T "$service" sh -ceu "$command"
  else
    daytona_compose exec -T "$service" sh -ceu "$command"
  fi
}

aggregate_compose config --quiet
daytona_compose config --quiet
aggregate_compose_sha=$(sha256sum "$compose" | awk '{print $1}')
daytona_compose_sha=$(sha256sum "$daytona_compose_file" | awk '{print $1}')
aggregate_config_sha=$(aggregate_compose config | sha256sum | awk '{print $1}')
daytona_config_sha=$(daytona_compose config | sha256sum | awk '{print $1}')
database_services=(postgres kestra-postgres mattermost-postgres nuq-postgres daytona-db)
server_majors=()
dump_majors=()
estimated_bytes=0
for service in "${database_services[@]:0:4}"; do
  aggregate_compose ps --status running --services | grep -Fx "$service" >/dev/null \
    || fail "required PostgreSQL service is not running: $service"
  read -r size server_major dump_major < <(database_info aggregate "$service")
  [[ $size =~ ^[0-9]+$ && $server_major =~ ^[0-9]+$ \
    && $dump_major =~ ^[0-9]+$ ]] || fail "invalid PostgreSQL preflight result: $service"
  [[ $server_major == "$dump_major" ]] \
    || fail "pg_dump/server major compatibility check failed: $service"
  server_majors+=("$server_major")
  dump_majors+=("$dump_major")
  ((estimated_bytes += size))
done
daytona_compose ps --status running --services | grep -Fx db >/dev/null \
  || fail "required PostgreSQL service is not running: daytona-db"
read -r size server_major dump_major < <(database_info daytona db)
[[ $size =~ ^[0-9]+$ && $server_major =~ ^[0-9]+$ \
  && $dump_major =~ ^[0-9]+$ ]] || fail "invalid PostgreSQL preflight result: daytona-db"
[[ $server_major == "$dump_major" ]] \
  || fail "pg_dump/server major compatibility check failed: daytona-db"
server_majors+=("$server_major")
dump_majors+=("$dump_major")
((estimated_bytes += size))
available_bytes=$(df --output=avail -B1 "$backup_root" | awk 'NR == 2 {print $1}')
required_bytes=$((estimated_bytes * 2 + minimum_free_reserve_bytes))
[[ $available_bytes =~ ^[0-9]+$ && $available_bytes -ge $required_bytes ]] \
  || fail "insufficient backup disk: require ${required_bytes} bytes, have ${available_bytes}; existing backups are never pruned automatically"

# Keep one bounded recovery cut: every client that was running is stopped before
# the first dump and remains stopped until the last dump is durable. The EXIT
# trap restores precisely that captured running set on success and failure.
while IFS= read -r service; do
  [[ -z $service ]] || aggregate_running+=("$service")
done < <(aggregate_compose ps --status running --services)
while IFS= read -r service; do
  [[ -z $service ]] || daytona_running+=("$service")
done < <(daytona_compose ps --status running --services)
for service in "${aggregate_running[@]}"; do
  case $service in postgres|kestra-postgres|mattermost-postgres|nuq-postgres) ;; *) aggregate_clients+=("$service");; esac
done
for service in "${daytona_running[@]}"; do
  [[ $service == db ]] || daytona_clients+=("$service")
done
clients_quiesced=1
((${#aggregate_clients[@]} == 0)) || aggregate_compose stop "${aggregate_clients[@]}"
((${#daytona_clients[@]} == 0)) || daytona_compose stop "${daytona_clients[@]}"
for service in postgres kestra-postgres mattermost-postgres nuq-postgres; do
  dump_database aggregate "$service" "$stage/$service.dump"
  aggregate_compose exec -T "$service" pg_restore --list <"$stage/$service.dump" >/dev/null \
    || fail "PostgreSQL archive validation failed: $service.dump"
done
dump_database daytona db "$stage/daytona-db.dump"
daytona_compose exec -T db pg_restore --list <"$stage/daytona-db.dump" >/dev/null \
  || fail "PostgreSQL archive validation failed: daytona-db.dump"

docker volume ls --format '{{.Name}}' | awk '$0 ~ /^mte-/' | LC_ALL=C sort \
  >"$stage/volume-inventory.txt"
created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
{
  printf 'format=mte-postgresql-logical-v1\n'
  printf 'backup_id=%s\n' "$backup_id"
  printf 'created_at=%s\n' "$created_at"
  printf 'aggregate_compose_sha256=%s\n' "$aggregate_compose_sha"
  printf 'daytona_compose_sha256=%s\n' "$daytona_compose_sha"
  printf 'aggregate_config_sha256=%s\n' "$aggregate_config_sha"
  printf 'daytona_config_sha256=%s\n' "$daytona_config_sha"
  for index in "${!database_services[@]}"; do
    service=${database_services[$index]}
    printf '%s_server_major=%s\n' "$service" "${server_majors[$index]}"
    printf '%s_pg_dump_major=%s\n' "$service" "${dump_majors[$index]}"
  done
  printf 'database_dumps=postgres,kestra-postgres,mattermost-postgres,nuq-postgres,daytona-db\n'
  printf 'volume_payloads=not_captured\n'
  printf 'pitr=unsupported\n'
  printf 'off_host_copy=unsupported\n'
  printf 'retention_days=%s\n' "$retention_days"
  printf 'prune_policy=manual_only\n'
} >"$stage/metadata"
(cd "$stage" && sha256sum *.dump metadata volume-inventory.txt >SHA256SUMS)
chmod 0600 "$stage"/*
mv -T -- "$stage" "$final"
restart_clients || fail "failed to restart every previously running database client"
rmdir "$lock"
trap - EXIT INT TERM
printf 'backup: created host-local logical backup: %s\n' "$final"
printf 'backup: retention is %s days; pruning is manual only and no existing backup was deleted\n' "$retention_days"
REMOTE

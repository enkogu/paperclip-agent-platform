#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fail() { printf 'restore: %s\n' "$*" >&2; exit 2; }
usage() { printf 'Usage: ./install.sh restore BACKUP_ID --confirm-restore\n' >&2; }

case " $* " in
  *' --pitr '*|*' --target '*|*' --off-host '*)
    fail "PITR and off-host targets are unsupported in the public MVP"
    ;;
esac
(( $# == 2 )) || { usage; fail "backup ID and --confirm-restore are required"; }
backup_id=$1
[[ $2 == --confirm-restore ]] || fail "destructive restore requires --confirm-restore"
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
backup=$backup_root/$backup_id
recovery_lock=$backup_root/.recovery.lock
compose=$platform_root/deployment/compose.yaml
env_file=$secrets_root/compose.env
daytona_compose_file=$platform_root/deployment/services/daytona/compose.yaml
daytona_root=$platform_root/runtime/paperclip-daytona
daytona_env=$daytona_root/platform.env.projection
fail() { printf 'restore: %s\n' "$*" >&2; exit 2; }
minimum_free_reserve_bytes=$((1024 * 1024 * 1024))

for path in "$compose" "$env_file" "$daytona_compose_file" "$daytona_env"; do
  [[ -r $path ]] || fail "required runtime file is unavailable: $path"
done
mkdir -p -m 0700 "$backup_root"
mkdir "$recovery_lock" 2>/dev/null || fail "another backup or restore is already in progress"
release_lock() { rmdir "$recovery_lock"; }
trap release_lock EXIT
[[ -d $backup && -r $backup/metadata && -r $backup/SHA256SUMS ]] \
  || fail "backup is incomplete or unavailable: $backup_id"
(cd "$backup" && sha256sum -c SHA256SUMS >/dev/null) \
  || fail "backup checksum validation failed"
grep -Fx 'format=mte-postgresql-logical-v1' "$backup/metadata" >/dev/null \
  || fail "unsupported backup format"
grep -Fx "backup_id=$backup_id" "$backup/metadata" >/dev/null \
  || fail "backup identity does not match requested ID"
for name in postgres kestra-postgres mattermost-postgres nuq-postgres daytona-db; do
  [[ -s $backup/$name.dump ]] || fail "required dump is missing: $name.dump"
done
metadata_value() {
  local key=$1
  awk -F= -v key="$key" '$1 == key { count++; value=substr($0,index($0,"=")+1) } END { if (count != 1 || value == "") exit 1; print value }' \
    "$backup/metadata"
}

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
preflight_database() {
  local family=$1 service=$2
  local command='command -v dropdb >/dev/null; command -v createdb >/dev/null; command -v pg_dump >/dev/null; command -v pg_restore >/dev/null; command -v psql >/dev/null; : "${POSTGRES_USER:?}" "${POSTGRES_DB:?}"; test "$(psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --tuples-only --no-align --command="SELECT 1")" = 1; size=$(psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --tuples-only --no-align --command="SELECT pg_database_size(current_database())"); server=$(psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --tuples-only --no-align --command="SHOW server_version_num"); restore_version=$(pg_restore --version); restore_version=${restore_version##* }; printf "%s %s %s\\n" "$size" "$((server / 10000))" "${restore_version%%.*}"'
  if [[ $family == aggregate ]]; then
    aggregate_compose exec -T "$service" sh -ceu "$command"
  else
    daytona_compose exec -T "$service" sh -ceu "$command"
  fi
}
validate_archive() {
  local family=$1 service=$2 input=$3
  if [[ $family == aggregate ]]; then
    aggregate_compose exec -T "$service" pg_restore --list <"$input" >/dev/null
  else
    daytona_compose exec -T "$service" pg_restore --list <"$input" >/dev/null
  fi
}
dump_database() {
  local family=$1 service=$2 output=$3
  local command='command -v pg_dump >/dev/null; : "${POSTGRES_USER:?}" "${POSTGRES_DB:?}"; exec pg_dump --format=custom --no-owner --no-privileges --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"'
  if [[ $family == aggregate ]]; then
    aggregate_compose exec -T "$service" sh -ceu "$command" >"$output"
  else
    daytona_compose exec -T "$service" sh -ceu "$command" >"$output"
  fi
  [[ -s $output ]] || return 1
  validate_archive "$family" "$service" "$output"
}
restore_database() {
  local family=$1 service=$2 input=$3
  if [[ $family == aggregate ]]; then
    aggregate_compose exec -T "$service" sh -ceu '
      dropdb --force --if-exists --username="$POSTGRES_USER" "$POSTGRES_DB"
      createdb --username="$POSTGRES_USER" "$POSTGRES_DB"
      exec pg_restore --exit-on-error --single-transaction --no-owner --no-privileges \
        --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"
    ' <"$input"
  else
    daytona_compose exec -T "$service" sh -ceu '
      dropdb --force --if-exists --username="$POSTGRES_USER" "$POSTGRES_DB"
      createdb --username="$POSTGRES_USER" "$POSTGRES_DB"
      exec pg_restore --exit-on-error --single-transaction --no-owner --no-privileges \
        --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"
    ' <"$input"
  fi
}

aggregate_compose config --quiet
daytona_compose config --quiet
expected_aggregate_compose_sha=$(metadata_value aggregate_compose_sha256) \
  || fail "backup lacks aggregate Compose identity"
expected_daytona_compose_sha=$(metadata_value daytona_compose_sha256) \
  || fail "backup lacks Daytona Compose identity"
expected_aggregate_config_sha=$(metadata_value aggregate_config_sha256) \
  || fail "backup lacks aggregate rendered-config identity"
expected_daytona_config_sha=$(metadata_value daytona_config_sha256) \
  || fail "backup lacks Daytona rendered-config identity"
[[ $(sha256sum "$compose" | awk '{print $1}') == "$expected_aggregate_compose_sha" ]] \
  || fail "aggregate Compose identity differs from the backup"
[[ $(sha256sum "$daytona_compose_file" | awk '{print $1}') == "$expected_daytona_compose_sha" ]] \
  || fail "Daytona Compose identity differs from the backup"
[[ $(aggregate_compose config | sha256sum | awk '{print $1}') == "$expected_aggregate_config_sha" ]] \
  || fail "aggregate rendered config differs from the backup"
[[ $(daytona_compose config | sha256sum | awk '{print $1}') == "$expected_daytona_config_sha" ]] \
  || fail "Daytona rendered config differs from the backup"

estimated_rollback_bytes=0
for service in postgres kestra-postgres mattermost-postgres nuq-postgres; do
  aggregate_compose ps --status running --services | grep -Fx "$service" >/dev/null \
    || fail "restore preflight requires running database service: $service"
  read -r current_size server_major restore_major \
    < <(preflight_database aggregate "$service")
  expected_server_major=$(metadata_value "${service}_server_major") \
    || fail "backup lacks server-major identity for $service"
  expected_dump_major=$(metadata_value "${service}_pg_dump_major") \
    || fail "backup lacks pg_dump-major identity for $service"
  [[ $server_major == "$expected_server_major" && $restore_major == "$expected_dump_major" \
    && $server_major == "$restore_major" ]] \
    || fail "PostgreSQL major compatibility check failed for $service"
  validate_archive aggregate "$service" "$backup/$service.dump" \
    || fail "PostgreSQL archive validation failed: $service.dump"
  ((estimated_rollback_bytes += current_size))
done
daytona_compose ps --status running --services | grep -Fx db >/dev/null \
  || fail "restore preflight requires running database service: daytona-db"
read -r current_size server_major restore_major \
  < <(preflight_database daytona db)
expected_server_major=$(metadata_value daytona-db_server_major) \
  || fail "backup lacks server-major identity for daytona-db"
expected_dump_major=$(metadata_value daytona-db_pg_dump_major) \
  || fail "backup lacks pg_dump-major identity for daytona-db"
[[ $server_major == "$expected_server_major" && $restore_major == "$expected_dump_major" \
  && $server_major == "$restore_major" ]] \
  || fail "PostgreSQL major compatibility check failed for daytona-db"
validate_archive daytona db "$backup/daytona-db.dump" \
  || fail "PostgreSQL archive validation failed: daytona-db.dump"
((estimated_rollback_bytes += current_size))
available_bytes=$(df --output=avail -B1 "$backup_root" | awk 'NR == 2 {print $1}')
required_bytes=$((estimated_rollback_bytes * 2 + minimum_free_reserve_bytes))
[[ $available_bytes =~ ^[0-9]+$ && $available_bytes -ge $required_bytes ]] \
  || fail "insufficient rollback disk: require ${required_bytes} bytes, have ${available_bytes}; existing backups are never pruned automatically"

declare -a aggregate_running=() daytona_running=() aggregate_clients=() daytona_clients=()
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
rollback_dir=$(mktemp -d "$backup_root/.pre-restore-$backup_id.XXXXXX")
clients_quiesced=0
mutation_started=0
rollback_failed=0
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
rollback_databases() {
  local status=0 service
  printf 'restore: failure detected after mutation; restoring verified pre-restore dumps\n' >&2
  for service in postgres kestra-postgres mattermost-postgres nuq-postgres; do
    restore_database aggregate "$service" "$rollback_dir/$service.dump" || status=$?
  done
  restore_database daytona db "$rollback_dir/daytona-db.dump" || status=$?
  return "$status"
}
finish() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  if (( status != 0 && mutation_started )); then
    rollback_databases
    rollback_failed=$?
  fi
  restart_clients
  local restart_status=$?
  if (( rollback_failed != 0 )); then
    printf 'restore: automatic rollback failed; verified rollback dumps retained at %s\n' "$rollback_dir" >&2
    status=$rollback_failed
  else
    rm -rf -- "$rollback_dir"
  fi
  if (( restart_status != 0 )); then
    printf 'restore: failed to restart every previously running database client\n' >&2
    (( status != 0 )) || status=$restart_status
  fi
  rmdir "$recovery_lock" || status=$?
  exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Hold one bounded recovery cut while verified rollback dumps are captured and
# every target database is replaced. The trap restarts exactly the captured set.
clients_quiesced=1
((${#aggregate_clients[@]} == 0)) || aggregate_compose stop "${aggregate_clients[@]}"
((${#daytona_clients[@]} == 0)) || daytona_compose stop "${daytona_clients[@]}"
for service in postgres kestra-postgres mattermost-postgres nuq-postgres; do
  dump_database aggregate "$service" "$rollback_dir/$service.dump" \
    || fail "could not create and verify pre-restore rollback dump: $service"
done
dump_database daytona db "$rollback_dir/daytona-db.dump" \
  || fail "could not create and verify pre-restore rollback dump: daytona-db"
(cd "$rollback_dir" && sha256sum *.dump >SHA256SUMS && sha256sum -c SHA256SUMS >/dev/null) \
  || fail "pre-restore rollback dump checksum validation failed"

mutation_started=1
for service in postgres kestra-postgres mattermost-postgres nuq-postgres; do
  restore_database aggregate "$service" "$backup/$service.dump"
done
restore_database daytona db "$backup/daytona-db.dump"
# A successful pg_restore process is not enough to close the transaction: prove
# each restored database is connectable before discarding the rollback set.
for service in postgres kestra-postgres mattermost-postgres nuq-postgres; do
  preflight_database aggregate "$service" >/dev/null
done
preflight_database daytona db >/dev/null
mutation_started=0
restart_clients || fail "failed to restart every previously running database client"
rm -rf -- "$rollback_dir"
rmdir "$recovery_lock"
trap - EXIT INT TERM
printf 'restore: restored logical PostgreSQL backup: %s\n' "$backup_id"
printf 'restore: non-database volumes were preserved and were not restored\n'
REMOTE

#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-install}
ENV_FILE='/root/.config/mte-secrets/platform.env'
SECRET_DIR='/root/.config/mte-secrets/cloudflare'
TOKEN_FILE="${SECRET_DIR}/tunnel-token"

require_protected_path() {
  local path=$1 expected_type=$2 expected_mode=$3 label=$4 owner mode
  if [[ "$expected_type" == 'file' ]]; then
    [[ -f "$path" && ! -L "$path" ]] || {
      echo "cloudflared-runtime: unsafe ${label}" >&2
      exit 2
    }
  else
    [[ -d "$path" && ! -L "$path" ]] || {
      echo "cloudflared-runtime: unsafe ${label}" >&2
      exit 2
    }
  fi
  owner=$(stat -c '%u:%g' "$path") || {
    echo "cloudflared-runtime: cannot inspect ${label}" >&2
    exit 2
  }
  mode=$(stat -c '%a' "$path") || {
    echo "cloudflared-runtime: cannot inspect ${label}" >&2
    exit 2
  }
  if [[ "$owner" != '0:0' || "$mode" != "$expected_mode" ]]; then
    echo "cloudflared-runtime: unsafe ${label}" >&2
    exit 2
  fi
}

canonical_value() {
  local key=$1
  awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; found=1; exit} END {if (!found) exit 2}' "$ENV_FILE"
}

require_canonical_value() {
  local key=$1
  local value
  if ! value=$(canonical_value "$key") || [[ -z "$value" ]]; then
    echo "cloudflared-runtime: missing canonical ${key}" >&2
    exit 2
  fi
  printf '%s\n' "$value"
}

require_protected_path "$ENV_FILE" file 600 'canonical platform.env'

IMAGE=$(require_canonical_value CLOUDFLARED_IMAGE)
NAME=$(require_canonical_value CLOUDFLARED_CONTAINER_NAME)
RESTART_POLICY=$(require_canonical_value CLOUDFLARED_RESTART_POLICY)
NETWORK_MODE=$(require_canonical_value CLOUDFLARED_NETWORK_MODE)
CONTAINER_USER=$(require_canonical_value CLOUDFLARED_USER)
CPU_LIMIT=$(require_canonical_value CLOUDFLARED_CPU_LIMIT)
MEMORY_LIMIT=$(require_canonical_value CLOUDFLARED_MEMORY_LIMIT)
PIDS_LIMIT=$(require_canonical_value MTE_PIDS_SERVICE_LIMIT)
LOG_MAX_SIZE=$(require_canonical_value MTE_DOCKER_LOG_MAX_SIZE)
LOG_MAX_FILES=$(require_canonical_value MTE_DOCKER_LOG_MAX_FILES)
LOG_LOOKBACK=$(require_canonical_value CLOUDFLARED_LOG_LOOKBACK)
METRICS_ADDRESS=$(require_canonical_value CLOUDFLARED_METRICS_ADDRESS)

if [[ ! "$RESTART_POLICY" =~ ^(no|always|unless-stopped)$ ]]; then
  echo "cloudflared-runtime: invalid CLOUDFLARED_RESTART_POLICY" >&2
  exit 2
fi
# All declared origins are host-loopback listeners, so another network mode
# would silently sever the tunnel from every application.
if [[ "$NETWORK_MODE" != 'host' ]]; then
  echo "cloudflared-runtime: invalid CLOUDFLARED_NETWORK_MODE" >&2
  exit 2
fi
if [[ ! "$CONTAINER_USER" =~ ^[0-9]+:[0-9]+$ ]]; then
  echo "cloudflared-runtime: invalid CLOUDFLARED_USER" >&2
  exit 2
fi
if [[ ! "$CPU_LIMIT" =~ ^(0\.[0-9]+|[1-9][0-9]*(\.[0-9]+)?)$ ]]; then
  echo "cloudflared-runtime: invalid CLOUDFLARED_CPU_LIMIT" >&2
  exit 2
fi
CPU_NANO=$(awk -v value="$CPU_LIMIT" 'BEGIN { if (value <= 0) exit 1; printf "%.0f", value * 1000000000 }') || {
  echo "cloudflared-runtime: invalid CLOUDFLARED_CPU_LIMIT" >&2
  exit 2
}
if [[ ! "$MEMORY_LIMIT" =~ ^[1-9][0-9]*[kKmMgG]$ ]]; then
  echo "cloudflared-runtime: invalid CLOUDFLARED_MEMORY_LIMIT" >&2
  exit 2
fi
MEMORY_BYTES=$(awk -v value="$MEMORY_LIMIT" '
  BEGIN {
    unit = tolower(substr(value, length(value), 1))
    amount = substr(value, 1, length(value) - 1) + 0
    multiplier = unit == "k" ? 1024 : (unit == "m" ? 1048576 : 1073741824)
    printf "%.0f", amount * multiplier
  }
')
if [[ ! "$PIDS_LIMIT" =~ ^[1-9][0-9]*$ ]]; then
  echo "cloudflared-runtime: invalid MTE_PIDS_SERVICE_LIMIT" >&2
  exit 2
fi
if [[ ! "$LOG_MAX_SIZE" =~ ^[1-9][0-9]*[kKmMgG]$ ]]; then
  echo "cloudflared-runtime: invalid MTE_DOCKER_LOG_MAX_SIZE" >&2
  exit 2
fi
if [[ ! "$LOG_MAX_FILES" =~ ^[1-9][0-9]*$ ]]; then
  echo "cloudflared-runtime: invalid MTE_DOCKER_LOG_MAX_FILES" >&2
  exit 2
fi
if [[ ! "$LOG_LOOKBACK" =~ ^[1-9][0-9]*(s|m|h)$ ]]; then
  echo "cloudflared-runtime: invalid CLOUDFLARED_LOG_LOOKBACK" >&2
  exit 2
fi
if [[ ! "$METRICS_ADDRESS" =~ ^127\.0\.0\.1:([1-9][0-9]{3,4})$ ]] \
  || ((10#${BASH_REMATCH[1]} > 65535)); then
  echo "cloudflared-runtime: invalid CLOUDFLARED_METRICS_ADDRESS" >&2
  exit 2
fi

expected_command_json() {
  python3 - "$METRICS_ADDRESS" <<'PY'
import json
import sys

print(json.dumps([
    "tunnel",
    "--metrics",
    sys.argv[1],
    "--no-autoupdate",
    "run",
    "--token-file",
    "/run/secrets/tunnel-token",
], separators=(",", ":")))
PY
}

log_config_matches() {
  local driver max_size max_files
  driver=$(docker inspect --format '{{.HostConfig.LogConfig.Type}}' "$NAME" 2>/dev/null) || return 1
  max_size=$(docker inspect --format '{{index .HostConfig.LogConfig.Config "max-size"}}' "$NAME" 2>/dev/null) || return 1
  max_files=$(docker inspect --format '{{index .HostConfig.LogConfig.Config "max-file"}}' "$NAME" 2>/dev/null) || return 1
  [[ "$driver" == 'json-file' ]] \
    && [[ "$max_size" == "$LOG_MAX_SIZE" ]] \
    && [[ "$max_files" == "$LOG_MAX_FILES" ]]
}

runtime_config_matches() {
  local image restart_policy network_mode container_user pids_limit nano_cpus memory_bytes command_json expected_command
  image=$(docker inspect --format '{{.Config.Image}}' "$NAME" 2>/dev/null) || return 1
  restart_policy=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$NAME" 2>/dev/null) || return 1
  network_mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$NAME" 2>/dev/null) || return 1
  container_user=$(docker inspect --format '{{.Config.User}}' "$NAME" 2>/dev/null) || return 1
  pids_limit=$(docker inspect --format '{{.HostConfig.PidsLimit}}' "$NAME" 2>/dev/null) || return 1
  nano_cpus=$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$NAME" 2>/dev/null) || return 1
  memory_bytes=$(docker inspect --format '{{.HostConfig.Memory}}' "$NAME" 2>/dev/null) || return 1
  command_json=$(docker inspect --format '{{json .Config.Cmd}}' "$NAME" 2>/dev/null) || return 1
  expected_command=$(expected_command_json) || return 1
  [[ "$image" == "$IMAGE" ]] \
    && [[ "$restart_policy" == "$RESTART_POLICY" ]] \
    && [[ "$network_mode" == "$NETWORK_MODE" ]] \
    && [[ "$container_user" == "$CONTAINER_USER" ]] \
    && [[ "$pids_limit" == "$PIDS_LIMIT" ]] \
    && [[ "$nano_cpus" == "$CPU_NANO" ]] \
    && [[ "$memory_bytes" == "$MEMORY_BYTES" ]] \
    && [[ "$command_json" == "$expected_command" ]] \
    && log_config_matches
}

verify_runtime_config() {
  if ! runtime_config_matches; then
    echo "cloudflared-runtime: live container config does not match canonical config" >&2
    exit 1
  fi
}

require_token() {
  require_protected_path "$SECRET_DIR" directory 700 'Cloudflare secret directory'
  require_protected_path "$TOKEN_FILE" file 600 'tunnel token file'
  if [[ ! -s "$TOKEN_FILE" ]]; then
    echo "cloudflared-runtime: missing non-empty token file" >&2
    exit 2
  fi
}

install_runtime() {
  require_token
  docker pull "$IMAGE" >/dev/null
  if docker inspect "$NAME" >/dev/null 2>&1; then
    if docker inspect --format '{{.State.Running}}' "$NAME" | grep -qx true \
      && runtime_config_matches; then
      echo "cloudflared-runtime: unchanged"
      return
    fi
    docker rm -f "$NAME" >/dev/null
  fi
  docker run -d \
    --name "$NAME" \
    --restart "$RESTART_POLICY" \
    --network "$NETWORK_MODE" \
    --user "$CONTAINER_USER" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit "$PIDS_LIMIT" \
    --cpus "$CPU_LIMIT" \
    --memory "$MEMORY_LIMIT" \
    --log-driver json-file \
    --log-opt "max-size=${LOG_MAX_SIZE}" \
    --log-opt "max-file=${LOG_MAX_FILES}" \
    --mount "type=bind,src=${TOKEN_FILE},dst=/run/secrets/tunnel-token,readonly" \
    "$IMAGE" tunnel --metrics "$METRICS_ADDRESS" --no-autoupdate run \
      --token-file /run/secrets/tunnel-token >/dev/null
  verify_runtime_config
  echo "cloudflared-runtime: installed"
}

status_runtime() {
  docker inspect --format '{"name":"{{.Name}}","running":{{.State.Running}},"status":"{{.State.Status}}","restartCount":{{.RestartCount}},"image":"{{.Config.Image}}","restartPolicy":"{{.HostConfig.RestartPolicy.Name}}","networkMode":"{{.HostConfig.NetworkMode}}","user":"{{.Config.User}}","pidsLimit":{{.HostConfig.PidsLimit}},"nanoCpus":{{.HostConfig.NanoCpus}},"memoryBytes":{{.HostConfig.Memory}},"logDriver":"{{.HostConfig.LogConfig.Type}}","logMaxSize":"{{index .HostConfig.LogConfig.Config "max-size"}}","logMaxFiles":"{{index .HostConfig.LogConfig.Config "max-file"}}"}' "$NAME"
}

verify_runtime() {
  status_runtime | grep -q '"running":true'
  verify_runtime_config
  if docker logs --since "$LOG_LOOKBACK" "$NAME" 2>&1 | grep -Eqi 'authentication failed|invalid tunnel secret|unable to establish'; then
    echo "cloudflared-runtime: connector log reports authentication/connection failure" >&2
    exit 1
  fi
  echo "cloudflared-runtime: running"
}

case "$ACTION" in
  install) install_runtime ;;
  status) status_runtime ;;
  verify) verify_runtime ;;
  remove)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    echo "cloudflared-runtime: removed"
    ;;
  *) echo "usage: cloudflare-tunnel.sh install|status|verify|remove" >&2; exit 2 ;;
esac

#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-install}
IMAGE='cloudflare/cloudflared:2026.7.1@sha256:188bb03589a32affed3cf4d0590565ffe67b78866e6b5582574afab2b705bafe'
NAME='mte-cloudflared'
SECRET_DIR='/root/.config/mte-secrets/cloudflare'
TOKEN_FILE="${SECRET_DIR}/tunnel-token"

require_token() {
  if [[ ! -s "$TOKEN_FILE" ]]; then
    echo "cloudflared-runtime: missing non-empty token file" >&2
    exit 2
  fi
  chmod 0700 "$SECRET_DIR"
  chmod 0600 "$TOKEN_FILE"
}

install_runtime() {
  require_token
  docker pull "$IMAGE" >/dev/null
  if docker inspect "$NAME" >/dev/null 2>&1; then
    current=$(docker inspect --format '{{.Config.Image}}' "$NAME")
    if [[ "$current" == "$IMAGE" ]] && docker inspect --format '{{.State.Running}}' "$NAME" | grep -qx true; then
      echo "cloudflared-runtime: unchanged"
      return
    fi
    docker rm -f "$NAME" >/dev/null
  fi
  docker run -d \
    --name "$NAME" \
    --restart unless-stopped \
    --network host \
    --user 0:0 \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 256 \
    --cpus 0.25 \
    --memory 256m \
    --mount "type=bind,src=${TOKEN_FILE},dst=/run/secrets/tunnel-token,readonly" \
    "$IMAGE" tunnel --no-autoupdate run --token-file /run/secrets/tunnel-token >/dev/null
  echo "cloudflared-runtime: installed"
}

status_runtime() {
  docker inspect --format '{"name":"{{.Name}}","running":{{.State.Running}},"status":"{{.State.Status}}","restartCount":{{.RestartCount}}}' "$NAME"
}

verify_runtime() {
  status_runtime | grep -q '"running":true'
  if docker logs --since 5m "$NAME" 2>&1 | grep -Eqi 'authentication failed|invalid tunnel secret|unable to establish'; then
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
  *) echo "usage: 90-cloudflare-tunnel.sh install|status|verify|remove" >&2; exit 2 ;;
esac

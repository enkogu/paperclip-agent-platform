#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(basename "$SCRIPT_DIR")" == "platform-cli" ]] && \
   [[ "$(basename "$(dirname "$SCRIPT_DIR")")" == "tools" ]]; then
  ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
else
  ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
VERSION="2026.707.0"
DATA_DIR="${PAPERCLIP_DATA_DIR:-$ROOT/state/paperclip}"

mkdir -p "$DATA_DIR" "$ROOT/.npm-cache"
export npm_config_fetch_retries="${npm_config_fetch_retries:-5}"
export npm_config_fetch_retry_maxtimeout="${npm_config_fetch_retry_maxtimeout:-120000}"
export npm_config_fetch_timeout="${npm_config_fetch_timeout:-300000}"
exec npx --yes --cache "$ROOT/.npm-cache" "paperclipai@$VERSION" onboard \
  --yes --data-dir "$DATA_DIR" --bind "${PAPERCLIP_BIND:-loopback}"

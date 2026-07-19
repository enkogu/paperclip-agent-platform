#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ $# -le 1 ]] || { echo "preflight: expected at most one component" >&2; exit 1; }

: "${MTE_OPERATOR_ENV:=$ROOT/config/platform.env}"
export MTE_OPERATOR_ENV

for command in bash curl python3 rsync ssh; do
  command -v "$command" >/dev/null 2>&1 \
    || { echo "preflight: missing required command: $command" >&2; exit 1; }
done

[[ -f $MTE_OPERATOR_ENV ]] \
  || { echo "preflight: operator env not found: $MTE_OPERATOR_ENV" >&2; exit 1; }
[[ ! -L $MTE_OPERATOR_ENV ]] \
  || { echo "preflight: operator env must not be a symlink" >&2; exit 1; }
if [[ $(uname -s) == Darwin ]]; then
  mode=$(stat -f '%Lp' "$MTE_OPERATOR_ENV")
else
  mode=$(stat -c '%a' "$MTE_OPERATOR_ENV")
fi
(( (8#$mode & 077) == 0 )) \
  || { echo "preflight: operator env must not be group/world accessible" >&2; exit 1; }

"$ROOT/platform" config check
"$ROOT/platform" preflight

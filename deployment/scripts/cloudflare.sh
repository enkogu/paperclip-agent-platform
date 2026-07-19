#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ $# -eq 0 ]] || { echo "cloudflare: this stage does not accept a component" >&2; exit 1; }

: "${MTE_OPERATOR_ENV:=$ROOT/config/platform.env}"
export MTE_OPERATOR_ENV

# Terraform owns only the Cloudflare edge. Application lifecycle remains in
# Docker Compose. External acceptance runs in the verify stage after every
# canonical-hash-bound evidence producer has been rebound to the post-apply
# runtime configuration.
"$ROOT/platform" cloudflare origin-firewall
"$ROOT/platform" cloudflare apply

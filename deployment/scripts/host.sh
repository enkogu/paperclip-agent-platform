#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ $# -le 1 ]] || { echo "host: expected at most one component" >&2; exit 1; }

: "${MTE_OPERATOR_ENV:=$ROOT/config/platform.env}"
export MTE_OPERATOR_ENV

[[ -f $MTE_OPERATOR_ENV ]] \
  || { echo "host: operator env not found: $MTE_OPERATOR_ENV" >&2; exit 1; }

# The platform bootstrap has exactly one host installer: deployment/steps/host.sh.
# It materializes the minimal canonical seed contract, runs the digest/version
# pinned Ubuntu bootstrap, imports operator inputs, and synchronizes the runtime.
"$ROOT/platform" bootstrap

# Harden the host immediately after the governed firewall step has been
# synchronized. The Cloudflare stage intentionally repeats the idempotent
# reconciliation before edge acceptance.
"$ROOT/platform" cloudflare origin-firewall

# ToolHive distributes a release binary rather than a supported server image.
# Install that official artifact before Compose starts the thin runtime
# container that mounts it read-only.
"$ROOT/platform" tools install

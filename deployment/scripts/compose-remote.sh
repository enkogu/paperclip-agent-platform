#!/usr/bin/env bash
set -euo pipefail

platform_root=$1
secrets_root=$2
post_up_action=${3:-none}
component=${4:-}
if (( $# >= 4 )); then
  shift 4
else
  shift $#
fi
compose="$platform_root/deployment/compose.yaml"
env_file="$secrets_root/compose.env"
config_renderer="$platform_root/bin/server-config.py"
[[ -r $compose ]] || { echo "compose: missing aggregate: $compose" >&2; exit 1; }
[[ -r $env_file ]] || { echo "compose: missing aggregate environment projection: $env_file" >&2; exit 1; }
[[ -r $config_renderer ]] \
  || { echo "compose: missing config projection auditor: $config_renderer" >&2; exit 1; }
python3 "$config_renderer" audit >/dev/null

# Compose gives the invoking process environment precedence over --env-file.
# Keep only the host settings needed to locate Docker, so stale SSH/session
# variables cannot override the canonical platform environment during
# interpolation.
compose_process_environment=(
  "HOME=${HOME:-/root}"
  "PATH=${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"
)
for system_variable in \
  DOCKER_CONFIG DOCKER_CONTEXT DOCKER_HOST \
  XDG_CONFIG_HOME XDG_RUNTIME_DIR; do
  if [[ -n ${!system_variable-} ]]; then
    compose_process_environment+=("$system_variable=${!system_variable}")
  fi
done
canonical_compose() {
  env -i "${compose_process_environment[@]}" \
    docker compose --env-file "$env_file" -f "$compose" "$@"
}

canonical_compose config --quiet

if [[ $component == bootstrap ]]; then
  mapfile -t services < <(
    canonical_compose config --services | awk '$1 != "postgrest"'
  )
  (( ${#services[@]} )) || {
    echo "compose: bootstrap service set is empty" >&2
    exit 1
  }
  canonical_compose up -d --wait "${services[@]}"
elif [[ $post_up_action == restart-alertmanager ]]; then
  canonical_compose up -d --wait config-init "$@"
elif (( $# )); then
  canonical_compose up -d --wait "$@"
else
  canonical_compose up -d --wait
fi

if [[ $post_up_action == restart-alertmanager ]]; then
  canonical_compose restart alertmanager
  canonical_compose up -d --wait alertmanager
fi

#!/usr/bin/env bash
# Isolated checks for deployment/steps/resource-preflight.sh.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT=$ROOT/deployment/steps/resource-preflight.sh
temporary=$(mktemp -d "${TMPDIR:-/tmp}/resource-preflight.XXXXXX")
trap 'rm -rf "$temporary"' EXIT

stub_bin=$temporary/bin
mkdir -p "$stub_bin"

cat >"$stub_bin/df" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
target=${!#}
available=$PRECHECK_ROOT_FREE_KIB
if [[ $target != / ]]; then
  available=$PRECHECK_DOCKER_FREE_KIB
fi
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
printf '/dev/stub 100000000 1 %s 1%% /\n' "$available"
EOF
cat >"$stub_bin/docker" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${PRECHECK_DOCKER_INFO_FAIL:-0} == 0 ]] || exit 1
[[ $1 == info && $2 == --format && $3 == '{{.DockerRootDir}}' ]] || exit 2
printf '%s\n' "$PRECHECK_DOCKER_ROOT"
EOF
cat >"$stub_bin/getconf" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ $1 == _NPROCESSORS_ONLN ]] || exit 2
printf '%s\n' "$PRECHECK_CPU_COUNT"
EOF
chmod 0755 "$stub_bin/df" "$stub_bin/docker" "$stub_bin/getconf"

write_proc() {
  cat >"$temporary/meminfo" <<EOF
MemTotal:       ${PRECHECK_MEM_TOTAL_KIB} kB
MemAvailable:   ${PRECHECK_MEM_AVAILABLE_KIB} kB
SwapTotal:      ${PRECHECK_SWAP_TOTAL_KIB} kB
SwapFree:       ${PRECHECK_SWAP_FREE_KIB} kB
EOF
  printf '%s 0.00 0.00 1/1 1\n' "$PRECHECK_LOAD" >"$temporary/loadavg"
}

run_preflight() {
  local mode=$1
  shift
  write_proc
  env \
    PATH="$stub_bin:/usr/bin:/bin" \
    RESOURCE_PREFLIGHT_PROC_MEMINFO="$temporary/meminfo" \
    RESOURCE_PREFLIGHT_PROC_LOADAVG="$temporary/loadavg" \
    PRECHECK_MEM_TOTAL_KIB="$PRECHECK_MEM_TOTAL_KIB" \
    PRECHECK_MEM_AVAILABLE_KIB="$PRECHECK_MEM_AVAILABLE_KIB" \
    PRECHECK_SWAP_TOTAL_KIB="$PRECHECK_SWAP_TOTAL_KIB" \
    PRECHECK_SWAP_FREE_KIB="$PRECHECK_SWAP_FREE_KIB" \
    PRECHECK_LOAD="$PRECHECK_LOAD" \
    PRECHECK_CPU_COUNT="$PRECHECK_CPU_COUNT" \
    PRECHECK_ROOT_FREE_KIB="$PRECHECK_ROOT_FREE_KIB" \
    PRECHECK_DOCKER_FREE_KIB="$PRECHECK_DOCKER_FREE_KIB" \
    PRECHECK_DOCKER_ROOT="$PRECHECK_DOCKER_ROOT" \
    MTE_RESOURCE_PREFLIGHT_MIN_MEM_TOTAL_KIB=4096 \
    MTE_RESOURCE_PREFLIGHT_MIN_MEM_AVAILABLE_KIB=2048 \
    MTE_RESOURCE_PREFLIGHT_MAX_SWAP_USED_KIB=1024 \
    MTE_RESOURCE_PREFLIGHT_MAX_LOAD_PER_CPU_MILLI=1000 \
    MTE_RESOURCE_PREFLIGHT_MIN_ROOT_FREE_KIB=4096 \
    MTE_RESOURCE_PREFLIGHT_MIN_DOCKER_FREE_KIB=4096 \
    "$@" "$SCRIPT" "$mode"
}

run_daytona_e2e_preflight() (
  export PRECHECK_MEM_TOTAL_KIB=20971520
  export PRECHECK_MEM_AVAILABLE_KIB=$1
  export PRECHECK_ROOT_FREE_KIB=31457280
  export PRECHECK_DOCKER_FREE_KIB=$2
  run_preflight daytona-e2e \
    MTE_RESOURCE_PREFLIGHT_MIN_MEM_TOTAL_KIB=20971520 \
    MTE_RESOURCE_PREFLIGHT_MIN_MEM_AVAILABLE_KIB=6291456 \
    MTE_RESOURCE_PREFLIGHT_MIN_ROOT_FREE_KIB=31457280 \
    MTE_RESOURCE_PREFLIGHT_MIN_DOCKER_FREE_KIB=31457280
)

expect_success() {
  local name=$1
  shift
  if ! "$@" >"$temporary/output" 2>&1; then
    printf 'failed: %s\n' "$name" >&2
    cat "$temporary/output" >&2
    exit 1
  fi
}

expect_failure() {
  local name=$1 expected=$2
  shift 2
  if "$@" >"$temporary/output" 2>&1; then
    printf 'unexpected success: %s\n' "$name" >&2
    exit 1
  fi
  grep -Fqx "resource-preflight: $expected" "$temporary/output" \
    || { printf 'wrong failure: %s\n' "$name" >&2; cat "$temporary/output" >&2; exit 1; }
}

export PRECHECK_MEM_TOTAL_KIB=8192
export PRECHECK_MEM_AVAILABLE_KIB=6144
export PRECHECK_SWAP_TOTAL_KIB=2048
export PRECHECK_SWAP_FREE_KIB=1536
export PRECHECK_LOAD=1.50
export PRECHECK_CPU_COUNT=2
export PRECHECK_ROOT_FREE_KIB=8192
export PRECHECK_DOCKER_FREE_KIB=20480
export PRECHECK_DOCKER_ROOT=/var/lib/docker

# Docker is optional for the general deploy admission check.
expect_success "healthy deploy without Docker" \
  run_preflight deploy RESOURCE_PREFLIGHT_DOCKER_BIN=missing-docker
expect_failure "MemTotal" "insufficient MemTotal" \
  run_preflight deploy MTE_RESOURCE_PREFLIGHT_MIN_MEM_TOTAL_KIB=9000
expect_failure "MemAvailable" "insufficient MemAvailable" \
  run_preflight deploy MTE_RESOURCE_PREFLIGHT_MIN_MEM_AVAILABLE_KIB=7000
expect_failure "swap" "excessive swap use" \
  run_preflight deploy MTE_RESOURCE_PREFLIGHT_MAX_SWAP_USED_KIB=500
expect_failure "load per CPU" "excessive load per CPU" \
  run_preflight deploy MTE_RESOURCE_PREFLIGHT_MAX_LOAD_PER_CPU_MILLI=700
expect_failure "root disk" "insufficient root filesystem space" \
  run_preflight deploy MTE_RESOURCE_PREFLIGHT_MIN_ROOT_FREE_KIB=9000
expect_failure "Docker root disk" "insufficient Docker filesystem space" \
  run_preflight deploy MTE_RESOURCE_PREFLIGHT_MIN_DOCKER_FREE_KIB=25000
expect_success "Daytona E2E admission" \
  run_daytona_e2e_preflight 8388608 41943040
expect_failure "Daytona E2E sandbox memory reserve" "insufficient MemAvailable" \
  run_daytona_e2e_preflight 8388607 41943040
expect_failure "Daytona E2E image pull reserve" "insufficient Docker filesystem space" \
  run_daytona_e2e_preflight 8388608 41943039
if run_preflight unsupported-mode >"$temporary/output" 2>&1; then
  printf 'unexpected success: unsupported mode\n' >&2
  exit 1
fi
grep -Fx "usage: resource-preflight.sh {deploy|daytona-e2e}" "$temporary/output" >/dev/null
expect_failure "Docker inspection" "Docker inspection unavailable" \
  run_preflight deploy PRECHECK_DOCKER_INFO_FAIL=1
expect_failure "invalid threshold" "invalid threshold: MTE_RESOURCE_PREFLIGHT_MIN_MEM_TOTAL_KIB" \
  run_preflight deploy MTE_RESOURCE_PREFLIGHT_MIN_MEM_TOTAL_KIB=not-an-integer

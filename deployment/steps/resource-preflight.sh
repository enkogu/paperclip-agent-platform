#!/usr/bin/env bash
# Read-only host resource admission checks for deployment.
set -Eeuo pipefail

usage() {
  echo "usage: resource-preflight.sh {deploy|daytona-e2e}" >&2
  exit 2
}

fail() {
  # Deliberately report check names only: resource values and the caller's
  # environment must not appear in logs.
  printf 'resource-preflight: %s\n' "$1" >&2
  exit 1
}

parse_uint() {
  local raw=$1 label=$2
  # Limiting values to 17 digits keeps bash's signed integer arithmetic safe.
  [[ $raw =~ ^[0-9]{1,17}$ ]] || fail "invalid ${label}"
  printf '%d\n' "$((10#$raw))"
}

read_threshold() {
  local name=$1 raw
  declare -p "$name" >/dev/null 2>&1 || fail "missing threshold: ${name}"
  raw=${!name}
  parse_uint "$raw" "threshold: ${name}"
}

meminfo_kib() {
  local field=$1 raw
  raw=$(awk -v field="$field" '
    $1 == field ":" {
      if (found++ || NF != 3 || $3 != "kB") exit 2
      value = $2
    }
    END {
      if (!found) exit 1
      print value
    }
  ' "$proc_meminfo") || fail "invalid memory information"
  parse_uint "$raw" "memory information"
}

load_milli() {
  local raw=$1 whole fraction remainder whole_value fraction_value result
  [[ $raw =~ ^[0-9]{1,14}(\.[0-9]+)?$ ]] || fail "invalid load information"
  whole=${raw%%.*}
  fraction=0
  if [[ $raw == *.* ]]; then
    fraction=${raw#*.}
  fi
  whole_value=$(parse_uint "$whole" "load information")
  fraction="${fraction}000"
  remainder=${fraction:3}
  fraction=${fraction:0:3}
  fraction_value=$(parse_uint "$fraction" "load information")
  result=$((whole_value * 1000 + fraction_value))
  # Round additional precision up so a fractional excess never slips through.
  if [[ $remainder =~ [1-9] ]]; then
    result=$((result + 1))
  fi
  printf '%d\n' "$result"
}

free_kib() {
  local target=$1 raw
  raw=$(df -Pk "$target" | awk '
    NR > 1 {
      if (NF < 4 || found++) exit 2
      value = $4
    }
    END {
      if (!found) exit 1
      print value
    }
  ') || fail "invalid filesystem information"
  parse_uint "$raw" "filesystem information"
}

[[ $# -eq 1 ]] || usage
mode=$1
case $mode in
  deploy|daytona-e2e) ;;
  *) usage ;;
esac

# Tests may substitute proc files. Production uses the kernel-owned defaults.
proc_meminfo=/proc/meminfo
proc_loadavg=/proc/loadavg
docker_command=docker
if [[ ${RESOURCE_PREFLIGHT_PROC_MEMINFO+x} ]]; then
  proc_meminfo=$RESOURCE_PREFLIGHT_PROC_MEMINFO
fi
if [[ ${RESOURCE_PREFLIGHT_PROC_LOADAVG+x} ]]; then
  proc_loadavg=$RESOURCE_PREFLIGHT_PROC_LOADAVG
fi
if [[ ${RESOURCE_PREFLIGHT_DOCKER_BIN+x} ]]; then
  docker_command=$RESOURCE_PREFLIGHT_DOCKER_BIN
fi

min_mem_total_kib=$(read_threshold MTE_RESOURCE_PREFLIGHT_MIN_MEM_TOTAL_KIB)
min_mem_available_kib=$(read_threshold MTE_RESOURCE_PREFLIGHT_MIN_MEM_AVAILABLE_KIB)
max_swap_used_kib=$(read_threshold MTE_RESOURCE_PREFLIGHT_MAX_SWAP_USED_KIB)
max_load_per_cpu_milli=$(read_threshold MTE_RESOURCE_PREFLIGHT_MAX_LOAD_PER_CPU_MILLI)
min_root_free_kib=$(read_threshold MTE_RESOURCE_PREFLIGHT_MIN_ROOT_FREE_KIB)
min_docker_free_kib=$(read_threshold MTE_RESOURCE_PREFLIGHT_MIN_DOCKER_FREE_KIB)

# The live E2E creates one 2 GiB coding sandbox and may pull its immutable
# image. Keep that headroom derived from the ordinary deploy policy instead of
# introducing a second set of operator-configurable resource keys.
if [[ $mode == daytona-e2e ]]; then
  min_mem_available_kib=$((min_mem_available_kib + 2 * 1024 * 1024))
  min_docker_free_kib=$((min_docker_free_kib + 10 * 1024 * 1024))
fi

mem_total_kib=$(meminfo_kib MemTotal)
mem_available_kib=$(meminfo_kib MemAvailable)
swap_total_kib=$(meminfo_kib SwapTotal)
swap_free_kib=$(meminfo_kib SwapFree)
(( swap_free_kib <= swap_total_kib )) || fail "invalid swap information"
swap_used_kib=$((swap_total_kib - swap_free_kib))

(( mem_total_kib >= min_mem_total_kib )) || fail "insufficient MemTotal"
(( mem_available_kib >= min_mem_available_kib )) || fail "insufficient MemAvailable"
(( swap_used_kib <= max_swap_used_kib )) || fail "excessive swap use"

load_raw=$(awk 'NR == 1 { print $1; exit }' "$proc_loadavg") \
  || fail "invalid load information"
current_load_milli=$(load_milli "$load_raw")
cpu_count=$(parse_uint "$(getconf _NPROCESSORS_ONLN)" "CPU count")
(( cpu_count > 0 )) || fail "invalid CPU count"
# Compare by quotient/remainder to avoid multiplying caller-provided integers.
load_per_cpu_whole=$((current_load_milli / cpu_count))
load_per_cpu_remainder=$((current_load_milli % cpu_count))
if (( load_per_cpu_whole > max_load_per_cpu_milli )) \
  || (( load_per_cpu_whole == max_load_per_cpu_milli && load_per_cpu_remainder > 0 )); then
  fail "excessive load per CPU"
fi

root_free_kib=$(free_kib /)
(( root_free_kib >= min_root_free_kib )) || fail "insufficient root filesystem space"

if command -v "$docker_command" >/dev/null 2>&1; then
  docker_root=$("$docker_command" info --format '{{.DockerRootDir}}') \
    || fail "Docker inspection unavailable"
  [[ $docker_root == /* && $docker_root != *$'\n'* ]] \
    || fail "invalid Docker root directory"
  docker_free_kib=$(free_kib "$docker_root")
  (( docker_free_kib >= min_docker_free_kib )) \
    || fail "insufficient Docker filesystem space"
elif [[ $mode == daytona-e2e ]]; then
  fail "Docker inspection unavailable"
fi

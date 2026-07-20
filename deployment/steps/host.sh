#!/usr/bin/env bash
set -euo pipefail

CONFIG='/root/.config/mte-secrets/platform.env'
DOCKER_KEYRING='/etc/apt/keyrings/docker.asc'
DOCKER_SOURCES='/etc/apt/sources.list.d/docker.sources'

canonical_value() {
  local key=$1
  awk -F= -v key="$key" '
    $0 !~ /^[[:space:]]*#/ && $1 == key {
      count++
      value = substr($0, index($0, "=") + 1)
    }
    END {
      if (count != 1 || value == "") exit 1
      print value
    }
  ' "$CONFIG"
}

fail() {
  echo "host-bootstrap: $*" >&2
  exit 1
}

require_https_url() {
  local name=$1 value=$2
  [[ $value == https://* ]] || fail "$name must be an HTTPS URL"
}

require_sha256() {
  local name=$1 value=$2
  [[ $value =~ ^[0-9a-f]{64}$ ]] || fail "$name must be a lowercase SHA-256"
}

require_fingerprint() {
  local value=$1
  [[ $value =~ ^[0-9A-F]{40}$ ]] || fail \
    "MTE_DOCKER_APT_KEY_FINGERPRINT must be a 40-character uppercase fingerprint"
}

package_version() {
  { dpkg-query -W -f='${Status}\t${Version}\n' "$1" 2>/dev/null || true; } \
    | awk '$1 == "install" && $2 == "ok" && $3 == "installed" {print $4}'
}

require_package_version() {
  local package=$1 expected=$2 actual
  actual=$(package_version "$package")
  [[ $actual == "$expected" ]] || fail \
    "$package version drift: expected $expected, found ${actual:-not-installed}"
}

require_available_package_version() {
  local package=$1 expected=$2
  apt-cache madison "$package" \
    | awk '{print $3}' \
    | grep -Fxq "$expected" \
    || fail "$package version $expected is unavailable from configured repositories"
}

install_exact_packages() {
  local -a specifications=()
  while (($#)); do
    specifications+=("$1=$2")
    shift 2
  done
  apt-get install -y -qq --no-install-recommends --allow-downgrades \
    "${specifications[@]}"
}

validate_required_ports() {
  local raw=$1 token
  local -A observed=()
  local -a tokens=()
  IFS=',' read -r -a tokens <<<"$raw"
  ((${#tokens[@]} > 0)) || fail "MTE_HOST_REQUIRED_TCP_PORTS is empty"
  for token in "${tokens[@]}"; do
    [[ $token =~ ^[1-9][0-9]{0,4}$ ]] || fail \
      "MTE_HOST_REQUIRED_TCP_PORTS contains invalid port $token"
    ((token <= 65535)) || fail \
      "MTE_HOST_REQUIRED_TCP_PORTS contains invalid port $token"
    [[ -z ${observed[$token]:-} ]] || fail \
      "MTE_HOST_REQUIRED_TCP_PORTS contains duplicate port $token"
    observed[$token]=1
  done
}

if [[ ${EUID} -ne 0 ]]; then
  fail "run as root"
fi

if [[ ! -r /etc/os-release ]]; then
  fail "/etc/os-release is missing"
fi

if [[ ! -r $CONFIG ]]; then
  fail "canonical config is missing"
fi

DOCKER_APT_KEY_URL=$(canonical_value MTE_DOCKER_APT_KEY_URL)
DOCKER_APT_REPOSITORY_URL=$(canonical_value MTE_DOCKER_APT_REPOSITORY_URL)
DOCKER_APT_KEY_SHA256=$(canonical_value MTE_DOCKER_APT_KEY_SHA256)
DOCKER_APT_KEY_FINGERPRINT=$(canonical_value MTE_DOCKER_APT_KEY_FINGERPRINT)
DOCKER_CE_VERSION=$(canonical_value MTE_DOCKER_CE_VERSION)
DOCKER_CLI_VERSION=$(canonical_value MTE_DOCKER_CLI_VERSION)
CONTAINERD_IO_VERSION=$(canonical_value MTE_CONTAINERD_IO_VERSION)
DOCKER_COMPOSE_VERSION=$(canonical_value MTE_DOCKER_COMPOSE_VERSION)
DOCKER_ALLOW_PROVIDER_MIGRATION=$(canonical_value MTE_DOCKER_ALLOW_PROVIDER_MIGRATION)
DOCKER_UBUNTU_DOCKER_IO_VERSION=$(canonical_value MTE_DOCKER_UBUNTU_DOCKER_IO_VERSION)
DOCKER_UBUNTU_CONTAINERD_VERSION=$(canonical_value MTE_DOCKER_UBUNTU_CONTAINERD_VERSION)
DOCKER_UBUNTU_COMPOSE_VERSION=$(canonical_value MTE_DOCKER_UBUNTU_COMPOSE_VERSION)
HOST_REQUIRED_TCP_PORTS=$(canonical_value MTE_HOST_REQUIRED_TCP_PORTS)
MTE_CONTROL_NETWORK_SUBNET=$(canonical_value MTE_CONTROL_NETWORK_SUBNET)
MTE_CONTROL_NETWORK_GATEWAY=$(canonical_value MTE_CONTROL_NETWORK_GATEWAY)

require_https_url MTE_DOCKER_APT_KEY_URL "$DOCKER_APT_KEY_URL"
require_https_url MTE_DOCKER_APT_REPOSITORY_URL "$DOCKER_APT_REPOSITORY_URL"
require_sha256 MTE_DOCKER_APT_KEY_SHA256 "$DOCKER_APT_KEY_SHA256"
require_fingerprint "$DOCKER_APT_KEY_FINGERPRINT"
[[ $DOCKER_ALLOW_PROVIDER_MIGRATION == false ]] || fail \
  "MTE_DOCKER_ALLOW_PROVIDER_MIGRATION must remain false; provider migration requires a separate reviewed operation"
validate_required_ports "$HOST_REQUIRED_TCP_PORTS"

# shellcheck disable=SC1091
. /etc/os-release
if [[ -z ${ID+x} || -z ${VERSION_ID+x} || -z ${VERSION_CODENAME+x} ]]; then
  fail "/etc/os-release does not declare ID, VERSION_ID and VERSION_CODENAME"
fi
if [[ $ID != ubuntu || $VERSION_ID != 24.04 || $VERSION_CODENAME != noble ]]; then
  fail "only Ubuntu 24.04 noble is supported; got $ID $VERSION_ID $VERSION_CODENAME"
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl gpg rsync python3 python3-yaml

install -m 0755 -d /etc/apt/keyrings
docker_key=$(mktemp)
docker_sources=$(mktemp)
cleanup() {
  rm -f "$docker_key" "$docker_sources"
}
trap cleanup EXIT

curl -fsSL "$DOCKER_APT_KEY_URL" -o "$docker_key"
actual_key_sha256=$(sha256sum "$docker_key" | awk '{print $1}')
[[ $actual_key_sha256 == "$DOCKER_APT_KEY_SHA256" ]] || fail \
  "Docker APT key checksum mismatch"
actual_key_fingerprint=$(
  gpg --batch --show-keys --with-colons "$docker_key" \
    | awk -F: '$1 == "fpr" {print $10; exit}'
)
[[ $actual_key_fingerprint == "$DOCKER_APT_KEY_FINGERPRINT" ]] || fail \
  "Docker APT key fingerprint mismatch"
install -m 0644 "$docker_key" "$DOCKER_KEYRING"

architecture=$(dpkg --print-architecture)
printf '%s\n' \
  'Types: deb' \
  "URIs: $DOCKER_APT_REPOSITORY_URL" \
  'Suites: noble' \
  'Components: stable' \
  "Architectures: $architecture" \
  "Signed-By: $DOCKER_KEYRING" >"$docker_sources"
install -m 0644 "$docker_sources" "$DOCKER_SOURCES"
apt-get update -qq

docker_ce_installed=$(package_version docker-ce)
docker_io_installed=$(package_version docker.io)
fresh_docker_install=false
if [[ -n $docker_ce_installed && -n $docker_io_installed ]]; then
  fail "conflicting Docker package providers are installed"
fi

if [[ -n $docker_io_installed ]]; then
  # Existing shared hosts remain on Ubuntu's provider. Do not restart or
  # replace the daemon from this bootstrap path.
  require_package_version docker.io "$DOCKER_UBUNTU_DOCKER_IO_VERSION"
  require_package_version containerd "$DOCKER_UBUNTU_CONTAINERD_VERSION"
  require_available_package_version docker-compose-v2 "$DOCKER_UBUNTU_COMPOSE_VERSION"
  install_exact_packages \
    docker-compose-v2 "$DOCKER_UBUNTU_COMPOSE_VERSION"
  require_package_version docker-compose-v2 "$DOCKER_UBUNTU_COMPOSE_VERSION"
  docker_provider=ubuntu
elif [[ -n $docker_ce_installed ]]; then
  require_package_version docker-ce "$DOCKER_CE_VERSION"
  require_package_version docker-ce-cli "$DOCKER_CLI_VERSION"
  require_package_version containerd.io "$CONTAINERD_IO_VERSION"
  require_package_version docker-compose-plugin "$DOCKER_COMPOSE_VERSION"
  docker_provider=docker-ce
elif command -v docker >/dev/null 2>&1; then
  fail "Docker binary exists without a supported dpkg provider"
else
  fresh_docker_install=true
  for package_and_version in \
    "docker-ce=$DOCKER_CE_VERSION" \
    "docker-ce-cli=$DOCKER_CLI_VERSION" \
    "containerd.io=$CONTAINERD_IO_VERSION" \
    "docker-compose-plugin=$DOCKER_COMPOSE_VERSION"; do
    require_available_package_version \
      "${package_and_version%%=*}" "${package_and_version#*=}"
  done
  install_exact_packages \
    docker-ce "$DOCKER_CE_VERSION" \
    docker-ce-cli "$DOCKER_CLI_VERSION" \
    containerd.io "$CONTAINERD_IO_VERSION" \
    docker-compose-plugin "$DOCKER_COMPOSE_VERSION"
  require_package_version docker-ce "$DOCKER_CE_VERSION"
  require_package_version docker-ce-cli "$DOCKER_CLI_VERSION"
  require_package_version containerd.io "$CONTAINERD_IO_VERSION"
  require_package_version docker-compose-plugin "$DOCKER_COMPOSE_VERSION"
  docker_provider=docker-ce
fi

systemctl enable --now docker >/dev/null
docker info >/dev/null
docker compose version >/dev/null

# Port ownership is a clean-host precondition. Existing Docker hosts may have
# the explicitly migrated legacy deployment on these ports; the opt-in
# migration owns that cutover and must not be bypassed by host bootstrap.
if [[ $fresh_docker_install == true ]]; then
  IFS=',' read -r -a required_ports <<<"$HOST_REQUIRED_TCP_PORTS"
  for port in "${required_ports[@]}"; do
    if ss -H -lnt "sport = :${port}" | grep -q .; then
      fail "port $port is already in use"
    fi
  done
fi

# These bridges are intentionally shared by more than one Compose project.
# Create them outside project ownership and reject incompatible pre-existing
# networks rather than letting Compose silently claim or replace them.
for network in mte-data-plane mte-tool-runtime mte-tool-plane mte-agent-plane; do
  if ! docker network inspect "$network" >/dev/null 2>&1; then
    docker network create --driver bridge "$network" >/dev/null
  fi
  contract=$(docker network inspect --format \
    '{{.Name}} {{.Driver}} {{.Scope}} {{.Internal}}' "$network")
  [[ $contract == "$network bridge local false" ]] \
    || fail "incompatible shared network: $network"
done

# Paperclip is a host-managed runtime, while Kestra is Compose-managed. Their
# shared control bridge must therefore live outside either lifecycle owner.
if ! docker network inspect mte-control >/dev/null 2>&1; then
  docker network create --driver bridge \
    --subnet "$MTE_CONTROL_NETWORK_SUBNET" \
    --gateway "$MTE_CONTROL_NETWORK_GATEWAY" \
    mte-control >/dev/null
fi
control_contract=$(docker network inspect --format \
  '{{.Name}} {{.Driver}} {{.Scope}} {{.Internal}} {{(index .IPAM.Config 0).Subnet}} {{(index .IPAM.Config 0).Gateway}}' \
  mte-control)
[[ $control_contract == "mte-control bridge local false $MTE_CONTROL_NETWORK_SUBNET $MTE_CONTROL_NETWORK_GATEWAY" ]] \
  || fail "incompatible shared network: mte-control"

echo "host-bootstrap: Docker provider $docker_provider and Compose runtime ready"

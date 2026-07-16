#!/usr/bin/env bash
set -euo pipefail

DOKPLOY_VERSION="v0.29.12"
DOKPLOY_INSTALL_SHA256="f169b483cd03cd135b56db414cbdde99e818214702065c216804c454f6fe49e5"
DOKPLOY_INSTALL_URL="https://github.com/Dokploy/dokploy/releases/download/${DOKPLOY_VERSION}/install.sh"

if [[ ${EUID} -ne 0 ]]; then
  echo "host-bootstrap: run as root" >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  echo "host-bootstrap: /etc/os-release is missing" >&2
  exit 1
fi

# shellcheck disable=SC1091
. /etc/os-release
if [[ ${ID:-} != "ubuntu" ]]; then
  echo "host-bootstrap: only Ubuntu is supported; got ${ID:-unknown}" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl gpg rsync python3 python3-yaml

if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  cat >/etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${UBUNTU_CODENAME:-${VERSION_CODENAME}}
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

systemctl enable --now docker >/dev/null
docker info >/dev/null
docker compose version >/dev/null

if docker service inspect dokploy >/dev/null 2>&1; then
  echo "host-bootstrap: Docker and Dokploy already present"
  exit 0
fi

for port in 80 443 3000; do
  if ss -H -lnt "sport = :${port}" | grep -q .; then
    echo "host-bootstrap: port ${port} is already in use" >&2
    exit 1
  fi
done

installer=$(mktemp)
trap 'rm -f "$installer"' EXIT
curl -fsSL "$DOKPLOY_INSTALL_URL" -o "$installer"
actual=$(sha256sum "$installer" | awk '{print $1}')
if [[ "$actual" != "$DOKPLOY_INSTALL_SHA256" ]]; then
  echo "host-bootstrap: Dokploy installer checksum mismatch" >&2
  exit 1
fi
chmod 0700 "$installer"
DOKPLOY_VERSION="$DOKPLOY_VERSION" "$installer"

docker service inspect dokploy >/dev/null
echo "host-bootstrap: Docker ready; Dokploy ${DOKPLOY_VERSION} installed"

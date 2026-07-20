#!/usr/bin/env bash
set -euo pipefail


ACTION=${1:-install}
CANONICAL_ENV='/root/.config/mte-secrets/platform.env'
[[ -r "$CANONICAL_ENV" ]] || { echo "paperclip-runtime: canonical platform.env missing" >&2; exit 2; }

canonical_value() {
  python3 - "$CANONICAL_ENV" "$1" <<'PY'
from pathlib import Path
import sys
key = sys.argv[2]
for line in Path(sys.argv[1]).read_text().splitlines():
    if line.startswith(key + "="):
        value = line.split("=", 1)[1]
        if value:
            print(value)
            raise SystemExit(0)
raise SystemExit(2)
PY
}

canonical_optional() {
  python3 - "$CANONICAL_ENV" "$1" <<'PY'
from pathlib import Path
import sys
key = sys.argv[2]
for line in Path(sys.argv[1]).read_text().splitlines():
    if line.startswith(key + "="):
        print(line.split("=", 1)[1])
        break
PY
}

PAPERCLIP_IMAGE=$(canonical_value MTE_PAPERCLIP_IMAGE)
PAPERCLIP_FORK_SOURCE_URL=$(canonical_value MTE_PAPERCLIP_FORK_SOURCE_URL)
PAPERCLIP_FORK_REVISION=$(canonical_value MTE_PAPERCLIP_FORK_REVISION)
PAPERCLIP_PORT=$(canonical_value PAPERCLIP_PORT)
PAPERCLIP_CPU_LIMIT=$(canonical_value PAPERCLIP_CPU_LIMIT)
PAPERCLIP_MEMORY_LIMIT=$(canonical_value PAPERCLIP_MEMORY_LIMIT)
PAPERCLIP_PIDS_LIMIT=$(canonical_value PAPERCLIP_PIDS_LIMIT)
PAPERCLIP_LOG_MAX_SIZE=$(canonical_value MTE_DOCKER_LOG_MAX_SIZE)
PAPERCLIP_LOG_MAX_FILES=$(canonical_value MTE_DOCKER_LOG_MAX_FILES)
PAPERCLIP_DEPLOYMENT_MODE=$(canonical_value PAPERCLIP_DEPLOYMENT_MODE)
PAPERCLIP_DEPLOYMENT_EXPOSURE=$(canonical_value PAPERCLIP_DEPLOYMENT_EXPOSURE)
PAPERCLIP_PUBLIC_URL=$(canonical_optional PAPERCLIP_PUBLIC_URL)
PAPERCLIP_AGENT_JWT_SECRET=$(canonical_optional PAPERCLIP_AGENT_JWT_SECRET)
PAPERCLIP_CONTAINER_HOST=$(canonical_value PAPERCLIP_CONTAINER_HOST)
PAPERCLIP_DAYTONA_UPSTREAM_URL=$(canonical_value PAPERCLIP_DAYTONA_UPSTREAM_URL)
PAPERCLIP_DAYTONA_PLUGIN_VERSION=$(canonical_value DAYTONA_PLUGIN_VERSION)
PAPERCLIP_DAYTONA_SDK_VERSION=$(canonical_value PAPERCLIP_DAYTONA_SDK_VERSION)
PAPERCLIP_AWS_S3_CLIENT_VERSION=$(canonical_value PAPERCLIP_AWS_S3_CLIENT_VERSION)
PAPERCLIP_DAYTONA_API_SERVICE='mte-daytona-api'
PAPERCLIP_DAYTONA_PROXY_SERVICE='mte-daytona-proxy'
PAPERCLIP_DAYTONA_NETWORK=$(canonical_value MTE_DAYTONA_PAPERCLIP_NETWORK)
PAPERCLIP_DAYTONA_INTERNAL_NETWORK=$(canonical_value MTE_DAYTONA_NETWORK)
PAPERCLIP_LEGACY_PORT=$(canonical_value PAPERCLIP_LEGACY_PORT)
: "${PAPERCLIP_IMAGE:?missing MTE_PAPERCLIP_IMAGE}"
[[ "$PAPERCLIP_IMAGE" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] || {
  echo "paperclip-runtime: MTE_PAPERCLIP_IMAGE must be an immutable digest-pinned image" >&2
  exit 2
}
python3 - "$PAPERCLIP_FORK_SOURCE_URL" "$PAPERCLIP_FORK_REVISION" <<'PY'
import re
import sys
from urllib.parse import urlsplit

source_url, revision = sys.argv[1:]
try:
    parsed = urlsplit(source_url)
    port = parsed.port
except ValueError:
    raise SystemExit("paperclip-runtime: MTE_PAPERCLIP_FORK_SOURCE_URL must be a canonical HTTPS source URL")
segments = parsed.path.split("/")
if (
    source_url != source_url.strip()
    or not source_url.startswith("https://")
    or parsed.scheme != "https"
    or not parsed.hostname
    or parsed.hostname != parsed.hostname.lower()
    or parsed.username
    or parsed.password
    or port is not None
    or parsed.query
    or parsed.fragment
    or not parsed.path.startswith("/")
    or parsed.path.endswith("/")
    or any(segment in {"", ".", ".."} for segment in segments[1:])
):
    raise SystemExit(
        "paperclip-runtime: MTE_PAPERCLIP_FORK_SOURCE_URL must be a canonical HTTPS source URL "
        "(lowercase host; no credentials, port, query, fragment, trailing slash, or dot segments)"
    )
if not re.fullmatch(r"[0-9a-f]{40}", revision):
    raise SystemExit(
        "paperclip-runtime: MTE_PAPERCLIP_FORK_REVISION must be an immutable lowercase 40-character commit"
    )
PY
: "${PAPERCLIP_LOG_MAX_SIZE:?missing MTE_DOCKER_LOG_MAX_SIZE}"
: "${PAPERCLIP_LOG_MAX_FILES:?missing MTE_DOCKER_LOG_MAX_FILES}"
EVIDENCE_ROOT='/opt/mte-platform/evidence'
RUNTIME_ROOT='/opt/mte-platform/runtime/paperclip'
PROFILE_RUNTIME='/opt/mte-platform/runtime/profiles/profiles.yaml'
SCRIPT_PATH=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}")
PRODUCER_SHA256=$(sha256sum "$SCRIPT_PATH" | awk '{print $1}')
: "${PAPERCLIP_PORT:?missing PAPERCLIP_PORT}"
LEGACY_PAPERCLIP_PORT=$PAPERCLIP_LEGACY_PORT
PAPERCLIP_AUTH_SECRET_FILE='/root/.config/mte-secrets/paperclip-runtime/agent-jwt-secret'
PAPERCLIP_CONTROL_NETWORK='mte-control'
PAPERCLIP_PRIVATE_ROUTE_EVIDENCE="$EVIDENCE_ROOT/paperclip-private-route.json"
VERIFIED_PAPERCLIP_IMAGE_ID=''

validate_deployment_contract() {
  case "$PAPERCLIP_DEPLOYMENT_MODE" in
    local_trusted)
      [[ "$PAPERCLIP_DEPLOYMENT_EXPOSURE" == private ]] || {
        echo "paperclip-runtime: local_trusted requires private exposure" >&2
        exit 2
      }
      ;;
    authenticated)
      [[ "$PAPERCLIP_DEPLOYMENT_EXPOSURE" == private || "$PAPERCLIP_DEPLOYMENT_EXPOSURE" == public ]] || {
        echo "paperclip-runtime: authenticated exposure must be private or public" >&2
        exit 2
      }
      [[ ${#PAPERCLIP_AGENT_JWT_SECRET} -ge 32 ]] || {
        echo "paperclip-runtime: authenticated mode requires PAPERCLIP_AGENT_JWT_SECRET (at least 32 characters)" >&2
        exit 2
      }
      if [[ "$PAPERCLIP_DEPLOYMENT_EXPOSURE" == public ]]; then
        [[ "$PAPERCLIP_PUBLIC_URL" =~ ^https://[^[:space:]]+$ ]] || {
          echo "paperclip-runtime: authenticated public mode requires HTTPS PAPERCLIP_PUBLIC_URL" >&2
          exit 2
        }
      fi
      ;;
    *)
      echo "paperclip-runtime: PAPERCLIP_DEPLOYMENT_MODE must be local_trusted or authenticated" >&2
      exit 2
      ;;
  esac
}

verify_registry_image_available() {
  docker manifest inspect "$PAPERCLIP_IMAGE" >/dev/null || {
    echo "paperclip-runtime: immutable MTE_PAPERCLIP_IMAGE is unavailable from the registry" >&2
    return 2
  }
}

verify_image_abi() {
  local config
  config=$(docker image inspect --format '{{json .Config}}' "$PAPERCLIP_IMAGE") || {
    echo "paperclip-runtime: MTE_PAPERCLIP_IMAGE is not present locally" >&2
    return 2
  }
  python3 - "$config" "$PAPERCLIP_FORK_SOURCE_URL" "$PAPERCLIP_FORK_REVISION" <<'PY'
import json
import sys

config = json.loads(sys.argv[1])
expected_source, expected_revision = sys.argv[2:]
entrypoint = config.get("Entrypoint") or []
command = config.get("Cmd") or []
labels = config.get("Labels") or {}
if entrypoint != ["docker-entrypoint.sh"]:
    raise SystemExit("paperclip-runtime: immutable image native entrypoint ABI drifted")
if command != ["node", "dist/index.js"]:
    raise SystemExit("paperclip-runtime: immutable image native command ABI drifted")
if labels.get("org.opencontainers.image.source") != expected_source:
    raise SystemExit("paperclip-runtime: immutable image source label drifted")
if labels.get("org.opencontainers.image.revision") != expected_revision:
    raise SystemExit("paperclip-runtime: immutable image revision label drifted")
PY
  docker run --rm --network none "$PAPERCLIP_IMAGE" node -e '
    const fs = require("node:fs");
    const path = require("node:path");
    const expected = new Map([
      ["@paperclipai/plugin-daytona", process.argv[1]],
      ["@daytonaio/sdk", process.argv[2]],
      ["@aws-sdk/client-s3", process.argv[3]],
    ]);
    if (!fs.existsSync("/app/server/dist/index.js")) {
      throw new Error("Paperclip server entrypoint is missing");
    }
    for (const [name, expectedVersion] of expected) {
      let current = path.dirname(require.resolve(name));
      while (current !== path.dirname(current)) {
        const manifestPath = path.join(current, "package.json");
        if (fs.existsSync(manifestPath)) {
          const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
          if (manifest.name === name) {
            if (manifest.version !== expectedVersion) {
              throw new Error(`${name} version drifted: expected ${expectedVersion}, got ${manifest.version}`);
            }
            break;
          }
        }
        current = path.dirname(current);
      }
      if (current === path.dirname(current)) {
        throw new Error(`${name} package manifest is missing`);
      }
    }
  ' "$PAPERCLIP_DAYTONA_PLUGIN_VERSION" "$PAPERCLIP_DAYTONA_SDK_VERSION" \
    "$PAPERCLIP_AWS_S3_CLIENT_VERSION" || {
    echo "paperclip-runtime: immutable image is missing the required Paperclip/Daytona ABI" >&2
    return 2
  }
}

pull_and_verify_image() {
  docker pull "$PAPERCLIP_IMAGE" >/dev/null || {
    echo "paperclip-runtime: failed to pull immutable MTE_PAPERCLIP_IMAGE" >&2
    return 2
  }
  verify_image_abi
}

verify_running_image_binding() {
  local canonical_image_id container_image_id container_image_ref
  canonical_image_id=$(docker image inspect --format '{{.Id}}' "$PAPERCLIP_IMAGE") || {
    echo "paperclip-runtime: cannot resolve canonical MTE_PAPERCLIP_IMAGE ID" >&2
    return 2
  }
  container_image_ref=$(docker inspect --format '{{.Config.Image}}' mte-paperclip) || {
    echo "paperclip-runtime: running Paperclip container is missing" >&2
    return 2
  }
  container_image_id=$(docker inspect --format '{{.Image}}' mte-paperclip) || {
    echo "paperclip-runtime: running Paperclip container image ID is unavailable" >&2
    return 2
  }
  if [[ "$container_image_ref" != "$PAPERCLIP_IMAGE" ]]; then
    echo "paperclip-runtime: running container image reference does not match MTE_PAPERCLIP_IMAGE" >&2
    return 2
  fi
  if [[ "$container_image_id" != "$canonical_image_id" ]]; then
    echo "paperclip-runtime: running container image ID does not match MTE_PAPERCLIP_IMAGE" >&2
    return 2
  fi
  VERIFIED_PAPERCLIP_IMAGE_ID=$canonical_image_id
}

reconcile_auth_secret_projection() {
  if [[ "$PAPERCLIP_DEPLOYMENT_MODE" != authenticated ]]; then
    rm -f "$PAPERCLIP_AUTH_SECRET_FILE"
    return 0
  fi
  local directory temporary
  directory=$(dirname "$PAPERCLIP_AUTH_SECRET_FILE")
  install -d -m 0700 -o root -g root "$directory"
  temporary=$(mktemp "$directory/.paperclip-env.XXXXXX")
  printf 'PAPERCLIP_AGENT_JWT_SECRET=%s\n' "$PAPERCLIP_AGENT_JWT_SECRET" >"$temporary"
  chmod 0400 "$temporary"
  chown 1000:1000 "$temporary"
  mv -f "$temporary" "$PAPERCLIP_AUTH_SECRET_FILE"
}

wait_http() {
  local url=$1
  local attempts=${2:-90}
  for ((i=1; i<=attempts; i++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  echo "paperclip-runtime: timeout waiting for ${url}" >&2
  return 1
}

validate_daytona_route_urls() {
  python3 - "$PAPERCLIP_DAYTONA_UPSTREAM_URL" "$PAPERCLIP_DAYTONA_API_SERVICE" <<'PY'
from urllib.parse import urlsplit
import sys

upstream = urlsplit(sys.argv[1])
expected_upstream_host = sys.argv[2]
if upstream.scheme != "http" or not upstream.hostname or upstream.port is None:
    raise SystemExit("paperclip-runtime: PAPERCLIP_DAYTONA_UPSTREAM_URL must use HTTP Docker DNS with an explicit port")
if any((upstream.username, upstream.password, upstream.query, upstream.fragment)):
    raise SystemExit("paperclip-runtime: PAPERCLIP_DAYTONA_UPSTREAM_URL must not contain credentials, query, or fragment")
if upstream.path.rstrip("/") != "/api":
    raise SystemExit("paperclip-runtime: PAPERCLIP_DAYTONA_UPSTREAM_URL must end in /api")
if upstream.hostname != expected_upstream_host:
    raise SystemExit("paperclip-runtime: PAPERCLIP_DAYTONA_UPSTREAM_URL host must be the reviewed Daytona API service")
PY
}

validate_private_route_contract() {
  docker network inspect "$PAPERCLIP_CONTROL_NETWORK" >/dev/null
  docker network inspect "$PAPERCLIP_DAYTONA_NETWORK" >/dev/null
  validate_daytona_route_urls
  python3 - "$PAPERCLIP_CONTAINER_HOST" <<'PY'
import re
import sys

hostname = sys.argv[1]
if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", hostname):
    raise SystemExit("paperclip-runtime: PAPERCLIP_CONTAINER_HOST is not a safe hostname")
PY
}

daytona_non_api_targets() {
  python3 - "$PAPERCLIP_DAYTONA_INTERNAL_NETWORK" "$1" <<'PY'
import json
import subprocess
import sys

network, mode = sys.argv[1:]
targets = (
    ("mte-daytona-db", 5432),
    ("mte-daytona-redis", 6379),
    ("mte-daytona-registry", 6000),
    ("mte-daytona-minio", 9000),
    ("mte-daytona-dex", 5556),
    ("mte-daytona-runner", 3003),
    ("mte-daytona-ssh-gateway", 2222),
)
result = []
for name, port in targets:
    inspected = subprocess.run(
        ["docker", "inspect", name], capture_output=True, text=True, check=False
    )
    if inspected.returncode:
        if mode == "strict":
            raise SystemExit(f"paperclip-runtime: missing Daytona isolation target {name}")
        continue
    container = json.loads(inspected.stdout)[0]
    endpoint = (container.get("NetworkSettings", {}).get("Networks", {}).get(network) or {})
    address = endpoint.get("IPAddress")
    if not address:
        raise SystemExit(f"paperclip-runtime: {name} is missing internal network {network}")
    result.append({"name": name, "host": address, "port": port})
if mode == "strict" and len(result) != len(targets):
    raise SystemExit("paperclip-runtime: incomplete Daytona non-API isolation inventory")
print(json.dumps(result, separators=(",", ":")))
PY
}

verify_private_route() {
  local mode=${1:-strict}
  local canonical_sha daytona_checked=false denied_target_count=0 denied_targets
  local kestra_container kestra_checked=false route_status=configured
  [[ "$mode" == strict || "$mode" == allow-daytona-pending ]] || {
    echo "paperclip-runtime: invalid private-route verification mode: $mode" >&2
    return 2
  }
  validate_private_route_contract
  python3 - "$PAPERCLIP_CONTROL_NETWORK" "$PAPERCLIP_CONTAINER_HOST" \
    "$PAPERCLIP_PORT" "$PAPERCLIP_DAYTONA_NETWORK" \
    "$PAPERCLIP_DAYTONA_API_SERVICE" "$PAPERCLIP_DAYTONA_PROXY_SERVICE" "$mode" \
    "$PAPERCLIP_LOG_MAX_SIZE" "$PAPERCLIP_LOG_MAX_FILES" <<'PY'
import json
import subprocess
import sys

(
    control_network,
    hostname,
    port,
    daytona_network,
    daytona_api_service,
    daytona_proxy_service,
    mode,
    log_max_size,
    log_max_files,
) = sys.argv[1:]
container = json.loads(subprocess.check_output(["docker", "inspect", "mte-paperclip"]))[0]
host = container["HostConfig"]
if host["NetworkMode"] != control_network:
    raise SystemExit("paperclip-runtime: Paperclip is not on the private control network")
expected_binding = {f"{port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": port}]}
if host.get("PortBindings") != expected_binding:
    raise SystemExit("paperclip-runtime: Paperclip port is not bound exclusively to host loopback")
if host.get("ExtraHosts"):
    raise SystemExit("paperclip-runtime: Paperclip must not have host-gateway aliases")
expected_log_config = {
    "Type": "json-file",
    "Config": {"max-size": log_max_size, "max-file": log_max_files},
}
if host.get("LogConfig") != expected_log_config:
    raise SystemExit("paperclip-runtime: Paperclip Docker log rotation drift")
networks = container["NetworkSettings"]["Networks"]
if set(networks) != {control_network, daytona_network}:
    raise SystemExit("paperclip-runtime: Paperclip network membership is not exact")
aliases = networks[control_network].get("Aliases") or []
if hostname not in aliases:
    raise SystemExit("paperclip-runtime: Paperclip private service alias is missing")
network = json.loads(subprocess.check_output(["docker", "network", "inspect", daytona_network]))[0]
members = {entry["Name"] for entry in (network.get("Containers") or {}).values()}
expected = (
    {"mte-paperclip", daytona_api_service, daytona_proxy_service}
    if mode == "strict"
    else {"mte-paperclip"}
)
if mode != "strict":
    for service in (daytona_api_service, daytona_proxy_service):
        if service in members:
            expected.add(service)
if members != expected:
    raise SystemExit(
        f"paperclip-runtime: API-only network membership drift: expected {sorted(expected)}, got {sorted(members)}"
    )
PY

  docker run --rm --network "$PAPERCLIP_CONTROL_NETWORK" \
    "$PAPERCLIP_IMAGE" node -e '
      const url = process.argv[1];
      fetch(url, {signal: AbortSignal.timeout(5000)})
        .then((response) => {
          if (!response.ok) throw new Error(`unexpected HTTP ${response.status}`);
        })
        .catch((error) => { console.error(error); process.exit(1); });
    ' "http://${PAPERCLIP_CONTAINER_HOST}:${PAPERCLIP_PORT}/api/health"

  denied_targets=$(daytona_non_api_targets "$mode")
  denied_target_count=$(python3 -c 'import json,sys; print(len(json.loads(sys.argv[1])))' "$denied_targets")
  docker exec mte-paperclip node -e '
    const net = require("node:net");
    const targets = JSON.parse(process.argv[1]);
    const deny = ({name, host, port}) => new Promise((resolve, reject) => {
      const socket = net.connect({host, port});
      const closeDenied = () => { socket.destroy(); resolve(); };
      socket.setTimeout(1500, closeDenied);
      socket.once("error", closeDenied);
      socket.once("connect", () => {
        socket.destroy();
        reject(new Error(`Paperclip unexpectedly reached ${name} at ${host}:${port}`));
      });
    });
    Promise.all(targets.map(deny)).catch((error) => {
      console.error(error.message);
      process.exit(1);
    });
  ' "$denied_targets"

  if docker inspect --format '{{.State.Running}}' "$PAPERCLIP_DAYTONA_API_SERVICE" \
    2>/dev/null | grep -Fx true >/dev/null; then
    docker exec mte-paperclip node -e '
      const url = process.argv[1];
      fetch(url, {signal: AbortSignal.timeout(5000)})
        .then((response) => {
          if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
        })
        .catch((error) => { console.error(error); process.exit(1); });
    ' "${PAPERCLIP_DAYTONA_UPSTREAM_URL%/}/config"
    daytona_checked=true
    if [[ "$denied_target_count" == 7 ]]; then
      route_status=ready
    fi
  elif [[ "$mode" == strict ]]; then
    echo "paperclip-runtime: Daytona API is required for strict private-route verification" >&2
    return 1
  fi

  kestra_container=$(docker ps --format '{{.ID}} {{.Names}}' \
    | awk '$2 ~ /kestra/ && $2 !~ /(storage-init|postgres)/ {print $1; exit}')
  if [[ -n "$kestra_container" ]]; then
    local kestra_status
    kestra_status=$(docker exec "$kestra_container" curl -sS --max-time 5 \
      -o /dev/null -w '%{http_code}' \
      "http://${PAPERCLIP_CONTAINER_HOST}:${PAPERCLIP_PORT}/api/health")
    [[ "$kestra_status" =~ ^2[0-9]{2}$ ]]
    kestra_checked=true
  fi

  canonical_sha=$(sha256sum "$CANONICAL_ENV" | awk '{print $1}')
  python3 - "$PAPERCLIP_PRIVATE_ROUTE_EVIDENCE" "$PAPERCLIP_CONTROL_NETWORK" \
    "$PAPERCLIP_DAYTONA_NETWORK" "$PAPERCLIP_CONTAINER_HOST" "$PAPERCLIP_PORT" \
    "$PAPERCLIP_DAYTONA_UPSTREAM_URL" "$daytona_checked" "$kestra_checked" \
    "$route_status" "$denied_target_count" "$canonical_sha" \
    "$SCRIPT_PATH" "$PRODUCER_SHA256" <<'PY'
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
(
    control_network,
    daytona_network,
    hostname,
    port,
    upstream_url,
    daytona_checked,
    kestra_checked,
    route_status,
    denied_target_count,
    canonical_sha,
    producer_path,
    producer_sha,
) = sys.argv[2:]
payload = {
    "apiVersion": "micro-task-engine/v1alpha1",
    "kind": "PaperclipPrivateRouteVerification",
    "status": route_status,
    "observedAt": datetime.now(timezone.utc).isoformat(),
    "canonicalEnvironmentSha256": canonical_sha,
    "producerPath": producer_path,
    "producerSha256": producer_sha,
    "route": {
        "networks": [control_network, daytona_network],
        "hostname": hostname,
        "port": int(port),
        "hostBinding": "127.0.0.1",
        "daytonaUpstreamUrl": upstream_url,
        "publicListener": False,
        "hostGatewayListener": False,
        "extraProxyContainer": False,
    },
    "checks": {
        "disposableControlNetworkClient": True,
        "kestraContainer": kestra_checked == "true",
        "hostBindingLoopbackOnly": True,
        "privateServiceAlias": True,
        "daytonaApiReachable": daytona_checked == "true",
        "daytonaDockerDnsRouteConfigured": True,
        "daytonaNonApiServicesUnreachable": int(denied_target_count) == 7,
        "daytonaNonApiTargetsChecked": int(denied_target_count),
        "daytonaApiNetworkMembershipExact": True,
        "exactNetworkMembership": True,
    },
}
temporary = path.with_suffix(".json.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.chmod(0o600)
temporary.replace(path)
path.chmod(0o600)
print(json.dumps({"paperclipPrivateRoute": route_status, "evidence": str(path)}))
PY
}

ensure_sources() {
  for path in \
    scripts/bootstrap-paperclip.py \
    scripts/profile_catalog.py; do
    [[ -r "$RUNTIME_ROOT/$path" ]] || { echo "paperclip-runtime: missing $RUNTIME_ROOT/$path" >&2; exit 2; }
  done
  [[ -r "$PROFILE_RUNTIME" ]] || { echo "paperclip-runtime: missing $PROFILE_RUNTIME" >&2; exit 2; }
  python3 - "$PROFILE_RUNTIME" "$RUNTIME_ROOT/profiles" <<'PY'
from pathlib import Path
import sys

import yaml

catalog = yaml.safe_load(Path(sys.argv[1]).read_text())
root = Path(sys.argv[2]).resolve()
profiles = catalog.get("profiles") if isinstance(catalog, dict) else None
if not isinstance(profiles, list) or not profiles:
    raise SystemExit("paperclip-runtime: profile catalog has no profiles")
for profile in profiles:
    ref = profile.get("instructions") if isinstance(profile, dict) else None
    if not isinstance(ref, str) or not ref:
        raise SystemExit("paperclip-runtime: profile instructions ref missing")
    path = (root / ref).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise SystemExit(f"paperclip-runtime: missing instruction bundle entry {ref}")
PY
}

paperclip_config_port() {
  docker run --rm --user 1000:1000 \
    -v mte-paperclip-native-data:/data \
    "$PAPERCLIP_IMAGE" node -e '
      const fs = require("node:fs");
      const path = "/data/instances/default/config.json";
      if (!fs.existsSync(path)) process.exit(3);
      const value = JSON.parse(fs.readFileSync(path, "utf8"));
      process.stdout.write(String(value?.server?.port ?? ""));
    '
}

reconcile_paperclip_config() {
  mkdir -p "$EVIDENCE_ROOT"
  docker volume create mte-paperclip-native-data >/dev/null
  docker run --rm --user 0:0 \
    -v mte-paperclip-native-data:/data \
    -v "$EVIDENCE_ROOT:/evidence" \
    "$PAPERCLIP_IMAGE" node -e '
      const fs = require("node:fs");
      const path = "/data/instances/default/config.json";
      const evidencePath = "/evidence/paperclip-runtime-config-migration.json";
      const desiredPort = Number(process.argv[1]);
      const deploymentMode = process.argv[2];
      const exposure = process.argv[3];
      const publicBaseUrl = process.argv[4] || "";
      const found = fs.existsSync(path);
      let before = null;
      if (found) {
        const stat = fs.statSync(path);
        const value = JSON.parse(fs.readFileSync(path, "utf8"));
        before = {
          paperclipPort: value?.server?.port ?? null,
          paperclipBind: value?.server?.bind ?? null,
          paperclipHost: value?.server?.host ?? null,
          deploymentMode: value?.server?.deploymentMode ?? null,
          exposure: value?.server?.exposure ?? null,
          authBaseUrlMode: value?.auth?.baseUrlMode ?? null,
          authPublicBaseUrl: value?.auth?.publicBaseUrl ?? null,
          secretsStrictMode: value?.secrets?.strictMode ?? null,
        };
        value.server = {
          ...(value.server ?? {}),
          deploymentMode,
          exposure,
          bind: "lan",
          host: "0.0.0.0",
          port: desiredPort,
        };
        value.auth = {
          ...(value.auth ?? {}),
          baseUrlMode: exposure === "public" ? "explicit" : "auto",
        };
        if (exposure === "public") value.auth.publicBaseUrl = publicBaseUrl;
        else delete value.auth.publicBaseUrl;
        value.secrets = { ...(value.secrets ?? {}), strictMode: true };
        value.$meta = { ...(value.$meta ?? {}), updatedAt: new Date().toISOString(), source: "configure" };
        const tmp = `${path}.tmp`;
        fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: stat.mode & 0o777 });
        fs.chownSync(tmp, stat.uid, stat.gid);
        fs.renameSync(tmp, path);
      }
      const desired = {
        paperclipPort: desiredPort,
        paperclipBind: "lan",
        paperclipHost: "0.0.0.0",
        deploymentMode,
        exposure,
        authBaseUrlMode: exposure === "public" ? "explicit" : "auto",
        authPublicBaseUrl: exposure === "public" ? publicBaseUrl : null,
        secretsStrictMode: true,
      };
      const payload = {
        apiVersion: "micro-task-engine/v1alpha1",
        kind: "PaperclipRuntimeConfigMigration",
        status: "ready",
        observedAt: new Date().toISOString(),
        configPath: path,
        configFound: found,
        desired,
        before,
        after: found ? desired : null,
        changed: found && (
          before.paperclipPort !== desiredPort
          || before.paperclipBind !== desired.paperclipBind
          || before.paperclipHost !== desired.paperclipHost
          || before.deploymentMode !== deploymentMode
          || before.exposure !== exposure
          || before.authBaseUrlMode !== desired.authBaseUrlMode
          || before.authPublicBaseUrl !== desired.authPublicBaseUrl
          || before.secretsStrictMode !== true
        ),
      };
      const evidenceTmp = `${evidencePath}.tmp`;
      fs.writeFileSync(evidenceTmp, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
      fs.renameSync(evidenceTmp, evidencePath);
      fs.chmodSync(evidencePath, 0o600);
      process.stdout.write(JSON.stringify({
        paperclipRuntimeConfig: found ? "reconciled" : "pending-first-onboard",
        desired,
        configFound: found,
        changed: payload.changed,
        evidence: evidencePath,
      }) + "\n");
    ' "$PAPERCLIP_PORT" "$PAPERCLIP_DEPLOYMENT_MODE" \
      "$PAPERCLIP_DEPLOYMENT_EXPOSURE" "$PAPERCLIP_PUBLIC_URL"
}

paperclip_config_strict_mode() {
  docker run --rm --user 1000:1000 \
    -v mte-paperclip-native-data:/data \
    "$PAPERCLIP_IMAGE" node -e '
      const fs = require("node:fs");
      const path = "/data/instances/default/config.json";
      if (!fs.existsSync(path)) process.exit(3);
      const value = JSON.parse(fs.readFileSync(path, "utf8"));
      process.stdout.write(String(value?.secrets?.strictMode === true));
    '
}

paperclip_config_contract_value() {
  docker run --rm --user 1000:1000 \
    -v mte-paperclip-native-data:/data \
    "$PAPERCLIP_IMAGE" node -e '
      const fs = require("node:fs");
      const value = JSON.parse(fs.readFileSync("/data/instances/default/config.json", "utf8"));
      const fields = {
        deploymentMode: value?.server?.deploymentMode ?? "",
        exposure: value?.server?.exposure ?? "",
        authBaseUrlMode: value?.auth?.baseUrlMode ?? "",
        authPublicBaseUrl: value?.auth?.publicBaseUrl ?? "",
      };
      process.stdout.write(String(fields[process.argv[1]] ?? ""));
    ' "$1"
}

paperclip_hostname_allowed() {
  docker exec mte-paperclip node -e '
    const fs = require("node:fs");
    const config = JSON.parse(fs.readFileSync("/data/instances/default/config.json", "utf8"));
    const allowed = config?.server?.allowedHostnames;
    process.exit(Array.isArray(allowed) && allowed.includes(process.argv[1]) ? 0 : 1);
  ' "$PAPERCLIP_CONTAINER_HOST"
}

reconcile_paperclip_allowed_hostname() {
  reconcile_paperclip_config >/dev/null
  if docker inspect mte-paperclip >/dev/null 2>&1; then
    docker restart mte-paperclip >/dev/null
    wait_http "http://127.0.0.1:${PAPERCLIP_PORT}/api/health"
  fi
  paperclip_hostname_allowed
}

write_runtime_verify_evidence() {
  local temporary
  install -d -m 0700 "$EVIDENCE_ROOT"
  temporary=$(mktemp "$EVIDENCE_ROOT/.paperclip-runtime-config-verify.XXXXXX")
  python3 - "$temporary" "$PAPERCLIP_IMAGE" "$VERIFIED_PAPERCLIP_IMAGE_ID" \
    "$PAPERCLIP_PORT" \
    "$PAPERCLIP_DEPLOYMENT_MODE" "$PAPERCLIP_DEPLOYMENT_EXPOSURE" \
    "$PAPERCLIP_DAYTONA_UPSTREAM_URL" <<'PY'
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
image, image_id, port, mode, exposure, daytona_url = sys.argv[2:]
payload = {
    "apiVersion": "micro-task-engine/v1alpha1",
    "kind": "PaperclipRuntimeConfigVerification",
    "status": "ready",
    "observedAt": datetime.now(timezone.utc).isoformat(),
    "runtime": {
        "image": image,
        "imageId": image_id,
        "entrypoint": "native-image-cmd",
        "home": "/data",
        "bind": "lan",
        "port": int(port),
        "deploymentMode": mode,
        "exposure": exposure,
        "daytonaUpstreamUrl": daytona_url,
        "deployTimePackageMutation": False,
    },
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\\n")
path.chmod(0o600)
PY
  mv -f "$temporary" "$EVIDENCE_ROOT/paperclip-runtime-config-verify.json"
  echo '{"paperclipRuntimeConfig":"ready"}'
}

start_paperclip_container() {
  local -a secret_mount=()
  validate_private_route_contract
  if [[ "$PAPERCLIP_DEPLOYMENT_MODE" == authenticated ]]; then
    secret_mount=(-v "$PAPERCLIP_AUTH_SECRET_FILE:/data/instances/default/.env:ro")
  fi
  docker create \
    --name mte-paperclip \
    --restart unless-stopped \
    --network "$PAPERCLIP_CONTROL_NETWORK" \
    --network-alias "$PAPERCLIP_CONTAINER_HOST" \
    --publish "127.0.0.1:${PAPERCLIP_PORT}:${PAPERCLIP_PORT}" \
    --user 1000:1000 \
    --cpus "${PAPERCLIP_CPU_LIMIT:?missing PAPERCLIP_CPU_LIMIT}" \
    --memory "${PAPERCLIP_MEMORY_LIMIT:?missing PAPERCLIP_MEMORY_LIMIT}" \
    --pids-limit "${PAPERCLIP_PIDS_LIMIT:?missing PAPERCLIP_PIDS_LIMIT}" \
    --log-driver json-file \
    --log-opt "max-size=${PAPERCLIP_LOG_MAX_SIZE}" \
    --log-opt "max-file=${PAPERCLIP_LOG_MAX_FILES}" \
    --security-opt no-new-privileges:true \
    -e HOME=/data \
    -e PAPERCLIP_HOME=/data \
    -e PAPERCLIP_INSTANCE_ID=default \
    -e PAPERCLIP_CONFIG=/data/instances/default/config.json \
    -e HOST=0.0.0.0 \
    -e PORT="$PAPERCLIP_PORT" \
    -e PAPERCLIP_BIND=lan \
    -e PAPERCLIP_ALLOWED_HOSTNAMES="$PAPERCLIP_CONTAINER_HOST" \
    -e PAPERCLIP_LISTEN_PORT="$PAPERCLIP_PORT" \
    -e PAPERCLIP_SECRETS_STRICT_MODE=true \
    -e PAPERCLIP_DEPLOYMENT_MODE="$PAPERCLIP_DEPLOYMENT_MODE" \
    -e PAPERCLIP_DEPLOYMENT_EXPOSURE="$PAPERCLIP_DEPLOYMENT_EXPOSURE" \
    -e PAPERCLIP_PUBLIC_URL="$PAPERCLIP_PUBLIC_URL" \
    -e PAPERCLIP_DAYTONA_UPSTREAM_URL="$PAPERCLIP_DAYTONA_UPSTREAM_URL" \
    -v mte-paperclip-native-data:/data \
    -v mte-paperclip-native-workspaces:/workspaces \
    -v mte-9router-data:/ninerouter-data:ro \
    "${secret_mount[@]}" \
    "$PAPERCLIP_IMAGE" >/dev/null
  docker network connect "$PAPERCLIP_DAYTONA_NETWORK" mte-paperclip
  docker start mte-paperclip >/dev/null
}

install_runtime() {
  validate_deployment_contract
  pull_and_verify_image
  reconcile_auth_secret_projection
  ensure_sources
  for volume in mte-paperclip-native-data mte-paperclip-native-workspaces; do
    docker volume create "$volume" >/dev/null
  done
  docker run --rm --user 0:0 \
    -v mte-paperclip-native-data:/data \
    -v mte-paperclip-native-workspaces:/workspaces \
    "$PAPERCLIP_IMAGE" sh -ceu \
      'mkdir -p /data/instances/default; chown -R 1000:1000 /data /workspaces'

  # Reconcile persisted Paperclip settings before start. Environment values do
  # not override an existing onboard config in all released versions.
  reconcile_paperclip_config

  docker rm -f mte-paperclip >/dev/null 2>&1 || true
  docker network inspect "$PAPERCLIP_DAYTONA_NETWORK" >/dev/null 2>&1 \
    || docker network create --driver bridge "$PAPERCLIP_DAYTONA_NETWORK" >/dev/null
  start_paperclip_container
  wait_http "http://127.0.0.1:${PAPERCLIP_PORT}/api/health"
  verify_runtime allow-daytona-pending >/dev/null
  echo "paperclip-runtime: installed"
}

status_runtime() {
  docker inspect --format '{"name":"{{.Name}}","running":{{.State.Running}},"status":"{{.State.Status}}"}' mte-paperclip
}

verify_runtime() {
  local route_mode=${1:-strict}
  local unauthorized_status=not_applicable
  validate_deployment_contract
  verify_image_abi
  verify_running_image_binding
  curl -fsS "http://127.0.0.1:${PAPERCLIP_PORT}/api/health" >/dev/null
  if curl -fsS --max-time 3 "http://127.0.0.1:${LEGACY_PAPERCLIP_PORT}/api/health" >/dev/null 2>&1; then
    echo "paperclip-runtime: legacy listener ${LEGACY_PAPERCLIP_PORT} is still active" >&2
    return 1
  fi
  docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' mte-paperclip \
    | grep -Fx "PORT=${PAPERCLIP_PORT}" >/dev/null
  docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' mte-paperclip \
    | grep -Fx "PAPERCLIP_LISTEN_PORT=${PAPERCLIP_PORT}" >/dev/null
  docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' mte-paperclip \
    | grep -Fx 'PAPERCLIP_SECRETS_STRICT_MODE=true' >/dev/null
  docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' mte-paperclip \
    | grep -Fx "PAPERCLIP_DEPLOYMENT_MODE=${PAPERCLIP_DEPLOYMENT_MODE}" >/dev/null
  docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' mte-paperclip \
    | grep -Fx "PAPERCLIP_DEPLOYMENT_EXPOSURE=${PAPERCLIP_DEPLOYMENT_EXPOSURE}" >/dev/null
  if [[ "$PAPERCLIP_DEPLOYMENT_MODE" == authenticated ]]; then
    [[ -s "$PAPERCLIP_AUTH_SECRET_FILE" \
      && "$(stat -c %a "$PAPERCLIP_AUTH_SECRET_FILE")" == 400 \
      && "$(stat -c %u "$PAPERCLIP_AUTH_SECRET_FILE")" == 1000 ]]
    [[ "$(sha256sum "$PAPERCLIP_AUTH_SECRET_FILE" | awk '{print $1}')" \
      == "$(printf 'PAPERCLIP_AGENT_JWT_SECRET=%s\n' "$PAPERCLIP_AGENT_JWT_SECRET" | sha256sum | awk '{print $1}')" ]]
    ! docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' mte-paperclip \
      | grep -q '^PAPERCLIP_AGENT_JWT_SECRET='
    unauthorized_status=$(curl -sS -o /dev/null -w '%{http_code}' \
      "http://127.0.0.1:${PAPERCLIP_PORT}/api/companies")
    [[ "$unauthorized_status" == 401 || "$unauthorized_status" == 403 ]]
  fi
  verify_private_route "$route_mode"
  write_runtime_verify_evidence
  echo "paperclip-runtime: immutable native control plane ready"
}

case "$ACTION" in
  preflight) validate_deployment_contract; verify_registry_image_available ;;
  config-migrate) validate_deployment_contract; pull_and_verify_image; reconcile_paperclip_config ;;
  install) install_runtime ;;
  status) status_runtime ;;
  verify) verify_runtime ;;
  remove)
    docker rm -f mte-paperclip >/dev/null 2>&1 || true
    echo "paperclip-runtime: containers removed; volumes preserved"
    ;;
  *) echo "usage: paperclip.sh preflight|config-migrate|install|status|verify|remove" >&2; exit 2 ;;
esac

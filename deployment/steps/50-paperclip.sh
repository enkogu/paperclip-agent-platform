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

PAPERCLIP_NODE_IMAGE=$(canonical_value PAPERCLIP_NODE_IMAGE)
PAPERCLIP_RUNTIME_VERSION=$(canonical_value PAPERCLIP_RUNTIME_VERSION)
CODEX_CLI_VERSION=$(canonical_value CODEX_CLI_VERSION)
CLAUDE_CODE_CLI_VERSION=$(canonical_value CLAUDE_CODE_CLI_VERSION)
PI_CLI_VERSION=$(canonical_value PI_CLI_VERSION)
PAPERCLIP_PORT=$(canonical_value PAPERCLIP_PORT)
PAPERCLIP_CPU_LIMIT=$(canonical_value PAPERCLIP_CPU_LIMIT)
PAPERCLIP_MEMORY_LIMIT=$(canonical_value PAPERCLIP_MEMORY_LIMIT)
PAPERCLIP_PIDS_LIMIT=$(canonical_value PAPERCLIP_PIDS_LIMIT)
PAPERCLIP_DEPLOYMENT_MODE=$(canonical_optional PAPERCLIP_DEPLOYMENT_MODE)
PAPERCLIP_DEPLOYMENT_EXPOSURE=$(canonical_optional PAPERCLIP_DEPLOYMENT_EXPOSURE)
PAPERCLIP_PUBLIC_URL=$(canonical_optional PAPERCLIP_PUBLIC_URL)
PAPERCLIP_AGENT_JWT_SECRET=$(canonical_optional PAPERCLIP_AGENT_JWT_SECRET)
PAPERCLIP_DEPLOYMENT_MODE=${PAPERCLIP_DEPLOYMENT_MODE:-local_trusted}
PAPERCLIP_DEPLOYMENT_EXPOSURE=${PAPERCLIP_DEPLOYMENT_EXPOSURE:-private}
: "${PAPERCLIP_NODE_IMAGE:?missing PAPERCLIP_NODE_IMAGE}"
: "${PAPERCLIP_RUNTIME_VERSION:?missing PAPERCLIP_RUNTIME_VERSION}"
: "${CODEX_CLI_VERSION:?missing CODEX_CLI_VERSION}"
: "${CLAUDE_CODE_CLI_VERSION:?missing CLAUDE_CODE_CLI_VERSION}"
: "${PI_CLI_VERSION:?missing PI_CLI_VERSION}"
PAPERCLIP_IMAGE=$PAPERCLIP_NODE_IMAGE
PAPERCLIP_VERSION=$PAPERCLIP_RUNTIME_VERSION
CODEX_VERSION=$CODEX_CLI_VERSION
CLAUDE_VERSION=$CLAUDE_CODE_CLI_VERSION
PI_VERSION=$PI_CLI_VERSION
RUNTIME_ROOT='/opt/mte-platform/runtime/paperclip'
PROFILE_RUNTIME='/opt/mte-platform/runtime/profiles/profiles.yaml'
EVIDENCE_ROOT='/opt/mte-platform/evidence'
: "${PAPERCLIP_PORT:?missing PAPERCLIP_PORT}"
LEGACY_PAPERCLIP_PORT=18110
PAPERCLIP_AUTH_SECRET_FILE='/root/.config/mte-secrets/paperclip-runtime/agent-jwt-secret'

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

reconcile_auth_secret_projection() {
  if [[ "$PAPERCLIP_DEPLOYMENT_MODE" != authenticated ]]; then
    rm -f "$PAPERCLIP_AUTH_SECRET_FILE"
    return 0
  fi
  local directory temporary
  directory=$(dirname "$PAPERCLIP_AUTH_SECRET_FILE")
  install -d -m 0700 -o root -g root "$directory"
  temporary=$(mktemp "$directory/.agent-jwt-secret.XXXXXX")
  chmod 0400 "$temporary"
  printf '%s' "$PAPERCLIP_AGENT_JWT_SECRET" >"$temporary"
  # The parent remains root-only on the host. UID 1000 ownership lets the
  # non-root Paperclip container read only this bind-mounted file.
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
          bind: "loopback",
          host: "127.0.0.1",
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

write_runtime_verify_evidence() {
  local configured_port strict_mode paperclip_env_port
  local actual_mode actual_exposure actual_auth_mode actual_public_url
  configured_port=$(paperclip_config_port)
  strict_mode=$(paperclip_config_strict_mode)
  actual_mode=$(paperclip_config_contract_value deploymentMode)
  actual_exposure=$(paperclip_config_contract_value exposure)
  actual_auth_mode=$(paperclip_config_contract_value authBaseUrlMode)
  actual_public_url=$(paperclip_config_contract_value authPublicBaseUrl)
  paperclip_env_port=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' mte-paperclip | sed -n 's/^PORT=//p' | tail -n1)
  python3 - "$EVIDENCE_ROOT/paperclip-runtime-config-verify.json" \
    "$PAPERCLIP_PORT" "$configured_port" "$strict_mode" "$paperclip_env_port" \
    "$PAPERCLIP_DEPLOYMENT_MODE" "$PAPERCLIP_DEPLOYMENT_EXPOSURE" \
    "$PAPERCLIP_PUBLIC_URL" "$actual_mode" "$actual_exposure" \
    "$actual_auth_mode" "$actual_public_url" "$unauthorized_status" <<'PY'
import json
from pathlib import Path
import sys
from datetime import datetime, timezone

path = Path(sys.argv[1])
desired_paperclip = int(sys.argv[2])
configured_port = int(sys.argv[3])
strict_mode = sys.argv[4] == "true"
paperclip_env_port = int(sys.argv[5])
desired_mode, desired_exposure, desired_public_url = sys.argv[6:9]
actual_mode, actual_exposure, actual_auth_mode, actual_public_url = sys.argv[9:13]
unauthorized_status = sys.argv[13]
desired_auth_mode = "explicit" if desired_exposure == "public" else "auto"
ready = (
    configured_port == desired_paperclip
    and strict_mode
    and paperclip_env_port == desired_paperclip
    and actual_mode == desired_mode
    and actual_exposure == desired_exposure
    and actual_auth_mode == desired_auth_mode
    and actual_public_url == (desired_public_url if desired_exposure == "public" else "")
)
payload = {
    "apiVersion": "micro-task-engine/v1alpha1",
    "kind": "PaperclipRuntimeConfigVerification",
    "status": "ready" if ready else "failed",
    "observedAt": datetime.now(timezone.utc).isoformat(),
    "desired": {
        "paperclipPort": desired_paperclip,
        "secretsStrictMode": True,
        "deploymentMode": desired_mode,
        "exposure": desired_exposure,
        "authBaseUrlMode": desired_auth_mode,
        "authPublicBaseUrlConfigured": desired_exposure == "public",
    },
    "actual": {
        "persistedPaperclipPort": configured_port,
        "paperclipContainerPort": paperclip_env_port,
        "persistedSecretsStrictMode": strict_mode,
        "deploymentMode": actual_mode,
        "exposure": actual_exposure,
        "authBaseUrlMode": actual_auth_mode,
        "authPublicBaseUrlConfigured": bool(actual_public_url),
        "unauthenticatedBoardStatus": unauthorized_status,
    },
}
temporary = path.with_suffix(".json.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
temporary.chmod(0o600)
temporary.replace(path)
path.chmod(0o600)
print(json.dumps({
    "paperclipRuntimeConfig": payload["status"],
    "desired": payload["desired"],
    "actual": payload["actual"],
    "evidence": str(path),
}))
if not ready:
    raise SystemExit(1)
PY
}

start_paperclip_container() {
  local -a secret_mount=()
  if [[ "$PAPERCLIP_DEPLOYMENT_MODE" == authenticated ]]; then
    secret_mount=(-v "$PAPERCLIP_AUTH_SECRET_FILE:/run/secrets/paperclip-agent-jwt-secret:ro")
  fi
  docker run -d \
    --name mte-paperclip \
    --restart unless-stopped \
    --network host \
    --user 1000:1000 \
    --cpus "${PAPERCLIP_CPU_LIMIT:?missing PAPERCLIP_CPU_LIMIT}" \
    --memory "${PAPERCLIP_MEMORY_LIMIT:?missing PAPERCLIP_MEMORY_LIMIT}" \
    --pids-limit "${PAPERCLIP_PIDS_LIMIT:?missing PAPERCLIP_PIDS_LIMIT}" \
    --security-opt no-new-privileges:true \
    -e HOME=/home/node \
    -e PORT="$PAPERCLIP_PORT" \
    -e PAPERCLIP_LISTEN_PORT="$PAPERCLIP_PORT" \
    -e PAPERCLIP_SECRETS_STRICT_MODE=true \
    -e PAPERCLIP_DEPLOYMENT_MODE="$PAPERCLIP_DEPLOYMENT_MODE" \
    -e PAPERCLIP_DEPLOYMENT_EXPOSURE="$PAPERCLIP_DEPLOYMENT_EXPOSURE" \
    -e PAPERCLIP_PUBLIC_URL="$PAPERCLIP_PUBLIC_URL" \
    -e CODEX_HOME=/home/node/.codex \
    -e PI_CODING_AGENT_DIR=/home/node/.pi/agent \
    -e PATH=/tools/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    -v "$RUNTIME_ROOT:/prototype:ro" \
    -v mte-paperclip-native-data:/data \
    -v mte-paperclip-native-npm:/home/node/.npm \
    -v mte-paperclip-native-home:/home/node \
    -v mte-paperclip-native-tools:/tools:ro \
    -v mte-paperclip-native-workspaces:/workspaces \
    -v mte-9router-data:/ninerouter-data:ro \
    "${secret_mount[@]}" \
    "$PAPERCLIP_IMAGE" \
    bash -ceu 'if [[ -r /run/secrets/paperclip-agent-jwt-secret ]]; then
      export PAPERCLIP_AGENT_JWT_SECRET="$(cat /run/secrets/paperclip-agent-jwt-secret)"
    fi
    exec npx --yes "paperclipai@$1" onboard --yes --data-dir /data --bind loopback' \
    paperclip-runtime "$PAPERCLIP_VERSION" >/dev/null
}

install_tools() {
  docker volume create mte-paperclip-native-tools >/dev/null
  docker run --rm --user 0:0 \
    -v mte-paperclip-native-tools:/tools \
    "$PAPERCLIP_IMAGE" bash -ceu '
      current="$(cat /tools/.mte-harness-versions 2>/dev/null || true)"
      wanted="codex='"$CODEX_VERSION"' claude='"$CLAUDE_VERSION"' pi='"$PI_VERSION"'"
      if [[ "$current" != "$wanted" ]]; then
        rm -rf /tools/node_modules /tools/package.json /tools/package-lock.json
        npm install --prefix /tools --omit=dev --ignore-scripts \
          @openai/codex@'"$CODEX_VERSION"' \
          @anthropic-ai/claude-code@'"$CLAUDE_VERSION"' \
          @earendil-works/pi-coding-agent@'"$PI_VERSION"' >/dev/null
      fi
      # Claude Code publishes a native executable through its postinstall
      # hook. We intentionally suppress all package lifecycle scripts above,
      # then invoke only the reviewed installer explicitly. This also repairs
      # an older volume whose version marker was written before the binary was
      # installed.
      if ! /tools/node_modules/.bin/claude --version >/dev/null 2>&1; then
        node /tools/node_modules/@anthropic-ai/claude-code/install.cjs >/dev/null
      fi
      /tools/node_modules/.bin/codex --version >/dev/null
      /tools/node_modules/.bin/claude --version >/dev/null
      /tools/node_modules/.bin/pi --version >/dev/null
      printf "%s\n" "$wanted" >/tools/.mte-harness-versions
      chown -R 1000:1000 /tools
    '
}

install_runtime() {
  validate_deployment_contract
  reconcile_auth_secret_projection
  ensure_sources
  install_tools
  for volume in mte-paperclip-native-data mte-paperclip-native-npm mte-paperclip-native-home mte-paperclip-native-workspaces; do
    docker volume create "$volume" >/dev/null
  done
  docker run --rm --user 0:0 \
    -v mte-paperclip-native-data:/data \
    -v mte-paperclip-native-npm:/home/node/.npm \
    -v mte-paperclip-native-home:/home/node \
    -v mte-paperclip-native-workspaces:/workspaces \
    "$PAPERCLIP_IMAGE" chown -R 1000:1000 /data /home/node /workspaces

  # Reconcile persisted Paperclip settings before start. Environment values do
  # not override an existing onboard config in all released versions.
  reconcile_paperclip_config

  docker rm -f mte-paperclip >/dev/null 2>&1 || true
  start_paperclip_container
  for ((i=1; i<=90; i++)); do
    if docker exec mte-paperclip test -s /data/instances/default/config.json >/dev/null 2>&1; then break; fi
    sleep 2
  done
  active_port=$(paperclip_config_port)
  [[ "$active_port" =~ ^[0-9]+$ ]] || { echo "paperclip-runtime: persisted server port is invalid" >&2; exit 2; }
  wait_http "http://127.0.0.1:${active_port}/api/health"
  if [[ "$active_port" != "$PAPERCLIP_PORT" ]]; then
    docker rm -f mte-paperclip >/dev/null
    reconcile_paperclip_config
    start_paperclip_container
  fi
  wait_http "http://127.0.0.1:${PAPERCLIP_PORT}/api/health"
  # First-time onboarding creates the file after the pre-start migration.
  reconcile_paperclip_config

  verify_runtime >/dev/null
  echo "paperclip-runtime: installed"
}

status_runtime() {
  docker inspect --format '{"name":"{{.Name}}","running":{{.State.Running}},"status":"{{.State.Status}}"}' mte-paperclip
}

verify_runtime() {
  local unauthorized_status=not_applicable
  validate_deployment_contract
  [[ "$(paperclip_config_port)" == "$PAPERCLIP_PORT" ]]
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
      == "$(printf '%s' "$PAPERCLIP_AGENT_JWT_SECRET" | sha256sum | awk '{print $1}')" ]]
    ! docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' mte-paperclip \
      | grep -q '^PAPERCLIP_AGENT_JWT_SECRET='
    unauthorized_status=$(curl -sS -o /dev/null -w '%{http_code}' \
      "http://127.0.0.1:${PAPERCLIP_PORT}/api/companies")
    [[ "$unauthorized_status" == 401 || "$unauthorized_status" == 403 ]]
  fi
  docker exec mte-paperclip sh -ceu '
    codex --version >/dev/null
    claude --version >/dev/null
    pi --version >/dev/null
  '
  write_runtime_verify_evidence
  echo "paperclip-runtime: native control plane and harness CLIs ready"
}

case "$ACTION" in
  config-migrate) reconcile_paperclip_config ;;
  install) install_runtime ;;
  status) status_runtime ;;
  verify) verify_runtime ;;
  remove)
    docker rm -f mte-paperclip >/dev/null 2>&1 || true
    echo "paperclip-runtime: containers removed; volumes preserved"
    ;;
  *) echo "usage: 50-paperclip.sh config-migrate|install|status|verify|remove" >&2; exit 2 ;;
esac

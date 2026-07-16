#!/usr/bin/env bash
set -Eeuo pipefail

ACTION=${1:-all}
ARG=${2:-}
ROOT=${DAYTONA_ROOT:-/opt/mte-platform/runtime/paperclip-daytona}
ENV_FILE=/root/.config/mte-secrets/platform.env
ENV_LOCK=/root/.config/mte-secrets/.platform-env.lock
COMPOSE=$ROOT/compose.yaml
COMPOSE_BIN=/usr/libexec/docker/cli-plugins/docker-compose
RUNTIME_ENV=$ROOT/platform.env.projection
RUNTIME_ENV_HASH=$ROOT/platform.env.projection.sha256
EVIDENCE_ROOT=/opt/mte-platform/evidence
EVIDENCE=$EVIDENCE_ROOT/paperclip-daytona-control-plane.json
SCRIPT_PATH=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}")
PRODUCER_SHA256=$(sha256sum "$SCRIPT_PATH" | awk '{print $1}')

log() { printf 'paperclip-daytona: %s\n' "$*"; }
die() { printf 'paperclip-daytona: %s\n' "$*" >&2; exit 2; }

env_value() {
  python3 - "$1" "$2" <<'PY'
from pathlib import Path
import sys
for line in Path(sys.argv[1]).read_text().splitlines():
    if line.startswith(sys.argv[2]+"="):
        print(line.split("=",1)[1]); raise SystemExit(0)
raise SystemExit(2)
PY
}

prepare_canonical_lock() {
  install -d -m 0700 "$(dirname "$ENV_LOCK")"
  command -v flock >/dev/null || die "flock is required"
  touch "$ENV_LOCK"
  chmod 0600 "$ENV_LOCK"
}

init_config() {
  install -d -m 0700 "$(dirname "$ENV_FILE")" "$ROOT" "$ROOT/releases" "$ROOT/keys"
  install -d -m 0755 "$EVIDENCE_ROOT"
  prepare_canonical_lock
  (
  flock -w 300 9 || die "timeout waiting for canonical platform.env lock"
  python3 - "$ENV_FILE" <<'PY'
from pathlib import Path
import secrets,sys
p=Path(sys.argv[1]); v={}
if p.exists():
    for line in p.read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            k,x=line.split("=",1); v[k]=x
defaults={
"MTE_PAPERCLIP_VERSION":"2026.707.0","MTE_PAPERCLIP_PORT":"3100",
"MTE_PAPERCLIP_API_BASE":"http://127.0.0.1:3100/api","MTE_DAYTONA_OSS_VERSION":"0.190.0",
"MTE_DAYTONA_API_PORT":"3310","MTE_DAYTONA_PROXY_PORT":"3410","MTE_DAYTONA_DEX_PORT":"3556","MTE_DAYTONA_SSH_PORT":"3222",
"MTE_AGENT_PLANE_NETWORK":"mte-agent-plane","MTE_AGENT_GATEWAY_IMAGE":"python:3.13-slim@sha256:bffeb7bd6a85767587059c6ba23e1e9122078e3aa3fa836099171b9bb5a9bb00",
"MTE_AGENT_GATEWAY_HOST":"172.20.0.1","MTE_AGENT_GATEWAY_NINEROUTER_PORT":"22080",
"MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_PORT":"22081","MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_PORT":"22082","MTE_AGENT_GATEWAY_TOOLHIVE_PI_PORT":"22083",
"MTE_AGENT_GATEWAY_NINEROUTER_BASE_URL":"http://172.20.0.1:22080",
"MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL":"http://172.20.0.1:22080/v1",
"MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL":"http://172.20.0.1:22081/mcp","MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_URL":"http://172.20.0.1:22082/mcp","MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL":"http://172.20.0.1:22083/mcp",
"MTE_AGENT_GATEWAY_NINEROUTER_UPSTREAM":"http://9router:20128","MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM":"http://toolhive:19011",
"MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_UPSTREAM":"http://toolhive:19012","MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM":"http://toolhive:19013",
"MTE_DAYTONA_API_URL":"http://127.0.0.1:3310/api","MTE_DAYTONA_PLUGIN_PACKAGE":"@paperclipai/plugin-daytona",
"MTE_DAYTONA_PLUGIN_NPM_VERSION":"2026.707.0","MTE_DAYTONA_PLUGIN_MANIFEST_VERSION":"0.1.0",
"MTE_DAYTONA_ENVIRONMENT_NAME":"MTE Daytona Coding","MTE_DAYTONA_TIMEOUT_MS":"300000","MTE_DAYTONA_REUSE_LEASE":"true",
"MTE_DAYTONA_SANDBOX_BASE_IMAGE":"daytonaio/sandbox:0.8.0@sha256:edb66f95f2f09a28a029a0e03d516cf5482ef13a218e93ab1d80954f6ee7ebbb","MTE_DAYTONA_CODING_IMAGE":"daytonaio/sandbox:0.8.0@sha256:edb66f95f2f09a28a029a0e03d516cf5482ef13a218e93ab1d80954f6ee7ebbb","MTE_DAYTONA_CODING_SNAPSHOT":"mte-coding-harness-v3",
"MTE_DAYTONA_GENERAL_SNAPSHOT":"mte-general-harness-v3","MTE_DAYTONA_CODING_CPU":"1","MTE_DAYTONA_CODING_MEMORY_GIB":"2",
"MTE_DAYTONA_GENERAL_CPU":"1","MTE_DAYTONA_GENERAL_MEMORY_GIB":"1","MTE_DAYTONA_DISK_GIB":"20",
"MTE_DAYTONA_AUTO_STOP_MIN":"5","MTE_DAYTONA_AUTO_ARCHIVE_MIN":"15","MTE_DAYTONA_AUTO_DELETE_MIN":"1440",
"MTE_CODEX_VERSION":"0.144.4","MTE_CLAUDE_CODE_VERSION":"2.1.209","MTE_PI_VERSION":"0.80.7","MTE_TOOLHIVE_VERSION":"0.36.0",
"MTE_CODEX_NPM_INTEGRITY":"sha512-DTHzYatlKq9dw55E0/HsbK4tRCEKabuJ10ybbqpsG8gVv/kvwEdg3Z4OI3cvLXKa21xkIa4lkGlZoO/HmqmFFw==",
"MTE_CLAUDE_CODE_NPM_INTEGRITY":"sha512-pouVZMdA3Dl4+x4Nlr+AInZla+L6yCiHe0L+AuprM3L6Gko4ErQxwl/DprLKXMF/IhckJhdsgGEaO1gYku+lZw==",
"MTE_PI_NPM_INTEGRITY":"sha512-mxq3IClhdgmCrYiKuzKehs4QKCVJgKmlA70nUEzsgeNsGdxriT7o5sKQTCcxzVJkzDRMcHD/8tAP4/eGrV4gKQ==",
"MTE_GITHUB_CLI_VERSION":"2.96.0","MTE_GITHUB_CLI_ARCHIVE_SHA256":"83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60",
"MTE_PI_CODING_AGENT_DIR":"/home/daytona/.pi/mte-profile",
"MTE_TOOLHIVE_ARCHIVE_SHA256":"ca87b9d9eec394d953868a8fbbbda88d7c6105ac65c1a45327b7af75bfcfbce9",
"MTE_DAYTONA_API_IMAGE":"daytonaio/daytona-api@sha256:8de6315a378430a58a44ce6c20b41050c2f602446e75f3ff559edbaa0b3758a7","MTE_DAYTONA_PROXY_IMAGE":"daytonaio/daytona-proxy@sha256:63834f0477e154f92de8d44efb0809dffbd2392c188b6cf41dac94ed8ade26c2",
"MTE_DAYTONA_RUNNER_IMAGE":"daytonaio/daytona-runner@sha256:3253f4fdfda80bfc3b13e9e7ddf022cb5412dca94230371091e16cd0860427e0","MTE_DAYTONA_SSH_IMAGE":"daytonaio/daytona-ssh-gateway@sha256:b931ec8b4713bc80596d867f892febd7638220b92ad0825a0fbae9e3e4cef17f",
"MTE_DAYTONA_POSTGRES_IMAGE":"postgres:18@sha256:c2d42a104eb6b37b286a2d9c5cf83f349de4d6516d513d00a2bd9610e2c2e5e4","MTE_DAYTONA_REDIS_IMAGE":"redis@sha256:0b13f549ab871acafaa84b673c4e29bd7dce8d12526aaafe3b4ea3366c322daf","MTE_DAYTONA_DEX_IMAGE":"dexidp/dex:v2.42.0@sha256:1b4a6eee8550240b0faedad04d984ca939513650e1d9bd423502c67355e3822f",
"MTE_DAYTONA_REGISTRY_IMAGE":"registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373","MTE_DAYTONA_MINIO_IMAGE":"minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e",
"DAYTONA_DB_USER":"daytona","DAYTONA_MINIO_USER":"mte_daytona","DAYTONA_REGISTRY_USER":"mte_daytona",
"DAYTONA_BOOTSTRAP_EMAIL":"daytona-admin@mte.local",
}
for k,x in defaults.items(): v.setdefault(k,x)
snapshot_migrations={
    "MTE_DAYTONA_CODING_SNAPSHOT":({"mte-coding-harness-v1","mte-coding-harness-v2"},"mte-coding-harness-v3"),
    "MTE_DAYTONA_GENERAL_SNAPSHOT":({"mte-general-harness-v1","mte-general-harness-v2"},"mte-general-harness-v3"),
}
for key,(legacy,current) in snapshot_migrations.items():
    if v.get(key) in legacy: v[key]=current
route_model="mte-minimax/"+v.get("MINIMAX_MODEL","MiniMax-M2.5")
profile_defaults={
"PROFILE_CODING_DAYTONA_CODEX_ADAPTER":"codex_local",
"PROFILE_CODING_DAYTONA_CODEX_DEFAULT_ENVIRONMENT":"daytona-coding",
"PROFILE_CODING_DAYTONA_CODEX_MODEL":route_model,
"PROFILE_CODING_DAYTONA_CODEX_TIMEOUT_SEC":"1800",
"PROFILE_CODING_DAYTONA_CODEX_MAX_CONCURRENT_RUNS":"1",
"PROFILE_CODING_DAYTONA_CODEX_TIMEOUT_SECONDS":"1800",
"PROFILE_CODING_DAYTONA_CODEX_CPU_LIMIT":v["MTE_DAYTONA_CODING_CPU"],
"PROFILE_CODING_DAYTONA_CODEX_MEMORY_LIMIT":v["MTE_DAYTONA_CODING_MEMORY_GIB"]+"Gi",
"PROFILE_CODING_DAYTONA_CODEX_PACKAGE_CODEX_VERSION":v["MTE_CODEX_VERSION"],
"PROFILE_CODING_DAYTONA_CODEX_PACKAGE_TOOLHIVE_VERSION":v["MTE_TOOLHIVE_VERSION"],
"PROFILE_CODING_DAYTONA_CLAUDE_ADAPTER":"claude_local",
"PROFILE_CODING_DAYTONA_CLAUDE_DEFAULT_ENVIRONMENT":"daytona-coding",
"PROFILE_CODING_DAYTONA_CLAUDE_MODEL":route_model,
"PROFILE_CODING_DAYTONA_CLAUDE_TIMEOUT_SEC":"1800",
"PROFILE_CODING_DAYTONA_CLAUDE_MAX_CONCURRENT_RUNS":"1",
"PROFILE_CODING_DAYTONA_CLAUDE_TIMEOUT_SECONDS":"1800",
"PROFILE_CODING_DAYTONA_CLAUDE_CPU_LIMIT":v["MTE_DAYTONA_CODING_CPU"],
"PROFILE_CODING_DAYTONA_CLAUDE_MEMORY_LIMIT":v["MTE_DAYTONA_CODING_MEMORY_GIB"]+"Gi",
"PROFILE_CODING_DAYTONA_CLAUDE_PACKAGE_CLAUDECODE_VERSION":v["MTE_CLAUDE_CODE_VERSION"],
"PROFILE_CODING_DAYTONA_CLAUDE_PACKAGE_TOOLHIVE_VERSION":v["MTE_TOOLHIVE_VERSION"],
"PROFILE_CODING_DAYTONA_PI_ADAPTER":"pi_local",
"PROFILE_CODING_DAYTONA_PI_DEFAULT_ENVIRONMENT":"daytona-coding",
"PROFILE_CODING_DAYTONA_PI_PROVIDER":"mte9router",
"PROFILE_CODING_DAYTONA_PI_MODEL":"mte9router/"+route_model,
"PROFILE_CODING_DAYTONA_PI_TIMEOUT_SEC":"1800",
"PROFILE_CODING_DAYTONA_PI_MAX_CONCURRENT_RUNS":"1",
"PROFILE_CODING_DAYTONA_PI_TIMEOUT_SECONDS":"1800",
"PROFILE_CODING_DAYTONA_PI_CPU_LIMIT":v["MTE_DAYTONA_CODING_CPU"],
"PROFILE_CODING_DAYTONA_PI_MEMORY_LIMIT":v["MTE_DAYTONA_CODING_MEMORY_GIB"]+"Gi",
"PROFILE_CODING_DAYTONA_PI_PACKAGE_PI_VERSION":v["MTE_PI_VERSION"],
"PROFILE_CODING_DAYTONA_PI_PACKAGE_TOOLHIVE_VERSION":v["MTE_TOOLHIVE_VERSION"],
}
for k,x in profile_defaults.items(): v.setdefault(k,x)
v.setdefault("DAYTONA_API_URL",v["MTE_DAYTONA_API_URL"])
v.setdefault("DAYTONA_TARGET","us")
def t(n=24): return secrets.token_hex(n)
generated={"DAYTONA_DB_PASSWORD":t(),"DAYTONA_ENCRYPTION_KEY":t(16),"DAYTONA_ENCRYPTION_SALT":t(16),
"DAYTONA_PROXY_API_KEY":t(),"DAYTONA_RUNNER_API_KEY":t(),"DAYTONA_SSH_GATEWAY_API_KEY":t(),
"DAYTONA_MINIO_PASSWORD":t(),"DAYTONA_REGISTRY_PASSWORD":t(),"DAYTONA_HEALTH_CHECK_API_KEY":t(),
"DAYTONA_OTEL_COLLECTOR_API_KEY":t(),"DAYTONA_ADMIN_API_KEY":"dtn_"+t(32),"DAYTONA_BOOTSTRAP_PASSWORD":secrets.token_urlsafe(32)}
generated.update({
"TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN":secrets.token_urlsafe(36),
"TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_BEARER_TOKEN":secrets.token_urlsafe(36),
"TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN":secrets.token_urlsafe(36),
})
for k,x in generated.items(): v.setdefault(k,x)
tmp=p.with_suffix(".tmp"); tmp.write_text("".join(f"{k}={v[k]}\n" for k in sorted(v))); tmp.chmod(0o600); tmp.replace(p)
PY
  ) 9>"$ENV_LOCK"
  if [[ ! -s $ROOT/keys/ssh ]]; then
    ssh-keygen -q -t ed25519 -N '' -f "$ROOT/keys/ssh"
    ssh-keygen -q -t ed25519 -N '' -f "$ROOT/keys/host"
  fi
  chmod 0600 "$ENV_FILE" "$ROOT/keys/ssh" "$ROOT/keys/host"
}

config_hash() {
  python3 - "${1:-$ENV_FILE}" <<'PY'
from pathlib import Path
import hashlib,sys
rows=[]
for line in Path(sys.argv[1]).read_text().splitlines():
    if "=" not in line: continue
    k,x=line.split("=",1)
    if k.startswith(("MTE_PAPERCLIP_","MTE_DAYTONA_","MTE_AGENT_","MTE_CODEX_","MTE_CLAUDE_","MTE_PI_","MTE_TOOLHIVE_","MTE_GITHUB_","PROFILE_CODING_DAYTONA_")): rows.append(k+"="+x)
for k in ("DAYTONA_API_KEY","DAYTONA_DB_PASSWORD","DAYTONA_PROXY_API_KEY","DAYTONA_RUNNER_API_KEY","DAYTONA_SSH_GATEWAY_API_KEY","TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN","TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_BEARER_TOKEN","TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN"): rows.append("secret-ref:"+k)
print(hashlib.sha256(("\n".join(sorted(rows))+"\n").encode()).hexdigest())
PY
}

snapshot_runtime_config() {
  prepare_canonical_lock
  (
  flock -w 300 9 || die "timeout waiting for canonical platform.env lock"
  python3 - "$ENV_FILE" "$RUNTIME_ENV" <<'PY'
from pathlib import Path
import sys
source,target=map(Path,sys.argv[1:])
tmp=target.with_suffix(".tmp"); tmp.write_bytes(source.read_bytes()); tmp.chmod(0o600); tmp.replace(target)
PY
  config_hash "$RUNTIME_ENV" >"$RUNTIME_ENV_HASH"
  chmod 0600 "$RUNTIME_ENV_HASH"
  ) 9>"$ENV_LOCK"
}

assert_runtime_config_current() {
  local expected actual
  expected=$(cat "$RUNTIME_ENV_HASH")
  prepare_canonical_lock
  (
  flock -w 300 9 || die "timeout waiting for canonical platform.env lock"
  actual=$(config_hash "$ENV_FILE")
  [[ "$actual" == "$expected" ]] || die "canonical Daytona config changed during deployment; rerun install"
  ) 9>"$ENV_LOCK"
}

resolve_images() {
  init_config
  local plan=$ROOT/image-plan.json resolved=$ROOT/image-resolved.json
  (
  flock -w 300 9 || die "timeout waiting for canonical platform.env lock"
  python3 - "$ENV_FILE" "$plan" <<'PY'
from pathlib import Path
import hashlib,json,sys
p,out=map(Path,sys.argv[1:]); v=dict(line.split("=",1) for line in p.read_text().splitlines() if "=" in line)
keys=["MTE_DAYTONA_API_IMAGE","MTE_DAYTONA_PROXY_IMAGE","MTE_DAYTONA_RUNNER_IMAGE","MTE_DAYTONA_SSH_IMAGE","MTE_AGENT_GATEWAY_IMAGE",
"MTE_DAYTONA_POSTGRES_IMAGE","MTE_DAYTONA_REDIS_IMAGE","MTE_DAYTONA_DEX_IMAGE","MTE_DAYTONA_REGISTRY_IMAGE","MTE_DAYTONA_MINIO_IMAGE"]
images={k:v[k] for k in keys}
source_hash=hashlib.sha256(json.dumps(images,sort_keys=True,separators=(",",":")).encode()).hexdigest()
tmp=out.with_suffix(".tmp"); tmp.write_text(json.dumps({"sourceHash":source_hash,"images":images},sort_keys=True)+"\n"); tmp.chmod(0o600); tmp.replace(out)
PY
  ) 9>"$ENV_LOCK"
  python3 - "$plan" "$resolved" <<'PY'
from pathlib import Path
import json,subprocess,sys
plan,out=map(Path,sys.argv[1:]); payload=json.loads(plan.read_text()); result={}
for k,src in payload["images"].items():
    if "@sha256:" in src:
        result[k]=src
        continue
    subprocess.run(["docker","pull",src],check=True,stdout=subprocess.DEVNULL)
    digest=subprocess.check_output(["docker","image","inspect",src,"--format","{{index .RepoDigests 0}}"],text=True).strip()
    if not digest: digest=subprocess.check_output(["docker","image","inspect",src,"--format","{{.Id}}"],text=True).strip()
    result[k]=digest
tmp=out.with_suffix(".tmp"); tmp.write_text(json.dumps({"sourceHash":payload["sourceHash"],"sourceImages":payload["images"],"resolvedImages":result},sort_keys=True)+"\n"); tmp.chmod(0o600); tmp.replace(out)
PY
  (
  flock -w 300 9 || die "timeout waiting for canonical platform.env lock"
  python3 - "$ENV_FILE" "$resolved" "$ROOT/releases" "$ROOT/current-release" <<'PY'
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,sys
envp,resolvedp,releases,current=map(Path,sys.argv[1:]); payload=json.loads(resolvedp.read_text())
v=dict(line.split("=",1) for line in envp.read_text().splitlines() if "=" in line)
if any(v.get(k)!=x for k,x in payload["sourceImages"].items()):
    raise SystemExit("canonical image refs changed while pulls were in progress")
v.update(payload["resolvedImages"])
tmp=envp.with_suffix(".tmp"); tmp.write_text("".join(f"{k}={v[k]}\n" for k in sorted(v))); tmp.chmod(0o600); tmp.replace(envp)
release=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
metadata={"releaseId":release,"sourceHash":payload["sourceHash"],"images":payload["resolvedImages"]}
rp=releases/(release+".json"); rt=rp.with_suffix(".tmp"); rt.write_text(json.dumps(metadata,indent=2,sort_keys=True)+"\n"); rt.chmod(0o600); rt.replace(rp)
ct=current.with_suffix(".tmp"); ct.write_text(release+"\n"); ct.chmod(0o600); ct.replace(current)
PY
  ) 9>"$ENV_LOCK"
  local release
  release=$(cat "$ROOT/current-release")
  log "immutable image lock $release"
}

render() {
  init_config
  grep -q '^MTE_DAYTONA_API_IMAGE=.*@sha256:' $ENV_FILE || resolve_images
  snapshot_runtime_config
  local pub priv host
  pub=$(base64 -w0 "$ROOT/keys/ssh.pub"); priv=$(base64 -w0 "$ROOT/keys/ssh"); host=$(base64 -w0 "$ROOT/keys/host")
  printf 'SSH_PUBLIC_KEY=%s\nSSH_PRIVATE_KEY=%s\nSSH_HOST_KEY=%s\n' "$pub" "$priv" "$host" >"$ROOT/ssh.env"
  chmod 0600 "$ROOT/ssh.env"
  python3 - "$RUNTIME_ENV" "$ROOT/keys/ssh.pub" "$COMPOSE" "$ROOT/dex.yaml" <<'PY'
from pathlib import Path
import crypt,json,os,sys
envp,pubp,outp,dexp=map(Path,sys.argv[1:]); v=dict(line.split("=",1) for line in envp.read_text().splitlines() if "=" in line)
q=lambda k: json.dumps(v[k]); port=lambda k:v[k]
bcrypt=crypt.crypt(v["DAYTONA_BOOTSTRAP_PASSWORD"],crypt.mksalt(crypt.METHOD_BLOWFISH))
dex=f"""issuer: http://127.0.0.1:{v['MTE_DAYTONA_DEX_PORT']}/dex
storage:
  type: sqlite3
  config: {{file: /var/dex/dex.db}}
web:
  http: 0.0.0.0:5556
  allowedOrigins: ['*']
  allowedHeaders: ['x-requested-with']
oauth2:
  passwordConnector: local
staticClients:
  - id: daytona
    redirectURIs:
      - http://127.0.0.1:{v['MTE_DAYTONA_API_PORT']}
      - http://127.0.0.1:{v['MTE_DAYTONA_API_PORT']}/dashboard
      - http://127.0.0.1:{v['MTE_DAYTONA_PROXY_PORT']}/callback
    name: Daytona
    public: true
enablePasswordDB: true
staticPasswords:
  - email: {v['DAYTONA_BOOTSTRAP_EMAIL']!r}
    hash: {bcrypt!r}
    username: admin
    userID: mte-daytona-admin
"""
dexp.write_text(dex); os.chown(dexp,1001,1001); dexp.chmod(0o600)
y=f"""name: mte-daytona
services:
  db:
    image: {q('MTE_DAYTONA_POSTGRES_IMAGE')}
    container_name: mte-daytona-db
    restart: unless-stopped
    environment: {{POSTGRES_USER: {q('DAYTONA_DB_USER')}, POSTGRES_PASSWORD: {q('DAYTONA_DB_PASSWORD')}, POSTGRES_DB: daytona}}
    volumes: [daytona-db:/var/lib/postgresql/18/docker]
    networks: [daytona]
  redis:
    image: {q('MTE_DAYTONA_REDIS_IMAGE')}
    container_name: mte-daytona-redis
    restart: unless-stopped
    networks: [daytona]
  registry:
    image: {q('MTE_DAYTONA_REGISTRY_IMAGE')}
    container_name: mte-daytona-registry
    restart: unless-stopped
    environment: {{REGISTRY_HTTP_ADDR: "registry:6000", REGISTRY_STORAGE_DELETE_ENABLED: "true"}}
    volumes: [daytona-registry:/var/lib/registry]
    networks: [daytona]
  minio:
    image: {q('MTE_DAYTONA_MINIO_IMAGE')}
    container_name: mte-daytona-minio
    restart: unless-stopped
    command: server /data --console-address :9001
    environment: {{MINIO_ROOT_USER: {q('DAYTONA_MINIO_USER')}, MINIO_ROOT_PASSWORD: {q('DAYTONA_MINIO_PASSWORD')}}}
    volumes: [daytona-minio:/data]
    networks: [daytona]
  dex:
    image: {q('MTE_DAYTONA_DEX_IMAGE')}
    container_name: mte-daytona-dex
    restart: unless-stopped
    command: [dex, serve, /etc/dex/config.yaml]
    volumes: [./dex.yaml:/etc/dex/config.yaml:ro, daytona-dex:/var/dex]
    ports: ["127.0.0.1:{port('MTE_DAYTONA_DEX_PORT')}:5556"]
    networks: [daytona]
  runner:
    image: {q('MTE_DAYTONA_RUNNER_IMAGE')}
    container_name: mte-daytona-runner
    restart: unless-stopped
    privileged: true
    env_file: [./ssh.env]
    environment:
      ENVIRONMENT: production
      API_PORT: 3003
      DAYTONA_RUNNER_TOKEN: {q('DAYTONA_RUNNER_API_KEY')}
      RESOURCE_LIMITS_DISABLED: "false"
      AWS_ENDPOINT_URL: http://minio:9000
      AWS_REGION: us-east-1
      AWS_ACCESS_KEY_ID: {q('DAYTONA_MINIO_USER')}
      AWS_SECRET_ACCESS_KEY: {q('DAYTONA_MINIO_PASSWORD')}
      AWS_DEFAULT_BUCKET: daytona
      DAYTONA_API_URL: http://api:3000/api
      RUNNER_DOMAIN: runner
      SSH_GATEWAY_ENABLE: "true"
      INTER_SANDBOX_NETWORK_ENABLED: "false"
    volumes: [daytona-runner:/home/daytona/runner]
    networks: [daytona, agent-plane, tool-runtime]
  agent-gateway:
    image: {q('MTE_AGENT_GATEWAY_IMAGE')}
    container_name: mte-agent-plane-gateway
    restart: unless-stopped
    network_mode: service:runner
    command: [python3, /app/agent-plane-gateway.py]
    environment:
      MTE_AGENT_GATEWAY_NINEROUTER_PORT: {q('MTE_AGENT_GATEWAY_NINEROUTER_PORT')}
      MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_PORT: {q('MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_PORT')}
      MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_PORT: {q('MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_PORT')}
      MTE_AGENT_GATEWAY_TOOLHIVE_PI_PORT: {q('MTE_AGENT_GATEWAY_TOOLHIVE_PI_PORT')}
      MTE_AGENT_GATEWAY_NINEROUTER_UPSTREAM: {q('MTE_AGENT_GATEWAY_NINEROUTER_UPSTREAM')}
      MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM: {q('MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM')}
      MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_UPSTREAM: {q('MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_UPSTREAM')}
      MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM: {q('MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM')}
      TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN: {q('TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN')}
      TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_BEARER_TOKEN: {q('TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_BEARER_TOKEN')}
      TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN: {q('TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN')}
    volumes:
      - /opt/mte-platform/bin/agent-plane-gateway.py:/app/agent-plane-gateway.py:ro
    depends_on: [runner]
  api:
    image: {q('MTE_DAYTONA_API_IMAGE')}
    container_name: mte-daytona-api
    restart: unless-stopped
    privileged: true
    env_file: [./ssh.env]
    environment:
      ENVIRONMENT: production
      NODE_ENV: production
      PORT: 3000
      RUN_MIGRATIONS: "true"
      DB_HOST: db
      DB_PORT: 5432
      DB_USERNAME: {q('DAYTONA_DB_USER')}
      DB_PASSWORD: {q('DAYTONA_DB_PASSWORD')}
      DB_DATABASE: daytona
      REDIS_HOST: redis
      REDIS_PORT: 6379
      OIDC_CLIENT_ID: daytona
      OIDC_ISSUER_BASE_URL: http://dex:5556/dex
      PUBLIC_OIDC_DOMAIN: http://127.0.0.1:{port('MTE_DAYTONA_DEX_PORT')}/dex
      OIDC_AUDIENCE: daytona
      DASHBOARD_URL: http://127.0.0.1:{port('MTE_DAYTONA_API_PORT')}/dashboard
      DASHBOARD_BASE_API_URL: http://127.0.0.1:{port('MTE_DAYTONA_API_PORT')}
      DEFAULT_SNAPSHOT: {q('MTE_DAYTONA_SANDBOX_BASE_IMAGE')}
      ENCRYPTION_KEY: {q('DAYTONA_ENCRYPTION_KEY')}
      ENCRYPTION_SALT: {q('DAYTONA_ENCRYPTION_SALT')}
      TRANSIENT_REGISTRY_URL: http://registry:6000
      TRANSIENT_REGISTRY_ADMIN: {q('DAYTONA_REGISTRY_USER')}
      TRANSIENT_REGISTRY_PASSWORD: {q('DAYTONA_REGISTRY_PASSWORD')}
      TRANSIENT_REGISTRY_PROJECT_ID: daytona
      INTERNAL_REGISTRY_URL: http://registry:6000
      INTERNAL_REGISTRY_ADMIN: {q('DAYTONA_REGISTRY_USER')}
      INTERNAL_REGISTRY_PASSWORD: {q('DAYTONA_REGISTRY_PASSWORD')}
      INTERNAL_REGISTRY_PROJECT_ID: daytona
      S3_ENDPOINT: http://minio:9000
      S3_STS_ENDPOINT: http://minio:9000/minio/v1/assume-role
      S3_REGION: us-east-1
      S3_ACCESS_KEY: {q('DAYTONA_MINIO_USER')}
      S3_SECRET_KEY: {q('DAYTONA_MINIO_PASSWORD')}
      S3_DEFAULT_BUCKET: daytona
      S3_ACCOUNT_ID: /
      S3_ROLE_NAME: /
      PROXY_DOMAIN: proxy.localhost:{port('MTE_DAYTONA_PROXY_PORT')}
      PROXY_PROTOCOL: http
      PROXY_API_KEY: {q('DAYTONA_PROXY_API_KEY')}
      PROXY_TEMPLATE_URL: http://{{{{PORT}}}}-{{{{sandboxId}}}}.proxy.localhost:{port('MTE_DAYTONA_PROXY_PORT')}
      DEFAULT_RUNNER_DOMAIN: runner:3003
      DEFAULT_RUNNER_API_URL: http://runner:3003
      DEFAULT_RUNNER_PROXY_URL: http://runner:3003
      DEFAULT_RUNNER_API_KEY: {q('DAYTONA_RUNNER_API_KEY')}
      DEFAULT_RUNNER_CPU: 4
      DEFAULT_RUNNER_MEMORY: 8
      DEFAULT_RUNNER_DISK: 50
      DEFAULT_RUNNER_NAME: default
      DEFAULT_REGION_ID: us
      DEFAULT_REGION_NAME: us
      DEFAULT_REGION_ENFORCE_QUOTAS: "true"
      DEFAULT_ORG_QUOTA_TOTAL_CPU_QUOTA: 4
      DEFAULT_ORG_QUOTA_TOTAL_MEMORY_QUOTA: 8
      DEFAULT_ORG_QUOTA_TOTAL_DISK_QUOTA: 200
      DEFAULT_ORG_QUOTA_MAX_CPU_PER_SANDBOX: 2
      DEFAULT_ORG_QUOTA_MAX_MEMORY_PER_SANDBOX: 4
      DEFAULT_ORG_QUOTA_MAX_DISK_PER_SANDBOX: 30
      DEFAULT_ORG_QUOTA_SNAPSHOT_QUOTA: 20
      DEFAULT_ORG_QUOTA_MAX_SNAPSHOT_SIZE: 30
      DEFAULT_ORG_QUOTA_VOLUME_QUOTA: 20
      SSH_GATEWAY_API_KEY: {q('DAYTONA_SSH_GATEWAY_API_KEY')}
      SSH_GATEWAY_PUBLIC_KEY: {json.dumps(pubp.read_text().strip())}
      SSH_GATEWAY_COMMAND: ssh -p {port('MTE_DAYTONA_SSH_PORT')} {{{{TOKEN}}}}@127.0.0.1
      SSH_GATEWAY_URL: 127.0.0.1:{port('MTE_DAYTONA_SSH_PORT')}
      RUNNER_DECLARATIVE_BUILD_SCORE_THRESHOLD: 10
      RUNNER_AVAILABILITY_SCORE_THRESHOLD: 10
      RUNNER_START_SCORE_THRESHOLD: 3
      SKIP_USER_EMAIL_VERIFICATION: "true"
      ADMIN_API_KEY: {q('DAYTONA_ADMIN_API_KEY')}
      HEALTH_CHECK_API_KEY: {q('DAYTONA_HEALTH_CHECK_API_KEY')}
      OTEL_ENABLED: "false"
      OTEL_COLLECTOR_API_KEY: {q('DAYTONA_OTEL_COLLECTOR_API_KEY')}
      POSTHOG_API_KEY: ""
    ports: ["127.0.0.1:{port('MTE_DAYTONA_API_PORT')}:3000"]
    networks: [daytona]
    depends_on: [db, redis, dex, registry, minio, runner]
  proxy:
    image: {q('MTE_DAYTONA_PROXY_IMAGE')}
    container_name: mte-daytona-proxy
    restart: unless-stopped
    environment:
      DAYTONA_API_URL: http://api:3000/api
      PROXY_PORT: 4000
      PROXY_API_KEY: {q('DAYTONA_PROXY_API_KEY')}
      PROXY_PROTOCOL: http
      OIDC_CLIENT_ID: daytona
      OIDC_DOMAIN: http://dex:5556/dex
      OIDC_PUBLIC_DOMAIN: http://127.0.0.1:{port('MTE_DAYTONA_DEX_PORT')}/dex
      OIDC_AUDIENCE: daytona
      REDIS_HOST: redis
      REDIS_PORT: 6379
      TOOLBOX_ONLY_MODE: "false"
      PREVIEW_WARNING_ENABLED: "false"
    ports: ["127.0.0.1:{port('MTE_DAYTONA_PROXY_PORT')}:4000"]
    networks: [daytona]
  ssh-gateway:
    image: {q('MTE_DAYTONA_SSH_IMAGE')}
    container_name: mte-daytona-ssh-gateway
    restart: unless-stopped
    env_file: [./ssh.env]
    environment: {{API_URL: "http://api:3000/api", API_KEY: {q('DAYTONA_SSH_GATEWAY_API_KEY')}, SSH_GATEWAY_PORT: "2222"}}
    ports: ["127.0.0.1:{port('MTE_DAYTONA_SSH_PORT')}:2222"]
    networks: [daytona]
volumes:
  daytona-db: {{}}
  daytona-registry: {{}}
  daytona-minio: {{}}
  daytona-dex: {{}}
  daytona-runner: {{}}
networks:
  daytona: {{name: mte-daytona-net, driver: bridge}}
  agent-plane: {{name: {q('MTE_AGENT_PLANE_NETWORK')}, external: true}}
  tool-runtime: {{name: mte-tool-runtime, external: true}}
"""
outp.write_text(y); outp.chmod(0o600)
PY
}

compose() { "$COMPOSE_BIN" --project-directory "$ROOT" --env-file "$RUNTIME_ENV" -f "$COMPOSE" "$@"; }

wait_url() {
  local url=$1
  for _ in $(seq 1 180); do curl -fsS --max-time 3 "$url" >/dev/null 2>&1 && return 0; sleep 2; done
  die "timeout waiting for $url"
}

preflight() {
  command -v docker >/dev/null
  [[ -x "$COMPOSE_BIN" ]] || die "Docker Compose plugin is missing"
  "$COMPOSE_BIN" version >/dev/null
  command -v python3 >/dev/null
  init_config
  local mem
  mem=$(awk '/MemAvailable:/{print int($2/1024)}' /proc/meminfo)
  [[ $mem -ge 3072 ]] || die "less than 3 GiB RAM available"
  printf '{"preflight":"passed","memoryAvailableMiB":%s,"canonicalConfigHash":"%s"}\n' "$mem" "$(config_hash)"
}

install_daytona() {
  preflight
  local agent_plane
  agent_plane=$(env_value "$ENV_FILE" MTE_AGENT_PLANE_NETWORK)
  docker network inspect "$agent_plane" >/dev/null 2>&1 || docker network create --driver bridge "$agent_plane" >/dev/null
  render; compose up -d
  local dex_port api_port
  dex_port=$(env_value "$RUNTIME_ENV" MTE_DAYTONA_DEX_PORT)
  api_port=$(env_value "$RUNTIME_ENV" MTE_DAYTONA_API_PORT)
  wait_url "http://127.0.0.1:${dex_port}/dex/.well-known/openid-configuration"
  wait_url "http://127.0.0.1:${api_port}/api/config"
  assert_runtime_config_current
  log "control plane ready"
}

provision_key() {
  init_config
  snapshot_runtime_config
  local result=$ROOT/daytona-api-key.result.json
  python3 - "$RUNTIME_ENV" "$result" <<'PY'
from pathlib import Path
import hashlib,json,sys,urllib.parse,urllib.request
p,out=map(Path,sys.argv[1:]); v=dict(line.split("=",1) for line in p.read_text().splitlines() if "=" in line); api=v["MTE_DAYTONA_API_URL"]
def req(method,path,data=None,headers=None):
    body=None if data is None else json.dumps(data).encode()
    with urllib.request.urlopen(urllib.request.Request(api+path,data=body,headers={"Content-Type":"application/json",**(headers or {})},method=method),timeout=60) as r:
        raw=r.read(); return json.loads(raw) if raw else None
form=urllib.parse.urlencode({"grant_type":"password","client_id":"daytona","scope":"openid profile email","username":v["DAYTONA_BOOTSTRAP_EMAIL"],"password":v["DAYTONA_BOOTSTRAP_PASSWORD"]}).encode()
url="http://127.0.0.1:"+v["MTE_DAYTONA_DEX_PORT"]+"/dex/token"
with urllib.request.urlopen(urllib.request.Request(url,data=form,headers={"Content-Type":"application/x-www-form-urlencoded"}),timeout=30) as r: token=json.load(r)["access_token"]
jwt={"Authorization":"Bearer "+token}; orgs=req("GET","/organizations",headers=jwt)
if not orgs: orgs=[req("POST","/organizations",{"name":"MTE Paperclip Daytona"},jwt)]
org=orgs[0]; jwt_org={**jwt,"X-Daytona-Organization-ID":org["id"]}
if not org.get("defaultRegionId"):
    req("PATCH",f"/organizations/{org['id']}/default-region",{"defaultRegionId":v["DAYTONA_TARGET"]},jwt_org)
    org={**org,"defaultRegionId":v["DAYTONA_TARGET"]}
key=v.get("DAYTONA_API_KEY","")
if key:
    try: req("GET","/api-keys/current",headers={"Authorization":"Bearer "+key})
    except Exception: key=""
if not key:
    rows=req("GET","/api-keys",headers=jwt_org) or []
    if any(x.get("name")=="paperclip-selfhost" for x in rows): req("DELETE","/api-keys/paperclip-selfhost",headers=jwt_org)
    created=req("POST","/api-keys",{"name":"paperclip-selfhost","permissions":["write:sandboxes","delete:sandboxes","write:snapshots","delete:snapshots"]},jwt_org)
    key=next((created.get(name) for name in ("key","token","apiKey","value") if created.get(name)),"")
    if not key: raise RuntimeError("unexpected API-key response fields: "+",".join(sorted(created)))
payload={"DAYTONA_API_KEY":key,"DAYTONA_ORGANIZATION_ID":org["id"]}
tmp=out.with_suffix(".tmp"); tmp.write_text(json.dumps(payload)+"\n"); tmp.chmod(0o600); tmp.replace(out)
print(json.dumps({"organizationId":org["id"],"defaultRegionId":org["defaultRegionId"],"apiKeyFingerprint":hashlib.sha256(key.encode()).hexdigest()[:16],"storedInCanonicalEnv":True}))
PY
  (
  flock -w 300 9 || die "timeout waiting for canonical platform.env lock"
  [[ "$(config_hash "$ENV_FILE")" == "$(cat "$RUNTIME_ENV_HASH")" ]] || die "canonical Daytona config changed while API key was provisioned"
  python3 - "$ENV_FILE" "$result" <<'PY'
from pathlib import Path
import json,sys
envp,resultp=map(Path,sys.argv[1:]); v=dict(line.split("=",1) for line in envp.read_text().splitlines() if "=" in line)
v.update({str(k):str(x) for k,x in json.loads(resultp.read_text()).items()})
tmp=envp.with_suffix(".tmp"); tmp.write_text("".join(f"{k}={v[k]}\n" for k in sorted(v))); tmp.chmod(0o600); tmp.replace(envp)
PY
  ) 9>"$ENV_LOCK"
  rm -f "$result"
}

set_target() {
  prepare_canonical_lock
  (
  flock -w 300 9 || die "timeout waiting for canonical platform.env lock"
  python3 - "$ENV_FILE" <<'PY'
from pathlib import Path
import hashlib, json, sys
p = Path(sys.argv[1])
values = dict(line.split("=", 1) for line in p.read_text().splitlines() if "=" in line)
values["DAYTONA_TARGET"] = "us"
tmp = p.with_suffix(".tmp")
tmp.write_text("".join(f"{key}={values[key]}\n" for key in sorted(values)))
tmp.chmod(0o600)
tmp.replace(p)
print(json.dumps({
    "daytonaTarget": "us",
    "canonicalConfigHash": hashlib.sha256(p.read_bytes()).hexdigest(),
}))
PY
  ) 9>"$ENV_LOCK"
}

build_images() {
  init_config
  [[ -n "$(env_value "$ENV_FILE" DAYTONA_API_KEY 2>/dev/null || true)" ]] || die "DAYTONA_API_KEY is not provisioned"
  local node_image registry_ip
  node_image=$(env_value "$ENV_FILE" PAPERCLIP_NODE_IMAGE)
  registry_ip=$(docker inspect mte-daytona-registry --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
  [[ "$registry_ip" =~ ^[0-9.]+$ ]] || die "cannot resolve Daytona registry address"
  docker run --rm -i --network host --user 0:0 \
    -e MTE_EVIDENCE_PRODUCER_SHA256="$PRODUCER_SHA256" \
    -e MTE_DAYTONA_REGISTRY_EVIDENCE_URL="http://${registry_ip}:6000" \
    -v "$ENV_FILE:/run/secrets/platform.env:ro" \
    -v mte-paperclip-native-home:/paperclip-home:ro \
    -v "$EVIDENCE_ROOT:/evidence" \
    "$node_image" node --input-type=module <<'NODE'
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
const canonicalSource=fs.readFileSync("/run/secrets/platform.env", "utf8");
const values = Object.fromEntries(
  canonicalSource.split(/\n/)
    .filter((line) => line && !line.startsWith("#") && line.includes("="))
    .map((line) => { const i=line.indexOf("="); return [line.slice(0,i),line.slice(i+1)]; })
);
const safe = (key, pattern=/^[A-Za-z0-9._+:/@-]+$/) => {
  const value=values[key] || "";
  if (!pattern.test(value)) throw new Error(`unsafe or missing canonical ${key}`);
  return value;
};
const { Daytona, Image } = await import("file:///paperclip-home/.paperclip/plugins/node_modules/@daytonaio/sdk/src/index.js");
const daytona = new Daytona({
  apiKey: values.DAYTONA_API_KEY,
  apiUrl: safe("MTE_DAYTONA_API_URL"),
  target: safe("DAYTONA_TARGET"),
});
const base = safe("MTE_DAYTONA_SANDBOX_BASE_IMAGE");
const codex = safe("MTE_CODEX_VERSION");
const claude = safe("MTE_CLAUDE_CODE_VERSION");
const pi = safe("MTE_PI_VERSION");
const codexIntegrity = safe("MTE_CODEX_NPM_INTEGRITY", /^sha512-[A-Za-z0-9+/]+={0,2}$/);
const claudeIntegrity = safe("MTE_CLAUDE_CODE_NPM_INTEGRITY", /^sha512-[A-Za-z0-9+/]+={0,2}$/);
const piIntegrity = safe("MTE_PI_NPM_INTEGRITY", /^sha512-[A-Za-z0-9+/]+={0,2}$/);
const thv = safe("MTE_TOOLHIVE_VERSION");
const thvSha = safe("MTE_TOOLHIVE_ARCHIVE_SHA256", /^[a-f0-9]{64}$/);
const gh = safe("MTE_GITHUB_CLI_VERSION");
const ghSha = safe("MTE_GITHUB_CLI_ARCHIVE_SHA256", /^[a-f0-9]{64}$/);
const piGatewayBaseUrl = safe("MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL");
const piModel = safe("HERMES_LLM_MODEL");
const piAgentDir = safe("MTE_PI_CODING_AGENT_DIR", /^\/home\/daytona\/\.pi\/mte-profile$/);
const codingName = safe("MTE_DAYTONA_CODING_SNAPSHOT");
const generalName = safe("MTE_DAYTONA_GENERAL_SNAPSHOT");
const resources = {
  cpu: Number(safe("MTE_DAYTONA_CODING_CPU", /^\d+$/)),
  memory: Number(safe("MTE_DAYTONA_CODING_MEMORY_GIB", /^\d+$/)),
  disk: Number(safe("MTE_DAYTONA_DISK_GIB", /^\d+$/)),
};
const imageContractKeys=[
  "DAYTONA_TARGET","MTE_DAYTONA_SANDBOX_BASE_IMAGE","MTE_CODEX_VERSION",
  "MTE_CLAUDE_CODE_VERSION","MTE_PI_VERSION","MTE_CODEX_NPM_INTEGRITY",
  "MTE_CLAUDE_CODE_NPM_INTEGRITY","MTE_PI_NPM_INTEGRITY","MTE_TOOLHIVE_VERSION",
  "MTE_TOOLHIVE_ARCHIVE_SHA256","MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL",
  "MTE_GITHUB_CLI_VERSION","MTE_GITHUB_CLI_ARCHIVE_SHA256",
  "HERMES_LLM_MODEL","MTE_PI_CODING_AGENT_DIR","MTE_DAYTONA_CODING_SNAPSHOT",
  "MTE_DAYTONA_GENERAL_SNAPSHOT","MTE_DAYTONA_CODING_CPU",
  "MTE_DAYTONA_CODING_MEMORY_GIB","MTE_DAYTONA_GENERAL_CPU",
  "MTE_DAYTONA_GENERAL_MEMORY_GIB","MTE_DAYTONA_DISK_GIB",
];
const imageContract=Object.fromEntries(imageContractKeys.sort().map((key)=>[key,values[key]||""]));
const imageContractHash=crypto.createHash("sha256").update(JSON.stringify(imageContract)).digest("hex");
const sourceCanonicalHash=crypto.createHash("sha256").update(canonicalSource).digest("hex");
// daytonaio/sandbox deliberately builds as uid 1001.  Its passwordless sudo
// is the supported privilege boundary for OS packages and /usr/local/bin.
const apt = "sudo apt-get update && sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl git jq ripgrep tar && sudo rm -rf /var/lib/apt/lists/*";
const toolhive = `curl -fsSL -o /tmp/toolhive.tar.gz https://github.com/stacklok/toolhive/releases/download/v${thv}/toolhive_${thv}_linux_amd64.tar.gz && echo '${thvSha}  /tmp/toolhive.tar.gz' | sha256sum -c - && tar -xzf /tmp/toolhive.tar.gz -C /tmp && sudo install -m 0755 /tmp/thv /usr/local/bin/thv && rm -f /tmp/toolhive.tar.gz /tmp/thv`;
const githubCliArchive = `gh_${gh}_linux_amd64.tar.gz`;
// Locked release artifact: gh_2.96.0_linux_amd64.tar.gz (version 2.96.0).
const githubCli = `curl -fsSL -o /tmp/${githubCliArchive} https://github.com/cli/cli/releases/download/v${gh}/${githubCliArchive} && echo '${ghSha}  /tmp/${githubCliArchive}' | sha256sum -c - && tar -xzf /tmp/${githubCliArchive} -C /tmp && sudo install -m 0755 /tmp/gh_${gh}_linux_amd64/bin/gh /usr/local/bin/gh && rm -rf /tmp/${githubCliArchive} /tmp/gh_${gh}_linux_amd64`;
const registry = "https://registry.npmjs.org/";
const npmInstall = `sudo env PATH="$PATH" timeout 600s npm install -g --no-audit --no-fund --prefer-online --registry=${registry}`;
const verifyNpmIntegrity = (packageName, version, integrity) =>
  `test "$(sudo env PATH=\"$PATH\" timeout 60s npm view --registry=${registry} ${packageName}@${version} dist.integrity)" = '${integrity}'`;
const workspaceDirectories = "install -d -m 0755 /home/daytona/workspaces /home/daytona/workspaces/coding-daytona-codex /home/daytona/workspaces/coding-daytona-claude /home/daytona/workspaces/coding-daytona-pi";
const gitConfig = "sudo git config --system user.name 'Paperclip Agent' && sudo git config --system user.email 'paperclip-agent@users.noreply.github.com' && sudo git config --system init.defaultBranch main && sudo git config --system credential.https://github.com.helper '!gh auth git-credential'";
const piProbeModels = {
  providers: {
    mte9router: {
      baseUrl: piGatewayBaseUrl,
      apiKey: "$OPENAI_API_KEY",
      api: "openai-completions",
      models: [{
        id: piModel,
        name: "MTE MiniMax",
        reasoning: false,
        input: ["text"],
        cost: {input:0,output:0,cacheRead:0,cacheWrite:0},
        contextWindow: 200000,
        maxTokens: 32768,
      }],
    },
  },
};
const piProbeModelsJson = JSON.stringify(piProbeModels);
const piProbeModelsBase64 = Buffer.from(piProbeModelsJson).toString("base64");
const piProbeConfig = `install -d -m 0700 ${piAgentDir} && printf '%s' '${piProbeModelsBase64}' | base64 -d > ${piAgentDir}/models.json && chmod 0600 ${piAgentDir}/models.json`;
const codingImage = Image.base(base).runCommands(
  workspaceDirectories,
  piProbeConfig,
  apt,
  verifyNpmIntegrity("@openai/codex", codex, codexIntegrity),
  `${npmInstall} @openai/codex@${codex} && codex --version`,
  verifyNpmIntegrity("@anthropic-ai/claude-code", claude, claudeIntegrity),
  `${npmInstall} @anthropic-ai/claude-code@${claude} && claude --version`,
  verifyNpmIntegrity("@earendil-works/pi-coding-agent", pi, piIntegrity),
  `${npmInstall} @earendil-works/pi-coding-agent@${pi} && pi --version`,
  toolhive,
  "thv version",
  githubCli,
  "gh --version",
  gitConfig,
);
const list = await daytona.snapshot.list(1, 100);
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
async function ensureSnapshot(name, image, snapshotResources) {
  let snapshot = list.items.find((row) => row.name === name);
  if (snapshot && snapshot.state === "error") {
    await daytona.snapshot.delete(snapshot);
    // Snapshot deletion is asynchronous in Daytona OSS.  Re-creating the same
    // declarative name before the row disappears produces a misleading 409.
    for (let attempt=0; attempt<90; attempt += 1) {
      const current = await daytona.snapshot.list(1, 100);
      snapshot = current.items.find((row) => row.name === name);
      if (!snapshot) break;
      await sleep(2000);
    }
    if (snapshot) throw new Error(`timed out deleting failed snapshot ${name}`);
  }
  if (!snapshot) {
    snapshot = await daytona.snapshot.create(
      { name, image, resources: snapshotResources },
      { timeout: 1800, onLogs: (line) => console.log(`[${name}] ${line}`) },
    );
  }
  if (snapshot.state !== "active") snapshot = await daytona.snapshot.activate(snapshot);
  return snapshot;
}
const codingSnapshot = await ensureSnapshot(codingName, codingImage, resources);
// A string image reference takes Daytona's register-image path and bypasses
// BUILD_SNAPSHOT entirely. This keeps a separate declarative resource
// envelope without repeating the multi-gigabyte custom-image build/push.
const verifiedImageRef = codingSnapshot.ref || codingSnapshot.imageName;
if (!verifiedImageRef) throw new Error(`active snapshot ${codingName} has no reusable image reference`);
const generalSnapshot = await ensureSnapshot(generalName, verifiedImageRef, {
  cpu: Number(safe("MTE_DAYTONA_GENERAL_CPU", /^\d+$/)),
  memory: Number(safe("MTE_DAYTONA_GENERAL_MEMORY_GIB", /^\d+$/)),
  disk: resources.disk,
});
async function snapshotEvidence(row) {
  const ref = String(row.ref || "");
  const match = ref.match(/^registry:6000\/(.+):([^/:]+)$/);
  if (!match) throw new Error(`snapshot ${row.name} has an unsupported registry ref`);
  const manifestUrl = new URL(
    `/v2/${match[1]}/manifests/${match[2]}`,
    process.env.MTE_DAYTONA_REGISTRY_EVIDENCE_URL,
  );
  // Node fetch follows the browser forbidden-port list and rejects registry
  // port 6000 before opening a socket.  The server-side HTTP client has no
  // browser policy and is the correct primitive for this private registry.
  const response = await new Promise((resolve, reject) => {
    const request = http.request(manifestUrl, {
      method: "HEAD",
      headers: {Accept: "application/vnd.docker.distribution.manifest.v2+json"},
    }, resolve);
    request.setTimeout(30000, () => request.destroy(new Error("registry manifest HEAD timeout")));
    request.on("error", reject);
    request.end();
  });
  response.resume();
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(`snapshot ${row.name} manifest HEAD failed (${response.statusCode})`);
  }
  const digest = String(response.headers["docker-content-digest"] || "");
  if (!/^sha256:[a-f0-9]{64}$/.test(digest)) throw new Error(`snapshot ${row.name} has no full manifest digest`);
  return {
    id: row.id, name: row.name, state: row.state, cpu: row.cpu, memoryGiB: row.mem,
    diskGiB: row.disk, sizeGiB: row.size, digest,
  };
}
const snapshotRows = await Promise.all([codingSnapshot, generalSnapshot].map(snapshotEvidence));
const evidence = {
  apiVersion: "micro-task-engine/v1alpha1",
  kind: "DaytonaHarnessSnapshots",
  status: "ready",
  generatedAt: new Date().toISOString(),
  canonicalSourceSha256: sourceCanonicalHash,
  producerSha256: process.env.MTE_EVIDENCE_PRODUCER_SHA256,
  snapshots: snapshotRows,
  harnessVersions: { codex, claudeCode: claude, pi, toolhive: thv, githubCli: gh },
  packageIntegrity: { codex: codexIntegrity, claudeCode: claudeIntegrity, pi: piIntegrity, githubCliSha256: ghSha },
  sourceCanonicalHash,
  imageContractHash,
  imageContract,
  credentialsBakedIntoImage: false,
};
const path="/evidence/daytona-images.json", temporary=path+".tmp";
fs.writeFileSync(temporary, JSON.stringify(evidence,null,2)+"\n", {mode:0o600});
fs.renameSync(temporary,path); fs.chmodSync(path,0o600);
console.log(JSON.stringify({status:"ready",snapshots:evidence.snapshots.map(({id,name,state})=>({id,name,state}))}));
NODE
  prepare_canonical_lock
  (
  flock -w 300 9 || die "timeout waiting for canonical platform.env lock"
  python3 - "$ENV_FILE" "$EVIDENCE_ROOT/daytona-images.json" <<'PY'
from pathlib import Path
import hashlib,json,sys
p,evidence_path=map(Path,sys.argv[1:]); raw=p.read_bytes(); v=dict(line.split("=",1) for line in raw.decode().splitlines() if "=" in line)
evidence=json.loads(evidence_path.read_text())
keys=["DAYTONA_TARGET","MTE_DAYTONA_SANDBOX_BASE_IMAGE","MTE_CODEX_VERSION","MTE_CLAUDE_CODE_VERSION","MTE_PI_VERSION","MTE_CODEX_NPM_INTEGRITY","MTE_CLAUDE_CODE_NPM_INTEGRITY","MTE_PI_NPM_INTEGRITY","MTE_TOOLHIVE_VERSION","MTE_TOOLHIVE_ARCHIVE_SHA256","MTE_GITHUB_CLI_VERSION","MTE_GITHUB_CLI_ARCHIVE_SHA256","MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL","HERMES_LLM_MODEL","MTE_PI_CODING_AGENT_DIR","MTE_DAYTONA_CODING_SNAPSHOT","MTE_DAYTONA_GENERAL_SNAPSHOT","MTE_DAYTONA_CODING_CPU","MTE_DAYTONA_CODING_MEMORY_GIB","MTE_DAYTONA_GENERAL_CPU","MTE_DAYTONA_GENERAL_MEMORY_GIB","MTE_DAYTONA_DISK_GIB"]
contract={key:v.get(key,"") for key in sorted(keys)}
contract_hash=hashlib.sha256(json.dumps(contract,sort_keys=True,separators=(",",":")).encode()).hexdigest()
if contract_hash != evidence.get("imageContractHash"):
    raise SystemExit("canonical Daytona image contract changed during snapshot build")
before_hash=hashlib.sha256(raw).hexdigest()
v["MTE_DAYTONA_CODING_SNAPSHOT_READY"]="true"; v["MTE_DAYTONA_GENERAL_SNAPSHOT_READY"]="true"
tmp=p.with_suffix(".tmp"); tmp.write_text("".join(f"{k}={v[k]}\n" for k in sorted(v))); tmp.chmod(0o600); tmp.replace(p)
after_hash=hashlib.sha256(p.read_bytes()).hexdigest()
evidence["canonicalBinding"]={"imageContractUnchanged":True,"fullCanonicalHashAtBuild":evidence.get("sourceCanonicalHash"),"fullCanonicalHashBeforeReadinessMerge":before_hash,"fullCanonicalHashAfterReadinessMerge":after_hash,"unrelatedFullSourceDrift":evidence.get("sourceCanonicalHash") != before_hash}
evidence["canonicalSourceSha256"]=after_hash
et=evidence_path.with_suffix(".tmp"); et.write_text(json.dumps(evidence,indent=2,sort_keys=True)+"\n"); et.chmod(0o600); et.replace(evidence_path)
print(json.dumps({"imageContractHash":contract_hash,"canonicalConfigHash":after_hash,"unrelatedFullSourceDrift":evidence["canonicalBinding"]["unrelatedFullSourceDrift"]}))
PY
  ) 9>"$ENV_LOCK"
}

lifecycle() {
  init_config
  [[ "$(env_value "$ENV_FILE" MTE_DAYTONA_CODING_SNAPSHOT_READY 2>/dev/null || true)" == "true" ]] || die "coding snapshot is not ready"
  local node_image
  node_image=$(env_value "$ENV_FILE" PAPERCLIP_NODE_IMAGE)
  docker run --rm -i --network host --user 0:0 \
    -e MTE_EVIDENCE_PRODUCER_SHA256="$PRODUCER_SHA256" \
    -v "$ENV_FILE:/run/secrets/platform.env:ro" \
    -v mte-paperclip-native-home:/paperclip-home:ro \
    -v "$EVIDENCE_ROOT:/evidence" \
    "$node_image" node --input-type=module <<'NODE'
import crypto from "node:crypto";
import fs from "node:fs";
const values = Object.fromEntries(
  fs.readFileSync("/run/secrets/platform.env", "utf8").split(/\n/)
    .filter((line) => line && !line.startsWith("#") && line.includes("="))
    .map((line) => { const i=line.indexOf("="); return [line.slice(0,i),line.slice(i+1)]; })
);
const { Daytona } = await import("file:///paperclip-home/.paperclip/plugins/node_modules/@daytonaio/sdk/src/index.js");
const daytona = new Daytona({apiKey:values.DAYTONA_API_KEY,apiUrl:values.MTE_DAYTONA_API_URL,target:values.DAYTONA_TARGET});
const labels={"mte.canary":"paperclip-daytona"};
const old = await daytona.list(labels,1,100);
for (const sandbox of old.items) await daytona.delete(sandbox);
const expected={
  cpu:Number(values.MTE_DAYTONA_CODING_CPU),
  memory:Number(values.MTE_DAYTONA_CODING_MEMORY_GIB),
  disk:Number(values.MTE_DAYTONA_DISK_GIB),
};
const states=[];
let sandbox;
let deleted=false;
let evidence;
const marker=`paperclip-daytona-${Date.now()}`;
const markerPath="/home/daytona/mte-lifecycle-marker.txt";
const state = (phase, value, providerState=sandbox?.state) => states.push({phase,state:value,providerState,at:new Date().toISOString()});
try {
  sandbox=await daytona.create({
    name:`mte-paperclip-canary-${Date.now()}`,
    snapshot:values.MTE_DAYTONA_CODING_SNAPSHOT,
    language:"typescript",
    labels,
    autoStopInterval:15,
    autoArchiveInterval:60,
  },{timeout:900});
  state("created","started");
  const gatewayRoute=await sandbox.process.executeCommand(
    `node -e "const fs=require('fs');const row=fs.readFileSync('/proc/net/route','utf8').split('\\n').map(x=>x.trim().split(/\\s+/)).find(x=>x[1]==='00000000');if(!row)process.exit(2);const h=row[2];console.log([6,4,2,0].map(i=>parseInt(h.slice(i,i+2),16)).join('.'))"`,
    undefined,undefined,30,
  );
  const observedGateway=String(gatewayRoute.result || "").trim();
  if (gatewayRoute.exitCode !== 0 || observedGateway !== values.MTE_AGENT_GATEWAY_HOST) {
    throw new Error("sandbox gateway does not match canonical agent gateway");
  }
  const credentialPaths=[
    "/home/daytona/.codex/auth.json",
    "/home/daytona/.claude/.credentials.json",
    "/home/daytona/.config/claude/credentials.json",
    "/home/daytona/.pi/agent/auth.json",
    "/home/daytona/.config/pi/agent/auth.json",
    "/home/daytona/.config/gh/hosts.yml",
  ];
  const workspacePaths=[
    "/home/daytona/workspaces/coding-daytona-codex",
    "/home/daytona/workspaces/coding-daytona-claude",
    "/home/daytona/workspaces/coding-daytona-pi",
  ];
  const workspaceProbe=await sandbox.process.executeCommand(
    `node -e 'const fs=require("fs");const paths=JSON.parse(process.argv[1]);const missing=paths.filter((path)=>!fs.existsSync(path)||!fs.statSync(path).isDirectory());if(missing.length)process.exit(43)' '${JSON.stringify(workspacePaths)}'`,
    undefined,undefined,30,
  );
  if (workspaceProbe.exitCode !== 0) throw new Error("native harness workspace directories are missing from snapshot");
  const expectedPiModels={providers:{mte9router:{baseUrl:values.MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL,apiKey:"$OPENAI_API_KEY",api:"openai-completions",models:[{id:values.HERMES_LLM_MODEL,name:"MTE MiniMax",reasoning:false,input:["text"],cost:{input:0,output:0,cacheRead:0,cacheWrite:0},contextWindow:200000,maxTokens:32768}]}}};
  const expectedPiConfigSha=crypto.createHash("sha256").update(JSON.stringify(expectedPiModels)).digest("hex");
  const piConfigPath=`${values.MTE_PI_CODING_AGENT_DIR}/models.json`;
  const piConfigProbe=await sandbox.process.executeCommand(`sha256sum ${piConfigPath}`,undefined,undefined,30);
  const observedPiConfigSha=String(piConfigProbe.result || "").trim().split(/\s+/)[0] || "";
  if (piConfigProbe.exitCode !== 0 || observedPiConfigSha !== expectedPiConfigSha) throw new Error("credential-free Pi probe config is missing or drifted");
  const credentialProbe=await sandbox.process.executeCommand(
    `node -e 'const fs=require("fs");const paths=JSON.parse(process.argv[1]);const found=paths.filter((path)=>fs.existsSync(path));if(found.length)process.exit(42)' '${JSON.stringify(credentialPaths)}'`,
    undefined,undefined,30,
  );
  if (credentialProbe.exitCode !== 0) throw new Error("native harness credential files are baked into snapshot");
  const versions=await sandbox.process.executeCommand("set -eu; codex --version; claude --version; pi --version; thv version; gh --version | head -1",undefined,undefined,180);
  if (versions.exitCode !== 0) throw new Error(`harness version probe failed (${versions.exitCode})`);
  const gitConfigProbe=await sandbox.process.executeCommand("set -eu; test \"$(git config --system --get user.name)\" = 'Paperclip Agent'; test \"$(git config --system --get user.email)\" = 'paperclip-agent@users.noreply.github.com'; test \"$(git config --system --get credential.https://github.com.helper)\" = '!gh auth git-credential'; ! git config --system --list | grep -E 'https://[^/[:space:]]+@github\\.com'",undefined,undefined,30);
  if (gitConfigProbe.exitCode !== 0) throw new Error("credential-free GitHub CLI/git configuration is missing or unsafe");
  await sandbox.fs.uploadFile(Buffer.from(marker,"utf8"),markerPath);
  const uploaded=await sandbox.fs.downloadFile(markerPath);
  if (Buffer.from(uploaded).toString("utf8") !== marker) throw new Error("upload/download mismatch");
  state("file-roundtrip","started");
  await sandbox.stop(); state("stopped","stopped");
  await sandbox.start(900); state("restarted","started");
  const afterRestart=Buffer.from(await sandbox.fs.downloadFile(markerPath)).toString("utf8");
  if (afterRestart !== marker) throw new Error("marker missing after stop/start");
  await sandbox.stop(); state("stopped-before-archive","stopped");
  await sandbox.archive(); state("archive-requested","archiving");
  for (let attempt=0; attempt<300; attempt += 1) {
    sandbox=await daytona.get(sandbox.id);
    if (sandbox.state === "archived") break;
    await new Promise((resolve)=>setTimeout(resolve,2000));
  }
  if (sandbox.state !== "archived") throw new Error(`archive timeout in state ${sandbox.state}`);
  state("archived","archived");
  await sandbox.start(900); state("restored-from-archive","restored");
  const afterArchive=Buffer.from(await sandbox.fs.downloadFile(markerPath)).toString("utf8");
  if (afterArchive !== marker) throw new Error("marker missing after archive restore");
  await sandbox.refreshData(); state("refreshed","started");
  const actual={cpu:sandbox.cpu,memory:sandbox.memory,disk:sandbox.disk};
  if (actual.cpu !== expected.cpu || actual.memory !== expected.memory || actual.disk !== expected.disk) {
    throw new Error(`resource mismatch ${JSON.stringify(actual)}`);
  }
  await sandbox.stop(); state("final-stop","stopped");
  evidence={
    apiVersion:"micro-task-engine/v1alpha1",kind:"DaytonaSandboxLifecycleEvidence",status:"ready",generatedAt:new Date().toISOString(),
    canonicalSourceSha256:crypto.createHash("sha256").update(fs.readFileSync("/run/secrets/platform.env")).digest("hex"),
    producerSha256:process.env.MTE_EVIDENCE_PRODUCER_SHA256,
    provider:"daytona",target:values.DAYTONA_TARGET,snapshot:values.MTE_DAYTONA_CODING_SNAPSHOT,
    sandboxId:sandbox.id,states,resources:{expected,actual,equal:true},
    fileRoundTrip:{verified:true,markerSha256:crypto.createHash("sha256").update(marker).digest("hex")},
    persistence:{verified:true,afterRestart:true,afterArchiveRestore:true},
    markerSha256:crypto.createHash("sha256").update(marker).digest("hex"),
    agentGateway:{expectedHost:values.MTE_AGENT_GATEWAY_HOST,observedDefaultGateway:observedGateway,matchesCanonical:true},
    harnessVersionOutput:versions.result.trim().split(/\r?\n/),credentialsBakedIntoImage:false,
    github:{
      cliVersion:values.MTE_GITHUB_CLI_VERSION,
      authentication:"GH_TOKEN-runtime-env",
      gitCredentialHelper:"gh auth git-credential",
      gitIdentity:{name:"Paperclip Agent",email:"paperclip-agent@users.noreply.github.com"},
      tokenInRemoteUrl:false,credentialFilePersisted:false,
    },
    credentialFileProbe:{checkedPaths:credentialPaths,foundPaths:[],credentialFree:true},
    workspaceDirectoryProbe:{checkedPaths:workspacePaths,missingPaths:[],allPresent:true},
    piProbeConfig:{path:piConfigPath,sha256:observedPiConfigSha,apiKeyReference:"$OPENAI_API_KEY",secretEmbedded:false},
  };
} finally {
  if (sandbox) {
    try { await daytona.delete(sandbox); deleted=true; } catch (error) { console.error(`sandbox cleanup failed: ${error.message}`); }
  }
}
if (!deleted) throw new Error("sandbox cleanup did not complete");
let getAfterDeleteStatus=0;
for (let attempt=0; attempt<90; attempt += 1) {
  try {
    await daytona.get(evidence.sandboxId);
  } catch (error) {
    const status=Number(error?.status || error?.statusCode || error?.response?.status || 0);
    if (status === 404 || /(?:^|\D)404(?:\D|$)/.test(String(error?.message || error))) {
      getAfterDeleteStatus=404;
      break;
    }
    throw error;
  }
  await new Promise((resolve)=>setTimeout(resolve,2000));
}
if (getAfterDeleteStatus !== 404) throw new Error("sandbox still exists after delete");
states.push({phase:"cleanup",state:"deleted",providerState:"not_found",at:new Date().toISOString()});
evidence.cleanupDeleted=true;
evidence.delete={requested:true,getAfterDeleteStatus};
const path="/evidence/daytona-lifecycle.json", temporary=path+".tmp";
fs.writeFileSync(temporary,JSON.stringify(evidence,null,2)+"\n",{mode:0o600});
fs.renameSync(temporary,path); fs.chmodSync(path,0o600);
console.log(JSON.stringify({status:"ready",sandboxId:evidence.sandboxId,states:states.map((row)=>row.state),resources:evidence.resources.actual,cleanupDeleted:true}));
NODE
}

status() { compose ps --format json; [[ -s $EVIDENCE ]] && cat $EVIDENCE || true; }
verify_gateway_upstreams() {
  python3 - "$ENV_FILE" <<'PY'
import json
from pathlib import Path
import subprocess
import sys
import urllib.parse

values = dict(
    line.split("=", 1)
    for line in Path(sys.argv[1]).read_text().splitlines()
    if line and not line.startswith("#") and "=" in line
)
inspected = json.loads(
    subprocess.check_output(
        ["docker", "inspect", "mte-daytona-runner", "mte-agent-plane-gateway"],
        text=True,
    )
)
by_name = {
    str(row.get("Name", "")).lstrip("/"): row
    for row in inspected
    if isinstance(row, dict)
}
runner = by_name.get("mte-daytona-runner") or {}
gateway = by_name.get("mte-agent-plane-gateway") or {}
runner_id = str(runner.get("Id") or "")
runner_networks = sorted((runner.get("NetworkSettings") or {}).get("Networks") or {})
expected_networks = sorted(
    {"mte-daytona-net", values["MTE_AGENT_PLANE_NETWORK"], "mte-tool-runtime"}
)
if runner_networks != expected_networks:
    raise SystemExit("Daytona runner private network set drifted")
gateway_network_mode = str((gateway.get("HostConfig") or {}).get("NetworkMode") or "")
if not runner_id or gateway_network_mode != "container:" + runner_id:
    raise SystemExit("agent gateway does not share the Daytona runner namespace")

def no_host_bindings(container):
    bindings = (container.get("HostConfig") or {}).get("PortBindings") or {}
    return not any(value for value in bindings.values())

if not no_host_bindings(runner) or not no_host_bindings(gateway):
    raise SystemExit("agent gateway or Daytona runner publishes a host port")

profiles = (
    ("coding-daytona-codex", "CODEX", 19011),
    ("coding-daytona-claude", "CLAUDE", 19012),
    ("coding-daytona-pi", "PI", 19013),
)
upstream_rows = []
for profile_ref, harness, expected_port in profiles:
    ref = f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_UPSTREAM"
    parsed = urllib.parse.urlsplit(values[ref])
    if (
        parsed.scheme != "http"
        or parsed.hostname != "toolhive"
        or parsed.port != expected_port
        or parsed.path not in {"", "/"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise SystemExit(f"{profile_ref} ToolHive upstream drifted")
    upstream_rows.append(
        {
            "profileRef": profile_ref,
            "upstreamRef": ref,
            "host": "toolhive",
            "port": expected_port,
        }
    )

inner = r'''
import json
import os
import urllib.request
profiles = (
    ("coding-daytona-codex", "CODEX", "TOOLHIVE_PROFILE_CODING_DAYTONA_CODEX_BEARER_TOKEN"),
    ("coding-daytona-claude", "CLAUDE", "TOOLHIVE_PROFILE_CODING_DAYTONA_CLAUDE_BEARER_TOKEN"),
    ("coding-daytona-pi", "PI", "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN"),
)
payload = json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"mte-daytona-gateway-verify","version":"1"}}}).encode()
rows = []
for profile_ref, harness, token_key in profiles:
    port = int(os.environ[f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_PORT"])
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/mcp",
        data=payload,
        method="POST",
        headers={"Accept":"application/json, text/event-stream","Authorization":"Bearer " + os.environ[token_key],"Content-Type":"application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read(1_000_000)
        if response.status != 200 or b'"result"' not in body or b'"error"' in body:
            raise SystemExit(f"{profile_ref} ToolHive gateway initialize failed")
        rows.append({"profileRef":profile_ref,"gatewayPort":port,"httpStatus":response.status,"initialize":True})
print(json.dumps({"status":"passed","profiles":rows}))
'''
completed = subprocess.run(
    ["docker", "exec", "mte-agent-plane-gateway", "python3", "-c", inner],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    check=True,
    timeout=120,
)
connectivity = json.loads(completed.stdout)
connectivity_by_profile = {
    row.get("profileRef"): row
    for row in connectivity.get("profiles", [])
    if isinstance(row, dict)
}
if connectivity.get("status") != "passed" or set(connectivity_by_profile) != {
    row[0] for row in profiles
}:
    raise SystemExit("ToolHive profile gateway connectivity proof is incomplete")
for row, (_, harness, _) in zip(upstream_rows, profiles, strict=True):
    observed = connectivity_by_profile[row["profileRef"]]
    expected_gateway_port = int(values[f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_PORT"])
    if (
        observed.get("gatewayPort") != expected_gateway_port
        or observed.get("httpStatus") != 200
        or observed.get("initialize") is not True
    ):
        raise SystemExit(f"{row['profileRef']} ToolHive gateway connectivity drifted")
    row.update(observed)

print(
    json.dumps(
        {
            "status": "passed",
            "profileCount": len(upstream_rows),
            "runnerContainerId": runner_id,
            "gatewayContainerId": str(gateway.get("Id") or ""),
            "gatewayNetworkMode": gateway_network_mode,
            "runnerNetworks": runner_networks,
            "expectedRunnerNetworks": expected_networks,
            "privateToolRuntimeNetwork": "mte-tool-runtime",
            "noPublishedPorts": True,
            "profiles": upstream_rows,
        },
        sort_keys=True,
    )
)
PY
}
verify() {
  local api_port paperclip_api gateway_proof canonical_sha config_sha
  api_port=$(env_value "$ENV_FILE" MTE_DAYTONA_API_PORT)
  paperclip_api=$(env_value "$ENV_FILE" MTE_PAPERCLIP_API_BASE)
  wait_url "http://127.0.0.1:${api_port}/api/config"
  wait_url "${paperclip_api}/health"
  gateway_proof=$(verify_gateway_upstreams)
  canonical_sha=$(sha256sum "$ENV_FILE" | awk '{print $1}')
  config_sha=$(config_hash)
  python3 - "$ENV_FILE" "$EVIDENCE" "$canonical_sha" "$config_sha" "$gateway_proof" "$PRODUCER_SHA256" "$SCRIPT_PATH" <<'PY'
from pathlib import Path
import datetime,hashlib,json,sys,urllib.request
v=dict(line.split("=",1) for line in Path(sys.argv[1]).read_text().splitlines() if "=" in line)
with urllib.request.urlopen(v["MTE_PAPERCLIP_API_BASE"]+"/instance/settings/experimental",timeout=30) as r: flags=json.load(r)
with urllib.request.urlopen(v["MTE_PAPERCLIP_API_BASE"]+"/plugins",timeout=30) as r: plugins=json.load(r)
gateway=json.loads(sys.argv[5])
e={"apiVersion":"micro-task-engine/v1alpha1","kind":"PaperclipDaytonaControlPlaneEvidence","status":"ready","generatedAt":datetime.datetime.now(datetime.timezone.utc).isoformat(),
"action":"verify","canonicalSourceSha256":sys.argv[3],"canonicalConfigHash":sys.argv[4],"producerSha256":sys.argv[6],"producerPath":sys.argv[7],"paperclipVersion":v["MTE_PAPERCLIP_VERSION"],"daytonaOssVersion":v["MTE_DAYTONA_OSS_VERSION"],
"experimental":{"environments":flags["enableEnvironments"],"isolatedWorkspaces":flags["enableIsolatedWorkspaces"]},
"pluginReady":any(x.get("pluginKey")=="paperclip.daytona-sandbox-provider" and x.get("status")=="ready" for x in plugins),
"daytonaApiKeyFingerprint":hashlib.sha256(v.get("DAYTONA_API_KEY","").encode()).hexdigest()[:16],
"agentGateway":gateway,"secretValuesPrinted":False,
"endpoints":{"paperclip":v["MTE_PAPERCLIP_API_BASE"],"daytona":v["MTE_DAYTONA_API_URL"]},
"knownUpstreamRisk":"Daytona OSS v0.190.0 is unmaintained; upstream Compose is not documented production-safe"}
p=Path(sys.argv[2]); tmp=p.with_suffix(".tmp"); tmp.write_text(json.dumps(e,indent=2)+"\n"); tmp.chmod(0o600); tmp.replace(p); print(json.dumps(e))
PY
}
rollback() {
  local release_file=$ROOT/releases/$ARG.json
  [[ -s "$release_file" ]] || die "unknown release"
  init_config
  (
  flock -w 300 9 || die "timeout waiting for canonical platform.env lock"
  python3 - "$ENV_FILE" "$release_file" "$ROOT/current-release" <<'PY'
from pathlib import Path
import json,sys
envp,releasep,current=map(Path,sys.argv[1:]); payload=json.loads(releasep.read_text())
v=dict(line.split("=",1) for line in envp.read_text().splitlines() if "=" in line)
v.update({str(k):str(x) for k,x in payload["images"].items()})
tmp=envp.with_suffix(".tmp"); tmp.write_text("".join(f"{k}={v[k]}\n" for k in sorted(v))); tmp.chmod(0o600); tmp.replace(envp)
ct=current.with_suffix(".tmp"); ct.write_text(str(payload["releaseId"])+"\n"); ct.chmod(0o600); ct.replace(current)
PY
  ) 9>"$ENV_LOCK"
  render
  compose up -d
  assert_runtime_config_current
}
remove() { compose down || true; log "containers removed; data preserved"; }
acceptance() { build_images; lifecycle; verify; }
all() {
  install_daytona
  provision_key
  set_target
}

case $ACTION in
preflight) preflight;; install) install_daytona;; provision-key) provision_key;; set-target) set_target;; verify) verify;; status) status;;
images) build_images;;
lifecycle) lifecycle;;
acceptance) acceptance;;
refresh-images) resolve_images; render; compose up -d;; rollback-images) rollback;; remove) remove;; all) all;;
*) die "usage: 60-daytona.sh preflight|install|provision-key|set-target|images|lifecycle|acceptance|verify|status|refresh-images|rollback-images RELEASE_ID|remove|all";;
esac

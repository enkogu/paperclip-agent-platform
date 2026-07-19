# Platform operations

Use the operator checkout for release orchestration and the installed host
scripts for Hermes. Do not run the checkout-only `./platform` wrapper from the
managed host: it is an SSH orchestrator, not the host control plane.

## Status labels

- **Implemented**: the command or API route exists in the pinned source.
- **Live-proven**: fresh, source-bound acceptance evidence proves the behavior
  on the current host. An implementation or an old evidence file is not proof.
- **Desired**: declared architecture with no complete implementation or live
  acceptance. Do not operate it as if it existed.

Source implementation and stored evidence are not a current-host claim. Treat
a failed or incomplete `./install.sh`, old evidence, or an unverified status
row as unproven; use the matching verifier against the active source revision.

## Contents

- [Start read-only](#start-read-only)
- [Native Paperclip Issue operations](#native-paperclip-issue-operations)
- [Native Kestra execution operations](#native-kestra-execution-operations)
- [Compose-managed applications](#compose-managed-applications)
- [App-by-app command map](#app-by-app-command-map)
- [GitHub PR/check cleanup](#github-prcheck-cleanup)
- [Completion evidence](#completion-evidence)

## Start read-only

From the operator checkout:

```bash
./platform status
./platform config audit
./platform config diff
./platform secrets audit
./platform acceptance check
./test.sh smoke
./test.sh e2e
```

From Hermes on the managed host:

```bash
sudo -n python3 /opt/mte-platform/bin/server-verify.py status
sudo -n python3 /opt/mte-platform/bin/server-config.py audit
sudo -n python3 /opt/mte-platform/bin/server-config.py diff
sudo -n python3 /opt/mte-platform/bin/server-secrets.py audit
sudo -n python3 /opt/mte-platform/bin/server-verify.py acceptance
```

`status` and several component `status` commands read stored evidence. Use the
narrow `verify` when freshness matters. Mutating repair requires explicit
approval, a canonical source, and a post-repair verifier.

## Native Paperclip Issue operations

**Implemented.** These routes are present in Paperclip `v2026.707.0` and used by
the current Kestra and canary source. **Live proof is per Issue/run evidence, not
the HTTP response.** Hermes receives only the scoped
`HERMES_PAPERCLIP_API_KEY`; never echo it or enable shell tracing.

In a Hermes terminal, define a narrow client. `HERMES_PAPERCLIP_URL` already
ends in `/api`.

```bash
set +x
pc() {
  curl --fail-with-body --silent --show-error \
    --config <(printf 'header = "Authorization: Bearer %s"\n' \
      "${HERMES_PAPERCLIP_API_KEY:?missing}") \
    -H 'Content-Type: application/json' "$@"
}
```

Create one Issue. Build JSON with a real serializer; do not interpolate task
text into JSON manually.

```bash
export COMPANY_ID PROJECT_ID ASSIGNEE_AGENT_ID TITLE DESCRIPTION
payload="$({
  python3 - <<'PY'
import json, os
print(json.dumps({
    "title": os.environ["TITLE"],
    "description": os.environ["DESCRIPTION"],
    "status": "todo",
    "priority": "medium",
    "projectId": os.environ["PROJECT_ID"],
    "assigneeAgentId": os.environ["ASSIGNEE_AGENT_ID"],
}))
PY
})"
pc -X POST \
  "${HERMES_PAPERCLIP_URL}/companies/${COMPANY_ID}/issues" \
  --data-binary "$payload" |
python3 -c 'import json,sys; v=json.load(sys.stdin); print(json.dumps({k:v.get(k) for k in ("id","identifier","status","assigneeAgentId")},indent=2))'
unset payload TITLE DESCRIPTION
```

Read durable Issue status and the latest heartbeat separately:

```bash
export ISSUE_ID
pc "${HERMES_PAPERCLIP_URL}/issues/${ISSUE_ID}" |
python3 -c 'import json,sys; v=json.load(sys.stdin); print(json.dumps({k:v.get(k) for k in ("id","identifier","status","assigneeAgentId","updatedAt")},indent=2))'
pc "${HERMES_PAPERCLIP_URL}/issues/${ISSUE_ID}/runs" |
python3 -c 'import json,sys; v=json.load(sys.stdin); r=(v if isinstance(v,list) else v.get("data",[])); r=sorted(r,key=lambda x:x.get("createdAt", "")); print(json.dumps(({k:r[-1].get(k) for k in ("id","status","livenessState","livenessReason","createdAt","updatedAt")} if r else {}),indent=2))'
```

Add a comment without changing status:

```bash
export COMMENT
payload="$(python3 -c 'import json,os; print(json.dumps({"body":os.environ["COMMENT"]}))')"
pc -X POST "${HERMES_PAPERCLIP_URL}/issues/${ISSUE_ID}/comments" \
  --data-binary "$payload" >/dev/null
unset payload COMMENT
```

The provisioned Hermes credential uses Paperclip's `task_bridge` scope. The
current source proves create, read, and comment access for bridge-created or
assigned Issues. It does **not** grant `tasks:manage_active_checkouts` or other
board-wide authority. Paperclip's ownership guard therefore rejects `PATCH` and
heartbeat cancellation when the authenticated caller does not own the active
checkout.

Before any cancellation, compare the authenticated caller identity, Issue
assignee, and active-checkout owner. A mismatch is a stop request, not a right
to mutate: Hermes may inspect state, add a comment, and cancel an owning Kestra
execution only when that separate credential permits it. Then wait for the
owning agent or an authenticated board operator to change the durable Issue
state. Do not report the task as stopped until both the run and Issue have
reached the observed terminal state.

Status mutation and heartbeat cancellation may be documented here only after
the provisioner grants a deliberately scoped Paperclip permission and a live
acceptance test proves both the allowed path and cross-company denial. Until
then, use the Paperclip UI or an independently authenticated board operator for
those actions; do not reuse a human token in Hermes.

Do not use the removed prototype `/v1/runs` gateway. Do not delete a business
Issue for ordinary cancellation. Deletion is reserved for bounded canary
cleanup after identity checks.

## Native Kestra execution operations

**Implemented.** The current source and Kestra `v1.3.27` agree on the Open
Source tenant `main`. **Live proof requires a terminal execution plus its
Paperclip/GitHub evidence.** This Bash helper keeps Basic Auth out of curl's
argument list by passing a temporary in-memory config descriptor.

```bash
set +x
kestra() {
  curl --fail-with-body --silent --show-error \
    --config <(printf 'user = "%s:%s"\n' \
      "${HERMES_KESTRA_USERNAME:?missing}" \
      "${HERMES_KESTRA_PASSWORD:?missing}") "$@"
}
```

Start a flow with one `-F 'input=value'` per declared input:

```bash
export NAMESPACE FLOW_ID
FLOW_PATH="$(python3 - "$NAMESPACE" "$FLOW_ID" <<'PY'
import sys, urllib.parse
print("/".join(urllib.parse.quote(value, safe="") for value in sys.argv[1:]))
PY
)"
kestra -X POST \
  "${HERMES_KESTRA_URL}/api/v1/main/executions/${FLOW_PATH}" \
  -F 'profile=coding-daytona-codex' |
python3 -c 'import json,sys; v=json.load(sys.stdin); print(json.dumps({"id":v.get("id"),"state":(v.get("state") or {}).get("current")},indent=2))'
```

Read status:

```bash
export EXECUTION_ID
EXECUTION_PATH="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1],safe=""))' "$EXECUTION_ID")"
kestra "${HERMES_KESTRA_URL}/api/v1/main/executions/${EXECUTION_PATH}" |
python3 -c 'import json,sys; v=json.load(sys.stdin); print(json.dumps({"id":v.get("id"),"namespace":v.get("namespace"),"flowId":v.get("flowId"),"state":(v.get("state") or {}).get("current")},indent=2))'
```

Request cancellation, then poll until `KILLED`, `FAILED`, `SUCCESS`,
`CANCELLED`, or another terminal state is observed:

```bash
kestra -X DELETE -o /dev/null \
  "${HERMES_KESTRA_URL}/api/v1/main/executions/${EXECUTION_PATH}/kill"
```

The kill endpoint returns `202` for a request, `404` when absent, and `409` for
an already-finished execution. A request is not terminal proof.

## Compose-managed applications

The aggregate project is `/opt/mte-platform/deployment/compose.yaml`. Inspect
its observed state directly instead of resolving a second control-plane ID:

```bash
sudo -n docker compose \
  --env-file /root/.config/mte-secrets/platform.env \
  -f /opt/mte-platform/deployment/compose.yaml ps
```

Read bounded logs only in a trusted terminal. Never copy raw logs into chat;
summarize timestamps, error classes, IDs, and hashes. Do not run
`docker inspect .Config.Env`, `env`, or `set -x`.

```bash
for cid in $(sudo -n docker ps -q \
  --filter 'label=com.docker.compose.project=mte-platform'); do
  sudo -n docker inspect --format '{{.Name}}' "$cid"
  sudo -n docker logs --since 15m --tail 200 --timestamps "$cid" 2>&1 |
  python3 -c 'import re,sys; p=re.compile(r"(?i)((?:authorization|bearer|token|api[_ -]?key|secret|password|cookie)\s*[:=]\s*)([^\s,;]+)"); [print(p.sub(r"\1<redacted>",x),end="") for x in sys.stdin]'
done
```

A transient restart is allowed only after approval and only for the one exact,
currently running Compose service identified during diagnosis. It is not
repair; never restart every container in the project:

```bash
SERVICE=paperclip # exact service name observed with `docker compose ps`
COMPONENT=paperclip # matching verifier component
container="$(sudo -n docker compose \
  --env-file /root/.config/mte-secrets/platform.env \
  -f /opt/mte-platform/deployment/compose.yaml ps -q "$SERVICE")"
test -n "$container"
test "$(printf '%s\n' "$container" | wc -l | tr -d ' ')" = 1
test "$(sudo -n docker inspect --format '{{.State.Running}}' "$container")" = true
sudo -n docker restart "$container" >/dev/null
sudo -n python3 /opt/mte-platform/bin/server-verify.py verify "$COMPONENT"
```

Canonical repair is a health-gated direct Compose reconcile followed by the
narrow verifier. From the operator checkout:

```bash
./install.sh compose "$COMPONENT"
./test.sh smoke "$COMPONENT"
```

## App-by-app command map

All rows are **implemented**. A row becomes **live-proven** only when its fresh
verify/acceptance evidence is bound to the active canonical source hash.

| App | Read-only status and proof | Approved repair |
| --- | --- | --- |
| 9Router | `sudo -n python3 /opt/mte-platform/bin/server-verify.py verify 9router`; `sudo -n python3 /opt/mte-platform/bin/server-provision.py status`; then `verify` | `./install.sh compose 9router`; then `./install.sh provision paperclip` if routing bindings changed |
| Mattermost | `sudo -n python3 /opt/mte-platform/bin/server-verify.py verify mattermost`; `sudo -n python3 /opt/mte-platform/bin/server-provision.py status` | `./install.sh compose mattermost`; reprovision only after preserving current IDs |
| Firecrawl | `sudo -n python3 /opt/mte-platform/bin/server-verify.py verify firecrawl` | `./install.sh compose firecrawl`; run integration canaries before claiming agent access |
| SearXNG | `sudo -n python3 /opt/mte-platform/bin/server-verify.py verify searxng` | `./install.sh compose searxng`; verify Firecrawl-to-SearXNG after repair |
| PostgreSQL/PostgREST | `sudo -n python3 /opt/mte-platform/bin/server-verify.py verify postgres postgrest`; `sudo -n python3 /opt/mte-platform/bin/server-provision.py status` | `./install.sh compose postgres`; never initialize or drop data during repair |
| Notion projection | `sudo -n python3 /opt/mte-platform/bin/server-notion.py status`; `sudo -n python3 /opt/mte-platform/bin/server-notion-sync.py status`; then `verify` | `sudo -n python3 /opt/mte-platform/bin/server-notion.py provision`; then `sudo -n python3 /opt/mte-platform/bin/server-notion-sync.py provision`; `drain`; `verify` |
| ToolHive | `sudo -n python3 /opt/mte-platform/bin/server-toolhive.py status`; then `verify`; `sudo -n python3 /opt/mte-platform/bin/server-profile-reconcile.py status` | `./install.sh compose toolhive`; `./install.sh provision toolhive-profiles` |
| Daytona | `sudo -n /opt/mte-platform/steps/daytona.sh status`; `sudo -n python3 /opt/mte-platform/bin/server-paperclip-experimental.py daytona status` | operator-side `./platform daytona apply`, then `./platform daytona verify`; do not hand-edit the provider or snapshots |
| Victoria*/Grafana | `sudo -n python3 /opt/mte-platform/bin/server-verify.py verify observability`; inspect current acceptance evidence | `./install.sh compose observability`; rerun full acceptance before claiming telemetry recovery |
| Cloudflare | `sudo -n /opt/mte-platform/steps/cloudflare-tunnel.sh status`; `sudo -n /opt/mte-platform/steps/origin-firewall.sh status`; `sudo -n python3 /opt/mte-platform/bin/server-verify.py verify cloudflare-edge` | operator-side `./platform cloudflare plan`, `apply`, `origin-firewall`, `verify`, and `acceptance` |
| Paperclip | `sudo -n /opt/mte-platform/steps/paperclip.sh status`; then `verify`; read Issue plus latest heartbeat | `sudo -n /opt/mte-platform/steps/paperclip.sh install`; then operator-side environments, secrets, profiles, and provision verification |
| Kestra | `sudo -n python3 /opt/mte-platform/bin/server-kestra-reconcile.py status`; native execution GET; `sudo -n python3 /opt/mte-platform/bin/server-verify.py verify kestra` | `./install.sh compose kestra`; `./install.sh provision kestra`; then `verify` |
| Hermes | `sudo -n python3 /opt/mte-platform/bin/server-hermes.py status`; then `health`; `sudo -n systemctl status mte-hermes` | `sudo -n python3 /opt/mte-platform/bin/server-hermes.py reconcile`; restart only through systemd; see `hermes.md` |

## GitHub PR/check cleanup

**Implemented.** It becomes **live-proven** for one bounded E2E identity only
after fresh cleanup evidence and global absence checks pass. Never merge or
close an arbitrary PR. The current canary owns draft PRs titled
`Paperclip Daytona E2E <execution-id>` on branches
`agent/paperclip-e2e-<execution-id>`.

Inspect identity and checks first:

```bash
export GH_REPO PR_NUMBER EXECUTION_ID BASE_BRANCH
OWNER="${GH_REPO%%/*}"
tmp="$(mktemp)"; ref_err="$(mktemp)"
chmod 600 "$tmp" "$ref_err"
trap 'rm -f "$tmp" "$ref_err"' EXIT
gh pr view "$PR_NUMBER" -R "$GH_REPO" \
  --json number,url,state,isDraft,title,headRefName,baseRefName,headRepositoryOwner \
  >"$tmp"
python3 - "$tmp" "$EXECUTION_ID" "$BASE_BRANCH" "$OWNER" <<'PY'
import json, sys
v=json.load(open(sys.argv[1])); run=sys.argv[2]; base=sys.argv[3]; owner=sys.argv[4]
assert v["state"] == "OPEN" and v["isDraft"] is True
assert v["title"] == f"Paperclip Daytona E2E {run}"
assert v["headRefName"] == f"agent/paperclip-e2e-{run}"
assert v["baseRefName"] == base
assert (v.get("headRepositoryOwner") or {}).get("login") == owner
print(json.dumps({k:v[k] for k in ("number","url","state","isDraft","headRefName","baseRefName")},indent=2))
PY
gh pr checks "$PR_NUMBER" -R "$GH_REPO" \
  --json name,state,bucket,link
```

After evidence capture and explicit cleanup approval:

```bash
gh pr close "$PR_NUMBER" -R "$GH_REPO" --delete-branch \
  --comment "Closing bounded Paperclip E2E resource after evidence capture."
gh pr view "$PR_NUMBER" -R "$GH_REPO" --json number,state,headRefName
if gh api "repos/${GH_REPO}/git/ref/heads/agent/paperclip-e2e-${EXECUTION_ID}" \
  --silent 2>"$ref_err"; then
  echo 'branch still exists' >&2
  exit 1
elif grep -q 'HTTP 404' "$ref_err"; then
  echo 'branch ref absent (HTTP 404)'
else
  sed -n '1,20p' "$ref_err" >&2
  echo 'unable to prove branch ref absence' >&2
  exit 1
fi
```

If cleanup identity is ambiguous, stop. Do not broaden a branch prefix or use a
repository-wide deletion command.

## Completion evidence

A component is complete only when live verification proves real behavior and
cleanup on the same source/release hash. Container health, a successful HTTP
mutation, source tests, or stored evidence alone are insufficient. For backup,
restore, upgrade, and rollback boundaries, read
[backup-upgrade.md](backup-upgrade.md).

Pinned upstream anchors: Paperclip
[`v2026.707.0` Issue API](https://github.com/paperclipai/paperclip/blob/390627b46eb333309d357004384b220ecf8a65af/docs/api/issues.md)
and Kestra
[`v1.3.27` ExecutionController](https://github.com/kestra-io/kestra/blob/58331bde2ec7389629a352936d74621307b9a4d7/webserver/src/main/java/io/kestra/webserver/controllers/api/ExecutionController.java).

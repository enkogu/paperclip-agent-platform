# Diagnosis and repair

Diagnose from the narrowest read-only command. Keep the active source hash,
release/run ID, native Issue/execution IDs, and timestamps. Never edit a
rendered projection or paste secret-bearing output.

## Contents

- [Triage](#triage)
- [Freshness and proof](#freshness-and-proof)
- [Failure map](#failure-map)
- [Stuck work](#stuck-work)
- [Safe secret readiness](#safe-secret-readiness)
- [Repair rules](#repair-rules)

## Triage

Operator checkout:

```bash
./platform status
./platform config audit
./platform config diff
./platform secrets audit
./platform acceptance check
```

Hermes on the managed host:

```bash
sudo -n python3 /opt/mte-platform/bin/server-verify.py status
sudo -n python3 /opt/mte-platform/bin/server-config.py audit
sudo -n python3 /opt/mte-platform/bin/server-config.py diff
sudo -n python3 /opt/mte-platform/bin/server-secrets.py audit
sudo -n python3 /opt/mte-platform/bin/server-verify.py acceptance
```

Then select exactly one component:

```bash
sudo -n python3 /opt/mte-platform/bin/server-verify.py verify COMPONENT
```

Read [operations.md](operations.md) for bounded container discovery and
redacted logs. Do not start with all container logs: that loses causal identity
and increases disclosure risk.

## Freshness and proof

Classify every finding before repair:

- **Implemented**: source path/route/command exists.
- **Live-proven**: fresh evidence is `passed`, has the active canonical source
  hash, has the expected producer hash, and proves cleanup where applicable.
- **Stale/unproven**: evidence is absent, old, source-mismatched, or from a
  failed/incomplete installation.
- **Desired**: only a manifest/connection declaration exists.

`sudo -n python3 /opt/mte-platform/bin/server-kestra-reconcile.py status`,
and many top-level status rows may read evidence without contacting the live
service. Run the matching verifier before calling the service healthy.

## Failure map

| Symptom | Read-only diagnosis | Repair owner |
| --- | --- | --- |
| Canonical/config drift | `sudo -n python3 /opt/mte-platform/bin/server-config.py audit`; then `diff`; compare only paths, hashes, missing key names | canonical operator input; then `sudo -n python3 /opt/mte-platform/bin/server-config.py render`; then `audit` |
| Compose service missing/unhealthy | `sudo -n docker compose --env-file /root/.config/mte-secrets/platform.env -f /opt/mte-platform/deployment/compose.yaml ps`; inspect the exact service | operator-side `./install.sh compose COMPONENT` |
| Paperclip task stuck | GET Issue, `/runs`, latest heartbeat, `/events`, and `/diagnostics/wakes` | Paperclip Issue/heartbeat cleanup; Kestra owns retry policy |
| Kestra flow/execution stuck | native execution GET; `sudo -n python3 /opt/mte-platform/bin/server-kestra-reconcile.py verify` | kill exact execution; reconcile flow from `workflows/kestra` |
| 9Router failure | `sudo -n python3 /opt/mte-platform/bin/server-provision.py status`; `sudo -n python3 /opt/mte-platform/bin/server-verify.py verify 9router`; correlate scoped route usage by run ID | `./install.sh compose 9router`, then `sudo -n python3 /opt/mte-platform/bin/server-provision.py verify`; never replace keys ad hoc |
| Mattermost/Hermes messaging failure | `sudo -n python3 /opt/mte-platform/bin/server-hermes.py health`; verify Mattermost apps and allowed IDs | preserve bot/user/channel IDs; reconcile Hermes projection |
| Firecrawl/SearXNG failure | `sudo -n python3 /opt/mte-platform/bin/server-verify.py verify searxng firecrawl`; check C023/C024 evidence | direct Compose repair from `operations.md`: SearXNG before Firecrawl; then integration canary |
| Postgres/PostgREST/Notion lag | `sudo -n python3 /opt/mte-platform/bin/server-verify.py verify postgres postgrest`; exact Notion status commands from `operations.md` | preserve PostgreSQL; provision connector; drain outbox; verify read-back |
| ToolHive tool unavailable | `sudo -n python3 /opt/mte-platform/bin/server-toolhive.py status`; then `verify`; `sudo -n python3 /opt/mte-platform/bin/server-profile-reconcile.py status` | deploy ToolHive; provision bundles; reconcile profiles twice |
| Daytona workspace failure | `sudo -n /opt/mte-platform/steps/daytona.sh status`; `sudo -n python3 /opt/mte-platform/bin/server-paperclip-experimental.py daytona status` | operator-side `./platform daytona apply`; preserve failed sandbox until inspected |
| Metrics/logs/traces disagree | `sudo -n python3 /opt/mte-platform/bin/server-verify.py verify observability`; compare one `run_id` across Victoria*/Grafana evidence | `./install.sh compose observability`; then full acceptance |
| Cloudflare route failure | exact tunnel, firewall, and component verify commands from `operations.md` | exact operator-side Cloudflare sequence from `operations.md`; no direct DNS edits |

## Stuck work

### Paperclip

1. GET `/api/issues/{issueId}`.
2. GET `/api/issues/{issueId}/runs` and select the latest by `createdAt`.
3. For a run, GET `/api/heartbeat-runs/{runId}`, `/events`, and Issue
   `/diagnostics/wakes`.
4. If useful output exists, validate the requested artifact before deciding
   completion. A `succeeded` heartbeat can still have `needs_followup`.
5. If cancellation is approved, first compare the authenticated caller, Issue
   assignee, and active-checkout owner. Only the owner or an authenticated board
   operator may POST the non-terminal heartbeat `/cancel` and PATCH the Issue to
   `cancelled` with an audit comment. A mismatch permits a stop-request comment
   only.
6. Re-read both resources. The durable Issue and latest heartbeat are separate
   facts; do not collapse them into one guessed state.

Do not delete the Issue to cancel it. Do not retry a checkout `409`: another
agent owns the task.

### Kestra

1. GET `/api/v1/main/executions/{executionId}` and record `state.current`.
2. Confirm the execution maps to the expected flow, namespace, Paperclip Issue,
   and GitHub branch before mutation.
3. DELETE `/api/v1/main/executions/{executionId}/kill` only after approval.
4. Poll the same execution to a terminal state; `202` means requested, not
   killed.
5. Cancel a remaining Paperclip heartbeat/Issue separately. Kestra kill does
   not prove downstream cleanup.

## Safe secret readiness

Use only redacted platform checks:

```bash
sudo -n python3 /opt/mte-platform/bin/server-config.py audit
sudo -n python3 /opt/mte-platform/bin/server-secrets.py audit
sudo -n python3 /opt/mte-platform/bin/server-provision.py status
sudo -n python3 /opt/mte-platform/bin/server-hermes.py status
```

`config audit` reports missing key **names** and projection hashes.
`secrets audit` scans registered config/evidence for copied sensitive values but
does not prove every external credential works. `provision status` and component
verifiers prove scoped API readiness without printing values.

For a one-key local readiness check, inspect presence and length only inside a
root process. Never print the value or its environment line:

```bash
sudo -n python3 - KEY_NAME <<'PY'
from pathlib import Path
import sys
key=sys.argv[1]
values=dict(line.split("=",1) for line in Path("/root/.config/mte-secrets/platform.env").read_text().splitlines() if "=" in line and not line.startswith("#"))
value=values.get(key, "")
print({"key": key, "configured": bool(value), "lengthClass": "24+" if len(value) >= 24 else ("1-23" if value else "missing")})
raise SystemExit(0 if value else 1)
PY
```

Do not use `env`, `printenv`, `docker inspect .Config.Env`, shell tracing, or a
command argument containing a credential. Fingerprints already produced by an
official redacted verifier are acceptable; do not invent a new fingerprint
when mere presence is enough.

## Repair rules

1. Ask for approval before restart, reconcile, cancellation, PR cleanup, or
   any externally visible action.
2. Fix `config/platform.env` and render it; never patch `/opt/mte-platform/config`, a
   service env file, Compose projection, Hermes runtime env, or live SaaS state
   by hand.
3. Use component dependency order. Databases precede apps; SearXNG precedes
   Firecrawl; 9Router precedes Kestra/Paperclip/Hermes.
4. Preserve failed workspaces, provider objects, and logs until evidence is
   captured. Cleanup only exact run-scoped resources.
5. Rerun only the failed idempotent stage. There is no hidden resume or
   automatic service/data rollback.
6. Run the narrow verifier after repair, then the acceptance gate required by
   the blast radius. If diagnosis is impossible without raw secrets or broad
   deletion, stop and escalate the observability gap.

Backup, restore, upgrade, and rollback limits are in
[backup-upgrade.md](backup-upgrade.md).

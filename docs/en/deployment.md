# Deployment runbook

The supported deployment target is a dedicated Linux host. Hostname, base
domain and excluded hosts are operator inputs; no real infrastructure address
is compiled into the public repository.

## 1. Prepare the operator environment

```bash
cp config/platform.env.example /secure/path/platform.env
chmod 600 /secure/path/platform.env
# Replace all example values in the copy.
export MTE_OPERATOR_ENV=/secure/path/platform.env
./platform config check
```

The private copy carries operator-owned deployment and external-service inputs.
It is not read by services. Bootstrap imports recognized non-empty values
fill-only and materializes safe defaults and generated credentials into the
single root-owned canonical environment on the host. Never commit the
populated copy.

## 2. Validate without mutation

```bash
./platform plan --all
./platform preflight
python3 tools/platform-cli/local-verify.py
make release-check
```

`plan --all` prints the indexed operation. `preflight` checks the source,
operator inputs and remote target without deploying applications.

## Numbered host steps

`deployment/steps` contains exactly five idempotent host-runtime installers:

```text
10-host.sh
50-paperclip.sh
60-daytona.sh
90-cloudflare-tunnel.sh
91-origin-firewall.sh
```

They are part of the immutable release as `/opt/mte-platform/steps/*.sh` and
are invoked by the platform CLI. They are not source-mutation patches. Service
definitions remain owner-scoped under `deployment/services`; already-applied
repository migrations are represented only by their final source and tests.

## 3. Deploy

```bash
./platform deploy --all
```

The command freezes the source and executes 39 ordered steps:

1. initialize, normalize, render and audit canonical configuration;
2. bootstrap the host, ToolHive binary and Dokploy;
3. deploy application databases and selected components;
4. install Paperclip and declarative profiles;
5. reconcile Paperclip environments and secret scopes;
6. provision services and verify a second idempotent pass;
7. reconcile PostgreSQL/PostgREST/Notion projections;
8. reconcile Kestra, ToolHive, Daytona, harness auth and Hermes;
9. run real Kestra/Paperclip/harness and integration canaries;
10. reconcile observability twice and prove idempotency;
11. plan/apply/accept Cloudflare;
12. rebind evidence, check connections and run the final verifier.

Each step remains individually callable through the CLI where a corresponding
command exists. `deploy --all` is the authoritative ordering.

## 4. Inspect and verify

```bash
./platform status
./platform verify --all
./platform connections check
./platform provision verify
./platform notion-projection status
./platform notion-projection verify
./platform tools verify
./platform harness-auth verify
./platform profile-acceptance verify
./platform integration-canaries status
./platform cloudflare status
./platform cloudflare acceptance
```

`verify --all` is the explicit complete-platform acceptance. `verify` without
the flag and `verify COMPONENT...` remain available for narrower diagnosis.

## Resume after failure

Resume only from the run ID or evidence printed by the failed indexed run:

```bash
./platform deploy --all --resume RUN_ID_OR_EVIDENCE
```

Do not resume after editing the source. Start a new full deployment so the
evidence remains bound to one immutable source hash.

Source promotion is transactional, but it does not imply destructive database
rollback. Provider objects and canonical data are retained for diagnosis unless
an explicit, verified cleanup operation owns them.

## Supported CLI map

```text
plan [COMPONENT...] [--all]
preflight
sync
bootstrap
secrets init|audit
config init|render|audit|diff
deploy [COMPONENT...] [--no-wait] [--all] [--resume ID]
verify [COMPONENT...] [--all]
status
connections export|check
profiles render|apply
runtime paperclip config-migrate|install|status|verify|remove
paperclip-environments apply|status|verify
paperclip-secrets apply|status|verify
daytona apply|status|verify
kestra-canary apply|status|verify
kestra-control provision|status|verify
profile-acceptance verify
integration-canaries run|status [ID...]
provision apply|status|verify
notion-projection apply|drain|status|verify
tools install|provision|status|verify
harness-auth status|verify
hermes preflight|install|status|health|remove [--purge-data]
cloudflare token-plan|token-status|token-apply|preflight|render|plan|apply|status|verify|acceptance
```

## Configuration workflow

```bash
./platform config init       # fill missing canonical values
./platform config render     # render projections
./platform config audit      # reject missing values and drift
./platform config diff       # inspect projection differences
./platform secrets audit     # permissions and disclosure checks
```

Do not hand-edit generated service files. Ordinary deployment is fill-only and
must not rotate an existing credential.

### Kestra workflow lifecycle

`workflows/kestra/*.yaml` is the only source of Kestra workflow definitions.
The Kestra Compose application mounts `application.yaml` for server settings,
but it neither mounts workflows nor enables `--flow-path`. During deployment,
the immutable release carries the canonical workflow sources and
`server-kestra-reconcile.py provision` creates or updates them through the
Kestra REST API. Its required second pass must be a no-op. `status` and
`verify` use the same API-owned state; manual UI imports and startup-time flow
imports are unsupported because they create a second lifecycle.

## Troubleshooting

1. Run `./platform status` and retain the run/release/source IDs.
2. Use the narrow `... status` or `... verify` command for the failed plane.
3. Run `./platform config audit` before changing any rendered file.
4. Check the matching evidence document; never paste secret-bearing logs.
5. Correct the canonical input or source, then start a new full deployment. Use
   `--resume` only if source and activation state are unchanged.

Common failure classes:

| Symptom | First check |
|---|---|
| SSH/preflight failure | explicit bootstrap target, host fingerprint and key access |
| configuration drift | `./platform config diff` then `config audit` |
| unhealthy application | component health plus Dokploy status |
| agent cannot start | Paperclip environment, Daytona and `harness-auth verify` |
| LLM failure | profile-specific 9Router route/key, never a shared raw credential |
| tool denial | profile bearer, aggregate endpoint and declared ToolHive allow-list |
| Notion divergence | PostgreSQL canonical revision/hash and projection outbox status |
| public endpoint mismatch | `cloudflare plan`, then `cloudflare acceptance` |

## Acceptance evidence

Completion requires fresh evidence from the same release for the real three
harness runs, GitHub PR/check lifecycle and cleanup, connections C027-C029 and
C036, profile isolation, Cloudflare, observability and final verification.
Passing local tests or merely seeing healthy containers is insufficient.

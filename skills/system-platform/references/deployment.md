# Deployment runbook

The supported target is a dedicated Ubuntu 24.04 host. Host, domain, provider
credentials, and excluded machines come only from `config/platform.env`; no
production address is compiled into the repository.

## Deployment model

```text
install.sh                         only ordering authority
└── deployment/scripts/*.sh       semantic, separately callable stages
    ├── host.sh                    target Docker/Compose bootstrap
    ├── compose.sh                 container reconciliation
    ├── provision.sh               API accounts, workflows, profiles, bindings
    ├── cloudflare.sh              firewall plus Cloudflare Terraform
    ├── verify.sh                  live semantic and E2E acceptance
    ├── backup.sh                  host-local Compose PostgreSQL logical dumps
    ├── restore.sh                 confirmed logical database replacement
    └── decommission.sh            confirmed container removal, volumes retained

deployment/compose.yaml           single Compose entrypoint
└── deployment/services/*         owner-scoped service definitions
```

Compose does not call installation scripts. The scripts call Compose. Compose
owns images, containers, networks, volumes, restart policies, and health
checks. Provisioning begins only after `docker compose up -d --wait` succeeds.

The five scripts in `deployment/steps` are narrow host-runtime installers used
by the semantic stages:

```text
host.sh
paperclip.sh
daytona.sh
cloudflare-tunnel.sh
origin-firewall.sh
```

They are not another ordered deployment list. Daytona deployment is pull-only:
the separate `daytona-harness-image` workflow owns the Dockerfile and lockfiles
under `deployment/image-build/daytona-harness`. Operators copy its exact image
digest, source URL, and commit into the canonical environment. Preflight rejects
empty values, mutable tags, missing source evidence, or references without a
full `sha256` digest. Paperclip follows the same immutable external-image rule.

## Full installation

For an ordinary new host:

```bash
cp config/platform.env.example config/platform.env
chmod 600 config/platform.env
# Fill the private file.

./test.sh quick
./install.sh
```

No generic legacy takeover or data migration is part of the installer. For an
existing host, use an operator-specific private runbook reviewed for that exact
inventory only after a proven backup and recovery procedure exists. The
installer does not convert, remove, or attach legacy state.

`install.sh` runs exactly:

1. `preflight` — local contract and remote Ubuntu/SSH checks;
2. `host` — install Docker/Compose when absent, initialize server runtime config;
3. `compose` — validate and incrementally reconcile the aggregate project;
4. `provision` — install host runtimes and reconcile external/API state;
5. `cloudflare` — default-deny origin, DNS, Tunnel, and Access;
6. `verify` — real all-three harness, integration, projection, edge, and final
   connection acceptance.

Every stage is callable independently:

```bash
./install.sh preflight
./install.sh host
./install.sh compose
./install.sh provision
./install.sh cloudflare
./install.sh verify
```

The recovery stages are separately callable and are never part of a normal
`all` installation:

```bash
./install.sh backup BACKUP_ID
./install.sh restore BACKUP_ID --confirm-restore
./install.sh decommission --confirm-decommission
```

Their intentionally limited data boundary is documented in
[backup-upgrade.md](backup-upgrade.md).

Component or provisioning-group selection is explicit:

```bash
./install.sh compose searxng
./install.sh provision toolhive-profiles
./install.sh verify searxng
```

Normal deployment is warm and incremental. It never runs `down`, removes
volumes, or recreates healthy unchanged services. A failed command stops the
index; correct the declarative source or `config/platform.env` and rerun the same
idempotent stage. There is no custom snapshot, rollback, checkpoint, or resume
engine.

## Fast testing

```bash
./test.sh quick                 # offline, seconds
./test.sh smoke [component]     # live health and semantic verifier
./test.sh e2e                   # real Paperclip/Daytona/all-three harness flow
make release-check              # complete source gate
```

Clean-host acceptance belongs on an explicitly selected disposable host. The
installer intentionally exposes no destructive reset command.

## Configuration workflow

The small `platform` utility exposes atomic operations used by the scripts and
for diagnosis. It is not the deployment orchestrator.

```bash
./platform config check
./platform config init
./platform config render
./platform config audit
./platform config diff
./platform secrets audit
```

Do not hand-edit rendered service files. `config init` is fill-only and does
not rotate an existing credential.

## Kestra workflow lifecycle

`workflows/kestra/*.yaml` is the source of Kestra workflow definitions.
`server-kestra-reconcile.py provision` creates or updates them through the
Kestra REST API and its required second pass proves idempotency. Workflows are
not mounted into the container and manual UI imports are unsupported because
they introduce a second lifecycle.

## Troubleshooting

1. Run `./test.sh smoke COMPONENT` or the narrow `./platform ... status`.
2. Run `./platform config audit` before changing a rendered file.
3. Correct `config/platform.env`, the Compose source, or provisioning declaration.
4. Rerun only the affected stage, then the full `./install.sh verify`.
5. Never paste raw secrets or unrestricted container environments into logs.

## Acceptance evidence

Completion requires fresh live evidence for Codex, Claude Code, and Pi through
9Router to MiniMax, Paperclip/Daytona lifecycle, GitHub PR/check and cleanup,
profile/ToolHive isolation, PostgreSQL/Notion projection, Cloudflare,
observability, and declared connections. Passing local tests or seeing healthy
containers is insufficient.

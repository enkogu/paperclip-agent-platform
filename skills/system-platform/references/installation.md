# Installation and quick start

## 1. Prepare the one environment file

```bash
git clone <repository-url> paperclip-agent-platform
cd paperclip-agent-platform
cp config/platform.env.example config/platform.env
chmod 600 config/platform.env
# Replace every documentation value in config/platform.env.
```

`config/platform.env` is ignored by Git and is the single operator-editable
source of truth. Bootstrap imports its recognized values fill-only into the
root-owned server runtime materialization at
`/root/.config/mte-secrets/platform.env`, where generated passwords, tokens,
ports, image digests, and provisioned resource IDs are added. Services read
only that generated server file; operators do not edit it. Ordinary
installation never overwrites an existing non-empty generated secret.

## 2. Run the fast local gate

```bash
./test.sh quick
```

This checks Bash syntax, ShellCheck when installed, YAML and Compose contracts,
configuration ownership, dependencies, and focused unit tests without
contacting the server.

## First ten minutes

Start only after these prerequisites are available: a clean local checkout,
Python 3.11+, `bash`, `ssh`, `rsync`, `curl`, an Ubuntu 24.04 host reachable as
root over SSH, and a Cloudflare-managed DNS zone. The repository intentionally
uses the placeholder below; obtain the clone location from the repository owner
rather than guessing one:

```bash
git clone <repository-url> paperclip-agent-platform
cd paperclip-agent-platform
./test.sh quick
cp config/platform.env.example config/platform.env
chmod 600 config/platform.env
./install.sh preflight
```

Expected outputs are a passing local source gate and a redacted preflight
result. A failed preflight reports missing or invalid key **names**, paths, or
readiness states; it must not print values. Complete the remaining documented
operator inputs before running `./install.sh`.

The first-owner checkpoint is deliberately human: on an empty authenticated
Paperclip instance, provisioning may report `needs_authorization` and create a
short-lived owner invite. The intended board owner redeems that invite in the
browser, then reruns `./install.sh`. Do not replace this checkpoint with a
database edit, a fabricated token, or a copied credential.

## 3. Install

For an ordinary new host:

```bash
./install.sh
```

This repository does not ship a legacy-takeover or generic data-migration
runner. An existing host requires an operator-specific private runbook that is
reviewed against its exact inventory and has a proven backup and recovery path.
Do not use `./install.sh` to infer, convert, delete, or attach legacy data.

Historical removal note: NocoDB, NocoDocs, Baserow, Wiki.js, and
sustainable-use were retired from the public deployment surface. Their former
state is not a supported input to this installer and has no bundled migration.

The only installation order is visible in `install.sh`:

```text
preflight → host → compose → provision → cloudflare → verify
```

The separately invoked `backup`, `restore`, and `decommission` recovery stages
are never appended to this normal installation order. Restore and decommission
require their exact confirmation flags.

- `preflight` validates the private env and SSH target without mutation;
- `host` installs Ubuntu Docker/Compose only when absent, initializes the
  server runtime env from `config/platform.env`, and installs the official
  ToolHive release binary;
- `compose` runs the aggregate `deployment/compose.yaml` incrementally;
- `provision` reconciles Paperclip, Kestra, profiles, Mattermost/Hermes,
  PostgreSQL/Notion, Daytona, and harness routing;
- `cloudflare` applies the origin firewall and the small Terraform edge module;
- `verify` produces and checks live E2E and connection evidence. Its final
  Notion create/update/archive canary runs immediately before the acceptance
  consumers so the ten-minute evidence freshness gate cannot observe an old
  projection proof.

The normal path never invokes `docker compose down`, deletes volumes, rebuilds
an upstream project, or implements a private release transaction.

### One unavoidable Paperclip owner confirmation

Paperclip intentionally has no declarative "first board administrator" flag.
On an empty authenticated instance, provisioning can create a short-lived,
one-time owner invite, but only the intended human owner may redeem it in a
browser. Do not bypass this with a database edit, a fabricated bearer token,
or a token copied into Hermes.

Until that confirmation is complete, the deployment correctly reports
`paperclip: needs_authorization`; Paperclip secret scopes, the Hermes
Paperclip credential, and the real Paperclip-to-Daytona harness E2E remain
blocked. Once the owner has redeemed the invite, replay the normal idempotent
command `./install.sh`. It resumes the declarative installation and still runs
the previously unreached Cloudflare and verification stages. No manual creation
of company secrets, profiles, agent keys, or Hermes bindings is required.

## 4. Iterate narrowly

```bash
./install.sh compose firecrawl
./install.sh provision kestra
./install.sh verify firecrawl

./test.sh smoke firecrawl
./test.sh e2e
```

No generic migration procedure is part of this installer. An operator-specific
migration must stay private, be reviewed against the actual host inventory, and
be approved only after its backup and recovery procedure has been proven. The
ordinary installer neither removes legacy services nor converts their state.

Compose leaves unchanged containers and volumes in place. Provisioning uses
read-before-create idempotency. No stage uses fixed sleeps.

Clean-host acceptance runs only on an explicitly selected disposable host; the
installer exposes no destructive reset command.

PostgreSQL is authoritative. Notion is a replaceable projection and may be
changed later without migrating canonical records.

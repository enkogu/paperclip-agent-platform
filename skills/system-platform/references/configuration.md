# Configuration and secrets

`config/platform.env` is the single operator-editable source of truth. Create it
from `config/platform.env.example`, keep it at mode `0600`, and do not commit
it. Installation imports recognized values fill-only into the root-owned
`/root/.config/mte-secrets/platform.env`; that server file is an enriched
runtime materialization for generated passwords, tokens, ports, digests, and
resource IDs, not a second editable input.

## Flow

```text
config/platform.env -> fill-only server materialization -> validated projections
  -> service env / Paperclip secret refs / harness env / ToolHive / Cloudflare
```

Use `./install.sh preflight` before installation. The narrow `./platform config
init`, `render`, `audit`, and `diff` helpers exist for stage internals and
diagnosis; they are not another deployment path. Ordinary installation is
fill-only and must not rotate an existing secret. Never edit the server
materialization, rendered service files, Paperclip environment payloads,
ToolHive credentials, or Cloudflare inputs directly.

Every consumer receives an allowlisted projection. A secret is documented by key name and purpose only; never place its value in Git, task text, skill files, commands, logs, evidence, or chat. Inspect existence, ownership, permissions, source hash, and fingerprint rather than content.

Daytona's internal database, object-store, registry, encryption, health,
telemetry, proxy, runner, SSH gateway, and administrator credentials are
generated on the server during the same fill-only initialization. They are
stored only in the root-owned canonical file and Daytona's registered `0600`
service projection. A rerun preserves every existing value; rotation is never
an installation side effect.

`config/platform.yaml` owns topology and exposure, `config/platform.lock.yaml` owns pinned versions/provider contracts, `config/profiles/catalog.yaml` owns agent runtime/tool policy, and `config/acceptance-requirements.yaml` owns required release evidence checks.

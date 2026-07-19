# Architecture and platform contract

This document describes ownership boundaries. `config/platform.yaml`,
`config/platform.lock.yaml`, `config/profiles/catalog.yaml` and
`config/acceptance-requirements.yaml` are the machine-readable release evidence
contract. Live readiness is deliberately not recorded here: use generated
acceptance evidence and the matching verifier for the active source revision.

## Contents

- [Control and execution](#control-and-execution)
- [Data and content](#data-and-content)
- [Configuration](#configuration)
- [Exposure](#exposure)
- [Observability and recovery](#observability-and-recovery)
- [Acceptance invariants](#acceptance-invariants)
- [Extension rule](#extension-rule)

## Control and execution

- **Kestra** owns schedules, workflow branching, retries and approval stages.
- **Paperclip** owns agent Issues, assignment, heartbeats, messages and run
  status. Its MTE runtime image is operator-supplied, immutable and
  digest-pinned; mutable image tags are rejected. It is not the business
  workflow engine.
- **Daytona** creates the isolated execution environment and workspace selected
  by the Paperclip profile.
- **Codex, Claude Code and Pi** run inside those environments. Their runtime
  configuration belongs to the profile and is delivered as secret references.
- **9Router** is the only LLM route for shipped harness profiles and retains
  the root-only upstream MiniMax credential.
- **ToolHive** manages MCP workloads and profile-private aggregates; a profile
  cannot use another profile's endpoint or bearer.
- **Hermes** runs its official upstream gateway for messaging, diagnosis and
  repair. There is no platform-specific proxy or command API in front of it.

## Data and content

The active profile is `postgres-notion`:

```text
Paperclip / Kestra
              |
     scoped PostgREST identities
              |
 PostgreSQL canonical_entities + canonical_documents  <- authority
              |
 provider_outbox + leased projection consumer
              |
 Notion tables and documents                          <- projection
```

PostgreSQL owns object IDs, revisions, content hashes and payloads. Notion may
be rebuilt or replaced without migrating the authoritative state. Platform
services use scoped PostgREST identities. Coding-agent PostgREST delivery is a
declared policy but is not yet present in the harness runtime allowlists; do not
claim that capability until live-proven. The separate `mte.notion.connector`
identity owns projection writes, while reviewed Notion reads are exposed by
profile ToolHive bundles. Codex and Claude have source-implemented native MCP
wiring; Pi `0.80.7` uses a committed local ToolHive extension alongside the
official Context7 extension. All three paths require fresh v4 release evidence
before they are called live-proven.

Additional data projections are extension packages, not dormant applications
or fallback sources of truth in the public core.

## Configuration

`config/platform.env` is the single operator-editable source of truth and
`config/platform.env.example` is its checked-in schema. Installation imports
recognized values into `/root/.config/mte-secrets/platform.env`, a root-owned
runtime materialization enriched with generated values. Services consume that
server file, but operators never edit it as an independent source.

The following are generated projections, never independent configuration:

- service environment files;
- Compose variables;
- Paperclip environments and secret bindings;
- harness configuration;
- ToolHive workloads and aggregates;
- Cloudflare/OpenTofu inputs;
- connection and evidence manifests.

Manual edits to a generated projection are drift and must fail `config audit`.

## Exposure

Human applications are reached through Cloudflare Tunnel and Access. Internal
APIs, databases, Docker, Daytona, 9Router, ToolHive control endpoints and
Victoria backends have no public origin. Notion is external SaaS reached by
outbound HTTPS and therefore receives no local component, DNS record or tunnel
route.

Exposure classes are declared per component:

- `human`: interactive Cloudflare Access plus application login;
- `service`: Cloudflare service authentication;
- `webhook`: an integration-level contract that requires its owning service to
  implement exact-path, signature/state, replay, and payload controls before
  exposure;
- `internal` or `loopback`: no public hostname;
- `egress`: outbound provider call only.

The shipped Cloudflare module currently creates Tunnel/DNS and Zero Trust
Access applications and policies only for declared `human` and `service`
routes. Each declared route gets its own Access application, policy and service
credential where required. It does not configure Cloudflare WAF rules, rate
limits, or webhook route policies. A webhook declaration therefore does not by
itself create an edge policy or make an endpoint releasable.

## Observability and recovery

OpenTelemetry carries correlated task, run, profile and release/source-hash
signals to VictoriaMetrics, VictoriaLogs and VictoriaTraces. Grafana is the
human UI; vmalert and Alertmanager deliver alerts to Mattermost. These backends
remain internal and acceptance requires a correlated canary across metrics,
logs, traces and alert delivery.

Recovery is intentionally narrower than the runtime topology: the public
surface supports checksummed logical backups of ordinary Compose PostgreSQL
services and a verified pre-restore logical rollback. Paperclip-native and all
other non-database volume payloads, off-host backups, PITR and generic
downgrades are outside that surface. See
[backup-upgrade.md](backup-upgrade.md) before making a recovery claim.

## Acceptance invariants

A release is accepted only when evidence from the same source hash proves:

1. all selected applications and health checks converge;
2. Codex, Claude Code and Pi complete real Paperclip/Daytona/9Router runs;
3. the Kestra GitHub workflow reaches terminal state and cleans up its PR,
   branch, workspace and sandbox;
4. profile credentials and ToolHive endpoints are isolated from one another;
5. PostgreSQL/PostgREST/Notion canaries pass and clean up;
6. Cloudflare exposes exactly the declared application set;
7. metrics, logs, traces and alert delivery are observable;
8. every required row of `config/acceptance-requirements.yaml` is verified;
9. raw secrets are absent from repository, runtime evidence and agent output.

Local tests prove source behavior only. They cannot substitute for live
acceptance. The explicit complete live gate is `./test.sh e2e`; the final
installation stage also runs it through `./install.sh verify`.

## Extension rule

New harnesses, tools and presentation providers are added behind a declarative
profile or connector contract. Core workflow, task and canonical-data
ownership must not depend on a vendor-specific implementation.

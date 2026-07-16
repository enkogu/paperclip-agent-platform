# Platform contract

This document describes ownership boundaries. `config/platform.yaml`,
`config/platform.lock.yaml`, `config/profiles/catalog.yaml` and
`config/connections.yaml` are the machine-readable contracts.

## Control and execution

- **Kestra** owns schedules, workflow branching, retries and approval stages.
- **Paperclip** owns agent Issues, assignment, heartbeats, messages and run
  status. It is not the business workflow engine.
- **Daytona** creates the isolated execution environment and workspace selected
  by the Paperclip profile.
- **Codex, Claude Code and Pi** run inside those environments. Their runtime
  configuration belongs to the profile and is delivered as secret references.
- **9Router** is the only LLM route for shipped harness profiles.
- **ToolHive** manages MCP workloads and profile-private aggregates.
- **Hermes** runs its official upstream gateway for messaging, diagnosis and
  repair. There is no platform-specific proxy or command API in front of it.

## Data and content

The active profile is `postgres-notion`:

```text
Paperclip / Kestra / Activepieces
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
be rebuilt or replaced without migrating the authoritative state. Agents write
canonical data through their scoped PostgREST identity and receive only the
reviewed read-only Notion MCP tools. The separate `mte.notion.connector`
identity owns projection writes.

The alternative `postgres-postgrest-nocodb-nocodocs` and `baserow-wikijs`
profiles are non-selectable. Their manifests are extension material, not
installed applications or fallback sources of truth.

## Configuration

The live installation has one authoritative root-owned environment file. The
repository contains one documented operator-input template in
`config/platform.env.example`; its populated private copy is only bootstrap
transport. The sole runtime source is
`/root/.config/mte-secrets/platform.env`.

The following are generated projections, never independent configuration:

- service environment files;
- Compose and Dokploy variables;
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
- `webhook`: exact path, signature/state protection and rate limiting;
- `internal` or `loopback`: no public hostname;
- `egress`: outbound provider call only.

## Acceptance invariants

A release is accepted only when evidence from the same source hash proves:

1. all selected applications and health checks converge;
2. Codex, Claude Code and Pi complete real Paperclip/Daytona/9Router runs;
3. the Kestra GitHub workflow reaches terminal state and cleans up its PR,
   branch, workspace and sandbox;
4. profile credentials and ToolHive endpoints are isolated from one another;
5. PostgreSQL/PostgREST/Notion and Activepieces canaries pass and clean up;
6. Cloudflare exposes exactly the declared application set;
7. metrics, logs, traces and alert delivery are observable;
8. every required row of `config/connections.yaml` is verified;
9. raw secrets are absent from repository, runtime evidence and agent output.

Local tests prove source behavior only. They cannot substitute for live
acceptance. The explicit complete gate is `./platform verify --all`.

## Extension rule

New harnesses, tools and presentation providers are added behind a declarative
profile or connector contract. Core workflow, task and canonical-data
ownership must not depend on a vendor-specific implementation.

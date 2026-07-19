# Canonical data and document connectors

Connectors make presentation systems replaceable while PostgreSQL remains the
source of truth. The executable registry is `spec.dataContentProfiles` in
`config/platform.lock.yaml`; `tools/platform-cli/data_content_plane.py` validates and resolves
the selected profile.

## Contents

- [Active profile](#active-profile)
- [Canonical and projection model](#canonical-and-projection-model)
- [Notion bootstrap](#notion-bootstrap)
- [Consumer identities](#consumer-identities)
- [Required checks](#required-checks)
- [Alternative providers](#alternative-providers)

## Active profile

`postgres-notion` maps responsibilities as follows:

| Responsibility | Provider | Authority |
|---|---|---|
| records/documents | PostgreSQL | authoritative |
| scoped canonical API | PostgREST | PostgreSQL-backed |
| tables UI/API | Notion | projection |
| documents UI/API | Notion | projection |
| agent projection tools | ToolHive Notion MCP | read-only; native delivery for Codex/Claude and reviewed Pi extension delivery |

The four presentation roles are `tablesUi`, `tablesApi`, `documentsUi` and
`documentsApi`. A future profile may assign them to one or several providers
without changing workflow/task ownership or canonical records.

## Canonical and projection model

The PostgreSQL contract contains:

- `canonical_entities`: stable ID, data, revision and content hash;
- `canonical_documents`: stable ID, body, content type, revision and hash;
- `provider_sync_state`: requested provider operation and delivery state;
- `provider_outbox`: payload-free delivery intent.

The Notion consumer claims intents with leases and `SKIP LOCKED`, reloads the
current canonical payload, performs create/update/archive, verifies the remote
ID/revision/hash/read-back and atomically finalizes state. Projection rows do
not become a recoverable canonical copy.

## Notion bootstrap

The operator creates or selects a root page and shares it with the integration.
The platform verifies that root and idempotently discovers/creates its managed
documents page and table database/data source. IDs and identity pins are
persisted in canonical configuration; token values never enter source or
evidence.

Important references include:

```text
NOTION_TOKEN
NOTION_ROOT_PAGE_ID
NOTION_DOCUMENTS_PAGE_ID
NOTION_TABLE_DATABASE_ID
NOTION_TABLE_DATA_SOURCE_ID
NOTION_WORKSPACE_ID
NOTION_BOT_ID
```

Existing canonical values are fill-only. A configured resource must match its
expected parent/title/schema; unrelated workspace content is not silently
adopted.

## Consumer identities

- `mte.postgrest.paperclip`: scoped canonical writer intended for the Paperclip
  agent plane; current coding harness allowlists do not yet deliver its URL/token;
- future connector packages must declare a separate scoped PostgREST identity;
- `mte.notion.connector`: external projection writer, not agent-reachable;
- per-profile ToolHive Notion workloads: projection read tools only.

The raw Notion token is never put in a harness image or agent environment.
Profile bearer enforcement is provided by the agent-plane gateway, not by a
ToolHive group name. Current source acceptance exercises the profile bundle
through native MCP in Codex and Claude and through the committed Pi extension in
Pi `0.80.7`. The extension is bound to the Pi endpoint/bearer refs and delegates
authorization to the exact ToolHive allow-list. Fresh v4 evidence, not the
declaration alone, is live proof.

## Required checks

- C027: Paperclip canonical record/document CRUD, role isolation and cleanup;
- C029: PostgreSQL-to-provider create/update/archive, ID/revision/hash read-back
  and cleanup;
- C036: connector resources, capabilities and secret references converge
  without credential disclosure.

Notion is external egress and has no local component, origin port, DNS record,
tunnel ingress or Access application.

## Alternative providers

Alternative presentation providers are separate connector packages, not
dormant applications in the public core. They must implement the same outbox,
read-back, cleanup, secret-delivery, license, and acceptance contracts before
they can be selected. PostgreSQL data is preserved when the presentation
provider changes.

To add a provider:

1. declare providers, capabilities, roles, reviewed adapters and credentials in
   `config/platform.lock.yaml`;
2. retain PostgreSQL authority and stable canonical schema;
3. implement idempotent provision/status/verify and exact resource adoption;
4. add redacted evidence, negative checks and cleanup;
5. expose agent tools only through a scoped ToolHive workload;
6. declare Cloudflare resources only for a locally hosted application;
7. leave the profile non-selectable until source tests and live C027/C029/C036
   acceptance pass.

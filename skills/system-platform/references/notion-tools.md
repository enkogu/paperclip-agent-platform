# Notion projection and agent tool policy

Policy `postgres-ssot-notion-readonly-v1` in `config/profiles/catalog.yaml` is the
fail-closed boundary for Codex, Claude Code and Pi.

## Ownership

- The policy permits agent-plane canonical writes through scoped PostgREST,
  but the current coding harness allowlists do not yet deliver that identity.
- Codex and Claude Code reach the Notion projection through native remote MCP
  configuration. Pi `0.80.7` reaches the same profile-private ToolHive
  aggregate through the reviewed local `mte-toolhive.js` extension.
- Only `mte.notion.connector` may create/update/archive the Notion projection.
- Raw `NOTION_TOKEN` is never present in harness environment, image or output.

## Enforcement

Every profile has a distinct Notion MCP workload and vMCP aggregate. The
reviewed ToolHive `--tools` allow-list filters both `tools/list` and
`tools/call`; hiding a mutating tool is not considered sufficient unless a
direct call is also rejected. The aggregate combines the identity `echo`
canary with the exact declared Notion read tools.

Profile identity is enforced by the MTE agent-plane gateway. Acceptance must
prove:

1. the declared read-only tool list is exact; real Codex/Claude/Pi harnesses call
   the profile identity canary while ToolHive policy canaries prove the exact
   Notion list and a valid read;
2. a valid read and identity canary succeed at the correct endpoint;
3. a mutating Notion call is rejected before reaching the backend;
4. the same bearer is rejected at another profile endpoint;
5. the current harness env contains neither a PostgREST writer ref nor a raw
   Notion credential, and the catalog marks PostgREST bundle delivery blocked;
6. connector create/update/archive is reflected from PostgreSQL revision/hash
   and leaves clean canary state.

Items 1-4 are implemented as source acceptance. They are live-proven only by
fresh v4 Daytona/profile evidence on the active release. When PostgREST writer
delivery is implemented, item 5 and the machine-readable blocked state must be
changed in the same reviewed release; documentation alone cannot enable it.

The reviewed list is machine-readable in `config/profiles/catalog.yaml`; this
document intentionally does not maintain a second copy of tool names. Any
policy drift must stop reconciliation.

Pinned ToolHive source used by the implementation:

- <https://github.com/stacklok/toolhive/blob/v0.36.0/cmd/thv/app/run_flags.go>
- <https://github.com/stacklok/toolhive/blob/v0.36.0/pkg/runner/middleware.go>
- <https://github.com/stacklok/toolhive/blob/v0.36.0/pkg/mcp/tool_filter.go>

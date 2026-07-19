# Agent runtime and profiles

Paperclip is the agent control plane; Daytona provides isolated workspaces; Codex, Claude Code, and Pi are the real harnesses. There is no platform-owned LLM loop in their place.

The shipped profiles are `coding-daytona-codex`, `coding-daytona-claude`, and `coding-daytona-pi`. Their authoritative declaration is `config/profiles/catalog.yaml`; the Paperclip environment and secret-scope resources are rendered from it.

Each profile binds its native adapter, workspace path, model/protocol, 9Router key reference, ToolHive URL/bearer reference, instructions, skills, packages, limits, and credential allowlist. The Daytona artifact selected by a release contains the pinned tools and MCP integrations, but no direct OpenAI or Anthropic subscription-auth home or API credential. At runtime, the profile receives its scoped 9Router route key; 9Router uses the operator-supplied, root-only MiniMax upstream credential.

## Tool delivery matrix

| Harness | Context7 | Profile ToolHive bundle | Delivery source |
|---|---|---|---|
| Codex | native remote MCP | native remote MCP | exact `nativeAdapterConfig.extraArgs`; no `/etc/codex/config.toml` dependency |
| Claude Code | native remote MCP | native remote MCP | `/etc/claude-code/managed-mcp.json` |
| Pi `0.80.7` | official `@upstash/context7-pi@0.1.1` extension | reviewed local Pi extension | `toolhive_list_tools` and `toolhive_call` under the pinned Pi agent directory |

Release acceptance launches each real harness. Codex and Claude must call
Context7 `resolve-library-id` and the profile-private ToolHive `echo`. Pi calls
Context7 through the official extension and ToolHive through the reviewed
`mte-toolhive.js` extension. The same acceptance checks right-endpoint ToolHive
access and wrong-profile `401`. Its receipt retains booleans and output hashes,
not raw model/tool output.

This matrix is **implemented in source and locally contract-tested**. Its live
status is established only by a fresh, release-bound acceptance receipt for the
selected Daytona artifact and active release. Source and local contract tests
do not prove current native tool delivery.

## Remaining runtime boundaries

- Context7 uses an optional profile-scoped `CONTEXT7_API_KEY` secret reference
  with anonymous IP-rate-limited fallback; no credential is embedded in the
  snapshot, catalog or evidence.
- Pi has no built-in MCP transport. Its committed local extension implements
  only the bounded profile-private ToolHive Streamable HTTP client and remains
  fail-closed when its endpoint, bearer or profile binding drifts.
- PostgREST agent-write policy is declarative and blocked; its URL/token are not
  in the current harness environment allowlists or profile tool bundle.
- `dangerouslyBypassApprovalsAndSandbox`/`dangerouslySkipPermissions` rely on
  Daytona as the outer isolation boundary and must remain explicit.

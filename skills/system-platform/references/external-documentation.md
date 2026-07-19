# Current upstream documentation with Context7

Use Context7 before changing component APIs, configuration keys, installation commands, or version-sensitive behavior. Resolve the library first, then query a narrow question that includes the pinned version from `config/platform.lock.yaml`. Never send secrets, private source, customer data, or full prompts in the query.

The remote MCP endpoint is `https://mcp.context7.com/mcp`. Its tools are `resolve-library-id` and `query-docs`. Anonymous access is supported with lower limits; `CONTEXT7_API_KEY` is optional and must be injected from the canonical secret source, never written into this skill.

| Component | Preferred Context7 library |
|---|---|
| Paperclip | `/paperclipai/docs` (fallback `/paperclipai/paperclip`) |
| Kestra | `/kestra-io/docs` |
| Daytona | `/daytonaio/daytona` |
| Hermes Agent | `/nousresearch/hermes-agent` |
| 9Router | `/decolua/9router` |
| ToolHive | `/stacklok/toolhive` |
| Mattermost | `/mattermost/docs` |
| Firecrawl | `/firecrawl/firecrawl-docs` |
| SearXNG | `/websites/searxng` |
| PostgreSQL | `/websites/postgresql_17` |
| PostgREST | `/websites/postgrest_en_v14` |
| Cloudflare | `/cloudflare/cloudflare-docs` |
| Grafana | `/websites/grafana` |
| VictoriaMetrics | `/websites/victoriametrics` |
| VictoriaLogs / VictoriaTraces | `/victoriametrics/victorialogs`, `/victoriametrics/victoriatraces` |
| Notion API | `/websites/developers_notion_reference` |
| GitHub | `/github/docs` |
| Codex | `/openai/codex` |
| Claude Code | `/anthropics/claude-code` |
| Pi | `/websites/pi_dev` |
| Context7 | `/upstash/context7` |

If Context7 has no trustworthy current match, use the component's official docs/repository and record the exact version or commit consulted. Do not vendor whole upstream manuals into this repository.

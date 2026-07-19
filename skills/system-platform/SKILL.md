---
name: system-platform
description: Install, configure, operate, diagnose, repair, secure, and extend the Paperclip agent platform. Use for any work involving its deployment, canonical configuration, applications, agent tasks, Daytona workspaces, Codex/Claude/Pi runtimes, Kestra workflows, Hermes, 9Router, ToolHive/MCP, integrations, data, Cloudflare, or observability.
---

# System Platform

This is the platform's documentation and operator skill. Read only the reference that matches the task; machine-readable contracts and live status take precedence over prose.

## Reference router

- Installing a new host or doing the first deployment: read [installation.md](references/installation.md), [deployment.md](references/deployment.md), then the Russian deployment map [deployment-architecture-ru.md](references/deployment-architecture-ru.md) when useful.
- Operating applications, tasks, agents, workflows, messages, tools, data, or alerts: read [operations.md](references/operations.md).
- Diagnosing a failure or making a repair: read [debugging.md](references/debugging.md), then the owning component reference.
- Understanding ownership, trust boundaries, and data flow: read [architecture.md](references/architecture.md); open [architecture.html](assets/architecture.html) for the interactive diagram.
- Working with the canonical environment, rendered projections, secrets, or rotation: read [configuration.md](references/configuration.md) and [security-ru.md](references/security-ru.md).
- Working with Paperclip tasks, Daytona, Codex, Claude Code, Pi, profiles, or state: read [agent-runtime.md](references/agent-runtime.md) and [state-model.md](references/state-model.md).
- Working with Kestra schedules, gates, retries, GitHub, or E2E: read [workflows.md](references/workflows.md).
- Working with PostgreSQL, PostgREST, Notion, OAuth, or optional connectors: read [data-connectors.md](references/data-connectors.md) and [notion-tools.md](references/notion-tools.md).
- Working with Hermes, Telegram, Mattermost, host repair, or approvals: read [hermes.md](references/hermes.md); for Paperclip Issue or Kestra execution work, then read [operations.md](references/operations.md).
- Working with networks, Cloudflare, exposure, vulnerability reporting, or connection checks: read [connections.md](references/connections.md), [security-ru.md](references/security-ru.md), and [security-policy.md](references/security-policy.md).
- Working with metrics, logs, traces, dashboards, or alerts: read [observability.md](references/observability.md).
- Planning a backup, restore, version upgrade, rollback, disaster recovery, or decommissioning: read [backup-upgrade.md](references/backup-upgrade.md) before any mutation, disposal, or recovery claim.
- Looking up current upstream APIs or component behavior: read [external-documentation.md](references/external-documentation.md) and use Context7 before relying on remembered syntax.
- Changing source, tests, versions, or release policy: read [development.md](references/development.md), [supply-chain.md](references/supply-chain.md), [third-party.md](references/third-party.md), and [known-limitations.md](references/known-limitations.md).
- Checking the Russian product contract and readiness criteria: read [specification-ru.md](references/specification-ru.md).
- Auditing the documentation migration or locating an old document: read [migration-provenance.md](references/migration-provenance.md).

## Non-negotiable rules

- Never print, copy, or persist secret values; report key names, IDs, hashes, and readiness only.
- Start with read-only `status`, `audit`, or `verify`; ask for approval before destructive or externally visible actions.
- Change `config/platform.env` or the owning declarative contract, not a generated projection or one-off live file.
- After a change, run the narrow verifier and then the complete acceptance gate appropriate to its blast radius.
- Treat PostgreSQL as data authority, Kestra as workflow authority, Paperclip as agent-task authority, Daytona as execution boundary, and Notion as a replaceable projection.

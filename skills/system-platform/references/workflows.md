# Kestra workflows and E2E

Kestra owns schedules, branching, retries, approvals, and external workflow state. Paperclip owns the agent Issue and heartbeat lifecycle.

> A healthy Kestra container or reconciled flow source is not evidence that this
> path has run. Treat the path as live-proven only when fresh, source-bound E2E
> evidence records the native Issue, harness result, work product, and cleanup.

`workflows/kestra/*.yaml` is the only workflow source. Deployment reconciles flows through the Kestra REST API; Compose does not mount workflow YAML and startup import is unsupported.

The native task path is:

```text
Kestra -> POST /api/companies/{company_id}/issues -> Paperclip assignment
        -> Daytona workspace -> Codex/Claude/Pi -> GitHub
Kestra -> GET /api/issues/{issue_id} and /runs -> gates -> cleanup
```

The E2E producer must create a uniquely marked Issue, retain the native Issue ID, wait for a terminal and verified harness result, prove the expected commit/PR/check, and clean the branch, PR, workspace, and sandbox. The consumer must verify the same source hash, current claim semantics, runtime-only secret refs, 9Router evidence, and cleanup. A missing Issue ID is a secondary symptom; retain the failing Kestra task and HTTP error as the primary cause.

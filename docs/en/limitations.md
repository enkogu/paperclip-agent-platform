# Gaps and risks found by the MVP

1. **The process adapter environment contradicts its documentation.** In pinned
   `2026.707.0`, official process-adapter docs say standard task/run/key variables
   are injected, but the stable implementation's `buildPaperclipEnv` supplies
   only agent ID, company ID and API URL. The live run contained no
   `PAPERCLIP_TASK_ID`, `PAPERCLIP_RUN_ID` or `PAPERCLIP_API_KEY`. The smoke
   worker recovers the newest assigned Issue only because the server is in
   loopback `local_trusted` mode. For authenticated production, use native
   Codex/Claude adapters or provision a scoped secret-ref API key/custom adapter.

2. **Profile declaration is partly custom.** Paperclip stores agent config and
   revisions natively, but this comparable three-profile catalog and idempotent
   bootstrap are approximately 140 lines of our Python glue. MCP policy entries
   are visible declarations; this MVP does not enforce them for native harnesses.

3. **Resource fields are not enforced.** Paperclip's local adapters can run on
   the host, SSH or sandbox environments, but this MVP uses the host process
   adapter. CPU and memory in the normalized request are metadata only. A real
   deployment needs Paperclip sandbox-provider configuration or an external
   container scheduler.

4. **Callbacks are not implemented.** Kestra must poll. Native run events and
   logs exist, but the normalization layer does not yet relay SSE/webhooks.

5. **Waiting for approval is Issue `blocked`, not Paperclip Approval API.** This
   gives visible state, an audit trail and explicit resume, but it does not use
   Paperclip's separate governance approval object.

6. **There is meaningful Kestra overlap.** Paperclip has Issues, goals, routines,
   schedules and approvals. This design deliberately ignores its top-level
   workflow features. Operators must enforce the ownership boundary to avoid
   two schedulers retrying the same business action.

7. **Startup is heavy.** The pinned npm package pulled roughly 1.6 GB into the
   temporary npm cache in this environment. First install also hit transient npm
   dependency timeouts; retry settings were added. The cache is not part of the
   deliverable.

8. **Operational maturity is only partially proven.** The Storage VPS run
   exercised real Codex and Claude Code runs through profile-scoped 9Router keys,
   a Paperclip restart,
   embedded PostgreSQL state preservation and sequential native tasks. HA
   PostgreSQL, backup restoration, network partition, multi-user auth and
   sustained load remain untested. Paperclip also warns that no database backup
   exists yet.

9. **The native container needs a purpose-built toolchain.** The generic Node
   image had no pytest, and Docker-copied fixture files retained host UID 501
   while Paperclip ran as UID 1000. A production image must pin the harnesses,
   test/runtime tools and ownership instead of installing or repairing them at
   runtime.

10. **Codex sandboxing needs an explicit isolation decision.** With normal
    Codex sandboxing, every command failed because `bwrap` could not create a
    user namespace inside this container. The successful isolated-server run
    used Paperclip's `dangerouslyBypassApprovalsAndSandbox` option and relied on
    the outer container/workspace boundary. Production should either provide a
    supported sandbox environment or make this outer-boundary trust explicit.

11. **Harness command discovery is sensitive to the launcher shell.** Starting
    Paperclip through `bash -lc` reset `PATH`, so native runs exhausted retries
    with `Command not found in PATH: codex` even though `docker exec codex`
    worked. `bash -c` preserved the pinned tools path. The deployment should use
    absolute harness commands or validate the Paperclip process environment.

12. **Successful native output does not finish the Issue automatically.** Both
    harnesses completed the work, but Paperclip classified the text as
    `needs_followup`/`advanced` and scheduled continuation heartbeats because
    the CLI sessions did not mutate the Issue to `done`. The controller had to
    verify the workspace result and close the Issue. Without that bridge, one
    small Codex task ran twice and the research task ran three times.

13. **Native workspace artifacts are invisible to the artifact endpoint.** The
    Claude task wrote valid `report.md` and `report.json`, but Paperclip returned
    zero Issue documents/work products, so normalized `/artifacts` was empty.
    A collector must register declared workspace outputs or ingest the harness's
    structured result before this API is reliable for downstream workflows.

14. **Liveness and terminal status need controller policy.** A Heartbeat Run can
    be process-level `succeeded` while liveness is `blocked` or
    `needs_followup`; an Issue can also be `blocked` after useful files exist.
    The API exposes both values, but Kestra/controller logic must decide when
    evidence is sufficient, when to stop continuations, and when to fail.

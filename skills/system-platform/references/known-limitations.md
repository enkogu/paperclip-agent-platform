# Known limitations and historical MVP findings

This is a topic-complete consolidation of durable source-derived limitations
and historical MVP design findings, not a release-status report. Git history
retains the byte-exact original document. Nothing here proves the state of a
deployment, server, or harness execution; use the separately generated,
release-bound acceptance evidence for that purpose.

1. **[upstream source contract] The process adapter environment contradicts its documentation.** In pinned
   `2026.707.0`, official process-adapter docs say standard task/run/key variables
   are injected, but the stable implementation's `buildPaperclipEnv` supplies
   only agent ID, company ID and API URL. The historical smoke-worker design
   recovered the newest assigned Issue only in loopback `local_trusted` mode;
   it is not an authenticated-production pattern. Use native Codex/Claude
   adapters or provision a scoped secret-ref API key/custom adapter instead.

2. **[platform ownership] Profile declaration is partly custom.**
   Paperclip stores agent config and revisions natively, but the comparable
   three-profile catalog and idempotent reconciler remain platform-owned Python
   glue. The repository's acceptance and E2E contracts enforce native Context7
   calls and profile-scoped ToolHive routing. Any profile or harness change
   needs its own release-bound acceptance evidence.

3. **[source contract] Resource fields need regression enforcement.** The old
   host process adapter treated CPU and memory as metadata. The platform
   profiles specify Paperclip's Daytona provider, a pinned snapshot, and
   explicit CPU/memory/disk limits; the contract also binds evidence to the
   sandbox, workspace, and execution directory. Source tests cover this
   contract. Keep regression coverage so a profile cannot fall back to host
   execution silently.

4. **[design limitation] Paperclip-to-Kestra callbacks are not implemented.** Kestra polls
   native Issue and heartbeat-run endpoints. Paperclip exposes native events and
   logs, but the platform does not relay them to Kestra through SSE or webhooks.

5. **[design rationale] Waiting for approval is Issue `blocked`, not Paperclip Approval API.** This
   gives visible state, an audit trail and explicit resume, but it does not use
   Paperclip's separate governance approval object.

6. **[architecture boundary] There is meaningful Kestra overlap.** Paperclip has Issues, goals, routines,
   schedules and approvals. This design deliberately ignores its top-level
   workflow features. Operators must enforce the ownership boundary to avoid
   two schedulers retrying the same business action.

7. **[release blocker] The Paperclip runtime evidence is external.** The MTE
   fork defines and publishes the immutable runtime, but this repository does
   not invent its digest, source URL, or revision. Until a signed release
   provides the exact `ghcr.io/...@sha256:...` reference and the operator sets
   `MTE_PAPERCLIP_IMAGE`, `MTE_PAPERCLIP_FORK_SOURCE_URL`, and
   `MTE_PAPERCLIP_FORK_REVISION`, validation, release, and preflight fail
   before host mutation. The same
   fail-closed gate verifies that the image has the native `node dist/index.js`
   command and bundles `@paperclipai/plugin-daytona`, `@daytonaio/sdk`, and the
   S3 client required by Daytona control-plane probes.

8. **[coverage boundary] Operational maturity needs release-specific evidence.**
   The MVP audit did not establish high-availability PostgreSQL, backup
   restoration, network-partition behavior, multi-user authentication, or
   sustained-load behavior. Scope and collect those checks in the relevant
   release acceptance record; do not infer them from source tests or a prior
   MVP exercise. Paperclip's database-backup warning must likewise be evaluated
   for the selected upstream release.

9. **[source contract] The native container needs a purpose-built toolchain.**
   The generic Node image had no pytest, and Docker-copied fixture files retained
   host UID 501 while Paperclip ran as UID 1000. The
   `mte-coding-harness-v4` snapshot pins the harnesses, test/runtime tools,
   Context7 integration, GitHub CLI, and ownership instead of repairing them at
   task runtime. Verify the selected snapshot build and native-tool acceptance
   before asserting runtime support.

10. **[isolation decision] Codex sandboxing needs an explicit boundary.** Nested
    Codex sandboxing can fail when `bwrap` cannot create a user namespace inside
    a container. Paperclip's `dangerouslyBypassApprovalsAndSandbox` option moves
    that trust to the outer container/workspace boundary. Production must either
    provide a supported inner sandbox or make the outer-boundary trust explicit.

11. **[historical regression] Harness command discovery is sensitive to the launcher shell.**
    An MVP failure showed that starting Paperclip through `bash -lc` could reset
    `PATH`, causing native harness discovery to fail, while `bash -c` preserved
    the pinned tools path. The deployment should use absolute harness commands
    or validate the Paperclip process environment.

12. **[E2E policy] Successful native output does not finish the Issue automatically.**
    A harness session can leave an Issue in `needs_followup` or `advanced` and
    schedule continuation heartbeats when the CLI does not mutate the Issue to
    `done`. The controller must verify the declared result and close the Issue;
    otherwise continuation work can repeat.

13. **[work-product semantics] Workspace files are not automatically assumed to
    be Paperclip work products.** E2E must explicitly prove the declared
    GitHub/work-product result; do not infer artifact registration from a file
    existing inside the workspace.

14. **[controller policy] Liveness and terminal status need controller policy.** A Heartbeat Run can
    be process-level `succeeded` while liveness is `blocked` or
    `needs_followup`; an Issue can also be `blocked` after useful files exist.
    The API exposes both values, but Kestra/controller logic must decide when
    evidence is sufficient, when to stop continuations, and when to fail.

15. **[access boundary] Hermes has scoped task-bridge access, not board-operator
    authority.** Its intended Paperclip key can create, read, and comment on
    scoped Issues, but it does not receive `tasks:manage_active_checkouts`.
    Status changes or heartbeat cancellation can therefore be rejected when
    another agent owns the active checkout. A stop-request comment is not
    terminal proof; the owning agent or an authenticated board operator must
    complete and verify the transition.

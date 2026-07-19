# Task, run, and workflow state model

| Normalized | Paperclip durable state | Paperclip heartbeat state |
|---|---|---|
| `queued` | Issue `backlog` or `todo` | `queued` or `scheduled_retry` |
| `provisioning` | Issue not created yet | none |
| `running` | Issue `in_progress` | `running` |
| `waiting_input` | Issue `blocked` or `in_review` | any |
| `succeeded` | Issue `done` | usually `succeeded` |
| `failed` | non-terminal issue | `failed` |
| `cancelled` | Issue `cancelled` | `cancelled` |
| `timed_out` | non-terminal issue | `timed_out` |

The durable Issue outcome takes precedence over a later Heartbeat Run. This is
intentional: the smoke run observed that a process agent can commit documents
and mark the Issue done while the latest run record is still `running` (and on
earlier attempts a redundant follow-up heartbeat failed). The response exposes
both native states so this precedence is auditable rather than hidden.

One exception is a terminal native failure: Issue `blocked` plus Heartbeat Run
`failed` or `timed_out` maps to that failure rather than `waiting_input`. The
Storage run showed Paperclip marking an Issue blocked after exhausting harness
launch retries; presenting that as a human-input wait hid the real failure.

For native CLI success, `succeeded` is not by itself proof that the requested
work is complete. Paperclip may set liveness to `needs_followup` or `blocked`
and schedule a continuation while useful workspace files already exist. The
controller must validate expected outputs and close the Issue to stop retries.

Stuck information comes from Paperclip `outputSilence`, `lastOutputAt`,
`lastUsefulActionAt`, `livenessState` and `livenessReason`. The adapter reports
it but does not automatically kill or retry a run; Kestra owns that policy.

The earlier prototype exposed `POST /v1/runs/{id}/resume`; the current platform
does not run that normalized gateway. Resume/cancel must use the native
Paperclip Issue contract supported by the pinned release, preserve an audit
comment, and verify both the durable Issue and latest heartbeat state.

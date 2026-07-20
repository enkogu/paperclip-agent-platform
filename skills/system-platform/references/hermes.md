# Hermes operator runtime

Hermes is the native operator entrypoint, not a custom platform gateway. The
pinned upstream runtime owns Telegram, Mattermost, the LLM loop, terminal tools,
approvals, and the gateway process. Platform scripts install and constrain it;
they do not emulate an agent API.

## Contents

- [Pinned runtime](#pinned-runtime)
- [Trust and approvals](#trust-and-approvals)
- [Configuration](#configuration)
- [Canonical skill and Context7](#canonical-skill-and-context7)
- [Lifecycle](#lifecycle)
- [Operator workflow](#operator-workflow)
- [Acceptance and proof](#acceptance-and-proof)
- [Known limits](#known-limits)

## Pinned runtime

**Reviewed scoped exception.** Hermes is deliberately the one host-native agent
runtime: its operator terminal must act against the host and its systemd
lifecycle, so moving it into Compose would add socket/namespace escape plumbing
without creating an isolation boundary. The exception is limited to the
official upstream wheel installed into an isolated versioned virtual
environment and launched directly by systemd. It is not a source build, custom
wrapper, fork, or general permission for host-installed application runtimes.

**Deployment target.** Hermes Agent `0.18.2` is installed from the official
PyPI `py3-none-any` wheel, SHA-256
`8f02155cfc84b28bd98551cd18dffec0efa9ec070dd08f90f1a850f1c779492f`.
Install downloads that exact wheel into a mode `0600` temporary directory and
verifies its size and SHA-256 before pip sees it. The PyPI publish attestation
and the upstream Sigstore bundle are downloaded beside it. Cryptographic
verification uses the official Sigstore JS verifier shipped in the existing
digest-pinned `node:24.3.0-bookworm` platform image; it requires Sigstore package
`3.1.0` and rejects any other embedded version. The verifier applies the
Fulcio chain and CT-log checks, Rekor signed-entry/inclusion checks, and the
exact `upload_to_pypi.yml@refs/tags/v2026.7.7.2` GitHub Actions identity and issuer.
This image reuse is the smallest locked standard-verifier dependency; no
project-specific certificate or transparency-log crypto is implemented. The
image may need to be pulled by immutable digest, and Sigstore TUF may refresh
its trusted root during install, so first install is not an offline operation.
The bundle itself remains SHA-256 locked. Temporary artifacts are removed on
every exit. The lock binds that release tag to commit
`9de9c25f620ff7f1ce0fd5457d596052d5159596`. The `messaging,mcp` dependency
closure is exact, hash-locked for CPython 3.12/Linux x86-64, and installed with
binary wheels only; the Hermes requirement itself points at the verified local
wheel during installation. There is no source checkout or local wheel build;
the pinned container is verification-only and is removed after each run. An
in-place migration also removes the former managed
`releases/0.18.2/source` checkout before accepting an already-current wheel
environment. Normal provision installs it under
`/opt/mte-hermes`, the service user is `mte-hermes`, state is under
`/var/lib/mte-hermes`, and systemd starts the upstream command directly:

```text
hermes gateway run --replace
```

The service is `mte-hermes.service`. A legacy
`mte-hermes-operator.service` is disabled during reconciliation.

**Upgrade boundary.** A Hermes upgrade is a reviewed change to the pinned wheel
URL, version, SHA-256, PyPI provenance, Sigstore identity/bundle, hash-locked
dependency closure, and supply-chain manifest. Install creates and validates
the new isolated venv before the `current` symlink and systemd service move to
it; the previous release is not a supported data rollback. Any upgrade that
can change Hermes state or another excluded authority remains blocked until the
recovery boundary in [backup-upgrade.md](backup-upgrade.md) is satisfied and
fresh native acceptance passes.

## Trust and approvals

The public default is `HERMES_OPERATOR_MODE=unprivileged_service`. Its unit is
hardened and any stale `/etc/sudoers.d/mte-hermes-platform-admin` file is
removed. The optional private-host mode requires both
`HERMES_OPERATOR_MODE=unrestricted_host_repair` in canonical configuration and
the explicit install flag `--grant-platform-admin`; either one without the
other fails closed. That mode installs unrestricted `NOPASSWD` sudo for
`mte-hermes` so the native terminal can repair the host. It is not least
privilege.

Unrestricted sudo changes capability, not authority:

- read-only status, audit, and bounded redacted logs may run directly;
- restart, reconcile, cancel, PR cleanup, Cloudflare changes, or any external
  mutation still requires explicit operator approval;
- backup/restore, arbitrary database mutation, secret rotation, and broad
  cleanup are unsupported unless a separate reviewed runbook owns them;
- native Hermes approvals remain the interaction boundary. There is no hidden
  command bridge or privileged operator proxy.

Check the declared and effective mode before assuming host access:

```bash
sudo -n python3 /opt/mte-platform/bin/server-hermes.py status
test ! -e /etc/sudoers.d/mte-hermes-platform-admin
```

In public mode the absent sudoers file is expected. Do not work around it. In
private mode, use `sudo -n true` only as a bounded verification after the
explicitly authorized install.

## Configuration

`server-hermes.py install` and `reconcile` validate the canonical platform
environment and render upstream `config.yaml` and `SOUL.md`. The canonical
`server-config.py` renderer is the only writer of the root-owned, mode `0600`
`/root/.config/mte-secrets/services/hermes.env`; it registers the exact source
and content hashes in `projections-manifest.json`. `server-hermes.py` verifies
that manifest binding, ownership, mode, and exact allowlist content without
rewriting the projection. The systemd unit receives only that explicit Hermes
allowlist, never the full canonical `platform.env`.

Important runtime variables available to Hermes include:

- `HERMES_PAPERCLIP_URL` and scoped `HERMES_PAPERCLIP_API_KEY`;
- `HERMES_KESTRA_URL`, `HERMES_KESTRA_USERNAME`, and
  `HERMES_KESTRA_PASSWORD`;
- scoped 9Router values mapped to upstream OpenAI-compatible variables;
- native Telegram/Mattermost tokens plus explicit user/channel allowlists.

Never echo, fingerprint, pass on the command line, or persist these values in a
skill or evidence file. Use the helpers in [operations.md](operations.md),
which read them from the process environment without displaying them.

9Router is Hermes' custom OpenAI-compatible provider. Telegram and Mattermost
remain native upstream integrations. An incomplete token/allowlist/channel
combination fails closed.

### Messaging command path

There is no platform-specific command bridge. A permitted Telegram or
Mattermost message enters the native Hermes gateway, which runs its own LLM and
terminal tools. The operator then uses Paperclip and Kestra's native APIs from
that terminal as described in [operations.md](operations.md). The Mattermost
bootstrap-created operator channel is also the native plugin's only command
channel by default; user allowlisting remains mandatory. Telegram uses its
native user allowlist plus mention/guest-mode gates. Do not add a second bot,
webhook relay, or REST wrapper merely to create or inspect work.

## Canonical skill and Context7

The complete repository tree `skills/system-platform` is the only platform
operator skill. Deployment projects that tree, including `SKILL.md`,
`references/`, `assets/`, and `agents/`, and installs it at:

```text
/var/lib/mte-hermes/.hermes/skills/system-platform
```

Installation copies into a sibling staging directory, applies owner
`mte-hermes` with directory mode `0755` and file mode `0644`, verifies the
deterministic tree SHA-256 plus file/directory counts, and only then replaces
the installed tree. The legacy `skills/mte-platform` copy is removed after the
canonical replacement succeeds. `status` reports the redacted `platformSkill`
object with source/installed tree hashes, counts, ownership/mode state, legacy
absence, and `ready`; the same result is gated by `checks.platformSkill`.

Hermes also receives a native remote MCP entry for
`https://mcp.context7.com/mcp`. Its exact exposed tool allowlist is
`resolve-library-id` and `query-docs`; MCP resource and prompt utilities are
disabled. Anonymous access is the default. If `CONTEXT7_API_KEY` exists in the
canonical secret source, the canonical renderer adds it only to the narrow
registered Hermes service projection; `config.yaml` contains the reference
`Authorization: Bearer ${CONTEXT7_API_KEY}`, never the value. Do not dump the
runtime environment or copy the key into a command, skill, log, or evidence.

`status` is network-neutral: it verifies `checks.context7McpConfig` and reports
the URL, allowlisted tool names, auth mode, and config readiness under
`context7Mcp`; discovery/query states remain `not-requested`. `health` and the
deployment Hermes acceptance additionally perform a real safe MCP initialize,
tool discovery, `resolve-library-id`, and `query-docs` chain. They report only
`checks.context7Discovery`, `checks.context7Query`, auth mode, and readiness
states, never returned documentation or credentials.

## Lifecycle

Read-only:

```bash
sudo -n python3 /opt/mte-platform/bin/server-hermes.py preflight
sudo -n python3 /opt/mte-platform/bin/server-hermes.py status
sudo -n python3 /opt/mte-platform/bin/server-hermes.py health
sudo -n systemctl status --no-pager mte-hermes.service
```

Approved install/reconcile/restart:

```bash
sudo -n python3 /opt/mte-platform/bin/server-hermes.py install
sudo -n python3 /opt/mte-platform/bin/server-hermes.py reconcile
sudo -n systemctl restart mte-hermes.service
sudo -n python3 /opt/mte-platform/bin/server-hermes.py health
```

The private-host variant is intentionally separate:

```bash
# Only after canonical HERMES_OPERATOR_MODE=unrestricted_host_repair is reviewed.
sudo -n python3 /opt/mte-platform/bin/server-hermes.py install \
  --grant-platform-admin
```

`reconcile` restarts an installed unit unless `--no-restart` is supplied. Do
not run both reconcile and a second restart without a reason.

Removal preserves sessions, memory, and skills by default:

```bash
sudo -n python3 /opt/mte-platform/bin/server-hermes.py remove
```

`--purge-data` is destructive and requires separate confirmation that
`/var/lib/mte-hermes` should be deleted.

Read bounded service logs in a trusted terminal and redact before relaying:

```bash
sudo -n journalctl -u mte-hermes.service --since '-15 min' \
  --no-pager -n 200 2>&1 |
python3 -c 'import re,sys; p=re.compile(r"(?i)((?:authorization|bearer|token|api[_ -]?key|secret|password|cookie)\s*[:=]\s*)([^\s,;]+)"); [print(p.sub(r"\1<redacted>",x),end="") for x in sys.stdin]'
```

Summarize error classes, timestamps, unit state, and IDs. Do not paste raw
journal output into a chat.

## Operator workflow

1. Run the exact `server-hermes.py` status and health commands from
   [Lifecycle](#lifecycle).
2. Run the exact read-only platform command proved by the acceptance canary:

   ```bash
   sudo -n python3 /opt/mte-platform/bin/server-verify.py status
   ```

3. For Paperclip Issue or Kestra execution work, use the native API helpers in
   [operations.md](operations.md). Preserve Issue ID, heartbeat run ID, Kestra
   execution ID, and any GitHub PR/check identity.
4. For an app failure, use the app-specific status row and aggregate Compose
   service identity from [operations.md](operations.md). Read bounded logs only
   after the failing component is known.
5. Before mutation, state the exact target, observed failure, command, expected
   effect, and verifier; obtain approval.
6. After mutation, run the narrow verifier and report whether the result is
   implemented-only or live-proven by fresh evidence.

## Acceptance and proof

The native acceptance canary is **implemented**:

```bash
sudo -n /opt/mte-hermes/bin/acceptance-canary
```

It submits a real turn through the native Hermes API, executes the exact
read-only platform status command through the native terminal tool, verifies
the same turn's 9Router usage, and checks configured native messaging
connections. The Mattermost check also reads the provisioned operator channel
with the bot credential; it does not post a test message. The redacted result
is written with mode `0600` and is consumed by the active release's acceptance
receipt.

Read Hermes' live status only from a fresh, release-bound acceptance receipt.
It must bind to the active source and include the upstream API run ID, completed
LLM turn, same-run 9Router usage, one approved terminal invocation, exact
status command, configured Mattermost/Telegram checks, direct systemd command,
and the declared mode's exact host policy (hardened/no sudoers for public mode;
explicit exact sudoers policy for private mode). An installed service or an
unbound prior result is not proof.

## Known limits

- The current source implements Hermes acceptance, but no completed current
  full-platform deploy may be inferred from source alone.
- The host status command is live-proven by the Hermes canary only when the
  current evidence passes; arbitrary repair commands are not implicitly proven.
- The provisioned Paperclip `task_bridge` credential supports scoped Issue
  creation, reads, and comments. It does not grant
  `tasks:manage_active_checkouts`, so Hermes cannot currently change status or
  cancel a heartbeat owned by another agent. A comment requesting stop is not
  terminal proof; the owning agent or an authenticated board operator must
  complete that transition.
- Hermes does not provide database backup/restore, service rollback, automatic
  automatic Compose recovery, or autonomous Cloudflare/GitHub mutation.
- Mattermost/Telegram delivery proof does not prove every user conversation or
  external provider is available.

Read [backup-upgrade.md](backup-upgrade.md) before any upgrade or recovery
claim.

# Hermes runtime

This directory contains deployment assets for the official Hermes Agent
runtime. It does not implement a gateway, an agent API adapter, or a privileged
operator proxy. The pinned upstream package provides Telegram, Mattermost, the
LLM loop, terminal tools, and the gateway process itself.

The installer pins Hermes Agent `0.18.2` at tag `v2026.7.7.2` and commit
`9de9c25f620ff7f1ce0fd5457d596052d5159596`. It installs the package under
`/opt/mte-hermes`, runs it as `mte-hermes`, stores state under
`/var/lib/mte-hermes`, and starts the upstream command directly:

```text
hermes gateway run --replace
```

## Configuration

`server-hermes.py install` and `reconcile` validate the canonical platform
environment, render the upstream `config.yaml` and `SOUL.md`, and create a
root-owned `hermes-runtime.env` containing only Hermes-specific values. The
systemd unit reads that projection; it never receives the full platform
credential file.

9Router is configured as Hermes' custom OpenAI-compatible model provider.
Telegram and Mattermost use their native upstream environment variables and
require explicit user allowlists. An incomplete messaging configuration fails
closed.

The service is hardened by default. This private deployment may explicitly use
`--grant-platform-admin`, which gives `mte-hermes` broad passwordless sudo so
the native terminal tool can diagnose and repair the host. There is no custom
command bridge in that path; Hermes' own approvals remain the interaction
boundary.

## Lifecycle

```bash
python3 /opt/mte-platform/bin/server-hermes.py preflight
python3 /opt/mte-platform/bin/server-hermes.py install --grant-platform-admin
python3 /opt/mte-platform/bin/server-hermes.py reconcile
python3 /opt/mte-platform/bin/server-hermes.py status
python3 /opt/mte-platform/bin/server-hermes.py health
python3 /opt/mte-platform/bin/server-hermes.py remove
```

`remove` preserves Hermes sessions, memory, and skills by default. Add
`--purge-data` only when that state should be deleted.

## Acceptance

After deployment, run:

```bash
sudo /opt/mte-hermes/bin/acceptance-canary
```

The canary submits a real turn through Hermes' native API, lets Hermes execute a
read-only platform status command with its native terminal tool, verifies
9Router usage, and checks the configured native messaging connections. The
redacted result is stored at
`/opt/mte-platform/evidence/hermes-live.json` with mode `0600`.

The connection verifier treats that one native run as a causal chain: upstream
API run ID, completed LLM turn, the same run's 9Router usage, one approved
terminal invocation, and the exact platform status command. Mattermost and
Telegram are checked as upstream Hermes messaging integrations. The separate
host-operator gate verifies the explicit unrestricted sudo policy and the
direct `hermes gateway run --replace` systemd unit.

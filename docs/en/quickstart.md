# Quick start

## Local preparation

```bash
git clone <repository-url> paperclip-agent-platform
cd paperclip-agent-platform
make release-check
. .venv/bin/activate
```

The release gate requires Python 3.11+ with `venv` and Docker Compose v2. It
creates the project `.venv`; keep it activated for the Python-backed
`./platform` commands. This infrastructure repository is not installed as a
Python wheel.

## Operator inputs

```bash
cp config/platform.env.example /secure/path/platform.env
chmod 600 /secure/path/platform.env
# Edit every example value in the external copy.
export MTE_OPERATOR_ENV=/secure/path/platform.env
./platform config check
```

This private file is a one-time operator input carrier, not a second runtime
configuration source. Bootstrap imports recognized values fill-only into the
single root-owned `/root/.config/mte-secrets/platform.env`, then materializes
safe defaults and generated credentials there. Never commit the populated
copy.

## Deploy and verify

```bash
./platform plan --all
./platform preflight
./platform deploy --all
./platform status
./platform verify --all
./platform connections check
```

The final `verify --all` is the complete acceptance gate. A failed immutable run may be resumed
with `./platform deploy --all --resume RUN_ID_OR_EVIDENCE`; after any source
change, start a new run.

The default profile deploys PostgreSQL/PostgREST and reconciles an external
Notion projection. It does not deploy NocoDB/NocoDocs or Baserow/Wiki.js.

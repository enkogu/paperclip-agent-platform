# Paperclip Agent Platform

Self-hosted control and execution platform for long-running AI-agent work. It
combines Paperclip task coordination, Kestra workflows, isolated Daytona
workspaces, Codex/Claude Code/Pi harnesses, scoped LLM routing through 9Router,
ToolHive MCP tools, integrations, communication and observability.

The repository is an infrastructure product, not an application template. A
single indexed deployment reconciles the host, applications, accounts, secret
references, agent profiles, connections and acceptance canaries.

## Architecture at a glance

```text
Schedules / operator messages
             |
       Kestra / Hermes
             |
          Paperclip  ---- task, claim, heartbeat, status
             |
          Daytona   ---- isolated workspace + custom sandbox image
             |
     Codex | Claude Code | Pi
        |         |          |
      9Router   ToolHive   GitHub
        |          |
      LLMs       MCP tools

PostgreSQL (authority) -> PostgREST -> Notion projection
           |                               (replaceable)
           +-> Activepieces / platform services

Cloudflare Tunnel + Access          OpenTelemetry + Victoria* + Grafana
```

The active data/content profile is `postgres-notion`: PostgreSQL owns canonical
records and documents; Notion is a replaceable tables/documents projection.
NocoDB/NocoDocs and Baserow/Wiki.js remain reviewed but non-selectable adapter
candidates and are not part of the default deployment.

## Main components

| Responsibility | Components |
|---|---|
| Workflow and agent control | Kestra, Paperclip, Hermes |
| Execution | Daytona custom environments/workspaces, Codex, Claude Code, Pi |
| LLM and tools | 9Router, ToolHive, per-profile MCP aggregates |
| Data and content | PostgreSQL, PostgREST, Notion connector/projection |
| Automation and research | Activepieces, Firecrawl, SearXNG |
| Communication | Mattermost; optional Telegram entrypoint for Hermes |
| Deployment and edge | Dokploy, Cloudflare Tunnel/Access |
| Observability | OpenTelemetry, VictoriaMetrics/Logs/Traces, Grafana, Alertmanager |

## Requirements

- Linux deployment host reachable over SSH with root privileges;
- Docker support on the host;
- local Python 3.11+ with `venv`, Docker Compose v2, `bash`, `ssh`, `rsync`
  and `curl`;
- a delegated DNS zone and Cloudflare credentials when edge deployment is
  enabled;
- operator-provided credentials for external systems. Secrets must never be
  committed.

Pinned application and harness versions live in `config/platform.lock.yaml`.

## Quick start

```bash
git clone <repository-url> paperclip-agent-platform
cd paperclip-agent-platform
make release-check
. .venv/bin/activate

cp config/platform.env.example /secure/path/platform.env
chmod 600 /secure/path/platform.env
# Edit the private copy outside the repository.
export MTE_OPERATOR_ENV=/secure/path/platform.env

./platform config check
./platform plan --all
./platform preflight
./platform deploy --all
./platform status
./platform verify --all
./platform connections check
```

`deploy --all` is the canonical end-to-end operation. It freezes the source,
runs 39 ordered steps and emits hash-bound evidence. A failed run can be
resumed only from its recorded run ID or evidence path:

```bash
./platform deploy --all --resume RUN_ID_OR_EVIDENCE
```

`make release-check` creates the project `.venv` and runs the Python, source,
dependency and Compose gates. Activate that environment before invoking the
Python-backed `./platform` CLI. The repository is not published as an
importable Python wheel.

## Configuration and secrets

`config/platform.env.example` is the only checked-in environment template. It
documents operator-owned inputs; initialization adds safe defaults, pinned
runtime values and generated secrets to the same root-owned
`/root/.config/mte-secrets/platform.env` on the deployment host. Rendered
Compose, Dokploy, profile and tool files are projections. Initialization is
fill-only: an ordinary deploy does not rotate existing values.

Never put credential values in YAML, task text, agent instructions, logs,
evidence or command arguments. See the [security guide](docs/en/security.md) and
[Russian security baseline](docs/ru/security.md).

## Agent profiles

`config/profiles/catalog.yaml` declares the three shipped runtime profiles:

- `coding-daytona-codex`;
- `coding-daytona-claude`;
- `coding-daytona-pi`.

Each profile owns its Paperclip environment, Daytona workspace/image contract,
9Router key and ToolHive bearer. Harnesses receive runtime secret references,
not subscription homes or raw connector credentials.

## Documentation

Start with the [documentation map](docs/README.md). It links to the quick start,
architecture, deployment, security, connector contracts, Russian guides and
the standalone [architecture diagram](docs/architecture/index.html).

## Project status

The source suite, connection verifiers and live canaries are designed to be
fail-closed. A green local test suite is not proof of a live installation: only
fresh evidence from the final `verify --all`, bound to the same release and source
hash as the indexed deployment, is an acceptance result.

See [known limitations](docs/en/limitations.md) before production use. Licensed
under the terms in [LICENSE](LICENSE); third-party components are listed in the
[third-party notice](docs/en/third-party.md).

# Documentation

All repository documentation belongs under `docs/`. The only Markdown
documentation allowed at the repository root is `README.md`; `LICENSE` and
`NOTICE` remain there as legal entrypoints. There are no component-local
documentation exceptions. Machine-readable contracts and runtime prompt
payloads are product inputs rather than repository documentation.

## English

1. [Quick start](en/quickstart.md) — prepare, validate and deploy a host.
2. [Platform architecture](en/platform.md) — ownership boundaries and invariants.
3. [Deployment runbook](en/deployment.md) — supported CLI, resume and evidence.
4. [Troubleshooting](en/troubleshooting.md) — diagnose without configuration drift.
5. [Security](en/security.md) — threat model, secrets and release checks.

Contracts and policies:

- [Data and document connectors](en/connectors.md)
- [Notion tool policy](en/notion-tool-policy.md)
- [State mapping](en/state-mapping.md)
- [Known limitations](en/limitations.md)

Project information:

- [Contributing](en/contributing.md)
- [Third-party components](en/third-party.md)
- [License](../LICENSE)

## Russian

- [Product specification](ru/specification.md)
- [Deployment architecture](ru/deployment-architecture.md)
- [Connection registry](ru/connections.md)
- [Security baseline](ru/security.md)

## Visuals

- [Interactive architecture diagram](architecture/index.html)

Machine-readable sources take precedence over prose:

- `config/platform.yaml`: components, dependencies and exposure;
- `config/platform.lock.yaml`: versions and data/content provider registry;
- `config/profiles/catalog.yaml`: harness and tool policies;
- `config/connections.yaml`: required integration checks;
- `config/platform.env.example`: the only operator environment template;
- `tools/platform-cli/platform.py`: supported CLI and indexed deployment sequence.

# Security policy and vulnerability reporting

## Supported versions

Security fixes are made on the latest released minor version and the default
branch. Older snapshots, experimental providers, and deployments with local
modifications are supported only after the issue is reproduced on a supported
version.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or include secrets,
production URLs, exploit payloads, or customer data in logs.

On GitHub, use **Security** -> **Report a vulnerability** when the repository
offers private vulnerability reporting. Maintainers can start a draft Security
Advisory when they need to coordinate the private process; the current GitHub
entrypoint and fallback are kept in the root [security reporting page](../../../SECURITY.md).
Include:

1. the affected version or commit;
2. the smallest safe reproduction;
3. expected and observed behavior;
4. impact and required privileges;
5. suggested mitigations, if known.

If neither path is available and no private contact is published, open a public
issue titled `Request secure vulnerability reporting channel` with no
vulnerability details. Wait for a private channel before sending sensitive
details. Maintainers aim to acknowledge a valid report within five business
days. Disclosure timing is coordinated after a fix and upgrade path exist.

## Operator responsibilities

This platform orchestrates privileged infrastructure. A secure deployment must:

- keep the canonical environment file and provider credentials outside Git;
- use least-privilege Cloudflare, GitHub, Notion, LLM, and service tokens;
- restrict SSH, Docker-compatible sockets, Daytona, ToolHive, and host-operator
  access to explicitly trusted identities;
- protect human applications with authentication and keep service endpoints on
  private networks wherever possible;
- pin and review images and dependencies, retain audit evidence, and rotate
  credentials after suspected exposure;
- review generated plans before applying them to production.

The examples in this repository are templates, not a security certification.
Never use placeholder credentials in a real deployment.

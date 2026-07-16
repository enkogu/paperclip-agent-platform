# Third-party software

Paperclip Agent Platform is an integration and deployment project. A normal
deployment downloads and runs software maintained by other projects. The root
`LICENSE` covers only original material in this repository; every external
component remains subject to its upstream license, notices, trademarks, and
service terms.

## Distribution boundary

- Container images and external CLIs are referenced, not vendored.
- Deployment scripts and declarative service definitions are original
  integration material unless a file explicitly carries an upstream notice.
- Generated outputs and downloaded dependencies are not covered by the root
  license merely because they appear in a local checkout.

## Known runtime license metadata

The machine-readable deployment catalog in `config/platform.lock.yaml` is one input
to the release inventory. It records pinned runtime versions and some license
exceptions, including these optional data-plane components:

| Component | License recorded by the platform |
| --- | --- |
| Paperclip | MIT (upstream runtime and SDK contract) |
| PostgREST | MIT |
| Baserow | MIT |
| Wiki.js | AGPL-3.0-only |

Other principal integrations include Paperclip, Daytona, Kestra, Dokploy,
ToolHive, Activepieces, Mattermost, Firecrawl, SearXNG, PostgreSQL, OpenTofu,
Cloudflare APIs, Notion APIs, Codex CLI, Claude Code, and Pi. Before shipping a
binary, image bundle, managed service, or modified upstream component, verify
the exact version's upstream license and satisfy its notice and source-offer
requirements. This file is an attribution aid, not legal advice or a substitute
for an automated SBOM generated from the final release artifacts.

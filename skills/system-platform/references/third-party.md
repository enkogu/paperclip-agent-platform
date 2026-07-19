# Third-party components and licenses

The repository's Apache-2.0 license covers only original platform code.
Images, CLIs, source installations and hosted APIs keep their upstream
licenses, notices, trademarks and service terms.

## Enforced policy

`config/licenses.lock.json` is the machine-readable source of truth for direct
dependency license decisions. `tools/platform-cli/validate-dependencies.py`
matches every pinned runtime image, npm package, download, system package and
source installation to exactly one decision:

- `approved-oss`: an expression on the reviewed open-source allowlist;
- `operator-provided-proprietary-tool`: fetched from the publisher only after
  deliberate operator enablement and never redistributed by this project;
- `blocked`: prevents the public release gate while the artifact is active.

Permissive and commercial-use copyleft licenses such as AGPL-3.0 may be used
for separate services. Business Source License, non-commercial, SSPL/RSAL,
Commons Clause and other restricted or source-available terms are not accepted
as open-source platform dependencies.

Run the gate with:

```bash
python3 tools/platform-cli/validate-dependencies.py
```

## Codex, Claude and Pi

| Harness | Executable license | Delivery policy |
| --- | --- | --- |
| Codex CLI 0.144.4 | Apache-2.0 | Operator-enabled proprietary harness; upstream service terms still apply |
| Claude Code 2.1.209 | Anthropic proprietary terms | Operator-enabled proprietary harness; no redistribution |
| Pi 0.80.7 | MIT | Approved open source |

Codex and Claude are mandatory supported harnesses, but they are outside the
open-source core distribution boundary. Both installers require
`MTE_ENABLE_OPERATOR_PROVIDED_PROPRIETARY_HARNESSES=true` in the canonical
`platform.env`. The checked-in default is `false`; any other value fails closed
before a package is fetched or installed. The flag records deliberate feature
enablement and the no-redistribution boundary; it does not claim legal-term
acceptance. Operators remain responsible for complying with upstream terms.
The runtime receives a scoped 9Router route key, not a direct OpenAI or
Anthropic subscription credential or API key; 9Router keeps the operator-
supplied MiniMax upstream credential root-only.

## Rejected and unresolved artifacts

- The official Activepieces 0.86.2 image is rejected. Its exact source tag
  includes `packages/ee` under a production-subscription license that does not
  permit redistribution. Removing that directory does not produce a working
  community build because OSS-side workspaces import enterprise modules.
- Automatisch and Windmill were evaluated but do not provide the required
  complete OAuth role from a strictly open-source distribution. Node-RED is a
  viable Apache-2.0 foundation, not a ready provider-neutral OAuth connector
  product; it is evaluated, not shipped.
- The frozen Daytona self-hosted control plane is `v0.187.0`, source commit
  `8a446cb96331737e5a2118cbcaa0604d95c07f71`; it is not represented as the
  newer sandbox release. The CI-only harness Dockerfile extends Daytona's
  official AGPL-3.0 `v0.190.0-slim-amd64` image pinned by immutable digest.
  Harness npm dependencies use the committed lockfile and every downloaded
  binary has an explicit SHA-256. The workflow publishes a private GHCR image,
  signs its digest with keyless Sigstore, and retains a digest-bound SPDX SBOM
  and source-revision receipt. Daytona creates both resource-profile snapshots
  from that published digest; the host never receives a build context. The Daytona
  API/proxy/runner/SSH images are separately pinned by immutable digest and
  bound to that frozen `v0.187.0` Daytona commit (AGPL-3.0).
- Paperclip uses the non-official MTE fork image by the exact operator-supplied
  `MTE_PAPERCLIP_IMAGE` digest, fork source URL, and immutable fork revision.
  The upstream Paperclip base is MIT-licensed, but it is provenance for the
  fork base rather than an official upstream runtime-image claim. The image
  already contains the server, UI, Daytona provider plugin and its SDK.
  Deployment runs the image's native
  command and performs no source build, npm install, `node_modules` patch,
  tool-volume mutation, loopback proxy, or command wrapper.
- Hermes provenance verification calls the exact Apache-2.0 `sigstore`
  JavaScript package `3.0.0` already shipped by the digest-pinned Node verifier
  image. The verifier package identity is an explicit direct-artifact license
  mapping; it is not a mutable `npm install` step.
- Firecrawl uses its three official AGPL-3.0 GHCR images for the API,
  Playwright service and NuQ PostgreSQL. Compose pins each multi-platform
  manifest by immutable digest; no source checkout, patch, private registry or
  image-promotion stage is part of deployment. The separate Docker MCP
  Firecrawl image is independent: its OCI
  revision `2bab1cc2f960e32a3071ec592c89e0c46731a45f` binds to the exact
  MIT-licensed Firecrawl MCP source.

## Distribution boundary and SBOM

- The repository references images and downloads; it does not vendor their
  payloads.
- Deployment scripts and declarative service definitions are original unless
  a file carries an upstream notice.
- Generated outputs and local dependency caches are not relicensed by the root
  license.
- `config/licenses.lock.json` covers direct pinned artifacts. It is not a full
  transitive container or operating-system SBOM. Generate and review an SBOM
  from the final release artifacts before redistributing image bundles.

The catalog contains the exact reviewed source reference and evidence URL for
each component. Update the catalog and its validator tests in the same change
as any dependency upgrade. This page is an operational policy summary, not
legal advice.

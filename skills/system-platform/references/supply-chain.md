# Release supply chain and SBOMs

Pushing a version tag runs
[`.github/workflows/release-sbom.yml`](../../../.github/workflows/release-sbom.yml)
before a GitHub release becomes public. The workflow resolves the tag to an
immutable commit, verifies that the remote tag still has that target, and
creates SPDX JSON SBOMs for the deployment source and every unique image digest
selected from `config/dependencies.lock.json`, `config/compose-seeds.lock.json`,
and the top-level `spec.images` contract in `config/platform.lock.yaml`
(including OpenTofu). A malformed, semantically mismatched, missing, or extra
SBOM fails before publication.

Repository administrators must protect version release tags (the `v*` release
namespace) as immutable: only authorized release automation may create them,
and force-updates or deletion must be forbidden. The workflow re-resolves the
remote tag after a draft exists and immediately before publication; if either
check fails, it exits without publishing and retains the draft for inspection
or retry. Protection is required because workflow checks can detect a moved tag
but cannot make a mutable tag safe between independent GitHub operations.

Repository administrators must also protect the `daytona-harness-*` tag
namespace as immutable: only the Daytona harness workflow may create these
tags, and updates or deletion must be forbidden. The harness workflow resolves
the remote tag to the exact source SHA immediately before and immediately after
making its digest-bound release public. Its release body, receipt, and SBOM are
byte-compared to artifacts that bind that same source SHA and image digest, so
a moved tag fails acceptance; tag protection closes the race between GitHub
operations that validation alone cannot eliminate.

The workflow retains short-lived assembly artifacts, revalidates the exact
complete set, and packs it into one deterministic release asset. Its internal
manifest binds every member to a SHA-256 checksum, the source root to the exact
GitHub repository and commit, and each image root name, version, OCI purl, and
digest to the locked image reference. The release is created as a draft only
after all generation jobs pass. Retries replace the expected bundle, remove
stale managed SBOM assets, verify the sole uploaded asset's size and GitHub
SHA-256 digest, and publish only after that reconciliation succeeds. A failure
therefore leaves a non-public draft rather than a public release without its
SBOM.

`config/licenses.lock.json` is the exact policy contract for every direct
runtime artifact and every shipped image catalog, including the OpenTofu image
from `config/platform.lock.yaml`. It is not a transitive image license
inventory. The repository does not vendor, rebuild, or relicense the external
image payloads: each released image SBOM describes the upstream image at the
pinned digest, while the source SBOM describes this repository's deployment
material. Operator-provided proprietary harnesses remain outside the public
redistribution boundary described in [third-party.md](third-party.md).

`deployment/image-build/daytona-harness/Dockerfile` is consumed only by the
SHA-pinned `daytona-harness-image` workflow. That workflow publishes by digest,
adds BuildKit provenance/SBOM attestations, signs the digest with GitHub OIDC,
and retains a Syft SPDX document plus the exact source/revision receipt. Host
deployment consumes only `MTE_DAYTONA_SANDBOX_IMAGE=image@sha256:...`; it does
not synchronize the Dockerfile or lockfiles and has no image build path.

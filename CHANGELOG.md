# Changelog

## Unreleased

## [0.1.0] - 2026-07-20

### Added

- A source-controlled platform installation lifecycle with the ordered
  `preflight`, `host`, `compose`, `provision`, `cloudflare`, and `verify`
  stages.
- Declarative platform, profile, connection, acceptance-requirement, and
  dependency contracts for the Paperclip, Daytona, 9Router, ToolHive, data,
  and observability service planes.
- Daytona sandbox runtime definitions for the Codex, Claude Code, and Pi
  agent profiles, plus Paperclip workflow and agent-plane integration tooling.
- Offline quick and release gates, including configuration, Compose, dependency,
  and focused verification tests.
- Pinned source secret scanning and a tag-bound SBOM workflow that validates an
  immutable release commit before preparing release assets.

### Changed

- Consolidated the operator documentation under the versioned
  `system-platform` skill, with root project files retained as concise entry
  points.

## Release policy

[`VERSION`](VERSION) is the single authoritative release version. It contains
only a three-part semantic version with no `v` prefix. To release, update
`VERSION`, move the reviewed Unreleased entries into a dated
`## [X.Y.Z] - YYYY-MM-DD` section, and commit both changes together. Run
`make release-check` from the resulting clean commit, then create one annotated
Git tag named `vX.Y.Z` pointing at that commit. A version or tag must never be
reused.

Compatibility notes and rollback guidance belong with the current
machine-readable contracts and the
[system-platform development reference](skills/system-platform/references/development.md).

Do not record live host status, evidence snapshots, or secret-bearing output in
this file.

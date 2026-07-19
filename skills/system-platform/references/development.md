# Development and contribution rules

Thank you for improving Paperclip Agent Platform. Changes should keep the
platform declarative, reproducible, fail-closed, and understandable to an
operator reading the repository for the first time.

## Development setup

Requirements:

- Python 3.11 or newer;
- the Python packages pinned in
  `tools/platform-cli/requirements-release-check.txt`;
- Docker with the Compose v2 plugin;
- Bash.

Install the locked packages explicitly into the environment used by the
system `python3` command:

```bash
python3 -m pip install --require-hashes --only-binary=:all: \
  --requirement tools/platform-cli/requirements-release-check.txt
```

Run the complete offline release gate from the repository root:

```bash
make release-check
```

The gate is deliberately release-commit-only: it fails if there are untracked,
staged, or unstaged changes, or if the Git index does not exactly match
`HEAD^{tree}`. Commit the reviewed release tree first, then run the gate from
that clean checkout. This prevents a local index from being scanned or shipped
as though it were the release commit.

The command and `./platform` use the system `python3` directly. The release
gate checks Python 3.11+ and the exact installed distribution versions from the
lock. Installed metadata cannot attest wheel hashes, so the hash-locked command
above remains the required remediation path for a mismatch. The removed hidden
virtual-environment/bootstrap lifecycle neither owns nor deletes `.runtime`:
that directory remains active generated runtime and evidence state. A local
release check does not claim that a live server deployment or real LLM canary
succeeded; those require the separately documented deployment acceptance flow.

## Change rules

1. Never commit credentials, private keys, production hostnames, personal file
   paths, live evidence, or generated runtime state.
2. Use the upstream project's supported published runtime and official
   Compose/Helm contract first. A custom source build, patch stack, private
   registry, wrapper, or promotion phase requires a verified functional blocker
   and a documented reason why the official artifact cannot satisfy it.
   Compose plus immutable image digests is the standard reproducibility
   boundary; do not build a second reproducibility system around it.
3. Every new file, service, deployment step, abstraction, and configuration key
   must have a current consumer and a simpler rejected alternative. Remove or
   merge it when that necessity cannot be demonstrated.
4. Update the declarative catalog before adding ad-hoc branching to a verifier
   or provisioner.
5. Keep detailed documentation under `skills/system-platform`. Root Markdown is
   limited to the README and the thin OSS participation entrypoints
   (`CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, and `CHANGELOG.md`);
   they must route here instead of duplicating operator instructions.
6. Add a regression test for behavior changes and a negative test for security
   or fail-closed behavior.
7. Keep Compose images and tool versions pinned consistently with
   `config/platform.lock.yaml`.
8. Document operator-visible configuration, migrations, and rollback behavior.

## Deployment design

The installation path is deliberately smaller than the platform it installs:

1. `install.sh` is the only ordering authority. It invokes the semantic shell
   steps in `deployment/scripts` and contains no release transaction, snapshot,
   resume, build-promotion, or private state machine.
2. Docker Compose owns container lifecycle, networks, volumes, health checks,
   and incremental reconciliation. Compose calls no platform installer; the
   installer calls Compose.
3. Provisioning scripts run only after the required APIs are healthy. They
   create or reconcile accounts, workflows, scoped credentials, and service
   bindings using read-before-create idempotency.
4. Terraform owns only Cloudflare DNS, Tunnel, and Access declarations. It does
   not manage application containers.
5. A Python helper is justified only for an API or validation operation that is
   materially clearer and safer in Python. Python must not become a second
   deployment orchestrator.

Normal deployment never runs `docker compose down`, deletes volumes, rebuilds
an upstream application, or recreates an unchanged service. Official published
images pinned by immutable digest are the reproducible runtime contract.

## Fast iteration

Use the narrowest honest feedback loop:

```bash
./test.sh quick
./install.sh compose SERVICE
./test.sh smoke SERVICE
```

The supported test levels are:

- `quick`: offline syntax, schema, Compose rendering, and unit tests;
- `smoke [SERVICE]`: live health and the narrow semantic verifier;
- `e2e [HARNESS]`: real Paperclip, Daytona, 9Router/MiniMax, and GitHub canary;
- clean-host acceptance: run the ordinary installer only on an explicitly
  selected disposable host; there is no destructive reset mode.

Do not add fixed sleeps. Use Compose health checks or bounded one-second API
polling. Keep volumes and Docker image cache during normal iterations, run only
the affected provisioning group, and reserve clean installation plus all-three
harness E2E for release acceptance.

## Pull requests

Describe the problem, design trade-offs, migration and rollback path, and the
evidence produced by `make release-check`. Keep unrelated cleanup in separate
commits. A pull request is ready only when the release gate passes from a clean
checkout and no generated files are staged.

By submitting a contribution, you agree that it is licensed under the Apache
License, Version 2.0, unless the contribution is conspicuously marked otherwise
and accepted by the maintainers.

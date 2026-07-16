# Contributing

Thank you for improving Paperclip Agent Platform. Changes should keep the
platform declarative, reproducible, fail-closed, and understandable to an
operator reading the repository for the first time.

## Development setup

Requirements:

- Python 3.11 or newer;
- Docker with the Compose v2 plugin;
- Bash.

Run the complete offline release gate from the repository root:

```bash
make release-check
```

The command creates the ignored `.venv`, installs the declared `release-check`
dependency group, and runs all bounded checks. Activate that environment before
using the Python-backed `./platform` CLI. A local release check does not claim
that a live server deployment or real LLM canary succeeded; those require the
separately documented deployment acceptance flow.

## Change rules

1. Never commit credentials, private keys, production hostnames, personal file
   paths, live evidence, or generated runtime state.
2. Update the declarative catalog before adding ad-hoc branching to a verifier
   or provisioner.
3. Keep all repository documentation under `docs/`; only the root `README.md`
   is an allowed Markdown documentation entrypoint outside that directory.
4. Add a regression test for behavior changes and a negative test for security
   or fail-closed behavior.
5. Keep Compose images and tool versions pinned consistently with
   `config/platform.lock.yaml`.
6. Document operator-visible configuration, migrations, and rollback behavior.

## Pull requests

Describe the problem, design trade-offs, migration and rollback path, and the
evidence produced by `make release-check`. Keep unrelated cleanup in separate
commits. A pull request is ready only when the release gate passes from a clean
checkout and no generated files are staged.

By submitting a contribution, you agree that it is licensed under the Apache
License, Version 2.0, unless the contribution is conspicuously marked otherwise
and accepted by the maintainers.

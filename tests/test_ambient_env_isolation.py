from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_SCRIPT = ROOT / "deployment/scripts/compose.sh"
RENDERER_PATH = ROOT / "tools/platform-cli/render-cloudflare.py"


def load_renderer():
    spec = importlib.util.spec_from_file_location(
        "ambient_env_cloudflare_renderer", RENDERER_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def remote_compose_script() -> str:
    source = COMPOSE_SCRIPT.read_text()
    marker = "<<'REMOTE'\n"
    return source.split(marker, 1)[1].rsplit("\nREMOTE", 1)[0]


def test_cloudflare_canonical_environment_wins_over_ambient_and_is_not_backfilled():
    renderer = load_renderer()
    with tempfile.TemporaryDirectory() as directory:
        env_file = Path(directory) / "platform.env"
        env_file.write_text("PLATFORM_BASE_DOMAIN=canonical.example.test\n")
        with mock.patch.dict(
            os.environ,
            {
                "PLATFORM_BASE_DOMAIN": "ambient.example.test",
                "CLOUDFLARE_API_TOKEN": "ambient-only-token",
            },
            clear=False,
        ):
            environment = renderer.combined_environment(env_file)

    assert environment["PLATFORM_BASE_DOMAIN"] == "canonical.example.test"
    assert "CLOUDFLARE_API_TOKEN" not in environment


def test_remote_compose_interpolation_ignores_conflicting_ambient_environment():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        platform_root = root / "platform"
        secrets_root = root / "secrets"
        bin_root = root / "bin"
        platform_root.joinpath("deployment").mkdir(parents=True)
        platform_root.joinpath("bin").mkdir()
        secrets_root.mkdir()
        bin_root.mkdir()
        platform_root.joinpath("deployment/compose.yaml").write_text(
            "services: {}\n"
        )
        secrets_root.joinpath("compose.env").write_text(
            "PLATFORM_BASE_DOMAIN=canonical.example.test\n"
        )
        platform_root.joinpath("bin/server-config.py").write_text(
            "import sys\nraise SystemExit(0 if sys.argv[1:] == ['audit'] else 93)\n"
        )

        docker = bin_root / "docker"
        docker.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
if [[ $1 == compose ]]; then
  [[ ${PLATFORM_BASE_DOMAIN+x} != x ]] || {
    echo "ambient leaked into compose: $PLATFORM_BASE_DOMAIN" >&2
    exit 90
  }
  while (( $# )); do
    if [[ $1 == --env-file ]]; then
      [[ $2 == */compose.env ]]
      grep -qx 'PLATFORM_BASE_DOMAIN=canonical.example.test' "$2"
      exit 0
    fi
    shift
  done
  echo "compose did not receive the aggregate env projection" >&2
  exit 91
fi
if [[ $1 == ps ]]; then
  exit 0
fi
if [[ $1 == stack && $2 == services ]]; then
  exit 1
fi
if [[ $1 == service && $2 == inspect ]]; then
  exit 1
fi
if [[ $1 == container && $2 == inspect ]]; then
  exit 1
fi
echo "unexpected docker invocation: $*" >&2
exit 92
"""
        )
        docker.chmod(0o755)

        completed = subprocess.run(
            [
                "bash",
                "-s",
                "--",
                str(platform_root),
                str(secrets_root),
            ],
            input=remote_compose_script(),
            env={
                "HOME": str(root),
                "PATH": f"{bin_root}:/usr/bin:/bin",
                "PLATFORM_BASE_DOMAIN": "ambient.example.test",
            },
            text=True,
            capture_output=True,
            check=False,
        )

    assert completed.returncode == 0, completed.stderr


def test_observability_reconcile_restarts_alertmanager_after_config_init():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        platform_root = root / "platform"
        secrets_root = root / "secrets"
        bin_root = root / "bin"
        log = root / "docker.log"
        platform_root.joinpath("deployment").mkdir(parents=True)
        platform_root.joinpath("bin").mkdir()
        secrets_root.mkdir()
        bin_root.mkdir()
        platform_root.joinpath("deployment/compose.yaml").write_text("services: {}\n")
        platform_root.joinpath("bin/server-config.py").write_text(
            "import sys\nraise SystemExit(0 if sys.argv[1:] == ['audit'] else 93)\n"
        )
        secrets_root.joinpath("compose.env").write_text("SAFE=value\n")
        docker = bin_root / "docker"
        docker.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            f"printf '%s\\n' \"$*\" >> {str(log)!r}\n"
            "[[ $1 == compose ]]\n"
        )
        docker.chmod(0o755)

        completed = subprocess.run(
            [
                "bash",
                "-s",
                "--",
                str(platform_root),
                str(secrets_root),
                "restart-alertmanager",
                "config-init",
                "alertmanager",
            ],
            input=remote_compose_script(),
            env={"HOME": str(root), "PATH": f"{bin_root}:/usr/bin:/bin"},
            text=True,
            capture_output=True,
            check=False,
        )

        prefix = f"compose --env-file {secrets_root}/compose.env -f {platform_root}/deployment/compose.yaml"
        assert completed.returncode == 0, completed.stderr
        assert log.read_text().splitlines() == [
            f"{prefix} config --quiet",
            f"{prefix} up -d --wait config-init alertmanager",
            f"{prefix} restart alertmanager",
            f"{prefix} up -d --wait alertmanager",
        ]

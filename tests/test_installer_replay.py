from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"
STAGES = ["preflight", "host", "compose", "provision", "cloudflare", "verify"]


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "checkout"
    scripts = root / "deployment" / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(INSTALLER, root / "install.sh")
    log = root / "stages.log"
    for stage in STAGES:
        script = scripts / f"{stage}.sh"
        script.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            f"printf '%s\\n' {stage!r} >> {str(log)!r}\n"
        )
        script.chmod(0o700)
    return root / "install.sh", log


def test_default_install_replays_the_complete_order(tmp_path: Path) -> None:
    installer, log = _fixture(tmp_path)

    subprocess.run([installer], check=True)
    subprocess.run([installer], check=True)

    assert log.read_text().splitlines() == STAGES * 2


def test_failure_stops_and_explicit_replay_can_resume_at_that_stage(tmp_path: Path) -> None:
    installer, log = _fixture(tmp_path)
    provision = installer.parent / "deployment" / "scripts" / "provision.sh"
    provision.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"printf '%s\\n' provision >> {str(log)!r}\n"
        "exit 75\n"
    )
    provision.chmod(0o700)

    failed = subprocess.run([installer], check=False)
    assert failed.returncode == 75
    assert log.read_text().splitlines() == STAGES[:4]

    provision.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"printf '%s\\n' provision >> {str(log)!r}\n"
    )
    provision.chmod(0o700)
    subprocess.run([installer, "provision"], check=True)

    assert log.read_text().splitlines() == [*STAGES[:4], "provision"]


def test_resource_preflight_failure_stops_before_host_mutation_and_replays_cleanly(
    tmp_path: Path,
) -> None:
    installer, log = _fixture(tmp_path)
    preflight = installer.parent / "deployment" / "scripts" / "preflight.sh"
    preflight.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"printf '%s\\n' preflight >> {str(log)!r}\n"
        "exit 76\n"
    )
    preflight.chmod(0o700)

    failed = subprocess.run([installer], check=False)
    assert failed.returncode == 76
    assert log.read_text().splitlines() == ["preflight"]

    preflight.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"printf '%s\\n' preflight >> {str(log)!r}\n"
    )
    preflight.chmod(0o700)
    subprocess.run([installer], check=True)
    assert log.read_text().splitlines() == ["preflight", *STAGES]


def test_components_are_rejected_before_non_component_stage_runs(tmp_path: Path) -> None:
    installer, log = _fixture(tmp_path)

    for stage in ("preflight", "host", "cloudflare"):
        result = subprocess.run(
            [installer, stage, "unexpected"],
            env={**os.environ, "MTE_OPERATOR_ENV": str(tmp_path / "unused.env")},
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert f"the {stage} step does not accept a component" in result.stderr

    assert not log.exists()

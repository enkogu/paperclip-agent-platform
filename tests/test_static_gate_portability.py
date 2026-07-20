from __future__ import annotations

import importlib.util
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
HOST_STEP = ROOT / "deployment/steps/host.sh"
BACKUP_SCRIPT = ROOT / "deployment/scripts/backup.sh"
RESTORE_SCRIPT = ROOT / "deployment/scripts/restore.sh"
RELEASE_CHECK = ROOT / "tools/platform-cli/release-check.sh"
CI_WORKFLOW = ROOT / ".github/workflows/ci.yml"
SERVER_VERIFY = ROOT / "tools/platform-cli/server-verify.py"


def load_server_verify():
    spec = importlib.util.spec_from_file_location("server_verify", SERVER_VERIFY)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StaticGatePortabilityTests(unittest.TestCase):
    def test_release_check_tmpdir_default_is_structural(self) -> None:
        findings = load_server_verify().static_config_findings(ROOT)
        self.assertFalse(
            any(
                finding.get("finding") == "script_env_default_outside_canonical"
                and finding.get("path") == "tools/platform-cli/release-check.sh"
                and finding.get("key") == "TMPDIR"
                for finding in findings
            ),
            findings,
        )

    def test_host_step_uses_bash_3_compatible_variable_presence_checks(self) -> None:
        source = HOST_STEP.read_text()
        self.assertNotIn("[[ -v", source)
        self.assertIn("${ID+x}", source)
        self.assertIn("${VERSION_ID+x}", source)
        self.assertIn("${VERSION_CODENAME+x}", source)
        subprocess.run(["/bin/bash", "-n", str(HOST_STEP)], check=True)

    def test_recovery_scripts_remain_bash_3_compatible(self) -> None:
        for script in (BACKUP_SCRIPT, RESTORE_SCRIPT):
            source = script.read_text()
            self.assertNotIn("declare -A", source)
            self.assertNotIn("mapfile", source)
            subprocess.run(["/bin/bash", "-n", str(script)], check=True)

    def test_release_check_does_not_replace_the_test_process_path(self) -> None:
        source = RELEASE_CHECK.read_text()
        self.assertNotIn("PYTEST_PATH", source)
        self.assertIn(
            'run_bounded "$CHECK_TIMEOUT" "$PYTHON" -m pytest',
            source,
        )

    def test_ci_workflow_parses_the_hash_locked_install_command(self) -> None:
        workflow = yaml.safe_load(CI_WORKFLOW.read_text())
        self.assertIn("jobs", workflow)
        steps = workflow["jobs"]["release-check"]["steps"]
        install = next(
            step
            for step in steps
            if step["name"] == "Install hash-locked release-check dependencies"
        )
        run = install["run"]
        self.assertIn("--only-binary=:all:", run)


if __name__ == "__main__":
    unittest.main()

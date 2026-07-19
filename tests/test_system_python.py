from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SystemPythonTests(unittest.TestCase):
    def test_launchers_use_system_python_without_runtime_cache(self) -> None:
        platform = (ROOT / "platform").read_text()
        release_check = (ROOT / "tools/platform-cli/release-check.sh").read_text()
        quick_check = (ROOT / "deployment/scripts/verify.sh").read_text()

        self.assertIn('exec python3 "$ROOT/tools/platform-cli/platform.py" "$@"', platform)
        self.assertIn("PYTHON=python3", release_check)
        self.assertIn("PYTHON=python3", quick_check)
        combined = platform + release_check + quick_check
        self.assertIn("requirements-release-check.txt", combined)
        self.assertNotIn("runtime.sh", combined)
        self.assertNotIn(".runtime/python", combined)
        self.assertFalse((ROOT / "tools/platform-cli/runtime.sh").exists())

    def test_clean_prunes_environment_directories_without_deleting_contents(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mte-system-python-") as temporary:
            root = Path(temporary) / "clean-fixture"
            root.mkdir()
            shutil.copy2(ROOT / "Makefile", root / "Makefile")

            owned = []
            protected = []
            for directory in ("deployment", "tools", "tests"):
                artifact_root = root / directory / "owned"
                cache = artifact_root / "__pycache__"
                cache.mkdir(parents=True)
                (cache / "module.pyc").write_bytes(b"cache")
                owned.append(cache)
                for environment in (".venv", ".runtime"):
                    preserved = artifact_root / environment / "state.pyc"
                    preserved.parent.mkdir(parents=True)
                    preserved.write_bytes(b"preserve")
                    protected.append(preserved)

            subprocess.run(
                ["make", "--no-print-directory", "clean"],
                cwd=root,
                check=True,
                timeout=10,
            )

            self.assertTrue(all(not path.exists() for path in owned))
            self.assertTrue(all(path.read_bytes() == b"preserve" for path in protected))

    def test_documentation_preserves_runtime_state_after_venv_lifecycle_removal(self) -> None:
        readme = (ROOT / "README.md").read_text()
        development = (
            ROOT / "skills/system-platform/references/development.md"
        ).read_text()

        self.assertIn("`.runtime` remains active generated runtime and evidence state", readme)
        self.assertIn("automatically deletes it", readme)
        self.assertIn("neither owns nor deletes `.runtime`", development)

    def test_release_check_rejects_exact_distribution_version_mismatches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "release-tree"
            script = root / "tools/platform-cli/release-check.sh"
            requirements = root / "tools/platform-cli/requirements-release-check.txt"
            workflow = root / ".github/workflows/ci.yml"
            fake_site = root / "fake-site"
            root.mkdir()
            script.parent.mkdir(parents=True)
            workflow.parent.mkdir(parents=True)
            fake_site.mkdir()
            shutil.copy2(ROOT / "tools/platform-cli/release-check.sh", script)
            shutil.copy2(
                ROOT / "tools/platform-cli/requirements-release-check.txt", requirements
            )
            workflow.write_text('GITLEAKS_VERSION: "8.30.1"\n')
            (fake_site / "sitecustomize.py").write_text(
                "import importlib.metadata\n"
                "_version = importlib.metadata.version\n"
                "def version(name):\n"
                "    if name.casefold().replace('-', '') in {'pytest', 'pyyaml'}:\n"
                "        return '0.0.0'\n"
                "    return _version(name)\n"
                "importlib.metadata.version = version\n"
            )
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=release-test",
                    "-c",
                    "user.email=release-test@example.invalid",
                    "commit",
                    "-qm",
                    "release tree",
                ],
                cwd=root,
                check=True,
            )

            environment = {
                **os.environ,
                "PYTHONPATH": str(fake_site),
                "PYTHONNOUSERSITE": "1",
            }
            result = subprocess.run(
                ["/bin/bash", str(script)],
                cwd=root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("pytest: expected", result.stderr)
        self.assertIn("pyyaml: expected", result.stderr)
        self.assertIn("installed metadata cannot attest wheel hashes", result.stderr)
        self.assertIn("--require-hashes", result.stderr)

    def test_platform_reports_locked_install_command_when_python_is_unusable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fake_python = Path(temporary) / "python3"
            fake_python.write_text("#!/bin/sh\nexit 1\n")
            fake_python.chmod(0o755)
            environment = {**os.environ, "PATH": temporary}

            result = subprocess.run(
                ["/bin/bash", str(ROOT / "platform"), "--help"],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("Python 3.11+", result.stderr)
        self.assertIn("--require-hashes", result.stderr)
        self.assertIn("requirements-release-check.txt", result.stderr)


if __name__ == "__main__":
    unittest.main()

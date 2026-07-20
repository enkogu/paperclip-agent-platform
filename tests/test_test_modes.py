from __future__ import annotations

from pathlib import Path
import os
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "test.sh"
VERIFY = ROOT / "deployment/scripts/verify.sh"
CLOUDFLARE = ROOT / "deployment/scripts/cloudflare.sh"


class TestModeEntrypointTests(unittest.TestCase):
    def run_test(self, *arguments: str, **environment: str) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env.pop("MTE_FRESH_CONFIRM", None)
        env.update(environment)
        return subprocess.run(
            ["bash", str(ENTRYPOINT), *arguments],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_help_names_modes_and_live_boundaries(self):
        result = self.run_test("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("quick is offline", result.stdout)
        self.assertIn("smoke [component]", result.stdout)
        self.assertIn("e2e [kestra]", result.stdout)
        self.assertNotIn("fresh", result.stdout)

    def test_e2e_rejects_a_fake_harness_before_live_actions(self):
        result = self.run_test("e2e", "fake")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsupported E2E harness", result.stderr)
        self.assertNotIn("Live Kestra", result.stdout)

    def test_scripts_do_not_poll_with_sleep_or_claim_remote_skips_passed(self):
        source = VERIFY.read_text()
        cloudflare_source = CLOUDFLARE.read_text()
        self.assertNotIn("sleep ", source)
        self.assertIn("no live host checks were run", source)
        self.assertIn('"$ROOT/platform" verify', source)
        self.assertIn('"$ROOT/platform" verify --all', source)
        rebind = source.index('"$ROOT/platform" evidence-rebind')
        cloudflare = source.index('"$ROOT/platform" cloudflare acceptance')
        acceptance = source.index('"$ROOT/platform" acceptance check')
        final_verify = source.index('"$ROOT/platform" verify --all')
        self.assertEqual(source.count('"$ROOT/platform" evidence-rebind'), 1)
        self.assertLess(rebind, cloudflare)
        self.assertLess(cloudflare, acceptance)
        self.assertLess(acceptance, final_verify)
        self.assertIn('"$ROOT/platform" cloudflare apply', cloudflare_source)
        self.assertNotIn('"$ROOT/platform" cloudflare acceptance', cloudflare_source)

    def test_e2e_refreshes_daytona_before_producing_canary_evidence(self):
        source = VERIFY.read_text()
        e2e = source.split("run_e2e() {", 1)[1].split("\nrun_release_acceptance()", 1)[0]
        daytona_apply = e2e.index('"$ROOT/platform" daytona apply')
        daytona_verify = e2e.index('"$ROOT/platform" daytona verify')
        canary_apply = e2e.index('"$ROOT/platform" kestra-canary apply')
        canary_verify = e2e.index('"$ROOT/platform" kestra-canary verify')
        self.assertLess(daytona_apply, daytona_verify)
        self.assertLess(daytona_verify, canary_apply)
        self.assertLess(canary_apply, canary_verify)
        self.assertEqual(e2e.count('"$ROOT/platform" daytona apply'), 1)
        self.assertEqual(e2e.count('"$ROOT/platform" daytona verify'), 1)

    def test_quick_syntax_check_covers_installer_and_every_stage_script(self):
        source = VERIFY.read_text()
        self.assertIn("shell_files=(platform install.sh test.sh)", source)
        self.assertIn("find deployment/scripts -type f -name '*.sh' -print0", source)


if __name__ == "__main__":
    unittest.main()

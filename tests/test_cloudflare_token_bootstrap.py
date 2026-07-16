from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "cloudflare_token_bootstrap",
    ROOT / "tools/platform-cli" / "cloudflare-token-bootstrap.py",
)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class CloudflareTokenBootstrapTests(unittest.TestCase):
    def test_desired_policy_has_only_exact_account_and_zone_scopes(self) -> None:
        groups = {
            name: f"group-{index}" for index, name in enumerate(module.REQUIRED_GROUPS)
        }
        policies = module.desired_policies("a" * 32, "b" * 32, groups)

        self.assertEqual(len(policies), 2)
        account, zone = policies
        self.assertEqual(
            account["resources"], {f"com.cloudflare.api.account.{'a' * 32}": "*"}
        )
        self.assertEqual(
            zone["resources"], {f"com.cloudflare.api.account.zone.{'b' * 32}": "*"}
        )
        self.assertEqual(len(account["permission_groups"]), 3)
        self.assertEqual(len(zone["permission_groups"]), 2)
        self.assertEqual(account["effect"], "allow")
        self.assertEqual(zone["effect"], "allow")

    def test_policy_comparison_ignores_cloudflare_generated_metadata(self) -> None:
        desired = [
            {
                "effect": "allow",
                "permission_groups": [{"id": "two"}, {"id": "one"}],
                "resources": {"resource": "*"},
            }
        ]
        actual = [
            {
                "id": "generated-policy-id",
                "effect": "allow",
                "permission_groups": [
                    {"id": "one", "name": "First"},
                    {"id": "two", "name": "Second", "meta": {}},
                ],
                "resources": {"resource": "*"},
            }
        ]
        self.assertEqual(
            module.normalized_policies(desired), module.normalized_policies(actual)
        )

    def test_canonical_conflicts_detect_non_token_drift(self) -> None:
        desired = {
            "PLATFORM_BASE_DOMAIN": "prin7r.com",
            "CLOUDFLARE_API_TOKEN": "new-secret",
        }
        snapshot = {
            "keys": {
                "PLATFORM_BASE_DOMAIN": {
                    "present": True,
                    "sha256": module.hash_value("other.example"),
                },
                "CLOUDFLARE_API_TOKEN": {
                    "present": True,
                    "sha256": module.hash_value("old-secret"),
                },
            }
        }
        self.assertEqual(
            module.canonical_conflicts(snapshot, desired),
            ["PLATFORM_BASE_DOMAIN"],
        )

    def test_safe_plan_is_not_ready_when_an_origin_is_unhealthy(self) -> None:
        context = {
            "token": None,
            "policies": [],
            "originBlockers": [
                {"code": "internal_origin_unhealthy", "component": "paperclip"}
            ],
            "canonicalConflicts": [],
            "snapshot": {"keys": {}},
            "canonicalDesired": {"PLATFORM_BASE_DOMAIN": "prin7r.com"},
            "zoneName": "prin7r.com",
            "idpMode": "onetimepin",
        }
        plan = module.safe_plan(context, "plan")
        self.assertFalse(plan["readyForApply"])
        self.assertFalse(plan["mutationPerformed"])
        self.assertIn("create_account_owned_token", plan["plannedActions"])
        self.assertIn(
            "render_audit_verify_manifest_under_shared_lock",
            plan["plannedActions"],
        )
        self.assertFalse(plan["token"]["localSecretProjectionPresent"])

    def test_remote_writer_uses_shared_lock_and_verifies_renderer_manifest(
        self,
    ) -> None:
        script = module.canonical_reconcile_script(
            Path("/opt/mte-platform"), Path("/root/.config/mte-secrets")
        )
        compile(script, "cloudflare-canonical-reconcile", "exec")
        self.assertIn('lock=secret_root/".platform-env.lock"', script)
        self.assertIn("fcntl.flock(descriptor,fcntl.LOCK_EX)", script)
        self.assertIn("os.fchown(descriptor,0,0)", script)
        self.assertIn("module.render()", script)
        self.assertIn("audited=module.audit()", script)
        self.assertIn('manifest_path=secret_root/"projections-manifest.json"', script)
        self.assertIn("projection manifest content gate failed", script)
        self.assertNotIn("api.env", script)

        lock = script.index("fcntl.flock(descriptor,fcntl.LOCK_EX)")
        reread = script.index("current={}", lock)
        replace = script.index("os.replace(temporary,canonical)", reread)
        render = script.index("module.render()", replace)
        audit = script.index("audited=module.audit()", render)
        unlock = script.index("fcntl.flock(descriptor,fcntl.LOCK_UN)", audit)
        self.assertEqual(
            [lock, reread, replace, render, audit, unlock],
            sorted([lock, reread, replace, render, audit, unlock]),
        )

    def test_write_canonical_keeps_secret_in_stdin_and_requires_full_evidence(
        self,
    ) -> None:
        secret_root = Path("/srv/mte-secrets")
        evidence = {
            "canonicalSourceSha256": "1" * 64,
            "manifestSha256": "2" * 64,
            "serverConfigSha256": "3" * 64,
            "projectionCount": 41,
            "generatorVersion": "mte-config-renderer/v1",
            "renderAuditVerified": True,
            "sharedLockPath": str(secret_root / ".platform-env.lock"),
        }
        observed = {}

        def ssh(target, command, *, input_text=None):
            observed.update(target=target, command=command, input_text=input_text)
            return subprocess.CompletedProcess([], 0, json.dumps(evidence), "")

        token = "unit-secret-token-" + "x" * 48
        with mock.patch.object(module, "ssh_command", side_effect=ssh):
            result = module.write_canonical(
                "root@example.test",
                {"CLOUDFLARE_API_TOKEN": token},
                platform_root=Path("/srv/mte"),
                secret_root=secret_root,
            )
        self.assertEqual(result, evidence)
        self.assertNotIn(token, observed["command"])
        self.assertEqual(
            json.loads(observed["input_text"])["CLOUDFLARE_API_TOKEN"], token
        )

        invalid = dict(evidence, renderAuditVerified=False)
        with self.assertRaises(module.BootstrapError):
            module.validate_canonical_update_evidence(invalid, secret_root=secret_root)

        for invalid in (
            dict(evidence, sharedLockPath="/wrong/lock"),
            dict(evidence, projectionCount=0),
            dict(evidence, manifestSha256="not-a-sha256"),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(module.BootstrapError):
                    module.validate_canonical_update_evidence(
                        invalid, secret_root=secret_root
                    )

    def test_write_canonical_fails_closed_when_remote_reconcile_fails(self) -> None:
        with mock.patch.object(
            module,
            "ssh_command",
            return_value=subprocess.CompletedProcess(
                [], 1, '{"renderAuditVerified":true}', "renderer failed"
            ),
        ):
            with self.assertRaisesRegex(
                module.BootstrapError, "locked canonical render and audit failed"
            ):
                module.write_canonical(
                    "root@example.test",
                    {"CLOUDFLARE_API_TOKEN": "secret-not-printed"},
                )

    def test_local_metadata_contains_hashes_but_no_secret_projection(self) -> None:
        evidence = {
            "canonicalSourceSha256": "1" * 64,
            "manifestSha256": "2" * 64,
            "serverConfigSha256": "3" * 64,
            "projectionCount": 41,
            "generatorVersion": "mte-config-renderer/v1",
        }
        with tempfile.TemporaryDirectory() as directory:
            metadata = Path(directory) / "cloudflare" / "metadata.json"
            with mock.patch.object(module, "LOCAL_METADATA", metadata):
                module.atomic_local_metadata(evidence)
            value = json.loads(metadata.read_text())
            self.assertEqual(value["canonicalSourceSha256"], "1" * 64)
            self.assertTrue(value["renderAuditVerified"])
            self.assertFalse(value["containsSecretValue"])
            self.assertNotIn("CLOUDFLARE_API_TOKEN", metadata.read_text())
            self.assertEqual(metadata.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()

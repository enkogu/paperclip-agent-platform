import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/platform-cli/server-deploy-transaction.py"


def load_module():
    spec = importlib.util.spec_from_file_location("server_deploy_transaction", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class DeployTransactionTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def source(self, root: Path, value: str) -> Path:
        source = root / "source"
        (source / "bin").mkdir(parents=True)
        (source / "config").mkdir()
        (source / "bin/runner.py").write_text(value)
        (source / "bin/runner.py").chmod(0o700)
        (source / "config/connections.yaml").write_text("value: " + value)
        (source / "config/connections.yaml").chmod(0o644)
        return source

    def seal_release(self, root: Path, release_id: str, value: str):
        upload = root / ".deploy/uploads" / (release_id + "-upload")
        source = self.source(upload, value)
        manifest = self.module.build_manifest(
            source, ["bin", "config/connections.yaml"]
        )
        (upload / "source-manifest.json").write_text(json.dumps(manifest))
        self.module.seal(root, upload, release_id)
        return manifest

    def test_seal_promote_verify_and_source_only_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "platform"
            root.mkdir()
            (root / "bin").mkdir()
            (root / "config").mkdir()
            (root / "bin/runner.py").write_text("old")
            (root / "config/connections.yaml").write_text("value: old")

            upload = root / ".deploy/uploads/run-upload"
            source = self.source(upload, "new")
            manifest = self.module.build_manifest(
                source, ["bin", "config/connections.yaml"]
            )
            (upload / "source-manifest.json").write_text(json.dumps(manifest))

            sealed = self.module.seal(root, upload, "release-12345678")
            active = self.module.promote(
                root,
                "release-12345678",
                "run-12345678",
                "run-12345678-a1",
            )
            proof = self.module.verify_current(
                root, "release-12345678", "run-12345678-a1"
            )
            self.assertEqual(sealed["sourceSha256"], manifest["sourceSha256"])
            self.assertEqual(active["status"], "active")
            self.assertTrue(proof["ok"])
            self.assertEqual((root / "bin/runner.py").read_text(), "new")

            rolled_back = self.module.rollback(root, "run-12345678-a1")
            self.assertEqual(rolled_back["status"], "rolledBack")
            self.assertEqual((root / "bin/runner.py").read_text(), "old")
            self.assertEqual(
                (root / "config/connections.yaml").read_text(), "value: old"
            )

    def test_verify_current_rejects_content_and_inventory_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "platform"
            root.mkdir()
            upload = root / ".deploy/uploads/run-upload"
            source = self.source(upload, "new")
            manifest = self.module.build_manifest(
                source, ["bin", "config/connections.yaml"]
            )
            (upload / "source-manifest.json").write_text(json.dumps(manifest))
            self.module.seal(root, upload, "release-12345678")
            self.module.promote(
                root,
                "release-12345678",
                "run-12345678",
                "run-12345678-a1",
            )
            (root / "bin/runner.py").write_text("drift")
            with self.assertRaises(self.module.TransactionError):
                self.module.verify_current(root, "release-12345678", "run-12345678-a1")

    def test_verify_current_ignores_only_python_bytecode_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "platform"
            root.mkdir()
            upload = root / ".deploy/uploads/run-upload"
            source = self.source(upload, "new")
            manifest = self.module.build_manifest(
                source, ["bin", "config/connections.yaml"]
            )
            (upload / "source-manifest.json").write_text(json.dumps(manifest))
            self.module.seal(root, upload, "release-12345678")
            self.module.promote(
                root,
                "release-12345678",
                "run-12345678",
                "run-12345678-a1",
            )
            pycache = root / "bin/__pycache__"
            pycache.mkdir()
            (pycache / "data_content_plane.cpython-312.pyc").write_bytes(b"drift")
            (root / "bin/generated.pyc").write_bytes(b"drift")

            proof = self.module.verify_current(
                root, "release-12345678", "run-12345678-a1"
            )
            self.assertTrue(proof["ok"])

            (root / "bin/unexpected.txt").write_text("drift")
            with self.assertRaisesRegex(
                self.module.TransactionError, "governed source inventory drift"
            ):
                self.module.verify_current(root, "release-12345678", "run-12345678-a1")

    def test_failed_promotion_restores_previous_source_before_returning(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "platform"
            root.mkdir()
            (root / "bin").mkdir()
            (root / "config").mkdir()
            (root / "bin/runner.py").write_text("old")
            (root / "config/connections.yaml").write_text("value: old")
            upload = root / ".deploy/uploads/run-upload"
            source = self.source(upload, "new")
            manifest = self.module.build_manifest(
                source, ["bin", "config/connections.yaml"]
            )
            (upload / "source-manifest.json").write_text(json.dumps(manifest))
            self.module.seal(root, upload, "release-12345678")
            original_verify = self.module.verify_tree

            def fail_after_moves(path, value):
                if path == root:
                    raise self.module.TransactionError("synthetic promotion failure")
                return original_verify(path, value)

            with (
                mock.patch.object(
                    self.module, "verify_tree", side_effect=fail_after_moves
                ),
                self.assertRaises(self.module.TransactionError),
            ):
                self.module.promote(
                    root,
                    "release-12345678",
                    "run-12345678",
                    "run-12345678-a1",
                )
            self.assertEqual((root / "bin/runner.py").read_text(), "old")
            self.assertEqual(
                (root / "config/connections.yaml").read_text(), "value: old"
            )

    def test_incomplete_promotion_journal_is_recovered_after_process_loss(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "platform"
            root.mkdir()
            (root / "bin").mkdir()
            (root / "config").mkdir()
            (root / "bin/runner.py").write_text("old")
            (root / "config/connections.yaml").write_text("value: old")
            upload = root / ".deploy/uploads/run-upload"
            source = self.source(upload, "new")
            manifest = self.module.build_manifest(
                source, ["bin", "config/connections.yaml"]
            )
            (upload / "source-manifest.json").write_text(json.dumps(manifest))
            self.module.seal(root, upload, "release-12345678")

            deploy = root / ".deploy"
            activation = deploy / "activations/run-12345678-a1/source"
            shutil.copytree(deploy / "releases/release-12345678/source", activation)
            backup = deploy / "backups/run-12345678-a1"
            backup.mkdir(parents=True)
            os.replace(root / "bin", backup / "bin")
            os.replace(activation / "bin", root / "bin")
            journal = deploy / "transactions/run-12345678-a1.json"
            self.module.atomic_json(
                journal,
                {
                    "status": "promoting",
                    "releaseId": "release-12345678",
                    "activationId": "run-12345678-a1",
                },
            )

            recovered = self.module.recover_incomplete(root)
            self.assertEqual(recovered, ["run-12345678-a1"])
            self.assertEqual((root / "bin/runner.py").read_text(), "old")
            recovered_journal = json.loads(journal.read_text())
            self.assertEqual(recovered_journal["status"], "rolledBack")
            self.assertIn("recoveredAt", recovered_journal)

    def test_seal_is_idempotent_only_for_the_same_source_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "platform"
            root.mkdir()
            first = root / ".deploy/uploads/first-upload"
            source = self.source(first, "same")
            manifest = self.module.build_manifest(
                source, ["bin", "config/connections.yaml"]
            )
            (first / "source-manifest.json").write_text(json.dumps(manifest))
            self.module.seal(root, first, "release-12345678")

            second = root / ".deploy/uploads/second-upload"
            source = self.source(second, "same")
            (second / "source-manifest.json").write_text(
                json.dumps(
                    self.module.build_manifest(
                        source, ["bin", "config/connections.yaml"]
                    )
                )
            )
            result = self.module.seal(root, second, "release-12345678")
            self.assertEqual(result["action"], "existing")

            third = root / ".deploy/uploads/third-upload"
            source = self.source(third, "different")
            (third / "source-manifest.json").write_text(
                json.dumps(
                    self.module.build_manifest(
                        source, ["bin", "config/connections.yaml"]
                    )
                )
            )
            with self.assertRaises(self.module.TransactionError):
                self.module.seal(root, third, "release-12345678")

    def test_every_promotion_move_crash_is_recovered_to_previous_tree(self):
        for failpoint in range(1, 5):
            with (
                self.subTest(failpoint=failpoint),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary) / "platform"
                root.mkdir()
                (root / "bin").mkdir()
                (root / "config").mkdir()
                (root / "bin/runner.py").write_text("old")
                (root / "config/connections.yaml").write_text("value: old")
                self.seal_release(root, "release-12345678", "new")

                original_replace = self.module.durable_replace
                calls = 0

                def crash_after_move(source, destination):
                    nonlocal calls
                    original_replace(source, destination)
                    calls += 1
                    if calls == failpoint:
                        raise SystemExit("synthetic process loss")

                with (
                    mock.patch.object(
                        self.module, "durable_replace", side_effect=crash_after_move
                    ),
                    self.assertRaises(SystemExit),
                ):
                    self.module.promote(
                        root,
                        "release-12345678",
                        "run-12345678",
                        "run-12345678-a1",
                    )

                recovered = self.module.recover_incomplete(root)
                self.assertEqual(recovered, ["run-12345678-a1"])
                self.assertEqual((root / "bin/runner.py").read_text(), "old")
                self.assertEqual(
                    (root / "config/connections.yaml").read_text(), "value: old"
                )
                journal = json.loads(
                    (root / ".deploy/transactions/run-12345678-a1.json").read_text()
                )
                self.assertEqual(journal["status"], "rolledBack")

    def test_every_rollback_move_crash_is_idempotently_recovered(self):
        for failpoint in range(1, 5):
            with (
                self.subTest(failpoint=failpoint),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary) / "platform"
                root.mkdir()
                (root / "bin").mkdir()
                (root / "config").mkdir()
                (root / "bin/runner.py").write_text("old")
                (root / "config/connections.yaml").write_text("value: old")
                self.seal_release(root, "release-12345678", "new")
                self.module.promote(
                    root,
                    "release-12345678",
                    "run-12345678",
                    "run-12345678-a1",
                )

                original_replace = self.module.durable_replace
                calls = 0

                def crash_after_move(source, destination):
                    nonlocal calls
                    original_replace(source, destination)
                    calls += 1
                    if calls == failpoint:
                        raise SystemExit("synthetic process loss")

                with (
                    mock.patch.object(
                        self.module, "durable_replace", side_effect=crash_after_move
                    ),
                    self.assertRaises(SystemExit),
                ):
                    self.module.rollback(root, "run-12345678-a1")

                recovered = self.module.recover_incomplete(root)
                self.assertEqual(recovered, ["run-12345678-a1"])
                self.assertEqual((root / "bin/runner.py").read_text(), "old")
                self.assertEqual(
                    (root / "config/connections.yaml").read_text(), "value: old"
                )
                repeated = self.module.rollback(root, "run-12345678-a1")
                self.assertEqual(repeated["status"], "rolledBack")

    def test_recovery_completes_commit_when_current_state_was_not_written(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "platform"
            root.mkdir()
            self.seal_release(root, "release-12345678", "new")
            original_atomic_json = self.module.atomic_json
            crashed = False

            def crash_before_current(path, payload):
                nonlocal crashed
                if (
                    not crashed
                    and path.name == self.module.STATE_NAME
                    and payload.get("status") == "active"
                ):
                    crashed = True
                    raise SystemExit("synthetic process loss")
                original_atomic_json(path, payload)

            with (
                mock.patch.object(
                    self.module, "atomic_json", side_effect=crash_before_current
                ),
                self.assertRaises(SystemExit),
            ):
                self.module.promote(
                    root,
                    "release-12345678",
                    "run-12345678",
                    "run-12345678-a1",
                )

            journal_path = root / ".deploy/transactions/run-12345678-a1.json"
            self.assertEqual(
                json.loads(journal_path.read_text())["status"], "committing"
            )
            self.assertFalse((root / ".deploy/current-release.json").exists())
            self.assertEqual(self.module.recover_incomplete(root), ["run-12345678-a1"])
            self.assertEqual(json.loads(journal_path.read_text())["status"], "active")
            self.assertTrue(
                self.module.verify_current(root, "release-12345678", "run-12345678-a1")[
                    "ok"
                ]
            )

    def test_recovery_closes_state_written_before_active_journal_window(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "platform"
            root.mkdir()
            self.seal_release(root, "release-12345678", "new")
            original_atomic_json = self.module.atomic_json
            journal_path = root / ".deploy/transactions/run-12345678-a1.json"
            crashed = False

            def crash_before_active_journal(path, payload):
                nonlocal crashed
                if (
                    not crashed
                    and path == journal_path
                    and payload.get("status") == "active"
                ):
                    crashed = True
                    raise SystemExit("synthetic process loss")
                original_atomic_json(path, payload)

            with (
                mock.patch.object(
                    self.module,
                    "atomic_json",
                    side_effect=crash_before_active_journal,
                ),
                self.assertRaises(SystemExit),
            ):
                self.module.promote(
                    root,
                    "release-12345678",
                    "run-12345678",
                    "run-12345678-a1",
                )

            state = json.loads((root / ".deploy/current-release.json").read_text())
            self.assertEqual(state["status"], "active")
            self.assertEqual(
                json.loads(journal_path.read_text())["status"], "committing"
            )
            self.assertEqual(self.module.recover_incomplete(root), ["run-12345678-a1"])
            self.assertEqual(json.loads(journal_path.read_text())["status"], "active")

    def test_recovery_repairs_legacy_active_journal_without_current_pointer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "platform"
            root.mkdir()
            self.seal_release(root, "release-12345678", "new")
            self.module.promote(
                root,
                "release-12345678",
                "run-12345678",
                "run-12345678-a1",
            )
            (root / ".deploy/current-release.json").unlink()

            self.assertEqual(self.module.recover_incomplete(root), ["run-12345678-a1"])
            self.assertTrue(
                self.module.verify_current(root, "release-12345678", "run-12345678-a1")[
                    "ok"
                ]
            )

    def test_rollback_restores_previous_activation_pointer_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "platform"
            root.mkdir()
            self.seal_release(root, "release-11111111", "first")
            first = self.module.promote(
                root, "release-11111111", "run-11111111", "run-11111111-a1"
            )
            self.seal_release(root, "release-22222222", "second")
            self.module.promote(
                root, "release-22222222", "run-22222222", "run-22222222-a1"
            )

            result = self.module.rollback(root, "run-22222222-a1")
            self.assertEqual(result["status"], "rolledBack")
            current = json.loads((root / ".deploy/current-release.json").read_text())
            self.assertEqual(current["activationId"], first["activationId"])
            self.assertEqual((root / "bin/runner.py").read_text(), "first")
            self.assertTrue(
                self.module.verify_current(root, "release-11111111", "run-11111111-a1")[
                    "ok"
                ]
            )
            self.assertEqual(
                self.module.rollback(root, "run-22222222-a1")["status"],
                "rolledBack",
            )

    def test_inspect_and_rollback_if_current_are_safe_for_retries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "platform"
            root.mkdir()
            self.seal_release(root, "release-12345678", "new")
            self.module.promote(
                root,
                "release-12345678",
                "run-12345678",
                "run-12345678-a1",
            )

            inspected = self.module.inspect_activation(root, "run-12345678-a1")
            self.assertTrue(inspected["current"])
            first = self.module.rollback_if_current(root, "run-12345678-a1")
            second = self.module.rollback_if_current(root, "run-12345678-a1")
            self.assertEqual(first["action"], "rolledBack")
            self.assertEqual(second["action"], "alreadyRolledBack")
            unrelated = self.module.rollback_if_current(root, "run-99999999-a1")
            self.assertEqual(unrelated["action"], "notCurrent")


if __name__ == "__main__":
    unittest.main()

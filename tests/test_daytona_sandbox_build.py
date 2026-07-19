from __future__ import annotations

import ast
import fcntl
import importlib.util
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SANDBOX = ROOT / "deployment/image-build/daytona-harness"
DOCKERFILE = SANDBOX / "Dockerfile"
NPM_LOCK_ROOT = SANDBOX
BASE_IMAGE = (
    "daytonaio/sandbox:v0.190.0-slim-amd64@sha256:"
    "91e37b087e04314e481009f9f95c98b6d882a930691deb03de6a68f774cdb16e"
)
REMOVED_FILES = {
    "build.py",
    "recipe.lock.json",
    "source-context.sha256",
    "build-context.sha256",
}
REMOVED_CONTRACT_TOKENS = {
    "MTE_DAYTONA_CODING_IMAGE",
    "MTE_DAYTONA_SANDBOX_EXPECTED_DIGEST",
    "MTE_DAYTONA_SANDBOX_SOURCE_ARCHIVE_URL",
    "MTE_DAYTONA_SANDBOX_SOURCE_GIT_TREE",
    "MTE_DAYTONA_SANDBOX_RECIPE_LOCK_SHA256",
    "SOURCE_BUILD_PROMOTIONS",
    "promote-source-build",
}


def load_server_config():
    path = ROOT / "tools/platform-cli/server-config.py"
    spec = importlib.util.spec_from_file_location("daytona_lock_server_config", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def literal_dict(path: Path, name: str) -> dict[str, object]:
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if isinstance(value, dict):
                return value
    raise AssertionError(f"missing literal dict {name} in {path}")


class DaytonaSandboxBuildTests(unittest.TestCase):
    def test_renderer_rejects_boolean_and_unheld_lock_spoofs(self) -> None:
        module = load_server_config()
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / ".platform-env.lock"
            lock.touch(mode=0o600)
            descriptor = os.open(lock, os.O_RDWR)
            wrong = Path(directory) / "wrong.lock"
            wrong.touch(mode=0o600)
            wrong_descriptor = os.open(wrong, os.O_RDWR)
            original_lock = module.LOCK
            module.LOCK = lock
            try:
                with self.assertRaisesRegex(TypeError, "lock_held"):
                    module.render(lock_held=True)
                with self.assertRaisesRegex(module.ConfigError, "file descriptor"):
                    module.render(lock_fd=True)
                with self.assertRaisesRegex(module.ConfigError, "not already held"):
                    module.verify_canonical_lock_fd(descriptor)
                contender = os.open(lock, os.O_RDWR)
                try:
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(contender, fcntl.LOCK_UN)
                finally:
                    os.close(contender)
                if sys.platform.startswith("linux") and hasattr(
                    fcntl, "F_OFD_SETLK"
                ):
                    request = struct.pack(
                        "hhqqi4x", fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0
                    )
                    fcntl.fcntl(descriptor, fcntl.F_OFD_SETLK, request)
                    self.assertEqual(
                        module.verify_canonical_lock_fd(descriptor), descriptor
                    )
                    unlock = struct.pack(
                        "hhqqi4x", fcntl.F_UNLCK, os.SEEK_SET, 0, 0, 0
                    )
                    fcntl.fcntl(descriptor, fcntl.F_OFD_SETLK, unlock)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                self.assertEqual(module.verify_canonical_lock_fd(descriptor), descriptor)
                with self.assertRaisesRegex(module.ConfigError, "unsafe"):
                    module.verify_canonical_lock_fd(wrong_descriptor)
            finally:
                module.LOCK = original_lock
                os.close(wrong_descriptor)
                os.close(descriptor)

    def test_renderer_lock_creation_rejects_symlink_and_hardlink_inodes(self) -> None:
        module = load_server_config()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "secrets"
            root.mkdir(mode=0o700)
            lock = root / ".platform-env.lock"
            target = root / "target.lock"
            original_root, original_lock = module.SECRET_ROOT, module.LOCK
            module.SECRET_ROOT, module.LOCK = root, lock
            try:
                with module.config_lock() as descriptor:
                    self.assertEqual(os.fstat(descriptor).st_nlink, 1)
                    self.assertEqual(lock.stat().st_mode & 0o777, 0o600)
                lock.unlink()
                target.touch(mode=0o600)
                lock.symlink_to(target)
                with self.assertRaisesRegex(module.ConfigError, "safely open"):
                    with module.config_lock():
                        pass
                lock.unlink()
                os.link(target, lock)
                with self.assertRaisesRegex(module.ConfigError, "unsafe"):
                    with module.config_lock():
                        pass
                lock.unlink()
                os.mkfifo(lock, mode=0o600)
                with self.assertRaisesRegex(module.ConfigError, "unsafe"):
                    with module.config_lock():
                        pass
            finally:
                module.SECRET_ROOT, module.LOCK = original_root, original_lock

    def test_sandbox_is_one_ordinary_dockerfile_context(self) -> None:
        self.assertTrue(DOCKERFILE.is_file())
        for name in REMOVED_FILES:
            self.assertFalse((SANDBOX / name).exists(), name)
        source = DOCKERFILE.read_text()
        self.assertEqual(
            [
                line.removeprefix("FROM ")
                for line in source.splitlines()
                if line.startswith("FROM ")
            ],
            [BASE_IMAGE],
        )
        self.assertNotIn("docker build", source)
        self.assertNotIn("git clone", source)

    def test_harness_packages_are_npm_lock_backed(self) -> None:
        manifest = json.loads((NPM_LOCK_ROOT / "package.json").read_text())
        lock = json.loads((NPM_LOCK_ROOT / "package-lock.json").read_text())
        self.assertEqual(lock["lockfileVersion"], 3)
        self.assertEqual(lock["packages"][""]["dependencies"], manifest["dependencies"])
        for path, row in lock["packages"].items():
            if not path or not isinstance(row, dict) or not row.get("resolved"):
                continue
            self.assertRegex(str(row.get("integrity") or ""), r"^sha512-")

    def test_deploy_image_is_operator_supplied_and_never_invented(self) -> None:
        defaults = literal_dict(
            ROOT / "tools/platform-cli/server-config.py", "ONE_TIME_MIGRATION_SEEDS"
        )
        dependencies = json.loads((ROOT / "config/dependencies.lock.json").read_text())
        self.assertNotIn("MTE_DAYTONA_SANDBOX_IMAGE", defaults)
        server_config = load_server_config()
        self.assertTrue(
            {
                "DAYTONA_CUSTOM_IMAGE_LIFECYCLE",
                "MTE_DAYTONA_NPM_LOCK_SHA256",
                "MTE_DAYTONA_NPM_PACKAGE_SHA256",
                "MTE_DAYTONA_SANDBOX_BASE_IMAGE",
            }
            <= server_config.RETIRED_CANONICAL_KEYS
        )
        image = dependencies["runtimeImages"]["MTE_DAYTONA_SANDBOX_IMAGE"]
        self.assertTrue(image["requiredDigestAtPreflight"])
        self.assertNotIn("ref", image)
        self.assertEqual(
            image["operatorEvidence"],
            {
                "sourceUrlKey": "MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL",
                "revisionKey": "MTE_DAYTONA_SANDBOX_IMAGE_REVISION",
                "upstreamComponent": "daytona-sandbox-image",
            },
        )
        self.assertNotIn("imageBuilds", dependencies)
        self.assertNotIn("dockerfilePatches", dependencies)
        self.assertEqual(
            dependencies["metadata"]["daytonaControlPlane"],
            {
                "version": "0.187.0",
                "sourceCommit": "8a446cb96331737e5a2118cbcaa0604d95c07f71",
                "composeSha256": "93801bd32eaf98b7af010b4d9eea9579caf56ef60caf489d48141bf10d3c63c2",
            },
        )
        self.assertEqual(
            dependencies["metadata"]["daytonaSandbox"], {"version": "0.190.0"}
        )

    def test_source_build_and_manual_promotion_contract_is_absent(self) -> None:
        paths = (
            ROOT / "config/dependencies.lock.json",
            ROOT / "config/licenses.lock.json",
            ROOT / "config/platform.yaml",
            ROOT / "tools/platform-cli/server-config.py",
            ROOT / "tools/platform-cli/validate-dependencies.py",
        )
        combined = "\n".join(path.read_text() for path in paths)
        for token in REMOVED_CONTRACT_TOKENS:
            self.assertNotIn(token, combined, token)

    def test_snapshot_apply_uses_only_the_digest_image_contract(self) -> None:
        step = (ROOT / "deployment/steps/daytona.sh").read_text()
        self.assertNotIn("Image.fromDockerfile", step)
        self.assertNotIn("sandbox-context", step)
        self.assertIn('safe("MTE_DAYTONA_SANDBOX_IMAGE"', step)
        self.assertIn("ensureSnapshot(codingName,sandboxImage", step)
        self.assertIn("/home/daytona/paperclip-workspace", step)
        self.assertNotIn("rollback-images", step)
        self.assertNotIn("build.py", step)
        self.assertNotIn("recipe.lock.json", step)

    def test_paperclip_abi_preflight_precedes_every_sdk_image_mutation(self) -> None:
        step = (ROOT / "deployment/steps/daytona.sh").read_text()
        preflight = step.split("\npreflight() {", 1)[1].split("\n}", 1)[0]
        images = step.split("build_images() {", 1)[1].split("\n}", 1)[0]
        lifecycle = step.split("lifecycle() {", 1)[1].split("\n}", 1)[0]
        for block in (preflight, images, lifecycle):
            self.assertIn('"$PAPERCLIP_STEP" preflight', block)
        self.assertLess(
            preflight.index('"$PAPERCLIP_STEP" preflight'),
            preflight.index("init_config"),
        )
        self.assertLess(
            lifecycle.index('"$PAPERCLIP_STEP" preflight'),
            lifecycle.index("init_config"),
        )
        self.assertLess(
            images.index('"$PAPERCLIP_STEP" preflight'),
            images.index("canonical_lock_run"),
        )

    def test_component_owned_compose_networks_are_explicit(self) -> None:
        platform = yaml.safe_load((ROOT / "config/platform.yaml").read_text())
        component = next(
            row for row in platform["spec"]["components"] if row["id"] == "daytona"
        )
        self.assertEqual(component["management"], "explicit-step")
        self.assertEqual(
            component["externalNetworkRefs"],
            ["MTE_DAYTONA_NETWORK", "MTE_DAYTONA_PAPERCLIP_NETWORK"],
        )
        self.assertIn("toolhive", component["dependsOn"])
        step = (ROOT / "deployment/steps/daytona.sh").read_text()
        for key in component["externalNetworkRefs"]:
            self.assertIn(key, step)
        self.assertIn("ensure_private_network", step)

    def test_compose_preserves_live_project_and_volume_identity(self) -> None:
        compose = yaml.safe_load(
            (ROOT / "deployment/services/daytona/compose.yaml").read_text()
        )
        self.assertEqual(compose["name"], "mte-daytona")
        volumes = compose["volumes"]
        self.assertEqual(
            set(volumes),
            {
                "daytona-db",
                "daytona-valkey",
                "daytona-registry",
                "daytona-minio",
                "daytona-dex",
                "daytona-runner",
            },
        )
        self.assertEqual(volumes["daytona-valkey"], {"name": "mte-daytona-valkey"})
        for name in (
            "daytona-db",
            "daytona-registry",
            "daytona-minio",
            "daytona-dex",
            "daytona-runner",
        ):
            self.assertEqual(volumes[name], {})
        registry = compose["services"]["registry"]
        self.assertEqual(
            registry["environment"]["REGISTRY_HTTP_ADDR"],
            "registry:${MTE_DAYTONA_REGISTRY_INTERNAL_PORT:?required}",
        )

    def test_step_creates_only_daytona_owned_private_networks(self) -> None:
        source = (ROOT / "deployment/steps/daytona.sh").read_text()
        install_body = source.split("install_daytona() {", 1)[1].split(
            "\n}\n\nprovision_key()", 1
        )[0]
        self.assertEqual(install_body.count("ensure_private_network"), 2)
        self.assertIn('ensure_private_network "$daytona_network"', install_body)
        self.assertIn('ensure_private_network "$paperclip_network"', install_body)
        self.assertIn('assert_bridge_network "$agent_plane"', install_body)
        self.assertIn('assert_bridge_network "$tool_runtime"', install_body)
        self.assertNotIn('ensure_private_network "$agent_plane"', install_body)
        self.assertNotIn('ensure_private_network "$tool_runtime"', install_body)

    def test_install_invalidates_only_derived_region_toolbox_proxy_cache(self) -> None:
        source = (ROOT / "deployment/steps/daytona.sh").read_text()
        self.assertIn(
            'valkey-cli DEL "toolbox-proxy-url:region:$(env_value '
            '"$RUNTIME_ENV" DAYTONA_TARGET)"',
            source,
        )
        self.assertNotIn('req("PATCH",f"/regions/', source)

    def test_orchestrator_actions_and_readiness_evidence_are_coherent(self) -> None:
        source = (ROOT / "deployment/steps/daytona.sh").read_text()
        self.assertIn("set_target() {", source)
        self.assertIn("set-target) set_target;;", source)
        image_block = source.split("build_images_while_locked() {", 1)[1].split(
            "\n}\n\nbuild_images() {", 1
        )[0]
        env_replace = image_block.index("temporary.replace(path)")
        evidence_rebind = image_block.index(
            'evidence["canonicalSourceSha256"] = canonical_sha'
        )
        self.assertLess(env_replace, evidence_rebind)
        self.assertIn(
            'values["MTE_DAYTONA_CODING_SNAPSHOT_READY"] = "true"', image_block
        )
        self.assertIn(
            'values["MTE_DAYTONA_GENERAL_SNAPSHOT_READY"] = "true"', image_block
        )
        self.assertIn(
            'values["MTE_DAYTONA_CODING_SNAPSHOT"] = snapshots["coding"]["name"]',
            image_block,
        )
        self.assertIn(
            'values["MTE_DAYTONA_GENERAL_SNAPSHOT"] = snapshots["general"]["name"]',
            image_block,
        )
        self.assertIn(
            "ensureSnapshot(codingName,sandboxImage,codingResources)", image_block
        )
        self.assertIn(
            "ensureSnapshot(generalName,sandboxImage,generalResources)", image_block
        )
        self.assertIn("ref:snapshotImageRef(snapshot)", image_block)
        self.assertIn("snapshotImageRef(snapshot)===image", image_block)
        self.assertIn("Number(snapshot.cpu)===expectedResources.cpu", image_block)
        self.assertIn(
            "Number(snapshot.mem ?? snapshot.memory)===expectedResources.memory",
            image_block,
        )
        self.assertIn("Number(snapshot.disk)===expectedResources.disk", image_block)
        self.assertIn(
            "snapshot && !snapshotMatchesContract(snapshot,image,resources)",
            image_block,
        )
        self.assertIn("await deleteSnapshot(snapshot);", image_block)
        self.assertIn("harnessVersions", image_block)
        self.assertIn("snapshotContractHash", image_block)
        self.assertIn("snapshotContractHash.slice(0,12)", image_block)
        self.assertIn("deferredCleanup", image_block)
        self.assertNotIn("previousHash!==snapshotContractHash", image_block)
        self.assertNotIn(
            "timed out deleting snapshots with a stale build contract", image_block
        )
        self.assertIn('new Set(["build_failed","error"])', image_block)
        self.assertIn("terminalStates.has(snapshot.state)", image_block)
        lifecycle_block = source.split("lifecycle() {", 1)[1].split("\nstatus() {", 1)[
            0
        ]
        self.assertIn("normalizedVersion", lifecycle_block)
        self.assertNotIn("versionOutput.includes", lifecycle_block)
        self.assertIn(
            "const internalToolboxProxyUrl=`http://proxy:${proxyPort}/toolbox`",
            lifecycle_block,
        )
        self.assertIn("useInternalToolboxProxy(sandbox);", lifecycle_block)
        self.assertIn('cp.execFileSync("/bin/sh",["-c",command]', lifecycle_block)
        self.assertNotIn('cp.execFileSync("/bin/sh",["-lc",command]', lifecycle_block)
        self.assertIn("memory:Number(sandbox.memory)", lifecycle_block)
        self.assertIn("MTE_CANONICAL_SOURCE_SHA256", lifecycle_block)
        self.assertIn("canonicalSourceSha256,", lifecycle_block)

    def test_snapshot_apply_lock_covers_create_wait_and_pointer_switch(self) -> None:
        source = (ROOT / "deployment/steps/daytona.sh").read_text()
        transaction = source.split("build_images_while_locked() {", 1)[1].split(
            "\n}\n\nbuild_images() {", 1
        )[0]
        image_block = source.split("build_images() {", 1)[1].split(
            "\nlifecycle() {", 1
        )[0]
        lock = image_block.index("canonical_lock_run build_images_transaction_while_locked")
        call = image_block.index("build_images_while_locked")
        config = transaction.index("init_config already-locked")
        override_read = transaction.index(
            'coding_prefix=$(env_value "$RUNTIME_ENV" MTE_DAYTONA_CODING_SNAPSHOT_PREFIX)'
        )
        create = transaction.index("snapshot=await daytona.snapshot.create")
        wait_active = transaction.index('if (snapshot.state==="active") break;')
        pointer_switch = transaction.index("temporary.replace(path)")
        projection = image_block.index("render_daytona_projection already-locked")
        snapshot = image_block.index("snapshot_runtime_config already-locked")
        self.assertLess(lock, call)
        self.assertLess(call, projection)
        self.assertLess(projection, snapshot)
        self.assertLess(config, override_read)
        self.assertLess(override_read, create)
        self.assertLess(create, wait_active)
        self.assertLess(wait_active, pointer_switch)
        self.assertIn('"timeout waiting for Daytona snapshot apply lock"', image_block)
        self.assertNotIn('9>"$ENV_LOCK"', source)
        self.assertNotIn('touch "$ENV_LOCK"', source)
        self.assertNotIn('chmod 0600 "$ENV_LOCK"', source)

    def test_snapshot_reuse_mismatch_is_deleted_and_recreated(self) -> None:
        source = (ROOT / "deployment/steps/daytona.sh").read_text()
        ensure = source.split("async function ensureSnapshot", 1)[1].split(
            "const codingSnapshot", 1
        )[0]
        mismatch = ensure.index(
            "snapshot && !snapshotMatchesContract(snapshot,image,resources)"
        )
        delete = ensure.index("await deleteSnapshot(snapshot);", mismatch)
        recreate = ensure.index("snapshot=await daytona.snapshot.create", delete)
        self.assertLess(mismatch, delete)
        self.assertLess(delete, recreate)
        self.assertIn("snapshotImageRef(snapshot)===image", source)
        self.assertIn("return unique.length===1 ? unique[0] : undefined", source)
        self.assertIn("harnessVersions", source.split("snapshotContractHash", 1)[0])
        self.assertIn("if (!ownedNames.has(snapshot.name))", source)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux OFD lock probe")
    def test_lock_open_rejects_unsafe_paths_without_mutating_targets(self) -> None:
        source = (ROOT / "deployment/steps/daytona.sh").read_text()
        definitions = source.split("\ncase $ACTION in\n", 1)[0]
        harness = definitions + textwrap.dedent(
            r"""
            ENV_LOCK=$1
            lock_probe() { assert_canonical_lock_held; }
            canonical_lock_run lock_probe 2
            """
        )

        def run(lock: Path) -> subprocess.CompletedProcess[str]:
            script = lock.parent / "lock-safety-harness.sh"
            script.write_text(harness)
            return subprocess.run(
                ["bash", str(script), str(lock)],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.lock"
            target.write_text("must remain unchanged\n")
            target.chmod(0o640)
            lock = root / "canonical.lock"
            lock.symlink_to(target)
            result = run(lock)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(target.read_text(), "must remain unchanged\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)

        for unsafe_kind in ("mode", "nlink", "uid", "gid"):
            with self.subTest(unsafe_kind=unsafe_kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                lock = root / "canonical.lock"
                lock.touch(mode=0o600)
                if unsafe_kind == "mode":
                    lock.chmod(0o640)
                elif unsafe_kind == "nlink":
                    os.link(lock, root / "second-link.lock")
                elif unsafe_kind == "uid" and os.geteuid() == 0:
                    os.chown(lock, 1, os.getegid())
                elif unsafe_kind == "gid" and os.geteuid() == 0:
                    os.chown(lock, os.geteuid(), 1)
                else:
                    continue
                before = lock.lstat()
                result = run(lock)
                after = lock.lstat()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(stat.S_IMODE(after.st_mode), stat.S_IMODE(before.st_mode))
                self.assertEqual((after.st_uid, after.st_gid), (before.st_uid, before.st_gid))
                self.assertEqual(after.st_nlink, before.st_nlink)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux OFD lock probe")
    def test_lock_open_rejects_pathname_replacement_while_waiting(self) -> None:
        source = (ROOT / "deployment/steps/daytona.sh").read_text()
        definitions = source.split("\ncase $ACTION in\n", 1)[0]
        harness = definitions + textwrap.dedent(
            r"""
            ENV_LOCK=$1
            lock_probe() { assert_canonical_lock_held; }
            canonical_lock_run lock_probe 3
            """
        )
        blocker_source = textwrap.dedent(
            """
            import fcntl, os, sys
            fd = os.open(sys.argv[1], os.O_RDWR | os.O_NOFOLLOW)
            fcntl.flock(fd, fcntl.LOCK_EX)
            print("ready", flush=True)
            sys.stdin.read(1)
            os.close(fd)
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "canonical.lock"
            lock.touch(mode=0o600)
            script = root / "replacement-race-harness.sh"
            script.write_text(harness)
            blocker = subprocess.Popen(
                [sys.executable, "-c", blocker_source, str(lock)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            contender = None
            try:
                self.assertEqual(blocker.stdout.readline().strip(), "ready")
                contender = subprocess.Popen(
                    ["bash", str(script), str(lock)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                original_identity = (lock.stat().st_dev, lock.stat().st_ino)
                deadline = time.monotonic() + 3
                while True:
                    children_path = Path(
                        f"/proc/{contender.pid}/task/{contender.pid}/children"
                    )
                    child_pids = (
                        children_path.read_text().split()
                        if children_path.exists()
                        else []
                    )
                    opened = False
                    for pid in [str(contender.pid), *child_pids]:
                        for fd_path in Path(f"/proc/{pid}/fd").glob("*"):
                            try:
                                observed = fd_path.stat()
                            except OSError:
                                continue
                            if (observed.st_dev, observed.st_ino) == original_identity:
                                opened = True
                                break
                        if opened:
                            break
                    if opened:
                        break
                    if time.monotonic() >= deadline:
                        self.fail("safe lock helper did not open the blocked inode")
                    time.sleep(0.02)
                lock.rename(root / "replaced.lock")
                lock.touch(mode=0o600)
                assert blocker.stdin is not None
                blocker.stdin.write("x")
                blocker.stdin.flush()
                blocker.stdin.close()
                blocker.stdin = None
                blocker.wait(timeout=5)
                stdout, stderr = contender.communicate(timeout=5)
            finally:
                if contender is not None and contender.poll() is None:
                    contender.kill()
                    contender.wait()
                if blocker.poll() is None:
                    blocker.kill()
                    blocker.wait()
            self.assertNotEqual(contender.returncode, 0, stdout)
            self.assertIn("identity is unsafe", stderr)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux OFD lock probe")
    def test_images_lock_is_reentrant_by_contract_and_serializes_processes(
        self,
    ) -> None:
        source = (ROOT / "deployment/steps/daytona.sh").read_text()
        definitions = source.split("\ncase $ACTION in\n", 1)[0]
        harness = definitions + textwrap.dedent(
            r"""
            TRACE=$2
            RUN_ID=$3
            ROOT=$1/runtime-$RUN_ID
            ENV_FILE=$1/platform.env
            DAYTONA_ENV_FILE=$1/daytona.env
            ENV_LOCK=$1/platform.env.lock
            EVIDENCE_ROOT=$1/evidence
            RUNTIME_ENV=$1/runtime-$RUN_ID.env
            RUNTIME_ENV_HASH=$1/runtime-$RUN_ID.env.sha256
            RELEASE_ROOT=$1/release
            SANDBOX_DOCKERFILE=$4
            NPM_LOCK_ROOT=$5
            PI_TOOLHIVE_EXTENSION_ASSET=$6
            PROFILE_SKILL_ROOT=$7
            PAPERCLIP_STEP=true
            export TRACE RUN_ID DAYTONA_ENV_FILE

            mkdir -p "$ROOT" "$EVIDENCE_ROOT" "$RELEASE_ROOT/bin"
            prepare_profile_skill_contract() { :; }
            init_config_while_locked() { assert_canonical_lock_held; }
            config_hash() {
              printf '%s:snapshot\n' "$RUN_ID" >>"$TRACE"
              sleep 0.1
              env_value "$DAYTONA_ENV_FILE" RUN_ID_VALUE
            }
            build_images_while_locked() {
              assert_canonical_lock_held
              printf '%s:start\n' "$RUN_ID" >>"$TRACE"
              sleep 0.25
              printf '%s:end\n' "$RUN_ID" >>"$TRACE"
            }
            build_images
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            script = temporary / "daytona-lock-harness.sh"
            trace = temporary / "trace"
            env_file = temporary / "platform.env"
            script.write_text(harness)
            env_file.write_text(
                "DAYTONA_API_KEY=test\n"
                "MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL=http://gateway.test\n"
                "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_URL=http://tools.test\n"
                "MTE_CONTEXT7_MCP_URL=http://context.test\n"
                "HERMES_LLM_MODEL=test-model\n"
            )
            (temporary / "daytona.env").write_text("RUN_ID_VALUE=initial\n")
            renderer = temporary / "release/bin/server-config.py"
            renderer.parent.mkdir(parents=True)
            renderer.write_text(
                textwrap.dedent(
                    """
                    import os
                    from pathlib import Path
                    import time

                    def render(*, lock_fd=None):
                        assert lock_fd == 9
                        trace = Path(os.environ["TRACE"])
                        run_id = os.environ["RUN_ID"]
                        with trace.open("a") as handle:
                            handle.write(f"{run_id}:projection-start\\n")
                        time.sleep(0.1)
                        Path(os.environ["DAYTONA_ENV_FILE"]).write_text(
                            f"RUN_ID_VALUE={run_id}\\n"
                        )
                        with trace.open("a") as handle:
                            handle.write(f"{run_id}:projection-end\\n")
                    """
                )
            )
            arguments = [
                str(script),
                str(temporary),
                str(trace),
                "unused",
                str(DOCKERFILE),
                str(NPM_LOCK_ROOT),
                str(ROOT / "deployment/agent-runtime/pi/mte-toolhive.js"),
                str(ROOT / "skills/verification-before-completion"),
            ]
            started = time.monotonic()
            first = subprocess.Popen(
                ["bash", *arguments[:3], "first", *arguments[4:]],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            second = subprocess.Popen(
                ["bash", *arguments[:3], "second", *arguments[4:]],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            processes = (first, second)
            try:
                results = [process.communicate(timeout=5) for process in processes]
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
            self.assertEqual(
                [
                    (process.returncode, stderr)
                    for process, (_, stderr) in zip(processes, results)
                ],
                [(0, ""), (0, "")],
            )
            self.assertLess(time.monotonic() - started, 5)
            rows = trace.read_text().splitlines()
            self.assertIn(
                rows,
                (
                    [
                        "first:start",
                        "first:end",
                        "first:projection-start",
                        "first:projection-end",
                        "first:snapshot",
                        "second:start",
                        "second:end",
                        "second:projection-start",
                        "second:projection-end",
                        "second:snapshot",
                    ],
                    [
                        "second:start",
                        "second:end",
                        "second:projection-start",
                        "second:projection-end",
                        "second:snapshot",
                        "first:start",
                        "first:end",
                        "first:projection-start",
                        "first:projection-end",
                        "first:snapshot",
                    ],
                ),
            )
            self.assertIn(
                "RUN_ID_VALUE=first", (temporary / "runtime-first.env").read_text()
            )
            self.assertIn(
                "RUN_ID_VALUE=second", (temporary / "runtime-second.env").read_text()
            )

    def test_already_locked_contract_rejects_spoof_fd9(self) -> None:
        source = (ROOT / "deployment/steps/daytona.sh").read_text()
        definitions = source.split("\ncase $ACTION in\n", 1)[0]
        harness = definitions + textwrap.dedent(
            r"""
            ENV_LOCK=$1/canonical.lock
            DAYTONA_ENV_LOCK_HELD=1
            exec 9>"$1/spoof.lock"
            flock -x 9
            assert_canonical_lock_held
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "spoof-lock-harness.sh"
            script.write_text(harness)
            result = subprocess.run(
                ["bash", str(script), directory],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("fd9 to reference the canonical", result.stderr)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux OFD lock probe")
    def test_already_locked_contract_rejects_unlocked_fd9_without_acquiring(self) -> None:
        source = (ROOT / "deployment/steps/daytona.sh").read_text()
        definitions = source.split("\ncase $ACTION in\n", 1)[0]
        harness = definitions + textwrap.dedent(
            r"""
            ENV_LOCK=$1/canonical.lock
            DAYTONA_ENV_LOCK_HELD=1
            exec 9>"$ENV_LOCK"
            set +e
            ( assert_canonical_lock_held )
            status=$?
            set -e
            [[ $status -eq 2 ]] || exit 90
            exec 10>"$ENV_LOCK"
            flock -n 10 || exit 91
            flock -u 10
            python3 - "$ENV_LOCK" <<'PY'
            import fcntl, os, struct, sys
            fd = os.open(sys.argv[1], os.O_RDWR | os.O_NOFOLLOW)
            try:
                request = struct.pack("hhqqi4x", fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0)
                observed = fcntl.fcntl(fd, fcntl.F_OFD_GETLK, request)
                if struct.unpack("hhqqi4x", observed)[0] != fcntl.F_UNLCK:
                    raise SystemExit("validation changed the canonical lock state")
            finally:
                os.close(fd)
            PY
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "unlocked-lock-harness.sh"
            script.write_text(harness)
            result = subprocess.run(
                ["bash", str(script), directory],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not locked before", result.stderr)

    def test_snapshot_prefix_overrides_must_remain_distinct(self) -> None:
        defaults = literal_dict(
            ROOT / "tools/platform-cli/server-config.py", "ONE_TIME_MIGRATION_SEEDS"
        )
        self.assertNotEqual(
            defaults["MTE_DAYTONA_CODING_SNAPSHOT_PREFIX"],
            defaults["MTE_DAYTONA_GENERAL_SNAPSHOT_PREFIX"],
        )
        source = (ROOT / "deployment/steps/daytona.sh").read_text()
        image_block = source.split("build_images_while_locked() {", 1)[1].split(
            "\n}\n\nbuild_images() {", 1
        )[0]
        self.assertIn('[[ "$coding_prefix" != "$general_prefix" ]]', image_block)
        self.assertIn("codingPrefix===generalPrefix", image_block)
        self.assertIn("codingName===generalName", image_block)

    def test_runner_bridge_and_gateway_are_one_fail_closed_contract(self) -> None:
        defaults = literal_dict(
            ROOT / "tools/platform-cli/server-config.py", "ONE_TIME_MIGRATION_SEEDS"
        )
        self.assertEqual(defaults["MTE_DAYTONA_SANDBOX_SUBNET"], "172.20.0.0/16")
        self.assertEqual(defaults["MTE_AGENT_GATEWAY_HOST"], "172.20.0.1")
        self.assertEqual(defaults["MTE_DAYTONA_CONTROL_PLANE_VERSION"], "0.187.0")
        self.assertEqual(defaults["MTE_DAYTONA_SANDBOX_VERSION"], "0.190.0")
        self.assertNotIn("MTE_DAYTONA_OSS_VERSION", defaults)
        source = (ROOT / "deployment/steps/daytona.sh").read_text()
        self.assertIn('"bip": f"{gateway}/{subnet.prefixlen}"', source)
        self.assertIn("gateway != subnet.network_address + 1", source)
        self.assertIn('agent_gateway.get("network_mode") != "service:runner"', source)
        self.assertIn('set(runner.get("networks") or {})', source)

    def test_daytona_compose_uses_least_privilege_ssh_env_and_valkey_health(
        self,
    ) -> None:
        compose = yaml.safe_load(
            (ROOT / "deployment/services/daytona/compose.yaml").read_text()
        )
        services = compose["services"]
        self.assertEqual(services["api"]["env_file"], ["./api-ssh.env"])
        self.assertEqual(services["runner"]["env_file"], ["./ssh.env"])
        self.assertEqual(services["ssh-gateway"]["env_file"], ["./ssh.env"])
        self.assertEqual(
            services["redis"]["healthcheck"],
            {
                "test": ["CMD", "valkey-cli", "ping"],
                "interval": "${MTE_HEALTHCHECK_STANDARD_INTERVAL:?required}",
                "timeout": "${MTE_HEALTHCHECK_STANDARD_TIMEOUT:?required}",
                "retries": "${MTE_HEALTHCHECK_STANDARD_RETRIES:?required}",
                "start_period": "${MTE_HEALTHCHECK_STANDARD_START_PERIOD:?required}",
            },
        )
        step = (ROOT / "deployment/steps/daytona.sh").read_text()
        api_projection = step.split("printf 'SSH_GATEWAY_PUBLIC_KEY=%s", 1)[1].split(
            '>"$ROOT/api-ssh.env"', 1
        )[0]
        self.assertNotIn("SSH_PRIVATE_KEY", api_projection)
        self.assertNotIn("SSH_HOST_KEY", api_projection)


if __name__ == "__main__":
    unittest.main()

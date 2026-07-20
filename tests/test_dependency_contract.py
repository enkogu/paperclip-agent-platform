from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_dependencies", ROOT / "tools/platform-cli/validate-dependencies.py"
)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class DependencyContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = json.loads((ROOT / "config/dependencies.lock.json").read_text())
        self.licenses = json.loads((ROOT / "config/licenses.lock.json").read_text())

    @staticmethod
    def paperclip_runtime_evidence() -> dict[str, str]:
        return {
            "MTE_PAPERCLIP_IMAGE": "ghcr.io/example/paperclip-mte@sha256:" + "a" * 64,
            "MTE_PAPERCLIP_FORK_SOURCE_URL": "https://github.com/example/paperclip-mte",
            "MTE_PAPERCLIP_FORK_REVISION": "b" * 40,
            "MTE_DAYTONA_SANDBOX_IMAGE": "ghcr.io/example/daytona@sha256:"
            + "c" * 64,
            "MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL": "https://github.com/example/platform",
            "MTE_DAYTONA_SANDBOX_IMAGE_REVISION": "d" * 40,
        }

    def test_repository_dependency_contract_has_only_declared_release_blockers(self) -> None:
        with mock.patch.dict(
            module.os.environ, self.paperclip_runtime_evidence(), clear=False
        ):
            findings = module.validate(ROOT)
        blocked = [
            row for row in findings if row["code"] == "license_component_blocked"
        ]
        self.assertEqual(
            {row["path"] for row in blocked},
            set(),
        )
        self.assertEqual(
            [row for row in findings if row["code"] != "license_component_blocked"],
            [],
        )

    def test_mte_runtime_evidence_is_a_release_blocker_until_all_exact_values_exist(
        self,
    ) -> None:
        findings: list[dict[str, str]] = []
        with mock.patch.dict(module.os.environ, {}, clear=True):
            module.validate_operator_runtime_evidence(self.lock, findings)
        self.assertEqual(
            {row["code"] for row in findings},
            {
                "operator_runtime_image_evidence_missing",
                "operator_runtime_source_evidence_missing",
                "operator_runtime_revision_evidence_missing",
            },
        )

    def test_source_contract_validation_does_not_require_operator_runtime_evidence(
        self,
    ) -> None:
        with mock.patch.dict(module.os.environ, {}, clear=True):
            findings = module.validate(ROOT, require_operator_evidence=False)

        self.assertEqual(findings, [])

    def test_embedded_sigstore_identity_and_license_mapping_are_exact(self) -> None:
        artifacts = module.license_artifacts(ROOT, self.lock)
        self.assertIn(
            "HERMES_SIGSTORE_VERIFIER_IMAGE/sigstore@3.1.0",
            artifacts["embeddedImagePackages"],
        )
        self.assertEqual(
            self.licenses["components"]["sigstore-js"]["licenseExpression"],
            "Apache-2.0",
        )
        self.assertEqual(
            self.licenses["components"]["sigstore-js"]["sourceRef"], "v3.1.0"
        )

    def test_embedded_image_package_version_drift_is_rejected(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["embeddedImagePackages"]["hermes-sigstore-js"]["version"] = "3.0.1"
        findings: list[dict[str, str]] = []
        module.validate_embedded_image_packages(ROOT, lock, findings)
        self.assertIn(
            "embedded_image_package_version_drift",
            {row["code"] for row in findings},
        )

    def test_mte_runtime_must_keep_the_mit_upstream_base_provenance(self) -> None:
        catalog = copy.deepcopy(self.licenses)
        catalog["components"]["paperclip-upstream-base"]["licenseExpression"] = (
            "Apache-2.0"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "licenses.lock.json"
            path.write_text(json.dumps(catalog))
            findings: list[dict[str, str]] = []
            module.validate_licenses(ROOT, self.lock, findings, path)
        self.assertIn(
            "operator_runtime_upstream_provenance_invalid",
            {row["code"] for row in findings},
        )

    def test_every_direct_artifact_has_exactly_one_license_decision(self) -> None:
        findings: list[dict[str, str]] = []
        module.validate_licenses(ROOT, self.lock, findings)
        self.assertNotIn(
            "license_metadata_missing", {row["code"] for row in findings}
        )
        self.assertNotIn(
            "license_metadata_ambiguous", {row["code"] for row in findings}
        )
        artifacts = module.license_artifacts(ROOT, self.lock)
        self.assertIn("openTofu", artifacts["platformLockImages"])
        self.assertEqual(
            self.licenses["components"]["opentofu"]["licenseExpression"],
            "MPL-2.0",
        )
        self.assertEqual(
            self.licenses["components"]["opentofu"]["sourceRef"],
            "v1.12.1",
        )

    def test_unclassified_direct_artifact_is_rejected(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["downloads"]["unreviewed-tool"] = copy.deepcopy(
            lock["downloads"]["jq-linux-amd64"]
        )
        findings: list[dict[str, str]] = []
        module.validate_licenses(ROOT, lock, findings)
        self.assertIn("license_metadata_missing", {row["code"] for row in findings})

    def test_disallowed_license_expression_is_rejected(self) -> None:
        catalog = copy.deepcopy(self.licenses)
        catalog["components"]["paperclip-upstream-base"]["licenseExpression"] = (
            "BUSL-1.1"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "licenses.lock.json"
            path.write_text(json.dumps(catalog))
            findings: list[dict[str, str]] = []
            module.validate_licenses(ROOT, self.lock, findings, path)
        codes = {row["code"] for row in findings}
        self.assertIn("license_disallowed", codes)
        self.assertIn("license_denied_token", codes)

    def test_operator_provided_harness_must_never_be_redistributed(self) -> None:
        catalog = copy.deepcopy(self.licenses)
        catalog["components"]["claude-code"]["redistributed"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "licenses.lock.json"
            path.write_text(json.dumps(catalog))
            findings: list[dict[str, str]] = []
            module.validate_licenses(ROOT, self.lock, findings, path)
        self.assertIn(
            "operator_tool_redistribution_invalid",
            {row["code"] for row in findings},
        )

    def test_rejected_connector_candidates_are_not_shipped_as_oss(self) -> None:
        evaluated = self.licenses["evaluatedNotShipped"]
        self.assertEqual(
            set(evaluated), {"activepieces", "automatisch", "node-red", "windmill"}
        )
        self.assertEqual(
            self.licenses["components"]["activepieces-official-image"]["decision"],
            "blocked",
        )

    def test_floating_compose_seed_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (
                "config",
                "deployment/services",
                "deployment/steps",
                "tools/platform-cli",
            ):
                (root / relative).mkdir(parents=True, exist_ok=True)
            for source in (ROOT / "deployment/services").glob("*/compose.yaml"):
                destination = (
                    root / "deployment/services" / source.parent.name / "compose.yaml"
                )
                destination.parent.mkdir(parents=True)
                shutil.copy2(source, destination)
            shutil.copy2(
                ROOT / "config/compose-seeds.lock.json",
                root / "config/compose-seeds.lock.json",
            )
            for relative in (
                "tools/platform-cli/server-config.py",
                "deployment/steps/daytona.sh",
                "deployment/steps/cloudflare-tunnel.sh",
            ):
                shutil.copy2(ROOT / relative, root / relative)
            catalog_path = root / "config/compose-seeds.lock.json"
            catalog = json.loads(catalog_path.read_text())
            catalog["seeds"]["MTE_SEARXNG_VALKEY_IMAGE"] = "valkey/valkey:latest"
            catalog_path.write_text(json.dumps(catalog))
            findings: list[dict[str, str]] = []
            module.validate_images(root, self.lock, findings)
            self.assertIn(
                "compose_seed_image_not_digest_pinned",
                {finding["code"] for finding in findings},
            )

    def test_unused_compose_image_seed_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            for relative in ("config", "deployment/services", "tools/platform-cli"):
                (root / relative).mkdir(parents=True, exist_ok=True)
            for source in (ROOT / "deployment/services").glob("*/compose.yaml"):
                destination = (
                    root / "deployment/services" / source.parent.name / "compose.yaml"
                )
                destination.parent.mkdir(parents=True)
                shutil.copy2(source, destination)
            shutil.copy2(
                ROOT / "tools/platform-cli/server-config.py",
                root / "tools/platform-cli/server-config.py",
            )
            shutil.copy2(
                ROOT / "config/compose-seeds.lock.json",
                root / "config/compose-seeds.lock.json",
            )
            catalog_path = root / "config/compose-seeds.lock.json"
            catalog = json.loads(catalog_path.read_text())
            catalog["seeds"]["MTE_UNUSED_IMAGE"] = (
                "example.invalid/unused@sha256:" + "0" * 64
            )
            catalog_path.write_text(json.dumps(catalog))
            findings: list[dict[str, str]] = []
            module.validate_images(root, self.lock, findings)
            self.assertIn(
                "compose_seed_image_unused",
                {finding["code"] for finding in findings},
            )

    def test_only_active_deployment_compose_files_are_scanned(self) -> None:
        self.assertEqual(
            self.lock["imageSources"]["directComposeGlobs"],
            ["deployment/services/*/compose.yaml"],
        )

    def test_floating_runtime_image_is_rejected(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["runtimeImages"]["MTE_DAYTONA_API_IMAGE"]["ref"] = (
            "daytonaio/daytona-api:latest"
        )
        findings: list[dict[str, str]] = []
        module.validate_images(ROOT, lock, findings)
        self.assertIn("image_not_digest_pinned", {row["code"] for row in findings})

    def test_runtime_image_consumer_must_reference_canonical_key(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["runtimeImages"]["CLOUDFLARED_IMAGE"]["consumers"] = ["README.md"]
        findings: list[dict[str, str]] = []
        module.validate_images(ROOT, lock, findings)
        self.assertIn("image_consumer_drift", {row["code"] for row in findings})

    def test_daytona_runtime_image_requires_external_digest_evidence(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["runtimeImages"]["MTE_DAYTONA_SANDBOX_IMAGE"][
            "requiredDigestAtPreflight"
        ] = False
        findings: list[dict[str, str]] = []
        module.validate_operator_runtime_evidence(lock, findings)
        self.assertIn(
            "operator_runtime_evidence_invalid",
            {row["code"] for row in findings},
        )

    def test_daytona_image_source_lock_is_hash_bound(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["npmLockfiles"][0]["lockSha256"] = "0" * 64
        findings: list[dict[str, str]] = []
        module.validate_npm(ROOT, lock, findings)
        self.assertIn(
            "npm_install_hash_contract_drift",
            {row["code"] for row in findings},
        )

    def test_download_without_checksum_is_rejected(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["downloads"]["toolhive-linux-amd64"]["sha256"] = ""
        findings: list[dict[str, str]] = []
        module.validate_downloads(ROOT, lock, findings)
        codes = {row["code"] for row in findings}
        self.assertIn("download_sha256_invalid", codes)
        self.assertIn("download_checksum_not_enforced", codes)

    def test_download_consumer_must_use_canonical_checksum_key(self) -> None:
        lock = copy.deepcopy(self.lock)
        binding = lock["downloads"]["github-cli-linux-amd64"]["bindings"][0]
        binding["sha256Key"] = "MISSING_SHA256_KEY"
        findings: list[dict[str, str]] = []
        module.validate_downloads(ROOT, lock, findings)
        codes = {row["code"] for row in findings}
        self.assertIn("download_checksum_not_enforced", codes)
        self.assertIn("download_checksum_canonical_drift", codes)

    def test_all_runtime_download_artifacts_are_locked(self) -> None:
        self.assertEqual(
            set(self.lock["downloads"]),
            {
                "github-cli-linux-amd64",
                "hermes-agent-sigstore-bundle",
                "hermes-agent-wheel",
                "jq-linux-amd64",
                "toolhive-linux-amd64",
            },
        )

    def test_system_package_version_drift_is_rejected(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["systemPackages"]["docker-ce"]["version"] = "5:0.0.0-invalid"
        findings: list[dict[str, str]] = []
        module.validate_system_packages(ROOT, lock, findings)
        self.assertIn(
            "system_package_version_declaration_drift",
            {row["code"] for row in findings},
        )

    def test_signed_repository_identity_drift_is_rejected(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["signedRepositories"]["docker-ubuntu"]["fingerprint"] = "A" * 40
        findings: list[dict[str, str]] = []
        module.validate_downloads(ROOT, lock, findings)
        self.assertIn(
            "signed_repository_canonical_drift",
            {row["code"] for row in findings},
        )

    def test_hermes_wheel_identity_drift_is_rejected(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["downloads"]["hermes-agent-wheel"]["sha256"] = "0" * 64
        findings: list[dict[str, str]] = []
        module.validate_python_distributions(ROOT, lock, findings)
        self.assertIn(
            "python_distribution_identity_drift",
            {row["code"] for row in findings},
        )

    def test_hermes_signer_tag_identity_drift_is_rejected(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["pythonDistributions"]["hermes-agent"]["signerTagRef"] = (
            "refs/tags/v0.0.0-untrusted"
        )
        findings: list[dict[str, str]] = []
        module.validate_python_distributions(ROOT, lock, findings)
        self.assertIn(
            "python_distribution_identity_drift",
            {row["code"] for row in findings},
        )
        self.assertIn(
            "python_distribution_identity_not_enforced",
            {row["code"] for row in findings},
        )

    def test_hermes_sigstore_projection_drift_is_rejected(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["pythonDistributions"]["hermes-agent"][
            "sigstoreVerifierPackageVersion"
        ] = "3.1.1"
        findings: list[dict[str, str]] = []
        module.validate_python_distributions(ROOT, lock, findings)
        self.assertIn(
            "python_distribution_canonical_drift",
            {row["code"] for row in findings},
        )

    def test_hermes_requirement_lock_hash_drift_is_rejected(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["pythonDistributions"]["hermes-agent"]["requirementsSha256"] = (
            "0" * 64
        )
        findings: list[dict[str, str]] = []
        module.validate_python_distributions(ROOT, lock, findings)
        self.assertIn(
            "python_requirements_hash_drift",
            {row["code"] for row in findings},
        )

    def test_unlisted_network_fetch_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "tools/platform-cli/rogue.sh"
            script.parent.mkdir(parents=True)
            script.write_text(
                "#!/bin/sh\ncurl -fsSL https://example.invalid/tool -o /tmp/tool\n"
            )
            self.assertEqual(
                module.discover_network_fetch_sources(root),
                {"tools/platform-cli/rogue.sh"},
            )

    def test_floating_npm_version_is_rejected(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["npmPackages"]["@openai/codex"]["version"] = "latest"
        findings: list[dict[str, str]] = []
        module.validate_npm(ROOT, lock, findings)
        self.assertIn("npm_version_floating", {row["code"] for row in findings})

    def test_npm_integrity_must_match_canonical_ssot(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["npmPackages"]["@openai/codex"]["integrityKey"] = "MISSING_KEY"
        findings: list[dict[str, str]] = []
        module.validate_npm(ROOT, lock, findings)
        self.assertIn(
            "npm_integrity_declaration_drift",
            {row["code"] for row in findings},
        )

    def test_every_root_npm_dependency_requires_a_canonical_contract(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["npmPackages"].pop("@upstash/context7-pi")
        findings: list[dict[str, str]] = []
        module.validate_npm(ROOT, lock, findings)
        self.assertIn(
            "npm_root_package_missing_from_contract",
            {row["code"] for row in findings},
        )

    def test_npm_install_set_hash_must_match_canonical_ssot(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["npmLockfiles"][0]["manifestSha256"] = "0" * 64
        findings: list[dict[str, str]] = []
        module.validate_npm(ROOT, lock, findings)
        self.assertIn(
            "npm_install_hash_contract_drift",
            {row["code"] for row in findings},
        )

    def test_transitive_npm_package_without_integrity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            temporary = Path(directory)
            source_root = ROOT / "deployment/image-build/daytona-harness"
            manifest = temporary / "package.json"
            package_lock = temporary / "package-lock.json"
            shutil.copy2(source_root / "package.json", manifest)
            document = json.loads((source_root / "package-lock.json").read_text())
            package = next(
                row
                for key, row in document["packages"].items()
                if key and isinstance(row, dict) and row.get("resolved")
            )
            package.pop("integrity", None)
            package_lock.write_text(json.dumps(document))

            lock = copy.deepcopy(self.lock)
            lock["npmLockfiles"] = [
                {
                    "manifest": str(manifest.relative_to(ROOT)),
                    "lockfile": str(package_lock.relative_to(ROOT)),
                    "manifestSha256": module.hashlib.sha256(
                        manifest.read_bytes()
                    ).hexdigest(),
                    "lockSha256": module.hashlib.sha256(
                        package_lock.read_bytes()
                    ).hexdigest(),
                    "consumer": "deployment/image-build/daytona-harness/Dockerfile",
                }
            ]
            findings: list[dict[str, str]] = []
            module.validate_npm(ROOT, lock, findings)
            self.assertIn(
                "npm_lock_package_unverified",
                {row["code"] for row in findings},
            )


if __name__ == "__main__":
    unittest.main()

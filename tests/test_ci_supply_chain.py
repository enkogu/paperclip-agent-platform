from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import tomllib
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = ROOT / ".github/workflows"
TOOL_ROOT = ROOT / "tools/platform-cli"
PYPROJECT = TOOL_ROOT / "pyproject.toml"
RELEASE_CHECK = TOOL_ROOT / "release-check.sh"
REQUIREMENTS_LOCK = TOOL_ROOT / "requirements-release-check.txt"
GITLEAKS_CONFIG = ROOT / ".gitleaks.toml"
VERSION = ROOT / "VERSION"
RELEASE_SBOM_WORKFLOW = WORKFLOW_ROOT / "release-sbom.yml"
DAYTONA_IMAGE_WORKFLOW = WORKFLOW_ROOT / "daytona-harness-image.yml"
SBOM_TARGETS = TOOL_ROOT / "sbom-targets.py"
SBOM_VERIFIER = TOOL_ROOT / "verify-sbom.py"
SBOM_BUNDLE = TOOL_ROOT / "sbom-bundle.py"
RELEASE_EVENT_VERIFIER = TOOL_ROOT / "verify-release-event.py"
SBOM_POLICY = ROOT / "skills/system-platform/references/supply-chain.md"
ACTION_USE = re.compile(r"^\s*-?\s*uses:\s*(?P<target>\S+)(?P<comment>\s+#.*)?$")
ACTION_SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"#\s*v\d+(?:\.\d+){1,2}\b")
REQUIREMENT = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+)==(?P<version>[^\s;\\]+)")


def normalize_package(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def locked_requirements() -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    current: list[str] = []

    def record() -> None:
        if not current:
            return
        block = "\n".join(current)
        match = REQUIREMENT.match(current[0])
        if match is None:
            raise AssertionError(f"Unpinned requirement block: {current[0]!r}")
        if "--hash=sha256:" not in block:
            raise AssertionError(f"Requirement has no SHA-256 hashes: {current[0]!r}")
        name = normalize_package(match.group("name"))
        entries[name] = (match.group("version"), block)

    for line in REQUIREMENTS_LOCK.read_text().splitlines():
        if line and not line[0].isspace() and not line.startswith("#"):
            record()
            current = [line]
        elif current:
            current.append(line)
    record()
    return entries


class CiSupplyChainTests(unittest.TestCase):
    def test_all_dockerfile_bases_are_digest_pinned(self) -> None:
        dockerfiles = sorted((ROOT / "deployment").rglob("Dockerfile"))
        self.assertEqual(
            dockerfiles,
            [ROOT / "deployment/image-build/daytona-harness/Dockerfile"],
        )
        for dockerfile in dockerfiles:
            bases = [
                line.split(maxsplit=1)[1]
                for line in dockerfile.read_text().splitlines()
                if line.startswith("FROM ")
            ]
            self.assertEqual(len(bases), 1, dockerfile)
            self.assertRegex(bases[0], r"@sha256:[0-9a-f]{64}$", dockerfile)

    def test_daytona_image_is_ci_built_signed_and_sbom_attested(self) -> None:
        workflow = DAYTONA_IMAGE_WORKFLOW.read_text()
        self.assertIn("deployment/image-build/daytona-harness/Dockerfile", workflow)
        self.assertIn("push: true", workflow)
        self.assertIn("provenance: mode=max", workflow)
        self.assertIn("sbom: true", workflow)
        self.assertIn("cosign sign --yes", workflow)
        self.assertIn(
            '--certificate-identity "$EXPECTED_CERTIFICATE_IDENTITY"', workflow
        )
        self.assertNotIn("--certificate-identity-regexp", workflow)
        self.assertIn("anchore/sbom-action@", workflow)
        sbom_generation = workflow.split(
            "- name: Generate a digest-bound SPDX SBOM", 1
        )[1].split("- id: sbom-identity", 1)[0]
        self.assertIn("SYFT_SOURCE_NAME: paperclip-daytona-harness", sbom_generation)
        self.assertIn(
            "SYFT_SOURCE_VERSION: ${{ steps.build.outputs.digest }}",
            sbom_generation,
        )
        self.assertIn("tools/platform-cli/verify-sbom.py", workflow)
        self.assertIn("--expected-root-purl", workflow)
        self.assertIn("--expected-digest", workflow)
        self.assertIn("Verify the exact harness and tool ABI", workflow)
        self.assertIn(
            'docker run --rm --network none --entrypoint node "$IMAGE_NAME@$IMAGE_DIGEST"',
            workflow,
        )
        self.assertIn("versionPatterns", workflow)
        self.assertNotIn("output.includes(version)", workflow)
        self.assertIn("actual !== version", workflow)
        self.assertIn("daytona-harness-image.json", workflow)
        self.assertIn('"image": f\'{os.environ["IMAGE_NAME"]}@{digest}\'', workflow)
        self.assertIn("IMAGE_NAME: ${{ needs.prepare.outputs.image_name }}", workflow)
        self.assertIn('gh release create "$RELEASE_TAG"', workflow)
        self.assertIn("--draft", workflow)
        self.assertIn('gh release edit "$RELEASE_TAG" --draft=false', workflow)
        publish = workflow.split(
            'if [[ "$(jq -r .isDraft "$existing_release")" == true ]]; then', 1
        )[1].split("\n          fi", 1)[0]
        self.assertRegex(
            publish,
            r"verify_release_tag\s+gh release edit \"\$RELEASE_TAG\" --draft=false\s+verify_release_tag",
        )
        self.assertIn('cmp "$asset_receipt"', workflow)
        self.assertIn('cmp "$asset_sbom"', workflow)
        self.assertNotIn(
            "docker build", (ROOT / "deployment/steps/daytona.sh").read_text()
        )

    def test_remote_github_actions_use_immutable_commits(self) -> None:
        findings: list[str] = []
        for workflow in sorted(WORKFLOW_ROOT.glob("*.y*ml")):
            for line_number, line in enumerate(workflow.read_text().splitlines(), 1):
                if "uses:" not in line:
                    continue
                match = ACTION_USE.match(line)
                if match is None:
                    findings.append(
                        f"{workflow.relative_to(ROOT)}:{line_number}: malformed uses"
                    )
                    continue
                target = match.group("target")
                if target.startswith("./"):
                    continue
                if target.startswith("docker://"):
                    if "@sha256:" not in target:
                        findings.append(
                            f"{workflow.relative_to(ROOT)}:{line_number}: "
                            "Docker action is not digest-pinned"
                        )
                    continue
                if "@" not in target:
                    findings.append(
                        f"{workflow.relative_to(ROOT)}:{line_number}: missing action ref"
                    )
                    continue
                _, reference = target.rsplit("@", 1)
                if ACTION_SHA.fullmatch(reference) is None:
                    findings.append(
                        f"{workflow.relative_to(ROOT)}:{line_number}: "
                        f"mutable action ref {reference!r}"
                    )
                if VERSION_COMMENT.search(match.group("comment") or "") is None:
                    findings.append(
                        f"{workflow.relative_to(ROOT)}:{line_number}: "
                        "missing readable version comment"
                    )

        self.assertEqual(findings, [])

    def test_release_check_requires_explicit_hash_locked_dependencies(self) -> None:
        release_check = RELEASE_CHECK.read_text().replace("\\\n", " ")
        workflow = (WORKFLOW_ROOT / "ci.yml").read_text()

        self.assertIn("PYTHON=python3", release_check)
        self.assertIn("command -v ruff", release_check)
        self.assertIn("from importlib.metadata import PackageNotFoundError, version", release_check)
        self.assertIn("installed distributions do not exactly match", release_check)
        self.assertIn("installed metadata cannot attest wheel hashes", release_check)
        self.assertEqual(release_check.count("-m pip install"), 1)
        self.assertIn("--require-hashes", release_check)
        self.assertIn("--only-binary=:all:", release_check)
        self.assertIn("requirements-release-check.txt", release_check)
        self.assertIn(
            "python3 -m pip install --require-hashes --only-binary=:all: "
            "--requirement tools/platform-cli/requirements-release-check.txt",
            workflow,
        )
        self.assertFalse((TOOL_ROOT / "runtime.sh").exists())

    def test_release_check_uses_a_pinned_redacted_source_scan(self) -> None:
        release_check = RELEASE_CHECK.read_text()
        workflow = (WORKFLOW_ROOT / "ci.yml").read_text()

        self.assertIn('gitleaks_version="$(awk -F', release_check)
        self.assertIn('GITLEAKS_VERSION:/{print $2; exit}', release_check)
        self.assertIn('mktemp -d "${TMPDIR:-/tmp}/paperclip-release-check-source.XXXXXX"', release_check)
        self.assertIn('git archive --format=tar "$(git write-tree)"', release_check)
        self.assertIn("gitleaks detect", release_check)
        self.assertIn("--redact=100", release_check)
        self.assertIn("Runtime evidence redaction audit", release_check)
        self.assertTrue(GITLEAKS_CONFIG.is_file())
        self.assertIn(
            "gitleaks/gitleaks-action@ff98106e4c7b2bc287b24eaf42907196329070c7",
            workflow,
        )
        self.assertIn("MTE_RELEASE_SECRET_SCAN=ci-action make release-check", workflow)

    def test_ci_removes_only_the_gitleaks_workspace_report_before_release_gate(self) -> None:
        workflow = (WORKFLOW_ROOT / "ci.yml").read_text()
        cleanup = "- name: Remove the Gitleaks workspace report\n        run: rm -f -- results.sarif"
        self.assertIn(cleanup, workflow)
        self.assertGreater(
            workflow.index(cleanup),
            workflow.index("- name: Scan tracked source for secrets"),
        )
        self.assertLess(
            workflow.index(cleanup),
            workflow.index("- name: Run offline release gate"),
        )
        self.assertIn(
            "MTE_SECRET_ROOT: ${{ runner.temp }}/mte-secrets",
            workflow,
        )

    def test_release_check_requires_a_clean_release_tree_before_tools_run(self) -> None:
        release_check = RELEASE_CHECK.read_text()

        self.assertIn('git status --porcelain=v1 --untracked-files=all', release_check)
        self.assertIn("a clean, index-complete release worktree is required", release_check)
        self.assertIn('git diff --quiet --ignore-submodules --', release_check)
        self.assertIn('git diff --cached --quiet --ignore-submodules --', release_check)
        self.assertIn("git rev-parse --verify 'HEAD^{tree}'", release_check)
        self.assertIn('git write-tree', release_check)
        self.assertIn(
            "index must exactly match the checked-out release commit", release_check
        )
        self.assertLess(
            release_check.index('section "Release tree completeness"'),
            release_check.index('section "Python dependency preflight"'),
        )

    def test_offline_release_check_validates_source_contract_without_live_image_evidence(
        self,
    ) -> None:
        release_check = RELEASE_CHECK.read_text().replace("\\\n", " ")

        self.assertRegex(
            release_check,
            r"tools/platform-cli/validate-dependencies\.py\s+--source-contract-only",
        )

    @unittest.skipUnless(shutil.which("gitleaks"), "gitleaks is required by release-check")
    def test_gitleaks_detector_rejects_a_synthetic_secret(self) -> None:
        """The scanner binary must fail closed instead of becoming a no-op."""
        secret = "ABCDEFGHIJKLMNOPQRST"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "gitleaks.toml"
            source = root / "source.txt"
            config.write_text(
                """title = \"detector regression\"\n\n[[rules]]\nid = \"synthetic-secret\"\ndescription = \"test only\"\nregex = '''SYNTHETIC_SECRET=([A-Z0-9]{20})'''\nsecretGroup = 1\n"""
            )
            source.write_text(f"SYNTHETIC_SECRET={secret}\n")
            result = subprocess.run(
                [
                    "gitleaks",
                    "dir",
                    "--config",
                    str(config),
                    "--redact=100",
                    "--no-banner",
                    "--no-color",
                    "--log-level",
                    "warn",
                    str(source),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

        self.assertEqual(result.returncode, 1)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_gitleaks_allowlists_are_exact_path_and_line_exceptions(self) -> None:
        config = tomllib.loads(GITLEAKS_CONFIG.read_text())
        allowlists = config["allowlists"]

        self.assertEqual(len(allowlists), 3)
        self.assertEqual(
            {allowlist["targetRules"][0] for allowlist in allowlists},
            {"generic-api-key", "cloudflare-api-key"},
        )
        for allowlist in allowlists:
            with self.subTest(description=allowlist["description"]):
                self.assertEqual(allowlist["condition"], "AND")
                self.assertEqual(allowlist["regexTarget"], "line")
                self.assertEqual(len(allowlist["targetRules"]), 1)
                self.assertEqual(len(allowlist["paths"]), 1)
                self.assertEqual(len(allowlist["regexes"]), 1)
                self.assertTrue(allowlist["paths"][0].startswith("(^|/"))

    def test_version_and_changelog_have_one_release_policy(self) -> None:
        changelog = (ROOT / "CHANGELOG.md").read_text()

        self.assertRegex(VERSION.read_text().strip(), r"^\d+\.\d+\.\d+$")
        self.assertIn("## Unreleased", changelog)
        self.assertIn("[`VERSION`](VERSION)", changelog)
        self.assertIn("three-part semantic version with no `v` prefix", changelog)
        self.assertIn("## [X.Y.Z] - YYYY-MM-DD", changelog)
        self.assertIn("Git tag named `vX.Y.Z`", changelog)
        self.assertRegex(changelog, r"must never be\s+reused")

    def test_every_locked_requirement_is_pinned_and_hashed(self) -> None:
        entries = locked_requirements()
        self.assertGreaterEqual(len(entries), 3)
        for name, (version, block) in entries.items():
            self.assertTrue(version, name)
            self.assertRegex(block, r"--hash=sha256:[0-9a-f]{64}")

    def test_lock_contains_exact_pyproject_release_check_pins(self) -> None:
        metadata = tomllib.loads(PYPROJECT.read_text())
        declared = metadata["dependency-groups"]["release-check"]
        entries = locked_requirements()

        expected: dict[str, str] = {}
        for requirement in declared:
            match = REQUIREMENT.match(requirement)
            self.assertIsNotNone(
                match, f"Dependency must be exactly pinned: {requirement}"
            )
            assert match is not None
            expected[normalize_package(match.group("name"))] = match.group("version")

        actual = {name: entries[name][0] for name in expected if name in entries}
        self.assertEqual(actual, expected)

    def test_cli_pyproject_does_not_claim_a_publishable_package(self) -> None:
        metadata = tomllib.loads(PYPROJECT.read_text())
        self.assertNotIn("project", metadata)
        self.assertIs(metadata["tool"]["uv"]["package"], False)

    def test_release_sbom_workflow_is_immutable_verified_and_public(self) -> None:
        workflow = RELEASE_SBOM_WORKFLOW.read_text()
        licenses = json.loads((ROOT / "config/licenses.lock.json").read_text())

        self.assertIn("push:", workflow)
        self.assertIn('      - "v[0-9]*"', workflow)
        self.assertNotIn("types: [published]", workflow)
        self.assertIn("ref: ${{ github.ref }}", workflow)
        self.assertIn("ref: ${{ needs.targets.outputs.release_sha }}", workflow)
        self.assertNotIn("ref: ${{ github.event.release.tag_name }}", workflow)
        self.assertNotIn("github.event.release.tag_name }}.spdx.json", workflow)
        self.assertIn("verify-release-event.py", workflow)
        self.assertIn("--version-file VERSION", workflow)
        self.assertIn(
            "remote release tag no longer resolves", RELEASE_EVENT_VERIFIER.read_text()
        )
        self.assertIn("needs.targets.outputs.release_sha", workflow)
        self.assertIn("tools/platform-cli/validate-dependencies.py", workflow)
        self.assertIn("tools/platform-cli/verify-sbom.py", workflow)
        self.assertIn("--expected-root-name", workflow)
        self.assertIn("--expected-root-version", workflow)
        self.assertIn("--expected-root-purl", workflow)
        self.assertIn("--expected-digest", workflow)
        self.assertIn("SYFT_SOURCE_NAME", workflow)
        self.assertIn("SYFT_SOURCE_VERSION", workflow)
        self.assertIn("matrix: ${{ fromJSON(needs.targets.outputs.matrix) }}", workflow)
        self.assertIn("max-parallel: 6", workflow)
        self.assertIn("retention-days: 1", workflow)
        self.assertIn("actions: read", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("sbom-bundle.py", workflow)
        self.assertIn("gh release create", workflow)
        self.assertIn("--draft", workflow)
        self.assertIn("gh release upload", workflow)
        self.assertIn("--clobber", workflow)
        self.assertIn('gh release edit "$RELEASE_TAG" --draft=false', workflow)
        self.assertIn("refusing to mutate an already-public release", workflow)
        self.assertIn("$managed | length == 1", workflow)
        publish = workflow.split(
            "Create or reconcile the draft, verify its sole SBOM asset, then publish",
            maxsplit=1,
        )[1]
        draft_creation = publish.index('gh release create "$RELEASE_TAG"')
        post_draft_revalidation = publish.index(
            "revalidate_remote_tag", draft_creation + 1
        )
        asset_upload = publish.index('gh release upload "$RELEASE_TAG"')
        final_revalidation = publish.rindex("revalidate_remote_tag")
        publication = publish.index('gh release edit "$RELEASE_TAG" --draft=false')
        self.assertLess(draft_creation, post_draft_revalidation)
        self.assertLess(post_draft_revalidation, asset_upload)
        self.assertLess(final_revalidation, publication)
        self.assertIn(
            "Fail closed: a moved tag leaves this release as a non-public draft.",
            publish,
        )
        self.assertIn("revalidate_remote_tag()", publish)
        self.assertIn(
            "anchore/sbom-action@fbfd9c6c189226748411491745178e0c2017392d",
            workflow,
        )
        self.assertEqual(workflow.count("syft-version: v1.38.0"), 2)
        self.assertEqual(licenses["components"]["syft"]["sourceRef"], "v1.38.0")
        self.assertEqual(
            licenses["components"]["syft"]["sourceUrl"],
            "https://github.com/anchore/syft/tree/v1.38.0",
        )
        self.assertIn(
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            workflow,
        )
        self.assertNotIn('upload-artifact: "true"', workflow)
        self.assertNotIn('upload-release-assets: "true"', workflow)
        self.assertNotIn("publish-sbom", workflow)

    def test_release_sbom_targets_cover_every_digest_pinned_release_image(self) -> None:
        module = load_module(SBOM_TARGETS)
        targets = module.release_images(ROOT)
        lock = json.loads((ROOT / "config/dependencies.lock.json").read_text())
        seed_path = ROOT / lock["imageSources"]["composeSeeds"]
        seeds = json.loads(seed_path.read_text())["seeds"]
        platform_images = module.platform_lock_images(
            ROOT / lock["imageSources"]["platformLock"]
        )
        expected = {
            row["ref"]
            for row in lock["runtimeImages"].values()
            if row.get("ref")
        }
        expected.update(value for key, value in seeds.items() if key.endswith("_IMAGE"))
        expected.update(platform_images.values())

        self.assertEqual({target["image"] for target in targets}, expected)
        self.assertEqual(len(targets), len(expected))
        self.assertTrue(all("@sha256:" in target["image"] for target in targets))
        self.assertEqual(len({target["id"] for target in targets}), len(targets))
        self.assertIn(platform_images["openTofu"], expected)
        tofu = next(
            target
            for target in targets
            if target["image"] == platform_images["openTofu"]
        )
        self.assertEqual(tofu["root_name"], "opentofu")
        self.assertEqual(tofu["root_version"], "1.12.1")
        self.assertTrue(tofu["purl"].startswith("pkg:oci/opentofu@sha256:"))

    def test_release_sbom_verifier_rejects_an_incomplete_document(self) -> None:
        module = load_module(SBOM_VERIFIER)
        release_sha = "a" * 40
        document = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "paperclip-agent-platform",
            "documentNamespace": "https://example.invalid/sbom",
            "creationInfo": {"creators": ["Tool: syft-v1.38.0"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-Root",
                    "name": "paperclip-agent-platform",
                    "versionInfo": release_sha,
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-Root",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / f"source-{release_sha}.spdx.json"
            path.write_text(json.dumps(document))
            self.assertEqual(
                module.verify(
                    path,
                    expected_package="paperclip-agent-platform",
                    expected_target=release_sha,
                    expected_root_version=release_sha,
                ),
                [],
            )
            document["creationInfo"] = {"creators": []}
            document["packages"] = []
            document["relationships"] = []
            path.write_text(json.dumps(document))
            findings = module.verify(path)
            self.assertIn("missing meaningful creationInfo creators", findings)
            self.assertIn("packages list is empty", findings)
            self.assertIn("document must describe exactly one root package", findings)

            path.write_text("{}")
            findings = module.verify(path)

        self.assertIn("missing SPDX version", findings)
        self.assertIn("missing packages list", findings)

    def test_release_sbom_verifier_rejects_filename_only_image_substitution(
        self,
    ) -> None:
        targets = load_module(SBOM_TARGETS)
        verifier = load_module(SBOM_VERIFIER)
        target = targets.image_identity(
            "ghcr.io/example/right:v1.2.3@sha256:" + "a" * 64
        )
        release_sha = "b" * 40
        document = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "renamed-file",
            "documentNamespace": "https://example.invalid/sbom",
            "creationInfo": {"creators": ["Tool: syft-v1.38.0"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-Root",
                    "name": "wrong",
                    "versionInfo": "v9",
                    "checksums": [{"algorithm": "SHA256", "checksumValue": "c" * 64}],
                    "externalRefs": [
                        {
                            "referenceType": "purl",
                            "referenceLocator": "pkg:oci/wrong@sha256:"
                            + "c" * 64
                            + "?repository_url=ghcr.io%2Fexample%2Fwrong&tag=v9",
                        }
                    ],
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-Root",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / f"image-right-{release_sha}.spdx.json"
            path.write_text(json.dumps(document))
            findings = verifier.verify(
                path,
                expected_target=release_sha,
                expected_root_name=target["root_name"],
                expected_root_version=target["root_version"],
                expected_root_purl=target["purl"],
                expected_digest=target["digest"],
            )
        self.assertIn("root package name does not match the expected source", findings)
        self.assertIn(
            "root package version does not match the expected source", findings
        )
        self.assertIn("root package purl does not match the expected image", findings)
        self.assertIn("root package digest does not match the expected image", findings)

    def test_release_sbom_verifier_rejects_an_extra_purl_qualifier(self) -> None:
        targets = load_module(SBOM_TARGETS)
        verifier = load_module(SBOM_VERIFIER)
        target = targets.image_identity(
            "ghcr.io/example/right:v1.2.3@sha256:" + "a" * 64
        )

        self.assertFalse(
            verifier.matching_purl(
                target["purl"] + "&unexpected=qualifier", target["purl"]
            )
        )
        self.assertFalse(
            verifier.matching_purl(target["purl"] + "&unexpected=", target["purl"])
        )

    def test_release_sbom_bundle_is_complete_checksummed_and_deterministic(
        self,
    ) -> None:
        targets = load_module(SBOM_TARGETS)
        bundle = load_module(SBOM_BUNDLE)
        release_sha = "d" * 40
        repository = "example/paperclip-agent-platform"

        def document(name: str, version: str, purl: str | None = None) -> dict:
            root = {"SPDXID": "SPDXRef-Root", "name": name, "versionInfo": version}
            if purl:
                root["externalRefs"] = [
                    {"referenceType": "purl", "referenceLocator": purl}
                ]
            return {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": name,
                "documentNamespace": "https://example.invalid/sbom/" + name,
                "creationInfo": {"creators": ["Tool: syft-v1.38.0"]},
                "packages": [root],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": "SPDXRef-Root",
                    }
                ],
            }

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / f"paperclip-agent-platform-source-{release_sha}.spdx.json"
            source.write_text(json.dumps(document(repository, release_sha)))
            for target in targets.release_images(ROOT):
                path = base / (
                    f"paperclip-agent-platform-image-{target['id']}-{release_sha}.spdx.json"
                )
                path.write_text(
                    json.dumps(
                        document(
                            target["root_name"], target["root_version"], target["purl"]
                        )
                    )
                )
            first = base / "first.tar.gz"
            second = base / "second.tar.gz"
            manifest = bundle.build_bundle(
                base,
                first,
                root=ROOT,
                release_sha=release_sha,
                repository=repository,
            )
            bundle.build_bundle(
                base,
                second,
                root=ROOT,
                release_sha=release_sha,
                repository=repository,
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(bundle.verify_bundle(first), manifest)
            source.unlink()
            with self.assertRaisesRegex(ValueError, "incomplete"):
                bundle.build_bundle(
                    base,
                    first,
                    root=ROOT,
                    release_sha=release_sha,
                    repository=repository,
                )

    def test_release_event_verifier_prefers_a_peeled_tag_target(self) -> None:
        module = load_module(RELEASE_EVENT_VERIFIER)
        tag_ref = "refs/tags/v1.2.3"
        self.assertEqual(
            module.remote_tag_target(
                "a" * 40
                + f"\t{tag_ref}\n"
                + "b" * 40
                + f"\t{tag_ref}^{{}}\n",
                tag_ref,
            ),
            "b" * 40,
        )
        with self.assertRaisesRegex(ValueError, "absent"):
            module.remote_tag_target("", tag_ref)

    def test_release_event_verifier_requires_exact_semver_version_tag(self) -> None:
        module = load_module(RELEASE_EVENT_VERIFIER)
        with tempfile.TemporaryDirectory() as directory:
            version_file = Path(directory) / "VERSION"
            version_file.write_text("1.2.3\n")
            self.assertEqual(module.release_version(version_file), "1.2.3")
            module.verify_release_tag("v1.2.3", module.release_version(version_file))
            with self.assertRaisesRegex(ValueError, "exactly match"):
                module.verify_release_tag("v1", module.release_version(version_file))
            with self.assertRaisesRegex(ValueError, "exactly match"):
                module.verify_release_tag("v1.2.4", module.release_version(version_file))
            version_file.write_text("01.2.3\n")
            with self.assertRaisesRegex(ValueError, "strict SemVer"):
                module.release_version(version_file)
            for invalid_version in (" 1.2.3\n", "1.2.3 \n", "1.2.3\n\n"):
                with self.subTest(invalid_version=invalid_version):
                    version_file.write_text(invalid_version)
                    with self.assertRaisesRegex(ValueError, "exactly one LF"):
                        module.release_version(version_file)

    def test_sbom_policy_keeps_license_and_image_boundaries_explicit(self) -> None:
        policy = SBOM_POLICY.read_text()

        self.assertIn("config/licenses.lock.json", policy)
        self.assertIn("not a transitive image", policy)
        self.assertIn("does not vendor, rebuild, or relicense", policy)
        self.assertIn("Operator-provided proprietary harnesses", policy)
        self.assertIn("protect version release tags", policy)
        self.assertIn("force-updates or deletion must be forbidden", policy)
        self.assertIn("protect the `daytona-harness-*` tag", policy)
        self.assertIn("immediately before and immediately after", policy)


if __name__ == "__main__":
    unittest.main()

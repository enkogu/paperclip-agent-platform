from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/verification-before-completion"
MANIFEST = SKILL / "SKILL.md"
CONTRACT_ID = "mte.verify-before-completion.v1"
DAYTONA_INSTALLER = ROOT / "deployment/steps/daytona.sh"
TOOL_ROOT = ROOT / "tools/platform-cli"
if str(TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOL_ROOT))

from profile_catalog import CatalogError, load_profile_catalog  # noqa: E402


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_verification_skill_is_compact_anthropic_compatible_and_valid() -> None:
    source = MANIFEST.read_text()
    match = re.fullmatch(r"---\n(.*?)\n---\n(.*)", source, flags=re.DOTALL)
    assert match is not None
    frontmatter = yaml.safe_load(match.group(1))
    assert set(frontmatter) == {"name", "description"}
    assert frontmatter["name"] == "verification-before-completion"
    assert CONTRACT_ID in match.group(2)
    assert len(source.splitlines()) < 40

    validator = (
        Path.home() / ".codex/skills/.system/skill-creator/scripts/quick_validate.py"
    )
    if validator.is_file():
        completed = subprocess.run(
            ["python3", str(validator), str(SKILL)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr


def test_verification_skill_ui_metadata_matches_the_manifest() -> None:
    metadata = yaml.safe_load((SKILL / "agents/openai.yaml").read_text())
    interface = metadata["interface"]
    assert interface["display_name"] == "Verification Before Completion"
    assert 25 <= len(interface["short_description"]) <= 64
    assert "$verification-before-completion" in interface["default_prompt"]
    assert re.fullmatch(r"[0-9a-f]{64}", sha256(MANIFEST))


def test_profile_catalog_binds_skill_source_hashes_and_native_destinations() -> None:
    catalog = load_profile_catalog(ROOT / "config/profiles/catalog.yaml")
    package = catalog.require_skill_package("verification-before-completion")
    assert package["source"] == "skills/verification-before-completion"
    assert package["projection"] == (
        "runtime/paperclip/profiles/skills/verification-before-completion"
    )
    assert package["manifestSha256"] == sha256(MANIFEST)
    assert package["metadataSha256"] == sha256(SKILL / "agents/openai.yaml")
    assert package["contractId"] == CONTRACT_ID
    assert package["nativeDestinations"] == {
        "codex": "/home/daytona/.agents/skills/verification-before-completion",
        "claude": "/home/daytona/.claude/skills/verification-before-completion",
        "pi": ("/home/daytona/.pi/mte-profile/skills/verification-before-completion"),
    }
    for profile in catalog.profiles:
        assert profile["skills"] == ["verification-before-completion"]
        harness = profile["runtimeContract"]["harnessKind"]
        assert harness in package["nativeDestinations"]


def test_daytona_snapshot_installs_and_hash_binds_the_skill_package() -> None:
    source = DAYTONA_INSTALLER.read_text()
    dockerfile = (ROOT / "deployment/image-build/daytona-harness/Dockerfile").read_text()
    assert "prepare_profile_skill_contract" in source
    assert "prepare_sandbox_context" not in source
    assert "contextFiles:files" not in source
    assert "contextHash" not in source
    assert (
        "COPY skills/verification-before-completion/SKILL.md /opt/mte-skill/SKILL.md"
        in dockerfile
    )
    assert (
        "COPY skills/verification-before-completion/agents/openai.yaml "
        "/opt/mte-skill/agents/openai.yaml" in dockerfile
    )
    for destination in (
        "/home/daytona/.agents/skills/verification-before-completion",
        "/home/daytona/.claude/skills/verification-before-completion",
        "/home/daytona/.pi/mte-profile/skills/verification-before-completion",
    ):
        assert destination in dockerfile


def test_lifecycle_probes_real_harnesses_without_prompt_or_secret_injection() -> None:
    source = DAYTONA_INSTALLER.read_text()
    probe = source.split("const probeScript=`", 1)[1].split("`;", 1)[0]
    assert CONTRACT_ID not in probe
    assert '["codex","claude","pi"]' in probe
    assert 'commandPath:exec("command -v "+name)' in probe
    assert 'realpath:exec("readlink -f $(command -v "+name+")")' in probe
    assert 'versionOutput:exec(name+" --version")' in probe
    assert "OPENAI_API_KEY" in probe
    assert "ANTHROPIC_API_KEY" in probe
    assert "GH_TOKEN" in probe
    assert "foundNames" in probe
    assert "Use the verification-before-completion skill" not in probe


@pytest.mark.parametrize(
    "mutation, expected",
    (
        (
            lambda document: document["skillPackages"][
                "verification-before-completion"
            ].update(manifestSha256="latest"),
            "skill_package_hash_invalid",
        ),
        (
            lambda document: document["skillPackages"][
                "verification-before-completion"
            ]["nativeDestinations"].pop("pi"),
            "profile_skill_destination_missing",
        ),
        (
            lambda document: document["profiles"][0].update(skills=["missing"]),
            "profile_skill_unknown",
        ),
    ),
)
def test_profile_skill_registry_fails_closed(mutation, expected: str) -> None:
    document = yaml.safe_load((ROOT / "config/profiles/catalog.yaml").read_text())
    mutation(document)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "catalog.yaml"
        path.write_text(yaml.safe_dump(document, sort_keys=False))
        with pytest.raises(CatalogError, match=expected):
            load_profile_catalog(path)

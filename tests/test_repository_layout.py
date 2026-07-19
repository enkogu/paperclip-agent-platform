from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml


ROOT = Path(__file__).resolve().parents[1]
SYSTEM_SKILL = ROOT / "skills/system-platform"
SYSTEM_SKILL_REFERENCES = SYSTEM_SKILL / "references"
PROFILE_VERIFICATION_SKILL = ROOT / "skills/verification-before-completion"
ROOT_MARKDOWN_ALLOWLIST = {
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
}
MARKDOWN_LINK = re.compile(r"!?\[[^]]*\]\(([^)]+)\)")
EXTERNAL_SCHEMES = {"data", "http", "https", "mailto"}
MIGRATION_ROW = re.compile(
    r"^\| `(?P<previous>docs/[^`]+)` \| `(?P<target>[^`]+)` \|$",
    re.MULTILINE,
)
NON_ACTIVE_RUN_CONTEXT = re.compile(
    r"(?:do not invent|\bdeprecated\b|\bearlier\b|\bhistor\w*\b|\blegacy\b|"
    r"\bold\b|\bprototype\b|\bremoved\b|\bretired\b|\bстар\w*\b)",
    re.IGNORECASE,
)
MIGRATED_DOCUMENTATION_PATHS = {
    "docs/architecture/index.html",
    "docs/en/connectors.md",
    "docs/en/contributing.md",
    "docs/en/deployment.md",
    "docs/en/hermes.md",
    "docs/en/limitations.md",
    "docs/en/notion-tool-policy.md",
    "docs/en/platform.md",
    "docs/en/quickstart.md",
    "docs/en/security.md",
    "docs/en/state-mapping.md",
    "docs/en/third-party.md",
    "docs/en/troubleshooting.md",
    "docs/ru/connections.md",
    "docs/ru/deployment-architecture.md",
    "docs/ru/security.md",
    "docs/ru/specification.md",
}
CANONICAL_CONTRACTS = {
    "config/platform.yaml",
    "config/platform.lock.yaml",
    "config/acceptance-requirements.yaml",
    "config/dependencies.lock.json",
    "config/compose-seeds.lock.json",
    "config/platform.env.example",
    "config/profiles/catalog.yaml",
    "deployment/services/kestra/application.yaml",
    "deployment/services/searxng/settings.yml",
    "deployment/services/hermes/service.unit",
    "deployment/services/hermes/config.yaml.template",
    "deployment/services/hermes/soul.txt",
    "deployment/services/hermes/acceptance-canary.py",
    "deployment/services/hermes/bootstrap-mattermost.py",
    "deployment/steps/host.sh",
    "deployment/steps/paperclip.sh",
    "deployment/steps/daytona.sh",
    "deployment/steps/cloudflare-tunnel.sh",
    "deployment/steps/origin-firewall.sh",
}
LEGACY_STATIC_PATHS = {
    "platform.yaml",
    "platform.lock.yaml",
    "connections.yaml",
    "acceptance-requirements.yaml",
    "dependencies.lock.json",
    "deploy",
    "deployment/compose",
    "deployment/systemd",
    "config/services",
    "hermes",
    "kestra",
    "profiles/profiles.yaml",
}
CANONICAL_DEPLOYMENT_STEPS = {
    "host.sh",
    "paperclip.sh",
    "daytona.sh",
    "resource-preflight.sh",
    "cloudflare-tunnel.sh",
    "origin-firewall.sh",
}
CANONICAL_COMPOSE_PATHS = {
    "deployment/services/9router/compose.yaml",
    "deployment/services/daytona/compose.yaml",
    "deployment/services/firecrawl/compose.yaml",
    "deployment/services/kestra-data/compose.yaml",
    "deployment/services/kestra/compose.yaml",
    "deployment/services/mattermost-db/compose.yaml",
    "deployment/services/mattermost/compose.yaml",
    "deployment/services/observability/compose.yaml",
    "deployment/services/postgres/compose.yaml",
    "deployment/services/postgrest/compose.yaml",
    "deployment/services/searxng/compose.yaml",
    "deployment/services/toolhive/compose.yaml",
}


def documentation_files() -> list[Path]:
    return [
        *(ROOT / name for name in sorted(ROOT_MARKDOWN_ALLOWLIST)),
        *sorted(SYSTEM_SKILL.rglob("*.md")),
    ]


def markdown_targets(document: Path) -> set[Path]:
    targets: set[Path] = set()
    for raw_target in MARKDOWN_LINK.findall(document.read_text()):
        target = raw_target.strip().strip("<>")
        parsed = urlsplit(target)
        if (
            parsed.scheme in EXTERNAL_SCHEMES
            or target.startswith("../../security/")
            or not parsed.path
        ):
            continue
        targets.add((document.parent / unquote(parsed.path)).resolve())
    return targets


def validate_skill_frontmatter_contract(skill_md: Path) -> list[str]:
    """Faithfully mirror the official skill-creator quick validator contract."""
    errors: list[str] = []
    content = skill_md.read_text()
    if not content.startswith("---"):
        return ["No YAML frontmatter found"]

    match = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
    if not match:
        return ["Invalid frontmatter format"]

    try:
        frontmatter = yaml.safe_load(match.group(1))
    except yaml.YAMLError as error:
        return [f"Invalid YAML in frontmatter: {error}"]
    if not isinstance(frontmatter, dict):
        return ["Frontmatter must be a YAML dictionary"]

    allowed = {"name", "description", "license", "allowed-tools", "metadata"}
    unexpected = set(frontmatter) - allowed
    if unexpected:
        errors.append(f"Unexpected frontmatter keys: {sorted(unexpected)}")

    for required in ("name", "description"):
        if required not in frontmatter:
            errors.append(f"Missing {required!r} in frontmatter")

    name = frontmatter.get("name", "")
    if not isinstance(name, str):
        errors.append("Name must be a string")
    else:
        name = name.strip()
        if name and not re.fullmatch(r"[a-z0-9-]+", name):
            errors.append("Name must use hyphen-case")
        if name.startswith("-") or name.endswith("-") or "--" in name:
            errors.append("Name has invalid hyphen placement")
        if len(name) > 64:
            errors.append("Name exceeds 64 characters")

    description = frontmatter.get("description", "")
    if not isinstance(description, str):
        errors.append("Description must be a string")
    else:
        description = description.strip()
        if "<" in description or ">" in description:
            errors.append("Description contains angle brackets")
        if len(description) > 1024:
            errors.append("Description exceeds 1024 characters")

    return errors


class RepositoryLayoutTests(unittest.TestCase):
    def test_python_tooling_is_owned_by_tools_directory(self) -> None:
        self.assertFalse((ROOT / "scripts").exists())
        self.assertFalse((ROOT / "pyproject.toml").exists())
        self.assertFalse((ROOT / "evidence").exists())
        self.assertTrue((ROOT / "tools/platform-cli/platform.py").is_file())
        self.assertTrue((ROOT / "tools/platform-cli/pyproject.toml").is_file())

    def test_root_contains_only_thin_documentation_entrypoints(self) -> None:
        root_markdown = {path.name for path in ROOT.glob("*.md")}
        self.assertEqual(root_markdown, ROOT_MARKDOWN_ALLOWLIST)

    def test_oss_entrypoints_route_to_the_documentation_ssot(self) -> None:
        expected_links = {
            "CONTRIBUTING.md": "skills/system-platform/references/development.md",
            "SECURITY.md": "skills/system-platform/references/security-policy.md",
            "CODE_OF_CONDUCT.md": "SECURITY.md",
            "CHANGELOG.md": "skills/system-platform/references/development.md",
        }
        for relative, target in expected_links.items():
            with self.subTest(relative=relative):
                content = (ROOT / relative).read_text()
                self.assertIn(target, content)
                self.assertTrue((ROOT / target).is_file(), target)

    def test_security_entrypoint_has_private_github_reporting_fallbacks(self) -> None:
        security = (ROOT / "SECURITY.md").read_text()

        self.assertIn("../../security/advisories/new", security)
        self.assertIn("Report a vulnerability", security)
        self.assertIn("draft Security Advisory", security)
        self.assertIn("Request secure vulnerability reporting channel", security)
        self.assertIn("wait for a private channel", security)

    def test_public_docs_do_not_offer_a_generic_legacy_migration_runner(self) -> None:
        migration_docs = (
            ROOT / "README.md",
            SYSTEM_SKILL_REFERENCES / "installation.md",
            SYSTEM_SKILL_REFERENCES / "deployment.md",
            SYSTEM_SKILL_REFERENCES / "backup-upgrade.md",
        )
        for document in migration_docs:
            with self.subTest(document=document.relative_to(ROOT)):
                content = document.read_text()
                self.assertNotIn("migrate-legacy", content)
                self.assertIn("operator-specific", content)
                self.assertIn("proven backup", content)

    def test_system_skill_is_the_single_documentation_source(self) -> None:
        self.assertFalse((ROOT / "docs").exists())
        self.assertTrue((SYSTEM_SKILL / "SKILL.md").is_file())

        allowed_product_inputs = ROOT / "config/profiles/instructions"
        generated_roots = {
            ".git",
            ".pytest_cache",
            ".ruff_cache",
            ".runtime",
            ".venv",
            "build",
            "dist",
            "node_modules",
        }
        misplaced = sorted(
            path.relative_to(ROOT).as_posix()
            for path in ROOT.rglob("*.md")
            if path.relative_to(ROOT).as_posix() not in ROOT_MARKDOWN_ALLOWLIST
            and SYSTEM_SKILL not in path.parents
            # Agent behavior packages are executable profile inputs, not a
            # second operator-documentation tree.
            and PROFILE_VERIFICATION_SKILL not in path.parents
            and allowed_product_inputs not in path.parents
            and not generated_roots.intersection(path.relative_to(ROOT).parts)
        )
        self.assertEqual(misplaced, [], "Markdown documentation outside its owners")

    def test_retired_daytona_patch_packages_stay_absent(self) -> None:
        self.assertFalse((ROOT / "patches/daytona-image-runtime-config").exists())
        self.assertFalse((ROOT / "patches/daytona-immutable-sandbox-image").exists())

    def test_notice_points_to_canonical_legal_sources(self) -> None:
        notice = (ROOT / "NOTICE").read_text()
        canonical_paths = (
            "skills/system-platform/references/third-party.md",
            "config/licenses.lock.json",
            "config/dependencies.lock.json",
        )
        for relative in canonical_paths:
            self.assertIn(relative, notice)
            self.assertTrue((ROOT / relative).is_file(), relative)
        self.assertNotIn("See docs/en/third-party.md", notice)
        self.assertNotIn("and platform.lock.yaml", notice)

    def test_system_skill_is_a_short_one_level_router(self) -> None:
        skill_md = SYSTEM_SKILL / "SKILL.md"
        references = set(SYSTEM_SKILL_REFERENCES.glob("*.md"))
        nested_references = sorted(
            path.relative_to(SYSTEM_SKILL).as_posix()
            for path in SYSTEM_SKILL_REFERENCES.rglob("*.md")
            if path.parent != SYSTEM_SKILL_REFERENCES
        )

        self.assertLessEqual(len(skill_md.read_text().splitlines()), 100)
        self.assertEqual(
            nested_references, [], "Skill references must be one level deep"
        )
        self.assertEqual(
            markdown_targets(skill_md) & set(SYSTEM_SKILL_REFERENCES.rglob("*.md")),
            references,
            "Every reference must be linked directly from SKILL.md",
        )

    def test_system_skill_metadata_and_architecture_asset_exist(self) -> None:
        metadata_path = SYSTEM_SKILL / "agents/openai.yaml"
        architecture = SYSTEM_SKILL / "assets/architecture.html"
        metadata = yaml.safe_load(metadata_path.read_text())
        context7_dependencies = [
            dependency
            for dependency in metadata["dependencies"]["tools"]
            if dependency.get("value") == "context7"
        ]

        self.assertEqual(len(context7_dependencies), 1)
        self.assertEqual(context7_dependencies[0]["type"], "mcp")
        self.assertEqual(
            context7_dependencies[0]["url"], "https://mcp.context7.com/mcp"
        )
        self.assertIn("$system-platform", metadata["interface"]["default_prompt"])
        self.assertTrue(architecture.is_file())
        self.assertIn(
            architecture.resolve(), markdown_targets(SYSTEM_SKILL / "SKILL.md")
        )

    def test_system_skill_passes_official_quick_validation_contract(self) -> None:
        validator = (
            Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
            / "skills/.system/skill-creator/scripts/quick_validate.py"
        )
        if validator.is_file():
            completed = subprocess.run(
                [sys.executable, str(validator), str(SYSTEM_SKILL)],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + completed.stderr,
            )
        else:
            self.assertEqual(
                validate_skill_frontmatter_contract(SYSTEM_SKILL / "SKILL.md"),
                [],
            )

    def test_documentation_migration_targets_exist(self) -> None:
        provenance = SYSTEM_SKILL_REFERENCES / "migration-provenance.md"
        migrations = {
            match.group("previous"): match.group("target")
            for match in MIGRATION_ROW.finditer(provenance.read_text())
        }

        self.assertEqual(set(migrations), MIGRATED_DOCUMENTATION_PATHS)
        missing_targets = sorted(
            target
            for target in migrations.values()
            if not (SYSTEM_SKILL / target).is_file()
        )
        self.assertEqual(missing_targets, [], "Missing documentation migration targets")

    def test_internal_documentation_links_resolve(self) -> None:
        broken: list[str] = []
        for document in documentation_files():
            for linked_path in markdown_targets(document):
                if not linked_path.exists():
                    broken.append(
                        f"{document.relative_to(ROOT)} -> "
                        f"{linked_path.relative_to(ROOT)}"
                    )

        self.assertEqual(broken, [], "Broken internal documentation links")

    def test_documentation_has_no_stale_active_run_claims(self) -> None:
        stale_step_claims: list[str] = []
        active_run_claims: list[str] = []
        for document in documentation_files():
            for line_number, line in enumerate(document.read_text().splitlines(), 1):
                location = f"{document.relative_to(ROOT)}:{line_number}"
                if "39 ordered" in line.lower():
                    stale_step_claims.append(location)
                if "/v1/runs" in line and not NON_ACTIVE_RUN_CONTEXT.search(line):
                    active_run_claims.append(location)

        self.assertEqual(stale_step_claims, [], "Stale deploy step-count claims")
        self.assertEqual(active_run_claims, [], "Active /v1/runs documentation claims")

    def test_evergreen_architecture_routes_live_status_to_evidence(self) -> None:
        architecture = (SYSTEM_SKILL_REFERENCES / "architecture.md").read_text()
        workflows = (SYSTEM_SKILL_REFERENCES / "workflows.md").read_text()
        interactive = (SYSTEM_SKILL / "assets/architecture.html").read_text()
        diagram = (SYSTEM_SKILL / "assets/platform-architecture.svg").read_text()

        self.assertIn("acceptance evidence", architecture)
        self.assertNotIn("Release-host snapshot", architecture)
        self.assertNotIn("LIVE SNAPSHOT", interactive)
        self.assertNotIn("Статус снимка развёртывания", interactive)
        self.assertNotIn("Current release-host status", workflows)
        self.assertIn("fresh, source-bound E2E\n> evidence", workflows)
        self.assertIn("Outbox", diagram)
        self.assertIn("leased connector", diagram)

    def test_public_operational_contracts_bound_recovery_and_edge_scope(self) -> None:
        readme = (ROOT / "README.md").read_text()
        backup = (SYSTEM_SKILL_REFERENCES / "backup-upgrade.md").read_text()
        architecture = (SYSTEM_SKILL_REFERENCES / "architecture.md").read_text()
        connections = (SYSTEM_SKILL_REFERENCES / "connections.md").read_text()
        security = (SYSTEM_SKILL_REFERENCES / "security-ru.md").read_text()

        self.assertIn("first public recovery surface", readme)
        self.assertIn("PITR, off-host backup targets", readme)
        self.assertIn("Compose PostgreSQL logical backup", backup)
        self.assertIn("Non-database and Paperclip-native volume", backup)
        self.assertIn("--confirm-decommission", backup)
        self.assertIn("does not configure", architecture)
        self.assertIn("не создаёт", connections)
        self.assertIn("не конфигурирует", security)

    def test_runbooks_require_exact_restart_and_cancellation_identity(self) -> None:
        operations = (SYSTEM_SKILL_REFERENCES / "operations.md").read_text()
        debugging = (SYSTEM_SKILL_REFERENCES / "debugging.md").read_text()
        installation = (SYSTEM_SKILL_REFERENCES / "installation.md").read_text()

        self.assertIn("SERVICE=paperclip", operations)
        self.assertNotIn("docker restart $ids", operations)
        self.assertIn("authenticated caller identity", operations)
        self.assertIn("active-checkout owner", debugging)
        self.assertIn("git clone <repository-url>", installation)
        self.assertIn("The first-owner checkpoint is deliberately human", installation)

    def test_canonical_contracts_replace_legacy_static_paths(self) -> None:
        missing = sorted(
            relative
            for relative in CANONICAL_CONTRACTS
            if not (ROOT / relative).is_file()
        )
        legacy = sorted(
            relative for relative in LEGACY_STATIC_PATHS if (ROOT / relative).exists()
        )

        self.assertEqual(missing, [], "Missing canonical contracts")
        self.assertEqual(legacy, [], "Legacy static paths remain")
        self.assertFalse(
            (ROOT / "deployment/services/hermes/platform-skill.txt").exists(),
            "Hermes must consume the canonical system-platform skill",
        )

    def test_manifest_owns_every_canonical_compose_file(self) -> None:
        manifest = yaml.safe_load((ROOT / "config/platform.yaml").read_text())
        declared = {
            component["compose"]
            for component in manifest["spec"]["components"]
            if "compose" in component
        }
        actual = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "deployment/services").glob("*/compose.yaml")
        }

        self.assertEqual(actual, CANONICAL_COMPOSE_PATHS)
        self.assertEqual(declared, CANONICAL_COMPOSE_PATHS)
        self.assertEqual(len(actual), 12)
        self.assertTrue(
            all(
                path.startswith("deployment/services/")
                and path.endswith("/compose.yaml")
                for path in declared
            )
        )

    def test_retired_provider_code_exists_only_in_exact_prune_contract(self) -> None:
        forbidden = (
            "noco" + "db",
            "noco" + "docs",
            "base" + "row",
            "wiki" + "js",
            "wiki" + ".js",
            "sustainable" + "-use",
        )
        # Retired providers may only be named by the historical installation
        # reference that explains their removal.
        allowed = {
            "skills/system-platform/references/installation.md",
        }
        generated_roots = {
            ".git",
            ".pytest_cache",
            ".ruff_cache",
            ".runtime",
            ".venv",
            "build",
            "dist",
            "node_modules",
            "__pycache__",
        }
        matches = set()
        for path in ROOT.rglob("*"):
            relative = path.relative_to(ROOT)
            if not path.is_file() or generated_roots.intersection(relative.parts):
                continue
            try:
                content = path.read_text().casefold()
            except (UnicodeDecodeError, OSError):
                continue
            if any(term in content for term in forbidden):
                matches.add(relative.as_posix())

        self.assertEqual(matches, allowed)

    def test_e2e_github_target_is_operator_owned_by_canonical_refs(self) -> None:
        manifest = yaml.safe_load((ROOT / "config/platform.yaml").read_text())
        e2e = manifest["spec"]["e2eCanary"]
        self.assertEqual(
            {
                key: e2e[key]
                for key in (
                    "githubOwnerRef",
                    "githubRepositoryRef",
                    "baseBranchRef",
                )
            },
            {
                "githubOwnerRef": "E2E_GITHUB_OWNER",
                "githubRepositoryRef": "E2E_GITHUB_REPOSITORY",
                "baseBranchRef": "E2E_GITHUB_BASE_BRANCH",
            },
        )
        self.assertTrue(
            {"githubOwner", "githubRepository", "baseBranch"}.isdisjoint(e2e)
        )

    def test_compose_mounts_canonical_service_assets(self) -> None:
        kestra = yaml.safe_load(
            (ROOT / "deployment/services/kestra/compose.yaml").read_text()
        )
        kestra_command = kestra["services"]["kestra"]["command"]
        kestra_volumes = kestra["services"]["kestra"]["volumes"]
        self.assertIn(
            "/opt/mte-platform/config/services/kestra/application.yaml:"
            "/etc/kestra/application.yaml:ro",
            kestra_volumes,
        )
        self.assertNotIn("--flow-path", kestra_command)
        self.assertNotIn("/app/flows", kestra_command)
        self.assertFalse(
            any("workflows/kestra" in volume for volume in kestra_volumes),
            "Kestra workflows must be reconciled through the REST API, not mounted",
        )

        searxng = yaml.safe_load(
            (ROOT / "deployment/services/searxng/compose.yaml").read_text()
        )
        self.assertIn(
            "/opt/mte-platform/config/services/searxng/settings.yml:"
            "/template/settings.yml:ro",
            searxng["services"]["searxng-config-init"]["volumes"],
        )

    def test_runtime_installers_are_exact_semantic_deployment_steps(self) -> None:
        steps = ROOT / "deployment/steps"
        children = {path.name: path for path in steps.iterdir()}
        self.assertEqual(
            set(children),
            CANONICAL_DEPLOYMENT_STEPS,
        )
        self.assertEqual(
            {name for name, path in children.items() if path.is_file()},
            CANONICAL_DEPLOYMENT_STEPS,
        )
        for name in sorted(CANONICAL_DEPLOYMENT_STEPS):
            path = steps / name
            with self.subTest(name=name):
                self.assertTrue(path.read_text().startswith("#!/usr/bin/env bash\n"))
                self.assertEqual(path.stat().st_mode & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main()

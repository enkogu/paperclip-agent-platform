from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "deployment/scripts/provision.sh"
HOST = ROOT / "deployment/scripts/host.sh"
HOST_STEP = ROOT / "deployment/steps/host.sh"
PAPERCLIP = ROOT / "deployment/steps/paperclip.sh"
DAYTONA = ROOT / "deployment/steps/daytona.sh"
RESOURCE_PREFLIGHT = ROOT / "deployment/steps/resource-preflight.sh"


def _fixture(tmp_path: Path) -> tuple[dict[str, str], Path]:
    log = tmp_path / "commands.log"
    cli = tmp_path / "platform"
    cli.write_text(
        f"#!/usr/bin/env bash\nset -eu\nprintf '%s\\n' \"$*\" >> {str(log)!r}\n"
    )
    cli.chmod(0o700)
    compose = tmp_path / "compose"
    compose.write_text(
        f"#!/usr/bin/env bash\nset -eu\nprintf 'compose %s\\n' \"$*\" >> {str(log)!r}\n"
    )
    compose.chmod(0o700)
    return {
        **os.environ,
        "MTE_PLATFORM_CLI": str(cli),
        "MTE_COMPOSE_RECONCILER": str(compose),
    }, log


def test_index_has_explicit_order_and_clean_bash_syntax() -> None:
    subprocess.run(["bash", "-n", INDEX], check=True)
    source = INDEX.read_text()
    expected = [
        "paperclip",
        "kestra",
        "toolhive-profiles",
        "mattermost-hermes",
        "notion-postgres",
        "daytona-harness-auth",
    ]
    positions = [source.index(f"  {group}\n") for group in expected]
    assert positions == sorted(positions)
    assert "server-provision.py" not in source
    assert "server-paperclip-experimental.py" not in source
    assert "API_KEY=" not in source
    assert "TOKEN=" not in source


def test_single_group_is_operator_side_and_forwards_domain(tmp_path: Path) -> None:
    env, log = _fixture(tmp_path)
    subprocess.run(
        [INDEX, "--domain", "agents.example.test", "toolhive/profiles"],
        env=env,
        check=True,
    )
    assert log.read_text().splitlines() == [
        "--domain agents.example.test config render",
        "--domain agents.example.test config audit",
        "--domain agents.example.test provision apply",
        "compose postgrest",
        "compose observability",
        "--domain agents.example.test tools provision",
    ]


def test_all_runs_once_in_order_and_uses_daytona_lifecycle(tmp_path: Path) -> None:
    env, log = _fixture(tmp_path)
    subprocess.run([INDEX], env=env, check=True)
    assert log.read_text().splitlines() == [
        "config render",
        "config audit",
        "runtime paperclip preflight",
        "runtime paperclip config-migrate",
        "runtime paperclip install",
        "profiles apply",
        "paperclip-environments apply",
        "paperclip-secrets apply",
        "provision apply",
        "compose postgrest",
        "compose observability",
        "compose kestra",
        "kestra-control provision",
        "tools provision",
        "hermes install",
        "daytona apply",
        "harness-auth verify",
    ]


def test_daytona_snapshot_apply_is_pull_only_without_build_admission() -> None:
    source = DAYTONA.read_text()
    transaction = source.split("build_images_while_locked() {", 1)[1].split(
        "\nbuild_images() {", 1
    )[0]
    assert "run_resource_preflight" not in transaction
    assert "prepare_sandbox_context" not in transaction
    assert "Image.fromDockerfile" not in transaction
    assert 'safe("MTE_DAYTONA_SANDBOX_IMAGE"' in transaction
    assert "docker run --rm -i" in transaction
    assert str(RESOURCE_PREFLIGHT.name) not in source
    assert "less than 3 GiB RAM available" not in source
    assert "3072" not in source


def test_normal_provision_stops_before_paperclip_config_mutation_when_image_preflight_fails(
    tmp_path: Path,
) -> None:
    env, log = _fixture(tmp_path)
    cli = Path(env["MTE_PLATFORM_CLI"])
    cli.write_text(
        "#!/usr/bin/env bash\n"
        f"printf '%s\\n' \"$*\" >> {str(log)!r}\n"
        "[ \"$*\" != 'runtime paperclip preflight' ]\n"
    )
    result = subprocess.run([INDEX, "paperclip"], env=env, check=False)
    assert result.returncode != 0
    assert log.read_text().splitlines() == [
        "config render",
        "config audit",
        "runtime paperclip preflight",
    ]


def test_failed_observability_reconcile_stops_after_base_provision(
    tmp_path: Path,
) -> None:
    env, log = _fixture(tmp_path)
    compose = Path(env["MTE_COMPOSE_RECONCILER"])
    compose.write_text(
        f"#!/usr/bin/env bash\nprintf 'compose %s\\n' \"$*\" >> {str(log)!r}\nexit 55\n"
    )
    result = subprocess.run([INDEX, "toolhive/profiles"], env=env, check=False)
    assert result.returncode == 55
    assert log.read_text().splitlines() == [
        "config render",
        "config audit",
        "provision apply",
        "compose postgrest",
    ]


def test_unknown_group_is_rejected_before_remote_work(tmp_path: Path) -> None:
    env, log = _fixture(tmp_path)
    result = subprocess.run([INDEX, "unknown"], env=env, check=False)
    assert result.returncode == 2
    assert not log.exists()


def test_host_hardens_before_tool_install_and_later_stages() -> None:
    source = HOST.read_text()
    bootstrap = source.index('"$ROOT/platform" bootstrap')
    firewall = source.index('"$ROOT/platform" cloudflare origin-firewall')
    tools_install = source.index('"$ROOT/platform" tools install')
    assert bootstrap < firewall < tools_install


def test_host_has_one_canonical_pinned_bootstrap_path() -> None:
    source = HOST.read_text()
    assert source.count('"$ROOT/platform" bootstrap') == 1
    assert "apt-get" not in source
    assert "docker.io" not in source
    assert "deployment/steps/host.sh" in source
    host_step = HOST_STEP.read_text()
    assert "docker network create --driver bridge" in host_step
    assert '--subnet "$MTE_CONTROL_NETWORK_SUBNET"' in host_step
    assert '--gateway "$MTE_CONTROL_NETWORK_GATEWAY"' in host_step
    assert "incompatible shared network: mte-control" in host_step


def test_host_control_network_ignores_ambient_values(tmp_path: Path) -> None:
    source = HOST_STEP.read_text()
    function_body = source.split("canonical_value() {", 1)[1].split(
        "\n}\n\nfail()", 1
    )[0]
    assignments = [
        line
        for line in source.splitlines()
        if line
        in {
            "MTE_CONTROL_NETWORK_SUBNET=$(canonical_value MTE_CONTROL_NETWORK_SUBNET)",
            "MTE_CONTROL_NETWORK_GATEWAY=$(canonical_value MTE_CONTROL_NETWORK_GATEWAY)",
        }
    ]
    assert len(assignments) == 2

    canonical = tmp_path / "platform.env"
    canonical.write_text(
        "MTE_CONTROL_NETWORK_SUBNET=172.30.0.0/16\n"
        "MTE_CONTROL_NETWORK_GATEWAY=172.30.0.1\n"
    )
    script = (
        "set -euo pipefail\n"
        f"CONFIG={str(canonical)!r}\n"
        f"canonical_value() {{{function_body}\n}}\n"
        + "\n".join(assignments)
        + "\nprintf '%s\\n' \"$MTE_CONTROL_NETWORK_SUBNET\" \"$MTE_CONTROL_NETWORK_GATEWAY\"\n"
    )
    result = subprocess.run(
        ["bash", "-c", script],
        env={
            **os.environ,
            "MTE_CONTROL_NETWORK_SUBNET": "10.0.0.0/8",
            "MTE_CONTROL_NETWORK_GATEWAY": "10.0.0.1",
        },
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.splitlines() == ["172.30.0.0/16", "172.30.0.1"]


def test_paperclip_runtime_uses_the_immutable_image_native_entrypoint():
    source = PAPERCLIP.read_text()
    assert "MTE_PAPERCLIP_IMAGE" in source
    assert '"$PAPERCLIP_IMAGE" >/dev/null' in source
    assert "mte-paperclip-native-tools" not in source
    assert "npm install" not in source
    assert "node_modules" not in source


def test_paperclip_preflight_rejects_an_incomplete_image_abi():
    source = PAPERCLIP.read_text()
    assert "verify_image_abi" in source
    assert 'command != ["node", "dist/index.js"]' in source
    assert '["@paperclipai/plugin-daytona", process.argv[1]]' in source
    assert '["@daytonaio/sdk", process.argv[2]]' in source
    assert '["@aws-sdk/client-s3", process.argv[3]]' in source
    assert "manifest.version !== expectedVersion" in source
    assert (
        "PAPERCLIP_DAYTONA_SDK_VERSION=$(canonical_value PAPERCLIP_DAYTONA_SDK_VERSION)"
        in source
    )
    assert (
        "PAPERCLIP_AWS_S3_CLIENT_VERSION=$(canonical_value PAPERCLIP_AWS_S3_CLIENT_VERSION)"
        in source
    )
    assert 'labels.get("org.opencontainers.image.source") != expected_source' in source
    assert (
        'labels.get("org.opencontainers.image.revision") != expected_revision' in source
    )


def test_paperclip_auth_dotenv_converges_to_one_real_newline(tmp_path: Path) -> None:
    source = PAPERCLIP.read_text()
    function = source.split("reconcile_auth_secret_projection() {", 1)[1].split(
        "\n}\n\nwait_http()", 1
    )[0]
    target = tmp_path / "paperclip.env"
    script = tmp_path / "reconcile.sh"
    script.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"PAPERCLIP_AUTH_SECRET_FILE={str(target)!r}\n"
        "PAPERCLIP_DEPLOYMENT_MODE=authenticated\n"
        "PAPERCLIP_AGENT_JWT_SECRET=exact-test-value\n"
        'install() { mkdir -p "${@: -1}"; }\n'
        "chown() { :; }\n"
        "reconcile_auth_secret_projection() {" + function + "\n}\n"
        "reconcile_auth_secret_projection\n"
    )
    script.chmod(0o700)
    subprocess.run([script], check=True)
    first = target.read_bytes()
    subprocess.run([script], check=True)
    assert (
        target.read_bytes() == first == b"PAPERCLIP_AGENT_JWT_SECRET=exact-test-value\n"
    )


def test_config_migrate_fails_abi_before_data_or_evidence_mutation(
    tmp_path: Path,
) -> None:
    source = PAPERCLIP.read_text()
    canonical = tmp_path / "platform.env"
    required = set(re.findall(r"canonical_value ([A-Z][A-Z0-9_]*)", source))
    values = {key: "fixture" for key in required}
    values.update(
        {
            "MTE_PAPERCLIP_IMAGE": "example.invalid/paperclip@sha256:" + "a" * 64,
            "MTE_PAPERCLIP_FORK_SOURCE_URL": "https://github.com/example/paperclip-mte",
            "MTE_PAPERCLIP_FORK_REVISION": "b" * 40,
            "PAPERCLIP_DEPLOYMENT_MODE": "local_trusted",
            "PAPERCLIP_DEPLOYMENT_EXPOSURE": "private",
            "DAYTONA_PLUGIN_VERSION": "0.1.0",
            "PAPERCLIP_DAYTONA_SDK_VERSION": "0.171.0",
            "PAPERCLIP_AWS_S3_CLIENT_VERSION": "3.1075.0",
        }
    )
    canonical.write_text("".join(f"{key}={values[key]}\n" for key in sorted(values)))

    script = tmp_path / "paperclip.sh"
    script.write_text(
        source.replace(
            "CANONICAL_ENV='/root/.config/mte-secrets/platform.env'",
            f"CANONICAL_ENV={str(canonical)!r}",
            1,
        ).replace(
            "EVIDENCE_ROOT='/opt/mte-platform/evidence'",
            f"EVIDENCE_ROOT={str(tmp_path / 'evidence')!r}",
            1,
        )
    )
    script.chmod(0o700)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker_log = tmp_path / "docker.log"
    docker = fake_bin / "docker"
    docker.write_text(
        "#!/usr/bin/env bash\n"
        "set -eu\n"
        f"printf '%s\\n' \"$*\" >> {str(docker_log)!r}\n"
        "if [[ $1 == image && $2 == inspect ]]; then\n"
        '  printf \'%s\\n\' \'{"Entrypoint":[],"Cmd":["node","dist/index.js"],"Labels":{}}\'\n'
        "  exit 0\n"
        "fi\n"
        "exit 97\n"
    )
    docker.chmod(0o700)
    env = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"}
    result = subprocess.run(
        [script, "config-migrate"], env=env, check=False, capture_output=True, text=True
    )
    assert result.returncode != 0
    assert "immutable image source label drifted" in result.stderr
    assert not (tmp_path / "evidence").exists()
    assert docker_log.read_text().splitlines() == [
        f"image inspect --format {{{{json .Config}}}} {values['MTE_PAPERCLIP_IMAGE']}"
    ]


def _paperclip_verify_fixture(
    tmp_path: Path,
    *,
    fork_source_url: str = "https://github.com/example/paperclip-mte",
    fork_revision: str = "b" * 40,
) -> tuple[Path, dict[str, str], Path]:
    source = PAPERCLIP.read_text()
    canonical = tmp_path / "platform.env"
    required = set(re.findall(r"canonical_value ([A-Z][A-Z0-9_]*)", source))
    values = {key: "fixture" for key in required}
    values.update(
        {
            "MTE_PAPERCLIP_IMAGE": "example.invalid/paperclip@sha256:" + "a" * 64,
            "MTE_PAPERCLIP_FORK_SOURCE_URL": fork_source_url,
            "MTE_PAPERCLIP_FORK_REVISION": fork_revision,
            "PAPERCLIP_DEPLOYMENT_MODE": "local_trusted",
            "PAPERCLIP_DEPLOYMENT_EXPOSURE": "private",
            "DAYTONA_PLUGIN_VERSION": "0.1.0",
            "PAPERCLIP_DAYTONA_SDK_VERSION": "0.171.0",
            "PAPERCLIP_AWS_S3_CLIENT_VERSION": "3.1075.0",
        }
    )
    canonical.write_text("".join(f"{key}={values[key]}\n" for key in sorted(values)))
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    evidence = evidence_root / "paperclip-runtime-config-verify.json"
    evidence.write_text("sentinel evidence\n")
    script = tmp_path / "paperclip.sh"
    script.write_text(
        source.replace(
            "CANONICAL_ENV='/root/.config/mte-secrets/platform.env'",
            f"CANONICAL_ENV={str(canonical)!r}",
            1,
        ).replace(
            "EVIDENCE_ROOT='/opt/mte-platform/evidence'",
            f"EVIDENCE_ROOT={str(evidence_root)!r}",
            1,
        )
    )
    script.chmod(0o700)
    return script, values, evidence


def test_paperclip_runtime_rejects_invalid_fork_evidence_before_docker_mutation(
    tmp_path: Path,
) -> None:
    script, _values, evidence = _paperclip_verify_fixture(
        tmp_path, fork_revision="B" * 40
    )
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker_log = tmp_path / "docker.log"
    docker = fake_bin / "docker"
    docker.write_text(
        "#!/usr/bin/env bash\n"
        f"printf '%s\\n' \"$*\" >> {str(docker_log)!r}\n"
        "exit 99\n"
    )
    docker.chmod(0o700)

    result = subprocess.run(
        [script, "install"],
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "MTE_PAPERCLIP_FORK_REVISION" in result.stderr
    assert evidence.read_text() == "sentinel evidence\n"
    assert not docker_log.exists()


def test_verify_fails_abi_before_evidence_mutation(tmp_path: Path) -> None:
    script, values, evidence = _paperclip_verify_fixture(tmp_path)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker_log = tmp_path / "docker.log"
    docker = fake_bin / "docker"
    docker.write_text(
        "#!/usr/bin/env bash\n"
        "set -eu\n"
        f"printf '%s\\n' \"$*\" >> {str(docker_log)!r}\n"
        "if [[ $1 == image && $2 == inspect ]]; then\n"
        "  printf '%s\\n' '{\"Entrypoint\":[],\"Cmd\":[\"node\",\"wrong.js\"],\"Labels\":{}}'\n"
        "  exit 0\n"
        "fi\n"
        "exit 97\n"
    )
    docker.chmod(0o700)
    env = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"}

    result = subprocess.run(
        [script, "verify"], env=env, check=False, capture_output=True, text=True
    )

    assert result.returncode != 0
    assert "immutable image native command ABI drifted" in result.stderr
    assert evidence.read_text() == "sentinel evidence\n"
    assert docker_log.read_text().splitlines() == [
        f"image inspect --format {{{{json .Config}}}} {values['MTE_PAPERCLIP_IMAGE']}"
    ]


def test_verify_rejects_wrong_running_image_before_evidence_mutation(
    tmp_path: Path,
) -> None:
    script, values, evidence = _paperclip_verify_fixture(tmp_path)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker_log = tmp_path / "docker.log"
    canonical_id = "sha256:" + "b" * 64
    docker = fake_bin / "docker"
    docker.write_text(
        "#!/usr/bin/env bash\n"
        "set -eu\n"
        "if [[ $1 == image && $2 == inspect && $3 == --format ]]; then\n"
        "  if [[ $4 == '{{json .Config}}' ]]; then\n"
        f"    printf '%s\\n' abi-inspect >> {str(docker_log)!r}\n"
        "    printf '%s\\n' "
        f"'{{\"Entrypoint\":[],\"Cmd\":[\"node\",\"dist/index.js\"],\"Labels\":{{\"org.opencontainers.image.source\":\"{values['MTE_PAPERCLIP_FORK_SOURCE_URL']}\",\"org.opencontainers.image.revision\":\"{values['MTE_PAPERCLIP_FORK_REVISION']}\"}}}}'\n"
        "  else\n"
        f"    printf '%s\\n' image-id-inspect >> {str(docker_log)!r}\n"
        f"    printf '%s\\n' '{canonical_id}'\n"
        "  fi\n"
        "  exit 0\n"
        "fi\n"
        "if [[ $1 == run ]]; then\n"
        f"  printf '%s\\n' abi-run >> {str(docker_log)!r}\n"
        "  exit 0\n"
        "fi\n"
        "if [[ $1 == inspect && $2 == --format && $3 == '{{.Config.Image}}' ]]; then\n"
        f"  printf '%s\\n' container-ref-inspect >> {str(docker_log)!r}\n"
        f"  printf '%s\\n' '{values['MTE_PAPERCLIP_IMAGE']}'\n"
        "  exit 0\n"
        "fi\n"
        "if [[ $1 == inspect && $2 == --format && $3 == '{{.Image}}' ]]; then\n"
        f"  printf '%s\\n' container-id-inspect >> {str(docker_log)!r}\n"
        "  printf '%s\\n' 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'\n"
        "  exit 0\n"
        "fi\n"
        "exit 97\n"
    )
    docker.chmod(0o700)
    env = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"}

    result = subprocess.run(
        [script, "verify"], env=env, check=False, capture_output=True, text=True
    )

    assert result.returncode != 0
    assert "running container image ID does not match" in result.stderr
    assert evidence.read_text() == "sentinel evidence\n"
    assert docker_log.read_text().splitlines() == [
        "abi-inspect",
        "abi-run",
        "image-id-inspect",
        "container-ref-inspect",
        "container-id-inspect",
    ]


def test_paperclip_runtime_has_data_auth_and_lan_contract():
    source = PAPERCLIP.read_text()
    assert "PAPERCLIP_HOME=/data" in source
    assert "PAPERCLIP_BIND=lan" in source
    assert "/data/instances/default/.env:ro" in source
    assert "PAPERCLIP_AGENT_JWT_SECRET=" in source


def test_paperclip_runtime_passes_direct_daytona_upstream_without_proxy():
    source = PAPERCLIP.read_text()
    assert (
        '-e PAPERCLIP_DAYTONA_UPSTREAM_URL="$PAPERCLIP_DAYTONA_UPSTREAM_URL"' in source
    )
    assert "mte-daytona-loopback-proxy" not in source


def test_kestra_is_reconciled_after_paperclip_service_key_provisioning():
    source = INDEX.read_text().split("kestra)", 1)[1].split(";;", 1)[0]
    assert source.index('"${COMPOSE_RECONCILER}" kestra') < source.index(
        "platform kestra-control provision"
    )

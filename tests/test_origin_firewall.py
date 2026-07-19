from __future__ import annotations

import importlib.util
import ipaddress
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment/steps/origin-firewall.sh"


def load_server_config():
    path = ROOT / "tools/platform-cli/server-config.py"
    spec = importlib.util.spec_from_file_location("firewall_server_config", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class OriginFirewallShellContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text()

    def test_shell_syntax_is_valid(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(SCRIPT)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_permission_mask_accepts_0600_and_rejects_0644_at_runtime(self) -> None:
        function_source = self.source.split("\nrequire_root\nrequire_tools\n", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            functions = root / "origin-firewall-functions.sh"
            functions.write_text(function_source)
            config = root / "platform.env"
            config.write_text("MTE_OPERATOR_SSH_CIDRS=203.0.113.0/24\n")

            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_mode = fake_bin / "mode"
            fake_stat = fake_bin / "stat"
            fake_stat.write_text(
                "#!/bin/sh\n"
                "case $2 in\n"
                "  %u) printf '0\\n' ;;\n"
                "  %a) cat \"${0%/*}/mode\" ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n"
            )
            fake_stat.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
            }

            def normalized_cidrs(mode: int) -> subprocess.CompletedProcess[str]:
                config.chmod(mode)
                fake_mode.write_text(f"{mode:o}\n")
                return subprocess.run(
                    [
                        "/bin/bash",
                        "-c",
                        'source "$1"; CONFIG="$2"; normalized_cidrs',
                        "origin-firewall-test",
                        str(functions),
                        str(config),
                    ],
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )

            secure = normalized_cidrs(0o600)
            self.assertEqual(secure.returncode, 0, secure.stderr)
            self.assertEqual(secure.stdout, "4\t203.0.113.0/24\n")

            exposed = normalized_cidrs(0o644)
            self.assertNotEqual(exposed.returncode, 0)
            self.assertIn(
                "canonical config must not be group/world accessible",
                exposed.stderr,
            )

    def test_ipv4_and_ipv6_cover_host_and_docker_tcp_and_udp(self) -> None:
        source = self.source
        self.assertIn('reconcile_family iptables 4 "$interface_v4"', source)
        self.assertIn('reconcile_family ip6tables 6 "$interface_v6"', source)
        self.assertIn('"$tool" -w -I INPUT 1', source)
        self.assertIn('"$tool" -w -I DOCKER-USER 1', source)
        self.assertIn(
            '-p tcp \\\n    -m comment --comment "$TCP_DROP_COMMENT" -j DROP',
            source,
        )
        self.assertIn(
            '-p udp \\\n    -m comment --comment "$UDP_DROP_COMMENT" -j DROP',
            source,
        )
        self.assertNotIn("PORTS='80,443,3000'", source)
        self.assertNotIn("--dports", source)

    def test_managed_rule_parser_runs_on_system_awk(self) -> None:
        function_source = self.source.split("\nrequire_root\nrequire_tools\n", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            functions = Path(temporary) / "origin-firewall-functions.sh"
            functions.write_text(function_source)
            completed = subprocess.run(
                [
                    "bash",
                    "-c",
                    (
                        'source "$1"; '
                        "fake_tool() { printf '%s\\n' "
                        "'-A INPUT -i eth0 -m comment --comment "
                        'mte-origin-v2-input -j MTEOIabcdef123456\'; }; '
                        "line=$(managed_jump_lines fake_tool INPUT "
                        "mte-origin-v2-input); "
                        'test "$(jump_target "$line")" = MTEOIabcdef123456'
                    ),
                    "origin-firewall-parser-test",
                    str(functions),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_policy_recovers_after_docker_restart_and_periodic_drift(self) -> None:
        self.assertIn("SELF='/usr/local/libexec/mte-origin-firewall'", self.source)
        self.assertIn('install -o root -g root -m 0700 "$source_self"', self.source)
        self.assertIn("PartOf=docker.service", self.source)
        self.assertIn("ExecStart=$SELF recover", self.source)
        self.assertIn("OnUnitInactiveSec=15s", self.source)
        self.assertIn(
            "systemctl enable --now mte-cloudflare-origin-firewall-recover.timer",
            self.source,
        )
        self.assertIn('"firewallRecoveryTimerActive"', self.source)
        self.assertIn('"firewallRecoveryTimerEnabled"', self.source)

    def test_apply_releases_reconciliation_lock_before_systemd_restart(self) -> None:
        apply_block = self.source.split("  apply)\n", 1)[1].split("    ;;", 1)[0]
        self.assertLess(
            apply_block.index("flock -u 9"),
            apply_block.index("systemctl restart"),
        )
        self.assertLess(
            apply_block.index("systemctl restart"),
            apply_block.index("flock -x 9"),
        )

    def test_ssh_allowlist_and_established_session_precede_default_deny(self) -> None:
        body = self.source.split("build_input_chain()", 1)[1].split(
            "build_forward_chain()", 1
        )[0]
        established = body.index("--ctstate ESTABLISHED,RELATED")
        ssh_allow = body.index('-s "$cidr" --dport 22')
        tcp_drop = body.index('comment --comment "$TCP_DROP_COMMENT" -j DROP')
        udp_drop = body.index('comment --comment "$UDP_DROP_COMMENT" -j DROP')
        self.assertLess(established, ssh_allow)
        self.assertLess(ssh_allow, tcp_drop)
        self.assertLess(tcp_drop, udp_drop)
        self.assertIn("current SSH client is not covered", self.source)

    def test_recovery_attaches_complete_policy_before_removing_stale_policy(
        self,
    ) -> None:
        body = self.source.split("reconcile_family()", 1)[1].split("enforce()", 1)[0]
        input_attach = body.index('"$tool" -w -I INPUT 1')
        forward_attach = body.index('"$tool" -w -I DOCKER-USER 1')
        cleanup = body.index("cleanup_managed_jumps")
        self.assertLess(input_attach, cleanup)
        self.assertLess(forward_attach, cleanup)
        self.assertIn("enforce | recover)", self.source)
        self.assertIn("flock -x 9", self.source)

    def test_status_exposes_strict_v2_evidence_without_cidr_values(self) -> None:
        required_fields = {
            "firewallPolicyVersion",
            "firewallServiceActive",
            "firewallServiceEnabled",
            "firewallRecoveryTimerActive",
            "firewallRecoveryTimerEnabled",
            "publicInterface",
            "operatorSshCidrsSha256",
            "firewallSshCidrCount",
            "firewallSshIpv4CidrCount",
            "firewallSshIpv6CidrCount",
            "firewallSshCidrsEnforced",
            "firewallV4Established",
            "firewallV6Established",
            "firewallV4InputTcpDrop",
            "firewallV4InputUdpDrop",
            "firewallV4DockerTcpDrop",
            "firewallV4DockerUdpDrop",
            "firewallV6InputTcpDrop",
            "firewallV6InputUdpDrop",
            "firewallV6DockerTcpDrop",
            "firewallV6DockerUdpDrop",
            "udp443Blocked",
            "publicTcpDefaultDenied",
            "publicUdpDefaultDenied",
        }
        for field in required_fields:
            with self.subTest(field=field):
                self.assertIn(f'"{field}"', self.source)
        self.assertNotIn('"operatorSshCidrs":', self.source)


class OriginFirewallConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_server_config()

    def test_operator_cidrs_are_required_by_the_manifest(self) -> None:
        manifest = yaml.safe_load((ROOT / "config/platform.yaml").read_text())
        self.assertEqual(
            manifest["spec"]["host"]["sshAllowedCidrsRef"],
            "MTE_OPERATOR_SSH_CIDRS",
        )
        self.assertIn(
            "MTE_OPERATOR_SSH_CIDRS",
            self.config.REQUIRED_OPERATOR_BOOTSTRAP_KEYS,
        )

    def test_cidr_normalization_is_strict_and_dual_stack(self) -> None:
        normalized = self.config.normalize_operator_ssh_cidrs(
            "203.0.113.0/24,2001:db8::/32,203.0.113.0/24"
        )
        self.assertEqual(normalized, "2001:db8::/32,203.0.113.0/24")
        for cidr in normalized.split(","):
            self.assertFalse(ipaddress.ip_network(cidr).is_global)
        with self.assertRaisesRegex(
            self.config.ConfigError, "must contain at least one CIDR"
        ):
            self.config.normalize_operator_ssh_cidrs("")
        with self.assertRaisesRegex(self.config.ConfigError, "invalid CIDR"):
            self.config.normalize_operator_ssh_cidrs("203.0.113.9/24")
        with self.assertRaisesRegex(self.config.ConfigError, "invalid CIDR"):
            self.config.normalize_operator_ssh_cidrs("not-a-network")

    def test_public_example_uses_only_documentation_cidrs(self) -> None:
        values: dict[str, str] = {}
        for raw in (ROOT / "config/platform.env.example").read_text().splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        cidrs = values["MTE_OPERATOR_SSH_CIDRS"].split(",")
        self.assertEqual(
            values["MTE_OPERATOR_SSH_CIDRS"],
            self.config.normalize_operator_ssh_cidrs(values["MTE_OPERATOR_SSH_CIDRS"]),
        )
        self.assertTrue(cidrs)
        self.assertTrue(all(not ipaddress.ip_network(cidr).is_global for cidr in cidrs))


if __name__ == "__main__":
    unittest.main()

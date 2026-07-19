#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-apply}
POLICY_VERSION='mte-origin-firewall/v2'
CONFIG='/root/.config/mte-secrets/platform.env'
UNIT='/etc/systemd/system/mte-cloudflare-origin-firewall.service'
RECOVERY_UNIT='/etc/systemd/system/mte-cloudflare-origin-firewall-recover.service'
RECOVERY_TIMER='/etc/systemd/system/mte-cloudflare-origin-firewall-recover.timer'
SELF='/usr/local/libexec/mte-origin-firewall'
LOCK='/run/lock/mte-cloudflare-origin-firewall.lock'
INPUT_COMMENT='mte-origin-v2-input'
FORWARD_COMMENT='mte-origin-v2-forward'
ESTABLISHED_COMMENT='mte-origin-v2-established'
SSH_COMMENT='mte-origin-v2-ssh'
TCP_DROP_COMMENT='mte-origin-v2-tcp-drop'
UDP_DROP_COMMENT='mte-origin-v2-udp-drop'

die() {
  printf 'origin firewall: %s\n' "$*" >&2
  exit 1
}

require_root() {
  test "$(id -u)" -eq 0 || die 'must run as root'
}

require_tools() {
  local tool
  for tool in awk flock install ip iptables ip6tables python3 readlink sha256sum stat systemctl; do
    command -v "$tool" >/dev/null 2>&1 || die "required command is missing: $tool"
  done
}

public_interface_v4() {
  ip -4 route show default | awk 'NR == 1 {print $5}'
}

public_interface_v6() {
  local interface
  interface=$(ip -6 route show default | awk 'NR == 1 {print $5}')
  if test -n "$interface"; then
    printf '%s\n' "$interface"
  else
    public_interface_v4
  fi
}

validate_interface() {
  [[ $1 =~ ^[A-Za-z0-9_.:-]+$ ]] || die 'public interface name is invalid'
}

normalized_cidrs() {
  local owner mode
  test -f "$CONFIG" || die "canonical config is missing: $CONFIG"
  test ! -L "$CONFIG" || die 'canonical config must not be a symlink'
  owner=$(stat -c '%u' "$CONFIG")
  mode=$(stat -c '%a' "$CONFIG")
  test "$owner" -eq 0 || die 'canonical config must be owned by root'
  (((8#$mode & 077) == 0)) || die 'canonical config must not be group/world accessible'
  python3 - "$CONFIG" <<'PY'
from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
matches: list[str] = []
for raw in path.read_text().splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    if key.strip() == "MTE_OPERATOR_SSH_CIDRS":
        matches.append(value.strip())
if len(matches) != 1:
    raise SystemExit("MTE_OPERATOR_SSH_CIDRS must occur exactly once")
raw_value = matches[0]
if not raw_value:
    raise SystemExit("MTE_OPERATOR_SSH_CIDRS must not be empty")
if raw_value[:1] in {'"', "'"} and raw_value[-1:] == raw_value[:1]:
    raw_value = raw_value[1:-1]
tokens = [item for item in re.split(r"[\s,]+", raw_value) if item]
if not tokens:
    raise SystemExit("MTE_OPERATOR_SSH_CIDRS must contain a CIDR")
normalized: list[str] = []
for token in tokens:
    try:
        network = ipaddress.ip_network(token, strict=True)
    except ValueError as error:
        raise SystemExit(f"invalid operator SSH CIDR: {token}: {error}") from error
    normalized.append(str(network))
normalized = sorted(set(normalized))
canonical = ",".join(normalized)
if raw_value != canonical:
    raise SystemExit(
        "MTE_OPERATOR_SSH_CIDRS must be sorted, unique, normalized and comma-separated: "
        + canonical
    )
for cidr in normalized:
    family = ipaddress.ip_network(cidr).version
    print(f"{family}\t{cidr}")
PY
}

load_cidrs() {
  local temporary family cidr
  temporary=$(mktemp)
  if ! normalized_cidrs >"$temporary"; then
    rm -f "$temporary"
    die 'operator SSH CIDR validation failed'
  fi
  IPV4_CIDRS=()
  IPV6_CIDRS=()
  while IFS=$'\t' read -r family cidr; do
    case "$family" in
      4) IPV4_CIDRS+=("$cidr") ;;
      6) IPV6_CIDRS+=("$cidr") ;;
      *)
        die 'unexpected operator SSH CIDR family'
        ;;
    esac
  done <"$temporary"
  rm -f "$temporary"
  ((${#IPV4_CIDRS[@]} + ${#IPV6_CIDRS[@]} > 0)) ||
    die 'at least one operator SSH CIDR is required'
}

assert_current_ssh_allowed() {
  local connection=${SSH_CONNECTION:-} client_ip
  test -z "$connection" && return 0
  client_ip=${connection%% *}
  python3 - "$client_ip" "${IPV4_CIDRS[@]}" "${IPV6_CIDRS[@]}" <<'PY'
import ipaddress
import sys

address = ipaddress.ip_address(sys.argv[1])
networks = [ipaddress.ip_network(value) for value in sys.argv[2:]]
if not any(address in network for network in networks):
    raise SystemExit("current SSH client is not covered by MTE_OPERATOR_SSH_CIDRS")
PY
}

create_chain() {
  local tool=$1 prefix=$2 seed chain attempt
  for attempt in 1 2 3 4 5; do
    seed=$(printf '%s:%s:%s:%s' "$prefix" "$$" "$(date +%s%N)" "$attempt" | sha256sum)
    chain="${prefix}${seed:0:12}"
    if "$tool" -w -N "$chain" >/dev/null 2>&1; then
      printf '%s\n' "$chain"
      return 0
    fi
  done
  die "unable to allocate managed chain for $tool"
}

managed_jump_lines() {
  local tool=$1 base=$2 comment=$3
  "$tool" -w -S "$base" | awk -v base="$base" -v marker="$comment" '
    $1 == "-A" && $2 == base {
      for (field = 1; field <= NF; field++) {
        if ($field == "--comment" && $(field + 1) == marker) print $0
      }
    }
  '
}

jump_target() {
  awk '{for (field = 1; field <= NF; field++) if ($field == "-j") print $(field + 1)}' <<<"$1"
}

first_jump_target() {
  local tool=$1 base=$2
  "$tool" -w -S "$base" | awk '
    $1 == "-A" {
      for (field = 1; field <= NF; field++) {
        if ($field == "-j") {
          print $(field + 1)
          exit
        }
      }
      exit
    }
  '
}

delete_jump_line() {
  local tool=$1 base=$2 line=$3
  local -a rule
  read -r -a rule <<<"${line#-A "$base" }"
  "$tool" -w -D "$base" "${rule[@]}"
}

build_input_chain() {
  local tool=$1 chain=$2 family=$3 interface=$4 cidr
  local -a cidrs
  if test "$family" = 4; then
    cidrs=("${IPV4_CIDRS[@]}")
  else
    cidrs=("${IPV6_CIDRS[@]}")
  fi
  "$tool" -w -A "$chain" -i "$interface" -m conntrack \
    --ctstate ESTABLISHED,RELATED -m comment --comment "$ESTABLISHED_COMMENT" -j ACCEPT || return
  for cidr in "${cidrs[@]}"; do
    "$tool" -w -A "$chain" -i "$interface" -p tcp -s "$cidr" --dport 22 \
      -m conntrack --ctstate NEW -m comment --comment "$SSH_COMMENT" -j ACCEPT || return
  done
  "$tool" -w -A "$chain" -i "$interface" -p tcp \
    -m comment --comment "$TCP_DROP_COMMENT" -j DROP || return
  "$tool" -w -A "$chain" -i "$interface" -p udp \
    -m comment --comment "$UDP_DROP_COMMENT" -j DROP || return
}

build_forward_chain() {
  local tool=$1 chain=$2 interface=$3
  "$tool" -w -A "$chain" -i "$interface" -m conntrack \
    --ctstate ESTABLISHED,RELATED -m comment --comment "$ESTABLISHED_COMMENT" -j ACCEPT || return
  "$tool" -w -A "$chain" -i "$interface" -p tcp \
    -m comment --comment "$TCP_DROP_COMMENT" -j DROP || return
  "$tool" -w -A "$chain" -i "$interface" -p udp \
    -m comment --comment "$UDP_DROP_COMMENT" -j DROP || return
}

cleanup_managed_jumps() {
  local tool=$1 base=$2 comment=$3 keep=$4 line target kept=false
  local -a lines=()
  mapfile -t lines < <(managed_jump_lines "$tool" "$base" "$comment")
  for line in "${lines[@]}"; do
    target=$(jump_target "$line")
    if test "$target" = "$keep" && test "$kept" = false; then
      kept=true
      continue
    fi
    delete_jump_line "$tool" "$base" "$line"
    if [[ $target =~ ^MTEO(I|F)[A-Fa-f0-9]{12}$ ]] && test "$target" != "$keep"; then
      "$tool" -w -F "$target" >/dev/null 2>&1 || true
      "$tool" -w -X "$target" >/dev/null 2>&1 || true
    fi
  done
}

cleanup_orphan_chains() {
  local tool=$1 keep_input=${2:-} keep_forward=${3:-} chain
  while read -r chain; do
    [[ $chain =~ ^MTEO(I|F)[A-Fa-f0-9]{12}$ ]] || continue
    test "$chain" = "$keep_input" && continue
    test "$chain" = "$keep_forward" && continue
    "$tool" -w -F "$chain" >/dev/null 2>&1 || true
    "$tool" -w -X "$chain" >/dev/null 2>&1 || true
  done < <("$tool" -w -S | awk '$1 == "-N" {print $2}')
}

discard_new_chains() {
  local tool=$1 input_chain=$2 forward_chain=$3
  "$tool" -w -F "$input_chain" >/dev/null 2>&1 || true
  "$tool" -w -X "$input_chain" >/dev/null 2>&1 || true
  "$tool" -w -F "$forward_chain" >/dev/null 2>&1 || true
  "$tool" -w -X "$forward_chain" >/dev/null 2>&1 || true
}

ensure_docker_user_first() {
  local tool=$1
  "$tool" -w -S DOCKER-USER >/dev/null 2>&1 || "$tool" -w -N DOCKER-USER
  if test "$(first_jump_target "$tool" FORWARD)" != DOCKER-USER; then
    "$tool" -w -I FORWARD 1 -j DOCKER-USER
  fi
}

reconcile_family() {
  local tool=$1 family=$2 interface=$3 input_chain forward_chain
  local -a input_jump forward_jump
  input_chain=$(create_chain "$tool" MTEOI)
  forward_chain=$(create_chain "$tool" MTEOF)
  if ! build_input_chain "$tool" "$input_chain" "$family" "$interface" ||
    ! build_forward_chain "$tool" "$forward_chain" "$interface"; then
    discard_new_chains "$tool" "$input_chain" "$forward_chain"
    return 1
  fi
  input_jump=(-i "$interface" -m comment --comment "$INPUT_COMMENT" -j "$input_chain")
  forward_jump=(-i "$interface" -m comment --comment "$FORWARD_COMMENT" -j "$forward_chain")
  "$tool" -w -I INPUT 1 "${input_jump[@]}"
  ensure_docker_user_first "$tool"
  "$tool" -w -I DOCKER-USER 1 "${forward_jump[@]}"
  cleanup_managed_jumps "$tool" INPUT "$INPUT_COMMENT" "$input_chain"
  cleanup_managed_jumps "$tool" DOCKER-USER "$FORWARD_COMMENT" "$forward_chain"
  cleanup_orphan_chains "$tool" "$input_chain" "$forward_chain"
}

enforce() {
  local interface_v4 interface_v6
  load_cidrs
  assert_current_ssh_allowed
  interface_v4=$(public_interface_v4)
  interface_v6=$(public_interface_v6)
  test -n "$interface_v4" || die 'IPv4 public interface is missing'
  test -n "$interface_v6" || die 'IPv6 public interface is missing'
  validate_interface "$interface_v4"
  validate_interface "$interface_v6"
  if family_status iptables 4 "$interface_v4" &&
    family_status ip6tables 6 "$interface_v6"; then
    return 0
  fi
  reconcile_family iptables 4 "$interface_v4"
  reconcile_family ip6tables 6 "$interface_v6"
}

install_unit() {
  local source_self runtime_temporary temporary recovery_temporary timer_temporary
  source_self=$(readlink -f "$0")
  test -f "$source_self" && test ! -L "$source_self" || die 'firewall producer is unsafe'
  install -d -o root -g root -m 0755 "$(dirname "$SELF")"
  runtime_temporary=$(mktemp "$(dirname "$SELF")/.mte-origin-firewall.XXXXXX")
  install -o root -g root -m 0700 "$source_self" "$runtime_temporary"
  mv "$runtime_temporary" "$SELF"
  temporary=$(mktemp /etc/systemd/system/.mte-cloudflare-origin-firewall.XXXXXX)
  cat >"$temporary" <<EOF
[Unit]
Description=Paperclip Agent Platform Cloudflare origin firewall
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service
PartOf=docker.service

[Service]
Type=oneshot
ExecStart=$SELF enforce
ExecReload=$SELF recover
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "$temporary"
  mv "$temporary" "$UNIT"

  recovery_temporary=$(mktemp /etc/systemd/system/.mte-cloudflare-origin-firewall-recover.XXXXXX)
  cat >"$recovery_temporary" <<EOF
[Unit]
Description=Reconcile Paperclip Agent Platform origin firewall
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=$SELF recover
EOF
  chmod 0644 "$recovery_temporary"
  mv "$recovery_temporary" "$RECOVERY_UNIT"

  timer_temporary=$(mktemp /etc/systemd/system/.mte-cloudflare-origin-firewall-recover-timer.XXXXXX)
  cat >"$timer_temporary" <<'EOF'
[Unit]
Description=Periodically verify and recover the Paperclip origin firewall

[Timer]
OnBootSec=30s
OnUnitInactiveSec=15s
AccuracySec=10s
Unit=mte-cloudflare-origin-firewall-recover.service

[Install]
WantedBy=timers.target
EOF
  chmod 0644 "$timer_temporary"
  mv "$timer_temporary" "$RECOVERY_TIMER"
  systemctl daemon-reload
  systemctl enable mte-cloudflare-origin-firewall.service >/dev/null
  systemctl enable --now mte-cloudflare-origin-firewall-recover.timer >/dev/null
}

current_target() {
  local tool=$1 base=$2 comment=$3 lines count
  lines=$(managed_jump_lines "$tool" "$base" "$comment")
  count=$(awk 'NF {count++} END {print count + 0}' <<<"$lines")
  test "$count" -eq 1 || return 1
  jump_target "$lines"
}

chain_rule_count() {
  local tool=$1 chain=$2
  "$tool" -w -S "$chain" | awk '$1 == "-A" {count++} END {print count + 0}'
}

family_status() {
  local tool=$1 family=$2 interface=$3 input_chain forward_chain cidr
  local -a cidrs
  if test "$family" = 4; then
    cidrs=("${IPV4_CIDRS[@]}")
  else
    cidrs=("${IPV6_CIDRS[@]}")
  fi
  input_chain=$(current_target "$tool" INPUT "$INPUT_COMMENT") || return 1
  forward_chain=$(current_target "$tool" DOCKER-USER "$FORWARD_COMMENT") || return 1
  [[ $input_chain =~ ^MTEOI[A-Fa-f0-9]{12}$ ]] || return 1
  [[ $forward_chain =~ ^MTEOF[A-Fa-f0-9]{12}$ ]] || return 1
  test "$(first_jump_target "$tool" INPUT)" = "$input_chain" || return 1
  test "$(first_jump_target "$tool" FORWARD)" = DOCKER-USER || return 1
  test "$(first_jump_target "$tool" DOCKER-USER)" = "$forward_chain" || return 1
  "$tool" -w -C "$input_chain" -i "$interface" -m conntrack \
    --ctstate ESTABLISHED,RELATED -m comment --comment "$ESTABLISHED_COMMENT" -j ACCEPT || return 1
  "$tool" -w -C "$forward_chain" -i "$interface" -m conntrack \
    --ctstate ESTABLISHED,RELATED -m comment --comment "$ESTABLISHED_COMMENT" -j ACCEPT || return 1
  for cidr in "${cidrs[@]}"; do
    "$tool" -w -C "$input_chain" -i "$interface" -p tcp -s "$cidr" --dport 22 \
      -m conntrack --ctstate NEW -m comment --comment "$SSH_COMMENT" -j ACCEPT || return 1
  done
  "$tool" -w -C "$input_chain" -i "$interface" -p tcp \
    -m comment --comment "$TCP_DROP_COMMENT" -j DROP || return 1
  "$tool" -w -C "$input_chain" -i "$interface" -p udp \
    -m comment --comment "$UDP_DROP_COMMENT" -j DROP || return 1
  "$tool" -w -C "$forward_chain" -i "$interface" -p tcp \
    -m comment --comment "$TCP_DROP_COMMENT" -j DROP || return 1
  "$tool" -w -C "$forward_chain" -i "$interface" -p udp \
    -m comment --comment "$UDP_DROP_COMMENT" -j DROP || return 1
  test "$(chain_rule_count "$tool" "$input_chain")" -eq "$((3 + ${#cidrs[@]}))" || return 1
  test "$(chain_rule_count "$tool" "$forward_chain")" -eq 3 || return 1
}

status_rules() {
  local interface_v4 interface_v6 normalized fingerprint active=false enabled=false timer_active=false timer_enabled=false
  load_cidrs
  interface_v4=$(public_interface_v4)
  interface_v6=$(public_interface_v6)
  validate_interface "$interface_v4"
  validate_interface "$interface_v6"
  systemctl is-active mte-cloudflare-origin-firewall.service >/dev/null 2>&1 && active=true
  systemctl is-enabled mte-cloudflare-origin-firewall.service >/dev/null 2>&1 && enabled=true
  systemctl is-active mte-cloudflare-origin-firewall-recover.timer >/dev/null 2>&1 && timer_active=true
  systemctl is-enabled mte-cloudflare-origin-firewall-recover.timer >/dev/null 2>&1 && timer_enabled=true
  normalized=$(printf '%s\n' "${IPV4_CIDRS[@]}" "${IPV6_CIDRS[@]}" | LC_ALL=C sort)
  fingerprint=$(printf '%s' "$normalized" | sha256sum | awk '{print $1}')
  family_status iptables 4 "$interface_v4"
  family_status ip6tables 6 "$interface_v6"
  printf '{"firewallPolicyVersion":"%s","firewallServiceActive":%s,"firewallServiceEnabled":%s,' \
    "$POLICY_VERSION" "$active" "$enabled"
  printf '"firewallRecoveryTimerActive":%s,"firewallRecoveryTimerEnabled":%s,' \
    "$timer_active" "$timer_enabled"
  printf '"publicInterface":"%s","publicInterfaceV4":"%s","publicInterfaceV6":"%s",' \
    "$interface_v4" "$interface_v4" "$interface_v6"
  printf '"operatorSshCidrsSha256":"%s","firewallSshCidrCount":%d,' \
    "$fingerprint" "$((${#IPV4_CIDRS[@]} + ${#IPV6_CIDRS[@]}))"
  printf '"firewallSshIpv4CidrCount":%d,"firewallSshIpv6CidrCount":%d,' \
    "${#IPV4_CIDRS[@]}" "${#IPV6_CIDRS[@]}"
  printf '"firewallSshCidrsEnforced":true,"firewallV4Established":true,"firewallV6Established":true,'
  printf '"firewallV4InputTcpDrop":true,"firewallV4InputUdpDrop":true,'
  printf '"firewallV4DockerTcpDrop":true,"firewallV4DockerUdpDrop":true,'
  printf '"firewallV6InputTcpDrop":true,"firewallV6InputUdpDrop":true,'
  printf '"firewallV6DockerTcpDrop":true,"firewallV6DockerUdpDrop":true,'
  printf '"firewallV4Input":true,"firewallV4Docker":true,"firewallV6Input":true,"firewallV6Docker":true,'
  printf '"udp443Blocked":true,"publicTcpDefaultDenied":true,"publicUdpDefaultDenied":true}\n'
  test "$active" = true && test "$enabled" = true \
    && test "$timer_active" = true && test "$timer_enabled" = true
}

remove_managed_family() {
  local tool=$1 base comment line target
  local -a lines=()
  for base in INPUT DOCKER-USER; do
    if test "$base" = INPUT; then
      comment=$INPUT_COMMENT
    else
      comment=$FORWARD_COMMENT
    fi
    mapfile -t lines < <(managed_jump_lines "$tool" "$base" "$comment")
    for line in "${lines[@]}"; do
      target=$(jump_target "$line")
      delete_jump_line "$tool" "$base" "$line" || true
      if [[ $target =~ ^MTEO(I|F)[A-Fa-f0-9]{12}$ ]]; then
        "$tool" -w -F "$target" >/dev/null 2>&1 || true
        "$tool" -w -X "$target" >/dev/null 2>&1 || true
      fi
    done
  done
  cleanup_orphan_chains "$tool"
}

remove_rules() {
  remove_managed_family iptables
  remove_managed_family ip6tables
}

require_root
require_tools
mkdir -p "$(dirname "$LOCK")"
exec 9>"$LOCK"
flock -x 9

case "$ACTION" in
  apply)
    enforce
    install_unit
    # ``apply`` already owns the reconciliation lock. The systemd unit runs
    # the same executable and takes that lock as well, so holding it across a
    # synchronous restart deadlocks the first deployment. Release it only
    # while systemd runs its idempotent enforcement, then reacquire it for the
    # status proof. The direct ``enforce`` above has already installed the
    # rule set, so this hand-off never opens the origin.
    flock -u 9
    systemctl restart mte-cloudflare-origin-firewall.service >/dev/null
    flock -x 9
    status_rules
    ;;
  enforce | recover)
    enforce
    ;;
  status)
    status_rules
    ;;
  remove)
    remove_rules
    systemctl disable --now mte-cloudflare-origin-firewall-recover.timer >/dev/null 2>&1 || true
    systemctl disable --now mte-cloudflare-origin-firewall.service >/dev/null 2>&1 || true
    rm -f "$UNIT" "$RECOVERY_UNIT" "$RECOVERY_TIMER"
    rm -f "$SELF"
    systemctl daemon-reload
    echo '{"removed":true}'
    ;;
  *)
    echo 'usage: origin-firewall.sh apply|enforce|recover|status|remove' >&2
    exit 2
    ;;
esac

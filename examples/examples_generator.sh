#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Generates example nftables fragments and setup commands for pam_authnft.
# Usage: examples_generator.sh [-s|-f|-m|-h]

USER_NAME="$(id -un)"
RULES_DIR="/etc/authnft/users"
HR="--------------------------------------------------------------------------------"

show_help() {
    echo "Usage: $(basename "$0") [username] [OPTION]"
    echo ""
    echo "Generates examples for the current user. Pass a username as the"
    echo "first argument to generate for a different user."
    echo ""
    echo "Options:"
    echo "  -s, --setup     Filesystem layout and PAM configuration."
    echo "  -f, --firewall  Example nftables rule fragments."
    echo "  -m, --monitor   Verification and log-parsing commands."
}

show_setup() {
    echo "### CONFIGURATION ###"
    echo "$HR"
    echo "# 1. Create the authnft group (members get session firewall rules)"
    printf "sudo groupadd authnft\n"
    printf "sudo usermod -aG authnft %s\n\n" "$USER_NAME"

    echo "# 2. Rules directory (root-owned, not world-readable)"
    printf "sudo mkdir -p %s\n" "$RULES_DIR"
    printf "sudo chmod 700 %s\n"  "$RULES_DIR"
    printf "sudo chown root:root %s\n\n" "$RULES_DIR"

    echo "# 3. PAM — add ONE of the following to /etc/pam.d/sshd (after pam_systemd.so)"
    echo ""
    echo "# Option A (recommended): standalone, module checks group membership internally."
    printf "session  optional  pam_authnft.so\n\n"
    echo "# Option B: PAM gates on group membership before the module runs."
    printf "session  [success=1 default=ignore]  pam_succeed_if.so  user notingroup authnft  quiet\n"
    printf "session  required  pam_authnft.so\n\n"
    echo "# Option C: with an upstream producer that writes session claims to the"
    echo "# kernel keyring via add_key(2) and passes the serial via pam_putenv(3)."
    echo "# The producer MUST run before pam_authnft in the session stack."
    printf "session  optional  pam_myidp.so           # writes MY_SESSION_KEY=<serial>\n"
    printf "session  optional  pam_authnft.so claims_env=MY_SESSION_KEY\n\n"

    echo "# 4. Create a fragment for the user (see -f for examples)"
    printf "sudo tee %s/%s > /dev/null <<'EOF'\n" "$RULES_DIR" "$USER_NAME"
    printf "add rule inet authnft filter ct state established,related accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip6 saddr @session_map_ipv6 accept\n"
    printf "EOF\n"
    printf "sudo chmod 644 %s/%s\n\n" "$RULES_DIR" "$USER_NAME"

    echo "# 5. (Optional) rhost_policy=kernel — derive peer IP from the kernel"
    echo "#    instead of trusting PAM_RHOST. Catches UseDNS=yes mismatches and"
    echo "#    load-balancer PROXY-protocol issues."
    printf "session  optional  pam_authnft.so rhost_policy=kernel\n\n"

    echo "# 6. (Optional) Per-session resource limits via authnft.slice"
    echo "#    All session scopes inherit from this slice."
    printf "sudo mkdir -p /etc/systemd/system/authnft.slice.d\n"
    printf "sudo tee /etc/systemd/system/authnft.slice.d/limits.conf > /dev/null <<'EOF'\n"
    printf "[Slice]\n"
    printf "MemoryMax=512M\n"
    printf "CPUQuota=50%%\n"
    printf "TasksMax=64\n"
    printf "EOF\n"
    printf "sudo systemctl daemon-reload\n\n"

    echo "# 7. (Optional) Shared group fragments directory"
    printf "sudo mkdir -p /etc/authnft/groups\n"
    printf "sudo chmod 700 /etc/authnft/groups\n"
    printf "sudo chown root:root /etc/authnft/groups\n"
    echo "$HR"
}

show_firewall() {
    echo "### EXAMPLE FRAGMENTS ###"
    echo "Fragments are plain text files containing nftables commands, one per"
    echo "line — the same syntax used in /etc/nftables.conf. Each user's fragment"
    echo "lives at /etc/authnft/users/<username> and is included at the top level"
    echo "by libnftables on every session open."
    echo "The file must be root-owned and not world-writable."
    echo ""
    echo "# HOW THE MATCH WORKS"
    echo "#"
    echo "# pam_authnft's chain hooks INPUT. The match expression"
    echo "#   socket cgroupv2 level 2 . ip saddr @session_map_ipv4"
    echo "# asks the kernel: 'does this packet's destination socket belong"
    echo "# to this session's cgroup, and did it come from this source IP?'"
    echo "#"
    echo "# WHAT MATCHES (Class A)"
    echo "#   Sockets the user creates INSIDE the session scope — listeners"
    echo "#   they open, outbound connections from their shell. These are"
    echo "#   tagged with the session's cgroup at socket creation time."
    echo "#"
    echo "# WHAT DOES NOT MATCH (Class B)"
    echo "#   Sockets that existed BEFORE the session scope was created —"
    echo "#   most importantly, the SSH TCP connection itself. The kernel"
    echo "#   tags a socket's cgroup when it is created (sk_alloc), and"
    echo "#   never updates it when the owning process moves between"
    echo "#   cgroups. The SSH socket was created by sshd before PAM ran."
    echo "#"
    echo "# HOW TO HANDLE CLASS B"
    echo "#   Every fragment should start with:"
    echo "#     add rule inet authnft filter ct state established,related accept"
    echo "#   This lets pre-scope traffic (the SSH connection, DNS lookups"
    echo "#   sshd made during login, etc.) through via conntrack before"
    echo "#   the cgroup match is evaluated. Without it, established SSH"
    echo "#   traffic would fall through to the chain's default policy."
    echo "#"
    echo "# SYN HANDLING"
    echo "#   The initial SYN of a new inbound connection is not classified"
    echo "#   by socket cgroupv2 (the kernel's socket lookup returns the"
    echo "#   LISTEN socket before request_sock promotion). Conntrack handles"
    echo "#   SYN as ct state new. Once the handshake completes, subsequent"
    echo "#   packets on that connection are ct state established and match"
    echo "#   normally."
    echo ""

    echo "# ═══════════════════════════════════════════════════════════════════"
    echo "# INBOUND (INPUT hook — session_map_ipv4 / session_map_ipv6)"
    echo "# ═══════════════════════════════════════════════════════════════════"
    echo ""

    printf "# --- Accept all session traffic ---\n"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "add rule inet authnft filter ct state established,related accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip6 saddr @session_map_ipv6 accept\n\n"

    printf "# --- Restrict to specific ports ---\n"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "add rule inet authnft filter ct state established,related accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 tcp dport { 80, 443 } accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip6 saddr @session_map_ipv6 tcp dport { 80, 443 } accept\n\n"

    printf "# --- Log and accept ---\n"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "add rule inet authnft filter ct state established,related accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 log prefix \"authnft_%s: \" accept\n" "$USER_NAME"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip6 saddr @session_map_ipv6 log prefix \"authnft_%s: \" accept\n\n" "$USER_NAME"

    printf "# --- Time-restricted access ---\n"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "add rule inet authnft filter ct state established,related accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 \\\\\n"
    printf "    meta day { \"Mon\",\"Tue\",\"Wed\",\"Thu\",\"Fri\" } hour \"09:00\"-\"17:00\" accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip6 saddr @session_map_ipv6 \\\\\n"
    printf "    meta day { \"Mon\",\"Tue\",\"Wed\",\"Thu\",\"Fri\" } hour \"09:00\"-\"17:00\" accept\n\n"

    printf "# --- Per-session rate limiting ---\n"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "# Accept up to 100 pps from this session; drop excess with a counter.\n"
    printf "add rule inet authnft filter ct state established,related accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 \\\\\n"
    printf "    limit rate 100/second burst 50 packets accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip6 saddr @session_map_ipv6 \\\\\n"
    printf "    limit rate 100/second burst 50 packets accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 \\\\\n"
    printf "    counter drop comment \"%s-rate-exceeded\"\n" "$USER_NAME"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip6 saddr @session_map_ipv6 \\\\\n"
    printf "    counter drop comment \"%s-v6-rate-exceeded\"\n\n" "$USER_NAME"

    printf "# --- Deny-by-default lockdown (zero-trust bastion) ---\n"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "# Whitelist specific ports; drop everything else from this session.\n"
    printf "add rule inet authnft filter ct state established,related accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 \\\\\n"
    printf "    tcp dport { 22, 443, 9090 } accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip6 saddr @session_map_ipv6 \\\\\n"
    printf "    tcp dport { 22, 443, 9090 } accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 \\\\\n"
    printf "    counter drop comment \"%s-deny-default\"\n" "$USER_NAME"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip6 saddr @session_map_ipv6 \\\\\n"
    printf "    counter drop comment \"%s-v6-deny-default\"\n\n" "$USER_NAME"

    printf "# --- Per-session traffic accounting ---\n"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "# Named counter visible via: nft list counters table inet authnft\n"
    printf "add counter inet authnft %s_bytes\n" "$USER_NAME"
    printf "add rule inet authnft filter ct state established,related accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 \\\\\n"
    printf "    counter name %s_bytes accept\n" "$USER_NAME"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip6 saddr @session_map_ipv6 \\\\\n"
    printf "    counter name %s_bytes accept\n\n" "$USER_NAME"

    echo "# ═══════════════════════════════════════════════════════════════════"
    echo "# OUTBOUND (OUTPUT hook — session_map_cg, cgroup-only)"
    echo "#"
    echo "# On the output path, the cgroup is the sending socket's and"
    echo "# ip daddr is the destination. Use session_map_cg (no src_ip leg)"
    echo "# because ip saddr on output is the host's own address."
    echo "# session_map_cg is family-agnostic; add ip daddr / ip6 daddr"
    echo "# variants for dual-stack destinations."
    echo "# ═══════════════════════════════════════════════════════════════════"
    echo ""

    printf "# --- Destination pinning (bastion host) ---\n"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "# Session processes can only reach the database tier.\n"
    printf "add chain inet authnft %s_egress { type filter hook output priority filter - 1; }\n" "$USER_NAME"
    printf "add rule inet authnft %s_egress ct state established,related accept\n" "$USER_NAME"
    printf "add rule inet authnft %s_egress socket cgroupv2 level 2 @session_map_cg ip daddr 10.0.5.0/24 accept\n" "$USER_NAME"
    printf "add rule inet authnft %s_egress socket cgroupv2 level 2 @session_map_cg ip6 daddr fd00:db::0/64 accept\n" "$USER_NAME"
    printf "add rule inet authnft %s_egress socket cgroupv2 level 2 @session_map_cg counter drop comment \"%s-egress-deny\"\n\n" "$USER_NAME" "$USER_NAME"

    printf "# --- DNS resolver pinning (only approved nameservers) ---\n"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "add chain inet authnft %s_dns { type filter hook output priority filter - 1; }\n" "$USER_NAME"
    printf "add rule inet authnft %s_dns socket cgroupv2 level 2 @session_map_cg \\\\\n" "$USER_NAME"
    printf "    meta l4proto { tcp, udp } th dport 53 ip daddr { 10.0.0.53, 10.0.0.54 } accept\n"
    printf "add rule inet authnft %s_dns socket cgroupv2 level 2 @session_map_cg \\\\\n" "$USER_NAME"
    printf "    meta l4proto { tcp, udp } th dport 53 ip6 daddr { fd00:dns::53, fd00:dns::54 } accept\n"
    printf "add rule inet authnft %s_dns socket cgroupv2 level 2 @session_map_cg \\\\\n" "$USER_NAME"
    printf "    meta l4proto { tcp, udp } th dport 53 counter drop comment \"%s-dns-pinned\"\n\n" "$USER_NAME"

    echo "# ═══════════════════════════════════════════════════════════════════"
    echo "# NAT (POSTROUTING hook — session_map_cg, cgroup-only)"
    echo "# ═══════════════════════════════════════════════════════════════════"
    echo ""

    printf "# --- Session masquerade ---\n"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "# In postrouting, ip saddr is the server's own IP — not the client's.\n"
    printf "# Use session_map_cg (cgroup-only) to match outbound traffic from this session.\n"
    printf "add chain inet authnft %s_nat { type nat hook postrouting priority srcnat; }\n" "$USER_NAME"
    printf "add rule inet authnft %s_nat socket cgroupv2 level 2 @session_map_cg masquerade\n\n" "$USER_NAME"

    echo "# ═══════════════════════════════════════════════════════════════════"
    echo "# COMPOSITION (include directive)"
    echo "# ═══════════════════════════════════════════════════════════════════"
    echo ""

    printf "# --- SRE break-glass: shared base policy + per-user escalation ---\n"
    printf "#\n"
    printf "# /etc/authnft/groups/sre-base.nft  (shared, root-owned)\n"
    printf "# SRE access: SSH to infra, HTTPS to dashboards, Prometheus.\n"
    printf "add rule inet authnft filter ct state established,related accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 \\\\\n"
    printf "    tcp dport { 22, 443, 9090 } accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip6 saddr @session_map_ipv6 \\\\\n"
    printf "    tcp dport { 22, 443, 9090 } accept\n\n"
    printf "# /etc/authnft/users/%s  (break-glass: base + database + Redis + Kafka)\n" "$USER_NAME"
    printf "# Deployed by automation during an incident; reverted when the\n"
    printf "# incident closes. The claims_env tag carries the ticket ID.\n"
    printf "include \"/etc/authnft/groups/sre-base.nft\"\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 \\\\\n"
    printf "    tcp dport { 5432, 6379, 9092 } accept comment \"%s-breakglass\"\n" "$USER_NAME"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip6 saddr @session_map_ipv6 \\\\\n"
    printf "    tcp dport { 5432, 6379, 9092 } accept comment \"%s-breakglass\"\n" "$USER_NAME"
    echo "$HR"
}

show_monitor() {
    echo "### MONITORING ###"
    echo "$HR"

    echo "# Current session elements (who is connected, from where)"
    printf "sudo nft list set inet authnft session_map_ipv4\n"
    printf "sudo nft list set inet authnft session_map_ipv6\n"
    printf "sudo nft list set inet authnft session_map_cg\n\n"

    echo "# Full table state (sets + chains + rules + counters)"
    printf "sudo nft list table inet authnft\n\n"

    echo "# Session JSON files (one per active session)"
    printf "ls -la /run/authnft/sessions/\n"
    printf "for f in /run/authnft/sessions/*.json; do jq . \"\$f\" 2>/dev/null; done\n\n"

    echo "# Structured audit events (open/close with correlation tokens)"
    printf "journalctl -t pam_authnft --since '1 hour ago' --no-pager\n\n"

    echo "# JSON export for SIEM — filter open events, extract fields"
    printf "journalctl -t pam_authnft AUTHNFT_EVENT=open --output=json --no-pager\n\n"

    echo "# Join open+close events by correlation token"
    printf "journalctl -t pam_authnft AUTHNFT_CORRELATION=authnft-<token> --no-pager\n\n"

    echo "# Active session scopes and cgroup resource usage"
    printf "systemctl list-units 'authnft-*.scope' --no-pager\n"
    printf "systemd-cgtop --depth=2 /authnft.slice\n\n"

    echo "# Per-session processes (replace with actual scope name)"
    printf "cat /sys/fs/cgroup/authnft.slice/authnft-%s-<pid>.scope/cgroup.procs\n\n" "$USER_NAME"

    echo "# Per-session named counter values (if fragments use named counters)"
    printf "sudo nft list counters table inet authnft\n\n"

    echo "# Verify cgroup match is firing (check packet counters on rules)"
    printf "sudo nft list chain inet authnft filter\n\n"

    echo "# Reset counters (useful before a test probe)"
    printf "sudo nft reset counters table inet authnft\n\n"

    echo "# Live nftables events (element insertions/deletions in real time)"
    printf "sudo nft monitor\n\n"

    echo "# Trace packet classification through authnft rules"
    printf "sudo nft add rule inet authnft filter meta nftrace set 1\n"
    printf "sudo nft monitor trace\n"
    echo "$HR"
}

# Handle optional username as first positional arg
case "${1:-}" in
    -s|--setup)    show_setup ;;
    -f|--firewall) show_firewall ;;
    -m|--monitor)  show_monitor ;;
    -h|--help|"")  show_help ;;
    *)
        # First arg might be a username; shift and re-dispatch
        USER_NAME="$1"; shift
        case "${1:-}" in
            -s|--setup)    show_setup ;;
            -f|--firewall) show_firewall ;;
            -m|--monitor)  show_monitor ;;
            *)             show_help; exit 1 ;;
        esac
        ;;
esac

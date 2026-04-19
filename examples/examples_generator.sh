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
    printf "EOF\n"
    printf "sudo chmod 644 %s/%s\n" "$RULES_DIR" "$USER_NAME"
    echo "$HR"
}

show_firewall() {
    echo "### EXAMPLE FRAGMENTS ###"
    echo "Fragments are included at top level as nftables commands."
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

    echo "$HR"
    echo ">> EXAMPLE 1: ACCEPT SESSION TRAFFIC <<"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "add rule inet authnft filter ct state established,related accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip6 saddr @session_map_ipv6 accept\n\n"

    echo "$HR"
    echo ">> EXAMPLE 2: RESTRICT TO SPECIFIC PORTS <<"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "add rule inet authnft filter ct state established,related accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 tcp dport { 80, 443 } accept\n\n"

    echo "$HR"
    echo ">> EXAMPLE 3: LOG AND ACCEPT <<"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "add rule inet authnft filter ct state established,related accept\n"
    printf "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 log prefix \"authnft_%s: \" accept\n\n" "$USER_NAME"

    echo "$HR"
    echo ">> EXAMPLE 4: NAT MASQUERADE <<"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "# In postrouting, ip saddr is the server's own IP — not the client's.\n"
    printf "# Use session_map_cg (cgroup-only) to match outbound traffic from this session.\n"
    printf "add chain inet authnft %s_nat { type nat hook postrouting priority srcnat; }\n" "$USER_NAME"
    printf "add rule inet authnft %s_nat socket cgroupv2 level 2 @session_map_cg masquerade\n\n" "$USER_NAME"

    echo "$HR"
    echo ">> EXAMPLE 5: TIME-RESTRICTED ACCESS <<"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "add rule inet authnft filter ct state established,related accept\n"
    echo 'add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 \'
    echo '    meta day { "Mon","Tue","Wed","Thu","Fri" } hour "09:00"-"17:00" accept'
    echo "$HR"
}

show_monitor() {
    echo "### MONITORING ###"
    echo "$HR"

    echo "# Current session elements (who is connected, from where)"
    printf "sudo nft list set inet authnft session_map_ipv4\n\n"

    echo "# Session JSON files (one per active session)"
    printf "ls -la /run/authnft/sessions/\n"
    printf "cat /run/authnft/sessions/*.json 2>/dev/null | python3 -m json.tool\n\n"

    echo "# Module log output (open/close events with correlation tokens)"
    printf "journalctl -t pam_authnft --since '1 hour ago' --no-pager\n\n"

    echo "# Correlate open+close events for a session"
    printf "journalctl -t pam_authnft AUTHNFT_EVENT=open --output=json --no-pager | head -1\n\n"

    echo "# Live nftables events"
    printf "sudo nft monitor\n\n"

    echo "# Active session scopes and cgroup resource usage"
    printf "systemctl list-units 'authnft-*.scope' --no-pager\n"
    printf "systemd-cgtop --depth=2 /authnft.slice\n"
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

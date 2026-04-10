#!/bin/bash
# Generates example nftables fragments and setup commands for pam_authnft.
# Usage: examples_generator.sh [-s|-f|-m|-h]

USER_NAME="${1:-$(id -un)}"
RULES_DIR="/etc/authnft/users"
HR="--------------------------------------------------------------------------------"

show_help() {
    echo "Usage: $(basename "$0") [username] [OPTION]"
    echo ""
    echo "Options:"
    echo "  -s, --setup     Filesystem layout and PAM configuration."
    echo "  -f, --firewall  Example nftables rule fragments."
    echo "  -m, --monitor   Verification and log-parsing commands."
}

show_setup() {
    echo "### SETUP ###"
    echo "$HR"
    echo "# Rules directory (root-owned, not world-readable)"
    printf "sudo mkdir -p %s\n" "$RULES_DIR"
    printf "sudo chmod 700 %s\n" "$RULES_DIR"
    printf "sudo chown root:root %s\n\n" "$RULES_DIR"

    echo "# Build and install"
    printf "make\nsudo make install\n\n"

    echo "# PAM — /etc/pam.d/sshd (after pam_systemd.so)"
    echo "# Option A: module handles group check internally"
    printf "session  optional  pam_authnft.so\n\n"
    echo "# Option B: explicit PAM-level group gate; enforces 'required' for members"
    printf "session  [success=1 default=ignore]  pam_succeed_if.so  user notingroup authnft  quiet\n"
    printf "session  required  pam_authnft.so\n"
    echo "$HR"
}

show_firewall() {
    echo "### EXAMPLE FRAGMENTS ###"
    echo "Fragments are included inside the 'inet authnft' table scope."
    echo "The sets session_map_ipv4 and session_map_ipv6 are keyed by"
    echo "cgroupv2 inode . source IP and populated at session open."
    echo ""

    echo "$HR"
    echo ">> EXAMPLE 1: ACCEPT SESSION TRAFFIC <<"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "add rule inet authnft filter meta cgroup . ip saddr @session_map_ipv4 accept\n"
    printf "add rule inet authnft filter meta cgroup . ip6 saddr @session_map_ipv6 accept\n\n"

    echo "$HR"
    echo ">> EXAMPLE 2: RESTRICT TO SPECIFIC PORTS <<"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "add rule inet authnft filter meta cgroup . ip saddr @session_map_ipv4 tcp dport { 80, 443 } accept\n\n"

    echo "$HR"
    echo ">> EXAMPLE 3: LOG AND ACCEPT <<"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "add rule inet authnft filter meta cgroup . ip saddr @session_map_ipv4 log prefix \"authnft_%s: \" accept\n\n" "$USER_NAME"

    echo "$HR"
    echo ">> EXAMPLE 4: NAT MASQUERADE <<"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "add chain inet authnft %s_nat { type nat hook postrouting priority srcnat; }\n" "$USER_NAME"
    printf "add rule inet authnft %s_nat meta cgroup . ip saddr @session_map_ipv4 masquerade\n\n" "$USER_NAME"

    echo "$HR"
    echo ">> EXAMPLE 5: TIME-RESTRICTED ACCESS <<"
    printf "# /etc/authnft/users/%s\n" "$USER_NAME"
    printf "add rule inet authnft filter meta cgroup . ip saddr @session_map_ipv4 \\\n"
    printf "    meta day { \"Mon\",\"Tue\",\"Wed\",\"Thu\",\"Fri\" } hour \"09:00\"-\"17:00\" accept\n"
    echo "$HR"
}

show_monitor() {
    echo "### MONITORING ###"
    echo "$HR"

    echo "# Live nftables events"
    printf "sudo nft monitor\n\n"

    echo "# Current session map state"
    printf "sudo nft list set inet authnft session_map_ipv4\n\n"

    echo "# Module log output"
    printf "journalctl -t authnft -f\n\n"

    echo "# Session cgroup resource usage"
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

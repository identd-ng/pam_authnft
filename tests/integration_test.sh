#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Integration tests for pam_authnft using pamtester.
# Must be run as root. Usage: sudo ./tests/integration_test.sh /path/to/pam_authnft.so
set -euo pipefail

SO_PATH="${1:-$(pwd)/pam_authnft.so}"
TEST_USER="${AUTHNFT_TEST_USER:-authnft-test}"
RULES_DIR="/etc/authnft/users"
PAM_TEST_CONF="/etc/pam.d/authnft_test"
RED='\033[1;31m' BLUE='\033[1;34m' YELLOW='\033[1;33m' CYAN='\033[36m' RESET='\033[0m'
pass() { printf "${BLUE}[PASS]${RESET} %s\n" "$1"; }
fail() { printf "${RED}[FAIL]${RESET} %s\n" "$1"; exit 1; }

if [[ $EUID -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
fi

# --- Setup ---
# Create the authnft group if absent, create a transient system user for
# testing, and add it to the group. All of this is undone in the cleanup trap.

USER_CREATED=0
GROUP_CREATED=0

cleanup() {
    rm -f "$RULES_DIR/$TEST_USER" "$PAM_TEST_CONF"
    if [[ $USER_CREATED -eq 1 ]]; then
        userdel "$TEST_USER" 2>/dev/null || true
    fi
    if [[ $GROUP_CREATED -eq 1 ]]; then
        groupdel authnft 2>/dev/null || true
    fi
}
trap cleanup EXIT

if ! getent group authnft > /dev/null 2>&1; then
    groupadd authnft
    GROUP_CREATED=1
fi

if ! getent passwd "$TEST_USER" > /dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -G authnft "$TEST_USER"
    USER_CREATED=1
else
    usermod -aG authnft "$TEST_USER"
fi

mkdir -p "$RULES_DIR"

# Write a minimal PAM config for testing
printf "auth     required  pam_permit.so\n" > "$PAM_TEST_CONF"
printf "account  required  pam_permit.so\n" >> "$PAM_TEST_CONF"
printf "session  required  %s\n" "$SO_PATH" >> "$PAM_TEST_CONF"
printf "password required  pam_deny.so\n"   >> "$PAM_TEST_CONF"

printf "${BLUE}>>> STAGE 10: PAMTESTER INTEGRATION${RESET}\n"

# 10.1: Group member denied when fragment is missing
printf "${YELLOW}10.1: Denial for '$TEST_USER' (no fragment)${RESET}\n"
rm -f "$RULES_DIR/$TEST_USER"
if pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" open_session > /dev/null 2>&1; then
    fail "Group member was not denied with missing fragment"
fi
pass "Group member correctly denied"

# 10.2: Group member allowed when fragment exists and is valid
printf "${YELLOW}10.2: Success for '$TEST_USER' (valid fragment)${RESET}\n"
echo "add rule inet authnft filter meta cgroup . ip saddr @session_map_ipv4 accept" \
    > "$RULES_DIR/$TEST_USER"
chown root:root "$RULES_DIR/$TEST_USER"
chmod 644 "$RULES_DIR/$TEST_USER"
if ! pamtester -v -I rhost=127.0.0.1 authnft_test "$TEST_USER" open_session; then
    fail "Session open failed — check journalctl -t authnft"
fi
printf "${CYAN}Ruleset state after open:${RESET}\n"
nft list table inet authnft
pamtester authnft_test "$TEST_USER" close_session
pass "Session opened and closed cleanly"

# 10.3: Root bypasses the module entirely
printf "${YELLOW}10.3: Root pass-through${RESET}\n"
if ! pamtester -v -I rhost=127.0.0.1 authnft_test root open_session; then
    fail "Root session open failed"
fi
pamtester authnft_test root close_session
pass "Root pass-through verified"

printf "\n${BLUE}>>> INTEGRATION TESTS COMPLETE${RESET}\n"

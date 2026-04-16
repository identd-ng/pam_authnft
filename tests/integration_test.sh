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

# nologin location differs across distros: /usr/sbin on Arch/Debian, /sbin on
# RHEL family. Fall back to /bin/false if neither exists.
if [[ -x /usr/sbin/nologin ]]; then
    NOLOGIN_SHELL="/usr/sbin/nologin"
elif [[ -x /sbin/nologin ]]; then
    NOLOGIN_SHELL="/sbin/nologin"
else
    NOLOGIN_SHELL="/bin/false"
fi
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

# Flush any leftover `inet authnft` table from prior runs. Residue can
# come from: (a) unit test stage 7 inserting {12345 . 127.0.0.1} without
# cleanup, or (b) a previous integration run where 10.2's close_session
# ran in a separate PAM handle and correctly no-opped (per invariant #6),
# leaving the element behind until its 24-hour timeout. 10.6 checks for
# "any element present" and would false-positive on such residue.
if nft list tables 2>/dev/null | grep -q "inet authnft"; then
    nft delete table inet authnft
fi

GROUP_FRAG_10_8=""
cleanup() {
    rm -f "$RULES_DIR/$TEST_USER" "$PAM_TEST_CONF"
    [[ -n "$GROUP_FRAG_10_8" ]] && rm -f "$GROUP_FRAG_10_8"
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
    useradd -r -s "$NOLOGIN_SHELL" -G authnft "$TEST_USER"
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

# Write a clean valid fragment for subsequent stages
FRAGMENT="$RULES_DIR/$TEST_USER"
valid_fragment() {
    echo "add rule inet authnft filter meta cgroup . ip saddr @session_map_ipv4 accept" \
        > "$FRAGMENT"
    chown root:root "$FRAGMENT"
    chmod 644 "$FRAGMENT"
}

# 10.4: Invariant #4 — fragment must be root-owned.
printf "${YELLOW}10.4: Fragment rejected when not root-owned${RESET}\n"
valid_fragment
chown "$TEST_USER:$TEST_USER" "$FRAGMENT"
if pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" open_session > /dev/null 2>&1; then
    fail "Non-root-owned fragment was accepted"
fi
pass "Non-root-owned fragment correctly rejected"

# 10.5: Invariant #4 — fragment must not be world-writable.
printf "${YELLOW}10.5: Fragment rejected when world-writable${RESET}\n"
valid_fragment
chmod 666 "$FRAGMENT"
if pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" open_session > /dev/null 2>&1; then
    fail "World-writable fragment was accepted"
fi
pass "World-writable fragment correctly rejected"

# 10.6: Invariant #1 — cg_id persisted via PAM data must survive into
# close_session so the set element is deleted cleanly. Running open_session
# and close_session in one pamtester invocation keeps the PAM handle alive;
# if the close path ever regresses to re-resolving the cgroup from getpid(),
# the element will not be deleted and this assertion will catch it.
printf "${YELLOW}10.6: Element cleanup via persisted cg_id${RESET}\n"
valid_fragment
if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" \
        open_session close_session > /dev/null 2>&1; then
    fail "open+close in a single PAM handle failed"
fi
if nft list set inet authnft session_map_ipv4 2>/dev/null | grep -q 'elements = {'; then
    fail "Element persisted after close_session — cg_id persistence path broken"
fi
pass "Element deleted at close_session"

# 10.7: Invariant #6 — close_session is best-effort. A close with no prior
# open (no stored cg_id in PAM data) must still return PAM_SUCCESS so the
# session can always unwind.
printf "${YELLOW}10.7: close_session best-effort when state missing${RESET}\n"
if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" close_session > /dev/null 2>&1; then
    fail "close_session without prior open did not return PAM_SUCCESS"
fi
pass "close_session best-effort semantics preserved"

# 10.8: Multi-fragment composition via nftables `include` directive.
# libnftables resolves `include` transitively when processing a fragment;
# a user fragment that includes a group-level fragment gets both files'
# rules loaded into the filter chain. No pam_authnft code change enables
# this — the test exists to catch a future libnftables parser regression.
printf "${YELLOW}10.8: Multi-fragment composition (transitive include)${RESET}\n"
GROUP_FRAG_10_8="/etc/authnft/composed-10-8.nft"
cat > "$GROUP_FRAG_10_8" <<NFT
add rule inet authnft filter meta cgroup . ip saddr @session_map_ipv4 counter accept comment "AUTHNFT-IT-GROUP"
NFT
chown root:root "$GROUP_FRAG_10_8"
chmod 644 "$GROUP_FRAG_10_8"
cat > "$FRAGMENT" <<NFT
include "$GROUP_FRAG_10_8"
add rule inet authnft filter meta cgroup . ip saddr @session_map_ipv4 counter accept comment "AUTHNFT-IT-USER"
NFT
chown root:root "$FRAGMENT"
chmod 644 "$FRAGMENT"
if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" open_session > /dev/null 2>&1; then
    fail "Composed-fragment open_session failed — check journalctl -t authnft"
fi
CHAIN_STATE=$(nft list chain inet authnft filter 2>&1)
if ! echo "$CHAIN_STATE" | grep -q "AUTHNFT-IT-GROUP"; then
    fail "Transitive include did not land the group fragment's rule"
fi
if ! echo "$CHAIN_STATE" | grep -q "AUTHNFT-IT-USER"; then
    fail "User fragment's own rule did not land alongside the include"
fi
# Close in a new handle; per invariant #6 this no-ops. Residual set
# element is flushed by the top-of-script nft delete on the next run.
pamtester authnft_test "$TEST_USER" close_session > /dev/null 2>&1 || true
pass "Composition via include resolved: group and user rules both applied"

printf "\n${BLUE}>>> INTEGRATION TESTS COMPLETE${RESET}\n"

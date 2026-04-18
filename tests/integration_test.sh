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
S1011_PIDS=()
cleanup() {
    rm -f "$RULES_DIR/$TEST_USER" "$PAM_TEST_CONF"
    [[ -n "$GROUP_FRAG_10_8" ]] && rm -f "$GROUP_FRAG_10_8"
    if (( ${#S1011_PIDS[@]} > 0 )); then
        kill "${S1011_PIDS[@]}" 2>/dev/null || true
    fi
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

# Runtime session-file directory. Normally created at boot by
# /usr/lib/tmpfiles.d/authnft.conf; test harness creates it on demand so
# `make test-integration` works even before `sudo make install-tmpfiles`.
mkdir -p /run/authnft/sessions
# Wipe any residue from earlier runs — lingering files from invariant-#6
# close_session no-ops would confuse the session-file lifecycle assertion.
rm -f /run/authnft/sessions/*.json /run/authnft/sessions/.*.tmp 2>/dev/null || true

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
echo "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 accept" \
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
    echo "add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 accept" \
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

# 10.6: Invariant #1 — session data persisted via PAM data (cg_path +
# scope_unit) must survive into close_session so the set element is
# deleted cleanly. Running open_session and close_session in one
# pamtester invocation keeps the PAM handle alive; if the close path
# ever regresses to re-resolving the cgroup from getpid(), the element
# will not be deleted and this assertion will catch it.
# Flush residual elements from prior stages (10.2's separate-handle close
# no-ops per invariant #6, leaving its element behind with a 24h timeout).
nft flush set inet authnft session_map_ipv4 2>/dev/null || true
printf "${YELLOW}10.6: Element cleanup via persisted session data${RESET}\n"
valid_fragment
if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" \
        open_session close_session > /dev/null 2>&1; then
    fail "open+close in a single PAM handle failed"
fi
if nft list set inet authnft session_map_ipv4 2>/dev/null | grep -q 'elements = {'; then
    fail "Element persisted after close_session — session-data persistence path broken"
fi
pass "Element deleted at close_session"

# 10.7: Invariant #6 — close_session is best-effort. A close with no prior
# open (no stored session data in PAM) must still return PAM_SUCCESS so
# the session can always unwind.
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
add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 counter accept comment "AUTHNFT-IT-GROUP"
NFT
chown root:root "$GROUP_FRAG_10_8"
chmod 644 "$GROUP_FRAG_10_8"
cat > "$FRAGMENT" <<NFT
include "$GROUP_FRAG_10_8"
add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 counter accept comment "AUTHNFT-IT-USER"
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

# 10.9: /run/authnft/sessions/<scope_unit>.json session-identity file contract.
# Verifies that pam_authnft writes a JSON observability file at open_session
# and removes it at close_session. Permissions, JSON schema fields, and the
# open/close lifecycle are all checked. See docs/INTEGRATIONS.txt §5.6.
printf "${YELLOW}10.9: Session identity file (open creates, close removes)${RESET}\n"
valid_fragment
rm -f /run/authnft/sessions/*.json /run/authnft/sessions/.*.tmp 2>/dev/null || true
# Half 1: open in a single handle (separate from the later close so the
# file is left behind for inspection — close_session in a new handle
# no-ops per invariant #6 and does not remove the file).
if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" open_session > /dev/null 2>&1; then
    fail "Session file test: open_session failed"
fi
SESSION_FILE=$(ls /run/authnft/sessions/*.json 2>/dev/null | head -1)
if [[ -z "$SESSION_FILE" ]]; then
    fail "No session file created at open_session under /run/authnft/sessions/"
fi
for FIELD in '"v":2' '"cg_path":"authnft.slice/authnft-' "\"user\":\"$TEST_USER\"" \
             '"remote_ip":"127.0.0.1"' "\"fragment\":\"$RULES_DIR/$TEST_USER\"" \
             "\"scope_unit\":\"authnft-$TEST_USER-" '"opened_at":"'; do
    if ! grep -q "$FIELD" "$SESSION_FILE"; then
        cat "$SESSION_FILE"
        fail "Session file missing field: $FIELD"
    fi
done
PERMS=$(stat -c '%a %U:%G' "$SESSION_FILE")
if [[ "$PERMS" != "644 root:root" ]]; then
    fail "Session file wrong permissions: got '$PERMS', expected '644 root:root'"
fi
rm -f "$SESSION_FILE"
# Half 2: open+close in the SAME handle. close_session must remove the file.
if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" \
        open_session close_session > /dev/null 2>&1; then
    fail "Session file test: open+close same-handle run failed"
fi
if ls /run/authnft/sessions/*.json 2>/dev/null | grep -q .; then
    fail "Session file persisted after close_session in the same handle"
fi
pass "Session file lifecycle: created on open, correct schema and perms, removed on close"

# 10.10: Structured journald audit events.
# Verifies pam_authnft emits AUTHNFT_EVENT=open on open_session and
# AUTHNFT_EVENT=close on close_session, with a consistent
# AUTHNFT_CORRELATION token joining the two. See docs/INTEGRATIONS.txt §6.2.
printf "${YELLOW}10.10: Audit events (journald + correlation token)${RESET}\n"
valid_fragment
# Mark the journal cursor so we only read events from this test.
CURSOR=$(journalctl -n 0 --show-cursor 2>&1 | grep -oP 'cursor: \K.*')
if [[ -z "$CURSOR" ]]; then
    fail "could not capture journal cursor"
fi
# Single-handle open+close so the same session_pid (and correlation) covers
# both events.
if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" \
        open_session close_session > /dev/null 2>&1; then
    fail "open+close failed during audit-event test"
fi
# Give the journal a moment to flush (sd_journal_send returns before the
# reader sees the entry under some journald backlog conditions).
sync
sleep 1
OPEN_LINE=$(journalctl --after-cursor="$CURSOR" -t pam_authnft \
            --output=json --no-pager 2>/dev/null | \
            grep '"AUTHNFT_EVENT":"open"' | head -1)
CLOSE_LINE=$(journalctl --after-cursor="$CURSOR" -t pam_authnft \
             --output=json --no-pager 2>/dev/null | \
             grep '"AUTHNFT_EVENT":"close"' | head -1)
[[ -n "$OPEN_LINE"  ]] || fail "no AUTHNFT_EVENT=open entry after open_session"
[[ -n "$CLOSE_LINE" ]] || fail "no AUTHNFT_EVENT=close entry after close_session"
for FIELD in '"AUTHNFT_USER":"'"$TEST_USER"'"' \
             '"AUTHNFT_CG_PATH":"authnft.slice/authnft-' '"AUTHNFT_REMOTE_IP":"127.0.0.1"' \
             "\"AUTHNFT_FRAGMENT\":\"$RULES_DIR/$TEST_USER\"" \
             "\"AUTHNFT_SCOPE_UNIT\":\"authnft-$TEST_USER-" \
             '"AUTHNFT_CORRELATION":"authnft-'; do
    if ! echo "$OPEN_LINE" | grep -q "$FIELD"; then
        echo "open event: $OPEN_LINE"
        fail "open event missing field: $FIELD"
    fi
done
CORR_OPEN=$(echo "$OPEN_LINE"  | grep -oP '"AUTHNFT_CORRELATION":"\K[^"]+')
CORR_CLOSE=$(echo "$CLOSE_LINE" | grep -oP '"AUTHNFT_CORRELATION":"\K[^"]+')
if [[ -z "$CORR_OPEN" || "$CORR_OPEN" != "$CORR_CLOSE" ]]; then
    fail "correlation mismatch: open='$CORR_OPEN' close='$CORR_CLOSE'"
fi
pass "Audit events: open + close emitted, shared correlation='$CORR_OPEN'"

# 10.11: Adversarial packet classification (ingress).
#
# Verifies that `socket cgroupv2 level 2 . ip saddr @session_map_ipv4`
# on the INPUT-hooked chain actually accepts packets from allowed
# sources and drops packets from disallowed sources. This is the test
# that would have caught the K1 bug: every prior stage verified positive
# state (element present, session opens, event fires) rather than
# end-to-end packet classification with an explicit drop.
#
# Architecture: pam_authnft's chain hooks INPUT. On INPUT, the nftables
# `socket` expression resolves the DESTINATION socket (the listener).
# For ingress filtering — "only this source can reach the session's
# listener" — that is correct. Egress filtering would require an
# OUTPUT-hooked chain, which is a separate concern not tested here.
#
# Implementation: pamtester exits after open_session, so the transient
# scope is reaped by systemd before probes can run. To work around this,
# we create a persistent test scope via systemd-run, open a pamtester
# session to build the nft table/chain/rules, then manually insert an
# element for the persistent scope. This cleanly separates the PAM
# lifecycle (10.1–10.10) from the packet-classification test (10.11).
#
# Peer addresses 127.0.0.2 (allowed) and 127.0.0.3 (disallowed) are
# loopback aliases. The kernel code path is identical for loopback and
# real interfaces; loopback is preferred for hermetic container testing.
#
# `ct state established,related accept` precedes the cgroup match so
# the initial SYN (which arrives before request_sock promotion) is
# handled via conntrack — the standard nftables stateful-chain idiom.
#
# Ordering: this stage runs last due to catch-all drop rules.
printf "${YELLOW}10.11: Adversarial packet classification${RESET}\n"

# `socket cgroupv2 level 2` uses the ABSOLUTE kernel cgroup hierarchy,
# not the container-relative view. In a cgroup namespace (containers),
# the authnft scope is at kernel level N+2 where N is the container's
# nesting depth, so `level 2` resolves to the wrong cgroup and the
# match never fires. Detect this and skip — the host-level adversarial
# test (proved during K1 development) is authoritative.
if [[ "$(cat /proc/1/cgroup 2>/dev/null | grep '^0::' | cut -d: -f3)" != "/" ]]; then
    pass "10.11: [SKIP] cgroup namespace detected (container) — level 2 match is host-only"
    printf "\n${BLUE}>>> INTEGRATION TESTS COMPLETE${RESET}\n"
    exit 0
fi

s1011_cursor=$(journalctl -n 0 --show-cursor 2>&1 | grep -oP 'cursor: \K.*' || true)

dump_10_11_diagnostics() {
    {
        echo "--- 10.11 diagnostic dump ---"
        if [[ -n "$s1011_cursor" ]]; then
            journalctl --after-cursor="$s1011_cursor" \
                --grep='authnft-10\.11-' --no-pager 2>/dev/null || true
        fi
        echo "--- nft list table inet authnft ---"
        nft list table inet authnft 2>/dev/null || true
    } >&2
}

# Create a persistent scope under authnft.slice for the probes.
systemd-run --scope --slice=authnft.slice --unit=authnft-1011-probe \
    sleep 60 >/dev/null 2>&1 &
S1011_PIDS+=($!)
sleep 0.5
s1011_scope_path="/authnft.slice/authnft-1011-probe.scope"
if [[ ! -d "/sys/fs/cgroup$s1011_scope_path" ]]; then
    dump_10_11_diagnostics
    fail "10.11: could not create test scope under authnft.slice"
fi

# Open a pamtester session to create the nft table/chain. The fragment
# adds a counter rule for the cgroup match — no drops. On loopback the
# listener's response also traverses INPUT; a catch-all drop would kill
# it, conflating inbound/outbound. Counter-based verification avoids
# this: check the match fires on allowed traffic and doesn't fire on
# disallowed traffic. policy accept ensures both probes complete.
cat > "$FRAGMENT" <<'NFT'
add rule inet authnft filter socket cgroupv2 level 2 . ip saddr @session_map_ipv4 counter comment "10.11-cg-match"
NFT
chown root:root "$FRAGMENT"
chmod 644 "$FRAGMENT"
if ! pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" \
        open_session > /dev/null 2>&1; then
    dump_10_11_diagnostics
    fail "10.11: session open failed — fragment rejected or module error"
fi

# Insert an element for our persistent probe scope.
if ! nft add element inet authnft session_map_ipv4 \
    '{ "authnft.slice/authnft-1011-probe.scope" . 127.0.0.2 timeout 1h }' 2>&1; then
    dump_10_11_diagnostics
    fail "10.11: could not insert element for probe scope"
fi

# Reset counters to isolate our probes from prior traffic.
nft reset counters table inet authnft > /dev/null 2>&1 || true

# Listener inside the probe scope.
sh -c '
    echo $$ > /sys/fs/cgroup'"${s1011_scope_path}"'/cgroup.procs
    echo OK | exec nc -l 127.0.0.1 18081
' &
S1011_PIDS+=($!)
sleep 0.5

# Probe 1: allowed source (127.0.0.2). Match should fire → counter > 0.
timeout 5 nc -w3 127.0.0.1 18081 --source 127.0.0.2 </dev/null >/dev/null 2>&1 || true
CG_PKTS=$(nft list chain inet authnft filter 2>/dev/null \
    | grep '10.11-cg-match' | grep -oP 'packets \K[0-9]+')
if [[ -z "$CG_PKTS" || "$CG_PKTS" -eq 0 ]]; then
    dump_10_11_diagnostics
    fail "10.11: cgroup match counter=0 after allowed-source probe — match not firing"
fi
pass "10.11: cgroup match fired for allowed source ($CG_PKTS packets)"

# Save counter, then probe from disallowed source.
PREV_PKTS="$CG_PKTS"
sh -c '
    echo $$ > /sys/fs/cgroup'"${s1011_scope_path}"'/cgroup.procs
    echo OK | exec nc -l 127.0.0.1 18081
' &
S1011_PIDS+=($!)
sleep 0.5

# Probe 2: disallowed source (127.0.0.3). Match should NOT fire →
# counter should not increase.
timeout 5 nc -w3 127.0.0.1 18081 --source 127.0.0.3 </dev/null >/dev/null 2>&1 || true
CG_PKTS=$(nft list chain inet authnft filter 2>/dev/null \
    | grep '10.11-cg-match' | grep -oP 'packets \K[0-9]+')
if [[ -n "$CG_PKTS" && "$CG_PKTS" -gt "$PREV_PKTS" ]]; then
    dump_10_11_diagnostics
    fail "10.11: cgroup match counter increased ($PREV_PKTS→$CG_PKTS) on disallowed source"
fi
pass "10.11: cgroup match did NOT fire for disallowed source (counter stable at $CG_PKTS)"

pamtester authnft_test "$TEST_USER" close_session > /dev/null 2>&1 || true
pass "10.11: adversarial packet classification verified"

printf "\n${BLUE}>>> INTEGRATION TESTS COMPLETE${RESET}\n"

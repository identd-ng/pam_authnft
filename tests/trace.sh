#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Audit aid for invariant #5 (seccomp allowlist provenance).
# Sets up a minimal test environment, runs ONE pamtester open+close cycle
# under `strace -f -c` with the sandbox bypassed, and writes the syscall
# summary to trace.log. Diff this list against SCMP_SYS(...) entries in
# src/sandbox.c before adding any new syscall to the allowlist.
#
# Usage: sudo ./tests/trace.sh /path/to/pam_authnft.so
set -euo pipefail

SO_PATH="${1:-$(pwd)/pam_authnft.so}"
TEST_USER="${AUTHNFT_TEST_USER:-authnft-test}"
RULES_DIR="/etc/authnft/users"
PAM_TEST_CONF="/etc/pam.d/authnft_test"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
fi

USER_CREATED=0 GROUP_CREATED=0
cleanup() {
    rm -f "$RULES_DIR/$TEST_USER" "$PAM_TEST_CONF"
    [[ $USER_CREATED -eq 1 ]] && userdel "$TEST_USER" 2>/dev/null || true
    [[ $GROUP_CREATED -eq 1 ]] && groupdel authnft 2>/dev/null || true
    nft list tables 2>/dev/null | grep -q "inet authnft" && nft delete table inet authnft || true
}
trap cleanup EXIT

if ! getent group authnft > /dev/null 2>&1; then
    groupadd authnft; GROUP_CREATED=1
fi
if ! getent passwd "$TEST_USER" > /dev/null 2>&1; then
    if   [[ -x /usr/sbin/nologin ]]; then NOLOGIN_SHELL=/usr/sbin/nologin
    elif [[ -x /sbin/nologin     ]]; then NOLOGIN_SHELL=/sbin/nologin
    else                                   NOLOGIN_SHELL=/bin/false
    fi
    useradd -r -s "$NOLOGIN_SHELL" -G authnft "$TEST_USER"; USER_CREATED=1
fi

mkdir -p "$RULES_DIR"
echo "add rule inet authnft filter meta cgroup . ip saddr @session_map_ipv4 accept" \
    > "$RULES_DIR/$TEST_USER"
chown root:root "$RULES_DIR/$TEST_USER"
chmod 644 "$RULES_DIR/$TEST_USER"

cat > "$PAM_TEST_CONF" <<EOF
auth     required  pam_permit.so
account  required  pam_permit.so
session  required  $SO_PATH
password required  pam_deny.so
EOF

# Trace a single open+close cycle. The module's seccomp is bypassed so the
# strace captures the full syscall set the module WOULD need to allow.
# pamtester's own stdout chatter ("sucessfully opened a session", etc.) is
# not relevant to the syscall audit; drop it. strace writes the summary to
# trace.log via -o, so stderr does not need redirecting.
AUTHNFT_NO_SANDBOX=1 strace -f -c -o trace.log \
    pamtester -I rhost=127.0.0.1 authnft_test "$TEST_USER" \
    open_session close_session > /dev/null

echo "Syscall summary in trace.log:"
echo ""
cat trace.log
echo ""
echo "Compare against SCMP_SYS(...) entries in src/sandbox.c."
echo "Syscalls that legitimately run before dlopen (e.g. execve) belong"
echo "excluded per the explanatory comment at the top of src/sandbox.c."

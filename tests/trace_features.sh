#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Feature-path audit aid for invariant #5 (seccomp allowlist provenance).
#
# The companion trace.sh exercises the default open_session + close_session
# path under pamtester. It does not traverse code paths gated by
# rhost_policy=kernel or claims_env=NAME, and therefore cannot prove that
# syscalls added for those features (or not added, in sock_diag's case) are
# correct.
#
# This script runs the unit suite under strace -f -c. The unit suite
# exercises:
#   stage 8  util_normalize_ip              pure userspace, no syscalls
#   stage 9  peer_lookup_tcp                sock_diag via NETLINK
#   stage 10 keyring_read_serial            keyctl(KEYCTL_READ)
# plus the pre-existing stages. Syscalls executed only by the unit test
# harness (not by the module in production) — e.g. add_key, socket(AF_INET)
# for the stage 9 localhost pair, pthread primitives from the test runner —
# must be identified and excluded from comparison against src/sandbox.c.
#
# Usage: ./tests/trace_features.sh
#
# Runs without root. No system state is modified. Output: trace-features.log
# containing the strace -c summary, plus a short diff-friendly report on
# stderr naming syscalls seen in each category.

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v strace >/dev/null 2>&1; then
    echo "strace not installed; skipping feature trace." >&2
    exit 0
fi

if [[ ! -x ./authnft_test ]]; then
    echo "authnft_test not built. Run 'make test' first." >&2
    exit 1
fi

LOG=trace-features.log
rm -f "$LOG"

# -f  follow forks (stages 2 and 3 fork children that run sandbox_apply)
# -c  produce a summary of counts and times per syscall
# -o  write the summary to LOG instead of stderr
strace -f -c -o "$LOG" ./authnft_test >/dev/null 2>&1 || true

echo "Syscall summary in $LOG:" >&2
echo "" >&2
cat "$LOG" >&2
echo "" >&2

# Extract the syscall name column for easy comparison. strace -c formats as
# `  % time  seconds  usecs/call  calls  errors  syscall`, with a trailing
# totals line; take the last whitespace-separated field on each data row.
seen=$(awk 'NF>=5 && $NF!~/^-+$/ && $NF!="syscall" && $NF!="total" {print $NF}' \
       "$LOG" | sort -u)

echo "=== Syscalls observed during the unit suite ===" >&2
echo "$seen" | sed 's/^/  /' >&2
echo "" >&2

# Syscalls known to be test-harness only, not reachable from the three PAM
# handlers in production. Maintainers comparing against src/sandbox.c should
# subtract these from the observed set.
cat >&2 <<'EOF'
=== Syscalls expected to appear but NOT required in the sandbox ===

These are exercised by the test harness (stage setup, libc/runtime startup,
fork plumbing for the sandbox-bypass stages) and are outside the module's
production reach:

  add_key         stage 10 fixture only — module reads, never writes keys
  execve          pamtester / shell startup before dlopen()
  wait4, waitid   stages 2 and 3 parent waits on forked children
  clone, clone3   stages 2 and 3 fork()
  fork, vfork     libc startup (if seen)
  listen, accept  stage 9 localhost socket pair fixture
                  (socket/bind/connect are also in the allowlist for
                   AF_NETLINK and AF_UNIX, so their appearance here is
                   expected for both test and production reasons)

Confirm the remaining observed syscalls are present in src/sandbox.c. If
not, investigate: either the allowlist is missing an entry and the next
production session will SIGSYS, or the new syscall is test-harness-only
and this list should be extended.
EOF

echo "" >&2
echo "Allowlist for quick cross-check (SCMP_SYS entries in src/sandbox.c):" >&2
echo "" >&2
grep -oE 'SCMP_SYS\([a-z_0-9]+\)' src/sandbox.c \
    | sed -E 's/SCMP_SYS\(//; s/\)//' | sort -u | sed 's/^/  /' >&2

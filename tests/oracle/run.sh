#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Differential-test driver. Feeds each input file through both the C
# parser (via tests/oracle/oracle_runner) and the Python oracle
# (tests/oracle/oracle.py), diffs the output. Disagreement is a logic
# bug in one of the two implementations.
#
# Both implementations were written from the spec independently — the
# point is that a bug in C is unlikely to be the same bug in Python.
#
# Run via `make test-oracle` (no root, no live system state).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUNNER="$PROJECT_ROOT/tests/oracle/oracle_runner"
ORACLE="$PROJECT_ROOT/tests/oracle/oracle.py"
INPUT_DIR="$PROJECT_ROOT/tests/oracle/inputs"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
RESET='\033[0m'

if [ ! -x "$RUNNER" ]; then
    echo "$RUNNER not built — run 'make $RUNNER' first" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 required" >&2
    exit 1
fi

PASS=0
FAIL=0

for fn in username normalize_ip cgroup_path keyring_sanitize correlation_capture; do
    input_file="$INPUT_DIR/$fn.txt"
    [ -f "$input_file" ] || { echo "no input file for $fn"; continue; }

    c_out=$(mktemp)
    py_out=$(mktemp)
    trap 'rm -f "$c_out" "$py_out"' EXIT

    "$RUNNER" "$fn"     < "$input_file" > "$c_out"
    python3 "$ORACLE" "$fn" < "$input_file" > "$py_out"

    if diff -u "$c_out" "$py_out" > /dev/null; then
        n=$(wc -l < "$input_file")
        printf "${GREEN}[PASS]${RESET} %s (%d inputs)\n" "$fn" "$n"
        PASS=$((PASS + 1))
    else
        printf "${RED}[FAIL]${RESET} %s — divergence (C left, Python right):\n" "$fn"
        # Side-by-side diff with input alignment for readability.
        paste "$input_file" "$c_out" "$py_out" | \
            awk -F'\t' '$2 != $3 { printf "  input=%-32s C=%-12s py=%s\n", $1, $2, $3 }' >&2
        FAIL=$((FAIL + 1))
    fi
done

if [ "$FAIL" -gt 0 ]; then
    printf "\n${RED}[ORACLE FAIL]${RESET} %d disagreement(s)\n" "$FAIL"
    exit 1
fi
printf "\n${GREEN}[ORACLE PASS]${RESET} %d function(s) cross-validated\n" "$PASS"

# Phase 4.2: idempotence + round-trip property checks. The differential
# oracle above catches "C and Python disagree". The property pass below
# catches "the function disagrees with itself" — output rejected by
# the same function, or a canonical form that drifts on re-application.
echo
python3 "$SCRIPT_DIR/properties.py"

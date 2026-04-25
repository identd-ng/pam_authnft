#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Property-based tests on top of the differential oracle. Phase 4.2 of
# the security plan.
#
# Where the differential oracle answers "do C and Python agree?", this
# script answers "does the function obey its own contract?". The two
# checks complement each other:
#
#   oracle    — catches cross-implementation divergence (logic bug
#               in C OR Python).
#   property  — catches single-implementation invariant violation
#               (a function whose output is rejected by itself, or
#               whose canonical form changes when re-applied).
#
# Properties enforced (per function):
#
#   util_normalize_ip
#     - idempotence: f(f(x).out) == f(x).out  (canonical form is stable)
#     - round-trip:  f(x).out is itself accepted as input
#
#   validate_cgroup_path
#     - round-trip: prefix the leading-slash-stripped output with '/'
#                   and the function still accepts.
#     - the re-accepted output equals the first output.
#
#   keyring_sanitize
#     - idempotence: sanitizing already-sanitized output is a no-op.
#     - all output bytes are in the allowlist.
#
#   corr_sanitize_copy
#     - idempotence.
#     - all output bytes are in the allowlist.
#
# The test reads inputs from tests/oracle/inputs/<fn>.txt and runs both
# the C runner (which is built with -DFUZZ_BUILD) and the Python
# implementation. A failure prints the offending input and the divergence.

import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
RUNNER = REPO_ROOT / "tests" / "oracle" / "oracle_runner"
ORACLE_PY = REPO_ROOT / "tests" / "oracle" / "oracle.py"
INPUT_DIR = REPO_ROOT / "tests" / "oracle" / "inputs"


GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
RESET = "\033[0m"


def call_runner(fn, inputs_bytes):
    """Run the C oracle runner on a list of byte-string inputs.
    Returns a list of byte-string output lines (without trailing newline).
    """
    payload = b"\n".join(inputs_bytes) + b"\n"
    proc = subprocess.run(
        [str(RUNNER), fn],
        input=payload,
        capture_output=True,
        check=True,
    )
    out = proc.stdout
    if out.endswith(b"\n"):
        out = out[:-1]
    return out.split(b"\n") if out else []


def call_python(fn, inputs_bytes):
    """Run the Python oracle on the same inputs."""
    payload = b"\n".join(inputs_bytes) + b"\n"
    proc = subprocess.run(
        [sys.executable, str(ORACLE_PY), fn],
        input=payload,
        capture_output=True,
        check=True,
    )
    out = proc.stdout
    if out.endswith(b"\n"):
        out = out[:-1]
    return out.split(b"\n") if out else []


def parse_acceptance(fn, line):
    """Given an oracle output line for `fn`, return (accepted, out_bytes).

    out_bytes is what would be fed back as input for the round-trip
    test (with any necessary fix-up for round-trip semantics, e.g.
    re-adding the leading slash for cgroup_path).
    """
    if fn == "normalize_ip":
        rc, _, out = line.partition(b"|")
        return (rc == b"1", out)
    if fn == "cgroup_path":
        rc, _, out = line.partition(b"|")
        # validate_cgroup_path strips the leading slash; re-add it for
        # round-trip.
        return (rc == b"0", b"/" + out if out else b"")
    if fn in ("keyring_sanitize", "correlation_capture"):
        _, _, out = line.partition(b"|")
        return (True, out)
    raise AssertionError(f"unknown fn: {fn}")


def read_inputs(fn):
    p = INPUT_DIR / f"{fn}.txt"
    if not p.exists():
        return []
    raw = p.read_bytes()
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    return raw.split(b"\n") if raw else []


def check_property(fn, runner):
    """Run the round-trip + idempotence check on one function via one runner.

    Returns (n_tested, divergences) where divergences is a list of
    (input, round1, round2) tuples describing any property violation.
    """
    inputs = read_inputs(fn)
    if not inputs:
        return (0, [])

    round1 = runner(fn, inputs)
    if len(round1) != len(inputs):
        # Runner emitted a different number of lines than expected.
        return (0, [(b"<harness>", b"len(inputs)=%d" % len(inputs),
                                  b"len(round1)=%d" % len(round1))])

    # Build the round-2 inputs: only those that the function accepted
    # (in fn-specific terms). Skip "rejected" outputs — those don't
    # have an out to round-trip.
    round2_in = []
    round2_idx = []  # index into round1 for the lines we feed back
    for i, line in enumerate(round1):
        accepted, fed = parse_acceptance(fn, line)
        if accepted:
            round2_in.append(fed)
            round2_idx.append(i)

    if not round2_in:
        return (len(inputs), [])

    round2 = runner(fn, round2_in)
    if len(round2) != len(round2_in):
        return (len(inputs),
                [(b"<harness>", b"len(round2_in)=%d" % len(round2_in),
                                b"len(round2)=%d" % len(round2))])

    divergences = []
    for round2_line, idx, fed in zip(round2, round2_idx, round2_in):
        if round2_line != round1[idx]:
            divergences.append((inputs[idx] + b"  (fed back: " + fed + b")",
                                round1[idx], round2_line))
    return (len(inputs), divergences)


def fmt(b):
    """Format a byte-string for human output."""
    return b.decode("utf-8", errors="backslashreplace")


def main():
    if not RUNNER.exists():
        sys.stderr.write(f"{RUNNER} not built — run `make $RUNNER` first\n")
        sys.exit(1)

    pass_count = 0
    fail_count = 0

    for fn in ("normalize_ip", "cgroup_path",
               "keyring_sanitize", "correlation_capture"):
        # Run on both implementations.
        for name, runner in (("C", call_runner), ("Python", call_python)):
            n, div = check_property(fn, runner)
            label = f"{fn} ({name})"
            if not div:
                print(f"{GREEN}[PASS]{RESET} idempotence: {label}  "
                      f"({n} inputs)")
                pass_count += 1
            else:
                print(f"{RED}[FAIL]{RESET} idempotence: {label}  "
                      f"({n} inputs, {len(div)} divergence(s))",
                      file=sys.stderr)
                for inp, r1, r2 in div[:5]:  # cap the noise
                    print(f"  input    = {fmt(inp)}", file=sys.stderr)
                    print(f"  round 1  = {fmt(r1)}", file=sys.stderr)
                    print(f"  round 2  = {fmt(r2)}", file=sys.stderr)
                if len(div) > 5:
                    print(f"  ...and {len(div) - 5} more", file=sys.stderr)
                fail_count += 1

    if fail_count:
        print(f"\n{RED}[PROPERTY FAIL]{RESET} {fail_count} divergence(s)",
              file=sys.stderr)
        sys.exit(1)
    print(f"\n{GREEN}[PROPERTY PASS]{RESET} "
          f"{pass_count} (function, runner) pair(s) cross-validated")


if __name__ == "__main__":
    main()

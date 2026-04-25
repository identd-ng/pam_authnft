#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Python re-implementation of pam_authnft's small parsers, used as a
# differential-testing oracle. Reads one input per stdin line, emits
# one result line in the same format as tests/oracle/oracle_runner.c.
#
# DO NOT make this a verbatim port of the C — the whole point of a
# differential oracle is that the two implementations are written
# independently from the spec, so a bug in one is unlikely to be a
# bug in the other. Rules of thumb here:
#   - prefer Python stdlib primitives (re, ipaddress) over hand-rolling
#   - match C semantics exactly for input acceptance/rejection
#   - match C output verbatim where C preserves the input (don't
#     canonicalize), but use Python's parsers as the truth for
#     branch decisions

import ipaddress
import re
import sys

# pam_authnft constants — kept in sync with include/authnft.h. If
# they drift, the oracle harness will start disagreeing with C.
MAX_USER_LEN = 32
IP_STR_MAX = 64
USERNAME_RE = re.compile(r"\A[A-Za-z0-9._-]+\Z")


def is_valid_username(u: str) -> int:
    """Mirrors util_is_valid_username (src/pam_entry.c)."""
    if not u:
        return 0
    if len(u) > MAX_USER_LEN:
        return 0
    if u[0] == "-" or u[0] == ".":
        return 0
    return 1 if USERNAME_RE.fullmatch(u) else 0


def normalize_ip(s: str):
    """Mirrors util_normalize_ip. Returns the normalized string on
    success, None on rejection. Preserves input form for non-mapped
    addresses; extracts canonical IPv4 from IPv6 v4-mapped addresses
    (::ffff:a.b.c.d -> a.b.c.d)."""
    if not s:
        return None

    pct = s.find("%")
    core = s[:pct] if pct >= 0 else s
    if not core or len(core) >= IP_STR_MAX:
        return None

    # Try IPv4 first — this matches the C ordering (inet_pton AF_INET
    # then AF_INET6). Python's ipaddress doesn't have a "try ipv4
    # only" mode, but ipv4 addresses also parse as ipv4.
    try:
        a4 = ipaddress.IPv4Address(core)
        # IPv4 path: return the input form verbatim (no canonicalization).
        return core
    except ValueError:
        pass

    try:
        a6 = ipaddress.IPv6Address(core)
        # v4-mapped v6: extract IPv4 in canonical form.
        if a6.ipv4_mapped is not None:
            return str(a6.ipv4_mapped)
        # Other IPv6: return input form verbatim.
        return core
    except ValueError:
        return None


def emit_username():
    for line in sys.stdin:
        line = line.rstrip("\n")
        sys.stdout.write(f"{is_valid_username(line)}\n")


def emit_normalize_ip():
    for line in sys.stdin:
        line = line.rstrip("\n")
        result = normalize_ip(line)
        if result is None:
            sys.stdout.write("0|\n")
        else:
            sys.stdout.write(f"1|{result}\n")


def main():
    if len(sys.argv) < 2:
        sys.stderr.write(f"usage: {sys.argv[0]} {{username|normalize_ip}}\n")
        sys.exit(2)
    fn = sys.argv[1]
    if fn == "username":
        emit_username()
    elif fn == "normalize_ip":
        emit_normalize_ip()
    else:
        sys.stderr.write(f"unknown function: {fn}\n")
        sys.exit(2)


if __name__ == "__main__":
    main()

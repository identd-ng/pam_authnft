// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar
//
// Oracle runner: feeds line-oriented stdin through one of pam_authnft's
// small parsers and prints a parser-agnostic result line for each input.
// Paired with tests/oracle/oracle.py — a Python re-implementation of
// the same parser. The driver script tests/oracle/run.sh feeds the same
// corpus through both, diffs the output. Disagreement = logic bug.
//
// I/O contract:
//   stdin:  one input per line, NUL-terminated by stripping '\n'
//   stdout: one result per input, format depends on the function
//   stderr: optional debug output
//   argv[1]: which function to test ("username" or "normalize_ip")
//
// Inputs containing literal newlines or NULs cannot be expressed in
// this protocol; covered by the libFuzzer harnesses instead.

#include "authnft.h"
#include <stdio.h>
#include <string.h>

static void run_username(void) {
    char line[1024];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = '\0';
        printf("%d\n", util_is_valid_username(line));
    }
}

static void run_normalize_ip(void) {
    char line[1024];
    char out[IP_STR_MAX];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = '\0';
        int rc = util_normalize_ip(line, out, sizeof(out));
        if (rc) printf("1|%s\n", out);
        else    printf("0|\n");
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s {username|normalize_ip}\n", argv[0]);
        return 2;
    }
    if      (strcmp(argv[1], "username") == 0)     run_username();
    else if (strcmp(argv[1], "normalize_ip") == 0) run_normalize_ip();
    else {
        fprintf(stderr, "unknown function: %s\n", argv[1]);
        return 2;
    }
    return 0;
}

// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Fuzzer for util_is_valid_username and util_normalize_ip.
 *
 * Both functions accept arbitrary C strings and have no side effects:
 * no file I/O, no syslog, no PAM context required. They are the first
 * gatekeepers for every session open — username validation is the very
 * first thing pam_sm_open_session does before any privileged operation.
 */

#include "authnft.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0)
        return 0;

    /* NUL-terminate — libFuzzer input bytes are not guaranteed to end with 0. */
    char buf[MAX_USER_LEN + 2];
    size_t n = size < sizeof(buf) - 1 ? size : sizeof(buf) - 1;
    memcpy(buf, data, n);
    buf[n] = '\0';

    util_is_valid_username(buf);

    char out[IP_STR_MAX];
    util_normalize_ip(buf, out, sizeof(out));

    return 0;
}

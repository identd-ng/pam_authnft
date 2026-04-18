// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#include "authnft.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <syslog.h>
#include <unistd.h>
#include <security/pam_ext.h>

/*
 * Kernel-keyring (see keyctl(2)) consumer for an opaque, printable-ASCII
 * payload supplied out-of-band by an earlier PAM module. The serial number
 * of the key is conveyed through a configurable PAM env variable; the key
 * itself is held in a session-scoped keyring (see keyrings(7)) and is
 * subject to whatever lifetime, ACL, and timeout the producer set.
 *
 * Sanitization is conservative: anything outside [A-Za-z0-9_=,.:;/-] is
 * replaced with '_'. The result is embedded in nftables comments and so
 * must never contain quote, backslash, or control characters.
 */

/* keyctl(2) command numbers — kept local to avoid an unconditional
 * dependency on <linux/keyctl.h> in the public header. */
#ifndef KEYCTL_READ
#define KEYCTL_READ 11
#endif

static long keyctl_syscall(int op, ...) {
    /* keyctl is variadic at the userspace level but the kernel takes 5
     * unsigned-long args; pass the ones we use and zero-fill. */
    va_list ap;
    va_start(ap, op);
    unsigned long a = va_arg(ap, unsigned long);
    unsigned long b = va_arg(ap, unsigned long);
    unsigned long c = va_arg(ap, unsigned long);
    unsigned long d = va_arg(ap, unsigned long);
    va_end(ap);
    return syscall(SYS_keyctl, op, a, b, c, d);
}

static int is_safe(unsigned char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9'))
        return 1;
    switch (c) {
        case '_': case '=': case ',': case '.': case ':':
        case ';': case '/': case '-':
            return 1;
        default:
            return 0;
    }
}

ssize_t keyring_read_serial(int32_t serial, char *out, size_t out_sz) {
    if (!out || out_sz == 0) return -1;

    char raw[CLAIMS_TAG_MAX * 2 + 1];
    long n = keyctl_syscall(KEYCTL_READ, (unsigned long)(uint32_t)serial,
                            (unsigned long)raw, (unsigned long)sizeof(raw),
                            0UL);
    if (n < 0) return -1;
    if ((size_t)n > sizeof(raw)) return -1;  /* payload truncated; caller logs */

    size_t w = 0;
    for (long i = 0; i < n && w + 1 < out_sz && w < CLAIMS_TAG_MAX; i++) {
        unsigned char c = (unsigned char)raw[i];
        if (c == '\0') break;
        out[w++] = is_safe(c) ? (char)c : '_';
    }
    out[w] = '\0';
    return (ssize_t)w;
}

int keyring_fetch_tag(pam_handle_t *pamh, const char *env_var,
                      char *out, size_t out_sz) {
    if (!pamh || !env_var || !out || out_sz == 0) return 0;
    out[0] = '\0';

    const char *val = pam_getenv(pamh, env_var);
    if (!val || *val == '\0') return 0;

    char *end = NULL;
    errno = 0;
    long parsed = strtol(val, &end, 10);
    if (errno != 0 || end == val || *end != '\0' ||
        parsed < INT32_MIN || parsed > INT32_MAX) {
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: claims env '%s' not a valid key serial", env_var);
        return 0;
    }

    ssize_t got = keyring_read_serial((int32_t)parsed, out, out_sz);
    if (got < 0) {
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: keyctl_read(serial=%ld) failed (payload may "
                   "exceed buffer or key is inaccessible): %m", parsed);
        return 0;
    }
    if (got == 0) {
        DEBUG_PRINT("keyring: serial %ld read but sanitized to empty", parsed);
        return 0;
    }
    DEBUG_PRINT("keyring: serial %ld → tag '%s' (%zd bytes)", parsed, out, got);
    return 1;
}

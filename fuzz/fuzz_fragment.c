// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Fuzzer for validate_fragment_content: the verb/include-path scanner
 * that runs on every per-user nftables fragment before libnftables sees it.
 *
 * validate_fragment_content is compiled as non-static when -DFUZZ_BUILD
 * is set (see the #ifndef FUZZ_BUILD guard in src/nft_handler.c).
 *
 * Fuzz input is presented to the function as a file path via an anonymous
 * in-memory file (memfd_create + /proc/self/fd/<n>). This avoids any
 * actual filesystem writes during corpus replay.
 *
 * pamh=NULL: pam_syslog(NULL, ...) falls back to syslog() which is
 * harmless in a fuzzer process — log output goes to /dev/null or is
 * suppressed by the runtime.
 */

#include "authnft.h"
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

/* Declared non-static when nft_handler.c is compiled with -DFUZZ_BUILD. */
int validate_fragment_content(pam_handle_t *pamh, const char *path);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int fd = memfd_create("fuzz_frag", MFD_CLOEXEC);
    if (fd < 0)
        return 0;

    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0;
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    validate_fragment_content(NULL, path);

    close(fd);

    /* Cover the fopen-failure branch (`if (!f) return -1;`). The memfd
     * path above always opens successfully, so this branch would
     * otherwise sit at zero hits in `make fuzz-coverage`. Cheap. */
    validate_fragment_content(NULL, "/dev/null/no-such-path");

    return 0;
}

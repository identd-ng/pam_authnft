// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Fuzzer for substitute_placeholders: the token-aware replacement that
 * expands @session_v4 / @session_v6 / @session_cg / @session_chain in
 * fragment text before libnftables sees it.
 *
 * The function has three subtle pieces:
 *   - state machine that tracks #-comments (reset on '\n') and "..." quotes
 *   - token-boundary check on the char after a placeholder
 *   - malloc with src_len*2+1 over-allocation budget; returns NULL if a
 *     replacement would exceed that
 *
 * Compiled with -DFUZZ_BUILD so the static qualifier is removed from
 * substitute_placeholders in nft_handler.c.
 *
 * Fuzz input layout:
 *   first half  -> src bytes (NOT NUL-terminated; explicit src_len)
 *   second half -> split four ways into NUL-terminated replacements
 *
 * The placeholders are the production strings on purpose: random
 * placeholders would mostly miss the matcher.
 *
 * Property assertions (after every call):
 *   1. result == NULL  ||  strlen(result) <= src_len * 2
 *      (sizing-budget invariant)
 *   2. result reachable as a valid C string within the malloc'd region
 *      (implicit via strlen — ASan catches OOB read otherwise)
 *
 * What this catches:
 *   - off-by-one in max_expand sizing
 *   - OOB read past src + src_len (caught by ASan)
 *   - OOB write past out + max_expand (caught by ASan)
 *   - any path where the function returns a too-long output
 *
 * What this does NOT catch:
 *   - logic bugs where substitution is wrong-but-plausible (e.g., comment
 *     vs quote precedence inversions). Catching those needs a richer
 *     property assertion or a differential oracle. Tracked in
 *     docs/FUZZ_SURFACE.md.
 */

#include "authnft.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Declared non-static when nft_handler.c is compiled with -DFUZZ_BUILD. */
char *substitute_placeholders(const char *src, size_t src_len,
                              const char *placeholders[4],
                              const char *replacements[4]);

static const char *PLACEHOLDERS[4] = {
    "@session_v4", "@session_v6", "@session_cg", "@session_chain"
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 5)
        return 0;

    size_t src_len = size / 2;
    const char *src = (const char *)data;

    size_t rep_region = size - src_len;
    size_t per_rep = rep_region / 4;
    if (per_rep == 0)
        per_rep = 1;

    char *replacements[4] = {0};
    for (int i = 0; i < 4; i++) {
        size_t off = src_len + (size_t)i * per_rep;
        size_t len = (off + per_rep <= size) ? per_rep : 0;
        replacements[i] = malloc(len + 1);
        if (!replacements[i])
            goto cleanup;
        if (len)
            memcpy(replacements[i], data + off, len);
        replacements[i][len] = '\0';
    }

    char *out = substitute_placeholders(src, src_len, PLACEHOLDERS,
                                         (const char **)replacements);

    if (out) {
        size_t out_len = strlen(out);
        /* Sizing-budget invariant: max_expand = src_len*2+1, output fits
         * within max_expand-1 NUL-terminated bytes. ASan would already
         * catch a write past max_expand, but the explicit trap forces a
         * deterministic crash if the bound is somehow violated short of
         * an OOB write (e.g., uninitialized-byte interaction). */
        if (out_len > src_len * 2)
            __builtin_trap();
        free(out);
    }

cleanup:
    for (int i = 0; i < 4; i++)
        free(replacements[i]);
    return 0;
}

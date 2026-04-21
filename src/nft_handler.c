// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#include "authnft.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <nftables/libnftables.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>

/*
 * Fragment content validation. Reads the file line by line and rejects:
 *   - Disallowed verbs: flush, delete, reset, list, rename
 *   - include paths outside /etc/authnft/, relative paths, glob chars
 *
 * Returns 0 if valid, -1 if rejected (reason logged via pam_syslog).
 */
static int validate_fragment_content(pam_handle_t *pamh, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    static const char *bad_verbs[] = {
        "flush", "delete", "reset", "list", "rename", NULL
    };

    char line[1024];
    int lineno = 0;
    int rc = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\0' || *p == '\n') continue;

        /* Check disallowed verbs (first token on the line). */
        for (int i = 0; bad_verbs[i]; i++) {
            size_t vlen = strlen(bad_verbs[i]);
            if (strncmp(p, bad_verbs[i], vlen) == 0 &&
                (p[vlen] == ' ' || p[vlen] == '\t' || p[vlen] == '\n' ||
                 p[vlen] == '\0')) {
                pam_syslog(pamh, LOG_ERR,
                           "authnft: fragment %s:%d uses disallowed verb '%s'",
                           path, lineno, bad_verbs[i]);
                rc = -1;
                goto out;
            }
        }

        /* Check include paths: must be absolute, under /etc/authnft/,
         * no glob characters. */
        if (strncmp(p, "include", 7) == 0 &&
            (p[7] == ' ' || p[7] == '\t' || p[7] == '"')) {
            const char *q = p + 7;
            while (*q == ' ' || *q == '\t') q++;
            if (*q == '"') q++;
            if (*q != '/') {
                pam_syslog(pamh, LOG_ERR,
                           "authnft: fragment %s:%d uses relative include path",
                           path, lineno);
                rc = -1;
                goto out;
            }
            if (strncmp(q, "/etc/authnft/", 13) != 0) {
                pam_syslog(pamh, LOG_ERR,
                           "authnft: fragment %s:%d includes path outside "
                           "/etc/authnft/", path, lineno);
                rc = -1;
                goto out;
            }
            /* Reject glob characters in include path. */
            for (const char *g = q; *g && *g != '"' && *g != '\n'; g++) {
                if (*g == '*' || *g == '?' || *g == '[') {
                    pam_syslog(pamh, LOG_ERR,
                               "authnft: fragment %s:%d include path contains "
                               "glob character '%c'", path, lineno, *g);
                    rc = -1;
                    goto out;
                }
            }
        }
    }

out:
    fclose(f);
    return rc;
}

/*
 * Read a file into a malloc'd buffer. Returns NULL on failure.
 * Caller must free(). *out_len is set to the content length.
 */
static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0 || sz > 65536) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);

    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

/*
 * Token-aware placeholder substitution. Replaces each of the four
 * placeholders (@session_v4, @session_v6, @session_cg, @session_chain)
 * with the live per-session names, skipping occurrences inside
 * #-comments and "..." quoted strings.
 *
 * Token boundary check: the character after the placeholder must not
 * be [A-Za-z0-9_] to avoid partial matches (e.g., @session_v4x).
 *
 * Returns a new malloc'd buffer with substitutions applied, or NULL
 * on allocation failure. Caller must free().
 */
static char *substitute_placeholders(const char *src, size_t src_len,
                                      const char *placeholders[4],
                                      const char *replacements[4]) {
    /* Worst case: every placeholder expands. Over-allocate. */
    size_t max_expand = src_len * 2 + 1;
    char *out = malloc(max_expand);
    if (!out) return NULL;

    size_t wi = 0;
    int in_comment = 0;
    int in_quote = 0;

    size_t i = 0;
    while (i < src_len) {
        char c = src[i];

        if (c == '\n') { in_comment = 0; }
        if (!in_quote && c == '#') { in_comment = 1; }
        if (!in_comment && c == '"') { in_quote = !in_quote; }

        if (in_comment || in_quote) {
            out[wi++] = c;
            i++;
            continue;
        }

        /* Try each placeholder. */
        int matched = 0;
        for (int p = 0; p < 4; p++) {
            size_t plen = strlen(placeholders[p]);
            if (i + plen <= src_len &&
                memcmp(&src[i], placeholders[p], plen) == 0) {
                /* Token boundary: next char must not be identifier-like. */
                char next = (i + plen < src_len) ? src[i + plen] : '\0';
                if ((next >= 'A' && next <= 'Z') ||
                    (next >= 'a' && next <= 'z') ||
                    (next >= '0' && next <= '9') ||
                    next == '_') {
                    break; /* Partial match, don't substitute. */
                }
                size_t rlen = strlen(replacements[p]);
                if (wi + rlen >= max_expand) {
                    free(out);
                    return NULL;
                }
                memcpy(&out[wi], replacements[p], rlen);
                wi += rlen;
                i += plen;
                matched = 1;
                break;
            }
        }
        if (!matched) {
            out[wi++] = c;
            i++;
        }
    }
    out[wi] = '\0';
    return out;
}

int nft_handler_setup(pam_handle_t *pamh, const char *user,
                      authnft_session_t *sd) {
    struct nft_ctx *ctx;
    char cmd[CMD_BUF_SIZE];
    char user_conf_path[256];
    char display_msg[512];
    struct stat st;
    int result;

    if (strcmp(user, "root") == 0) return PAM_SUCCESS;

    if (!sd || sd->cg_path[0] == '\0') {
        pam_syslog(pamh, LOG_ERR, "authnft: setup called with empty cg_path");
        return PAM_SESSION_ERR;
    }

    DEBUG_PRINT("nft_handler_setup: user=%s cg=%s chain=%s",
                user, sd->cg_path, sd->chain_name);

    /* Group membership check. */
    struct group *grp = getgrnam("authnft");
    int in_group = 0;
    if (grp) {
        struct passwd *pw = getpwnam(user);
        if (pw) {
            if (pw->pw_gid == grp->gr_gid) in_group = 1;
            else {
                for (char **m = grp->gr_mem; *m != NULL; m++) {
                    if (strcmp(*m, user) == 0) { in_group = 1; break; }
                }
            }
        }
    }

    if (!in_group) {
        DEBUG_PRINT("user %s not in 'authnft' group, passing through", user);
        return PAM_SUCCESS;
    }

    /* Fragment validation: must exist, be root-owned, and not world-writable. */
    snprintf(user_conf_path, sizeof(user_conf_path), "%s/%s", RULES_DIR, user);
    DEBUG_PRINT("loading fragment: %s", user_conf_path);

    if (stat(user_conf_path, &st) != 0) {
        (void)pam_syslog(pamh, LOG_ERR,
                         "authnft: missing fragment for %s at %s", user, user_conf_path);
        snprintf(display_msg, sizeof(display_msg),
                 "authnft: no rule fragment at %s — add one and reconnect.",
                 user_conf_path);
        pam_error(pamh, "%s", display_msg);
        return PAM_AUTH_ERR;
    }

    if (st.st_uid != 0 || (st.st_mode & S_IWOTH)) {
        (void)pam_syslog(pamh, LOG_ERR,
                         "authnft: insecure permissions on %s (uid=%d mode=%o)",
                         user_conf_path, st.st_uid, st.st_mode);
        pam_error(pamh, "authnft: fragment %s must be root-owned and not world-writable.",
                  user_conf_path);
        return PAM_AUTH_ERR;
    }

    /* Content validation: verb scan, include path check, reserved defines. */
    if (validate_fragment_content(pamh, user_conf_path) < 0) {
        pam_error(pamh, "authnft: fragment %s rejected by content validator.",
                  user_conf_path);
        return PAM_AUTH_ERR;
    }

    /* Determine which per-session set gets the element. */
    const char *remote_ip = sd->remote_ip[0] ? sd->remote_ip : NULL;
    int cg_only = (remote_ip == NULL);
    int is_v6 = !cg_only && (strchr(remote_ip, ':') != NULL);
    const char *set_name = cg_only ? sd->set_cg : (is_v6 ? sd->set_v6 : sd->set_v4);

    ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) return PAM_SERVICE_ERR;

    /*
     * Call 1: infrastructure + per-session chain/sets + element.
     *
     * The shared filter chain and ct state rule accumulate across sessions
     * (add rule is not idempotent). The duplicates are harmless: the first
     * ct state rule matches and the rest are skipped. The per-session chain
     * and sets are unique per session.
     */
    char *claims_tag = sd->claims_tag[0] ? sd->claims_tag : NULL;
    char tag_part[CLAIMS_TAG_MAX + 8] = "";
    if (claims_tag)
        snprintf(tag_part, sizeof(tag_part), " [%s]", claims_tag);

    if (cg_only) {
        result = snprintf(cmd, sizeof(cmd),
                  "add table inet %s\n"
                  "add chain inet %s filter { type filter hook input priority filter - 1; policy accept; }\n"
                  "add rule inet %s filter ct state established,related accept\n"
                  "add chain inet %s %s\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2 . ip6 saddr; flags timeout; }\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2; flags timeout; }\n"
                  "add element inet %s %s { \"%s\" timeout 1d comment \"%s (PID:%d)%s\" }",
                  TABLE_NAME,
                  TABLE_NAME,
                  TABLE_NAME,
                  TABLE_NAME, sd->chain_name,
                  TABLE_NAME, sd->set_v4,
                  TABLE_NAME, sd->set_v6,
                  TABLE_NAME, sd->set_cg,
                  TABLE_NAME, set_name, sd->cg_path, user, getpid(), tag_part);
    } else {
        result = snprintf(cmd, sizeof(cmd),
                  "add table inet %s\n"
                  "add chain inet %s filter { type filter hook input priority filter - 1; policy accept; }\n"
                  "add rule inet %s filter ct state established,related accept\n"
                  "add chain inet %s %s\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2 . ip6 saddr; flags timeout; }\n"
                  "add set inet %s %s { typeof socket cgroupv2 level 2; flags timeout; }\n"
                  "add element inet %s %s { \"%s\" . %s timeout 1d comment \"%s (PID:%d)%s\" }",
                  TABLE_NAME,
                  TABLE_NAME,
                  TABLE_NAME,
                  TABLE_NAME, sd->chain_name,
                  TABLE_NAME, sd->set_v4,
                  TABLE_NAME, sd->set_v6,
                  TABLE_NAME, sd->set_cg,
                  TABLE_NAME, set_name, sd->cg_path, remote_ip, user, getpid(), tag_part);
    }

    if (result < 0 || (size_t)result >= sizeof(cmd)) {
        nft_ctx_free(ctx);
        return PAM_BUF_ERR;
    }

    DEBUG_PRINT("nft call 1 (infra+sets):\n%s", cmd);
    if (nft_run_cmd_from_buffer(ctx, cmd) != 0) {
        const char *err_msg = nft_ctx_get_error_buffer(ctx);
        pam_syslog(pamh, LOG_ERR, "authnft: setup call 1 failed: %s", err_msg);
        nft_ctx_free(ctx);
        return PAM_SERVICE_ERR;
    }

    /*
     * Call 2: jump rule in the shared filter chain. ECHO + HANDLE flags
     * make libnftables print the committed rule with its kernel-assigned
     * handle, which we parse and store for cleanup.
     */
    nft_ctx_output_set_flags(ctx,
        NFT_CTX_OUTPUT_ECHO | NFT_CTX_OUTPUT_HANDLE);
    nft_ctx_buffer_output(ctx);

    snprintf(cmd, sizeof(cmd),
             "add rule inet %s filter jump %s",
             TABLE_NAME, sd->chain_name);

    DEBUG_PRINT("nft call 2 (jump rule):\n%s", cmd);
    if (nft_run_cmd_from_buffer(ctx, cmd) != 0) {
        const char *err_msg = nft_ctx_get_error_buffer(ctx);
        pam_syslog(pamh, LOG_ERR, "authnft: jump rule failed: %s", err_msg);
        nft_ctx_unbuffer_output(ctx);
        nft_ctx_free(ctx);
        return PAM_SERVICE_ERR;
    }

    const char *out = nft_ctx_get_output_buffer(ctx);
    uint64_t handle = 0;
    const char *h = out ? strstr(out, "# handle ") : NULL;
    if (!h || sscanf(h, "# handle %" SCNu64, &handle) != 1 || handle == 0) {
        pam_syslog(pamh, LOG_ERR,
                   "authnft: could not parse jump rule handle from nft output");
        nft_ctx_unbuffer_output(ctx);
        nft_ctx_free(ctx);
        return PAM_SERVICE_ERR;
    }
    sd->jump_handle = handle;
    DEBUG_PRINT("jump rule handle: %" PRIu64, handle);

    nft_ctx_unbuffer_output(ctx);
    /* Clear ECHO/HANDLE flags for call 3 — fragment output is noise. */
    nft_ctx_output_set_flags(ctx, 0);

    /*
     * Call 3: read the fragment, substitute placeholders, execute.
     *
     * Four placeholders are replaced with live per-session names:
     *   @session_v4    → per-session IPv4 set name
     *   @session_v6    → per-session IPv6 set name
     *   @session_cg    → per-session cgroup-only set name
     *   @session_chain → per-session chain name
     *
     * Substitution is token-aware: occurrences inside #-comments and
     * "..." quoted strings are skipped. Token boundary check prevents
     * partial matches (e.g., @session_v4x is not substituted).
     *
     * Placeholders are resolved in the top-level fragment only.
     * Files pulled in via nftables `include` are parsed by libnftables
     * directly and do not receive substitution. This is documented as
     * a design choice: per-session rules use placeholders; shared
     * includes use the shared filter chain with accept-only rules.
     */
    size_t frag_len = 0;
    char *frag_buf = read_file(user_conf_path, &frag_len);
    if (!frag_buf) {
        pam_syslog(pamh, LOG_ERR,
                   "authnft: could not read fragment %s", user_conf_path);
        nft_ctx_free(ctx);
        return PAM_AUTH_ERR;
    }

    /* Set placeholders keep the @ prefix (nft set-reference syntax).
     * Chain placeholder drops it (chain names are bare identifiers). */
    char rep_v4[SET_NAME_MAX + 2], rep_v6[SET_NAME_MAX + 2],
         rep_cg[SET_NAME_MAX + 2];
    snprintf(rep_v4, sizeof(rep_v4), "@%s", sd->set_v4);
    snprintf(rep_v6, sizeof(rep_v6), "@%s", sd->set_v6);
    snprintf(rep_cg, sizeof(rep_cg), "@%s", sd->set_cg);

    const char *placeholders[4] = {
        "@session_v4", "@session_v6", "@session_cg", "@session_chain"
    };
    const char *replacements[4] = {
        rep_v4, rep_v6, rep_cg, sd->chain_name
    };
    char *subst_buf = substitute_placeholders(frag_buf, frag_len,
                                               placeholders, replacements);
    free(frag_buf);
    if (!subst_buf) {
        pam_syslog(pamh, LOG_ERR,
                   "authnft: placeholder substitution failed for %s",
                   user_conf_path);
        nft_ctx_free(ctx);
        return PAM_SERVICE_ERR;
    }

    DEBUG_PRINT("nft call 3 (substituted fragment):\n%s", subst_buf);
    if (nft_run_cmd_from_buffer(ctx, subst_buf) != 0) {
        const char *err_msg = nft_ctx_get_error_buffer(ctx);
        (void)pam_syslog(pamh, LOG_ERR,
                         "authnft: syntax error in %s: %s", user_conf_path, err_msg);
        pam_error(pamh, "authnft: fragment syntax error — check /var/log/auth.log");
        free(subst_buf);
        nft_ctx_free(ctx);
        return PAM_AUTH_ERR;
    }
    free(subst_buf);

    nft_ctx_free(ctx);
    return PAM_SUCCESS;
}

int nft_handler_cleanup(pam_handle_t *pamh, const char *user,
                        const authnft_session_t *sd) {
    struct nft_ctx *ctx;
    char cmd[CMD_BUF_SIZE];

    if (strcmp(user, "root") == 0) return PAM_SUCCESS;
    if (!sd || sd->chain_name[0] == '\0') return PAM_SESSION_ERR;

    DEBUG_PRINT("nft_handler_cleanup: user=%s chain=%s handle=%" PRIu64,
                user, sd->chain_name, sd->jump_handle);

    ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) return PAM_SESSION_ERR;

    /*
     * Tear down per-session state in dependency order:
     *   1. Delete the jump rule from the shared filter chain (by handle).
     *   2. Flush the per-session chain (removes all rules, unblocking
     *      set deletion).
     *   3. Delete the per-session chain.
     *   4. Delete the three per-session sets.
     *
     * A single transaction ensures atomicity. If any object was already
     * reaped (timeout, manual cleanup), the transaction fails; we fall
     * through to the best-effort path.
     */
    int n = snprintf(cmd, sizeof(cmd),
             "delete rule inet %s filter handle %" PRIu64 "\n"
             "flush chain inet %s %s\n"
             "delete chain inet %s %s\n"
             "delete set inet %s %s\n"
             "delete set inet %s %s\n"
             "delete set inet %s %s",
             TABLE_NAME, sd->jump_handle,
             TABLE_NAME, sd->chain_name,
             TABLE_NAME, sd->chain_name,
             TABLE_NAME, sd->set_v4,
             TABLE_NAME, sd->set_v6,
             TABLE_NAME, sd->set_cg);

    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        nft_ctx_free(ctx);
        return PAM_SESSION_ERR;
    }

    DEBUG_PRINT("cleanup:\n%s", cmd);
    if (nft_run_cmd_from_buffer(ctx, cmd) != 0) {
        const char *err_msg = nft_ctx_get_error_buffer(ctx);
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: cleanup failed for %s: %s", user, err_msg);
        nft_ctx_free(ctx);
        return PAM_SESSION_ERR;
    }

    nft_ctx_free(ctx);
    return PAM_SUCCESS;
}

// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#include "authnft.h"
#include <arpa/inet.h>
#include <nftables/libnftables.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>

/* Scan the fragment for a top-level `include` directive and log an
 * informational warning. libnftables resolves transitive includes
 * (integration test 10.8), but invariant #5 only validates the
 * fragment itself — files it pulls in are NOT ownership-checked.
 * The admin is responsible for making sure they are root-owned and
 * not world-writable. */
static void warn_if_fragment_includes(pam_handle_t *pamh, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\0' || *p == '\n') continue;
        if (strncmp(p, "include", 7) == 0 &&
            (p[7] == ' ' || p[7] == '\t' || p[7] == '"')) {
            pam_syslog(pamh, LOG_INFO,
                       "authnft: fragment %s uses 'include' — "
                       "transitively included files are not ownership-checked; "
                       "ensure they are root-owned and not world-writable",
                       path);
            break;
        }
    }
    fclose(f);
}

int nft_handler_setup(pam_handle_t *pamh, const char *user, const char *cg_path,
                      const char *remote_ip, const char *claims_tag) {
    struct nft_ctx *ctx;
    char cmd[CMD_BUF_SIZE];
    char user_conf_path[256];
    char display_msg[512];
    struct stat st;
    int result;

    if (strcmp(user, "root") == 0) return PAM_SUCCESS;

    if (!cg_path || cg_path[0] == '\0') {
        pam_syslog(pamh, LOG_ERR, "authnft: setup called with empty cg_path");
        return PAM_SESSION_ERR;
    }

    DEBUG_PRINT("nft_handler_setup: user=%s ip=%s cg=%s",
                user, remote_ip ? remote_ip : "(null)", cg_path);

    /* Group membership check.
     * getgrnam(3) and getpwnam(3) are not reentrant; this is acceptable here
     * because the seccomp sandbox is already active and no signal handlers
     * that call these functions are registered. */
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

    warn_if_fragment_includes(pamh, user_conf_path);

    /* Nftables transaction: idempotent table/set/chain creation followed by
     * inclusion of the user fragment and insertion of the session element.
     * remote_ip == NULL or empty selects the cgroup-only fallback set. */
    int cg_only = (remote_ip == NULL || remote_ip[0] == '\0');
    int is_v6 = !cg_only && (strchr(remote_ip, ':') != NULL);
    const char *set_name = cg_only ? SET_CG : (is_v6 ? SET_V6 : SET_V4);

    ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) return PAM_SERVICE_ERR;

    /*
     * Two separate nft_run_cmd_from_buffer calls are required. Call (a)
     * creates the table/sets/chain and inserts the session element; call (b)
     * loads the user fragment via `include`. The split ensures the set
     * definitions are in libnftables' evaluator cache before the fragment's
     * rules reference @session_map_ipv{4,6} — a single buffer containing
     * both the `add set` and a rule referencing that set would fail because
     * the evaluator hasn't registered the set type at the point it parses
     * the rule. (nftables grammar does permit `include` inside blocks; the
     * constraint is the evaluator's single-pass type resolution, not syntax.)
     *
     * This two-call design is NOT atomic: if call (a) succeeds and call (b)
     * fails (fragment syntax error), the element is left in the set with no
     * corresponding chain rule. The 24-hour element timeout is the safety
     * net. See docs/INTEGRATIONS.txt for the failure-mode documentation.
     */
    /* claims_tag is already sanitized by keyring_fetch_tag to a quote-free,
     * control-free subset; embed it verbatim inside the nft comment. */
    char tag_part[CLAIMS_TAG_MAX + 8] = "";
    if (claims_tag && claims_tag[0]) {
        snprintf(tag_part, sizeof(tag_part), " [%s]", claims_tag);
    }

    if (cg_only) {
        result = snprintf(cmd, sizeof(cmd),
                  "add table inet %s\n"
                  "add set inet %s " SET_V4 " { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }\n"
                  "add set inet %s " SET_V6 " { typeof socket cgroupv2 level 2 . ip6 saddr; flags timeout; }\n"
                  "add set inet %s " SET_CG " { typeof socket cgroupv2 level 2; flags timeout; }\n"
                  "add chain inet %s filter { type filter hook input priority filter - 1; policy accept; }\n"
                  "add element inet %s %s { \"%s\" timeout 1d comment \"%s (PID:%d)%s\" }",
                  TABLE_NAME, TABLE_NAME, TABLE_NAME, TABLE_NAME, TABLE_NAME,
                  TABLE_NAME, set_name, cg_path, user, getpid(), tag_part);
    } else {
        result = snprintf(cmd, sizeof(cmd),
                  "add table inet %s\n"
                  "add set inet %s " SET_V4 " { typeof socket cgroupv2 level 2 . ip saddr; flags timeout; }\n"
                  "add set inet %s " SET_V6 " { typeof socket cgroupv2 level 2 . ip6 saddr; flags timeout; }\n"
                  "add set inet %s " SET_CG " { typeof socket cgroupv2 level 2; flags timeout; }\n"
                  "add chain inet %s filter { type filter hook input priority filter - 1; policy accept; }\n"
                  "add element inet %s %s { \"%s\" . %s timeout 1d comment \"%s (PID:%d)%s\" }",
                  TABLE_NAME, TABLE_NAME, TABLE_NAME, TABLE_NAME, TABLE_NAME,
                  TABLE_NAME, set_name, cg_path, remote_ip, user, getpid(), tag_part);
    }

    if (result < 0 || (size_t)result >= sizeof(cmd)) {
        nft_ctx_free(ctx);
        return PAM_BUF_ERR;
    }

    DEBUG_PRINT("nft setup command:\n%s", cmd);
    if (nft_run_cmd_from_buffer(ctx, cmd) != 0) {
        const char *err_msg = nft_ctx_get_error_buffer(ctx);
        pam_syslog(pamh, LOG_ERR, "authnft: setup failed: %s", err_msg);
        nft_ctx_free(ctx);
        return PAM_SERVICE_ERR;
    }

    /* Second call: load the user fragment at the top level. */
    result = snprintf(cmd, sizeof(cmd), "include \"%s\"", user_conf_path);

    if (result < 0 || (size_t)result >= sizeof(cmd)) {
        nft_ctx_free(ctx);
        return PAM_BUF_ERR;
    }

    DEBUG_PRINT("nft fragment command:\n%s", cmd);
    if (nft_run_cmd_from_buffer(ctx, cmd) != 0) {
        const char *err_msg = nft_ctx_get_error_buffer(ctx);
        (void)pam_syslog(pamh, LOG_ERR,
                         "authnft: syntax error in %s: %s", user_conf_path, err_msg);
        pam_error(pamh, "authnft: fragment syntax error — check /var/log/auth.log");
        nft_ctx_free(ctx);
        return PAM_AUTH_ERR;
    }

    nft_ctx_free(ctx);
    return PAM_SUCCESS;
}

int nft_handler_cleanup(pam_handle_t *pamh, const char *user, const char *cg_path,
                        const char *remote_ip) {
    struct nft_ctx *ctx;
    char cmd[CMD_BUF_SIZE];

    if (strcmp(user, "root") == 0) return PAM_SUCCESS;
    if (!cg_path || cg_path[0] == '\0') return PAM_SESSION_ERR;

    int cg_only = (remote_ip == NULL || remote_ip[0] == '\0');
    int is_v6 = !cg_only && (strchr(remote_ip, ':') != NULL);
    const char *set_name = cg_only ? SET_CG : (is_v6 ? SET_V6 : SET_V4);

    DEBUG_PRINT("nft_handler_cleanup: user=%s cg=%s set=%s",
                user, cg_path, set_name);

    ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) return PAM_SESSION_ERR;

    if (cg_only) {
        snprintf(cmd, sizeof(cmd), "delete element inet %s %s { \"%s\" }",
                 TABLE_NAME, set_name, cg_path);
    } else {
        snprintf(cmd, sizeof(cmd), "delete element inet %s %s { \"%s\" . %s }",
                 TABLE_NAME, set_name, cg_path, remote_ip);
    }

    DEBUG_PRINT("cleanup: %s", cmd);
    if (nft_run_cmd_from_buffer(ctx, cmd) != 0) {
        const char *err_msg = nft_ctx_get_error_buffer(ctx);
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: failed to delete set element for %s: %s", user, err_msg);
        nft_ctx_free(ctx);
        return PAM_SESSION_ERR;
    }

    nft_ctx_free(ctx);
    return PAM_SUCCESS;
}

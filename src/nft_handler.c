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

int nft_handler_setup(pam_handle_t *pamh, const char *user, uint64_t cg_id,
                      const char *remote_ip) {
    struct nft_ctx *ctx;
    char cmd[CMD_BUF_SIZE];
    char user_conf_path[256];
    char display_msg[512];
    struct stat st;
    int result;

    if (strcmp(user, "root") == 0) return PAM_SUCCESS;

    DEBUG_PRINT("nft_handler_setup: user=%s ip=%s cg=%llu",
                user, remote_ip, (unsigned long long)cg_id);

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

    /* Nftables transaction: idempotent table/set/chain creation followed by
     * inclusion of the user fragment and insertion of the session element. */
    int is_v6 = (strchr(remote_ip, ':') != NULL);
    const char *set_name = is_v6 ? "session_map_ipv6" : "session_map_ipv4";

    ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) return PAM_SERVICE_ERR;

    /*
     * Two separate nft_run_cmd_from_buffer calls are required: nftables does not
     * support 'include' inside nested declarative blocks via the libnftables API.
     * The element is inserted first so the set exists before any rules in the
     * fragment can reference it.
     */
    result = snprintf(cmd, sizeof(cmd),
                  "add table inet %s\n"
                  "add set inet %s session_map_ipv4 { typeof meta cgroup . ip saddr; flags timeout; }\n"
                  "add set inet %s session_map_ipv6 { typeof meta cgroup . ip6 saddr; flags timeout; }\n"
                  "add chain inet %s filter { type filter hook input priority filter - 1; policy accept; }\n"
                  "add element inet %s %s { %llu . %s timeout 1d comment \"%s (PID:%d)\" }",
                  TABLE_NAME, TABLE_NAME, TABLE_NAME, TABLE_NAME,
                  TABLE_NAME, set_name, (unsigned long long)cg_id, remote_ip, user, getpid());

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

int nft_handler_cleanup(pam_handle_t *pamh, const char *user, uint64_t cg_id,
                        const char *remote_ip) {
    struct nft_ctx *ctx;
    char cmd[CMD_BUF_SIZE];

    if (strcmp(user, "root") == 0) return PAM_SUCCESS;
    if (!remote_ip || cg_id == 0) return PAM_SESSION_ERR;

    DEBUG_PRINT("nft_handler_cleanup: user=%s cg=%llu", user, (unsigned long long)cg_id);

    int is_v6 = (strchr(remote_ip, ':') != NULL);
    const char *set_name = is_v6 ? "session_map_ipv6" : "session_map_ipv4";

    ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) return PAM_SESSION_ERR;

    snprintf(cmd, sizeof(cmd), "delete element inet %s %s { %llu . %s }",
             TABLE_NAME, set_name, (unsigned long long)cg_id, remote_ip);

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

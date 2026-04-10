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
    
    DEBUG_PRINT("Entering nft_handler_setup for user: %s (IP: %s, CG: %llu)", 
                user, remote_ip, (unsigned long long)cg_id);

    // 1. Group Membership Check
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
        DEBUG_PRINT("User %s not in 'authnft' group. Passing through.", user);
        return PAM_SUCCESS;
    }

    // 2. Fragment Validation
    snprintf(user_conf_path, sizeof(user_conf_path), "%s/%s", RULES_DIR, user);
    DEBUG_PRINT("Loading fragment: %s", user_conf_path);

    if (stat(user_conf_path, &st) != 0) {
        DEBUG_PRINT("REJECT: Missing fragment at %s", user_conf_path);
        snprintf(display_msg, sizeof(display_msg), 
                 "Your account is missing a %s nft rule fragment, add it and reconnect.", 
                 user_conf_path);
        (void)pam_syslog(pamh, LOG_ERR, "authnft: MISSING CONFIG for %s at %s", user, user_conf_path);
        pam_error(pamh, "%s", display_msg); 
        return PAM_AUTH_ERR;
    }

    if (st.st_uid != 0 || (st.st_mode & S_IWOTH)) {
        DEBUG_PRINT("Security: Fragment %s has insecure permissions (UID: %d, Mode: %o)", user_conf_path, st.st_uid, st.st_mode);
        (void)pam_syslog(pamh, LOG_ERR, "authnft: REJECT - Insecure permissions on %s", user_conf_path);
        pam_error(pamh, "Your authnft fragment has insecure permissions (must be root-owned).");
        return PAM_AUTH_ERR;
    }

    // 3. Nftables Transaction
    int is_v6 = (strchr(remote_ip, ':') != NULL);
    const char *set_name = is_v6 ? "session_map_ipv6" : "session_map_ipv4";

    ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) return PAM_SERVICE_ERR;

    result = snprintf(cmd, sizeof(cmd),
                  "add table inet %s\n"
                  "add set inet %s session_map_ipv4 { typeof meta cgroup . ip saddr; flags timeout; }\n"
                  "add set inet %s session_map_ipv6 { typeof meta cgroup . ip6 saddr; flags timeout; }\n"
                  "add chain inet %s filter { type filter hook input priority filter - 1; policy accept; }\n"
                  "include \"%s\"\n"
                  "add element inet %s %s { %llu . %s comment \"%s (PID:%d)\" }",
                  TABLE_NAME, TABLE_NAME, TABLE_NAME, TABLE_NAME, 
                  user_conf_path,
                  TABLE_NAME, set_name, (unsigned long long)cg_id, remote_ip, user, getpid());

    if (result < 0 || (size_t)result >= sizeof(cmd)) {
        nft_ctx_free(ctx);
        return PAM_BUF_ERR;
    }

    DEBUG_PRINT("Executing nft command:\n%s", cmd);
    result = nft_run_cmd_from_buffer(ctx, cmd);
    if (result != 0) {
        const char *err_msg = nft_ctx_get_error_buffer(ctx);
        DEBUG_PRINT("Nftables Error: %s", err_msg);
        (void)pam_syslog(pamh, LOG_ERR, "authnft: SYNTAX ERROR in %s: %s", user_conf_path, err_msg);
        pam_error(pamh, "Your authnft fragment has a syntax error. Check /var/log/auth.log");
        nft_ctx_free(ctx);
        return PAM_AUTH_ERR;
    }

    nft_ctx_free(ctx);
    return PAM_SUCCESS;
}

int nft_handler_cleanup(pam_handle_t *pamh, const char *user, int session_pid, const char *remote_ip) {
    struct nft_ctx *ctx;
    char cmd[CMD_BUF_SIZE];
    uint64_t cg_id = 0;

    if (strcmp(user, "root") == 0) return PAM_SUCCESS;
    if (!remote_ip) return PAM_SESSION_ERR;

    DEBUG_PRINT("Cleaning up session for user: %s (PID: %d)", user, session_pid);

    if (util_get_cgroup_id(session_pid, &cg_id) < 0) {
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: cleanup: could not resolve cgroup for pid %d", session_pid);
        return PAM_SESSION_ERR;
    }

    int is_v6 = (strchr(remote_ip, ':') != NULL);
    const char *set_name = is_v6 ? "session_map_ipv6" : "session_map_ipv4";

    ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) return PAM_SESSION_ERR;

    snprintf(cmd, sizeof(cmd), "delete element inet %s %s { %llu . %s }", 
             TABLE_NAME, set_name, (unsigned long long)cg_id, remote_ip);
  
    DEBUG_PRINT("Executing cleanup: %s", cmd);
    (void)nft_run_cmd_from_buffer(ctx, cmd);
    nft_ctx_free(ctx);
    return PAM_SUCCESS;
}

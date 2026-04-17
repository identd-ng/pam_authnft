// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#include "authnft.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

static void free_pam_data(pam_handle_t *pamh, void *data, int error_status) {
    (void)pamh; (void)error_status;
    free(data);
}

static int is_debug_bypass_requested(int argc, const char **argv) {
    if (getenv("AUTHNFT_NO_SANDBOX")) return 1;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "AUTHNFT_NO_SANDBOX=1") == 0)
            return 1;
    }
    return 0;
}

int util_is_valid_username(const char *user) {
    if (!user || *user == '\0') return 0;
    size_t len = strlen(user);
    if (len > MAX_USER_LEN || user[0] == '-' || user[0] == '.') return 0;
    for (size_t i = 0; i < len; i++) {
        if (!isalnum((unsigned char)user[i]) &&
            user[i] != '-' && user[i] != '_' && user[i] != '.')
            return 0;
    }
    return 1;
}

int util_normalize_ip(const char *in, char *out, size_t out_sz) {
    if (!in || !out || out_sz == 0) return 0;
    unsigned char addr_buf[sizeof(struct in6_addr)];

    /* Strip an IPv6 zone suffix ("fe80::1%eth0" -> "fe80::1"). nftables
     * ip6 saddr does not accept zone identifiers; the zone is meaningful
     * only to the host's socket layer, and discarding it here lets the
     * kernel's normal scope rules handle routing. */
    const char *pct = strchr(in, '%');
    size_t core_len = pct ? (size_t)(pct - in) : strlen(in);
    if (core_len == 0 || core_len >= out_sz) return 0;

    char core[IP_STR_MAX];
    if (core_len >= sizeof(core)) return 0;
    memcpy(core, in, core_len);
    core[core_len] = '\0';

    if (inet_pton(AF_INET, core, addr_buf) == 1) {
        memcpy(out, core, core_len + 1);
        return 1;
    }

    if (inet_pton(AF_INET6, core, addr_buf) == 1) {
        /* v4-mapped v6 (::ffff:a.b.c.d) → extract as plain IPv4 so the
         * element lands in session_map_ipv4 rather than session_map_ipv6.
         * Common when sshd listens on :: with IPV6_V6ONLY=0. */
        const struct in6_addr *a6 = (const struct in6_addr *)addr_buf;
        if (IN6_IS_ADDR_V4MAPPED(a6)) {
            if (!inet_ntop(AF_INET, &a6->s6_addr[12], out, (socklen_t)out_sz))
                return 0;
            return 1;
        }
        memcpy(out, core, core_len + 1);
        return 1;
    }

    return 0;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *user = NULL;
    const char *rhost = NULL;
    char norm_ip[IP_STR_MAX] = {0};
    int session_pid = getpid();
    uint64_t cg_id = 0;

    (void)flags;

    if (pam_get_item(pamh, PAM_USER, (const void **)&user) != PAM_SUCCESS ||
        !user || !util_is_valid_username(user))
        return PAM_SESSION_ERR;

    if (strcmp(user, "root") == 0) {
        DEBUG_PRINT("PAM: root user, skipping");
        return PAM_SUCCESS;
    }

    DEBUG_PRINT("PAM: open_session for user=%s pid=%d", user, session_pid);

    /*
     * PAM_RHOST handling. sshd with `UseDNS yes` writes a hostname here,
     * not an IP; historically that tripped inet_pton and denied login.
     * Policies:
     *   lax (default) — normalize if possible, else cg-only fallback.
     *   strict        — deny on any non-IP PAM_RHOST.
     *   kernel        — prefer the sock_diag-derived peer over PAM_RHOST;
     *                   log a warning on divergence; fall back to lax
     *                   semantics if the kernel lookup fails.
     */
    int strict_rhost = 0, kernel_rhost = 0;
    const char *claims_env = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "rhost_policy=strict") == 0) strict_rhost = 1;
        else if (strcmp(argv[i], "rhost_policy=kernel") == 0) kernel_rhost = 1;
        else if (strncmp(argv[i], "claims_env=", 11) == 0) claims_env = argv[i] + 11;
    }

    int rhost_parsed = 0;
    if (pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) == PAM_SUCCESS && rhost) {
        rhost_parsed = util_normalize_ip(rhost, norm_ip, sizeof(norm_ip));
    }

    if (kernel_rhost) {
        char kern_ip[IP_STR_MAX] = {0};
        if (peer_lookup_tcp(pamh, session_pid, kern_ip, sizeof(kern_ip))) {
            /* Normalize kernel peer (v4-mapped v6 → plain v4) so the
             * divergence comparison and set selection use the same form
             * as the PAM_RHOST path. */
            char tmp_ip[IP_STR_MAX];
            if (util_normalize_ip(kern_ip, tmp_ip, sizeof(tmp_ip)))
                memcpy(kern_ip, tmp_ip, sizeof(kern_ip));
            if (rhost_parsed && strcmp(kern_ip, norm_ip) != 0) {
                pam_syslog(pamh, LOG_WARNING,
                           "authnft: PAM_RHOST/kernel peer divergence: "
                           "app='%s' kernel='%s' — trusting kernel",
                           norm_ip, kern_ip);
            } else if (!rhost_parsed && rhost) {
                pam_syslog(pamh, LOG_WARNING,
                           "authnft: PAM_RHOST '%s' unparseable, "
                           "using kernel-derived peer %s",
                           rhost, kern_ip);
            }
            memcpy(norm_ip, kern_ip, sizeof(norm_ip));
            rhost_parsed = 1;
        } else {
            pam_syslog(pamh, LOG_INFO,
                       "authnft: kernel peer lookup failed for pid %d, "
                       "falling back to PAM_RHOST", session_pid);
            /* rhost_parsed retains whatever util_normalize_ip returned */
        }
    }

    if (!rhost_parsed) {
        if (rhost) {
            DEBUG_PRINT("PAM: unparseable PAM_RHOST: %s", rhost);
            if (strict_rhost) {
                pam_syslog(pamh, LOG_ERR,
                           "authnft: PAM_RHOST '%s' not an IP literal (strict policy)",
                           rhost);
                return PAM_SESSION_ERR;
            }
            pam_syslog(pamh, LOG_INFO,
                       "authnft: PAM_RHOST '%s' not an IP literal, binding cgroup only",
                       rhost);
        } else {
            DEBUG_PRINT("PAM: PAM_RHOST not set");
            if (strict_rhost) return PAM_SESSION_ERR;
        }
        norm_ip[0] = '\0';
    }

    if (is_debug_bypass_requested(argc, argv)) {
        pam_syslog(pamh, LOG_DEBUG, "authnft: seccomp bypassed");
    } else {
        if (sandbox_apply(pamh) < 0) {
            pam_syslog(pamh, LOG_ERR, "authnft: failed to apply sandbox");
            return PAM_SESSION_ERR;
        }
    }

    if (bus_handler_start(pamh, user, session_pid) < 0)
        return PAM_SESSION_ERR;

    if (util_get_cgroup_id(session_pid, &cg_id) < 0) {
        pam_syslog(pamh, LOG_ERR, "authnft: failed to resolve cgroup for pid %d",
                   session_pid);
        return PAM_SESSION_ERR;
    }

    /*
     * Persist cg_id + the normalized IP that was actually bound. The stored
     * remote_ip (empty string for the cg-only path) tells close_session which
     * set to delete from, removing the v4-vs-v6 strchr(':') guess and making
     * the cg-only path's cleanup deterministic. Key name predates this struct
     * (invariant #3); kept for compatibility.
     */
    authnft_session_t *sd = calloc(1, sizeof(*sd));
    if (!sd) {
        pam_syslog(pamh, LOG_ERR, "authnft: out of memory storing session data");
        return PAM_SESSION_ERR;
    }
    sd->cg_id = cg_id;
    memcpy(sd->remote_ip, norm_ip, sizeof(sd->remote_ip));
    if (claims_env) {
        (void)keyring_fetch_tag(pamh, claims_env, sd->claims_tag,
                                sizeof(sd->claims_tag));
    }
    event_correlation_capture(pamh, sd->correlation_id,
                              sizeof(sd->correlation_id));
    if (pam_set_data(pamh, "authnft_cg_id", sd, free_pam_data) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "authnft: failed to store session data");
        free(sd);
        return PAM_SESSION_ERR;
    }

    int rc = nft_handler_setup(pamh, user, cg_id,
                               norm_ip[0] ? norm_ip : NULL,
                               sd->claims_tag[0] ? sd->claims_tag : NULL);
    if (rc == PAM_SUCCESS) {
        (void)session_file_write(pamh, sd, user, session_pid);
        event_open_emit(pamh, sd, user, session_pid);
    }
    return rc;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                     int argc, const char **argv) {
    const char *user = NULL;
    (void)flags; (void)argc; (void)argv;

    if (pam_get_item(pamh, PAM_USER, (const void **)&user) != PAM_SUCCESS || !user)
        return PAM_SUCCESS;

    if (strcmp(user, "root") == 0)
        return PAM_SUCCESS;

    const authnft_session_t *sd = NULL;
    if (pam_get_data(pamh, "authnft_cg_id",
                     (const void **)&sd) != PAM_SUCCESS || !sd) {
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: no stored session data for %s — element may persist", user);
        return PAM_SUCCESS;
    }

    DEBUG_PRINT("PAM: close_session for user=%s cg_id=%llu ip='%s'",
                user, (unsigned long long)sd->cg_id, sd->remote_ip);

    const char *ip = sd->remote_ip[0] ? sd->remote_ip : NULL;
    if (nft_handler_cleanup(pamh, user, sd->cg_id, ip) != PAM_SUCCESS)
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: cleanup failed for %s — element may persist", user);

    (void)session_file_remove(pamh, sd->cg_id);
    event_close_emit(pamh, sd, user);

    return PAM_SUCCESS;
}

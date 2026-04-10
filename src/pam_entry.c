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

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *user = NULL;
    const char *rhost = NULL;
    unsigned char addr_buf[sizeof(struct in6_addr)];
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

    if (pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) != PAM_SUCCESS || !rhost) {
        DEBUG_PRINT("PAM: PAM_RHOST not set, skipping");
        return PAM_SUCCESS;
    }

    if (inet_pton(AF_INET, rhost, addr_buf) != 1 &&
        inet_pton(AF_INET6, rhost, addr_buf) != 1) {
        DEBUG_PRINT("PAM: invalid IP for PAM_RHOST: %s", rhost);
        return PAM_SESSION_ERR;
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
     * Persist the cgroup ID for close_session. The transient .scope created by
     * bus_handler_start may already be gone by the time close_session runs, so
     * re-resolving the cgroup from the PID is unreliable. Storing cg_id here
     * guarantees that nft_handler_cleanup can delete the exact set element that
     * was inserted, preventing a leak of the { cg_id . src_ip } entry.
     */
    uint64_t *stored_cg = malloc(sizeof(uint64_t));
    if (!stored_cg) {
        pam_syslog(pamh, LOG_ERR, "authnft: out of memory storing cgroup ID");
        return PAM_SESSION_ERR;
    }
    *stored_cg = cg_id;
    if (pam_set_data(pamh, "authnft_cg_id", stored_cg, free_pam_data) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "authnft: failed to store cgroup ID in PAM data");
        free(stored_cg);
        return PAM_SESSION_ERR;
    }

    return nft_handler_setup(pamh, user, cg_id, rhost);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                     int argc, const char **argv) {
    const char *user = NULL;
    const char *rhost = NULL;
    (void)flags; (void)argc; (void)argv;

    if (pam_get_item(pamh, PAM_USER, (const void **)&user) != PAM_SUCCESS || !user)
        return PAM_SUCCESS;

    if (strcmp(user, "root") == 0)
        return PAM_SUCCESS;

    /* Retrieve the cgroup ID recorded at open_session. */
    const uint64_t *stored_cg = NULL;
    if (pam_get_data(pamh, "authnft_cg_id",
                     (const void **)&stored_cg) != PAM_SUCCESS || !stored_cg) {
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: no stored cgroup ID for %s — element may persist", user);
        return PAM_SUCCESS;
    }
    uint64_t cg_id = *stored_cg;

    DEBUG_PRINT("PAM: close_session for user=%s cg_id=%llu",
                user, (unsigned long long)cg_id);

    if (pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) == PAM_SUCCESS && rhost) {
        if (nft_handler_cleanup(pamh, user, cg_id, rhost) != PAM_SUCCESS)
            pam_syslog(pamh, LOG_WARNING,
                       "authnft: cleanup failed for %s — element may persist", user);
    }

    return PAM_SUCCESS;
}

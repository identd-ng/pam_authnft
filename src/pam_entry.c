// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#include "authnft.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <inttypes.h>
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
         * element lands in the per-session IPv4 set rather than the IPv6 set.
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

    /*
     * Construct cg_path deterministically from the scope we just created
     * rather than reading /proc/<pid>/cgroup. The path is guaranteed by
     * the Slice=authnft.slice parameter in StartTransientUnit; reading
     * /proc would race with the cgroup migration (the kernel updates
     * /proc/<pid>/cgroup asynchronously after the D-Bus call returns).
     *
     * Persist cg_path + scope_unit + the normalized IP that was actually
     * bound. The stored remote_ip (empty string for the cg-only path)
     * tells close_session which set to delete from. cg_path is what the
     * kernel resolves to the u64 inode at nft insert time via
     * `socket cgroupv2 level 2`; scope_unit is the filename key for
     * session JSON files. Both fields are fixed-size inside the struct
     * so free_pam_data remains a plain free(data). Key name
     * 'authnft_cg_id' predates this struct (invariant #3); kept for
     * lifecycle compatibility.
     */
    authnft_session_t *sd = calloc(1, sizeof(*sd));
    if (!sd) {
        pam_syslog(pamh, LOG_ERR, "authnft: out of memory storing session data");
        /* bus_handler_start created the scope unit above; roll it back
         * so a failed open_session leaves no orphan in systemd state. */
        (void)bus_handler_stop(pamh, user, session_pid);
        return PAM_SESSION_ERR;
    }
    snprintf(sd->scope_unit, sizeof(sd->scope_unit), "authnft-%s-%d.scope",
             user, session_pid);
    snprintf(sd->cg_path, sizeof(sd->cg_path), "authnft.slice/%s",
             sd->scope_unit);
    /* Build per-session nft names. Usernames may contain '-' and '.'
     * which are not valid in nftables identifiers (hyphen is parsed as
     * subtraction). Replace with '_'. */
    char safe_user[MAX_USER_LEN + 1];
    snprintf(safe_user, sizeof(safe_user), "%s", user);
    for (char *p = safe_user; *p; p++) {
        if (*p == '-' || *p == '.') *p = '_';
    }
    snprintf(sd->chain_name, sizeof(sd->chain_name), "session_%s_%d",
             safe_user, session_pid);
    snprintf(sd->set_v4, sizeof(sd->set_v4), "session_%s_%d_v4",
             safe_user, session_pid);
    snprintf(sd->set_v6, sizeof(sd->set_v6), "session_%s_%d_v6",
             safe_user, session_pid);
    snprintf(sd->set_cg, sizeof(sd->set_cg), "session_%s_%d_cg",
             safe_user, session_pid);
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
        (void)bus_handler_stop(pamh, user, session_pid);
        return PAM_SESSION_ERR;
    }

    int rc = nft_handler_setup(pamh, user, sd);
    if (rc == PAM_SUCCESS) {
        (void)session_file_write(pamh, sd, user, session_pid);
        event_open_emit(pamh, sd, user, session_pid);

        /*
         * Carry session state through PAM env so close_session can find
         * it even when it runs in a different process from open_session
         * (OpenSSH privsep model — open in child, close in monitor;
         * pam_set_data doesn't cross the fork). sd is fully populated
         * by nft_handler_setup at this point — jump_handle in
         * particular is only set after the jump rule is committed. See
         * issue #35.
         *
         * Failure here is non-fatal. pam_set_data above is the
         * primary channel for same-process PAM stacks (pamtester, su,
         * systemd-logind console login); the env carry is the
         * privsep-survival path. close_session will try env first then
         * fall back to pam data.
         */
        char carry[1024];
        int n = session_carry_encode(sd, carry, sizeof(carry));
        if (n < 0) {
            pam_syslog(pamh, LOG_WARNING,
                       "authnft: session-carry encode overflowed; "
                       "close_session may need pam_set_data fallback");
        } else {
            char buf[1024 + sizeof("AUTHNFT_SESSION=")];
            int w = snprintf(buf, sizeof(buf), "AUTHNFT_SESSION=%s", carry);
            if (w > 0 && (size_t)w < sizeof(buf)) {
                if (pam_putenv(pamh, buf) != PAM_SUCCESS) {
                    pam_syslog(pamh, LOG_WARNING,
                               "authnft: pam_putenv(AUTHNFT_SESSION) failed");
                }
            }
        }
    } else {
        /* nft_handler_setup rolled back its own partial nft state.
         * The systemd scope created by bus_handler_start above is
         * still live — roll it back too. `sd` stays registered with
         * PAM and is freed by free_pam_data when the handle ends. */
        (void)bus_handler_stop(pamh, user, session_pid);
    }
    return rc;
}

/*
 * Re-validate a session struct that was decoded from external transport
 * (PAM env via session_carry_decode). Each populated field is checked
 * against the same validator that produced it on the open path. Returns
 * 0 if all populated fields pass, -1 otherwise. Empty fields (remote_ip,
 * claims_tag) pass implicitly because empty is a legitimate value.
 *
 * This is the trust boundary for the env-carry path. If a hostile or
 * buggy peer puts something in AUTHNFT_SESSION that doesn't pass these
 * checks, close_session must refuse to act on it rather than passing
 * malformed identifiers down to libnftables.
 */
static int revalidate_session(const authnft_session_t *sd) {
    if (!sd) return -1;

    /* cg_path: must be "authnft.slice/<scope_unit>" — depth-1 invariant */
    if (sd->cg_path[0] == '\0') return -1;
    static const char prefix[] = "authnft.slice/";
    if (strncmp(sd->cg_path, prefix, sizeof(prefix) - 1) != 0) return -1;
    /* No further '/' beyond the one in the prefix (depth invariant). */
    if (strchr(sd->cg_path + sizeof(prefix) - 1, '/')) return -1;

    /* scope_unit: ASCII safe, ends in .scope */
    size_t su_len = strlen(sd->scope_unit);
    if (su_len == 0 || su_len < 6) return -1;
    if (strcmp(sd->scope_unit + su_len - 6, ".scope") != 0) return -1;
    for (size_t i = 0; i < su_len; i++) {
        char c = sd->scope_unit[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'))
            return -1;
    }

    /* remote_ip: empty (cg-only path) or a valid IP literal */
    if (sd->remote_ip[0] != '\0') {
        char tmp[IP_STR_MAX];
        if (!util_normalize_ip(sd->remote_ip, tmp, sizeof(tmp))) return -1;
        if (strcmp(tmp, sd->remote_ip) != 0) return -1;
    }

    /* claims_tag: charset already enforced upstream; recheck the safe set */
    for (size_t i = 0; sd->claims_tag[i]; i++) {
        char c = sd->claims_tag[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '_' || c == '=' || c == ',' || c == '.' ||
              c == ':' || c == ';' || c == '/' || c == '-'))
            return -1;
    }

    /* correlation_id: charset [A-Za-z0-9_.:-] */
    for (size_t i = 0; sd->correlation_id[i]; i++) {
        char c = sd->correlation_id[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.' || c == ':'))
            return -1;
    }

    /* chain_name and per-session set names: nft identifier rules
     * (alnum + underscore). Builder uses "session_<safe_user>_<pid>"
     * shape; recheck the charset. */
    const char *names[] = { sd->chain_name, sd->set_v4, sd->set_v6, sd->set_cg };
    for (size_t k = 0; k < 4; k++) {
        if (names[k][0] == '\0') return -1;
        if (strncmp(names[k], "session_", 8) != 0) return -1;
        for (size_t i = 0; names[k][i]; i++) {
            char c = names[k][i];
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_'))
                return -1;
        }
    }

    /* jump_handle: 0 means "not captured" — refuse, since cleanup needs it */
    if (sd->jump_handle == 0) return -1;

    return 0;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                     int argc, const char **argv) {
    const char *user = NULL;
    (void)flags; (void)argc; (void)argv;

    if (pam_get_item(pamh, PAM_USER, (const void **)&user) != PAM_SUCCESS || !user)
        return PAM_SUCCESS;

    if (strcmp(user, "root") == 0)
        return PAM_SUCCESS;

    /*
     * Two-channel session-state lookup:
     *
     *   1. PAM env (AUTHNFT_SESSION) — survives the privsep monitor/
     *      child boundary in OpenSSH. open_session ran in the privsep
     *      child and called pam_putenv; sshd's import_environments(3)
     *      proxied the env across the fork to the monitor where
     *      close_session runs. See issue #35 and src/session_carry.c.
     *
     *   2. pam_set_data ("authnft_cg_id") — same-process fallback. Used
     *      by pamtester, su, systemd-logind console login, and any PAM
     *      stack where open and close run in the same address space.
     *
     * Try env first; if it parses and passes re-validation, use it.
     * Fall back to pam_data otherwise. Warn-and-skip only if both fail.
     *
     * Re-validate env-decoded fields before use: the env crosses a
     * process boundary, so its content is treated as external input.
     */
    authnft_session_t carry = {0};
    const authnft_session_t *sd = NULL;
    int from_env = 0;

    const char *env_json = pam_getenv(pamh, "AUTHNFT_SESSION");
    if (env_json && env_json[0]) {
        if (session_carry_decode(env_json, &carry) == 0 &&
            revalidate_session(&carry) == 0) {
            sd = &carry;
            from_env = 1;
            DEBUG_PRINT("PAM: close_session using env-carried sd");
        } else {
            pam_syslog(pamh, LOG_WARNING,
                       "authnft: AUTHNFT_SESSION present but malformed; "
                       "falling back to pam_set_data");
        }
    }

    if (!sd) {
        const authnft_session_t *pd = NULL;
        if (pam_get_data(pamh, "authnft_cg_id",
                         (const void **)&pd) == PAM_SUCCESS && pd) {
            sd = pd;
            DEBUG_PRINT("PAM: close_session using pam_data sd");
        }
    }

    if (!sd) {
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: no stored session data for %s — element may persist "
                   "(issue #35: privsep close_session leak)", user);
        return PAM_SUCCESS;
    }

    DEBUG_PRINT("PAM: close_session for user=%s chain=%s handle=%" PRIu64 " src=%s",
                user, sd->chain_name, sd->jump_handle, from_env ? "env" : "pam_data");

    if (nft_handler_cleanup(pamh, user, sd) != PAM_SUCCESS)
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: cleanup failed for %s — per-session state may persist", user);

    (void)session_file_remove(pamh, sd->scope_unit);
    event_close_emit(pamh, sd, user);

    /* Clear the env carry so a subsequent stage can't pick up stale state. */
    if (from_env) (void)pam_putenv(pamh, "AUTHNFT_SESSION");

    return PAM_SUCCESS;
}

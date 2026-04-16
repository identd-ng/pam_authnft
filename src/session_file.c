// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Runtime session identity files under /run/authnft/sessions/<cg_id>.json.
 *
 * Written on open_session after nft_handler_setup completes; removed on
 * close_session. Lets non-PAM observers (SIEM agents, workload schedulers,
 * container runtimes, operator dashboards) correlate a cgroup inode back to
 * the pam_authnft session that created it without needing privileged access
 * to the PAM handle. The schema is versioned (v=1); future contract
 * revisions MUST be additive per docs/INTEGRATIONS.txt §5.6.
 *
 * File creation is atomic via a tempfile-plus-rename pattern. Directory is
 * created at boot by tmpfiles.d (data/authnft.tmpfiles); the module assumes
 * it exists and logs at LOG_WARNING if it does not — session establishment
 * is not failed on a session-file write error (observability is best-effort).
 */

#include "authnft.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define SESSION_DIR  "/run/authnft/sessions"
#define PATH_MAX_LEN 128
#define JSON_MAX     1024

static void session_file_path(char out[PATH_MAX_LEN], uint64_t cg_id) {
    snprintf(out, PATH_MAX_LEN, SESSION_DIR "/%" PRIu64 ".json", cg_id);
}

static void session_file_tmp_path(char out[PATH_MAX_LEN], uint64_t cg_id) {
    snprintf(out, PATH_MAX_LEN, SESSION_DIR "/.%" PRIu64 ".tmp", cg_id);
}

int session_file_write(pam_handle_t *pamh, const authnft_session_t *sd,
                       const char *user, int session_pid) {
    if (!sd || !user) return -1;

    char path[PATH_MAX_LEN];
    char tmp[PATH_MAX_LEN];
    session_file_path(path, sd->cg_id);
    session_file_tmp_path(tmp, sd->cg_id);

    /* ISO 8601 UTC timestamp. clock_gettime + gmtime_r are pure-userspace
     * after the vDSO path; already covered by the existing allowlist. */
    char when[32] = "";
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        struct tm gm;
        if (gmtime_r(&ts.tv_sec, &gm))
            strftime(when, sizeof(when), "%Y-%m-%dT%H:%M:%SZ", &gm);
    }

    /* All string fields are producer-validated upstream:
     *   user       — [A-Za-z0-9._-], max 32 (util_is_valid_username)
     *   remote_ip  — inet_ntop canonical form, no JSON-special chars
     *   claims_tag — sanitized to [A-Za-z0-9_=,.:;/-]
     *   fragment   — derived from user, no escape needed
     *   scope_unit — built from user + pid, same charset
     * No JSON escaping required; the full format is ASCII-safe. */
    char fragment[PATH_MAX_LEN];
    snprintf(fragment, sizeof(fragment), RULES_DIR "/%s", user);
    char scope_unit[UNIT_BUF_SIZE];
    snprintf(scope_unit, sizeof(scope_unit), "authnft-%s-%d.scope",
             user, session_pid);

    char json[JSON_MAX];
    int n = snprintf(json, sizeof(json),
        "{\"v\":1,"
        "\"cg_id\":%" PRIu64 ","
        "\"user\":\"%s\","
        "\"remote_ip\":\"%s\","
        "\"fragment\":\"%s\","
        "\"claims_tag\":\"%s\","
        "\"scope_unit\":\"%s\","
        "\"opened_at\":\"%s\"}\n",
        sd->cg_id, user, sd->remote_ip, fragment,
        sd->claims_tag, scope_unit, when);
    if (n < 0 || n >= (int)sizeof(json)) {
        if (pamh) pam_syslog(pamh, LOG_WARNING,
                             "authnft: session file JSON overflow for cg_id=%"
                             PRIu64, sd->cg_id);
        return -1;
    }

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        if (pamh) pam_syslog(pamh, LOG_WARNING,
                             "authnft: session file open(%s) failed: %m", tmp);
        return -1;
    }
    ssize_t w = write(fd, json, (size_t)n);
    close(fd);
    if (w != n) {
        (void)unlink(tmp);
        if (pamh) pam_syslog(pamh, LOG_WARNING,
                             "authnft: session file write failed: %m");
        return -1;
    }
    if (rename(tmp, path) < 0) {
        (void)unlink(tmp);
        if (pamh) pam_syslog(pamh, LOG_WARNING,
                             "authnft: session file rename(%s -> %s) failed: %m",
                             tmp, path);
        return -1;
    }
    DEBUG_PRINT("session_file: wrote %s", path);
    return 0;
}

int session_file_remove(pam_handle_t *pamh, uint64_t cg_id) {
    char path[PATH_MAX_LEN];
    session_file_path(path, cg_id);
    if (unlink(path) < 0 && errno != ENOENT) {
        if (pamh) pam_syslog(pamh, LOG_WARNING,
                             "authnft: session file unlink(%s) failed: %m", path);
        return -1;
    }
    DEBUG_PRINT("session_file: removed %s", path);
    return 0;
}

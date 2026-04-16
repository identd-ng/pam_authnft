// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Structured audit events via sd_journal_send(3).
 *
 * Every open_session success emits AUTHNFT_EVENT=open and every
 * close_session that actually runs emits AUTHNFT_EVENT=close. Both carry
 * the session's cg_id, user, and a correlation token — either inherited
 * from the PAM environment (upstream-supplied) or synthesized at open.
 *
 * Goal: make a pam_authnft session trivially correlatable to the
 * authentication event that preceded it, in the same journal stream, via
 * a shared field (AUTHNFT_CORRELATION). Contract: docs/INTEGRATIONS.txt
 * §6.4.
 *
 * Failure mode: sd_journal_send talks to /run/systemd/journal/socket.
 * If unreachable (non-systemd host, socket removed), we fall back to
 * pam_syslog(LOG_INFO) so the event is still captured by the system log.
 * The session itself is never failed on an audit-emit error.
 */

#include "authnft.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <syslog.h>
#include <systemd/sd-journal.h>
#include <time.h>
#include <unistd.h>

/* Sanitization class for the correlation token. Deliberately narrower
 * than the claims_tag class: correlation tokens are opaque IDs, not
 * human-readable labels, so we don't need ';', '/', ',' etc. */
static int is_corr_safe(unsigned char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9'))
        return 1;
    return c == '_' || c == '-' || c == '.' || c == ':';
}

void event_correlation_capture(pam_handle_t *pamh, char *out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    out[0] = '\0';

    /* Prefer an upstream-supplied correlation from the PAM env. Producers
     * set AUTHNFT_CORRELATION via pam_putenv(3) before pam_authnft runs.
     * See docs/INTEGRATIONS.txt §6.4 for the contract. */
    const char *supplied = pamh ? pam_getenv(pamh, "AUTHNFT_CORRELATION") : NULL;
    if (supplied && supplied[0]) {
        size_t w = 0;
        for (size_t i = 0; supplied[i] && w + 1 < out_sz; i++) {
            unsigned char c = (unsigned char)supplied[i];
            if (is_corr_safe(c)) out[w++] = (char)c;
        }
        out[w] = '\0';
        if (w > 0) return;
    }

    /* Synthesize. Format: "authnft-<unixtime>-<pid>-<8-hex random>".
     * clock_gettime + getrandom + getpid are all in the existing seccomp
     * allowlist; no new syscall surface. */
    struct timespec ts = {0};
    (void)clock_gettime(CLOCK_REALTIME, &ts);
    unsigned char rnd[4] = {0};
    (void)getrandom(rnd, sizeof(rnd), GRND_NONBLOCK);
    (void)snprintf(out, out_sz, "authnft-%ld-%d-%02x%02x%02x%02x",
                   (long)ts.tv_sec, (int)getpid(),
                   rnd[0], rnd[1], rnd[2], rnd[3]);
}

void event_open_emit(pam_handle_t *pamh, const authnft_session_t *sd,
                     const char *user, int session_pid) {
    if (!sd || !user) return;

    char cg_id_str[32];
    (void)snprintf(cg_id_str, sizeof(cg_id_str), "%" PRIu64, sd->cg_id);
    char scope_unit[UNIT_BUF_SIZE];
    (void)snprintf(scope_unit, sizeof(scope_unit), "authnft-%s-%d.scope",
                   user, session_pid);
    char fragment[128];
    (void)snprintf(fragment, sizeof(fragment), RULES_DIR "/%s", user);

    int r = sd_journal_send(
        "MESSAGE=session opened: user=%s cg_id=%" PRIu64 " remote=%s corr=%s",
            user, sd->cg_id,
            sd->remote_ip[0] ? sd->remote_ip : "-",
            sd->correlation_id,
        "PRIORITY=%d", LOG_INFO,
        "SYSLOG_IDENTIFIER=pam_authnft",
        "AUTHNFT_EVENT=open",
        "AUTHNFT_USER=%s", user,
        "AUTHNFT_CG_ID=%s", cg_id_str,
        "AUTHNFT_REMOTE_IP=%s", sd->remote_ip,
        "AUTHNFT_FRAGMENT=%s", fragment,
        "AUTHNFT_CLAIMS_TAG=%s", sd->claims_tag,
        "AUTHNFT_SCOPE_UNIT=%s", scope_unit,
        "AUTHNFT_CORRELATION=%s", sd->correlation_id,
        NULL);
    if (r < 0 && pamh) {
        pam_syslog(pamh, LOG_INFO,
                   "authnft: EVENT=open user=%s cg_id=%" PRIu64
                   " remote=%s correlation=%s (journal unavailable: %s)",
                   user, sd->cg_id,
                   sd->remote_ip[0] ? sd->remote_ip : "-",
                   sd->correlation_id, strerror(-r));
    }
}

void event_close_emit(pam_handle_t *pamh, const authnft_session_t *sd,
                      const char *user) {
    if (!sd || !user) return;

    char cg_id_str[32];
    (void)snprintf(cg_id_str, sizeof(cg_id_str), "%" PRIu64, sd->cg_id);

    int r = sd_journal_send(
        "MESSAGE=session closed: user=%s cg_id=%" PRIu64 " corr=%s",
            user, sd->cg_id, sd->correlation_id,
        "PRIORITY=%d", LOG_INFO,
        "SYSLOG_IDENTIFIER=pam_authnft",
        "AUTHNFT_EVENT=close",
        "AUTHNFT_USER=%s", user,
        "AUTHNFT_CG_ID=%s", cg_id_str,
        "AUTHNFT_CORRELATION=%s", sd->correlation_id,
        NULL);
    if (r < 0 && pamh) {
        pam_syslog(pamh, LOG_INFO,
                   "authnft: EVENT=close user=%s cg_id=%" PRIu64
                   " correlation=%s (journal unavailable: %s)",
                   user, sd->cg_id, sd->correlation_id, strerror(-r));
    }
}

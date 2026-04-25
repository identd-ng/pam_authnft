// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * audit(7) hook for fragment-rejection events. Phase 6.5 of the
 * security audit plan.
 *
 * Up to this commit, every fragment-rejection path in
 * nft_handler_setup logged via pam_syslog only — readable in the
 * usual auth log but not visible to a SOC consumer that scrapes the
 * Linux audit framework. This file emits a parallel structured event
 * via libaudit's audit_log_user_message(), classified as
 * AUDIT_USER_ERR. The pam_syslog channel stays in place; the audit
 * channel is additive.
 *
 * Rejection causes the hook fires for:
 *   - missing fragment (stat() failure)
 *   - bad fragment ownership/mode (uid != 0 OR world-writable)
 *   - content-validator rejection (disallowed verb / include path)
 *   - libnftables syntax error at load time
 *
 * Format (kernel embeds inside type=USER_ERR audit record):
 *   op=authnft-fragment-reject reason=<short-id> user="<user>" \
 *       fragment="<path>"
 *
 * The `reason` token is a short fixed identifier (no spaces, no quotes)
 * that a SIEM rule can string-match without the full message parser:
 *   missing | perms | content | nft-syntax
 *
 * `user` and `fragment` are bounded by upstream input validation — the
 * user has already passed util_is_valid_username (only [A-Za-z0-9._-])
 * and the fragment path is RULES_DIR + user, so neither contains
 * audit-confusing characters. Belt-and-braces: anything unexpected
 * would be visible in the audit record body, not break the encoding.
 *
 * Failure mode: if audit_open() fails (e.g., audit subsystem
 * disabled, no CAP_AUDIT_WRITE in unusual configurations) the
 * function silently returns. The session-rejection PAM_AUTH_ERR
 * still fires; the audit miss is logged at DEBUG level only.
 *
 * Seccomp surface: audit_open uses socket(AF_NETLINK, ...);
 * audit_log_user_message uses sendto/sendmsg; audit_close uses close.
 * All four syscalls are already in the existing allowlist; no
 * sandbox.c changes needed.
 */

#include "authnft.h"

#include <libaudit.h>
#include <stdio.h>
#include <string.h>

void authnft_audit_fragment_reject(const char *user,
                                    const char *reason,
                                    const char *path) {
    if (!user || !reason) return;

    int afd = audit_open();
    if (afd < 0) {
        DEBUG_PRINT("audit_open failed (audit subsystem unavailable?)");
        return;
    }

    /* Bounded by MAX_USER_LEN (32) + RULES_DIR + reason length plus
     * fixed key/quote/space overhead. 256 is comfortable headroom. */
    char msg[256];
    int n = snprintf(msg, sizeof(msg),
                     "op=authnft-fragment-reject reason=%s user=\"%s\" "
                     "fragment=\"%s\"",
                     reason, user, path ? path : "(none)");
    if (n < 0 || (size_t)n >= sizeof(msg)) {
        /* Truncated. Send what we have; the SIEM-side parser sees
         * a truncated message and can flag it. Better than dropping
         * the event entirely. */
        msg[sizeof(msg) - 1] = '\0';
    }

    /* result=0 emits res=failed in the audit record. */
    (void)audit_log_user_message(afd, AUDIT_USER_ERR, msg,
                                  NULL, NULL, NULL, 0);
    audit_close(afd);
}

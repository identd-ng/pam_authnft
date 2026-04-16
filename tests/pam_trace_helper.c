// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * Test-only PAM module used by tests/trace.sh to stage PAM environment
 * variables ahead of pam_authnft in the session stack. Not installed
 * anywhere. Built on demand by trace.sh with:
 *
 *   gcc -fPIC -shared -o /tmp/pam_trace_helper.so \
 *       tests/pam_trace_helper.c -lpam
 *
 * Module arguments are of the form `env=NAME=VALUE` and result in
 * pam_putenv(pamh, "NAME=VALUE"). Multiple env= arguments may be given.
 * This matches the real-world pattern of an identity-layer PAM module
 * calling pam_putenv() from pam_sm_authenticate; in the trace harness
 * we do it at session-open time because pamtester invokes open_session
 * directly.
 */

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <string.h>

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
    (void)flags;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "env=", 4) == 0) {
            (void)pam_putenv(pamh, argv[i] + 4);
        }
    }
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

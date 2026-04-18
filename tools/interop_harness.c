// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar
//
// interop_harness — PAM test client that holds a session open so we can
// capture nftables state and run packet tests between open and close.
//
// Unlike pamtester (which runs open+close atomically), this program:
//   1. Opens a PAM session (triggering pam_authnft to insert nft elements)
//   2. Runs a test script while the session is held open
//   3. Closes the PAM session (triggering cleanup)
//
// The test script runs inside the same process (same cgroup scope), so
// any sockets it creates are subject to the nftables rules loaded by
// pam_authnft's fragment.
//
// Usage: interop_harness <pam_service> <username> <rhost> <test_script>

#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

// Null conversation function — no keyboard-interactive prompts expected
static int null_conv(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *appdata_ptr) {
    (void)num_msg; (void)msg; (void)appdata_ptr;
    *resp = NULL;
    return PAM_SUCCESS;
}

static struct pam_conv conv = { null_conv, NULL };

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <service> <user> <rhost> <test_script>\n", argv[0]);
        return 1;
    }

    const char *service = argv[1];
    const char *user    = argv[2];
    const char *rhost   = argv[3];
    const char *script  = argv[4];

    pam_handle_t *pamh = NULL;
    int rc;

    // ── Initialize PAM ──
    rc = pam_start(service, user, &conv, &pamh);
    if (rc != PAM_SUCCESS) {
        fprintf(stderr, "pam_start failed: %s\n", pam_strerror(pamh, rc));
        return 1;
    }

    // Set PAM_RHOST so pam_authnft binds the session to an IP
    pam_set_item(pamh, PAM_RHOST, rhost);

    // ── Authenticate (pam_permit.so will succeed) ──
    rc = pam_authenticate(pamh, 0);
    if (rc != PAM_SUCCESS) {
        fprintf(stderr, "pam_authenticate failed: %s\n", pam_strerror(pamh, rc));
        pam_end(pamh, rc);
        return 1;
    }

    // ── Open session ──
    // This triggers the PAM stack:
    //   pam_keyinit     → create session keyring
    //   pam_keyring_demo → publish claims to keyring (prmana simulator)
    //   pam_authnft     → read keyring, create scope, insert nft element, load fragment
    fprintf(stdout, "[HARNESS] Opening PAM session for user '%s' from %s...\n", user, rhost);
    rc = pam_open_session(pamh, 0);
    if (rc != PAM_SUCCESS) {
        fprintf(stderr, "[HARNESS] pam_open_session failed: %s\n", pam_strerror(pamh, rc));
        pam_end(pamh, rc);
        return 1;
    }
    fprintf(stdout, "[HARNESS] Session OPEN — nftables rules are LIVE\n");

    // ── Run test script while session is held open ──
    // The script inherits our cgroup scope, so any sockets it creates
    // are subject to the nftables rules.
    fprintf(stdout, "[HARNESS] Running test script: %s\n", script);
    int status = 0;
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/bash", "bash", script, NULL);
        _exit(127);
    } else if (pid > 0) {
        waitpid(pid, &status, 0);
    } else {
        perror("fork");
    }
    fprintf(stdout, "[HARNESS] Test script exited with status %d\n",
            WIFEXITED(status) ? WEXITSTATUS(status) : -1);

    // ── Close session ──
    fprintf(stdout, "[HARNESS] Closing PAM session...\n");
    rc = pam_close_session(pamh, 0);
    if (rc != PAM_SUCCESS) {
        fprintf(stderr, "[HARNESS] pam_close_session failed: %s\n", pam_strerror(pamh, rc));
    } else {
        fprintf(stdout, "[HARNESS] Session CLOSED — nft element removed\n");
    }

    pam_end(pamh, rc);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

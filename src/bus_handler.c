// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#include "authnft.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>
#include <errno.h>

int util_get_cgroup_path(pam_handle_t *pamh, pid_t pid, char *out, size_t out_sz) {
    char *cgroup_path = NULL;
    int result = -1;

    if (sd_pid_get_cgroup(pid, &cgroup_path) < 0) {
        DEBUG_PRINT("sd_pid_get_cgroup failed for pid %d", pid);
        if (pamh)
            pam_syslog(pamh, LOG_ERR,
                       "authnft: sd_pid_get_cgroup failed for pid %d", (int)pid);
        return -1;
    }

    DEBUG_PRINT("cgroup_path: %s", cgroup_path);

    /*
     * Depth invariant (HANDOFF §3.1, §3.2): path MUST be exactly
     * "/authnft.slice/<name>.scope" — two components under the root.
     * Anything deeper, shallower, or outside authnft.slice is a
     * misconfiguration that would silently produce packet-level match
     * failures under `socket cgroupv2 level 2`.
     */
    do {
        /* Must start with '/' */
        if (!cgroup_path || cgroup_path[0] != '/') break;

        const char *p = cgroup_path + 1; /* skip leading '/' */

        /* First component: "authnft.slice/" */
        const char *slash = strchr(p, '/');
        if (!slash) break;
        size_t first_len = (size_t)(slash - p);
        if (first_len != 14 || memcmp(p, "authnft.slice", 14) != 0) break;

        /* Second component: "<name>.scope" with no further slashes */
        const char *second = slash + 1;
        if (second[0] == '\0') break;
        if (strchr(second, '/') != NULL) break;

        /* Must end with ".scope" */
        size_t slen = strlen(second);
        if (slen < 7 || memcmp(second + slen - 6, ".scope", 6) != 0) break;

        /* Strip leading '/' and copy */
        size_t total = strlen(p);
        if (total >= out_sz) break;
        memcpy(out, p, total + 1);
        result = 0;
    } while (0);

    if (result < 0) {
        out[0] = '\0';
        if (pamh)
            pam_syslog(pamh, LOG_ERR,
                       "authnft: cgroup path '%s' violates depth invariant "
                       "(expected /authnft.slice/<name>.scope)",
                       cgroup_path ? cgroup_path : "(null)");
        DEBUG_PRINT("cgroup path validation failed: %s",
                    cgroup_path ? cgroup_path : "(null)");
    }

    free(cgroup_path);
    return result;
}

int bus_handler_start(pam_handle_t *pamh, const char *user, int session_pid) {
    sd_bus *bus = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    char unit_name[UNIT_BUF_SIZE];
    int r;

    DEBUG_PRINT("bus: requesting transient scope for %s (pid %d)", user, session_pid);

    if (sd_bus_open_system(&bus) < 0) {
        pam_syslog(pamh, LOG_ERR, "authnft: failed to connect to system bus: %m");
        return -1;
    }

    snprintf(unit_name, sizeof(unit_name), "authnft-%s-%d.scope", user, session_pid);
    DEBUG_PRINT("bus: StartTransientUnit %s", unit_name);

    r = sd_bus_call_method(bus,
                           "org.freedesktop.systemd1",
                           "/org/freedesktop/systemd1",
                           "org.freedesktop.systemd1.Manager",
                           "StartTransientUnit",
                           &error,
                           NULL,
                           "ssa(sv)a(sa(sv))",
                           unit_name,
                           "fail",
                           2,
                           "PIDs",  "au", 1, (uint32_t)session_pid,
                           "Slice", "s",  "authnft.slice",
                           0);

    if (r < 0) {
        pam_syslog(pamh, LOG_ERR, "authnft: systemd handoff failed for %s: %s",
                   unit_name, error.message ? error.message : strerror(-r));
        DEBUG_PRINT("bus: rejected %s: %s", unit_name,
                    error.message ? error.message : "unknown");
        sd_bus_error_free(&error);
        sd_bus_unref(bus);
        return -1;
    }

    DEBUG_PRINT("bus: accepted %s", unit_name);
    sd_bus_error_free(&error);
    sd_bus_unref(bus);
    return 0;
}

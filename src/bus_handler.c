#include "authnft.h"
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>
#include <sys/stat.h>
#include <errno.h>

int util_get_cgroup_id(pid_t pid, uint64_t *cg_id) {
    char *cgroup_path = NULL;
    char full_path[1024];
    struct stat st;
    int result = -1;

    if (sd_pid_get_cgroup(pid, &cgroup_path) < 0) {
        DEBUG_PRINT("sd_pid_get_cgroup failed for PID %d", pid);
        return -1;
    }

    // Construct the absolute path in the V2 hierarchy
    snprintf(full_path, sizeof(full_path), "/sys/fs/cgroup%s", cgroup_path);
    DEBUG_PRINT("Statting cgroup path: %s", full_path);
    DEBUG_PRINT("Cgroup: sd_pid_get_cgroup returned path: %s", cgroup_path);

    if (stat(full_path, &st) == 0) {
        *cg_id = (uint64_t)st.st_ino;
        DEBUG_PRINT("Resolved Inode: %llu", (unsigned long long)*cg_id);
        result = 0;
    } else {
        DEBUG_PRINT("stat() failed on %s: %s", full_path, strerror(errno));
        
        // Fallback check for unified hierarchy systems
        snprintf(full_path, sizeof(full_path), "/sys/fs/cgroup/unified%s", cgroup_path);
        DEBUG_PRINT("Trying fallback path: %s", full_path);
        
        if (stat(full_path, &st) == 0) {
            *cg_id = (uint64_t)st.st_ino;
            DEBUG_PRINT("Resolved Inode via fallback: %llu", (unsigned long long)*cg_id);
            result = 0;
        } else {
            DEBUG_PRINT("Fallback path also failed: %s", full_path);
        }
    }

    free(cgroup_path);
    return result;
}

int bus_handler_start(pam_handle_t *pamh, const char *user, int session_pid) {
    sd_bus *bus = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    char unit_name[UNIT_BUF_SIZE];
    int r;

    DEBUG_PRINT("Bus: Requesting transient scope for %s (PID %d)", user, session_pid);

    if (sd_bus_open_system(&bus) < 0) {
        pam_syslog(pamh, LOG_ERR, "authnft: Failed to connect to system bus: %m");
        DEBUG_PRINT("Failed to connect to system bus");
        return -1;
    }

    snprintf(unit_name, sizeof(unit_name), "authnft-%s-%d.scope", user, session_pid);
    DEBUG_PRINT("Bus: Sending StartTransientUnit for %s", unit_name);

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
                           1, 
                           "PIDs", "au", 1, (uint32_t)session_pid,
                           0);

    if (r < 0) {
        DEBUG_PRINT("Bus: systemd REJECTED unit %s: %s (Code: %d)", 
                    unit_name, error.message ? error.message : "Unknown", r);
        pam_syslog(pamh, LOG_ERR, "authnft: systemd handoff failed: %s", 
                   (error.message ? error.message : strerror(-r)));
        sd_bus_error_free(&error);
        sd_bus_unref(bus);
        return -1;
    }

    DEBUG_PRINT("Bus: systemd ACCEPTED unit %s", unit_name);
    sd_bus_unref(bus);
    return 0;
}

// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#ifndef AUTHNFT_H
#define AUTHNFT_H

#ifdef DEBUG
    #define DEBUG_PRINT(fmt, ...) \
        do { fprintf(stderr, "authnft [DEBUG]: " fmt "\n", ##__VA_ARGS__); } while (0)
#else
    #define DEBUG_PRINT(fmt, ...) do {} while (0)
#endif

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

/* --- Configuration Constants --- */
#define RULES_DIR "/etc/authnft/users"
#define TABLE_NAME "authnft"

/* --- Buffer Management --- */
#define CMD_BUF_SIZE 2048
#define UNIT_BUF_SIZE 128
#define MAX_USER_LEN 32

/*
 * nft_handler_setup:
 * Checks 'authnft' group membership, validates the user's root-owned fragment,
 * and inserts the { cgroup_id . src_ip } element into the appropriate set.
 */
int nft_handler_setup(pam_handle_t *pamh, const char *user, uint64_t cg_id,
                      const char *remote_ip);

/*
 * nft_handler_cleanup:
 * Atomically removes the { cgroup_id . src_ip } element inserted at open_session.
 * cg_id is passed directly from PAM data to avoid re-resolution after scope teardown.
 */
int nft_handler_cleanup(pam_handle_t *pamh, const char *user, uint64_t cg_id,
                        const char *remote_ip);

/*
 * bus_handler_start:
 * Connects to systemd via D-Bus and creates a transient .scope unit under
 * authnft.slice, placing the session process into a named cgroup.
 */
int bus_handler_start(pam_handle_t *pamh, const char *user, int session_pid);

/*
 * sandbox_apply:
 * Installs a seccomp-BPF allowlist with SCMP_ACT_KILL default and sets
 * PR_SET_NO_NEW_PRIVS before loading the filter.
 */
int sandbox_apply(pam_handle_t *pamh);

/*
 * util_is_valid_username:
 * Validates the username for length and illegal characters.
 * Rejects path traversal sequences, shell metacharacters, and leading hyphens.
 */
int util_is_valid_username(const char *user);

/*
 * util_get_cgroup_id:
 * Resolves the 64-bit cgroupv2 inode for a given PID via sd_pid_get_cgroup(3)
 * and stat(2) on /sys/fs/cgroup/<path>.
 */
int util_get_cgroup_id(pid_t pid, uint64_t *cg_id);

#endif /* AUTHNFT_H */

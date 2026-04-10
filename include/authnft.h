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

/**
 * nft_handler_setup:
 * Checks 'authnft' group membership, enforces existence of user fragment,
 * and configures the nftables ruleset.
 */
int nft_handler_setup(pam_handle_t *pamh, const char *user, uint64_t cg_id,
                      const char *remote_ip);

/**
 * nft_handler_cleanup:
 * Surgical removal of the specific cgroup . IP element from the set.
 */
int nft_handler_cleanup(pam_handle_t *pamh, const char *user, int session_pid, const char *remote_ip);

/**
 * bus_handler_start:
 * Connects to systemd via D-Bus and creates the transient .scope unit.
 */
int bus_handler_start(pam_handle_t *pamh, const char *user, int session_pid);

/**
 * sandbox_apply:
 * Applies the Seccomp-BPF sandbox to the current process.
 */
int sandbox_apply(pam_handle_t *pamh);

/**
 * util_is_valid_username:
 * Validates the username for length and illegal characters.
 */
int util_is_valid_username(const char *user);

/**
 * util_get_cgroup_id:
 * Resolves the 64-bit cgroupv2 ID (inode) for a given process ID.
 */
int util_get_cgroup_id(pid_t pid, uint64_t *cg_id);

#endif /* AUTHNFT_H */

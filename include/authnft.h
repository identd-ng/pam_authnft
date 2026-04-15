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
#define SET_V4   "session_map_ipv4"
#define SET_V6   "session_map_ipv6"
#define SET_CG   "session_map_cg"

/* --- Buffer Management --- */
#define CMD_BUF_SIZE 2048
#define UNIT_BUF_SIZE 128
#define MAX_USER_LEN 32
#define IP_STR_MAX   64   /* INET6_ADDRSTRLEN (46) + headroom */

/*
 * Session data persisted via pam_set_data("authnft_cg_id", ...).
 * The key name predates this struct; it is kept for compatibility with the
 * documented lifecycle invariant. `remote_ip[0] == '\0'` marks the cg-only
 * fallback path, where no src_ip was bound.
 */
typedef struct {
    uint64_t cg_id;
    char     remote_ip[IP_STR_MAX];
} authnft_session_t;

/*
 * nft_handler_setup:
 * Checks 'authnft' group membership, validates the user's root-owned fragment,
 * and inserts the session element. If remote_ip is NULL or empty, the element
 * is inserted into session_map_cg (cgroup-only); otherwise it goes into the
 * v4/v6 map selected by the address family.
 */
int nft_handler_setup(pam_handle_t *pamh, const char *user, uint64_t cg_id,
                      const char *remote_ip);

/*
 * nft_handler_cleanup:
 * Atomically removes the element inserted at open_session. Set selection
 * mirrors nft_handler_setup: NULL/empty remote_ip targets session_map_cg.
 * cg_id is passed directly from PAM data to avoid re-resolution after scope
 * teardown.
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

/*
 * peer_lookup_tcp:
 * Derives the remote IP of an ESTABLISHED TCP socket owned by `pid` by
 * issuing a SOCK_DIAG_BY_FAMILY query over NETLINK_SOCK_DIAG and matching
 * returned inodes against socket inodes walked from /proc/<pid>/fd/.
 * Writes a canonical IP literal (inet_ntop form) into out[out_sz].
 * Returns 1 on success, 0 on any failure (no TCP socket, netlink denied,
 * multiple ambiguous sockets, buffer too small). Uses only syscalls in
 * the existing seccomp allowlist; safe to call post-sandbox as well but
 * currently invoked pre-sandbox in lockstep with PAM_RHOST parsing.
 */
int peer_lookup_tcp(pid_t pid, char *out, size_t out_sz);

/*
 * util_normalize_ip:
 * Validates an IP literal and writes a canonical form to out[out_sz].
 * Accepts IPv4, IPv6, and IPv6 link-local with a zone suffix ("%zone");
 * the zone is stripped because nftables ip6 saddr matches do not accept it.
 * Returns 1 on success, 0 on any rejection (NULL, empty, hostname, overlong,
 * malformed literal).
 */
int util_normalize_ip(const char *in, char *out, size_t out_sz);

#endif /* AUTHNFT_H */

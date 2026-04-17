// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

#include "authnft.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Peer-IP resolution via NETLINK_SOCK_DIAG (see ss(8)). PAM_RHOST is
 * application-supplied and under sshd UseDNS=yes is a hostname, not an
 * IP; asking the kernel for the remote address of the session process's
 * own ESTABLISHED TCP socket is authoritative instead. Rationale in
 * docs/ARCHITECTURE.txt and pam_authnft(8).
 *
 * Uses only allowlisted syscalls (socket/sendmsg/recvmsg/close for
 * netlink, plus openat/getdents64/readlink for the /proc fd walk).
 * No additions to src/sandbox.c required.
 */

#define RECV_BUF   (8 * 1024)

/* Collect socket inodes held by `pid` by readlink-ing each entry under
 * /proc/<pid>/fd. Returns the count or -1 on failure. On exit,
 * *truncated is set to 1 if at least one socket inode was observed
 * beyond `cap` and dropped. */
static int collect_socket_inodes(pid_t pid, ino_t *inodes, size_t cap,
                                  int *truncated) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/fd", (int)pid);

    DIR *d = opendir(path);
    if (!d) return -1;

    int count = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        if (strlen(de->d_name) > 8) continue;  /* fd numbers, never long */

        char linkpath[96];
        char target[128];
        int k = snprintf(linkpath, sizeof(linkpath), "%s/%s", path, de->d_name);
        if (k < 0 || (size_t)k >= sizeof(linkpath)) continue;
        ssize_t n = readlink(linkpath, target, sizeof(target) - 1);
        if (n <= 0) continue;
        target[n] = '\0';

        /* "socket:[12345]" */
        unsigned long ino;
        if (sscanf(target, "socket:[%lu]", &ino) != 1) continue;

        if ((size_t)count >= cap) {
            *truncated = 1;
            break;
        }
        inodes[count++] = (ino_t)ino;
    }
    closedir(d);
    return count;
}

/* Send one SOCK_DIAG_BY_FAMILY request for `family`, filtering to
 * TCP_ESTABLISHED. Returns 0 on successful send. */
static int send_diag_request(int fd, int family) {
    struct {
        struct nlmsghdr       nlh;
        struct inet_diag_req_v2 req;
    } msg;
    memset(&msg, 0, sizeof(msg));

    msg.nlh.nlmsg_len   = sizeof(msg);
    msg.nlh.nlmsg_type  = SOCK_DIAG_BY_FAMILY;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.nlh.nlmsg_seq   = 1;

    msg.req.sdiag_family   = (uint8_t)family;
    msg.req.sdiag_protocol = IPPROTO_TCP;
    msg.req.idiag_states   = 1U << TCP_ESTABLISHED;

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = &msg, .iov_len = sizeof(msg) };
    struct msghdr m = {
        .msg_name    = &sa,
        .msg_namelen = sizeof(sa),
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
    };
    return sendmsg(fd, &m, 0) < 0 ? -1 : 0;
}

/* Scan dump responses, and when an entry's inode matches one we own,
 * format its remote address into out[out_sz]. Returns 1 on match, 0 if
 * the dump ended without a match, -1 on protocol error. Non-loopback
 * peers are preferred; a loopback match is held back and only emitted
 * if nothing better arrives. */
static int scan_diag_reply(int fd, const ino_t *inodes, int n_inodes,
                            char *out, size_t out_sz) {
    char buf[RECV_BUF];
    char pending[IP_STR_MAX] = {0};

    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) return -1;

        for (struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
             NLMSG_OK(nlh, (size_t)n);
             nlh = NLMSG_NEXT(nlh, n)) {

            if (nlh->nlmsg_type == NLMSG_DONE) {
                if (pending[0] && out_sz > strlen(pending)) {
                    memcpy(out, pending, strlen(pending) + 1);
                    return 1;
                }
                return 0;
            }
            if (nlh->nlmsg_type == NLMSG_ERROR) return -1;

            const struct inet_diag_msg *dm = NLMSG_DATA(nlh);

            int owned = 0;
            for (int i = 0; i < n_inodes; i++) {
                if ((ino_t)dm->idiag_inode == inodes[i]) { owned = 1; break; }
            }
            if (!owned) continue;

            char tmp[IP_STR_MAX];
            if (dm->idiag_family == AF_INET) {
                if (!inet_ntop(AF_INET, &dm->id.idiag_dst, tmp, sizeof(tmp)))
                    continue;
            } else if (dm->idiag_family == AF_INET6) {
                if (!inet_ntop(AF_INET6, &dm->id.idiag_dst, tmp, sizeof(tmp)))
                    continue;
            } else continue;

            int is_loop = (strncmp(tmp, "127.", 4) == 0) ||
                          (strcmp(tmp, "::1") == 0);
            if (is_loop) {
                if (!pending[0]) {
                    size_t L = strlen(tmp);
                    if (L < sizeof(pending)) memcpy(pending, tmp, L + 1);
                }
                continue;
            }
            if (out_sz > strlen(tmp)) {
                memcpy(out, tmp, strlen(tmp) + 1);
                return 1;
            }
        }
    }
}

int peer_lookup_tcp(pam_handle_t *pamh, pid_t pid, char *out, size_t out_sz) {
    if (!out || out_sz == 0) return 0;
    out[0] = '\0';

    ino_t inodes[INODES_CAP];
    int truncated = 0;
    int n = collect_socket_inodes(pid, inodes, INODES_CAP, &truncated);
    if (n <= 0) return 0;
    if (truncated && pamh) {
        pam_syslog(pamh, LOG_WARNING,
                   "authnft: /proc/%d/fd has more than %d socket inodes — "
                   "peer lookup may miss the session's TCP socket",
                   (int)pid, INODES_CAP);
    }

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) return 0;

    int found = 0;
    for (int i = 0; i < 2 && !found; i++) {
        int family = (i == 0) ? AF_INET6 : AF_INET;
        if (send_diag_request(fd, family) == 0 &&
            scan_diag_reply(fd, inodes, n, out, out_sz) == 1) {
            found = 1;
        }
    }
    close(fd);
    return found;
}

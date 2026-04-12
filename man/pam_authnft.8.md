% PAM_AUTHNFT(8) pam_authnft | System Administration
% Avinash H. Duduskar
% 2026

# NAME

pam_authnft - PAM session module that binds nftables rules to authenticated sessions

# SYNOPSIS

**pam_authnft.so** [*AUTHNFT_NO_SANDBOX=1*]

# DESCRIPTION

**pam_authnft** is a PAM session module that pins each authenticated user
session to a systemd transient **.scope** unit and inserts a
*{ cgroup_inode . src_ip }* element into a named nftables set. Rules
authored in a per-user fragment are then evaluated against that set,
binding packet-filter policy to the session for its entire lifetime
without referencing PIDs, UIDs, or usernames at match time.

The module exports only **pam_sm_open_session** and
**pam_sm_close_session**. It is not an authentication module.

# OPTIONS

**AUTHNFT_NO_SANDBOX=1**
:   Disable the seccomp-BPF sandbox. Accepted as a module argument in the
    PAM config or as an environment variable. Intended for debugging
    only; do not enable in production.

# OPERATION

On session open, the module:

1. Validates *PAM_USER* against a conservative charset
   (*[A-Za-z0-9._-]*, maximum 32 characters, no leading hyphen or dot).
2. Short-circuits to **PAM_SUCCESS** for the **root** user.
3. Retrieves *PAM_RHOST* and requires it to parse as an IPv4 or IPv6
   address via **inet_pton**(3).
4. Installs a seccomp-BPF allowlist with **SCMP_ACT_KILL** as the
   default action, after setting **PR_SET_NO_NEW_PRIVS**.
5. Calls **StartTransientUnit** on
   *org.freedesktop.systemd1.Manager* to create a scope named
   *authnft-\<user\>-\<pid\>.scope* under *authnft.slice*.
6. Resolves the scope's cgroupv2 inode via **sd_pid_get_cgroup**(3)
   and **stat**(2) on */sys/fs/cgroup/\<path\>* (fallback
   */sys/fs/cgroup/unified/\<path\>*).
7. Persists the inode in PAM data under the key *authnft_cg_id* so
   **pam_sm_close_session** can delete the exact element inserted.
8. Verifies the user is a member of the **authnft** group. Non-members
   pass through with **PAM_SUCCESS**.
9. Validates the fragment at */etc/authnft/users/\<user\>*: it must
   exist, be owned by UID 0, and not be world-writable.
10. Issues two libnftables calls:
    - *add table inet authnft*; *add set session_map_ipv4 { typeof
      meta cgroup . ip saddr; flags timeout; }*; the corresponding IPv6
      set; *add chain filter { type filter hook input priority filter
      - 1; policy accept; }*; *add element { cg_id . src_ip timeout 1d
      comment "..." }*.
    - *include "/etc/authnft/users/\<user\>"* at the top level.

On session close, the stored *cg_id* is retrieved from PAM data and
the element is deleted atomically. Cleanup failures are logged but do
not prevent session teardown.

# FILES

*/etc/authnft/users/\<user\>*
:   Per-user nftables fragment. Must be owned by root and not
    world-writable. Included at the top level of the nftables command
    stream after the session element has been inserted.

*/etc/systemd/system/authnft.slice*
:   Parent slice unit for all session scopes. Use
    **systemd.resource-control**(5) directives to apply combined
    limits. Shipped with all directives commented out.

*/usr/lib/security/pam_authnft.so*
:   The module itself.

# ENVIRONMENT

**AUTHNFT_NO_SANDBOX**
:   If set to a non-empty value, **sandbox_apply** becomes a no-op.
    Identical effect to passing **AUTHNFT_NO_SANDBOX=1** as a PAM
    module argument.

# RETURN VALUES

**PAM_SUCCESS**
:   Session set up successfully, root short-circuit, or user is not a
    member of the **authnft** group.

**PAM_SESSION_ERR**
:   Generic session setup failure: invalid user, unparseable
    *PAM_RHOST*, seccomp load failure, systemd handoff failure, or
    cgroup inode resolution failure.

**PAM_AUTH_ERR**
:   Fragment missing, wrong ownership, world-writable, or contains a
    syntax error rejected by libnftables. A diagnostic is shown to the
    user via **pam_error**(3).

**PAM_SERVICE_ERR**
:   libnftables context allocation failed or the setup transaction
    failed at the kernel.

**PAM_BUF_ERR**
:   Command buffer overflow during nftables transaction assembly.

# EXAMPLE PAM STACK

In */etc/pam.d/sshd*, after *pam_systemd.so*:

    session  optional  pam_authnft.so

Or, with PAM-level group gating:

    session  [success=1 default=ignore]  pam_succeed_if.so  user notingroup authnft  quiet
    session  required  pam_authnft.so

# SECURITY

The fragment trust model is identical to */etc/nftables.conf* and
sudoers includes: only root writes fragments. The module enforces
ownership and mode before loading. End users cannot author or modify
their own fragments.

The seccomp allowlist is derived empirically from strace traces of
complete open/close cycles; syscalls reached only during pre-sandbox
startup (such as **execve**(2) from the service binary) are
deliberately excluded.

# BUGS

Cgroupv1 and hybrid hierarchies are unsupported. Non-systemd init is
unsupported. On PAM stacks where the process invoking
**pam_sm_open_session** is not the direct parent of the user session,
the resolved cgroup may differ from the session's eventual cgroup.

Report issues via GitHub Security Advisories on *identd-ng/pam_authnft*
for security-sensitive reports, or the public issue tracker otherwise.

# SEE ALSO

**pam.conf**(5), **pam_systemd**(8), **nft**(8), **systemd.scope**(5),
**systemd.slice**(5), **systemd.resource-control**(5),
**seccomp**(2), **cgroups**(7)

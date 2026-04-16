% PAM_AUTHNFT(8) pam_authnft | System Administration
% Avinash H. Duduskar
% 2026

# NAME

pam_authnft - PAM session module that binds nftables rules to authenticated sessions

# SYNOPSIS

**pam_authnft.so** [*rhost_policy=strict|lax|kernel*] [*claims_env=NAME*] [*AUTHNFT_NO_SANDBOX=1*]

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

**rhost_policy=lax** (default)
:   If *PAM_RHOST* parses as an IPv4 or IPv6 literal, bind the session
    element into *session_map_ipv4* / *session_map_ipv6* as
    *{ cgroup_inode . src_ip }*. Otherwise — *PAM_RHOST* missing,
    a hostname (*UseDNS yes* in sshd), or unparseable — fall back to
    *session_map_cg*, which is keyed on *cgroup_inode* alone. Session
    identity is still enforced; only the src_ip leg is dropped.

**rhost_policy=strict**
:   Restore the pre-0.2 behaviour: a valid IP literal in *PAM_RHOST* is
    required; the session is denied with **PAM_SESSION_ERR** otherwise.

**rhost_policy=kernel**
:   Derive the peer IP from the session process's own ESTABLISHED TCP
    socket via **NETLINK_SOCK_DIAG** (see **ss**(8)). The
    kernel-reported address is authoritative and cannot be spoofed by
    a misconfigured or hostile PAM caller. If the kernel lookup
    succeeds and the value differs from a parseable *PAM_RHOST*, the
    module logs a **LOG_WARNING** of the form
    *"PAM_RHOST/kernel peer divergence: app='X' kernel='Y' — trusting
    kernel"*. Common causes: sshd behind a TCP load balancer (PROXY
    protocol not terminated) or **UseDNS yes**. If the kernel lookup
    fails (no ESTABLISHED TCP socket on the session PID, netlink denied),
    the module falls through to **rhost_policy=lax** semantics.

**claims_env=NAME**
:   Look up PAM environment variable *NAME* for a kernel-keyring serial
    (decimal *key_serial_t*). When present, the keyed payload is read via
    **keyctl**(2), sanitized to a printable ASCII subset, and embedded
    inside the nftables element's *comment* field as
    *"\<user\> (PID:\<pid\>) [\<tag\>]"*. The producer of the keyring
    entry is responsible for setting an appropriate timeout
    (*KEYCTL_SET_TIMEOUT*) and access mode (*KEYCTL_SETPERM*); this
    module never writes keys, only reads. If the env var is absent, the
    serial is malformed, or the key is inaccessible, the module
    proceeds without a tag — **claims_env** is non-fatal by design.
    See **keyctl**(2), **keyrings**(7).

**AUTHNFT_NO_SANDBOX=1**
:   Disable the seccomp-BPF sandbox. Accepted as a module argument in the
    PAM config or as an environment variable. Intended for debugging
    only; do not enable in production.

# OPERATION

On session open, the module:

1. Validates *PAM_USER* against a conservative charset
   (*[A-Za-z0-9._-]*, maximum 32 characters, no leading hyphen or dot).
2. Short-circuits to **PAM_SUCCESS** for the **root** user.
3. Retrieves *PAM_RHOST* and normalizes it: IPv4 / IPv6 literals pass
   through; an IPv6 zone suffix (*fe80::1%eth0*) is stripped because
   nftables *ip6 saddr* does not accept zones. Hostnames (*UseDNS yes*)
   and unparseable values fall through to the cgroup-only path under
   the default **rhost_policy=lax**, or are rejected under
   **rhost_policy=strict**.
4. Installs a seccomp-BPF allowlist with **SCMP_ACT_KILL** as the
   default action, after setting **PR_SET_NO_NEW_PRIVS**.
5. Calls **StartTransientUnit** on
   *org.freedesktop.systemd1.Manager* to create a scope named
   *authnft-\<user\>-\<pid\>.scope* under *authnft.slice*.
6. Resolves the scope's cgroupv2 inode via **sd_pid_get_cgroup**(3)
   and **stat**(2) on */sys/fs/cgroup/\<path\>* (fallback
   */sys/fs/cgroup/unified/\<path\>*).
7. Persists session state (cgroup inode + normalized remote IP +
   optional sanitized claims tag) in PAM data under the key
   *authnft_cg_id* so **pam_sm_close_session** can delete the exact
   element inserted from the correct set. The key name is retained
   for compatibility; the stored value shape is an internal ABI.
8. Verifies the user is a member of the **authnft** group. Non-members
   pass through with **PAM_SUCCESS**.
9. Validates the fragment at */etc/authnft/users/\<user\>*: it must
   exist, be owned by UID 0, and not be world-writable.
10. Issues two libnftables calls:
    - *add table inet authnft*; *add set session_map_ipv4 { typeof
      meta cgroup . ip saddr; flags timeout; }*; the corresponding IPv6
      set; *add set session_map_cg { typeof meta cgroup; flags timeout; }*;
      *add chain filter { type filter hook input priority filter - 1;
      policy accept; }*; *add element* into either
      *session_map_ipv{4,6}* as *{ cg_id . src_ip ... }* or into
      *session_map_cg* as *{ cg_id ... }*.
    - *include "/etc/authnft/users/\<user\>"* at the top level.

On session close, the stored session state is retrieved from PAM data
and the element is deleted atomically from the set it was inserted
into. Cleanup failures are logged but do not prevent session teardown.

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

*/run/authnft/sessions/\<cg_id\>.json*
:   Per-session identity file written on open_session and removed on
    close_session. Mode 0644 root:root, JSON schema documented in
    **docs/INTEGRATIONS.txt** §5.6. Intended for unprivileged
    observers (SIEM agents, monitoring daemons, operator consoles)
    that need to correlate a cgroup inode back to the owning
    session. The directory is created by
    */usr/lib/tmpfiles.d/authnft.conf* at boot.

*/usr/lib/tmpfiles.d/authnft.conf*
:   systemd-tmpfiles(5) snippet that creates */run/authnft/sessions/*
    and reaps orphaned per-session files older than 7 days.

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
:   Generic session setup failure: invalid user, unparseable *PAM_RHOST*
    under **rhost_policy=strict**, seccomp load failure, systemd handoff
    failure, or cgroup inode resolution failure.

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

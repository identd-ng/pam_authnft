# Security Policy

pam_authnft is alpha software. It runs inside the PAM process of services
like `sshd`, `login`, and `su` with whatever privilege that service holds —
typically root. Security reports are taken seriously.

## Scope

In scope:

- Anything that bypasses the fragment permission check
  (`st_uid == 0 && !world-writable`)
- Anything that causes `pam_authnft.so` to execute attacker-controlled code
  or syscalls outside the seccomp allowlist
- Username, `PAM_RHOST`, or fragment-path handling that permits injection
  into nftables commands, D-Bus method calls, or filesystem operations
- Leaks of session elements (in `session_map_ipv4`, `session_map_ipv6`, or
  `session_map_cg`) that outlive the session beyond the 24-hour safety-net
  timeout
- Misuse of the `rhost_policy=kernel` sock_diag path: incorrect peer-address
  resolution that binds a session element to the wrong source IP
- Cleanup or resource-exhaustion issues triggerable by an unauthenticated
  remote party via repeated session churn

Out of scope:

- Misconfiguration of user-authored fragments (administrator responsibility)
- Non-systemd init systems (explicitly unsupported)
- Cgroupv1 / hybrid hierarchies (explicitly unsupported)

## Reporting

Report privately via GitHub Security Advisories on the `identd-ng/pam_authnft`
repository ("Report a vulnerability" tab under Security). Please include a
minimal reproducer, kernel version, nftables version, and the PAM service
stack (`/etc/pam.d/<service>`) in use.

Public issues and pull requests are not the right channel for vulnerability
reports.

## Expectations

Given the alpha status and single-maintainer cadence, no fixed response SLA
is offered. Reports are acknowledged when read and addressed as priorities
allow. Coordinated disclosure is welcome; please agree a timeline before
publishing.

# pam_authnft

[![build](https://github.com/identd-ng/pam_authnft/actions/workflows/build.yml/badge.svg)](https://github.com/identd-ng/pam_authnft/actions/workflows/build.yml)
[![sanitizers](https://github.com/identd-ng/pam_authnft/actions/workflows/sanitizers.yml/badge.svg)](https://github.com/identd-ng/pam_authnft/actions/workflows/sanitizers.yml)
[![CodeQL](https://github.com/identd-ng/pam_authnft/actions/workflows/codeql.yml/badge.svg)](https://github.com/identd-ng/pam_authnft/actions/workflows/codeql.yml)
[![cppcheck](https://github.com/identd-ng/pam_authnft/actions/workflows/cppcheck.yml/badge.svg)](https://github.com/identd-ng/pam_authnft/actions/workflows/cppcheck.yml)
[![Coverity Scan](https://scan.coverity.com/projects/identd-ng-pam_authnft/badge.svg)](https://scan.coverity.com/projects/identd-ng-pam_authnft)
[![codecov](https://codecov.io/gh/identd-ng/pam_authnft/branch/master/graph/badge.svg)](https://codecov.io/gh/identd-ng/pam_authnft)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/identd-ng/pam_authnft/badge)](https://scorecard.dev/viewer/?uri=github.com/identd-ng/pam_authnft)
[![Language: C](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![License](https://img.shields.io/github/license/identd-ng/pam_authnft.svg)](LICENSE)

<p align="center">
  <img src="docs/mascot.svg" alt="pam_authnft mascot" width="320">
</p>

> **Status: alpha (0.0.x).** Interfaces, configuration paths, and invariants
> may change without notice. Review [docs/CONTRIBUTING.txt](docs/CONTRIBUTING.txt)
> and [docs/ARCHITECTURE.txt](docs/ARCHITECTURE.txt) before deploying, and
> report security issues via GitHub Security Advisories (see
> [SECURITY.md](SECURITY.md)).

A PAM session module that binds nftables firewall rules to authenticated user
sessions using the session's cgroupv2 inode as a stable kernel identity.
Works with any PAM-enabled service (SSH, login, su, VPN gateways, etc.) and
handles both IPv4 and IPv6.

OpenBSD's pf, via named anchors and pfctl, makes per-session packet filter
policy possible. pam_authnft brings the same model to Linux: nftables named
sets serve as the anchor equivalent, and the cgroupv2 inode of a systemd
transient scope replaces the authenticated shell as the session identity —
no dedicated shell, no setuid binary, no kernel patches.

Session policy is inspectable with standard `nft` tooling
(`nft list table inet authnft`) without requiring `bpftool` or BPF program
inspection.

The cgroupv2 filesystem assigns each cgroup directory a unique inode that is
stable for the lifetime of that cgroup. When systemd creates a transient
`.scope` for the session via D-Bus, all session processes land under that
cgroup. The module reads the inode via `stat(2)` on `/sys/fs/cgroup/<path>`
and inserts `{ inode . src_ip }` into an nftables set typed as
`typeof meta cgroup . ip saddr`.

At packet classification time, `meta cgroup` reads the cgroupv2 inode from
the socket's originating cgroup. Rules referencing `@session_map_ipv4` match
all processes in the session hierarchy regardless of uid, exec, or privilege
changes. The element is atomically deleted at logout.

## What it does

On session open:

1. Validates `PAM_RHOST` is a valid IP address
2. Locks the PAM process with a seccomp-BPF allowlist (`SCMP_ACT_KILL` default)
3. Creates a named transient `.scope` under `authnft.slice` via D-Bus
4. Reads the scope's cgroupv2 inode via `stat(2)` and stores it in PAM data
5. Validates and loads the user's root-owned fragment at `/etc/authnft/users/<username>`
6. Inserts `{ cgroup_id . src_ip }` into `session_map_ipv4` or `session_map_ipv6`

On logout, the stored cgroup ID is retrieved from PAM data and the element is
deleted. The nftables table and sets persist across sessions.

## Requirements

- Linux kernel >= 5.10, cgroupv2 unified hierarchy
- systemd with D-Bus
- nftables >= 1.0 (`meta cgroup` match requires kernel >= 4.19)
- Build: `gcc`, `make`, `pkg-config`
- Libraries: `libnftables`, `libseccomp`, `libsystemd`, `libcap`, `pam`

## Build and install

```
make                # release build
make debug          # rebuild with -DDEBUG -g for stderr tracing
make man            # build pam_authnft(8) manpage (requires pandoc)
sudo make install   # installs pam_authnft.so and authnft.slice
sudo make install-man
```

Installs the module to `/usr/lib/security/pam_authnft.so` and
`authnft.slice` to `/etc/systemd/system/`.

## Configuration

`make install` creates `/etc/authnft/users/` and installs the module and slice.
The remaining setup is manual:

```bash
# Create the authnft group (members are subject to session firewall rules)
sudo groupadd authnft

# Add a user to the group
sudo usermod -aG authnft alice

# Create a root-owned fragment for that user
sudo tee /etc/authnft/users/alice > /dev/null <<'EOF'
add rule inet authnft filter meta cgroup . ip saddr @session_map_ipv4 accept
EOF
sudo chmod 644 /etc/authnft/users/alice
```

Group members without a valid fragment are denied at session open (logged to
syslog). Non-members pass through unaffected.

### PAM stack (`/etc/pam.d/sshd`, after `pam_systemd.so`)

Option A — module checks group membership internally; non-members pass through:
```
session  optional  pam_authnft.so
```

Option B — PAM gates on group membership. Members without a valid fragment are
denied; non-members skip the module entirely. Use this once all fragments are in place:
```
session  [success=1 default=ignore]  pam_succeed_if.so  user notingroup authnft  quiet
session  required  pam_authnft.so
```

### Per-user fragments

Each group member needs `/etc/authnft/users/<username>`, owned by root and not
world-writable. Before loading, the module calls `stat(2)` on the fragment path
and rejects it unless `st_uid == 0` and the world-writable bit is clear. This
ensures only root can author or modify fragments — the same trust model used by
`/etc/nftables.conf` and sudoers includes. The fragment is then included at the
top level and run as nftables commands. A minimal example:

```nft
add rule inet authnft filter meta cgroup . ip saddr @session_map_ipv4 accept
```

See `examples/examples_generator.sh -f` for port-restricted, masquerade, and
time-limited variants.

### nftables state after session open

```
# nft list table inet authnft
table inet authnft {
    set session_map_ipv4 {
        typeof meta cgroup . ip saddr
        flags timeout
        elements = { 27711 . 127.0.0.1 timeout 1d expires 23h55m56s comment "authnft-test (PID:1127936)" }
    }

    set session_map_ipv6 {
        typeof meta cgroup . ip6 saddr
        flags timeout
    }

    chain filter {
        type filter hook input priority filter - 1; policy accept;
        meta cgroup . ip saddr @session_map_ipv4 accept
    }
}
```

`27711` is the cgroupv2 inode of `authnft-authnft-test-1127936.scope`. At packet
classification time, `meta cgroup` in the kernel matches this inode against the
socket's originating cgroup — binding the firewall rule to the session without
referencing PIDs, UIDs, or usernames. The 24-hour timeout is a safety net;
explicit deletion at logout is the primary cleanup mechanism.

### systemd controls

Because every session lands in a named `.scope` unit, the full systemd resource
control and sandboxing machinery is available — `man systemd.resource-control(5)`.
All settings in `data/authnft.slice` are commented out; uncomment what you need.

**Outbound network policy** — enforced via systemd's cgroup-BPF integration, orthogonal to nftables:
```ini
IPAddressDeny=any
IPAddressAllow=10.0.0.0/8
SocketBindDeny=ipv4:tcp:1-1023
SocketBindDeny=ipv6:tcp:1-1023
```

**Syscall and capability restriction** — applied to all processes in the scope at creation:
```ini
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
NoNewPrivileges=yes
CapabilityBoundingSet=
RestrictNamespaces=yes
```

## Seccomp allowlist

`SCMP_ACT_KILL` default, `PR_SET_NO_NEW_PRIVS` set before load. The allowlist
was derived empirically: `strace -f` across a complete `open_session` +
`close_session` cycle; only syscalls observed after `sandbox_apply()` returns
are included. `execve(2)` appears in the trace but originates from the test
harness before `dlopen()` loads the module — excluded.

## Limitations

- cgroupv2 unified hierarchy only; hybrid setups untested.
- Hard systemd dependency; non-systemd init not supported.
- Fragment syntax errors are caught at load time and logged; semantic errors
  are the administrator's responsibility.
- If cleanup fails at logout (e.g., nftables unavailable), the set element
  expires after 24 hours via the safety-net timeout on insert.
- The cgroup ID is resolved from the PAM process at `open_session`. On PAM
  stacks where the process invoking `open_session` is not the direct parent of
  the user session (e.g., a forking daemon that hands off before the module
  runs), the resolved cgroup may differ from the session cgroup.

## Testing

```
make test               # unit tests, no root needed
make test-integration   # pamtester + valgrind, requires root
```

The integration test creates and cleans up its own test user and group
automatically. Set `AUTHNFT_TEST_USER` to override the test account name
(default: `authnft-test`).

| # | What is tested |
|---|----------------|
| 1 | `util_is_valid_username` rejects path traversal and shell metacharacters |
| 2 | A syscall outside the allowlist triggers SIGSYS |
| 3 | An allowlisted syscall (`close`) returns normally through the sandbox |
| 4 | libnftables dry-run API accepts well-formed syntax |
| 5 | `util_get_cgroup_id` resolves a live PID to its cgroupv2 inode |
| 6 | Compiled `.so` has full RELRO, canary, PIE, CFI (via `checksec`) |
| 7 | `nft_handler_setup` loads a root-owned fragment end-to-end |
| 8 | Group member denied on missing fragment; allowed with valid fragment; root bypasses |
| 9 | No memory errors or leaks under Valgrind memcheck |

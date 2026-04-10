# pam_authnft

A PAM session module that binds nftables firewall rules to authenticated user
sessions using the session's cgroupv2 inode as a stable kernel identity.
Works with any PAM-enabled service (SSH, login, su, VPN gateways, etc.).

OpenBSD's pf anchor mechanism makes `authpf(8)` possible: named anchors let
rules be inserted and removed per session, binding packet filter policy to the
authenticated user's shell process. The author has been conscripting packet filters for unintended purposes
[since 2007](https://undeadly.org/cgi?action=article;sid=20070920214130).

pam_authnft applies the same idea to
Linux authenticated sessions: nftables named sets act as the anchor equivalent,
and the cgroupv2 inode of a systemd transient scope replaces the authenticated
shell as the session identity — no dedicated shell, no setuid binary, no kernel
patches.

Unlike BPF-based approaches, session policy is fully auditable via `nft list table inet authnft`.

The cgroupv2 filesystem assigns each cgroup directory a unique inode immutable
for its lifetime. When systemd creates a transient `.scope` for the session via
D-Bus, all session processes land under that cgroup. The module reads the inode
via `stat(2)` on `/sys/fs/cgroup/<path>` and inserts `{ inode . src_ip }` into
an nftables set typed as `typeof meta cgroup . ip saddr`.

At packet classification time, `meta cgroup` reads the cgroupv2 inode from the
socket's originating cgroup. Rules on `@session_map_ipv4` therefore match all
processes in the session hierarchy regardless of uid, exec, or privilege changes.
The element is atomically deleted at logout.

## What it does

On session open:

1. Validates `PAM_RHOST` is a routable IP address
2. Locks down the PAM process with a seccomp-BPF allowlist (`SCMP_ACT_KILL` default)
3. Creates a named transient `.scope` under `authnft.slice` via D-Bus
4. Reads the scope's cgroupv2 inode via `stat(2)`
5. Validates the user's root-owned fragment at `/etc/authnft/users/<username>`
6. Inserts `{ cgroup_id . src_ip }` into `session_map_ipv4` or `session_map_ipv6`

On logout, the element is deleted. The nftables table and sets persist.

## Requirements

- Linux kernel >= 5.10, cgroupv2 unified hierarchy
- systemd with D-Bus
- nftables >= 1.0 (`meta cgroup` match requires kernel >= 4.19)
- Build: `gcc`, `make`, `pkg-config`
- Libraries: `libnftables`, `libseccomp`, `libsystemd`, `libcap`, `pam`

## Build

```
make            # release build
make debug      # rebuild with -DDEBUG -g for stderr tracing
sudo make install
```

Installs to `/usr/lib/security/pam_authnft.so`.

## Configuration

```
sudo mkdir -p /etc/authnft/users
sudo chmod 700 /etc/authnft/users
sudo groupadd authnft
sudo usermod -aG authnft alice
sudo install -m 644 data/authnft.slice /etc/systemd/system/
sudo systemctl daemon-reload
```

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

Each group member needs `/etc/authnft/users/<username>`, root-owned, not
world-writable. The fragment runs as nftables commands inside `inet authnft`.
A minimal example:

```nft
add rule inet authnft filter meta cgroup . ip saddr @session_map_ipv4 accept
```

See `examples/examples_generator.sh -f` for port-restricted, masquerade, and
time-limited variants. The module enforces `st_uid == 0 && !(st_mode & S_IWOTH)`
before passing the path to libnftables.

### nftables state after session open

```nft
table inet authnft {
    set session_map_ipv4 { typeof meta cgroup . ip saddr; flags timeout; }
    set session_map_ipv6 { typeof meta cgroup . ip6 saddr; flags timeout; }
    chain filter { type filter hook input priority filter - 1; policy accept; }
}
```

Element inserted: `{ 1234567 . 192.0.2.1 comment "alice (PID:8492)" }` where
`1234567` is the inode of `authnft-alice-8492.scope`.

### systemd controls

Because every session lands in a named `.scope` unit, the full systemd resource
control and sandboxing machinery is immediately available — `man systemd.resource-control(5)`.
All settings in `data/authnft.slice` are commented out; uncomment what you need.

**Outbound network policy** — enforced via cgroup-attached BPF, orthogonal to nftables:
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

`SCMP_ACT_KILL` default, `PR_SET_NO_NEW_PRIVS` before load. The allowlist was
derived empirically: `strace -f` across a complete `open_session` + `close_session`
cycle; only syscalls observed after `sandbox_apply()` returns are included.
`execve(2)` appears in the trace but originates from the test harness before
`dlopen()` loads the module — excluded.

## Limitations

- cgroupv2 unified hierarchy only; hybrid setups untested.
- Hard systemd dependency; non-systemd init not supported.
- Fragment syntax errors are caught at load time and logged; semantic errors
  are the administrator's responsibility.
- The cgroup ID is resolved from the PAM process. If the PAM service forks
  before calling `open_session`, the resolved cgroup may not match the session.

## Testing

```
make test               # unit tests, no root needed
make test-integration   # pamtester + valgrind, requires root
```

| # | What is tested |
|---|----------------|
| 1 | `util_is_valid_username` rejects path traversal and shell metacharacters |
| 2 | A syscall outside the allowlist triggers SIGSYS |
| 3 | An allowlisted syscall (`close`) returns normally through the sandbox |
| 4 | libnftables dry-run API accepts well-formed syntax |
| 5 | `util_get_cgroup_id` resolves a live PID to its cgroupv2 inode |
| 6 | Compiled `.so` has full RELRO, canary, PIE, CFI (via `checksec`) |
| 7 | `nft_handler_setup` loads a root-owned fragment end-to-end |
| 10 | Group member denied on missing fragment; allowed with valid fragment; root bypasses |
| 11 | No memory errors or leaks under Valgrind memcheck |

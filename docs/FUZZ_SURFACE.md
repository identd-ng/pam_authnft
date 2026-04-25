# Fuzz coverage surface

Single source of truth for what's fuzzed in pam_authnft and what isn't.
Every parser, sanitizer, and byte-handler in the codebase appears here.
Update on every harness addition or non-trivial source change.

This document is deliberately blunt about gaps. A green checkmark is
earned, not assumed.

---

## Status legend

| Mark | Meaning |
|---|---|
| ✅ | Harness exists, property assertions in place, run by CIFuzz on every PR |
| 🟡 | Harness exists but lacks property assertions, OR `make fuzz-coverage` shows the harness reaches < 90% of the targeted function |
| 🟠 | Function is `static` and needs the `#ifndef FUZZ_BUILD / static / #endif` guard before a harness can target it directly |
| ❌ | No harness. Listed with priority (High/Med/Low) by attacker reachability |

Property assertions matter. Without them, a harness only catches crashes;
with them, it catches behavior outside spec, which is where the real
bugs hide.

---

## Inventory

### Direct attacker-controlled inputs

| Function | Source | Trust | Status | Harness | Notes |
|---|---|---|---|---|---|
| `util_is_valid_username` | `PAM_USER` (sshd) | hostile | ✅ | `fuzz_username` | 100% region / line, 95% branch. Pure crash-only harness; adequate given the simple validator semantics |
| `util_normalize_ip` | `PAM_RHOST` (sshd, possibly via DNS or proxy) | hostile | ✅ | `fuzz_username` (combined) | 93.02% region, 96.15% line, 91.30% branch. Seed corpus covers v4-mapped / IPv4 / IPv6 / zone-suffix paths; harness explicitly calls with NULL/zero-size args to cover the early-out guards. Defensive `inet_ntop` failure on v4-mapped extraction (line 72) is unreachable by design — IP_STR_MAX is always large enough for an IPv4 literal |

### Kernel-supplied bytes

| Function | Source | Trust | Status | Harness | Notes |
|---|---|---|---|---|---|
| netlink walker in `peer_lookup_tcp` | `NETLINK_SOCK_DIAG` reply | semi-hostile (any CAP_NET_ADMIN process) | 🟠 ❌ **High** | — | Hand-rolled NLA walker. Highest-payoff harness in the codebase |
| `socket:[NNNN]` parser in `peer_lookup_tcp` | `/proc/<pid>/fd/N` symlink | trusted | 🟠 ❌ Med | — | Integer parse, embedded NUL, overflow |
| `keyring_read_serial` payload sanitizer | `keyctl(KEYCTL_READ)` | semi-trusted (producer trusted, consumer must defend) | 🟠 ❌ Med | — | printable-ASCII filter; truncation, journal-field-confusing chars |
| `util_get_cgroup_path` invariant | `sd_pid_get_cgroup` return | trusted | ❌ Med | — | Depth/prefix validator; rejection paths matter |

### Admin-controlled inputs (root-owned files / PAM env)

| Function | Source | Trust | Status | Harness | Notes |
|---|---|---|---|---|---|
| `validate_fragment_content` | `/etc/authnft/users/<user>` | admin | ✅ | `fuzz_fragment` | 100% region / line / branch. Seed corpus covers all rejection paths (relative include, outside-/etc/authnft/, glob characters); harness exercises both the memfd success path and a forced fopen-failure path |
| `substitute_placeholders` | fragment content after validation | admin | ✅ | `fuzz_substitute_placeholders` | State machine + malloc sizing; sizing-invariant property assertion. **Found two heap-buffer-overflow bugs on first run** — see "Bugs found" below |
| `read_file` size cap | fragment file size | admin | ❌ Low | — | Trivially correct (`fseek` + `ftell` + bound check); no harness planned |
| `event_correlation_capture` sanitizer | PAM env `AUTHNFT_CORRELATION` | semi-trusted (upstream PAM module) | ❌ Med | — | Tiny but high-frequency surface |
| PAM module arg parser (`rhost_policy=…`, `claims_env=…`) | PAM config | admin | ❌ Low | — | Tiny |

### Composed nft command stream

| Function | Source | Trust | Status | Harness | Notes |
|---|---|---|---|---|---|
| `nft_handler_setup` `snprintf` chain | composed from validated user/IP/cg_path/scope_unit | n/a (composed) | ❌ Med | — | Injection / truncation risk if composer trusts inputs incorrectly |
| nft handle parser (echo output → `uint64_t`) | libnftables echo buffer | trusted | ❌ Low | — | |

### Out of scope

- libnftables internals — their fuzz farm
- libsystemd internals — their fuzz farm
- libpam internals — their fuzz farm
- Seccomp filter itself — static config, not a parser
- Session JSON emitter — composed from validated input, output-only
- nftables fragment after `include` resolution — libnftables's responsibility once validated

---

## What fuzz cannot find here

Honest disclosure. These bug classes will not surface from any harness
in this document, regardless of duration:

- **Kernel/protocol semantic bugs.** K1 (wrong nft expression family on
  cgroupv2), K2 (delete-by-path race after scope reap), K10 (Class A/B
  socket-scope semantic gap). These are kernel-API-contract bugs.
  Defense: kernel-feature audit, integration tests that exercise the
  actual semantics, K-numbered findings tracked in HANDOFF.
- **Distributed/multi-host bugs.** N/A while pam_authnft is per-host.
- **Cgroupfs TOCTOU races.** K2 lives here. Best caught by
  crash-and-recover integration tests, not unit fuzz.
- **PAM stack ordering bugs across distros.** Caught by integration
  tests on each distro target.
- **Logic bugs that don't violate stated invariants.** A function that
  returns wrong-but-plausible answers will pass property-assertion
  fuzz forever. Defense: differential testing against an oracle (see
  plan §D.1).

---

## Coverage measurement

`make fuzz-coverage` builds the harnesses with `-fprofile-instr-generate
-fcoverage-mapping` (in addition to ASan + libFuzzer), runs each harness
for ~10s, merges profdata, generates an HTML report at
`docs/fuzz-coverage/index.html` and a text summary on stderr.

**Run after every harness addition.** Without coverage measurement, "we
have a harness for X" is a claim, not a fact. The coverage report is the
mechanism that promotes a row from 🟡 to ✅.

The 90% threshold is the bar for ✅. Below that, the row stays 🟡 and
the gap is documented in this file.

---

## Bugs found

A running record of bugs each harness has caught. The point is to make
the case for fuzzing self-evident.

| Harness | Bug | Severity | Fixed in |
|---|---|---|---|
| `fuzz_substitute_placeholders` | 1-byte heap-buffer-overflow at `nft_handler.c:208` (terminator write). Triggered when a placeholder expansion pushes `wi` to `max_expand-1` and is followed by an unmatched byte; the unmatched-byte path had no bounds check, advancing `wi` to `max_expand` and the post-loop `out[wi]='\0'` wrote 1 byte past the allocation. Found ~200k iterations after harness was wired in. | Med (fragment trust model is admin-only, so triggering is admin-self-foot-shot, but ASan-detectable OOB is a memory-safety bug regardless). Caused by replacement strings whose total expansion approaches `2*src_len`. | this PR |
| `fuzz_substitute_placeholders` | Same OOB pattern at `nft_handler.c:163` (comment/quote pass-through write). Three write paths in the function, only the matched-placeholder path had a bounds check. Found seconds after the first fix. | Med (same trust model) | this PR |

Regression inputs preserved at:
- `fuzz/corpus/substitute_placeholders/regression_oob_terminator`
- `fuzz/corpus/substitute_placeholders/regression_oob_unmatched_path`

CIFuzz re-runs these on every PR.

## Current coverage (per `make fuzz-coverage`)

Per-function coverage on the **fuzzed** functions (the only ones the
status legend applies to). HTML report under `docs/fuzz-coverage/`.

| Function | Region | Line | Branch | Status |
|---|---|---|---|---|
| `util_is_valid_username` | 100.00% | 100.00% | 95.00% | ✅ |
| `util_normalize_ip` | 93.02% | 96.15% | 91.30% | ✅ |
| `validate_fragment_content` | 100.00% | 100.00% | 100.00% | ✅ |
| `substitute_placeholders` | 96.83% | 100.00% | 97.92% | ✅ |

Per-source-file region coverage (illustrating how much codebase is
*untouched* by any harness):

| File | Region cover | Why |
|---|---|---|
| `nft_handler.c` | 35.12% | covered: `validate_fragment_content`, `substitute_placeholders`. uncovered: `nft_handler_setup` cmd assembler, libnftables call sites, `nft_handler_cleanup`, `read_file` |
| `pam_entry.c` | 29.41% | covered: `util_is_valid_username`, `util_normalize_ip`. uncovered: PAM entry points, arg parser, `is_debug_bypass_requested`, `free_pam_data` |
| `event.c` | 0% | no harness — `event_correlation_capture` sanitizer pending |
| `keyring.c` | 0% | no harness — `keyring_read_serial` sanitizer pending |
| `peer_lookup.c` | 0% | no harness — netlink walker is the highest-priority outstanding |
| `bus_handler.c` | 0% | no harness; sd-bus surface mostly out-of-scope |
| `sandbox.c` | 0% | static config, not a parser; no harness planned |
| `session_file.c` | 0% | output-only JSON emitter; low priority |
| **TOTAL** | **14.10%** | The bar is per-function ≥90% for ✅, not aggregate; aggregate goes up by adding harnesses, not by fuzzing the same surface harder |

## Sustained-fuzz channel

| Channel | Status | Duration | Trigger |
|---|---|---|---|
| CIFuzz per-PR | live | 60 s × harness | every pull request |
| Nightly cron (planned) | not implemented | 30 min × harness | daily |
| OSS-Fuzz registration (deferred) | submission staged | continuous | once project age threshold met |
| Self-hosted fuzz farm (optional) | not implemented | always-on | continuous |

Plan and rationale: see issue tracker / fuzz-strategy discussion.

---

## How to add a new harness

1. **Refactor**: if the target function is `static`, wrap with
   `#ifndef FUZZ_BUILD / static / #endif`. The non-fuzz build is
   bit-identical because `FUZZ_BUILD` is undefined.
2. **Write the harness** in `fuzz/fuzz_<name>.c`. Include
   property assertions (`__builtin_trap()` on invariant violation),
   not just `LLVMFuzzerTestOneInput` returning 0.
3. **Add to `Makefile`**: append to `FUZZ_TARGETS`.
4. **Add to `infra/oss-fuzz/build.sh`**: one extra `$CC` invocation.
5. **Add to `.github/workflows/cifuzz.yml`**: one extra step running
   the new binary with `-max_total_time=60`.
6. **Run `make fuzz-coverage`**: verify the harness reaches the
   targeted code paths. If not, fix the harness or split into
   smaller harnesses.
7. **Update this document**: change the status mark, set the harness
   name, note any property assertions in place.

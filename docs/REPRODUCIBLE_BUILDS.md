# Reproducible builds

`pam_authnft.so` is a small dynamically-linked PAM module. Reproducibility
matters here for a narrow but real reason: a downstream packager (Arch,
Debian, Fedora, NixOS overlay) wants to be able to verify that *their*
build of pam_authnft from a given source tag matches the upstream
release artefact. Without that property, every distro is implicitly
trusting upstream's build infrastructure on top of the source.

This file documents what reproducibility we provide and what we don't.

## Same-machine: ✅ verified

Two consecutive builds on the same host with the same toolchain produce
**bit-identical** `pam_authnft.so`. Verified by `make reproducibility-check`,
which builds twice and diffs the SHA-256 of the artefact.

We didn't need any special flags to achieve this — modern GCC + GNU `ld`
already produce deterministic output given identical inputs. The
contributing factors are:

- The `OBJS` list in the Makefile is alphabetically sorted, so link order
  is deterministic.
- GCC's default `--build-id=sha1` derives from the input bytes of the
  link, which are themselves deterministic.
- Section ordering and symbol layout are stable across runs.

## Cross-machine: ⚠️ partial

A build on machine A and a build on machine B with **identical** toolchain
(same GCC version, same libc, same binutils, same kernel headers) and
the same source should produce bit-identical output. We don't run a
cross-machine reproducibility check in CI, but the build does not
introduce any host-specific data (no embedded paths, no timestamps from
`__DATE__`/`__TIME__`, no PID-derived state).

The toolchain pin we currently test on is recorded in
[`docs/THIRD_PARTY.md`](THIRD_PARTY.md) ("Build tooling" table); the
distribution-shipped versions are what packagers should match.

## Cross-distro: ❌ not promised

Reproducibility across `gcc-12` vs `gcc-14`, glibc 2.39 vs 2.40, etc., is
not provided. Compiler-emitted instruction sequences, optimiser choices,
and even default symbol-mangling subtly differ across versions; we do
not pin to a specific compiler.

A distro packager who needs cross-distro reproducibility can:

- Build inside a dedicated reproducible-build environment (e.g.,
  `disorderfs` + `reprotest`) using their distro's exact toolchain
  version.
- Compare the resulting hash against the upstream-published hash for
  *that toolchain*. We don't currently publish per-toolchain hashes.

This is a deferred OSTIF best-practices §3 item. It becomes worth
investing in once pam_authnft has multiple distro packagers actively
tracking releases.

## Verifying a release artefact

Once a release tag exists:

```
git checkout v0.1.0          # pinned source
make reproducibility-check    # local build twice, hashes match
sha256sum pam_authnft.so      # compare against the release-notes hash
```

The release-notes hash is the maintainer's commitment that *that source
tag, on the maintainer's build machine, produces this artefact*. A
mismatch means either:
- Toolchain differs (most common); or
- The maintainer's machine was compromised (rare but the reason
  reproducibility matters).

## What's NOT a reproducibility goal

- Across operating systems (Linux only)
- Across architectures (`x86_64` only currently)
- Cross-libc (musl vs glibc) — different ABIs, not an apples-to-apples
  comparison
- Across release versions — a 0.1.0 binary will not match a 0.1.1 binary
  even with the same toolchain; that's by design

## Known reproducibility-friendly facts about the codebase

For the curious, here's why we get same-machine reproducibility "for
free":

| Factor | Status | Notes |
|---|---|---|
| `__DATE__` / `__TIME__` macros | not used | grep src/ for `__DATE__` returns nothing |
| Embedded build path | none | no `__FILE__` recorded in the binary; debug info would but we don't ship `-g` in release |
| Embedded hostname/user | none | no `whoami` / `hostname` in the build |
| PID-dependent code | none | `getpid()` is called at runtime only |
| Random-seed init | none | the only `getrandom()` is at runtime, in `event_correlation_capture` |
| Object file ordering | alphabetical | enforced by the Makefile `OBJS` list |
| Linker `--build-id=sha1` (GCC default) | deterministic | hash of input bytes, not of the link timestamp |
| File-mtime-sensitive paths | none | `ar` is not invoked; `.o` mtimes are not embedded |

If any of these change in a way that breaks reproducibility, the
`make reproducibility-check` target catches it before the change lands.

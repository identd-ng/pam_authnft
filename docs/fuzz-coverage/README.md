# Fuzz coverage report

This directory holds the most recent llvm-cov HTML report for the
project's libFuzzer harnesses. It IS committed — so it renders on
GitHub and persists in fresh clones — and is regenerated on demand by:

    make fuzz-coverage

The report survives `make clean` (only the build artefacts under
`fuzz/coverage/` get wiped). Refresh in a commit when a harness change
or a bug fix is expected to move coverage.

Open [`index.html`](index.html) in a browser. The summary table at
`make fuzz-coverage` time is also written to stdout.

## How to read it

The bar that matters is **per-function coverage**, not aggregate. A
function at < 90% is recorded as 🟡 in [`../FUZZ_SURFACE.md`](../FUZZ_SURFACE.md);
≥ 90% promotes it to ✅. Aggregate coverage is the wrong metric — it
goes up by adding harnesses, not by fuzzing the same surface harder.

## Refresh frequency

Run after every harness addition. The report can also be regenerated on
demand to confirm a coverage delta after a refactor or bug fix.

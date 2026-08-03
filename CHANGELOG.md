# Changelog

All notable changes to `.lexe` are recorded here (format: *Keep a Changelog*).
Versioning follows [docs/ALPHA.md](docs/ALPHA.md): the **runtime** version is a
distinct axis from the **package format** (`0.1`, FORMAT-0.1) and the **Tux32**
baseline (`tux32-core-1`). Dates are UTC.

## [Unreleased] — 0.1.0-alpha (Alpha candidate)

The first Alpha candidate. Everything below is implemented and green on Linux
(GCC) and Windows (MSVC); items marked *(CI)* are additionally proven by a
GitHub Actions job. No release tag is created by this line — tagging is an
explicit operator action (see [docs/ALPHA.md](docs/ALPHA.md)).

### Platform
- Signed `.lexe` package format (FORMAT-0.1): deterministic ZIP, Ed25519 over
  exact bytes, per-file SHA-256, strict hardened parser.
- Runtime lifecycle in userspace: verify → install → launch → update → rollback
  → remove; transactional installs with crash recovery; atomic version activation.
- Linux **bubblewrap** isolation (read-only image; private data/cache/temp;
  sanitized environment; network denied unless the `network` permission is
  granted); the launcher **fails closed** and never runs an app unconfined.
- Local **trust-on-first-use** publisher trust (key continuity, changed-key
  refusal, local block/unblock); permission-expansion **consent** gate.
- OS-backed concurrency: operation locks, launch leases, and the launch TOCTOU
  closure.

### Developer experience
- Automatic ELF dependency analysis (direct ELF reading; typed classification;
  glibc aggregation); compatibility analysis; runtime profiles; build report.
- `lexe analyze`, `lexe build`, and the graphical Builder wizard.

### Tux32 Core 1 — cross-distribution portability
- Frozen `tux32-core-1` baseline (dynamically linked x86-64 ELF, `x86-64-v1`,
  glibc symbol ceiling `2.31`); machine-readable `profile.json` pinned to the
  compiled definition by a test.
- Typed verification engine and `lexe sdk verify` (typed verdict and exit codes)
  that reuse the dependency engine — no second analysis path.
- The Builder **hard-gates** the Core Portable profile on Core 1; the build
  report carries the typed Tux32 verdict.
- Minimal build-in-sysroot SDK (`sdk/tux32-core-1/`) and a dynamically linked
  reference application.
- End-to-end cross-distribution proof, `scripts/portability-demo.sh` *(CI)*: one
  unchanged signed package build → verify → install → sandboxed launch across a
  real distribution boundary, plus the above-ceiling negative proof.

### Alpha stabilization
- Centralized version metadata (`src/core/version.hpp`); `lexe version`
  (`--version` / `-V`), human and `--json`, reporting the runtime, package-format
  and Tux32 axes distinctly; the runtime version is shown in the GUI titles.
- Headless, warning-clean, markup-safe GUI smoke test, `scripts/gui-smoke.sh`
  *(CI)*.
- CI hardening: `scripts/build.sh` made executable; the `linux` job installs
  bubblewrap and the GTK SVG loader and enables unprivileged user namespaces so
  the real isolation-launch tests run; the `portability` job runs under rootless
  podman.
- `packaging/install.sh` and `packaging/uninstall.sh` made executable so the
  README's install step works on a fresh clone.

### Known limitations
See [docs/ALPHA.md#known-limitations](docs/ALPHA.md#known-limitations) — most
notably: Linux-only isolation (Windows is a build/test host), isolation requires
a working bubblewrap + user-namespace backend, Core 1 is x86-64 + dynamic-ELF
only, and publisher trust is local (Tier 1) with no global revocation or
authenticated key rotation.

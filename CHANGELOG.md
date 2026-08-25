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

### Developer & consumer experience (final Alpha polish)
- `lexe inspect` — a human-first package inspector (identity, verification,
  dependencies, checksum; `--json` / `--manifest` for raw).
- `lexe apps` — the installed-application manager (version, publisher, disk
  usage, install date, last run, local trust; `--json`).
- `lexe config` + `src/core/settings` — persisted preferences (theme,
  update-check, developer mode, diagnostics); cosmetic only, never a security
  toggle.
- CLI polish: grouped example-rich help, terminal styling (TTY-only, NO_COLOR
  aware), friendlier errors with actionable hints, `lexe completion bash`/`zsh`.
- Builder: a first-run welcome screen (remembered) and staged build progress.
- Installer: an "After install" plain-language section (where it goes, how to
  remove it, what happens to data). install.sh / uninstall.sh get a banner,
  step progress, and an up-front preservation guarantee.
- Consumer errors read as "what happened / why / how to fix it" (e.g. the
  permission-expansion prompt).
- New docs: FAQ, Troubleshooting; new `examples/` (cli-tool, bundled-library).

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

### Alpha acceptance fixes
Found by driving the documented paths end to end on a real Linux host, rather
than by reading the code:
- **A directory or FIFO handed to a package command no longer crashes or
  hangs.** `util::slurp` refused nothing but missing files, so a directory —
  which opens successfully and reports `INT64_MAX` as its size — ended in
  `lexe: std::bad_alloc`, and a FIFO blocked forever waiting for a writer. Whole
  file reads now require a regular file and read to EOF rather than trusting a
  seek (which also fixes reading unseekable `/proc` entries). `PackageReader`
  additionally fails **closed**: the 2 GiB package bound used to be skipped
  entirely whenever the size could not be determined.
- **`lexe analyze` reported the build host's glibc requirement as the
  application's.** `max_glibc_version()` aggregated across the whole dependency
  graph, so the host's own `libc`/`libm` internals (`GLIBC_2.36` on Ubuntu
  24.04) were attributed to the package — contradicting the Tux32 verifier's
  answer for the same binary in the same output, and making the compatibility
  verdict depend on the machine that ran the analysis. It is now the package's
  own requirement (root executable + bundled libraries), matching Tux32, so the
  CLI, the build report and the Builder all agree.
- **Actionable hints are now accurate.** Errors can carry their own hint, and
  the ones that were wrong were fixed: "no update source configured" said to
  re-check the path instead of naming `lexe source set`; a malformed
  `update.json` said to re-download the package instead of pointing at the
  FORMAT-0.1 §7 shape; `analyze`/`build`/`inspect` path errors and a rollback
  with no previous version all suggested `lexe apps`. The permission-expansion
  refusal no longer prints its fix twice.

### Alpha acceptance polish
- `lexe <command> --help` / `-h` and `lexe help <command>` now print that
  command's own summary and usage, instead of "unknown option" (exit 2) or the
  full banner.
- `lexe completion zsh`, alongside bash; both scripts are generated from one
  shared command/subcommand table so they cannot drift.
- `scripts/gui-smoke.sh` tolerates the `gdk_seat_get_keyboard` assertion a
  just-started virtual X server produces — verified environmental (a stock GTK
  window reproduces it 3/3 against a cold Xvfb; both GUIs are clean 8/8 against
  a warm one), so the race no longer fails CI.

### Known limitations
See [docs/ALPHA.md#known-limitations](docs/ALPHA.md#known-limitations) — most
notably: Linux-only isolation (Windows is a build/test host), isolation requires
a working bubblewrap + user-namespace backend, Core 1 is x86-64 + dynamic-ELF
only, and publisher trust is local (Tier 1) with no global revocation or
authenticated key rotation.

# Changelog

All notable changes to `.lexe` are recorded here (format: *Keep a Changelog*).
Versioning follows [docs/ALPHA.md](docs/ALPHA.md): the **runtime** version is a
distinct axis from the **package format** (`0.1`, FORMAT-0.1) and the **Tux32**
baseline (`tux32-core-1`). Dates are UTC.

## [Unreleased] — Definitive Architecture convergence

Moves the runtime from the alpha prototype onto the canonical
*.LEXE Definitive Architecture*. See
[docs/DEFINITIVE-ARCHITECTURE.md](docs/DEFINITIVE-ARCHITECTURE.md) for the full
description, including a plainly-stated list of what is still missing.

### Added
- **Package roles.** A `.lexe` is an installable `"application"` or a
  `"launch"` reference, decided by the SIGNED manifest rather than the file
  name. The two roles are structurally distinct: a launch reference may not
  declare `applicationType`/`architectures`/`entrypoint`/`install` and carries
  no payload; an application may not claim a launch target.
- **`payload-role` verification stage.** A native package's declared entrypoint
  must BE a runnable ELF for a declared architecture, checked before
  installation. This is the direct fix for the alpha package that declared a
  native application while its entrypoint was `helloworld.cpp`.
- **Execution policy.** `execution.missionCritical` (an execution restriction,
  not a safety certification) and `execution.allowedChains`. A strict resolver
  for mission-critical software that stops rather than falling back, and a
  normal resolver that prefers native and uses a compatibility chain only when
  needed, permitted and available.
- **Declared launch semantics.** `launch.mode` is `gui`, `console` or
  `service`. A console application launched without a terminal is given one by
  `.LEXE`; exit code 0 is success even when no window appears.
- **Durable desktop integration.** `integration.json` records every
  registration `.LEXE` owns with its content hash; `lexe doctor` names what is
  missing or modified and `lexe doctor --repair` re-establishes it from
  installed state, with no package file present. The default `.lexe`
  association is written to `mimeapps.list`, which is what actually survives a
  reboot.
- **Launch references.** `run.lexe` — a real, fully signed, fully verifiable
  `.lexe` with role `launch` and no payload, signed by a stable machine-local
  key. The installed ELF stays private inside the application store.
- **Structured diagnostics.** Typed `.lexe-error` records under
  `~/.local/state/lexe/errors/<id>/` carrying the failure stage, execution
  chain, host OS/ISA, runtime, exit code *or signal*, captured stream
  references and a timestamp. Bounded per-stream and per-app, with truncation
  disclosed.
- **Per-application overrides** under `~/.config/lexe/apps/<id>.json` that can
  narrow or reorder the publisher's permitted chains but never extend them, and
  never modify or invalidate the signed package.
- **Display access for a declared GUI launch mode**, reported truthfully in the
  isolation control map rather than silently claimed.
- **New commands:** `lexe open`, `lexe doctor`, `lexe errors`, `lexe compat`,
  `lexe launch-ref`, `lexe trust classes`, `lexe integrate --verify/--remove`,
  `lexe run --chain`.
- `lexe-ui` — the consumer and power-user frontend, and the registered `.lexe`
  handler, superseding `lexe-installer`.

### Changed
- The canonical MIME type is `application/vnd.usha.lexe`; the alpha's
  `application/x-lexe` is kept as an alias so existing files and registrations
  keep working.
- Runtime/dependency resolution happens once at install and repair and is
  recorded; a normal native launch only confirms the recorded state and execs.
- `packaging/install.sh` no longer hand-rolls MIME/desktop registration in
  shell; it installs the binaries and calls `lexe integrate`, so there is one
  implementation of registration and therefore one thing to repair.

### Fixed
- A package whose native entrypoint is source text is now rejected before
  installation instead of becoming a mysterious launch failure.
- Desktop integration that does not survive a reboot is now a detected, named,
  repairable condition rather than a silent failure.
- A console application launched from the desktop no longer looks like
  "nothing happened".
- `present_isolation()` no longer claims GUI forwarding is unavailable now that
  display access is implemented.

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
  aware), friendlier errors with actionable hints, `lexe completion bash`.
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

### Known limitations
See [docs/ALPHA.md#known-limitations](docs/ALPHA.md#known-limitations) — most
notably: Linux-only isolation (Windows is a build/test host), isolation requires
a working bubblewrap + user-namespace backend, Core 1 is x86-64 + dynamic-ELF
only, and publisher trust is local (Tier 1) with no global revocation or
authenticated key rotation.

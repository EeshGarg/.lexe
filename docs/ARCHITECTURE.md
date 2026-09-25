# Lexe Reference Runtime — Architecture (0.1)

The reference runtime is modern C++ (C++20). It targets Linux x86-64 first; the
portable core also compiles and is unit-tested on Windows/MSVC (the development
host), with Linux-only behaviour (XDG desktop integration, GTK GUI) isolated
behind small platform seams and verified in CI on `ubuntu-latest`.

Normative companion: [FORMAT-0.1.md](FORMAT-0.1.md). Product intent:
[SPEC.md](../SPEC.md).

## Conventions

* Namespace `lexe`. C++20, compiles clean under MSVC (`/W4 /utf-8 /EHsc`),
  GCC and Clang (`-Wall -Wextra`).
* Errors are exceptions: `lexe::Error : std::runtime_error` (base), with
  `VerificationError`, `NotFoundError`, `UsageError` derived. The CLI catches at
  the top level and maps to exit codes.
* `std::filesystem` for all path work; narrow UTF-8 strings throughout
  (MSVC gets `/utf-8`).
* No mutable globals. Everything that touches disk goes through a
  `lexe::Paths` value constructed once from the environment.
* Third-party code is vendored, pinned, and never modified (compile-time
  configuration only, e.g. `MINIZ_NO_TIME`).

## Third-party (vendored under `third_party/`)

| Library | Version | Files | License | Purpose |
|---|---|---|---|---|
| nlohmann/json | 3.11.3 | `nlohmann/json.hpp` | MIT | JSON |
| miniz | 3.0.2 (amalgamated) | `miniz/miniz.{h,c}` | MIT | ZIP read/write |
| orlp/ed25519 | master (vendored snapshot) | `ed25519/*.{h,c}` | zlib | Ed25519 |
| PicoSHA2 | master (vendored snapshot) | `picosha2/picosha2.h` | MIT | SHA-256 |
| doctest | 2.4.11 | `doctest/doctest.h` | MIT | tests |

`third_party/README.md` records exact upstream URLs and licenses. miniz is
compiled with `MINIZ_NO_TIME` (deterministic archives, FORMAT §1).

## Modules — `src/core/` → static lib `lexe_core`

| Module | Responsibility |
|---|---|
| `error.hpp` | exception hierarchy, exit-code mapping |
| `util.{hpp,cpp}` | hex/base64 encode-decode, file slurp/spit, recursive dir ops, `run_process(argv, …) -> {exit_code, stdout}` (CreateProcess / posix_spawn), RFC 3339 UTC timestamps (callers pass no clock; a single `now_utc_string()` lives here) |
| `paths.{hpp,cpp}` | `Paths::detect(env)` — resolves `LEXE_HOME` override, XDG dirs on Linux, `%LOCALAPPDATA%\lexe` on Windows; exposes `apps_dir()`, `data_dir()`, `cache_dir()`, `applications_dir()` (XDG), `icons_dir()`, `mime_dir()`, plus the Definitive Architecture's separate roots: `state_dir()` (diagnostics), `config_dir()` (user overrides), `launch_dir()`, `keys_dir()`, `errors_dir()`, `apps_config_dir()`, `integration_state_file()`, `mimeapps_file()` |
| `crypto.{hpp,cpp}` | SHA-256 of bytes/files (streamed); Ed25519 keygen from OS entropy, sign, verify; publisher-key string encode/decode (`ed25519:` + base64, FORMAT §4); key file read/write (0600 on POSIX) |
| `manifest.{hpp,cpp}` | `Manifest` struct mirroring FORMAT §5; `Manifest::parse(bytes)` with full validation; `to_json()` |
| `package.{hpp,cpp}` | `PackageReader` — open `.lexe`, path-safety checks (FORMAT §2), list entries, read entry bytes, extract `payload/` to a directory (zip-slip safe: every resolved destination must remain under the target root); `PackageWriter` — deterministic pack of a source tree (FORMAT §1), computes `hashes.json`, signs with a key file |
| `verify.{hpp,cpp}` | the FORMAT §6 pipeline plus the `payload-role` stage (Definitive Architecture §14.2): a native package's declared entrypoint must BE a runnable ELF for a declared architecture, and a launch reference must carry no payload. Returns `VerificationReport { stages: [{name, ok, detail}], ok() }` |
| `registry.{hpp,cpp}` | installed-app records under `<LEXE_HOME>/apps/` (FORMAT §9): `InstallationRecord` (installation.json) read/write, list installed apps, resolve current version (symlink or `current.txt` fallback), flip current, record/remove created files; the ONE canonical per-app path API (data/cache/runtime-temp/lock/lease/owner-marker), all id/version-validated |
| `lock.{hpp,cpp}` | OS-backed operation locking (WS9, docs/CONCURRENCY.md): `OperationLockManager` with an `flock(2)` backend + permissive non-POSIX backend + test fake; `AppLock`/`LaunchLease`/`GlobalRecoveryLock` scoped types; kernel-released on death (no timestamp staleness), ordered to avoid deadlock |
| `trust.{hpp,cpp}` | LOCAL trust-on-first-use model (WS3/WS4, docs/TRUST-MODEL.md): typed `SignatureState`/`PublisherKeyState`/`TrustDecision`; canonical key fingerprints; strict `TrustRecord` under `<home>/trust/<id>.json`; `TrustStore` evaluate/record/block/unblock/forget. Authenticity ≠ real-world identity |
| `presentation.{hpp,cpp}` | Frontend-neutral display model (WS10): `present_authenticity`/`present_permissions`/`present_isolation` produce the truthful strings the CLI and GTK both render (no "verified"/"trusted"/"safe"; first-seen is caution, per-permission enforcement, platform isolation summary) |
| `installer.{hpp,cpp}` | `install(package_path, opts)` → verify, extract to `versions/<v>/`, write records, desktop integration, data-owner marker; three-mode `uninstall(id, mode)`; `rollback(id)`; `garbage_collect(id, keep)` (lease-aware, conservative); `repair(id, package?)`; every mutation serialized by the per-app lock |
| `desktop.{hpp,cpp}` | Content generation for desktop artifacts: `lexe-<id>.desktop` text (Exec=`lexe run <id>`, never a payload path), MIME XML for file associations, icon mapping. Pure string functions, unit-testable on any platform |
| `integration.{hpp,cpp}` | DURABLE desktop integration (Definitive Architecture §14.1/§15.1). Integration is installed system state, not a side effect: `integration.json` enumerates every artifact .LEXE owns with its content hash; `verify()` names what is missing or modified; `repair()` re-establishes it FROM INSTALLED STATE with no package present. Owns the persistent `application/vnd.usha.lexe` handler (alias `application/x-lexe`) and the `mimeapps.list` default association — the piece that survives reboot |
| `launchref.{hpp,cpp}` | First-class `run.lexe` launch references (§15.1): a real, fully signed, fully verifiable `.lexe` with role `launch` and no payload, signed by a stable machine-local key (the "Locally Trusted" signer class) so the raw ELF never becomes the user-facing launch object |
| `execpolicy.{hpp,cpp}` | The execution resolver (§6/§7/§8): STRICT resolver for mission-critical software (Linux-native + host-ISA-native or stop), NORMAL resolver otherwise. Probes compatibility providers (FEX/Box64/qemu-user/Wine/Proton), builds chains incl. layered `proton+fex` forms. Pure with respect to package policy and user preference; host reality enters through a probed `ProviderSet` |
| `appconfig.{hpp,cpp}` | Per-application USER overrides under `<config>/apps/<id>.json` (§10). Can only narrow or reorder what the manifest permits — never extend it, and never reach past mission-critical policy |
| `diagnostics.{hpp,cpp}` | Structured `.lexe-error` records under `<state>/errors/<id>/` (§9): typed `FailureStage`, execution chain, host OS/ISA, runtime, exit code **or signal**, captured stream references, timestamp. Bounded per-stream and per-app with disclosed truncation |
| `desktop.{hpp,cpp}` | Pure content generation, and nothing else: `desktop_entry_text(manifest)` (Exec=`lexe run <id>`) and `mime_xml_text(manifest)`, computed identically on every platform and testable as strings anywhere. WRITING, registering, recording and repairing those documents belongs to `integration` alone — this module used to own a second implementation of that job, under a MIME type the runtime no longer claims |
| `hostbuild.{hpp,cpp}` | Host-ISA compilation of a portable package (§5/§7, FORMAT §5.8/§6.9). Holds all four properties in one place: approval gates the OPERATION (`CompileApproval`), the build runs unprivileged in the launcher's sandbox with the network denied unconditionally (`IsolationRequest::build`), the output is VERIFIED as a host-ISA ELF before use, and approval grants no privilege. `build_commands()` is pure — what a recipe will run is inspectable without running it. `BuildRecord` (`meta/<v>/build.json`) records the approval, the toolchain that actually ran and the product hashes, which is what lets a compiled entrypoint be tamper-checked and repaired exactly like an extracted one |
| `http.{hpp,cpp}` | `fetch_to_file(url, dest)` / `fetch_bytes(url)`: `https://`/`http://` via `curl` subprocess (`--fail -sS -L --max-time`), `file://` and plain paths via filesystem; no shell — argv arrays only |
| `updater.{hpp,cpp}` | fetch + verify `update.json` (+`.sig`), FORMAT §7 checks 1–7, download to cache, hand to installer as new version, retain previous; `check(id)` (dry) and `apply(id)`; `set_source(id, url)` |
| `launcher.{hpp,cpp}` | `run_application(paths, RunRequest) -> ExecutionReport` — the POST-INSTALL/RUN role of §7. Resolves current version, takes a shared launch lease (WS9 TOCTOU closure), enforces local trust, reads the EXECUTION POLICY and resolves the chain, confirms the runtime contract recorded at install (§16), validates entrypoint containment + hash integrity, applies the DECLARED launch presentation (§14.4 — a console app with no terminal is given one), launches THROUGH the isolation backend (WS7), records an execution report, and writes a structured error record on any failure |
| `versioncmp.{hpp,cpp}` | FORMAT §8 semver-lite total order |
| `elf.{hpp,cpp}` | Defensive, bounds-checked ELF metadata reader (DX3, docs/DEPENDENCY_ENGINE.md): class/arch/type, interpreter, `DT_NEEDED`/`SONAME`/`RPATH`/`RUNPATH`, `DT_VERNEED` version needs. Never runs `ldd`; never over-reads |
| `pe.{hpp,cpp}` | Defensive, bounds-checked PE/COFF metadata reader — the foreign-OS counterpart of `elf`. Exists for the `payload-role` stage: a package declaring `applicationType: "windows"` must be proven to carry a runnable Windows executable for a declared architecture, before install and without running anything. Machine, PE32/PE32+, subsystem, executable-image and DLL characteristics, and whether the image is CLR-managed. Never loads or maps the image; every read is bounds-checked |
| `depengine.{hpp,cpp}` | Automatic dependency resolution (DX3): recursive graph from a root binary, deterministic soname resolution, typed classification (host-interface / bundle / forbidden / unresolved / language-runtime hook), hashing, cycles, glibc-version aggregation |
| `runtime_profile.{hpp,cpp}` | Runtime-profile model (DX2, docs/RUNTIME_PROFILES.md): Core Portable / Forward Runtime / Native Capture + honest `assess_profile` (no silent portability claim) |
| `compat.{hpp,cpp}` | Compatibility analysis (DX4): per-runtime verdicts (UshaOS/Fedora/Debian/Ubuntu glibc baselines) + explained warnings |
| `tux32.{hpp,cpp}` | Tux32 Core 1 baseline (docs/TUX32.md): the compiled `tux32_core_1()` profile (frozen: `elf-dynamic`, x86_64, x86-64-v1, glibc ceiling 2.31), strict `profile.json` parse (pinned to the compiled profile by a test), and `verify_against_profile(deps, profile)` — a typed `Core1VerifyResult` over the dependency engine's graph (no second analysis path) |
| `buildreport.{hpp,cpp}` | Build/analysis summary (DX5): identity + deps + profile + compatibility + output, rendered to text and JSON. Shared by `lexe analyze` and the builder result screen. Attaches a typed Tux32 Core 1 verdict for the Core Portable profile |

Dependency order (implementation waves): `crypto`/`manifest`/`package`/`versioncmp`
→ `verify`/`registry`/`desktop` → `installer`/`updater`/`launcher` → CLI/GUI.
`util`, `paths`, `http`, `error` are foundation and land with the scaffold.

## CLI — `src/cli/` → binary `lexe`

`main.cpp` (dispatch, exit codes) + `commands.{hpp,cpp}`. Commands (SPEC §CLI +
developer tools):

```text
lexe install <file.lexe> [--yes] [--channel <c>]
lexe run <id> [-- args…]
lexe update <id> | --all [--check]
lexe remove <id> [--purge-data] [--yes]
lexe repair <id>
lexe info <file.lexe | id> [--json]
lexe analyze <binary | project-dir | payload-dir> [--json] [--profile <p>]
lexe sdk verify <binary | project-dir | payload-dir> [--json] [--profile tux32-core-1]
lexe verify <file.lexe> [--json]
lexe source set <id> <url>
lexe rollback <id>
lexe gc <id> [--keep <n>]
lexe trust show|block|unblock|forget <id>
lexe list [--json]
lexe keygen <keyfile.json>
lexe pack <source-dir> --manifest <lexe.json> --key <keyfile.json> -o <out.lexe>
lexe build <project-dir> [-o <out.lexe>] [--key <keyfile.json>]
lexe sign-update <update.json> --key <keyfile.json>
lexe integrate            # register .lexe MIME + desktop entry for the runtime
```

`lexe sdk verify` reports whether a target satisfies the [Tux32 Core 1](TUX32.md)
contract with a typed verdict and typed exit codes (0 conformant, 3 a
non-conformant verdict, 2 usage, 4 not found); it reuses the dependency engine —
there is no second analysis path.

`lexe install` without `--yes` prints the SPEC "primary screen" summary
(name, publisher, version, type/arch, source, permissions, size, update policy)
and asks for confirmation on stdin. Exit codes: `0` ok, `1` runtime error,
`2` usage, `3` verification failure, `4` not installed/found.

`lexe pack` source-dir convention: the directory's contents become `payload/`;
`--manifest` supplies `lexe.json`; optional `--icons <dir>`, `--metadata <dir>`.

## GUI — `src/gui/` → `lexe-ui` + `lexe-builder` (Linux only)

GTK 3 via the C API (`pkg-config gtk+-3.0`). Each GUI splits into a pure,
GTK-free presentation/validation layer (the "view model", unit-tested on every
host — including Windows — via `LEXE_GUI_VIEWMODEL_ONLY`) and the GTK wiring
(compiled only when CMake finds gtk+-3.0; never built on Windows). Both link
`lexe_core` directly and shell out to nothing. All user-supplied text embedded in
Pango markup is escaped (`g_markup_escape_text`); a headless
[smoke test](../scripts/gui-smoke.sh) asserts both GUIs render warning-clean,
including markup-hostile names/headings.

Accessibility rests on GTK 3's defaults, which the code preserves: every control
is a standard focusable widget (keyboard navigation, Tab order and focus rings
come for free), windows are resizable, long strings use wrapping labels rather
than truncation, and the system light/dark theme and font scaling are honored
because no colors or sizes are hard-coded over the theme. `lexe-builder` opens
with a first-run welcome screen (shown once).

* **`lexe-ui`** — the consumer and power-user frontend, and the registered
  `.lexe` handler. `--open <file.lexe>` verifies the artifact, reads its SIGNED
  role and dispatches: role `application` → the install flow (verification →
  primary screen → Install → progress → success with Launch); role `launch` →
  resolve the application id and launch it. `--app <id>` opens an application's
  page (".LEXE Menu"); `--errors <id>` opens its Error History (".LEXE Error").
  Single-instance: a second invocation focuses the existing window and
  navigates. Pages: Home, Install, Apps → App (Launch, Compatibility, Runtime,
  Permissions, Diagnostics, Error History, Uninstall), Settings.
* **`lexe-builder`** — a seven-step wizard (Source → Dependencies → Architecture →
  Installer → Signing → Output → Build) that turns a project folder into a signed
  `.lexe`. The Build step enforces the Core Portable / Tux32 Core 1 gate (a
  non-conformant closure disables Build); the result screen renders the build
  report including the Tux32 verdict.

## Tests — `tests/` → binary `lexe_tests` (doctest, run via CTest)

* **No automated test may put a window on screen.** The acceptance harness
  severs `WAYLAND_DISPLAY`/`DISPLAY` for its whole run, and `gui-smoke.sh`
  requires `xvfb-run` and unsets the real session before invoking it. A test
  that needs to render brings its own synthetic display; one that steals focus
  from the developer, or that only passes on a live desktop, is a broken test.
* Every test creates a temp dir and sets `LEXE_HOME` into it — no test touches
  the real home.
* `tests/helpers.hpp`: `make_keyfile()`, `make_test_app_tree()`,
  `make_test_package()` (uses `PackageWriter`), tamper helpers (flip a byte of a
  chosen entry via re-zip).
* Per-module unit tests: crypto (known-answer SHA-256 + Ed25519 RFC 8032 test
  vector, round-trips), manifest (accept/reject tables), package (determinism:
  pack twice → identical bytes; zip-slip corpus: `../evil`, absolute, backslash,
  drive letter, symlink entry, duplicate), verify (each pipeline stage fails on
  the matching tamper), versioncmp table, registry round-trip + current-link
  fallback, installer (install/uninstall/rollback/repair on a fake app),
  updater (file:// update source end-to-end: old→new, wrong key, wrong hash,
  downgrade, wrong id), launcher (runs a trivial payload, propagates exit code).
* `test_cli_e2e.cpp`: drives the built `lexe` binary as a subprocess through
  keygen → pack → verify → info → install --yes → list → run → source set +
  update (file://) → rollback → remove, asserting outputs and registry state.

## Build

* `CMakeLists.txt` (single top-level): `lexe_core` static lib, `lexe` CLI,
  `lexe_tests` (CTest-registered), `lexe-ui` behind
  `LEXE_BUILD_GUI` (auto: ON when gtk+-3.0 found).
* `CMakePresets.json`: `msvc` (Ninja, cl, dev-host) and `linux` (Ninja or Make).
* `scripts/build.cmd` — Windows one-shot: calls
  `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat`,
  prepends the Build Tools CMake/Ninja dirs to `PATH`
  (`…\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin`,
  `…\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja`), then
  `cmake --preset msvc && cmake --build --preset msvc && ctest --preset msvc`.
  Accepts an optional argument to use a different build dir (parallel agents use
  their own build dirs).
* `scripts/build.sh` — Linux equivalent.
* CI (`.github/workflows/ci.yml`): `ubuntu-latest` (GCC, `libgtk-3-dev` + `xvfb`,
  GUIs built, ctest, then the headless [GUI smoke test](../scripts/gui-smoke.sh)),
  `windows-latest` (MSVC, ctest), and a `portability` job that runs the
  cross-distribution [Tux32 Core 1 proof](../scripts/portability-demo.sh) under
  rootless podman.

## Security invariants (review checklist)

1. Zip-slip: no extracted file may resolve outside its target root (checked with
   `weakly_canonical` on the joined path); entry-name rules in FORMAT §2 enforced
   before any extraction.
2. Signature-before-parse discipline: hashes verified before payload bytes are
   trusted; `scripts/` never executed in 0.1.
3. No shell interpolation anywhere — `run_process` takes argv arrays.
4. Update key pinning: the installed publisher key is the trust anchor
   (FORMAT §7.1); downgrades refused (§7.7).
5. Key files 0600; private seeds never logged.
6. `lexe run` never executes anything outside the app's current version dir.

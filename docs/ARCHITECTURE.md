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
| `paths.{hpp,cpp}` | `Paths::detect(env)` — resolves `LEXE_HOME` override, XDG dirs on Linux, `%LOCALAPPDATA%\lexe` on Windows; exposes `apps_dir()`, `data_dir()`, `cache_dir()`, `applications_dir()` (XDG), `icons_dir()`, `mime_dir()` |
| `crypto.{hpp,cpp}` | SHA-256 of bytes/files (streamed); Ed25519 keygen from OS entropy, sign, verify; publisher-key string encode/decode (`ed25519:` + base64, FORMAT §4); key file read/write (0600 on POSIX) |
| `manifest.{hpp,cpp}` | `Manifest` struct mirroring FORMAT §5; `Manifest::parse(bytes)` with full validation; `to_json()` |
| `package.{hpp,cpp}` | `PackageReader` — open `.lexe`, path-safety checks (FORMAT §2), list entries, read entry bytes, extract `payload/` to a directory (zip-slip safe: every resolved destination must remain under the target root); `PackageWriter` — deterministic pack of a source tree (FORMAT §1), computes `hashes.json`, signs with a key file |
| `verify.{hpp,cpp}` | the FORMAT §6 pipeline; returns `VerificationReport { stages: [{name, ok, detail}], ok() }` |
| `registry.{hpp,cpp}` | installed-app records under `<LEXE_HOME>/apps/` (FORMAT §9): `InstallationRecord` (installation.json) read/write, list installed apps, resolve current version (symlink or `current.txt` fallback), flip current, record/remove created files |
| `installer.{hpp,cpp}` | `install(package_path, opts)` → verify, extract to `versions/<v>/`, write records, desktop integration; `uninstall(id, purge_data)`; `rollback(id)`; `repair(id, package?)` — re-verify hashes of installed files against manifest copy, re-extract on mismatch |
| `desktop.{hpp,cpp}` | Linux: write `lexe-<id>.desktop` (Exec=`lexe run <id>`), install icons to hicolor, MIME XML, best-effort `update-desktop-database`/`update-mime-database`; also `integrate_runtime()` used by packaging to register `application/x-lexe` for the runtime itself. Windows: every function is a recorded no-op (returns `skipped`) so core tests run anywhere |
| `http.{hpp,cpp}` | `fetch_to_file(url, dest)` / `fetch_bytes(url)`: `https://`/`http://` via `curl` subprocess (`--fail -sS -L --max-time`), `file://` and plain paths via filesystem; no shell — argv arrays only |
| `updater.{hpp,cpp}` | fetch + verify `update.json` (+`.sig`), FORMAT §7 checks 1–7, download to cache, hand to installer as new version, retain previous; `check(id)` (dry) and `apply(id)`; `set_source(id, url)` |
| `launcher.{hpp,cpp}` | `run(id, argv)` — resolve current version, ensure entrypoint exists & (POSIX) is executable, spawn with cwd = version dir, wait, record last-run/exit in installation.json, propagate exit code |
| `versioncmp.{hpp,cpp}` | FORMAT §8 semver-lite total order |

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
lexe verify <file.lexe> [--json]
lexe source set <id> <url>
lexe rollback <id>
lexe list [--json]
lexe keygen <keyfile.json>
lexe pack <source-dir> --manifest <lexe.json> --key <keyfile.json> -o <out.lexe>
lexe integrate            # register .lexe MIME + desktop entry for the runtime
```

`lexe install` without `--yes` prints the SPEC "primary screen" summary
(name, publisher, version, type/arch, source, permissions, size, update policy)
and asks for confirmation on stdin. Exit codes: `0` ok, `1` runtime error,
`2` usage, `3` verification failure, `4` not installed/found.

`lexe pack` source-dir convention: the directory's contents become `payload/`;
`--manifest` supplies `lexe.json`; optional `--icons <dir>`, `--metadata <dir>`.

## GUI — `src/gui/` → binary `lexe-installer` (Linux only)

GTK 3 via the C API (`pkg-config gtk+-3.0`), single source file. Flow per SPEC
§User Interface: open with a `.lexe` argument → run verification → primary screen
(app, publisher, version, source, type/arch, permissions, size, update policy,
verification status) → Install / Advanced (install summary of directories used;
channel selector) → progress → success screen with Launch button (`lexe run`).
Built only when CMake finds gtk+-3.0; never built on Windows. The GUI shells out
to nothing — it links `lexe_core` directly.

## Tests — `tests/` → binary `lexe_tests` (doctest, run via CTest)

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
  `lexe_tests` (CTest-registered), `lexe-installer` behind
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
* CI (`.github/workflows/ci.yml`): matrix — `ubuntu-latest` (GCC,
  `libgtk-3-dev` installed, GUI built, ctest) and `windows-latest` (MSVC, ctest).

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

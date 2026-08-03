# Software Bill of Materials — `.lexe` 0.1.0-alpha.1

> **Informative.** A human-readable inventory of third-party components, for the
> Alpha release. It reflects the source tree; the source-only Alpha ships no
> prebuilt binaries. `third_party/README.md` records exact upstream URLs.

## Vendored (compiled into the runtime, under `third_party/`)

Pinned, never modified (compile-time configuration only, e.g. `MINIZ_NO_TIME`).

| Component | Version | License | Purpose |
|---|---|---|---|
| nlohmann/json | 3.11.3 | MIT | JSON parsing/serialization |
| miniz | 3.0.2 | MIT | ZIP read/write (deterministic) |
| orlp/ed25519 | snapshot (2026-07-13) | zlib | Ed25519 fallback provider + test key derivation |
| PicoSHA2 | snapshot (2026-07-13) | MIT | SHA-256 |
| doctest | 2.4.11 | MIT | unit tests (test binary only, not shipped in a package) |

## Runtime / system dependencies (Linux; found at build/run time, not vendored)

| Component | License | Role | Required? |
|---|---|---|---|
| glibc (≥ 2.31) | LGPL-2.1-or-later (with linking exception) | host C runtime / loader | yes (host) |
| libsodium | ISC | preferred Ed25519 provider (via `pkg-config`) | optional — vendored `orlp/ed25519` is the fallback |
| GTK 3 | LGPL-2.1-or-later | the Builder and Installer GUIs | for the GUIs |
| bubblewrap (`bwrap`) | LGPL-2.1-or-later | the runtime isolation sandbox (invoked as a subprocess) | to run apps under isolation |
| curl | curl license (MIT/X-derived) | `https://` fetch for updates (invoked as a subprocess) | for network update sources |

## Build-only tools (not shipped)

CMake ≥ 3.22, Ninja, `pkg-config`, and a C++20 compiler (GCC/Clang or MSVC). See
the [Quick install](../README.md#quick-install) for per-distribution packages.

## Notes

- **License posture.** Vendored components are permissive (MIT/zlib). System
  dependencies are permissive or LGPL, used via dynamic linking or as
  subprocesses, so they do not impose copyleft on the first-party source. This is
  compatible with the project's proprietary-then-GPL plan (see [../LICENSE](../LICENSE)).
- **Machine-readable SBOM.** An SPDX or CycloneDX document can be generated from
  this inventory in a later release; until a release workflow produces one, this
  human-readable table is the authoritative bill of materials.

<h1 align="center">.lexe</h1>

<p align="center"><strong>A Linux application platform with a Windows-simple experience and Linux-native security.</strong></p>

<p align="center">
  <a href="https://github.com/EeshGarg/.lexe/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/EeshGarg/.lexe/actions/workflows/ci.yml/badge.svg" /></a>
  <img alt="C++20" src="https://img.shields.io/badge/C%2B%2B-20-00599c" />
  <img alt="Platforms" src="https://img.shields.io/badge/build-Linux%20(GCC)%20%C2%B7%20Windows%20(MSVC)-333" />
  <img alt="Status" src="https://img.shields.io/badge/status-approaching%20alpha-b4622a" />
</p>

---

> **One application. One package.**
> **Build it once. Package it once. Run it on every conforming runtime.**

`.lexe` brings the thing Linux never quite had: **download a program, double-click
it, and install it** — with the trust, sandboxing, and honesty a modern platform
should provide. No package manager to fight, no repository to add, no Wine prefix
to configure, no desktop file to hand-write.

For **users**, a `.lexe` file is a self-describing application: double-click it and
the Runtime verifies its signature and payload, shows exactly what it is and what
it can do, and installs it into your home directory. For **developers**, the
Builder turns a compiled folder into a signed `.lexe` — automatically discovering
dependencies, reporting compatibility, and never asking you to understand the
format's internals.

## What `.lexe` is

`.lexe` is a **platform**, not just a file format. It has five parts:

| Part | What it is |
|---|---|
| **Package format** | A signed, deterministic ZIP container (`FORMAT-0.1`): a JSON manifest, the application payload, per-file SHA-256 hashes, and Ed25519 signatures. |
| **Runtime** | `lexe` — verifies, installs, launches (inside a sandbox), updates, rolls back, and removes applications entirely in userspace. |
| **Builder** | `lexe-builder` (a graphical wizard) and `lexe build` (CLI) — turn a compiled folder into a signed package. |
| **Dependency engine** | Reads ELF metadata directly (never `ldd`) to discover, classify, and hash an application's shared-library dependencies. |
| **Compatibility analysis** | Rates a package against known runtime baselines and explains, in plain words, where it will and will not run. |

Developers interact with the **Builder**. Users interact with **`.lexe` packages**.
The complexity lives inside the platform, not inside either person.

## Quick install

The reference runtime installs per-user (no root), under your home directory:

```sh
# Build the runtime + GUIs
cmake -S . -B build -G Ninja -DLEXE_BUILD_GUI=ON
cmake --build build

# Install for the current user (idempotent — safe to re-run)
./packaging/install.sh
```

**Inspect first (recommended).** The installer is a short, per-user shell script
that touches only `$HOME` — read it before running. Nothing here ever pipes a
remote script into a shell:

```sh
less packaging/install.sh   # review exactly what it does
./packaging/install.sh      # then run it
```

**Uninstall:**

```sh
./packaging/uninstall.sh
```

> **Removing the runtime does _not_ remove anything you installed or created.**
> Installed applications, their data, and local publisher-trust records are left
> in place on purpose. To remove an application and its data deliberately, use the
> runtime *before* uninstalling: `lexe remove <app-id> --purge-data`.

## Quick start

**Package an app graphically** — launch the Builder, point it at your compiled
folder, and follow the seven steps (Source → Dependencies → Architecture →
Installer → Signing → Output → Build):

```sh
lexe-builder
```

**Inspect an app's dependencies and compatibility** — headless, no build required:

```sh
lexe analyze ./my-app            # human-readable report
lexe analyze ./my-app --json     # structured output
```

**Build a signed package from a project folder** (`lexe.json` + `payload/`):

```sh
lexe build ./my-project -o my-app.lexe
```

Then a user just runs `lexe install my-app.lexe` (or double-clicks it).
`lexe help` lists the full command surface.

## Platform capabilities

Everything below is **implemented and tested** today.

- **Runtime** — verify → install → launch → update → roll back → remove, all in
  userspace; transactional installs with crash recovery; atomic version
  activation; typed, race-safe concurrency.
- **Builder** — a graphical seven-step wizard and a CLI; automatic source
  detection; a build report with dependency, profile, and compatibility summaries.
- **Security** — Ed25519 signature verification over exact bytes before any byte
  is trusted; a strict, hardened package parser (zip-slip, decompression, and
  malformed-input defenses); a frozen permission vocabulary with an explicit,
  separate consent gate; a typed **local trust-on-first-use** model (signing-key
  continuity, changed-key refusal, local block/unblock, honest "not identity"
  language).
- **Runtime isolation** *(Linux)* — every application runs inside a bubblewrap
  sandbox: read-only application image, private data/cache/temp, sanitized
  environment, and network denied unless the `network` permission is granted. The
  launcher fails closed — it never runs an app unconfined when isolation is
  required.
- **Dependency analysis** — direct ELF reading; recursive, deterministic
  resolution; typed classification (host-interface / bundle / forbidden /
  unresolved); cycle handling; hashing; glibc-version aggregation.
- **Compatibility** — per-runtime verdicts (UshaOS Core / Fedora / Debian /
  Ubuntu baselines) with explained warnings (newer glibc symbols, GPU driver
  passthrough, unresolved or unusually-bundled libraries).
- **Runtime profiles** — Core Portable (default), Forward Runtime, and Native
  Capture, each with an honest portability assessment that never overstates.
- **Installation & desktop integration** — per-user install, `.desktop` entries,
  hicolor icons, and MIME registration so a double-click opens the graphical
  installer.
- **Developer experience** — `lexe analyze`, the Builder wizard, a shared truthful
  presentation model used identically by the CLI and the GUI.

## Architecture

The developer pipeline — a compiled application becomes a signed package:

```
        Compiled application
                 │
                 ▼
          ELF analysis                core/elf — reads ELF metadata directly
                 │
                 ▼
      Dependency resolution           core/depengine — graph + classification
                 │
          ┌──────┴───────┐
          ▼              ▼
     Runtime         Compatibility     core/runtime_profile · core/compat
     profiles          analysis
          └──────┬───────┘
                 ▼
           Build report               core/buildreport — text + JSON
                 │
                 ▼
             Builder                   lexe analyze · lexe-builder
                 │
                 ▼
        Signed .lexe package
```

At runtime, the user side is: **verify → consent → transactional install →
sandboxed launch → update / roll back / remove.** See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the module map.

## Repository layout

```
src/core/      the platform: package, crypto, verify, manifest, installer,
               launcher, isolation, lock, trust, elf, depengine, compat, …
src/cli/       the `lexe` command-line interface
src/gui/       the GTK 3 apps: lexe-installer and lexe-builder (Linux)
tests/         doctest unit + integration tests (+ tests/integration/*.sh)
docs/          format, architecture, security, and developer specifications
packaging/     per-user install.sh / uninstall.sh + desktop/MIME files
scripts/       one-shot build helpers (build.sh / build.cmd)
third_party/   vendored dependencies (miniz, PicoSHA2, orlp/ed25519, doctest)
```

New here? Start with [CONTRIBUTING.md](CONTRIBUTING.md), then
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Documentation

Full index with reading order: **[docs/README.md](docs/README.md)**.

| Document | What it covers |
|---|---|
| [SPEC.md](SPEC.md) | The overall specification and the 0.1 → 0.3 vision. |
| [docs/FORMAT-0.1.md](docs/FORMAT-0.1.md) | The `.lexe` package format (structure, manifest, hashes, signatures, storage layout). |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Module map, build, conventions, and the test matrix. |
| [docs/HARDENING.md](docs/HARDENING.md) | The security hardening gates (A–H) and the proven-invariants table. |
| [docs/ISOLATION.md](docs/ISOLATION.md) | The Linux bubblewrap runtime-isolation design. |
| [docs/CONCURRENCY.md](docs/CONCURRENCY.md) | OS-backed locking, launch leases, and TOCTOU closure. |
| [docs/TRUST.md](docs/TRUST.md) | The trust & signing tiers (design; Tier 1 implemented). |
| [docs/TRUST-MODEL.md](docs/TRUST-MODEL.md) | The implemented local trust-on-first-use model. |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Adversaries, mitigations, and explicit non-guarantees. |
| [docs/DEPENDENCY_ENGINE.md](docs/DEPENDENCY_ENGINE.md) | The ELF reader and dependency-resolution engine. |
| [docs/RUNTIME_PROFILES.md](docs/RUNTIME_PROFILES.md) | The runtime-profile model and honest assessment. |
| [docs/TUX32.md](docs/TUX32.md) | The future conforming-runtime baseline (placeholder). |

## Project status

**Milestone:** Developer Experience — **complete.**
**Stage:** approaching **Alpha.**

The reference Runtime is written in modern C++ (C++20) and builds on Linux (GCC,
with the GTK GUIs) and Windows (MSVC). The full suite is **green on both
platforms** — 386 tests on Linux and 370 on Windows, over 5,800 assertions,
exercised in CI on every push.

**Implemented**
- Package format, deterministic packing, strict hardened parsing.
- Ed25519 signing/verification; transactional install; crash recovery; rollback.
- Frozen permission vocabulary + separate consent gate.
- Linux runtime isolation (bubblewrap); fail-closed launcher.
- Application lifecycle (data / cache / temp, three uninstall modes, lease-aware GC).
- Concurrency locking, launch leases, TOCTOU closure.
- Typed local trust-on-first-use model + truthful CLI/GUI presentation.
- Dependency engine, compatibility analysis, runtime profiles, build report.
- Graphical Builder wizard and `lexe analyze`.

**In progress**
- Repository/documentation polish for Alpha readiness (this milestone).

**Planned (not yet implemented)**
- The Tux32 conforming-runtime baseline specification.
- An SDK / sysroot for building broadly-portable binaries.
- Multi-architecture (multi-ISA) packaging with per-architecture payloads.
- Language-runtime dependency extensions (Python, Java, Node, …).
- The repository (Tier 2) and root-accreditation (Tier 3) trust tiers.

The reference runtime's isolation is **Linux-only**; the Windows build is a
development host with no runtime containment (reported truthfully, never implied
otherwise). On Windows the Ed25519 provider is a vendored fallback rather than
libsodium. Publisher trust is **local** (trust-on-first-use); a valid signature
proves consistency with a key, not a publisher's real-world identity.

## Alpha roadmap

**Completed**
- Platform foundations — format, crypto, install/lifecycle, isolation, concurrency, trust.
- Developer experience — dependency engine, compatibility, profiles, build report, Builder.

**Next (toward Alpha)**
- Formalize the **Tux32** runtime-profile / baseline specification.
- Design the **SDK / sysroot** architecture for portable builds.
- Lay the groundwork for **multi-ISA packaging** (universal + per-arch payloads).

**Future**
- Language-runtime dependency extensions.
- A **UshaOS** reference conforming runtime.
- A conformance ecosystem (test suite + certification for third-party runtimes).

## Philosophy

- **A Windows-like application experience** — download, double-click, install, launch.
- **Linux-native security** — signatures, sandboxing, explicit permissions, honest trust.
- **An open runtime** — a language-neutral specification any conforming runtime can implement.
- **Cross-distribution portability** — build once, package once, run on every conforming runtime.

## License

**Proprietary during the pre-release phase**, while the signing and trust
infrastructure is established — see [LICENSE](LICENSE). The stated intent is to
relicense under the **GPL** once that foundation is in place. The specification
itself is language-neutral, so conforming third-party runtimes may be implemented
independently. Revisions published before the relicense remain under their
original Apache-2.0 terms.

## Contributing

Contributions are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers building,
running the tests, and finding your way around the code. In short:

```sh
./scripts/build.sh          # configure + build + run the full test suite
```

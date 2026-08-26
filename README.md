<h1 align="center">.lexe</h1>

<p align="center"><strong>Download an app, double-click it, install it — on Linux, with real signatures and sandboxing.</strong></p>

<p align="center">
  <a href="https://github.com/EeshGarg/.lexe/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/EeshGarg/.lexe/actions/workflows/ci.yml/badge.svg" /></a>
  <img alt="C++20" src="https://img.shields.io/badge/C%2B%2B-20-00599c" />
  <img alt="Runtime" src="https://img.shields.io/badge/runtime-Linux%20x86--64-333" />
  <img alt="Status" src="https://img.shields.io/badge/status-Developer%20Alpha-b4622a" />
</p>

<p align="center">
  <img src="docs/images/installer-light.png" alt="The .lexe Installer showing an application's publisher, signing-key fingerprint, requested permissions and the isolation applied, before anything is written" width="420" />
</p>

<p align="center"><em>What a user sees before anything is installed: who signed it, what it may do, and what the sandbox will enforce.</em></p>

---

## What is `.lexe`?

`.lexe` is a **Linux application platform**: a signed package format plus a
userspace runtime that verifies, sandboxes, installs, and launches desktop
applications.

**The problem.** Installing a Linux desktop app can still mean adding a
repository, fetching an AppImage, configuring Flatpak, extracting an archive,
running an install script, and hand-writing a desktop shortcut — each with its
own trust and update story. **The idea.** A `.lexe` file is one self-describing,
signed application. Double-click it and the **Runtime** shows exactly what it is,
who signed it, and what it can do, then installs it into your home directory —
inside a sandbox, no root required.

**Why care.** Developers get *build once, package once, and know where it runs*;
users get a Windows-simple experience with Linux-native security — signatures
checked before any byte is trusted, a real bubblewrap sandbox, explicit
permissions, and honest trust language that never overstates.

> This is a **Developer Alpha**. It is a complete platform to *use* today; it is
> not production-ready. See [Project status](#project-status).

## What does it do?

For a **user**, installing an app is a straight line — and every step is visible:

```
Download  →  Double-click  →  Inspect  →  Verify  →  Install  →  Launch
   .lexe       (or CLI)       what it is   signature   per-user    sandboxed
                              & permits    & hashes    no root
```

For a **developer**, shipping an app is just as short:

```
Compile  →  Build .lexe  →  Distribute  →  Runs on conforming runtimes
  your app   sign + verify   any channel    (Tux32 Core 1)
```

## Platform overview

| Component | What it is |
|---|---|
| **`.lexe` Package Format** | A signed, deterministic ZIP container ([FORMAT-0.1](docs/FORMAT-0.1.md)): a JSON manifest, the application payload, per-file SHA-256 hashes, and Ed25519 signatures. Self-describing and tamper-evident. |
| **Runtime** | `lexe` — verifies, installs, launches (inside a sandbox), updates, rolls back, and removes applications, entirely in userspace. It fails closed: it never runs an app unconfined when isolation is required. |
| **Builder** | `lexe-builder` (a graphical wizard) and `lexe build` (CLI) turn a compiled folder into a signed package — discovering dependencies and reporting compatibility so you never touch the format's internals. |
| **Installer** | `lexe-installer` (the GUI that opens on a double-click) and `lexe install` (CLI) verify a package and present its identity, permissions, and isolation before anything is written. |
| **Tux32 Core 1** | The frozen, versioned **portability contract**: a dynamically linked x86-64 ELF within a glibc symbol ceiling of 2.31. A package that passes `lexe sdk verify` runs unchanged on any conforming host. See [TUX32.md](docs/TUX32.md). |

## Quick install

The Runtime installs **per-user, no root**, under your home directory. It is
built from source today (no distribution packages yet — see
[Supported platforms](#supported-platforms)).

**1. Install the build prerequisites** (a C++20 compiler, CMake ≥ 3.22, Ninja,
pkg-config, GTK 3, libsodium) **and bubblewrap** (the runtime sandbox):

<table>
<tr><th>Debian / Ubuntu</th><td><code>sudo apt install build-essential cmake ninja-build pkg-config libgtk-3-dev libsodium-dev bubblewrap</code></td></tr>
<tr><th>Fedora</th><td><code>sudo dnf install gcc-c++ cmake ninja-build pkgconf-pkg-config gtk3-devel libsodium-devel bubblewrap</code></td></tr>
<tr><th>Arch Linux</th><td><code>sudo pacman -S --needed base-devel cmake ninja pkgconf gtk3 libsodium bubblewrap</code></td></tr>
</table>

**2. Clone, build, and install:**

```sh
git clone https://github.com/EeshGarg/.lexe.git && cd .lexe
cmake -S . -B build -G Ninja -DLEXE_BUILD_GUI=ON
cmake --build build
./packaging/install.sh          # per-user; idempotent — safe to re-run
```

**Inspect first (recommended).** `install.sh` is a short shell script that only
touches `$HOME`. Nothing here ever pipes a remote script into a shell — read it,
then run it:

```sh
less packaging/install.sh
./packaging/install.sh
```

**Uninstall the Runtime:**

```sh
./packaging/uninstall.sh
```

> **Removing the Runtime does _not_ remove:** the applications you installed,
> their data, or your local trust records. That is always deliberate — to remove
> an app and its data, use the Runtime *first*: `lexe remove <app-id> --purge-data`.

## Quick start

Under two minutes, from a compiled folder to a launched app:

```sh
lexe-builder                       # package a folder graphically (wizard)

lexe analyze ./my-app              # dependencies + compatibility (no build)
lexe sdk verify ./my-app           # Tux32 Core 1 verdict — exit 0 / 3
lexe build ./my-project -o my-app.lexe --key key.json

lexe inspect my-app.lexe           # full package view before you trust it
lexe install my-app.lexe --yes     # verify + install, per-user
lexe run com.example.my-app        # launch inside the sandbox

lexe apps                          # what's installed: version, disk, trust
lexe config                        # view or change preferences
```

`lexe help` groups the full command surface, `lexe <command> --help` explains one,
and bash/zsh completion comes from `lexe completion`. See the full
**[tutorial](docs/TUTORIAL.md)**.

**What verification actually prints** — every stage, named, with what it checked:

```console
$ lexe verify hello.lexe
Verifying hello.lexe
  [ ok ] structure          archive OK: 5 entries, §2 path rules hold, required entries present
  [ ok ] manifest           lexe.json is a valid 0.1 manifest: org.lexe.examples.cli-tool 1.0.0
  [ ok ] key                publisher.publicKey decodes to a 32-byte Ed25519 key (Lexe Examples)
  [ ok ] manifest-signature signatures/manifest.sig verifies over the stored lexe.json bytes (476 bytes)
  [ ok ] payload-signature  signatures/payload.sig verifies over the stored metadata/hashes.json bytes (140 bytes)
  [ ok ] hashes             all 1 covered entries present, coverage is exact (both directions), every SHA-256 digest matches
verification: OK (signature valid, Ed25519)
signing key fingerprint: 4F46 E2C5 0A81 5180 983E EBEA 4CC7 BCF9 F52E 926F A6D9 A74A 6BBD 4C39 F75E 7350
note: this proves package integrity + signature, NOT the publisher's real-world identity.
```

That last line is the house style: the runtime states what a signature proves and
declines to imply more.

## Screenshots

Real windows, captured headlessly from the build in this repository — the same
[GUI smoke test](scripts/gui-smoke.sh) that takes them fails the build on any GTK
warning.

<table>
<tr>
<td width="50%" valign="top">
<img src="docs/images/installer-light.png" alt="Installer, light theme" />
<p><strong>The Installer.</strong> Authenticity and local trust, the signing-key
fingerprint in full, each permission with its <em>truthful</em> enforcement state
on this platform, install scope and size, and what the sandbox does — all before
the Install button does anything.</p>
</td>
<td width="50%" valign="top">
<img src="docs/images/installer-dark.png" alt="Installer, dark theme" />
<p><strong>Light and dark.</strong> The theme follows your desktop by default and
is switchable in place; the preference is the same one <code>lexe config set
theme</code> writes, not a second store.</p>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<img src="docs/images/builder-wizard.png" alt="Builder wizard, Source step" />
<p><strong>The Builder.</strong> A seven-step wizard from a folder of compiled
files to a signed package. Drag a folder onto the window, or choose one; the
executable, architecture, icons and full dependency graph are detected for you.</p>
</td>
<td width="50%" valign="top">
<img src="docs/images/installer-drop.png" alt="Installer drop zone" />
<p><strong>Drag and drop.</strong> Opened with no argument, the Installer waits
for a package. However one arrives, it goes through the same verification — a
drop is not a shortcut past any check.</p>
</td>
</tr>
</table>

## Platform capabilities

Only implemented, tested capabilities are listed.

| Area | What works today |
|---|---|
| **Runtime** | Verify → install → launch → update → roll back → remove, all in userspace; transactional installs with crash recovery; atomic version activation; typed, race-safe concurrency (locks, launch leases, TOCTOU closure). |
| **Security** | Ed25519 verification over exact bytes before any byte is trusted; a strict, hardened parser (zip-slip, decompression, malformed-input defenses); a frozen permission vocabulary with a separate consent gate; a typed local trust-on-first-use model (key continuity, changed-key refusal, block/unblock). |
| **Portability** | The frozen **Tux32 Core 1** baseline; `lexe sdk verify` (typed verdict + exit codes) reusing the one dependency engine; a Builder that hard-gates Core Portable on it; a minimal build-in-sysroot SDK; an end-to-end cross-distribution proof in CI. |
| **Developer experience** | `lexe analyze`, `lexe build`, `lexe inspect`; the Builder wizard with automatic source detection (off the UI thread) and a dependency / profile / compatibility build report; drag a folder onto the window; a native folder picker; grouped help, bash + zsh completion, JSON everywhere. |
| **Consumer experience** | A double-click installer that explains itself, or drag a package onto it; light/dark that follows your desktop and is switchable in place; `lexe apps`, `lexe config`; errors that say what happened, why, and how to fix it. |
| **Lifecycle** | Per-app data / cache / temp; three uninstall modes; lease-aware GC; updates that require fresh consent to expand permissions; rollback. |
| **Isolation** *(Linux)* | Every app runs in a bubblewrap sandbox: read-only image, private data/cache/temp, sanitized environment, network denied unless the `network` permission is granted. The launcher **fails closed**. |
| **Builder & install** | GTK Builder + CLI; per-user install, `.desktop` entries, hicolor icons, and MIME registration so a double-click opens the Installer. |

## Architecture

A compiled application becomes a signed package, then a running app:

```
   Compiled application
            │
            ▼
      ELF analysis            core/elf — reads ELF metadata directly (never ldd)
            │
            ▼
    Dependency graph          core/depengine — resolution + typed classification
            │
     ┌──────┴───────┐
     ▼              ▼
 Compatibility   Runtime       core/compat · core/runtime_profile
  analysis       Profile
     └──────┬───────┘
            ▼
    Tux32 Core 1 verify        core/tux32 — typed conformance verdict
            │                   (Core Portable; reuses the graph above)
            ▼
      Build report             core/buildreport — text + JSON
            │
            ▼
        Builder                lexe build · lexe-builder
            │
            ▼
    Signed .lexe package
            │
            ▼
       Installer               verify → consent → transactional install
            │
            ▼
        Runtime                sandboxed launch → update / roll back / remove
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the module map and build.

## Supported platforms

Honest status. "Tested" means exercised in CI or by the cross-distribution proof;
"Builds" means the source build is verified but the runtime is not yet CI-tested.

**Runtime host** (install + sandboxed launch), x86-64:

| Distribution | Status | Notes |
|---|---|---|
| Ubuntu 22.04+ | **Tested** | Full test suite (incl. the sandboxed launcher) runs in CI on `ubuntu-latest`. |
| Debian 12+ | **Tested** | The cross-distribution proof installs and launches a package on Debian 12. |
| Fedora | **Builds** (experimental) | Source build verified; runtime expected but not yet CI-tested. |
| Arch Linux | **Builds** (experimental) | Source build verified; runtime expected but not yet CI-tested. |

**Builder / development host:**

| Host | Status | Notes |
|---|---|---|
| Linux (GCC) | **Tested** | Full build including the GTK Builder and Installer. |
| Windows (MSVC) | **Development host** | The portable core is built and unit-tested; there is **no runtime isolation** on Windows. |

**Tux32 Core 1 target:** dynamically linked **x86-64 ELF** — **Supported**.
aarch64 / RISC-V / multi-ISA — **Future** (see [MULTI_ARCH.md](docs/MULTI_ARCH.md)).

> Development happens on Linux (GCC) and Windows (MSVC), with CI on Ubuntu; Linux
> is the reference runtime host. Fedora and Arch build cleanly but are not yet
> part of the tested runtime matrix — the project does not claim what it has not
> verified.

## Documentation

Full index with reading order: **[docs/README.md](docs/README.md)**.

**Getting started**

| Document | What it covers |
|---|---|
| [docs/TUTORIAL.md](docs/TUTORIAL.md) | One walkthrough: analyze → verify → build → inspect → install → launch → remove. |
| [docs/FAQ.md](docs/FAQ.md) | Short, honest answers to common questions. |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common runtime issues and developer mistakes, with fixes. |
| [examples/](examples/) | Small, buildable sample apps (cli-tool, bundled-library). |

**Architecture & specifications**

| Document | What it covers |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Module map, build system, GUIs, and the test matrix. |
| [SPEC.md](SPEC.md) | The product specification and the 0.1 → 0.3 vision. |
| [docs/FORMAT-0.1.md](docs/FORMAT-0.1.md) | The `.lexe` container: structure, manifest, hashes, signatures, storage layout. |

**Security**

| Document | What it covers |
|---|---|
| [SECURITY.md](SECURITY.md) | How to report a vulnerability privately, what is in scope, and the documented non-guarantees. |
| [docs/HARDENING.md](docs/HARDENING.md) | The hardening gates (A–H) and the proven-invariants table. |
| [docs/ISOLATION.md](docs/ISOLATION.md) | The Linux bubblewrap runtime-isolation design. |
| [docs/CONCURRENCY.md](docs/CONCURRENCY.md) | OS-backed locking, launch leases, and the TOCTOU closure. |
| [docs/TRUST-MODEL.md](docs/TRUST-MODEL.md) | The implemented local trust-on-first-use model. |
| [docs/TRUST.md](docs/TRUST.md) | The three trust & signing tiers (Tier 1 implemented). |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Adversaries, mitigations, and explicit non-guarantees. |

**Portability & developer docs**

| Document | What it covers |
|---|---|
| [docs/TUX32.md](docs/TUX32.md) | The Tux32 Core 1 baseline: the contract, the verifier, and the proof. |
| [docs/SDK.md](docs/SDK.md) | The minimal Core 1 SDK (`lexe sdk verify` + `sdk/tux32-core-1/`). |
| [docs/DEPENDENCY_ENGINE.md](docs/DEPENDENCY_ENGINE.md) | The direct-ELF reader and dependency-resolution engine. |
| [docs/RUNTIME_PROFILES.md](docs/RUNTIME_PROFILES.md) | The Runtime Profile model and Core Portable enforcement. |
| [docs/IMPLEMENTERS.md](docs/IMPLEMENTERS.md) | A reading path for implementing `.lexe` in another language. |

**Status, contributing & history**

| Document | What it covers |
|---|---|
| [docs/ALPHA.md](docs/ALPHA.md) | The Alpha support contract, known limitations, and the evidence checklist. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Building, testing, and finding your way around the code. |
| [CHANGELOG.md](CHANGELOG.md) | Release history. |

## FAQ

**Why not AppImage / Flatpak / Snap?** Those solve real problems, but each mixes
bundling, sandboxing, and distribution differently. `.lexe` is a single signed
file with a self-describing manifest, a fail-closed sandbox, explicit
permissions, and a *verifiable* portability contract (Tux32 Core 1) — trust and
"where does this run" are first-class, not afterthoughts.

**Why Tux32?** "Runs everywhere" is only meaningful if "everywhere" is defined.
Tux32 Core 1 is that definition, frozen and checkable, so the build host can't
silently become the compatibility target. See [TUX32.md](docs/TUX32.md).

**Does this replace my package manager?** No. It is a userspace, per-user way to
install desktop applications alongside your distribution's packages — not a
system package manager.

**Can I publish proprietary software?** Yes. The format and Runtime never require
source; you sign with your own key. (The `.lexe` *project* is under a pre-release
license — see [License](#license) — but the apps you package can be any license.)

**How does trust work?** Local **trust-on-first-use**: a valid signature proves a
package is consistent with a signing *key*, not a real-world identity. The first
time a key is seen it is "first-seen"; thereafter the Runtime warns if the key for
an App ID changes. There is no global revocation in this Alpha.

**Can I build on Fedora and run on Debian?** Yes — that is exactly what Tux32
Core 1 is for. Build to the Core 1 contract (in a sysroot), `lexe sdk verify` it,
and the same signed package runs on any conforming host. The CI proof builds on
one distribution and launches on an older, different one.

More in [docs/FAQ.md](docs/FAQ.md).

## Project status

**Milestone:** Developer Alpha. The full suite is green on both platforms — **494
tests on Linux, 474 on Windows (~6,700 assertions)** — plus a headless GUI smoke
test and a cross-distribution portability proof, exercised in CI on every push.
See the **[Alpha support contract](docs/ALPHA.md)** for exactly what is and is not
claimed.

**Implemented** — package format + deterministic packing + hardened parsing;
Ed25519 signing/verification; transactional install, crash recovery, rollback;
permission vocabulary + consent gate; Linux bubblewrap isolation with a
fail-closed launcher; full lifecycle (data/cache/temp, three uninstall modes,
lease-aware GC); concurrency locking; local trust-on-first-use; the dependency
engine, compatibility analysis, Runtime Profiles, and build report; the Builder
and Installer (GUI + CLI); and **Tux32 Core 1** with `lexe sdk verify`, the Core
Portable gate, the minimal SDK, and the CI cross-distribution proof.

**In progress / next** — additional Tux32 baselines; automated sysroot
provisioning (`lexe sdk install`); groundwork for multi-ISA packaging; a wider
tested runtime matrix (Fedora, Arch).

**Alpha limitations** — isolation is **Linux-only** (Windows is a build/test host
with no containment); isolation requires a working bubblewrap + user-namespace
backend, else the launcher refuses to run; Core 1 is **dynamic x86-64 ELF only**;
trust is **local (Tier 1)** with no global revocation or authenticated key
rotation; the SDK verifies and builds-in-sysroot but does not yet provision
sysroots. Not production-ready.

## Roadmap

| Stage | Focus |
|---|---|
| **Alpha** *(here)* | The foundations — format, crypto, install/lifecycle, isolation, concurrency, trust — plus the developer/consumer experience and **Tux32 Core 1** cross-distribution portability. |
| **Beta** | A wider tested runtime matrix; additional Tux32 baselines and automated sysroot provisioning; the repository (Tier 2) trust tier; multi-ISA packaging groundwork. |
| **1.0** | Root accreditation (Tier 3) trust; a conformance test suite and certification for third-party runtimes; a reference conforming runtime. |

Nothing here is a commitment date; see [docs/ALPHA.md](docs/ALPHA.md) for the
current contract.

## Contributing

Contributions are welcome. **[CONTRIBUTING.md](CONTRIBUTING.md)** takes you from a
fresh clone to a green test run and points you at the rest of the platform. New
contributors should start there, then read
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the module map. In short:

```sh
./scripts/build.sh          # configure + build + run the full test suite
```

Bug reports, feature requests and portability reports each have an
[issue template](.github/ISSUE_TEMPLATE). **Security findings go privately**
through the Security tab, not the public tracker — see
**[SECURITY.md](SECURITY.md)** for the channel, what is in scope, and the
documented non-guarantees that are *not* vulnerabilities.

## License

**Proprietary during the pre-release phase**, while the signing and trust
infrastructure is established — see [LICENSE](LICENSE). The stated intent is to
relicense under the **GPL** once that foundation is in place. The specification
itself is language-neutral, so conforming third-party runtimes may be implemented
independently. Revisions published before the relicense remain under their
original Apache-2.0 terms.

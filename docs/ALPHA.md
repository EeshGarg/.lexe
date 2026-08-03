# .lexe — Alpha Support Contract

> **Stage: Alpha candidate.** This document is the honest, frozen statement of
> what the first `.lexe` Alpha is and is not. It is deliberately conservative:
> an impressive feature set is not a release qualification, and nothing below is
> claimed that is not backed by an automated test, a CI job, or a reproducible
> script linked in the [evidence checklist](#evidence-linked-alpha-checklist).

- **Runtime version:** `0.1.0-alpha` (`lexe version`)
- **Package format:** `0.1` (FORMAT-0.1) — a distinct axis from the runtime
- **Portability baseline:** `tux32-core-1` (spec `1`) — a distinct axis again
- **Supported host for the runtime:** Linux x86-64 with an unprivileged
  user-namespace + bubblewrap sandbox. Windows is a **development/build host
  only** (the portable core is built and unit-tested there; it has no runtime
  isolation).

## Support contract

What "Alpha" commits to:

- The behaviours in [What this Alpha claims](#what-this-alpha-claims) are
  implemented and covered by the regression suite on Linux (GCC) and Windows
  (MSVC), and by the cross-distribution CI proof.
- The `.lexe` **package format is 0.1 and stable** for this line: a package the
  Alpha produces installs and launches on the Alpha runtime. Format changes will
  bump `lexeVersion`.
- The **Tux32 Core 1** contract is frozen (see [TUX32.md](TUX32.md)); a package
  verified conformant stays conformant against `tux32-core-1`.
- Security posture is **fail-closed**: the launcher never runs an application
  unconfined when isolation is required, signatures are verified over exact bytes
  before any byte is trusted, and permission expansion requires fresh consent.

What "Alpha" does **not** commit to:

- API/ABI stability of the C++ internals, on-disk layouts beyond FORMAT-0.1, or
  any interface not named above.
- Production use, uptime, data-durability guarantees, or a security audit.
- Backwards compatibility of the runtime version number across Alphas.

## What this Alpha claims

Each item is backed by evidence in the [checklist](#evidence-linked-alpha-checklist):

- Signed `.lexe` packages (Ed25519 over exact bytes; deterministic packing).
- Transactional installation and crash recovery.
- Local **trust-on-first-use** publisher trust (signing-key continuity;
  changed-key refusal; local block/unblock; honest "not identity" language).
- Permission-expansion **consent** (a frozen permission vocabulary with a
  separate, explicit consent gate).
- Linux **bubblewrap** filesystem/network isolation where the host supports it
  (read-only image, private data/cache/temp, sanitized environment, network
  denied unless granted).
- Lifecycle-safe **updates, rollback, uninstall**, and OS-backed **concurrency**
  (locks, launch leases, TOCTOU closure).
- Automatic **ELF dependency analysis** (direct ELF reading; typed
  classification; glibc-version aggregation).
- **Tux32 Core 1 verification** (`lexe sdk verify`, typed verdict and exit codes;
  the Builder hard-gates Core Portable on it).
- One unchanged, signed, dynamically linked package **proven across the declared
  distribution boundary** — build → verify → package → install → sandboxed launch
  from a newer host to a fresh, older, different distribution.

## What this Alpha does NOT claim

Stated plainly so the documentation never overreaches:

- **Not** universal Linux compatibility — portability is the specific,
  verifiable `tux32-core-1` contract, not "runs on any Linux".
- **Not** production-ready.
- **No** ARM64, RISC-V, or multi-ISA support; **no** automatic ISA translation.
- **No** GUI-application forwarding inside the sandbox (Core 1 is
  headless/terminal).
- **No** language-runtime dependency harvesting (Python/Java/Node/…).
- **No** externally verified publisher identity; a valid signature proves
  key-continuity, not a real-world identity.
- **No** global revocation and **no** authenticated key rotation.
- **No** Windows-equivalent isolation and **no** cross-process concurrency
  guarantees on Windows.

## Known limitations

- **Linux-only isolation.** On Windows the runtime runs applications directly
  (reported truthfully as `policy-unsupported`); it is a build/test host.
- **Isolation requires a working backend.** Bubblewrap plus unprivileged user
  namespaces must be available; where they are not, the launcher **fails closed**
  (refuses to launch) rather than running unconfined.
- **Static ELF and non-x86-64 binaries are out of Core 1 scope** — Core 1 is a
  dynamically linked x86-64 contract; other shapes get a non-portable verdict.
- **`dlopen`-ed / runtime plugin dependencies** are not discoverable from static
  ELF metadata and must be declared/bundled by the developer.
- **libsodium is the preferred crypto provider** on Linux (found via
  `pkg-config`); the MSVC dev host uses the vendored `orlp/ed25519` fallback with
  the runtime's own strict canonical checks.
- **The SDK is minimal**: it verifies and provides a build-in-sysroot workflow;
  it does not download or assemble sysroots for you (`lexe sdk install` is future).
- **Trust is local (Tier 1).** Repository endorsement (Tier 2) and root
  accreditation (Tier 3) are designed ([TRUST.md](TRUST.md)) but not implemented.

## Release artifacts

The first Alpha is a **source-only release**, chosen strictly on what actually
exists: the repository builds from source, and no prebuilt binaries are produced
or published by CI. There is therefore nothing to ship *but* source, and the
Alpha does not pretend otherwise.

| Field | Value |
|---|---|
| Kind | Source-only (a tagged source tree) |
| Artifact | The tag's auto-generated source archive, e.g. `lexe-0.1.0-alpha.tar.gz` / `.zip` |
| Checksum | SHA-256 of the archive, recorded on the release at tag time |
| Runtime version | `0.1.0-alpha` (`lexe version`) |
| Target architecture | Linux **x86-64** (runtime + isolation); Windows x86-64 is a build/test host with no isolation |
| Build requirements | CMake ≥ 3.22, a C++20 compiler (GCC/Clang or MSVC), Ninja, `pkg-config`; Linux also `libgtk-3-dev`, `libsodium-dev` |
| Runtime dependencies (Linux) | glibc ≥ 2.31, `libsodium`, GTK 3 (for the GUIs), `bubblewrap` (for isolation) |
| Installation method | Build from source (README *Quick install*), then `./packaging/install.sh` — per-user, no root; reverse with `./packaging/uninstall.sh` |

A future release may add prebuilt binaries via a dedicated release workflow that
builds and uploads them with checksums; until that workflow exists, publishing
binaries would be claiming an artifact that does not exist, so it is out of scope.

## Evidence-linked Alpha checklist

Every claim is verifiable from a fresh checkout. Suites run inside the single
`lexe_tests` binary (filter with `lexe_tests -ts=<suite>`); CI runs them on every
push (`.github/workflows/ci.yml`).

| Capability | Evidence |
|---|---|
| Signed packages, deterministic packing | `tests/test_package.cpp`, `tests/test_crypto.cpp`, `tests/test_ed25519_strict.cpp` |
| Verification pipeline (§6) | `tests/test_verify.cpp`, `tests/test_hostile_packages.cpp` |
| Transactional install + crash recovery | `tests/test_installer.cpp`, `tests/test_transaction.cpp`, `tests/test_crash_recovery.cpp` |
| Local TOFU trust; changed-key refusal | `tests/test_trust.cpp`, `tests/test_trust_adversarial.cpp`, `tests/test_trust_lifecycle.cpp` |
| Permission vocabulary + consent gate | `tests/test_permissions.cpp` |
| Bubblewrap isolation; fail-closed launcher | `tests/test_isolation.cpp`, `tests/test_isolation_linux.cpp`, `tests/test_launcher.cpp` |
| Updates / rollback / uninstall lifecycle | `tests/test_updater.cpp`, `tests/test_cli_e2e.cpp` |
| Concurrency: locks, leases, TOCTOU | `tests/test_lock.cpp`, `tests/test_race_linux.cpp` |
| ELF dependency analysis | `tests/test_elf.cpp`, `tests/test_depengine.cpp`, `tests/test_compat.cpp` |
| Tux32 Core 1 verification | `tests/test_tux32.cpp`, `tests/test_tux32_verify.cpp`, `tests/test_cli_sdk.cpp` |
| Builder Core Portable gate + report evidence | `tests/test_builder.cpp`, `tests/test_buildreport.cpp` |
| Distinct version axes + `lexe version` | `tests/test_version.cpp` |
| Warning-clean, markup-safe GUIs | `scripts/gui-smoke.sh` (CI `linux` job) |
| Cross-distribution portability proof | `scripts/portability-demo.sh` (CI `portability` job) |

**Regression totals (this line):** Linux (GCC) 413 test cases / 6000 assertions;
Windows (MSVC) 397 test cases / 5893 assertions — both green.

See [../CHANGELOG.md](../CHANGELOG.md) for the release history and
[../README.md#project-status](../README.md#project-status) for the current stage.

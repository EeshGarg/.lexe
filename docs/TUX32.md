# Tux32 — Conforming Runtime Baseline

> **Status: Core 1 is implemented and normative.** The `tux32-core-1` baseline is
> compiled into the runtime, mirrored in a checked-in `profile.json`, enforced by
> a verification engine, exposed as `lexe sdk verify`, and demonstrated end to end
> across a real distribution boundary. Later baselines remain future work; this
> document is normative for Core 1 and marks anything beyond it **Future**.

## The problem Tux32 names

A Core Portable package "runs on every conforming runtime" — but *conforming to
what?* **Tux32** is the answer: a **versioned, documented runtime baseline** — the
exact ABI contract a runtime must satisfy to run a Core Portable `.lexe` package
unchanged. "Build once, package once, run on every conforming runtime" is only
precise once "conforming" has a definition. Core 1 is that definition, frozen.

The central invariant:

> A package may claim Core 1 portability **only** when its executable and its
> bundled dependency closure satisfy the published Core 1 rules. **The build host
> must not silently become the compatibility target.** A binary built against a
> newer glibc than the ceiling must fail verification, not be waved through.

## Tux32 Core 1 — the frozen baseline

Core 1 is deliberately narrow. It is defined once, authoritatively, in
[`src/core/tux32.cpp`](../src/core/tux32.cpp) (`tux32_core_1()`), and mirrored in
[`sdk/tux32-core-1/profile.json`](../sdk/tux32-core-1/profile.json). A test pins
the two together so they can never drift.

| Property | Core 1 value |
|---|---|
| Baseline id | `tux32-core-1` (spec version `1`) |
| Executable format | dynamically linked ELF (`elf-dynamic`) — fully static images are out of scope; they do not exercise the dynamic ABI contract |
| Architecture | `x86_64` only |
| CPU baseline | `x86-64-v1` |
| glibc symbol ceiling | **2.31** (the newest glibc common to Debian 11 and Ubuntu 20.04) |
| Host-provided (never bundled) | glibc (`libc`/`libm`/`libdl`/`libpthread`/`librt`/…), `libgcc_s`, the dynamic loader, the vDSO |
| Must bundle | every other shared library the app needs |
| Forbidden to bundle | host GPU/driver interfaces (`libGL`, `libEGL`, `libvulkan`, `libdrm`, …) — host-provided or not at all |
| Isolation | the [baseline sandbox](ISOLATION.md): read-only image, private data/cache/temp, environment sanitization, network denied unless granted |
| Graphics / network | Core 1 is headless/terminal; network only with the `network` permission |

**Why 2.31?** It is the newest glibc symbol level available on *both* Debian 11
and Ubuntu 20.04 — the oldest still-maintained mainstream LTS bases. A binary
built on a current host (Ubuntu 24.04 / Fedora, glibc 2.39) imports
`__libc_start_main@GLIBC_2.34` and other newer symbols, and will not load on a
2.31 host. 2.31 is the widest ceiling that keeps a package running on those older
hosts unchanged.

## Verification (implemented)

`verify_against_profile(deps, profile)`
([`src/core/tux32.hpp`](../src/core/tux32.hpp)) takes the dependency engine's
already-computed graph — **it does not re-analyze** — and returns a typed
`Core1VerifyResult`. It computes the *package's* glibc requirement from the
executable plus every **bundled** library (host-interface libraries are supplied
by the host and are not counted), names the exact offending object and version,
and buckets the closure. The verdict follows a documented precedence — structural
(is it a dynamic ELF? supported arch?), then the symbol ceiling, then forbidden
driver interfaces, then closure completeness:

| Verdict | Meaning |
|---|---|
| `conformant` / `conformant-with-notes` | satisfies every Core 1 rule (the only cases a build may claim the profile) |
| `symbol-ceiling-exceeded` | requires a glibc symbol newer than 2.31 (names the object + version) |
| `forbidden-dependency` | needs a host driver/GPU interface that must not be bundled |
| `unresolved-dependency` | a `DT_NEEDED` soname could not be found |
| `unsupported-architecture` | not `x86_64` |
| `unsupported-executable` | not a dynamically linked ELF |
| `invalid-input` | not an analyzable ELF |

Automation switches on the typed verdict, never on message text.

## `lexe sdk verify` (implemented)

```
lexe sdk verify <binary | project-dir | payload-dir> [--json] [--profile tux32-core-1]
```

Resolves the target exactly as `lexe analyze` does, runs the one shared
dependency engine, and prints the verdict (human or, with `--json`, a
machine-consumable superset: the typed verdict, a `conformant` gate, the required
glibc, the named symbol offenders, and the bundle/host/forbidden/unresolved
buckets). Exit codes are typed: **0** conformant, **3** a non-conformant verdict,
**2** a bad profile/usage, **4** a missing target. Only shipped profiles are
accepted; a speculative id is refused.

## In the build report and the Builder (implemented)

The build report ([`buildreport`](DEPENDENCY_ENGINE.md)) attaches a Core 1
verdict **only** for the **Core Portable** profile — the profile that makes a
cross-distribution portability claim — so `lexe analyze --profile core-portable`
and every Builder result screen show it, while Forward Runtime and Native Capture
stay quiet (they make no such claim). The Builder **hard-gates** Core Portable: a
non-conformant closure disables the Build button and explains exactly why. See
[RUNTIME_PROFILES.md](RUNTIME_PROFILES.md).

## Building to the contract (the minimal SDK)

The ceiling is enforced by the **sysroot you build in**, not by a compiler flag —
a compiler cannot invent old symbols, and `-static` dodges the dynamic contract
rather than satisfying it. The minimal reference SDK lives at
[`sdk/tux32-core-1/`](../sdk/tux32-core-1/): the pinned `profile.json`, a
`toolchain.cmake`, a `build-in-sysroot.sh` that compiles inside a glibc ≤ 2.31
sysroot (rootless podman, Debian 11) with pkg-config isolated to the sysroot, and
a small dynamically linked reference app. See [SDK.md](SDK.md).

## Proven across a real distribution boundary

[`scripts/portability-demo.sh`](../scripts/portability-demo.sh) (run in CI)
demonstrates the invariant with real containers, not simulation. It builds the
runtime and a reference app in the glibc-2.31 sysroot; shows `lexe sdk verify`
reject a newer-host build (and that binary genuinely failing to load on a
glibc-2.31 host); then installs and **launches** the one signed artifact under the
isolation sandbox on a fresh, older, different-distribution host — checksum
unchanged end to end, its persistent data surviving across launches. One
unchanged, dynamically linked, signed `.lexe` traverses build → verify → package
→ install → isolate → launch across the boundary.

## Conformance

A runtime is **`tux32-core-1` conforming** when it provides the host interface
above with a glibc of at least 2.31, the stated kernel/isolation capabilities, and
runs a conforming package's exact signed artifact unchanged.

## Versioning and what's Future

Baselines are named `tux32-core-N`, monotonically versioned; a newer baseline may
only **add** to or **raise** the contract, so conformance stays a straight-line
check. **Future:** additional architectures, newer baselines, downloadable native
variants, and multi-ISA packaging ([MULTI_ARCH.md](MULTI_ARCH.md)) are out of
scope for Core 1 and add no new guarantees here.

# Tux32 Core 1 — SDK guidance

This directory is the **minimal, reference** SDK for the `tux32-core-1` runtime
baseline. It is intentionally small: it is guidance plus a verifier, not a
packaged toolchain, language runtime, or translation layer.

`Tux32 Core 1` is the stable ABI contract a **Core Portable** package targets.
Its full definition is compiled into the runtime ([../../src/core/tux32.cpp](../../src/core/tux32.cpp))
and mirrored, byte-checked, in [profile.json](profile.json). The prose rationale
is in [../../docs/TUX32.md](../../docs/TUX32.md). In brief, Core 1 is:

| Property            | Core 1 value                                             |
| ------------------- | -------------------------------------------------------- |
| Executable format   | dynamically linked ELF (static images are out of scope)  |
| Architecture        | `x86_64` only                                            |
| CPU baseline        | `x86-64-v1`                                               |
| glibc symbol ceiling| **2.31** (Debian 11 / Ubuntu 20.04)                      |
| Host-provided       | glibc, libgcc_s, the dynamic loader, the vDSO — never bundled |
| Must bundle         | every other shared library the app needs                 |
| Forbidden to bundle | host GPU/driver interfaces (libGL, libEGL, libvulkan, …)  |

## The one invariant

> A package may claim Core 1 portability **only** when its executable and its
> bundled dependency closure satisfy the published Core 1 rules. **The build
> host must not silently become the compatibility target.**

A binary built on a newer host (say Fedora or Ubuntu 24.04, glibc 2.39) imports
newer glibc symbols — most visibly `__libc_start_main@GLIBC_2.34`. Such a binary
is *not* Core 1 portable even though it links fine on the build host, and
`lexe sdk verify` **rejects** it. That rejection is the feature.

## Files

| File                                          | Purpose                                                            |
| --------------------------------------------- | ------------------------------------------------------------------ |
| [profile.json](profile.json)                  | Machine-readable mirror of the compiled Core 1 profile (pinned).   |
| [toolchain.cmake](toolchain.cmake)            | Minimal CMake toolchain: pins the CPU baseline, targets a sysroot. |
| [build-in-sysroot.sh](build-in-sysroot.sh)    | Build a project inside a glibc ≤ 2.31 sysroot (rootless podman).   |
| [reference-app/](reference-app/)              | A small, dynamically linked reference app (libm, data/cache/temp). |

## Workflow: build → verify → package

```sh
# 1. Build against a Core 1 sysroot (glibc <= 2.31), NOT the host glibc.
sdk/tux32-core-1/build-in-sysroot.sh sdk/tux32-core-1/reference-app

# 2. Verify the built closure against the Core 1 profile. Exit 0 = conformant;
#    exit 3 = a typed non-conformant verdict (read --json for the exact reason).
lexe sdk verify sdk/tux32-core-1/reference-app --json

# 3. Only once it verifies, package and sign it.
lexe build sdk/tux32-core-1/reference-app -o probe.lexe --key mykey.json
```

`lexe sdk verify` reuses the runtime's own dependency engine — the same analysis
`lexe analyze`, `lexe build`, and the installer use. There is no second,
divergent notion of "what this binary needs".

## Why build in a sysroot

The glibc ceiling is enforced by the **sysroot you build in**, not by a compiler
flag — a compiler cannot invent old symbols, and `-static` is not a substitute
(it dodges the dynamic ABI instead of satisfying it). Build inside a distribution
whose glibc is ≤ 2.31 (Debian 11 and Ubuntu 20.04 are the reference sysroots),
keep pkg-config pinned to that sysroot so a newer host library cannot leak in,
and confirm every build with `lexe sdk verify`.

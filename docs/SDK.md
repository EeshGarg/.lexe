# SDK & Sysroot

> **Status: a minimal Core 1 SDK is implemented.** `lexe sdk verify` and the
> `sdk/tux32-core-1/` reference (a pinned profile, a CMake toolchain, a
> build-in-sysroot script, and a reference app) ship today. A full,
> multi-baseline, sysroot-provisioning SDK remains **Future**; sections below are
> marked accordingly.

## The problem the SDK solves

`lexe analyze` on a binary built on a current host is instructive:

```
Runtime profile: Core Portable
Tux32 tux32-core-1: symbol-ceiling-exceeded (needs glibc 2.34, ceiling 2.31)
    ! <executable> requires GLIBC_2.34
```

Nothing is *wrong* with the binary — it simply picked up `GLIBC_2.34` symbols
because it was built on a host with a new glibc. A developer who wants broad
portability must build against an **older, pinned** host interface, not their
bleeding-edge machine. That pinned build environment is a **sysroot**.

## What ships today

The minimal Core 1 SDK is [`sdk/tux32-core-1/`](../sdk/tux32-core-1/):

| File | Purpose | Status |
|---|---|---|
| `profile.json` | Machine-readable mirror of the compiled Core 1 profile (pinned by a test). | **Implemented** |
| `toolchain.cmake` | A minimal CMake toolchain: pins the `x86-64-v1` baseline, targets a sysroot, warns when building against a newer host glibc. | **Implemented** |
| `build-in-sysroot.sh` | Builds a project **inside** a glibc ≤ 2.31 sysroot (rootless podman, Debian 11), with pkg-config pinned to the sysroot so a newer host library cannot leak in. | **Implemented** |
| `reference-app/` | A small, dynamically linked app (links libm; exercises the data/cache/temp contract). | **Implemented** |

And the verifier, exposed on the CLI:

```
lexe sdk verify <binary | project-dir | payload-dir> [--json] [--profile tux32-core-1]
```

## How verification reuses the engine (no second path)

`lexe sdk verify` needs **no new analysis engine**. It resolves the target exactly
as `lexe analyze` does, runs the same [dependency engine](DEPENDENCY_ENGINE.md),
and hands the resulting graph to `verify_against_profile()`. The build host never
becomes the compatibility target, and there is exactly one notion of "what this
binary needs".

| Step | Mechanism | Status |
|---|---|---|
| Detect a binary's symbol requirements | `core/elf` `DT_VERNEED` parsing | **Implemented** |
| Aggregate the glibc requirement across the closure | `core/depengine` | **Implemented** |
| Verify against the Core 1 profile (typed verdict) | `core/tux32` `verify_against_profile` | **Implemented** |
| Provision/assemble a sysroot automatically | the SDK | **Future** |
| Multiple baselines / `lexe sdk install` | the SDK | **Future** |

## Why build in a sysroot (not a flag)

The glibc ceiling is enforced by the **sysroot you build in**, not a compiler
flag: a compiler cannot invent symbols its glibc does not define, and `-static`
sidesteps the dynamic ABI rather than satisfying it. The reference workflow:

```sh
# 1. Build against a Core 1 sysroot (glibc <= 2.31), not the host glibc.
sdk/tux32-core-1/build-in-sysroot.sh sdk/tux32-core-1/reference-app

# 2. Verify the closure. Exit 0 = conformant; exit 3 = a typed non-conformant verdict.
lexe sdk verify sdk/tux32-core-1/reference-app --json

# 3. Only once it verifies, package and sign it.
lexe build sdk/tux32-core-1/reference-app -o probe.lexe --key mykey.json
```

The rejection of a newer-host build is the feature — see the end-to-end proof in
[`scripts/portability-demo.sh`](../scripts/portability-demo.sh) and
[TUX32.md](TUX32.md).

## Non-goals (for now)

- The SDK is **not** a compiler or a full toolchain distribution; it constrains an
  existing toolchain against a baseline.
- No sysroot is *downloaded or assembled* for you yet; you supply the build
  environment (the script uses a stock Debian 11 image).
- No `.lexe` manifest or package-format fields are added.
- Nothing here changes trust, isolation, lifecycle, or concurrency guarantees.

## Relationship summary

- **Tux32 Core 1** defines the contract (the baseline).
- **The SDK/sysroot** helps a developer *build to* that contract.
- **The dependency engine + `verify_against_profile`** *verify* a build against it.
- **Runtime profiles** let the package *declare* which contract it targets, and the
  Builder *enforces* it for Core Portable.

Implementing a conforming verifier, builder, or runtime in another language? See
[IMPLEMENTERS.md](IMPLEMENTERS.md) for a reading path through the normative specs
([../SPEC.md](../SPEC.md), [FORMAT-0.1.md](FORMAT-0.1.md), [TUX32.md](TUX32.md)).

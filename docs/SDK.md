# SDK & Sysroot Architecture (design groundwork)

> **Status: design groundwork, not implemented.** This document describes the
> architecture and interfaces of a future `.lexe` SDK. It introduces **no code
> and no package-format fields yet**. Sections are marked **Implemented**,
> **Planned**, or **Future**.

## The problem the SDK solves

`lexe analyze` on the reference runtime itself is instructive:

```
Dependencies: 6 total — 4 host, 2 bundle
glibc floor:  2.38
Compatibility: [ ok ] UshaOS Core   [ no ] Ubuntu Runtime — needs glibc 2.38
```

Nothing is *wrong* with the binary — it simply picked up `GLIBC_2.38` symbols
because it was built on a host with a new glibc. A developer who wants broad
portability must build against an **older, pinned** host interface, not their
bleeding-edge machine. That pinned build environment is a **sysroot**, and the
**SDK** is what provisions and manages it.

The dependency engine already *detects* this problem *(Implemented — it aggregates
the glibc floor and reports per-runtime compatibility)*. The SDK's job is to help
developers *avoid* it at build time, and to *verify* a build was produced against
the baseline it claims.

## Architecture

*(Planned.)* Three layered concepts, each building on the previous:

1. **Baseline** — a [Tux32](TUX32.md) runtime baseline: the host-interface set +
   symbol-version floor a package targets. *(Design groundwork; see TUX32.md.)*
2. **Sysroot** — a concrete build environment pinned to a baseline: the headers,
   link stubs, and symbol-version scripts that make a toolchain *refuse* to emit
   references newer than the baseline. A sysroot is identified by its baseline id
   (`tux32-1`) and is toolchain-agnostic — it constrains what the compiler/linker
   may reference, it is not itself a compiler.
3. **SDK** — the tooling that installs sysroots, selects one for a build, and
   verifies a produced binary against it.

```
   baseline (contract)            sysroot (build env)           SDK (tooling)
   host interface + floor   →     headers + link stubs +   →    provision · select ·
   (Tux32)                        version scripts               verify
```

## How it plugs into what exists

The verification half already exists and is reused, not reinvented:

| Step | Mechanism | Status |
|---|---|---|
| Detect a binary's symbol requirements | `core/elf` `DT_VERNEED` parsing | **Implemented** |
| Aggregate the glibc floor across the graph | `core/depengine` `max_glibc_version` | **Implemented** |
| Rate against runtime baselines | `core/compat` | **Implemented** |
| Provision a baseline-pinned sysroot | the SDK | **Planned** |
| Verify a build ≤ a baseline's floor | reuse the engine against a chosen baseline | **Planned** |
| Auto-select the profile from the sysroot used | Builder ↔ SDK integration | **Future** |

The Builder would surface this directly: analyze a candidate binary, and if it
exceeds the selected baseline, recommend rebuilding in the matching sysroot rather
than silently shipping a package that only runs on new hosts.

## Interface sketch

*(Planned — illustrative, not final, no code yet.)* A `lexe sdk` command group,
sitting beside `lexe analyze`/`lexe build`:

```
lexe sdk list                     # baselines/sysroots available locally
lexe sdk install tux32-1          # provision a baseline-pinned sysroot
lexe sdk verify ./my-app --baseline tux32-1
                                  # does the binary stay within the baseline?
```

`lexe sdk verify` needs **no new engine** — it runs the existing dependency
analysis and checks the aggregated version floor against the named baseline. Only
`install` (fetching/assembling a sysroot) is genuinely new work.

## Non-goals (for now)

- The SDK is **not** a compiler or a full toolchain distribution; it constrains an
  existing toolchain against a baseline.
- No sysroot artifacts are shipped in this repository yet.
- No `.lexe` manifest or package-format fields are added.
- Nothing here changes trust, isolation, lifecycle, or concurrency guarantees.

## Relationship summary

- **Tux32** defines the contract (a baseline).
- **The SDK/sysroot** helps a developer *build to* that contract.
- **The dependency engine + compatibility analysis** *verify* a build against it
  (this half is implemented today).
- **Runtime profiles** let the package *declare* which contract it targets.

# Tux32 — Conforming Runtime Baseline (design groundwork)

> **Status: design groundwork, not implemented.** This document specifies the
> *shape* of the Tux32 baseline and the interfaces it will plug into. Phase 2
> built the pieces it sits on — the [dependency engine](DEPENDENCY_ENGINE.md) and
> [runtime profiles](RUNTIME_PROFILES.md). Tux32 itself introduces **no code and
> no package-format fields yet**, and changes none of the shipped security,
> trust, isolation, lifecycle, or concurrency guarantees.
>
> Every section below is marked **Implemented**, **Planned**, or **Future**.

## The problem Tux32 names

A Core Portable package "runs on every conforming runtime" — but *conforming to
what?* Today the compatibility analysis compares a package's requirements against
a small, hardcoded list of distro glibc baselines (`core/compat.cpp`). That is
useful but ad hoc. **Tux32** is the working name for a **versioned, documented
runtime baseline**: the exact contract a runtime must satisfy to run Core Portable
`.lexe` packages unchanged. "Build once, package once, run on every conforming
runtime" becomes precise when "conforming" has a definition.

## What a baseline is

*(Planned.)* A Tux32 baseline is an immutable, versioned descriptor of what a
conforming host provides. It has four parts:

1. **Host interface set** — the sonames a conforming runtime guarantees (the core
   glibc/loader/toolchain runtime). This is exactly the set the dependency engine
   already classifies as `host-interface` *(Implemented — `is_host_interface` in
   `core/depengine.cpp`)*; Tux32 makes that set a **named, versioned contract**
   rather than a hardcoded predicate.
2. **Symbol-version floors** — the maximum versioned symbol requirement a package
   may use and still be Core Portable (e.g. a glibc floor). The engine already
   aggregates the highest `GLIBC_x.y` across a graph *(Implemented —
   `max_glibc_version`)*; Tux32 fixes the floor a baseline promises.
3. **Kernel & platform features** — the minimum kernel capabilities a conforming
   host provides (namespaces, `flock`, the syscalls the sandbox relies on).
4. **Isolation guarantees** — the sandbox controls a conforming runtime enforces
   (the [ISOLATION.md](ISOLATION.md) baseline: read-only image, private
   data/cache/temp, environment sanitization, network denial when not granted).

## Baseline identity and versioning

*(Planned.)* Baselines are named `tux32-<N>` (e.g. `tux32-1`), monotonically
versioned. A newer baseline may only **add** to or **raise** the contract; a
package built for `tux32-1` runs on any runtime conforming to `tux32-1` or later.
This keeps conformance a straight-line check, never path-finding.

## How the existing pieces map

| Concept | Today | Under Tux32 |
|---|---|---|
| host-interface classification | hardcoded soname predicate *(Implemented)* | the baseline's host-interface set |
| glibc floor | per-distro constants in `compat.cpp` *(Implemented)* | the baseline's symbol-version floor |
| runtime targets | fixed list (UshaOS/Fedora/Debian/Ubuntu) *(Implemented)* | "conforms to `tux32-N`" |
| Core Portable profile | bundles all non-host *(Implemented)* | targets a chosen baseline |
| Forward Runtime profile | warns above a broad floor *(Implemented)* | targets a *newer* baseline, explicitly |
| Native Capture profile | reduced portability *(Implemented)* | not baseline-portable by definition |

## Interface sketch

*(Planned — illustrative, not final, no code yet.)* A baseline is a value the
compatibility layer consults instead of the current hardcoded distro list:

```
RuntimeBaseline {
    id                 // "tux32-1"
    host_interface[]   // guaranteed sonames
    glibc_floor        // e.g. 2.31
    kernel_features[]  // required kernel capabilities
    isolation[]        // enforced sandbox controls
}
```

`analyze_compatibility()` would take a target baseline (or "all known baselines")
and answer, per baseline, Compatible / Warning / Incompatible — the same typed
result it produces today, sourced from the baseline instead of a constant table.
Packages remain unchanged; conformance is a runtime property, not a package field.

## Conformance

*(Future.)* A runtime is **`tux32-N` conforming** when it provides baseline `N`.
A conformance test suite — analogous to the platform's own test corpus — would
validate a third-party runtime against a baseline, so "conforming runtime" is
verifiable rather than asserted. This is the seed of the conformance ecosystem in
the [Alpha roadmap](../README.md#alpha-roadmap).

## Explicitly out of scope (for now)

- No baseline version numbers are normative yet; the values above are
  placeholders.
- No new `.lexe` manifest or package fields.
- No change to trust, isolation, lifecycle, or concurrency guarantees.

When Tux32 is specified, this becomes the normative baseline document, and
[RUNTIME_PROFILES.md](RUNTIME_PROFILES.md) and
[DEPENDENCY_ENGINE.md](DEPENDENCY_ENGINE.md) will reference its baselines directly
in place of their current hardcoded tables.

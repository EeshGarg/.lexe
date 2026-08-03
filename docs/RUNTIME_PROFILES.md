# Runtime Profiles (Phase 2 / DX2)

A **runtime profile** is the portability contract a package targets. The profile
*infrastructure* (`core/runtime_profile.{hpp,cpp}`) is the typed model plus an
honest, dependency-aware assessment. Core Portable is now bound to a concrete,
enforced baseline — [Tux32 Core 1](TUX32.md) — so its portability claim is
verified, not asserted.

## The three profiles

| Profile | Portability | What it means |
|---|---|---|
| **Core Portable** (default) | Maximum | Bundle everything except the host interface; aims to run unchanged on any conforming `.lexe` runtime. |
| **Forward Runtime** | Forward-compatible | Bundles like Core Portable but is explicit that it may need a newer runtime baseline; **warns** when the app raises the minimum runtime (e.g. a newer glibc). |
| **Native Capture** | Reduced | Captures host libraries for this build's host. Self-contained for matching hosts, but **clearly labelled reduced portability** — never presented as universal. |

The builder defaults to **Core Portable**.

## Honest assessment

`assess_profile(profile, dependency_report)` returns a `ProfileAssessment` that
never overstates portability:

- **Unresolved** dependencies and **forbidden** host driver/GPU interfaces always
  limit portability, under every profile.
- **Native Capture** always reports reduced portability.
- **Forward Runtime** warns when the app's glibc requirement exceeds a
  broadly-available floor (`2.31`, ~Debian 11 / Ubuntu 20.04 era).
- **Core Portable** claims portability only when there are no unresolved
  dependencies.

No profile silently claims "runs everywhere."

## Core Portable is enforced against Tux32 Core 1

Core Portable is the profile that makes a cross-distribution portability claim, so
it is **verified** against [Tux32 Core 1](TUX32.md), not merely assessed:

- The build report attaches a typed Core 1 verdict **only** for Core Portable
  (`assemble_report` runs `verify_against_profile` over the same dependency
  closure). Forward Runtime and Native Capture carry no Tux32 verdict — they make
  no such claim.
- The Builder **hard-gates** Core Portable: a non-conformant closure disables the
  Build button and names the offending object/version, forbidden interface, or
  unresolved soname. Forward Runtime builds but is labeled advisory; Native
  Capture builds but is labeled host-locked. The build host cannot silently ship
  an over-ceiling binary under a portability claim.

## Where it surfaces

- CLI: `lexe analyze --profile <core-portable|forward-runtime|native-capture>`
  (Core Portable reports include the Tux32 verdict), and `lexe sdk verify` for the
  verdict on its own with typed exit codes.
- Builder: the Runtime profile step selects the profile; the Build step enforces
  the Core Portable gate; the result screen and build report include the verdict.

## Future (Tux32)

Additional Tux32 baselines, downloadable native variants, and the profile's
relationship to signed runtime manifests are deferred to [TUX32.md](TUX32.md). The
types here (`RuntimeProfile`, `RuntimeProfileInfo`, `ProfileAssessment`) are the
seam those features build on.

*See also:* the overall specification in [../SPEC.md](../SPEC.md) and the frozen
portability contract in [TUX32.md](TUX32.md).

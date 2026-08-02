# Tux32 — Runtime Baseline Specification (PLACEHOLDER — future work)

> **Status: placeholder.** Tux32 is not specified or implemented yet. Phase 2
> built the *groundwork* it will sit on — runtime profiles
> ([RUNTIME_PROFILES.md](RUNTIME_PROFILES.md)) and the dependency engine
> ([DEPENDENCY_ENGINE.md](DEPENDENCY_ENGINE.md)) — but the full specification is
> deliberately deferred. This file records intent so the direction is clear, not
> a committed design.

## Idea

"Tux32" is the working name for a **conforming runtime baseline**: the exact set
of host interfaces (libc/loader version floor, kernel features, the sandbox
guarantees) that any runtime claiming to run `.lexe` Core Portable packages must
provide. A package built for Core Portable against the Tux32 baseline should run
unchanged on every Tux32-conforming runtime — "build once, package once, run on
every conforming runtime."

## Anticipated scope (not final)

- A versioned, documented **baseline** (host interface set + version floors) that
  runtime profiles target.
- **Downloadable native variants**: an architecture-specific payload fetched for
  the host at install time, coordinated with the runtime profile.
- The relationship between a profile, the baseline it targets, and a **signed
  runtime manifest** — layered on top of the existing FORMAT-0.1 integrity and
  the local trust model, without weakening either.

## Explicitly out of scope for now

- No baseline version numbers are normative yet.
- No new package-format fields are introduced.
- Nothing here changes the security, trust, isolation, or lifecycle guarantees
  already shipped.

When Tux32 is specified, this file becomes the normative document and
[RUNTIME_PROFILES.md](RUNTIME_PROFILES.md) will reference its baselines directly.

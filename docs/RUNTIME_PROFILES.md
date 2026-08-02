# Runtime Profiles (Phase 2 / DX2)

A **runtime profile** is the portability contract a package targets. This phase
implements the profile *infrastructure* (`core/runtime_profile.{hpp,cpp}`) — the
typed model and an honest, dependency-aware assessment — as groundwork for the
full [Tux32](TUX32.md) specification, which is future work.

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

## Where it surfaces

- CLI: `lexe analyze --profile <core-portable|forward-runtime|native-capture>`.
- Builder: the Output step offers the profile; the build report states the
  chosen profile's portability and any warnings.

## Future (Tux32)

The full Tux32 model — richer runtime baselines, downloadable native variants,
and the profile's relationship to signed runtime manifests — is deferred to
[TUX32.md](TUX32.md). The types here (`RuntimeProfile`, `RuntimeProfileInfo`,
`ProfileAssessment`) are the seam those features will build on.

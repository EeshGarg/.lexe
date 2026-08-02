# .lexe documentation

The specifications and design documents for the `.lexe` platform. Start with the
top-level [README](../README.md) for the overview, then use this index to go
deeper. Each document is marked **Normative** (specifies implemented behavior),
**Design** (an approach, partly or fully implemented), or **Placeholder**
(future direction, not yet implemented).

## Start here

| Document | Kind | What it covers |
|---|---|---|
| [../README.md](../README.md) | — | Platform overview, install, quick start, status. |
| [../SPEC.md](../SPEC.md) | Normative | The overall specification and the 0.1 → 0.3 vision. |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | — | Building, running tests, and finding your way around. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Normative | Module map, build, conventions, and the test matrix. |

## Package format

| Document | Kind | What it covers |
|---|---|---|
| [FORMAT-0.1.md](FORMAT-0.1.md) | Normative | The `.lexe` container: structure, manifest, hashes, signatures, and the installed storage layout. |

## Security

| Document | Kind | What it covers |
|---|---|---|
| [HARDENING.md](HARDENING.md) | Normative | The hardening gates (A–H), the proven-invariants table, and the evidence bar. |
| [ISOLATION.md](ISOLATION.md) | Design | The Linux bubblewrap runtime-isolation design. |
| [CONCURRENCY.md](CONCURRENCY.md) | Normative | OS-backed operation locking, launch leases, and the launch TOCTOU closure. |
| [TRUST.md](TRUST.md) | Design | The three trust & signing tiers (Tier 1 implemented; Tiers 2–3 future). |
| [TRUST-MODEL.md](TRUST-MODEL.md) | Normative | The implemented local trust-on-first-use model. |
| [THREAT-MODEL.md](THREAT-MODEL.md) | Normative | Adversaries, mitigations, and explicit non-guarantees. |

## Developer experience

| Document | Kind | What it covers |
|---|---|---|
| [DEPENDENCY_ENGINE.md](DEPENDENCY_ENGINE.md) | Normative | The ELF reader and the dependency-resolution engine. |
| [RUNTIME_PROFILES.md](RUNTIME_PROFILES.md) | Normative | The runtime-profile model and its honest assessment. |

## Roadmap groundwork (not yet implemented)

These documents describe the direction toward Alpha and beyond. They are design
groundwork — each distinguishes what is Implemented, Planned, and Future.

| Document | Kind | What it covers |
|---|---|---|
| [TUX32.md](TUX32.md) | Placeholder | The future conforming-runtime baseline. |

## Conventions

- **`.lexe`** — the platform and its package format (always lowercase, with the dot).
- **Runtime** — the reference implementation (`lexe`) that verifies, installs, and launches packages.
- **Builder** — `lexe-builder` (GUI) and `lexe build` (CLI) that produce packages.
- **Runtime Profile** — the portability contract a package targets (see RUNTIME_PROFILES.md).

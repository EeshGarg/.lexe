# .lexe documentation

The specifications and design documents for the `.lexe` platform. New here? Read
the top-level **[README](../README.md)** first, then follow this index. Each entry
is marked **Normative** (specifies implemented behavior), **Design** (an approach,
partly or fully implemented), or **Placeholder** (future direction, not yet
implemented).

## Getting started

| Document | Kind | What it covers |
|---|---|---|
| [../README.md](../README.md) | — | Platform overview, install, quick start, status. |
| [TUTORIAL.md](TUTORIAL.md) | — | One walkthrough: analyze → verify → build → inspect → install → launch → remove. |
| [FAQ.md](FAQ.md) | — | Short, honest answers to common questions. |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | — | Common runtime issues and developer mistakes, with fixes. |
| [../examples/](../examples/) | — | Small, buildable sample apps (cli-tool, bundled-library). |

## Architecture

| Document | Kind | What it covers |
|---|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Normative | The module map, build system, conventions, GUIs, and the test matrix. |

## Specifications

| Document | Kind | What it covers |
|---|---|---|
| [../SPEC.md](../SPEC.md) | Normative | The product specification and the 0.1 → 0.3 vision. |
| [FORMAT-0.1.md](FORMAT-0.1.md) | Normative | The `.lexe` container: structure, manifest, hashes, signatures, and storage layout. |

## Security

| Document | Kind | What it covers |
|---|---|---|
| [../SECURITY.md](../SECURITY.md) | Informative | How to report a vulnerability privately, what is in scope, and the documented non-guarantees that are not. |
| [HARDENING.md](HARDENING.md) | Normative | The hardening gates (A–H), the proven-invariants table, and the evidence bar. |
| [ISOLATION.md](ISOLATION.md) | Design | The Linux bubblewrap runtime-isolation design. |
| [CONCURRENCY.md](CONCURRENCY.md) | Normative | OS-backed operation locking, launch leases, and the launch TOCTOU closure. |
| [TRUST-MODEL.md](TRUST-MODEL.md) | Normative | The implemented local trust-on-first-use model. |
| [TRUST.md](TRUST.md) | Design | The three trust & signing tiers (Tier 1 implemented; Tiers 2–3 future). |
| [THREAT-MODEL.md](THREAT-MODEL.md) | Normative | Adversaries, mitigations, and explicit non-guarantees. |

## Portability

| Document | Kind | What it covers |
|---|---|---|
| [TUX32.md](TUX32.md) | Normative | The Tux32 Core 1 baseline: the frozen contract, the verifier, `lexe sdk verify`, and the cross-distribution proof. |
| [SDK.md](SDK.md) | Design | The minimal Core 1 SDK (`lexe sdk verify` + `sdk/tux32-core-1/`); full sysroot provisioning is future. |

## Developer docs

| Document | Kind | What it covers |
|---|---|---|
| [DEPENDENCY_ENGINE.md](DEPENDENCY_ENGINE.md) | Normative | The direct-ELF reader and the dependency-resolution engine. |
| [RUNTIME_PROFILES.md](RUNTIME_PROFILES.md) | Normative | The Runtime Profile model, and Core Portable's Tux32 Core 1 enforcement. |
| [IMPLEMENTERS.md](IMPLEMENTERS.md) | Informative | A reading path for implementing a conforming `.lexe` verifier, builder, or runtime in another language. |

## Contributor docs

| Document | Kind | What it covers |
|---|---|---|
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | — | Building, running the tests, and finding your way around the code. |
| [../CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | — | What is expected in issues and pull requests, and how enforcement actually works here. |

## Status & roadmap

| Document | Kind | What it covers |
|---|---|---|
| [ALPHA.md](ALPHA.md) | Normative | The Alpha support contract: claims boundary, known limitations, release artifacts, and the evidence-linked checklist. |
| [RELEASE.md](RELEASE.md) | Informative | The operator's release runbook for `v0.1.0-alpha.1` (notes, artifacts, checklist). |
| [SBOM.md](SBOM.md) | Informative | Software bill of materials — vendored and runtime dependencies with licenses. |
| [COMPATIBILITY.md](COMPATIBILITY.md) | Normative | Compatibility promises vs. implementation details across every stable surface. |
| [../CHANGELOG.md](../CHANGELOG.md) | — | Release history. |
| [MULTI_ARCH.md](MULTI_ARCH.md) | Placeholder | Future multi-architecture (multi-ISA) packaging. |

## Terminology

Used consistently across the code, the GUIs, and the docs:

- **`.lexe`** — the platform and its package format (always lowercase, with the
  dot). *Lexe* (capitalized, no dot) names the project/product in prose and
  titles — e.g. the *Lexe Reference Runtime*; the file and format are always `.lexe`.
- **Runtime** — the reference implementation (`lexe`) that verifies, installs, launches, updates, and removes packages.
- **Builder** — `lexe-builder` (GUI) and `lexe build` (CLI) that produce packages.
- **Installer** — `lexe-installer` (GUI) and `lexe install` (CLI) that install a package.
- **Runtime Profile** — the portability contract a package targets (see [RUNTIME_PROFILES.md](RUNTIME_PROFILES.md)).
- **Tux32 Core 1** — the frozen, versioned portability baseline (see [TUX32.md](TUX32.md)).

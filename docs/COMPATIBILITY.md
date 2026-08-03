# Compatibility & stability

> **Normative for what it marks as a promise.** This document inventories every
> surface where a future change could break existing packages, installs, or
> third-party implementations, and states plainly whether each is a **compatibility
> promise** or an **implementation detail** that may change. When in doubt, a
> compatibility promise is defined by [FORMAT-0.1.md](FORMAT-0.1.md), not by the
> reference code.

## The three version axes (never conflated)

`.lexe` versions three independent things (see [ALPHA.md](ALPHA.md), `lexe version`):

| Axis | Value now | Promise |
|---|---|---|
| **Package format** | `0.1` (manifest `lexeVersion`) | **Promise.** A package produced in this line installs and launches on this line. A breaking format change bumps `lexeVersion`; the runtime rejects an unknown `lexeVersion`. |
| **Tux32 baseline** | `tux32-core-1` (spec `1`) | **Promise.** Frozen: a package verified conformant stays conformant. New baselines are additive (`tux32-core-N`), never a redefinition. |
| **Runtime** | `0.1.0-alpha` | **Not** a compatibility axis. The runtime version may change freely across Alphas; it is a build identity, not a contract. |

## Package-facing surfaces — promises

These are what a package or a third-party implementation may rely on:

| Surface | Status | Governed by |
|---|---|---|
| Container shape (deterministic ZIP; `lexe.json` + `payload/` + `metadata/hashes.json`) | **Promise** | FORMAT-0.1 §1–§3 |
| Entry-name rules (no absolute paths / `..` / backslashes / symlink escapes) | **Promise** | FORMAT-0.1 §2 |
| Hashing (per-file SHA-256 in `hashes.json`) | **Promise** | FORMAT-0.1 §3 |
| Signatures (detached Ed25519 over exact bytes; `ed25519:` + base64 key encoding) | **Promise** | FORMAT-0.1 §4 |
| Manifest required fields; unknown fields ignored (forward-compatible) | **Promise** | FORMAT-0.1 §5 |
| Verification pipeline order | **Promise** | FORMAT-0.1 §6 |
| Update manifest (`update.json`) checks | **Promise** | FORMAT-0.1 §7 |
| Version ordering (semver-lite total order) | **Promise** | FORMAT-0.1 §8 |
| Package **IDs** (reverse-DNS; the durable identity for install/update/trust) | **Promise** | FORMAT-0.1 §5 |
| App storage env (`$LEXE_APP_DATA`, `$LEXE_APP_CACHE`, `$TMPDIR`) seen by a launched app | **Promise** | FORMAT-0.1 §9, [ISOLATION.md](ISOLATION.md) |
| Trust **model** (local TOFU; key continuity; changed-key refusal) | **Promise** | [TRUST-MODEL.md](TRUST-MODEL.md) |
| Tux32 Core 1 rules + machine-readable `sdk/tux32-core-1/profile.json` | **Promise** | [TUX32.md](TUX32.md) |

## Internal surfaces — implementation details (may change)

Not part of the contract; do not depend on their exact shape across versions:

| Surface | Status | Note |
|---|---|---|
| On-disk **installed layout** beyond FORMAT-0.1 §9 (e.g. `versions/`, `meta/` internals) | **Detail** | The documented per-app roots are stable; the internal arrangement within them is not. |
| **Trust record** file format (`<home>/trust/<id>.json`) | **Detail** | The trust *model* is a promise; the on-disk serialization is internal. |
| **Settings** file (`<home>/settings.json`) | **Detail** | Preferences only; unknown fields are ignored, but the schema may grow. |
| Registry/installation.json field set | **Detail** | Internal bookkeeping; read via `lexe apps`/`info`, not by hand. |
| C++ APIs, module boundaries, and `src/core` types | **Detail** | ALPHA makes no API/ABI promise. |
| CLI `--json` **shapes** | **Informative** | Stable enough to script an Alpha, but may gain fields; treat additively. |
| CLI **exit codes** (0 ok · 1 runtime · 2 usage · 3 verification · 4 not-found · 5 permission · 6 busy · 7 trust) | **Promise (this line)** | Documented and depended on by `lexe sdk verify` (0/3) and tests. |
| **Builder defaults** (Core Portable default, x86-64, generated key path) | **Detail** | Convenience defaults; may change without affecting produced packages. |

## Forward compatibility rules

- **Unknown manifest fields are ignored**, so a newer builder can add optional
  metadata a `0.1` runtime simply skips. Do not repurpose or remove a defined
  field without a `lexeVersion` bump.
- **Unknown settings keys are ignored** (`lexe config`), so preferences can grow.
- **New Tux32 baselines are additive.** `tux32-core-1` is never redefined; a newer
  baseline gets a new id, and a package declares which contract it targets.
- **The runtime version is not a gate.** Nothing keys behavior off the runtime
  version string; compatibility is decided by the package format and the baseline.

## What this Alpha explicitly does not promise

API/ABI stability of the C++ internals; on-disk stability of internal records
beyond FORMAT-0.1; the runtime version number across Alphas; or any interface not
named a promise above. See [ALPHA.md](ALPHA.md).

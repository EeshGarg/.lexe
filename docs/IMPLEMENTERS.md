# Implementing `.lexe` in another language

> **Informative.** This is a reading path, not a new specification. The normative
> documents it points at are the contract; where this guide and a normative
> document disagree, the normative document wins.

`.lexe` is a language-neutral format. You can implement a conforming **verifier**,
**builder**, or **runtime** in any language by following the specifications below
— the C++ reference implementation in `src/core/` is one implementation, not the
definition. Start with the product overview in [../SPEC.md](../SPEC.md).

## What you might build

| You want to… | Read, in order | Reference code |
|---|---|---|
| **Verify** a package | FORMAT-0.1 §1–§6 | `src/core/{package,crypto,verify,manifest}.cpp` |
| **Build & sign** a package | FORMAT-0.1 §1–§5, §8 | `src/core/{package,crypto}.cpp`, `src/cli` `build`/`pack` |
| **Run** packages (a runtime) | all of FORMAT-0.1, [TRUST-MODEL.md](TRUST-MODEL.md), [ISOLATION.md](ISOLATION.md), [CONCURRENCY.md](CONCURRENCY.md) | `src/core/{installer,launcher,isolation,registry}.cpp` |
| **Verify Tux32 Core 1 portability** | [TUX32.md](TUX32.md) + `sdk/tux32-core-1/profile.json` | `src/core/{elf,depengine,tux32}.cpp` |

## The container (FORMAT-0.1 §1–§3)

A `.lexe` is a deterministic ZIP: a `lexe.json` manifest (§5), a `payload/` tree,
and `metadata/hashes.json` mapping every payload path to its SHA-256 (§3). Entry
names are constrained (§2) — enforce those rules **before** extracting anything
(no absolute paths, no `..`, no backslashes, no symlink escapes).

## Verification (FORMAT-0.1 §6 — the normative order)

Implement the pipeline in the specified order; stop at the first failure and
trust no bytes until it passes:

1. Open the container and enforce the §2 entry rules.
2. Parse `lexe.json` (§5) and `metadata/hashes.json` (§3) with a strict parser
   (reject duplicate keys; bound the input size).
3. Recompute the SHA-256 of every `payload/` entry and match `hashes.json`.
4. Verify the Ed25519 signature over the **exact bytes** of the signed content
   using the publisher key from the manifest (§4).

## Signatures and keys (FORMAT-0.1 §4)

Publisher keys are encoded `ed25519:` + unpadded/padded base64 of the 32-byte
public key (§4 "Publisher key encoding"). Signatures are detached Ed25519 (RFC
8032) over exact bytes. A valid signature proves consistency with a **key**, not a
real-world identity — see [TRUST-MODEL.md](TRUST-MODEL.md); do not present it as
identity verification, and reject a package whose bound key changed for an
installed App ID (there is no authenticated key rotation in this line).

## The manifest (FORMAT-0.1 §5)

`lexe.json` is UTF-8 JSON, no BOM, with `lexeVersion` `"0.1"`. Unknown fields are
ignored for forward compatibility; required fields and their validation are in
§5. Version ordering for updates is the semver-lite total order in §8.

## Tux32 Core 1 portability ([TUX32.md](TUX32.md))

The baseline is machine-readable in [`../sdk/tux32-core-1/profile.json`](../sdk/tux32-core-1/profile.json)
(pinned to the compiled definition by a test). To verify a package: read the
executable's ELF metadata (`DT_NEEDED`, `DT_VERNEED`), classify each dependency
(host-interface / bundle / forbidden / unresolved), and check that the package's
own glibc requirement — the executable plus every **bundled** library, not the
host libraries — stays within the ceiling. The typed verdict and its precedence
are documented in TUX32.md; `lexe sdk verify --json` shows the exact shape.

## Worked examples

Every step above is exercised end to end by real artifacts you can read and run:

- [../examples/](../examples/) — CLI, shared-library, and GTK sample projects.
- [`../sdk/tux32-core-1/reference-app/`](../sdk/tux32-core-1/reference-app/) — the
  reference package the portability proof carries across distributions.
- [`../scripts/portability-demo.sh`](../scripts/portability-demo.sh) — build →
  verify → package → install → sandboxed launch, in real containers.
- [TUTORIAL.md](TUTORIAL.md) — the same path with the CLI.

## Conformance

A runtime is **`tux32-core-1` conforming** when it provides the Core 1 host
interface (glibc ≥ 2.31, the loader, libgcc_s, the vDSO), the stated
kernel/isolation capabilities, and runs a conforming package's exact signed
artifact unchanged. A formal conformance test suite is a post-Alpha item
([ALPHA.md](ALPHA.md)); until then the reference runtime and
`scripts/portability-demo.sh` are the practical oracle.

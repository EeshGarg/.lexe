# Multi-Architecture (Multi-ISA) Packaging (design groundwork)

> **Status: design groundwork, not implemented.** This describes how `.lexe` will
> carry more than one instruction-set architecture (ISA). It introduces **no code
> and no package-format changes yet**. Sections are marked **Implemented**,
> **Planned**, or **Future**.

## Where things stand

A `.lexe` manifest already **declares** the architectures an application supports
*(Implemented — `architectures[]`, e.g. `["x86_64", "aarch64"]`)*, and the runtime
checks the host architecture against that list at install/update time
*(Implemented — verify stage 7 "compatibility" against `host_architecture()`)*.
The dependency engine reads **any** ISA's ELF metadata, so cross-architecture
analysis already works *(Implemented — `core/elf` maps `EM_X86_64` / `EM_AARCH64`
/ `EM_RISCV`, and the Builder's Architecture step lets a developer select more
than one)*.

What does **not** exist yet: a single package's `payload/` today holds **one**
architecture's binaries. Declaring `["x86_64", "aarch64"]` does not make the
payload runnable on both — it only records intent. Multi-ISA packaging closes
that gap.

## Two shapes

*(Planned.)* Two complementary approaches, matching the runtime profiles:

1. **Universal package** — one `.lexe` that carries per-architecture payloads and
   the runtime installs the subtree matching the host. Simplest for the user
   (double-click, it just works), larger download.
2. **Downloadable native variants** — a base package plus per-architecture
   payloads fetched at install time for the host ISA. Smaller base, needs a
   source at install; a natural fit for the Forward Runtime / repository future.

Both keep the security model intact: every per-architecture payload is hashed and
signed exactly as a single-architecture payload is today; nothing is trusted
before verification.

## Format direction

*(Planned — illustrative, not final.)* A per-architecture payload layout keeps the
container self-describing without a new trust surface:

```
payload/                 # shared, architecture-neutral files (data, assets)
payload-x86_64/          # architecture-specific binaries
payload-aarch64/
```

At install the runtime selects `payload-<host-arch>` (falling back to `payload/`
for a universal script/interpreted app), extracts it exactly as it extracts a
single payload today, and the existing per-file hashes + signatures cover it. The
manifest's `architectures[]` remains the declared set; a package is installable
when the host arch is present. No new signing or trust concepts are introduced.

## How the pieces extend

| Step | Today | Under multi-ISA |
|---|---|---|
| Declare architectures | `architectures[]` *(Implemented)* | unchanged |
| Detect a binary's ISA | `core/elf` machine mapping *(Implemented)* | per-payload, one analysis each |
| Dependency + compatibility analysis | one graph *(Implemented)* | one report **per architecture** |
| Builder architecture selection | multi-select *(Implemented)* | each ISA maps to a source directory |
| Pack the payload | single `payload/` *(Implemented)* | per-architecture payload subtrees *(Planned)* |
| Install | extract `payload/` *(Implemented)* | extract `payload-<host-arch>` *(Planned)* |

The Builder's Architecture step is the natural authoring surface: the objective's
design already anticipates "each architecture may use a different source
directory." The build report would then carry **one dependency/compatibility
section per architecture** rather than one overall.

## Non-goals (for now)

- Single-architecture payloads remain the only implemented shape.
- No new manifest or container fields are added yet.
- No emulation/translation (Box64/FEX/QEMU) — this is native per-ISA payloads
  only; translated execution is a separate, later concern.
- Nothing here changes the signing, trust, isolation, lifecycle, or concurrency
  guarantees.

## Relationship summary

- **The manifest** declares supported architectures (today).
- **Multi-ISA packaging** makes a package actually *carry* those architectures
  (planned), via per-architecture payload subtrees that reuse the existing
  hashing and signing.
- **The dependency engine** already analyzes each ISA's ELF, so per-architecture
  reports need no new engine.
- **Runtime profiles** distinguish a universal package from downloadable native
  variants.

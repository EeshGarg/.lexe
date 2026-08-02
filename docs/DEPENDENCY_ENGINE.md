# Dependency Engine (Phase 2 / DX3)

The dependency engine discovers, classifies, and reasons about an application's
native dependencies so the builder can recommend the right handling without the
developer understanding the internals. This document describes what is
**implemented today**; language-runtime resolution (Python/Java/Node/…) is an
extension point that is intentionally **not** implemented yet.

## Reading ELF directly (not `ldd`)

`core/elf.{hpp,cpp}` is a small, defensive ELF metadata reader. It extracts,
directly from the ELF structures:

- class (32/64-bit) and byte order;
- object type (executable / shared object / …) and machine (`x86_64`,
  `aarch64`, `riscv64`, …), mapped to a `.lexe` architecture string;
- the program interpreter (`PT_INTERP`);
- the dynamic linking info: `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, `DT_RUNPATH`;
- versioned symbol requirements from `DT_VERNEED` (e.g. `GLIBC_2.34`).

It deliberately does **not** shell out to `ldd`/`readelf`: `ldd` can execute the
target binary's loader, and text-parsing external tools is fragile and
security-sensitive. Every field access is bounds-checked against the file
length, so a malformed or truncated file yields best-effort partial info and
never crashes, over-reads, or throws.

## Resolution and classification

`core/depengine.{hpp,cpp}` (`analyze_dependencies`) walks the dependency graph
from a root binary:

- **Resolution** is deterministic and read-only. Each `DT_NEEDED` soname is
  resolved against, in order: the payload search paths (the app's own bundled
  libraries), the object's `RUNPATH`/`RPATH` (with `$ORIGIN` expanded), and the
  host's default library directories (the multiarch triplet + `lib`/`lib64`). It
  never consults `LD_LIBRARY_PATH`, so results are reproducible.
- **Classification** assigns each dependency a typed handling:
  - **host-interface** — the core system runtime (glibc, the loader, libgcc_s,
    the vDSO). Present on every conforming host; must **not** be bundled.
  - **bundle** — an ordinary library. Recommend bundling it into the payload for
    portability.
  - **forbidden** — a host GPU/graphics/accelerator driver interface (`libGL`,
    `libcuda`, `libvulkan`, `libdrm`, …). Must come from the host (driver
    passthrough) and must **not** be bundled.
  - **unresolved** — a soname that could not be found anywhere; a warning.
  - **language-runtime** — reserved for the future extension hooks.
- The graph is **deduplicated** (each soname once, with all dependants
  recorded), **cycle-safe** (a visited set prevents infinite recursion; cycles
  are noted), and resolved bundle files are **hashed** (SHA-256).
- Versioned requirements are aggregated: `max_glibc_version()` returns the
  highest `GLIBC_x.y` across the whole graph, driving the compatibility
  analysis.

## Compatibility analysis

`core/compat.{hpp,cpp}` turns a dependency graph into an explained report: a
per-runtime verdict (UshaOS Core / Fedora / Debian / Ubuntu, each with a
documented glibc baseline) plus cross-cutting warnings that explain the issue —
newer glibc symbols, GPU driver passthrough, unknown dependencies, and
host-typical libraries bundled into the payload. See
[RUNTIME_PROFILES.md](RUNTIME_PROFILES.md).

## Using it

- CLI: `lexe analyze <binary | project-dir | payload-dir> [--json]
  [--profile <p>]`.
- Builder: Step 1 (Source) runs `detect_source`, which uses the engine to find
  the main executable + its dependency graph; Step 2 (Dependencies) shows the
  classified review.

## Extension point: language runtimes (not implemented)

`LanguageRuntimeHook` + `register_language_hook()` let a future contributor add
language-specific runtime resolution (Python, Java, Node, …) without touching
the core engine. No language is implemented in this phase; the registry is empty
and `analyze_dependencies` simply consults it.

## Limitations (this phase)

- Native (ELF) dependencies only; interpreted/language runtimes are not yet
  resolved.
- Runtime `dlopen`-ed plugins are not discoverable from static metadata.
- glibc baselines for the known runtimes are coarse, documented approximations,
  not a live probe of any specific host.

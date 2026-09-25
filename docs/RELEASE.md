# Release runbook — `.lexe` 0.1.0-alpha.1

> **Informative / operator runbook.** Everything the operator needs to cut the
> first Alpha. The tag is created by a human, not by CI or this document.

## Identity

| Field | Value |
|---|---|
| **Tag** | `v0.1.0-alpha.1` |
| **Release title** | `.lexe 0.1.0-alpha.1 — Tux32 Core 1 Developer Alpha` |
| **Target** | the reviewed `main` commit with green CI |
| **Pre-release** | **yes** (mark as a pre-release on GitHub) |
| **Runtime version** | `0.1.0-alpha` (`lexe version`) · Package format `0.1` · Baseline `tux32-core-1` |

## Release notes (draft)

The first Developer Alpha of `.lexe`: a signed Linux application format plus a
userspace runtime that verifies, sandboxes, installs, and launches desktop apps,
with a frozen cross-distribution portability contract.

- **Runtime** — verify → install → sandboxed launch → update → roll back → remove,
  in userspace; transactional installs + crash recovery; fail-closed launcher.
- **Security** — Ed25519 over exact bytes; hardened parser; permission consent;
  local trust-on-first-use.
- **Portability** — Tux32 Core 1, `lexe sdk verify`, the Builder's Core Portable
  gate, a minimal build-in-sysroot SDK, and an end-to-end cross-distribution proof
  in CI.
- **Developer & consumer experience** — the Builder wizard, `lexe analyze` /
  `build` / `inspect` / `apps` / `config`, grouped help, "did you mean"
  suggestions, and bash/zsh completion.
- **Both GUIs redesigned** — light and dark palettes following the system theme
  by default, drag-and-drop onto either window, a native file picker, and
  severity carried by tint, a leading bar and text colour together so a
  first-seen key can never read like a verified one.

Verified on the tagged commit: **495 test cases / 6681 assertions** on Linux
(GCC), **475 / 6540** on Windows (MSVC), the headless GUI smoke test, and the
end-to-end cross-distribution portability proof — all green.

Full detail: [../CHANGELOG.md](../CHANGELOG.md). What is and is not claimed:
[ALPHA.md](ALPHA.md). How to report a vulnerability: [../SECURITY.md](../SECURITY.md).

## Artifacts

**Source-only.** No prebuilt binaries are produced or published by CI, so the
release ships source only (see [ALPHA.md](ALPHA.md#release-artifacts)).

| Artifact | Name | Notes |
|---|---|---|
| Source archive (tar.gz) | `lexe-0.1.0-alpha.1.tar.gz` | GitHub auto-generates this for the tag. |
| Source archive (zip) | `lexe-0.1.0-alpha.1.zip` | GitHub auto-generates this for the tag. |

**Checksums** — after the tag is pushed, one command fetches the archives GitHub
generated for it and writes `SHA256SUMS` beside them:

```sh
scripts/release-checksums.sh v0.1.0-alpha.1      # -> dist/{*.tar.gz,*.zip,SHA256SUMS}
```

It downloads from the tag rather than running `git archive`, because the digest
published must be for the exact bytes the release serves — a locally produced
archive can differ in mtimes, compression and prefix, and would publish a
checksum nobody can reproduce. It fails rather than checksumming a 404 page if
the tag is not pushed yet, and it verifies both archives actually decompress
before writing any digest. Attach all three files to the release.

**SBOM** — the software bill of materials (vendored + runtime dependencies and
their licenses) is [SBOM.md](SBOM.md).

## Installation

Build from source and install per-user; see the README
[Quick install](../README.md#quick-install) (verified on Debian/Ubuntu, Fedora,
and Arch). No prebuilt binary install exists in this line.

## Known limitations

See [ALPHA.md § Known limitations](ALPHA.md#known-limitations). In brief:
Linux-only isolation (Windows is a build/test host); isolation needs a working
bubblewrap + user-namespace backend; Core 1 is dynamic x86-64 ELF only; trust is
local Tier 1 (no global revocation or authenticated rotation).

## Upgrade notes

This is the **first** tagged release — there is nothing to upgrade from. Future
Alphas may bump the runtime version independently of the package format (`0.1`,
stable for this line) and the Tux32 baseline (`tux32-core-1`, frozen). See
[COMPATIBILITY.md](COMPATIBILITY.md) for what is promised vs. an implementation
detail.

## Feedback

Report bugs, portability results, and packaging feedback via **GitHub Issues** on
the repository. Useful to include: your distribution + `lexe version`, the exact
command, and `--json` output where a command supports it. Contribution guidance
is in [../CONTRIBUTING.md](../CONTRIBUTING.md).

## Operator pre-tag checklist

Do all of these on the exact commit you intend to tag:

- [ ] `main` is the intended commit; working tree clean; `origin/main` identical.
- [ ] Hosted CI is green on that commit (linux, windows, portability).
- [ ] `./scripts/build.sh` passes locally on Linux; MSVC build + `ctest` pass.
- [ ] `scripts/gui-smoke.sh` passes; `scripts/portability-demo.sh` passes.
- [ ] `lexe version` prints `0.1.0-alpha`; README/ALPHA totals match the suite.
- [ ] All doc links resolve; no secrets or private keys in the tree; `LICENSE` present.
- [ ] Enable **private vulnerability reporting** (Settings → Advanced Security)
      — [SECURITY.md](../SECURITY.md) sends reporters to that channel, and it
      returns 404 until it is switched on.
- [ ] Create the annotated tag `v0.1.0-alpha.1`, push it, and publish a GitHub
      **pre-release** with the notes above and `SHA256SUMS` attached
      (`scripts/release-checksums.sh` produces it).

Nothing here creates the tag — that is the operator's explicit action.

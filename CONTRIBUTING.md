# Contributing to .lexe

Thanks for your interest. This guide gets you from a fresh clone to a green test
run, and points you at the rest of the platform. You should not need any external
explanation to build, test, and find your way around.

> **Licensing note.** `.lexe` is under a proprietary pre-release
> [LICENSE](LICENSE) while the signing and trust infrastructure is established
> (the stated intent is to relicense under the GPL). Per the license, a
> contribution submitted to this repository is assigned to the copyright holder —
> please only contribute work you are able to assign.

> **Found a vulnerability?** Do not open a pull request or a public issue for it
> — the PR itself discloses the weakness before there is a fix. Report it
> privately instead: [SECURITY.md](SECURITY.md) has the channel, what is in
> scope, and the documented non-guarantees that are *not* vulnerabilities.

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) covers what is expected in issues and
pull requests. It is short, and it is honest about the fact that enforcement
here is one person's judgement rather than a committee's.

## Build

The reference runtime is modern C++ (C++20). No network access is needed to
build — all dependencies are either system libraries or vendored under
`third_party/`.

**Linux** (full build, including the GTK apps). Prerequisites: a C++20 compiler,
CMake ≥ 3.22, Ninja, pkg-config, GTK 3, and libsodium — plus bubblewrap to run
apps locally. The following were each verified by a full source build (runtime +
both GUIs) in that distribution's container:

```sh
# Debian / Ubuntu
sudo apt install build-essential cmake ninja-build pkg-config libgtk-3-dev libsodium-dev bubblewrap
# Fedora
sudo dnf install gcc-c++ cmake ninja-build pkgconf-pkg-config gtk3-devel libsodium-devel bubblewrap
# Arch Linux
sudo pacman -S --needed base-devel cmake ninja pkgconf gtk3 libsodium bubblewrap
```

Then build (and run the full test suite):

```sh
./scripts/build.sh                 # configure + build + ctest
# or by hand:
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DLEXE_BUILD_GUI=ON
cmake --build build
```

- `libsodium` is the preferred Ed25519 provider on Linux (found via pkg-config);
  without it the build falls back to the vendored `orlp/ed25519`. `gtk3`/
  `libgtk-3-dev` builds `lexe-installer` and `lexe-builder`.
- The runtime's isolation uses **bubblewrap** (`bwrap`) at launch time; install
  it to exercise `lexe run` locally. On some distributions (e.g. Ubuntu 24.04+)
  unprivileged user namespaces must be enabled — see
  [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

**Windows** (MSVC, core + CLI; the GTK apps are Linux-only):

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

On Windows the Ed25519 provider is the vendored `orlp/ed25519` fallback (no
libsodium), and there is no runtime isolation — it is a development host.

## Run the tests

The test binary is `lexe_tests` (doctest). `scripts/build.sh` runs it via `ctest`.

```sh
./build/lexe_tests                       # the whole suite
./build/lexe_tests --list-test-suites    # what's available
./build/lexe_tests --test-suite=trust    # one suite
```

Real-binary integration scripts live in `tests/integration/*.sh` (Linux; they
drive the actual `lexe` CLI end to end). The GitHub Actions CI
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) builds and tests on both
Linux (GCC, GUIs) and Windows (MSVC) on every push.

**The bar: a change must keep the full suite green on both platforms**, and any
security-relevant change needs the evidence bundle in
[docs/HARDENING.md](docs/HARDENING.md) §I — MSVC-green alone is not Linux
validation.

## Find your way around

- [docs/README.md](docs/README.md) — the documentation index (start here).
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — the module map. Every `src/core`
  module has a one-line description and its proving test.
- `src/core/` — the platform; `src/cli/` — the `lexe` command surface;
  `src/gui/` — the GTK apps (each has a GTK-free, unit-tested "view model").
- `tests/` — one `test_<module>.cpp` per module.

## Conventions

- **One canonical implementation** per security-relevant concern (HARDENING §A) —
  don't duplicate verification, path handling, or JSON parsing. All
  security-relevant JSON goes through `json_strict` (duplicate-key rejection).
- **Tests are part of the change.** New behavior ships with a test that fails if
  it regresses. Prefer a focused `test_<module>.cpp`.
- **The GUI stays thin.** Presentation/validation logic lives in the GTK-free
  view model so it can be unit-tested without a display; GTK callbacks only wire
  widgets to it.
- **Truthful language.** Never claim a control is enforced when it isn't, or
  present a signature as real-world identity. See
  [docs/TRUST-MODEL.md](docs/TRUST-MODEL.md).
- **Terminology:** `.lexe` (the platform/format), the **Runtime** (`lexe`), the
  **Builder** (`lexe-builder` / `lexe build`), and a **Runtime Profile**.

## Commits and pull requests

- Write focused commits with a clear subject line; explain *why* in the body.
- Keep a PR to one reviewable concern where possible.
- Confirm the full suite is green on both platforms before opening a PR, and note
  any platform-specific validation you ran (e.g. a `tests/integration` script on
  Linux).
- The [pull-request template](.github/PULL_REQUEST_TEMPLATE.md) is filled in for
  you when you open one; its checklist is this project's actual bar, including
  the [HARDENING.md §I](docs/HARDENING.md) evidence bundle for a
  security-relevant change.
- Reporting rather than contributing? There are
  [issue forms](.github/ISSUE_TEMPLATE) for bugs, feature requests and
  portability results — the last of these exists because a result from a
  distribution nobody here runs is genuinely useful to this project.

# Contributing to .lexe

Thanks for your interest. This guide gets you from a fresh clone to a green test
run, and points you at the rest of the platform. You should not need any external
explanation to build, test, and find your way around.

> **Licensing note.** `.lexe` is under a proprietary pre-release
> [LICENSE](LICENSE) while the signing and trust infrastructure is established
> (the stated intent is to relicense under the GPL). Per the license, a
> contribution submitted to this repository is assigned to the copyright holder —
> please only contribute work you are able to assign.

## Build

The reference runtime is modern C++ (C++20). No network access is needed to
build — all dependencies are either system libraries or vendored under
`third_party/`.

**Linux** (full build, including the GTK apps):

```sh
sudo apt-get install -y build-essential cmake ninja-build libgtk-3-dev libsodium-dev
./scripts/build.sh                 # configure + build + run the full test suite
```

Or by hand:

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DLEXE_BUILD_GUI=ON
cmake --build build
```

- `libsodium` is the Ed25519 provider on Linux; `libgtk-3-dev` builds
  `lexe-installer` and `lexe-builder`. Both are optional to *run* the core, but
  the CI Linux job builds the GUIs.
- The runtime's isolation uses **bubblewrap** (`bwrap`) at launch time; install
  it (`sudo apt-get install -y bubblewrap`) to exercise `lexe run` locally.

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

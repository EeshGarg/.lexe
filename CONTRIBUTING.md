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

One entry point, and it needs no tribal knowledge:

```sh
./scripts/test.sh --list      # every lane, with availability resolved for THIS host
./scripts/test.sh --unit      # just the doctest binary
./scripts/test.sh --all       # the executable definition of a releasable build here
```

`--all` reports four outcomes, and the last two are not the same: **SKIP** means
"deliberately not applicable here", **BLOCKED** means "this applies, it is
expected to work, and this machine cannot show it". A blocked lane is never
counted as a pass. [docs/TESTING.md](docs/TESTING.md) is the full account,
including the lane table, the headless rule, and what this machine cannot prove.

To run one suite of the unit binary directly:

```sh
./build/lexe_tests --list-test-suites
./build/lexe_tests -ts=trust
```

The GitHub Actions CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml))
builds and tests on both Linux (GCC, GUIs) and Windows (MSVC) on every push.

**The bar: a change must keep the full suite green on both platforms**, and any
security-relevant change needs the evidence bundle in
[docs/HARDENING.md](docs/HARDENING.md) §I — MSVC-green alone is not Linux
validation.

### A defect is not fixed until a test reproduces it

The loop, in this order:

1. understand the root cause — not the symptom;
2. correct the implementation;
3. write a test that FAILS against the old behaviour;
4. watch it pass against the new one;
5. confirm the broader suite is still green.

A fix without step 3 is an assertion. And "it worked once" is not done: the alpha
installed and launched perfectly and then did not survive a reboot, which is why
persistence, repair and uninstall are treated as part of correctness and why
`tests/lifecycle/` interrupts operations on purpose.

## Find your way around

- [docs/README.md](docs/README.md) — the documentation index (start here).
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — the module map. Every `src/lexe`
  module has a one-line description and its proving test.
- `src/lexe/` — the platform; `src/lexe/commands/` — the `lexe` command surface;
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

## Decisions that are settled

These read as over-cautious until you remember what the alternative was. Each one
exists because the other way round was tried, or nearly shipped.

- **Truthful wording.** Nothing says "verified", "trusted" (unqualified), "safe"
  or "secure" on its own authority. An unavailable capability is shown as
  unavailable WITH a reason rather than omitted. The alternative is lying to a
  user about what a signature proves. `diagnostics/presentation` is the single
  source of that wording for every frontend.
- **The headless test rule.** No automated test may put a window on the user's
  screen. `tests/acceptance/lib.sh` severs the display for the whole harness;
  anything that must render brings its own via
  `scripts/lib/private-display.sh`, which cannot reach the real session even by
  mistake. See [docs/TESTING.md](docs/TESTING.md) §3.
- **One implementation of desktop registration.** `packaging/install.sh` calls
  `lexe integrate`; it must never hand-roll MIME XML again.
  `integration/desktop` is content generation only. There were once three copies
  and which registration a machine ended up with depended on which ran last —
  `tests/test_desktop.cpp` pins that the extra ones stay gone.
- **Fail-closed isolation.** A backend that should work but does not never
  degrades to an unconfined launch, and since the portable work, never to an
  unconfined *build* either.
- **Approval is not consent to everything.** `--approve-compile` is separate from
  `--yes`, from `--accept-permissions` and from `--trust`, for the same reason
  those three are separate from each other: each authorizes exactly one thing.
  Do not collapse them into a single "yes". In particular, **`--yes` must never
  imply compile approval.**
- **Mission-critical mode does not get broader.** Normal compatibility mode may
  grow all it likes. Mission-critical stays Linux-native, host-ISA-native, no
  Wine, no Proton, no ISA translation, no fallback. A contradictory manifest is
  refused at build time.
- **The dependency direction is one-way.** `lexe_engine` <- CLI, lexe-ui,
  lexe-builder, and never between frontends. `tests/test_architecture.cpp`
  enforces it by reading the tree, and [docs/CAPABILITY-MATRIX.md](docs/CAPABILITY-MATRIX.md)
  makes a second copy of a behaviour visible if one appears.

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

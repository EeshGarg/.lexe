# Changelog

All notable changes to `.lexe` are recorded here (format: *Keep a Changelog*).
Versioning follows [docs/ALPHA.md](docs/ALPHA.md): the **runtime** version is a
distinct axis from the **package format** (`0.1`, FORMAT-0.1) and the **Tux32**
baseline (`tux32-core-1`). Dates are UTC.

## [0.1.0-alpha.1] — 2026-08-26

The first tagged Alpha. Everything below is implemented and green on Linux
(GCC) and Windows (MSVC); items marked *(CI)* are additionally proven by a
GitHub Actions job. Source-only: there are no prebuilt binaries in this line,
and the support contract is [docs/ALPHA.md](docs/ALPHA.md).

Verified on the tagged commit: 493 test cases / 6665 assertions on Linux,
473 / 6524 on Windows, headless GUI smoke green, and the cross-distribution
portability proof green.

### Platform
- Signed `.lexe` package format (FORMAT-0.1): deterministic ZIP, Ed25519 over
  exact bytes, per-file SHA-256, strict hardened parser.
- Runtime lifecycle in userspace: verify → install → launch → update → rollback
  → remove; transactional installs with crash recovery; atomic version activation.
- Linux **bubblewrap** isolation (read-only image; private data/cache/temp;
  sanitized environment; network denied unless the `network` permission is
  granted); the launcher **fails closed** and never runs an app unconfined.
- Local **trust-on-first-use** publisher trust (key continuity, changed-key
  refusal, local block/unblock); permission-expansion **consent** gate.
- OS-backed concurrency: operation locks, launch leases, and the launch TOCTOU
  closure.

### Developer experience
- Automatic ELF dependency analysis (direct ELF reading; typed classification;
  glibc aggregation); compatibility analysis; runtime profiles; build report.
- `lexe analyze`, `lexe build`, and the graphical Builder wizard.

### Tux32 Core 1 — cross-distribution portability
- Frozen `tux32-core-1` baseline (dynamically linked x86-64 ELF, `x86-64-v1`,
  glibc symbol ceiling `2.31`); machine-readable `profile.json` pinned to the
  compiled definition by a test.
- Typed verification engine and `lexe sdk verify` (typed verdict and exit codes)
  that reuse the dependency engine — no second analysis path.
- The Builder **hard-gates** the Core Portable profile on Core 1; the build
  report carries the typed Tux32 verdict.
- Minimal build-in-sysroot SDK (`sdk/tux32-core-1/`) and a dynamically linked
  reference application.
- End-to-end cross-distribution proof, `scripts/portability-demo.sh` *(CI)*: one
  unchanged signed package build → verify → install → sandboxed launch across a
  real distribution boundary, plus the above-ceiling negative proof.

### Developer & consumer experience (final Alpha polish)
- `lexe inspect` — a human-first package inspector (identity, verification,
  dependencies, checksum; `--json` / `--manifest` for raw).
- `lexe apps` — the installed-application manager (version, publisher, disk
  usage, install date, last run, local trust; `--json`).
- `lexe config` + `src/core/settings` — persisted preferences (theme,
  update-check, developer mode, diagnostics); cosmetic only, never a security
  toggle.
- CLI polish: grouped example-rich help, terminal styling (TTY-only, NO_COLOR
  aware), friendlier errors with actionable hints, `lexe completion bash`/`zsh`.
- Builder: a first-run welcome screen (remembered) and staged build progress.
- Installer: an "After install" plain-language section (where it goes, how to
  remove it, what happens to data). install.sh / uninstall.sh get a banner,
  step progress, and an up-front preservation guarantee.
- Consumer errors read as "what happened / why / how to fix it" (e.g. the
  permission-expansion prompt).
- New docs: FAQ, Troubleshooting; new `examples/` (cli-tool, bundled-library).

### Alpha stabilization
- Centralized version metadata (`src/core/version.hpp`); `lexe version`
  (`--version` / `-V`), human and `--json`, reporting the runtime, package-format
  and Tux32 axes distinctly; the runtime version is shown in the GUI titles.
- Headless, warning-clean, markup-safe GUI smoke test, `scripts/gui-smoke.sh`
  *(CI)*.
- CI hardening: `scripts/build.sh` made executable; the `linux` job installs
  bubblewrap and the GTK SVG loader and enables unprivileged user namespaces so
  the real isolation-launch tests run; the `portability` job runs under rootless
  podman.
- `packaging/install.sh` and `packaging/uninstall.sh` made executable so the
  README's install step works on a fresh clone.

### Alpha acceptance fixes
Found by driving the documented paths end to end on a real Linux host, rather
than by reading the code:
- **A directory or FIFO handed to a package command no longer crashes or
  hangs.** `util::slurp` refused nothing but missing files, so a directory —
  which opens successfully and reports `INT64_MAX` as its size — ended in
  `lexe: std::bad_alloc`, and a FIFO blocked forever waiting for a writer. Whole
  file reads now require a regular file and read to EOF rather than trusting a
  seek (which also fixes reading unseekable `/proc` entries). `PackageReader`
  additionally fails **closed**: the 2 GiB package bound used to be skipped
  entirely whenever the size could not be determined.
- **`lexe analyze` reported the build host's glibc requirement as the
  application's.** `max_glibc_version()` aggregated across the whole dependency
  graph, so the host's own `libc`/`libm` internals (`GLIBC_2.36` on Ubuntu
  24.04) were attributed to the package — contradicting the Tux32 verifier's
  answer for the same binary in the same output, and making the compatibility
  verdict depend on the machine that ran the analysis. It is now the package's
  own requirement (root executable + bundled libraries), matching Tux32, so the
  CLI, the build report and the Builder all agree.
- **Actionable hints are now accurate.** Errors can carry their own hint, and
  the ones that were wrong were fixed: "no update source configured" said to
  re-check the path instead of naming `lexe source set`; a malformed
  `update.json` said to re-download the package instead of pointing at the
  FORMAT-0.1 §7 shape; `analyze`/`build`/`inspect` path errors and a rollback
  with no previous version all suggested `lexe apps`. The permission-expansion
  refusal no longer prints its fix twice.

### Alpha acceptance polish
- `lexe <command> --help` / `-h` and `lexe help <command>` now print that
  command's own summary and usage, instead of "unknown option" (exit 2) or the
  full banner.
- `lexe completion zsh`, alongside bash; both scripts are generated from one
  shared command/subcommand table so they cannot drift.
- `scripts/gui-smoke.sh` tolerates the `gdk_seat_get_keyboard` assertion a
  just-started virtual X server produces — verified environmental (a stock GTK
  window reproduces it 3/3 against a cold Xvfb; both GUIs are clean 8/8 against
  a warm one), so the race no longer fails CI.

### GUI acceptance fixes
Found by capturing what the GUIs actually render, rather than only checking that
they render without warnings:
- **The Installer opened with its primary action off-screen.** The `[Close]
  [Install]` row was packed at the bottom of the *scrolled* content, so at the
  default 520x640 window a package with ordinary detail pushed `Install` below
  the fold — an installer whose install button you had to go looking for. The
  action bar is now pinned below the scroller and is visible on open.
- **A line came up highlighted for no reason.** Body labels are selectable so a
  fingerprint can be copied, and GTK's `gtk-label-select-on-focus` therefore
  made the first one select all of its text the moment the window opened. Turned
  off in both GUIs; the labels stay selectable by hand.
- **"Install size not specified"** where the size is knowable. The Installer
  showed the manifest's estimate or nothing, while `lexe info` falls back to the
  real uncompressed payload size. The Installer now applies the same fallback,
  so the CLI and the GUI cannot disagree about how much space an install takes.

### Test-fidelity fixes
- **The GUI smoke test was not headless on any Wayland host.** With
  `WAYLAND_DISPLAY` set — every WSLg session and most current desktops — GTK
  prefers Wayland and connected to *that*, silently ignoring the virtual X
  server `xvfb-run` had just created: the test passed while the GUIs rendered on
  the developer's real desktop. It now unsets `WAYLAND_DISPLAY` and pins
  `GDK_BACKEND=x11` before anything launches.
- **The smoke test now asserts each GUI MAPS a window**, not merely that it
  emitted no warnings — the failure above produced no output at all and passed
  for exactly that reason. Verified against a negative control (a process that
  starts and shows nothing now fails the test). CI installs `x11-utils` for the
  `xwininfo` this needs.
- The remaining wrong hints were swept: a missing signing key now names
  `lexe keygen`, an unreachable update source names `lexe source set`, and
  "no ELF executable found" explains what the command accepts instead of
  suggesting `lexe apps`.

### One wording, every surface
The CLI and the GTK Installer each carried their own copy of the code that turns a
package into words. The copies had drifted, so the same package was described
differently depending on where you looked:

| Fact | CLI said | Installer said |
|---|---|---|
| `user-files-selected` | "Access to files you choose" | "Access to files you select" |
| Application type | `Native Linux - x86_64` (hyphen) | `Native Linux — x86_64` (em dash) |
| Install scope (system) | "System-wide" | "All users (system-wide)" |
| No update source | "No automatic updates" | "Updates are disabled for this package." |
| Install size, no estimate | real payload size | "Install size not specified" |

`lexe info` was a third voice again, printing raw permission ids
(`user-files-selected`) and its own type format (`native (x86_64)`) where every
other surface printed human titles.

- `core/presentation` — which already existed to be the ONE place both frontends
  render trust, permission and isolation text — now also owns size, application
  type, install scope, source and update-policy wording. Both frontends call it;
  neither formats these itself any more.
- Where the two disagreed, **SPEC.md's "Opening a .lexe File" mock is the
  tie-breaker**: the em dash and "Access to files you select" (which also matches
  the permission's own id, `user-files-selected`) win. The frozen vocabulary's
  title was corrected to match — a title is display text, not part of the
  permission-set digest, so no consent record changes.
- The Installer no longer carries its own permission list. It had eleven entries,
  **nine of which name permissions that do not exist in the 0.1 vocabulary** and
  can never be reached (a manifest declaring them is rejected at parse time).
  Permission wording now comes from the frozen vocabulary, so a permission cannot
  be added to the runtime without the GUI naming it correctly.
- New regression tests lock this shut: the GUI's formatters are asserted equal to
  `core/presentation`'s, and every id in the vocabulary is asserted to render
  through the GUI exactly as the vocabulary titles it.
- `lexe build` now reports the Tux32 Core 1 verdict it never used to mention, the
  way the Builder reports it at the same moment. Advisory — `lexe build` takes no
  runtime profile, so there is no portability claim to gate — but a developer
  building from the CLI no longer has to know to run `lexe sdk verify` to find out.

### The Installer could not grant a permission it asked you to grant
An update that requests a permission you have not approved before was a **dead
end in the GUI**. The Installer showed "New permissions this update requests
(separate approval required)", offered no way to give that approval, and never
set `allow_permission_expansion` — so pressing Install failed with "requests
permissions you have not approved for it: network", and pressing it again failed
identically. The only way through was to abandon the GUI and run
`lexe install --accept-permissions`.

The window now shows a **"Grant the new permissions listed above"** checkbox
directly beneath the list, unticked, and keeps **Install disabled until it is
ticked** — so the failure cannot be reached at all rather than being explained
after the fact. Consent stays a separate, explicit act: ticking the box is what
grants the authority, never pressing Install, which is the same rule the CLI
follows by refusing to infer `--accept-permissions` from `--yes`.

Verified end to end through the GUI alone: 1.0.0 installed, an update adding
`network` opened, Install inert until the box was ticked, then 2.0.0 installed.
The view model reports the expansion, and a regression test asserts it is flagged
when the set grows and not flagged when it does not.

Also: the Installer no longer opens with a **text caret blinking in read-only
prose** (a selectable body label took focus). Focus starts on Close — which also
puts the dialog's default where a consent dialog's default belongs, matching
`lexe install`'s `[y/N]` prompt.

### The changed-key refusal told users to do something that does not work
Refusing a package signed by a different key is correct and deliberate — a
rotated key is indistinguishable from someone else publishing under the same App
ID. But the refusal said to "remove the application and its data to accept a new
publisher", and **that alone does not work**: `lexe remove --purge-data` leaves
the local trust record in place, so the next install is refused identically. A
user following the instructions exactly ends up back where they started with no
indication why.

Verified end to end: remove + purge alone is still refused; adding
`lexe trust forget <id>` succeeds. The refusal now names both commands with the
App ID filled in, warns that it deletes the application's data, and points at
`lexe trust show` for the full fingerprints. TROUBLESHOOTING.md carried the same
wrong advice ("only proceed if you understand why the key changed", implying a
way to proceed that did not exist) and now documents the verified sequence. A
test asserts the message names the step that actually works.

The same correction reached both surfaces that show it:
- The Installer's changed-key screen printed ONE fingerprint — the key in front
  of you — with nothing to compare it against and no way forward offered. It now
  labels both, "Expected (already installed)" against "Presented (this package)",
  and carries a "What you can do:" section with the verified procedure.
- `lexe install` printed the whole details screen, including "Refused — the
  signing key has changed", and then asked "Install …? [y/N]" anyway. Answering
  y produced the refusal that had already been decided before the screen was
  drawn. It now refuses immediately after rendering, with the same typed error
  and exit 7.

Also in this pass:
- Both fingerprints in that message are five-group PREFIXES of the sixteen-group
  fingerprint every other surface prints, and nothing said so — an unmarked
  prefix next to a full fingerprint reads as a different key, which is exactly
  the comparison the user is making. They end in "…" now.
- `lexe build` refuses to build a package requesting a permission outside the
  frozen 0.1 vocabulary. Build, verify and info all accepted one, so a developer
  could ship a package that signs, verifies and inspects perfectly and fails for
  every user at install with `unknown permission "camera"`.
- `lexe info` labels the payload figure "Install size", since the header line
  above it already prints the .lexe file size and two unlabelled figures that
  disagree invite the reader to assume one is wrong.

### Final acceptance pass — Builder, Installer, integration
Structural:
- **The Builder's chosen runtime profile is now recorded in the package.** It
  was not, so every reader re-judged every package against Core Portable and a
  package deliberately built as Native Capture — host-locked *by definition* —
  came back from `lexe inspect` as a hard portability failure, from the same
  runtime whose Builder had just accepted it. `runtimeProfile` is an optional
  manifest field (FORMAT-0.1 §5), which is exactly the forward-compatible
  mechanism the format documents: older runtimes ignore it, and a reader that
  cannot resolve the value MUST treat the package as declaring none rather than
  substituting a default.
- **Source detection no longer freezes the wizard.** It walked the folder, read
  every ELF and resolved the whole dependency graph on the UI thread, so
  choosing a folder of any size locked the window — no spinner, no message,
  nothing repainting — until it finished. It runs on a worker now, with Next and
  Back disabled and a message naming what is happening.

Builder:
- **"Generate a new signing key" no longer destroys an existing key** (see
  above), and the result screen names the key file and says whether it was
  reused or created.
- A folder with **no runnable executable** no longer auto-selects the first file
  alphabetically as the entrypoint and builds a signed package around it.
- **"Open output folder" reported nothing when it failed.** Both error paths were
  discarded, so on a machine with no file-manager handler the button silently did
  nothing forever. It now says so and prints the path.
- Only the **selected** signing option stays live; both inputs used to be enabled
  with nothing to say which one the build would read.
- A **version advisory** for versions that can never be superseded: FORMAT-0.1 §8
  orders any string, so none is invalid, but one whose first component is not
  numeric sorts after every numeric version and every update to it is refused as
  a downgrade.
- "No shared-library dependencies (a static or script app)" was also printed when
  **nothing had been analyzed at all** — a missing executable reported as a clean
  bill of health.
- The Description field says what actually happens to it (stored as
  forward-compatible metadata; no 0.1 surface displays it).

Installer:
- **A heading over an empty body.** An unreadable package rendered "Authenticity
  & local trust:" above four blank strings. It now states which of the two
  situations occurred — the file could not be decoded, or the local record could
  not be read — since those are different facts.
- **The progress screen reports the stage genuinely running**, read from the
  transaction journal the installer already writes, plus elapsed time. No bar, no
  percentage, no ETA: the installer publishes phases, not byte counts, and a
  fraction would be fabricated.
- **Closing the window mid-install was an unsafe cancel** — `[X]` quit the main
  loop with the worker still writing into `.txn-staging`. It is now vetoed while
  an install is in flight, with the reason on screen, and closes normally the
  moment it finishes. A real Cancel needs a cancellation token through
  `core/installer`; inviting a mid-flight abort is the failure HARDENING §A
  exists to survive, not to encourage.

CLI and integration:
- `lexe verify` / `lexe inspect` **warn when local trust will refuse the package**
  install would reject — you were told a package was fine and then refused at
  install. The §6 verdict and every exit code are unchanged; the note is
  additive, and `--json` states it either way.
- **`Source:` labelled two unrelated facts** — the package path in the CLI, the
  packaging mode in the Installer. The CLI's are now `Package file:` and
  `Installed from:`.
- **`lexe integrate` claimed to register a handler it had not registered.** With
  `LEXE_HOME` set the files land in a tree no desktop scans; the command said
  "Registered the Lexe runtime as the .lexe handler" regardless. It now
  distinguishes writing the files from registering them, and explains why
  double-clicking a `.lexe` will not work plus how to fix it.
- `packaging/uninstall.sh` no longer claims to have removed things it did not:
  it counts removals, only refreshes databases that exist, and cleans up the
  confined copies too.

### The GUIs got a design
Both frontends rendered in whatever the GTK theme handed them: a flat run of
bold-label-then-text, controls at default proportions, severity carried by a
coloured word. They now share one stylesheet (`src/gui/style.hpp`), so they
cannot drift apart visually the way their wording once did.

- **Cards** group related facts, **a type scale** carries hierarchy (26px title,
  muted section labels, 14px body — GTK's uniform 11px is itself a period
  detail), and **one solid accent** marks the single primary action per screen.
- **Flat, not glassy.** A first attempt took "Aero" literally — gradient strips,
  a bordered gradient button, hairline borders — which are exactly the cues that
  date a window to the late 2000s. Depth is now a two-layer shadow; that is the
  only thing from Aero worth keeping.
- **Buttons are pills** with a hover transition, the primary one wider than the
  quiet ones beside it.
- **Severity is a style class, not a colour in markup.** Tint, a 4px leading bar
  and text colour move together, so the three states stay distinguishable
  without relying on hue — the entire point of that banner being that a
  first-seen key must not read like a verified one.
- **Light and dark palettes**, chosen at runtime. `Theme{System,Light,Dark}`
  with System the default; `apply()` is re-appliable so the theme can change a
  live window, and it pushes the resolved mode into GtkSettings so GTK's own
  chooser dialogs and menus follow rather than opening light out of a dark
  window. `System` asks the desktop three ways — the prefer-dark setting, a
  theme name ending `-dark`, and `GTK_THEME=…:dark` — because any one alone
  leaves some sessions rendering the wrong way round.
- The Builder's **first-run welcome screen** was restyled too. It had been
  missed, so a first launch still looked entirely unchanged, and its empty step
  strip and action bar are now hidden rather than drawn blank.

### Repository
- **A security policy** ([SECURITY.md](SECURITY.md)) that routes reports to
  GitHub's private advisory channel and states scope in this project's own
  terms — a threat-model row, an ISOLATION guarantee, or a FORMAT-0.1 §6 stage.
  Its out-of-scope list is the documented non-guarantees, so a restated
  limitation gets a link rather than a fix.
- **A code of conduct**, **issue forms** for bugs, features and portability
  results, and a **pull-request template** whose checklist is the bar this
  project already holds: both platforms green, a test that fails without the
  change, HARDENING §I evidence where security-relevant, and an explicit check
  that nothing is described as enforced where it is advisory. Blank issues are
  disabled so a security finding is steered privately first.
- **Dependabot** scoped to GitHub Actions only; the C++ dependencies are
  pkg-config system libraries or pinned `third_party/` sources reviewed by hand
  against [SBOM.md](docs/SBOM.md).
- The README leads with the interface rather than describing it: a hero
  screenshot, the four GUI captures in `docs/images/`, and a real captured
  `lexe verify` transcript showing all six pipeline stages by name.

### Fixed
- **The headless GUI smoke test raced its own timeout.** It allowed a window 10
  seconds to appear but ran the whole check under a 6-second `timeout`, so on a
  runner slower than 6 seconds to first paint it reported "never mapped a
  window" — an accurate message and a wrong conclusion, since it was measuring
  runner speed rather than the GUI. Six of the last seven CI failures on `main`
  were this, and none was a defect. The budgets are now explicit and ordered
  (`MAP_WAIT`, `DWELL`, outer timeout derived from both), and a pass no longer
  depends on the timeout firing: a GUI still running after the dwell is closed
  and reported clean, while one that exits on its own has its status propagated
  so a crash is still a crash. Locally the check went from ~18s to 5s while
  tolerating a startup four times slower than the old ceiling.

### Known limitations
See [docs/ALPHA.md#known-limitations](docs/ALPHA.md#known-limitations) — most
notably: Linux-only isolation (Windows is a build/test host), isolation requires
a working bubblewrap + user-namespace backend, Core 1 is x86-64 + dynamic-ELF
only, and publisher trust is local (Tier 1) with no global revocation or
authenticated key rotation.

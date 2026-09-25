# Session log

Newest session at the bottom.

---

# Session 1 — Definitive Architecture convergence

**Date:** 2026-09-24 · **Host:** Fedora 44, KDE Plasma (Wayland), x86_64
**Base:** `badf9f5` · **Head:** 11 commits later · **Tree:** clean

The task was to take the alpha implementation and make it converge on the
canonical *.LEXE Definitive Architecture* design reference — not to analyse it
or plan it, but to implement, build, run, debug and retest until the described
paths actually work on this machine.

---

## Starting state

The alpha was already a substantial runtime (~16k lines, 438 passing tests):
signed `.lexe` packages, a verification pipeline, transactional installs with
crash recovery, bubblewrap isolation, local trust-on-first-use, dependency
analysis, and two GTK frontends.

What it did **not** have was the Definitive Architecture's product layer. The
architecture document's own post-mortem (§13/§14) named the gaps precisely, and
each one became a work item:

| Alpha failure | Root cause | What was built |
|---|---|---|
| Worked, then broke after reboot | integration was session state, unrecorded | durable integration + `lexe doctor` |
| `helloworld.cpp` shipped as a native app | nothing checked bytes against the manifest | `payload-role` verification stage |
| The raw ELF became the desktop's problem | no first-class launch artifact | `run.lexe` launch references |
| Console app "looked like a failed launch" | presentation inferred, not declared | `launch.mode` + terminal policy |
| A failure was indistinguishable from success | errors were strings, not records | structured `.lexe-error` store |

---

## Commits, in order

### `bc9b17b` core: package role, execution policy, durable integration, structured errors

The foundation. Manifest gains `role`, `execution.{missionCritical,allowedChains}`
and `launch.{mode,singleInstance}`. New verification stage `payload-role`. New
core modules: `integration` (durable desktop state), `launchref` (run.lexe),
`execpolicy` (strict/normal resolvers + provider probing), `appconfig` (per-app
overrides), `diagnostics` (structured error store). `Paths` gains the XDG state
and config roots. The launcher was rewritten around the §7 flow. Display access
was added to the sandbox for a declared GUI launch mode.

A subagent migrated the test suite from shell-script entrypoints to real
compiled ELFs (the new stage correctly rejected the old fixtures) and added
`tests/test_payload_role.cpp`, 8 cases covering the exact alpha bug.

### `e2bbf47` cli: the handler, diagnostics and compatibility command surface

`lexe open` (role dispatch), `doctor [--repair]`, `errors`, `compat`,
`launch-ref`, `run --chain`, `integrate --verify`. Install and repair now
resolve the runtime/dependency contract once and record it (§16).

### `c5b20ab` tests: the execution model's architectural invariants

22 cases over the places where being subtly wrong would be invisible — roles
being structural rather than cosmetic, the strict resolver refusing to fall back
even when the user explicitly asks, preferences narrowing but never extending.

### `f09ee94` packaging: let the runtime own desktop registration

`install.sh` hand-rolled MIME XML and `xdg-mime` defaults in shell — a second
implementation that could silently diverge from the runtime's. It now installs
binaries and calls `lexe integrate`.

### `9d6d1c3` / `883ae82` docs

`docs/DEFINITIVE-ARCHITECTURE.md` (the implemented-state map) and the normative
manifest/pipeline additions in `docs/FORMAT-0.1.md`.

### `63b338f` trust: the §4 signer classes

All six classes implemented **including the two this runtime cannot establish**,
marked unavailable with reasons rather than trimmed from the list — omitting
them would let a user read "Developer Signed" as the top of the scale.

### `e19838c` docs(isolation): specify display access, and say what it costs

`ISOLATION.md` claimed GUI forwarding was unimplemented; it now is, so the doc
states exactly what is bound and what it costs (including that an X11 client
with socket access can observe input to other clients).

### `d865b50` docs(changelog)

### `252d87e` fix(integration): repair now restores icons instead of de-registering them

**A real defect in this session's own work**, found by the acceptance harness.
See "Bugs fixed" below.

### `40cf905` lexe-ui, the GUI example, the acceptance harness — headless test policy

Two subagents delivered `lexe-ui` (3.4k lines, 44 view-model tests) and
`examples/gui-hello` + `tests/acceptance/`. Plus the headless test policy after
the user added that rule mid-session.

---

## Bugs fixed

1. **`doctor --repair` destroyed icon registrations** *(mine, found by the
   harness)*. `repair()` looked for icons in the version directory, where they
   never were — install extracted them to a scratch dir and deleted it. So
   `install_app()` recorded zero icon artifacts and, because it replaces the
   app's whole scope, repairing one missing icon silently de-registered the
   other three: unrepairable, and not removed on uninstall. Root cause was that
   icons had no *installed state* to regenerate from, violating the
   architecture's own requirement. Icons are now retained in the per-version
   meta store and promoted atomically with the version. Plus a defensive fix so
   an artifact is never forgotten merely because it cannot be regenerated now.

2. **Typed exceptions were collapsed** *(mine)*. The error-recording helper
   turned `BlockedKeyError`/`CorruptTrustError` into the base `TrustError`.
   Frontends switch on those types. Now records and re-throws the original.
   Caught by two existing tests — they were right and the new code was wrong.

3. **`allow_terminal_spawn` defaulted to true** *(mine)*. A library call could
   open a terminal window behind its caller's back. Now opt-in; `lexe run` and
   the frontends opt in explicitly.

4. **A false claim in user-facing text** *(pre-existing, became false)*.
   `present_isolation()` said GUI forwarding was unavailable after it had been
   implemented.

---

## Verification performed

See `handoff/VERIFICATION.md` for the reproducible commands and outputs.

Headline results:

* **517 unit tests**, 6922 assertions, 0 failures (from 438 at session start).
* **All 4 acceptance suites pass**, with the display environment severed —
  which is itself the proof they were genuinely headless.
* **Real Fedora tooling agrees**: `xdg-mime` resolves a `.lexe` to
  `application/vnd.usha.lexe` and both that type and the legacy alias to
  `lexe-handler.desktop`; both generated desktop entries pass
  `desktop-file-validate`.
* **The real GUI window genuinely appears under the sandbox** — confirmed by a
  subagent three independent ways (KWin reporting it as a managed window with
  the sandboxed pid, a screenshot, and the bwrap argv).
* **The alpha's actual failure was reproduced and fixed on real state**: the
  user's machine had no persistent `.lexe` association at all, and an alpha-era
  app with no recorded integration. `doctor` named all three problems;
  `doctor --repair` fixed them.
* **Native steady state measured, not asserted**: the process tree is
  `lexe → bwrap → gui-hello`, `/proc/<pid>/exe` IS the installed entrypoint, and
  nothing matching FEX/Box64/QEMU/Wine/Proton appears.

---

## Subagents used

Three, sequentially bounded, each with a narrow brief (max 5 concurrent was the
limit; 2 ran concurrently at peak):

1. **Test migration** — moved fixtures to real compiled ELFs after the new
   verification stage correctly rejected shell-script entrypoints. Added the
   `payload-role` regression suite.
2. **`lexe-ui`** — the consumer frontend. Reused the existing installer's view
   model rather than rewriting it.
3. **GUI example + acceptance harness** — and found the icon defect above, which
   is the single most valuable thing any of them did.

---

## Things deliberately NOT done

* The architecture was not redesigned. Where implementation needed a decision
  the PDF did not make (e.g. the default `launch.mode`, where launch references
  live), the smallest choice preserving the architecture was taken and
  documented.
* No portable-code path was stubbed. It is absent and stated as absent, rather
  than half-present and misleading.
* No compatibility cruft. Superseded alpha artifacts (`lexe-installer`,
  `application-x-lexe.xml`) are removed on install rather than carried forever;
  the legacy MIME type survives only as a proper `<alias>`.

---

# Session 2 — 2026-09-25 — portable code, and one less engine

First session on the **new machine** (Windows 11 + WSL2 Ubuntu 24.04; see
[MACHINE.md](MACHINE.md)). Four commits.

## Before any feature work: a green baseline

The merge that moved the repository to this machine left the suite red: one
`desktop` test looked for `packaging/application-x-lexe.xml`, a file an earlier
commit had deliberately deleted when `packaging/install.sh` stopped hand-rolling
registration.

Chasing that one assertion found the real problem. `core/desktop.cpp` still
contained the **alpha's entire desktop-registration implementation** — it
planned files, wrote them, copied icons into the hicolor theme, refreshed the
freedesktop databases, and registered the runtime handler under
`application/x-lexe` with an `Exec=lexe-installer %f` line naming a binary the
packaging scripts now delete. Nothing in `src/` called any of it. Only its tests
did, which is exactly how a duplicated engine stays green while diverging from
the one that ships.

**`6748e44` — desktop: one implementation of registration, not two.** The
writing half is gone; what remains is the part `integration.cpp` actually calls
(`desktop_entry_text`, `mime_xml_text` — pure manifest→document functions). The
obsolete tests were replaced rather than deleted: the suite now pins that this
module writes nothing, that `packaging/` delegates to the runtime instead of
hand-rolling registration in shell, that `application/x-lexe` survives only as
an alias, and that registration under `LEXE_HOME` still writes nothing outside
it.

The excision also exposed a real regression from the convergence: the durable
engine refreshed the freedesktop caches even for a confined layout, building a
cache nobody reads and printing `update-mime-database`'s "not in the search
path" advice over `lexe integrate`'s own output — and over every test that
registered anything. The old module had skipped it deliberately; the new one
does too now.

## The gap itself: portable code and host-ISA compilation

Split into three commits so each one is a coherent, tested piece.

**`4c9c925` — the declarative half.** `applicationType: "portable"` and the
`build` block (FORMAT-0.1 §5.8), plus the `payload-role` stage for it. The
interesting decision here is what the stage demands: source under
`build.sourceDir`, and the declared entrypoint **absent**. A portable package
shipping a prebuilt entrypoint is the alpha's source-packaged-as-native bug told
backwards — the installed binary would be one this host never compiled — so
neither type can smuggle the other's payload past verification now.

Two smaller decisions worth knowing:

* `build.command` is an **argv**, never a shell string. A shell string is a
  second language between the manifest and `exec`, with its own quoting bugs.
* `build.toolchain` is **required and non-empty**. It is what lets the host be
  checked before an approval is sought, so a machine that cannot build the
  package names the missing tool instead of failing part-way through a compile.

**`d360bbb` — the engine.** `core/hostbuild.{hpp,cpp}` holds all four of the
architecture's properties in one place, because implementing three of them is
remote code execution with extra steps. The one that took the most thought was
the fourth-order consequence of the third: the compiled entrypoint is **not**
covered by the package's signed `hashes.json`, because it did not exist when the
package was signed. `NEXT-STEPS.md` had flagged this. The resolution:
`meta/<version>/build.json` records the product hashes, keyed exactly like
`hashes.json`, and the launcher **fails closed** when a portable application has
no recorded hash for its entrypoint. Skipping the check instead would have left
the binaries the runtime compiled itself as the only ones it never noticed being
replaced.

That record also forced an honest answer on repair: a portable entrypoint cannot
be copied back out of a package that never contained it, so repairing one
compiles again — behind the same explicit approval, because a repair command
must not silently build code.

Three decisions the design reference did not make, taken as small as possible
and documented:

* **"ADMIN COMPILE APPROVAL" with no administrator.** A per-user installation
  has no privileged authority to appeal to. Rather than invent one, the record
  says what the approval actually was: `authority: "user"`, meaning the owner of
  this installation authorized it. A system-scope install would need something
  else, and system scope is not supported in 0.1.
* **Mission-critical accepts portable.** Compiled here, for this ISA, verified
  before promotion is Linux-native + host-ISA-native + verified. The
  `linux_native` check became an explicit enumeration rather than a
  "not foreign" test, so adding a foreign-OS type is a compile error at that
  line instead of a silent default.
* **The build gets no network, ever.** A `network` permission describes the
  application, not its build. A build that downloads is fetching unsigned code
  at install time behind a signature that says nothing about it.

**`ec87e52` — the evidence.** `examples/portable-hello/` (ships `src/`, no
binary; the program reports `__DATE__`/`__TIME__` and its ISA from the
compiler's own macros, so the proof that it was compiled here does not come from
the runtime's bookkeeping) and `tests/acceptance/05_portable_compile.sh`, 47
checks including third-party witnesses (`unzip`, `file`, `sha256sum`) and the
fail-closed paths: no approval, no sandbox, tampered binary, missing build
record.

## What went wrong along the way

* The first `git` state on this machine was a **merge commit** whose two sides
  had diverged on desktop registration. Reading the failing test as "fix the
  assertion" would have preserved the duplicated engine. It was worth the hour.
* `compile_for_host` was first written to **throw** for every failure. That made
  it impossible for the caller to put the build's own output into the error
  record — which is the only thing that makes a failed compile diagnosable. It
  now returns a `CompileOutcome`, and the installer maps outcome → exception
  type, so "you did not approve this" (exit 5) and "this host cannot build it"
  (exit 3) stay distinct.
* The launcher's tamper message was reworded, which broke an acceptance
  assertion pinning the old phrase. The old phrase was better; it was restored.
  The harness did its job.

## Things deliberately NOT done, again

* **No GUI wiring for the compile approval.** `lexe-ui` and `lexe-builder` have
  no `--approve-compile` equivalent, so installing a portable package through
  them is refused with no way to say yes. That is listed in `NEXT-STEPS.md`
  rather than half-built: a consent dialog that does not exist is better than
  one that exists and is wrong.
* **No second ISA claimed.** Everything was built on x86_64. §15 of the
  architecture doc now says so, in the same breath as the FEX/Box64 gap.

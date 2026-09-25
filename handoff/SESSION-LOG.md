# Session log — Definitive Architecture convergence

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

# handoff/ — continuity for the next session

This folder exists so the next person (or agent) can pick `.LEXE` up cold
without re-deriving what happened or re-discovering the constraints of this
machine.

| File | Read it when |
|---|---|
| **[HANDOFF-PROMPT.txt](HANDOFF-PROMPT.txt)** | **Starting a new session.** Paste the whole file as the opening message. It carries the context, the current state, the hard constraints, and the next piece of work. |
| [SESSION-LOG.md](SESSION-LOG.md) | You want to know *what was done and why* — commit by commit, including the bugs found and fixed. |
| [VERIFICATION.md](VERIFICATION.md) | You want to *reproduce* the evidence, or you need to know what was NOT verified. |
| [NEXT-STEPS.md](NEXT-STEPS.md) | You are deciding what to build next. Prioritized, with entry points into the code. |

## The 30-second version

The alpha runtime was converged onto the canonical *.LEXE Definitive
Architecture* design reference (a PDF the user holds). Eleven commits added
package roles, an execution-policy resolver, durable repairable desktop
integration, first-class `run.lexe` launch artifacts, declared launch
semantics, structured diagnostics, per-application overrides, and the `lexe-ui`
consumer frontend — plus a GUI example and a scripted acceptance harness.

517 unit tests and 4 acceptance suites pass. The runtime is installed on this
machine and `lexe doctor` reports healthy.

Three things constrain work here and will bite you if you forget them:

1. **Automated tests must never open a window on the user's screen.**
2. **There are no git push credentials** — commit locally and tell the user.
3. **`sudo` needs a password** — `dnf install` is unavailable; `gdb` is not.

## Where the real documentation lives

This folder is *continuity*, not architecture. The architecture is:

* [`docs/DEFINITIVE-ARCHITECTURE.md`](../docs/DEFINITIVE-ARCHITECTURE.md) —
  what the runtime does, and §15 says plainly what it does not.
* [`docs/FORMAT-0.1.md`](../docs/FORMAT-0.1.md) — the normative container and
  manifest specification.
* [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) — module map and conventions.
* [`docs/ISOLATION.md`](../docs/ISOLATION.md) — the sandbox, including what
  display access costs.

## The one open item that needs a human

[`tests/acceptance/REBOOT.md`](../tests/acceptance/REBOOT.md) — the reboot
boundary and the two double-click paths cannot be automated. The GUI example
`com.usha.guihello` is already installed on this machine so the checklist can be
run as-is.

Persistence is part of correctness: the alpha worked on the first attempt and
then did not survive a reboot. Something working once is not done.

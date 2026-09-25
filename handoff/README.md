# handoff/ — continuity for the next session

This folder exists so the next person (or agent) can pick `.LEXE` up cold
without re-deriving what happened or re-discovering the constraints of this
machine.

| File | Read it when |
|---|---|
| **[MACHINE.md](MACHINE.md)** | **Before you try to build anything.** The development machine CHANGED: it is Windows 11 + WSL2 Ubuntu now, not the Fedora box the rest of this folder describes. Build commands, what is installed, and what this machine still cannot prove. |
| **[HANDOFF-PROMPT.txt](HANDOFF-PROMPT.txt)** | **Starting a new session.** Paste the whole file as the opening message. It carries the context, the current state, the hard constraints, and the next piece of work. Its paths and its "sudo needs a password" constraint are stale — MACHINE.md supersedes them. |
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

A later session (2026-09-25, on the new machine) closed four of the gaps that
convergence left open, so all three payload kinds now work end to end:

| Type | The payload is | Runs by |
|---|---|---|
| `native` | a compiled Linux ELF | running directly |
| `portable` | source code | being compiled on the machine that installs it, behind an explicit approval, inside the launcher's sandbox with the network denied, with the output verified as a host-ISA executable before anything is promoted |
| `windows` | a Windows PE | Wine or Proton — and a real Windows program really runs |

`launch.mode: "service"` also detaches for real now, and both graphical
frontends can approve a compile. Along the way it removed a duplicated
desktop-registration engine that had survived the convergence, and fixed a leak
in `lexe pack` that AddressSanitizer found the first time anyone ran it.

**636 unit tests and 6 acceptance suites pass**, and the suite is clean under
ASan + UBSan.

Three things constrain work here and will bite you if you forget them:

1. **Automated tests must never open a window on the user's screen.** WSLg
   makes this easier to get wrong: a GUI process started in WSL renders on the
   real Windows desktop.
2. **There are no git push credentials** — commit locally and tell the user.
3. **The machine is not the one this folder was written on.** Read
   [MACHINE.md](MACHINE.md) first. In particular the old "`sudo` needs a
   password, nothing can be installed" constraint no longer applies, and the
   "the runtime is installed on this machine, `lexe doctor` is healthy" claim
   below is about the *Fedora* machine and is no longer true here.

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
boundary and the two double-click paths cannot be automated. On the Fedora
machine the GUI example was already installed so the checklist could be run
as-is; **on the current machine it cannot be run at all**, because WSL has no
desktop session, no file manager and no reboot of its own. It needs a real
Linux desktop.

Persistence is part of correctness: the alpha worked on the first attempt and
then did not survive a reboot. Something working once is not done.

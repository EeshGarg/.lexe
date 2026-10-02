# Handoff — end of 2026-10-01 (second phase: uninstall and purge)

Where .LEXE stands, what is proven, and what the next session starts with.
Written to be read cold. Earlier handoffs are in git history (`7d7c318`,
`29d230b`).

## Current commit

**`91439b9`** is the evidence commit: the full run below was taken there,
from a clean tree. The handoff commit after it changes only this file. No
stashes. Checkpoints `28d209d` and `8cd909d` are preserved, untouched.

## Verdict

**x86-64: green, from one immutable run at `91439b9`.** `scripts/test.sh --all` at `91439b9`: **15 passed, 0 failed, 0 skipped, 0
blocked**, exit 0, tree identical before and after (HEAD unchanged, 0
porcelain lines, no `EVIDENCE INVALID`). Unit 775/775 and the same 775 under
ASan+UBSan; all 12 acceptance scripts; 3 integration scripts.
Log: `../lexe-run-evidence/full-run-91439b9-rerun.log`.

**Resources — read this before citing the run.** Meter (tree, 0.5 s samples):
peak RSS **2002 MiB (48%)**, peak CPU **48.7%** — within budget. An external
per-second host-wide timeline ran beside it
(`../lexe-run-evidence/full-run-91439b9-rerun.cpu-*`): **one second of 3190**
above 50% (90.9%, ~8 s into the explore lane, where its first parallel engine
starts at the lane's hard-coded `JOBS=8`); worst 10 s / 30 s / 60 s averages
**24.6% / 19.6% / 18.4%**. The tree meter misses it because processes that
start and exit between its samples are invisible to a tree walk. A FIRST run at
the same commit was flagged by the meter at **69.6% peak** ("OVER BUDGET ... at
peak"); it is kept as `full-run-91439b9-OVER-BUDGET-cpu69.6.log`, NOT cited, and
the rerun is what established the timeline. The policy bounds *sustained*
utilization (TESTING.md §10) and defines no window; by any window of 10 s or
more this run is under half the limit. Whether a one-second burst counts is a
policy question left open, not settled here — and if it does, the lever is
explore's `JOBS`, which can only go down.

**Developer Preview: NOT READY.** Every remaining gate is external, and the
first one needs a person: the ARM64 tablet is physically disconnected
(`adb devices` empty; `scripts/arm-worker.sh probe` → `INFRASTRUCTURE no device
attached`). That is **BLOCKED: PHYSICAL DEVICE DISCONNECTED** — not failed, not
skipped. See *First actions*.

## Uninstall and purge — implemented this phase (`671ab31`)

`lexe remove` (three modes) is replaced by two commands:

* **`lexe uninstall <id>`** — remove the installed program. Keeps a fixed,
  documented list: local trust record, persistent data, compatibility
  preferences, error history. A reinstall is a **returning** one.
* **`lexe purge <id>`** — make .LEXE forget the application, whether or not it
  is still installed. A reinstall is a **first** install.

The contract is one table (`src/lexe/state/appstate.cpp`), reproduced word for
word in `docs/REFERENCE-POLICY.md` "Uninstall and purge" (a unit test fails if
they drift). It states the invariant: *after a successful `lexe purge A`, no
.LEXE-managed state associated exclusively with A can affect a later
installation, verification, authorization, configuration or execution of A.*

* **Trust is per App ID.** One record binds one App ID to one key; there is no
  publisher- or key-wide trust. Purging A cannot reach B's trust even when B
  shares A's key and A's App ID is B's prefix.
* **Purge is transactional and fails closed**: running apps refused before
  anything is written; journal `apps/.removing/<id>.purge` first; atomic detach;
  trust record deleted first; post-check before success. While unfinished,
  `install` and `purge` finish it; launch, `uninstall` and trust mutations
  refuse (6). It never reports success over remaining state.
* **Ownership boundary**: purge never touches files outside .LEXE's own storage,
  and refuses (does not delete) a recorded path outside the runtime's tree.
* **`lexe remove` is retired, not aliased** — exit 2 naming both replacements,
  because `remove --purge-data` kept the trust record and `purge` deletes it.
* **Decided by this change, stated rather than implied:** purge removes a local
  **block** too (it follows from "forget this application"; the prompt says so).

**Evidence.** `tests/test_purge.cpp` — the five cases asked for, at the installer
API, each with an independent walk of LEXE_HOME; interruption at four failpoints
recovered both ways; a valid trust record written back mid-purge must yield
failure, not success; an undeletable trust record fails closed. **12 mutants,
all killed**, each by the case built for it. `tests/integration/uninstall_purge.sh`
— the real binary, observed through the install PREVIEW ("explicitly trusted by
you" after uninstall, "first seen" after purge) and B's `trust show`
byte-identical across A's purge. `tests/lifecycle/02_interrupted.sh` §8b — real
SIGKILLs at the journal's appearance and the trust record's disappearance. The
explore model pins the new semantics (the "does purge discard the binding?"
cell it left UNDERSPEC yesterday is decided): 0 divergences.

One harness rule changed, narrowly: `lc_assert_coherent` required every
installed app to RUN, stricter than FORMAT-0.1 §9.2 ("launchable, or report
honestly"). Only while a purge journal exists, it now requires intact files AND
an exit-6 refusal naming the purge AND nothing executed — proven against three
controls (intact: pass; entrypoint gone: fail; launcher ignoring the purge:
fail).

## Open question (recorded, not decided)

**Should permission approval survive an uninstall?** FORMAT-0.1 §9.5.1 says
approval persists across "reinstall by the same publisher key". Approvals live
in the installation record, which uninstall removes — so they do not survive an
uninstall, and did not before this change either. This runtime meets §9.5.1 for
a reinstall over an existing installation. If §9.5.1 means reinstalling after an
uninstall, that is a gap in this runtime, recorded in REFERENCE-POLICY rather
than settled by reading the sentence narrowly. Deciding it either way is a
product decision: if approvals should survive, they become a fourth
SurvivesUninstall location in the table.

## Earlier on 2026-10-01: the five reds of 2026-09-29, resolved

None of them was caused by `45704e1` (healing installs return 0), which the
previous handoff named as the leading suspect. Checking it rather than
believing it was the right call.

| Lane | What it really was | Class | Fix |
|---|---|---|---|
| lifecycle `02_interrupted` | `uninstall` deleted `apps/<id>` with one `remove_all`, in readdir order. A SIGKILL between `versions/` and `installation.json` left an app listed as installed at a version with no directory — FORMAT-0.1 §9.2 violation, HARDENING §C.9. **6 of 12** runs, idle or loaded. | IMPLEMENTATION | `606b439`: rename `apps/<id>` → `apps/.removing/<id>` (atomic), then delete; swept by the next mutation. **0 of 12** after. Unit failpoint `uninstall-after-detach`; mutant with the old order fails 5 assertions. |
| integration `ws3_ws4` | Step 2 piped `y` into a prompt that, by REFERENCE-POLICY §4 (2164dd9), refuses pipes (exit 5) — and never checked the exit, so 8 downstream assertions failed instead of one. | TEST | `1861c1c`: answer from a regular file; assert install exit codes; keep the pipe as an explicit exit-5 negative. Two mutants killed. |
| workloads | Not "corpora absent". `test.sh` prefers `$HOME/lexe-workloads*` (since `4a1d275`), which survives WSL restarts. The `$HOME` ELF corpus held a baseline recorded through `private-display.sh` the day before A2's fix: 138 bytes of the wrapper's own "Segmentation fault" line as the specimen's stderr. A2 stays closed. | HARNESS PROVENANCE | `6d8b851`: generators record `baseline_harness`; the engine refuses a corpus made by other generator/wrapper code (exit 4 → lane **BLOCKED**, not FAIL). Corpora regenerated. |
| explore | 2 divergence groups at seed 20260929 reproduce exactly (3000 seq / 21681 ops). Both: install → remove → remove; runtime says 6 ("this machine removed it earlier", dbbd625), model pinned 4. | STALE MODEL + DOC GAP | `09dbde0`: model pins 4 never-installed / 6 removed-with-data / UNDERSPEC after purge; ERRORS.md §6 records dbbd625. 0 divergences after; mutant fires. |
| evidence | Partly the HANDOFF.md edit mid-run — and partly `docs/ALPHA.md` already publishing 761 cases when the suite had 762. | DOC | `17072f9`: totals from an observed run. |

## Defects found in the test machinery itself

* **The resource meter changed what it measured** (`e6ffef9`). `"$@" &` in a
  non-interactive bash ignores SIGINT/SIGQUIT in the child and points stdin at
  `/dev/null`. A SIGQUIT specimen exited 0 under the meter. The 09-29 clean run
  was metered, so every lane in it ran that way. Fixed and checked against
  direct execution (signals, stdin, the specimen, and a caller's own ignore).
* **A missing ELF corpus was recorded SKIP** ("not applicable") with a stray
  `corpora:` line as the reason (`b760f2c`); and the corpora line itself was
  never shown on a passing check.
* **A BLOCKED lane whose summary said "0 blocked"** (`9342622`).
* **`lc_complete_install` still accepted exit 6**, keeping 45704e1's misreport
  legal in the lane built to provoke it (`f4723bb`).
* **HARDENING.md claimed "any lexe command sweeps stale staging on startup"**.
  Nothing does; `recover_all` has no production caller. Corrected (`606b439`).
* **A roster entry blocking a PE specimen on a reason the corpus no longer
  supported** (`8cd909d`). The proton-wine hang it descended from is still
  Open in README-PE — 1 in 35 observations now, which is not proof it is gone.

## Resource policy

Unchanged limits (docs/TESTING.md §10). Measured today, all with the fixed meter:

| Workload | Peak RAM | Peak CPU |
|---|---|---|
| `test.sh --all` at `09dbde0` | 2687 MiB (65%) | 49.2% |
| `test.sh --all` at `8cd909d` | 2670 MiB (65%) | 48.7% |
| `test.sh --all` at `91439b9` (first) | 2447 MiB (59%) | **69.6% — flagged, not cited** |
| `test.sh --all` at `91439b9` (rerun, evidence) | 2002 MiB (48%) | 48.7% (1 s host-wide burst 90.9%; 10 s max 24.6%) |
| ELF corpus generation | 1241 MiB (30%) | 24.6% |
| PE corpus generation | 959 MiB (23%) | 14.9% |
| explore model, 3000 seq, jobs 4 | see `lexe-resource-evidence/explore-model-*.json` | |

Peak CPU at 48.7–49.2% is inside the limit with almost no margin; the meter now
samples every 0.5 s and sees shorter peaks than the 1 s sampling of 09-29.
Do not raise concurrency.

## Corpora

In `$HOME/lexe-workloads` and `$HOME/lexe-workloads-pe`, generated 2026-10-01
from `6d8b851`'s generators, under the fixed meter. ELF 201/201 baseline-ok,
PE 147 baseline-ok + 1 blocked (`pe-io-stdin-under-proton-run`: its only layer is not generated by default, so it has no baseline). **Any edit to `generate*.py` or `private-display.sh` makes
them stale by design** — the lane will then report BLOCKED with the command to
regenerate. On Windows with `core.autocrlf=true`, a checkout that rewrites
those `.py` files as CRLF would do the same.

## ARM64 worker — BLOCKED: physical device disconnected

Nothing changed in the transport or the scripts; nothing about ARM was run.
`scripts/arm-worker.sh` (`probe` exercised; `sync`/`build`/`levels` written,
never run) and `scripts/second-isa.sh` (never run) are as described in
`7d7c318`'s handoff, including the level-mapping self-audit.

## First actions next session, in order

1. Reconnect the tablet by USB, unlock it. `adb devices` must show
   `R52XA081A5Y   device`; accept the USB-debugging prompt if `unauthorized`.
   Termux `sshd` running. `adb forward tcp:8022 tcp:8022`.
2. `bash scripts/arm-worker.sh probe` — PASS through "termux ssh: reachable"
   and "debian guest".
3. `bash scripts/arm-worker.sh sync` — the worker must report the SHA you
   asked for (HEAD at that moment).
   A different SHA voids the evidence.
4. `bash scripts/arm-worker.sh build` — `file` must say `ARM aarch64`.
5. `bash scripts/arm-worker.sh levels 5` — 0–3 substantive; Level 4 measured,
   not assumed; Level 5 not applicable.
6. `bash scripts/second-isa.sh all` — package hashes must match on both hosts,
   or the experiment is void.
7. Final evidence audit, then the Preview decision.

## Evidence — do not delete

* `../lexe-run-evidence/` — full `--all` logs from today.
* `../lexe-resource-evidence/*.json` — metered peaks.
* `$HOME/lexe-workloads*.stale-20260928` (in WSL) — the stale corpora, kept
  until this handoff is read; they are what the provenance guard was proven
  against. Safe to delete afterwards.

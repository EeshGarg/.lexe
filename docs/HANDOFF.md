# Handoff — end of 2026-10-02

Where .LEXE stands and what tomorrow starts with. Written to be read cold.
Earlier handoffs are in git history (`7d7c318`, `29d230b`, `5bccec3`).

## Commits and where they are

| | |
|---|---|
| **Final HEAD** | the commit that adds this file (docs only); `git log -1` |
| **Tested code commit** | **`fb477f6`** — the last commit that changes code |
| **Full local evidence run** | `e6129d3` (see *x86-64*); `fb477f6` differs from it only by changes proven not to alter the Linux build (below) |
| **GitHub** | `origin/main` = local HEAD, verified with `git ls-remote` after the push, not from the push's own output |
| **GitHub CI** | Run 36968632887 on `fb477f6`: **linux ✅** (ctest 100%, GUI smoke maps windows), **portability ✅**, **windows ❌** — it now *builds*, but **20 of 751 unit tests fail**. Windows tests last passed in CI on 2026-08-27 (`54f3099`); the build was broken from 2026-09-25, so five weeks of changes never ran there. Includes 3 of tonight's purge walk cases and the retired-`remove` stderr check (same stderr-capture failure as every other Windows CLI-stderr test). Not worked through tonight — top non-ARM item. Docs-only commits after `fb477f6` trigger CI again and will show the same. |

Working tree clean, no stashes. Checkpoints `28d209d`, `8cd909d`, `91439b9` are
preserved.

## x86-64

`scripts/test.sh --all` at `e6129d3`, tree unchanged: **15 passed, 0 failed, 0 skipped, 0 blocked**, exit 0. Unit 777 / 10094 assertions (also under ASan+UBSan), 12 acceptance suites. Resources (new meter): peak RSS **1901 MiB (46%)**, **rolling 10 s CPU peak 20.3%** (policy limit 50%); one-sample peak 93.5% (explore start-up burst, informational); independent `/proc/stat` timeline agrees (worst 10 s 22.5%). `fb477f6` differs from `e6129d3` only by: the Windows guard move (Linux preprocessed `installer.cpp` byte-identical, sha256 f85a7959…), a Proton test now self-contained (passes with real and empty HOME; full unit 777/777 locally), and the CI portability script. Logs: `../lexe-run-evidence/full-run-e6129d3.*`.

## The two policy items closed today

**CPU budget — "sustained" is a rolling 10-second average.** The aggregate CPU
of the build/test tree averaged over any rolling 10-second window must stay
≤ 50%; a shorter burst may exceed it. RAM (≤ 4 GiB) has no window. The meter
(`scripts/resource-meter.sh`) reports and verdicts on that metric, prints the
single-sample peak as informational, and now counts reaped children's CPU
(it under-read a short-lived-process storm 9.9% vs 31.3%). Validated against
`/proc/stat` with a control that must fire (13 cores → 54.3%, OVER BUDGET).
docs/TESTING.md §10.2a.

**Permission approvals — FORMAT-0.1 §9.5.1, implemented as written.** Approval
persists across reinstall by the **same publisher key** and is discarded by
purge. Uninstall saves the approved set with the key that received it
(`approvals/<id>.json`); a fresh install inherits it only for the same App ID
and the same key, merged with what it requests. Another key, another App ID's
record, a symlink, a duplicate-key file: nothing is granted. 6 mutants, all
killed (`tests/test_purge.cpp` CASE 6/6b).

## Uninstall and purge

* **`lexe uninstall <id>`** — removes the program, its integration and debris.
  Keeps: persistent data, the trust record (incl. a local block), permission
  approvals (same key only), compatibility preferences, error history. A
  reinstall is a returning one.
* **`lexe purge <id>`** — .LEXE forgets the application, installed or not. A
  reinstall is a first install. Transactional and fail-closed (journal first,
  post-check before success; launch/uninstall/trust changes refuse while
  unfinished; install finishes it). Never touches files outside .LEXE's own
  storage.
* Trust is per App ID; purging A never touches B, even with the same key.
* `lexe remove` is retired (exit 2, names both).
* Contract: one table, `src/lexe/state/appstate.cpp`, mirrored word for word in
  docs/REFERENCE-POLICY.md "Uninstall and purge"; a unit test fails if they
  drift.

## Fixed tonight because CI showed them (all pre-existing; CI had been red since at least 2026-09-26)

* **Windows build (MSVC C3861)** — `resolve_runtime_contract` sat inside a
  POSIX-only `#ifndef _WIN32` block by accident since `e2bbf47`. Moved out. On
  Linux the preprocessed `installer.cpp` (`g++ -E -P`) is byte-identical before
  and after, which is why e6129d3's full run still describes the Linux build.
* **Linux CI, 1 of 777** — a Proton discovery test read the REAL home and so
  needed Steam installed; it passed here and failed on the runner. Reproduced
  locally with an empty HOME, then made to arrange its own Steam layout.
* **Portability job** — Debian 11's `bullseye-security` pool now 404s (LTS
  ended); apt exit 100 before any .LEXE code ran. First fix (drop the suite)
  was wrong (held broken packages); now served from snapshot.debian.org pinned
  2026-09-01 — CI portability passes.

## Observations, not acted on tonight

* Orphaned Wine service processes from `generate_pe.py`'s proton-wine GUI prefix
  were still running ~10 h later (~3% CPU each). A generator hygiene leak;
  cleaned by hand.
* The explore lane's first parallel engine produces a ~1 s burst (90.9% host
  wide) at `JOBS=8`; no 10-second window comes near the limit, so JOBS is
  unchanged.

## ARM64 — BLOCKED: PHYSICAL DEVICE DISCONNECTED

`adb devices` is empty; `scripts/arm-worker.sh probe` → `INFRASTRUCTURE no
device attached`. Nothing about ARM was attempted. Historical: commit `7f82fe4`
was built and run natively on the tablet — not evidence for current code.

## Developer Preview: NOT READY

Remaining gates, all needing the tablet: current-code AArch64 evidence, the
same-package second-ISA experiment, a final evidence audit.

## First action tomorrow

1. Connect the tablet (SM-X610) by USB and **unlock** it. `adb devices` must
   show `R52XA081A5Y   device` (accept the USB-debugging prompt if it says
   `unauthorized`).
2. In Termux on the tablet, start `sshd`.
3. `adb forward tcp:8022 tcp:8022`
4. `bash scripts/arm-worker.sh probe` — PASS through "termux ssh: reachable" and
   "debian guest".
5. `bash scripts/arm-worker.sh sync` — the worker must report exactly the SHA
   you asked for (sync the tested code commit `fb477f6` or HEAD); any other
   SHA voids the evidence.
6. `bash scripts/arm-worker.sh build` — `file` must say `ARM aarch64`.
7. `bash scripts/arm-worker.sh levels 5` — Levels 0–3 substantive; Level 4
   measured, not assumed; Level 5 not applicable.
8. `bash scripts/second-isa.sh all` — the same signed portable-source package on
   x86-64 and AArch64; package hashes must match or the experiment is void.
9. Final evidence audit, then the Developer Preview decision.

## Evidence — do not delete

* `../lexe-run-evidence/` — full-run logs and CPU timelines.
* `../lexe-resource-evidence/*.json` — metered peaks.

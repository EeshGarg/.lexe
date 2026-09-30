# Handoff — end of 2026-09-29

Where .LEXE stands, what is proven, and what tomorrow starts with. Written to
be read cold: nothing here assumes you remember yesterday.

## Current commit

**`28d209d`** — *arm: key-only transport, and levels that account for every
suite*. Working tree clean, no stashes.

Preserve `28d209d` as today's known-good checkpoint. A wrap-up commit may
follow it; that does not change which commit is the checkpoint.

## The clean-run result

See *Clean run* at the end of this file — it is recorded there after the run
finished, rather than predicted here. If that section says a lane failed, the
failure is documented and **was deliberately not repaired tonight**.

An earlier 15-lane attempt was **VOIDED by the evidence guard**, correctly:

> EVIDENCE INVALID: the tree changed underneath this run … some lanes ran
> before that write and some after, so this run describes no single tree.

Source files were being edited while it ran. The guard did exactly its job.
The rule it teaches is worth keeping: **do not touch tracked source while a
lane run is in flight.** `docs/` is exempt from the fingerprint by design, so
writing this file during a run is safe; nothing else is.

## Resource policy

The limits (docs/TESTING.md §10) are now **enforced, not merely documented**:

| | |
|---|---|
| WSL2 ceiling | `memory=4GB`, `swap=2GB`, `pageReporting=true` in `~/.wslconfig` |
| Verified after restart | `MemTotal` **3912 MiB** (was 15544) |
| Ordinary build concurrency | **-j6**, derived from the RAM budget, not `nproc` |
| Sanitizer build concurrency | **-j3** |

Three defects were found in the policy itself today, all in work written the
same day:

1. **The full stack exceeded the budget** — measured peak **4143 MiB, 101%**.
   The meter flagged it; a point-in-time sample had not.
2. **A documented sanitizer limit that nothing implemented.** §10.1 promised
   sanitizer builds their own lower concurrency; `test.sh` gave them the
   ordinary `-j6` — the number derived from the cheapest translation units,
   applied to ASan's most expensive. Now `-j3`, with the multiplier honestly
   labelled **not yet measured** rather than fabricated. When it is measured,
   switch it to the same budget arithmetic `JOBS` uses.
3. **Nothing enforced the cap.** No `.wslconfig` existed, so WSL2 was entitled
   to ~8 GiB. A 4 GiB limit under an 8 GiB ceiling is a wish.

The meter's CPU metric was also wrong — it summed `ps -o pcpu`, a process
*lifetime average*, and reported `107.1% of 24 CPUs`, which is not a possible
number. It now differences `utime+stime` from `/proc/<pid>/stat` between
samples. Re-validated against known loads: 12 of 24 cores → 51.5%, 6 → 25.5%.

Measured costs, for planning tomorrow:

| Workload | Peak RAM | % of budget |
|---|---|---|
| Clean build `-j6` | 2917–2938 MiB | ~71% |
| Corpus generation | 1607 MiB | 39% |
| Workloads ELF lane | 1384 MiB | 34% |
| Unit suite | 1545 MiB | 37% |

Compilation is **memory-bound, not CPU-bound**, on this machine. Do not raise
concurrency because CPU looks idle.

## Findings closed today

**A1 — launcher stdio shape. REAL, FIXED.** The runtime substituted pipes for
the caller's streams. With `stdout` a regular file: direct gives
`regular`/seekable, `.LEXE` gave `fifo`/not-seekable. With fd 1 **closed**:
direct gives `closed` and `EBADF`, `.LEXE` gave `fifo` and told the program the
write **succeeded**. Cause was `!stdout_is_terminal()`, commented "nowhere to
print" — a regular file is somewhere to print. Now interposes only where a pipe
is indistinguishable from what the caller supplied. Specified into FORMAT-0.1
§9.5.2, which gained a fourth property. Regression: `tests/acceptance/11_stdio_fidelity.sh`,
which compares against direct execution and fails 6/10 against the old
behaviour. Streaming tee unregressed — 256 MiB through the relay peaks at
14 MiB RSS.

**A2 — "signal-killed launch loses stderr". NOT A DEFECT. Root-caused.** The
136 "lost" bytes were bash's job-control message, printed by the harness's own
`scripts/lib/private-display.sh` when it reaped the signal-killed child — the
line contains the wrapper's own path. The specimen writes **0 bytes** to
stderr; `.LEXE` delivers 0. The harness was comparing its wrapper against the
runtime. Fixed at the wrapper (background + `{ wait; } 2>/dev/null`, chosen by
measuring four constructions against three requirements). **Baselines had to be
regenerated** — the fix alone left the lane red against a stale recorded
measurement.

**A3 — GUI orphan. INTENDED SEMANTICS.** With `launch.mode: gui` held constant:
direct orphan survives, `.LEXE`'s does not, and the runtime records
`descendantsPreserved: false`. REFERENCE-POLICY.md:397 and FORMAT-0.1 §9.
Classified in the expectations file with citation, not forgiven. Do not reopen
without contradictory evidence.

**B — portable `sourceDir`. DONE.** It is not a working directory and confines
nothing; the schema's "sees this directory and nothing else" claim is retracted
with demonstrated evidence. The observer had **two** defects, the second hidden
behind the first, and the independent assertion was proven to earn its place by
breaking claim and driver *together* — which the product-derived check cannot
catch by construction.

**C — packaging. BOTH FORMAT.** Zeroed mtimes (§2 determinism) and symlink
rejection (§2 entry rules) are mandated by Format 0.1. **Neither is a bug to
fix.** What was missing was the consequence where a publisher meets it:
autotools regenerating `configure` against a network-denied build sandbox, and
a shared library's `libfoo.so -> .so.1 -> .so.1.2.3` chain being unpackageable.
Documented; behaviour unchanged.

**D — evidence provenance. DONE.** The doc-claims check now names the binary,
its build time, the commit, and whether the tree is dirty, and warns when the
artifact is older than tracked source so a stale build is not read as a
documentation defect.

**E — build-tree sprawl. DONE.** 8.3 GB reclaimed; three trees retained with a
purpose each.

## ARM64 worker

**Status: transport PROVEN, then the device physically disconnected.**

Working earlier today, verified:

```
ARM_KEY_AUTH_OK
u0_a248
aarch64            # SM-X610, physical ARM64
```

Then: `adb devices` empty, `adb forward --list` empty, ssh `Connection
refused`. Restarting the adb server did not recover it.

**Exact reconnect requirement:**

1. Reconnect the tablet by USB and unlock the screen.
2. `adb devices` must show `R52XA081A5Y   device` (not `unauthorized`, not
   empty). If `unauthorized`, accept the USB-debugging prompt on the tablet.
3. Termux sshd must be running (`sshd` in Termux if not).
4. `adb forward tcp:8022 tcp:8022`
5. Verify: `bash scripts/arm-worker.sh probe` — expect PASS through
   "termux ssh: reachable" and "debian guest".

No Android setting needs changing beyond the USB debugging already authorized.
No root. The forward is USB-only; nothing is exposed to the LAN.

### `scripts/arm-worker.sh` — READY, partially exercised

- `probe` — **exercised.** Correctly reported device, aarch64 kernel, and the
  adb forward; correctly reported INFRASTRUCTURE (not SKIP) when ssh was
  unavailable.
- `sync` / `build` / `levels` — **written, never run.** Not claimed to work.
- Auth: key-only (`~/.ssh/lexe_arm_worker`), `BatchMode`, password and
  keyboard-interactive refused, so an unattended run fails rather than hangs.
- Commit transport is a **git bundle**; the worker independently reports the
  SHA it checked out, and `sync` refuses outright on a dirty tree.
- **Level mapping self-audit runs before any level is claimed.** It found 8 of
  66 suites belonging to no level (`tux32-verify`, `ui`, `uninstall_paths`,
  `updater`, `util`, `verify`, `version`, `versioncmp`) — "levels 0–3 passed"
  would have been a claim about an unenumerated subset. Preserve this check.
- ARM build concurrency defaults to **2**: passively cooled, on battery.

### `scripts/second-isa.sh` — READY, never run

One signed portable-source package, hashed **independently on both machines**,
with the experiment **VOIDED if the bytes differ in transit**. Both hosts answer
the same questions in the same order (the same function body shipped over ssh).
Products read with both `file` and `readelf -h`.

The claim it is built to support, and its limit, are written into the script:
portable source materializes and executes native products on x86-64 Linux and
on physical AArch64 hardware — **not** that .LEXE is supported on arbitrary
ARM64 Linux desktops. The ARM host is Debian arm64 under PRoot on Android.

## Remaining Developer Preview gates

**Not ready.** Not because of test counts — because criteria have no
evidence at all:

1. **No ARM64 evidence against current HEAD.** The only ARM data is commit
   `7f82fe4`, ~80 commits stale. Its unit-test discrepancy (expected exit 3,
   observed 0) is **historical**, not a current ARM defect, and must not be
   reported as one.
2. **No second-ISA materialization.** The central portable claim is unproven.
3. **Level 4 capability on ARM is unmeasured.** Expected BLOCKED under PRoot
   (no user namespaces, which bubblewrap requires) — but that must be
   *measured*, not predeclared.
4. The clean-commit lane run must be green from a still tree.

Done and not blocking: wrong-ISA negative test (with its positive control) on
x86-64; x86-64 workloads lane green; no unexplained red specimens.

## Evidence and artifacts — do not delete

- `../lexe-resource-evidence/*.json` — metered peaks, including the
  over-budget run that prompted the enforcement work.
- `../lexe-isa-evidence/` — created by `second-isa.sh` (may not exist yet).
- `/tmp/lexe-workloads*` — the ELF/PE corpora. **`/tmp` is wiped by WSL
  restarts**, and WSL was restarted today to apply the memory cap, so expect to
  regenerate: `python3 tests/workloads/generate.py` then `generate_pe.py`.
- `build/` — Ninja, at HEAD. `scripts/test.sh` requires Ninja; a bare
  `cmake -B build` picks Makefiles and the generator mismatch will fail the run.

## Security note

Checked: no private key, `authorized_keys`, `.pem`, or credential has ever been
added to this repository, and no tracked file contains key material. Keys live
in `~/.ssh`, outside the tree. `arm-worker.sh` references a key by path and
refuses password authentication.

## First actions tomorrow, in order

0. **Before ARM**, resolve the two real x86-64 failures — they are small and
   they block the Preview decision: `tests/lifecycle/02_interrupted.sh` and
   `tests/integration/ws3_ws4_trust_lifecycle.sh`. Start by reading their
   assertion output against commit `45704e1`'s change to healing installs.
1. Reconnect the tablet; `bash scripts/arm-worker.sh probe` until it passes.
2. Regenerate the workload corpora (`/tmp` was wiped).
3. `bash scripts/arm-worker.sh sync` — confirm the worker reports the **same
   SHA** you asked for. If it differs, stop: the evidence is void.
4. `bash scripts/arm-worker.sh build` — expect `ARM aarch64` from `file`; a
   non-AArch64 artifact means it is not second-ISA evidence.
5. `bash scripts/arm-worker.sh levels 5` — Levels 0–3 substantive; Level 4
   measured, not assumed; Level 5 not applicable (Wine/Proton are x86-64 chains
   and reaching them on AArch64 needs the ISA translation §20 forbids).
6. `bash scripts/second-isa.sh all` — require matching package hashes or void.
7. Final evidence audit, then the Preview decision.

## Clean run — result

Run from commit `28d209d`, clean tree at start, under the enforced 4 GiB cap.

**10 lanes passed, 5 failed, 0 skipped, 0 blocked.**

| PASS | FAIL |
|---|---|
| unit (762 cases / 9794 assertions) | evidence |
| sanitizers (ASan+UBSan, 762) | integration |
| acceptance (all 12 scripts) | lifecycle |
| gui, concurrency, session | workloads |
| conformance, security | explore |
| windows (34), proton (27) | |

**Resource compliance: PASS.** Peak **1931 MiB (47% of the 4 GiB budget)**,
peak **37.2% CPU**. Both inside policy — compare the pre-enforcement run at
4143 MiB / 101%. The `.wslconfig` ceiling and the `-j3` sanitizer limit are
what changed.

### Why each lane failed — diagnosed, deliberately not repaired tonight

**workloads, explore — CORPORA ABSENT.** `/tmp/lexe-workloads` and
`/tmp/lexe-workloads-pe` do not exist. WSL was restarted today to apply the
memory cap, and **`/tmp` does not survive a WSL restart**. These lanes had
nothing to run.

Worth examining tomorrow, and *not* tonight: absent corpora produced **FAIL**
with `0 blocked`, where the intended behaviour is BLOCKED. A lane that cannot
find its inputs has not tested anything, and reporting that as a failure of the
product is the same category error this project keeps hunting. Regenerate
first (`python3 tests/workloads/generate.py`, then `generate_pe.py`) and re-run
before concluding anything about the runtime.

The `explore` lane additionally reported a genuine model result that survives
the corpus question: *2 divergence groups over 3000 sequences / 21681
operations*, reproducible with `LEXE_EXPLORE_SEED=20260929`. **That is a real
lead and is the most interesting thing outstanding on x86-64.** It is recorded,
not investigated.

**evidence — my fault, not the product's.** It passes standalone (`2 passed, 0
failed`). It failed inside the stack because I wrote `docs/HANDOFF.md` while
the run was in flight. I had reasoned that `docs/` is exempt — it is exempt
from the *source fingerprint*, but `02_doc_claims.sh` independently asks
`git status --porcelain`, which sees any dirty file. So the run was disturbed
by the act of documenting it. The rule stands without the exemption I invented:
**touch nothing in the working tree while lanes are running.**

**lifecycle — `02_interrupted` FAILS** (`01_ordinary_sequence` and
`03_service` pass; service is 23/0). Real, reproducible, and **the first thing
to look at tomorrow**.

**integration — `ws3_ws4_trust_lifecycle` fails with 8 assertions.** Real and
reproducible.

**The leading hypothesis for both, and it points at today's work.** Commit
`45704e1` changed what `install` returns when it heals an interrupted install:
it used to throw `BusyError` (exit 6, "already installed and current") and now
returns success, because recovery had completed the transaction and the claim
"nothing was changed" was false. `02_interrupted` exists precisely to
interrupt installs and re-drive them, and the trust lifecycle asserts on
install outcomes — so a lane that pinned the old exit code would fail exactly
like this.

**Do not assume that is the cause.** It is the obvious suspect, which is the
reason to check it rather than to believe it. Two possibilities and they need
distinguishing: either those lanes encoded the old behaviour and should be
updated, or the change was wrong for the interrupted case and the runtime
should be. The second would mean a real defect in `45704e1`. Read the actual
assertion failures before deciding, and note `02_interrupted` was itself
rewritten earlier today (commit `38322c5`, "the interruption suite that
interrupted nothing") — so a third possibility is that the rewrite and the
runtime change disagree with each other rather than either being wrong alone.

Neither was repaired tonight, per instruction.

### What this run does and does not establish

It does establish: the unit suite, sanitizers, all 12 acceptance scripts, the
GUI/Windows/Proton paths, security, conformance, concurrency and session lanes
are green from a clean commit inside the resource envelope.

It does **not** establish a green `--all`. Five lanes did not report a
trustworthy result, three of them for reasons external to the product
(wiped `/tmp`, and my own edit mid-run) and two unexamined.

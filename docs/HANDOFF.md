# Handoff — 2026-10-02, ARM campaign

Where .LEXE stands after the first current-code run on physical AArch64.
Written to be read cold. Earlier handoffs: `55ad1ab`, `5bccec3`, `29d230b`.

## Verdict: Developer Preview — NOT READY

The Preview claim is *".LEXE portable source materializes and executes native
products on x86-64 Linux and physical AArch64 hardware"*. The x86-64 half is
demonstrated. The AArch64 half is **BLOCKED: ENVIRONMENT** — the only AArch64
worker cannot run .LEXE's sandbox, and .LEXE (correctly, by design) refuses to
build or launch without it. Nothing was found that is wrong with the product on
AArch64; the claim is simply not shown there.

## Commits

| | |
|---|---|
| **Final HEAD** | the commit that adds this file (docs only); `git log -1` |
| **ARM evidence** | **`b5c115f`** — synced as a git bundle, the worker read back `b5c115f1681692ef9bcca92ca434635a73c076ad` itself |
| **Second-ISA evidence** | **`b5c115f`** on both hosts (each records its own `GIT_SHA`) |
| **x86-64 evidence** | unit 777/777 (10100 assertions) at `b5c115f`; the last full 15-lane run is `e6129d3` — code since then: test fixtures and scripts only, plus the MSVC fix proven byte-identical on Linux (see `55ad1ab`) |
| **GitHub CI on `cabc329`** | run 37020284311: linux ✅, portability ✅, windows ❌ — Test step 731/751, the same 20 pre-existing Windows failures as before this campaign (purge cases, hostbuild, config, repair, …); none of the tests changed here is among them |
| **After `b5c115f`** | `b9bc710` harness-only (second-isa key reuse, claim wording, bundle location) and this docs commit. Neither changes product or test code. |

## The ARM worker

Samsung SM-X610, Android 16, kernel `aarch64`; Debian 13.7 arm64 under PRoot
(proot-distro); g++ 14.2.0, git 2.47.3, 8 cores, ~7.7 GB RAM. Reached by USB:
`adb forward tcp:8022` → Termux sshd, key-only (`IdentitiesOnly`, `BatchMode`,
password and keyboard-interactive off). `ARM_KEY_AUTH_OK` verified. Build at
`-j2`.

**Measured limits** (not assumed):

* Native Termux: `unshare --user` → `EINVAL`. The kernel offers no user
  namespaces.
* In the PRoot guest, `unshare --user` **exits 0 without creating anything**
  (no `/proc/self/ns`, the "new PID namespace" child is PID 2676, not 1).
* With bubblewrap 0.12 installed in the guest, bwrap gets past the faked
  namespace calls and fails at `sethostname` (`ENOSYS`).
* **.LEXE is not fooled**: `lexe sandbox` → *"Isolation is unavailable — launch
  will be refused"*, user namespaces: no. Its probe executes the backend.
* doctest under PRoot: `TracerPid` ≠ 0, so doctest thinks a debugger is
  attached and traps on any failed assertion. Run with `--no-breaks`.

## ARM levels at `b5c115f` (`../lexe-arm-evidence/arm-run-b5c115f.log`)

| Level | Result |
|---|---|
| 0 environment, ELF, CLI | **PASS** — `file`: ARM aarch64; `readelf`: AArch64; CLI starts |
| mapping self-audit | **PASS** (it caught `purge` and `wrong_isa` in no level on the first run) |
| 1 unit logic | **PASS** 341/341, 6436 assertions |
| 2 install lifecycle | 285/289. The 4 failures are all launches: refused fail-closed (ENVIRONMENT) |
| 3 launcher/process | 33/39. The 6 failures are all launches (ENVIRONMENT). 7 hostbuild cases and `wrong_isa` report SKIP/BLOCKED: no sandbox, so no build |
| 4 sandbox/namespaces | **BLOCKED: ENVIRONMENT** — measured by .LEXE's own probe |
| 5 Wine/Proton | not applicable on AArch64 |

The CLI-run failures do not print their reason inside doctest, so it was shown
directly (`arm-run-probe.txt`): a native AArch64 package builds and installs
(rc 0); `lexe run` exits 1 with *"refusing to launch … unconfined"*; the
installed AArch64 entrypoint, executed directly, runs (rc 7, as written).

## Second ISA at `b5c115f` (`../lexe-isa-evidence/`)

| | x86-64 (WSL Ubuntu 24.04) | AArch64 (tablet) |
|---|---|---|
| package sha256 | `ea0ffa80…3fc23f` | `ea0ffa80…3fc23f` (re-hashed on arrival, and again by the guest) |
| signer | Ed25519 `85B8 352D 4D50 1D06 8757 85AC 90FF B25D D5EC 52A6 4C3C D22F 0292 57FD 59C5 514A` | identical verify report |
| compiler | gcc 13.3.0 | gcc 14.2.0 |
| install | rc 0, product `5b82a8a6…`, ELF64 x86-64, `build.json` hostIsa x86_64 | **rc 1: "needs an isolated build environment and this host has none … refusing to build unconfined"** |
| run | rc 0, `COMPILED_FOR=x86_64` | no product |

`compare`: identical bytes PASS, identical signer PASS, x86 product PASS;
AArch64 product **absent** — the experiment is not void (the inputs matched),
it is **BLOCKED** on the AArch64 side.

Wrong-ISA negative: kept on x86-64 (real host ELF with `e_machine` patched,
plus its positive control) and now ISA-symmetric — on AArch64 it would patch to
`EM_X86_64` — but on this worker it reports BLOCKED, because the check sits on a
build product and no build runs without a sandbox.

## Failures found and how they were classified

* **TEST/HARNESS (fixed):** arm-worker ssh options word-split the key path;
  `git bundle` refuses a bare SHA; Git Bash rewrote `/sdcard`; Termux storage
  needed a tap (bytes now go over ssh, hashed both ends); doctest traps under
  PRoot; suites in no level; FAILED_CASE listed SKIP messages; second-isa had
  the wrong key, path, transport and an incomplete record; six tests assumed
  the host is x86-64 (`wrong_isa`, `cli_apps`, `cli_inspect` ×2, `cli` ×2).
* **SPEC (by design, not a bug):** launch and portable-source builds fail
  closed without isolation; Tux32 Core 1 is x86_64-only.
* **ENVIRONMENT:** no user namespaces on the worker (see measurements).
* **PRODUCT PORTABILITY BUG:** none found.
* Minor, not acted on: bwrap's own `Can't open source /usr` line reaches the
  user's stderr above .LEXE's refusal message.

## Resources

Tablet build `-j2`; the full first build and each level ran without the
device or adb dropping once the tablet was unlocked and Termux held a wake
lock (before that, adb shell hung and sshd stalled at the banner). Tablet
thermal zones are not readable from Termux; no throttling was measured either
way. Desktop work was builds at the existing `-j6` and unit runs; it was not
metered this session.

## What would make it READY — a decision for you

The tablet cannot do it as it is. Two ways forward:

1. **Run the same second-ISA script on real AArch64 Linux with unprivileged
   user namespaces** (a Raspberry Pi 4/5 or any arm64 SBC on Debian/Ubuntu, a
   cloud arm64 VM such as Graviton/Ampere, an arm64 Mac running a Linux VM).
   `scripts/second-isa.sh` needs only `LEXE_ARM_*` pointing at it. Recommended.
2. **A product change**: an explicit, consented "unconfined" mode for hosts
   without isolation. That is a security-design decision, contrary to the
   current fail-closed contract, and was **not** made here.

## First actions next time

1. Get an AArch64 Linux host with user namespaces (option 1), or decide (2).
2. `bash scripts/arm-worker.sh probe | sync | build | levels 4`, then
   `bash scripts/second-isa.sh build && … local` (in WSL) and `… remote` and
   `… compare` (from Git Bash). Both must show the same `GIT_SHA`.
3. Tablet only: unlock it, open Termux, `termux-wake-lock`, `sshd`; then
   `adb forward tcp:8022 tcp:8022`.

## Evidence — do not delete

* `../lexe-arm-evidence/` — `arm-run-b5c115f.log`, `arm-run-probe.txt`, levels.
* `../lexe-isa-evidence/` — both records, `compare-b5c115f.txt`, the package.
  `../lexe-isa-evidence.trial-f64572f/` is the x86-only trial, not evidence.
* `../lexe-run-evidence/`, `../lexe-resource-evidence/` — x86-64 runs.

# Testing .LEXE

Everything here is reproducible. If a capability is claimed anywhere in this
repository, the intent is that a command in this document demonstrates it.

```sh
./scripts/test.sh --all       # the executable definition of a releasable build
./scripts/test.sh --list      # what each lane covers, and what it needs
```

`--all` is not "run everything and hope". It reports four distinct outcomes, and
the difference between the last two is the whole point:

| | Meaning |
|---|---|
| **PASS** | the behaviour was demonstrated on this machine |
| **FAIL** | the behaviour was expected here and did not happen — a defect |
| **SKIP** | deliberately not applicable on this host, with the reason named |
| **BLOCKED** | needs hardware or an environment this host does not have |

A BLOCKED lane is never counted as success. `scripts/test.sh` exits non-zero on
any FAIL and zero on SKIP/BLOCKED, and prints every skip and block with its
reason so the gap stays visible instead of disappearing into a green tick.

---

## 1. Build

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j"$(nproc)"
```

GTK 3 is detected automatically; when `pkg-config` finds `gtk+-3.0` the two
graphical frontends (`lexe-ui`, `lexe-builder`) build alongside the CLI. Force
it with `-DLEXE_BUILD_GUI=ON` to turn a missing GTK into a configure error
rather than a silently CLI-only build.

**First-party code must build with zero warnings** under `-Wall -Wextra`.
Vendored code in `third_party/` is compiled with warnings silenced and exposed
as SYSTEM includes precisely so that stays true.

## 1.5 Three roles, deliberately not merged

Testing this project is split across three responsibilities that are kept
independent on purpose. The split is not organisational tidiness — it exists
because the failure mode it prevents has happened repeatedly here.

| | asks | owns |
|---|---|---|
| **Implementation / Format** | *What should `.LEXE` do?* | production code, Format 0.1, runtime, installer, verifier, CLI, schemas |
| **Independent Test** | *Where does it break?* | hypotheses, assertions, adversarial and differential testing, fuzzing, fault injection, auditing the tests themselves |
| **Workload / Fixture** | *What can I make `.LEXE` deal with?* | specimen programs (Linux, Windows, portable source), build and compiler matrices, fixture metadata, reproducibility |

The failure mode:

```
        BAD                                   WANTED
implementation chooses behaviour          the SPEC
        ↓                                 /      \
test reads implementation          reference     independent
        ↓                          impl.          tests
test copies behaviour                 \          /
        ↓                              observable behaviour
       PASS
```

A test written from the implementation agrees with the implementation by
construction, and proves nothing about the format. This is not a theoretical
concern: building a 181-case conformance corpus **from the specification instead**
found that the `permissions` vocabulary existed only in a freeze record and that
§5.5 contradicted itself — neither of which any test derived from the code could
have surfaced.

Two rules keep the split real:

**The workload engineer does not decide whether `.LEXE` is correct.** It
manufactures programs and records what they do *on their own*. Deciding what
`.LEXE` should do with them is a different job, and a fixture that carried its
own verdict would be marking its own homework.

**Verify outside `.LEXE` first.** A specimen enters the corpus only once its
direct-execution behaviour is recorded:

```
source → compiler → binary → DIRECT EXECUTION → known behaviour → corpus → .LEXE
```

Without that baseline, `.LEXE → program fails` is unattributable: it could be a
runtime defect or a broken executable, and there is no way to tell them apart
after the fact.

## 1.6 Evidence integrity

`scripts/test.sh` records the commit and a fingerprint of the source tree when it
starts, and checks it again at the end. A run whose sources changed underneath it
is reported as **EVIDENCE INVALID** and exits non-zero whatever the lanes said.

This is mechanical rather than a convention because the convention failed three
times, and once it failed in the most misleading way available: the sanitizer lane
reported eight failures that looked exactly like logic bugs — three unrelated
booleans in one struct reading `false` while set `true` — because a field had been
added to that struct and the build tree held object files from two layouts. The
same tests passed in the ordinary build, and passed again under sanitizers from a
clean tree. The failure was indistinguishable from a real defect and sent the
investigation after a bug that did not exist.

A green run that cannot be attributed to a commit is worse than a red one,
because it invites trust it has not earned. The guard therefore fails closed: an
unrelated file appearing mid-run also invalidates the run, and the cost of that
is one re-run against a still tree.

## 2. Test lanes

| Lane | What it is | Needs |
|---|---|---|
| `--unit` | the doctest binary: every subsystem, the view models of both GUIs, the architecture rules | nothing |
| `--acceptance` | `tests/acceptance/0*.sh` — end-to-end scripts against a throwaway `LEXE_HOME` | a built CLI |
| `--integration` | `tests/integration/*.sh` — trust and lifecycle across process boundaries | a built CLI |
| `--gui` | `scripts/gui-smoke.sh` — the frontends start, render and exit under a private display | GTK 3, Xvfb |
| `--lifecycle` | install → run → update → rollback → repair → uninstall, then the same with operations interrupted | bubblewrap |
| `--concurrency` | the same operations SIMULTANEOUSLY: contended locks, lease races, deadlock detection (every participant is hard-timed out, so a deadlock FAILS the suite rather than hanging it) | bubblewrap, `flock(1)` |
| `--session` | the session-manager boundary, against the REAL `systemd --user` of the invoking session: enable, status, start, stop, repair, retraction on uninstall | a running `systemd --user` session (SKIPs without one) |
| `--conformance` | `lexe verify` against the independent validator in `tools/lexe-conformance`: a **181-case corpus generated from `docs/FORMAT-0.1.md`** (37 of them valid packages, deliberately on the bounds), plus a lane asserting that `verify` passing is never followed by `install` rejecting the package as invalid. Checks each verdict against the SPEC *and* the two implementations against each other — neither subsumes the other, since a shared misreading would pass the first and an identically-wrong pair would pass the second. A disagreement fails the lane rather than being resolved in favour of the C++ | python3 |
| `--security` | hostile packages: traversal, symlink escape, tampered hashes, architecture lies, injection | nothing |
| `--windows` | a purpose-built Windows PE, run through Wine | Wine, MinGW |
| `--proton` | the same payload through the Proton chain | a Proton installation |
| `--sanitizers` | a separate ASan + UBSan build of the unit suite | clang or gcc sanitizer runtime |

Run one lane, several, or `--all`. `--list` prints the table above with each
lane's availability resolved on the current host.

## 3. The headless rule

**No automated test may put a window on the user's screen.** This is a hard
guard, not a convention. A window that steals focus mid-run is disruptive, and a
test whose result depends on a live desktop session is not reproducible on a
build machine.

`tests/acceptance/lib.sh` unsets `WAYLAND_DISPLAY` and `DISPLAY` for the whole
harness before any test runs, and pins `GDK_BACKEND=x11` so that a future change
which tried to open a window would find nothing to open it on and fail loudly
instead of appearing on screen.

Anything that genuinely must render brings **its own** display. It never borrows
the developer's.

### The one deliberate exception: `--session`

The session lane **does** talk to the invoking user's real `systemd --user`, and
that is a departure worth stating rather than burying.

There is no way around it. The feature under test is a contract with a program
`.LEXE` does not control, so the only test that means anything is one where
systemd is the other party. A stub would have agreed with every assumption that
turned out to be wrong — including the one that cost a `203/EXEC`: that
`ExecStart=` may contain an unquoted path. That defect was invisible to every
check except systemd's own, and a mock would have shipped it.

What bounds the exception:

- It **starts no window** — a service has no UI, so the headless rule above is
  untouched.
- The installation still lives in a throwaway `LEXE_HOME`; only the unit
  registration reaches the real session, because a unit systemd cannot see is a
  unit that proves nothing.
- Every unit it creates is the example's own
  `lexe-org.lexe.examples.heartbeat.service`, cleaned up on `EXIT` — including on
  an interrupt — and the last assertion of the lane is that the real profile has
  nothing of the lane left in it. A leftover enabled unit pointing into a deleted
  scratch root would fail at the developer's next login, so that cleanup is
  correctness, not tidiness.
- It **SKIPs**, not BLOCKs, where there is no user session: a host without a
  session manager is one where the feature does not apply, and
  `tests/test_session.cpp` still covers everything that is a function of its
  inputs.

### Rendering without touching the real desktop

Under WSLg this is less obvious than it looks, and the obvious approach does not
work:

```
$ mount | grep x11
none on /tmp/.X11-unix type tmpfs (ro,relatime)
$ ls /tmp/.X11-unix/
X0            <- WSLg's own display, and nothing else
```

WSLg mounts `/tmp/.X11-unix` **read-only** and puts the user's real display there
as `X0`. So `Xvfb :99` cannot create `/tmp/.X11-unix/X99`; it falls back to an
abstract socket, which a sandboxed process can never reach, because the sandbox
unshares the network namespace and abstract sockets do not cross one. Ubuntu's
Xorg 21.1 has no `-unixdir` to relocate the socket either. That left the
launcher with no display socket to bind for a GUI launch, and binding `X0` was
never an option: `X0` **is** the user's screen.

The mechanism that does work is `scripts/lib/private-display.sh`, and it is
safer than the thing it replaces rather than a workaround for it:

```sh
unshare --mount --map-root-user sh -c '
    mount -t tmpfs tmpfs /tmp/.X11-unix   # private to this namespace
    chmod 1777 /tmp/.X11-unix
    Xvfb :99 -screen 0 1024x768x24 -nolisten tcp & ...'
```

Inside that mount namespace `/tmp/.X11-unix` is a fresh writable tmpfs, so Xvfb
creates a **real filesystem socket** at `/tmp/.X11-unix/X99`. Children — the
launcher, and the `bwrap` sandbox it starts — inherit the namespace and can bind
that socket like any other path. The user's `X0` is not touched, not bound, and
not even visible in the namespace. Nothing reaches their desktop.

This is what lets `--gui` and `--lifecycle` prove a window actually **mapped**
rather than merely that a process started: `xwininfo`/`xlsclients` against the
private display are third-party witnesses, and they are running against a
display that only the test owns.

## 4. Environment

Developed and validated on **WSL2 Ubuntu 24.04** (x86_64, 24 cores). Packages
the lanes above need:

```sh
sudo apt-get install -y \
    cmake ninja-build pkg-config g++ \
    bubblewrap libsodium-dev libgtk-3-dev \
    file unzip ccache strace valgrind \
    xvfb x11-utils x11-apps xdotool xauth \
    desktop-file-utils xdg-utils shared-mime-info \
    wine mingw-w64 binutils-mingw-w64 \
    clang
```

What each group buys:

| Package group | Which lane stops being SKIP |
|---|---|
| `bubblewrap` | `--lifecycle`, and the isolation and portable-compile suites stop skipping for want of a sandbox |
| `libgtk-3-dev` | `--gui`, and the frontends build at all |
| `xvfb x11-utils xdotool` | `--gui` can prove a window mapped, not just that a process lived |
| `desktop-file-utils xdg-utils` | desktop integration gets third-party validation instead of the runtime's own bookkeeping |
| `wine mingw-w64` | `--windows`: a real PE, cross-compiled here, actually run |
| `clang` | `--sanitizers`, and the fuzz-ready parser harnesses |

`bubblewrap` works unprivileged under the WSL2 kernel, so the isolation and
portable-compile suites run for real here.

Building on `/mnt/c` works and is what this checkout does; a full build is about
80 seconds at `-j24`, most of it reading sources over the 9p filesystem.

## 5. Sanitizers

```sh
./scripts/test.sh --sanitizers
```

or by hand:

```sh
cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
cmake --build build-asan -j"$(nproc)"
env -u WAYLAND_DISPLAY -u DISPLAY ./build-asan/lexe_tests
```

Sanitizers are not decoration here: the first run of ASan over this tree found a
real leak in `lexe pack`. Vendored `third_party/ed25519` performs signed
left-shifts that UBSan reports; those are suppressed by name in
`tests/ubsan.supp` rather than tolerated in the output, so a *new* finding is
still visible.

## 6. What this machine cannot prove

Recorded here rather than left implied. `scripts/test.sh` reports each of these
as BLOCKED with the same reason, so the list cannot rot silently.

| Claim | Why it is not proven here | What would settle it |
|---|---|---|
| **The same portable `.lexe` compiles on ARM64** | the same-package test has not run; a physical AArch64 worker exists (an older commit ran natively there — historical, not current) | that worker, connected; see §7 |
| **Integration survives a reboot** | WSL has no session to reboot and no login sequence to re-run | a standalone Linux desktop; checklist in `tests/acceptance/REBOOT.md` |
| **Double-clicking a `.lexe` in a file manager opens it** | no file manager and no desktop session | same |
| **`service` mode under a real user session manager** | no systemd user session under WSL | a systemd-enabled Linux host |
| **ISA translation chains (FEX, Box64, qemu-user)** | none of those runtimes is installed, and x86_64-on-x86_64 would not exercise them anyway | a machine where the translation is real |

Emulation is explicitly **not** accepted as a substitute for the first of these.
`qemu-user` can exercise the *refusal* path — "this output targets a machine
that is not the builder's" — and that is worth having, but producing an AArch64
binary under emulation on an x86_64 host does not demonstrate the architecture's
central claim.

## 7. The decisive cross-ISA test

When ARM64 hardware is available, this is the test that settles the portable
type:

> Take the **exact same** signed portable-source `.lexe` to an x86_64 host and
> an AArch64 host. Install it on each. Verify that each machine independently
> produces a native ELF **for its own ISA**, with its own `build.json` recording
> its own toolchain and product hash. Execute both successfully.

Until then, `--all` reports it BLOCKED, and the documentation says
*designed, implemented and unit-tested — not demonstrated on hardware.*

## 8. Discipline

Two rules, both learned the hard way.

**A defect is not fixed until a test reproduces it.** The loop is: understand the
root cause, correct the implementation, write a test that fails against the old
behaviour, watch it pass against the new one, and confirm the broader suite is
still green. A fix without that fourth step is an assertion.

**Working once is not done.** The alpha installed and launched perfectly and
then did not survive a reboot. Persistence, repair and uninstall are part of
correctness, which is why `--lifecycle` interrupts operations on purpose and
`tests/acceptance/02_persistence.sh` destroys installed state and demands that
`lexe doctor` name each missing artifact before repairing it.

## 9. When to stop building test infrastructure

Every section above argues for more machinery. This one argues for less, because
the machinery has a cost that does not show up as a failing test, and there is a
point past which the next lane is a liability rather than an asset.

The cost is not CPU time. It is that **test infrastructure is code nobody
tests**, and this project has the numbers to prove that is not a slogan. Roughly
a dozen defects have been found in `.LEXE` itself. **Eleven** have been found in
the machinery built to find them — a fingerprint that hashed nothing and
approved every run it saw; an evidence lane structurally incapable of failing; a
relay regression that had been vacuous since the day it was written; an
interruption suite that interrupted nothing; a mutation gate that passed having
checked zero mutants. That ratio is about one to one. Machinery is not a free
multiplier on confidence; it is a second body of code with its own defect rate,
and its defects are worse than product defects because they are silent and they
launder false confidence.

So: **stop adding lanes when the marginal lane is more likely to be wrong than
the code it would test.** Four signals that the point has arrived, in rough
order of how early they show up.

**1. The last few additions found nothing the existing lanes would not have.**
Ask it concretely and answer with names: what did the last three lanes find? If
the honest answer is "they found problems in themselves", the useful work is
repairing what exists, not extending it.

**2. Specimen count grows without dimension growth.** Five thousand copies of
hello world is not five thousand tests. A corpus earns its size by spanning
axes — link mode, symbol versioning, rpath shape, exit behaviour, output volume
— and a specimen that differs from an existing one only in its name adds
maintenance and subtracts nothing from the space of undetected bugs.

**3. Real software is available and is not being used.** This is the strongest
signal, and the cheapest to act on. Sixteen ordinary Linux CLI programs —
packaged, installed and run against direct-execution baselines — produced three
findings that 201 purpose-built synthetic specimens had not: a granted `network`
permission on which no standard TLS client can verify a certificate, an `/etc`
reduction that strips an application's *own* hardening so it is less restricted
inside the sandbox than outside it, and a report contradicting its own adjacent
line. None of those was reachable by a specimen written to test a dimension,
because each came from software doing something nobody thought to model. Real
software is also the better deal on maintenance: it is written and maintained by
someone else.

**4. The proportion of effort spent on observability exceeds the proportion
spent on coverage.** A check that is not observed is not a check (§1.6). If most
of the work is going into proving that existing checks fire, that is not a
failure — it is the correct response to signal 1, and it is finished work when
the existing checks are trustworthy, not when more exist.

### What this rule does not apply to

**The evidence lane is exempt.** `tests/evidence/` tests the machinery that
decides whether a run may be cited at all, and it exists precisely because that
machinery was wrong twice without anyone noticing. A stop condition on the thing
that detects false confidence would be self-defeating.

**So is anything closing a BLOCKED row in §6.** Those are claims this machine
cannot make, recorded as gaps. Work that converts one into a demonstration is
never "more infrastructure for its own sake" — it is the only thing that moves
the honesty of §6 forward.

### What to do instead

Run real applications, and follow §1.5's rule while doing it: record the
direct-execution baseline **first**, or a divergence is unattributable. Then
classify every divergence as a `.LEXE` defect, intended runtime semantics with
the specification cited, a packaging mistake, or a property of the application —
and report intended semantics as intended, not as a finding. The temptation at
this stage is to count divergences; the value is in attributing them.

## 10. The resource policy

Resource efficiency is a first-class engineering requirement here, not a
courtesy. No build, test, lane, fuzz campaign, corpus run, sanitizer pass,
soak, or agent-driven workload may **intentionally** drive the development
machine past these limits:

| Resource | Limit |
|---|---|
| CPU | **≤ 50%** sustained host utilization — **averaged over any rolling 10-second window** (§10.2a); a shorter burst may exceed it |
| RAM | **≤ 4 GiB** total for test/build infrastructure, excluding the editor and the agent harness themselves |
| Storage | no sustained SSD saturation (≤ ~50% active time) |

The budget is **aggregate, not per-process and not per-agent**. Six agents do
not get six budgets; they get this one, between them. That is the rule the
previous wave broke — each agent was given its own build tree to avoid
concurrent `ninja` corruption, which was right, and they then all built at
once, which was not. It left eleven trees and ~12 GiB behind.

`HEAVY` and `SOAK` no longer mean "use the whole machine". They mean *run more
work for longer inside this envelope*.

### 10.1 Concurrency is derived from measurement, not from `nproc`

The starting formula is `workers ≤ ceil(logical_CPUs / 2)`. **On this machine
that formula is wrong, and measurement is what says so.**

A clean build of the full tree, metered with `scripts/resource-meter.sh`
(490 samples at 0.5 s):

| jobs | peak tree RSS | % of 4 GiB budget | peak host CPU |
|---|---|---|---|
| `-j6` | **2938 MiB** | **71%** | **23.4%** of 24 logical CPUs |

Two things follow, and the second is the point:

**Memory is the binding constraint, not CPU.** At `-j6` the CPU target has more
than half its headroom left while RAM is already at 71% of budget. Compilation
of this project costs roughly 490 MiB per worker.

**The CPU-derived formula would violate the RAM budget.** `ceil(24/2) = 12`
workers extrapolates to ~5.9 GiB — about 44% over. So the documented default is
**6**, set by the memory budget, and the CPU ceiling is not the operative limit
here at all. This is exactly why the policy says observed utilization takes
precedence over the formula: a machine with many cores and ordinary RAM is
memory-bound long before it is core-bound, and a worker count chosen from
`nproc` would have looked principled while being 44% over.

Sanitizer builds are heavier still (ASan shadow memory) and get their own,
lower limit rather than inheriting this one.

### 10.2 Measuring, and why `/usr/bin/time -v` is not enough

`scripts/resource-meter.sh` runs a command and reports **peak total RSS and CPU
across its whole process tree**. `time -v` reports the largest *single* child,
and what this policy bounds is the *sum* of a dozen concurrent compilers.

The meter was validated against three known loads before being trusted —
allocate 600 MiB (reported 609 MiB), saturate 12 of 24 cores (reported exactly
50.0%), saturate 6 (reported 25.0%). Two observers that fail for different
reasons, plus a discrimination test, per §1.6.

It refuses to report a peak it did not observe. During development it twice
sampled nothing — once because `setsid` forked and the sampler watched a process
that had already exited — and each time printed *"nothing was sampled — this is
not evidence of a cheap run"* rather than `0 MiB`. A resource meter that reports
zero when it is broken says "well within budget" in the same words it would use
for a genuinely cheap run, and this project has been caught by that shape of
silence often enough to design against it.

Known limitation, stated rather than papered over: the meter walks the process
tree, so a process that re-parents to `init` stops being counted. Build and test
drivers wait on their children and are unaffected; a deliberately detaching
daemon would under-report and needs a second observer.

### 10.2a What "sustained" means: a rolling 10-second window

**Definition.** The CPU limit is on aggregate CPU utilization of the
build/test process tree **averaged over every rolling 10-second window** of a
run. A burst shorter than that — a lane forking its workers, a linker — may
exceed 50% for a moment; no 10-second window may average over 50%. RAM has no
window: the 4 GiB limit applies at every sample.

**Why it had to be written down.** The policy said "sustained" and the meter
verdicted on its single highest 0.5-second sample. On 2026-10-01 one run of
`91439b9` was flagged "OVER BUDGET … at peak" at 69.6%, and a rerun of the same
commit read 48.7%. An external per-second `/proc/stat` timeline on the rerun
found exactly one second above 50% in 3190 (90.9%, as the explore lane's first
parallel engine starts) and a worst 10-second average of 24.6%. The policy and
the measurement were not measuring the same thing.

**What the meter does now.** `scripts/resource-meter.sh` keeps a timestamped
cumulative CPU counter for the tree and reports the peak **rolling 10-second**
average (`rolling 10 s`, JSON `peak_rolling10_cpu_pct`); its CPU verdict is on
that. The single-sample peak is still printed, marked informational. The counter
now includes `cutime`/`cstime` — time of children already reaped — because the
old one summed only processes alive at a sample, and a short-lived child's CPU
vanished when it exited. Validated against `/proc/stat` before use:

| control | host `/proc/stat` | meter, rolling 10 s | verdict |
|---|---|---|---|
| 6 of 24 cores, 15 s | 24.7% | 24.9% | none |
| 13 of 24 cores, 15 s | 52.9% | 54.3% | **OVER BUDGET** (the check fires) |
| 22 cores for 1 s, then idle | 5.8% | 8.6% (one sample: 92.2%) | none |
| a storm of short-lived CPU-burning children | 31.3% | 31.3% (previous meter: 9.9%) | none |

A run shorter than the window gets no CPU verdict rather than a guessed one.

### 10.3 What counts as a failure

A result obtained by breaking these limits is an **infrastructure failure** and
is reported as one — it is not a passing test that happened to be expensive.

But the limits never buy a weakened assertion. If a test genuinely cannot run
inside the envelope, it is **BLOCKED with the measured reason**, which is a
result, not a silent skip. Lowering what a check demands in order to fit a
resource budget converts a resource problem into an evidence problem, and this
project has spent eleven separate occasions learning what that costs.

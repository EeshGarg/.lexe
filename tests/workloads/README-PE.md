# `.LEXE` workload corpus — Windows PE factory

Legitimate, deliberately unusual Windows programs for `.LEXE` to consume, with a
**separate recorded baseline per translation layer**. Companion to
[README.md](README.md), which covers the Linux ELF corpus; the contract, the
golden rule and the OBS_ convention are the same, and only what is specific to
Windows is repeated here.

Sources and a generator, not binaries. The corpus is a pure function of
`specs_pe/` plus `generate_pe.py`, regenerated into a scratch directory outside
the repository.

## Why per-layer baselines

A difference between Wine and Proton is **not the same fact** as a difference
caused by `.LEXE`, and the two must never be conflated. Each specimen therefore
gets up to four cells recorded before `.LEXE` is involved at all:

| Layer | What it is | stdio reaches the caller? |
|---|---|---|
| `native` | the same source built as a Linux ELF by `gcc -O2`, where the source is portable enough for that to mean anything | yes — the reference |
| `wine` | the system Wine, directly | yes |
| `proton-run` | Proton's own entry point, `python3 proton run` | **no** |
| `proton-wine` | the Wine binary shipped *inside* Proton, run directly against Proton's prefix | yes |

`proton-wine` exists to separate *"Proton's Wine behaves differently"* from
*"Proton's launcher behaves differently"*. That distinction turned out to matter
three times in one afternoon — see **What running it taught us** below.

## The oracle is a FILE

Every specimen writes each oracle line **twice**: to the stream, and to
`<fixture-id>.oracle` in its working directory. The file is the primary
comparison artifact.

This is not a stylistic choice. Under `proton run` the guest program's stdout and
stderr do not reach the caller at all, while its exit code and its file side
effects do. A GUI-subsystem PE has no console in the first place. A corpus that
reported only on stdout would be unobservable under exactly the layer it most
needs to be compared across. The file is flushed after every line, so a specimen
that crashes leaves everything it managed to report up to the fault.

Process-tree nodes use `orc_begin_fixed`, which ignores `FIXTURE_ID`, so each
node writes its own file (`t_launcher.oracle`, `t_main.oracle`, …) and the whole
tree is reconstructible from the run directory after every process in it is gone.

## Regenerating

```sh
cd "/mnt/c/Users/.../.lexe/tests/workloads"
python3 generate_pe.py --out /tmp/lexe-workloads-pe --repeats 5 --jobs 8
# one family, one layer, quickly:
python3 generate_pe.py --only pe-tree --layers wine --repeats 2
```

Exit status 0 means every selected specimen reached `baseline-ok` on every layer
it declares. Expect a first run to take the better part of an hour: a fresh Wine
prefix costs ~35 s, a Proton prefix ~60 s, and `proton-run` is **serialised**
(see below) at roughly 5 s per invocation including its private display.

## Two environment facts that shape everything

**1. `proton run` needs a working X server, even for a console program.** Without
one it never returns: the guest runs to completion and writes its files, and
Proton's launcher hangs forever. `DISPLAY` merely *set* is not enough, and a
`DISPLAY` naming a display that does not exist is not enough either. Every
`proton-run` invocation in this corpus — including the one that creates the
Proton prefix — is therefore wrapped in the project's own namespaced X server
(`scripts/lib/private-display.sh`), never the real desktop. `wine` and
`proton-wine` both run perfectly headless, which is what makes this a property of
Proton's *launcher* rather than of Proton's Wine.

**2. `proton-run` must not be parallelised.** Two concurrent `proton run`
invocations against one Proton prefix intermittently produce a run in which the
guest never starts at all: no oracle file, no output, exit 0. Five serial repeats
are stable. The generator serialises that layer and runs every other layer in
parallel. A consumer who parallelises it will see phantom failures.

Both facts are recorded in `index.json` under `layers`, with the measurement that
established them.

## Display policy

GUI specimens run **only** on a private, namespaced X server. Every other
specimen runs with `DISPLAY` and `WAYLAND_DISPLAY` removed from its environment
entirely, so nothing can reach the developer's desktop even by mistake. The one
exception is `proton-run`, which needs a display to terminate at all, and gets a
private one for the same reason.

## Repeat-count stability

Every baseline is run **five times per layer** (`--repeats`). The index records
`deterministic_across_repeats` and, when false, the lines that moved. A specimen
that is deterministic once and not five times is worse than one known to be
nondeterministic, because it will eventually produce a mystery failure that gets
blamed on `.LEXE`. This is how the `proton-run` parallelism defect above was
found.

## The fixture manifest (`index.json`)

`schema: lexe.workload.pe-index/1`. Same shape as the ELF index, with the
per-layer parts added:

| Field | Contents |
|---|---|
| `layers` | one entry per layer actually used: what it is, its version, its prefix, how long the prefix took to create, **what was configured in that prefix and why**, whether its stdio is observable, and any measured constraint (needs a display, must be serialised) |
| `private_display` | the helper used, the wrapper written, and the policy |
| `toolchains` | `mingw64-O2`, `mingw64-O0`, `mingw32-O2`, `clang-mingw64-O2`, with versions |
| `support_binaries` | the two DLLs, the six process-tree executables, and where the C++ runtime DLLs were found on this host |
| `specimens[].binary.pe` | read out of the PE headers with `objdump -p/-f/-t/-h`: PE32 vs PE32+, machine, subsystem (CUI/GUI), imported DLLs, image base, DLL characteristics, symbol table and debug sections, and the `file(1)` string |
| `specimens[].declared` | hand-written before the run: exit code (or `nonzero_exit_required`), `expect`, `expect_by_layer`, `expect_one_of`, `expect_absent`, post-run files and their required content, PE properties, capabilities, filesystem effects, process behaviour, and `timeout_allowed` |
| `specimens[].baselines.<layer>` | every repeat, each with its launches (command, exit code, duration, oracle file presence, the parsed oracle, the deterministic lines, the observations, stream sizes and hashes, and the run-directory listing), plus `deterministic_across_repeats`, `unstable_lines`, `exit_codes_seen` and `stdio_observable` |
| `specimens[].cross_layer` | which layers agreed with the reference layer, and exactly which deterministic lines differ where they did not. **Kept out of the verdict on purpose** |
| `specimens[].verdict` | `baseline-ok`, `baseline-mismatch`, `build-failed` or `generator-error`, with reasons naming the layer |
| `layer_differences`, `unstable_specimens`, `differential_divergences` | corpus-level summaries |

### Declaring a legitimate per-layer difference

`expect_by_layer` is how a real difference is declared rather than papered over.
`pe-io-stdin-text-mode-ctrl-z` declares `STDIN_BYTES=4096` natively and
`STDIN_BYTES=35` under both Wine layers, because that is what the Windows C
runtime does and the specimen exists to pin it down.

`expect_one_of` is for a property whose outcome is a *platform* choice rather than
a program choice — an unhandled noncontinuable exception either ends the process
or does not, and both are legitimate observations of the layer.

## Coverage

| Family | n | Covers |
|---|---|---|
| `format` | 10 | x86-64 console PE, the same at -O0, 32-bit PE32 through WoW64, clang-built, stripped, a 48 MiB PE, C++ with the runtime linked in, C++ with the runtime DLLs bundled beside the exe |
| `gui` | 3 | a real window with a registered class and a message loop; the same program with no display at all; a GUI-subsystem PE that never creates a window |
| `io` | 6 | stdout only, stderr only, both, 4096 binary bytes of stdin, the DOS-EOF text-mode truncation, and what Proton's launcher does with stdin |
| `interface` | 7 | narrow argv (flags, empty, spaces, tabs), the wide command line through `CommandLineToArgvW` (UTF-8 round trip, spaces, embedded quotes), narrow and wide environment variables, `GetModuleFileNameW` vs `argv[0]` |
| `outcome` | 15 | exits 0/1/42/255, an access violation, `abort()`, `RaiseException`, `TerminateProcess` with a chosen status, a 500 ms run, a 3 s run, a deterministic CPU-bound run |
| `filesystem` | 7 | create/write/read/rename/delete, `GetTempFileNameW`, state across two launches, a backslash-relative asset, a non-ASCII filename through `CreateFileW`/`FindFirstFileW`, a `CreateDirectoryW` tree walk |
| `registry` | 1 | `HKCU` key created, a string and a DWORD written and read back with their types, then deleted |
| `dll` | 5 | an implicit import from a bundled DLL (with `DllMain` evidence), the same exe with the DLL **absent**, `LoadLibraryW` present, missing, and **wrong-architecture** |
| `process` | 7 | 4 and 64 Win32 threads with a critical section, a named mutex that really serialises, an event handoff, a named pipe |
| `sockets` | 3 | Winsock TCP loopback, UDP loopback, `getaddrinfo` |
| `process-tree` | 7 | the deliberate shape below |
| `layer` | 1 | what the layer says it is — every value an observation |

### The process tree

```
t_launcher.exe → t_bootstrap.exe → t_main.exe → t_helper.exe
                                                t_worker.exe
                                                t_crash_handler.exe
```

Six binaries, one mode token passed down the chain, seven shapes:

| Fixture | Shape |
|---|---|
| `pe-tree-chain-wait` | every parent waits; the launcher's exit really does mean the application finished |
| `pe-tree-launcher-exits` | **the case that matters**: the launcher exits 0 in milliseconds while the application is still starting |
| `pe-tree-bootstrap-only` | each parent exits as soon as its child is started; nothing above the application is left alive |
| `pe-tree-fanout` | three children at once — one clean, one exiting 33, one crashing — all reaped by the parent |
| `pe-tree-detach-helper` | `DETACHED_PROCESS`: a helper outlives the application that started it |
| `pe-tree-orphan-tree` | every parent exits immediately and a detached helper finishes alone |
| `pe-tree-crash-child` | a child dies of an access violation and its parent exits 0 having observed `0xC0000005` |

`t_helper.oracle` containing `HELPER_COMPLETED=yes` is the load-bearing evidence
in four of these: it means work survived the exit of everything that started it.
Each node reports its child's status as **decimal and hex**, because an abnormal
Windows status is unreadable in decimal and that is what this family is about.

## What running it taught us

Every one of these was found by running the corpus and comparing against a
hand-written declaration, not by reading documentation. They are recorded here
because each one would otherwise have surfaced later as a `.LEXE` finding that
was really a finding about Wine, Proton, the Windows C runtime, or my own
fixture.

**1. `proton run` delivers none of the guest's stdout or stderr.** The exit code
propagates and the files it writes appear, but the console output is gone. This
is why the oracle is a file. *(Design consequence for the whole corpus.)*

**2. `proton run` never returns without a working X server**, even for a console
program that never touches a display. `DISPLAY` merely set is not enough, and a
`DISPLAY` naming a nonexistent display is not enough. The guest completes either
way; Proton's launcher is what hangs. `wine` and `proton-wine` are both perfectly
headless.

**3. Under `proton run`, a guest that reads stdin blocks forever** — it starts,
writes its first oracle line, and never sees data or EOF, even with stdin at
`/dev/null`. `pe-io-stdin-under-proton-run` exists to record exactly that, and
its timeout is the declared outcome.

**4. `proton run` cannot be parallelised.** Two concurrent invocations against one
prefix intermittently produce a run where the guest never starts at all: no
oracle file, no output, exit 0.

**5. `proton run` leaves unkillable processes when interrupted.** Any interrupted
invocation — including by its own timeout, with no mount namespace anywhere —
leaves processes in uninterruptible `D` state waiting on a FUSE connection that
nothing will ever answer. `SIGKILL` does not touch them, they hold that Proton
prefix against every later run, and only restarting the WSL distro clears them.
**This is why `proton-run` is not a default layer**: a layer that cannot be
baselined is not a baseline. Proton coverage is carried by `proton-wine` —
Proton's own Wine binary and prefix, run directly — which is stable, headless,
parallel-safe and fully baselined. The generator still implements `proton-run`
and `--layers …,proton-run` selects it on a host where the launcher behaves.

**6. The system Wine is nondeterministic for an unhandled noncontinuable
exception.** `pe-outcome-abnormal-raise` resumed execution and exited 0 in four
repeats out of five, and died with exit 66 in the fifth. Proton's Wine killed it
with 66 all five times — and 66 is `0x42`, the low byte of the `0xE0000042`
exception code the specimen chose. The specimen is unchanged between repeats, so
the nondeterminism belongs to the layer; it is now **declared** via
`instability_expected` and `exit_one_of_by_layer`, so it can never be mistaken for
a `.LEXE` regression. **Four repeats would have called this stable.**

**7. Wine starts a debugger on an unhandled fault**, which hangs the parent's
`WaitForSingleObject` for the full timeout instead of letting the child die. Every
prefix is configured with `HKCU\Software\Wine\WineDbg ShowCrashDialog = 0`, and
that configuration is recorded as part of the layer. Before it, the `fanout` tree
took 120 s and reported `CRASH_WAIT=timeout`; after it, 1 s and
`CRASH_EXIT_HEX=0xc0000005`.

**8. An access violation has two different "exit codes" at once.** The parent PE
process sees `0xC0000005` through `GetExitCodeProcess`; the Unix caller of `wine`
sees 5. Both are recorded, and neither is declared as *the* answer.

**9. A cold Wine prefix makes the first GUI launch enormously expensive.** The
first windowed launch cost 2.3 s under system Wine and **320 s** under Proton's
Wine, after which every repeat took about 1 s. The GUI specimen therefore declares
a warm-up launch whose cost is recorded separately, so the measured repeats
describe steady state.

### Baseline mismatches in my own fixtures

Disclosed for the same reason as in the ELF corpus: a fixture bug fixed silently
is a fixture bug nobody learns from.

1. **`pe-io-stdin-consumed` declared 4096 bytes and got 35.** I had written a
   POSIX expectation for a Windows program: the C runtime opens stdin in **text**
   mode, where `0x1A` (Ctrl-Z, the DOS EOF) terminates the stream, and the
   runner's input has its first `0x1A` at offset 35. The specimen now asks for
   binary mode explicitly, and `pe-io-stdin-text-mode-ctrl-z` was added to pin
   down the truncation as a property in its own right.
2. **`pe-fs-cwd-relative-asset` looked nondeterministic and was not.** It reported
   the working directory under the deterministic key `CWD_HEX`, and the working
   directory differs per repeat by construction. The real properties were
   identical in all five repeats. `orc_wide_obs` was added so a wide string whose
   value depends on the environment cannot be emitted under a deterministic key.
3. **`pe-socket-name-resolution` flaked on the second generation.** The bogus-name
   lookup returned `WSATRY_AGAIN` after a 15-second DNS timeout on one repeat
   instead of `WSAHOST_NOT_FOUND`. *Which* failure a resolver reports is
   environment-dependent; that it failed is not. The code is now an observation.
4. **`pe-outcome-abnormal-raise` was declared with one outcome for every layer.**
   Its baseline corrected it twice: first that Wine and Proton's Wine disagree,
   then that the system Wine disagrees with itself (finding 6).
5. **`pe-dll-implicit-missing` did not build.** Its stage told the generator not to
   link the import library, so the specimen that must *fail to start for want of a
   DLL* failed to compile instead — which is not the same thing at all, and would
   have been a hole disguised as a row.
6. **`pe-tree-fanout` passed while its `WaitForSingleObject` timed out.** The
   parent reported `RESULT=PASS` without checking that it had actually reaped the
   crashing child. It now checks all three children explicitly.

## Deliberately NOT generated

- **A full `proton-run` baseline.** Implemented, attempted at length, and
  abandoned for the five measured reasons above. Reported rather than faked: a
  layer that cannot be baselined is not a baseline.
- **GUI under `proton-run`.** A window needs the namespaced private display, and
  `proton-run` must not be run inside a mount namespace. The two requirements are
  incompatible on this host, so the GUI specimens declare `wine` and `proton-wine`.
- **ARM64 or ISA-translated PE.** No FEX, Box64 or qemu-user here, and a specimen
  that cannot run is not coverage.
- **Anything needing a real Windows.** `.NET`, MSI installers, drivers, services,
  DirectX and COM servers all need components this host does not have. Each would
  be its own pass with its own evidence.
- **Malformed or hostile PE.** That is a `.LEXE` *verification* input, not a
  workload; every specimen here is a legitimate program.
- **Deliberate `SetErrorMode`/`MessageBox` dialogs**, or anything else that waits
  for a human. Every specimen is bounded and closes itself.
- **Blind flag permutations.** Four toolchain configurations on a chosen subset,
  each with a stated reason; `-O1`, `-Os`, `-flto`, `-fsanitize`, and `/MT` style
  runtime permutations were left out because none of them was tied to an assumption
  worth probing here.
- **Timings as assertions.** Every duration is an `OBS_` value. Wine and Proton
  differ by more than an order of magnitude on a cold prefix, and the first
  `proton run` of a prefix costs about a minute.

## Adding a specimen

1. Write one small program in `specs_pe/` that isolates **one** property, using
   `oracle_win.h`. Anything environment-dependent goes behind `orc_obs` or
   `orc_wide_obs` — including working directories, module paths, ports, pids and
   every duration.
2. Add one `S(...)` entry to `generate_pe.py`, with the expectations written
   **before** you run it. If a property legitimately differs per layer, say so with
   `expect_by_layer`; if the outcome is a platform choice, use `expect_one_of`; if
   the layer is nondeterministic, declare it with `instability_expected` and say how
   you measured that.
3. Regenerate with `--repeats 5`. A `baseline-mismatch` means the fixture or the
   declaration is wrong. Fix it, and write down what you got wrong.

## Hygiene

Wine and Proton leave server processes behind. The generator kills the wineservers
for its own prefixes when it finishes, and records
`host.preexisting_wine_processes` when it starts, because debris from a previous
interrupted run demonstrably interferes with prefix creation. If a generation is
interrupted, check for leftover `wineserver`, `*.exe` and `Xvfb` processes before
starting another one — and note that `proton run` can leave processes that cannot
be killed at all (finding 5).

## Corpus at a glance (as measured on this host)

| Fact | Value |
|---|---|
| Specimens | 72 (63 base + 9 compiler differentials) |
| Layer cells | 159 — `wine` 71, `proton-wine` 71, `native` 17 |
| Baseline runs per generation | 805 (5 repeats per cell, plus the two-launch and warm-up specimens) |
| Verdicts | **72 baseline-ok**, 0 mismatch, 0 build failures |
| Unstable across 5 repeats | 0 undeclared; 1 declared (`pe-outcome-abnormal-raise`, with the measurement) |
| Compiler differentials | 9, **0 substantive divergences** |
| Recorded layer differences | 3 (`pe-io-stdin-consumed`, `pe-io-stdin-text-mode-ctrl-z`, `pe-outcome-abnormal-raise`) |
| Cross-generation determinism | **159/159 cells identical**, **72/72 binaries byte-identical** |
| Toolchains | mingw64-O2 (60), clang-mingw64-O2 (5), mingw32-O2 (4), mingw64-O0 (3) |
| Wall time | ~7.3 min per generation at `--jobs 8`; prefixes ~44 s each |
| Largest / smallest binary | 50,587,594 B / 40,960 B |
| Compiler diagnostics | none |

Byte-identical binaries need `-Wl,--no-insert-timestamp`, which the generator
always passes: without it two builds of one source differ in exactly two bytes
(the PE `TimeDateStamp`). Verified under gcc x86-64, gcc i686 and clang.

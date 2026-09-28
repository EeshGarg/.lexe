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

> **The corpus does not persist. `/tmp` is wiped when the WSL distribution
> restarts**, and that takes the whole of `--out` with it: the binaries, the
> prefixes, the per-specimen run directories and `index.json`. **Nothing in this
> document may be cited as a current measurement unless the corpus has been
> regenerated in the live distro.** A stale `index.json` from a previous boot is
> the most dangerous artifact here, because it is complete, internally consistent
> and describes a tree that no longer exists — check its `generated_at` and the
> mtime of the file before believing a word of it. Regenerating is the only way
> to make the numbers below true again; it is also the only way to get the
> binaries back, since the repository holds sources and a generator and never
> build products.

`windres` is now a build dependency: `pe-format-resources` compiles a `.rc` into
a COFF object carrying a `.rsrc` section, so `x86_64-w64-mingw32-windres` (and
`i686-w64-mingw32-windres` for the 32-bit cells) must be installed. A missing
`windres` is a **build failure**, reported as such, never a silently skipped row.

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
| `support_binaries` | the four DLLs — including the **two same-named `wsearch.dll` builds** in separate directories that make DLL search order observable — the **ten** process-tree executables with the flags each was built with, and where the C++ runtime DLLs were found on this host |
| `specimens[].build.resources` | for a specimen with a `.rc` source, the `windres` command and whether it succeeded. A missing or failing `windres` is a build failure, never a skipped row |
| `specimens[].baselines.<layer>.repeats[].launches[].stdio_pipe_still_held_after_exit` | the guest exited but something still held the write end of its stdout/stderr — a lingering Wine service, usually. An observation about the layer; everything the guest wrote was already collected |
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
or does not, and both are legitimate observations of the layer. It is used
sparingly and never to make a failing declaration pass: the three current uses are
a non-blocking loopback `connect` (Windows always defers it, a Unix kernel behind
a layer need not), a path longer than `MAX_PATH` through the `\\?\` prefix (which
depends on the filesystem underneath), and `AddDllDirectory`, whose very existence
is a property of the Windows being emulated.

### Never an offset over a stream that carries `FIXTURE_ID`

A deterministic oracle value is **never** a byte position, length or count over a
stream that also carries `FIXTURE_ID`. `FIXTURE_ID` is environment-derived, so an
offset measured past it moves when the environment moves — a "deterministic" value
that is nothing of the sort. The bulk, binary and paced output specimens are built
around that rule:

- the payload is written a second time to a file of its own (`bulk.bin`,
  `binary.out`, `paced.log`) that carries nothing else, and **that** file's length,
  hash and line count are the deterministic claims;
- in the stream the payload is bracketed by **delimiter lines**
  (`BULK_PAYLOAD_BEGIN` … `BULK_PAYLOAD_END`), so a consumer locates it by
  **content**, never by offset;
- any absolute offset is reported under `OBS_`.

The same rule is why `pe-fs-file-position` can assert exact numbers like
`SIZE_AFTER_EXTEND=200`: every one of them is an offset into the specimen's own
data file, which never carried an oracle line at all.

## Coverage

| Family | n | Covers |
|---|---|---|
| `format` | 15 | x86-64 console PE, the same at -O0, 32-bit PE32 through WoW64, clang-built, stripped, a 48 MiB PE, a **PE resource directory** built by windres, and **all four** C++ runtime packagings (both linked in, both shipped as DLLs beside the exe, and each of the two one-sided splits) with the import table read out of the PE to prove which was built |
| `gui` | 6 | a real window with a registered class and a blocking message loop; the same with no display at all; a GUI-subsystem PE that never creates a window; a **console-subsystem** PE that *does*; a **PeekMessage game loop** with an exact frame count; **GDI rendering checked by reading the pixels back** |
| `io` | 14 | stdout only, stderr only, both, 4096 binary bytes of stdin, the DOS-EOF text-mode truncation, what Proton's launcher does with stdin, **256 KiB on stdout / stderr / both**, **4 MiB on stdout**, **binary output with NULs**, **slowly paced output**, and **what the standard handles actually are** |
| `interface` | 7 | narrow argv (flags, empty, spaces, tabs), the wide command line through `CommandLineToArgvW` (UTF-8 round trip, spaces, embedded quotes), narrow and wide environment variables, `GetModuleFileNameW` vs `argv[0]` |
| `outcome` | 25 | exits 0/1/2/42/127/255, **256, 1000 and 0xC0000005 chosen deliberately**, an access violation, `abort()`, `RaiseException`, `TerminateProcess`, a **top-level exception filter that converts a crash into a chosen exit code**, **vectored-handler ordering**, an **exception continued from**, a 500 ms run, a 3 s run, a deterministic CPU-bound run |
| `filesystem` | 18 | create/write/read/rename/delete, `GetTempFileNameW`, state across two launches, a backslash-relative asset, a non-ASCII filename, a `CreateDirectoryW` tree walk, **kernel-enforced share modes**, **DOS attributes**, **directory error paths**, **memory-mapped files and named sections**, **case-insensitive/case-preserving names**, **exact FILETIMEs**, **SetEndOfFile and zero-filled extension**, **CopyFile/MoveFileEx**, **deep and over-MAX_PATH paths**, **overlapped I/O** |
| `registry` | 4 | a typed round trip; **subkey and value enumeration** to `ERROR_NO_MORE_ITEMS`; **REG_BINARY / REG_MULTI_SZ / REG_EXPAND_SZ / REG_QWORD**; the **error paths** (absent key, absent value, `ERROR_MORE_DATA`) |
| `dll` | 9 | implicit import from a bundled DLL (with `DllMain` evidence), the same exe with the DLL **absent**, `LoadLibraryW` present / missing / **wrong-architecture**, and **search order**: application directory wins, `SetDllDirectoryW`, an absolute path, `AddDllDirectory` |
| `process` | 23 | 4 and 64 Win32 threads, a named mutex, an event handoff, a named pipe, **TLS both ways**, a **counting semaphore**, **WaitForMultipleObjects**, **Interlocked atomics with exact totals**, **SRWLOCK + CONDITION_VARIABLE**, **fibers**, **APCs**, **CREATE_SUSPENDED and nested suspend counts**, a process **spawning itself with redirected handles**, and a **job object** |
| `memory` | 2 | `VirtualAlloc` reserve/commit/protect/decommit/release verified by `VirtualQuery`; `PAGE_NOACCESS` **actually enforced**, the fault caught and converted |
| `sockets` | 6 | Winsock TCP loopback, UDP loopback, `getaddrinfo`, **IPv6 loopback**, **non-blocking sockets and `select`**, and **four distinct socket errors** |
| `process-tree` | 18 | the deliberate shapes below |
| `layer` | 1 | what the layer says it is — every value an observation |

### The process tree

Ten binaries now, one mode token passed down the chain, eighteen shapes. The
payload chain is three levels deep in most modes and **six** in the `deep-*` ones:

```
t_launcher.exe ─┬─ t_bootstrap.exe ─┬─ t_main.exe ─┬─ t_helper.exe
                │                   │              ├─ t_worker.exe ─┬─ t_grandchild.exe
                │  (deep-* only)    │              │                └─ t_crash_handler.exe
                │  t_stage2.exe ────┘              ├─ t_crash_handler.exe
                │                                  └─ t_supervisor.exe ── t_worker.exe ×3
                └─ t_window.exe   (gui-top: a sibling of the whole chain)
```

`t_window.exe` is the only **GUI-subsystem** binary in the family (`-mwindows`),
because in real Windows software the process that owns the window and the process
doing the work are usually not the same process.

| Fixture | Shape |
|---|---|
| `pe-tree-chain-wait` | every parent waits; the launcher's exit really does mean the application finished |
| `pe-tree-launcher-exits` | **the case that matters**: the launcher exits 0 in milliseconds while the application is still starting |
| `pe-tree-bootstrap-only` | each parent exits as soon as its child is started; nothing above the application is left alive |
| `pe-tree-fanout` | three children at once — one clean, one exiting 33, one crashing — all reaped by the parent |
| `pe-tree-detach-helper` | `DETACHED_PROCESS`: a helper outlives the application that started it |
| `pe-tree-orphan-tree` | every parent exits immediately and a detached helper finishes alone |
| `pe-tree-crash-child` | a child dies of an access violation and its parent exits 0 having observed `0xC0000005` |
| `pe-tree-deep-chain` | **six levels**, five nested waits; a status chosen at the bottom (44) carried all the way up |
| `pe-tree-deep-orphan` | six levels, **not one wait anywhere**; the deepest node writes the persistent state 2.5 s after the launcher returned 0 |
| `pe-tree-grandchild-survives` | every process the launcher can see is reaped *with the right status*, while a detached **grandchild** works on for another 2.5 s |
| `pe-tree-supervisor-restart` | a **supervisor restarts the same worker three times** and collects each status separately |
| `pe-tree-redirect-to-file` | the parent opens a file and hands it to the child as **both** its standard handles |
| `pe-tree-split-stdio` | a child that **inherits stderr and has stdout redirected** to a file — both halves asserted |
| `pe-tree-no-wait-crash` | a child crashes and its parent **never asks**: every exit status in the tree is 0 |
| `pe-tree-crash-at-depth` | the crash is **four levels down** and the level above it reports a clean, *specific* 33 |
| `pe-tree-wait-timeout` | a parent **waits with a deadline**, gives up after 500 ms, and exits while the child works on |
| `pe-tree-gui-leaf` | the **window is owned by a detached leaf** that outlives everything that started it |
| `pe-tree-gui-top` | the **launcher owns the window**; work two levels down takes it away by a side effect |

What each one makes observable, in one line each:

- **Window ownership** varies independently of the payload chain: bottom
  (`gui-leaf`) and top (`gui-top`). A window belongs to the thread that created it
  and cannot outlive that thread, so *"the window outlives the process that created
  it"* is not something any program can do; the real version of it — the window and
  its owning process outliving everything that **started** them — is `gui-leaf`,
  and the window node proves it by finding `main_exited.flag` on disk rather than
  inferring it from a sleep.
- **Stream ownership** varies independently too: both streams to one file
  (`redirect-to-file`), one inherited and one redirected (`split-stdio`). The
  worker writes one line to stderr specifically so the two can be told apart, and
  `split-stdio` asserts *both* that the redirected line is in the file and that
  the inherited line is **not**.
- **Who waits**: always (`chain-wait`, `deep-chain`), never (`bootstrap-only`,
  `orphan-tree`, `deep-orphan`, `no-wait-crash`), or with a deadline
  (`wait-timeout`).
- **Who notices a crash**: the parent that waits (`crash-child`), the parent that
  does not (`no-wait-crash`), and the one that waits but is four levels too high
  (`crash-at-depth`).
- **Persistent state** is owned by the *deepest, latest* process: every node
  appends its own line to `tree_state.dat`, and in `deep-orphan` the last line is
  written by the grandchild long after every ancestor has gone. The declaration
  checks each node's line is **present**, never the order — the order is not a
  contract.
- **Repeated spawning**: `supervisor-restart` starts three sequential children
  from one image in one process. It also creates the evidence problem a restart
  loop always creates — `supervisor.log` accumulates while `t_worker.oracle` is
  overwritten — which is why the log is a declared post-run file.

`t_helper.oracle` containing `HELPER_COMPLETED=yes`, and `t_grandchild.oracle`
containing `GRANDCHILD_COMPLETED=yes`, are the load-bearing evidence across most of
these: they mean work survived the exit of everything that started it. Each node
reports its child's status as **decimal and hex**, because an abnormal Windows
status is unreadable in decimal and that is what this family is about.

### Why one tree mode has a wait that is not part of its shape

`pe-tree-gui-leaf` is the one place where the harness leaks into the fixture, and
it is called out in `t_launcher.c` as well as here. A GUI specimen runs inside a
**private, namespaced X server**; when the process the wrapper launched returns,
that namespace and its display go away and take any surviving process with them.
So the launcher polls for the window node's own flag file before exiting. It never
waits on a process handle — it never had one — and the evidence that the window
outlived its starters is `t_window.oracle`, not that wait.

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

**9. Proton's Wine calls the very same pipes a character device; the system Wine
calls them a pipe.** The generator hands every specimen the same three pipes on
every layer. Under `wine`, `GetFileType` on all three returns `FILE_TYPE_PIPE`;
under `proton-wine` it returns `FILE_TYPE_CHAR`. Both then fail `GetConsoleMode`
with `ERROR_INVALID_HANDLE` — so under Proton's Wine the two questions a program
asks to find out whether it is interactive give **contradictory** answers.
Coloured output, progress bars and prompting all branch on exactly this, so the
same program is liable to behave differently under the two layers for reasons that
have nothing to do with `.LEXE`. Declared with `expect_by_layer` in
`pe-io-standard-handles`.

**10. A clang-built `__thread` crashes under Proton's Wine and works under the
system Wine.** `pe-tls-both-mechanisms` passes everywhere when gcc builds it —
both Wines, `-O2`, and 32-bit. Rebuilt by **clang** for the same target it still
passes under the system Wine (complete oracle, `RESULT=PASS`, exit 0) and dies
under Proton's Wine with an access violation, exit 5, immediately after `TlsAlloc`
returns: the oracle file stops at `OBS_TLS_SLOT_INDEX`, before the first touch of
the `__thread` variable. Deterministic across five repeats on both layers. This is
a legitimate program, built by a legitimate installed toolchain, that runs under
one Wine and not another — and it is exactly the assumption the differential was
added to probe. It is now **declared** per layer rather than left to surface later
as a mystery.

**11. Truncating a Windows exit status is not a plain `& 0xFF`.** A guest exiting
1000 gives the Unix caller 232, and one exiting `0xC0000005` gives 5 — both as
predicted. But a guest exiting **256** gives **1**, not 0: a non-zero Windows
status whose low byte happens to be zero is reported as 1 rather than allowed to
become a success. Sensible, and not what I had declared. The consequence for a
supervisor is that the exact status is lost while the failure is not, and the
oracle file is where the full 32-bit intent survives either way.

**12. A send on a never-connected socket reports `WSAECONNRESET` here, not
`WSAENOTCONN`.** Wine relays the Unix `EPIPE` rather than synthesising the Win32
error Windows documents. The other three errors in `pe-socket-error-paths` came
back exactly as declared. This one matters because a reconnect loop reads
`WSAECONNRESET` as *"the peer went away, retry"* and `WSAENOTCONN` as *"you have a
bug"*, so the same code takes a different branch under the layer.

**13. A finished guest can still hold the harness open, and it cost a 300-second
timeout to notice.** `pe-tree-gui-top` under Proton's Wine completed its entire
six-process tree in about a second — every oracle file present, `RESULT=PASS` at
the launcher, every flag written — and the generator sat there for the full 300 s
timeout anyway, once in five repeats. The cause was not the guest: a Wine service
process left alive in the private display's namespace had **inherited the guest's
stdout and stderr**, so the pipes never reached EOF, and `subprocess.communicate()`
waits for EOF rather than for the child. The generator now drains the pipes in
threads and waits for the **process**, recording
`stdio_pipe_still_held_after_exit` when the write end outlives the guest. It
deliberately does **not** kill the process group to break the deadlock: several
specimens leave a detached process running past the launcher's exit on purpose and
the generator reads what it writes afterwards, so killing the group would destroy
exactly the evidence those specimens exist to produce.

**14. A cold Wine prefix makes the first GUI launch enormously expensive.** The
first windowed launch cost 2.3 s under system Wine and **320 s** under Proton's
Wine, after which every repeat took about 1 s. The GUI specimen therefore declares
a warm-up launch whose cost is recorded separately, so the measured repeats
describe steady state. All six GUI specimens now declare one.

**15. `Sleep` and `QueryPerformanceCounter` are different clocks, and one of this
corpus's own checks had quietly assumed they were not.** `pe-run-bounded-3s`
required the elapsed performance-counter time to be within 20 ms of the requested
3000 — 0.67% — and on a busy host it came back at **2962 ms**, under both Wines,
across repeats. `Sleep` did not return early in any useful sense; the two clocks
simply do not agree to better than a few tens of milliseconds when the machine is
loaded. That check was a **performance assertion wearing a correctness
assertion's clothes**, which this corpus forbids everywhere else, and it had been
passing quietly on an idle machine since the specimen was written. The
deterministic check is now the one that actually separates a working `Sleep` from
a layer that dropped it on the floor, and the clock disagreement itself is
reported as `OBS_SLEEP_VERSUS_QPC_MS` and `OBS_QPC_AGREED_WITHIN_20MS`, where it
is visible instead of fatal.

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
7. **`pe-fs-sharing-mode` had the sharing rule backwards, and the layer was
   right.** I declared that a reader asking for `FILE_SHARE_READ` could open a file
   a writer was holding with `FILE_SHARE_READ`; it was refused. The check is
   **symmetric**: the new opener's share mode has to permit the access existing
   handles already hold, as well as the other way round, and a reader demanding
   `FILE_SHARE_READ` alone is saying *nobody may write this* while somebody
   already is. The C source was fixed to permit the writer — and the wrong case was
   **kept**, as `READER_WITH_INCOMPATIBLE_SHARE`, because a layer that enforced only
   one direction would pass the corrected check and fail that one. A fixture bug
   that turned into a specimen.
8. **`pe-outcome-exit-256` declared exit 0 and got 1.** See finding 11 above. The
   reasoning behind the declaration ("a Unix wait status is eight bits") was
   confirmed by the other two specimens in the same family and wrong for this one.
9. **`pe-socket-error-paths` declared `WSAENOTCONN` and got `WSAECONNRESET`.** See
   finding 12. The declaration now records what this platform actually does, with
   the difference from documented Windows stated rather than smoothed over.
10. **`pe-io-standard-handles` declared `pipe` on every layer.** It is `pipe` under
    the system Wine and `char` under Proton's — finding 9. Now `expect_by_layer`.
11. **`pe-tls-both-mechanisms--clang-mingw64-O2` was declared as a plain clone of
    its base and is not one.** Finding 10. Its declaration was split per layer
    after the fact, in the block at the bottom of the specimen table, so the
    difference is recorded as a property of the layer rather than as a failure.
12. **`pe-run-bounded-3s` had a 0.67% timing tolerance in a deterministic check.**
    Finding 15. This one was not written this pass — it was already in the corpus,
    green, and only failed once the machine was busy enough to expose it. That is
    the worst kind of fixture bug: one that passes for months and then fails for a
    reason that has nothing to do with what it is testing. The tolerance is now
    tied to what the check is actually for, and the clock disagreement it was
    accidentally measuring is an observation in its own right.
13. **The generator waited for EOF on pipes the guest no longer owned.** Finding
    13 — a harness bug rather than a fixture one, but the same disease: a 300 s
    timeout on a run that had in fact succeeded in about a second, which would have
    been reported as a flaky specimen by anyone who did not open the oracle files.

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
  worth probing here. The same test applied to every new differential: eleven of
  them now, each naming the assumption a *second* toolchain could break, and the
  ones that would only have raised the count were not added.
- **A second process for the IPC specimens.** The named pipe, the named mutex, the
  named semaphore and the named section are all exercised across two *handles* and
  two *threads* in one process, not across two processes. Two-process IPC is
  covered where it is genuinely different — `pe-proc-self-spawn-redirect` and the
  whole `process-tree` family — and duplicating the pipe specimen across a process
  boundary would have added a row without adding a mechanism.
- **A GUI specimen that waits for input.** Every window here closes itself.
  `SetErrorMode`/`MessageBox` dialogs and anything else that waits for a human are
  still out, for the same reason as before.
- **`AddVectoredExceptionHandler` returning `EXCEPTION_CONTINUE_EXECUTION` from a
  memory fault.** Recovering from an access violation by patching the faulting
  register is architecture-specific in a way that would make the specimen say more
  about the specimen than about the layer. The continuable case is covered instead
  with `RaiseException`, where continuing is well defined.
- **Multi-process shared memory.** The named section is opened twice by name in one
  process, which proves it is one object; doing it across two processes needs a
  second binary and proves the same thing about the section, so it was not added.
- **Icons and manifests in the resource directory.** `w_resource.rc` carries a
  string table, an RCDATA blob and a VERSIONINFO block — three resource types read
  back three different ways. An icon would need a binary `.ico` checked into the
  tree, and an application manifest changes process-wide behaviour (DPI awareness,
  comctl32 version) in ways that belong in their own pass with their own evidence.
- **Timings as assertions.** Every duration is an `OBS_` value. Wine and Proton
  differ by more than an order of magnitude on a cold prefix, and the first
  `proton run` of a prefix costs about a minute.

## Adding a specimen

1. Write one small program in `specs_pe/` that isolates **one** property, using
   `oracle_win.h`. Anything environment-dependent goes behind `orc_obs` or
   `orc_wide_obs` — including working directories, module paths, ports, pids and
   every duration. If the specimen produces bulk output, write it to a file of its
   own as well and put the deterministic claims **there**; never report an offset
   into a stream that also carries `FIXTURE_ID` (see above).
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

Some of that debris **inherits the guest's pipes** and can therefore outlive the
guest on the reading end as well as the running end; see finding 13 for what that
did before the generator stopped waiting for EOF.

**Do not draw timing conclusions from a generation that shared the machine.** This
corpus is developed on a host that other work runs on, and several of the numbers
below moved by a factor of two between generations for that reason alone. Every
duration in `index.json` is an `OBS_` value precisely so that a slow run is never
mistaken for a wrong one — and finding 15 below is the story of the one place a
timing assumption had quietly been written down as a correctness check anyway.

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

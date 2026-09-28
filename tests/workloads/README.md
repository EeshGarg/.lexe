# `.LEXE` workload corpus — Linux ELF factory

Legitimate, deliberately unusual Linux programs for `.LEXE` to consume. This
directory contains **sources and a generator**, not binaries: the corpus is a
pure function of `specs/` plus `generate.py`, and is regenerated on demand into a
scratch directory outside the repository.

Nothing here knows anything about `.LEXE`. These programs do not test `.LEXE`;
they are the material a test can be made of. Whether `.LEXE` runs them correctly
is not a question this directory answers, and no file here should ever be
weakened so that something else passes.

## The golden rule

```
source -> compiler -> binary -> DIRECT EXECUTION -> known observable behaviour
       -> fixture accepted into the corpus -> only then used as test material
```

Every specimen is compiled, executed directly, and compared against
hand-written declarations *before* it is admitted. A specimen with no verified
direct-execution baseline cannot distinguish "`.LEXE` is broken" from "the
fixture is broken", so it is not evidence. The index records the verdict per
specimen: **only `verdict.status == "baseline-ok"` may be used as test
material.**

## Regenerating

> **`/tmp` does not survive a WSL restart — three times in one day here.**
> The default corpus root is `/tmp/lexe-workloads`, and a corpus generated
> before a restart is simply gone. **Prefer `--out ~/lexe-workloads`**, which
> survives; the `/tmp` default is kept only because other lanes already point at
> it, and changing it is a cross-role decision rather than this directory's.
>
> Either way, **regenerate before citing any of it**, and check `index.json`'s
> `generated_at` against the time of the claim you are making. An `index.json`
> from a previous boot is not stale in any way you can see by reading it; it is
> a complete, plausible, internally consistent description of files that no
> longer exist. The same applies to the PE, portable and foreign corpora.

Inside WSL (the corpus is Linux-native and must not be built on `/mnt/c`):

```sh
cd "/mnt/c/Users/.../.lexe/tests/workloads"
python3 generate.py --out /tmp/lexe-workloads --jobs 12
# a subset:
python3 generate.py --out /tmp/lexe-workloads --only linux-socket
```

Exit status 0 means every selected specimen reached `baseline-ok`. Build
products, run directories and `index.json` all land under `--out`
(default `/tmp/lexe-workloads`); nothing is written back into the repository.
**Cost, measured rather than remembered.** Eleven consecutive full generations,
every one of them `201 specimens, baseline-ok=201`, on 24 cores at `--jobs 12`:

| | value |
|---|---|
| wall time | median **25.2 s**, p90 25.7 s, max 27.0 s (11 samples) |
| CPU time | median **72.2 CPU-seconds** (50.3–55.8 user + 19.6–21.8 sys, 7 samples) |
| direct execution, per specimen | median **14.6 ms**, p95 2.19 s, p99 6.86 s, max 10.0 s; 152 of 201 finish under 100 ms |
| direct execution, total | 66.3 s across all 201 specimens |

**Why there is a control.** Three other roles were working on this machine and
the 1-minute load average did not drop below 3 once in fifteen minutes of
waiting, so the first eight samples were taken at loads between **8.1 and 19.3**.
A wall time taken on a contended host is a measurement of the other work, and
quoting one as a figure is how 37–41 s of Wine prefix creation once became a
documented 152 s and manufactured a mystery that did not exist. So three more
samples were taken later, the first of them at **load 2.51**:

| | loaded (8 samples, load 8.1–19.3) | quiet (3 samples, load 2.5–10.8) |
|---|---|---|
| wall | 23.87 – 26.97 s | 25.44 – 25.70 s |
| CPU | 68.3 – 77.6 CPU-s | 69.9 – 73.2 CPU-s |

They agree, so the loaded samples were measuring the generator and not the other
roles — 12 jobs on 24 cores were not fighting for CPU here. Without that control
neither set would be quotable, and **CPU time is still the figure to prefer**,
because it is what the generator costs rather than what this afternoon cost.

The p99 and the maximum of the per-specimen distribution are dominated by four
specimens that are *supposed* to be slow: `linux-run-long-10s` sleeps for ten
seconds on purpose, and the 256 MiB and 2×128 MiB streams take as long as they
take. The median of 14.6 ms is the honest description of a specimen.

Layout produced:

```
/tmp/lexe-workloads/
  index.json                  the corpus manifest (see below)
  bin/<fixture-id>            most specimens
  bin/helper_child            the exec/fork target used by several specimens
  lib/lib{alpha,beta,gamma,plugin,ver,thrower}.so
  stage/<fixture-id>/bin,lib  specimens whose property IS the directory layout
  run/<fixture-id>/           the working directory each baseline ran in, kept
  run/<fixture-id>/stdio/     the files a non-pipe stdio shape produced
  run_on_private_display.sh   how the gui specimens got a display
```

The GUI specimens run inside a private mount and network namespace, so run the
generator with the developer's display severed —
`env -u DISPLAY -u WAYLAND_DISPLAY python3 generate.py …` — which is also what
the project's other lanes do.

## The behavioural oracle

Specimens emit `KEY=VALUE` lines, never prose. The contract (also stated at the
top of `specs/oracle.h`):

| Form | Meaning |
|---|---|
| `KEY=value` | **deterministic.** Must match the baseline byte for byte. |
| `OBS_KEY=value` | an **observation**: pid, path, port, duration, kernel detail. Environment-dependent. Never a failure on its own. |
| `RESULT=PASS` / `RESULT=FAIL` | the specimen's own self-check verdict, last line of the oracle stream. `FAIL` means the program ran and reported that its environment did not behave as it requires. |
| no `RESULT` line | the specimen did not reach its end: crash, signal, timeout — or it `exec`ed into something else on purpose. |
| `EXPECT_DEATH=<how>` | printed by specimens that are **supposed** to die, so a missing `RESULT` is still distinguishable from an accident. |
| `FIXTURE_BUILD_ID=<id>` | **the identity oracle.** Compiled into the binary. The same value under direct execution and under anything else. |
| `FIXTURE_ID=<id>` | the identity the **environment** claimed. Treat it as an observation. |

### Which specimen is this? Use `FIXTURE_BUILD_ID`, not `FIXTURE_ID`

`FIXTURE_ID` reaches the program through the environment — this generator sets
it — and a conforming runtime is **required to reset the environment**
(FORMAT-0.1 §9.5.2). So under one, every specimen falls back to the literal its
*source* was written with, and several specimens share a source: `io_stream.c`
backs five fixtures and all five answer `linux-io-stream`. An independent test
pass took **16 false violations** from exactly that before it was found.

This is the same shape as the `ERR_PAYLOAD_OFFSET` defect below, and worth
stating as a rule: **a value can be perfectly stable across every baseline run
precisely because the baseline holds the environment constant**, and diverge the
moment something legitimately does not. A baseline cannot see that class of
problem at all, because the thing that varies is the thing the baseline fixes.

So every specimen also carries `FIXTURE_BUILD_ID`, put in the binary at compile
time with `-DLEXE_FIXTURE_BUILD_ID="<fixture id>"`. Nothing outside the program
can clear, rewrite or forget it. The generator **checks** it — a specimen whose
compiled-in identity disagrees with the fixture it was built as, or that reaches
its end without emitting one at all, is a `baseline-mismatch` — so this is an
enforced property and not a convention.

Measured, on two specimens built from one source:

```
# as the generator runs them
[linux-io-stream-4mib]   FIXTURE_BUILD_ID=linux-io-stream-4mib   FIXTURE_ID=linux-io-stream-4mib
[linux-io-stream-64mib]  FIXTURE_BUILD_ID=linux-io-stream-64mib  FIXTURE_ID=linux-io-stream-64mib

# under `env -i`, as a conforming runtime leaves them
[linux-io-stream-4mib]   FIXTURE_BUILD_ID=linux-io-stream-4mib   FIXTURE_ID=linux-io-stream
[linux-io-stream-64mib]  FIXTURE_BUILD_ID=linux-io-stream-64mib  FIXTURE_ID=linux-io-stream
```

Two different specimens, indistinguishable by `FIXTURE_ID` — that is the shape
of the 16 false violations — and correctly told apart by `FIXTURE_BUILD_ID`.
`linux-env-emptied` makes the point without needing a runtime at all: it
re-executes itself with `environ` literally empty, and its second phase reports
`FIXTURE_BUILD_ID=linux-env-emptied` and `ENVIRON_COUNT=0`.

Consumers: compare `FIXTURE_BUILD_ID` to know which specimen produced a stream.
Both identity lines are excluded from the compiler-differential comparison, for
two different reasons: `FIXTURE_ID` because the generator sets it per specimen,
`FIXTURE_BUILD_ID` because a differential is a different binary by definition.

The oracle stream is stdout unless `declared.oracle_stream` says `stderr` (used
by the specimens whose property is that stdout carries binary or bulk data).

A key printed more than once reports its **final** value in `oracle`; the full
ordered stream is in `oracle_deterministic_lines`, and repeated keys are listed
in `oracle_repeated_keys`.

A non-zero exit code is frequently the *declared* outcome
(`linux-outcome-exit-42`, `linux-outcome-atexit-order` exits 7). `RESULT=PASS`
with a non-zero exit is normal and must not be read as a malfunction.

## The fixture manifest (`index.json`)

`schema: lexe.workload.index/1`. Filenames are not a source of truth; this file
is. Top level:

| Field | Contents |
|---|---|
| `generated_at`, `generator` | timestamp, generator filename and its own sha256, wall seconds, job count |
| `host` | uname, distro, libc version, nproc, page size, unprivileged-userns sysctls |
| `private_display` | the helper that gave the `gui` specimens a display, and the sha256 of `scripts/lib/private-display.sh` that provided it — the isolation is part of the definition of those runs |
| `stdio_shapes` | the eight connection shapes, each described in words, so a consumer reading `baseline.runs[].stdio_shape.mode` does not have to guess what it means |
| `toolchains` | for each of `gcc-O0`, `gcc-O2`, `clang-O0`, `clang-O2`: driver, version string, optimisation flags, common flags |
| `absent_toolchains` | anything declared but not installed here (empty on this host) |
| `support_libraries`, `helper_binary` | the shared libraries and exec target, with link commands and hashes |
| `counts`, `families`, `differential_divergences` | corpus summary |
| `specimens[]` | one record per specimen |

Each specimen record:

| Field | Contents |
|---|---|
| `id` | the fixture id; also the binary name |
| `family`, `property`, `notes` | one property per specimen, in words |
| `source` | source filenames, sha256 per file, sha256 of `oracle.h` |
| `build` | toolchain name, compiler, **compiler version**, full flag list, the exact command, whether it succeeded, compile seconds, any compiler diagnostics |

Compiler diagnostics are a **declared** property, not a field nobody reads. A
specimen must compile with none unless it says otherwise with
`expect_build_warning=<substring>`, in which case the diagnostic must be present
and must contain that substring. Exactly one specimen declares one:
`linux-format-static-resolver`, where glibc warns that `getaddrinfo` in a
statically linked program still needs shared libraries at runtime — a real,
common shape whose dependency is invisible in the file's `NEEDED` list, and
whose link-time warning is the only place it is ever stated.
| `binary` | path, **sha256**, size, and `elf`: e_type, machine, interpreter, NEEDED, RPATH, RUNPATH, BIND_NOW, symtab/debug presence, `file(1)` string, plus derived `statically_linked` / `pie` / `stripped` |
| `binary.declared_elf_problems` | where the built file disagrees with what the entry declared it would be — read out of the ELF with `readelf`, not assumed from flags |
| `invocation` (`argv`, `env`, `stdin`, `stage`, `staged_files`, `runs`, `timeout_s`) | exactly how it was launched |
| `declared` | **hand-written before the specimen ever ran**: expected exit code or death signal, oracle stream, `expect` key/value pairs, expected filesystem effects, expected process behaviour, expected duration class, required capabilities, post-run files and what must be in them |
| `baseline` | what direct execution actually did: per run the exit code/signal, duration, stdout and stderr byte counts and sha256, the deterministic oracle lines, the observations, the surviving run-directory listing |
| `verdict` | `baseline-ok`, `baseline-mismatch`, `build-failed` or `generator-error`, with the reasons |
| `differential_of`, `differential_reason`, `differential_agreement` | for compiler differentials only |

### How a consumer should compare a `.LEXE` run against the baseline

1. Compare `exit_code` / `signal` against `declared`.
2. Compare the non-`OBS_` oracle lines against
   `baseline.runs[-1].oracle_deterministic_lines`.
3. Treat `OBS_` values as information, not assertions.
4. For bulk specimens, recompute the FNV-1a the specimen reports over the
   captured stream (`declared.bulk_check` names the keys).
5. Check `declared.post_files` after `settle_s` for the specimens whose work
   continues after the launching process exits.

## Coverage

201 specimens, 164 distinct binaries + 37 compiler differentials, one property
each unless the family is `compound`:

| Family | n | Covers |
|---|---|---|
| `format` | 20 | dynamic PIE, non-PIE, static, static-PIE, stripped, unstripped+DWARF, full RELRO/BIND_NOW, explicit lazy binding, a 48 MiB executable, **256 MiB of `.bss` in a file that is tiny on disk**, a self-contained static one, and the three cases where `-static` actually changes the answer: **static + threads**, **static C++ with exceptions unwound by a statically linked libgcc**, and **static + `getaddrinfo`**, whose NSS dependency is invisible in `NEEDED` and stated only by a link-time warning |
| `linkage` | 20 | three interdependent shared libraries via `LD_LIBRARY_PATH`, `DT_RPATH`, `DT_RUNPATH`, `$ORIGIN`-relative lookup, symbol versioning, `dlopen` of a built plugin, `dlopen` of a missing library, C++ against shared and static libstdc++, `$ORIGIN`-relative twins of `DT_RPATH`, symbol versioning and `dlopen` (see **Relocatability**), **the C++ surface under four language standards**, and **an exception thrown inside a `.so` and caught in the executable** |
| `process` | 24 | 4 and 256 threads, fork+wait, exec of self, exec of a sibling binary, fork+exec, **execvp through `PATH`**, grandchildren, double-fork daemon, a parent that exits leaving a live child, death-by-signal wait status, `posix_spawn`, session/process-group facts, and **threads beyond the count**: TLS, a detached thread, main exiting while one is still working, a fault off the main thread, `fork()` from a threaded process, a condition-variable handoff |
| `signals` | 11 | catch and report, ignore, die from SIGTERM/SIGQUIT, SIGALRM-bounded run, SIGPIPE both ways, SIGCHLD reaping inside the handler |
| `io` | 23 | stdin to EOF, stdout only, stderr only, both, pipe round trip, FIFO, 256 fds, 8 MiB bulk stdout, all 256 byte values on stdout, isatty, dup2 self-redirection, and the **volume** family: 4 / 64 / 256 MiB on stdout, 128 MiB on stdout and stderr at once, 64 MiB then exit 3, paced output with a silent tail, 16 MiB of binary |
| `stdio` | 18 | the **connection** rather than the content: one prober through all eight shapes (pipe, regular file, `tee`, command substitution, early-closing consumer, `/dev/null` stdin, file stdin, closed stdout), plus 4 MiB to a file, 4 MiB through `tee`, 4 MiB truncated into SIGPIPE, an oracle stream through `$( )`, binary through `tee` and through `$( )`, both streams to files, paced output to a file, and a program that requires stdin launched with `/dev/null`. See **Stdio shapes** |
| `filesystem` | 18 | mkstemp, state across two launches, a `./assets` CWD assumption, `flock` contention, `fcntl` record locks, file mmap, 1 GiB anonymous mmap, POSIX shm with a child, symlinks, a 46-entry directory tree, fsync+rename, HOME/XDG/TMPDIR writability, denied-write probes, and **five awkward filenames**: spaces, UTF-8, a leading dash, shell metacharacters, an embedded newline |
| `interface` | 15 | no args, flags, empty-string args, spaces/tabs/quotes, UTF-8 args, 512 args, a 100 000-byte arg, present/absent/empty/UTF-8 env vars, an emptied environ, `argv[0]` vs `/proc/self/exe`, and **locale**: one this host has, one it does not, and whatever the environment says |
| `outcome` | 37 | exit 0/1/2/42/77/126/127/128/130/137/200/255, atexit ordering, a 500 ms run, a 3 s run, **a 10 s run**, a deterministic CPU-bound run, and **seven deaths**: SIGSEGV (null write), SIGSEGV (exhausted stack), SIGABRT (`abort`), SIGABRT (failed `assert`), SIGABRT (`std::terminate` on an exception from a `.so`), SIGILL, SIGFPE, SIGBUS |
| `gui` | 6 | a mapped top-level window confirmed viewable by the server, the same binary with no display at all, two windows from one process, a two-second hold, a crash with a window up, a child that keeps the window after the launched process exits. See **GUI** |
| `sockets` | 5 | `socketpair`, named AF_UNIX, TCP loopback, UDP loopback, `getaddrinfo` |
| `compound` | 4 | a 3-stage self-exec pipeline over two pipes; a threaded AF_UNIX service with shm, a forked client and signal shutdown |

Exit codes deserve a note. 126, 127 and 128+n are what a *shell* invents when it
cannot run a program or when one dies from a signal, so a program that
legitimately exits 137 is indistinguishable, from the status alone, from one the
OOM killer reached — and only one of those is a problem. Each of those specimens
runs to completion and prints `RESULT=PASS`; the status is its declared outcome.

Argument and environment specimens declare **byte length and hex**, so an empty
string, a trailing space, a tab and a multi-byte character are all
distinguishable from each other and from damage.

## Output volume and concurrency

Seven specimens whose property is the size or the timing of output rather than
its content. Each attests to what it wrote with a SHA-256 it computes itself
(`specs/orc_bulk.h`, a hand-written SHA-256 checked against eight published
vectors and against `sha256sum` over 5 MiB of the specimen's own stream), and the
runner recomputes that digest over what it captured. A byte count alone cannot
tell a truncated stream from a reordered one, or from one whose NUL bytes were
eaten.

| Specimen | stdout | measured directly |
|---|---|---|
| `linux-io-stream-4mib` | 4 MiB | `sha256 1613d62c…`, both digests verified |
| `linux-io-stream-64mib` | 64 MiB | `sha256 b0529b58…`; the 4 MiB stream is a byte-for-byte prefix of it |
| `linux-io-stream-256mib` | 256 MiB | `sha256 8077dcc2…`; 2.55 s wall and **1536 kB peak RSS** for the specimen itself |
| `linux-io-stream-both-128mib` | 128 MiB + 128 MiB on stderr | a naive relay stalls after exactly 65536 bytes; a polling relay reads all 256 MiB in 1.9 s |
| `linux-io-stream-fail-64mib` | 64 MiB, then `exit 3` | `sha256 b0529b58…`, identical stream, exit 3 |
| `linux-io-stream-slow-paced` | 16 × 32 KiB, 150 ms apart, 1 s silent tail | 3.26 s wall; bursts at 0, 151, 301 … 2257 ms |
| `linux-io-binary-bulk-16mib` | 16 MiB binary | 256 distinct byte values, 65866 NULs, every hazard sequence at its declared offset |

The sizes were chosen to make the property observable and for no other reason. Of
note, because it is the whole point of the 256 MiB entry: the specimen needs about
1.5 MiB of memory to produce 256 MiB of output. The cost of the volume belongs
entirely to whatever is reading it.

`linux-io-stream-both-128mib` is the shape that deadlocks a naive relay, and the
deadlock was reproduced directly rather than argued: a reader that drains stdout
to EOF before touching stderr stops after one pipe buffer and never resumes,
because the specimen is then blocked writing to stderr and will never close
stdout. Both its streams are bulk, so its oracle is appended to stderr after the
payload and it reports where the payload starts; `bulk_check` verifies that slice.

Four more specimens send these same streams through a different **connection**
rather than at a different size — 4 MiB to a regular file, 4 MiB through `tee`,
4 MiB into a consumer that closes after 64 KiB, and paced output into a file.
They are in the `stdio` family below rather than here, because what they vary is
the pipe and not the payload.

## Stdio shapes

A launcher once discarded the program's output entirely, so **how** a specimen's
three streams are connected is an axis of its own, recorded per specimen in
`stdio` and per run in `baseline.runs[].stdio_shape`. Eight shapes, every one of
them something a shell or a supervisor does to a program every day:

| Shape | What it is | What it changes |
|---|---|---|
| `pipe` | the control: three pipes, stdin closed after the declared input | — |
| `file` | `prog >out 2>err` | the fd is a **regular file**: seekable, and glibc picks full buffering rather than line buffering |
| `tee` | `prog \| tee out` | two independent copies of one stream that must be byte-identical |
| `cmdsub` | `out=$(prog)` | **lossy by design**: strips trailing newlines, cannot carry NUL |
| `earlyclose` | `prog \| head -c N` | truncates; whether the writer notices depends on the size |
| `devnull-stdin` | `prog </dev/null` | stdin is a **character device** at EOF, not a pipe |
| `file-stdin` | `prog <in.dat` | stdin is a regular file: seekable |
| `closed-stdout` | `prog >&-` | fd 1 is not open; writes fail with `EBADF` |

`specs/io_stdio_shape.c` is compiled once and launched through all eight. It
varies nothing itself: it reports what its three fds actually *are* — fifo,
regular, chardev or closed; seekable or not; writable or `EBADF` — so each shape
has a **different deterministic answer** and the difference between them is the
measurement. That is what makes the family a matrix rather than eight
near-copies. A pipe and `/dev/null` both give `STDIN_BYTES=0`, so byte count
alone cannot tell them apart; `STDIN_KIND` can, and the distinction is exactly
the one a launcher gets wrong when it "connects stdin" by handing over an empty
pipe it never closes.

**The two transforming shapes are verified against a reference capture** of the
same program through a plain pipe, taken in the same run (`stdio_reference`). So
"the shell stripped the trailing newline" and "the shell dropped the NULs" are
measured relations between two captures — `captured_equals_reference_rstrip_newlines`,
`captured_equals_reference_nuls_removed_rstrip_newlines` — rather than an
assumption about what bash does.

The most useful pair in the family is the two `earlyclose` specimens, which are
the same shape over two sizes:

- `linux-stdio-shape-earlyclose` — 4158 bytes, which **fits in one 64 KiB pipe
  buffer**. Every write succeeds, `WRITE_STDOUT=ok`, `RESULT=PASS`, exit 0 — and
  the consumer kept 1024 bytes and threw the rest away. Nothing anywhere returns
  an error.
- `linux-stdio-earlyclose-4mib` — 4 MiB, which does not fit. The writer is killed
  by **SIGPIPE** mid-stream and never prints its attestation at all.

Same shape, opposite symptoms. Anything that tested only one size would draw the
wrong conclusion about the other. What is asserted for both is that the captured
bytes are a genuine **prefix** of the full stream — a truncated stream and a
reordered one have the same length, so the prefix relation is the check and the
length is not.

`tee` and `cmdsub` take the specimen's status from bash's `${PIPESTATUS[0]}`/`$?`,
which encodes death-by-signal as 128+n and cannot tell that apart from an exit
code of 128+n. The generator refuses those shapes for any specimen not declared
to exit normally below 128, rather than recording an ambiguous number as if it
were a fact. `closed-stdout` avoids the problem entirely by `exec`ing, so the
shell process *becomes* the specimen and the wait status is the specimen's own;
`earlyclose` uses a real pipe rather than a shell for the same reason.

## GUI

Six specimens in the `gui` family, raw Xlib and no toolkit, because a toolkit
would put a dozen libraries and a settings daemon between the specimen and the
property.

**No automated test may put a window on the developer's screen.** On WSLg that
is not a matter of setting `DISPLAY`: `/tmp/.X11-unix` is mounted read-only with
the user's real `X0` in it, Xvfb's fallback abstract socket lives in the network
namespace, and a stale lock on the shared `/tmp` blocks display numbers that look
free. `scripts/lib/private-display.sh` handles all three, and these specimens use
it unchanged — a private **mount and network** namespace in which the user's
display is not merely unbound but invisible.

What is asserted is the window's state read back **from the X server** —
`map_state == IsViewable`, the geometry it reports — never a pixel and never a
screenshot. `XMapWindow` is asynchronous, so the specimen round-trips until the
server answers rather than asking once and racing.

The pair that matters is `linux-gui-window-mapped` and `linux-gui-no-display`:
**the same binary**, one difference in the environment, two fully declared
outcomes (a viewable window and exit 0; `XOPEN_DISPLAY=fail` and exit 3). That is
what makes "the GUI program could not start" distinguishable from "the GUI
program was never run", which from the outside look identical. The other four
cover two top-level windows from one process, a window held up for two seconds,
a crash with a window mapped, and a child that keeps the window after the process
that was launched has exited — the Linux counterpart of the Windows
launcher-exits shape, proved by a post-run file because by then nothing is left
reading the child's stdout.

## The foreign-ISA fixtures

`generate_foreign.py` (sources in `specs_foreign/`, manifest at
`/tmp/lexe-workloads-foreign/index.json`, schema `lexe.workload.foreign/1`) makes
genuine **AArch64** ELF files on this x86-64 host, so that a consumer's
architecture check can be reached at all.

**It proves nothing about AArch64 support, anywhere.** There is no AArch64
kernel, no `qemu-user` and no cross libc here, so these fixtures **cannot be
executed** and have **no direct-execution baseline**. Their verdict is
`structural-ok`, their `baseline_kind` is `structural-only`, and the only
execution fact recorded is the measured refusal (`ENOEXEC`, shell status 126).
Every record says so in `baseline_caveat`. Citing this corpus as AArch64 coverage
would be wrong.

Three fixtures, from one clang-assembled object:

| Fixture | Type | Why |
|---|---|---|
| `linux-foreign-aarch64-object` | `ET_REL` | the **labelled control**, and the reason the other two exist |
| `linux-foreign-aarch64-exec` | `ET_EXEC` | the fixture: non-PIE, one `PT_LOAD`, entry inside it |
| `linux-foreign-aarch64-pie` | `ET_DYN` | the same bytes as a static PIE, the shape a modern consumer meets first |

The control is the important part of the design. A relocatable object is not
executable in *structural* terms, so a compile stage that checks the ELF **type**
before it checks the **machine** rejects it for the wrong reason and never
reaches the architecture check. A test built on the object would pass while
proving nothing. It is kept, labelled, and must never be used as the
foreign-architecture case.

**Nothing on this host can link machine 183** — measured every run and recorded
in `link_route_probe`: GNU `ld` has no `aarch64linux` emulation, `ld.gold` rejects
"unsupported ELF machine number 183", and `lld` is not installed.
`gcc-aarch64-linux-gnu` and `lld` are both in apt and installing either needs
authorisation this role does not have, so a **linker-produced** AArch64
executable is recorded as **BLOCKED** in `index.blocked`, with the evidence.

So the generator performs the link itself: it reads `.text` straight out of
clang's object and writes an ELF header, one program header and a minimal section
header table around it. That is a **linker substitute, not a forgery**, and the
discriminating question is checkable rather than a matter of taste:

> would a correct loader on the **target** platform run this successfully?

A patched `e_machine` — the thing this corpus previously declined to make — fails
that test: the header would claim AArch64 over x86-64 instructions, no loader
anywhere could run it, and its only possible use is to see whether a checker
notices an inconsistency. That is a *verification input*, not a workload. The
hand-linked file passes it: a Linux/AArch64 kernel loads it, jumps to the entry
point, and the program writes its oracle and exits 0.

Two guardrails keep that defensible, and both are **enforced** rather than
asserted:

1. **Zero relocations.** `specs_foreign/aarch64_oracle.S` uses only PC-relative
   `adr` and immediate operands, and the generator fails with
   `guardrail-failed` if the object contains any relocation at all. If it did,
   hand-linking would mean resolving addresses by hand — a much weaker claim.
2. **The bytes are clang's.** The extracted `.text` is cross-checked against an
   independent extraction by `llvm-objcopy`, and the sha256 of the object, of the
   `.text` and of the final file are all recorded, so anyone can re-extract and
   compare without trusting the script. The generator also verifies that the
   bytes *at the entry point of the finished file* hash to the object's `.text`.

Five facts are recorded per fixture under `five_facts`, each measured rather than
inferred: compilation succeeded; the output is a valid ELF; the machine type is
AArch64; it is structurally executable (type, entry point, one loadable
executable segment containing the entry, 4-byte entry alignment, `p_offset ≡
p_vaddr (mod p_align)`); and it does not match the host ISA.

`aarch64_oracle.S` needs no `.gitattributes` pin: this repository is developed on
Windows with `* text=auto`, so a fresh checkout has CRLF, and that was **checked
rather than assumed** — the same source at 2888 bytes (LF) and 2966 bytes (CRLF)
assembles to byte-identical machine code, `39e2d369…`, which is the
`text_sha256` the index records.

## Relocatability

A specimen that cannot start covers nothing. Measured by building the corpus at
one path, renaming the whole tree, and running every `baseline-ok` specimen from
the new location with argv rewritten for the new path and `LD_LIBRARY_PATH`
unset — which is what `audit_relocation.py` does.

Re-measured over the enlarged corpus: of 201 specimens, **197 started and the
same 4 did not**. None of the 77 specimens added in this wave is among them —
including `linux-cxx-so-exception`, which needs `libthrower.so` and finds it
through `$ORIGIN/../lib` after the tree has moved. The four are unchanged from
the earlier measurement over 112 specimens:

| Specimen | why | rescued by `LD_LIBRARY_PATH` |
|---|---|---|
| `linux-link-three-libs-ldpath` | no `RPATH` at all — **this is its declared property** | yes |
| `linux-link-rpath` | `DT_RPATH` is the absolute build-tree stage directory | yes |
| `linux-link-runpath` | `DT_RUNPATH` is the absolute build-tree stage directory | yes |
| `linux-link-symbol-versioning` | `DT_RUNPATH` is the absolute corpus `lib/` directory | yes |

All four fail identically: `exit 127`, `error while loading shared libraries:
…: cannot open shared object file`.

Only the first of the four is *supposed* to behave that way. For the other three
the absolute path is incidental to the property being tested, and it made that
property unreachable for anything that does not run the binary in the directory
it was built in. So each now has a `$ORIGIN`-relative twin, and the absolute
originals stay — a binary that bakes in an absolute `RPATH` is a legitimate and
extremely common shape, and the pair is more informative than either alone
because the difference between them is one link-line argument:

| absolute original | `$ORIGIN` twin | what the twin makes reachable |
|---|---|---|
| `linux-link-rpath` | `linux-link-rpath-origin` | `DT_RPATH` semantics in a relocatable binary |
| `linux-link-runpath` | `linux-link-origin-relative` (already existed) | `DT_RUNPATH` semantics, relocatable |
| `linux-link-symbol-versioning` | `linux-link-symbol-versioning-origin` | symbol versioning, which the corpus could not test at all before |
| `linux-dlopen-plugin` | `linux-dlopen-plugin-origin` | `dlopen` of a bare soname through the caller's own `RUNPATH` |

The last row is a different case and worth separating. Five specimens name an
absolute path *inside the corpus* in their declared `argv`:

```
linux-dlopen-plugin       argv = ["{LIBDIR}/libplugin.so", "ok"]
linux-dlopen-missing      argv = ["{LIBDIR}/libnotpresent.so", "fail"]
linux-proc-exec-helper    argv = ["{HELPER}"]
linux-proc-fork-exec      argv = ["{HELPER}"]
linux-proc-posix-spawn    argv = ["{HELPER}"]
```

These all **start** — the dependence is in the argument, not in the file — but
their property is only reachable if the consumer substitutes the path for wherever
the corpus now lives, and for the three `{HELPER}` entries only if `helper_child`
is shipped alongside. The placeholders are in `index.json`, so this is a stated
contract rather than a trap, but it is a contract and not a property of the
binary. `linux-dlopen-plugin-origin` removes the dependence entirely for the
`dlopen` case: its argument is a bare soname.

## Compiler differentials

37 specimens are the same source under a second toolchain, chosen because a real
assumption could break — not enumerated flag by flag. Each names its reason in
`differential_reason`:

- the control case under all four toolchains (float folding, default PIE/PIC);
- threads (TLS model, atomics lowering);
- `volatile sig_atomic_t` at `-O2`, where a wrong assumption about
  handler-visible state shows up;
- a pure-integer checksum that **must** be bit-identical everywhere, so a
  difference means a miscompile or undefined behaviour in the source;
- the deliberate null dereference at `clang -O2`, because an optimiser is
  entitled to delete undefined behaviour and a specimen that stops crashing is a
  broken fixture;
- 8 MiB through stdio; the compound pipeline; clang++ against the same libstdc++;
  static linking under clang;
- the 4 MiB stream and the 16 MiB binary stream, because the xorshift generator
  and the SHA-256 in `specs/orc_bulk.h` are hand-written integer code: one
  differing byte or digit would mean undefined behaviour in a header that every
  volume specimen includes. Both produce a byte-identical stream and an identical
  digest under `clang -O2`.

`-O3` was added as a sixth toolchain pair, and it is on the specimens where
automatic vectorisation and aggressive inlining could actually change an answer,
not sprayed across the table — a differential that cannot fail is not evidence,
it is a bigger number:

- the control case at `-O3` under both compilers, so the other `-O3` entries have
  something to be compared against;
- the integer checksum and the 4 MiB stream, because `-O3` vectorises exactly
  that shape of loop and the result must stay bit-identical to the scalar one;
- **the deliberate SIGFPE**, because an integer division by zero is undefined
  behaviour that an optimiser may delete outright — both operands are `volatile`,
  and whether that survives `-O3` is the question;
- **the stack overflow**, whose entire fault depends on the recursion not being
  turned into a loop; tail-call elimination is precisely what a second compiler
  at a higher level is most likely to do differently;
- `__builtin_trap` under clang, which does not always lower to the same
  instruction;
- TLS, whose access sequence depends on the model the compiler picks;
- the C++ core under clang++, and the `.so` exception crossing a GCC-built
  library into a clang-built executable — if the typeinfo is not unified, the
  catch is skipped silently and that is the only specimen that would notice.

`generate.py` cross-checks every differential against its base and reports any
deterministic line that differs. On this host: **0 divergences**.

## Determinism

Two independent generations into different output directories produced
**identical deterministic output for all 112 specimens**, and 109 of 112
binaries were byte-identical. The three that differ are exactly the specimens
that bake an absolute path into the file (`DT_RPATH`, `DT_RUNPATH`), so their
hash depends on the output directory by construction. That was measured before
the volume family and the `$ORIGIN` twins existed; the twins bake in no absolute
path, so they do not add to the three.

## Baseline mismatches found while building this corpus

Recorded because a fixture bug fixed silently is a fixture bug nobody learns
from. All of them were **my** errors, caught by the specimens' own
direct-execution baselines before any of this became test material — the first
five below, then a sixth the baseline could not have caught, then five more from
the wave that added the `stdio`, `gui`, C++ and crash families:

1. **`linux-io-dup2-redirect`** — while fd 1 pointed at the file, the oracle's
   own `DUP2_OK=yes` line was written *into* the file, so the file was 32 bytes
   instead of 20 and the content check failed. The specimen now holds every
   outcome in a variable and reports after restoring stdout.
2. **`linux-proc-daemon-double-fork`** — I declared `DAEMON_SID_IS_SELF=yes`.
   Wrong: after the *second* fork the daemon is **not** the session leader, and
   that is precisely what the second fork buys (a non-leader can never acquire a
   controlling terminal). The specimen now reports `DAEMON_SID_CHANGED` and
   `DAEMON_IS_SESSION_LEADER=no`.
3. **`linux-proc-exec-self`** and 4. **`linux-env-emptied`** — both print `PHASE`
   twice (before and after re-exec) and I declared the second value, while the
   runner reported the first. Fixed in the runner, not the fixtures: a repeated
   key now reports its final value, and repeats are listed explicitly.
5. **`linux-proc-exec-helper`** — declared a `RESULT=PASS` line that cannot
   exist: after the exec the process *is* `helper_child`, which prints no
   `RESULT`. The entry now declares `result=False`.

Two declared properties that the ELF tags alone cannot prove were verified by
hand as well: the `$ORIGIN` tree still runs after the whole directory is moved
elsewhere, and `linux-link-three-libs-ldpath` genuinely refuses to start when
`LD_LIBRARY_PATH` is removed.

### A sixth, and the one the baseline could not have caught

6. **`linux-io-stream-both-128mib`** reported `ERR_PAYLOAD_OFFSET`, an absolute
   byte position into stderr, as a deterministic value. The offset counts the
   header lines that precede the payload, and one of those is
   `FIXTURE_ID=<id>` — whose value comes from the environment. Clear the
   environment and the id falls back to the shorter compiled-in literal, the
   header shrinks, and a value declared deterministic moves by exactly the
   difference in id length. Measured on the original binary: **127 with
   `FIXTURE_ID` set, 120 with the environment cleared.**

   The payload is now **framed** rather than located by arithmetic. The
   specimen announces `ERR_PAYLOAD_DELIMITER`, writes that delimiter on its own
   line before and after the payload, and the consumer takes what lies between
   the two `\n`-anchored occurrences. The delimiter cannot appear inside the
   payload by construction rather than by luck: the payload alphabet is the 16
   lowercase hex characters and `\n`, so it can contain neither `<` nor `=`
   (verified — 0 of each in 2 MiB). The absolute offset is still reported, as
   `OBS_ERR_PAYLOAD_OFFSET`, because it is useful when diagnosing a stream that
   arrived wrong; nothing compares it.

   **Why the five above were caught here and this one was not.** A baseline is
   two or more direct executions under *the same* conditions, and this generator
   always sets `FIXTURE_ID`. A value derived from the environment is therefore
   perfectly stable across every baseline run, and perfectly stable across a
   second generation into a different directory, and diverges only when
   something changes the environment. The baseline mechanism cannot see that
   class of defect at all. It surfaced when the specimen ran somewhere that
   clears the environment by design.

   The rule this yields, which applies to any specimen added later: **a
   deterministic oracle value must not be a byte position, length or count over
   a stream that also carries `FIXTURE_ID`.** Locate a region by its content.
   Every wave-3 specimen was re-checked against that rule by running it twice,
   once with `FIXTURE_ID` set and once under `env -i`, and requiring every
   deterministic value except `FIXTURE_ID` itself to be identical: all six pass,
   and the stderr byte counts shift by exactly the id-length difference
   (5 bytes for `linux-io-stream-4mib`, 7 for `linux-io-stream-both-128mib`),
   which is the line itself and no value.

   The wave-4 specimens were put through the same check, since the `stdio`
   family is exactly where a count over a stream would have crept back in:
   **58 specimens run twice in their own run directories, once with
   `FIXTURE_ID` set and once with it unset, every deterministic line other than
   `FIXTURE_ID` byte-identical, 0 problems.** Sixteen were skipped and are
   covered another way rather than left unchecked — the non-`pipe` stdio shapes,
   because running them by hand would measure a different connection than the
   one they declare, and the GUI specimens, which need the private display; both
   groups assert their stream relations through `stdio_expect` instead.

   `FIXTURE_ID` differing is not a defect and is not new: every specimen in the
   corpus takes its id from the environment with a compiled-in fallback, and
   every consumer already drops the line — `expand_differentials` excludes it
   explicitly. What is not allowed is a *second* value that moves with it.

### Wave 4: five more, and where each one was caught

Of the 77 specimens added in this wave, **76 declarations were correct on the
first run**. The five entries below are the exceptions plus two generator gaps,
and they are recorded in that spirit: the value of this section is not the count
of errors but the record of which mechanism caught each one, because three of
these were caught by something other than the declaration itself.

7. **`io_stdio_shape.c` contaminated the stream it was measuring.** Its oracle
   is on stderr, but it reported one observation with `orc_obs` — and `orc_obs`
   in `oracle.h` writes to **stdout**. Thirty-one bytes of
   `OBS_STDOUT_BYTES_ACCEPTED=4158\n` were appended to the payload, so the
   stream was 4189 bytes against the 4158 the specimen attested to, and its own
   SHA-256 no longer matched. Caught by the attestation, which is what
   attestations are for; a byte count alone would have shown the same 31-byte
   discrepancy without saying where it came from. Fixed in the specimen
   (`orc_ekv("OBS_…")`, since the `OBS_` prefix and not the file descriptor is
   what makes a line an observation) rather than in `oracle.h`, whose sha256 is
   recorded for every specimen in the corpus. No existing specimen was affected
   — of the sources that call `orc_obs`, none is declared `oracle="stderr"` —
   so this was a latent hazard rather than a live defect, and it is now
   written down in **Adding a specimen**.

8. **`linux-gui-crash-with-window` declared death by SIGSEGV and got exit 139.**
   The private display is reached through `unshare` and `bash`, which report a
   signal as exit 128+n. Nothing downstream can tell that apart from a program
   that exited 139. The specimen now declares the **exit code**, says why, and
   `generate.py` *refuses* a `signal=` declaration on any private-display
   specimen rather than accepting 139 as if it were a signal — inventing a
   distinction the measurement cannot make would be worse than not making it.
   `linux-outcome-sigsegv` on the console is what proves signal death is
   observable; the GUI specimen proves the crash happens with a window up, which
   is a different claim.

9. **`linux-gui-orphan-window` produced nothing at all, four times, for three
   different reasons** — and the third was the real one.

   First, `pd_run` kills Xvfb the instant the command it launched returns, so an
   orphan left behind loses its display and then its namespace before it can do
   any work: the specimen was measuring the harness rather than the program. A
   real X server does not die when one application exits, so the generator now
   holds the stage open after the launched process exits (`display_hold_s`). The
   launched process still exits first, which is the property.

   Second, the hold was **three seconds, sized on an idle machine**, and failed
   under load. Eight seconds passed when the family ran alone and failed again
   with twelve other specimens running. Both of those failures were the fixture
   reporting the state of the host rather than the state of the program, and a
   bigger number would only have moved the threshold: **a fixed margin is a race,
   not a fix.** The hold is now a *condition* — it waits for `gui_orphan.log` to
   appear, with a 30 s ceiling — which weakens nothing, because the declaration
   is still that the file exists and contains the declared lines and the wait
   simply expires if it never does.

   Third, and actually responsible: **the child inherited a live Xlib connection
   across `fork()`, and Xlib is not fork-safe.** The tell was that the specimen
   passed on some runs and produced nothing on others with no pattern in the
   environment or the load — at one point the run with the *inherited* shell
   environment failed while the one with the generator's stripped environment
   succeeded, and an hour earlier the same pair had come out the other way
   round. The parent now closes its display and destroys its window **before**
   forking, so the child holds no inherited Xlib state at all. That is also the
   more honest shape: a launcher that hands the display to a child has no
   business keeping a connection open. Verified as fixed by **ten consecutive
   generations, 10 passes and 0 failures**, at a 1-minute load average of 22 —
   because a fixture that works once has not been shown to work.

10. **`SIGNAMES` had no entry for SIGBUS**, so the first specimen to declare
    death by SIGBUS came back as `generator-error: KeyError('SIGBUS')` — a
    verdict that blames the fixture for a gap in the generator's lookup table.
    The table now covers the signals a specimen can plausibly declare.

12. **`FIXTURE_ID` was never an identity oracle, and the baseline could not have
    said so.** Found not here but by the independent pass that runs this corpus
    through `.LEXE`, at a cost of **16 false violations**: `FIXTURE_ID` is
    injected by this generator *through the environment*, and FORMAT-0.1 §9.5.2
    requires a conforming runtime to reset the environment — so under one, every
    specimen reports the literal its **source** was written with. Several
    specimens share a source (`io_stream.c` backs five), so that literal names
    the program, not the fixture, and a consumer asking "which specimen is this"
    gets the same answer for five different streams.

    Not a defect in the generator; a property of the contract that the corpus
    had not stated. And the same shape as number 6 above: a value stable across
    every baseline run *because* the baseline holds the environment constant.
    Twice now, so it is written up as a rule in **The behavioural oracle** rather
    than as another entry in this list.

    Fixed by giving every specimen a second identity that is **in the binary**:
    `-DLEXE_FIXTURE_BUILD_ID="<fixture id>"` at compile time, emitted as
    `FIXTURE_BUILD_ID`, and checked by the generator, so a specimen that does not
    carry one or carries the wrong one is a `baseline-mismatch` rather than a
    convention nobody enforces. The check immediately found four sources that
    print their own preamble instead of calling `orc_begin` and had therefore
    been missed — including `linux-env-emptied`, which re-executes itself with an
    **empty** environment and is now the corpus's direct demonstration of the
    point: in its second phase there is no `FIXTURE_ID` to be had at all, and the
    compiled-in identity is still there.

11. **A helper named `yn` collided with a built-in.** `yn` is the Bessel function
    of the second kind, `double yn(int, double)`, so the specimen compiled with a
    `-Wbuiltin-declaration-mismatch` warning — in a corpus whose index records a
    compiler-diagnostics field that had been empty for every specimen. Renamed.
    Worth recording because the warning was visible only in `index.json`, not in
    the verdict: the specimen was `baseline-ok` throughout.

## Deliberately NOT generated

- **Anything Windows/PE, Wine or Proton.** That is a separate, equally
  documented pass; see [README-PE.md](README-PE.md). Foreign-ISA fixtures were on
  this list and no longer are: see **The foreign-ISA fixtures** below.
- **setuid/setgid, capabilities, or anything needing root.** Out of scope for an
  unprivileged application format, and untestable without privilege. `setcap` is
  installed here but needs root to do anything, so this stays BLOCKED rather
  than unexplored.
- **Permission-mode specimens under `/mnt/c`.** DrvFS reports mode 0755 for
  every file, so a permissions property measured there would be a lie. Every
  binary and every run directory is on native ext4 under `/tmp`.
- **Deliberately malformed or hostile ELF.** That is a `.LEXE` *verification*
  input, not a workload; these specimens are all legitimate programs.
- **Non-ELF payloads** (shell scripts, interpreted entrypoints): still a real
  gap and still not a Linux-ELF-process property. **Wayland** likewise — the
  headers are here but the private-display mechanism is X11, and a Wayland
  compositor to run against is not. X11 GUI specimens are no longer on this
  list; see the `gui` family.
- **`dlopen` from a fully static binary**, which glibc does not support: it would
  be a specimen whose declared outcome is "the platform refuses", which says
  nothing about `.LEXE`.
- **Unbounded or nondeterministic workloads** (anything whose output depends on
  timing, real network access, or an unseeded RNG). Every duration-dependent
  value in the corpus is an `OBS_` observation.
- **Blind flag permutations.** Six toolchain configurations on a chosen subset,
  each with a stated reason. `-O3` was added because automatic vectorisation and
  tail-call elimination can change an answer or delete a fault the specimen
  depends on, which is an assumption worth probing. `-O1`, `-Os`, `-flto`,
  `-Ofast` and `-fsanitize=*` are still out: none of them is tied to an
  assumption this corpus makes. (`-Ofast` in particular implies
  `-ffast-math`, which would change the floating-point answers on purpose — a
  divergence that says nothing about anything except `-ffast-math`.)

## Adding a specimen

1. Write one small program in `specs/` that isolates **one** property, using
   `oracle.h`. Keep every environment-dependent value behind `orc_obs` — but
   note that **`orc_obs` writes to stdout**, so a specimen whose oracle is on
   stderr must emit observations with `orc_ekv("OBS_…", …)` instead. The `OBS_`
   prefix on the key, not the file descriptor, is what makes a line an
   observation. Getting this wrong appends the observation to the stream under
   test; it cost 31 bytes and a broken digest in `io_stdio_shape.c`, and it was
   caught only because that specimen attests to what it wrote.
2. Add one `S(...)` entry to `generate.py` with the expectations written
   **before** you run it — that is the entire value of the exercise.
3. Regenerate. If the verdict is `baseline-mismatch`, the fixture or the
   declaration is wrong. Fix it, and record what you got wrong.

Optional `S(...)` keys beyond the expectations:

| Key | Effect |
|---|---|
| `stdio=` | one of the eight **Stdio shapes**; default `pipe` |
| `stdio_limit=` | bytes the consumer reads before closing, for `earlyclose` |
| `stdio_reference=` | also capture the same program through a plain pipe, so a transforming shape can be checked as a relation to it |
| `stdio_expect=` | declared facts about the **connection**, checked against `baseline.runs[].stdio_shape` |
| `display=` | `"private"` for the namespaced X server, `"none"` to strip `DISPLAY` and `WAYLAND_DISPLAY` |

Never declare a deterministic value that is a **byte position, length or count
over a stream that also carries `FIXTURE_ID`**. The id comes from the
environment, so its length does — a payload offset declared deterministic once
moved from 129 to 122 the moment the environment was cleared. Locate regions by
content: a delimiter line, a prefix relation, a digest. An absolute offset may be
reported, as an `OBS_`.

---

## The Windows PE corpus

The companion Windows corpus — PE specimens, a per-translation-layer baseline
(native / Wine / Proton), the process-tree family, and the repeat-stability runs —
lives in [README-PE.md](README-PE.md), with sources in `specs_pe/` and its own
generator, `generate_pe.py`.

## The portable-source factory

The third payload kind — packages that ship SOURCE and are compiled at install
time — lives in [README-PORTABLE.md](README-PORTABLE.md), with recipes in
`specs_portable/` and its own generator, `generate_portable.py`. It records a
baseline for the BUILD as well as the program, and runs every product twice: once
in the tree that built it and once from somewhere else with that tree renamed
away.

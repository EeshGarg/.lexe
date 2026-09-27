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
A full generation takes about 11 seconds of wall time on 12 jobs.

Layout produced:

```
/tmp/lexe-workloads/
  index.json                  the corpus manifest (see below)
  bin/<fixture-id>            most specimens
  bin/helper_child            the exec/fork target used by several specimens
  lib/lib{alpha,beta,gamma,plugin,ver}.so
  stage/<fixture-id>/bin,lib  specimens whose property IS the directory layout
  run/<fixture-id>/           the working directory each baseline ran in, kept
```

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
| `build` | toolchain name, compiler, **compiler version**, full flag list, the exact command, whether it succeeded, compile seconds, any compiler diagnostics (empty for the whole corpus) |
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

124 specimens, 102 distinct binaries + 22 compiler differentials, one property
each unless the family is `compound`:

| Family | n | Covers |
|---|---|---|
| `format` | 14 | dynamic PIE, non-PIE, static, static-PIE, stripped, unstripped+DWARF, full RELRO/BIND_NOW, explicit lazy binding, a 48 MiB executable, a self-contained static one |
| `linkage` | 13 | three interdependent shared libraries via `LD_LIBRARY_PATH`, `DT_RPATH`, `DT_RUNPATH`, `$ORIGIN`-relative lookup, symbol versioning, `dlopen` of a built plugin, `dlopen` of a missing library, C++ against shared and static libstdc++, plus `$ORIGIN`-relative twins of `DT_RPATH`, symbol versioning and `dlopen` (see **Relocatability**) |
| `process` | 15 | 4 and 256 threads, fork+wait, exec of self, exec of a sibling binary, fork+exec, grandchildren, double-fork daemon, a parent that exits leaving a live child, death-by-signal wait status, `posix_spawn`, session/process-group facts |
| `signals` | 11 | catch and report, ignore, die from SIGTERM/SIGQUIT, SIGALRM-bounded run, SIGPIPE both ways, SIGCHLD reaping inside the handler |
| `io` | 20 | stdin to EOF, stdout only, stderr only, both, pipe round trip, FIFO, 256 fds, 8 MiB bulk stdout, all 256 byte values on stdout, isatty, dup2 self-redirection, and the **volume** family: 4 / 64 / 256 MiB on stdout, 128 MiB on stdout and stderr at once, 64 MiB then exit 3, paced output with a silent tail, 16 MiB of binary |
| `filesystem` | 13 | mkstemp, state across two launches, a `./assets` CWD assumption, `flock` contention, `fcntl` record locks, file mmap, 1 GiB anonymous mmap, POSIX shm with a child, symlinks, a 46-entry directory tree, fsync+rename, HOME/XDG/TMPDIR writability, denied-write probes |
| `interface` | 12 | no args, flags, empty-string args, spaces/tabs/quotes, UTF-8 args, 512 args, a 100 000-byte arg, present/absent/empty/UTF-8 env vars, an emptied environ, `argv[0]` vs `/proc/self/exe` |
| `outcome` | 15 | exit 0/1/42/255, atexit ordering, SIGSEGV, abort, a 500 ms run, a 3 s run, a deterministic CPU-bound run |
| `sockets` | 5 | `socketpair`, named AF_UNIX, TCP loopback, UDP loopback, `getaddrinfo` |
| `compound` | 4 | a 3-stage self-exec pipeline over two pipes; a threaded AF_UNIX service with shm, a forked client and signal shutdown |

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

## Relocatability

A specimen that cannot start covers nothing. Measured by building the corpus at
one path, renaming the whole tree, and running every `baseline-ok` specimen from
the new location with argv rewritten for the new path and `LD_LIBRARY_PATH`
unset — which is what `audit_relocation.py` does.

Of 112 specimens (before this wave), **108 started and 4 did not**:

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

22 specimens are the same source under a second toolchain, chosen because a real
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
from. All five were **my** errors, caught by the specimens' own direct-execution
baselines before any of this became test material:

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

   `FIXTURE_ID` differing is not a defect and is not new: every specimen in the
   corpus takes its id from the environment with a compiled-in fallback, and
   every consumer already drops the line — `expand_differentials` excludes it
   explicitly. What is not allowed is a *second* value that moves with it.

## Deliberately NOT generated

- **Anything Windows/PE, Wine, Proton or foreign-ISA.** MinGW-w64 and wine exist
  on this host; this pass is the Linux ELF factory only, so a PE corpus would be
  a separate, equally documented pass rather than a few stray specimens.
- **setuid/setgid, capabilities, or anything needing root.** Out of scope for an
  unprivileged application format, and untestable without privilege.
- **Permission-mode specimens under `/mnt/c`.** DrvFS reports mode 0755 for
  every file, so a permissions property measured there would be a lie. Every
  binary and every run directory is on native ext4 under `/tmp`.
- **Deliberately malformed or hostile ELF.** That is a `.LEXE` *verification*
  input, not a workload; these specimens are all legitimate programs.
- **Non-ELF payloads** (shell scripts, interpreted entrypoints) and
  **GUI/X11/Wayland** specimens: both are real gaps, both need their own pass,
  and neither is a Linux-ELF-process property.
- **`dlopen` from a fully static binary**, which glibc does not support: it would
  be a specimen whose declared outcome is "the platform refuses", which says
  nothing about `.LEXE`.
- **Unbounded or nondeterministic workloads** (anything whose output depends on
  timing, real network access, or an unseeded RNG). Every duration-dependent
  value in the corpus is an `OBS_` observation.
- **Blind flag permutations.** Four toolchain configurations on a chosen subset,
  each with a stated reason. `-O1`, `-Os`, `-flto`, `-fsanitize=*` and the rest
  were left out because none of them was tied to an assumption worth probing
  here.

## Adding a specimen

1. Write one small program in `specs/` that isolates **one** property, using
   `oracle.h`. Keep every environment-dependent value behind `orc_obs`.
2. Add one `S(...)` entry to `generate.py` with the expectations written
   **before** you run it — that is the entire value of the exercise.
3. Regenerate. If the verdict is `baseline-mismatch`, the fixture or the
   declaration is wrong. Fix it, and record what you got wrong.

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

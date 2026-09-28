# `.LEXE` workload corpus — portable-source factory

Recipes, not binaries. A `native` package ships a compiled ELF and a `windows`
package ships a PE; a **`portable`** package ships **source**, and the machine
that installs it compiles it. Neither of the other two corpora exercises that,
because in both of them the compiler ran here, before the package existed.

So the artifact this directory records a baseline for is the **build** as much as
the program:

```
recipe (lexe.json + payload source + build file)
    -> assembled package
    -> DIRECT BUILD, outside .LEXE, in a clean environment
    -> what it produced, read out of the file with readelf and file(1)
    -> DIRECT EXECUTION in the tree that built it
    -> DIRECT EXECUTION again, from a different directory,
       with the build tree renamed away
    -> only then admitted to the corpus
```

The last step is the one that matters. A build that bakes an absolute path into
its product — and an ordinary `-Wl,-rpath,$(pwd)/../lib` in a Makefile does
exactly that — produces something that runs perfectly in the directory it was
built in and cannot start anywhere else. Measuring only the first run records
that specimen as healthy.

Nothing here knows anything about `.LEXE`. Each generated `lexe.json` is
validated against `schema/lexe-manifest-0.1.schema.json` with `jsonschema`, which
is an independent check that the package is well formed; whether `.LEXE` should
accept, reject or rewrite any of these recipes is not a question this directory
answers.

## Regenerating — and why you must, before citing anything

```sh
cd "/mnt/c/Users/.../.lexe/tests/workloads"
python3 generate_portable.py --out /tmp/lexe-workloads-portable --jobs 6
# a subset:
python3 generate_portable.py --only portable-rpath
python3 generate_portable.py --only portable-link
```

Exit status 0 means every selected recipe reached `baseline-ok`. Everything lands
under `--out`; nothing is written back into the repository.

> **`/tmp` does not survive a WSL restart.** The corpus lives entirely under
> `--out`, which defaults to `/tmp`, and WSL wipes `/tmp` when the distribution
> shuts down — which happens on a reboot, on `wsl --shutdown`, and on its own
> after the last session closes. An `index.json` from a previous boot is
> therefore usually *absent*, and if one is present it describes a source tree
> that may since have changed. **Regenerate before citing any number out of it**,
> and check `generated_at` and the generator `sha256` in the file you are reading
> against the tree you are reading it about. This is not hypothetical bookkeeping:
> every absolute path recorded in the index — every `{SRCDIR}` baked into a
> product, every `DT_RUNPATH` in the rpath table — names a directory under
> `/tmp` that no longer exists.

```
/tmp/lexe-workloads-portable/
  index.json              the manifest (see below)
  pkg/<id>/               the package as it would SHIP: lexe.json + payload/
  build/<id>/             a copy of it, in which the build actually ran
  installed/<id>/         what an install would promote: the payload minus its
                          source directory, same relative layout
  rundir/<id>/            the working directory the relocated run used
```

A full generation is well under a minute on 6 jobs on an idle host — see
**Cost** below, where the spread and the load averages it was measured under are
given together, because separately neither is worth anything.

## What a recipe is

```
specs_portable/<recipe>/payload/...        the source tree and its build file
specs_portable/<recipe>/makefiles/Makefile.<variant>
                                           a build file copied over the
                                           payload's own, so a family of
                                           specimens can share one source tree
```

`lexe.json` is **generated** from the declaration table in
`generate_portable.py`, not hand-written ninety-four times: the table is the
source of truth for what each recipe declares, and a manifest that had drifted
from it would be a fixture that lies. The payload tree is real files in the
repository.

The `makefiles/Makefile.<variant>` mechanism is what keeps ninety-four specimens
down to a few dozen source trees. `variant_dest` generalises it beyond
`Makefile`. Several families go further and share a payload *and* a build,
varying only `lexe.json`:

* `portable-run-*` (17) — one product, seventeen different `entrypoint.arguments`
* `portable-multi-exec-*` (2) — one build, a different entrypoint declared
* `portable-env-flags-*` (2) — one build, a different build environment
* `portable-cmake-option-*` (2) — one build, a different cache variable
* `portable-make-{serial,parallel-env}` and `portable-command-make-parallel` (3)
* `portable-product-pe` / `portable-product-path-mismatch` — identical payload

Each package is self-contained: no recipe includes a header from outside its own
payload, because a portable package that reaches outside its payload for a header
is not a portable package. The oracle is a line format, not a library — the
programs print `KEY=VALUE` with plain `printf`.

## The oracle

The same contract as the ELF corpus (`specs/oracle.h`): `KEY=value` is
deterministic, `OBS_KEY=value` is an environment-dependent observation, and the
last line is `RESULT=PASS` or `RESULT=FAIL`. Every portable program prints
`OBS_BUILD_STAMP` from `__DATE__`/`__TIME__`, which the compiler on the
installing machine fills in and the package cannot forge, and `BUILD_ISA` from
the compiler's own predefined macros rather than from the manifest's claim.

**No deterministic oracle value is a byte position, a length or a count over the
oracle stream itself.** That stream carries `FIXTURE_ID`, whose length differs
per specimen, so any offset into it would be a number that changes for reasons
having nothing to do with the property being measured. Regions are located by
content — a key name, a first line, a delimiter — never by offset. Absolute
offsets and sizes appear only as `OBS_` observations and in the index.

## The index (`index.json`)

`schema: lexe.workload.portable.index/1`. Per recipe:

| Field | Contents |
|---|---|
| `declared` | written by hand **before** the recipe was ever built; every field is checked against the observation |
| `manifest`, `manifest_schema` | the generated `lexe.json` and the `jsonschema` verdict on it |
| `package` | the shipped tree: every file with size and sha256, and the total |
| `toolchain_probe` | each declared tool, resolved on PATH or reported ABSENT, with its version |
| `build` | the **exact argv sequence** and the directory each step ran in, the clean environment (including any declared `build_env_extra`), per-step exit code, seconds, stdout and stderr |
| `build_products` | every file that appeared under the payload that was not in the package |
| `product` | the declared entrypoint: exists, size, sha256, **mode**, `file(1)`, full ELF facts (`e_type`, PIE, program interpreter, `DT_NEEDED`, `.symtab`), `RUNPATH`/`RPATH` and which tag, `ldd`, and a `kind` decided from `file(1)` and `readelf` rather than from the flags the recipe used |
| `runs.in_build_tree` | direct execution from the tree that built it |
| `runs.after_build_tree_removed` | direct execution of the promoted copy, from a different directory, with the build tree renamed away and `LD_LIBRARY_PATH` unset |
| `installed` | every file an install would promote, which is what the hygiene declarations are checked against |
| `verdict` | `baseline-ok` or `baseline-mismatch` with every disagreement named |

Top level also carries `rpath_variant_table` — the whole point of that family,
side by side — and `host.loadavg_at_start` / `generator.loadavg_at_end`, because
`runs.*.duration_ms` is in this file and a duration taken under load is not a
measurement of anything. The first of those two is read before the first build
starts and the second after the last one finishes; they were briefly both read
at the end, and came out byte-identical, which is how that was noticed. A field
named `loadavg_at_start` that is measured at the end is worse than no field,
because it reads as evidence that the run was idle.

`LD_LIBRARY_PATH` is never set for a run. Whether a product finds its own library
has to be a property of the product.

### What a declaration can say

Beyond the original `build_succeeds` / `product_exists` / `runpath` /
`starts_*` / `expect`, a recipe may declare:

* the built file: `e_type`, `pie`, `interpreter`, `needed_contains`,
  `needed_empty`, `has_symtab`, `product_mode`, `product_min_bytes`,
  `product_max_bytes`
* what the build said: `build_stdout_contains`, `build_stderr_contains`
* how the product behaved: `exit_code`, `signal`, `run_stderr_contains`
* **the relocated run specifically**: `relocated_exit_code`, `relocated_signal`,
  `expect_relocated`. Without these the relocated check only asks whether `main`
  was reached, and a product that starts and then cannot find its data would
  pass — which is exactly the shape `portable-data-baked-abs-path` is about.
* what an install promotes: `installed_present`, `installed_absent`

`{SRCDIR}` and `{INSTALLDIR}` in a declared value are substituted with the
absolute build and install directories, which are the only two values a
declaration cannot know in advance.

## Coverage

**94 recipes.** By axis:

| Axis | Recipes | Covers |
|---|---:|---|
| **Build drivers** | 12 | bare compiler argv (`portable-bare-cc`, no build system at all); `make`; recursive make with two sub-makes; parallel make requested through `MAKEFLAGS` and through a declared argv, with a serial control; a shell build script; cmake flat, cmake with a subdirectory and an installed target, cmake for C++, cmake for a shared library, cmake with a cache option (on and off) |
| **Build inputs** | 4 | a generated header from a configure-like probe step; generated sources; a build that reads an environment variable to choose its flags (set and unset); a source tree three directories deep |
| **Languages / standards** | 12 | C89, C99, C11, C17, gnu89; C++11, C++14, C++17, C++20; C and C++ in one product; a C++ product linking a C static archive; C++ with threads and exceptions |
| **Products** | 10 | one executable; three executables from one package (two entrypoint choices); a static library + consumer; a shared library + consumer; an executable + a data file it needs; a script wrapping a compiled binary; a 96 MiB product; an ELF shared object at the entrypoint; a relocatable object; a static archive |
| **Linkage** | 8 | PIE, non-PIE, `-static`, `-static-pie`, stripped, with debug info, plus the shared-library pair |
| **Relocatability** | 13 | ten `-Wl,-rpath` idioms, cmake's `INSTALL_RPATH`, `/proc/self/exe` data lookup, a baked absolute path, a cwd-relative lookup |
| **Build outcomes** | 10 | success; success with warnings; failure at compile; at link (undefined symbol); at configure (cmake); before the compiler runs at all (no rule); a missing system header; a missing toolchain; success with the product at the wrong path; success with the compiler's failure swallowed by make |
| **Degenerate products** | 5 | zero-byte file; correct ELF left mode 0644; text file with no shebang; object file; static archive |
| **Runtime behaviour** | 17 | no arguments, three arguments, an argument with spaces, an empty argument, a non-ASCII argument, forty-one arguments; exit 7 and exit 255; SIGSEGV and SIGABRT; stderr output; an environment variable present and absent; writing and re-reading a file; a sub-millisecond run and a multi-second one; stdin at EOF |
| **Foreign products** | 3 | a PE32+ executable, a PE32+ DLL, and the path-mismatch shape the first of them exposed |
| **Hygiene** | 3 | files in the source directory that must not be installed (with a file outside it that must); spaces and non-ASCII in the source directory, source filenames and the product name, built by a script; a space in the source directory built by make |

A recipe appears under every axis it covers, so that column sums to more than 94
— the shared-library pair is both a product shape and a relocatability shape, and
`portable-outcome-archive` is both a degenerate product and a build outcome.
Every recipe still names exactly **one** property, in words, and it is declared
before the recipe is built: the `property` field of each `index.json` record, and
the `prop=` argument in the declaration table in `generate_portable.py`. The
table is the documentation; this README is the map.

### Baselines, measured

From a clean full generation (`counts` and the per-recipe records in
`index.json`, not reasoning):

| | |
|---|---:|
| recipes | 94 |
| builds that succeed | 88 |
| products that exist at the declared entrypoint | 85 |
| products that exist and **cannot** be launched | 12 |
| products that reach `main` in the build tree | 73 |
| products that reach `main` after relocation | 70 |
| declared to start in the build tree and **not** after relocation | 3 |

Every one of those is deliberate and separately declared:

* **6 builds fail** — `toolchain-absent`, `build-fails-partway` (missing own
  header), `outcome-link-fails` (undefined symbol), `outcome-missing-sys-header`,
  `outcome-no-rule` (make, before any compile), `cmake-fails-configure`.
* **3 builds succeed with nothing at the entrypoint** —
  `product-path-mismatch`, `outcome-no-product`, `outcome-swallowed-error`.
* **12 products exist and do not start** — 5 rpath variants whose search path is
  wrong (`make-var-pwd`, `absolute`, `none`, `origin-double-quoted`,
  `origin-single-dollar`), 1 Windows DLL (`product-pe-dll` — the PE
  *executable* next to it does start, through `binfmt_misc`), 1 ELF shared
  object, and 5 degenerate products (`empty-product`, `not-executable`,
  `object`, `archive`, `text-product`).
* **3 start and do not relocate** — `portable-rpath-shell-pwd`,
  `portable-rpath-curdir`, `portable-rpath-shell-func-pwd`: the three idioms
  that bake the build directory into `DT_RUNPATH`.

`portable-data-baked-abs-path` is a fourth kind of non-relocatable and appears in
none of those counts, because it *starts* after relocation and then fails: see
below.

## The rpath family

One program, one library, ten link lines that differ in nothing but the
`-Wl,-rpath` argument (and, for one of them, `--disable-new-dtags`). The table
below is measured, not reasoned about: the `RUNPATH` column is what `readelf -d`
reports in the built file, and the last two columns are whether the product
reached `main` in the tree that built it and after that tree was renamed away.

| variant | written in the Makefile | tag | value in the built file | in build tree | relocated |
|---|---|---|---|---|---|
| `make-var-pwd` | `-Wl,-rpath,$(pwd)/../lib` | `DT_RUNPATH` | `/../lib` | no | no |
| `shell-pwd` | `-Wl,-rpath,$$PWD/../lib` | `DT_RUNPATH` | `<build>/payload/src/../lib` | yes | no |
| `curdir` | `-Wl,-rpath,$(CURDIR)/../lib` | `DT_RUNPATH` | `<build>/payload/src/../lib` | yes | no |
| `shell-func-pwd` | `-Wl,-rpath,$(shell pwd)/../lib` | `DT_RUNPATH` | `<build>/payload/src/../lib` | yes | no |
| `absolute` | `-Wl,-rpath,/opt/lexe-workload/lib` | `DT_RUNPATH` | `/opt/lexe-workload/lib` | no | no |
| `origin` | `-Wl,-rpath,'$$ORIGIN/../lib'` | `DT_RUNPATH` | `$ORIGIN/../lib` | yes | **yes** |
| `origin-dtrpath` | the same, `-Wl,--disable-new-dtags` | **`DT_RPATH`** | `$ORIGIN/../lib` | yes | **yes** |
| `origin-double-quoted` | `-Wl,-rpath,"$$ORIGIN/../lib"` | `DT_RUNPATH` | `/../lib` | no | no |
| `origin-single-dollar` | `-Wl,-rpath,'$ORIGIN/../lib'` | `DT_RUNPATH` | `RIGIN/../lib` | no | no |
| `none` | *(no `-Wl,-rpath` at all)* | *(none)* | *(none)* | no | no |

`portable-cmake-shared-origin` reaches `$ORIGIN/../lib` by a completely different
route — cmake properties rather than a link flag the recipe wrote — and is in the
same table in `index.json`.

The failures are all the same shape, `exit 127` with `error while loading shared
libraries: libutil.so: cannot open shared object file`, and `ldd` on the
relocated product says `libutil.so => not found`.

Five of these deserve naming:

* **`$(pwd)` in a Makefile is not a command substitution.** It is a reference to
  a make *variable* named `pwd`, which nobody defined, so make expands it to the
  empty string and the linker is handed `/../lib`. Anyone who writes this means
  `$(shell pwd)`.
* **`$ORIGIN` needs two levels of quoting** — `$$` so make emits one dollar,
  single quotes so the shell does not expand it. The next three rows are what
  happens when you lose one of them:
* **double quotes lose it to the shell.** `"$$ORIGIN/../lib"` gets one dollar
  past make correctly, and then the shell expands `$ORIGIN` — an ordinary
  environment variable nobody has set — to nothing. Identical wreckage to
  `$(pwd)`, from the opposite direction.
* **one dollar loses it to make.** `'$ORIGIN/../lib'` is read by make as `$O`
  (a variable named `O`, undefined) followed by the literal `RIGIN/../lib`. The
  linker accepts `RIGIN/../lib` without complaint, because a *relative*
  `DT_RUNPATH` is legal — it is resolved against the process's working directory
  — so there is no build-time diagnostic and the product's library search path
  now depends on where somebody launches it from.
* **`DT_RPATH` is not `DT_RUNPATH`.** `--disable-new-dtags` puts the identical
  string under the old tag. The difference is not cosmetic: `DT_RPATH` is
  consulted *before* `LD_LIBRARY_PATH` and cannot be overridden by it,
  `DT_RUNPATH` after and can. Anything that greps a product for `RUNPATH` finds
  nothing here and concludes it has no search path at all.

Whether `.LEXE` should accept, reject or rewrite any of these strings is not a
question this directory answers.

## The data-file family — the same question, one layer up

`portable-data-{proc-self-exe,baked-abs-path,cwd-relative}` ask the rpath
question about a *data* file instead of a library, and the answers differ in one
important way: **there is no loader, so a wrong answer produces no diagnostic at
all.**

| variant | how it finds its data | in build tree | relocated |
|---|---|---|---|
| `proc-self-exe` | `readlink("/proc/self/exe")`, then `../share` | PASS | **PASS** |
| `baked-abs-path` | `-DDATA_DIR='"$(CURDIR)/../share"'` | PASS | *starts*, `RESULT=FAIL`, exit 3 |
| `cwd-relative` | `"share/message.txt"` | `RESULT=FAIL`, exit 3 | `RESULT=FAIL`, exit 3 |

`baked-abs-path` is why `expect_relocated` and `relocated_exit_code` exist. It
**starts** after relocation — `main` is reached, the oracle is printed, the
`starts_after_build_tree_removed` check passes — and the program is useless. Only
a declaration about what the relocated run *said* catches it. The equivalent
rpath failure is loud (exit 127, a loader message, an `ldd` line); this one is
silent unless the program itself thought to check, and most do not.

`cwd-relative` is declared to fail in **both** runs, including the one in the
tree that built it. That is not a broken recipe: a launcher chooses the working
directory and it is never the payload root, so the shape is broken everywhere and
looks fine to anyone who tests it by `cd`-ing into the payload first.

## Baseline mismatches found while building this factory

Recorded because a wrong prediction quietly corrected is a prediction nobody
learns from.

1. **mingw-w64 gcc appends `.exe`.** The recipe declared its entrypoint as
   `bin/portable-product-pe`, matching the Makefile's own target, and
   `x86_64-w64-mingw32-gcc -o ../bin/portable-product-pe` produced
   `../bin/portable-product-pe.exe`. The build exits 0, prints no diagnostic, and
   the file the manifest names is not there. Rather than rename one, both shapes
   are kept: `portable-product-pe` declares the `.exe` path, and
   `portable-product-path-mismatch` declares the suffix-less path and covers "a
   successful build that does not produce the declared entrypoint". The two
   packages have byte-identical payloads and differ only in `lexe.json`.
   (`portable-outcome-no-product` now covers the same property without needing a
   cross-compiler.)
2. **A PE32+ is executable on this host.** The recipe declared that the product
   would not start, on the reasoning that a Linux kernel cannot exec a PE. It
   starts, exits 0 and prints its oracle: `binfmt_misc` has `WSLInterop-late`
   registered and the kernel hands the file to Windows. Confirmed to be the
   `binfmt` path rather than anything about the filename by copying the same
   bytes to a name with no `.exe` suffix, which also ran. The environment does
   **not** cross that boundary — with `FIXTURE_ID=probe` set the program reported
   its compiled-in default, so `getenv` returned NULL.

   The declaration now matches this host and names the dependency in
   `declared.host_dependency`, so nobody inherits the claim on a machine without
   WSL interop. On this host a `portable` package can produce and launch a
   Windows binary without ever declaring `applicationType: "windows"`.
3. **That same PE emits CRLF.** Every oracle value came back with a trailing
   `\r`: the Windows C runtime translates `\n` to `\r\n` on a text-mode stream,
   so the identical source compiled by `cc` and by `x86_64-w64-mingw32-gcc`
   produces output that differs by one byte per line. The declaration says
   `"RESULT": "PASS\r"` deliberately — stripping CR in `parse_oracle` would have
   hidden a real property of this shape for the whole corpus, and for every
   future specimen too.
4. **A parse-time `$(MAKEFLAGS)` test cannot see `-j`.** `portable-make-parallel-env`
   declares that make really was given four jobs, and the Makefile reported
   `PORTABLE_PARALLEL_SEEN=no` for a build whose `MAKEFLAGS` demonstrably
   contained `-j4`. The probe was written as
   `ifneq (,$(findstring j,$(MAKEFLAGS)))` at the top of the file. GNU make
   appends `-j` and `--jobserver-auth` to `MAKEFLAGS` **after** it has finished
   reading the makefiles: at parse time the variable held only `w` (the
   `--print-directory` that `-C` implies), and expanded inside a recipe line the
   same variable reads `w -j4 --jobserver-auth=3,4`. The declaration was right
   and the probe was wrong; the test moved into the recipe. Any makefile that
   changes its own behaviour from a parse-time look at `MAKEFLAGS` is deciding on
   stale information.

   This one also cost the recipe an extra specimen. `portable-make-serial` exists
   because the product is byte-identical whether or not `-j` arrived, so without
   a sibling that declares `PORTABLE_PARALLEL_SEEN=no` there is nothing the two
   parallel specimens are being compared against.

Every other declaration in the corpus — all ten rpath predictions, all six ELF
linkage predictions, every product classification, every exit code and signal —
was right on its first run. That is a claim about the declarations, so it was
tested rather than asserted: each new kind of check was deliberately corrupted in
memory and required to produce a `baseline-mismatch` naming the field, with
untouched controls required to stay clean. A check that cannot fail is not
evidence that anything passed.

## Things worth knowing that came out of this

* **`file(1)` and `readelf` disagree about a static archive.** `file -b` says
  `current ar archive`; `readelf -h` **succeeds** and reports `REL`, having read
  the first member rather than the file. `portable-outcome-archive` is the only
  specimen the classifier calls `elf-other`, which is the honest answer for a
  file that is an archive of ELFs and is not an ELF.
* **`e_type DYN` does not mean "shared library" and does not mean "dynamically
  linked".** A PIE is `DYN`. So is a `-static-pie` executable, which has no
  program interpreter and an empty `DT_NEEDED`. `portable-link-static-pie` exists
  for exactly the code that infers either.
* **"Executable bit set" and "executable" are different claims.** A zero-byte
  file, a text file with no shebang, an object file and an archive all fail
  `execve` with `ENOEXEC`; a correct ELF at mode 0644 fails with `EACCES`. Four
  of those are `baseline-ok` specimens whose declared behaviour is *not to
  start*.
* **An entrypoint need not be an ELF.** `portable-outcome-script-wrapper` is a
  generated `#!/bin/sh` script that `exec`s a binary beside it, located from
  `$0`. It relocates. A wrapper with an absolute path in it would be the rpath
  mistake written in shell.
* **make cannot have a space in a target.** `portable-unicode-paths-make` works
  only because the spaced path is never a target or a prerequisite: `all` is
  `.PHONY` with no file prerequisites and the path appears only inside a recipe
  line, where the *shell* parses it and ordinary double quotes work. The cost is
  that the product is rebuilt unconditionally, because make no longer knows what
  the rule produces. `make -C "src with space"` itself is fine — that path is an
  argument to make, never a token in a makefile. The script-driven
  `portable-unicode-paths-command` has no such restriction, which is why the
  non-ASCII *filenames* live there.
* **The schema permits all of that.** `entrypoint.executable` and
  `build.sourceDir` forbid a NUL byte, a backslash, a leading `/`, a drive
  designator, an empty segment and a `..` segment — and say nothing about spaces
  or non-ASCII. `bin/pörtable unicode` is a well-formed entrypoint.
* **cmake's default is the non-relocatable shape.** cmake links the build tree
  with an absolute rpath into its own build directory and rewrites it at install
  time — and the rewrite never happens for a product that is *copied* rather than
  installed. `BUILD_WITH_INSTALL_RPATH` with `INSTALL_RPATH "$ORIGIN/../lib"` is
  what puts the final value in at link time; that is what
  `portable-cmake-shared-origin` does and why it is worth its own specimen.
* **A failed cmake configure still leaves a build tree.** `CMakeCache.txt` and
  the compiler-detection output are written before `find_package(... REQUIRED)`
  reaches its error, so "the build directory has contents" is not evidence of
  progress.
* **The four new cmake recipes declare `make` in their toolchain and
  `portable-cmake` does not.** cmake's default generator here *is* Unix
  Makefiles, so `cmake --build` shells out to make and a host without it cannot
  run any of them. The older recipe is left under-declared on purpose: a manifest
  may under-declare its toolchain and still build, and having both shapes in the
  corpus records that rather than hiding it.

## Cost

Generation must stay cheap enough to repeat, because `/tmp` means it *will* be
repeated.

Five consecutive full generations at `--jobs 6`, wall clock including process
start and the `rm -rf` of the previous output, each with the 1-minute load
average at the moment it finished:

| sample | wall | load (1 min) |
|---|---:|---:|
| 2 | 25.4 s | 20.7 |
| 3 | 27.1 s | 19.2 |
| 1 | 39.4 s | 20.5 |
| 4 | 61.7 s | 31.6 |
| 5 | 63.6 s | 39.5 |

**median 39.4 s, p95 ≈ 63 s, at load averages of 19–40.** The generator's own
`wall_seconds` — the figure it writes into `index.json`, which excludes
interpreter start-up — was 15.2 s for the run recorded in `/tmp/port-final`, at
load 16.9.

Those numbers are not a benchmark and must not be quoted as one. This tree is
worked on by several roles at once and every sample above was taken while others
were compiling; the 2.5× spread tracks the load column and nothing else. On an
idle host the same corpus generates in well under half a minute. The point of
the table is the shape — cheap enough to regenerate on demand, which is the only
property that matters here.

The expensive specimens, and why they are worth it:

| Recipe | Cost | Why |
|---|---|---|
| `portable-slow-build` | ~14 s of build | The time goes into the compiler, not a sleep — 800 generated translation units. A sleep exercises none of what a build costs. |
| `portable-large-product` | 96 MiB written | A few kilobytes of package. Any size taken from the package is wrong by four orders of magnitude. |
| `portable-run-spin-long` | ~1–3 s × 2 runs | A run long enough to be distinguishable from the sub-millisecond ones. No duration is declared for it — that would be a performance assertion. |

`index.json` records `host.loadavg_at_start` and `generator.loadavg_at_end` for
the same reason, and `runs.*.duration_ms` should be read with them in view. No
declaration anywhere in this corpus asserts a duration, a rate or a size that
depends on how busy the machine was.

## Deliberately NOT generated

* **A foreign-ISA ELF product.** The obvious companion to the PE case, and
  **BLOCKED**: no `aarch64-linux-gnu-gcc`, `arm-linux-gnueabihf-gcc` or
  `riscv64-linux-gnu-gcc` is installed on this host. Patching `e_machine` in a
  host binary would produce a deliberately malformed ELF, which is a `.LEXE`
  *verification* input and not a workload.
* **A C23 recipe.** **BLOCKED** on this host's gcc 13.3, which does not
  recognise `-std=c23` and offers `-std=c2x`. A specimen declaring `c2x` would be
  declaring a compiler-specific spelling rather than a language standard, which
  is not the property the `std_c` family measures.
* **A build that needs the network.** A real and important shape, and the build
  sandbox denies the network by design, so the specimen's declared outcome would
  be "the sandbox refused" — which says nothing about the recipe. It belongs with
  the permission specimens.
* **A build that exceeds the build timeout.** `BUILD_TIMEOUT_S` is 600, so a
  specimen that reached it would add ten minutes to every generation to
  demonstrate one boolean. The timeout path is exercised by the harness, not by a
  recipe.
* **A build that tries to escape its source directory.** Hostile, not
  legitimate.
* **A full autotools bootstrap.** `portable-configure-step` covers the property
  that matters — a build that generates a header by probing the host before
  anything is compiled, so the file the compiler sees is not in the package — in
  three files and under a second. `autoreconf` would add minutes and no new
  property.
* **Anything declaring a duration, a rate or a memory ceiling.** Those are
  measurements of this machine at the moment it ran, not properties of a recipe.
* **Recipes under `/mnt/c`.** DrvFS reports mode 0755 for every file, so any
  permission or executable-bit property measured there would be a lie — and
  `portable-outcome-not-executable` is exactly such a property. Every build and
  every run is on native ext4 under `/tmp`.

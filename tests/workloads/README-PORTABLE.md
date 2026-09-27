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

## Regenerating

```sh
cd "/mnt/c/Users/.../.lexe/tests/workloads"
python3 generate_portable.py --out /tmp/lexe-workloads-portable --jobs 6
# a subset:
python3 generate_portable.py --only portable-rpath
```

Exit status 0 means every selected recipe reached `baseline-ok`. Everything lands
under `--out`; nothing is written back into the repository.

```
/tmp/lexe-workloads-portable/
  index.json              the manifest (see below)
  pkg/<id>/               the package as it would SHIP: lexe.json + payload/
  build/<id>/             a copy of it, in which the build actually ran
  installed/<id>/         what an install would promote: the payload minus its
                          source directory, same relative layout
  rundir/<id>/            the working directory the relocated run used
```

A full generation is about 95 s on 6 jobs, nearly all of it
`portable-slow-build`.

## What a recipe is

```
specs_portable/<recipe>/payload/src/    the source tree and its build file
specs_portable/rpath_variants/makefiles/Makefile.<variant>
                                        the six link lines of the rpath family
```

`lexe.json` is **generated** from the declaration table in
`generate_portable.py`, not hand-written nineteen times: the table is the source
of truth for what each recipe declares, and a manifest that had drifted from it
would be a fixture that lies. The payload tree is real files in the repository.

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

## The index (`index.json`)

`schema: lexe.workload.portable.index/1`. Per recipe:

| Field | Contents |
|---|---|
| `declared` | written by hand **before** the recipe was ever built; every field is checked against the observation |
| `manifest`, `manifest_schema` | the generated `lexe.json` and the `jsonschema` verdict on it |
| `package` | the shipped tree: every file with size and sha256, and the total |
| `toolchain_probe` | each declared tool, resolved on PATH or reported ABSENT, with its version |
| `build` | the **exact argv sequence** and the directory each step ran in, the clean environment, per-step exit code, seconds, stdout and stderr |
| `build_products` | every file that appeared under the payload that was not in the package |
| `product` | the declared entrypoint: exists, size, sha256, mode, `file(1)`, full ELF facts, `RUNPATH`/`RPATH` and which tag, `ldd`, and a `kind` decided from `file(1)` and `readelf` rather than from the flags the recipe used |
| `runs.in_build_tree` | direct execution from the tree that built it |
| `runs.after_build_tree_removed` | direct execution of the promoted copy, from a different directory, with the build tree renamed away and `LD_LIBRARY_PATH` unset |
| `verdict` | `baseline-ok` or `baseline-mismatch` with every disagreement named |

Top level also carries `rpath_variant_table` — the whole point of that family,
side by side, rather than something a reader has to assemble from nineteen
records.

`LD_LIBRARY_PATH` is never set for a run. Whether a product finds its own library
has to be a property of the product.

## Coverage

19 recipes.

| Recipe | Covers |
|---|---|
| `portable-c-single` | one translation unit, one Makefile, one product |
| `portable-c-multi-tu` | four translation units, an object list, a link order |
| `portable-cxx` | C++17 at install: static init order, an unwound exception, `std::thread`, `<algorithm>` |
| `portable-cmake` | the second driver; cmake probes for its compiler and wants its own build directory |
| `portable-command-driver` | the third driver: `build.system: "command"` with a declared argv, `["sh", "build.sh"]` |
| `portable-shared-lib` | a build that produces a shared library **and** links the program against it |
| `portable-toolchain-absent` | a declared tool that resolves nowhere on this host |
| `portable-build-fails-partway` | two objects built, then a missing header; a partial tree and no product |
| `portable-product-pe` | a successful build whose product is a PE32+ |
| `portable-product-path-mismatch` | a successful build that does not produce the declared entrypoint |
| `portable-product-shared-object` | a successful build whose product is an ELF shared object with no interpreter |
| `portable-slow-build` | generated sources and then a real compile |
| `portable-large-product` | a few kilobytes of package, a 96 MiB product |
| `portable-rpath-*` (6) | what six ordinary `-Wl,-rpath` idioms actually put in the built file |

## The rpath family

One program, one library, six link lines that differ in nothing but the
`-Wl,-rpath` argument. The table below is measured, not reasoned about: the
`RUNPATH` column is what `readelf -d` reports in the built file, and the last two
columns are whether the product reached `main` in the tree that built it and
after that tree was renamed away.

| variant | written in the Makefile | `DT_RUNPATH` in the built file | runs in build tree | runs relocated |
|---|---|---|---|---|
| `make-var-pwd` | `-Wl,-rpath,$(pwd)/../lib` | `/../lib` | no | no |
| `shell-pwd` | `-Wl,-rpath,$$PWD/../lib` | `<build>/payload/src/../lib` | yes | no |
| `curdir` | `-Wl,-rpath,$(CURDIR)/../lib` | `<build>/payload/src/../lib` | yes | no |
| `shell-func-pwd` | `-Wl,-rpath,$(shell pwd)/../lib` | `<build>/payload/src/../lib` | yes | no |
| `absolute` | `-Wl,-rpath,/opt/lexe-workload/lib` | `/opt/lexe-workload/lib` | no | no |
| `origin` | `-Wl,-rpath,'$$ORIGIN/../lib'` | `$ORIGIN/../lib` | yes | **yes** |

All six are `DT_RUNPATH`, not `DT_RPATH`: this toolchain defaults to new dtags.
The failures are all the same, `exit 127` with
`error while loading shared libraries: libutil.so: cannot open shared object
file`, and `ldd` on the relocated product says `libutil.so => not found`.

Two of these deserve naming:

* **`$(pwd)` in a Makefile is not a command substitution.** It is a reference to
  a make *variable* named `pwd`, which nobody defined, so make expands it to the
  empty string and the linker is handed `/../lib`. Anyone who writes this means
  `$(shell pwd)`, which is the `shell-func-pwd` variant. The product then fails
  even in the directory that built it.
* **`$ORIGIN` needs two levels of quoting** — `$$` so make emits one dollar,
  single quotes so the shell does not expand it. Losing either one is the single
  most common way to get the relocatable idiom wrong.

Whether `.LEXE` should accept, reject or rewrite any of these strings is not a
question this directory answers. What each recipe *produces* is a fact about the
recipe and the toolchain, observable without `.LEXE`, and that is what is
recorded.

## Baseline mismatches found while building this factory

Recorded because a wrong prediction quietly corrected is a prediction nobody
learns from. All six rpath predictions were right on the first run, and so was
every other recipe's; the three that were wrong were all about the PE recipe, in
three successive runs, and each is more interesting than the specimen I set out
to make.

1. **mingw-w64 gcc appends `.exe`.** The recipe declared its entrypoint as
   `bin/portable-product-pe`, matching the Makefile's own target, and
   `x86_64-w64-mingw32-gcc -o ../bin/portable-product-pe` produced
   `../bin/portable-product-pe.exe`. The build exits 0, prints no diagnostic, and
   the file the manifest names is not there. Rather than rename one, both shapes
   are kept: `portable-product-pe` declares the `.exe` path and covers "a
   successful build whose product is foreign", and
   `portable-product-path-mismatch` declares the suffix-less path and covers "a
   successful build that does not produce the declared entrypoint". The two
   packages have byte-identical payloads and differ only in `lexe.json`.
2. **A PE32+ is executable on this host.** The recipe declared that the product
   would not start, on the reasoning that a Linux kernel cannot exec a PE. It
   starts, exits 0 and prints its oracle in about 0.9 s: `binfmt_misc` has
   `WSLInterop-late` registered and the kernel hands the file to Windows.
   Confirmed to be the `binfmt` path rather than anything about the filename by
   copying the same bytes to a name with no `.exe` suffix, which also ran. The
   environment does **not** cross that boundary — with `FIXTURE_ID=probe` set the
   program reported its compiled-in default, so `getenv` returned NULL.

   The declaration now matches this host and names the dependency in
   `declared.host_dependency`, so nobody inherits the claim on a machine without
   WSL interop. The consequence is worth stating plainly and is not this
   directory's to judge: on this host a `portable` package can produce and launch
   a Windows binary without ever declaring `applicationType: "windows"`.
3. **That same PE emits CRLF.** Having declared that it starts, the next run
   still failed: every oracle value came back with a trailing `\r`. The Windows C
   runtime translates `\n` to `\r\n` on a text-mode stream, so the identical
   source compiled by `cc` and by `x86_64-w64-mingw32-gcc` produces output that
   differs by one byte per line. The declaration now says `"RESULT": "PASS\r"`
   and so on, deliberately: stripping CR in `parse_oracle` would have hidden a
   real property of this shape for the whole corpus, and would have hidden it
   from every future specimen too.

## Deliberately NOT generated

* **A foreign-ISA ELF product.** The obvious companion to the PE case, and
  **BLOCKED**: no `aarch64-linux-gnu-gcc`, `arm-linux-gnueabihf-gcc` or
  `riscv64-linux-gnu-gcc` is installed on this host. Patching `e_machine` in a
  host binary would produce a deliberately malformed ELF, which is a `.LEXE`
  *verification* input and not a workload.
* **A build that needs the network.** A recipe that fetches a dependency is a
  real and important shape, and the build sandbox denies the network by design,
  so the specimen's declared outcome would be "the sandbox refused" — which says
  nothing about the recipe. It belongs with the permission specimens.
* **A build that tries to escape its source directory.** Hostile, not
  legitimate.
* **`configure`-style autotools recipes.** The `command` driver already covers
  "the build is a script"; a full autotools bootstrap would add minutes of build
  time and no new property.
* **Recipes under `/mnt/c`.** DrvFS reports mode 0755 for every file, so any
  permission or executable-bit property measured there would be a lie. Every
  build and every run is on native ext4 under `/tmp`.

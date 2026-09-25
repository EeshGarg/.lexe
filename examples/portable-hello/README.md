# Example: portable-hello

A package whose payload is **source code**, compiled into a native program by
the machine that installs it. This is the example for
`applicationType: "portable"` (FORMAT-0.1 §5.3 and §5.8) and the Definitive
Architecture's portable-code path:

```text
        SAME App.lexe
              |
    +---------+---------+
    |         |         |
  x86-64    ARM64    RISC-V
    |         |         |
  compile  compile  compile      <- on the destination machine
    |         |         |
    +---------+---------+
              |
        Native Linux
```

It is the counterpart to [`../gui-hello/`](../gui-hello/), which ships a
compiled ELF and demonstrates the native path.

## What is in the package, and what is not

```text
portable-hello/
├── lexe.json
└── payload/
    └── src/
        ├── main.c      <- what ships
        └── Makefile    <- the recipe .LEXE runs on the destination machine
```

There is **no `payload/bin/portable-hello`**. The manifest declares it as the
entrypoint, and verification *requires it to be absent*: a portable package
that shipped a prebuilt entrypoint would install a binary the host never
compiled, which is the alpha's source-packaged-as-native bug told backwards
(FORMAT-0.1 §6.7).

## The manifest side

```jsonc
"applicationType": "portable",
"architectures": ["x86_64", "aarch64"],     // ISAs the recipe is declared to build for
"entrypoint": { "executable": "bin/portable-hello" },   // what the build must PRODUCE
"build": {
  "system": "make",          // `make -C src`, invoked by the runtime
  "sourceDir": "src",
  "toolchain": ["make", "cc"]  // probed on the host BEFORE approval is sought
},
"launch": { "mode": "console" }   // it prints and exits, so it says so
```

## Building and installing it

```sh
lexe keygen /tmp/key.json
cp -r examples/portable-hello /tmp/portable-hello
lexe build /tmp/portable-hello -o /tmp/portable-hello.lexe --key /tmp/key.json

lexe verify /tmp/portable-hello.lexe      # payload-role: source, no prebuilt entrypoint
lexe info   /tmp/portable-hello.lexe      # Type: Portable source, compiled on this machine

lexe install /tmp/portable-hello.lexe                      # refused: exit 5
lexe install /tmp/portable-hello.lexe --approve-compile     # compiles, then installs
lexe run com.usha.portablehello
```

The first install is **refused**, and that is the feature. Installing this
package runs a compiler on your machine, so it needs your explicit approval:

```text
$ lexe install /tmp/portable-hello.lexe
lexe: installing com.usha.portablehello compiles its source on this machine,
      and that was not approved
  hint: Re-run with `--approve-compile` to authorize the compilation. Approval
        authorizes THIS operation for this package and version; it grants the
        build no privileges. The build still runs unprivileged, isolated, and
        with the network denied.
```

## What the program prints, and why each line is evidence

```text
Lexe Portable Hello
  compiled on this machine: Sep 25 2026 02:48    <- the compiler stamped this, here, at install
  compiled for:             x86_64               <- from the compiler's own macros, not the manifest
  LEXE_APP_ID:              com.usha.portablehello
  LEXE_APP_DATA:            /run/lexe/data       <- launched by .LEXE, sandboxed like any payload
```

`__DATE__`/`__TIME__` cannot be forged by the package: they are filled in by the
compiler that ran on the installing machine. The ISA comes from the compiler's
predefined macros, so it is what the build actually targeted.

Every start also appends a line to
`$LEXE_APP_DATA/portable-hello-launches.log`, which makes a launch provable on a
host with no terminal and no display.

## What the runtime recorded

```sh
cat ~/.local/share/lexe/apps/com.usha.portablehello/meta/1.0.0/build.json
```

```jsonc
{
  "schema": "lexe.build/1",
  "buildSystem": "make",
  "hostIsa": "x86_64",
  "builtAt": "2026-09-25T02:48:16Z",
  "approval": { "granted": true, "authority": "user", "approvedBy": "you", "approvedAt": "…" },
  "toolchain": [ { "name": "make", "path": "/usr/bin/make" },
                 { "name": "cc",   "path": "/usr/bin/cc" } ],
  "products": { "payload/bin/portable-hello": "<sha256>" }
}
```

The compiled entrypoint is not covered by the package's signed `hashes.json` —
it did not exist when the package was signed — so its hash is recorded here.
That is what makes tamper detection and repair work the same for a compiled
entrypoint as for an extracted one:

```sh
printf '\xff' | dd of=~/.local/share/lexe/apps/com.usha.portablehello/versions/1.0.0/bin/portable-hello \
    bs=1 seek=1024 conv=notrunc
lexe run com.usha.portablehello          # refused: integrity check failed
lexe repair com.usha.portablehello       # refused: repairing means compiling again
lexe repair com.usha.portablehello --approve-compile   # rebuilt
lexe run com.usha.portablehello          # works again
```

## Building it outside .LEXE

The source is an ordinary C program; nothing about it requires the runtime.

```sh
make -C examples/portable-hello/payload/src
./examples/portable-hello/payload/bin/portable-hello --selftest
```

That is deliberate: a portable package's recipe must be a recipe a developer can
run themselves, or they cannot debug the build the destination machine will run.

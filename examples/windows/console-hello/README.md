# Example: windows-hello

A package whose payload is a **Windows executable**, run on Linux through a
compatibility layer. This is the example for
`applicationType: "windows"` (FORMAT-0.1 §5.3) and the Definitive
Architecture's foreign-OS path.

It is the third of the three payload kinds:

| Example | Payload | Runs by |
|---|---|---|
| [`../gui-hello/`](../gui-hello/) | a compiled Linux ELF | running directly — no layer at all |
| [`../portable-hello/`](../portable-hello/) | source code | being compiled on the machine that installs it |
| **windows-hello** | a Windows PE | Wine or Proton |

## What the manifest says, and what it costs

```jsonc
"applicationType": "windows",
"architectures": ["x86_64"],                  // the ISA of the PE
"entrypoint": { "executable": "bin/windows-hello.exe" },
"execution": { "allowedChains": ["wine", "proton"] },   // REQUIRED
"launch": { "mode": "console" }
```

`allowedChains` is not optional here. Nothing runs a Windows executable
natively on Linux, so a `"windows"` package that permits no foreign-OS chain —
**including one that just leaves the default `["native"]` in place** — is
rejected by the manifest parser. Silence is not consent to run under a
compatibility layer, and a package that installs happily and can never start is
worse than one that is refused.

For the same reason it cannot be `missionCritical`: that mode requires a
Linux-native, host-ISA-native realization, and a Windows payload has none.

## Building and installing it

```sh
# Debian/Ubuntu: apt install gcc-mingw-w64-x86-64 wine64
make -C examples/windows/console-hello

lexe keygen /tmp/key.json
cp -r examples/windows/console-hello /tmp/windows-hello
lexe build /tmp/windows-hello -o /tmp/windows-hello.lexe --key /tmp/key.json

lexe verify /tmp/windows-hello.lexe    # payload-role: a runnable PE for a declared ISA
lexe info   /tmp/windows-hello.lexe    # Type: Windows application, run through a compatibility layer
lexe install /tmp/windows-hello.lexe --yes
lexe compat com.usha.windowshello      # which layer was chosen, and what is missing
lexe run com.usha.windowshello
```

On a host with neither Wine nor Proton, the install still succeeds and the
launch is refused with both permitted chains listed and a reason for each:

```text
$ lexe compat com.usha.windowshello
    Execution chain: none available
    Why:          no execution chain permitted by this package is available on this host
  Not available:
    wine    — Wine is not installed on this host
    proton  — Proton is not installed on this host
```

That is the whole point of reporting unavailable chains instead of hiding them:
the user can see what to install.

## What verification proves before any of that

`payload-role` (FORMAT-0.1 §6.7) reads the PE headers directly — it never runs
or loads the image — and requires the entrypoint to be:

* a real PE image (`MZ` … `PE\0\0`);
* marked as a runnable image, and **not** a DLL. A DLL carries the
  executable-image bit too, so both are checked;
* built for one of the declared architectures.

So the three ways a "Windows package" can be wrong are all caught before
install: a Linux binary wearing a `.exe` name, a library that nothing can
launch, and a binary for an architecture the package does not claim.

A 32-bit Windows program cannot be declared at all in 0.1: FORMAT-0.1 §5
recognises `x86_64` and `aarch64`, and has no id for i386. Such a payload is
refused by name rather than mis-reported against a list it could never match.

## What the program prints, and why

```text
Lexe Windows Hello
  this is a Windows PE running on Linux
  Windows API version:  10.0        <- reported by the Windows API, i.e. by the layer
  module path:          Z:\...      <- Wine's mapping of the Linux path
  LEXE_APP_ID:          com.usha.windowshello
  LEXE_APP_DATA:        /run/lexe/data
selftest: PASS                      <- it wrote into its private data root and read it back
```

The environment crosses the Wine boundary intact, and the private data root is
writable *from inside a Windows process*. That is the sandbox working, not a
claim that it works.

## Where Wine's own state goes

Into the application's private data root — `$LEXE_APP_DATA/.wine` — so it
persists across launches like any other application data, and is removed with
the application. Nothing of the host session is visible: no D-Bus, no home
directory, no Wayland socket, and no network.

The sandbox does provide one thing a native Linux payload does not need: a
**private, empty `/run/user/<uid>`**. Wine computes that path from its own uid
and ignores `XDG_RUNTIME_DIR`, and without it, it aborts during prefix setup.
The directory the sandbox provides is a fresh tmpfs containing nothing of the
user's session — it is not the host's runtime directory, which is never bound.

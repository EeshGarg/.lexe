# Example: gui-hello

A **real GTK 3 desktop application that runs under the .LEXE sandbox**. This is
the acceptance payload for the Definitive Architecture's GUI launch path: it is
the example used by [`tests/acceptance/`](../../tests/acceptance/) to prove the
install-and-launch criteria end to end.

It is deliberately different from [`../gtk-app/`](../gtk-app/), which exists to
*show the Tux32 Core 1 boundary* and is not meant to run sandboxed. `gui-hello`
is meant to run.

## What it demonstrates

| The window shows | Which proves |
|---|---|
| its own name and a live clock | the process is really running and rendering |
| `LEXE_APP_ID` | .LEXE launched it — the desktop did not exec a raw ELF |
| `LEXE_APP_DATA` | the private per-application data root was provided |
| **a button that writes a file there and reads it back** | the private-data sandbox is real and writable *from inside the app* |
| process id `2` | it is inside a private PID namespace |
| (no window needed) every start appends to `$LEXE_APP_DATA/gui-hello-launches.log` | a launch really reached the payload, provable on a headless host |

It also demonstrates the manifest side of the contract:

```jsonc
"role": "application",                 // an installable app, not a run.lexe
"execution": { "allowedChains": ["native"] },   // no compatibility layer
"launch":    { "mode": "gui", "singleInstance": true }
```

`launch.mode: "gui"` is what grants the sandbox the session display socket
(bound to `/run/lexe/session/<name>` with `XDG_RUNTIME_DIR=/run/lexe/session`),
the X11 socket, `/etc/fonts`, `/var/cache/fontconfig`, `/etc/machine-id` and
`/dev/dri`. **A console or service application declares a different mode and
gets no display at all.** D-Bus, `$HOME` and the network are not forwarded in
any mode.

## `--selftest`

```sh
./payload/bin/gui-hello --selftest     # exits 0, opens no window
```

`--selftest` reports the launch environment, writes and reads back the probe
file in `$LEXE_APP_DATA`, and exits — without initialising GTK. That makes the
same binary usable as a **headless** acceptance payload, so CI needs no display:

```sh
lexe run com.usha.guihello -- --selftest
```

When `LEXE_APP_DATA` is unset (a bare host run, no sandbox) the data check is
skipped rather than failed — that case is "not launched by .LEXE", not a bug.

Both modes append one line to `$LEXE_APP_DATA/gui-hello-launches.log` *before*
GTK is initialised. `tests/acceptance/02_persistence.sh` uses that to assert
"`run.lexe` still launches" without needing a display or a window manager.

## Build, package, install, run

```sh
make -C examples/native/gui-hello                       # -> payload/bin/gui-hello
lexe keygen /tmp/key.json
lexe build examples/native/gui-hello -o /tmp/gui-hello.lexe --key /tmp/key.json
lexe verify /tmp/gui-hello.lexe --json           # payload-role stage must pass
lexe install /tmp/gui-hello.lexe --yes --trust
lexe run com.usha.guihello -- --selftest         # headless: exits 0
lexe run com.usha.guihello                       # opens the window
```

Requires the GTK 3 development package (`gtk3-devel` on Fedora,
`libgtk-3-dev` on Debian/Ubuntu).

Installing also produces the artifacts the architecture requires, all of which
the acceptance harness asserts:

```
<LEXE_HOME>/apps/com.usha.guihello/versions/1.0.0/bin/gui-hello   the payload, private
<LEXE_HOME>/applications/lexe-com.usha.guihello.desktop           Exec=lexe run com.usha.guihello
<LEXE_HOME>/icons/hicolor/{64x64,128x128,256x256,scalable}/apps/  from icons/
<LEXE_HOME>/launch/com.usha.guihello.lexe                         the run.lexe launch reference
<LEXE_HOME>/integration.json                                      every artifact .LEXE owns
```

Note the `.desktop` `Exec` line: it is `lexe run com.usha.guihello`, never a
path to the ELF. The raw executable is never the user-facing launch object.

## Icons

`icons/scalable.svg` is the source; `icons/64.png`, `128.png` and `256.png` are
rendered from it. The packager picks up exactly those four names and the
installer maps them into the hicolor theme as `lexe-<app-id>`.

To regenerate the PNGs after editing the SVG:

```sh
for s in 64 128 256; do
  magick -background none -density 384 icons/scalable.svg -resize ${s}x${s} icons/${s}.png
done
```

## Tux32 Core 1

Like any GTK application built against a current host toolchain, `gui-hello`
imports newer glibc symbols, so `lexe sdk verify` reports it non-conformant on
the symbol axis; build it in the Core 1 sysroot
([../../sdk/tux32-core-1/](../../sdk/tux32-core-1/)) for a Core Portable result.
GTK also `dlopen`s its graphics stack, so those dependencies do not appear in
static ELF metadata — a documented Core 1 limitation. Neither affects the
sandboxed launch path this example exists to prove.

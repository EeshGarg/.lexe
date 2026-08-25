# Lexe — Linux packaging

Per-user installer that puts the Lexe runtime on your machine and wires up the
desktop so **double-clicking a `.lexe` file opens the graphical installer**.
Everything installs under `$HOME` (XDG paths) — no root required.

## Files

| File | Purpose |
|---|---|
| `install.sh` | Installs the binaries, desktop entries and MIME definition, refreshes the databases, and registers the default `.lexe` handler. |
| `uninstall.sh` | Reverses `install.sh`. |
| `lexe-installer.desktop` | Handler entry for `.lexe` files. `Exec=lexe-installer %f`, `NoDisplay=true` (it is a file handler, not a menu launcher). |
| `lexe-builder.desktop` | Menu entry for the package builder (`lexe-builder`). Shows under Development / Utility. |
| `application-x-lexe.xml` | freedesktop shared-mime-info definition for `application/x-lexe` (glob `*.lexe`, sub-class of `application/zip`). |

## Install

First build the runtime (GUI enabled so `lexe-installer` is produced):

```sh
cmake -S . -B build -G Ninja -DLEXE_BUILD_GUI=ON
cmake --build build
```

Then run the installer, optionally pointing it at a non-default build dir:

```sh
./packaging/install.sh          # one line: uses ./build
./packaging/install.sh out/rel  # uses ./out/rel
```

**Inspect first (recommended).** The installer is a short, per-user shell
script that touches only `$HOME`. Read it before running — nothing here ever
pipes a remote script straight into a shell:

```sh
less packaging/install.sh       # review exactly what it does
./packaging/install.sh          # then run it
```

One-line uninstall: `./packaging/uninstall.sh`.

This installs:

* `lexe`, `lexe-installer`, `lexe-builder` → `~/.local/bin`
* `lexe-installer.desktop`, `lexe-builder.desktop` → `~/.local/share/applications`
* `application-x-lexe.xml` → `~/.local/share/mime/packages`

and then runs `update-mime-database`, `update-desktop-database`, and
`xdg-mime default lexe-installer.desktop application/x-lexe` (each best-effort).

If `~/.local/bin` is not on your `PATH`, the script prints a warning telling you
to add it. The script is idempotent — re-running it just refreshes everything.

## Uninstall

```sh
./packaging/uninstall.sh
```

Removes the three binaries, both `.desktop` files and the MIME XML, clears the
default-handler association, and refreshes the databases. Installed application
data under `~/.local/share/lexe` is intentionally left in place. It reports what
it actually removed — on a machine where the runtime was never installed it says
so rather than announcing a removal that did not happen. If `LEXE_HOME` is set it
also clears the confined copy described below, so nothing `lexe integrate` wrote
survives an uninstall that claims to have removed it.

## `LEXE_HOME` and desktop registration

A desktop environment reads `.desktop` entries and MIME packages from
`$XDG_DATA_HOME` (default `~/.local/share`) and nowhere else. `install.sh` always
writes there, whatever `LEXE_HOME` says.

`lexe integrate` is different, and deliberately so: when `LEXE_HOME` is set it
confines its writes to `$LEXE_HOME/applications` and `$LEXE_HOME/mime/packages`,
because `LEXE_HOME` is exactly how the test suite and the demos keep out of your
real profile, and nothing in the environment tells a test run apart from an
install under a custom `LEXE_HOME`. The files are still written, and they are
still correct — no desktop just ever looks at them. The command says so instead
of reporting a registration (`IntegrationResult::note` in
`src/core/desktop.hpp`).

So if you keep a custom `LEXE_HOME` and want the double-click association, run
either of these — the two files contain no `LEXE_HOME`-dependent paths, so a
registration made without it is correct for your custom install too:

```sh
./packaging/install.sh          # writes to $XDG_DATA_HOME regardless
env -u LEXE_HOME lexe integrate # same two files, same two destinations
```

## How the double-click association works

1. `application-x-lexe.xml` teaches the desktop's MIME system that files
   matching `*.lexe` are `application/x-lexe` (a specialised ZIP). After
   `update-mime-database`, the file manager recognises the type.
2. `lexe-installer.desktop` declares `MimeType=application/x-lexe;`, so it is a
   registered handler for that type. Its `Exec=lexe-installer %f` passes the
   double-clicked file to the GUI installer.
3. `xdg-mime default lexe-installer.desktop application/x-lexe` makes it the
   *default* handler, so a double-click opens it directly rather than prompting
   for an application.

This matches the runtime's own registration (`lexe integrate`, implemented in
`src/core/desktop.cpp`): same MIME type `application/x-lexe`, same
`Exec=lexe-installer %f` convention. The explicit files here make the packaging
self-describing and add the builder's menu entry, which `lexe integrate` does
not create.

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
data under `~/.local/share/lexe` is intentionally left in place.

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

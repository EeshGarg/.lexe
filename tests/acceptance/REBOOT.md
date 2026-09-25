# Manual acceptance: the reboot boundary and the double-click path

`run_all.sh` automates everything that can be automated. Three things cannot be,
because they are properties of *this machine's desktop session*, not of the
runtime:

1. **A real double-click** — the file manager, the MIME database and the
   `.desktop` handler resolving together.
2. **A real reboot** — every cache, socket and session-scoped association gone.
3. **A real desktop-session change** — logging out and back in, or switching
   between Plasma Wayland and Plasma X11 (or to GNOME).

Work through this file top to bottom and write the result in the box at the end.
Every step says what *passing* looks like, so a failure is unambiguous.

> **This one test uses your REAL profile.** Unlike the automated scripts, the
> point here is durability across a reboot, so `LEXE_HOME` must NOT be set.
> Everything installed here is removed again in the teardown section.

---

## 0. Prerequisites

```sh
cd <repo>
cmake --build build -j"$(nproc)"
ls build/lexe build/lexe-ui          # both must exist; lexe-ui is the .lexe handler
```

Both binaries must be on `PATH` under exactly those names, because the desktop
entries .LEXE writes are `Exec=lexe run <id>` and `Exec=lexe-ui --open %f`:

```sh
mkdir -p ~/.local/bin
ln -sf "$PWD/build/lexe"    ~/.local/bin/lexe
ln -sf "$PWD/build/lexe-ui" ~/.local/bin/lexe-ui
command -v lexe lexe-ui              # both must resolve
```

`~/.local/bin` must be on the `PATH` of your **graphical session**, not only of
your terminal — a file manager launched at login does not read your shell rc.
On Fedora/KDE, `~/.config/plasma-workspace/env/*.sh` or `~/.profile` is the
right place, and it only takes effect after step 4's logout.

Record the starting state so the teardown is exact:

```sh
ls ~/.local/share/applications/lexe-*.desktop 2>/dev/null
ls ~/.local/share/lexe/launch/ 2>/dev/null
```

## 1. Build and package the GUI test application

```sh
make -C examples/gui-hello
lexe keygen /tmp/lexe-manual-key.json
lexe build examples/gui-hello -o ~/Desktop/App.lexe --key /tmp/lexe-manual-key.json
git checkout -- examples/gui-hello/lexe.json   # `build` fills in publisher.publicKey
```

**Pass:** `~/Desktop/App.lexe` exists and `lexe verify ~/Desktop/App.lexe`
reports every stage OK, including `payload-role`.

## 2. Double-click `App.lexe` → the .LEXE installer opens

Register the handler once so the desktop knows who owns `.lexe`:

```sh
lexe integrate
update-desktop-database ~/.local/share/applications
update-mime-database    ~/.local/share/mime
```

Then, **in the file manager (Dolphin/Nautilus — not from a terminal)**,
double-click `~/Desktop/App.lexe`.

| Check | Pass looks like |
|---|---|
| 2.1 | A .LEXE window opens. No "how do you want to open this file?" chooser, no text editor, no archive manager. |
| 2.2 | It shows the package identity: name *Lexe GUI Hello*, version 1.0.0, id `com.usha.guihello`, and the publisher key fingerprint. |
| 2.3 | It shows the verification result — hashes and signature valid — **before** offering to install. |
| 2.4 | It shows the package role (*application*), the entrypoint type (a native ELF) and the declared ISA (`x86_64`). |
| 2.5 | Install it. It completes without dropping you into a terminal. |

If 2.1 fails, the cause is almost always `lexe-ui` not being on the graphical
session's `PATH` (`TryExec=lexe-ui` in `~/.local/share/applications/lexe-handler.desktop`)
— re-check step 0, then `update-desktop-database` again.

## 3. Double-click `run.lexe` → the GUI launches through .LEXE

```sh
ls -l ~/.local/share/lexe/launch/com.usha.guihello.lexe
cp    ~/.local/share/lexe/launch/com.usha.guihello.lexe ~/Desktop/run.lexe
```

Double-click `~/Desktop/run.lexe` **in the file manager**.

| Check | Pass looks like |
|---|---|
| 3.1 | The *Lexe GUI Hello* window opens. |
| 3.2 | No terminal window appears at any point. |
| 3.3 | No dialog asks you to choose a program, confirm an executable, or "run anyway". |
| 3.4 | The window shows `LEXE_APP_ID = com.usha.guihello` — proof that .LEXE launched it, not the desktop running the ELF. |
| 3.5 | The window shows `LEXE_APP_DATA = /run/lexe/data`, and `process id` is a small number (a private PID namespace). |
| 3.6 | Click **Write a file into my private data directory**. The label turns green and names the file. |
| 3.7 | In a terminal: `ls ~/.local/share/lexe/data/com.usha.guihello/` shows `gui-hello-probe.txt`. |
| 3.8 | `pstree -p $(pgrep -f 'apps/com.usha.guihello')` shows `lexe → bwrap → gui-hello` and **no** FEX / Box64 / QEMU / Wine / Proton process. |

Also confirm the application-menu entry works (the same criterion by a different
route): search for *Lexe GUI Hello* in the application launcher and start it.
Its icon must be the gui-hello icon, not a generic placeholder.

Close both windows before continuing.

## 4. Reboot

```sh
sudo reboot
```

A real reboot — not a logout, not `systemctl restart`. After logging back in,
**without running any `lexe` command first**, double-click the *same*
`~/Desktop/run.lexe`.

| Check | Pass looks like |
|---|---|
| 4.1 | The window opens **identically** to step 3 — same title, same fields, same icon. |
| 4.2 | No chooser dialog, no terminal, no "unknown file type". |
| 4.3 | The application-menu entry is still present and still works. |
| 4.4 | `lexe doctor` reports *Desktop integration is healthy* and **0 problems**. |

If 4.1–4.3 pass but 4.4 reports problems, that is still a failure: the
integration survived by luck, not by design. Record exactly which artifact
`doctor` names.

If 4.1 fails, capture the evidence before repairing anything:

```sh
lexe doctor --json > /tmp/lexe-postreboot.json
cat ~/.config/mimeapps.list
ls -l ~/.local/share/applications/lexe-*.desktop
ls -l ~/.local/share/lexe/launch/
```

then `lexe doctor --repair` and re-test. Whether repair fixes it is a *separate*
result from whether it survived unaided — record both.

## 5. Change the desktop session

Log out. At the login screen pick a **different session** than the one you have
been using (Plasma X11 if you were on Plasma Wayland, or vice versa; GNOME also
counts). Log in and double-click `~/Desktop/run.lexe` again.

| Check | Pass looks like |
|---|---|
| 5.1 | The window opens; launch is still under .LEXE control. |
| 5.2 | On an X11 session the window still opens (the sandbox binds `/tmp/.X11-unix/X<n>` as well as the Wayland socket). |
| 5.3 | `lexe doctor` still reports 0 problems. |

Log back into your normal session before the teardown.

## 6. Forced failure → .LEXE Error

```sh
V=~/.local/share/lexe/apps/com.usha.guihello/versions/1.0.0/bin/gui-hello
cp "$V" /tmp/gui-hello.orig
chmod u+w "$V" && printf 'TAMPER' >> "$V"
```

Double-click `~/Desktop/run.lexe`.

| Check | Pass looks like |
|---|---|
| 6.1 | A **.LEXE Error** view appears. The application does **not** start. |
| 6.2 | It is a structured diagnostic: the stage (*verification*), the execution chain (*native*), the host OS/ISA, the runtime version and a timestamp — not a bare error string. |
| 6.3 | It offers a retry, and a way to change compatibility settings. |
| 6.4 | `lexe errors com.usha.guihello --latest --json` shows the same record; `lexe errors com.usha.guihello --path` opens onto it. |

Restore and confirm recovery:

```sh
cp /tmp/gui-hello.orig "$V" && chmod u+x "$V"
```

Double-click `run.lexe` again — the window must open normally (6.5).

## 7. Teardown

```sh
lexe remove com.usha.guihello --purge-data --yes
rm -f ~/Desktop/App.lexe ~/Desktop/run.lexe /tmp/lexe-manual-key.json /tmp/gui-hello.orig
lexe doctor                      # should report no orphaned registrations
```

Remove the `PATH` symlinks from step 0 if you do not want them permanently:

```sh
rm -f ~/.local/bin/lexe ~/.local/bin/lexe-ui
```

---

## Result sheet

Copy this into the ticket/commit message and fill it in.

```
host            : Fedora __  kernel ______  session ____________ (wayland/x11)
runtime         : lexe ______            commit ________
date            : ____-__-__

2. double-click App.lexe -> installer      2.1 [ ] 2.2 [ ] 2.3 [ ] 2.4 [ ] 2.5 [ ]
3. double-click run.lexe -> GUI            3.1 [ ] 3.2 [ ] 3.3 [ ] 3.4 [ ] 3.5 [ ]
                                           3.6 [ ] 3.7 [ ] 3.8 [ ]
4. after a real reboot                     4.1 [ ] 4.2 [ ] 4.3 [ ] 4.4 [ ]
5. after a session change (to ________)    5.1 [ ] 5.2 [ ] 5.3 [ ]
6. forced failure -> .LEXE Error           6.1 [ ] 6.2 [ ] 6.3 [ ] 6.4 [ ] 6.5 [ ]

automated suite (tests/acceptance/run_all.sh):  ____ passed / ____ failed

notes / failures (artifact named by `lexe doctor`, exact dialog text, …):
  ______________________________________________________________________
  ______________________________________________________________________
```

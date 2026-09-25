# Verification — what was actually tested, and how to redo it

Every claim below was produced on this machine (Fedora 44, KDE Plasma Wayland,
x86_64, 24 cores). Commands are copy-pasteable. Nothing here needs root.

---

## 1. Build and unit tests

```sh
cd "/home/bennyt7/Desktop/lexe dev"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLEXE_BUILD_GUI=ON
cmake --build build -j"$(nproc)"
./build/lexe_tests
```

**Result:** `517 test cases, 517 passed, 0 failed` · `6922 assertions, 0 failed`.
Zero compiler warnings under `-Wall -Wextra`.

Suites worth running individually:

```sh
./build/lexe_tests -ts=payload-role              # the alpha packaging bug
./build/lexe_tests -ts=execution-architecture    # roles, resolvers, overrides
./build/lexe_tests -ts=integration-durability    # icon/launch-ref repair
./build/lexe_tests -ts=ui                        # lexe-ui view model
./build/lexe_tests -ts=presentation              # truthful wording + signer classes
```

---

## 2. Acceptance harness

```sh
bash tests/acceptance/run_all.sh
```

**Result:** all 4 suites pass.

| Suite | Covers |
|---|---|
| `01_install_and_launch` | verify (incl. `payload-role`), install, payload stays private, `Exec=lexe run <id>`, `run.lexe` verifies as role `launch`, `integration.json` contents |
| `02_persistence` | delete the handler / association / launch reference, assert `doctor` NAMES each, repair, assert restored and still launching |
| `03_failure_diagnostics` | forced failure produces a structured record with the expected JSON fields; a tampered entrypoint is refused |
| `04_native_steady_state` | the real process tree has no compatibility process |

Everything runs against a throwaway `LEXE_HOME` under `mktemp -d`; the real
`~/.local/share/lexe` is never touched.

**Headless proof:** `tests/acceptance/lib.sh` unsets `WAYLAND_DISPLAY` and
`DISPLAY` for the whole harness before any test runs. The suites pass with the
display severed — which is the evidence they never needed one.

---

## 3. Real Fedora desktop tooling

The runtime's own bookkeeping is not proof; these are third-party checks.

```sh
printf 'PK\x03\x04' > /tmp/Check.lexe
xdg-mime query filetype /tmp/Check.lexe          # -> application/vnd.usha.lexe
xdg-mime query default application/vnd.usha.lexe # -> lexe-handler.desktop
xdg-mime query default application/x-lexe        # -> lexe-handler.desktop (alias)

desktop-file-validate ~/.local/share/applications/lexe-handler.desktop
desktop-file-validate ~/.local/share/applications/lexe-com.usha.guihello.desktop
```

**Result:** the canonical type resolves, the legacy alias resolves to the same
handler, and both entries validate.

---

## 4. The alpha's actual failure, reproduced and fixed on real state

Before this session the user's machine had:
* **no** `.lexe` handler entry,
* **no** persistent default association (the exact reboot-persistence gap),
* an alpha-era app (`com.usha.us`) with **no recorded integration**.

```sh
lexe doctor          # named all three problems, exit 1
lexe doctor --repair # re-established 4 registrations
lexe doctor          # healthy, exit 0
lexe verify ~/.local/share/lexe/launch/com.usha.us.lexe
```

**Result:** the alpha-era application was migrated — it now has a verified
`run.lexe` launch reference it never had, generated purely from installed state
with no original package present.

---

## 5. Simulated reboot damage (scratch home)

```sh
export LEXE_HOME=/tmp/lexe-scratch
# ... build, install an app ...
rm "$LEXE_HOME/applications/lexe-handler.desktop" \
   "$LEXE_HOME/config-home/mimeapps.list" \
   "$LEXE_HOME/launch/<id>.lexe"
rm -rf "$LEXE_HOME/mime"

lexe doctor           # names all four artifacts individually, exit 1
lexe doctor --repair
lexe doctor           # healthy
lexe open "$LEXE_HOME/launch/<id>.lexe" --no-terminal   # launches again
```

**Result:** every destroyed artifact was named, repaired, and the
`run.lexe → lexe → app` chain worked again.

---

## 6. The GUI payload really renders under the sandbox

Verified by a subagent three independent ways (evidence screenshot at
`scratchpad/EVIDENCE-gui-hello-window.png`, outside the repo):

1. **KWin reported it as a managed window** — enumerated via a KWin script over
   `org.kde.KWin /Scripting`: `class=gui-hello name=gui-hello pid=123999`,
   where that pid was the `gui-hello` process under `bwrap`.
2. **Screenshot** showing `LEXE_APP_ID = com.usha.guihello`,
   `LEXE_APP_DATA = /run/lexe/data`, `process id 2`, live clock.
3. **The bwrap argv** does exactly what the header claims:
   `--bind /run/user/1000/wayland-0 /run/lexe/session/wayland-0`,
   `--setenv XDG_RUNTIME_DIR /run/lexe/session`, `--bind /tmp/.X11-unix/X0`,
   `--ro-bind-try /etc/fonts`, `--dev-bind-try /dev/dri`, `--unshare-net`,
   **no D-Bus, no $HOME**.

Headless equivalent, safe to run any time:

```sh
env -u WAYLAND_DISPLAY -u DISPLAY lexe run com.usha.guihello -- --selftest
```

**Result:** `pid: 2` (PID namespace), `HOME=/run/lexe/data` (real home hidden),
`LEXE_APP_DATA=/run/lexe/data` with a successful write-and-read-back,
`selftest: PASS`.

---

## 7. Mission-critical policy

```sh
# A contradiction is refused at build time:
lexe pack ... --manifest <missionCritical:true, allowedChains:[native,proton]>
# -> manifest: execution.missionCritical forbids compatibility chains ...

lexe compat com.usha.mission             # strict native, no alternatives offered
lexe compat com.usha.mission --set proton
# -> this application's execution policy does not permit the "proton" chain
#    — it is mission-critical, so only strict native execution is allowed.
```

---

## 8. Tamper detection and structured diagnostics

```sh
python3 -c "p='<installed entrypoint>'; b=bytearray(open(p,'rb').read()); b[0x400]^=0xFF; open(p,'wb').write(b)"
lexe run <id>          # refused, exit 1, diagnostic path printed
lexe errors <id> --latest
lexe repair <id>       # recovers
lexe run <id>          # works again
```

**Result:** the record carried application, version, stage `verification`,
summary, detail, host OS (`Fedora Linux 44 (KDE Plasma Desktop Edition)`), host
ISA, runtime version, timestamp and its own path.

---

## What could NOT be verified here

* **A real reboot.** `tests/acceptance/REBOOT.md` is the manual checklist. The
  GUI example is installed on the real system so it can be run.
* **A real double-click** in Dolphin — same checklist.
* **Sanitizers / valgrind.** `libasan`, `libubsan` and `valgrind` are not
  installed and `sudo` requires a password. `gdb` is available.
* **Cross-ISA execution.** No ARM64 hardware; FEX/Box64 chain selection is
  unit-tested with synthetic provider sets only.
* **Every `lexe-ui` control clicked.** Rendering and the `--open`/`--app` entry
  points were verified against a real install, and the handlers for
  Compatibility→Apply, the three Uninstall modes and the Error History buttons
  were reviewed for wiring and bounds safety — but "does the pixel respond"
  needs the manual pass, since the headless rule forbids test windows.

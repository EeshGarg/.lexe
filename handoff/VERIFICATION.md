# Verification — what was actually tested, and how to redo it

> **Read [MACHINE.md](MACHINE.md) first.** Sections 1–8 below were produced on
> **Fedora 44 / KDE Plasma Wayland**, which is no longer the development
> machine. Sections 1 and 2 reproduce on the current machine (with the build
> commands from MACHINE.md, and with the counts updated in §10). Sections 3–8
> involved a real desktop session and **cannot** be reproduced under WSL.
> Sections 9, 10 and 11 are what was verified on the current machine.

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
| `05_portable_compile` | *(added later — see §9)* a source-only package: refused without approval, compiled under the sandbox with approval, recorded, run, tampered with, refused, rebuilt |
| `06_foreign_os` | *(added later — see §10)* a Windows payload: verified as a runnable PE, the three ways it can be wrong refused, installed, resolved to Wine, and really run |

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

## 9. Portable code and host-ISA compilation (2026-09-25, WSL2 Ubuntu 24.04)

Build and test commands are in [MACHINE.md](MACHINE.md).

**Result:** `592 test cases, 592 passed, 0 failed` · `7551 assertions, 0 failed`.
Zero compiler warnings under `-Wall -Wextra`. All **5** acceptance suites pass,
including the new `05_portable_compile` (47 checks, 0 skipped).

Suites worth running individually:

```sh
./lexe_tests -ts=hostbuild        # the four properties of host-ISA compilation
./lexe_tests -ts=payload_role     # native AND portable, both directions
./lexe_tests -ts=desktop          # one implementation of registration
```

Unlike the Fedora box, this machine has a working unprivileged `bubblewrap`, so
nothing in the isolation or portable suites is skipped for want of a sandbox.

### What was proved by hand, end to end

Against a scratch `LEXE_HOME`, with the display severed
(`env -u WAYLAND_DISPLAY -u DISPLAY`):

| Step | Result |
|---|---|
| `lexe pack` a source-only project | 1.6 KB package, no entrypoint binary in it |
| `lexe verify` | `payload-role` reports *"the package carries source under `src` and no prebuilt entrypoint"* |
| `lexe info` | `Type: Portable source, compiled on this machine — x86_64` |
| `lexe install` (no approval) | refused, **exit 5**, with a §9 record at stage `compile`; nothing installed |
| `lexe install --approve-compile` with `LEXE_BWRAP` pointed at nothing | refused: *"refusing to build unconfined"*; nothing installed |
| `lexe install --approve-compile` | announced the compile, built under `bwrap`, installed |
| `meta/1.0.0/build.json` | schema, build system, host ISA, the approval (granted / authority `user` / who / when), the toolchain paths actually used, and the product SHA-256 — which matches `sha256sum` of the installed entrypoint |
| `lexe run` | ran natively, args forwarded, `installation.json` records `lastExecution.chain = native` |
| flip one byte of the COMPILED entrypoint, `lexe run` | refused: integrity check failed, pointing at `lexe repair --approve-compile` |
| `lexe repair` (no approval) | refused, **exit 5**: *"repairing … means compiling its source again"* |
| `lexe repair --approve-compile` | rebuilt `payload/bin/app`; the application runs again |
| move `build.json` away, `lexe run` | refused — fails closed rather than treating an unverifiable compiled binary as unchecked |

`unzip` independently confirms the archive carries `payload/src/main.c` and does
**not** carry `payload/bin/portable-hello`; `file(1)` independently confirms the
installed entrypoint is an ELF executable; and the example program reports the
ISA from its own compiler's predefined macros, so the evidence that the compile
happened here does not come from the runtime's own bookkeeping.

### What could NOT be verified here

Everything in the list at the end of this file still stands, plus:

* **A second ISA.** Every build was x86_64. The portable type's central claim —
  the same `.lexe` compiles on ARM64 — remains designed-but-unproven, exactly
  like the FEX/Box64 chain selection in §"What could NOT be verified".
* **The real desktop integration checks of §3.** `xdg-mime` and
  `desktop-file-validate` have nothing to talk to under WSL.
---

---

## 10. Foreign-OS payloads (2026-09-25, WSL2 Ubuntu 24.04)

**Result:** `626 test cases, 626 passed, 0 failed` · `8493 assertions, 0 failed`.
All **6** acceptance suites pass, including the new `06_foreign_os` (29 checks,
0 skipped on a host with Wine and MinGW).

```sh
./lexe_tests -ts=pe                   # the PE reader, including hostile input
./lexe_tests -ts=payload_role         # native, portable AND windows
./lexe_tests -ts=isolation            # what a compatibility chain needs
./lexe_tests -ts=execution-architecture
```

This machine has `wine64`, `gcc-mingw-w64-x86-64` and `mingw-w64-x86-64-dev`
installed, so nothing here is skipped for want of a tool.

### The PE reader, against real Windows binaries

The synthetic images in `tests/pe_builder.hpp` prove the parser handles
malformed input. These prove it reads the real thing, and they come from the
Windows host this WSL instance runs on:

| File | Read as |
|---|---|
| `C:\Windows\System32\notepad.exe` | PE32+, x86-64, GUI, executable, not a DLL → `x86_64` |
| `C:\Windows\SysWOW64\notepad.exe` | PE32, i386, GUI, executable → **no `.lexe` architecture id**, correctly |
| `C:\Windows\System32\kernel32.dll` | PE32+, x86-64, **DLL** → not runnable |
| `/bin/ls` (an ELF) | not a PE |
| a Markdown file | not a PE |

### A Windows program really runs

```sh
x86_64-w64-mingw32-gcc -O2 -o payload/bin/app.exe src/main.c
lexe pack … && lexe verify … && lexe install … --yes
lexe run com.usha.windowshello -- --selftest one "two words"
```

| Step | Result |
|---|---|
| `verify` | `payload-role`: *"the declared entrypoint … is a runnable Windows executable for a declared architecture"* |
| `info` | `Type: Windows application, run through a compatibility layer — x86_64` |
| a package permitting only `["native"]` | refused at **pack** time, naming the missing policy |
| a Linux binary named `.exe` | refused: *"not a Windows PE image"* |
| a real `kernel32.dll` as the entrypoint | refused: *"is a Windows DLL … cannot be launched"* |
| `compat` | `Execution chain: wine`, with *"Proton is not installed on this host"* listed as unavailable |
| `run` | the PE executes; `LEXE_APP_ID` and `LEXE_APP_DATA` cross the Wine boundary; `arg: two words` stays one argument; `selftest: PASS` (it wrote into its private data root from inside a Windows process) |
| `installation.json` | `lastExecution.chain = wine`, `runtime.source = foreign-os` |
| Wine's prefix | `<LEXE_HOME>/data/com.usha.windowshello/.wine`, reused by a second launch |
| the app's data root | no `wayland-*`, no `bus`, no `pulse` — nothing of the host session |

### The two things that only running it revealed

Both were bisected against bubblewrap rather than reasoned about:

1. **A compatibility layer outside `/usr` is unreachable** in the sandbox. The
   layer's installation prefix is now bound read-only.
2. **Wine aborts without `/run/user/<uid>`** — it computes that path from its
   own uid and ignores `XDG_RUNTIME_DIR`. Every namespace control was ruled out
   one at a time; the filesystem view was the cause. Binding the HOST's runtime
   directory worked and was rejected: it would expose the user's Wayland
   socket, D-Bus and keyring. A **private, empty tmpfs** at that path works
   just as well and exposes nothing.

Reproduce the bisection with `bwrap` directly: with `--dev-bind / /` and every
namespace unshared, Wine runs; with the launcher's view plus a bind of the
host's `/run/user/<uid>`, it runs; with the launcher's view plus a `--tmpfs`
at the same path, it runs; without it, it aborts with `free(): invalid pointer`.

### What could NOT be verified here

* **Proton, and layered chains** (`proton+fex`). Only Wine was installed.
* **A GUI Windows application.** The proof is a console program.
* **32-bit Windows payloads**, which FORMAT-0.1 §5 cannot name at all.

---

## 11. Service mode, the frontends, and sanitizers (2026-09-25)

**Result:** `636 test cases, 636 passed, 0 failed` · `8549 assertions, 0 failed`.
All 6 acceptance suites pass. No compiler warnings.

### `launch.mode: "service"` detaches for real

```sh
lexe run com.usha.svc --no-terminal     # returns immediately
```

| Check | Result |
|---|---|
| the call returns | 0 seconds, with "started in the background (service)" |
| the payload keeps running | still ticking a heartbeat file 3s later, after `lexe run` had returned |
| the sandbox survived its starter | `bwrap` + the payload still in the process tree |
| the version stays leased | `fuser` on the lease shows **exactly one** holder: the supervisor |
| nothing leaks into the sandbox | the payload does NOT hold the lease fd (it did until the supervisor's `open` gained `O_CLOEXEC` — caught by this check) |
| no zombies | the launcher waits only for an intermediate that exits at once |
| `--wait` | runs the same service in the foreground, and says it is doing so |
| the record | `lastExecution.chain = native`, `launchMode = service`; no error record for a launch nothing waited for |

### Sanitizers

Possible here for the first time — the Fedora machine had no `libasan`.

```sh
cmake -S ~/lexe-src -B ~/lexe-build/asan -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLEXE_BUILD_GUI=OFF \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build ~/lexe-build/asan -j24
cd ~/lexe-build/asan && ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 \
  env -u WAYLAND_DISPLAY -u DISPLAY ./lexe_tests
```

**Result:** exit 0. Zero leaks, zero first-party undefined behaviour, 636/636.

It was not clean the first time: **3.4 MB leaked in 562 allocations**, from
`mz_zip_writer_finalize_heap_archive`, whose buffer miniz hands to the caller
(it clears `m_pMem`, so `mz_zip_writer_end` frees nothing). One production site
(`PackageWriter::write` — a leak per `pack`, which matters in `lexe-builder`,
which does not exit) and three test helpers. Fixed; see commit "package: free
the archive buffer miniz hands over".

The only UBSan reports remaining are signed left-shifts inside
`third_party/ed25519`, which is pinned, vendored and never modified — a known
property of that reference implementation, not a defect in this runtime.

### What could NOT be verified here

* **A systemd user unit.** WSL has no systemd user session, so the durable form
  of `service` cannot be built or tested on this machine at all.
* **The GUI compile-approval control being clicked.** Its view model is tested
  headlessly (`-ts=gui`); the tick box itself needs the manual pass, because
  the headless rule forbids test windows.

## What could NOT be verified here (the standing list)

Each §9 and §10 adds its own list above; these are the ones that outlive any
one session. Where a line was true on Fedora and is not true now, it says so.

* **A real reboot.** `tests/acceptance/REBOOT.md` is the manual checklist. On
  the Fedora machine the GUI example was installed so it could be run; the
  current machine has no Linux desktop session at all (see
  [MACHINE.md](MACHINE.md)).
* **A real double-click** in a file manager — same checklist, same obstacle.
* ~~**Sanitizers / valgrind.**~~ Installed on the current machine; still not
  wired into a routine run.
* **Cross-ISA execution.** No ARM64 hardware. FEX/Box64 chain selection is
  unit-tested with synthetic provider sets only, and no portable package has
  been compiled on a second ISA.
* **Every `lexe-ui` control clicked.** Rendering and the `--open`/`--app` entry
  points were verified against a real install, and the handlers for
  Compatibility→Apply, the three Uninstall modes and the Error History buttons
  were reviewed for wiring and bounds safety — but "does the pixel respond"
  needs the manual pass, since the headless rule forbids test windows.

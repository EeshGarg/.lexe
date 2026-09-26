# Testing .LEXE

Everything here is reproducible. If a capability is claimed anywhere in this
repository, the intent is that a command in this document demonstrates it.

```sh
./scripts/test.sh --all       # the executable definition of a releasable build
./scripts/test.sh --list      # what each lane covers, and what it needs
```

`--all` is not "run everything and hope". It reports four distinct outcomes, and
the difference between the last two is the whole point:

| | Meaning |
|---|---|
| **PASS** | the behaviour was demonstrated on this machine |
| **FAIL** | the behaviour was expected here and did not happen — a defect |
| **SKIP** | deliberately not applicable on this host, with the reason named |
| **BLOCKED** | needs hardware or an environment this host does not have |

A BLOCKED lane is never counted as success. `scripts/test.sh` exits non-zero on
any FAIL and zero on SKIP/BLOCKED, and prints every skip and block with its
reason so the gap stays visible instead of disappearing into a green tick.

---

## 1. Build

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j"$(nproc)"
```

GTK 3 is detected automatically; when `pkg-config` finds `gtk+-3.0` the two
graphical frontends (`lexe-ui`, `lexe-builder`) build alongside the CLI. Force
it with `-DLEXE_BUILD_GUI=ON` to turn a missing GTK into a configure error
rather than a silently CLI-only build.

**First-party code must build with zero warnings** under `-Wall -Wextra`.
Vendored code in `third_party/` is compiled with warnings silenced and exposed
as SYSTEM includes precisely so that stays true.

## 2. Test lanes

| Lane | What it is | Needs |
|---|---|---|
| `--unit` | the doctest binary: every subsystem, the view models of both GUIs, the architecture rules | nothing |
| `--acceptance` | `tests/acceptance/0*.sh` — end-to-end scripts against a throwaway `LEXE_HOME` | a built CLI |
| `--integration` | `tests/integration/*.sh` — trust and lifecycle across process boundaries | a built CLI |
| `--gui` | `scripts/gui-smoke.sh` — the frontends start, render and exit under a private display | GTK 3, Xvfb |
| `--lifecycle` | install → run → update → rollback → repair → uninstall, then the same with operations interrupted | bubblewrap |
| `--security` | hostile packages: traversal, symlink escape, tampered hashes, architecture lies, injection | nothing |
| `--windows` | a purpose-built Windows PE, run through Wine | Wine, MinGW |
| `--proton` | the same payload through the Proton chain | a Proton installation |
| `--sanitizers` | a separate ASan + UBSan build of the unit suite | clang or gcc sanitizer runtime |

Run one lane, several, or `--all`. `--list` prints the table above with each
lane's availability resolved on the current host.

## 3. The headless rule

**No automated test may put a window on the user's screen.** This is a hard
guard, not a convention. A window that steals focus mid-run is disruptive, and a
test whose result depends on a live desktop session is not reproducible on a
build machine.

`tests/acceptance/lib.sh` unsets `WAYLAND_DISPLAY` and `DISPLAY` for the whole
harness before any test runs, and pins `GDK_BACKEND=x11` so that a future change
which tried to open a window would find nothing to open it on and fail loudly
instead of appearing on screen.

Anything that genuinely must render brings **its own** display. It never borrows
the developer's.

### Rendering without touching the real desktop

Under WSLg this is less obvious than it looks, and the obvious approach does not
work:

```
$ mount | grep x11
none on /tmp/.X11-unix type tmpfs (ro,relatime)
$ ls /tmp/.X11-unix/
X0            <- WSLg's own display, and nothing else
```

WSLg mounts `/tmp/.X11-unix` **read-only** and puts the user's real display there
as `X0`. So `Xvfb :99` cannot create `/tmp/.X11-unix/X99`; it falls back to an
abstract socket, which a sandboxed process can never reach, because the sandbox
unshares the network namespace and abstract sockets do not cross one. Ubuntu's
Xorg 21.1 has no `-unixdir` to relocate the socket either. That left the
launcher with no display socket to bind for a GUI launch, and binding `X0` was
never an option: `X0` **is** the user's screen.

The mechanism that does work is `scripts/lib/private-display.sh`, and it is
safer than the thing it replaces rather than a workaround for it:

```sh
unshare --mount --map-root-user sh -c '
    mount -t tmpfs tmpfs /tmp/.X11-unix   # private to this namespace
    chmod 1777 /tmp/.X11-unix
    Xvfb :99 -screen 0 1024x768x24 -nolisten tcp & ...'
```

Inside that mount namespace `/tmp/.X11-unix` is a fresh writable tmpfs, so Xvfb
creates a **real filesystem socket** at `/tmp/.X11-unix/X99`. Children — the
launcher, and the `bwrap` sandbox it starts — inherit the namespace and can bind
that socket like any other path. The user's `X0` is not touched, not bound, and
not even visible in the namespace. Nothing reaches their desktop.

This is what lets `--gui` and `--lifecycle` prove a window actually **mapped**
rather than merely that a process started: `xwininfo`/`xlsclients` against the
private display are third-party witnesses, and they are running against a
display that only the test owns.

## 4. Environment

Developed and validated on **WSL2 Ubuntu 24.04** (x86_64, 24 cores). Packages
the lanes above need:

```sh
sudo apt-get install -y \
    cmake ninja-build pkg-config g++ \
    bubblewrap libsodium-dev libgtk-3-dev \
    file unzip ccache strace valgrind \
    xvfb x11-utils x11-apps xdotool xauth \
    desktop-file-utils xdg-utils shared-mime-info \
    wine mingw-w64 binutils-mingw-w64 \
    clang
```

What each group buys:

| Package group | Which lane stops being SKIP |
|---|---|
| `bubblewrap` | `--lifecycle`, and the isolation and portable-compile suites stop skipping for want of a sandbox |
| `libgtk-3-dev` | `--gui`, and the frontends build at all |
| `xvfb x11-utils xdotool` | `--gui` can prove a window mapped, not just that a process lived |
| `desktop-file-utils xdg-utils` | desktop integration gets third-party validation instead of the runtime's own bookkeeping |
| `wine mingw-w64` | `--windows`: a real PE, cross-compiled here, actually run |
| `clang` | `--sanitizers`, and the fuzz-ready parser harnesses |

`bubblewrap` works unprivileged under the WSL2 kernel, so the isolation and
portable-compile suites run for real here.

Building on `/mnt/c` works and is what this checkout does; a full build is about
80 seconds at `-j24`, most of it reading sources over the 9p filesystem.

## 5. Sanitizers

```sh
./scripts/test.sh --sanitizers
```

or by hand:

```sh
cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
cmake --build build-asan -j"$(nproc)"
env -u WAYLAND_DISPLAY -u DISPLAY ./build-asan/lexe_tests
```

Sanitizers are not decoration here: the first run of ASan over this tree found a
real leak in `lexe pack`. Vendored `third_party/ed25519` performs signed
left-shifts that UBSan reports; those are suppressed by name in
`tests/ubsan.supp` rather than tolerated in the output, so a *new* finding is
still visible.

## 6. What this machine cannot prove

Recorded here rather than left implied. `scripts/test.sh` reports each of these
as BLOCKED with the same reason, so the list cannot rot silently.

| Claim | Why it is not proven here | What would settle it |
|---|---|---|
| **The same portable `.lexe` compiles on ARM64** | every build so far has happened on x86_64 | real AArch64 hardware; see §7 |
| **Integration survives a reboot** | WSL has no session to reboot and no login sequence to re-run | a standalone Linux desktop; checklist in `tests/acceptance/REBOOT.md` |
| **Double-clicking a `.lexe` in a file manager opens it** | no file manager and no desktop session | same |
| **`service` mode under a real user session manager** | no systemd user session under WSL | a systemd-enabled Linux host |
| **ISA translation chains (FEX, Box64, qemu-user)** | none of those runtimes is installed, and x86_64-on-x86_64 would not exercise them anyway | a machine where the translation is real |

Emulation is explicitly **not** accepted as a substitute for the first of these.
`qemu-user` can exercise the *refusal* path — "this output targets a machine
that is not the builder's" — and that is worth having, but producing an AArch64
binary under emulation on an x86_64 host does not demonstrate the architecture's
central claim.

## 7. The decisive cross-ISA test

When ARM64 hardware is available, this is the test that settles the portable
type:

> Take the **exact same** signed portable-source `.lexe` to an x86_64 host and
> an AArch64 host. Install it on each. Verify that each machine independently
> produces a native ELF **for its own ISA**, with its own `build.json` recording
> its own toolchain and product hash. Execute both successfully.

Until then, `--all` reports it BLOCKED, and the documentation says
*designed, implemented and unit-tested — not demonstrated on hardware.*

## 8. Discipline

Two rules, both learned the hard way.

**A defect is not fixed until a test reproduces it.** The loop is: understand the
root cause, correct the implementation, write a test that fails against the old
behaviour, watch it pass against the new one, and confirm the broader suite is
still green. A fix without that fourth step is an assertion.

**Working once is not done.** The alpha installed and launched perfectly and
then did not survive a reboot. Persistence, repair and uninstall are part of
correctness, which is why `--lifecycle` interrupts operations on purpose and
`tests/acceptance/02_persistence.sh` destroys installed state and demands that
`lexe doctor` name each missing artifact before repairing it.

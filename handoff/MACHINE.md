# The machine this is developed on (read before you try to build)

**This changed.** The earlier handoff describes Fedora 44 / KDE Plasma Wayland
at `/home/bennyt7/Desktop/lexe dev`. That machine is gone. As of 2026-09-25 the
repository lives on **Windows 11**, and the runtime is built and tested inside
**WSL2 Ubuntu 24.04**.

| | |
|---|---|
| Repository (Windows) | `C:\Users\Bennyt 2\Desktop\projects\.lexe` |
| Same tree, from WSL | `/mnt/c/Users/Bennyt 2/Desktop/projects/.lexe` |
| Convenience symlink | `~/lexe-src` in WSL — **use this**: the real path contains a space, which breaks CMake variables, Make and half of everything else |
| Build directory | `~/lexe-build/cm` in WSL (ext4, not `/mnt/c` — much faster, and it keeps build output out of the Windows tree) |
| Cores / RAM | 24 / 15 GB visible to WSL |

## Build and test

```sh
wsl -d Ubuntu-24.04 -e bash -lc '
  cmake -S ~/lexe-src -B ~/lexe-build/cm -G Ninja \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLEXE_BUILD_GUI=ON &&
  cmake --build ~/lexe-build/cm -j24 &&
  cd ~/lexe-build/cm && env -u WAYLAND_DISPLAY -u DISPLAY ./lexe_tests'
```

```sh
wsl -d Ubuntu-24.04 -e bash -lc '
  cd ~/lexe-src && LEXE_BUILD_DIR=$HOME/lexe-build/cm bash tests/acceptance/run_all.sh'
```

`LEXE_BUILD_DIR` is needed because the build directory is outside the repo.

A full build is about **100 seconds** at `-j24`; most of that is reading sources
over the 9p filesystem, so an incremental build of one file is fast.

## What is installed in WSL, and how it got there

`wsl -u root` gives a root shell **with no password** — that is how WSL works,
and it is why the earlier handoff's "sudo needs a password, so nothing can be
installed" constraint does **not** apply here. Installed with
`apt-get install`: `cmake ninja-build pkg-config bubblewrap libsodium-dev
ccache strace valgrind xvfb libgtk-3-dev file unzip`.

So this machine can do things the Fedora box could not:

* `bubblewrap` works unprivileged under the WSL2 kernel — the isolation and
  portable-compile suites run for real, not skipped;
* GTK 3 development headers are present, so `lexe-ui`, `lexe-builder` and the
  `gui-hello` example all build;
* `valgrind`, `strace` and `xvfb` are available if you need them.

## The things that have NOT changed

* **No automated test may put a window on the user's screen.** They are using
  this computer. WSLg makes this *easier* to get wrong, not harder: a GUI
  process started in WSL renders on the real Windows desktop. Every test run
  above severs `WAYLAND_DISPLAY` and `DISPLAY`, and `tests/acceptance/lib.sh`
  does it for the whole harness. Anything that must render brings its own
  synthetic display (`xvfb-run`).
* **No git push credentials.** Commit locally and tell the user.

## What this machine still cannot do

* **Run the manual reboot checklist** (`tests/acceptance/REBOOT.md`). It needs a
  real Linux desktop session, a real file manager and a real reboot. WSL has no
  desktop session of its own, and the Windows host is not a `.LEXE` target.
* **Prove the cross-ISA claims.** Still x86_64 only. That includes the portable
  path: it is implemented and tested, but every build so far has happened on
  x86_64, so "the same `.lexe` compiles on ARM64" remains designed-but-unproven.
* **Test the real desktop integration.** `xdg-mime`, `desktop-file-validate`
  and an actual `~/.local/share/applications` that something scans do not exist
  here. `lexe doctor` and the integration suites work against a scratch
  `LEXE_HOME`, which is exactly what they were built to do — but the evidence in
  `VERIFICATION.md` §3 came from a real Fedora desktop and cannot be reproduced
  on this machine.

* **Run a SANDBOXED graphical application against a virtual X server.** This
  one is worth knowing before you try it, because it looks like it should work:

  ```
  $ mount | grep x11
  none on /tmp/.X11-unix type tmpfs (ro,relatime)
  $ ls /tmp/.X11-unix/
  X0            <- WSLg's own display, and nothing else
  ```

  WSLg mounts `/tmp/.X11-unix` **read-only** and puts its own `X0` there, so
  `Xvfb` on `:99` cannot create `/tmp/.X11-unix/X99`. It falls back to an
  abstract socket, which a sandboxed process cannot reach because the sandbox
  unshares the network namespace — abstract sockets do not cross it. So the
  launcher has no display socket to bind for a GUI launch.

  `X0` **is** the user's real desktop. Binding it would put the window on their
  screen, which the headless rule forbids outright. Do not be tempted.

  `scripts/gui-smoke.sh` is unaffected and passes: it runs the GTK frontends
  directly under `xvfb-run`, not inside the sandbox, so it never needs a bound
  socket.

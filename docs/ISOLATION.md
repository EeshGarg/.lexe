# Lexe Runtime Isolation (0.1)

How a `.lexe` application is contained when it runs. This document describes
**only behavior proven by tests** (`tests/test_isolation.cpp`,
`tests/test_isolation_linux.cpp`); anything not enforced is labeled as such.

Every launch path (`lexe run`, the desktop `.lexe` MIME handler which runs
`lexe run <id>`, and the installer's Launch action) funnels through the shared
launcher `run_app`, which — after resolving the trusted active version,
re-parsing the manifest, enforcing entrypoint containment, and re-hashing the
entrypoint (integrity) — constructs an isolation request and launches **through
the isolation backend**. The application is never executed by the launcher
directly on a platform that has a backend.

## Backend

* **Linux:** [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`),
  unprivileged. No root, no setuid helper, no daemon.
* **Other platforms (e.g. the Windows dev host):** no isolation backend; the
  capability is reported `policy-unsupported` and the app runs **without
  isolation** (this is a dev/test convenience, not a supported deployment
  target).

`bwrap` is a runtime dependency; on Debian/Ubuntu it is the `bubblewrap`
package.

## Kernel / distribution assumptions

Isolation requires working **unprivileged user namespaces** and, for network
denial, **network namespaces**. These are present on mainstream modern kernels.
Some environments disable unprivileged user namespaces (e.g. certain hardened
kernels, or Ubuntu's AppArmor `kernel.apparmor_restrict_unprivileged_userns`).
When they do not work, the backend reports `unavailable` and the launcher
**fails closed** (it does not run the app unconfined).

### WSL / WSLg

Verified working on WSL2 (Ubuntu 24.04, kernel 6.x): unprivileged user and
network namespaces function, and all the denials below were demonstrated.
WSLg (the Wayland/X bridge) is **not** forwarded into the sandbox in 0.1 — see
GUI below.

## Capability detection

Detection **runs a real probe** — "bwrap is installed" is never treated as proof
it works. On each launch the backend:

* checks the `bwrap` executable exists (overridable with `LEXE_BWRAP`);
* runs a minimal sandbox (user namespace + read-only bind + merged-usr symlinks
  + a dynamically-linked binary) — success ⇒ user namespaces and bind mounts
  work;
* runs the same with `--unshare-net` — success ⇒ network namespaces work.

Outcome is one of `available`, `partially-available` (no netns),
`unavailable`, `policy-unsupported`, `setup-failed`.

## Filesystem view

Inside the sandbox:

* A read-only system view: `/usr` bound read-only, with `/bin`, `/lib`,
  `/lib64`, `/sbin` as symlinks into it (merged-usr), plus a few read-only
  `/etc` files needed for dynamic linking and name resolution
  (`ld.so.cache`, `passwd`, `group`, `nsswitch.conf`, …; `resolv.conf`/`hosts`
  only when networking is permitted).
* The **installed application version**, bound at its real path **read-only** —
  the application cannot modify its own installation (proven: a write to the app
  root is denied).
* **No bind of the user's home directory** — a real host-home file is not
  readable (proven).
* **No bind of another application's data** — a second App ID's private data is
  not readable (proven).
* No installer trust records, transaction journals, staging directories, signing
  keys, or unrelated `apps/`/`data/` state are exposed.

## Writable roots

Private, per-application, installer-owned roots derived from the validated App
ID, mapped to fixed sandbox paths:

| Purpose | Sandbox path | Host location |
|---|---|---|
| Persistent data | `/run/lexe/data` (`$LEXE_APP_DATA`, also `$HOME`) | `<LEXE_HOME>/data/<id>` |
| Cache | `/run/lexe/cache` (`$LEXE_APP_CACHE`) | `<LEXE_HOME>/cache/apps/<id>` |
| Temp | `/tmp` (`$TMPDIR`) | a private tmpfs (ephemeral) |

All three are writable (proven); the app root is not. The working directory is
the private data root — **never the caller's cwd** (proven).

This pass introduces only the minimum data/cache root helpers needed for
isolation. The full uninstall data-retention workflow is a separate,
not-yet-implemented workstream.

## Environment policy

The environment is **cleared** and only an allowlist is set:

* `HOME` = the private data root
* `PATH` = `/usr/bin:/bin`
* `TMPDIR` = `/tmp`
* `LEXE_APP_ID`, `LEXE_APP_DATA`, `LEXE_APP_CACHE`

Everything else the caller had is dropped. In particular `LD_PRELOAD`,
`LD_LIBRARY_PATH`, `PYTHONPATH` (and other interpreter/loader injection
variables), secrets, proxy variables, and D-Bus/session variables are **not**
forwarded — proven for `LD_PRELOAD`, a secret, and `PYTHONPATH`.

## Network

* **`network` permission absent (default):** the network namespace is unshared —
  the sandbox has only an isolated loopback and **no route off it**. An outbound
  connection to a routable address fails with `ENETUNREACH` (proven). If network
  denial is required but network namespaces are unavailable, the launch **fails
  closed** rather than run unconfined.
* **`network` permission present:** the host network namespace is shared and the
  application reaches the host network (proven against a host listener).

There is **no silent fallback to unrestricted networking**.

## Privilege / process creation

* No shell is ever invoked; the application argv is passed as argv elements after
  `--`, so shell metacharacters in arguments are inert (proven: args containing
  spaces, `;`, `$…`, backticks, quotes are passed verbatim).
* setuid privilege escalation is prevented by the unprivileged user namespace.
* A private PID namespace, and unshared IPC/UTS/cgroup namespaces, are used;
  `--die-with-parent` and `--new-session` bound the process.
* No seccomp filter is applied in 0.1 (a real, maintained policy is future work;
  a fake or overly-permissive filter would be dishonest, so none is claimed).

## GUI forwarding

**Not implemented in 0.1.** No display, Wayland/X, or D-Bus socket is forwarded
into the sandbox, so a `.lexe` GUI application launched via `lexe run` runs
headless (isolation is terminal/headless only). The Lexe builder and installer
GTK apps are the runtime's own tools — they are not `.lexe` applications and are
not launched through this isolation path, so they are unaffected. GUI capability
is reported as **not forwarded**; the filesystem and network controls are never
weakened to make GUI launch work.

## Fail-closed behavior

The launcher refuses to run (never falling back to direct execution) when:

* the isolation backend is unavailable or broken (proven: `LEXE_BWRAP` pointed
  at a missing path ⇒ `IsolationError`, and the app does not run);
* network denial is required but cannot be established;
* a required baseline control (user namespace / bind mounts) cannot be
  established;
* the backend executable disappears between planning and launch;
* backend execution fails before the application starts.

## Enforcement matrix (0.1)

| Permission | State | Basis |
|---|---|---|
| (absent) network | **enforced** — denied | network namespace; `ENETUNREACH` proven |
| `network` | **enforced** — permitted | shared netns; host reach proven |
| `user-files-selected` | **advisory** | accepted and recorded, but **no runtime host-file grant mechanism** exists in 0.1; it does NOT grant home or any host path, and its absence still means no general home access |

Baseline controls, independent of requested permissions:

| Control | State |
|---|---|
| app root read-only | enforced (proven) |
| private data / cache / temp | enforced (proven) |
| home hidden | enforced (proven) |
| cross-application data hidden | enforced (proven) |
| environment sanitized | enforced (proven) |
| no shell / verbatim argv | enforced (proven) |
| no-setuid-escalation (user namespace) | enforced |
| private PID namespace | enforced |
| GUI forwarding | **not implemented** (headless only) |
| seccomp syscall filter | **not implemented** |

## Exact guarantees / non-guarantees

**Guaranteed (proven on Linux with a working backend):** an application cannot
modify its installed files, read the user's home, read another application's
data, inherit dangerous loader/interpreter environment variables, see the
caller's working directory, or use the network without the `network` permission;
and if the sandbox cannot be established, the app is not run.

**Not guaranteed:** any containment on a platform without a backend (reported as
unsupported); syscall-level restriction (no seccomp); GUI isolation (no GUI
forwarding at all in 0.1); `user-files-selected` enforcement (advisory); and
protection on kernels where unprivileged namespaces are disabled (there the
launch fails closed rather than running unconfined).

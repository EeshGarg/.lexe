# Lexe Runtime Isolation (0.1)

How a `.lexe` application is contained when it runs. This document describes
**only behavior proven by tests** (`tests/test_isolation.cpp`,
`tests/test_isolation_linux.cpp`, `tests/test_etc_surface.cpp`); anything not
enforced is labeled as such.

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
WSLg (the Wayland/X bridge) exposes an ordinary Wayland/X socket, so the display
rules below apply to it unchanged — but this has not been re-verified on WSL2
since display access was implemented.

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
  `/lib64`, `/sbin` as symlinks into it (merged-usr), plus an **allowlist** of
  read-only `/etc` entries — see [The `/etc` allowlist](#the-etc-allowlist)
  below for the complete list and for what its absence costs.
* The **installed application version**, bound at its real path **read-only** —
  the application cannot modify its own installation (proven: a write to the app
  root is denied).
* **No bind of the user's home directory** — a real host-home file is not
  readable (proven).
* **No bind of another application's data** — a second App ID's private data is
  not readable (proven).
* No installer trust records, transaction journals, staging directories, signing
  keys, or unrelated `apps/`/`data/` state are exposed.

## The `/etc` allowlist

`/etc` inside the sandbox is not the host's `/etc`. It is a fresh directory
holding only the entries below, each bound read-only from the host at its own
path, each optional (a host that lays one out differently skips it rather than
failing to launch). Everything else in `/etc` is **not there**.

The exact set is pinned by `tests/test_etc_surface.cpp`, which asserts it three
ways: against the rendered `bwrap` argv, against a fabricated sysroot, and —
the only one that proves anything about the operating system — against a probe
that calls `access()` from inside a real sandbox, for a console launch, a
network launch and a GUI launch. The list is exact in both directions: adding
an entry fails that test as loudly as removing one, because an addition to
`/etc` widens what the application learns about the host.

| Entry | When | Why |
|---|---|---|
| `/etc/ld.so.cache`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d` | always | dynamic linking |
| `/etc/passwd`, `/etc/group`, `/etc/nsswitch.conf` | always | name resolution (`getpwuid`, `getgrgid`) |
| `/etc/alternatives` | always | Debian alternatives symlinks, which `/usr` paths resolve through |
| `/etc/localtime` | always | local time |
| `/etc/resolv.conf`, `/etc/hosts` | `network` granted | DNS and static name resolution |
| `/etc/ssl/certs`, `/etc/ssl/openssl.cnf`, `/etc/pki/tls`, `/etc/pki/ca-trust`, `/etc/ca-certificates`, `/var/lib/ca-certificates` | `network` granted | the system TLS trust store — see below |
| `/etc/fonts`, `/etc/machine-id` | `launch.mode` is `gui` | font configuration (fontconfig keys its cache on the machine id) |

Note that `launch.mode` **defaults to `gui`** in FORMAT 0.1. A manifest that
declares no mode receives the GUI row, including `/etc/machine-id` — a stable
per-device identifier. A publisher who wants the smaller surface has to say
`"mode": "console"` (or `"service"`) explicitly; silence is not the narrow
choice here.

### TLS trust store

The allowlist above was originally chosen for dynamic linking and name
resolution, and the trust store was not on it. The measured consequence, on
Ubuntu 24.04, in a sandbox built from the argv this runtime renders for a
network-permitted console launch:

| Request | Result |
|---|---|
| `http://example.com/` | 200 — the network works, DNS works |
| `https://example.com/` | **curl exit 77**, "error setting certificate file" |
| `https://example.com/` with `-k` | 200 — the transport was fine; verification was impossible |
| `https://example.com/` with a CA bundle shipped in the payload | 200 |
| any of the above with the network denied | refused — the permission gate itself is correct |

(Whether the trust store is reachable at all, through the real launcher, with
and without the permission, is asserted in `tests/test_etc_surface.cpp`; the
curl numbers above are a hand measurement and are not in the suite, because a
test that reaches the public internet is not a test.)

So a granted `network` permission produced a network on which no standard
Linux TLS client could verify a certificate, and said nothing about it. That is
a silent failure of a granted permission, which is the opposite of this
runtime's fail-closed posture, so the trust store is now bound — **only when
`network` is granted**, on the same terms as `resolv.conf` and `hosts`: the
permission is what makes a trust store meaningful, and an application with no
network has no use for one.

Requiring publishers to ship their own CA bundle was the alternative, and it
works today (the row above proves it). It was rejected *for a trust store
specifically*: a bundle baked into a signed package is pinned at build time and
can never receive a distribution security update, so a CA distrusted by the
world stays trusted by that package until the publisher rebuilds. That is a bad
property for this file and only this file. A publisher who wants to pin a
private CA can still ship one and point the application at it; what changed is
that the ordinary case no longer requires it.

The `/etc/ssl/certs` entry is verified on this host: with it, `curl` and
python3's `ssl` module both completed a verified `https://` request inside the
sandbox, and without it neither could. The Fedora/RHEL (`/etc/pki/…`) and
openSUSE/Arch (`/etc/ca-certificates`, `/var/lib/ca-certificates`) entries are
included from those distributions' documented layout and have **not** been
measured here.

**A host with none of them warns.** Because the binds are optional, a host with
no trust store in any known location would produce a sandbox that starts
perfectly and fails every certificate check inside it — the silent failure
reintroduced by the fix's own error handling. The backend therefore prints one
line to stderr before the application starts, naming the permission and saying
that verification will fail. On an ordinary host it is silent.

### What the allowlist costs

An allowlist chosen for linking and name resolution removes far more than it
was aimed at, and some of what it removes is an application's **own security
configuration**. This is a real, measured limitation, not a theoretical one,
and it is written up as threat #12 in [THREAT-MODEL.md](THREAT-MODEL.md) rather
than being claimed away here. Read that row before assuming that running
something under `.LEXE` is at least as safe as running it directly — for one
class of application it is not.

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

## Display access

Display access is **granted only to an application whose manifest resolves to
`launch.mode: "gui"`** (Definitive Architecture §14.4) — which, note, is the
**default** when the manifest declares no mode at all, so a package gets this
by saying nothing. It is a deliberate,
declared reduction of isolation — the display socket is the one host resource a
graphical application genuinely cannot do without — and it is reported as such
rather than claimed away.

**What a GUI launch gets:**

| Resource | Bind | Why |
|---|---|---|
| the Wayland socket | read-write, at `/run/lexe/session/<name>` | connecting to a unix socket requires write access; the host's real `XDG_RUNTIME_DIR` layout is never exposed — only the one socket is bound in, and `XDG_RUNTIME_DIR` is rewritten to the fixed sandbox path |
| the X11 socket | read-write, at `/tmp/.X11-unix/X<n>` | derived from `DISPLAY`; a remote `host:0` DISPLAY is deliberately unsupported, since it would need network access the sandbox does not grant |
| `/etc/fonts`, `/var/cache/fontconfig`, `/etc/machine-id` | read-only, optional | font configuration. `/etc/machine-id` is a stable per-device identifier and fontconfig keys its cache on it; a console or service launch does not get it (pinned in `tests/test_etc_surface.cpp`) |
| `/dev/dri` | dev-bind, optional | GPU rendering |

Plus a small set of rendering-only environment variables
(`XDG_SESSION_TYPE`, `XDG_CURRENT_DESKTOP`, `GDK_BACKEND`, `QT_QPA_PLATFORM`,
and the locale variables). These affect how the application draws, never what
it may reach.

**What it does NOT get:** D-Bus (neither session nor system bus), the home
directory, the network, the user's real runtime directory, or any relaxation of
the filesystem controls. Those are never weakened to make a GUI launch work.

**A console or service application gets no display socket at all.** Because the
mode is declared in the signed manifest rather than guessed, this is a decision
the publisher makes explicitly and the user can inspect before installing.

**Truthful reporting.** The control map carries `display-isolated`. It is
`enforced` for a console/service launch, and `not-applicable` for a GUI launch
where a socket was actually bound — never a silent claim that the display is
still isolated when it is not. If a GUI application is launched in a session
with no Wayland or X socket at all, the control stays `enforced`, because
nothing was granted.

The `lexe-ui` and `lexe-builder` GTK apps are the runtime's own tools — they are
not `.lexe` applications and are not launched through this isolation path.

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
| `network` | **enforced** — permitted | shared netns; host reach proven, and the system TLS trust store is bound so certificate verification works (proven both ways in `tests/test_etc_surface.cpp`) |
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
| `/etc` reduced to a fixed allowlist | enforced (proven from inside a real sandbox) |
| display isolation (console/service launch) | enforced |
| display isolation (declared GUI launch) | **deliberately not applicable** — one display socket is bound, and that is reported, not hidden |
| D-Bus access (any launch mode) | never forwarded |
| seccomp syscall filter | **not implemented** |

## Exact guarantees / non-guarantees

**Guaranteed (proven on Linux with a working backend):** an application cannot
modify its installed files, read the user's home, read another application's
data, inherit dangerous loader/interpreter environment variables, see the
caller's working directory, or use the network without the `network` permission;
and if the sandbox cannot be established, the app is not run.

**Not guaranteed:** any containment on a platform without a backend (reported as
unsupported); syscall-level restriction (no seccomp); isolation from the display
server for an application that DECLARES `launch.mode: "gui"` (it is given the
session's display socket, with everything that implies — on X11 in particular, a
client with socket access can observe input to other clients);
`user-files-selected` enforcement (advisory); protection on kernels where
unprivileged namespaces are disabled (there the launch fails closed rather than
running unconfined); and — stated plainly because it cuts against what a
sandbox is assumed to do — that an application is **at least as constrained
inside as outside**. The `/etc` allowlist removes host-installed application
policy along with everything else, and for an application that reads its own
security policy out of `/etc` the sandbox is *less* restrictive than the host.
See threat #12 in [THREAT-MODEL.md](THREAT-MODEL.md).

# Services and the session manager

A `.LEXE` application whose manifest declares `launch.mode: "service"` is a
background program by declaration. That much is a property of the package.

**Whether the machine keeps it running is not.** That is a decision the owner of
the installation makes, and it is the whole subject of this document.

---

## 1. Two modes, one supervisor each

There are exactly two ways a `.LEXE` service runs, and the rule that matters is
that **each has exactly one supervisor**. Two supervisors for one process is the
failure this design exists to avoid: each would observe the other's actions as
crashes and act on them.

| | **`.LEXE`-supervised** (default) | **Session-managed** (opt in) |
|---|---|---|
| How it starts | `lexe run <id>` | `systemctl --user start lexe-<id>` |
| Who supervises | a detached `lexe` supervisor process | `systemd --user` |
| Starts at login | no | yes, when enabled |
| Restart on crash | **no** | yes, `on-failure` |
| Survives logout | no | only with lingering enabled (see §7) |
| Output goes to | the streams of whatever ran `lexe run` | the journal |
| Status | none — nothing has one to report | `systemctl --user status` |
| Enabled by | nothing; it is the default | `lexe service enable <id>` |

`.LEXE` never runs both at once for one application. `lexe service enable` does not
start a second copy, and the unit it writes invokes the runtime in its
**non-detaching** form (§3) precisely so that systemd is the only supervisor.

## 2. What `.LEXE` supervises, and what it does not

`.LEXE`-supervised is deliberately minimal, and the CLI says so in as many words
when you start one. What the detached supervisor does:

* holds the **version lease** — a shared `flock` on
  `<LEXE_HOME>/locks/<id>.v.<version>.lease` — for the application's whole
  lifetime, which is what makes `lexe uninstall` and `lexe purge` refuse while it runs and `lexe gc`
  keep its files;
* keeps the sandbox alive after `lexe run` returns, by omitting bubblewrap's
  `--die-with-parent`;
* reaps the sandbox when the payload exits, and then exits itself, releasing the
  lease in the kernel.

What it does **not** do, and never has: restart the application, start it at
login, report its status, or record its exit code. A detached launch reports
`exitCode: 0` meaning *started*, not *succeeded*.

That set is a deliberate floor, not an unfinished ceiling. A runtime that
restarted things without being asked would be a session manager, and the host
already has one.

## 3. The unit `lexe service enable` writes

```ini
[Unit]
Description=<application name> (.LEXE)
Documentation=man:lexe(1)
PartOf=graphical-session.target

[Service]
Type=simple
ExecStart="/usr/bin/lexe" run "<id>" --wait
Restart=on-failure
RestartSec=5s
TimeoutStopSec=20s
Environment="LEXE_HOME=<home>"        # only when LEXE_HOME is overridden

[Install]
WantedBy=default.target
```

Six decisions in there are load-bearing:

**`--wait` is mandatory, not stylistic.** Without it the runtime detaches by
declaration and `lexe run` returns immediately; a `Type=simple` unit would see its
main process exit, conclude the service died, and — with `Restart=` set — restart
it forever while the real payload kept running. `--wait` makes the `lexe` process
itself the unit's `MAINPID` for the payload's whole lifetime, and it also restores
bubblewrap's `--die-with-parent`, so `systemctl --user stop` tears the sandbox
down through the mechanism systemd already uses.

**`Type=simple`, not `forking`.** The runtime has no pid file and writes no
supervisor identity anywhere, so there is nothing for `PIDFile=` to name. With
`--wait` there is nothing to fork, either.

**`Restart=on-failure`, not `always`.** A service that exits 0 has finished; a
runtime that restarted it anyway would be overruling the program. `on-failure`
covers a crash, a non-zero exit, and a signal.

**`ExecStart` names the runtime, never the payload.** The payload path is inside
an installed version directory that changes on every update, and a unit pointing
at one would break on the next one — and would bypass verification, trust and the
sandbox entirely. `lexe run <id>` resolves the current version at start, which is
what makes an update take effect on restart and nowhere else.

**`Environment=LEXE_HOME=` only when it is overridden.** A unit is generated
against the install root it was enabled from. Without this the test suites, which
run against a scratch root, could not exercise any of it.

**Every path is quoted, and specifiers are escaped.** This one was learned the
hard way: systemd splits `ExecStart=` and `Environment=` on whitespace exactly as
a shell would, and the runtime path is wherever the runtime happens to be
installed. A `lexe` under `/mnt/c/Users/Some Name/build/lexe` produced

```ini
ExecStart=/mnt/c/Users/Some Name/build/lexe run <id> --wait
```

which systemd read as the command `/mnt/c/Users/Some` with the arguments
`Name/build/lexe`, `run`, … and failed with `203/EXEC` at every start — then
`Restart=on-failure` turned that into a restart loop. The unit was valid,
`systemctl --user is-enabled` said `enabled`, and it could never run. Nothing
about it looked wrong.

So every word is double-quoted unconditionally, and the four characters that mean
something inside systemd's quoting are escaped: `\` and `"` (C-style escapes),
`$` (variable expansion; `$$` is the literal), and `%` (a specifier — `%h` is the
home directory, and an *unknown* one makes the whole unit fail to load, so a
runtime under `~/opt/50%off/` needs `50%%off`). All four are legal in a POSIX
path. Unconditional quoting rather than "quote when it contains a space": a rule
with no exceptions cannot be got wrong by the next path that turns up, and
systemd accepts a quoted word that needed no quoting.

### How the unit reaches systemd

`enable` runs `systemctl --user enable <absolute path to the unit>`, never
`enable <name>`, and that is what lets the test suite exercise the production
code path rather than a parallel one.

The unit is written under `config_home_`, which `LEXE_HOME` redirects — so a test
never writes into the real user profile. But a unit outside systemd's search path
cannot be enabled by *name*: systemd answers `Unit file lexe-<id>.service does not
exist`. Verified against systemd 255 rather than assumed, enabling by path covers
both cases:

| the unit file is | `systemctl --user enable <path>` does |
|---|---|
| outside the search path | links it into `~/.config/systemd/user` **and** creates the `default.target.wants` symlink; it is then startable and stoppable by name |
| inside the search path | creates only the `wants` symlink — no redundant self-link, no complaint |

`disable` by *name* removes whatever either of those created. Everything else —
`is-enabled`, `is-active`, `start`, `stop` — addresses the unit by name, which
works in both cases once it is enabled.

## 4. Enablement is authority, and a package cannot grant itself any

A package declares that it *is* a service. It does not get to decide that the
machine should keep it running, start it at login, or restart it when it crashes.

So `lexe service enable` is an explicit, separate act, for the same reason
`--approve-compile` is separate from `--yes`: **each authorizes exactly one
thing.** Installing a package MUST NOT write a unit, and MUST NOT enable one.
There is no manifest field that asks for it, and there will not be one.

`lexe doctor` reports whether a unit exists and whether it is enabled. It does not
enable or disable anything — that is a decision, and diagnostics do not make
decisions.

## 5. Lifecycle ownership

| Operation | Who acts | What happens to the unit |
|---|---|---|
| `install` | `.LEXE` | nothing. No unit is written or enabled |
| `update` | `.LEXE` | the unit is untouched. A **running** service keeps running the version it started with, because its lease protects those files. The new version takes effect on the next restart, and `lexe update` says so rather than restarting it silently |
| `rollback` | `.LEXE` | same |
| `repair` | `.LEXE` | same |
| `uninstall` / `purge` | `.LEXE` | the unit is **stopped, disabled and deleted** before the application is removed. A unit left pointing at an uninstalled application is a systemd restart loop against a binary that is gone |
| `service enable` | user | unit written, recorded in `integration.json`, `daemon-reload`, enabled |
| `service disable` | user | stopped, disabled, deleted, un-recorded, `daemon-reload` |
| crash | systemd | restarted after `RestartSec`, per `Restart=on-failure` |
| logout | systemd | stopped, unless the user has enabled lingering (§7) |

The update rule is the one worth arguing about. Restarting a user's service as a
side effect of an update is surprising, and for some services actively harmful. So
the runtime reports that a restart is pending and leaves the decision alone.

## 6. The unit is durable integration state

A generated unit is recorded in `<LEXE_HOME>/integration.json` as an artifact of
kind `session-unit`, with its content hash, exactly like a `.desktop` entry, an
icon or a MIME document. That buys three things for free from machinery that
already exists:

* `lexe doctor` **names** a unit that has gone missing or been modified;
* `lexe doctor --repair` re-establishes the file **from installed state**, with no
  package present;
* uninstall removes it, because uninstall removes recorded artifacts.

With one deliberate asymmetry: repair restores the unit **file**, and never
changes whether it is *enabled*. Enablement is the user's decision, and a repair
that re-enabled something a user had disabled would be overruling them under the
name of fixing them.

## 7. What this does not do

* **It does not enable lingering.** `loginctl enable-linger` makes a user's units
  survive logout and start at boot. That is a change to the user's session
  policy, not to an application, and `.LEXE` does not make it. Without it a
  session-managed service stops at logout — which for a desktop application is
  usually what is wanted, and the documentation says so rather than surprising
  anyone.
* **It does not support system-wide units.** `install.scope` is `user` in
  Format 0.1; a `/etc/systemd/system` unit would run as root, and nothing in the
  trust model justifies that.
* **It does not invent a status channel.** `systemctl --user status` and
  `journalctl --user -u lexe-<id>` are the interface. `.LEXE` does not duplicate
  them.
* **It does not enforce single-instance.** `launch.singleInstance` is an advisory
  hint for frontends and the engine does not read it: two `lexe run` invocations
  today both start a payload. A session-managed service does not change that — it
  means `systemctl --user start` is idempotent while a bare `lexe run` is not.
  This is a known gap, tracked in [ROADMAP.md](ROADMAP.md).

## 8. Using it

```sh
lexe service enable org.example.daemon    # write the unit and enable it
lexe service status org.example.daemon    # what .LEXE and systemd each think
lexe service disable org.example.daemon   # stop, disable, remove the unit

systemctl --user status lexe-org.example.daemon
journalctl --user -u lexe-org.example.daemon -f
```

`lexe service status` reports both sides deliberately: whether a unit exists, is
enabled and is active, **and** whether a `.LEXE`-supervised copy is running
outside systemd. Those can disagree, and when they do, that is the thing you need
to be told.

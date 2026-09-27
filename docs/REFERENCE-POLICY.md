# Reference implementation policy

Everything the reference `lexe` runtime does that is **not** part of the
`.lexe` package format.

[FORMAT-0.1.md](FORMAT-0.1.md) is the contract: the bytes of a package, and the
behaviour any conforming implementation must provide. This document is the other
half — the choices this particular implementation made, which another
implementation could make differently while reading exactly the same packages.

Why the split exists, in one example. The earlier draft of Format 0.1 specified
`<LEXE_HOME>/apps/<id>/versions/<version>/` as though it were part of the
format. It never was: a package cannot observe where it is installed, so an
implementation that stored applications in a database rather than a directory
tree would have been "non-conforming" for a difference no package could detect.
Meanwhile the things a package *can* depend on — that its version content is
immutable, that rollback returns the content that was verified, that an
interrupted install leaves no half-applied state — were stated only implicitly,
as consequences of the layout. Those are now §9 of the format, without a path in
sight, and the layout is here.

The test that decided every case:

> Could another, independently written implementation behave differently here
> and still correctly consume the same `.lexe` package?

If yes, it is in this document.

**Nothing here is frozen.** These are implementation choices and may change
between releases of the reference runtime. Do not build another implementation
against this document; build it against the format.

## 1. Resource limits

Format 0.1 §10.2 requires a reader to document the processing limits it imposes
and to report a refusal distinctly from a format violation. These are the
reference runtime's values.

| Limit | Value | Applies to |
|---|---|---|
| package file size | 2 GiB | checked against the on-disk size before the file is read |
| entry count | 65 535 | central-directory records |
| per-entry uncompressed size | 1 GiB | each member |
| total uncompressed size | 2 GiB | sum over all members |
| expansion ratio | 200× | total uncompressed ÷ packaged size |
| ratio grace threshold | 256 MiB | below this total, the ratio is not applied |

The grace threshold exists so that a highly compressible package is not refused
for a ratio that says nothing about whether it is legitimate.

It was 16 MiB, and 16 MiB was too low — demonstrated by a program, not by
reasoning. A 48 MiB executable whose `.data` section is large, initialised and
low-entropy compressed to 53,914 bytes, a ratio of 934×, and could not be
installed at all. It ran correctly outside the runtime. Worse, the refusal's
hint asserted that "a package this compressible is not a normal application
payload", which was a claim about the input that the input disproved: embedded
tables and low-entropy resources do exactly this.

Raising it costs very little, because the ratio guard was never the real defence
— the absolute caps above are. Whatever a package claims, extraction stops at
1 GiB per entry and 2 GiB overall, and both are checked against the declared
sizes before a single byte is decompressed. The ratio guard only rejects the
pathological small-file-claiming-a-lot case earlier than those caps would, and
at 256 MiB it still does.

Both aggregate limits are enforced twice: once in the reader's constructor from
the central directory's declared sizes, so nothing is inflated before the
decision, and again during extraction against the bytes actually emitted,
because the central directory is the package's own claim about itself and a
claim can lie.

A refusal under any of these is reported with the category `resource-limit`
(`lexe verify --json`, field `failure.category`), against `format-invalid` for a
genuine violation. The human-readable output says explicitly that the limit is
this runtime's policy and that another implementation may accept the package.

## 2. Installed layout

Base directory (`LEXE_HOME` environment variable overrides; used by tests):

* Linux: `$XDG_DATA_HOME/lexe` or `~/.local/share/lexe`
* Windows (development host only): `%LOCALAPPDATA%\lexe`

```text
<LEXE_HOME>/apps/<id>/
├── versions/<version>/           immutable extracted payload/ contents
├── meta/<version>/               exact lexe.json + hashes.json bytes for that
│                                 version (repair hash source; rollback restore),
│                                 plus build.json for a portable package (§6.9)
├── current                       symlink to versions/<version>; where symlinks are
│                                 unavailable, a text file `current.txt` containing
│                                 the version string is written instead
├── manifest.json                 copy of lexe.json of the active version
├── hashes.json                   copy of the active version's hashes
├── installation.json             install record: source path/url, publisher key,
│                                 UTC timestamp, files created outside the app dir
│                                 (desktop entries, icons, MIME xml), channel
├── txn.json / .txn-staging/      transaction journal + staging (see HARDENING §A)
└── icons are copied to the hicolor theme; the .desktop entry Exec line is
    `lexe run <id>` (never a version-specific path)

<LEXE_HOME>/data/<id>/            PERSISTENT application data (see below)
├── .lexe-data-owner              the publisher key that owns this data
└── …                             app-managed contents (installer never reads them)
<LEXE_HOME>/cache/apps/<id>/      disposable per-app cache
<LEXE_HOME>/cache/runtime-tmp/    per-launch private temp roots (recovered after a crash)
<LEXE_HOME>/locks/                OS-backed operation locks (see docs/CONCURRENCY.md)
├── <id>.lock                     per-app exclusive mutation lock
├── <id>.v.<version>.lease        per-version launch lease (shared while running)
└── global.recovery.lock          global recovery coordination
```

### `meta/<version>/build.json` — what a portable package's build produced

Written by the install that compiled the package (§6.9), and by a repair that
compiled it again. Absent for a native package, which is not an error.

```json
{
  "schema": "lexe.build/1",
  "applicationId": "com.example.app",
  "applicationVersion": "1.0.0",
  "buildSystem": "make",
  "sourceDir": "src",
  "hostIsa": "x86_64",
  "builtAt": "2026-09-25T02:48:16Z",
  "runtimeVersion": "0.1.0-alpha",
  "approval": {
    "granted": true,
    "authority": "user",
    "approvedBy": "someone",
    "approvedAt": "2026-09-25T02:48:16Z"
  },
  "toolchain": [{ "name": "cc", "path": "/usr/bin/cc" }],
  "products": { "payload/bin/app": "<sha256>" }
}
```

`products` is keyed exactly like `hashes.json`, so one lookup answers "what
should this file hash to?" for a compiled entrypoint and an extracted one
alike. A runtime MUST check a compiled entrypoint against it before executing,
and MUST fail closed — refusing to launch — when a portable application has no
recorded hash for its entrypoint. Falling back to "unchecked" would leave
exactly the binaries the runtime compiled itself as the only ones it never
notices being replaced.

`approval.authority` records what the approval actually was. It MUST NOT claim
a privileged authority that was not involved (§6.9 property 1).

### Desktop integration is written to one of two places

Desktop entries, icons and MIME definitions are the only things the runtime
writes *outside* its own tree, and where they go depends on whether `LEXE_HOME`
is set:

| Scope | When | Written to | Seen by the desktop? |
|---|---|---|---|
| `xdg` | `LEXE_HOME` unset | `$XDG_DATA_HOME/{applications,icons,mime}` (default `~/.local/share`) | **yes** |
| `confined` | `LEXE_HOME` set | `<LEXE_HOME>/{applications,icons,mime}` | **no** |

A confined layout keeps the runtime from touching the real user profile — which
is what makes the test suite and the demos safe to run — but nothing scans those
directories, so the files are inert. Integration therefore reports **whether the
files are live, not merely that they were written**: `IntegrationResult` carries
`visible_to_desktop` and, when they are inert, a `note` naming the directory,
the consequence and the remedy. `lexe integrate` says "Registered the Lexe
runtime as the .lexe handler" only in the `xdg` case; otherwise it says it wrote
the files and explains why double-clicking a `.lexe` will not open them.

The database refresh (`update-desktop-database`, `update-mime-database`) is
skipped entirely for a confined tree: those caches exist for a desktop to read,
and running the tools against `<LEXE_HOME>/mime` only builds a cache nobody
consults while printing "…is not in the search path set by the XDG_DATA_HOME and
XDG_DATA_DIRS environment variables" over the command's own output.

**Storage taxonomy (paths are constructed and validated in ONE place — the
registry — never assembled ad hoc by callers).**

* **Persistent data** (`data/<id>/`) belongs to the App ID, not a version. It
  survives ordinary update, rollback and app-only uninstall; a package cannot
  redirect its location. The `.lexe-data-owner` marker pins the publisher key
  that owns the data: a reinstall by the same key reuses it, but a DIFFERENT
  key claiming the same id over retained data is refused (`RetainedDataConflict`,
  exit 6) until the data is purged. The installer never parses or executes app
  data. A binary rollback is not a data-format rollback.
* **Cache** (`cache/apps/<id>/`) is disposable and removed independently of data.
* **Runtime temp** (`cache/runtime-tmp/`) holds per-launch private directories
  under an installer-controlled root; the sandbox maps them to `/tmp`.

**Uninstall has three explicit modes:**

| Command | binaries + integration | cache | persistent data |
|---|---|---|---|
| `lexe remove <id>` | removed | preserved | preserved |
| `lexe remove <id> --remove-cache` | removed | removed | preserved |
| `lexe remove <id> --purge-data` | removed | removed | **removed** |

Full data removal requires the explicit `--purge-data` flag — `--yes` confirms
a prompt but never widens the scope to include persistent data. Uninstall refuses
(exit 6) while the application is running (a launch holds a version lease).

`lexe gc <id> [--keep <n>]` reclaims superseded immutable versions, always
keeping the active version, everything at or newer than it, the newest `n`
older versions, any version referenced by a pending transaction, and any version
a running launch is using.


## 2.1 Measured costs

Baselines, not budgets. They are recorded so a change can be NOTICED, which is
the thing that was missing: a launch took 1.8 seconds for an entire development
wave with every lane green, because nothing in the suite asked what anything
cost. It was found by measuring the command, not by a test failing.

Measured on the development host (WSL2, ext4 scratch tree, warm cache):

| | |
|---|---|
| the payload executed directly | 2–3 ms |
| bare `bwrap … /bin/true` | 5–6 ms |
| `lexe list`, `lexe info` | 17–19 ms |
| `lexe run` (native, sandboxed, `launch.mode: service`) | **27 ms** |
| `lexe run` (native, sandboxed, `launch.mode: gui`) | **57 ms** |
| `lexe run` (native, sandboxed, `launch.mode: console`) | **64 ms** |

A single figure used to stand here for all of them, and that is partly why the
defect in §2.1.1 went unnoticed for so long: one number, measured on one path,
read as though it covered every launch. Launch modes do different work and the
table now says so.

`lexe run` was **1800 ms** before the fix described below, and the difference was
not in the sandbox, the registry, or the payload — those together account for
about 25 ms of it.

`probe_providers()` searches every directory on `PATH` for `qemu-x86_64`,
`proton`, `box64` and `FEXInterpreter`, and a launch called it unconditionally.
Under WSL, `PATH` carries several dozen Windows directories where each stat costs
milliseconds: a trace showed 784 failed `newfstatat` calls hunting for
interpreters a native launch can never use. A native launch now skips the probe
entirely (`native_launch_is_certain`), and anything that might actually use a
chain still takes the full probe.

The waste existed on every host. It was merely cheap where `PATH` is short and
local, which is why nobody had noticed.

What guards it now is `tests/test_launch_cost.cpp`, and it deliberately asserts
the **work** rather than the time: that a launch which cannot use a compatibility
runtime does not look for one. A wall-clock budget on a shared machine is the
flakiest test there is — one had already cost this suite three false failures —
so the assertion is on a property of the code, which is stable under load and is
what actually regressed.

## 2.1.2 A first Windows launch costs minutes, and says so

The table above measures NATIVE launches. A foreign-OS chain has a one-off cost
that dwarfs all of it, paid the first time a given application runs on a given
chain, while its private compatibility prefix is built:

| | |
|---|---|
| first launch, `wine` chain | **152 s** |
| later launches, `wine` chain | **18 s** |
| first launch, `proton` chain | **150–170 s** |
| later launches, `proton` chain | **22 s** |

The cost itself is Wine's and Proton's, not this runtime's, and it is not
avoidable. What was this runtime's fault is that it said **nothing** for those
three minutes: no output, no progress, no diagnostic record, just a data root
quietly growing. Someone who double-clicks a Windows application and watches
nothing happen for two and a half minutes has exactly one conclusion available to
them, and the natural response — kill it — leaves a half-built prefix that makes
the next attempt worse.

So a first launch on a compatibility chain now prints one line to stderr saying a
compatibility environment is being prepared and that later launches are fast.
stderr, because stdout belongs to the application; once, because it is keyed on
whether this application has ever completed a launch on this chain.

That last detail is worth recording, because the obvious implementation is wrong.
Testing "did we just create the chain's required data directory" covers Proton,
which declares one, and silently misses **wine**, which declares none and builds
its prefix itself under the sandbox `HOME` — so the cheap test would have stayed
quiet for a 152-second launch. Asking the installation record whether this
application has run on this chain before is the same question for every chain.

This also cost an independent test pass most of an afternoon and three wrong
attributions — a harness timeout of `specimen timeout + 30 s` is shorter than a
cold prefix, so 33 slow-but-correct launches were recorded as hangs, then blamed
on host debris, then on a runtime regression. Nothing was wrong except the
margin. A cost that large and that silent invites exactly that mistake, which is
the strongest argument for announcing it.

## 2.1.1 Why a captured console launch used to cost 1.3 seconds

Recorded because the cause was not where anyone looked for it, including the
person who measured it.

A console launch whose stdout is not a terminal measured **1303 ms**, against
38 ms for a GUI launch, 26 ms for a service and 39 ms for the same console
launch with `--attached-terminal`. It was flat in output size (80 bytes, 1291 ms;
8 MiB, 1340 ms) and flat in dependency count, so it looked exactly like a fixed
timer — a one-second poll or a settle delay — and the capture code was the
obvious suspect.

The capture code has no timer in it. A syscall-*time* profile found the answer:
**1634 ms spent in 511 `newfstatat` calls**, every one of them under `/mnt/c`,
looking for `alacritty`, `xfce4-terminal`, `ptyxis` and seven other terminal
emulators. A console application with no terminal is *given* one (§14.4), and
finding one means searching `PATH` — which on a WSL host carries the whole
Windows `PATH`, about fifty directories on a DrvFS mount where one failed stat
costs roughly 10 ms.

Nothing was wrong with the search except where it was looking, and two things
follow from that:

* a Windows executable cannot host a Linux console application, so those
  directories could never contain an answer — the terminal search now skips
  `PATH` entries under `/mnt/`;
* a terminal emulator needs somewhere to draw, so on a host with no display the
  search can only fail — it is now skipped entirely, which is exactly the
  scripted and CI case that was paying most for it and could never use the
  result.

Measured after: **67 ms**, and 141 `newfstatat` calls totalling 9 ms. The output
still arrives.

The general point, and the reason this is in a document rather than just a commit:
a cost that is flat in every input looks like a timer, and this one was a loop
over a slow filesystem. The syscall *count* was the tell and the syscall-time
summary was where it showed up; a profile of CPU time would have shown almost
nothing, because waiting on a stat is not CPU.

## 2.2 The execution context of a launch

Format 0.1 §9.5.2 requires a writable working directory that is not the
installed content, an environment reset to a defined set, locale sufficient for
non-ASCII text, and a documented teardown rule. It deliberately does not fix the
spellings. These are this runtime's.

| Property | This runtime's choice |
|---|---|
| working directory | the application's private data root |
| data / cache discovery | `LEXE_APP_ID`, `LEXE_APP_DATA`, `LEXE_APP_CACHE` |
| locale | the caller's `LANG` / `LC_ALL` / `LC_MESSAGES` when set, else `LANG=C.UTF-8` |
| forwarded from the caller | nothing else, except display variables for a declared GUI launch |
| descendant teardown | console and GUI launches are torn down with the entrypoint; `service` is not |

Two of these are recorded because they were wrong and the reason they were wrong
is instructive.

The locale variables were forwarded **only** for a GUI launch, filed among
"toolkit hints that only affect rendering". A locale is not a rendering hint. A
console application on the Windows chain therefore received arguments and
filenames with the high bit stripped from every non-ASCII byte, while the same
binary declared as a GUI application received them intact. The default exists
for the other half of the problem: a launch from a session manager frequently
has no locale at all, and no locale means ASCII, which produces the same
corruption with nobody to blame for it.

The system view is sealed read-only **last**, after every mount is in place.
bubblewrap's root is a fresh tmpfs and a tmpfs is writable, so although `/usr`
was correctly bound read-only, the root directory and the `/etc` directory
holding the read-only `/etc` binds were both writable: a program could create
`/anything`. Not an escape — the writes landed on the sandbox's own tmpfs,
invisible outside and gone when it exited — but it contradicted the read-only
system view this runtime advertises, and it gave a program probing its own
privileges a different answer inside `.LEXE` than outside. Ordering is what makes
the fix safe: the seal is applied after the binds, tmpfs mounts and `--dev`, so
those keep their own mount flags and the private data root, `/tmp` and the
runtime directory stay writable.

## 3. Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | an unexpected failure |
| 2 | usage error |
| 3 | verification failed (including a resource-limit refusal — see §1) |
| 4 | not found |
| 5 | permission denied |
| 6 | busy, or retained data belongs to a different publisher |
| 7 | a local publisher-trust rejection |

Exit codes are a CLI contract, not a format one: they tell a script what
happened, and no package can observe them.

## 4. Other implementation choices

* **Sandboxing** is bubblewrap on Linux. The format requires isolation between
  applications (§9.6); it does not name a mechanism.
* **Proton is invoked as `proton runinprefix`, never `proton run`**, and there is
  now measured evidence for that beyond the reason originally recorded.

  The original reason was diagnostics: `run` does not leave the child's stdout and
  stderr attached, so a failed launch produced an empty diagnostic instead of one
  carrying the program's own output. An independent workload pass measured exactly
  that from the outside — `proton run` delivers none of the guest's output, while
  exit codes and file effects do propagate — and then found four more properties of
  `run` that this runtime would have inherited:

  | `proton run` behaviour | consequence had `.LEXE` used it |
  |---|---|
  | never returns unless `DISPLAY` names a **working** X server, even for a console program | every headless launch would hang |
  | a guest that reads stdin blocks forever, even with stdin at `/dev/null` | any interactive program would hang |
  | two concurrent invocations against one prefix intermittently produce a run where the guest never starts | a silent no-op launch reporting success |
  | **an interrupted invocation leaves processes in uninterruptible `D` state** that survive `SIGKILL`, hold the prefix against every later run, and clear only by restarting the distro | one cancelled launch would wedge the application permanently |

  The last one is the serious one, so it was tested against this runtime directly
  rather than reasoned about: a Proton launch interrupted mid-flight added **zero**
  `D`-state processes (4 before, 4 after), and the next launch succeeded in 2
  seconds against the same prefix. `runinprefix` plus a per-application prefix
  under the app's own private data root does not reproduce any of the four.

  This is recorded because the choice looks like a detail and is not: a runtime
  that had taken the obvious verb would have shipped a launcher that hangs
  headless, hangs on stdin, and can be wedged by pressing Ctrl-C once.

  **A nondeterminism that turned out to be the same defect.** Recorded because
  the wrong conclusion was written here first. Putting 72 Windows programs
  through the Proton chain twice produced a different set of failures each time —
  output delivery failed for 16 specimens in one pass and 17 in the other,
  including several that exited 0 — so this section said whether a successful
  program's output reaches the caller varies between runs, and called it an
  undiagnosed limitation of the chain.

  It was not. Re-measured after the launcher's output relay was fixed: the eight
  specimens that had flapped were run five times each on the Proton chain, with
  **8 of 8 delivered and zero delivery failures in all five passes, membership
  identical across repeats**. The relay defect was the whole of it; what looked
  like chain nondeterminism was a deterministic bug interacting with which
  specimens happened to emit a NUL or exit non-zero.

  The lesson is worth more than the entry: "undiagnosed and probably
  environmental" is the most comfortable thing to write about a flaky result, and
  it was wrong. A fixed defect documented as live tells the next person not to
  rely on something they can rely on.

* **Other compatibility chains** (Wine, FEX, Box64) are how this runtime
  executes payloads it cannot run natively. The format defines the *vocabulary*
  a package uses to declare what it permits (§5.5), because a package must be
  able to say "never translate my instructions"; it does not require any
  implementation to provide a particular chain, or any chain at all.
* **Locking** is `flock(2)` on per-application and per-version lock files. The
  format requires that a running application is not disturbed (§9.4); it does
  not say how to know one is running.
* **Desktop integration** writes freedesktop `.desktop`, icon and MIME files.
  Nothing in the format requires a runtime to integrate with a desktop at all.
* **`build.json`**, the record of what a portable package's build produced, is
  this runtime's format for the digests §9.7 requires it to keep. Another
  implementation must keep equivalent information; it need not keep it this way.

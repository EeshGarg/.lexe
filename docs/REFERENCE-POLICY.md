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
| ratio grace threshold | 16 MiB | below this total, the ratio is not applied |

The grace threshold exists so that a small, highly compressible package — a few
kilobytes of text that deflates well — is not refused for a ratio that means
nothing at that size.

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
| `lexe run` (native, sandboxed) | **35 ms** |

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
* **Compatibility chains** (Wine, Proton, FEX, Box64) are how this runtime
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

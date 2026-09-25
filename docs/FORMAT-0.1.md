# Lexe Package Format 0.1 — Normative

This document defines the exact on-disk format that the reference runtime reads and
writes for `lexeVersion: "0.1"`. Where [SPEC.md](../SPEC.md) describes intent, this
document defines bytes. The reference runtime MUST reject packages that violate a
MUST below.

## 1. Container

A `.lexe` file is a ZIP archive (PKZIP AppNote 6.3 compatible).

Writers (i.e. `lexe pack`) MUST produce **deterministic** archives:

* entries are added in lexicographic byte order of their full path;
* all entry timestamps are zeroed (the reference implementation compiles miniz with
  `MINIZ_NO_TIME`);
* entry paths use forward slashes (`/`) and are UTF-8;
* compression is DEFLATE at a fixed level (9), or STORE for entries smaller than
  64 bytes;
* each central-directory record carries the entry's Unix permission mode in its
  external attributes (high word), with "version made by" marked Unix: **0755**
  for a file that is executable in the source tree, **0644** otherwise. Only
  these two canonical modes are ever written — no umask leakage, and setuid,
  setgid and sticky bits are never recorded. On filesystems without Unix
  permission bits (e.g. Windows) every collected file is recorded as 0644, so
  helper executables must be packed on a POSIX filesystem;
* no ZIP64 unless the archive requires it; no encryption; no archive comment;
  no per-entry extra fields or comments beyond what the amalgamated miniz writer
  emits with the settings above.

Packing the same input tree twice MUST produce byte-identical `.lexe` files.

## 2. Entry Layout

```text
Application.lexe
├── lexe.json                      REQUIRED  application manifest
├── signatures/
│   ├── manifest.sig               REQUIRED  raw 64-byte Ed25519 signature
│   └── payload.sig                REQUIRED  raw 64-byte Ed25519 signature
├── metadata/
│   ├── hashes.json                REQUIRED  per-entry SHA-256 index
│   ├── description.md             optional
│   ├── license.txt                optional
│   └── permissions.json           optional
├── icons/                         optional  64.png 128.png 256.png scalable.svg
├── payload/                       REQUIRED for role "application"; MUST be
│                                  ABSENT for role "launch"
└── scripts/                       optional  RESERVED — never executed in 0.1
```

Readers MUST reject an archive when:

* any entry path is absolute, contains `..` as a path segment, contains a backslash,
  a NUL byte, or a Windows drive designator (`X:`);
* any entry path's first segment is not one of
  `lexe.json`, `signatures`, `metadata`, `icons`, `payload`, `scripts`;
* two entries have the same path;
* an entry is a symbolic link (ZIP external attributes: Unix mode `S_IFLNK`);
* a required entry is missing;
* `payload/` entries are absent and the manifest's `role` is not `"launch"`
  (bundled mode requires payload bytes; a launch reference carries none).

`scripts/` entries are carried but MUST NOT be executed by a 0.1 runtime.

## 3. Hashing — `metadata/hashes.json`

Algorithm: SHA-256. Digests are lowercase hexadecimal.

```json
{
  "algorithm": "sha256",
  "files": {
    "icons/128.png": "9f86d081884c7d65…",
    "metadata/description.md": "…",
    "payload/bin/example": "…"
  }
}
```

`files` MUST contain exactly one key for every entry in the archive **except**
`lexe.json`, `metadata/hashes.json` itself, and everything under `signatures/`.
Keys are the full entry paths. Verification MUST fail if a covered entry's digest
mismatches, if a covered entry is missing from the archive, or if an archive entry
that should be covered is absent from `files` (set equality, both directions).

## 4. Signatures

Signature scheme: **Ed25519** (RFC 8032), 64-byte raw signatures, stored as raw
binary (not hex, not base64).

* `signatures/manifest.sig` — signature over the **exact bytes** of the stored
  `lexe.json` entry (after decompression, before any JSON parsing).
* `signatures/payload.sig` — signature over the **exact bytes** of the stored
  `metadata/hashes.json` entry.

Signing raw entry bytes, not parsed structures, means no JSON canonicalization is
required anywhere.

### Publisher key encoding

`publisher.publicKey` in the manifest is the string

```text
"ed25519:" + base64(32-byte public key)
```

Base64 is the standard RFC 4648 alphabet **with** padding. Readers MUST reject any
other prefix or a decoded length ≠ 32.

### Key files (developer tooling)

`lexe keygen` writes a JSON key file:

```json
{
  "algorithm": "ed25519",
  "publicKey": "ed25519:BASE64…",
  "privateSeed": "BASE64 of the 32-byte seed"
}
```

The keypair is re-derived from the seed on every use. On POSIX the key file MUST be
created with mode `0600`.

## 5. Manifest — `lexe.json`

Encoding: UTF-8 JSON, no BOM. Unknown fields MUST be ignored (forward
compatibility). Required fields for 0.1:

### 5.1 Role

`role` selects which of the two `.lexe` artifact kinds this manifest describes.

| Value | Meaning |
|---|---|
| `"application"` | an installable application package (the default when absent) |
| `"launch"` | a launch reference naming an already-installed application |

The role is part of the SIGNED manifest, so it cannot be changed by renaming
the file. A handler MUST dispatch on the role, never on the file name or
extension. An unrecognised role MUST be rejected.

### 5.2 Fields required for every role

| Field | Constraint |
|---|---|
| `lexeVersion` | MUST be the string `"0.1"` |
| `id` | reverse-DNS: 2+ dot-separated segments of `[a-zA-Z0-9-]+`, ≤ 255 chars |
| `name` | non-empty string |
| `version` | non-empty string, see §8 ordering |
| `publisher.name` | non-empty string |
| `publisher.publicKey` | see §4 |

### 5.3 Fields required for `role: "application"`

These MUST be present for an application, and MUST be ABSENT for a launch
reference — the two roles are structurally distinct, not merely differently
labelled.

| Field | Constraint |
|---|---|
| `applicationType` | `"native"`, `"portable"` or `"windows"` |
| `architectures` | non-empty array; recognised values: `x86_64`, `aarch64` |
| `entrypoint.executable` | relative path inside `payload/` (no leading `/`, no `..`, no backslash) |
| `install.mode` | MUST be `"bundled"` in 0.1 (`network`/`launcher` → "unsupported in 0.1") |
| `build` | REQUIRED for `"portable"`, FORBIDDEN otherwise (§5.8) |

`applicationType` decides what the payload IS, and therefore what §6.7 demands
of the archive:

| Value | The payload is | `entrypoint.executable` names |
|---|---|---|
| `"native"` | the compiled program, for Linux | an ELF entry that MUST be present in the archive |
| `"portable"` | source code | the file the build MUST PRODUCE, and which MUST NOT be present in the archive |
| `"windows"` | the compiled program, for Windows | a PE entry that MUST be present in the archive |

`architectures` means something slightly different for each, and is a hard gate
in all three: the host's ISA MUST be one of them for the package to install
(§6.8).

| Value | `architectures` means |
|---|---|
| `"native"` | the entrypoint ELF targets one of these |
| `"portable"` | the build recipe is declared to produce a working program for these |
| `"windows"` | the entrypoint PE targets one of these |

A `"windows"` payload is not runnable on Linux by itself, so such a package
MUST permit a foreign-OS execution chain in `execution.allowedChains` — one
whose id contains `wine` or `proton`, including layered forms like
`proton+fex` (§5.5). A `"windows"` package that permits none, **including one
that relies on the default `["native"]`**, MUST be rejected: silence is not
consent to run under a compatibility layer. It MUST also be rejected when
`missionCritical` is true, which is the same contradiction stated directly —
mission-critical execution requires a Linux-native, host-ISA-native
realization, and a Windows payload has none by construction.

### 5.4 Fields required for `role: "launch"`

| Field | Constraint |
|---|---|
| `launch.applicationId` | the installed App ID this reference launches; same shape as `id` |

A launch reference MUST NOT carry any `payload/` entries (§6.7). Its own `id`
SHOULD NOT be the target application's id: a trust store binds ids to keys, and
a locally-signed reference must not bind a real application's id to a local
key. This implementation uses the fixed id `org.lexe.launch`.

`launch.applicationId` MUST be absent for `role: "application"`.

### 5.5 Execution policy — `execution`

| Field | Default | Constraint |
|---|---|---|
| `execution.missionCritical` | `false` | boolean |
| `execution.allowedChains` | `["native"]` | non-empty array of chain ids `[a-zA-Z0-9-+_]+` |

`missionCritical` is an EXECUTION RESTRICTION, not a safety certification. When
it is `true` the runtime MUST require a Linux-native, host-ISA-native
realization of a verified package, and MUST forbid ISA translation, Wine/Proton,
foreign-OS execution, compatibility fallback and any "run anyway" affordance.
If strict native execution cannot be achieved, execution stops.

A manifest with `missionCritical: true` and any `allowedChains` entry other than
`"native"` is a contradiction and MUST be rejected.

`allowedChains` is the set a resolver may choose from and a frontend may offer.
A user preference may narrow or reorder it; it MUST NOT extend it.

**Chain ids.** A chain id is one layer, or several joined with `+`, outermost
first. Each layer is one of:

| Layer | Kind | Runs |
|---|---|---|
| `native` | — | the payload directly; contributes no argv prefix at all |
| `fex`, `box64`, `qemu-user` | ISA translation | a foreign-ISA **Linux** binary |
| `wine`, `proton` | foreign OS | a **Windows** binary on Linux |

A layered id puts the foreign-OS layer outermost and the ISA-translation layer
innermost — `proton+fex` is Proton over FEX, for a Windows x86-64 payload on an
ARM64 host. The reverse (`fex+proton`) is not a chain.

A chain "runs a foreign-OS payload" when any of its layers is a foreign-OS
layer. That is the property §5.3 requires of a `"windows"` package.

### 5.6 Launch semantics — `launch`

| Field | Default | Constraint |
|---|---|---|
| `launch.mode` | `"gui"` | one of `"gui"`, `"console"`, `"service"` |
| `launch.singleInstance` | `false` | boolean; advisory hint for frontends |

Presentation MUST be taken from this declaration and MUST NOT be inferred from
whether the desktop happens to provide a terminal. A `"console"` application
launched without a terminal MUST be given one by the runtime, or have its output
captured and surfaced — it must not silently appear to do nothing. Exit code 0
MUST be recorded as success even when no window appears.

A `"service"` MUST be started detached: the runtime returns once it is running
rather than waiting for it, and the application MUST survive the process that
started it. Because nothing waited for it, the runtime MUST NOT report an exit
status for that launch. It MUST keep the launched version leased for as long as
the application runs, so the files it is executing cannot be removed underneath
it.

Detaching is not supervision. A runtime that does not restart a service, start
it at login, or track its status MUST NOT describe it as though it did.

### 5.7 Optional fields with defaults

`entrypoint.arguments` (`[]`), `install.scope` (`"user"`),
`install.estimatedSize`, `permissions` (`[]`, informational in 0.1), `updates`
(disabled when absent, see §7), `integration` (§9), `publisher.website`,
`runtimeProfile`.

`runtimeProfile` names the [runtime profile](RUNTIME_PROFILES.md) the builder
targeted and gated the build on — `"core-portable"`, `"forward-runtime"` or
`"native-capture"`. It is **declarative, not a promise about the payload**: a
reader MUST still verify conformance itself rather than trusting the string.

A reader that cannot resolve the value — including one naming a profile it does
not know — MUST treat the package as declaring no profile, and MUST NOT
substitute a default. Reading an absent or unknown declaration as
`"core-portable"` makes a package deliberately built as `"native-capture"` —
host-locked by definition — report as a portability failure.

### 5.8 Build recipe — `build` (portable packages)

Present exactly when `applicationType` is `"portable"`. A native package
declaring `build` MUST be rejected (there is nothing to build); a portable
package without one MUST be rejected (it can be installed nowhere).

| Field | Default | Constraint |
|---|---|---|
| `build.system` | — | REQUIRED; one of `"make"`, `"cmake"`, `"command"` |
| `build.sourceDir` | — | REQUIRED; relative path inside `payload/`, same path rules as `entrypoint.executable` |
| `build.command` | — | REQUIRED for `"command"`, FORBIDDEN otherwise; non-empty argv of non-empty strings |
| `build.toolchain` | — | REQUIRED, non-empty; bare executable names (no `/`), never absolute paths |

```json
"applicationType": "portable",
"architectures": ["x86_64", "aarch64"],
"entrypoint": { "executable": "bin/app" },
"build": {
  "system": "command",
  "sourceDir": "src",
  "command": ["cc", "-O2", "-o", "bin/app", "src/main.c"],
  "toolchain": ["cc"]
}
```

`build.command` is an **argv**, never a shell string: a shell string is a
second language between the manifest and `exec`, with its own quoting rules and
its own injection bugs. `argv[0]` is resolved on the build sandbox's `PATH`.

`build.toolchain` names the host executables the build needs. It exists so the
host can be checked BEFORE the user is asked to approve anything, and so a host
that cannot build the package can say which tool is missing instead of failing
part-way through a build. Entries are bare names because an absolute path in a
signed manifest would be a claim about a machine the publisher has never seen.

The build is performed at install time, under the rules in §6.9.

## 6. Verification Pipeline (normative order)

`lexe verify`, `lexe install`, and update application MUST run, in order:

1. **Structure** — archive opens; entry paths pass §2; required entries present.
2. **Manifest** — `lexe.json` parses; §5 constraints hold.
3. **Key decode** — `publisher.publicKey` decodes per §4.
4. **Manifest signature** — `manifest.sig` verifies over `lexe.json` bytes.
5. **Payload signature** — `payload.sig` verifies over `hashes.json` bytes.
6. **Hashes** — §3 set equality and digest checks over all covered entries.
7. **Payload role** — the bytes ARE what the manifest declares (§6.7).
8. **Compatibility** (install/update only) — host architecture ∈ `architectures`.
   Skipped for `role: "launch"`, which declares no architectures.

The report distinguishes every failed stage; the CLI exits `3` on any verification
failure.

### 6.7 Payload role

A manifest can only be trusted to describe the artifact if the artifact is
checked against it. Stage 7 closes that gap, BEFORE anything is installed.

For `role: "application"` with `applicationType: "native"`, the entry named by
`entrypoint.executable` MUST:

* be present in the archive;
* be a valid ELF object;
* have ELF type `ET_EXEC` or `ET_DYN` (an executable, or a position-independent
  executable) — a relocatable object or a core file is not runnable;
* target a machine that maps to one of the manifest's `architectures`.

For `role: "application"` with `applicationType: "portable"`, the archive MUST:

* contain at least one entry under `payload/<build.sourceDir>/` — a portable
  package must carry the source it is compiled from;
* **NOT** contain the entry named by `entrypoint.executable`. That file is what
  the build produces on the destination machine. A portable package that ships
  it is a native payload wearing a portable label: the binary that would end up
  installed is one this host never compiled.

For `role: "application"` with `applicationType: "windows"`, the entry named by
`entrypoint.executable` MUST:

* be present in the archive;
* be a valid PE image (an `MZ` header whose `e_lfanew` points, in range, at a
  `PE\0\0` signature);
* have `IMAGE_FILE_EXECUTABLE_IMAGE` set and `IMAGE_FILE_DLL` clear — a DLL is
  a library and cannot be launched, and it carries the executable-image bit
  too, so both must be checked;
* target a machine that maps to one of the manifest's `architectures`. A PE for
  a machine this format version cannot name (i386, ARM32, IA-64) MUST be
  refused as such, rather than reported as a mismatch against a list the
  publisher could not have satisfied.

A .NET/CLR image is NOT a verification failure: whether the host can run it is
a host-capability question for the execution resolver, not a question about
whether the bytes are what the manifest says.

For `role: "launch"`, the archive MUST contain no `payload/` entries.

This stage exists because of a real, observed failure: a package declared a
native application while its entrypoint was a C++ SOURCE FILE. Every signature
and hash was valid — the package was internally consistent and completely
wrong. Source belongs in a portable-code package and must go through host-ISA
compilation; it must never be installed as a native executable. The portable
rule above is the same requirement in the other direction, so neither type can
be used to smuggle the other's payload past verification.

Note the ordering: stage 7 runs AFTER hashes, so a tampered entrypoint is
reported as an integrity failure (stage 6), not as a role failure.

### 6.8 Compatibility

Stage 8 runs for `lexe install` and for an update, and is skipped for
`lexe verify` unless asked for and for `role: "launch"` (which declares no
architectures). The host's ISA MUST appear in `architectures`.

For `applicationType: "portable"` this is a statement about what the build
recipe is declared to produce, not about bytes already in the package. It is
still a hard gate: a package that does not claim this ISA is not installed on
it, and the compile in §6.9 never runs.

### 6.9 Host-ISA compilation (portable packages)

Installing a `applicationType: "portable"` package COMPILES its source on the
destination machine. That is the point of the type — one `.lexe` becomes native
to the machine it lands on — and it is also the most dangerous thing a package
format can ask for, so all four of the following MUST hold. A runtime that
implements any three of them has implemented remote code execution.

**1. Approval gates the operation.** The compilation MUST require explicit
authorization from the owner of the installation, obtained for this package and
this version, and MUST NOT be implied by a general "yes" to installing. Without
it the install MUST be refused before any toolchain is probed and before
anything is staged. The authorization MUST be recorded (§9 `build.json`).

The authorizing party for an `install.scope: "user"` installation — the only
scope 0.1 supports — is the user who owns that installation. A runtime MUST NOT
present this as an administrator's approval when no privileged authority was
involved.

**2. The build runs unprivileged and isolated.** It MUST run with no more
privilege than the installed application would receive, inside the same
isolation the runtime launches applications in, with:

* the **network denied unconditionally** — a `network` permission in the
  manifest MUST NOT reach the build. A build that downloads is fetching
  unsigned code onto the machine at install time, behind a signature that says
  nothing about what was fetched;
* **no display access**, whatever `launch.mode` says;
* a **writable build tree** (the staged version directory) and nothing else of
  the user's writable by it;
* a sanitized environment, as for a launch.

If the isolation cannot be established, the install MUST fail. Building
unconfined is not a fallback.

**3. The output is verified before it is used.** A build exiting 0 proves
nothing. The file named by `entrypoint.executable` MUST, after the build:

* exist;
* be a valid ELF object;
* have ELF type `ET_EXEC` or `ET_DYN`;
* target **the host's** machine — not merely one of `architectures`. A recipe
  that cross-compiles has not produced a host-ISA native executable.

This is §6.7's question asked of bytes that did not exist when the package was
signed.

**4. Approval grants no privilege.** It authorizes the operation. It MUST NOT
elevate the build, the installer, or the application.

**The build must happen before promotion.** Every failure above — including a
refused approval — MUST leave a previously installed version of the application
exactly as it was.

**The result MUST be recorded** as described in §9, because it is not covered
by the package's signed `hashes.json`: it did not exist when the package was
signed. A runtime that does not record it cannot detect tampering with exactly
the binaries it compiled itself.

## 7. Updates — `update.json`

`manifest.updates.manifest` is an `https://` URL (the runtime also accepts
`file://` and plain filesystem paths, which the test-suite uses). The runtime
fetches `update.json` and its detached signature at the same URL + `".sig"`
(raw 64-byte Ed25519 over the exact `update.json` bytes, same publisher key).

```json
{
  "lexeVersion": "0.1",
  "id": "com.example.application",
  "channels": {
    "stable": {
      "version": "1.4.3",
      "package": { "url": "https://example.com/releases/App-1.4.3.lexe",
                    "sha256": "…" },
      "minimumRuntime": "0.1"
    }
  }
}
```

Applying an update MUST enforce **all** of:

1. `update.json` signature verifies with the **installed** publisher key
   (key rotation is out of scope for 0.1 — a key mismatch aborts with an
   explanation; the user may reinstall manually to accept a new key);
2. `id` matches the installed application;
3. channel entry exists for the app's configured channel (default `stable`);
4. downloaded package's SHA-256 matches `package.sha256`;
5. the downloaded package passes the full §6 pipeline;
6. the package's own `id` and publisher key match the installed ones;
7. the new version is strictly greater (§8).

The previous version directory is retained for `lexe rollback`.

## 8. Version Ordering ("semver-lite")

Split both versions on `.`. Compare component-wise. For a pair of components:

* if **both** are all ASCII digits, compare numerically (leading zeros ignored,
  so `1` == `01`; arbitrary length, no integer overflow);
* if exactly **one** is all ASCII digits, the numeric one sorts **before** the
  non-numeric one (this class partition is what keeps the order total — a raw
  byte compare here would contradict the leading-zero stripping above and break
  transitivity);
* if **neither** is all ASCII digits, compare as unsigned byte strings.

A version that is a strict prefix (fewer components) is smaller. This is a total
order and is the ONLY ordering the 0.1 runtime uses; `version_less` derived from
it is a valid strict-weak-ordering comparator for `std::sort`.

## 9. Installed Layout

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

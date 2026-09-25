# .LEXE — the Definitive Architecture, as implemented

**Kind:** Normative. This document describes what the runtime in this
repository actually does, section by section, against the canonical
*.LEXE Definitive Architecture* design reference.

> One execution system, two graphical frontends, automatic for normal users,
> fully exposed for developers and power users.

The consumer contract is deliberately stupid-simple:

```
App.lexe
   |
double-click
   |
 works
```

Everything below exists so that line stays true across distributions, across
reboots, across desktop sessions, and across the cases where "native" is not
achievable.

---

## 1. The shape of the system

```
                    .LEXE
                      |
                     lexe
              CLI / source of truth
                      |
        +-------------+-------------+
        |                           |
   lexe-builder                  lexe-ui
   Developer GUI                Consumer GUI
        |                           |
        +------ frontend to lexe ---+
```

`lexe` owns every real operation: build, sign, verify, inspect, install, run,
configure, diagnose and uninstall. It is usable on its own; neither GUI is
required for anything. The GUIs **expose** `.LEXE` — they never reimplement it,
and they link `lexe_core` directly rather than shelling out to a second engine.

| Binary | Role |
|---|---|
| `lexe` | The runtime and CLI. The source of truth. |
| `lexe-ui` | Consumer + power-user frontend, and the registered `.lexe` handler. |
| `lexe-builder` | Developer frontend for build/sign/package. |

The alpha's `lexe-installer` is superseded by `lexe-ui`; `packaging/install.sh`
removes it if an older install left it behind, so two programs never both claim
the `.lexe` type.

---

## 2. Package roles — what an artifact *is*

A `.lexe` file can be one of two things, and **the signed manifest decides
which**. Never the file name.

```json
"role": "application"   // an installable package  (App.lexe / install.lexe)
"role": "launch"        // a launch reference      (run.lexe)
```

The role is structural, not cosmetic. The manifest parser enforces it:

* a **launch reference** may not declare `applicationType`, `architectures`,
  `entrypoint` or `install`, and **must** declare `launch.applicationId`;
* an **application** may not declare `launch.applicationId`;
* the verification pipeline additionally checks that the *bytes* match: a
  launch reference may carry no `payload/` entries at all.

Because `role` lives inside `lexe.json`, which is covered by
`signatures/manifest.sig`, renaming a file cannot change what opening it does.

### The `.LEXE` handler

`lexe open <artifact.lexe>` is the dispatcher, and it is what the desktop
handler entry ultimately drives:

```
double-click any .lexe
   |
   v  verify (structure, manifest, key, signatures, hashes, payload-role)
   v  read the SIGNED role
   |
   +-- role "application" --> install flow
   +-- role "launch"      --> resolve applicationId --> lexe run <id>
```

Verification comes first, always: the role is only trustworthy once the bytes
that carry it have verified.

---

## 3. Verification — including "is it what it claims to be?"

The pipeline has eight ordered stages. The pipeline stops at the first failure.

| # | Stage | What it proves |
|---|---|---|
| 1 | `structure` | the archive opens; entry-path rules hold; required entries present |
| 2 | `manifest` | `lexe.json` parses and satisfies every manifest constraint |
| 3 | `key` | `publisher.publicKey` decodes to a 32-byte Ed25519 key |
| 4 | `manifest-signature` | the signature verifies over the exact `lexe.json` bytes |
| 5 | `payload-signature` | the signature verifies over the exact `hashes.json` bytes |
| 6 | `hashes` | coverage is exact in both directions; every SHA-256 matches |
| 7 | **`payload-role`** | **the bytes ARE what the manifest declares** |
| 8 | `compatibility` | (install/update) the host architecture is supported |

Stage 7 is new, and it exists because of a specific alpha failure.

### `payload-role`: the fix for source-packaged-as-native

The alpha shipped a package that declared a native application while its
entrypoint was `helloworld.cpp` — source text where a compiled ELF was
expected. Nothing caught it, so the bad state surfaced later as a mysterious
launch failure.

For `role: "application"` with `applicationType: "native"`, the declared
entrypoint must now, **before installation**:

* be present in the archive,
* be a real ELF object,
* be an executable or position-independent executable (not a relocatable
  object, not a core file),
* target a machine listed in the manifest's `architectures`.

For `role: "application"` with `applicationType: "portable"` (§5A) the stage
asks the mirror image: the archive must carry source under `build.sourceDir`,
and must **not** carry the entrypoint it declares — that file is what the build
produces on the destination machine. A portable package shipping a prebuilt
entrypoint is the same lie told backwards, and it would install a binary this
host never compiled.

For `role: "launch"`, the archive must carry no payload entries.

The failure message says so in plain words — *"a native package must contain a
COMPILED executable — source files belong in a portable-code package"* — rather
than leaving the developer to guess. `tests/test_payload_role.cpp` covers the
exact alpha bug plus the wrong-architecture, relocatable-object, missing-
entrypoint, portable-with-prebuilt-entrypoint, portable-without-source and
happy-path cases, and pins the stage's position in the pipeline.

---

## 4. Execution policy — strict and normal resolvers

```
READ EXECUTION POLICY
     |
     +-- missionCritical = TRUE  --> STRICT RESOLVER
     |      Linux-native + host-ISA-native + verified, or STOP.
     |
     +-- missionCritical = FALSE --> NORMAL RESOLVER
            native when possible; ISA translation / Wine / Proton /
            combined layers when needed AND permitted AND available.
```

Manifest fields:

```json
"execution": {
  "missionCritical": false,
  "allowedChains": ["native"]
}
```

`missionCritical` is an **execution restriction, not a safety certification**,
and the runtime says exactly that wherever it surfaces.

### Three inputs that are never collapsed

| Input | Where it lives | What it can do |
|---|---|---|
| Package policy | the signed manifest | defines the permitted set |
| User preference | `~/.config/lexe/apps/<id>.json` | **narrow or reorder** that set |
| Host reality | probed at resolve time | removes what is not installed |

A user preference can never *extend* what the publisher permitted, and none of
the three can reach past mission-critical policy. `lexe compat <id> --set
proton` on a mission-critical application is refused with an explanation rather
than silently ignored at launch.

A mission-critical manifest that also lists a compatibility chain is rejected
at parse time as the contradiction it is.

### Chains

`native` is the boring fast path and contributes **no argv prefix at all** — so
the native steady state genuinely has no extra process in it, which is one of
the acceptance criteria. Compatibility chains contribute an argv prefix built
from providers probed on the host (`fex`, `box64`, `qemu-user`, `wine`,
`proton`, and the layered forms `proton+fex`, `wine+box64`, …). A layered chain
puts the ISA-translation layer innermost and the foreign-OS layer outermost.

Anything permitted but unavailable is **reported with a reason**, never
silently hidden:

```
$ lexe compat com.example.app
  Not available:
    proton  — Proton is not installed on this host
```

---

## 5. Launch semantics — presentation is declared

```json
"launch": { "mode": "gui" | "console" | "service" }
```

The alpha's console Hello World "looked like a failed launch": it printed to
stdout and exited 0 with no visible terminal, and the desktop's behaviour was
left to imply what happened. Presentation is now **declared in the manifest**
and never inferred.

| Mode | Behaviour |
|---|---|
| `gui` | Opens directly. The sandbox is granted the session's display socket. **Exit code 0 is success even when no window appears.** |
| `console` | If there is no terminal, `.LEXE` chooses one and re-enters through `lexe run --attached-terminal`. If no terminal emulator exists on the host, the output is captured and surfaced instead of vanishing. |
| `service` | Background; no terminal, no window expected. |

The default is `gui`. A console program **must** declare `console` — that
declaration is what lets `.LEXE` apply a terminal policy instead of the user
seeing nothing happen.

### Display access is a declared, truthful reduction of isolation

A `gui` launch binds exactly one extra host resource into the sandbox: the
session's display socket (Wayland at a fixed sandbox path under
`/run/lexe/session`, or the X11 socket), plus font configuration and `/dev/dri`
for rendering. It does **not** forward D-Bus, the home directory, or the
network. The control map records this honestly: `display-isolated` becomes
`not-applicable` when a display was granted, never a silent claim that it is
still enforced.

---

## 5A. Portable code — the destination machine compiles it

```
        SAME App.lexe
              |
    +---------+---------+
    |         |         |
  x86-64    ARM64    RISC-V
    |         |         |
  compile  compile  compile      <- on the destination machine
    |         |         |
    +---------+---------+
              |
        Native Linux
```

`applicationType: "portable"` is the type whose payload is **source**. The
program named by `entrypoint.executable` does not exist in the package: it is
what the build produces on the machine that installs it. One `.lexe` therefore
becomes native to the machine it lands on, instead of being several
architecture-specific packages carried together.

Verification asks the mirror image of the question it asks a native package
(§3). A native package must carry a compiled ELF; a portable package must carry
source under `build.sourceDir` and must **not** carry the entrypoint it
declares. A prebuilt entrypoint in a portable package is the alpha's
source-packaged-as-native bug told backwards — the binary that would end up
installed is one this host never compiled — so stage 7 refuses it.

### The four properties, and why all four

Compiling a downloaded package is the most dangerous thing a package format can
ask a machine to do. Implementing three of these four is remote code execution
with extra steps.

| Property | What it means here |
|---|---|
| **Approval gates the operation** | `--approve-compile`. Checked before a toolchain is even probed. A bare `--yes` does not set it: consenting to an install is not consenting to run a build. Recorded in `build.json` with who and when. |
| **The build is unprivileged and isolated** | The launcher's own sandbox with a writable build tree, **no network at all** and no display. Fails closed: no sandbox, no build. |
| **The output is verified** | Exiting 0 proves nothing. The declared entrypoint must exist, be an ELF, be runnable, and target **this host's** ISA — a recipe that cross-compiles has not produced a host-ISA native executable. |
| **Approval grants no privilege** | It authorizes the operation. The build gets strictly less authority than the installed application would. |

The build runs inside the **staged** version directory, before promotion, so
every failure — including a refused approval — leaves a previously installed
version exactly as it was.

There is no privileged administrator in a per-user installation, and the
runtime does not pretend otherwise: `approval.authority` records `"user"`,
meaning the owner of this installation authorized it. A system-scope install
would need a different authority, and system scope is not supported in 0.1.

### The build has no network, whatever the manifest says

A `network` permission describes what the *application* may do once installed.
It does not reach the build. A build that downloads is fetching unsigned code
onto the machine at install time, behind a signature that says nothing about
what was fetched — so `IsolationRequest::build` denies the network
unconditionally, and refuses to build at all if network denial cannot be
enforced.

### The compiled binary is protected like an extracted one

The output is not covered by the package's signed `hashes.json`: it did not
exist when the package was signed. It is recorded in `meta/<version>/build.json`
instead, keyed exactly like `hashes.json`, and everything downstream uses one
lookup for both kinds of entrypoint. The launcher checks it before exec and
**fails closed** when a portable application has no recorded product hash —
falling back to "unchecked" would leave the binaries the runtime compiled
itself as the only ones it never notices being replaced.

Repair cannot copy a portable entrypoint back out of the package, because it
was never in there. Repairing one **compiles again**, behind the same explicit
approval (`lexe repair <id> --approve-compile`): a repair command must not
silently build code.

### It is native afterwards, including for mission-critical policy

A compiled portable package resolves to the `native` chain with no argv prefix
— it is an ordinary host-ISA ELF at that point. The strict resolver (§4)
accepts it for the same reason: compiled here, for this ISA, checked before
promotion is Linux-native, host-ISA-native and verified.

`examples/portable-hello/` is the worked example, and
`tests/acceptance/05_portable_compile.sh` is the end-to-end evidence.

---

## 6. Durable integration — the reboot fix

The alpha's first end-to-end run worked, and then did not survive a reboot. The
conclusion the architecture draws is not "blame a KDE component" but:

> `.LEXE` desktop integration must be durable, explicit, and repairable across
> login sessions and reboots.

Integration is therefore **installed system state**, not a side effect:

* **explicit** — every registration `.LEXE` owns is enumerated in
  `~/.local/share/lexe/integration.json` with its expected content hash;
* **durable** — everything is written to persistent user locations, including
  the default association in `mimeapps.list`, which is the piece that actually
  decides who owns `.lexe` after a reboot;
* **repairable** — per-application entries regenerate from the **installed
  manifest**, with no package file present.

### What is registered

| Artifact kind | Path |
|---|---|
| `runtime-mime` | `~/.local/share/mime/packages/lexe.xml` |
| `runtime-handler` | `~/.local/share/applications/lexe-handler.desktop` |
| default association | `~/.config/mimeapps.list` |
| `app-desktop-entry` | `~/.local/share/applications/lexe-<id>.desktop` |
| `app-icon` | `~/.local/share/icons/hicolor/<size>/apps/lexe-<id>.*` |
| `app-mime-types` | `~/.local/share/mime/packages/lexe-<id>.xml` |
| `launch-reference` | `~/.local/share/lexe/launch/<id>.lexe` |

The MIME type is `application/vnd.usha.lexe`, with the alpha's
`application/x-lexe` kept as an `<alias>` so already-registered desktops and
previously-downloaded files keep resolving.

Every application desktop entry's `Exec` is `lexe run <id>` — **never** a path
to the payload. Normal launch therefore does not depend on
`application/x-executable` behaviour, and a desktop-environment policy change
cannot redefine whether an installed application launches.

### Verify and repair

```sh
lexe doctor            # names every missing or modified registration
lexe doctor --repair   # re-establishes them from installed state
```

`doctor` also reports the host picture that matters when something is odd: the
isolation backend and its probe result, the terminal emulator console
applications would use, which compatibility providers are installed, and where
all state lives.

This makes the architecture's reboot test a real, checkable property:

```
before reboot:  run.lexe -> lexe -> app
reboot
after reboot:   run.lexe -> lexe -> app
anything else = integration bug   <- doctor names which artifact broke
```

---

## 7. Launch references — the raw ELF is never the product

```
what the user sees                what .LEXE keeps private
------------------                ------------------------
App.lexe / install.lexe   ----->  signed package contents
run.lexe                  ----->  installed app ID + launch role
application-menu icon     ----->  lexe run <application-id>

                                  ~/.local/share/lexe/apps/
                                  <application-id>/versions/<version>/
                                     payload ELF
                                     resources
                                     private/bundled libraries
```

A `run.lexe` is a **real, fully signed, fully verifiable `.lexe`** — same
container, same MIME type, same eight-stage pipeline. What differs is the
signed `role`.

Launch references are generated on *this* machine for applications installed on
it, so they are signed by a **machine-local key** — the "Locally Trusted" signer
class — stored owner-only at `~/.local/share/lexe/keys/local-root.json`. That
key is stable: regenerating it would invalidate every `run.lexe` already on the
user's desktop.

A launch reference's own `id` is the fixed `org.lexe.launch`, deliberately
**not** the target application's id: the trust store binds ids to keys, and a
locally-signed reference must never bind a real application's id to the
machine-local key.

```sh
lexe launch-ref <id> -o ~/Desktop/run.lexe   # put one wherever you want
```

---

## 8. Runtime semantics — intelligence before exec, native performance after

Runtime/dependency resolution is expensive, so it happens **once**, at install
and at repair, and is recorded:

```json
"runtime": {
  "resolvedAt": "2026-09-24T23:40:31Z",
  "source": "host",          // bundled | host | mixed | static
  "glibc": "2.35",
  "unresolved": []
}
```

A normal native launch only **confirms the recorded state still holds**, then
execs. No compatibility layer required means no compatibility-layer performance
tax. When `unresolved` is non-empty the launcher refuses with a structured
diagnostic naming the missing libraries rather than exec'ing into a loader
failure, and points at `lexe repair <id>`.

```
first install / repair          normal native launch
----------------------          --------------------
read manifest                   read installed state
verify signatures + hashes      confirm required state still valid
check ISA + package policy      select native path
check dependency contract       exec native binary
install or provide what is missing
record installed state
```

---

## 9. Errors and diagnostics

Every hard gate follows one rule:

```
any ? bool failed --> .lexe-error message
```

and a `.lexe-error` message is a **typed record**, never an arbitrary string:

```
~/.local/state/lexe/errors/<application-id>/<timestamp>-<n>.json
                                            <timestamp>-<n>.stdout
                                            <timestamp>-<n>.stderr
```

Each record carries the application id and version, the **typed failure stage**
(`verification`, `execution-policy`, `chain-resolution`, `runtime-resolution`,
`integration`, `install`, `isolation`, `launch`, `runtime`), a human summary and
a full detail, the execution chain attempted, the declared launch mode, the host
OS and ISA, the runtime version and resolved profile, the exit code **or the
signal**, references to the captured streams, and a timestamp.

The store is bounded in both directions — each captured stream is truncated
(with the truncation disclosed in the file, not silently) and old records are
pruned — so a crash loop cannot generate unlimited diagnostic data.

```sh
lexe errors                 # applications with recorded errors
lexe errors <id>            # full structured history
lexe errors <id> --latest   # the most recent failure
lexe errors <id> --path     # the folder ("Open Error Folder")
lexe errors <id> --clear
```

Crucially: **exit code 0 is recorded as success even if no window appears.** A
real failure is distinguishable from successful-but-invisible execution, which
is precisely what the alpha could not do.

One deliberate detail: recording a diagnostic never collapses the typed
exception hierarchy. A blocked key still raises `BlockedKeyError`, a corrupt
trust record still raises `CorruptTrustError` — the record is written and the
original exception is re-thrown, because frontends switch on those types.

---

## 10. Per-application settings

User overrides live **outside** the signed package:

```
~/.config/lexe/apps/<application-id>.json
```

```json
{
  "compatibility": {
    "mode": "manual",
    "preferredChain": ["proton", "box64"]
  }
}
```

Changing a compatibility preference therefore cannot modify, re-sign or
invalidate the installed application. The resolver intersects the preference
with the manifest policy, so the file can only ever narrow or reorder.

---

## 11. Filesystem layout

| Path | Contents |
|---|---|
| `~/.local/share/lexe/apps/<id>/versions/<v>/` | the private payload: ELF, resources, bundled libraries |
| `~/.local/share/lexe/apps/<id>/installation.json` | installed state, runtime contract, last execution report |
| `~/.local/share/lexe/apps/<id>/manifest.json` | the exact signed manifest bytes |
| `~/.local/share/lexe/apps/<id>/meta/<v>/` | per-version `lexe.json` + `hashes.json` |
| `~/.local/share/lexe/data/<id>/` | persistent application data (survives update/rollback) |
| `~/.local/share/lexe/launch/<id>.lexe` | the generated `run.lexe` launch reference |
| `~/.local/share/lexe/keys/local-root.json` | machine-local launch-reference key (0600) |
| `~/.local/share/lexe/trust/<id>.json` | local publisher-trust records |
| `~/.local/share/lexe/integration.json` | the durable desktop-integration state |
| `~/.local/state/lexe/errors/<id>/` | structured error records + captured streams |
| `~/.config/lexe/apps/<id>.json` | per-application user overrides |
| `~/.config/mimeapps.list` | the durable `.lexe` default association |
| `~/.cache/lexe/` | downloads, probes, per-launch temp roots |

`LEXE_HOME` overrides the lot (tests and scratch runs put state, config and
`mimeapps.list` under it), so nothing ever has to touch a real user profile to
be exercised.

---

## 12. The install and run lifecycle

### Install

```
install.lexe / App.lexe
   |
   v  persistent .LEXE handler
   v  verify package (manifest / hashes / signature)
   v  validate package ROLE and entrypoint TYPE
   v  admin/user install approval + permission consent
   |
   +-- applicationType "portable" --> COMPILE APPROVAL
   |                                  v  probe the declared toolchain
   |                                  v  build, unprivileged + isolated,
   |                                  |  network denied, in the STAGED tree
   |                                  v  verify the output is a host-ISA ELF
   |                                  v  record build.json (approval, tools,
   |                                  |  product hashes)
   |                                  |  any failure: nothing is promoted
   |                                  v
   +---------------------------+---------------------------+
   |                                                       |
   v internal application store                v persistent integration
   raw ELF / resources / libs                  MIME + icons + menu entry
   (private)                                   + run.lexe launch reference
   |                                                       |
   +---------------------------+---------------------------+
                               v
                    resolve runtime contract, record it
                               v
                         INSTALL COMPLETE
```

### Run

```
run.lexe  (or the menu entry, or `lexe run <id>`)
   |
   v  persistent .LEXE handler -> resolve installed app ID
   v  verify local trust + installed state
   v  READ EXECUTION POLICY  (strict vs normal resolver)
   v  confirm the recorded runtime contract still holds
   v  SELECT EXECUTION CHAIN
   v  SANDBOX / PREPARE
   v  exec the internal application
   v  record execution report
   |
   +-- exit 0 --> success (even with no window)
   +-- failure --> structured .lexe-error record -> .LEXE Error view
```

---

## 13. Command surface

```
Applications
  open <artifact.lexe>              open any .lexe: install a package, launch a run.lexe
  install <file.lexe>               verify and install
  run <id> [--chain <c>]            launch (sandboxed)
  compat <id> [--set <c> | --auto]  show or change how an application is executed
  errors [<id>]                     structured diagnostics for a failed launch
  apps / list / info / inspect      what is installed, and what a package contains
  update / rollback / repair / remove / gc

Developer
  build / analyze / sdk / pack / keygen / sign-update

Trust & verification
  verify / trust / source

System
  doctor [--repair]                 check and repair .LEXE desktop integration
  integrate [--verify | --remove]   register or deregister the .lexe handler
  launch-ref <id> [-o <run.lexe>]   write a launch reference
  config / completion / version
```

---

## 14. How to reproduce the tests

### Unit and integration suite

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLEXE_BUILD_GUI=ON
cmake --build build -j"$(nproc)"
./build/lexe_tests                                  # everything
./build/lexe_tests -ts=execution-architecture       # the execution model
./build/lexe_tests -ts=payload-role                 # the alpha packaging bug
```

Test fixtures compile a **real** native ELF with the host toolchain
(`cc`/`gcc`/`clang`, cached per distinct program). On a host with no compiler
the fixtures fall back to a synthesized ELF so verification-only tests still
run, and tests that need to *execute* a payload skip with a message.

### End-to-end acceptance

```sh
bash tests/acceptance/run_all.sh
```

Four scripted suites covering install + launch, persistence and repair, failure
diagnostics, and the native steady state (which asserts the process tree is
`lexe → bwrap → gui-hello` with no compatibility process in it). Everything runs
against a throwaway `LEXE_HOME`; the real `~/.local/share/lexe` is never
touched.

**Automated tests are headless by construction.** `tests/acceptance/lib.sh`
severs `WAYLAND_DISPLAY`/`DISPLAY` for the whole harness before any test runs,
so no window can appear on a developer's screen — a window that steals focus
mid-run is disruptive, and a test whose result depends on a live desktop session
is not reproducible on a build machine. The GUI example's `--selftest` and
`--sleep` flags return before GTK is initialised, and the guard means a future
change that tried to open a window would fail loudly rather than silently
render. Anything that genuinely must draw brings its own synthetic display:
`scripts/gui-smoke.sh` runs the GTK frontends under `xvfb-run`, and refuses to
fall back to the real session.

[`tests/acceptance/REBOOT.md`](../tests/acceptance/REBOOT.md) covers the parts
that genuinely require a real reboot and a real double-click — those are
explicitly manual and are the one place a window is expected on screen.

### A manual end-to-end run against a scratch home

```sh
export LEXE_HOME=/tmp/lexe-scratch
./build/lexe keygen /tmp/key.json
./build/lexe build examples/gui-hello -o /tmp/App.lexe --key /tmp/key.json
./build/lexe verify /tmp/App.lexe           # all 8 stages, incl. payload-role
./build/lexe install /tmp/App.lexe --yes
./build/lexe doctor                         # integration healthy
./build/lexe open "$LEXE_HOME/launch/com.usha.guihello.lexe"

# Now break it the way a reboot did in the alpha, and watch it be diagnosable:
rm "$LEXE_HOME/applications/lexe-handler.desktop" \
   "$LEXE_HOME/config-home/mimeapps.list"
./build/lexe doctor          # names both, exits non-zero
./build/lexe doctor --repair # puts them back
./build/lexe doctor          # healthy again
```

---

## 15. What is not done

Stated plainly, because an architecture document that hides its gaps is worse
than useless.

* **Portable code has not been exercised on a second ISA.** The path itself is
  implemented and tested (§5A below), but every build so far has happened on
  x86_64. "The same `.lexe` compiles on ARM64 too" is the architecture's claim
  and it remains unproven on hardware, exactly like the cross-ISA claims below.
* **Only `make`, `cmake` and an explicit `command` are understood** as build
  systems. Anything else must be expressed as a `command`.
* **A portable package is compiled at install and never again** unless it is
  repaired or reinstalled. A host whose toolchain or libraries move underneath
  it keeps running the binary that was built at install time; the runtime
  notices a *changed* entrypoint, not a stale one.
* **Foreign-OS payloads.** The resolver knows the Wine/Proton chain shapes and
  will select and prefix them, but no package can currently *declare* a
  foreign-OS payload, so those chains are unreachable in practice on a 0.1
  manifest. They are real code paths with real provider probing, not stubs —
  but they are untested against an actual Windows binary.
* **Cross-ISA execution has not been exercised on real hardware.** The chain
  selection, argv prefixing and provider probing are unit-tested with synthetic
  provider sets; no FEX/Box64 run has been performed on an ARM64 host.
* **Signer classes.** The trust model implements local trust-on-first-use with
  explicit trust and blocking. The design reference's named tiers — Usha
  Verified, Organization Signed — have no distinct implementation beyond
  "Locally Trusted" and "Developer Signed"; there is no signing authority.
* **`service` launch mode** is declared, parsed and carried through, but it does
  not yet detach or integrate with the session manager; it currently behaves
  like a non-GUI foreground launch.
* **Reboot verification** is scripted and locally verified against simulated
  damage. A genuine reboot-boundary pass requires the manual checklist.

---

## See also

* [ARCHITECTURE.md](ARCHITECTURE.md) — module map, build system, conventions.
* [FORMAT-0.1.md](FORMAT-0.1.md) — the container and manifest specification.
* [ISOLATION.md](ISOLATION.md) — the bubblewrap sandbox design.
* [TRUST-MODEL.md](TRUST-MODEL.md) — the implemented local trust model.
* [ALPHA.md](ALPHA.md) — the alpha support contract.

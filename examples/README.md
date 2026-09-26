# .LEXE examples

Small, real, deterministic projects. Each one is a ready `lexe build` project — a
`lexe.json` plus a `payload/` its `Makefile` produces — and each exists to
demonstrate one mechanism rather than to be impressive.

They double as documentation. If you want to know what a portable package looks
like, `portable/c-hello/` is a shorter and more honest answer than any prose, and
it is a thing you can run.

They are also the payloads the test suites use, which is the point: an example
that stopped working would fail a test rather than quietly rot.
`tests/acceptance/00_repository.sh` additionally checks that every example is
actually **in** the repository — a payload's source committed, its compiled output
not — because that had once silently not been true.

```text
examples/
├── native/       a compiled Linux ELF, run directly
├── portable/     source, compiled by the machine that installs it
├── windows/      a Windows PE, run through Wine or Proton
├── service/      a background application
└── broken/       packages that are supposed to be refused
```

## native/ — a compiled ELF, run directly

| Example | What it demonstrates | Proved by |
|---|---|---|
| [native/cli-hello/](native/cli-hello/) | the simplest real thing: a dynamically linked C CLI that links libm, so it has a genuine dynamic ABI rather than being a static hello-world | `lexe sdk verify` reports it conformant |
| [native/gui-hello/](native/gui-hello/) | a GTK 3 desktop application **that runs under the sandbox**: declares `launch.mode: "gui"`, shows its `LEXE_APP_ID`, writes into `$LEXE_APP_DATA`. `--selftest` is the headless check; `--window-for <n>` opens the window and then exits 0 on its own, which is what lets a test witness a window AND a real exit code | [acceptance 01](../tests/acceptance/01_install_and_launch.sh), [acceptance 08](../tests/acceptance/08_native_gui.sh) |
| [native/bundled-library/](native/bundled-library/) | an application carrying its **own** shared library (`RPATH $ORIGIN/../lib`); the dependency engine classifies it as a *bundle* rather than a host requirement | `lexe analyze` |
| [native/gtk-portability/](native/gtk-portability/) | the Core 1 **boundary**: Core 1 is headless in this alpha, so `lexe sdk verify` reports a GTK app non-conformant, and GTK's `dlopen`-ed graphics stack illustrates the dlopen limitation. An example of a HONEST NO | `lexe sdk verify` |

## portable/ — source, compiled where it lands

| Example | What it demonstrates | Proved by |
|---|---|---|
| [portable/c-hello/](portable/c-hello/) | `applicationType: "portable"`: the payload is `payload/src/`, there is deliberately **no** entrypoint binary in the package, and installing it requires `--approve-compile`. The program reports the ISA from its own compiler's predefined macros, so the evidence that it was compiled here does not come from the runtime's own bookkeeping | [acceptance 05](../tests/acceptance/05_portable_compile.sh) |

The claim this type exists for — *the same signed package compiles on x86_64 and
on AArch64* — is implemented and unit-tested and has never run on a second ISA.
See [../docs/ROADMAP.md](../docs/ROADMAP.md) §1 for the test that would settle it.

## windows/ — a PE, run on Linux

| Example | What it demonstrates | Proved by |
|---|---|---|
| [windows/console-hello/](windows/console-hello/) | `applicationType: "windows"`: a console PE cross-compiled with MinGW, resolved to Wine or Proton. Its stdout crosses the compatibility boundary, its arguments survive, and it writes into its private data root **from inside a Windows process** | [acceptance 06](../tests/acceptance/06_foreign_os.sh), [acceptance 07](../tests/acceptance/07_proton.sh) |
| [windows/gui-hello/](windows/gui-hello/) | a real Win32 **GUI** PE (`-mwindows`, so the PE header says GUI subsystem): RegisterClass, CreateWindow, a message loop. A foreign-OS *window* is a different question from a foreign-OS *process*, and this is what answers it | [acceptance 09](../tests/acceptance/09_windows_gui.sh) — both Wine and Proton |

A `windows` package **must** permit a foreign-OS chain: nothing can run a Windows
payload natively, and a manifest that declares only `native` is refused at build
time rather than at launch.

## service/ — a background application

| Example | What it demonstrates | Proved by |
|---|---|---|
| [service/heartbeat/](service/heartbeat/) | `launch.mode: "service"`: detaches for real, is supervised, holds a version lease so its files cannot be removed underneath it, and terminates cleanly | [lifecycle](../tests/lifecycle/) |

## broken/ — packages that are supposed to be refused

A verifier is only as good as what it turns away, and "it rejected something" is
not interesting on its own — *which* stage caught it, and what it said, is.

These are real project folders you can try to build and install, each wrong in
exactly one way, with the refusal it should produce written down beside it. See
[broken/README.md](broken/README.md).

They are deliberately NOT a test harness. The byte-level adversarial matrix —
traversal, symlink escape, duplicate entries, tampered hashes, signature
substitution — lives in [../tests/security/](../tests/security/) and
[../tests/test_security_boundary.cpp](../tests/test_security_boundary.cpp), where
it can be exhaustive without being readable. These are the handful a developer
will actually hit by accident, kept understandable.

## The flow, for any of them

```sh
make -C examples/native/cli-hello                     # build the payload
lexe analyze examples/native/cli-hello                # dependencies + compatibility
lexe sdk verify examples/native/cli-hello             # Tux32 Core 1 verdict
lexe keygen key.json
lexe build examples/native/cli-hello -o app.lexe --key key.json
lexe inspect app.lexe                                 # what a user sees first
lexe install app.lexe --yes --trust
lexe run org.lexe.examples.cli-tool -- 2 9 16
```

[../docs/TUTORIAL.md](../docs/TUTORIAL.md) walks through it properly.

## Also worth reading

[../sdk/tux32-core-1/reference-app/](../sdk/tux32-core-1/reference-app/) — the
reference package: dynamic libm, persistent data/cache/temp. The artifact the
portability proof carries across the distribution boundary.

# .lexe examples

Small, real projects you can build, verify, package, install and run. Each is a
ready `lexe build` project — a `lexe.json` plus a `payload/` produced by its
`Makefile`. Build them in the Core 1 sysroot
([../sdk/tux32-core-1/build-in-sysroot.sh](../sdk/tux32-core-1/build-in-sysroot.sh))
for a Core Portable result.

| Example | Shows |
|---|---|
| [cli-tool/](cli-tool/) | A minimal dynamically linked C **CLI utility** (reads args, links libm). Verifies conformant. |
| [bundled-library/](bundled-library/) | An app that carries its **own shared library** in the payload (RPATH `$ORIGIN/../lib`); the dependency engine classifies it as a *bundle*. Verifies conformant. |
| [gui-hello/](gui-hello/) | A **GTK 3 desktop application that runs under the sandbox**: declares `launch.mode: "gui"`, shows its `LEXE_APP_ID` and writes into `$LEXE_APP_DATA`, and has a `--selftest` flag for headless CI. The payload used by [../tests/acceptance/](../tests/acceptance/). |
| [portable-hello/](portable-hello/) | A **package whose payload is source**: `applicationType: "portable"`, compiled by the machine that installs it. Ships `payload/src/` and deliberately no entrypoint binary; installing it needs `--approve-compile`. The payload used by [../tests/acceptance/05_portable_compile.sh](../tests/acceptance/05_portable_compile.sh). |
| [windows-hello/](windows-hello/) | A **Windows PE payload run on Linux**: `applicationType: "windows"`, cross-compiled with MinGW, resolved to Wine or Proton. Shows why such a package *must* permit a foreign-OS chain, and what verification proves about the bytes first. The payload used by [../tests/acceptance/06_foreign_os.sh](../tests/acceptance/06_foreign_os.sh). |
| [gtk-app/](gtk-app/) | A minimal **GTK desktop application** — shows the Core 1 boundary: Core 1 is headless in this Alpha, so `lexe sdk verify` reports a GUI app non-conformant, and GTK's `dlopen`-ed graphics stack illustrates the dlopen limitation. |
| [../sdk/tux32-core-1/reference-app/](../sdk/tux32-core-1/reference-app/) | The **reference package**: dynamic libm, persistent data/cache/temp — the artifact the portability proof carries across the distribution boundary. |

Each example follows the same flow (see [../docs/TUTORIAL.md](../docs/TUTORIAL.md)):

```sh
make -C examples/cli-tool                 # build the payload
lexe analyze examples/cli-tool            # dependencies + compatibility
lexe sdk verify examples/cli-tool         # Tux32 Core 1 verdict
lexe keygen key.json
lexe build examples/cli-tool -o cli-tool.lexe --key key.json
lexe inspect cli-tool.lexe                # what a user sees before installing
lexe install cli-tool.lexe --yes --trust
lexe run org.lexe.examples.cli-tool -- 2 9 16
```

A small **game** example is planned but not yet shipped; it is tracked in the
roadmap rather than stubbed here. GUI applications themselves are no longer
blocked: a package that declares `"launch": {"mode": "gui"}` is granted the
session display socket by the sandbox, which is what `gui-hello` demonstrates.

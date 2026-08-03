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

A small **game** example is planned but not yet shipped; like `gtk-app` it would
be a GUI application, which Core 1 does not run in the sandbox in this Alpha
(headless/terminal only — GUI forwarding is a later milestone), so it is tracked
in the roadmap rather than stubbed here.

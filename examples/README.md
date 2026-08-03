# .lexe examples

Small, real projects you can build, verify, package, install and run. Each is a
ready `lexe build` project — a `lexe.json` plus a `payload/` produced by its
`Makefile`. Build them in the Core 1 sysroot
([../sdk/tux32-core-1/build-in-sysroot.sh](../sdk/tux32-core-1/build-in-sysroot.sh))
for a Core Portable result.

| Example | Shows |
|---|---|
| [cli-tool/](cli-tool/) | A minimal dynamically linked C CLI (reads args, links libm). |
| [bundled-library/](bundled-library/) | An app that carries its **own** shared library in the payload (RPATH `$ORIGIN/../lib`); the dependency engine classifies it as a *bundle*. |
| [../sdk/tux32-core-1/reference-app/](../sdk/tux32-core-1/reference-app/) | The reference package: dynamic libm, persistent data/cache/temp, the artifact the portability proof carries across the distribution boundary. |

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

**Planned examples** (templates, not yet shipped): a GTK desktop app and a small
game. Core 1 is headless/terminal, so a GUI app runs GUI-forwarded only in a
later milestone; these are intentionally out of scope for the Alpha and are
tracked in the roadmap, not stubbed here.

# Example: gtk-app

A minimal GTK 3 desktop application, packaged as a `.lexe`. It builds and packages
like any other project — and it is the clearest way to *see the Tux32 Core 1
boundary*.

```sh
make                          # -> payload/bin/gtk-example  (needs GTK 3 dev headers)
lexe analyze .                # see the large GTK dependency closure it bundles
lexe sdk verify .             # NON-conformant (exit 3) — see below
```

**Why it is not Core 1 conformant — and why that is correct.**

- **Core 1 is a headless/terminal contract.** GUI *forwarding* is no longer a
  later milestone — the sandbox now binds the session display socket for a
  package that declares `"launch": {"mode": "gui"}`, and
  [../gui-hello/](../gui-hello/) is a GTK app that really runs that way. This
  example predates that and does not declare a launch mode, so it stays on the
  boundary side: use `gui-hello` for the runnable GUI path and this one to see
  where Core 1 stops.
- **Built on a current host, it trips the symbol ceiling.** Like any binary built
  on a newer glibc, `gtk-example` imports `GLIBC_2.34`, so `lexe sdk verify`
  returns `symbol-ceiling-exceeded` — build it in a Core 1 sysroot to clear that
  axis (see [../../../sdk/tux32-core-1/](../../../sdk/tux32-core-1/)).
- **GTK loads its graphics stack with `dlopen`.** Interfaces like `libGL` are not
  in the executable's static ELF metadata, so they do not appear as dependencies
  — a documented Core 1 limitation: `dlopen`-ed dependencies must be reasoned
  about by the developer.

Use this example to see the Core 1 boundary and the dependency closure of a real
GUI app. The `cli-tool`, `bundled-library`, and reference-probe examples are the
ones that verify conformant, and [../gui-hello/](../gui-hello/) is the GUI
application that actually launches under the sandbox.

# Tux32 Core 1 reference probe

A deliberately small but **non-trivial**, dynamically linked application. It is
the artifact the cross-distribution proof carries **unchanged** from a newer
build host to an older conforming runtime, so it is intentionally *not* a static
hello-world — it exercises the real dynamic ABI and the Core 1 runtime contract.

What it demonstrates:

- **Real dynamic linking.** [src/portable_probe.c](src/portable_probe.c) links
  the host glibc *and* libm (`sqrt`/`sin`/`pow` force a `DT_NEEDED` on
  `libm.so.6`). It genuinely uses the dynamic-linking contract; it does not
  sidestep it with a fully static image.
- **Persistent data.** A launch counter under `$LEXE_APP_DATA` that must survive
  across launches, updates and rollback.
- **Disposable cache.** A `last-run` marker under `$LEXE_APP_CACHE`.
- **Private per-launch temp.** A scratch file under `$TMPDIR` (tmpfs).
- **Identity.** It prints `$LEXE_APP_ID`.

These variables come from the runtime's sanitized environment
([../../../docs/ISOLATION.md](../../../docs/ISOLATION.md)); each has a safe
fallback so the program also runs for local testing outside the sandbox.

## Build and verify

```sh
# Conformant build: compile in the Core 1 sysroot (glibc <= 2.31).
../build-in-sysroot.sh .
lexe sdk verify . --json          # expect verdict "conformant", exit 0

# Contrast: a build on a host with glibc > 2.31 exceeds the ceiling.
make                              # builds with the HOST cc
lexe sdk verify .                 # expect "symbol-ceiling-exceeded", exit 3
```

The second case is the whole point: the same source, built against a newer host
glibc, imports newer symbols and is correctly refused a Core 1 claim.

## Package

```sh
lexe build . -o probe.lexe --key mykey.json
```

The result is a single signed `.lexe` that installs and launches on any Core 1
conforming host — including one older than the machine it was verified on.

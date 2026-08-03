# Troubleshooting

Common runtime issues and common developer mistakes, with the fix for each.
Every `lexe` error also prints a one-line hint; this is the longer form.

## Running applications

### "runtime isolation backend is unavailable … refusing to launch unconfined"

The Linux sandbox needs **bubblewrap** and unprivileged **user namespaces**. The
launcher fails closed on purpose — it never runs an app without isolation.

- Install bubblewrap: `sudo apt install bubblewrap` (or your distro's package).
- If user namespaces are restricted (Ubuntu 24.04+), allow them:
  `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.
- Inside a container, run it `--privileged` (nested user namespaces).

### "command not found: lexe" after installing

`~/.local/bin` is not on your `PATH`. Add it:
`export PATH="$HOME/.local/bin:$PATH"` in your `~/.bashrc` or `~/.profile`.
`packaging/install.sh` prints this note when it applies.

### Double-clicking a `.lexe` does nothing

Desktop integration may not be registered. Re-run `packaging/install.sh` (it
wires the MIME type and default handler), or `lexe integrate`. Some minimal
desktop environments need you to log out and back in to pick up new MIME
associations.

### "libsodium runtime library not found"

The runtime links libsodium for Ed25519. Install it:
`sudo apt install libsodium23` (Debian/Ubuntu) or the equivalent.

### An update was refused: "requests additional permissions …"

The new version wants a capability you did not previously approve. Review the
listed permissions, then re-run with `--accept-permissions` to grant them. A
bare confirmation never grants new authority.

### "install refused: signed by a different key"

The package is signed by a **different key** than the one bound to this App ID
locally. This Alpha has no authenticated key rotation, so it is refused. Inspect
with `lexe trust show <id>`; only proceed if you understand why the key changed.

## Building and packaging

### `lexe sdk verify` says "symbol-ceiling-exceeded"

Your binary imports a glibc symbol newer than the Core 1 ceiling (2.31) — almost
always because it was built on a newer host. Build it in a Core 1 sysroot
(`sdk/tux32-core-1/build-in-sysroot.sh`) and verify again. This is the check
doing its job, not a bug. The offending symbol/version is named in the output.

### `lexe sdk verify` says "unsupported-executable" or "invalid-input"

Core 1 is a **dynamically linked x86-64 ELF** contract. A static binary, a
script, or a non-x86-64 binary gets a non-portable verdict. Ship a dynamically
linked ELF, or choose a non-portable profile in the builder if that is genuinely
what you want.

### The Builder disables the Build button

You are on the **Core Portable** profile and the source does not satisfy Tux32
Core 1 — the reason (an over-ceiling symbol, a forbidden host-driver interface,
or an unresolved dependency) is shown. Fix it, or pick a different runtime
profile on the profile step (which relaxes the claim honestly).

### `lexe build` says the manifest key does not match the signing key

Set `publisher.publicKey` to `"AUTO"` (or remove it) in your `lexe.json` and let
`lexe build --key <keyfile>` fill it in from your key.

### A dependency shows as "unresolved" or "forbidden"

- **unresolved**: the loader could not find that library. Bundle it in your
  `payload/`, or confirm the host provides it.
- **forbidden**: it is a host GPU/driver interface (libGL, libvulkan, …) that
  must come from the host and must not be bundled. Such an app is not Core 1
  portable without host driver passthrough.

## Getting more detail

- `lexe inspect <file.lexe>` — full package view (identity, verification,
  dependencies, checksum) before installing.
- `lexe analyze <dir> --json` — the raw dependency/compatibility report.
- `lexe apps` — installed apps with version, disk, trust and last run.
- `lexe verify <file.lexe>` — run the verification pipeline stage by stage.
- Add `--json` to most commands for machine-readable output.

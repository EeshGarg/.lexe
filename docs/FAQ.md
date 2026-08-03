# .lexe FAQ

Short, honest answers. For the full picture see the [README](../README.md),
[TUTORIAL.md](TUTORIAL.md), and the [Alpha contract](ALPHA.md).

## What is a `.lexe` file?

A single signed package containing an application: a JSON manifest, the payload,
per-file SHA-256 hashes, and Ed25519 signatures. Double-click it (or run
`lexe install app.lexe`) and the runtime verifies it, shows exactly what it is
and what it can do, and installs it into your home directory.

## Do I need root to install anything?

No. The runtime, and every application you install, live under your home
directory. `packaging/install.sh` and `lexe install` never require root.

## Is my machine sandboxed when I run an app?

On Linux, yes: each app runs inside a bubblewrap sandbox — a read-only
application image, private data/cache/temp, a sanitized environment, and no
network unless you granted the `network` permission. If no isolation backend is
available, the launcher **refuses to run the app** rather than run it
unconfined. Windows is a development/build host only and has no runtime
isolation (it says so plainly).

## Does a valid signature mean the publisher is who they claim?

No — and the runtime never says otherwise. A valid signature proves the package
is consistent with a signing **key**. Trust is local **trust-on-first-use**: the
first time you see a key it is "first-seen", and thereafter the runtime warns if
the key for that App ID ever changes. There is no external identity verification,
and no global revocation, in this Alpha.

## What does "Tux32 Core 1" mean?

It is the frozen portability contract: a dynamically linked x86-64 ELF built
against a glibc symbol ceiling of 2.31. A **Core Portable** package that passes
`lexe sdk verify` runs unchanged on any conforming host. A binary built on a
newer machine that imports newer glibc symbols is *rejected* — the build host is
not allowed to silently become the compatibility target. See [TUX32.md](TUX32.md).

## Will my app run on every Linux distribution?

Only the specific, verifiable Core 1 contract is promised — not "any Linux".
Build to the contract and verify it, and it runs on conforming hosts. That's the
whole point of `lexe sdk verify`.

## How do I package my own app?

Point `lexe-builder` at your compiled folder and follow the wizard, or run
`lexe build ./my-project` on a folder with a `lexe.json` and a `payload/`. See
[TUTORIAL.md](TUTORIAL.md) and [SDK.md](SDK.md).

## Where is everything stored?

Under `$LEXE_HOME` if set, otherwise the XDG locations
(`~/.local/share/lexe`, `~/.cache/lexe`). `lexe apps` shows each app's version,
disk usage, install date and trust; `lexe config path` shows the settings file.

## How do I remove an app, or the runtime?

- An app: `lexe remove <id>` (keeps its data) or `lexe remove <id> --purge-data`.
- The runtime: `packaging/uninstall.sh`. **It never removes apps you installed,
  their data, or your trust records** — that is always a deliberate action.

## Can I script the CLI?

Yes. Most commands take `--json` for stable, plain (never colored) output, and
exit codes are typed (0 ok, 1 runtime, 2 usage, 3 verification, 4 not-found,
5 permission, 6 busy, 7 trust). `lexe sdk verify` returns 0/3 for
conformant/non-conformant. `source <(lexe completion bash)` adds tab completion.

## Is this production-ready?

No. This is an **Alpha**. It is a complete platform to *use* as a developer and
an end user, but Beta features (multi-architecture, language runtimes, GUI
forwarding, repository/root trust tiers) are intentionally out of scope. See
[ALPHA.md](ALPHA.md) for exactly what is and is not claimed.

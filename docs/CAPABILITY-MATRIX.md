# Capability matrix

What the engine can do, which tooling reaches it, and what proves it.

This exists to answer four questions that are easy to get wrong and hard to
notice:

1. **Is there engine functionality no tooling can reach?** A capability with no
   interface is a capability nobody has.
2. **Is anything implemented twice?** The dependency direction is one-way — every
   frontend links `lexe_engine` and reimplements none of it — and a second copy
   of a behaviour shows up here as a row where a GUI does something the engine
   does not.
3. **Does the same thing have two names?** A row whose CLI and GUI cells describe
   different vocabulary is a row where a user has to learn the difference.
4. **What has no automated proof?** The **Automated proof** column is the whole
   point. A row with an engine implementation, two frontends and an empty proof
   cell is a claim, not a capability.

## How to read it

| Symbol | Meaning |
|---|---|
| **yes** | reachable, and the named surface is the one to use |
| **n/a** | deliberately not exposed here — see the row's note |
| **—** | not reachable, and it probably should be (a gap) |

GUI parity is **not** a goal. Developer-only and obscure diagnostic functionality
belongs in the CLI; a consumer frontend that exposed every flag would be worse,
not better. A `n/a` with a reason is a design decision; a `—` is a gap.

The dependency direction this table exists to protect:

```text
                      lexe
                canonical engine
               /       |        \
            CLI    lexe-ui    lexe-builder
```

Never `CLI logic <-> GUI logic <-> engine logic`.

---

## Package lifecycle

| Capability | Engine | CLI | lexe-ui | lexe-builder | Automated proof |
|---|---|---|---|---|---|
| Verify a package (FORMAT §6 pipeline) | `verify/verify` | `lexe verify`, `lexe inspect` | yes — the Install view runs the full pipeline before offering Install | yes — the verify stage of a build | `test_verify.cpp`, `test_hostile_packages.cpp`, acceptance 01, security lane |
| Inspect a package without installing | `package`, `verify` | `lexe inspect`, `lexe info` | yes — drop a `.lexe` on the window | n/a — the builder inspects what it is building | `test_cli_inspect.cpp`, acceptance 01 |
| Install | `install/installer` | `lexe install`, `lexe open` | yes | n/a | `test_installer.cpp`, acceptance 01, lifecycle 01 |
| Launch (sandboxed) | `runtime/launcher` | `lexe run`, `lexe open` | yes — Launch, and the `.lexe` handler | n/a | `test_launcher.cpp`, acceptance 01/08, lifecycle 01 |
| Update | `install/updater` | `lexe update` | yes | n/a | `test_updater.cpp`, integration lane, lifecycle 01 |
| Roll back | `install/installer` | `lexe rollback` | yes | n/a | lifecycle 01, `test_repair_after_rollback.cpp` |
| Repair | `install/installer` | `lexe repair` | yes | n/a | lifecycle 01/02, `test_repair_after_rollback.cpp` |
| Uninstall (3 modes) | `install/installer` | `lexe remove [--purge-data]` | yes — all three modes | n/a | `test_installer.cpp`, lifecycle 01 |
| Reclaim old versions | `install/installer` | `lexe gc` | yes — Reclaim disk, on the Uninstall page, keeping one older version so Roll back still works | n/a | `test_installer.cpp`, `test_ui.cpp`, integration lane |
| List installed applications | `state/registry` | `lexe apps`, `lexe list` | yes — Apps | n/a | `test_cli_apps.cpp`, `test_registry.cpp` |

## Trust and identity

| Capability | Engine | CLI | lexe-ui | lexe-builder | Automated proof |
|---|---|---|---|---|---|
| Signature verification | `package/crypto` | `lexe verify` | yes | yes | `test_crypto.cpp`, `test_ed25519_strict.cpp` |
| Local trust (TOFU), key pinning | `verify/trust` | `lexe trust show/block/unblock/forget` | yes — trust state per application | n/a | `test_trust*.cpp`, integration lane, security lane |
| Truthful trust language | `diagnostics/presentation` | yes | yes — same strings | yes — same strings | `test_presentation.cpp`, `test_package_view.cpp` |
| Detect a changed signing key | `verify/trust` | yes — refuses with `ChangedKeyError` | yes | n/a | `test_trust_adversarial.cpp`, security lane |
| Generate a signing key | `package/crypto` | `lexe keygen` | n/a — consumers do not sign | yes — generate or choose | `test_crypto.cpp`, `test_builder.cpp` |

A valid signature proves the package is intact and that whoever produced it held
the matching private key. It does **not** establish who they are. No surface says
"verified", "trusted" or "safe" about a publisher on its own authority — see
[TRUST-MODEL.md](TRUST-MODEL.md).

## Execution and compatibility

| Capability | Engine | CLI | lexe-ui | lexe-builder | Automated proof |
|---|---|---|---|---|---|
| Native execution | `runtime/launcher` | `lexe run` | yes | n/a | acceptance 01/04 |
| Execution-policy resolution | `runtime/execpolicy` | `lexe compat` | yes — Compatibility | yes — shows what a declared policy will permit | `test_execution_architecture.cpp` |
| Choose a chain (within what the package permits) | `state/appconfig` | `lexe compat --set/--auto` | yes | n/a | `test_execution_architecture.cpp`, acceptance 06/07 |
| See what runtimes this host has | `runtime/execpolicy` | `lexe runtime [show]` | yes — Runtime | yes — warns when the host cannot build | `test_proton.cpp`, acceptance 07 |
| Wine (foreign-OS payload) | `runtime/execpolicy` | yes | yes | yes — declarable | acceptance 06 |
| Proton | `runtime/execpolicy` | yes | yes | yes — declarable | acceptance 07, `test_proton.cpp` |
| ISA translation (FEX, Box64, qemu-user) | `runtime/execpolicy` | yes | yes | yes — declarable | `test_execution_architecture.cpp` only — **no runtime installed here** |
| Layered chains (`proton+fex`) | `runtime/execpolicy` | yes | yes | yes | `test_execution_architecture.cpp` only — needs a host where the translation is real |
| Mission-critical strict mode | `runtime/execpolicy`, `package/manifest` | yes — refuses every compatibility chain | yes — shown as strict, with no alternatives offered | yes — refuses a contradictory manifest at build time | `test_execution_architecture.cpp`, acceptance 07 |
| Declared launch presentation (console/gui/service) | `runtime/launcher` | yes | yes | yes — an Application behaviour selector that states what each choice costs. It emitted NO `launch` block until this wave, so every package it built took the manifest default of `gui` and was granted a display socket, including command-line tools | `test_launcher.cpp`, `test_builder.cpp`, acceptance 08 |

## Portable source

| Capability | Engine | CLI | lexe-ui | lexe-builder | Automated proof |
|---|---|---|---|---|---|
| Package source instead of a binary | `package/manifest` | `lexe build`, `lexe pack` | n/a | yes | acceptance 05, `test_payload_role.cpp` |
| Host-ISA compile at install | `runtime/hostbuild` | `lexe install --approve-compile` | yes — approval beside Install | n/a | acceptance 05, `test_hostbuild.cpp` |
| Explicit compile approval (never implied by `--yes`) | `runtime/hostbuild` | yes | yes — a separate control | n/a | acceptance 05, `test_hostbuild.cpp` |
| Build attestation (`build.json`) | `runtime/buildreport` | `lexe info` | yes — build product information | n/a | acceptance 05, `test_buildreport.cpp` |
| Verify the compiled product before use | `runtime/hostbuild` | yes | yes | n/a | acceptance 05 |
| Rebuild on repair rather than copying | `install/installer` | `lexe repair --approve-compile` | yes | n/a | acceptance 05 |
| **The same package compiling on a second ISA** | designed | — | — | — | **none — this is the open hardware milestone** |

## Isolation

| Capability | Engine | CLI | lexe-ui | lexe-builder | Automated proof |
|---|---|---|---|---|---|
| Sandboxed launch | `sandbox/isolation` | `lexe run` | yes | n/a | `test_isolation*.cpp`, acceptance 01/08 |
| Report what confinement covers | `sandbox/isolation` | `lexe sandbox` | yes — Permissions | n/a | `test_isolation.cpp`, `test_presentation.cpp` |
| Fail closed when confinement is unavailable | `sandbox/isolation` | yes | yes | n/a | `test_isolation_linux.cpp` |
| Permission model | `sandbox/permissions` | yes — `--accept-permissions` | yes | yes — declarable | `test_permissions.cpp` |
| Display access only for a declared GUI | `sandbox/isolation` | yes | yes | yes | `test_isolation_linux.cpp`, `test_security_boundary.cpp`, acceptance 08 |
| Network denied unless granted | `sandbox/isolation` | yes | yes | yes | `test_security_boundary.cpp` |

## Diagnostics and integration

| Capability | Engine | CLI | lexe-ui | lexe-builder | Automated proof |
|---|---|---|---|---|---|
| Structured failure records | `diagnostics/diagnostics` | `lexe errors` | yes — Error History | n/a | `test_health_check.cpp`, acceptance 03, lifecycle 02 |
| Durable desktop integration | `integration/integration` | `lexe integrate`, `lexe doctor` | yes — integration state, repair | n/a | `test_desktop.cpp`, acceptance 02, lifecycle 02 |
| Health check and repair of integration | `integration/integration` | `lexe doctor --repair` | yes | n/a | acceptance 02, lifecycle 02 |
| Launch references (`run.lexe`) | `runtime/launchref` | `lexe launch-ref` | yes — opening one navigates and launches | n/a | acceptance 01, `test_payload_role.cpp` |
| Runtime settings | `base/settings` | `lexe config` | yes — Settings | yes — theme | `test_settings.cpp` |
| Dependency and portability analysis | `analysis/depengine`, `analysis/tux32` | `lexe analyze`, `lexe sdk verify` | n/a — developer-only | yes — dependency review, profile gate | `test_depengine.cpp`, `test_tux32*.cpp`, `test_cli_sdk.cpp` |
| Shell completion | `commands` | `lexe completion bash\|zsh` | n/a | n/a | `test_cli_ux.cpp` |

## Known gaps in this table

Each of these is a `—` above, kept here so the list is one thing rather than
scattered through the tables.

| Gap | Why it matters | Status |
|---|---|---|
| ~~`lexe gc` has no graphical equivalent~~ | | **closed.** `lexe-ui` has a Reclaim disk control on the Uninstall page. It keeps the active version plus one, leads with what is KEPT, and reports a version held by a launch lease as kept rather than silently skipping it |
| ISA translation chains are unit-tested only | the layered-chain vocabulary is broader than anything demonstrated | needs a host where the translation is real; see [TESTING.md](TESTING.md) §6 |
| Cross-ISA portable compilation is unproven | it is the central claim of the portable type | needs real AArch64 hardware; the decisive test is written down in [TESTING.md](TESTING.md) §7 |

## What each frontend is for

**`lexe`** — the command-line interface, and the whole engine's surface. Anything
the engine can do is reachable here; scripts, CI and debugging live here.

**`lexe-ui`** — the consumer and power-user frontend. `.LEXE Menu` and `.LEXE
Error` are views inside this one window, not separate programs. It is the `.lexe`
file handler, and it is deliberately **not** a mandatory launcher: an ordinary
launch stays automatic and invisible.

**`lexe-builder`** — the developer frontend, for producing valid packages of all
three payload kinds without hand-editing JSON. It is a frontend over
`lexe_engine`, with no package-writing logic of its own: the same
`PackageWriter`, the same manifest validation, the same verifier. If it offers
something the verifier or runtime would reject, that is a bug in the builder.

The alpha's third frontend, `lexe-installer`, is gone. `lexe-ui` is the handler,
and the install/consent view model the two once shared by `#include`-ing each
other's translation unit now lives in `src/gui/package_view.hpp`, which both
include as a header and neither owns.

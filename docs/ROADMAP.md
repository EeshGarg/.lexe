# Roadmap — what is not done, and how to start

The authoritative statement of what the runtime does NOT do is
[DEFINITIVE-ARCHITECTURE.md](DEFINITIVE-ARCHITECTURE.md) §15. This file adds the
"where to start" half, and it is ordered by how much each item would change what
`.LEXE` can honestly claim.

What proves a capability, rather than merely implementing it, is in
[TESTING.md](TESTING.md). What reaches it through which tool is in
[CAPABILITY-MATRIX.md](CAPABILITY-MATRIX.md).

---

## 1. Portable code on a second ISA — the open hardware milestone

Everything about the portable type is implemented, tested and demonstrated except
the one thing it exists for: **every build so far has happened on x86_64.**

"The same `.lexe` compiles on ARM64 too" is the whole promise of the type, and no
amount of code closes it. The decisive test is written down in
[TESTING.md](TESTING.md) §7:

> Take the exact same signed portable-source `.lexe` to an x86_64 host and an
> AArch64 host. Install it on each. Verify that each machine independently
> produces a native ELF **for its own ISA**, with its own `build.json` recording
> its own toolchain and product hash. Execute both successfully.

**Emulation is not a substitute.** Producing an AArch64 binary under `qemu-user`
on an x86_64 host does not demonstrate the claim; it demonstrates qemu. What
emulation IS worth doing first, because it is cheap and covers a path currently
reachable only through synthesized ELFs in unit tests: build a portable package
under `qemu-user` with an aarch64 sysroot and confirm the runtime REFUSES the
result, because "this output targets a machine that is not the builder's" is a
real rejection that deserves a real test.

Where it lives: `runtime/hostbuild.{hpp,cpp}`, `tests/test_hostbuild.cpp`,
`tests/acceptance/05_portable_compile.sh`.

## 2. ISA translation chains

`fex`, `box64`, `qemu-user` and the layered forms (`proton+fex`, `wine+box64`)
are manifest vocabulary the resolver understands and that nothing has ever
executed. They are covered by unit tests over synthesized provider sets, which
proves the resolver's decisions and nothing about the runtimes.

This is the same class of gap as item 1 and wants the same thing: a host where the
translation is real. On x86_64, `fex` translating x86_64 would be a no-op even if
installed.

Where it lives: `runtime/execpolicy.cpp` (`provider_specs`, `layered_chain`).

One thing worth checking when such a host exists: the argv order of a layered
chain. `layered_chain()` builds `{inner, outer}` and the chain id is documented
as outermost-first; on a real ARM host running an x86_64 Windows program the
correct invocation is `FEXInterpreter wine app.exe`, and whether the current
order produces that has never been executed.

## 3. The reboot boundary and real desktop integration

`tests/acceptance/REBOOT.md` is the one acceptance criterion an automated run
cannot close. It needs a real Linux desktop session, a real file manager, and a
real reboot.

Under WSL, `lexe doctor` and the integration suites work against a scratch
`LEXE_HOME` — which is exactly what they were built to do, and
`tests/acceptance/02_persistence.sh` destroys installed state and demands that
`doctor` name each missing artifact before repairing it. What cannot be shown
here is the part that only a login sequence exercises: that the handler
registration and the default association survive a reboot, and that
double-clicking a `.lexe` in a file manager opens it.

Persistence is part of correctness. The alpha installed and launched perfectly and
then did not survive a reboot.

## 4. `service` launch mode and the session manager

`launch.mode: "service"` works: `tests/lifecycle/03_service.sh` demonstrates that
it detaches without being asked, that the sandbox supervisor outlives the
launcher, that it holds a version lease so uninstalling a running service is
refused rather than silently killing it, that an update leaves the running
version's files alone, that SIGTERM produces a distinguishable clean stop, that
SIGKILL does not, and that the lease dies with its holder so nothing is stranded.

What does **not** exist is any integration with a session manager, and the reason
is worth stating precisely because it was previously recorded as an environment
limitation:

```
$ grep -rl systemd src/lexe/
$
```

Nothing. The development notes said this was unprovable because WSL has no
systemd user session — and WSL2 with systemd enabled turns out to have a running
one (`systemctl --user is-system-running` answers `running`). So the gap is a
missing feature, not a missing machine.

It is a design question before it is a task. A service that only runs while a
login session exists is a different product from one that starts at boot, and a
`.LEXE` service is deliberately an unprivileged, sandboxed, user-owned thing —
which is a poor fit for half of what people mean by "service". Decide what is
being promised before implementing a unit generator.

Where it lives: `runtime/launcher.cpp` (the detach path), `sandbox/isolation.cpp`
(`plan.detach`, `supervisor_lock_file`).

## 5. Signer tiers beyond local trust

The trust model today is local trust-on-first-use: a key is pinned on first
install and a change is refused. [TRUST-MODEL.md](TRUST-MODEL.md) §4 describes
signer CLASSES, and only two of them are real ("first seen" and "locally
trusted", plus the machine-local signer that produces launch references).

Anything beyond that — a publisher whose real-world identity is established by
some separate mechanism — needs that mechanism to exist first. Until it does, the
wording stays as it is: a valid signature proves integrity and possession of a
private key, and nothing about who holds it.

## 6. A graphical way to reclaim disk

`lexe gc` has no equivalent in `lexe-ui`, so a consumer cannot reclaim disk from
retained old versions without the command line. The engine call is
`Installer::garbage_collect`, it is lease-aware and conservative, and the Apps
view already shows per-application disk usage — this is a missing control, not
missing behaviour. Tracked in [CAPABILITY-MATRIX.md](CAPABILITY-MATRIX.md).

## 7. Fuzzing the parsers

The deterministic adversarial cases are established: `tests/test_package.cpp`,
`tests/test_hostile_packages.cpp`, `tests/test_security_boundary.cpp` and
`tests/security/run_all.sh` attack the container, the manifest, the generated
documents and the installed state. The parser boundaries are now suitable for
fuzzing, and `clang` is available.

The three worth starting with, in order of what an attacker reaches first:
`PackageReader` (a ZIP from anywhere), `Manifest::parse` (attacker-controlled
JSON), and the `elf` / `pe` readers (attacker-controlled binaries, both already
written to be bounds-checked and never to over-read).

---

## Things that are deliberately finished

Listed in [CONTRIBUTING.md](../CONTRIBUTING.md) under "Decisions that are
settled". They are settled because the other way round was tried or nearly
shipped — not because nobody has thought about them since.

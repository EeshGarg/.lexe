# Next steps, in priority order

Each item says what is missing, why it matters, and where to start. The
authoritative statement of gaps is §15 of `docs/DEFINITIVE-ARCHITECTURE.md`;
this file adds the "how to start" half.

---

> **Item 1 is DONE** (2026-09-25). It is kept below, struck through at the top,
> because the entry points it names are still the right map of where the
> feature lives. What remains of it is item 1b.

## 1b. Portable code on a second ISA

The portable path is implemented, tested and documented — see
`docs/DEFINITIVE-ARCHITECTURE.md` §5A, `src/core/hostbuild.{hpp,cpp}`,
`tests/test_hostbuild.cpp` and `tests/acceptance/05_portable_compile.sh`.

What is left is the part no amount of code closes: **every build so far has
happened on x86_64.** "The same `.lexe` compiles on ARM64 too" is the whole
promise of the type and it is unproven on hardware. This is the same class of
gap as item 3 below, and it wants the same thing: an ARM64 machine.

Cheaper than hardware, and worth doing first: a portable package built under
`qemu-user` + an aarch64 sysroot would at least exercise the
"output targets a machine that is not the builder's" refusal path, which is
currently only covered by unit tests with synthesized ELFs.

---

## ~~1. Portable code and host-ISA compilation — §5 and §7~~ (DONE)

**~~The largest remaining gap.~~** ~~`applicationType` still accepts only `"native"`.~~

The architecture's promise is that one `.lexe` becomes native to the machine it
lands on, instead of being three architecture-specific packages bundled
together:

```
        SAME App.lexe
              |
    +---------+---------+
    |         |         |
  x86-64    ARM64    RISC-V
    |         |         |
  compile  compile  compile
    |         |         |
    +---------+---------+
              |
        Native Linux
```

Required properties, all of them:

* `ADMIN COMPILE APPROVAL` gates the **operation**;
* the build runs **unprivileged**, inside an **isolated** environment;
* the output is **verified** as a host-ISA native executable before it is used;
* approval authorizes the operation — it does **not** give build code root.

**Where to start**

| File | Why |
|---|---|
| `docs/FORMAT-0.1.md` §5/§6 | extend the normative manifest first — what a portable package declares (source layout, build recipe, toolchain contract) |
| `src/core/manifest.cpp` | `applicationType` validation is one place; role-conditional field requirements already exist as a pattern to copy |
| `src/core/verify.cpp` | the `payload-role` stage is where a portable package validates a SOURCE payload instead of requiring an ELF |
| `src/core/isolation.hpp` | `build_plan()` is pure and testable; a build sandbox is a network-denied, writable-output variant of the launch sandbox |
| `src/core/execpolicy.cpp` | the resolver already has the shape for "portable source → host-ISA compile → native" |
| `src/core/installer.cpp` | compilation is an install-time step, before promotion, inside the existing transaction |

**Watch out for:** the compile output must go through the same integrity
recording as an extracted payload, or the launcher's post-install hash check
will reject it. Decide deliberately whether the compiled result is hashed into
the per-version meta store (probably yes — it makes repair and tamper detection
work identically for both package types).

> **How it was resolved:** the compiled entrypoint is hashed into
> `meta/<version>/build.json`, keyed exactly like `hashes.json`. The launcher
> consults that record and FAILS CLOSED when a portable application has no
> recorded product hash — the alternative was leaving the binaries the runtime
> compiled itself as the only ones it never noticed being replaced. Repair
> counts the products in its expected set and rebuilds them, because they
> cannot be copied back out of a package that never contained them.

---

> **Item 2 is DONE** (2026-09-25) — declarable, verified, and a Windows console
> program really runs under Wine, proven by `tests/acceptance/06_foreign_os.sh`.
> What is left is narrower; see 2b.

## 2b. The parts of the foreign-OS path still unproven

* **Proton, and layered chains.** Only Wine has been exercised. Proton is
  selected, argv-prefixed and reported by the same code, which is an argument,
  not evidence. `proton+fex` has never run at all. Installing Proton is
  awkward (it ships inside Steam); a hand-placed Proton tree would at least
  exercise the "layer outside /usr is bound into the sandbox" path, which is
  currently only a unit test.
* **A GUI Windows application.** The proof is a console program. A graphical
  one needs the display socket to reach Wine's graphics driver — the same §5
  display grant, untested through a compatibility layer. Note the headless
  rule: any test of this brings its own synthetic display.
* **32-bit payloads cannot be declared at all**, because FORMAT-0.1 §5
  recognises only `x86_64` and `aarch64`. A 32-bit Windows program — still
  common — is refused by name. Adding an `i386` architecture id is a format
  change; decide deliberately rather than drifting into it.
* **Wine's 32-bit half.** A 64-bit-only Wine prints a "wine32 is missing"
  warning during prefix setup and continues. It is noise in the captured
  output of every foreign-OS launch on such a host, and worth understanding
  before someone reads it as a `.LEXE` failure.

---

## 3. Real cross-ISA validation

Chain selection, argv prefixing and provider probing are unit-tested with
**synthetic** provider sets. No FEX or Box64 run has happened on real ARM64
hardware. Until it does, treat §8's cross-ISA claims as designed-but-unproven.

---

## 4. `service` launch mode

Parsed, carried through the manifest and recorded in the execution report, but
it does **not** detach or integrate with the session manager — it currently
behaves like a non-GUI foreground launch. `RunRequest::detach` exists as the
seam. Decide whether a service is a systemd user unit (durable, correct,
more work) or a plain detached process (simpler, weaker).

---

## 5. Signer tiers beyond local trust — §4

`Usha Verified` and `Organization Signed` are implemented as **explicitly
unavailable**, with reasons, because there is no signing authority and no
organizational attestation mechanism. That is honest and should stay honest —
do not make them assignable without the infrastructure that would justify them.

If/when a signing authority exists: `presentation::classify_signer()` is the one
place that maps trust state to a class, and `signer_classes()` carries the
availability flags the frontends already render.

---

## 6. Smaller, worth doing

* **Run the manual reboot checklist** (`tests/acceptance/REBOOT.md`) and record
  the result. This is the one acceptance criterion an agent cannot close — and
  on the current machine (see [MACHINE.md](MACHINE.md)) it needs a real Linux
  desktop, which WSL does not provide.
* **Click through `lexe-ui`** once — Compatibility→Apply, the three Uninstall
  modes, the Error History buttons. Their wiring was reviewed and their view
  models are tested, but no human has pressed them.
* **Surface the compile approval in the GUIs.** `lexe-ui` and `lexe-builder`
  have no equivalent of `--approve-compile`: installing a portable package
  through them will be refused with the CLI's message and no way to say yes.
  The frontends already render permission consent; this is the same shape.
  `InstallOptions::approve_compile` is the seam, `probe_toolchain()` gives the
  dialog its "what this machine will run" line, and the refusal text in
  `hostbuild.cpp` is the wording to reuse rather than reinvent.
* **`lexe-builder` cannot build a portable project.** It writes
  `applicationType: "native"` unconditionally (`src/gui/builder.cpp`) and has no
  UI for the `build` block.
* ~~**Install the missing dev tooling**~~ — done, see [MACHINE.md](MACHINE.md).
  bubblewrap, GTK 3, valgrind, strace, xvfb, ccache and unzip are all present
  in WSL now, so nothing is skipped for want of a tool.
* **Push the commits** — see the constraints section of `HANDOFF-PROMPT.txt`.
* **`lexe-ui` Settings → theme** is persisted but not applied to the running UI.
* **Update `docs/ALPHA.md`** — the alpha support contract predates all of this.

---

## Things that are deliberately finished, don't "improve" them

* **The truthful-wording discipline.** Nothing says "verified", "trusted"
  (unqualified), "safe" or "secure" on its own authority. Unavailable
  capabilities are shown as unavailable with reasons rather than omitted. This
  reads as over-cautious until you remember the alternative is lying to a user
  about what a signature proves.
* **The headless test rule.** No automated test may put a window on the user's
  screen. See `tests/acceptance/lib.sh`.
* **One implementation of desktop registration.** `packaging/install.sh` calls
  `lexe integrate`; it must never hand-roll MIME XML again. `core/desktop` is
  content generation only — the second copy that used to live there is gone,
  and `tests/test_desktop.cpp` pins that it stays gone.
* **Fail-closed isolation.** A backend that should work but does not never
  degrades to an unconfined launch — and, since the portable work, never
  degrades to an unconfined *build* either.
* **Approval is not consent to everything.** `--approve-compile` is separate
  from `--yes`, from `--accept-permissions` and from `--trust` for the same
  reason those three are separate from each other: each authorizes one specific
  thing. Do not collapse them into a single "yes".

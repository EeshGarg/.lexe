# Next steps, in priority order

Each item says what is missing, why it matters, and where to start. The
authoritative statement of gaps is §15 of `docs/DEFINITIVE-ARCHITECTURE.md`;
this file adds the "how to start" half.

---

## 1. Portable code and host-ISA compilation — §5 and §7

**The largest remaining gap.** `applicationType` still accepts only `"native"`.

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

---

## 2. Foreign-OS payloads — §8

The resolver knows the Wine/Proton chain shapes, probes for the providers, and
will select and argv-prefix them. But **no package can currently declare a
foreign-OS payload**, so those chains are unreachable in practice on a 0.1
manifest. They are real code paths with real provider probing — not stubs — but
untested against an actual Windows binary.

Start at `docs/FORMAT-0.1.md` §5.3 (`applicationType`), then
`src/core/execpolicy.cpp` (`resolve_chain`'s `linux_native` check already exists
precisely so a future foreign-OS type cannot slip through the strict resolver).

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
  the result. This is the one acceptance criterion an agent cannot close.
* **Click through `lexe-ui`** once — Compatibility→Apply, the three Uninstall
  modes, the Error History buttons. Their wiring was reviewed and their view
  models are tested, but no human has pressed them.
* **Install the missing dev tooling** when a password is available:
  `sudo dnf install libasan libubsan valgrind ccache strace xorg-x11-server-Xvfb`.
  Xvfb in particular unblocks `scripts/gui-smoke.sh` locally (CI already has it).
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
  `lexe integrate`; it must never hand-roll MIME XML again.
* **Fail-closed isolation.** A backend that should work but does not never
  degrades to an unconfined launch.

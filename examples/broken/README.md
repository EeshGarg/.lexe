# Packages that are supposed to be refused

A verifier is only as good as what it turns away, and "it rejected something" is
not interesting on its own. *Which* stage caught it, and what it told the
developer, is.

Each of these is a real project folder, wrong in exactly **one** way, with the
refusal it should produce written down beside it. Try them:

```sh
lexe keygen /tmp/key.json
lexe build examples/broken/wrong-architecture -o /tmp/broken.lexe --key /tmp/key.json
```

They are deliberately **not** a test harness. The byte-level adversarial matrix —
path traversal, symlink escape, duplicate entries, tampered hashes, signature
substitution, abusive archive structure — lives in
[../../tests/security/](../../tests/security/) and
[../../tests/test_security_boundary.cpp](../../tests/test_security_boundary.cpp),
where it can be exhaustive without needing to be readable. These are the handful a
developer will actually hit **by accident**, kept short enough to read.

---

## `wrong-architecture/`

Declares `architectures: ["aarch64"]` and ships an x86_64 binary.

**Caught by:** the `payload-role` verification stage, before install.

**Why it matters more than it looks:** this is the failure mode a cross-compiling
build script produces when it silently falls back to the host compiler. The
manifest is not lying on purpose; it is lying because the build did something
different from what the developer thought. Catching it at verification rather than
at launch means the package never reaches a user whose machine cannot run it.

```
[FAIL] payload-role  applicationType "native" declares "bin/app" as the
                     entrypoint, but those bytes target x86_64 and the manifest
                     declares only aarch64
```

## `source-as-native/`

Declares `applicationType: "native"` and ships `src/main.c` as the entrypoint —
source code where a compiled program should be.

**Caught by:** the `payload-role` stage.

**Why:** this is the honest mistake that the `portable` type exists to serve. The
refusal says so, rather than saying "invalid package":

```
[FAIL] payload-role  applicationType "native" declares "src/main.c" as the
                     entrypoint, but those bytes are not an ELF object (a native
                     package must contain a COMPILED executable — source files
                     belong in a portable-code package)
```

The same shape of error caught two of this project's own integration test
scripts, which had been declaring a shell script as a native entrypoint since the
stage was added. See the note at the top of
[../../tests/integration/ws8_ws9_lifecycle.sh](../../tests/integration/ws8_ws9_lifecycle.sh).

## `dll-entrypoint/`

An `applicationType: "windows"` package whose entrypoint is a `.dll` rather than
an `.exe`.

**Caught by:** the `payload-role` stage, which reads the PE characteristics.

**Why:** a DLL is a perfectly valid PE image. It is not a program — nothing can
execute it as one — so "is this a runnable Windows executable?" is a different
question from "is this a PE?", and the verifier asks the one that matters.

```
[FAIL] payload-role  applicationType "windows" declares "bin/lib.dll" as the
                     entrypoint, but that image is a DLL and not an executable
```

---

## Three more that cannot be a folder here

These are refused at BUILD time rather than at verification, which is better —
they never become a package at all — so there is nothing to ship as a specimen.
They are in the test suites instead.

| Mistake | What happens |
|---|---|
| a `windows` package permitting only the `native` chain | refused by the manifest parser: nothing can run a Windows payload natively, so a policy that permits no foreign-OS chain is a contradiction rather than a restriction |
| a `missionCritical: true` package permitting `wine` or `proton` | refused by the manifest parser. Mission-critical means Linux-native, host-ISA-native, no compatibility layer — declaring both is declaring two different things |
| a version with whitespace in it, e.g. `"1.0.0 "` | refused by the manifest parser. It used to be accepted, and `apps/<id>/current.txt` is read back trimmed — so the runtime resolved a current version whose directory did not exist and the application could not launch. See `base/identity.hpp` |

# Tutorial — a `.lexe` from analyze to remove

One canonical walkthrough of the whole developer + user path, using the shipped
[reference application](../sdk/tux32-core-1/reference-app/): **analyze → SDK
verify → build → inspect → install → launch → data persistence → remove**. Every
step here is exercised end to end from a fresh checkout by
[`scripts/portability-demo.sh`](../scripts/portability-demo.sh) and the clean-room
lifecycle check, so it is a real path, not an aspirational one.

Prerequisites: the runtime is built and installed (README *Quick install*), so
`lexe`, `lexe-builder` and `lexe-installer` are on your `PATH`. On Linux you also
need `bubblewrap` for the launch step. Confirm your versions:

```console
$ lexe version
lexe 0.1.0-alpha
  runtime:        0.1.0-alpha
  package format: 0.1 (.lexe FORMAT-0.1)
  Tux32 baseline: tux32-core-1 (spec 1)
```

## 1. Build the reference app's payload

The reference app is a small, dynamically linked C program that links `libm`,
keeps a persistent launch counter, and writes to its private cache and temp
dirs. Compile it into `payload/bin/` (its `Makefile` does this):

```console
$ make -C sdk/tux32-core-1/reference-app
$ file sdk/tux32-core-1/reference-app/payload/bin/portable-probe
ELF 64-bit LSB pie executable, x86-64, dynamically linked, ...
```

## 2. Analyze the dependencies

`lexe analyze` reads the ELF directly (never `ldd`) and classifies every
dependency — host-interface vs. bundle vs. forbidden vs. unresolved:

```console
$ lexe analyze sdk/tux32-core-1/reference-app
Runtime profile: Core Portable (maximum portability)
Dependencies:    ... — N host, 0 bundle, 0 forbidden, 0 unresolved
...
```

## 3. Verify Tux32 Core 1 portability

`lexe sdk verify` gives a typed verdict and a typed exit code. **Build host
matters**: a binary built against a glibc newer than the 2.31 ceiling is
*honestly rejected*, even though it links fine on your machine —

```console
$ lexe sdk verify sdk/tux32-core-1/reference-app --json ; echo "exit=$?"
{ "verdict": "symbol-ceiling-exceeded", "requiredGlibc": "2.34", ... }
exit=3
```

To get a `conformant` verdict, build the payload inside a Core 1 sysroot
(glibc ≤ 2.31) instead of on your newer host:

```console
$ sdk/tux32-core-1/build-in-sysroot.sh sdk/tux32-core-1/reference-app
$ lexe sdk verify sdk/tux32-core-1/reference-app --json ; echo "exit=$?"
{ "verdict": "conformant", "requiredGlibc": "2.7", ... }
exit=0
```

Exit `0` is the only case a build may claim the Core Portable profile; the
Builder enforces exactly this gate. See [TUX32.md](TUX32.md).

## 4. Build and inspect the signed package

Generate a signing key, then build a signed `.lexe`. The manifest's
`publisher.publicKey` is `"AUTO"`, so `lexe build` fills it from your key:

```console
$ lexe keygen mykey.json
$ lexe build sdk/tux32-core-1/reference-app -o probe.lexe --key mykey.json
$ lexe info probe.lexe
Package: probe.lexe (...)
  Name:        Tux32 Core 1 Reference Probe
  Version:     1.0.0
  Fingerprint: ...
  ...
```

`lexe info` shows what a user would see before installing — identity, signing
fingerprint, type/architecture, and declared permissions.

## 5. Install

Installation verifies the signature and every payload hash over the exact bytes
before anything is written, then installs into your home directory. `--trust`
accepts this new publisher key on first use (trust-on-first-use):

```console
$ lexe install probe.lexe --yes --trust
Installed Tux32 Core 1 Reference Probe 1.0.0 (org.lexe.reference.probe)
$ lexe list
org.lexe.reference.probe   1.0.0   ...
```

## 6. Launch (under isolation) and see data persist

On Linux, `lexe run` launches the app inside the bubblewrap sandbox — a
read-only image, a private writable data/cache/temp, a sanitized environment,
and no network (the probe needs none). Run it twice and watch the **persistent
counter advance**, proving per-app data survives across launches:

```console
$ lexe run org.lexe.reference.probe
Tux32 Core 1 reference probe
  app id:        org.lexe.reference.probe
  launch count:  1  (persisted at /run/lexe/data/state.txt)
  ...
  status:        OK
$ lexe run org.lexe.reference.probe
  ...
  launch count:  2  (persisted at /run/lexe/data/state.txt)
```

`/run/lexe/data` is the in-sandbox path; on the host it is your per-app data
directory. If no isolation backend is available, `lexe run` **fails closed** and
refuses to launch rather than running the app unconfined.

## 7. Remove (and the data-preservation rule)

Removing the app leaves its data in place by default — you opt in to deleting it:

```console
$ lexe remove org.lexe.reference.probe            # keeps data
$ lexe remove org.lexe.reference.probe --purge-data --yes   # also deletes data
```

Likewise, **uninstalling the runtime** (`./packaging/uninstall.sh`) never removes
installed applications, their data, or your local trust records — that is always
a deliberate, explicit action.

---

Next: package your own app the same way (`lexe build <your-project>` with a
`lexe.json` + `payload/`), or drive the whole flow graphically with
`lexe-builder`. See [SDK.md](SDK.md) and [ALPHA.md](ALPHA.md).

# Security policy

`.lexe` is a signed application format and a userspace runtime whose whole
purpose is to make a security claim precise. It therefore has a written
[threat model](docs/THREAT-MODEL.md), a written [trust model](docs/TRUST-MODEL.md)
and a written [isolation contract](docs/ISOLATION.md), and this policy is read
against those three documents rather than against a general expectation of
"secure".

> **Stage: Developer Alpha.** `0.1.0-alpha` is **not production-ready** and has
> not had an external security audit. It is published so that its design can be
> reviewed and its failures found. See [docs/ALPHA.md](docs/ALPHA.md) for the
> exact support contract.

## Supported versions

There is exactly one line, and it is the development line.

| Version | Axis | Status |
|---|---|---|
| `0.1.0-alpha` (runtime, `lexe version`) | runtime / CLI | The only supported line. Source-only; fixes land on `main`, not in a backport branch. |
| `0.1` (package format, FORMAT-0.1) | package format | Stable for this line; a format change bumps `lexeVersion`. |
| `tux32-core-1` (spec `1`) | portability baseline | Frozen. |

These three axes are deliberately distinct and are never conflated
([COMPATIBILITY.md](docs/COMPATIBILITY.md)). There are no prebuilt binaries and
no older releases, so a report is assessed against current `main`. "Supported"
here means the report is read and acted on — it does not mean the runtime is fit
for production use.

Linux x86-64 with bubblewrap and unprivileged user namespaces is the supported
runtime host. **Windows is a build and test host with no isolation of any kind**,
and its lack of containment is out of scope (see below).

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting.** Open the repository's
**Security** tab and choose **Report a vulnerability**, or go straight to
[github.com/EeshGarg/.lexe/security/advisories/new](https://github.com/EeshGarg/.lexe/security/advisories/new).
That channel is private to you and the maintainer, needs no email address, and
keeps the report out of the public tracker until there is a fix to describe.

**Please do not open a public issue for a suspected vulnerability**, and do not
post one in a pull request, a discussion, or a comment on an unrelated issue.
Public issues are the right place for ordinary bugs — see
[.github/ISSUE_TEMPLATE](.github/ISSUE_TEMPLATE) — but a working bypass of
verification, trust, consent or isolation should arrive privately first.

There is no security email address. If GitHub's private reporting is unavailable
to you, open a public issue that says only that you have a security report and
asks for a private channel: no details, no reproducer.

### What to include

The more of this a report carries, the faster it can be confirmed or refuted:

- **Which boundary you believe was crossed**, in the terms this project already
  uses: a row of the [threat model table](docs/THREAT-MODEL.md), a guarantee in
  [ISOLATION.md](docs/ISOLATION.md), or a stage of the FORMAT-0.1 §6 verification
  pipeline.
- `lexe version --json`.
- Distribution and kernel (`uname -a`), and whether `bwrap` and unprivileged user
  namespaces are available.
- The exact commands and their full output (`--json` where the command supports
  it).
- A minimal reproducer. For a parsing or verification finding, the smallest
  `.lexe` (or the raw bytes) that triggers it is worth more than a description;
  the hostile-package corpus in `tests/test_hostile_packages.cpp` shows the shape
  such cases take in this repository.
- What you believe an attacker gains, and from what starting position.

Please **do not send real private keys**, credentials, or personal data. Generate
a throwaway keypair with `lexe keygen` for any reproducer that needs one.

Test only against your own machine and your own packages. Nothing here authorises
testing against anyone else's system; the [LICENSE](LICENSE) permits reading this
source for evaluation, review and security research, and grants nothing beyond
that.

## What to expect

This is a one-person Developer Alpha. Rather than publish a response-time
commitment that cannot be staffed, here is what is actually true:

- Reports are read and triaged as time allows. **There is no response-time SLA**,
  and none is implied.
- You will be told which of three things a report is: in scope and confirmed, in
  scope but not reproduced, or one of the documented non-guarantees below — with
  the reasoning, not just a verdict.
- A confirmed fix ships the way every change in this project ships: with a
  regression test that fails without it, green on Linux (GCC) and Windows (MSVC),
  and — for a security-relevant change — the evidence bundle required by
  [HARDENING.md § I](docs/HARDENING.md). Where a finding contradicts a documented
  claim, the documentation is corrected in the same change.
- A GitHub Security Advisory is published where a report warrants one, and the
  fix is recorded in [CHANGELOG.md](CHANGELOG.md).
- Credit is given in the advisory and the changelog if you want it, and withheld
  if you do not.
- **There is no bug bounty and no payment.**

## Scope

### In scope

Anything that breaks a guarantee the runtime actually makes:

- **Verification bypass** — getting a modified, truncated, unsigned or
  wrongly-signed package past `lexe verify`, `lexe install` or `lexe update`; any
  path where a byte is trusted or written before the FORMAT-0.1 §6 pipeline has
  accepted it.
- **Signature handling** — non-canonical or malleable Ed25519 acceptance, or
  signing and verifying over anything other than the exact stored entry bytes.
- **Package parsing** — memory-unsafety, path escape (`..`, absolute paths,
  symlink entries, case collisions), decompression bombs, duplicate-key JSON
  acceptance, or any write outside the store while handling a hostile package.
- **Trust-record handling** — accepting a changed signing key for a known App ID,
  silently repairing or recreating a corrupt record, App-ID substitution, or a
  symlinked trust record being followed.
- **Consent bypass** — an application gaining a permission without the explicit
  consent gate, or a flag or code path that grants new authority on a bare
  confirmation.
- **Isolation escape on Linux with a working backend** — reading the user's home,
  reading another application's data, writing the read-only application image,
  reaching the network without the `network` permission, or inheriting
  `LD_PRELOAD`-class variables into the sandbox.
- **Fail-closed failures** — any path where the launcher runs an application
  unconfined when isolation is required, or reports containment it did not
  establish.
- **Lifecycle and concurrency** — TOCTOU between launch, update, rollback and
  uninstall; lock or launch-lease bypass; a crash leaving partial or
  attacker-influenced state in the store.
- **Dishonest reporting** — the runtime or a GUI describing a control as
  enforced, a publisher as verified, or a package as safe, when it is not. In a
  project whose defining rule is that it does not overstate, that is a defect in
  its own right ([TRUST-MODEL.md](docs/TRUST-MODEL.md)).

### Out of scope

These are **documented non-guarantees**, not vulnerabilities. They are already
written down, and a report that restates one will be answered with a link rather
than a fix:

- **No seccomp filter** in 0.1. An application has syscall latitude inside the
  sandbox by design, and no syscall-level restriction is claimed
  ([ISOLATION.md](docs/ISOLATION.md)).
- **`user-files-selected` is advisory** — accepted and recorded, never enforced,
  and it grants no host path.
- **No GUI forwarding.** The sandbox is headless in 0.1; no display, Wayland/X or
  D-Bus socket is bound into it.
- **Windows has no isolation and no cross-process locking.** It is a build and
  test host; applications there run directly and are reported truthfully as
  `policy-unsupported`.
- **No authenticated key rotation and no global revocation.** A stolen but
  already-trusted publisher key can sign updates that pass authenticity and
  continuity until the user blocks it locally with `lexe trust block`
  ([THREAT-MODEL.md](docs/THREAT-MODEL.md), row 10).
- **Trust on first use is local and unverified.** A valid signature proves
  key-continuity, never a real-world identity, website ownership, reputation or
  safety, and the first binding for an App ID is trusted on sight.
- **Trust tiers 2 and 3** (repository endorsement, root accreditation) are
  **design only** ([TRUST.md](docs/TRUST.md)) and unimplemented; their absence is
  not a finding.
- **An attacker who already controls the local account or filesystem** is outside
  the trust boundary. Deleting a trust record to force an App ID back to
  first-seen, for example, is a local-compromise scenario the runtime does not
  claim to survive.
- **Kernels with unprivileged user namespaces disabled**, or a host without
  bubblewrap: the launcher refuses to run rather than running unconfined. That
  refusal is the intended behaviour, not a denial of service.
- **Third-party components.** Report issues in glibc, libsodium, GTK, bubblewrap,
  curl, miniz, nlohmann/json, PicoSHA2 or orlp/ed25519 to their upstreams; the
  inventory is [SBOM.md](docs/SBOM.md). A finding in *how this project uses* one
  of them is in scope.
- **Infrastructure.** There is no hosted service, package repository, update
  server or prebuilt binary in this line — the Alpha is source-only
  ([ALPHA.md](docs/ALPHA.md)). There is nothing there to test.
- **Scanner output with no demonstrated impact** on one of the boundaries listed
  above.

## Where the design is written down

| Document | What it settles |
|---|---|
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | The adversaries, each mitigation, and the residual risk left over |
| [docs/TRUST-MODEL.md](docs/TRUST-MODEL.md) | What a signature does and does not prove; the local TOFU rules |
| [docs/ISOLATION.md](docs/ISOLATION.md) | The enforcement matrix and the exact guarantees and non-guarantees |
| [docs/FORMAT-0.1.md](docs/FORMAT-0.1.md) | The package format and the §6 verification pipeline |
| [docs/HARDENING.md](docs/HARDENING.md) | The normative hardening gates and the evidence a fix must carry |
| [docs/ALPHA.md](docs/ALPHA.md) | What this Alpha claims, and what it explicitly does not |

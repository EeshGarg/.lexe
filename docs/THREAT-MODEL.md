# Threat Model (runtime-trust milestone)

Scope: the `.lexe` reference runtime with trust (WS3/WS4), permissions (WS2/WS5),
isolation (WS6/WS7), storage lifecycle (WS8) and concurrency (WS9) in place. This
enumerates the adversaries the runtime defends against, what is mitigated, and —
just as important — what is **not**. Be conservative: a valid signature proves
consistency with a key, not the safety or identity of the publisher.

Trust boundaries: the package file (untrusted input); the installed store under
`<LEXE_HOME>` (integrity-checked, installer-owned); the local trust records
(`<LEXE_HOME>/trust`, outside package control, never in the sandbox); the running
application (untrusted code, confined by isolation); the host OS and kernel
(trusted TCB); the user (makes the trust-on-first-use and permission decisions).

| # | Threat | Mitigation | Residual / non-guarantee |
|---|---|---|---|
| 1 | **Malicious package author** ships hostile code | Package runs only inside the isolation sandbox (WS7): read-only app image, private data/cache/temp, sanitized env, network denied unless `network` is granted. Permissions are an explicit, consented, frozen vocabulary (WS2/WS5). | Advisory permissions (`user-files-selected`) are not enforced in 0.1; no seccomp filter; the app is still arbitrary code within the sandbox. |
| 2 | **Tampered package** (bytes modified after signing) | §6 pipeline verifies structure, manifest, key, both signatures over exact bytes, and every payload hash BEFORE any byte is trusted or written. Any change fails closed (exit 3). | — |
| 3 | **Publisher-name impersonation** (identical display name, attacker key) | Identity shown to the user is the signing-key **fingerprint**, never the free-form publisher string. A different key for a known App ID is a changed-key refusal regardless of matching name (WS4). | On a genuine *first* install the user has only TOFU — the real-world identity behind a first-seen key is not verified. |
| 4 | **Signing-key substitution** (attacker's key claims a known App ID) | Local App-ID↔key continuity: a changed key is refused (`ChangedKeyError`, exit 7) at install/update, and cannot inherit retained data; the installed-record key pin is defense-in-depth even if trust was forgotten. No `--yes`/`--force`/`--accept-permissions` bypass. | Continuity is local (TOFU): the very first binding is trusted on first use. |
| 5 | **Local trust-record corruption / substitution** (tampered, wrong-App-ID, or symlinked record) | Strict parse fails closed (`CorruptTrustError`, exit 7): duplicate-key rejection, byte budget, canonical key, fingerprint match, App-ID-substitution and symlink checks. The runtime never silently recreates/overwrites a corrupt record; `trust forget --force` is the explicit reset. | An attacker with write access to `<LEXE_HOME>/trust` can **delete** a record (reverting an App ID to first-seen) — a local-filesystem-compromise scenario outside the runtime's TCB. |
| 6 | **Malicious installed application** (a running app attacks the host / other apps / trust state) | Isolation confines it (WS7); trust records and lock/txn metadata live outside the sandbox and are never bound in; per-App data is private. | Advisory controls and the absence of seccomp mean a determined app has syscall latitude within the sandbox. |
| 7 | **Race between launch, update and uninstall** (TOCTOU, delete-out-from-under) | OS-backed `flock` locking (WS9): per-app mutation lock serializes mutations; a launch holds a shared version lease across resolve→validate→hash→exec and uses the immutable `versions/<v>` path; uninstall/GC refuse or skip a leased version; locks release on process death. | — |
| 8 | **Hostile environment** (dangerous env vars, ambient state leaking into the app) | The sandbox environment is an allowlist; `LD_PRELOAD`/`LD_LIBRARY_PATH`/etc. are stripped; lock/lease fds are `O_CLOEXEC` so the child never inherits them. | — |
| 9 | **Isolation backend unavailable** (no/broken bwrap where isolation is expected) | Fail closed: the launcher refuses to run an application unconfined when isolation is required but unavailable (`IsolationError`). | On a platform with **no** isolation backend (the Windows dev host) the app runs directly — reported truthfully as "no OS-level isolation", never as sandboxed. |
| 10 | **Compromised *trusted* signing key** (the publisher's own key is stolen) | Local blocking (`lexe trust block`) lets a user refuse a key locally (install/update/launch) once they learn of a compromise. | **Not defended in general.** 0.1 has no revocation service and no authenticated key rotation, so a stolen trusted key can sign malicious updates that pass authenticity + continuity until the user blocks it locally. This is stated plainly and not claimed otherwise. |
| 11 | **Unsupported authenticated key rotation** (attacker forges a "rotation") | There is no rotation mechanism to forge: FORMAT 0.1 defines none, and the runtime refuses a changed key rather than honoring any rotation file/field. | Legitimate key rotation therefore requires an explicit user action (remove + forget, or a new App ID) — a usability cost accepted for safety in 0.1. |
| 12 | **The sandbox strips the application's own hardening** (an application whose security policy lives in `/etc` runs with *more* capability inside `.LEXE` than outside it) | Partial only. The isolation controls all still hold — read-only app image, private data/cache/temp, hidden home, network denied without the permission — so this is not an escape. What is *not* mitigated is the reduction itself: `/etc` is an allowlist, and distribution-installed application policy is not on it. | **Explicitly not defended.** See "the claim that is retracted" below. |

## The claim that is retracted

`.LEXE` does **not** guarantee that running an application under it is at least
as safe as running that application directly. For one class of application it
is measurably not, and the reason is structural rather than a bug to be fixed.

The mechanism: `/etc` inside the sandbox is an allowlist (see
[ISOLATION.md](ISOLATION.md#the-etc-allowlist)) chosen for dynamic linking and
name resolution. An application that reads its own security policy out of
`/etc` does not find it, and falls back to whatever its built-in defaults are —
which are, by construction, the *unhardened* defaults the distribution shipped
a policy file to override.

Measured on Ubuntu 24.04, with ImageMagick as the witness. Ubuntu ships
ImageMagick's hardening in `/etc/ImageMagick-6/policy.xml`; unbound,
ImageMagick reports `Path: [built-in]` with `rights: None` instead.

| | directly | under `.LEXE` |
|---|---|---|
| `convert -list policy` | `/etc/ImageMagick-6/policy.xml` | `[built-in]` |
| `convert label:@m.txt info:` (indirect file read, which Ubuntu's policy denies) | **exit 1**, "not allowed by the security policy" | **exit 0** |
| Area limit | 256MP | 65.197GP |
| Memory limit | 1GiB | 15.18GiB |
| Disk limit | 2GiB | unlimited |

ImageMagick is only the witness; the class is "application reads its security
policy from `/etc`", and ghostscript, Java security properties and OpenSSL's
`MinProtocol`/`SECLEVEL` settings are the same shape.

The same root cause has two milder manifestations, which are worth naming
because together they show the allowlist is narrow in general and not merely
missing one file: a granted `network` permission that could not verify a
certificate (fixed — see [ISOLATION.md](ISOLATION.md#tls-trust-store)), and GUI
applications that render visibly wrong because `/etc/X11/app-defaults` is the
only place the Xt resource search path resolves on Debian/Ubuntu (`xcalc` loses
its keypad). Only the hardening case has a security consequence, and only it is
retracted here.

**Why this is not fixed by binding `/etc` read-only.** That was weighed, and it
does work for the measured case — with all of `/etc` bound, `convert -list
policy` reports the host file again. It was rejected on three grounds:

1. **It is a much larger information surface, and the wrong kind.** `/etc` is
   183 entries on this host. File modes still protect what they protect — the
   application runs as the invoking user, so `/etc/shadow` is no more readable
   inside than outside — so the new exposure is not secrets but *recon*:
   hostname, `machine-id` (a stable per-device identifier), `os-release`,
   `fstab`, the installed-software fingerprint of the whole machine. A sandbox
   handing every console application a permanent device identifier by default
   is a privacy regression that no amount of policy restoration pays for.
2. **The denylist cannot be right.** Covering that surface means a list of what
   to exclude, per distribution, maintained forever, silently wrong whenever it
   misses something. Every other control in this runtime is an allowlist; this
   one would invert the posture for a whole tree, and a denylist that quietly
   fails to cover a case is the exact failure mode this project keeps finding.
   It would also undo a reduction that already exists: `/etc/hosts` and
   `/etc/resolv.conf` are deliberately gated on the `network` permission, and a
   blanket bind hands them to an application with no network.
3. **It would not make the claim true anyway.** Application hardening also
   lives in AppArmor and SELinux profiles, systemd unit sandboxing, distribution
   wrapper scripts and PAM limits — none of which a bind mount restores. The
   claim would still be false, only less obviously.

So the honest position is retraction plus visibility: the reduction is
documented exactly, and `tests/test_etc_surface.cpp` asserts from inside a real
sandbox that these files are invisible — which means the day someone changes
this, in either direction, a test says so and this row has to be rewritten
rather than quietly outlived.

**What a publisher should do.** An application that depends on a policy file in
`/etc` should ship that policy inside its own payload and point at it
explicitly, rather than relying on the host's copy. The sandbox does not remove
the *ability* to be hardened; it removes the host's copy of the configuration.
Verified for the case above: with a `policy.xml` in the payload and
`MAGICK_CONFIGURE_PATH` set to it, `convert -list policy` reports that file
inside the sandbox and `convert label:@m.txt info:` goes back to exiting 1,
"not allowed by the security policy".

## Explicit non-guarantees (repeated for emphasis)

- A valid signature does **not** establish the publisher's real-world identity,
  legal name, website ownership, reputation, or safety.
- First-seen (TOFU) trust is **local** and unverified; it is never presented as
  external verification.
- There is **no** protection from a compromised *trusted* signing key beyond
  local blocking after the fact (no revocation, no authenticated rotation).
- Tiers 2/3 of [TRUST.md](TRUST.md) (repository / root endorsement) are **not
  implemented**; only local Tier-1 TOFU exists today.
- Non-Linux platforms provide **no** equivalent runtime containment or
  cross-process locking.
- An attacker who already controls the local filesystem/account is outside the
  runtime's trust boundary.
- Running an application under `.LEXE` is **not** guaranteed to be at least as
  safe as running it directly: the `/etc` reduction removes host-installed
  application policy, and an application that reads its hardening from `/etc`
  runs with its unhardened defaults inside the sandbox. Measured, with numbers,
  under "The claim that is retracted" above.

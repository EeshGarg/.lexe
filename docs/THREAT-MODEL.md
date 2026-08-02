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

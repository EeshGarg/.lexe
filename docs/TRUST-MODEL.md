# Local Trust Model (runtime-trust WS3/WS4/WS10)

This describes the trust model the runtime **implements today**. It realizes
**Tier 1** ("self-signed, TOFU-pinned") of the aspirational three-tier design in
[TRUST.md](TRUST.md); Tiers 2 and 3 (repository endorsement, root accreditation)
are **not implemented** and nothing in the UI claims them.

The cardinal rule: **a cryptographically valid signature proves the package is
consistent with a key — not the publisher's real-world identity, name, ownership
of a website, reputation, or safety.** The runtime never collapses trust into a
single "verified" / "trusted" / "safe" boolean.

## Three separate dimensions

The runtime keeps three concerns strictly apart and shows all three truthfully:

1. **Package authenticity** (`SignatureState`, from the FORMAT-0.1 §6 pipeline)
   — is the signature cryptographically valid over the exact signed bytes, and
   which key signed it. Answers integrity + "signed by *some* key", nothing else.
2. **Local publisher trust** (`PublisherKeyState` / `TrustDecision`, this model)
   — has this (App ID, key) been seen / accepted / explicitly trusted / blocked
   **on this machine**. This is trust-on-first-use, purely local.
3. **Runtime enforcement** (`IsolationControl` / `ControlState`, docs/ISOLATION.md)
   — which sandbox controls the backend can actually establish on this platform.

## No central authority

There is **no** certificate authority, online identity service, package store,
transparency log, daemon, or remote revocation. Trust decisions are made and
stored locally. Local blocking is the only revocation-like control and is
labelled a **local** block, never a global or real-world revocation.

## Trust-on-first-use (first install)

1. The package is cryptographically verified (§6). A failure stops here.
2. With no local trust record for the App ID, the key is classified `FirstSeen`.
3. The user is shown: signature **valid**, publisher identity **not
   independently verified**, the signing-key **fingerprint**, and the caveat.
   First-seen is styled as **caution**, never a green "verified".
4. Installing is the user's consent (`--yes` / the GUI Install button / the
   confirmation prompt). It is a decision to install, not a claim of identity.
5. **Only after the install transactionally commits** is the App-ID/key binding
   recorded. A failed install records nothing; crash recovery completes the
   binding for a promoted (committed) transaction and never fabricates one for a
   rolled-back transaction (idempotent, derived from the committed manifest).
6. A plain install records the binding as **accepted**. `lexe install --trust`
   (or an equivalent GUI action) additionally records an **explicit** local
   trust decision — a separate, stronger act.

## App-ID / key continuity

The (App ID → signing key) binding is pinned locally. It persists across
ordinary uninstall **and** `--purge-data` (purging application data must not
silently delete trust history). Only `lexe trust forget` removes it.

- **Known matching key** → allowed under the normal update policy; no repeated
  identity prompt.
- **Explicitly trusted key** → same, and shown as a local trust decision.
- **Changed key** (a different key for a known App ID) → **refused**
  (`ChangedKeyError`, exit 7). The installed version and any retained data stay
  bound to the original key. There is no generic "continue anyway".
- **Locally blocked** → install, update **and launch** are refused
  (`BlockedKeyError`, exit 7) until `lexe trust unblock`.
- **Retained-data conflict** (data retained under another key, no trust record)
  → refused (`RetainedDataConflict`, exit 6).
- **Corrupt trust record** → fail closed (`CorruptTrustError`, exit 7); the
  runtime never silently recreates or overwrites it. `lexe trust forget --force`
  is the documented administrative reset.

The installed-record key pin is kept as defense-in-depth: even if the trust
record is forgotten while the app stays installed, a changed key is still
refused.

## Key rotation

FORMAT 0.1 has **no authenticated key-rotation mechanism** (`KeyRotationState`
is `Unsupported`). A changed key is always refused. To accept a new publisher
key for an App ID the user must deliberately remove the application and its data
(and forget its trust), or install under a different App ID. The runtime does
**not** invent an insecure rotation file or unsigned manifest field.

## Retained-data ownership

Persistent data belongs to the App ID and carries an owner marker bound to the
publisher key. A different key never inherits retained data (it is refused as a
changed key while a trust record exists, or as a retained-data conflict when
trust was forgotten but data remains). See [FORMAT-0.1.md §9](FORMAT-0.1.md).

## Permission consent is a SEPARATE decision

Approving new permissions on an update is independent of publisher trust. A
known, trusted key whose update **expands** the permission set is still refused
(`PermissionError`, exit 5) until permissions are explicitly approved
(`--accept-permissions`). Neither `--yes` nor `--trust` nor `--accept-permissions`
implies any of the others, and none of them bypass key continuity.

## Trust record format

One record per App ID at `<LEXE_HOME>/trust/<id>.json` — **outside** every
package-controlled path and **never** bound into the sandbox. Fields: schema
version, App ID, canonical `ed25519:…` public key, full fingerprint, first/last
seen, explicit-trust flag + provenance, blocked flag + time, optional prior-key
audit evidence. It stores **no private key**.

Parsing is strict and fails closed (`CorruptTrustError`): duplicate-key
rejection, a byte budget, canonical key encoding (mixed-case/alternate encodings
rejected), fingerprint-must-match-key, an App-ID-substitution check (a record
naming another App ID is refused), and a symlink/path-substitution check.
Writes are atomic and serialize with install/update/rollback/remove of the same
App ID under the per-app mutation lock (docs/CONCURRENCY.md).

## Fingerprints

A fingerprint is `SHA-256(raw 32-byte Ed25519 public key)`, shown grouped in
uppercase quads. It is derived from the canonical key bytes (stable across
platforms) and is the identity shown to users — never the free-form publisher
display string. The full 64-hex value is available in every structured output.

## Enforcement-state terminology (what the words mean)

- **enforced** — the OS backend actually establishes the control this launch.
- **advisory** — recorded/displayed but 0.1 has no mechanism to enforce it
  (e.g. `user-files-selected`).
- **unavailable** / **not established** — a control that would apply here but the
  backend cannot provide it (launch fails closed if it was required).
- **not enforced on this platform** — the platform has no isolation backend.
- **not implemented** — deliberately absent in 0.1 (e.g. a seccomp filter).

For the current **Linux** backend: baseline filesystem controls (read-only app
image, private data/cache/temp), environment sanitization, and network denial
(when `network` is not granted) are **enforced**; `network` is **enforced** via a
network namespace; `user-files-selected` is **advisory**; GUI forwarding is
**unavailable** (isolated apps are headless); seccomp is **not implemented**. On
**Windows** (development host) there is no equivalent runtime containment and no
cross-process locking, and the UI never implies otherwise.

## UI phrases that must NOT be used

Never present, for a merely signed / first-seen package: "verified publisher",
"trusted publisher", "publisher confirmed", "verified app", "safe application",
"secure application"; never "sandboxed" / "permission granted" when the control
is advisory, partial, or unavailable. First-seen is never styled or described as
externally verified.

## Guarantees and non-guarantees

**Guaranteed:** package integrity + signature before anything is trusted; a
stable local App-ID↔key binding; changed/blocked/corrupt keys refused (install,
update, launch) with typed errors and no `--yes`/`--force` bypass; trust
recorded only after a committed install; idempotent crash recovery; truthful,
identical authenticity/permission/isolation presentation across CLI and GTK.

**NOT guaranteed:** the publisher's real-world identity, legal name, website
ownership, reputation, or safety; protection once a *trusted* signing key is
itself compromised (0.1 has no revocation or authenticated rotation to recover
from that — see the threat model); any Tier 2/3 endorsement; Linux-equivalent
containment on non-Linux platforms.

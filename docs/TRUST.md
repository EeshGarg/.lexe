# Lexe Trust & Signing Infrastructure — Design (targeting 0.2)

Three trust tiers, one fixed chain shape, no X.509. This layers **on top of**
the FORMAT-0.1 integrity model (which stays exactly as specified: publisher
Ed25519 over exact entry bytes). Integrity answers "is this package intact and
from the key that claims it?"; trust answers "who vouches for that key?"

```text
Tier 3   Lexe Root Authority key          (ships pinned in the runtime)
            │  signs: repository accreditation
Tier 2   Repository key                    (a distro, forge, or company repo)
            │  signs: publisher endorsement
Tier 1   Publisher key                     (self-generated, TOFU-pinned)
            │  signs: manifest.sig / payload.sig / update.json   ← FORMAT-0.1, unchanged
         Package
```

The chain depth is fixed at exactly these three levels. No arbitrary-depth
chains, no cross-signing graphs, no delegation. That keeps verification a
straight-line function instead of a path-finding problem — most PKI bugs live
in path building.

## Trust Tiers (what the user sees)

| Tier | Meaning | Default UI |
|---|---|---|
| 1 — Self-signed | Valid publisher signature; key known only by TOFU | "Unverified publisher — trust on first use" + warning styling |
| 2 — Repository-signed | Tier 1 **and** an unexpired endorsement of that publisher key by a repository key the user has added | "Verified by <Repository Name>" |
| 3 — Root-approved | Tier 2 **and** the repository key carries an unexpired accreditation from a pinned Lexe Root key | "Verified by <Repository> · Lexe-approved" |

Install policy is user/enterprise-configurable: `minimumTier` (default **1**,
with explicit warnings — Linux decentralization is non-negotiable, so
self-signing must always remain *possible*; enterprises and cautious users can
require 2 or 3). This mirrors the Windows Authenticode/WHQL posture: unsigned
runs are possible but loud, vendor-approved is quiet.

## Artifacts

All statements are JSON documents signed as **exact bytes** with detached raw
64-byte Ed25519 signatures — the same discipline as FORMAT-0.1 §4. No
canonicalization anywhere.

### Publisher endorsement (Tier 2), issued by a repository

```json
{
  "endorsementVersion": "0.1",
  "type": "publisher-endorsement",
  "subject": {
    "publisherKey": "ed25519:…",
    "publisherName": "Example Corporation",
    "appScope": ["com.example.*"]
  },
  "issuer": { "repositoryId": "org.flathub.repo", "repositoryKey": "ed25519:…" },
  "issuedAtUtc": "2026-07-13T00:00:00Z",
  "expiresAtUtc": "2027-07-13T00:00:00Z",
  "revocation": "https://repo.example.org/lexe/revocations.json"
}
```

* `appScope` (glob on application ids) bounds the blast radius of a repository
  compromise: an endorsement for `com.example.*` cannot bless a hijacked
  `org.mozilla.firefox`.
* Endorsements travel **inside the package** (`signatures/endorsements/<repositoryId>.json`
  + `.sig`) so the offline double-click flow keeps working, and/or are fetched
  from the repository at verify time. Embedded and fetched endorsements are
  validated identically.

### Repository accreditation (Tier 3), issued by the Lexe Root Authority

```json
{
  "endorsementVersion": "0.1",
  "type": "repository-accreditation",
  "subject": { "repositoryId": "org.flathub.repo", "repositoryKey": "ed25519:…" },
  "issuer": { "rootId": "usha-root-1", "rootKey": "ed25519:…" },
  "issuedAtUtc": "…",
  "expiresAtUtc": "…",
  "revocation": "https://authority.ushacorp.example/revocations.json"
}
```

The root authority is **Usha Corporation of America**. Root ids are
`usha-root-<n>`; the format carries `rootId` strings so additional roots can be
added or rotated without a format change. (The revocation URL above is a
placeholder until the corporation's domain is chosen.)

### Revocation lists

A revocation list is a signed JSON document listing revoked keys and
endorsement/accreditation ids, fetched from the `revocation` URL, cached with a
TTL. Policy: best-effort check at install/update (offline ≠ broken —
decentralization again), but a **successfully fetched** revocation is always
enforced, and `minimumTier >= 2` policies may be configured fail-closed.

## Verification (extends FORMAT-0.1 §6)

Stages 1–7 are unchanged (integrity). New stage 8 — **trust evaluation** —
runs only after integrity passes, never influences it, and cannot fail an
install on its own; it *classifies*:

```text
8a. collect endorsements (embedded + repository-provided)
8b. validate signature, expiry, publisherKey match, appScope match
8c. resolve repository key against the user's repository list
8d. validate accreditation of that repository key against pinned roots
8e. check cached revocations
8f. result: tier ∈ {1, 2, 3} + explanation strings for the UI
    → compare against policy.minimumTier for the install decision
```

Trust conclusions are recorded in `installation.json` (tier at install time,
endorsement ids). Updates re-evaluate: a package whose tier *drops* below
policy at update time is refused with an explanation.

## Key management

| Key | Where it lives | Rotation |
|---|---|---|
| Root | Held offline by Usha Corporation of America, ideally hardware-backed; **multiple roots supported** (`usha-root-1`, `-2`) so one can be rotated/retired without a flag day | New root ships via runtime update; old root's accreditations honored until expiry |
| Repository | Repo operator's signing service | Root issues accreditation for the new key; old key revoked |
| Publisher | Developer machine / CI secret (FORMAT-0.1 §4 key file) | 0.2 adds the rotation statement SPEC.md sketches: old key signs a succession statement for the new key; otherwise re-endorsement or explicit user approval |

The runtime pins the root public keys in a signed configuration file installed
with the runtime itself (not silently downloadable — changing roots requires a
runtime update or explicit user action, per SPEC's update-ownership rule).

## Tooling (new binary: `lexe-authority`)

Kept **separate** from the user-facing `lexe` CLI — end users never need it,
and the runtime never needs private-key material:

```bash
lexe-authority keygen --role root|repository|publisher -o key.json
lexe-authority endorse-publisher  --repo-key repo.json --publisher-pub ed25519:… \
                                  --name "Example Corp" --scope "com.example.*" \
                                  --expires 2027-07-13 -o endorsement.json   # + .sig
lexe-authority accredit-repository --root-key root.json --repo-pub ed25519:… \
                                  --repo-id org.flathub.repo -o accreditation.json
lexe-authority revoke  --key <signer>.json --target <keyOrStatementId> \
                                  --list revocations.json                    # re-signs list
lexe-authority inspect <statement.json>
```

`lexe pack` gains `--endorsement <file>` to embed endorsement chains.

## Threat model (what each tier defends against)

| Attack | Defense |
|---|---|
| Tampered package | FORMAT-0.1 integrity (unchanged) |
| Stolen **publisher** key | Repo revokes endorsement → drops to Tier 1 warning everywhere; TOFU pin still blocks silent key *swap* |
| Malicious repository endorsing malware | `appScope` bounds damage; root revokes accreditation → repo drops to Tier 1-equivalent |
| Stolen **repository** key | Root revocation; endorsement expiry keeps the horizon short |
| Root compromise | Multiple pinned roots + runtime-update rotation path; roots kept offline |
| Endorsement replay for a different app | `appScope` + publisherKey binding inside the signed bytes |
| Downgrade / update replay | FORMAT-0.1 §7 (unchanged), plus tier re-evaluation at update |

## Sequencing

1. **0.1 (current build)** — Tier 1 only. Already forward-compatible: unknown
   entries under `signatures/endorsements/` are carried and hashed like any
   other metadata; verify stage 8 simply doesn't exist yet.
2. **0.2** — endorsement/accreditation formats frozen, stage 8, policy knob,
   `lexe-authority`, revocation lists, publisher key rotation statements.
3. **Root ceremony** — generate `usha-root-1` offline, document the ceremony,
   pin it in the runtime build.
4. **GPL relicensing** — only after the GPL Transition Gate below is fully
   green (per LICENSE §4).

## GPL Transition Gate

The project stays proprietary until every item below is demonstrably true —
"the infrastructure is ready" is this checklist, not a judgment call:

- [ ] Endorsement + accreditation formats frozen and versioned, with a
      malformed-statement test corpus (mirroring HARDENING.md §B discipline).
- [ ] `usha-root-1` generated in a documented offline ceremony; public half
      pinned in a tagged runtime build; private half never touched a
      networked machine.
- [ ] A second root (`usha-root-2`) generated and held in reserve, so root
      rotation is proven possible before anyone depends on root 1.
- [ ] `lexe-authority` tooling complete and tested: keygen, endorse,
      accredit, revoke, inspect.
- [ ] At least one repository (Usha's own reference repository is fine)
      accredited, endorsing at least one real publisher, with a package
      installing at Tier 3 end-to-end on a clean Linux machine.
- [ ] Revocation exercised end-to-end: revoke a test publisher key and a test
      repository key, observe the tier drop and the refusal paths.
- [ ] Key rotation exercised end-to-end at all three levels.
- [ ] Trademark/entity posture reviewed by counsel: after GPL, the *code* is
      copyleft but Tier-3 approval remains Usha Corporation of America's
      alone — the root private keys and the "Usha-approved" designation are
      the durable control points, exactly like Microsoft with Authenticode.
      Counsel also reviews the license transition itself.
- [ ] LICENSE §3 contribution-assignment provably covers all contributions to
      date (trivially true while the sole contributors are the owner and
      owner-directed tooling).

## Open decisions (owner input wanted)

1. ~~The controlling entity's real name~~ — **resolved: Usha Corporation of
   America** (`usha-root-<n>`). Still open: the authority's domain for
   revocation URLs.
2. Default `minimumTier`: 1 (recommended — decentralization with loud
   warnings) or 2 for a more locked-down default.
3. Whether Tier-3 approval should ever be *required* for anything (e.g.
   packages requesting privileged-helper operations) — recommendation: yes,
   that's the one place a hard floor of Tier ≥ 2 makes sense.

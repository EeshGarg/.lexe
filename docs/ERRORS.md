# `.LEXE` error taxonomy

Every way this runtime can refuse, what each refusal *means*, what it does **not**
mean, and what to do about it.

Two audiences. A person who ran a command and wants the next step, and a script
that must decide whether to reject a package, raise its own limits, or escalate
to a human. The second audience is why this document exists at all: an error
surface that only produces English sentences forces every gate to pattern-match
on prose, and prose changes.

Referenced by `tests/concurrency/lib.sh`.

---

## 1. Exit codes

Authoritative. Defined by `exit_code_for()` in `src/lexe/base/error.hpp`; every
CLI command maps through it.

| Code | Meaning | Type |
|---|---|---|
| 0 | success | — |
| 1 | runtime error — the operation failed for a reason with no more specific code | `Error`, `LaunchError`, `IsolationError`, `LockError` |
| 2 | usage — the command line was wrong | `UsageError` |
| 3 | verification failure — the file was not accepted | `VerificationError`, `CompileError`, `ResourceLimitError` |
| 4 | not installed / not found | `NotFoundError` |
| 5 | permission or consent required | `PermissionError` |
| 6 | busy, or an operation conflict | `BusyError`, `RetainedDataConflict` |
| 7 | local publisher-trust rejection | `TrustError`, `ChangedKeyError`, `BlockedKeyError`, `CorruptTrustError` |

Two properties a script may rely on:

* **Exit 3 never means "probably fine".** The file was not accepted. It is not a
  warning, and there is no `--force` that turns it into an acceptance.
* **Exit 7 is never bypassable.** Not by `--yes`, not by `--force`, not by
  `--accept-permissions`. A trust rejection is a decision about continuity of
  identity, and Format 0.1 has no authenticated key rotation, so there is no
  generic "continue anyway" to offer.

### 1.1 Why 3 and 7 are different codes

A valid signature proves a package is internally consistent with *a* key. It
proves nothing about who holds that key. So "this package's cryptography does not
check out" (3) and "this package checks out perfectly, against the wrong key" (7)
are different facts with different remedies, and collapsing them would hide the
more alarming one inside the more common one.

### 1.2 Why a lock failure is 1 and not 6

Exit 6 means *someone else holds the lock* — a healthy system, busy. A lock file
that cannot be opened, an OS lock call that fails, or corrupt lock metadata is the
locking machinery itself failing, which is not a retry-and-it-clears situation.
`LockError` is exit 1, and the caller fails closed rather than proceeding
unlocked.

---

## 2. What each refusal does not mean

The "does not mean" column is the useful one. Most support questions are someone
acting on the wrong reading of a correct message.

| Type | Means | Does **not** mean |
|---|---|---|
| `VerificationError` | this file was not accepted as a 0.1 package | that the publisher is malicious, or that a re-download will help |
| `ResourceLimitError` | well-formed, but larger or wider than *this runtime* will process | that the package is invalid — see §5 |
| `CompileError` | host-ISA compilation of a portable package failed | that the package is unsigned or tampered with |
| `NotFoundError` | no such application, file or entry | that it was uninstalled; a mistyped path lands here too |
| `PermissionError` | the package is valid and wants a capability you have not approved | any integrity problem whatsoever |
| `BusyError` | another `lexe` operation holds this app's lock, or a launch lease blocks a destructive change | corruption; wait and retry |
| `RetainedDataConflict` | data is retained for this App ID under a **different** publisher key | that the new package is bad — it is a refusal to let it inherit the old data |
| `ChangedKeyError` | the signing key differs from the one bound to this App ID locally | global revocation; this is a local record |
| `BlockedKeyError` | you blocked this locally | a real-world revocation |
| `CorruptTrustError` | the local trust record is unparseable or inconsistent | that the app is untrusted — the runtime fails closed because it cannot tell |
| `IsolationError` | a required isolation control could not be established | that the app ran with reduced isolation. It did **not** run |

The last row is a guarantee, not a description: a launch that cannot enforce its
isolation policy never falls through to direct execution.

---

## 3. The hint contract

Every failure may carry one actionable sentence. Resolution order, in `hint_for()`
(`src/lexe/commands/main.cpp`):

1. **A hint the throw site attached wins.** It knows the specific reason; the
   fallbacks below know only the category.
2. **Otherwise a hint chosen from the type** — `ChangedKeyError`,
   `BlockedKeyError`, `TrustError`, `PermissionError`, `BusyError`,
   `VerificationError`, `NotFoundError`.
3. **Otherwise nothing.** `UsageError` is deliberately silent here, because its
   message already is the remedy.

A type-based fallback is only ever as good as the type is specific. That is the
whole design constraint: `CorruptTrustError` can be answered from its type alone
("review the record with `lexe trust show <id>`"), and a plain `Error` cannot be
answered from its type at all.

### 3.1 Measured coverage

Counted across 264 throw sites in `src/`:

| Type | Throws | With a hint | Type fallback |
|---|---|---|---|
| `Error` | 128 | 15 (11%) | **none** |
| `VerificationError` | 44 | 9 (20%) | generic |
| `UsageError` | 26 | 0 | none, by design |
| `NotFoundError` | 25 | 11 (44%) | good |
| `IsolationError` | 10 | 1 (10%) | **none** |
| `ResourceLimitError` | 6 | 2 (33%) | generic, and wrong — §5 |
| `BusyError` | 5 | 1 (20%) | good |
| `ChangedKeyError` | 3 | 0 | good |
| `BlockedKeyError` | 3 | 0 | good |
| `LockError` | 3 | 0 | **none** |
| `PermissionError` | 3 | 3 (100%) | good |
| `CorruptTrustError` | 2 | 0 | good, via `TrustError` |
| `CompileError` | 2 | 2 (100%) | generic |
| `RetainedDataConflict` | 1 | 0 | **none** |
| **total** | **264** | **45 (17%)** | |

17% is not itself a defect — a sufficiently specific type needs no throw-site
hint. The gap is where a **generic** type is thrown for a **specific** reason and
no fallback covers it. Four such places, in severity order:

1. **`IsolationError` — 10 sites, 9 without a hint, no fallback.** These are "the
   application will not start" failures, the most opaque kind for a normal user,
   and they currently print a bare message. Eight of the nine are in `sandbox`,
   one in `runtime`, so this is a small and well-localised fix.
2. **Plain `Error` — 128 sites, 113 without a hint, no fallback.** The catch-all,
   exit 1. Hintless sites concentrate in `base` (46) and `package` (34), then
   `install` (12), `runtime` (9), `commands` (7), `state` (4),
   `diagnostics` (1).
3. **`RetainedDataConflict`.** Its own class comment states the remedy — the user
   must purge the retained data first — and the CLI never says so. It is exit 6
   but not a `BusyError`, so it misses that fallback too.
4. **`LockError` — 3 sites.** Fails closed correctly and explains nothing.

Open work, not a description of intended behaviour.

---

## 4. The machine-readable surface

`lexe verify --json` is the contract for gates. On failure:

```json
{
  "ok": false,
  "signatureState": "malformed",
  "identityVerified": false,
  "stages": [ { "name": "structure", "ok": false, "detail": "…",
                "category": "format-invalid" } ],
  "failure": { "stage": "…", "category": "…", "detail": "…", "hint": "" }
}
```

The pipeline stops at the first failing stage, so stages after it are **absent**,
not `false`. Do not read absence as success.

Stages, in normative order (FORMAT-0.1 §6): `structure`, `manifest`, `key`,
`manifest-signature`, `payload-signature`, `hashes`, and `compatibility` for
install and update only.

`identityVerified` is always `false` in 0.1, and that is not an oversight:
verification establishes integrity and authenticity against a key, never the
publisher's real-world identity. A gate must not treat a passing verification as
an identity claim.

---

## 5. For gate authors: reject, or raise your limits?

`category` exists for exactly one decision, and it is the one place where reading
the English would give a wrong answer.

* **`format-invalid`** — the package violates Format 0.1. *Any* conforming
  implementation must reject it. Nothing you configure will make it acceptable.
  Reject it.
* **`resource-limit`** — the package is well-formed and merely exceeds a limit
  *this* runtime imposes: total uncompressed size, entry count, expansion ratio,
  per-entry size. Another conforming implementation may set a different limit, or
  none, and read the same package correctly.

So a `resource-limit` failure **is not evidence that the package is bad**, and a
gate that reported it as malformed would be making a claim the format does not
support. The remedy is to raise the limit, or to decline on your own policy
grounds — stated as your policy, not as a defect in the package.

This is also why the generic `VerificationError` hint ("re-download it from the
original source") is wrong for a hintless `ResourceLimitError`: the download was
fine. It is the same mistake, in the same words, that repair used to make when it
told users to re-download a package that was never the problem.

---

## 6. The error-identity gap: "already done" looks like "broke"

The largest hole in this taxonomy is not a missing hint, it is a missing *type*.

`install` serialises on the per-app mutation lock. When two installs race, the
loser does not fail to acquire the lock — it acquires it second, and then finds
the desired state already holds. Refusing rather than silently exiting 0 is
deliberate: reinstalling the files is a different operation, and the message
points at the one that does it (`lexe repair`).

But that refusal is a plain `Error`, so it is **exit 1** — the same code as
"something broke". A script racing two installs cannot tell the two apart from
the exit status, and there is no `category` on this surface the way there is on
`verify --json`.

The consequence is already in the tree. `tests/concurrency/lib.sh` has to do
this to decide whether a loser lost legitimately:

```sh
grep -qiE "already installed|already current|already at"
```

That is prose pattern-matching, by this project's own test suite, against its own
error messages — precisely the pattern-matching-on-prose that the opening of this
document gives as the reason it exists. And it is load-bearing: reword one of
those three sentences and a concurrency test silently changes meaning.

The remedy is a distinct outcome for "the requested state already holds", carried
in the type rather than the prose, so that both the CLI and any gate can
distinguish a satisfied no-op from a failure. Until that exists, treat exit 1
from `install` as ambiguous and do not build a gate on it.

Recorded as an open design decision, not a defect: whether a satisfied no-op
should be a success code, a distinct failure code, or an explicit
`--already-ok` contract is a product question about what a package manager
promises, and it should be answered deliberately rather than by whichever type
was nearest to hand.

---

## 7. Known diagnostic defects

Recorded because a misleading message sends someone hunting for the wrong thing.

* **A ZIP64 archive is reported as trailing data.** An archive with more than
  65535 entries is rejected with "archive does not span the whole file
  (trailing/prepended data or an archive comment)". The real cause is a ZIP64
  end-of-central-directory record, which the span check does not recognise.
  Rejecting it is correct and specified — FORMAT-0.1 §2 permits a reader to
  reject ZIP64, and such an archive cannot be a conforming 0.1 package anyway,
  since §10.1 caps entries at 65535. Only the stated reason is wrong.

* **The entry-count guard is unreachable.** `limits::kMaxEntryCount` is 65535, and
  the classic end-of-central-directory record stores the entry count in 16 bits,
  so an archive that exceeds it **must** carry a ZIP64 record and is always caught
  by the span check first. Measured: 65535 total entries pass structure and go on
  to fail for a genuine reason (`required entry missing: metadata/hashes.json`);
  65601 entries hit the span check. The `ResourceLimitError` at
  `src/lexe/package/package.cpp:499` can therefore never fire. Harmless defence
  in depth, but it reads as a live guard and is not one.

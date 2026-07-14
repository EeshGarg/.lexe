# Lexe 0.1 Hardening Gates — Normative

These gates are the exit criteria between "the tests are green" and "0.1 is a
platform foundation". They are normative for the hardening pass in the same way
[FORMAT-0.1.md](FORMAT-0.1.md) is normative for the format. A MUST here that
lacks a test is a defect.

## A. Canonical Implementations (one source of truth)

Locally-correct modules can still be conceptually inconsistent. The following
concerns MUST each have exactly **one** implementation; every other module calls
it. The hardening audit greps for and eliminates duplicates, and adds tests that
drive the same hostile input through *every* entry point (verify, install,
update, GUI) asserting identical rejection.

| Concern | Canonical home | Forbidden elsewhere |
|---|---|---|
| Entry/path validation (FORMAT §2) | `package.cpp` — a single `validate_entry_path()` | any ad-hoc `..`/separator checks |
| Package identity | one `AppIdentity {id, publisherKey}` value type + equality | comparing ids without keys |
| Version ordering (FORMAT §8) | `versioncmp.cpp` | any other string compare on versions |
| Signature input construction | one helper returning **exact stored entry bytes** | re-serializing JSON for signing/verifying |
| Filesystem ownership ("may Lexe delete this?") | `registry.cpp` | direct `remove_all` on computed paths |
| Update authorization (FORMAT §7 checks 1–7) | one `updater.cpp` function, ordered | partial re-checks in CLI/GUI |
| Error taxonomy | `error.hpp` | new exception types elsewhere |

## B. Malformed Package Corpus — `tests/test_hostile_packages.cpp`

Every case below MUST be rejected at its documented stage, with **zero**
filesystem effects outside the test's temp dirs and no partial registry state.
Corpus packages are constructed in-test (raw miniz / raw bytes where the
`PackageWriter` is too honest to produce them).

1. duplicate ZIP entry paths (both local-header and central-directory level);
2. absolute entry paths (`/etc/x`, `C:/x`), `..` traversal, backslash separators, NUL in names;
3. symlink entries (Unix mode `S_IFLNK` in external attrs);
4. **case-colliding paths** (`Payload/a` vs `payload/A` vs `payload/a`) — reject: they alias on case-insensitive filesystems;
5. **overlapping/inconsistent ZIP records** — central directory and local header disagree on name, size, or offset; reader MUST use one authoritative view and reject mismatches;
6. decompression bombs — per-entry cap, total-extracted cap, and a global ratio cap sanity-checked against `install.estimatedSize`; verification MUST bound memory (streaming, no full-package slurp of payload entries);
7. truncated (63-byte) and oversized (65-byte) signature entries;
8. **duplicate JSON keys** in `lexe.json`, `hashes.json`, `update.json` — MUST reject (SAX-level detection; nlohmann's default last-wins is not acceptable);
9. invalid UTF-8 in JSON documents and in entry names;
10. giant fields — caps: `lexe.json` ≤ 1 MiB, `hashes.json` ≤ 16 MiB, `id` ≤ 255, `name` ≤ 1 KiB, entry path ≤ 1 KiB; archive entry count ≤ 65535;
11. ZIP directory entries (paths ending `/`) — writers never emit them; readers reject in 0.1;
12. ZIP extra fields / archive comment present — reader tolerates, writer never emits; the determinism test asserts their absence in written packages (see §D);
13. `hashes.json` covering a missing entry / omitting a present entry (both directions, already FORMAT §3 — corpus keeps it honest end-to-end through *install*, not just verify).

## C. Crash-Recovery Corpus — `tests/test_crash_recovery.cpp`

Installation MUST be transactional: extract + verify into a staging directory
under `apps/<id>/staging.<nonce>/` (same filesystem), verify the staged tree,
atomically rename to `versions/<v>/`, then atomically flip `current`
(temp-name + rename for both symlink and `current.txt`). Any `lexe` command
sweeps stale staging dirs on startup.

Fault injection: a test-only hook (`LEXE_TEST_FAULT=<site>` env var checked by a
`maybe_fault(site)` helper compiled in tests/debug builds) aborts the process at
named sites. Corpus:

1. killed mid-extraction (staging half-written);
2. killed between staged-verify and version rename;
3. killed between version rename and current flip;
4. killed mid-registry-commit (installation.json half-written → write temp + rename, never truncate-in-place);
5. disk full during update download and during extraction (simulated via fault site);
6. update source disappears mid-download (`file://` source deleted between manifest fetch and package fetch);
7. update applies but health check fails → **automatic rollback** (§E);
8. rollback interrupted mid-flip;
9. uninstall interrupted after removing some recorded files.

Post-condition after EVERY case: `current` resolves to a complete, verified
version or the app is cleanly absent; re-running the interrupted operation
either completes it or aborts cleanly; `lexe repair` clears residue; the
registry never references a missing file; `lexe list` never crashes.

## D. Deterministic-ZIP Completeness

The determinism test MUST assert byte-identity of repeated packs **and**
structurally assert: zeroed timestamps, lexicographic entry order, forward-slash
UTF-8 names (flag bit 11 handling pinned), fixed compression parameters, no
directory entries, no extra fields, no archive comment, stable external
attributes (Unix mode in the external-attrs high word: **0755** for files
executable in the source tree, **0644** otherwise — the only two modes ever
written; no special bits; see FORMAT §1), no ZIP64 records for small archives.
Two different source-tree enumeration orders (created shuffled) MUST still
produce identical packages. Multi-executable payloads (a helper binary beside
the entrypoint) MUST install and run — the round-trip preserves each file's
exec bit, not only the declared entrypoint's.

## E. Health Check + Automatic Rollback (minimal 0.1 semantics)

Optional manifest field:

```json
"healthCheck": { "arguments": ["--health"], "timeoutSeconds": 10 }
```

Semantics: after an update is staged and flipped, the runtime runs **the
entrypoint executable itself** (never another program, never a shell) with
exactly these arguments, structured argv end-to-end. Non-zero exit or timeout →
automatic rollback to the previous version and a non-zero `lexe update` exit
with an explanation. No `healthCheck` field → no health gate. This is the whole
0.1 hook surface: `scripts/` remain inert (FORMAT §2) and no package-controlled
shell ever runs.

## F. Update Trust Binding

Explicit tests beyond FORMAT §7's happy path:

1. **cross-app replay** — same publisher ships apps A and B; A's channel entry
   points at B's (validly signed) package → refused (§7.6 id match);
2. `update.json` whose own `id` ≠ installed id (§7.2);
3. stale `update.json` replay after a newer install → downgrade refusal (§7.7);
4. `.sig` valid but for different bytes; `.sig` missing; `.sig` signed by a
   different (valid) key → key-pinning refusal (§7.1);
5. update source URL flipped to another publisher's repo via `lexe source set`
   → next update refused on key pinning, with a message explaining why.

## G. Crypto Scrutiny

* `crypto.cpp` MUST enforce **canonical signatures** itself — reject `s ≥ L`
  (malleability) and non-canonical point encodings if the vendored library
  accepts them; do not rely on the provider.
* RFC 8032 test vectors: positive AND negative (flipped bit in message, in R,
  in s, in public key).
* Provider independence: `crypto.hpp` exposes no orlp types. The vendored
  orlp/ed25519 is the 0.1 provider; libsodium is the intended future default
  (`LEXE_CRYPTO_PROVIDER` CMake option), and the format stays
  provider-independent (FORMAT §4 already fixes raw 64-byte signatures).
* Key files: `0600` enforced and tested on POSIX; private seed never appears in
  any log, error message, or `--json` output (grep-audited).

## H. GUI Thinness Rule

`src/gui/main.cpp` MAY include only the public headers the CLI uses
(`manifest`, `verify`, `installer`, `updater`, `launcher`, `error`, `paths`) and
MUST NOT contain installation logic — it renders reports and calls the same
`lexe_core` entry points as the CLI. Replacing GTK3 with GTK4/Qt later must not
touch a single line under `src/core/`. Enforced by review + an include audit in
the hardening pass.

## I. Evidence Bundle (definition of done for any "it works" claim)

1. full `ctest` output (both platforms);
2. Ubuntu CI run result (link + conclusion);
3. repository tree;
4. verbatim CLI end-to-end transcript;
5. security-review findings with per-finding disposition (fixed / refuted / accepted-risk);
6. explicit remaining-limitations list;
7. an example `.lexe`: entry listing (name, size, method, CRC), decoded
   `lexe.json` and `hashes.json`, and a signature-verification demonstration.

## J. Linux Lifecycle Acceptance (the 0.1 exit criterion)

On a real Linux desktop (VM or physical; CI approximates but does not satisfy
this):

1. double-click `hello.lexe` (opens the GUI via MIME association);
2. install;
3. launch from the desktop menu;
4. publish a signed update to a local repository;
5. `lexe update` picks it up and applies it;
6. force a failing update (health check exits non-zero);
7. observe **automatic rollback** to the working version;
8. remove cleanly — no orphaned files, associations, or menu entries.

When this passes reliably, 0.1 has crossed from an idea into a platform
foundation. Until then, no new features.

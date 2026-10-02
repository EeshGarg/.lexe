# Lexe Package Format 0.1 — Normative

This document defines the `.lexe` package format for `lexeVersion: "0.1"`. Where
[SPEC.md](../SPEC.md) describes intent, this document defines bytes.

It is written to be implementable **without reading the reference
implementation**. If you find yourself needing to consult `src/` to answer a
question about what a package means, that is a defect in this document; please
report it.

## 0. How to read this document

### 0.1 Conformance language

**MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are used in the
RFC 2119 sense. They are addressed to one of three actors, and the document says
which every time it matters:

| Actor | Means |
|---|---|
| **a writer** | anything that produces a `.lexe` file |
| **a reader** | anything that parses one: a verifier, an installer, an inspector, a repository gate |
| **a runtime** | a reader that also installs and executes packages |

A rule addressed to a writer is not automatically a rule a reader enforces, and
the difference is load-bearing. §1's determinism rules bind writers; a reader
that rejected a package for being compressed at level 6 would reject conformant
output from a legitimate writer that made a different choice.

### 0.2 What belongs in this document, and what does not

Every requirement here had to pass one test:

> Could another, independently written implementation behave differently here
> and still correctly consume the same `.lexe` package?

If **yes**, the behaviour is not part of the package format, however sensible it
may be. It lives in [REFERENCE-POLICY.md](REFERENCE-POLICY.md) instead, which
documents what the reference `lexe` runtime happens to do.

If **no** — if two implementations disagreeing here would read the same package
differently, or would disagree about whether it is a package at all — it is
specified here, precisely.

This distinction is why, for example, the exact filesystem paths a runtime
installs into are **not** in this document, while the *identity* of an installed
version is; and why the reference runtime's decompression-ratio limit is **not**
a validity rule, while the archive's structure is. §10 and
[REFERENCE-POLICY.md](REFERENCE-POLICY.md) explain both.

A second question decides close calls:

> Can a package observe or depend upon this behaviour?

If package compatibility depends on it, that is evidence it belongs in the
contract.

### 0.3 Status of 0.1

Format 0.1 is **frozen**. The rules below will not change meaning under the
`lexeVersion: "0.1"` label. A package that conforms today will be readable by
any conforming 0.1 reader, now and later.

Unknown JSON object members MUST be ignored by readers (§6), which is the one
forward-compatibility hinge: a later format version may add fields, and a 0.1
reader encountering them must not fail. It does **not** license new archive
members — §2 and §3 are closed sets, for the reasons §3 gives.

## 1. Container

A `.lexe` file is a ZIP archive (PKZIP AppNote 6.3 compatible).

Writers (i.e. `lexe pack`) MUST produce **deterministic** archives:

* entries are added in lexicographic byte order of their full path;
* all entry timestamps are zeroed (the reference implementation compiles miniz with
  `MINIZ_NO_TIME`);

  **What this costs a `portable` package, stated because it is not obvious.**
  Zeroed timestamps mean a package carries no *relative* modification order
  between its files. On install, extraction writes them in archive order and
  they take the wall-clock time as they land — so the installed tree's mtimes
  reflect the order they were written, not the order the publisher built them.
  A build system that treats mtime ordering as its rebuild signal will
  therefore draw conclusions the publisher did not intend. Autotools is the
  common case: it may decide `configure` is older than `configure.ac` and try
  to regenerate it with tools the build sandbox does not have and cannot
  fetch, since the build runs with the network denied.

  This is a deliberate trade, not an oversight. Reproducible packing requires
  that the same inputs produce the same bytes, and embedded timestamps destroy
  that. A `portable` package whose build is mtime-sensitive should ship
  pre-generated artifacts and a recipe that does not try to regenerate them —
  for autotools, that means shipping `configure` and invoking it directly
  rather than relying on `make` to decide whether it is stale.
* entry paths use forward slashes (`/`) and are UTF-8;
* compression is DEFLATE at a fixed level (9), or STORE for entries smaller than
  64 bytes;
* each central-directory record carries the entry's Unix permission mode in its
  external attributes (high word), with "version made by" marked Unix: **0755**
  for a file that is executable in the source tree, **0644** otherwise. Only
  these two canonical modes are ever written — no umask leakage, and setuid,
  setgid and sticky bits are never recorded. On filesystems without Unix
  permission bits (e.g. Windows) every collected file is recorded as 0644, so
  helper executables must be packed on a POSIX filesystem;
* no ZIP64 structures. A writer MUST NOT emit them, and a **reader** MUST reject
  an archive carrying a ZIP64 end-of-central-directory record or locator: the
  end record MUST be the classic 22-byte EOCD and the final bytes of the file
  (§2.2). (This previously said a reader MAY reject ZIP64, justified by "§10.1's
  limits" — but §10.1 sets no archive-size or entry-count limit; those are
  reference policy. A MAY made the verdict reader-defined, which is exactly what
  a format rule must not be.) A package that genuinely needs more than 65535
  entries or 4 GiB cannot be expressed in 0.1;
* no encryption; no archive comment;
  no per-entry extra fields or comments beyond what the amalgamated miniz writer
  emits with the settings above.

A **reader** MUST reject an archive that does not occupy exactly the whole
file: the classic end-of-central-directory record MUST be the file's final 22
bytes, with a zero comment length, and the central
directory MUST end exactly where it begins (§2.2 says what must fill the space
before). Bytes before the first local record or after the end record are
covered by no signature. (Appendix A.4 #28 cited this section for that rule; the
section previously stated only the writer's half.)

Compression: a reader MUST accept method 0 (STORE) and method 8 (DEFLATE) for
any entry, whatever its size, and MUST reject every other method. The writer's
"under 64 bytes → STORE" choice is a writer rule only; a reader MUST NOT check it
(Appendix A.5 #33). For a STORE entry the compressed and uncompressed sizes
MUST be equal, and for every entry the decompressed length MUST equal the
declared uncompressed size.

Packing the same input tree twice MUST produce byte-identical `.lexe` files.

## 2. Entry Layout

```text
Application.lexe
├── lexe.json                      REQUIRED  application manifest
├── signatures/
│   ├── manifest.sig               REQUIRED  raw 64-byte Ed25519 signature
│   └── payload.sig                REQUIRED  raw 64-byte Ed25519 signature
│                                  nothing else may appear here — see §3
├── metadata/
│   ├── hashes.json                REQUIRED  per-entry SHA-256 index
│   ├── description.md             optional
│   └── license.txt                optional
├── icons/                         optional  64.png 128.png 256.png scalable.svg
├── payload/                       REQUIRED for role "application"; MUST be
│                                  ABSENT for role "launch"
└── scripts/                       optional  RESERVED — never executed in 0.1
```

### 2.1 Entry path rules

An entry path is a sequence of `/`-separated segments. A reader MUST reject an
archive when any entry path:

* is empty, or is empty after a single trailing `/` is removed;
* is absolute (begins with `/`);
* contains a NUL byte;
* is not well-formed UTF-8 — including an overlong encoding, a UTF-16 surrogate
  half (U+D800–U+DFFF), or a value above U+10FFFF. These are not pedantry: an
  overlong encoding is a second spelling of a character, so a segment that does
  not compare byte-equal to `..` can still decode to it, and every other rule
  here compares bytes;
* contains a backslash (`\`);
* contains a segment equal to `..` or `.`;
* contains an empty segment (`a//b`, or a trailing `/` — §2.2 rejects every
  directory entry, so there is no case where a trailing `/` is allowed);
* contains a segment beginning with an ASCII letter followed by `:`
  (a Windows drive designator, `C:`);
* exceeds 1024 bytes in total, or has any segment exceeding 255 bytes, or has
  more than 64 segments;
* has a first segment that is not exactly one of `lexe.json`, `signatures`,
  `metadata`, `icons`, `payload`, `scripts` (this comparison is
  case-sensitive: `Payload/` is not `payload/`);
* is `lexe.json` with anything after it — `lexe.json` MUST be a top-level file,
  never a directory or a path prefix.

A reader MUST also reject an archive when:

* two entries have the same path;
* two entry paths differ only in ASCII case (`payload/App` and `payload/app`).
  Such entries would alias on a case-insensitive filesystem, so one could
  overwrite the other after extraction. This is rejected regardless of the
  host filesystem, because whether a package is valid MUST NOT depend on where
  it is read;
* an entry is a symbolic link (ZIP external attributes: Unix mode `S_IFLNK`);
* an entry is encrypted (general-purpose bit 0 or 6 set), or uses a compression
  method other than STORE or DEFLATE (§1);
* a required entry is missing;
* `payload/` entries are absent and the manifest's `role` is not `"launch"`.

**Paths are compared as bytes.** Every comparison in this document between
entry paths, or between an entry path and a manifest value, is an exact
byte comparison of UTF-8. No Unicode normalization is applied and no case
folding beyond the ASCII rule above: `é` precomposed (U+00E9) and `e` + U+0301
are two different, individually valid paths, and an archive carrying both is
**valid** under 0.1. Whether 0.2 should reject normalization-equivalent pairs
(they alias on normalizing filesystems, as ASCII case pairs do on folding ones)
is recorded in Appendix A.7; a 0.1 reader MUST NOT reject for it.

### 2.2 One archive, not two

A ZIP records every entry twice: once in a local header beside the data, once in
the central directory at the end. A reader MUST treat the **central directory**
as authoritative, and MUST reject the archive when the two disagree about an
entry's name, compression method, or sizes.

This is not tidiness. When the two copies disagree, two conforming ZIP readers
see two different archives — and only one of those views is the one the
package's hashes and signatures were computed over. The other is unaccounted
bytes with a signature apparently vouching for them. A local header naming
`payload/../../ev` beside a central directory naming `payload/data.txt` is the
concrete case: it verified cleanly, and an independent validator that happened
to read local names disagreed with the reference implementation about what the
file even contained.

A reader MUST further require that the bytes before the central directory are
**exactly** the local records it names, laid end to end:

* no bytes before the first local record;
* no gap or overlap between records;
* no gap between the last record's data and the start of the central directory.

The central directory itself MUST be **exactly** the records its end record
counts: the end record's two entry counts MUST be equal, and that many central
records, each beginning where the previous one ends, MUST fill the space from
the central directory's offset to the end record — no slack bytes, and no
further record the count does not include. (An uncounted record is invisible
to a reader that walks the count and listed by one that scans; it was used to
show `signatures/evil.bin` to one reader and not the other.)

Without this, a complete extra local record can be spliced into the gap and the
central directory's offset advanced past it. Checking only that the archive ends
cleanly (§1) does not catch it: that establishes there is nothing after the
central directory, and says nothing about holes before it.

A data descriptor (general-purpose bit 3) is tolerated: it legitimately leaves
the local size fields zero, with the real values following the data. Its
presence changes where a record ends, not whether every byte is accounted for.

A reader MUST reject an archive containing a ZIP **directory entry** (a record
whose name ends in `/`), and a writer MUST NOT emit one.

An earlier draft of this section said such entries should be *ignored*, on the
reasoning that a directory record carries no content and so has nothing to
smuggle. That reasoning is false, and was demonstrated to be false: a ZIP
directory record can carry data bytes perfectly well. Ignoring them was worse
than a missed opportunity — an entry that a reader skips is an entry no
subsequent rule applies to, so a directory record named `signatures/evil/` with
a payload attached walked straight past the exact allowlist in §3.2, which was
written for the sole purpose of stopping content appearing there.

Rejection also makes the reader's model of an archive complete: every record in
the central directory is a file, every file is either signed directly or
covered by §3.6, and there is no third kind of thing. The interoperability cost
is bounded, because a `.lexe` is produced by a `.lexe` writer — not by `zip -r`.

`scripts/` entries are carried but MUST NOT be executed by a 0.1 runtime. See
§3 for what this means for their integrity coverage; a reserved namespace is
still inside the envelope.

## 3. The integrity envelope

This section exists because its absence was a vulnerability.

`signatures/` was excluded from hash coverage as a whole prefix — correctly,
since a hash document cannot cover a signature taken over itself — while §2's
allowlist permitted the prefix in general. Neither rule was wrong on its own.
Together they left a gap: an additional entry under `signatures/` was covered by
no hash, covered by no signature, and rejected by nothing. A package carrying
`signatures/smuggled.bin` reported `verification: OK (signature valid, Ed25519)`
with every stage green, because its hashes really were correct and its
signatures really were valid — the smuggled bytes simply lay outside everything
integrity was computed over.

So 0.1 states the invariant directly:

> **Every byte of a package that can influence installation, execution,
> identity, permissions, compatibility, or user-visible package behaviour MUST
> lie inside the integrity envelope, except the cryptographic signature material
> whose relationship to the signed material is defined below.**

### 3.1 The envelope

| Member | Covered by | Why |
|---|---|---|
| `lexe.json` | `signatures/manifest.sig` directly | it *is* the identity, permissions and execution policy |
| `metadata/hashes.json` | `signatures/payload.sig` directly | it is the index that covers everything else |
| every other member | its SHA-256 digest in `metadata/hashes.json`, which is itself signed | one signature transitively covers all content |
| `signatures/manifest.sig` | — | it cannot sign itself |
| `signatures/payload.sig` | — | it cannot sign itself |

Two signatures, two directly-signed documents, and one transitive step. Every
member of the archive is on this table. There is no fourth case, and that is the
property §3.2 protects.

### 3.1.1 Permission bits are outside the envelope, and therefore inert

A ZIP entry carries a Unix permission mode in its central-directory external
attributes. That mode is covered by nothing: `metadata/hashes.json` digests
entry **content**, and the two signatures cover `lexe.json` and
`metadata/hashes.json`. It can therefore be altered on a signed package without
detection — and this was demonstrated, by flipping a data file's recorded mode
to `04755` on a validly signed package. Verification reported OK with every
stage green, because nothing it checks had changed.

The invariant at the head of this section names permissions explicitly, so this
had to be resolved rather than noted. Three resolutions were available:

| | |
|---|---|
| cover the mode in `metadata/hashes.json` | a format change; its values would stop being digests |
| reject any non-canonical mode | does not help — `0644` → `0755` is a flip *within* the permitted pair |
| **make the mode unable to influence anything** | no format change, and the answer comes from bytes that are signed |

0.1 takes the third, with a correction. The first draft of this rule removed
the mode's influence by deriving executability from *content* — ELF, PE, or a
`#!` line. That closed the hole, but it replaced a publisher **declaration**
with a **heuristic** at a security boundary, and the heuristic is lossy in both
directions: a `.jar`, a .NET assembly, a WASM module and a shebang-less helper
script are all legitimately executable and match none of those magics, while a
data file that happens to begin `MZ` would gain an executable bit nobody asked
for. "The runtime guesses" is a weaker contract than "the publisher declares,
and the declaration is signed."

So the declaration moved inside the envelope instead.

**`metadata/hashes.json` MAY carry an `executable` member**: an array of entry
paths, each of which MUST also be a key of `files`. It is covered by
`signatures/payload.sig` along with the rest of that document, so it is a signed
statement of publisher intent.

```json
{
  "algorithm": "sha256",
  "files": { "payload/bin/app": "…", "payload/bin/helper.sh": "…" },
  "executable": ["payload/bin/app", "payload/bin/helper.sh"]
}
```

A reader MUST then behave as follows:

* When `executable` is present, it is **authoritative**: exactly those members
  are executable, and no others.
* When it is absent — a package written before this member existed — a reader
  SHOULD fall back to examining content (ELF, PE, or a leading `#!`). Treating
  absence as "nothing is executable" would break every existing package's
  helper binaries.
* A reader **MUST NOT** derive executability, or any permission it grants, from
  an entry's recorded ZIP mode.
* A runtime MUST NOT honour setuid, setgid or sticky bits from a package, under
  any circumstances, however they are expressed.

**Two deliberate exceptions, which are the whole of the list.** The external
attributes are still read for two *rejection* rules, and only these:

* the Unix file-type nibble, to reject a symbolic-link entry (§2.1);
* the DOS directory attribute bit, to reject a directory entry (§2.1).

Both decide only whether the package is refused. Neither grants a permission,
selects content, or influences what is installed. An earlier draft of this
section said a reader "MUST NOT derive **any** behaviour" from the mode, which
was simply false against these two rules — and a rule that a conforming reader
must violate to be correct is worse than no rule. They are enumerated instead.

The consequence is that an attacker who flips these bits can cause a package to
be **rejected**, and can do nothing else. That is an availability effect, not an
integrity one, and anybody able to flip them could equally corrupt a content
byte and fail the hash instead.

### 3.2 `signatures/` is a closed set

A reader MUST reject an archive containing any member under `signatures/` other
than exactly `signatures/manifest.sig` and `signatures/payload.sig`.

This is an **exact set, not a pattern**. `signatures/extra.sig` and
`signatures/manifest.sig.bak` are as invalid as `signatures/evil.so`. A later
format version that introduces another signature scheme will give it a specified
name *and* a specified coverage rule in the same breath; it does not get to
arrive unannounced in a directory nothing checks.

The two permitted members are the only bytes in a conforming package that lie
outside the envelope, and neither can carry content: each MUST be exactly 64
bytes, and each MUST be a valid Ed25519 signature over its defined input, or
verification fails.

### 3.3 Coverage is exact in both directions

`metadata/hashes.json`'s `files` object MUST contain exactly one key for every
archive member **except** `lexe.json`, `metadata/hashes.json` itself, and the
two `signatures/` members. Set equality is checked in both directions:

* a covered key naming a member that is not in the archive → reject;
* an archive member that should be covered and is not a key → reject;
* a covered key naming an *excluded* member → reject (a package MUST NOT
  attempt to cover `lexe.json`, `hashes.json` or a signature; doing so is a
  sign of a writer that has misunderstood the envelope).

Both directions matter, and the second is the one that closes smuggling: without
it, any member simply omitted from `files` would be unsigned content in a
package that verifies.

Note what this means for the reserved namespace: `scripts/` is **inside** the
envelope. A 0.1 runtime does not execute it, but a 0.2 runtime might, and
content that a later version may act upon MUST NOT be able to enter a package
unsigned today.

### 3.4 What is signed is what is installed

A runtime MUST NOT install, execute, or otherwise act upon package content it
did not verify. Concretely: the bytes extracted MUST be the bytes whose digests
were checked, read from the same archive in the same operation. A runtime that
verified one file and then re-opened, re-read, or re-fetched the package before
extracting would have a time-of-check-to-time-of-use gap, and the signature
would be proving something about a file that no longer matters.

### 3.5 Verification order

§6 defines the pipeline. The ordering requirement relevant here is that **no
member's content may be acted upon before the stage that authenticates it**,
with one unavoidable exception: a reader must read `lexe.json`'s `role` during
structural checking in order to know whether `payload/` is required (§2), before
any signature has been verified.

That read is safe only because of what a reader MUST NOT do with it. The value
is used solely to choose between two structural rules, both of which reject.
A reader MUST NOT derive trust, identity, permissions, execution policy, or any
other decision from the manifest before `signatures/manifest.sig` has verified
over its exact bytes. A lying `role` therefore buys nothing: it only changes
which rule rejects the package.

### 3.6 The hash document — `metadata/hashes.json`

The index that carries the envelope's transitive coverage. It is a JSON object
subject to the strict-JSON rules of §5.0 (UTF-8, no BOM, no duplicate keys at any
depth, no trailing data) and MUST NOT exceed 16 MiB.

```json
{
  "algorithm": "sha256",
  "files": {
    "icons/128.png": "9f86d081884c7d65…",
    "metadata/description.md": "…",
    "payload/bin/example": "…"
  }
}
```

* `algorithm` MUST be present and MUST be the string `"sha256"`. A reader MUST
  NOT infer the algorithm from digest length.
* `files` MUST be a JSON object. Its keys are full entry paths, exactly as they
  appear in the archive.
* Each value MUST be a 64-character **lowercase** hexadecimal string. An
  uppercase digest is malformed, not merely mismatched: a reader comparing
  digests case-sensitively is conforming, so a package with uppercase digests
  would be read differently by different implementations, which is precisely
  what a format rule must prevent.
* Coverage is exact in both directions, per §3.3.
* Verification MUST fail if any covered member's recomputed SHA-256 differs from
  its recorded digest.

Digests are computed over the member's **decompressed** bytes.

**`executable`** (optional) is an array of entry paths declaring which members
are executable, per §3.1.1. Each element MUST be a string and MUST also be a key
of `files` — a path that is not covered by a digest cannot be declared
executable, because the declaration would then apply to content nothing
authenticates.

A writer MUST emit the member whenever it can, **including as an empty array**.

Omitting it when nothing is executable seems harmless and is not: absence means
"fall back to examining content", so a package with no executables at all — but
with, say, a text file beginning `#!` — would have that file made executable by
the fallback. The false positive the declaration exists to remove, reintroduced
for exactly the packages that needed it least. `[]` says "nothing here is
executable"; absence cannot say it.

A reader MUST reject the package when `executable` is present and any of the
following holds:

* it is not an array;
* any element is not a string;
* any element is not a key of `files` — a path with no digest cannot be declared
  executable, because the declaration would then apply to content nothing
  authenticates;
* any element is not under `payload/`;
* the same path appears more than once.

These are checked at **verification**, not at extraction, and the distinction is
deliberate. By extraction time the bytes are authenticated and a nonsense entry
is inert — the declared string is only ever compared against archive paths,
never used to build a filesystem path. But a typo accepted at verification
surfaces as "Permission denied" at first launch, arbitrarily far from its cause,
after a verifier said the package was fine. That is exactly what set-equality on
`files` exists to prevent, for the same reason. A writer generates this list
itself, so strictness costs a publisher nothing.

A reader MUST NOT treat an unrecognised member of this document as an error
(§5.0). `executable` was itself added during the 0.1 freeze, and a reader that
rejected unknown members would have made adding it impossible.

## 4. Signatures

Signature scheme: **Ed25519** (RFC 8032), 64-byte raw signatures, stored as raw
binary (not hex, not base64).

* `signatures/manifest.sig` — signature over the **exact bytes** of the stored
  `lexe.json` entry (after decompression, before any JSON parsing).
* `signatures/payload.sig` — signature over the **exact bytes** of the stored
  `metadata/hashes.json` entry.

Signing raw entry bytes, not parsed structures, means no JSON canonicalization is
required anywhere.

**Verification is strict.** RFC 8032 leaves implementations room to disagree on
edge-case signatures, and two readers that disagree on whether a signature is
valid disagree on whether a package is authentic. A reader MUST reject:

* a signature whose scalar `S` is not less than the group order `L`;
* a non-canonical encoding of the signature's `R` or of the public key `A`;
* a public key `A` of small order — including the identity point, for which a
  "signature" verifies over **every** message without anyone holding a key.

(These were enforced by the reference implementation and recorded only in
Appendix A.4 #30; an independent reader built from this section accepted the
identity-point key. They are format rules.)

### Publisher key encoding

`publisher.publicKey` in the manifest is the string

```text
"ed25519:" + base64(32-byte public key)
```

Base64 is the standard RFC 4648 alphabet **with** padding. Readers MUST reject any
other prefix or a decoded length ≠ 32.

The encoding MUST be **canonical**: the prefix is exactly `ed25519:` (case
sensitive), followed by exactly 44 characters of the standard alphabet ending in
one `=`, with no whitespace, and with the unused low bits of the final character
zero — equivalently, re-encoding the decoded 32 bytes MUST reproduce the string.
Base64 otherwise allows several spellings of one key, and a key must have exactly
one (Appendix A.3 #10).

### Key files (developer tooling)

`lexe keygen` writes a JSON key file:

```json
{
  "algorithm": "ed25519",
  "publicKey": "ed25519:BASE64…",
  "privateSeed": "BASE64 of the 32-byte seed"
}
```

The keypair is re-derived from the seed on every use. On POSIX the key file MUST be
created with mode `0600`.

## 5. Manifest — `lexe.json`

### 5.0 Strict JSON

Every JSON document this format defines — `lexe.json`, `metadata/hashes.json`,
and `update.json` (§7) — MUST satisfy all of the following. A reader MUST reject
a document that does not.

* **Valid UTF-8**, with **no byte-order mark**. A BOM is not whitespace and is
  not permitted before the top-level value.
* **No duplicate object member names, at any nesting depth.** This is the rule
  that most often surprises implementers, because most JSON parsers silently
  keep the last (or the first) of a repeated key. It is required here because a
  document with a duplicated `publicKey` or `entrypoint` can be read two ways,
  and two implementations — or a verifier and the human reviewing it — could
  read it differently. A signature over ambiguous bytes proves less than it
  appears to.
* **RFC 8259 syntax**, nothing laxer: no comments, no trailing commas, no
  single quotes, no `NaN`/`Infinity`, no leading zeros, no raw control
  characters inside strings, and a number whose magnitude exceeds an IEEE-754
  double (`1e999`) is rejected rather than rounded to infinity.
* **No raw NUL byte anywhere** in the document. RFC 8259 already excludes it
  (it is neither whitespace nor permitted unescaped in a string); it is stated
  because common parsers treat it as end-of-input, which turns
  `{…}` + NUL + *anything* into a document that "ends cleanly" and silently
  discards signed bytes. `\u0000` (escaped) is ordinary JSON and allowed.
* **No unpaired surrogate escape** (`"\ud800"` alone): it denotes no character,
  and implementations disagree about what to do with it.
* **No trailing data** after the top-level value.
* **A JSON object** at the top level.
* Within the applicable size budget (§10.1).

`null` is treated as **absent** everywhere in these documents. `"entrypoint":
null` and an omitted `entrypoint` are the same thing, for required fields and
forbidden fields alike. A reader MUST NOT distinguish them.

Numbers that this format declares as integers MUST be written as integer
**tokens**. `1048576` is an integer; `1.0` and `1e6` are not, even though they
denote integral values.

0.1 declares exactly one such field: **`install.estimatedSize`**, a non-negative
integer number of bytes. (This was previously unstated, which left the
integer-token rule with nothing to apply to — a rule with no subject, found by
building a conformance corpus from this document.)

**Unknown object members MUST be ignored** (forward compatibility). This applies
at every level: the top-level object and every nested object alike. A reader
MUST NOT reject a manifest for carrying a member this version does not define.

Where a length is given in this document, it is a count of **bytes**, not of
characters or code points.

### 5.1 Role

`role` selects which of the two `.lexe` artifact kinds this manifest describes.

| Value | Meaning |
|---|---|
| `"application"` | an installable application package (the default when absent) |
| `"launch"` | a launch reference naming an already-installed application |

The role is part of the SIGNED manifest, so it cannot be changed by renaming
the file. A handler MUST dispatch on the role, never on the file name or
extension. An unrecognised role MUST be rejected.

### 5.2 Fields required for every role

These five are required for every role, and are checked before `role` is read.
Per §5.0, `null` counts as absent: `"name": null` is a missing field, not a
type error.

| Field | Constraint |
|---|---|
| `lexeVersion` | MUST be exactly the string `"0.1"`. Compared literally — `"0.1.0"` and `"0.10"` are other versions, not this one |
| `id` | 2+ dot-separated segments of `[a-zA-Z0-9-]+`, ≤ 255 bytes |
| `name` | non-empty, ≤ 1024 bytes |
| `version` | see below |
| `publisher.name` | non-empty, ≤ 1024 bytes |
| `publisher.publicKey` | ≤ 128 bytes; see §4 |

**`id`.** "Reverse-DNS" describes the convention, not the rule: `-` is legal
anywhere in a segment, including first, so `-foo.bar` is a valid App ID even
though it is not a valid DNS name. The rule is the character class above and
nothing more.

**`version`.** The value is not only compared (§8) — it is used verbatim as a
path component by implementations that store versions as directories, and as
part of lock and lease file names. Its grammar is therefore much narrower than a
display string:

* 1 to 64 bytes;
* MUST NOT be `.` or `..`;
* MUST NOT contain any byte ≤ 0x20 (every C0 control, and space) or 0x7F;
* MUST NOT contain `/`, `\` or `:`.

Bytes ≥ 0x80 are permitted, so a version may be non-ASCII; the length bound is
in **bytes**, so a 64-character non-ASCII version can exceed it.

### 5.3 Fields required for `role: "application"`

These MUST be present for an application, and MUST be ABSENT for a launch
reference — the two roles are structurally distinct, not merely differently
labelled.

| Field | Constraint |
|---|---|
| `applicationType` | `"native"`, `"portable"` or `"windows"` |
| `architectures` | non-empty array; recognised values: `x86_64`, `aarch64` |
| `entrypoint.executable` | relative path inside `payload/`, under the **same grammar as an entry path (§2.1)**: no leading `/`, no `..` **or `.`** segment, no empty segment or trailing `/`, no backslash, no NUL, no drive designator. It is compared to archive entries as the exact bytes of `payload/` + value |
| `install.mode` | MUST be `"bundled"` in 0.1 (`network`/`launcher` → "unsupported in 0.1") |
| `build` | REQUIRED for `"portable"`, FORBIDDEN otherwise (§5.8) |

`applicationType` decides what the payload IS, and therefore what §6.7 demands
of the archive:

| Value | The payload is | `entrypoint.executable` names |
|---|---|---|
| `"native"` | the compiled program, for Linux | an ELF entry that MUST be present in the archive |
| `"portable"` | source code | the file the build MUST PRODUCE, and which MUST NOT be present in the archive |
| `"windows"` | the compiled program, for Windows | a PE entry that MUST be present in the archive |

`architectures` means something slightly different for each, and is a hard gate
in all three: the host's ISA MUST be one of them for the package to install
(§6.8).

| Value | `architectures` means |
|---|---|
| `"native"` | the entrypoint ELF targets one of these |
| `"portable"` | the build recipe is declared to produce a working program for these |
| `"windows"` | the entrypoint PE targets one of these |

A `"windows"` payload is not runnable on Linux by itself, so such a package
MUST permit a foreign-OS execution chain in `execution.allowedChains` — one
whose id contains `wine` or `proton`, including layered forms like
`proton+fex` (§5.5). A `"windows"` package that permits none, **including one
that relies on the default `["native"]`**, MUST be rejected: silence is not
consent to run under a compatibility layer. It MUST also be rejected when
`missionCritical` is true, which is the same contradiction stated directly —
mission-critical execution requires a Linux-native, host-ISA-native
realization, and a Windows payload has none by construction.

### 5.4 Fields required for `role: "launch"`

| Field | Constraint |
|---|---|
| `launch.applicationId` | the installed App ID this reference launches; same shape as `id` |

A launch reference MUST NOT carry any `payload/` entries (§6.7). Its own `id`
SHOULD NOT be the target application's id: a trust store binds ids to keys, and
a locally-signed reference must not bind a real application's id to a local
key. This implementation uses the fixed id `org.lexe.launch`.

`launch.applicationId` MUST be absent for `role: "application"`.

### 5.5 Execution policy — `execution`

| Field | Default | Constraint |
|---|---|---|
| `execution.missionCritical` | `false` | boolean |
| `execution.allowedChains` | `["native"]` | array of chain ids `[a-zA-Z0-9-+_]+`, each ≤ 1024 bytes; **an absent or empty array means `["native"]`** |

`missionCritical` is an EXECUTION RESTRICTION, not a safety certification. When
it is `true` the runtime MUST require a Linux-native, host-ISA-native
realization of a verified package, and MUST forbid ISA translation, Wine/Proton,
foreign-OS execution, compatibility fallback and any "run anyway" affordance.
If strict native execution cannot be achieved, execution stops.

A manifest with `missionCritical: true` and any `allowedChains` entry other than
`"native"` is a contradiction and MUST be rejected.

`allowedChains` is the set a resolver may choose from and a frontend may offer.
A user preference may narrow or reorder it; it MUST NOT extend it.

**Chain ids.** A chain id is one layer, or several joined with `+`, outermost
first. Each layer is one of:

| Layer | Kind | Runs |
|---|---|---|
| `native` | — | the payload directly; contributes no argv prefix at all |
| `fex`, `box64`, `qemu-user` | ISA translation | a foreign-ISA **Linux** binary |
| `wine`, `proton` | foreign OS | a **Windows** binary on Linux |

A layered id puts the foreign-OS layer outermost and the ISA-translation layer
innermost — `proton+fex` is Proton over FEX, for a Windows x86-64 payload on an
ARM64 host. The reverse (`fex+proton`) is not a chain.

A chain "runs a foreign-OS payload" when any of its layers is a foreign-OS
layer. That is the property §5.3 requires of a `"windows"` package.


**An absent or EMPTY `allowedChains` means `["native"]`.** Both forms are
accepted and both mean the same thing. An implementer reading an earlier draft
of this section — which said the array must be non-empty — would have rejected a
package this runtime accepts, which is the precise failure a format document
exists to prevent.

Each chain id MUST match `[A-Za-z0-9+_-]+` and MUST be ≤ 1024 bytes. An
**unrecognised** chain id is NOT an error: a package may name a chain a given
reader has never heard of, and the reader simply cannot offer it. Rejecting
would make every package that mentions a future chain unreadable today.

### 5.6 Launch semantics — `launch`

| Field | Default | Constraint |
|---|---|---|
| `launch.mode` | `"gui"` | one of `"gui"`, `"console"`, `"service"` |
| `launch.singleInstance` | `false` | boolean; advisory hint for frontends |

Presentation MUST be taken from this declaration and MUST NOT be inferred from
whether the desktop happens to provide a terminal. A `"console"` application
launched without a terminal MUST be given one by the runtime, or have its output
captured and surfaced — it must not silently appear to do nothing. Exit code 0
MUST be recorded as success even when no window appears.

A `"service"` MUST be started detached: the runtime returns once it is running
rather than waiting for it, and the application MUST survive the process that
started it. Because nothing waited for it, the runtime MUST NOT report an exit
status for that launch. It MUST keep the launched version leased for as long as
the application runs, so the files it is executing cannot be removed underneath
it.

Detaching is not supervision. A runtime that does not restart a service, start
it at login, or track its status MUST NOT describe it as though it did.

### 5.7 Optional fields with defaults

`entrypoint.arguments` (`[]`), `install.scope` (`"user"`),
`install.estimatedSize`, `permissions` (`[]`, informational in 0.1), `updates`
(disabled when absent, see §7), `integration` (§9), `publisher.website`,
`runtimeProfile`.

`runtimeProfile` names the [runtime profile](RUNTIME_PROFILES.md) the builder
targeted and gated the build on — `"core-portable"`, `"forward-runtime"` or
`"native-capture"`. It is **declarative, not a promise about the payload**: a
reader MUST still verify conformance itself rather than trusting the string.

A reader that cannot resolve the value — including one naming a profile it does
not know — MUST treat the package as declaring no profile, and MUST NOT
substitute a default. Reading an absent or unknown declaration as
`"core-portable"` makes a package deliberately built as `"native-capture"` —
host-locked by definition — report as a portability failure.


### 5.7.1 `permissions` — the closed 0.1 vocabulary

This section previously said only that `permissions` is "informational in 0.1",
and the document named no valid permission anywhere. That was a real defect in
this specification, found by building a conformance corpus from the prose: an
implementer could not write this check at all, and an independent validator
written from the document correctly accepted `["telepathy"]` while the reference
runtime refused it. A rule that exists only in a freeze record is not a rule.

**The 0.1 vocabulary is closed and complete.** These are the only permissions a
package may request:

| Id | Means | Enforcement in 0.1 |
|---|---|---|
| `network` | outbound and inbound network sockets | **enforced** — the sandbox denies network without it |
| `user-files-selected` | files the user explicitly selects at runtime | advisory — no ambient file access is granted either way |

A reader MUST reject a manifest whose `permissions` array contains:

* any id not in the table above — an unrecognised permission is refused, never
  ignored. A package asking for authority this version cannot express must not be
  installed as though it had asked for nothing;
* the same id more than once. Duplicates are rejected because the approved set is
  recorded with a digest, so two spellings of one request would produce two
  different digests for the same authority.

The array may be absent or empty, and both mean "no permissions requested".

"Informational" applied to `user-files-selected` and was never true of the
vocabulary itself. A later version may add ids; it will add them to this table,
and a 0.1 reader will correctly refuse a package that uses them, which is the
behaviour a closed vocabulary exists to produce.

**`install.scope`** MUST be `"user"` in 0.1. Other values are reserved and a
reader MUST reject them. The reference implementation accepted any non-empty
string, which was an omission rather than an extension point — a package
declaring `"scope": "machine-wide"` was installed per-user anyway, silently
doing something other than what it said.

**`updates.allowSourceChange`** defaults to **`true`**, which is worth stating
because every other security-relevant boolean in this format defaults to off.
It is stated rather than changed: packages already rely on the current default,
and a publisher who wants the stricter behaviour can set it explicitly.

**`updates.enabled`** defaults to `false` and **`updates.channel`** to
`"stable"`.

**`integration.desktopEntry`** defaults to `true`.

### 5.8 Build recipe — `build` (portable packages)

Present exactly when `applicationType` is `"portable"`. A native package
declaring `build` MUST be rejected (there is nothing to build); a portable
package without one MUST be rejected (it can be installed nowhere).

| Field | Default | Constraint |
|---|---|---|
| `build.system` | — | REQUIRED; one of `"make"`, `"cmake"`, `"command"` |
| `build.sourceDir` | — | REQUIRED; relative path inside `payload/`, same path rules as `entrypoint.executable` |
| `build.command` | — | REQUIRED for `"command"`, FORBIDDEN otherwise; non-empty argv of non-empty strings |
| `build.toolchain` | — | REQUIRED, non-empty; bare executable names (no `/`), never absolute paths |

```json
"applicationType": "portable",
"architectures": ["x86_64", "aarch64"],
"entrypoint": { "executable": "bin/app" },
"build": {
  "system": "command",
  "sourceDir": "src",
  "command": ["cc", "-O2", "-o", "bin/app", "src/main.c"],
  "toolchain": ["cc"]
}
```

`build.command` is an **argv**, never a shell string: a shell string is a
second language between the manifest and `exec`, with its own quoting rules and
its own injection bugs. `argv[0]` is resolved on the build sandbox's `PATH`.

`build.toolchain` names the host executables the build needs. It exists so the
host can be checked BEFORE the user is asked to approve anything, and so a host
that cannot build the package can say which tool is missing instead of failing
part-way through a build. Entries are bare names because an absolute path in a
signed manifest would be a claim about a machine the publisher has never seen.

The build is performed at install time, under the rules in §6.9.

## 6. Verification Pipeline (normative order)

`lexe verify`, `lexe install`, and update application MUST run, in order:

1. **Structure** — archive opens; entry paths pass §2; required entries present.
2. **Manifest** — `lexe.json` parses; §5 constraints hold.
3. **Key decode** — `publisher.publicKey` decodes per §4.
4. **Manifest signature** — `manifest.sig` verifies over `lexe.json` bytes.
5. **Payload signature** — `payload.sig` verifies over `hashes.json` bytes.
6. **Hashes** — §3 set equality and digest checks over all covered entries.
7. **Payload role** — the bytes ARE what the manifest declares (§6.7).
8. **Compatibility** (install/update only) — host architecture ∈ `architectures`.
   Skipped for `role: "launch"`, which declares no architectures.

The report distinguishes every failed stage; the CLI exits `3` on any verification
failure.

### 6.7 Payload role

A manifest can only be trusted to describe the artifact if the artifact is
checked against it. Stage 7 closes that gap, BEFORE anything is installed.

For `role: "application"` with `applicationType: "native"`, the entry named by
`entrypoint.executable` MUST:

* be present in the archive;
* be a valid ELF object;
* have ELF type `ET_EXEC` or `ET_DYN` (an executable, or a position-independent
  executable) — a relocatable object or a core file is not runnable;
* target a machine that maps to one of the manifest's `architectures`.

For `role: "application"` with `applicationType: "portable"`, the archive MUST:

* contain at least one entry under `payload/<build.sourceDir>/` — a portable
  package must carry the source it is compiled from;
* **NOT** contain the entry named by `entrypoint.executable`. That file is what
  the build produces on the destination machine. A portable package that ships
  it is a native payload wearing a portable label: the binary that would end up
  installed is one this host never compiled.

For `role: "application"` with `applicationType: "windows"`, the entry named by
`entrypoint.executable` MUST:

* be present in the archive;
* be a valid PE image (an `MZ` header whose `e_lfanew` points, in range, at a
  `PE\0\0` signature);
* have `IMAGE_FILE_EXECUTABLE_IMAGE` set and `IMAGE_FILE_DLL` clear — a DLL is
  a library and cannot be launched, and it carries the executable-image bit
  too, so both must be checked;
* target a machine that maps to one of the manifest's `architectures`. A PE for
  a machine this format version cannot name (i386, ARM32, IA-64) MUST be
  refused as such, rather than reported as a mismatch against a list the
  publisher could not have satisfied.

Recorded plainly, because the consequence is larger than the rule looks: since
`architectures` recognises only `x86_64` and `aarch64`, **a 32-bit Windows
program cannot be named by a conforming 0.1 manifest at all.** There is no
spelling that packages it. That excludes a large and entirely legitimate class
of existing Windows software — much of it precisely the old, unmaintained,
still-needed kind that a compatibility story exists to serve.

This is a deliberate limitation of 0.1 rather than an oversight, and it is the
right shape of limitation: such a package is refused at verification with an
accurate reason, not accepted and then broken at launch. Adding an `i386` value
is a 0.2 question, and it is a real one.

A .NET/CLR image is NOT a verification failure: whether the host can run it is
a host-capability question for the execution resolver, not a question about
whether the bytes are what the manifest says.

For `role: "launch"`, the archive MUST contain no `payload/` entries.

This stage exists because of a real, observed failure: a package declared a
native application while its entrypoint was a C++ SOURCE FILE. Every signature
and hash was valid — the package was internally consistent and completely
wrong. Source belongs in a portable-code package and must go through host-ISA
compilation; it must never be installed as a native executable. The portable
rule above is the same requirement in the other direction, so neither type can
be used to smuggle the other's payload past verification.

Note the ordering: stage 7 runs AFTER hashes, so a tampered entrypoint is
reported as an integrity failure (stage 6), not as a role failure.

### 6.8 Compatibility

Stage 8 runs for `lexe install` and for an update, and is skipped for
`lexe verify` unless asked for and for `role: "launch"` (which declares no
architectures). The host's ISA MUST appear in `architectures`.

For `applicationType: "portable"` this is a statement about what the build
recipe is declared to produce, not about bytes already in the package. It is
still a hard gate: a package that does not claim this ISA is not installed on
it, and the compile in §6.9 never runs.

### 6.9 Host-ISA compilation (portable packages)

Installing a `applicationType: "portable"` package COMPILES its source on the
destination machine. That is the point of the type — one `.lexe` becomes native
to the machine it lands on — and it is also the most dangerous thing a package
format can ask for, so all four of the following MUST hold. A runtime that
implements any three of them has implemented remote code execution.

**1. Approval gates the operation.** The compilation MUST require explicit
authorization from the owner of the installation, obtained for this package and
this version, and MUST NOT be implied by a general "yes" to installing. Without
it the install MUST be refused before any toolchain is probed and before
anything is staged. The authorization MUST be recorded (§9 `build.json`).

The authorizing party for an `install.scope: "user"` installation — the only
scope 0.1 supports — is the user who owns that installation. A runtime MUST NOT
present this as an administrator's approval when no privileged authority was
involved.

**2. The build runs unprivileged and isolated.** It MUST run with no more
privilege than the installed application would receive, inside the same
isolation the runtime launches applications in, with:

* the **network denied unconditionally** — a `network` permission in the
  manifest MUST NOT reach the build. A build that downloads is fetching
  unsigned code onto the machine at install time, behind a signature that says
  nothing about what was fetched;
* **no display access**, whatever `launch.mode` says;
* a **writable build tree** (the staged version directory) and nothing else of
  the user's writable by it;
* a sanitized environment, as for a launch.

If the isolation cannot be established, the install MUST fail. Building
unconfined is not a fallback.

**3. The output is verified before it is used.** A build exiting 0 proves
nothing. The file named by `entrypoint.executable` MUST, after the build:

* exist;
* be a valid ELF object;
* have ELF type `ET_EXEC` or `ET_DYN`;
* target **the host's** machine — not merely one of `architectures`. A recipe
  that cross-compiles has not produced a host-ISA native executable.

This is §6.7's question asked of bytes that did not exist when the package was
signed.

**4. Approval grants no privilege.** It authorizes the operation. It MUST NOT
elevate the build, the installer, or the application.

**Where the build runs.** `build.sourceDir` declares where the sources are. It
is **not** a working directory and **not** a boundary, and the three drivers do
not treat it alike:

| `build.system` | invoked as | the recipe's own working directory | reaches `build.sourceDir` |
|---|---|---|---|
| `make` | `make -C <sourceDir>` | `payload/<sourceDir>` — `make -C` chdirs make | by the driver |
| `cmake` | `cmake -S <sourceDir> -B lexe-build`, then `cmake --build lexe-build` | the payload root | by the driver, as `-S` |
| `command` | `build.command`, exactly as written | the payload root | **not at all** |

`entrypoint.executable` is resolved from the **payload root** under every
driver. A `make` recipe therefore writes it one level up (`../bin/app`), and a
`command` recipe writes it where it already stands (`bin/app`).

A `command` recipe is the escape hatch: its argv runs unchanged, so a recipe
that means to run `./configure` or `make` inside the sources must say so
(`["sh", "-c", "cd src && ./configure && make"]`). This is stated because it is
not inferable from `sourceDir`'s presence, and because the failure it produces
— `./configure: not found` with the file demonstrably packaged — names the
symptom and not the cause.

**`sourceDir` confines nothing.** The build gets the whole staged version
directory writable, which is what item 2 above says and all it says. A recipe
can read and write every `payload/` entry whether or not it lies under
`sourceDir`; `make -C` and `cmake -S` change a tool's directory, they do not
restrict what a recipe can reach. 0.1 enforces no boundary *inside* the
payload, and a publisher must not read one into `sourceDir`.

**The build must happen before promotion.** Every failure above — including a
refused approval — MUST leave a previously installed version of the application
exactly as it was.

**The result MUST be recorded** as described in §9, because it is not covered
by the package's signed `hashes.json`: it did not exist when the package was
signed. A runtime that does not record it cannot detect tampering with exactly
the binaries it compiled itself.

## 7. Updates — `update.json`

`manifest.updates.manifest` is an `https://` URL (the runtime also accepts
`file://` and plain filesystem paths, which the test-suite uses). The runtime
fetches `update.json` and its detached signature at the same URL + `".sig"`
(raw 64-byte Ed25519 over the exact `update.json` bytes, same publisher key).

```json
{
  "lexeVersion": "0.1",
  "id": "com.example.application",
  "channels": {
    "stable": {
      "version": "1.4.3",
      "package": { "url": "https://example.com/releases/App-1.4.3.lexe",
                    "sha256": "…" },
      "lexeVersion": "0.1"
    }
  }
}
```

Applying an update MUST enforce **all** of:

1. `update.json` signature verifies with the **installed** publisher key
   (key rotation is out of scope for 0.1 — a key mismatch aborts with an
   explanation; the user may reinstall manually to accept a new key);
2. `id` matches the installed application;
3. channel entry exists for the app's configured channel (default `stable`);
4. downloaded package's SHA-256 matches `package.sha256`;
5. the downloaded package passes the full §6 pipeline;
6. the package's own `id` and publisher key match the installed ones;
7. the new version is strictly greater (§8).

The previous version directory is retained for `lexe rollback`.

### 7.0 Field rules

These were enforced by the reference implementation and stated nowhere, which a
conformance corpus built from this document found by producing a definite runtime
behaviour the document did not authorise. A second implementer would have had to
guess at every one.

**`lexeVersion`** is OPTIONAL in `update.json`, and when present MUST be exactly
`"0.1"`. The asymmetry is deliberate: absent means the document does not claim a
format version, and a reader that already knows which format it speaks can
proceed; a *wrong* version is an explicit claim to be a document this reader does
not understand, and MUST be refused. (`lexe.json` differs — there the field is
required, because a package must say what it is.)

**`package.sha256`** MUST be 64 **lowercase** hexadecimal characters. An
uppercase digest is malformed, not merely unusual, for the reason §3.6 already
gives about `metadata/hashes.json`: a reader comparing digests case-sensitively
is conforming, so a document with an uppercase digest would be read differently
by different implementations. The reference runtime used to lowercase the value
before comparing it, and therefore accepted such a document and applied the
update.

**`minimumRuntime`** is **not a field of Format 0.1.** It appeared only in §7's
example, nothing has ever read it, and §5.0 requires readers to ignore unknown
members — so a publisher who set it got no gate and no warning. That is the
`healthCheck` situation (see `HARDENING.md` §E) and the
`metadata/permissions.json` one (Appendix A row 41): a member with no semantics
is a trap, because somebody will believe it is doing something. It has been
removed from the example rather than specified, because gating on a runtime
version needs a version-ordering rule for *runtimes* that 0.1 does not define.

### 7.0.1 Transport

`manifest.updates.manifest` MUST be an `https://` URL. A reader MUST refuse a
plaintext `http://` source, and MUST NOT allow a redirect to downgrade the
transport.

This is not what makes an update trustworthy — every update document is
signature-pinned to the installed publisher key, and a forged one fails check 1
whatever carried it. It is what protects the two things a signature cannot:

* **confidentiality** — an observer otherwise learns which applications a user
  has installed and which versions they are on;
* **freshness** — §7.1's freeze attack is undefended, and over plaintext it
  becomes available to anyone on the network path rather than only to whoever
  operates the source.

`file://` URLs and plain paths are unaffected: they have no transport to
protect.

### 7.1 What update verification does NOT protect against

Two limitations, stated because the alternative is a user believing otherwise.

**Freshness is not protected.** Nothing in the seven checks constrains how *old*
a validly-signed `update.json` may be. A signature does not expire, and 0.1 has
no timestamp or snapshot role. An attacker who controls the update URL can
therefore re-serve an older, still-correctly-signed document indefinitely and
hold a user back from a security fix — the classic freeze attack — and every
check above will pass.

A runtime MUST NOT describe this state in a way that implies more than was
verified. "Up to date" is a claim about what the source offered, not about what
exists: the honest report is that the configured source offers no newer version.

Defending properly needs expiring metadata and a snapshot role (as TUF does),
which 0.1 does not define. If you are operating an update source for something
that matters, serve it over a channel you control end to end, and understand
that the signature proves authorship, not recency.

**Downgrade is prevented only on the update path.** Check 7 refuses an update to
a lower version. It does not govern a *direct install* of an older package: that
package is authentic, and `lexe install` is a different operation with different
semantics. A runtime SHOULD warn when a direct install moves an application
backwards, because "open this `.lexe`" is the primary user gesture and it should
not silently return someone to a known-vulnerable version.

## 8. Version Ordering ("semver-lite")

Split both versions on `.`. Compare component-wise. For a pair of components:

* if **both** are all ASCII digits, compare numerically (leading zeros ignored,
  so `1` == `01`; arbitrary length, no integer overflow);
* if exactly **one** is all ASCII digits, the numeric one sorts **before** the
  non-numeric one (this class partition is what keeps the order total — a raw
  byte compare here would contradict the leading-zero stripping above and break
  transitivity);
* if **neither** is all ASCII digits, compare as unsigned byte strings.

A version that is a strict prefix (fewer components) is smaller. This is a total
order and is the ONLY ordering the 0.1 runtime uses; `version_less` derived from
it is a valid strict-weak-ordering comparator for `std::sort`.

## 9. Required runtime semantics

A runtime installs, updates, rolls back and removes packages. Everything in this
section is required of any conforming runtime. **None of it names a path.**

That split was a deliberate freeze decision, and it is worth stating why. The
earlier draft of 0.1 specified the reference runtime's exact directory tree —
`<LEXE_HOME>/apps/<id>/versions/<version>/`, `current.txt`, `locks/<id>.lock`.
Those paths fail the test in §0.2: another implementation could store installed
applications anywhere it liked and still read, verify, install and run exactly
the same packages. Freezing them would have turned an implementation's storage
choices into an interoperability requirement, and would have made a conforming
implementation that used a database instead of a directory tree "wrong" for no
reason a package could ever observe.

What a package *can* observe is the behaviour below, so that is what is
specified. The reference runtime's actual layout is documented in
[REFERENCE-POLICY.md](REFERENCE-POLICY.md), where it can change without
changing the format.

### 9.1 Version identity

An installed application is identified by its App ID. An installed **version**
is identified by the pair (App ID, version string).

* Installed version content MUST be immutable for as long as that version is
  installed. A runtime MUST NOT modify a version's files in place except to
  replace the version as a whole, or to repair it to its verified content.
* Two versions of the same application MUST be able to exist simultaneously,
  because rollback requires it (§9.3) and because a running application MUST NOT
  be disturbed by an update (§9.4).
* A version string is compared only as defined in §8.

### 9.2 Atomic state transitions

> A failed or interrupted operation MUST leave either the previous valid state
> or the new valid state — never an ambiguous, partially applied one.

Concretely, at any instant at which a runtime could be terminated:

* the set of installed applications, the active version of each, and the content
  of that version MUST be mutually consistent;
* an application that reports as installed MUST be launchable, or MUST report
  honestly that it is damaged — it MUST NOT silently be missing files;
* a failed installation MUST NOT leave a partially-extracted version reachable
  as the active one.

How this is achieved — staging directories, journals, atomic rename, a
transactional database — is not specified. That it holds is.

### 9.3 Rollback

A runtime that has applied an update MUST be able to return to the immediately
previous version, and that version MUST be the content that was originally
verified and installed — not re-fetched, and not reconstructed.

Rollback restores **program content**. It does not, and MUST NOT, roll back
persistent application data (§9.5): a binary rollback is not a data-format
rollback, and pretending otherwise would silently corrupt applications that
migrated their data forward.

### 9.4 A running application is not disturbed

Installing, updating, rolling back or repairing an application MUST NOT modify
or remove the files of a version that is currently executing.

A runtime MUST either refuse such an operation while the version is in use, or
complete it without touching the running version's content. It MUST NOT remove
those files and rely on the operating system's open-file semantics to keep the
process alive.

### 9.5 Persistent data

An application MUST have persistent storage that:

* belongs to the App ID, not to a version — it survives update, rollback, and
  removal of the program;
* is bound to the publisher key that created it. A package signed by a
  **different** key MUST NOT be given access to data retained under the previous
  key. Format 0.1 has no authenticated key rotation (§4), so there is no way to
  prove that a new key is the same publisher; a runtime MUST refuse rather than
  guess, and MUST offer an explicit way to discard the retained data instead;
* cannot be redirected by the package. No manifest field selects a data
  location, because a package that could choose where its data lives could
  choose another application's;
* is never parsed or executed by the runtime.

Removal of persistent data MUST require an explicit, separate instruction. A
confirmation of removal MUST NOT be interpreted as consent to discard data.

### 9.5.1 Permission approval is bound to the application, not to a version

A user's approval of an application's requested permissions persists across
update, rollback and reinstall by the same publisher key. It is **not**
re-requested per version, and a rollback does **not** narrow it.

This was ambiguous and is now decided, because both answers are defensible and
the consequence of leaving it open is a runtime that does something nobody chose.
The consequence of THIS answer, stated so nobody is surprised by it: approving
`network` for version 2.0.0, rolling back to a 1.0.0 that requests nothing, and
later updating to 2.0.0 again will not prompt a second time. The authority was
granted to the application under that key and has not been withdrawn.

The alternative — version-bound approval — was rejected because it re-prompts
for authority the user has already granted, and prompt fatigue is a security
cost, not a security feature. The publisher key is pinned (§9.5), so a *different*
publisher cannot inherit the approval.

What a runtime MUST still do:

* refuse an update whose permission set EXPANDS beyond what was approved, until
  that expansion is explicitly approved — approval covers a set, not a blank
  cheque (this is enforced, and a bare confirmation MUST NOT satisfy it);
* make the approved set inspectable, so a user can see what an application has
  been granted without having to remember when they granted it;
* discard the approval when the application's persistent data is purged.

### 9.5.2 The execution context a launched application receives

Four properties of a launch were specified nowhere in this document, were
discovered only by running foreign programs, and each fails the §0.2 test: a
package can observe them, so a package can work on one conforming
implementation and fail on another. They are specified here for that reason.

**The working directory.** A runtime MUST launch the entrypoint with its working
directory set to a directory the application MAY write to, and that directory
MUST NOT be the installed content directory. A package MUST NOT assume that its
payload is reachable by a path relative to the working directory; content is
found relative to the executable's own location.

Both halves matter and for different reasons. Without the first, a program that
writes a file to its own working directory behaves differently on every
implementation — and half of them break. Without the second, the working
directory becomes the installed tree, which makes the application's own content
writable and turns every "save a file next to me" program into a self-modifying
package. Publishers should read this as: a relative path on open is a path into
your data, never into your payload.

**The environment.** A runtime MUST reset the environment to a defined set
rather than inheriting the caller's, and MUST NOT forward any variable that
confers authority over the launch — `LD_PRELOAD`, `LD_LIBRARY_PATH` and their
equivalents on other loaders. It MUST provide locale configuration sufficient
for the application to handle non-ASCII text.

That last clause reads like a detail and is not. Measured on a real
implementation: with no locale in the environment, non-ASCII bytes in arguments
and filenames reached a Windows-chain application with the high bit stripped
from every byte, and opening a file by its own non-ASCII name failed — for a
package that was intact and correctly signed, on a compatibility layer that was
behaving correctly. An environment stripped for safety had silently become an
environment that corrupts text.

**The standard streams.** A runtime MUST NOT substitute a stream of a different
kind for the one its caller provided. If the caller's `stdout` is a regular
file, the application's `stdout` MUST be a regular file; if the caller closed
it, the application MUST find it closed. A runtime MAY interpose — to relay, to
retain output for diagnostics — only where the interposition is not observable,
which in practice means the caller's stream was already a pipe.

This is the same §0.2 test as the two properties above, and it was found the
same way. Measured on a real implementation, running one binary directly and
then through the runtime with identical redirection:

| caller's `stdout` | direct | through the runtime |
|---|---|---|
| regular file | regular, seekable | **pipe, not seekable** |
| closed (`>&-`) | closed; `write` gives `EBADF` | **pipe; `write` reports success** |

The second row is the one that matters. Closing file descriptor 1 is how a
program is told to produce nothing. It produced output anyway, and a program
that checks for `EBADF` to notice was told its write had landed when nothing
could receive it. The first row is quieter and still a conformance problem: a
pager, a progress renderer, or anything that seeks its own output behaves
differently inside the runtime than outside it, for a package that is intact
and correctly signed.

A runtime that wants to keep a copy of a failing application's output must do so
without changing what the application sees, and must accept that it cannot
always keep one. Diagnostics are the runtime's convenience; the stream shape is
the application's environment, and a package can tell them apart.

**Known limitation, to be resolved in a later version.** The *names* by which an
application discovers its own writable data location are not fixed by 0.1. The
reference implementation sets `LEXE_APP_ID`, `LEXE_APP_DATA` and
`LEXE_APP_CACHE` ([REFERENCE-POLICY.md](REFERENCE-POLICY.md)), but a package
that reads them is relying on that implementation, not on this format. This is
recorded as a gap rather than closed here, because closing it means adding a
required interface to a frozen format, and that is a 0.2 decision — not
something to slip in under a clarification. Until then, a package that must be
portable across implementations should treat its working directory as the
writable location it was given.

**Background work and teardown.** A runtime MAY terminate the entrypoint's
descendants when the entrypoint exits, for any launch mode other than
`service`. A package whose work must outlive its entrypoint — a launcher that
starts a worker and returns, which is the commonest shape in some ecosystems —
MUST declare `launch.mode: "service"` (§5.6); it MUST NOT rely on descendants
surviving any other mode.

A runtime that does tear descendants down SHOULD say so in its report for that
launch. It is otherwise indistinguishable, to the caller, from an application
that started and chose to do nothing — and reporting a successful launch of an
application whose actual work was killed before it ran is the most misleading
outcome a launcher can produce.

Note what that SHOULD can and cannot ask for. A runtime can report the RULE that
applied to a launch; it cannot generally report that descendants actually
existed. In the reference implementation nothing outside the sandbox can tell the
two cases apart — the sandbox process exits identically whether or not the kernel
had anything left to kill in its PID namespace — so "we tore something down" and
"there was nothing to tear down" are not distinguishable after the fact. The
clause is therefore satisfied by stating the applicable rule, and an
implementation that claimed to have observed a teardown it had not observed would
be worse than one that says nothing. See
[REFERENCE-POLICY.md](REFERENCE-POLICY.md) §2.2 for where this runtime states
it.

### 9.6 Isolation between applications

One installed application MUST NOT be able to read or modify another's
persistent data, installed content, or installation records through any
mechanism the runtime provides.

### 9.7 Compiled content is verified before it is executed

This one has teeth because a portable package's entrypoint is produced on the
host, so no signature in the package covers it.

A runtime that compiles a portable package (§6.9) MUST record the digest of each
compiled product at build time, and MUST verify a compiled entrypoint against
that record before executing it. It MUST **fail closed**: if a portable
application has no recorded digest for its entrypoint, the runtime MUST refuse
to launch it.

Falling back to "unchecked" here would leave exactly the binaries the runtime
built itself as the only ones it never notices being replaced.

**The trust boundary this assumes, stated plainly.** That recorded digest is
*local* state: it was produced on this host at build time, and no publisher
signature covers it — there cannot be one, because the publisher never saw the
binary. So the guarantee is asymmetric, and it is worth being explicit about
which half you have:

| | digest comes from | an attacker who can write to the runtime's own storage |
|---|---|---|
| bundled package | `metadata/hashes.json`, signed by the publisher | cannot forge a matching record |
| portable package | a record written locally at build time | can edit the record instead of the binary |

For a portable package, §9.7 protects against a binary being **replaced**; it
does not protect against an attacker who can also rewrite the record. A runtime
MUST NOT claim otherwise. Implementations SHOULD protect the record as well as
they protect their own installation state — and an implementation whose
installation state is writable by an untrusted party has already lost, portable
packages or not.

### 9.8 What a runtime reports

A runtime MUST be able to report, for each installed application: its App ID,
its active version, the publisher key it is bound to, and whether its installed
content still matches what was verified. An implementation that cannot answer
the last question cannot honour §9.2.

### 9.8.1 A launch reference proves only local provenance

A `role: "launch"` artifact (§5.4) is a local shortcut, not a distributable
package. Its signature's entire claim is "the machine that made me made me", and
a runtime MUST verify that claim: a launch reference whose signing key is not
this machine's launch key MUST be refused, and MUST NOT be reported as verified.

This was not enforced, and the shape of the gap is worth recording. A reference
signed by *any* key verified as OK — `lexe verify` even printed the signer's
fingerprint, as though it established something — and opening it launched the
application it named. The blast radius was small: a reference carries no
arguments, so the worst outcome was starting an application the user already had,
in its normal configuration, which anyone able to write that file could have done
with a desktop entry instead. It did not affect the target's trust binding.

It is specified anyway, for the reason that generalises: reporting an artifact as
verified when the only thing its signature could attest was never checked tells a
user, or a repository gate, something untrue. And if a later version lets a
reference carry arguments, a chain selection or a version pin, an unchecked
signature stops being cosmetic and becomes the delivery mechanism.

### 9.9 Icons are validated before they leave the package

An `icons/` member is the one place a package's publisher-controlled bytes are
handed to a rich parser in a process that is **not** sandboxed: the application
runs confined, and its icon is installed into the desktop's theme, where the
session parses it — gdk-pixbuf for PNG, librsvg for SVG — with the user's full
privileges.

A runtime that installs icons into a shared theme MUST NOT install bytes it has
not checked are plausibly the image kind their name claims, and SHOULD bound
their size. Refusing an icon MUST NOT fail the installation: an application with
a missing icon still works, and shipping unvalidated bytes into a directory the
desktop reads is the worse outcome.

A check here is deliberately shallow — a signature and a size, not a decoder.
Adding an image parser to the runtime would add the very class of attack surface
this exists to limit.

The bytes are hash-covered and signed (§3), so this is a defence against a
malicious *publisher*, not against tampering.

## 10. Resource limits

A reader parses untrusted input, so it must be able to refuse input that would
cost more than it is willing to spend. This section says what a reader is
obliged to do about that, and — just as importantly — what it is **not**
permitted to conclude.

### 10.1 Document budgets are format rules

These three are genuinely part of the contract, because a writer must know them
to produce a package every conforming reader will accept:

| Document | Maximum |
|---|---|
| `lexe.json` | 1 MiB |
| `metadata/hashes.json` | 16 MiB |
| `update.json` (§7) | 1 MiB |

A reader MUST reject a document exceeding its budget. A writer MUST NOT produce
one. These are fixed by this document and are not a matter of local policy.

Field-level budgets are likewise fixed, because a manifest that exceeds one is
invalid everywhere:

| Field | Maximum |
|---|---|
| `id` | 255 bytes |
| `version` | 64 bytes |
| `name`, `publisher.name` | 1024 bytes |
| `publisher.publicKey` | 128 bytes |
| each `build.command` element | 1024 bytes |
| each `execution.allowedChains` element | 1024 bytes |
| entry path (§2.1) | 1024 bytes total, 255 per segment, 64 segments deep |

### 10.2 Processing limits are NOT format rules

A reader MAY impose limits on what it will expand or process — total
uncompressed size, entry count, per-entry size, compression ratio — and a
reader that processes untrusted packages **SHOULD** impose some.

But such a limit is a property of the **reader**, not of the package. This
document deliberately does not fix a value for any of them, and the reason is
best seen by trying to write the rule down:

> A package that expands to 199× its packaged size is a `.lexe`.
> A package that expands to 201× its packaged size is not a `.lexe`.

That is not an interoperability rule. It makes validity depend on how well a
compressor happened to perform on one particular payload, it would make a
package become invalid by being recompressed, and two conforming
implementations choosing different thresholds would disagree about whether the
same bytes are a package at all.

So:

* A reader MAY refuse a package that exceeds a processing limit it has set.
* A reader that does so MUST report the refusal as **distinct from a format
  violation**, and MUST make the distinction available to programs, not only to
  humans. "This is not a valid package" and "this is a valid package I decline
  to expand" have different remedies: the first says reject the package, the
  second says raise the limit or do not.
* A reader MUST document the limits it imposes.
* A reader MUST NOT report a package that merely exceeds one of its limits as
  malformed, invalid, or non-conforming. It has not been shown to be any of
  those things.
* A limit MUST be enforced **before** the work it is meant to avoid. A guard
  that fires after the expansion it was protecting against has already happened
  is decoration.

The reference runtime's chosen values are in
[REFERENCE-POLICY.md](REFERENCE-POLICY.md). It reports a limit refusal with the
category `resource-limit`, against `format-invalid` for a genuine violation;
both appear in `lexe verify --json`.

### 10.3 Verification does not promise installability

`verify` answers exactly one question:

> Is this a valid Format 0.1 package, correctly signed, whose content matches
> what was signed?

It does **not** answer "will this install here". Those are different questions
and a reader MUST NOT conflate them, in either direction:

* If a package fails `verify`, it is invalid, and no environment can install it.
* If a package passes `verify`, it MAY still be un-installable **here** — the
  host architecture is not among its declared architectures, a required
  compatibility runtime is absent, a toolchain it needs is missing, the disk is
  full, the App ID is already installed under a different publisher key, or the
  user declines its permissions. None of these are defects in the package.

The rule that follows, and which a conforming implementation MUST observe:

> A package that passes verification MUST NOT be rejected at install time for an
> **intrinsic property of the package**. If installation refuses for a reason
> that is true of the package everywhere, verification should have caught it.

This is not a stylistic preference. `verify` is what a repository gate, a CI
job, or a cautious user runs to decide whether a package is acceptable; if it
passes things the installer refuses, it is handing out an assurance the runtime
does not honour, and a publisher who trusts it ships a package that fails for
every user. Three instances of exactly this were found and fixed while freezing
0.1 — an unknown permission id, a decompression bomb, and a non-UTF-8 entry
name — each of which verified cleanly and then failed at install.

The `compatibility` stage (§6.8) is therefore explicitly **environmental** and
is reported separately: it is the one stage whose result is a fact about the
host rather than about the package.

## Appendix A — Freeze record

Every discrepancy found between this document and the reference implementation
while freezing 0.1, and what was decided about it. Four outcomes:

| | |
|---|---|
| **FORMAT** | required for interoperability. Specified normatively above. |
| **POLICY** | real behaviour, but not required of an implementation. Moved to [REFERENCE-POLICY.md](REFERENCE-POLICY.md). |
| **ACCIDENT** | behaviour that should not become a requirement. Fixed, or explicitly left outside the contract. |
| **DECIDED** | a genuine design question with more than one defensible answer. Resolved deliberately; the reasoning is recorded. |

The test that sorted them is §0.2: *could another implementation behave
differently here and still correctly consume the same package?*

### A.1 Integrity envelope

| # | Finding | Outcome |
|---|---|---|
| 1 | Any member under `signatures/` other than the two `.sig` files was covered by no hash and no signature, and verified OK | **FORMAT** — §3.2, an exact allowlist. Two implementations disagreeing here would disagree about whether unsigned content is present |
| 2 | ZIP directory entries were silently skipped — and could carry data, bypassing finding 1's allowlist because it walks file entries only | **FORMAT** — §2.1, rejected. The earlier draft said "ignore", on a rationale ("nothing to smuggle") that was demonstrated false |
| 3 | Local header and central directory were never compared; name, method and size could disagree | **FORMAT** — §2.2. Two readers would see two different archives; only one view is signed |
| 4 | A complete extra local record could occupy the gap before the central directory; `archive_spans_whole_file` checks only the tail | **FORMAT** — §2.2, every byte before the central directory must belong to a record it names |
| 5 | ZIP external-attribute permission bits are covered by nothing and reached the filesystem | **DECIDED** — §3.1.1, in two steps. The first resolution derived executability from *content* (ELF/PE/`#!`), which closed the hole but replaced a publisher declaration with a heuristic that is lossy both ways: a `.jar`, a WASM module and a shebang-less script lose their exec bit, while a data file beginning `MZ` gains one. Both directions were demonstrated. The final resolution adds an `executable` array to `metadata/hashes.json`, inside the document `payload.sig` already covers, with the content sniff kept only as the fallback for packages predating it. Publisher intent is preserved *and* signed |
| 5a | §3.1.1's first draft said a reader "MUST NOT derive **any** behaviour" from the recorded mode — false, since symlink and directory rejection both key on that field | **FORMAT** — the prohibition is narrowed to executability and granted permissions, and the two rejection rules are enumerated as exceptions. A rule a conforming reader must violate to be correct is worse than no rule |
| 5b | The contiguity check added for finding 4 assumed a 16-byte data descriptor; APPNOTE 4.3.9.3 makes its signature word optional, so a 12-byte descriptor was rejected as an overlap | **FORMAT** — §2.2, the length is derived from whether the signature word is present. Fail-closed, so not a security defect, but it refused a conformant archive — a reminder that a new check is new surface |
| 6 | An entry name was not required to be UTF-8, though `utf8_segment_to_path` documented that it was | **FORMAT** — §2.1. An overlong encoding is a second spelling of a character, so a byte comparison against `..` can be evaded |

### A.2 Where verification and installation disagreed

Each of these let `verify` pass a package `install` refused. §10.3 now states
the rule they violate.

| # | Finding | Outcome |
|---|---|---|
| 7 | A decompression bomb passed all seven stages; `install` refused it | **DECIDED** — the guard moved into the reader so every consumer inherits it, and the limit itself became POLICY (§10.2). It is not a validity rule: 199× valid and 201× invalid is not an interoperability contract |
| 8 | `permissions` vocabulary was enforced by consumers but not by verification | **FORMAT** — §5.7's vocabulary is closed and checked at stage 2 |
| 9 | A non-UTF-8 entry name verified and failed later | **FORMAT** — see finding 6 |

### A.3 Publisher identity

| # | Finding | Outcome |
|---|---|---|
| 10 | Base64 leaves the final group's unused bits free, so one key had many spellings; trust was pinned by comparing the *string* | **DECIDED** — both halves. A package MUST carry the canonical encoding (§4), so there is one spelling on the wire; and identity comparison decodes to key material, so it does not depend on that rule holding elsewhere. A recorded key predating the rule still matches its own publisher |
| 11 | `trust.cpp` required canonical encoding of trust records; the manifest did not | **FORMAT** — §4, now consistent |

### A.4 Manifest rules that existed only in code

All **FORMAT**: an implementer following the old text would have produced or
accepted packages this runtime does not.

| # | Finding |
|---|---|
| 12 | `version` grammar: 1–64 bytes, not `.` or `..`, no byte ≤ 0x20 or 0x7F, no `/ \ :` — the value is used as a directory name |
| 13 | Byte budgets for `id` (255), `name` and `publisher.name` (1024), `publisher.publicKey` (128) — §10.1 |
| 14 | `lexe.json` ≤ 1 MiB, `hashes.json` ≤ 16 MiB, `update.json` ≤ 1 MiB — §10.1 |
| 15 | No UTF-8 BOM; no duplicate object keys at any depth; no trailing data — §5.0 |
| 16 | JSON `null` is treated as absent everywhere, for required and forbidden fields alike — §5.0 |
| 17 | An integer field must be an integer *token*: `1.0` and `1e6` are rejected — §5.0 |
| 18 | `execution.allowedChains`: an absent **or empty** list means `["native"]`; chain ids match `[A-Za-z0-9+_-]+` and are ≤ 1024 bytes |
| 19 | `build.command` elements reject NUL and are ≤ 1024 bytes; `build.toolchain` entries reject `\` as well as `/` |
| 20 | `build.command` is "forbidden" in the sense of absent, `null`, **or empty** for `make`/`cmake` |
| 21 | Payload path rules also reject NUL, a drive designator, empty segments, and `.` segments — now stated in §5.3 itself |
| 22 | `applicationType: "windows"` requires an `execution` block naming a foreign-OS chain |
| 23 | `missionCritical: true` forbids any chain but `native`; a `windows` package cannot be mission-critical |
| 24 | Digests in `hashes.json` must be **lowercase** hex — an uppercase digest is malformed, not merely mismatched, because a case-sensitive comparison is conforming |
| 25 | Entry path budgets: 1024 bytes total, 255 per segment, 64 segments — §2.1 |
| 26 | Case-insensitive path collisions are rejected regardless of host filesystem — §2.1 |
| 27 | Encrypted entries and unsupported compression methods are rejected — §2.1 |
| 28 | The archive must occupy exactly the whole file — §1 |
| 29 | Key files: ≤ 64 KiB, `algorithm` must be `ed25519`, `privateSeed` must decode to 32 bytes, a present `publicKey` must match the seed |
| 30 | Ed25519: a signature with scalar S ≥ L, a non-canonical point encoding, or a small-order key is rejected |
| 31 | `update.json`: the signature is verified **before** the document is parsed — a real security property, now stated |

### A.5 Accidents — not frozen

| # | Finding | Outcome |
|---|---|---|
| 32 | `hashes.json` is emitted with sorted keys and no trailing newline, while `build.json` and `installation.json` emit a trailing newline | **ACCIDENT** — authoring order, not design. Left unspecified: §4 signs exact bytes, so no canonical JSON form is needed anywhere, and specifying one would create an obligation with no purpose |
| 33 | STORE below 64 bytes, DEFLATE above | **ACCIDENT** — a writer heuristic. A writer MAY; a reader MUST NOT check, or it would reject conformant output from another writer |
| 34 | `limits::kMaxVersionBytes = 256` is checked after a 64-byte cap has already applied | **ACCIDENT** — dead policy. 64 is the rule; 256 does not appear in this document |
| 35 | `publisher.publicKey: "AUTO"` | **ACCIDENT** — a `lexe build` authoring placeholder, rewritten in place before signing. A signed package can never carry it. Toolchain convention, not a format value |
| 36 | `install.scope` accepted any non-empty string, including `"galaxy"` | **ACCIDENT** — an omission, not an extension point. 0.1 defines `"user"`; other values are reserved and MUST be rejected |
| 37 | `updates.allowSourceChange` defaults to **true**, unlike every other security-relevant boolean | **DECIDED** — kept, and now stated explicitly rather than discovered. Changing the default silently would break existing packages; stating it lets a publisher who wants otherwise set it |
| 38 | `architectures` tolerates duplicates; `entrypoint.arguments` tolerates empty strings; `build.command` rejects them; `permissions` rejects duplicates | **ACCIDENT** — four policies for four arrays. Uniqueness is required only where it changes meaning (`permissions`, because it feeds the permission digest); elsewhere duplicates are harmless and rejecting them would be gratuitous |
| 39 | Case folding in the collision guard is ASCII-only | **DECIDED** — stated as **ASCII** in §2.1 rather than widened. Unicode case folding is locale- and version-dependent, and a rule whose answer depends on which Unicode table a reader shipped is worse than a narrower rule that is exact |
| 40 | `declared_role()` swallows every exception and answers `"application"` | **ACCIDENT** — a sensible fail-safe. §3.5 specifies the obligation; the recovery behaviour is an implementation's own |
| 41 | `metadata/permissions.json` was listed as an optional member and read by nothing | **ACCIDENT** — removed from §2. A member with no semantics is a trap: a publisher could believe it was doing something |
| 42 | `scripts/` is an allowed top-level name the reference writer cannot produce | **FORMAT** — kept reserved and inert, and explicitly **inside** the envelope (§3.3). Content a later version may act upon MUST NOT be able to enter unsigned today |
| 43 | Setuid, setgid and sticky bits were stripped on extraction as a side effect of an exec-bit mask | **FORMAT** — promoted to an explicit `MUST NOT honour` in §3.1.1, rather than left as an emergent property |

### A.6 Scope

| # | Finding | Outcome |
|---|---|---|
| 44 | §9 specified the reference runtime's exact directory tree | **DECIDED** — replaced by path-free runtime semantics (§9). The paths fail §0.2: no package can observe them. What a package *can* observe — immutable version content, rollback to verified content, atomicity, data separation and binding, isolation, fail-closed compiled entrypoints — is now stated as requirements. The layout moved to [REFERENCE-POLICY.md](REFERENCE-POLICY.md) |
| 45 | `build.json` and `installation.json` field contracts were underspecified | **POLICY** — both are host-produced records, not package content. §9.7 states the obligation they serve (a compiled entrypoint MUST be verified against a recorded digest, failing closed); the file formats are the reference runtime's |
| 46 | Exit codes, sandbox mechanism, lock files, desktop integration | **POLICY** — no package can observe any of them |
| 47 | `HARDENING.md` §E specified a `healthCheck` manifest field that nothing implements | **ACCIDENT** — marked deferred there. Because §5.0 requires unknown members to be ignored, a package carrying it was silently accepted and silently ignored, which is the worst outcome for a field a publisher might trust |
| 48 | `HARDENING.md` §C named a staging path the code does not use | **POLICY** — corrected there |

### A.8 Threats 0.1 does not defend against

Stated rather than resolved. Each was demonstrated; each is a scope decision, not
a bug, and §7.1 and §9.7 now say so in the normative text rather than leaving a
reader to assume otherwise.

| # | Threat | Status |
|---|---|---|
| 49 | **Update freeze.** Nothing bounds how old a validly-signed `update.json` may be, so a hostile mirror can re-serve an older signed document indefinitely and hold a user back from a fix, while every check passes and the runtime reports "up to date" | **Out of scope for 0.1** — §7.1. Defending needs expiring metadata and a snapshot role. What 0.1 does owe is honesty: a runtime MUST NOT describe this state as more than "the configured source offers no newer version" |
| 50 | **Silent downgrade by direct install.** Check 7 governs updates; `lexe install <older>.lexe` moved the active version backwards with a success exit and no mention | **FIXED** — refused unless explicitly allowed. `--yes` does not imply it |
| 51 | **The portable build record is local, unsigned state.** Rewriting the recorded digest makes an attacker-supplied binary launch | **Boundary stated** — §9.7. A bundled package's digests come from the signed `hashes.json`; a portable package's cannot, because the publisher never saw the binary. §9.7 protects against replacement, not against an attacker who can also rewrite the record |
| 52 | **`update.json`'s 1 MiB budget was enforced by the parser, after the transport had read the whole document — and before anything was authenticated.** A source serving 256 MiB had it read in full; the first complaint was about the signature | **FIXED** — §7.0 and §10.1. The fetch takes a required limit, enforced by `--max-filesize` and again against the received file, so a source that lies about its length gains nothing. A limit that fires after the allocation it prevents is decoration |
| 53 | **`http://` was accepted identically to `https://`, and redirects were unrestricted** | **FIXED** — §7.0. Refused at the point of use and at `lexe source set`, with `--proto-redir =https` so a server cannot downgrade a redirect |
| 54 | **Icons were never validated as images.** Whatever a package carried as `128.png` was written into the user's hicolor theme, where the desktop parses it unsandboxed | **FIXED** — §9.9. Magic-byte check and a size cap; a rejected icon is skipped rather than failing the install |
| 55 | **The `executable` declaration was accepted with paths not covered by `files`, outside `payload/`, duplicated, or of the wrong type** — each silently doing nothing, and wrong-type vs wrong-contents produced opposite outcomes for the same publisher mistake | **FIXED** — §3.6. Validated at verification, lenient at extraction, and the asymmetry is gone |
| 56 | **A launch reference was accepted with any signing key at all**, and `lexe verify` printed the signer's fingerprint as though it established something | **FIXED** — §9.8.1. Small blast radius today (a reference carries no arguments), specified because reporting an artifact as verified when its signature's only claim was never checked is untrue, and because a reference that ever carries arguments makes it a delivery mechanism |
| 58 | **A UTF-8 BOM was rejected in `lexe.json` and accepted in `metadata/hashes.json`.** §5.0 binds all three documents the format defines; the check lived in `Manifest::parse` instead of in the strict-JSON reader every document goes through | **FIXED** — the check moved into `json_strict`, so it now applies to `update.json` too and to whatever document a later version adds. The lesson is about WHERE a rule lives: written once per document it holds for the documents somebody remembered; enforced in the one function they all pass through it holds for all of them |
| 59 | **§5.5's table said `allowedChains` must be non-empty while a paragraph below it said an absent or empty array means `["native"]`.** A self-contradiction introduced by this very freeze | **FIXED (spec)** — the table was the wrong half. The reader substitutes `["native"]` and the package launches natively, which was verified rather than assumed: the reported consequence, that such a package "can never be launched", did not hold |
| 60 | **The `permissions` vocabulary existed only in this appendix.** Row 8 claimed it was "closed and checked at stage 2" and row 38 that duplicates are rejected, but §5.7 said only "informational in 0.1" and the document **named no valid permission anywhere** | **FIXED** — §5.7.1 states the closed vocabulary, lists both members, and gives the reason duplicates are refused. This was the sharpest test of the claim that the document is implementable without reading the implementation, and it failed it: a validator written from the prose correctly accepted `["telepathy"]`. A rule that exists only in a freeze record is not a rule |
| 61 | **§5.0 required integer TOKENS while 0.1 declared no field as an integer** — a rule with no subject | **FIXED** — `install.estimatedSize` is now declared a non-negative integer |
| 68 | **`doctor --repair` deleted any absolute path named in `integration.json`** — local, unsigned state. Two records appended by hand, pointing at files in the user's home, were removed, and the report said only "Re-established 6 registration(s)" | **FIXED** — deletion is confined to the five directories this runtime writes, and a record naming anything else is REPORTED rather than obeyed or ignored. Not a privilege crossing, but it turned "can write one file inside LEXE_HOME" into "delete any file this user can delete" — and corruption is a likelier route than malice. It also broke a rule the project had already adopted: `HARDENING.md`'s single-source table assigns filesystem ownership to the registry and names "direct `remove_all` on computed paths" as the anti-pattern |
| 69 | **Two conditional artifacts were de-registered instead of carried forward.** `AppDesktopEntry` and `AppMimeTypes` are written only when the manifest asks for them, and `install_app` rewrites a whole scope — so an update that turned `integration.desktopEntry` off dropped the RECORD while leaving the file in the desktop's directories. `AppIcon` and `SessionUnit` already carried forward | **FIXED**, and the severity is narrower than the surrounding comments feared: uninstall removes the files anyway, so nothing is left behind forever. What was lost is DETECTION — `doctor` reported "healthy" while untracked files sat in the desktop's directories, which is the one guarantee `integration.json` exists to provide — plus a stale menu entry and MIME association outliving the update that removed them |
| 63 | **A detached launch inherited the caller's stdio**, so a caller whose stdout was a pipe never observed the launch returning: `OUT=$(lexe run svc)` and `lexe run svc \| tee log` hung forever, while the same command redirected to a file returned in 30 ms | **FIXED** — the detached supervisor reopens stdin, stdout and stderr on `/dev/null`. `/dev/null` rather than a log file, because §5.6 already establishes that a detached direct run is unsupervised with no status to report, and inventing a log file would invent unbounded state with it. The systemd path was never affected: the unit gets the journal |
| 64 | **`lexe update` said "up to date (1.0.0)" with no attribution**, violating the §7.1 MUST NOT that had just been added — and on the command a user actually runs, not on `--check`. Worse, a source offering a version LOWER than installed was reported identically to the healthy case | **FIXED** — the report now says what the SOURCE offered, and an older offer is called out explicitly as anomalous. That is the only externally visible symptom of the freeze attack §7.1 documents as undefended, and detection there costs nothing |
| 65 | **`update.json`'s `package.sha256` accepted an uppercase digest** and applied the update, because the value was lowercased before being compared | **FIXED** — §7.0 requires lowercase, for the reason §3.6 already gives about `hashes.json`: a case-sensitive reader is conforming, so an uppercase digest would be read differently by different implementations |
| 66 | **`lexeVersion` in `update.json` was enforced and undocumented, and asymmetrically** — absent tolerated, wrong refused | **FIXED (spec)** — §7.0 states both halves and why the asymmetry is deliberate |
| 67 | **`minimumRuntime` sat in §7's example and was read by nothing** | **REMOVED from the example** — the third instance of this shape, after `healthCheck` and `metadata/permissions.json`. A member with no semantics is a trap, because somebody will believe it is doing something. Specifying it would need a version-ordering rule for *runtimes* that 0.1 does not define |
| 62 | **§1 forbade a writer emitting an unnecessary ZIP64 record and said nothing about what a reader does with one** | **FIXED** — stated as a reader MAY, with the reference implementation's answer named. It remains the one corpus case the spec deliberately does not determine |
| 57 | **`write_atomic` used one temporary name for every writer**, so two concurrent writers of the same file collided — and the loser removed the DESTINATION before retrying, deleting the record the winner had just written | **FIXED** — a unique temporary per writer, and the destination is never removed unless our own temporary is still there to replace it. Introduced by the fix for an *unobserved* torn read, and caught by the concurrency lane added in the same tranche, on `installation.json` during simultaneous launches. A reminder that "strictly better, and free" is a claim to test rather than assert |

### A.7 Still open

Recorded rather than resolved, because each needs a decision this freeze does
not force. None affects whether a conforming implementation can read a 0.1
package.

| Question | Why it is open |
|---|---|
| Is execution-chain layer **order** normative? §5.5 says `fex+proton` "is not a chain", and nothing checks it. Order is a naming convention today | Resolving it toward "normative" would change which packages are valid, so it needs the compatibility work first |
| **`updates.manifest` scheme at verification time.** §7 says "an https:// URL (also accepts file:// and paths)"; §7.0.1 says MUST be https and then exempts file/path. Whether an `http://` value fails §6 verification or only fails at update time is not stated | Either reading is defensible; the safer one (verify rejects anything but `https://` in a PACKAGE, local paths only from local configuration) changes which packages are valid |
| **Launch references and a stateless validator.** §9.8.1 requires refusing a reference not signed by this machine's launch key; a validator with no such key cannot decide it | Likely answer: report "unverifiable here", never OK — needs wording |
| **`integration` members.** §5.7 points at §9 for `integration`, which defines only `desktopEntry`. Other members are presumably ignored as unknown (§5.0), but this is not said | Text-only, but it fixes what an `integration` block may mean |
| **Unicode normalization.** §2.1 compares bytes, so NFC/NFD-equivalent paths are distinct and both valid in 0.1. They alias on a normalizing filesystem exactly as ASCII case pairs alias on a folding one | Rejecting them changes which packages are valid; 0.2 question |
| **File/directory prefix conflicts.** An entry `payload/bin` beside `payload/bin/app`, or a bare file named `payload`/`metadata`/`signatures`, satisfies every §2.1 rule but cannot be extracted to any filesystem. Both implementations accept it today | Deterministic rejection is the likely answer; it is a validity change for both implementations, not made in this campaign |
| **Unsigned bytes inside records.** Per-entry comments, local extra fields and bytes after a DEFLATE stream's end are covered by no signature. They cannot change what is extracted, but they make the package's SHA-256 malleable and are a covert channel | Rejecting them needs a check of what real writers emit first |
| **Text in `name`/`publisher.name`.** No character restriction: a newline or bidi override is valid manifest text. The reference implementation escapes it on display (REFERENCE-POLICY) | Whether FORMAT should forbid control characters is a validity change |
| **A session-managed service whose program is replaced underneath it.** `ExecStart` is version-independent (`lexe run <id> --wait`), so after an update the unit keeps executing the OLD version until something unrelated restarts it, at which point it silently switches — and `service status` reports it healthy throughout | §9.4 permits this (it forbids disturbing a running version) and §5.6 says detaching is not supervision, but neither covers the case where the runtime IS the supervisor and the program changed. The likely answer is a REPORT rather than a restart — `service status` saying "running 1.0.0, installed version is 2.0.0" — because restarting a service because a file changed is a policy decision that belongs to the user. Recorded as open rather than decided quietly |
| `build.json` vocabularies: legal values of `hostIsa`, `approval.authority`, and a timestamp grammar | All three are free strings today. Tightening them is POLICY work, not format work |

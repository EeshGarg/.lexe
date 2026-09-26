# lexe-conformance — an independent `.lexe` conformance validator

A second opinion on `.lexe` packages, written to **disagree** with the C++
reference implementation.

```sh
python3 lexe_conformance.py PACKAGE.lexe          # human-readable report
python3 lexe_conformance.py --json PACKAGE.lexe   # machine-readable report
```

Exit codes: `0` conformant, `1` violations, `2` the package could not be read
at all.

## Why it exists

A reference implementation cannot audit itself. Any check it gets wrong it gets
wrong in both the writer and the reader, and the result is a package that is
perfectly self-consistent and still wrong. The only way to find that class of
bug is a second reader that was never told how the first one works.

So the independence is the requirement, not an implementation detail:

* **Python 3, standard library only.** `zipfile`, `json`, `hashlib`, `base64`,
  `binascii`, `re`, `struct`, `argparse`, `sys`, `pathlib`. No `pip install`,
  no third-party dependency, no build step.
* **It never runs `lexe`.** Not for a judgement, not for a hint, not to parse
  anything. It does not link, wrap, or embed `lexe_engine`.
* **It re-derives each rule from the prose.** Every predicate here was written
  from `docs/FORMAT-0.1.md` (and `docs/HARDENING.md` for the resource caps),
  not transcribed from `package.cpp`. The path-safety analysis in
  `path_problems()` is a textual analysis of the **raw** central-directory name
  bytes, not a port of `entry_path_problem()`; the ELF and PE readers in
  `parse_elf()` / `parse_pe()` read the header fields the spec names and
  nothing else, rather than mirroring `elf.cpp` / `pe.cpp`.
* **It parses the ZIP central directory by hand.** `zipfile` is used only to
  inflate entry data. Several §2 rules are about bytes `zipfile` has already
  normalised away — it decodes entry names (hiding an embedded NUL and
  non-UTF-8 bytes) and exposes neither the raw name nor the general-purpose
  flag bits.

Every finding is a machine-readable record with a stable `code`, a `severity`,
a `where`, what was **expected**, what was **observed**, and the `spec` section
it comes from. There is no prose-only failure.

```json
{
  "package": "app.lexe",
  "conformant": false,
  "violations": [
    {
      "code": "CONTAINER_EXPANSION_RATIO",
      "severity": "error",
      "where": "whole archive",
      "expected": "expansion ratio at most 200x once past the 16777216-byte grace threshold",
      "observed": "419447386 uncompressed bytes from a 411609-byte package (1019.0x)",
      "spec": "§1"
    }
  ],
  "skipped": []
}
```

`severity` is `error` for a spec MUST (these decide the exit code and the
`conformant` flag), `warning` for an advisory finding the spec does not make a
MUST, and `fatal` for the one unreadable-package record that accompanies exit
`2`.

---

## What it checks

### Container — §1, §2

| Code | Rule |
|---|---|
| `CONTAINER_UNREADABLE` | not a readable ZIP at all (exit 2) |
| `CONTAINER_NOT_SPANNING_FILE` | the archive occupies exactly the whole file: the EOCD is the final 22 bytes and the central directory ends where the EOCD begins. Catches prepended data, trailing data and a comment-shifted EOCD |
| `CONTAINER_ARCHIVE_COMMENT` | EOCD comment length is 0 |
| `CONTAINER_MISSING_REQUIRED_ENTRY` | `lexe.json`, `metadata/hashes.json`, `signatures/manifest.sig`, `signatures/payload.sig` each present as a **file** |
| `CONTAINER_TOPLEVEL_NOT_ALLOWED` | first path segment ∈ {`lexe.json`, `signatures`, `metadata`, `icons`, `payload`, `scripts`} |
| `CONTAINER_PATH_ABSOLUTE` | no leading `/` |
| `CONTAINER_PATH_TRAVERSAL` | no `..` segment |
| `CONTAINER_PATH_DOT_SEGMENT` | no `.` segment |
| `CONTAINER_PATH_EMPTY_SEGMENT` | no empty segment (no `//`) |
| `CONTAINER_PATH_BACKSLASH` | no backslash |
| `CONTAINER_PATH_DRIVE_LETTER` | no `X:` drive designator in any segment |
| `CONTAINER_PATH_NUL` | no NUL byte (checked on the raw name bytes) |
| `CONTAINER_PATH_NOT_UTF8` | entry names decode as UTF-8 |
| `CONTAINER_PATH_TOO_LONG` / `CONTAINER_COMPONENT_TOO_LONG` / `CONTAINER_DEPTH_EXCEEDED` | ≤ 1024 bytes / ≤ 255 bytes / ≤ 64 components |
| `CONTAINER_ENTRY_COUNT_EXCEEDED` | ≤ 65535 entries |
| `CONTAINER_PACKAGE_TOO_LARGE` | ≤ 2 GiB, checked from the on-disk size **before** the file is read into memory |
| `CONTAINER_ENTRY_TOO_LARGE` | ≤ 1 GiB uncompressed per entry |
| `CONTAINER_TOTAL_UNCOMPRESSED_EXCEEDED` | ≤ 2 GiB total uncompressed |
| `CONTAINER_EXPANSION_RATIO` | ≤ 200× expansion, applied only once the uncompressed total passes a 16 MiB grace threshold |
| `CONTAINER_DUPLICATE_PATH` | no repeated entry path |
| `CONTAINER_CASE_COLLISION` | no two paths differing only in ASCII case |
| `CONTAINER_ENCRYPTED_ENTRY` | general-purpose flag bit 0 clear on every entry |
| `CONTAINER_SYMLINK_ENTRY` | no Unix `S_IFLNK` in the external-attributes high word |
| `CONTAINER_LEXE_JSON_NOT_FILE` | `lexe.json` is a top-level file, never a directory or a path prefix |
| `CONTAINER_PAYLOAD_MISSING` | `payload/` entries present unless `role` is `"launch"` |
| `CONTAINER_DIRECTORY_ENTRY` | **warning** — see spec gap G2 |

### Hashes — §3

`HASH_JSON_PARSE`, `HASH_JSON_BOM`, `HASH_JSON_NOT_UTF8`,
`HASH_JSON_TRAILING_DATA`, `HASH_JSON_TOO_LARGE`, `HASH_DUPLICATE_KEY`,
`HASH_JSON_NOT_OBJECT`, `HASH_ALGORITHM`, `HASH_FILES_NOT_OBJECT`,
`HASH_DIGEST_NOT_STRING`, `HASH_DIGEST_MALFORMED`, `HASH_MISMATCH`,
`HASH_COVERAGE_MISSING`, `HASH_COVERAGE_ORPHAN`, `HASH_COVERAGE_EXCLUDED`,
`HASH_ENTRY_UNREADABLE`.

* `algorithm` must be exactly `"sha256"`; `files` must be an object.
* Every digest must be 64 **lowercase** hex characters — checked as a shape,
  not only as a string comparison, so an uppercase digest is reported as
  malformed rather than merely as a mismatch.
* SHA-256 is recomputed for every covered entry, **streamed** in 64 KiB chunks
  so no entry is ever fully resident.
* Set equality in both directions: `HASH_COVERAGE_MISSING` for an archive
  entry that should be covered and is not, `HASH_COVERAGE_ORPHAN` for a key
  naming no archive entry, `HASH_COVERAGE_EXCLUDED` for a key naming an entry
  §3 excludes.
* Exclusions: `lexe.json`, `metadata/hashes.json`, everything under
  `signatures/`, and ZIP **directory entries** (spec gap G2).

### Manifest — §5

`MANIFEST_BOM`, `MANIFEST_NOT_UTF8`, `MANIFEST_TOO_LARGE`, `MANIFEST_PARSE`,
`MANIFEST_TRAILING_DATA`, `MANIFEST_DUPLICATE_KEY`, `MANIFEST_NOT_OBJECT`,
`MANIFEST_FIELD_MISSING`, `MANIFEST_FIELD_TYPE`, `MANIFEST_FIELD_EMPTY`,
`MANIFEST_FIELD_TOO_LONG`, `MANIFEST_FIELD_FORBIDDEN`,
`MANIFEST_LEXEVERSION`, `MANIFEST_ID_SHAPE`, `MANIFEST_VERSION_SHAPE`,
`MANIFEST_ENUM_INVALID`, `MANIFEST_PATH_INVALID`,
`MANIFEST_ENTRYPOINT_NOT_IN_ARCHIVE`, `MANIFEST_BUILD_REQUIRED`,
`MANIFEST_BUILD_FORBIDDEN`, `MANIFEST_BUILD_COMMAND_REQUIRED`,
`MANIFEST_BUILD_COMMAND_FORBIDDEN`, `MANIFEST_LAUNCH_APPID_REQUIRED`,
`MANIFEST_LAUNCH_APPID_FORBIDDEN`, `MANIFEST_CHAIN_ID_SHAPE`,
`MANIFEST_MISSION_CRITICAL_CONTRADICTION`,
`MANIFEST_WINDOWS_NO_FOREIGN_OS_CHAIN`.

* UTF-8, no BOM, ≤ 1 MiB, no trailing data after the JSON value.
* **Duplicate object keys at any depth** are rejected, via a
  `json.JSONDecoder(object_pairs_hook=...)` that reports a repeated key instead
  of silently letting the last one win. This matters because a duplicated
  `publicKey` or `applicationType` would let the verifier and a human reviewer
  read different values from the same bytes.
* Required for every role: `lexeVersion` == `"0.1"`, `id`, `name`, `version`,
  `publisher.name`, `publisher.publicKey`.
* `role` ∈ {`application`, `launch`}, defaulting to `application` when absent.
* Role-conditional structure: `applicationType`, `architectures`,
  `entrypoint.executable` and `install.mode` are required for
  `role: "application"` and **forbidden** for `role: "launch"`;
  `launch.applicationId` is required for `"launch"` and forbidden for
  `"application"`.
* `build` required **iff** `applicationType == "portable"`; `build.command`
  required **iff** `build.system == "command"` and forbidden otherwise;
  `build.sourceDir` and a non-empty `build.toolchain` of bare executable names
  are required.
* `id` is reverse-DNS (2+ dot-separated `[a-zA-Z0-9-]+` segments), ≤ 255 bytes.
* `version` is 1–64 characters with no whitespace, control character, `/`, `\`
  or `:`, and is not `.` or `..` (spec gap G3).
* `entrypoint.executable` and `build.sourceDir` are relative payload paths: no
  leading `/`, no `..`, no `.`, no empty segment, no backslash, no NUL, no
  drive designator.
* For `native` and `windows`, the entry named by `entrypoint.executable` must
  exist in the archive as `payload/<executable>`.
* Enums checked: `role`, `applicationType`, `architectures[]`, `launch.mode`,
  `install.mode`, `build.system`.
* §5.5 contradictions: `missionCritical` with a non-`native` chain; a
  `"windows"` package that is `missionCritical`; a `"windows"` package whose
  `allowedChains` permits no `wine`/`proton` layer — **including** one that
  relies on the default `["native"]`, because silence is not consent.

### Signatures — §4

`SIGNATURE_KEY_PREFIX`, `SIGNATURE_KEY_BASE64`, `SIGNATURE_KEY_LENGTH`,
`SIGNATURE_LENGTH`, `SIGNATURE_UNREADABLE`, `SIGNATURE_INVALID`.

* `publisher.publicKey` must start with `ed25519:` and base64-decode (standard
  RFC 4648 alphabet, padding required, `validate=True`) to exactly 32 bytes.
* `signatures/manifest.sig` and `signatures/payload.sig` must each be exactly
  64 raw bytes.
* **Ed25519 verification is an honest skip, never a silent pass.** The Python
  standard library cannot verify Ed25519. When neither `cryptography` nor
  `pynacl` is importable the report carries a `skipped` entry saying in plain
  words that stages 4 and 5 of the §6 pipeline were **not** checked. When one
  of them *is* importable it is used, the signature is verified over the exact
  stored `lexe.json` / `metadata/hashes.json` bytes, and the report names the
  backend and version that did it — so a reader can tell a real pass from an
  unchecked one. There is no code path in this tool that reports a signature as
  good without a real verification.

### Payload role — §6.7

`PAYLOAD_NATIVE_NOT_ELF`, `PAYLOAD_NATIVE_ELF_TYPE`,
`PAYLOAD_NATIVE_ARCH_MISMATCH`, `PAYLOAD_NATIVE_ARCH_UNNAMEABLE`,
`PAYLOAD_WINDOWS_NOT_PE`, `PAYLOAD_WINDOWS_IS_DLL`,
`PAYLOAD_WINDOWS_NOT_EXECUTABLE_IMAGE`, `PAYLOAD_WINDOWS_ARCH_MISMATCH`,
`PAYLOAD_WINDOWS_ARCH_UNNAMEABLE`, `PAYLOAD_WINDOWS_SUBSYSTEM_MISMATCH`
(warning), `PAYLOAD_PORTABLE_ENTRYPOINT_PRESENT`,
`PAYLOAD_PORTABLE_SOURCEDIR_MISSING`, `PAYLOAD_LAUNCH_HAS_PAYLOAD`,
`PAYLOAD_ENTRYPOINT_UNREADABLE`.

* `native`: the entrypoint bytes begin with `\x7fELF`; `e_type` is `ET_EXEC` or
  `ET_DYN`; `e_machine` maps to a declared architecture (x86-64 `0x3E`,
  AArch64 `0xB7`). An `e_machine` 0.1 cannot name is reported as such rather
  than as a mismatch against a list the publisher could not have satisfied.
* `windows`: `MZ`, then a `PE\0\0` signature at an in-range `e_lfanew`; the
  COFF `Machine` maps to a declared architecture (`0x8664`, `0xAA64`);
  `IMAGE_FILE_DLL` (0x2000) is clear and `IMAGE_FILE_EXECUTABLE_IMAGE` (0x0002)
  is set. The optional header's `Subsystem` is read and compared with
  `launch.mode` as an **advisory warning only** — §5.6 makes presentation
  declarative, so a mismatch is not a MUST.
* `portable`: the entrypoint must **not** already exist in the archive, and at
  least one entry must live under `payload/<build.sourceDir>/`.
* `launch`: no `payload/` entries at all.

---

## Spec gaps — rules that are not in `docs/FORMAT-0.1.md`

A rule that had to be read out of the implementation or a sibling document is a
rule the format spec is missing. Each of these is implemented here, and each is
a place `FORMAT-0.1.md` should be amended.

**G1 — the resource caps are nowhere in `FORMAT-0.1.md`.** The 2 GiB package,
65535-entry, 1 GiB-per-entry, 2 GiB-total, 200× ratio, 16 MiB grace, 1024-byte
path, 255-byte component and 64-component depth limits appear only in
`docs/HARDENING.md` §B.10 / §F and in `src/lexe/base/limits.hpp`. A third-party
implementer reading only the normative format document would build a reader
with no bound at all on any of them. `FORMAT-0.1.md` §1 should state them,
since they determine whether a package is acceptable.

**G2 — §3 does not exclude ZIP directory entries from hash coverage.** §3 says
`files` "MUST contain exactly one key for every entry in the archive **except**
`lexe.json`, `metadata/hashes.json` itself, and everything under
`signatures/`". A ZIP directory entry (a name ending in `/`) is an entry, so as
written §3 demands a digest for it — which is unsatisfiable, since it carries
no bytes. `package.cpp` resolves this silently: its central-directory walk does
`if (mz_zip_reader_is_file_a_directory(...)) continue;`, so directory entries
never enter the entry list and never reach coverage. This validator implements
the same exclusion (`coverage_excluded()`), and documents it because the spec
does not.

The same gap has a second half. `docs/HARDENING.md` §B.11 says directory
entries are a hostile-corpus case that "readers reject in 0.1" — but
`FORMAT-0.1.md` §2's list of reader MUST-rejects does not mention them, and
`package.cpp` does not reject them either. Two normative documents and the
implementation give three different answers. This validator reports a directory
entry as a **warning** (`CONTAINER_DIRECTORY_ENTRY`) rather than picking a side:
it does not fail a package the format spec permits, but it does not stay silent
about something another normative document says to refuse. Confirmed by test:
both `lexe verify` and this validator accept a package with a bare
`payload/bin/` directory entry, so `HARDENING.md` §B.11 is the odd one out.

**G3 — the `version` shape rule is only in `identity.cpp`.** §5.2 constrains
`version` to a "non-empty string, see §8 ordering", and §8 defines only the
ordering. The real constraint — 1–64 characters, no whitespace or control
character, no `/`, `\` or `:`, and not `.` or `..` — lives in
`src/lexe/base/identity.cpp`'s `version_string_is_valid()`, and exists because a
version is used as a path component, inside lock and lease file names, and as
the entire contents of `current.txt`. That is a format-level constraint on a
signed field and belongs in §5.2.

**G4 — §2 does not forbid a `.` path segment or an empty one.** §2 names
absolute paths, `..`, backslashes, NUL and drive designators. It does not
mention a `.` segment or a `//` empty segment, both of which `package.cpp`
rejects (`"'.' path segment"`, `"empty path segment"`). Implemented here; §2
should list them.

**G5 — §2 does not forbid case-colliding paths.** `payload/App` beside
`payload/app` aliases on a case-insensitive filesystem, so one overwrites the
other after extraction. `package.cpp` rejects it and `HARDENING.md` §B.4
requires it, but `FORMAT-0.1.md` §2's reader MUST-reject list does not.

**G6 — §1 says "no encryption" of writers but never tells readers to check.**
§1 is a list of writer obligations ("Writers ... MUST produce"); §2's reader
list does not include encrypted entries. `package.cpp` checks
`st.m_is_encrypted`. Implemented here as `CONTAINER_ENCRYPTED_ENTRY`.

**G7 — the archive-must-span-the-whole-file rule is a HARDENING rule, not a
format rule.** §1 says "no archive comment", which implies it, but the actual
requirement — the EOCD is the tail and the central directory ends exactly where
it begins, so no prepended or trailing bytes ride along outside the signatures —
is stated in `docs/HARDENING.md` and implemented in `package.cpp`'s
`archive_spans_whole_file()`. It is a security property of the container and
belongs in §1.

**G8 — §5 does not give the field length budgets.** `id` ≤ 255 is in §5.2, but
`name` ≤ 1 KiB, `publisher.publicKey` ≤ 128 bytes and `lexe.json` ≤ 1 MiB come
from `HARDENING.md` §B.10 and `limits.hpp`. This validator implements the
`lexe.json` and `id` budgets; see "deliberately not checked" for the rest.

**G9 — duplicate JSON keys.** §5 says "Unknown fields MUST be ignored" and says
nothing about repeated ones. The requirement to reject them is in
`HARDENING.md` §B.8. Implemented here for both `lexe.json` and
`metadata/hashes.json`.

---

## Disagreement with `lexe verify`

Tested on packages built by `build-linux/lexe` from `examples/native/cli-hello`,
`examples/portable/c-hello` and `examples/windows/console-hello`: all three are
**CONFORMANT**, with both signatures verified for real against the publisher key
using the `cryptography` backend. 51 hand-crafted broken packages each produce
the expected violation code, and `lexe verify` rejects every one of them too.

There was exactly one disagreement, it was a defect in the reference
implementation, and it is now **FIXED**. The account below is kept because it is
the clearest argument for why this validator exists and why it does not share
the C++ parser.

> **`lexe verify` reported `verification: OK` for a decompression bomb.**
>
> **Resolved.** Independently reproduced, then fixed: the aggregate resource
> guards moved from `extract_payload()` into the `PackageReader` constructor, so
> they apply to every consumer at once — `verify`, `install`, `info`, `inspect` —
> and are read from the central directory's declared sizes, which means a bomb is
> now refused before a single byte of it is decompressed. Both tools reject it,
> at the first stage. Pinned by the `"a decompression bomb is refused by VERIFY,
> not only by install"` case in `tests/test_hostile_packages.cpp`, and the
> `--conformance` lane (`tests/conformance/01_differential.sh`) now runs both
> implementations over this and 19 other packages on every run, so a future
> divergence fails the suite instead of waiting to be noticed.

A package was built with correct hashes and valid signatures over the real
publisher key, containing one extra payload entry of 400 MiB of zeroes. It
deflates to 411 609 bytes on disk and expands 1019×.

```
$ lexe verify v01-zip-bomb.lexe
  [ ok ] structure          archive OK: 6 entries, §2 path rules hold, required entries present
  ...
  [ ok ] hashes             all 2 covered entries present, coverage is exact (both directions), every SHA-256 digest matches
  [ ok ] payload-role       role "application": the declared entrypoint "bin/cli-tool" is a runnable ELF object ...
verification: OK (signature valid, Ed25519)
exit 0

$ python3 lexe_conformance.py v01-zip-bomb.lexe
  [error] CONTAINER_EXPANSION_RATIO  (§1)
      expected: expansion ratio at most 200x once past the 16777216-byte grace threshold
      observed: 419447386 uncompressed bytes from a 411609-byte package (1019.0x)
exit 1

$ lexe install v01-zip-bomb.lexe --yes
lexe: package: expands more than 200× its packaged size (decompression-bomb guard)
exit 3
```

**Who is right: this validator.** Three reasons.

1. `lexe install` refuses the very same file. A package that the runtime will
   never install should not be reported as verifying OK — that is exactly the
   "distinguishes every failed stage" contract of §6 failing to distinguish
   anything.
2. The aggregate caps are enforced in only one place. `grep -n 'limits::'
   src/lexe/package/package.cpp` shows `kMaxTotalUncompressedBytes`,
   `kRatioGraceBytes` and `kMaxExpansionRatio` used only inside
   `extract_payload()` (lines 491–504); `verify.cpp` references no limit but
   `kMaxHashesBytes`. The per-entry 1 GiB cap *is* applied during verification,
   because it lives in `read_entry()`. Only the total and ratio caps are
   missing, and those are precisely the two that catch a many-entry or
   high-ratio bomb.
3. `docs/HARDENING.md` §B.6 makes this normative and specific: decompression
   bombs must be rejected "at [their] documented stage", and "verification MUST
   bound memory (streaming, no full-package slurp of payload entries)".
   `verify.cpp` stage 6 hashes every covered entry through
   `PackageReader::read_entry()`, which calls
   `mz_zip_reader_extract_to_heap()` — a full 400 MiB heap slurp of a single
   payload entry, on top of the whole archive already being resident from
   `util::slurp()` in the `PackageReader` constructor. The bomb is not merely
   accepted; verifying it costs the memory the gate exists to prevent. This
   validator streams every digest in 64 KiB chunks and never holds an entry
   whole.

The severity is bounded — the guard does fire before anything is extracted, so
this is not remote code execution or an unbounded install — but `lexe verify`
is the command a user, a CI job or a repository gate runs to decide whether a
package is acceptable, and on this input it answers wrongly. The fix is to
apply the same `limits.hpp` aggregate policy in `verify.cpp` stage 6, where the
entries are being read anyway, rather than only in `extract_payload`.

A control package (20 MiB of incompressible random bytes, past the grace
threshold but only ~1× expansion) is accepted by both tools, so the disagreement
is the ratio guard and not merely size.

---

## What it deliberately does **not** check

Not an oversight list — each of these is a decision.

* **Ed25519 verification without a backend.** Reported as `skipped` with the
  reason, never as a pass. See §4 above. The tool also adds no small-order or
  non-canonical point checks of its own on top of whatever backend it finds, and
  says so in the report; `HARDENING.md` §G asks the reference implementation for
  canonical-S enforcement, and auditing that properly needs a scalar
  implementation this tool has no business carrying.

* **Writer determinism (§1).** Zeroed timestamps, lexicographic entry order,
  DEFLATE level 9 / STORE under 64 bytes, the canonical `0755`/`0644` external
  attributes, absence of extra fields, absence of ZIP64 for small archives, and
  byte-identical repeated packs. These are obligations on **writers**. §2's
  reader MUST-reject list does not include them, so a reader that failed a
  package for them would reject conformant output from a different, legitimate
  writer. Verifying them belongs in a pack-determinism test, not in a package
  validator. (`HARDENING.md` §D already assigns them to exactly such a test.)

* **ZIP64 archives.** The whole-file-span check parses only the 32-bit EOCD.
  When the ZIP64 sentinels are present the tool emits a `skipped` entry saying
  the span check and the raw central-directory checks did not run, rather than
  guessing. No conformant 0.1 package produced by `lexe pack` needs ZIP64.

* **Local-header / central-directory consistency** (`HARDENING.md` §B.5). Two
  disagreeing views of the same entry is a real attack, but it is a ZIP-reader
  concern, and this tool inherits `zipfile`'s view for entry data while using
  its own for metadata. Detecting the disagreement properly means parsing local
  headers too; it is a worthwhile addition and it is not here.

* **Field length budgets other than `id` and `lexe.json`.** `name` ≤ 1 KiB,
  `publisher.publicKey` ≤ 128 bytes and `hashes.json` ≤ 16 MiB exist only in
  `limits.hpp` / `HARDENING.md` (gap G8). The `hashes.json` and `lexe.json`
  document budgets and the `id` budget are enforced here because §3 and §5.2
  make them format-visible; the rest are implementation self-defence and
  enforcing them would make this tool a transcription of `limits.hpp` rather
  than a reading of the spec.

* **Host compatibility (§6.8).** Whether the host's ISA is in `architectures`
  is a property of the machine, not of the package. §6.8 itself skips it for
  `lexe verify`.

* **Everything past installation (§6.9, §7, §8, §9).** Host-ISA compilation and
  its approval gates, `update.json` and the seven update-authorization checks,
  semver-lite version *ordering* (the version *shape* is checked; comparing two
  versions needs two packages), the installed layout, `build.json`, trust
  binding, leases and locks. None of them are properties of a single `.lexe`
  file, which is what this tool takes as input.

* **`permissions`, `integration`, `updates`, `runtimeProfile` semantics.** §5.7
  makes them optional and §5.7 explicitly says `runtimeProfile` is
  "declarative, not a promise about the payload" and that an unknown value must
  read as "no profile declared". There is nothing to validate beyond their JSON
  shape, and this tool does not invent a rule the spec declined to make.

* **`scripts/` contents.** §2 says they are carried and never executed in 0.1.
  Nothing about their bytes is constrained.

* **Whether the payload actually runs.** Nothing here executes, maps, or loads
  package content. §6.7 is a question about bytes, and it is answered by reading
  bytes.

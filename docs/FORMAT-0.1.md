# Lexe Package Format 0.1 — Normative

This document defines the exact on-disk format that the reference runtime reads and
writes for `lexeVersion: "0.1"`. Where [SPEC.md](../SPEC.md) describes intent, this
document defines bytes. The reference runtime MUST reject packages that violate a
MUST below.

## 1. Container

A `.lexe` file is a ZIP archive (PKZIP AppNote 6.3 compatible).

Writers (i.e. `lexe pack`) MUST produce **deterministic** archives:

* entries are added in lexicographic byte order of their full path;
* all entry timestamps are zeroed (the reference implementation compiles miniz with
  `MINIZ_NO_TIME`);
* entry paths use forward slashes (`/`) and are UTF-8;
* compression is DEFLATE at a fixed level (9), or STORE for entries smaller than
  64 bytes;
* no ZIP64 unless the archive requires it; no encryption; no archive comment;
  no per-entry extra fields or comments beyond what the amalgamated miniz writer
  emits with the settings above.

Packing the same input tree twice MUST produce byte-identical `.lexe` files.

## 2. Entry Layout

```text
Application.lexe
├── lexe.json                      REQUIRED  application manifest
├── signatures/
│   ├── manifest.sig               REQUIRED  raw 64-byte Ed25519 signature
│   └── payload.sig                REQUIRED  raw 64-byte Ed25519 signature
├── metadata/
│   ├── hashes.json                REQUIRED  per-entry SHA-256 index
│   ├── description.md             optional
│   ├── license.txt                optional
│   └── permissions.json           optional
├── icons/                         optional  64.png 128.png 256.png scalable.svg
├── payload/                       REQUIRED for bundled mode  application files
└── scripts/                       optional  RESERVED — never executed in 0.1
```

Readers MUST reject an archive when:

* any entry path is absolute, contains `..` as a path segment, contains a backslash,
  a NUL byte, or a Windows drive designator (`X:`);
* any entry path's first segment is not one of
  `lexe.json`, `signatures`, `metadata`, `icons`, `payload`, `scripts`;
* two entries have the same path;
* an entry is a symbolic link (ZIP external attributes: Unix mode `S_IFLNK`);
* a required entry is missing.

`scripts/` entries are carried but MUST NOT be executed by a 0.1 runtime.

## 3. Hashing — `metadata/hashes.json`

Algorithm: SHA-256. Digests are lowercase hexadecimal.

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

`files` MUST contain exactly one key for every entry in the archive **except**
`lexe.json`, `metadata/hashes.json` itself, and everything under `signatures/`.
Keys are the full entry paths. Verification MUST fail if a covered entry's digest
mismatches, if a covered entry is missing from the archive, or if an archive entry
that should be covered is absent from `files` (set equality, both directions).

## 4. Signatures

Signature scheme: **Ed25519** (RFC 8032), 64-byte raw signatures, stored as raw
binary (not hex, not base64).

* `signatures/manifest.sig` — signature over the **exact bytes** of the stored
  `lexe.json` entry (after decompression, before any JSON parsing).
* `signatures/payload.sig` — signature over the **exact bytes** of the stored
  `metadata/hashes.json` entry.

Signing raw entry bytes, not parsed structures, means no JSON canonicalization is
required anywhere.

### Publisher key encoding

`publisher.publicKey` in the manifest is the string

```text
"ed25519:" + base64(32-byte public key)
```

Base64 is the standard RFC 4648 alphabet **with** padding. Readers MUST reject any
other prefix or a decoded length ≠ 32.

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

Encoding: UTF-8 JSON, no BOM. Unknown fields MUST be ignored (forward
compatibility). Required fields for 0.1:

| Field | Constraint |
|---|---|
| `lexeVersion` | MUST be the string `"0.1"` |
| `id` | reverse-DNS: 2+ dot-separated segments of `[a-zA-Z0-9-]+`, ≤ 255 chars |
| `name` | non-empty string |
| `version` | non-empty string, see §8 ordering |
| `publisher.name` | non-empty string |
| `publisher.publicKey` | see §4 |
| `applicationType` | MUST be `"native"` in 0.1 |
| `architectures` | non-empty array; recognised values: `x86_64`, `aarch64` |
| `entrypoint.executable` | relative path inside `payload/` (no leading `/`, no `..`, no backslash) |
| `install.mode` | MUST be `"bundled"` in 0.1 (`network`/`launcher` → "unsupported in 0.1") |

Optional with defaults: `entrypoint.arguments` (`[]`), `install.scope` (`"user"`),
`install.estimatedSize`, `permissions` (`[]`, informational in 0.1), `updates`
(disabled when absent, see §7), `integration` (§9), `publisher.website`.

## 6. Verification Pipeline (normative order)

`lexe verify`, `lexe install`, and update application MUST run, in order:

1. **Structure** — archive opens; entry paths pass §2; required entries present.
2. **Manifest** — `lexe.json` parses; §5 constraints hold.
3. **Key decode** — `publisher.publicKey` decodes per §4.
4. **Manifest signature** — `manifest.sig` verifies over `lexe.json` bytes.
5. **Payload signature** — `payload.sig` verifies over `hashes.json` bytes.
6. **Hashes** — §3 set equality and digest checks over all covered entries.
7. **Compatibility** (install/update only) — host architecture ∈ `architectures`.

The report distinguishes every failed stage; the CLI exits `3` on any verification
failure.

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
      "minimumRuntime": "0.1"
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

## 8. Version Ordering ("semver-lite")

Split both versions on `.`. Compare component-wise: if both components are all
ASCII digits, compare numerically; otherwise compare as byte strings. A version
that is a strict prefix (fewer components) is smaller. This is a total order and
is the ONLY ordering the 0.1 runtime uses.

## 9. Installed Layout

Base directory (`LEXE_HOME` environment variable overrides; used by tests):

* Linux: `$XDG_DATA_HOME/lexe` or `~/.local/share/lexe`
* Windows (development host only): `%LOCALAPPDATA%\lexe`

```text
<LEXE_HOME>/apps/<id>/
├── versions/<version>/           extracted payload/ contents
├── current                       symlink to versions/<version>; where symlinks are
│                                 unavailable, a text file `current.txt` containing
│                                 the version string is written instead
├── manifest.json                 copy of lexe.json of the active version
├── installation.json             install record: source path/url, publisher key,
│                                 UTC timestamp, files created outside the app dir
│                                 (desktop entries, icons, MIME xml), channel
└── icons are copied to the XDG hicolor theme; the .desktop entry Exec line is
    `lexe run <id>` (never a version-specific path)
```

Uninstall removes everything recorded in `installation.json`, then the app
directory. Application data under `<LEXE_HOME>/data/<id>/` is removed only with
`--purge-data`.

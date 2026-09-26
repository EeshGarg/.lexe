#!/usr/bin/env python3
"""corpus.py — the systematic differential conformance corpus for Format 0.1.

Emits a directory of `.lexe` packages plus `index.json`, a machine-readable list
of `(name, file, rule, expect, why)`. `03_corpus.sh` drives both implementations
over it and compares verdicts.

    corpus.py <out-dir> [--include-large]

WRITTEN FROM `docs/FORMAT-0.1.md`, NOT FROM `src/`. Every case cites the section
whose MUST it exercises. Where the spec does not determine an outcome the case is
recorded as `expect: "unspecified"` and the lane checks only that the two
implementations AGREE — a disagreement there is a spec defect, not an
implementation bug, and is reported as such.

Three properties this corpus is built to have:

1. **Valid cases, not only invalid ones.** A corpus of rejections cannot
   distinguish a correct reader from one that refuses everything. Roughly a
   quarter of these cases are `expect: accept`, and they deliberately sit on the
   legitimate edges — a path exactly at each length bound, a non-ASCII entry
   name, a data descriptor in BOTH encodings, `executable: []`, unknown members
   for forward compatibility, a package with no icons at all.

2. **Every mutation stays AUTHENTIC.** Anything touching covered content is
   re-hashed into `metadata/hashes.json` and both signatures are recomputed, so a
   package is never refused for an uninteresting reason. The only cases with a
   deliberately broken signature are the §4 cases that are ABOUT signatures.

3. **Hermetic.** No compiler, no network, no fixtures on disk. The ELF and PE
   entrypoints are synthesised here from the header fields §6.7 names, so the
   corpus is a pure function of this file.

Signing needs a real Ed25519 backend; without one the generator exits 2 and the
lane SKIPs rather than reporting a result it did not obtain. The independent
validator uses the same module, so whenever this generator can run the validator
can check signatures too — which is why no case here needs a "signature-only,
not compared" caveat.
"""
import argparse
import base64
import hashlib
import json
import os
import shutil
import struct
import sys
import zlib

# --------------------------------------------------------------------- crypto

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
except Exception:  # pragma: no cover - reported to the caller as exit 2
    sys.stderr.write(
        "corpus.py: no Ed25519 backend (python3 -m pip install cryptography).\n"
        "Signing is not optional: an unsigned corpus would test nothing.\n"
    )
    sys.exit(2)

SEED = bytes(range(32))           # fixed, so the corpus is reproducible
FOREIGN_SEED = bytes(range(32, 64))


def signer(seed=SEED):
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_str(seed=SEED):
    raw = signer(seed).public_key().public_bytes_raw()
    return "ed25519:" + base64.b64encode(raw).decode()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------ synthetic images
# §6.7 names exactly which header fields decide the payload-role stage, so the
# entrypoints are built from those fields and nothing else.

EM_X86_64 = 62
EM_AARCH64 = 183
ET_REL, ET_EXEC, ET_DYN = 1, 2, 3


def elf64(e_type=ET_EXEC, e_machine=EM_X86_64):
    """A structurally valid little-endian ELF64 object header."""
    h = bytearray()
    h += b"\x7fELF"          # magic
    h += bytes([2, 1, 1, 0])  # 64-bit, little-endian, version 1, SYSV
    h += bytes(8)            # padding
    h += struct.pack("<HHI", e_type, e_machine, 1)
    h += struct.pack("<QQQ", 0x401000, 64, 0)   # entry, phoff, shoff
    h += struct.pack("<IHHHHHH", 0, 64, 56, 1, 64, 0, 0)
    # One PT_LOAD program header, so the object is a plausible image.
    h += struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0x1000,
                     0x1000, 0x1000)
    return bytes(h)


IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_DLL = 0x2000
PE_AMD64, PE_ARM64, PE_I386 = 0x8664, 0xAA64, 0x014C


def pe32plus(machine=PE_AMD64, characteristics=IMAGE_FILE_EXECUTABLE_IMAGE):
    """MZ header whose e_lfanew points, in range, at a PE\\0\\0 signature."""
    lfanew = 0x40
    dos = bytearray(b"MZ" + bytes(0x3A))
    dos += struct.pack("<I", lfanew)
    assert len(dos) == 0x40, len(dos)
    coff = struct.pack("<IHHIIIHH", 0x00004550, machine, 0, 0, 0, 0, 240,
                       characteristics)
    return bytes(dos) + coff + bytes(240)


# ------------------------------------------------------------------ ZIP writer
# Written by hand rather than with `zipfile`, because several §2.1/§2.2 rules are
# about bytes `zipfile` normalises away: the raw name bytes, the general-purpose
# flags, the external attributes, and the local/central relationship itself.

LFH, CDH, EOCD, DD = 0x04034B50, 0x02014B50, 0x06054B50, 0x08074B50
STORE, DEFLATE = 0, 8


class Entry:
    def __init__(self, name, data, *, mode=0o644, method=None, gpflag=0,
                 extattr=None, dos_dir=False, central_name=None,
                 data_descriptor=None, extra_local=b"", extra_central=b"",
                 local_name=None, force_sizes=None, force_method_central=None):
        self.name = name if isinstance(name, bytes) else name.encode()
        self.local_name = (local_name.encode()
                           if isinstance(local_name, str) else local_name)
        self.central_name = (central_name.encode()
                             if isinstance(central_name, str) else central_name)
        self.data = data
        self.mode = mode
        self.gpflag = gpflag
        self.extattr = extattr
        self.dos_dir = dos_dir
        self.extra_local = extra_local
        self.extra_central = extra_central
        # data_descriptor: None | "with-sig" | "no-sig"
        self.data_descriptor = data_descriptor
        self.force_sizes = force_sizes                # (comp, uncomp) in LFH
        self.force_method_central = force_method_central
        if method is not None:
            self.method = method
        else:
            self.method = STORE if len(data) < 64 else DEFLATE
        if self.method == DEFLATE:
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            self.comp = co.compress(data) + co.flush()
        else:
            self.comp = data

    @property
    def crc(self):
        return zlib.crc32(self.data) & 0xFFFFFFFF


def build_zip(entries, *, comment=b"", prepend=b"", append=b"",
              cd_offset_delta=0, insert_before_cd=b"", zip64_eocd=False):
    out = bytearray(prepend)
    offsets = []
    for e in entries:
        offsets.append(len(out))
        dd = e.data_descriptor is not None
        comp_size, uncomp_size = len(e.comp), len(e.data)
        if e.force_sizes is not None:
            comp_size, uncomp_size = e.force_sizes
        lname = e.local_name if e.local_name is not None else e.name
        out += struct.pack("<IHHHHHIIIHH", LFH, 20, e.gpflag | (0x08 if dd else 0),
                           e.method, 0, 0,
                           0 if dd else e.crc,
                           0 if dd else comp_size,
                           0 if dd else uncomp_size,
                           len(lname), len(e.extra_local))
        out += lname + e.extra_local + e.comp
        if dd:
            if e.data_descriptor == "with-sig":
                out += struct.pack("<I", DD)
            out += struct.pack("<III", e.crc, len(e.comp), len(e.data))

    out += insert_before_cd
    cd_start = len(out)
    central = bytearray()
    for e, off in zip(entries, offsets):
        cname = e.central_name if e.central_name is not None else e.name
        ext = e.extattr if e.extattr is not None else (e.mode << 16)
        if e.dos_dir:
            ext |= 0x10
        method = (e.force_method_central if e.force_method_central is not None
                  else e.method)
        central += struct.pack("<IHHHHHHIIIHHHHHII", CDH, (3 << 8) | 20, 20,
                               e.gpflag | (0x08 if e.data_descriptor else 0),
                               method, 0, 0, e.crc, len(e.comp), len(e.data),
                               len(cname), len(e.extra_central), 0, 0, 0,
                               ext, off)
        central += cname + e.extra_central
    out += central
    cd_size = len(central)
    if zip64_eocd:
        # A ZIP64 end-of-central-directory record and locator before the EOCD.
        z64 = struct.pack("<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0,
                          len(entries), len(entries), cd_size, cd_start)
        loc = struct.pack("<IIQI", 0x07064B50, 0, len(out), 1)
        out += z64 + loc
    out += struct.pack("<IHHHHIIH", EOCD, 0, 0, len(entries), len(entries),
                       cd_size, cd_start + cd_offset_delta, len(comment))
    out += comment + append
    return bytes(out)


# ------------------------------------------------------------- package builder

EXCLUDED = ("lexe.json", "metadata/hashes.json")
SIG_MANIFEST = "signatures/manifest.sig"
SIG_PAYLOAD = "signatures/payload.sig"


def base_manifest():
    return {
        "lexeVersion": "0.1",
        "id": "com.example.corpus",
        "name": "Corpus",
        "version": "1.0.0",
        "publisher": {"name": "Corpus Publisher",
                      "publicKey": public_key_str()},
        "applicationType": "native",
        "architectures": ["x86_64"],
        "entrypoint": {"executable": "bin/app", "arguments": []},
        "install": {"scope": "user", "mode": "bundled"},
    }


class Pkg:
    """A package under construction. Mutations poke at these fields; build()
    re-derives hashes.json and both signatures so the result stays authentic."""

    def __init__(self):
        self.manifest = base_manifest()
        self.members = {
            "payload/bin/app": elf64(),
            "payload/data.txt": b"corpus payload data\n",
            "icons/128.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 40,
            "metadata/description.md": b"# Corpus\n",
        }
        self.executable = ["payload/bin/app"]     # None => omit the member
        self.seed = SEED                           # key that SIGNS
        self.manifest_raw = None                   # exact bytes override
        self.hashes_raw = None
        self.hashes_extra = {}                     # merged into the document
        self.files_override = None                 # replaces the files object
        self.algorithm = "sha256"
        self.sig_manifest = None                   # raw bytes override
        self.sig_payload = None
        self.entry_opts = {}                       # path -> Entry kwargs
        self.extra_entries = []                    # Entry objects appended
        self.drop = set()                          # member paths to omit
        self.zip_opts = {}
        self.post = None                           # fn(bytes) -> bytes
        self.sort_entries = True

    # -- derived documents -------------------------------------------------
    def manifest_bytes(self):
        if self.manifest_raw is not None:
            return self.manifest_raw
        return json.dumps(self.manifest, indent=2).encode() + b"\n"

    def hashes_bytes(self):
        if self.hashes_raw is not None:
            return self.hashes_raw
        if self.files_override is not None:
            files = self.files_override
        else:
            files = {p: sha256_hex(d) for p, d in sorted(self.members.items())
                     if p not in EXCLUDED and not p.startswith("signatures/")}
        doc = {"algorithm": self.algorithm, "files": files}
        if self.executable is not None:
            doc["executable"] = self.executable
        doc.update(self.hashes_extra)
        return json.dumps(doc, indent=2).encode() + b"\n"

    def build(self):
        man = self.manifest_bytes()
        hsh = self.hashes_bytes()
        key = signer(self.seed)
        sm = self.sig_manifest if self.sig_manifest is not None else key.sign(man)
        sp = self.sig_payload if self.sig_payload is not None else key.sign(hsh)

        blobs = dict(self.members)
        blobs["lexe.json"] = man
        blobs["metadata/hashes.json"] = hsh
        blobs[SIG_MANIFEST] = sm
        blobs[SIG_PAYLOAD] = sp
        for p in self.drop:
            blobs.pop(p, None)

        names = sorted(blobs) if self.sort_entries else list(blobs)
        entries = [Entry(n, blobs[n],
                         mode=0o755 if n == "payload/bin/app" else 0o644,
                         **self.entry_opts.get(n, {}))
                   for n in names]
        entries += self.extra_entries
        data = build_zip(entries, **self.zip_opts)
        return self.post(data) if self.post else data


# ------------------------------------------------------------------- registry

CASES = []


def case(name, rule, expect, why, mutate=None):
    """Register one case. `mutate(pkg)` may return a replacement Pkg."""
    CASES.append({"name": name, "rule": rule, "expect": expect, "why": why,
                  "mutate": mutate, "large": False})


def large_case(name, rule, expect, why, mutate):
    case(name, rule, expect, why, mutate)
    CASES[-1]["large"] = True


def json_with_raw(text):
    """A manifest supplied as exact bytes (for §5.0 shapes JSON cannot express)."""
    return text if isinstance(text, bytes) else text.encode()


# ============================ §1  Container ================================

case("valid-baseline", "§1", "accept",
     "the reference shape every other case is a mutation of")

case("container-archive-comment", "§1", "reject",
     "an EOCD comment puts bytes in the file that no signature covers",
     lambda p: p.zip_opts.update(comment=b"unsigned commentary"))
case("container-trailing-data", "§1", "reject",
     "a .lexe is exactly its archive; trailing bytes are uncovered",
     lambda p: p.zip_opts.update(append=b"TRAILING"))
case("container-prepended-data", "§1", "reject",
     "prepended bytes are uncovered and shift every recorded offset",
     lambda p: p.zip_opts.update(prepend=b"PREPENDED"))
case("container-encrypted-entry", "§2.1", "reject",
     "general-purpose bit 0 marks an encrypted entry, which 0.1 forbids",
     lambda p: p.entry_opts.update({"payload/data.txt": {"gpflag": 0x01}}))
case("container-unsupported-method", "§2.1", "reject",
     "a compression method the reader does not support must be refused",
     lambda p: p.entry_opts.update({"payload/data.txt": {"method": 99}}))
case("container-zip64-eocd", "§1", "unspecified",
     "§1 forbids a WRITER emitting ZIP64 unless required but does not say what "
     "a READER must do with one on a small archive",
     lambda p: p.zip_opts.update(zip64_eocd=True))

# ============================ §2.1 Entry paths ==============================

def _rename(old, new, *, keep_cover=True):
    """Rename a payload member, keeping coverage consistent."""
    def m(p):
        data = p.members.pop(old)
        p.members[new] = data
        if p.executable and old in p.executable:
            p.executable = [new if x == old else x for x in p.executable]
    return m


case("path-nul-byte", "§2.1", "reject",
     "a NUL in an entry name truncates the path for anything using C strings",
     _rename("payload/data.txt", "payload/da\x00ta.txt"))
case("path-backslash", "§2.1", "reject",
     "a backslash is a separator on some hosts, so it must never appear",
     _rename("payload/data.txt", "payload/sub\\data.txt"))
case("path-dotdot-segment", "§2.1", "reject",
     "a `..` segment escapes the extraction root",
     _rename("payload/data.txt", "payload/../data.txt"))
case("path-dot-segment", "§2.1", "reject",
     "a `.` segment is a second spelling of the same path",
     _rename("payload/data.txt", "payload/./data.txt"))
case("path-empty-segment", "§2.1", "reject",
     "`a//b` has an empty segment and two spellings",
     _rename("payload/data.txt", "payload//data.txt"))
case("path-absolute", "§2.1", "reject",
     "an absolute entry path ignores the extraction root",
     _rename("payload/data.txt", "/payload/data.txt"))
case("path-drive-designator", "§2.1", "reject",
     "a segment of an ASCII letter then `:` is a Windows drive designator",
     _rename("payload/data.txt", "payload/C:/data.txt"))
# The three malformed-UTF-8 names are added as RAW BYTE entries rather than as
# `members`, because a name that is not well-formed UTF-8 cannot also be a JSON
# string key in `metadata/hashes.json` — so §2.1 and §3.3 make such a member
# doubly impossible, and no package can have the path defect alone. A conforming
# reader rejects at the structure stage, before coverage is considered (§3.5).
case("path-overlong-utf8", "§2.1", "reject",
     "an overlong encoding is a second spelling of a character, so a segment "
     "that is not byte-equal to `..` can still decode to it",
     lambda p: p.extra_entries.append(Entry(b"payload/\xc0\xae\xc0\xae", b"x")))
case("path-utf16-surrogate", "§2.1", "reject",
     "a UTF-16 surrogate half (U+D800-U+DFFF) is not well-formed UTF-8",
     lambda p: p.extra_entries.append(Entry(b"payload/\xed\xa0\x80", b"x")))
case("path-above-u10ffff", "§2.1", "reject",
     "a value above U+10FFFF is not well-formed UTF-8",
     lambda p: p.extra_entries.append(Entry(b"payload/\xf5\x80\x80\x80", b"x")))
case("path-bare-0xff-byte", "§2.1", "reject",
     "a lone 0xFF is not a legal UTF-8 byte in any position",
     lambda p: p.extra_entries.append(Entry(b"payload/\xff", b"x")))
case("path-first-segment-not-allowed", "§2.1", "reject",
     "the first segment must be one of the six names the layout defines",
     _rename("payload/data.txt", "extras/data.txt"))
case("path-first-segment-case", "§2.1", "reject",
     "the top-level comparison is case-sensitive: `Payload/` is not `payload/`",
     _rename("payload/data.txt", "Payload/data.txt"))
case("path-lexe-json-as-prefix", "§2.1", "reject",
     "`lexe.json` must be a top-level file, never a path prefix",
     lambda p: p.members.__setitem__("lexe.json/extra", b"x"))
case("path-duplicate", "§2.1", "reject",
     "two entries with the same path can be read two ways",
     lambda p: p.extra_entries.append(Entry("payload/data.txt", b"second")))
case("path-case-collision", "§2.1", "reject",
     "two paths differing only in ASCII case alias on a case-insensitive host",
     lambda p: p.members.__setitem__("payload/DATA.txt", b"collide\n"))
case("path-symlink-entry", "§2.1", "reject",
     "a symlink entry (Unix mode S_IFLNK in external attributes) is refused",
     lambda p: p.entry_opts.update(
         {"payload/data.txt": {"extattr": (0o120777 << 16)}}))
case("path-too-long", "§2.1/§10.1", "reject",
     "an entry path over 1024 bytes exceeds the format's bound",
     _rename("payload/data.txt", "payload/" + "a" * 1020))
case("path-segment-too-long", "§2.1/§10.1", "reject",
     "a segment over 255 bytes exceeds the format's bound",
     _rename("payload/data.txt", "payload/" + "b" * 256))
case("path-too-deep", "§2.1/§10.1", "reject",
     "more than 64 segments exceeds the format's depth bound",
     _rename("payload/data.txt", "payload/" + "/".join(["d"] * 64)))

# Accepting cases that sit exactly ON the bounds: a reader that is off by one in
# the safe direction is still wrong, and only a valid case can catch it.
# Exactly 1024 bytes total, built from segments that each stay within the
# 255-byte segment bound: 7 ("payload") + 4 separators + 255+255+255+248 = 1024.
_AT_BOUND = "payload/" + "/".join(["a" * 255, "b" * 255, "c" * 255, "d" * 248])
assert len(_AT_BOUND.encode()) == 1024, len(_AT_BOUND.encode())

case("path-at-length-bound", "§2.1", "accept",
     "a path of exactly 1024 bytes, with every segment within the 255-byte "
     "segment bound, is within bounds and must be accepted",
     _rename("payload/data.txt", _AT_BOUND))
case("path-at-segment-bound", "§2.1", "accept",
     "a segment of exactly 255 bytes is within bounds",
     _rename("payload/data.txt", "payload/" + "b" * 255))
case("path-at-depth-bound", "§2.1", "accept",
     "exactly 64 segments is within bounds",
     _rename("payload/data.txt", "payload/" + "/".join(["d"] * 63)))
case("path-non-ascii-name", "§2.1", "accept",
     "entry names are UTF-8; a non-ASCII name is legal and must be accepted",
     _rename("payload/data.txt", "payload/documentación-ünïcode-日本語.txt"))
case("path-id-hyphen-segments", "§2.1", "accept",
     "`scripts/` is an allowed top-level name and is inside the envelope",
     lambda p: p.members.__setitem__("scripts/hook.sh", b"# reserved, not run\n"))

# ============================ §2.2 One archive ==============================

case("zip-local-central-name-mismatch", "§2.2", "reject",
     "two conforming readers would see two different archives",
     lambda p: p.entry_opts.update(
         {"payload/data.txt": {"local_name": "payload/../../ev"}}))
case("zip-local-central-method-mismatch", "§2.2", "reject",
     "the two records disagree about the compression method",
     lambda p: p.entry_opts.update(
         {"payload/bin/app": {"force_method_central": STORE}}))
case("zip-local-central-size-mismatch", "§2.2", "reject",
     "the two records disagree about the entry's sizes",
     lambda p: p.entry_opts.update(
         {"payload/data.txt": {"force_sizes": (999, 999)}}))
case("zip-gap-before-central-directory", "§2.2", "reject",
     "a complete extra local record can hide in a gap the CD offset skips",
     lambda p: p.zip_opts.update(insert_before_cd=b"\x00" * 64,
                                 cd_offset_delta=0))
case("zip-bytes-before-first-record", "§2.2", "reject",
     "nothing may precede the first local record",
     lambda p: p.zip_opts.update(prepend=b"\x00" * 16, cd_offset_delta=0))
case("zip-directory-entry-trailing-slash", "§2.2", "reject",
     "a record whose name ends in `/` is a directory entry, which 0.1 forbids; "
     "it can carry data, and a skipped entry is one no later rule applies to",
     lambda p: p.extra_entries.append(
         Entry("payload/adir/", b"SMUGGLED-DIRECTORY-PAYLOAD")))
case("zip-directory-entry-dos-bit", "§2.2", "reject",
     "the DOS directory attribute bit is the second spelling of the same thing, "
     "and the one with an ordinary-looking name",
     lambda p: p.entry_opts.update({"payload/data.txt": {"dos_dir": True}}))

# Data descriptors are TOLERATED, in both encodings: APPNOTE 4.3.9.3 makes the
# 0x08074b50 signature word optional, so both are legitimate and both must be
# accepted. These are valid cases on purpose.
case("zip-data-descriptor-with-sig-word", "§2.2", "accept",
     "a data descriptor carrying the optional 0x08074b50 word is tolerated",
     lambda p: p.entry_opts.update(
         {"payload/data.txt": {"data_descriptor": "with-sig"}}))
case("zip-data-descriptor-no-sig-word", "§2.2", "accept",
     "the signature word is OPTIONAL per APPNOTE 4.3.9.3, so the 12-byte "
     "descriptor is equally legitimate and must also be tolerated",
     lambda p: p.entry_opts.update(
         {"payload/data.txt": {"data_descriptor": "no-sig"}}))
case("zip-data-descriptor-every-entry", "§2.2", "accept",
     "descriptors on every entry is unusual but conforming",
     lambda p: p.entry_opts.update(
         {k: {"data_descriptor": "with-sig"} for k in
          list(p.members) + ["lexe.json", "metadata/hashes.json",
                             SIG_MANIFEST, SIG_PAYLOAD]}))

# ============================ §3.2 signatures/ ==============================

case("sig-extra-member", "§3.2", "reject",
     "`signatures/` is an exact set; any other member there is covered by no "
     "hash and no signature",
     lambda p: p.members.__setitem__("signatures/smuggled.bin", b"X" * 64))
case("sig-plausible-name", "§3.2", "reject",
     "an exact set cannot be widened by a name that looks plausible",
     lambda p: p.members.__setitem__("signatures/manifest.sig.bak", b"X" * 64))
case("sig-manifest-missing", "§2.1", "reject",
     "a required entry is missing",
     lambda p: p.drop.add(SIG_MANIFEST))
case("sig-payload-missing", "§2.1", "reject",
     "a required entry is missing",
     lambda p: p.drop.add(SIG_PAYLOAD))
case("required-manifest-missing", "§2.1", "reject",
     "`lexe.json` is required",
     lambda p: p.drop.add("lexe.json"))
case("required-hashes-missing", "§2.1", "reject",
     "`metadata/hashes.json` is required",
     lambda p: p.drop.add("metadata/hashes.json"))
case("required-payload-absent-application", "§2.1", "reject",
     "an application in bundled mode must carry payload content",
     lambda p: [p.drop.add("payload/bin/app"), p.drop.add("payload/data.txt"),
                p.__setattr__("executable", [])])

# ============================ §3.3 Coverage =================================

def _cover(extra=None, drop=None):
    def m(p):
        files = {q: sha256_hex(d) for q, d in sorted(p.members.items())
                 if q not in EXCLUDED and not q.startswith("signatures/")}
        for k in (drop or []):
            files.pop(k, None)
        files.update(extra or {})
        p.files_override = files
        if drop:
            p.executable = [x for x in (p.executable or []) if x in files]
    return m


case("coverage-orphan-key", "§3.3", "reject",
     "a covered key naming a member that is not in the archive",
     _cover(extra={"payload/ghost.bin": "00" * 32}))
case("coverage-member-not-covered", "§3.3", "reject",
     "an archive member that should be covered and is not a key — this is the "
     "direction that closes smuggling",
     _cover(drop=["payload/data.txt"]))
case("coverage-covers-manifest", "§3.3", "reject",
     "a package must not attempt to cover `lexe.json`",
     _cover(extra={"lexe.json": "00" * 32}))
case("coverage-covers-hashes", "§3.3", "reject",
     "a package must not attempt to cover `metadata/hashes.json` itself",
     _cover(extra={"metadata/hashes.json": "00" * 32}))
case("coverage-covers-signature", "§3.3", "reject",
     "a package must not attempt to cover a signature",
     _cover(extra={SIG_MANIFEST: "00" * 32}))
case("coverage-scripts-inside-envelope", "§3.3", "accept",
     "`scripts/` is inside the envelope: carried, covered, and not executed",
     lambda p: p.members.__setitem__("scripts/post.sh", b"# not run in 0.1\n"))
case("coverage-scripts-uncovered", "§3.3", "reject",
     "content a 0.2 runtime might act upon must not enter a package unsigned",
     lambda p: [p.members.__setitem__("scripts/post.sh", b"# unsigned\n"),
                _cover(drop=["scripts/post.sh"])(p)])

# ============================ §3.6 hashes.json ==============================

case("hashes-uppercase-digest", "§3.6", "reject",
     "an uppercase digest is malformed, not merely mismatched: a case-sensitive "
     "comparison is conforming, so two readers would disagree",
     lambda p: _cover(extra={"payload/data.txt":
                             sha256_hex(p.members["payload/data.txt"]).upper()})(p))
case("hashes-wrong-algorithm", "§3.6", "reject",
     "`algorithm` must be the string \"sha256\"",
     lambda p: setattr(p, "algorithm", "sha512"))
case("hashes-algorithm-missing", "§3.6", "reject",
     "`algorithm` must be present; a reader must not infer it from digest length",
     lambda p: setattr(p, "hashes_raw", json.dumps(
         {"files": {q: sha256_hex(d) for q, d in sorted(p.members.items())
                    if q not in EXCLUDED and not q.startswith("signatures/")}},
         indent=2).encode() + b"\n"))
case("hashes-digest-wrong-length", "§3.6", "reject",
     "each value must be a 64-character hexadecimal string",
     lambda p: _cover(extra={"payload/data.txt": "abc123"})(p))
case("hashes-digest-not-string", "§3.6", "reject",
     "a digest must be a string",
     lambda p: _cover(extra={"payload/data.txt": 12345})(p))
case("hashes-digest-mismatch", "§3.6", "reject",
     "verification must fail when a covered member's recomputed digest differs",
     lambda p: _cover(extra={"payload/data.txt": "11" * 32})(p))
case("hashes-files-not-object", "§3.6", "reject",
     "`files` must be a JSON object",
     lambda p: setattr(p, "hashes_raw",
                       json.dumps({"algorithm": "sha256", "files": []},
                                  indent=2).encode() + b"\n"))
case("hashes-unknown-member", "§3.6/§5.0", "accept",
     "an unrecognised member must be ignored — `executable` itself was added "
     "during the freeze, so a reader rejecting unknowns would have blocked it",
     lambda p: p.hashes_extra.update({"futureThing": {"nested": True}}))
case("hashes-over-budget", "§10.1", "reject",
     "`metadata/hashes.json` must not exceed 16 MiB", None)  # replaced below

# The 16 MiB case is real but slow to build, so it is gated behind
# --include-large rather than paid for on every run.
CASES.pop()
large_case("hashes-over-budget", "§10.1", "reject",
           "`metadata/hashes.json` must not exceed 16 MiB",
           lambda p: p.hashes_extra.update({"pad": "z" * (16 * 1024 * 1024 + 64)}))

# -- the `executable` declaration (§3.6 / §3.1.1) ---------------------------

case("exec-not-array", "§3.6", "reject",
     "`executable` must be an array",
     lambda p: setattr(p, "executable", "payload/bin/app"))
case("exec-element-not-string", "§3.6", "reject",
     "every element must be a string",
     lambda p: setattr(p, "executable", ["payload/bin/app", 7]))
case("exec-element-not-covered", "§3.6", "reject",
     "a path with no digest cannot be declared executable — the declaration "
     "would apply to content nothing authenticates",
     lambda p: setattr(p, "executable", ["payload/bin/app", "payload/ghost"]))
case("exec-element-outside-payload", "§3.6", "reject",
     "only `payload/` members are ever extracted, so only they can be declared",
     lambda p: setattr(p, "executable", ["payload/bin/app", "icons/128.png"]))
case("exec-duplicate-element", "§3.6", "reject",
     "the same path must not appear more than once",
     lambda p: setattr(p, "executable", ["payload/bin/app", "payload/bin/app"]))
case("exec-typo-path", "§3.6", "reject",
     "a one-letter typo must fail verification, not surface as Permission "
     "denied at first launch",
     lambda p: setattr(p, "executable", ["payload/bin/apps"]))
case("exec-empty-array", "§3.6", "accept",
     "`[]` says \"nothing here is executable\" and must be expressible",
     lambda p: setattr(p, "executable", []))
case("exec-absent", "§3.6", "accept",
     "absence is legal and means fall back to examining content",
     lambda p: setattr(p, "executable", None))
case("exec-declares-data-file", "§3.6", "accept",
     "declaring a non-magic data file executable is the publisher's choice over "
     "content that is hash-covered",
     lambda p: setattr(p, "executable", ["payload/bin/app", "payload/data.txt"]))

# ============================ §4 Signatures =================================

case("sig-swapped", "§4", "reject",
     "each signature is over its own defined input; swapping them verifies "
     "neither",
     lambda p: (setattr(p, "sig_manifest",
                        signer().sign(p.hashes_bytes())),
                setattr(p, "sig_payload",
                        signer().sign(p.manifest_bytes()))))
case("sig-foreign-key", "§4", "reject",
     "a signature by a key other than the manifest's publisher key",
     lambda p: setattr(p, "seed", FOREIGN_SEED))
case("sig-manifest-truncated", "§4", "reject",
     "a signature must be exactly 64 bytes",
     lambda p: setattr(p, "sig_manifest", signer().sign(p.manifest_bytes())[:63]))
case("sig-manifest-overlong", "§4", "reject",
     "a signature must be exactly 64 bytes",
     lambda p: setattr(p, "sig_manifest",
                       signer().sign(p.manifest_bytes()) + b"\x00"))
case("sig-manifest-corrupt", "§4", "reject",
     "a 64-byte value that is not a valid signature over the stored bytes",
     lambda p: setattr(p, "sig_manifest", b"\x00" * 64))
case("key-bad-prefix", "§4", "reject",
     "the publisher key must use the `ed25519:` prefix exactly",
     lambda p: p.manifest["publisher"].__setitem__(
         "publicKey", public_key_str().replace("ed25519:", "ed25519-")))
case("key-no-prefix", "§4", "reject",
     "a bare base64 key has no algorithm and must be refused",
     lambda p: p.manifest["publisher"].__setitem__(
         "publicKey", public_key_str().split(":", 1)[1]))
case("key-31-bytes", "§4", "reject",
     "a decoded length other than 32 must be refused",
     lambda p: p.manifest["publisher"].__setitem__(
         "publicKey", "ed25519:" + base64.b64encode(b"\x01" * 31).decode()))
case("key-33-bytes", "§4", "reject",
     "a decoded length other than 32 must be refused",
     lambda p: p.manifest["publisher"].__setitem__(
         "publicKey", "ed25519:" + base64.b64encode(b"\x01" * 33).decode()))
case("key-unpadded-base64", "§4", "reject",
     "base64 is the RFC 4648 alphabet WITH padding",
     lambda p: p.manifest["publisher"].__setitem__(
         "publicKey", "ed25519:" + base64.b64encode(
             signer().public_key().public_bytes_raw()).decode().rstrip("=")))
case("key-not-base64", "§4", "reject",
     "a value that is not base64 at all",
     lambda p: p.manifest["publisher"].__setitem__(
         "publicKey", "ed25519:!!!not base64!!!"))

# ============================ §5.0 Strict JSON ==============================

case("json-manifest-bom", "§5.0", "reject",
     "a BOM is not whitespace and is not permitted before the top-level value",
     lambda p: setattr(p, "manifest_raw",
                       b"\xef\xbb\xbf" + json.dumps(p.manifest).encode()))
case("json-manifest-duplicate-key-top", "§5.0", "reject",
     "a duplicated top-level member can be read two ways",
     lambda p: setattr(p, "manifest_raw", json_with_raw(
         '{"lexeVersion":"0.1","lexeVersion":"0.2","id":"com.example.corpus",'
         '"name":"Corpus","version":"1.0.0","publisher":{"name":"P",'
         '"publicKey":"' + public_key_str() + '"},"applicationType":"native",'
         '"architectures":["x86_64"],"entrypoint":{"executable":"bin/app"},'
         '"install":{"mode":"bundled"}}')))
case("json-manifest-duplicate-key-nested", "§5.0", "reject",
     "the no-duplicates rule applies at ANY nesting depth: a duplicated "
     "publicKey is the case that makes a signature prove less than it appears",
     lambda p: setattr(p, "manifest_raw", json_with_raw(
         '{"lexeVersion":"0.1","id":"com.example.corpus","name":"Corpus",'
         '"version":"1.0.0","publisher":{"name":"P","publicKey":"'
         + public_key_str() + '","publicKey":"' + public_key_str(FOREIGN_SEED)
         + '"},"applicationType":"native","architectures":["x86_64"],'
         '"entrypoint":{"executable":"bin/app"},"install":{"mode":"bundled"}}')))
case("json-manifest-trailing-data", "§5.0", "reject",
     "no trailing data after the top-level value",
     lambda p: setattr(p, "manifest_raw",
                       json.dumps(p.manifest).encode() + b"\n{}"))
case("json-manifest-not-object", "§5.0", "reject",
     "the top level must be a JSON object",
     lambda p: setattr(p, "manifest_raw", b"[1,2,3]"))
case("json-manifest-invalid-utf8", "§5.0", "reject",
     "the document must be valid UTF-8",
     lambda p: setattr(p, "manifest_raw",
                       json.dumps(p.manifest).encode().replace(
                           b"Corpus", b"Cor\xffus")))
case("json-hashes-duplicate-key", "§5.0", "reject",
     "the strict-JSON rules apply to `metadata/hashes.json` too",
     lambda p: setattr(p, "hashes_raw", json_with_raw(
         '{"algorithm":"sha256","algorithm":"sha256","files":{}}')))
case("json-hashes-bom", "§5.0", "reject",
     "no BOM, in the hash document as well",
     lambda p: setattr(p, "hashes_raw", b"\xef\xbb\xbf" + p.hashes_bytes()))
case("json-unknown-member-top", "§5.0", "accept",
     "unknown members MUST be ignored for forward compatibility",
     lambda p: p.manifest.update({"futureTopLevel": {"a": [1, 2]}}))
case("json-unknown-member-nested", "§5.0", "accept",
     "forward compatibility applies at every level, not only the top",
     lambda p: p.manifest["entrypoint"].update({"futureNested": "ignored"}))
case("json-null-is-absent-optional", "§5.0", "accept",
     "`null` is treated as absent: a null optional field is not a type error",
     lambda p: p.manifest.update({"runtimeProfile": None, "updates": None}))
case("json-null-is-absent-required", "§5.0", "reject",
     "`null` is absent for required fields too, so a null `name` is missing",
     lambda p: p.manifest.update({"name": None}))
case("json-integer-as-float-token", "§5.0", "reject",
     # Was `unspecified`, and the case is why: §5.0 required integer TOKENS while
     # 0.1 declared no field as an integer, so the rule had no subject. §5.0 and
     # §5.7 now name `install.estimatedSize` as a non-negative integer.
     "`install.estimatedSize` is declared an integer, so 1.0 is not a valid "
     "token for it even though it denotes an integral value",
     lambda p: p.manifest["install"].update({"estimatedSize": 1.0}))

# ============================ §5.1 Role =====================================

case("role-unrecognised", "§5.1", "reject",
     "an unrecognised role must be rejected, not defaulted",
     lambda p: p.manifest.update({"role": "installer"}))
case("role-absent-defaults-application", "§5.1", "accept",
     "role is optional and defaults to \"application\"",
     lambda p: p.manifest.pop("role", None))
case("role-explicit-application", "§5.1", "accept",
     "the explicit spelling of the default must also be accepted",
     lambda p: p.manifest.update({"role": "application"}))

# ============================ §5.2 Common fields ============================

def _mf(**kw):
    def m(p):
        p.manifest.update(kw)
    return m


case("field-lexeversion-wrong", "§5.2", "reject",
     "`lexeVersion` is compared literally: \"0.1.0\" is another version",
     _mf(lexeVersion="0.1.0"))
case("field-lexeversion-0-10", "§5.2", "reject",
     "\"0.10\" is another version, not this one",
     _mf(lexeVersion="0.10"))
case("field-name-empty", "§5.2", "reject", "`name` must be non-empty",
     _mf(name=""))
case("field-name-too-long", "§5.2/§10.1", "reject",
     "`name` is bounded at 1024 bytes", _mf(name="n" * 1025))
case("field-name-at-bound", "§5.2/§10.1", "accept",
     "exactly 1024 bytes is within bounds", _mf(name="n" * 1024))
case("field-id-single-segment", "§5.2", "reject",
     "an App ID needs 2+ dot-separated segments", _mf(id="single"))
case("field-id-bad-character", "§5.2", "reject",
     "the character class is `[a-zA-Z0-9-]` and nothing more",
     _mf(id="com.exa_mple.app"))
case("field-id-empty-segment", "§5.2", "reject",
     "an empty segment is not a segment of `[a-zA-Z0-9-]+`",
     _mf(id="com..app"))
case("field-id-too-long", "§5.2/§10.1", "reject",
     "`id` is bounded at 255 bytes",
     _mf(id="com.example." + "a" * 250))
case("field-id-leading-hyphen", "§5.2", "accept",
     "`-` is legal anywhere in a segment, so `-foo.bar` is a valid App ID even "
     "though it is not a valid DNS name — the rule is the character class",
     _mf(id="-foo.bar"))
case("field-version-empty", "§5.2", "reject",
     "`version` is 1 to 64 bytes", _mf(version=""))
case("field-version-dot", "§5.2", "reject",
     "`version` must not be `.`: it is used verbatim as a path component",
     _mf(version="."))
case("field-version-dotdot", "§5.2", "reject",
     "`version` must not be `..`", _mf(version=".."))
case("field-version-slash", "§5.2", "reject",
     "`version` must not contain `/`", _mf(version="1.0/0"))
case("field-version-backslash", "§5.2", "reject",
     "`version` must not contain `\\`", _mf(version="1.0\\0"))
case("field-version-colon", "§5.2", "reject",
     "`version` must not contain `:`", _mf(version="1.0:0"))
case("field-version-control-byte", "§5.2", "reject",
     "no byte <= 0x20, which includes space and every C0 control",
     _mf(version="1.0 0"))
case("field-version-del", "§5.2", "reject",
     "0x7F is excluded as well", _mf(version="1.0\x7f"))
case("field-version-too-long", "§5.2/§10.1", "reject",
     "`version` is bounded at 64 bytes", _mf(version="1." + "0" * 64))
case("field-version-non-ascii", "§5.2", "accept",
     "bytes >= 0x80 are permitted, so a version may be non-ASCII",
     _mf(version="1.0.0-café"))
case("field-publisher-name-empty", "§5.2", "reject",
     "`publisher.name` must be non-empty",
     lambda p: p.manifest["publisher"].__setitem__("name", ""))
case("field-publickey-too-long", "§5.2/§10.1", "reject",
     "`publisher.publicKey` is bounded at 128 bytes",
     lambda p: p.manifest["publisher"].__setitem__(
         "publicKey", "ed25519:" + "A" * 200))
case("field-manifest-over-budget", "§10.1", "reject",
     "`lexe.json` must not exceed 1 MiB",
     _mf(padding="p" * (1024 * 1024 + 64)))

# ============================ §5.3 Application fields =======================

case("app-applicationtype-missing", "§5.3", "reject",
     "`applicationType` is required for an application",
     lambda p: p.manifest.pop("applicationType"))
case("app-applicationtype-unknown", "§5.3", "reject",
     "the value must be native, portable or windows",
     _mf(applicationType="flatpak"))
case("app-architectures-empty", "§5.3", "reject",
     "`architectures` must be a non-empty array", _mf(architectures=[]))
case("app-architectures-missing", "§5.3", "reject",
     "`architectures` is required for an application",
     lambda p: p.manifest.pop("architectures"))
case("app-entrypoint-missing", "§5.3", "reject",
     "`entrypoint.executable` is required for an application",
     lambda p: p.manifest.pop("entrypoint"))
case("app-entrypoint-absolute", "§5.3", "reject",
     "the entrypoint is a relative path inside `payload/`",
     lambda p: p.manifest["entrypoint"].__setitem__("executable", "/bin/app"))
case("app-entrypoint-dotdot", "§5.3", "reject",
     "the entrypoint must not contain `..`",
     lambda p: p.manifest["entrypoint"].__setitem__("executable",
                                                    "../bin/app"))
case("app-entrypoint-backslash", "§5.3", "reject",
     "the entrypoint must not contain a backslash",
     lambda p: p.manifest["entrypoint"].__setitem__("executable",
                                                    "bin\\app"))
case("app-install-mode-network", "§5.3", "reject",
     "`install.mode` must be \"bundled\" in 0.1",
     lambda p: p.manifest["install"].__setitem__("mode", "network"))
case("app-build-on-native", "§5.8", "reject",
     "a native package declaring `build` must be rejected: there is nothing "
     "to build",
     _mf(build={"system": "make", "sourceDir": "src", "toolchain": ["make"]}))
case("app-launch-id-on-application", "§5.4", "reject",
     "`launch.applicationId` must be absent for an application",
     _mf(launch={"applicationId": "com.example.other"}))

# ============================ §5.5 Execution policy =========================

case("exec-missioncritical-with-chain", "§5.5", "reject",
     "missionCritical true with any non-native chain is a contradiction",
     _mf(execution={"missionCritical": True, "allowedChains": ["proton"]}))
case("exec-allowedchains-empty", "§5.5", "accept",
     # Reclassified from `reject` when the SPEC was corrected, not when an
     # implementation was. §5.5's table said "non-empty array" while a paragraph
     # below it said an absent or empty array means `["native"]` -- a
     # self-contradiction in the frozen document, which this corpus found. The
     # table was the wrong half: the reader substitutes `["native"]`, the package
     # launches natively, and the table now says so.
     "an absent or EMPTY `allowedChains` means [\"native\"]",
     _mf(execution={"allowedChains": []}))
case("exec-chain-bad-character", "§5.5", "reject",
     "a chain id is `[a-zA-Z0-9-+_]+`",
     _mf(execution={"allowedChains": ["wine!"]}))
case("exec-chain-over-budget", "§10.1", "reject",
     "each `allowedChains` element is bounded at 1024 bytes",
     _mf(execution={"allowedChains": ["a" * 1025]}))
case("exec-missioncritical-native-ok", "§5.5", "accept",
     "missionCritical with the default native chain is consistent",
     _mf(execution={"missionCritical": True, "allowedChains": ["native"]}))
case("exec-windows-empty-chains", "§5.3/§5.5", "reject",
     "an empty `allowedChains` permits no chain at all, so a windows package "
     "carrying one permits no foreign-OS chain — the §5.3 refusal — and any "
     "package with one can never be launched by a resolver that must choose "
     "from the set",
     lambda p: [_windows()(p),
                p.manifest.update({"execution": {"allowedChains": []}})])

# ============================ §6.7 Payload role =============================

case("role-native-entrypoint-not-elf", "§6.7", "reject",
     "the observed alpha failure: a manifest declaring native while the "
     "entrypoint is source text",
     lambda p: p.members.__setitem__("payload/bin/app",
                                     b"int main(){return 0;}\n"))
case("role-native-entrypoint-relocatable", "§6.7", "reject",
     "ET_REL is not runnable; only ET_EXEC or ET_DYN",
     lambda p: p.members.__setitem__("payload/bin/app", elf64(e_type=ET_REL)))
case("role-native-arch-mismatch", "§6.7", "reject",
     "the entrypoint must target one of the declared architectures",
     lambda p: p.members.__setitem__("payload/bin/app",
                                     elf64(e_machine=EM_AARCH64)))
case("role-native-entrypoint-absent", "§6.7", "reject",
     "the declared entrypoint must be present in the archive",
     lambda p: [p.drop.add("payload/bin/app"),
                setattr(p, "executable", []),
                _cover(drop=["payload/bin/app"])(p)])
case("role-native-pie-accepted", "§6.7", "accept",
     "ET_DYN is a position-independent executable and is runnable",
     lambda p: p.members.__setitem__("payload/bin/app", elf64(e_type=ET_DYN)))
case("role-native-aarch64-declared", "§6.7", "accept",
     "an aarch64 entrypoint with aarch64 declared is consistent",
     lambda p: [p.members.__setitem__("payload/bin/app",
                                      elf64(e_machine=EM_AARCH64)),
                p.manifest.update({"architectures": ["aarch64"]})])

# -- windows ---------------------------------------------------------------

def _windows(**over):
    def m(p):
        p.manifest.update({
            "applicationType": "windows",
            "architectures": ["x86_64"],
            "execution": {"allowedChains": ["proton"]},
        })
        p.manifest["entrypoint"]["executable"] = "bin/app.exe"
        p.members.pop("payload/bin/app", None)
        p.members["payload/bin/app.exe"] = over.get("image", pe32plus())
        p.executable = ["payload/bin/app.exe"]
        p.manifest.update(over.get("manifest", {}))
    return m


case("role-windows-valid", "§6.7", "accept",
     "a PE image, executable-image set, DLL clear, arch declared, and a "
     "foreign-OS chain permitted",
     _windows())
case("role-windows-no-foreign-chain", "§5.3", "reject",
     "a windows package permitting no foreign-OS chain must be rejected: "
     "silence is not consent to run under a compatibility layer",
     _windows(manifest={"execution": {"allowedChains": ["native"]}}))
case("role-windows-default-chain", "§5.3", "reject",
     "relying on the default `[\"native\"]` is the same refusal",
     lambda p: [_windows()(p), p.manifest.pop("execution", None)])
case("role-windows-mission-critical", "§5.3", "reject",
     "mission-critical requires a host-native realization, which a Windows "
     "payload has none of by construction",
     _windows(manifest={"execution": {"missionCritical": True,
                                      "allowedChains": ["proton"]}}))
case("role-windows-is-dll", "§6.7", "reject",
     "a DLL is a library and cannot be launched, and it carries the "
     "executable-image bit too, so both must be checked",
     _windows(image=pe32plus(
         characteristics=IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL)))
case("role-windows-not-executable-image", "§6.7", "reject",
     "a PE object without IMAGE_FILE_EXECUTABLE_IMAGE is not a runnable image",
     _windows(image=pe32plus(characteristics=0)))
case("role-windows-unnameable-machine", "§6.7", "reject",
     "a PE for a machine 0.1 cannot name must be refused as such",
     _windows(image=pe32plus(machine=PE_I386)))
case("role-windows-elf-entrypoint", "§6.7", "reject",
     "a Linux binary belongs in a native package",
     _windows(image=elf64()))
case("role-windows-layered-chain", "§5.5", "accept",
     "`proton+fex` is a foreign-OS layer outermost over ISA translation",
     _windows(manifest={"execution": {"allowedChains": ["proton+fex"]}}))

# -- portable --------------------------------------------------------------

def _portable(ship_entrypoint=False, omit_source=False, **over):
    def m(p):
        p.manifest.update({
            "applicationType": "portable",
            "entrypoint": {"executable": "bin/built", "arguments": []},
            "build": {"system": "command", "sourceDir": "src",
                      "command": ["cc", "-o", "bin/built", "src/main.c"],
                      "toolchain": ["cc"]},
        })
        p.members.pop("payload/bin/app", None)
        p.executable = []
        if not omit_source:
            p.members["payload/src/main.c"] = b"int main(void){return 0;}\n"
        if ship_entrypoint:
            p.members["payload/bin/built"] = elf64()
            p.executable = ["payload/bin/built"]
        p.manifest.update(over.get("manifest", {}))
        if "build" in over:
            p.manifest["build"] = over["build"]
    return m


case("role-portable-valid", "§6.7", "accept",
     "source present, entrypoint absent — the build produces it on the host",
     _portable())
case("role-portable-ships-entrypoint", "§6.7", "reject",
     "a portable package shipping its entrypoint is a native payload wearing a "
     "portable label: the binary installed is one this host never compiled",
     _portable(ship_entrypoint=True))
case("role-portable-no-source", "§6.7", "reject",
     "a portable package must carry the source it is compiled from",
     _portable(omit_source=True))
case("role-portable-no-build", "§5.8", "reject",
     "a portable package without `build` can be installed nowhere",
     lambda p: [_portable()(p), p.manifest.pop("build")])
case("role-portable-build-command-missing", "§5.8", "reject",
     "`build.command` is REQUIRED for system \"command\"",
     _portable(build={"system": "command", "sourceDir": "src",
                      "toolchain": ["cc"]}))
case("role-portable-build-command-on-make", "§5.8", "reject",
     "`build.command` is FORBIDDEN for any system other than \"command\"",
     _portable(build={"system": "make", "sourceDir": "src",
                      "command": ["make"], "toolchain": ["make"]}))
case("role-portable-toolchain-absolute", "§5.8", "reject",
     "toolchain entries are bare names: an absolute path in a signed manifest "
     "is a claim about a machine the publisher has never seen",
     _portable(build={"system": "make", "sourceDir": "src",
                      "toolchain": ["/usr/bin/make"]}))
case("role-portable-toolchain-empty", "§5.8", "reject",
     "`build.toolchain` is REQUIRED and non-empty",
     _portable(build={"system": "make", "sourceDir": "src", "toolchain": []}))
case("role-portable-build-system-unknown", "§5.8", "reject",
     "`build.system` is one of make, cmake, command",
     _portable(build={"system": "bazel", "sourceDir": "src",
                      "toolchain": ["bazel"]}))
case("role-portable-sourcedir-escape", "§5.8", "reject",
     "`build.sourceDir` follows the same path rules as the entrypoint",
     _portable(build={"system": "make", "sourceDir": "../src",
                      "toolchain": ["make"]}))
case("role-portable-command-element-over-budget", "§10.1", "reject",
     "each `build.command` element is bounded at 1024 bytes",
     _portable(build={"system": "command", "sourceDir": "src",
                      "command": ["cc", "a" * 1025], "toolchain": ["cc"]}))
case("role-portable-make-valid", "§5.8", "accept",
     "a make recipe with no command member is the correct shape",
     _portable(build={"system": "make", "sourceDir": "src",
                      "toolchain": ["make"]}))

# -- launch references -----------------------------------------------------

def _launch(**over):
    def m(p):
        p.manifest = {
            "lexeVersion": "0.1",
            "id": "org.lexe.launch",
            "name": "Run Corpus App",
            "version": "1.0.0",
            "publisher": {"name": "Local", "publicKey": public_key_str()},
            "role": "launch",
            "launch": {"applicationId": "com.example.corpus"},
        }
        p.manifest.update(over.get("manifest", {}))
        for k in list(p.members):
            if k.startswith("payload/"):
                p.members.pop(k)
        p.executable = []
        if over.get("payload"):
            p.members["payload/smuggled.bin"] = over["payload"]
            p.executable = []
    return m


case("role-launch-valid", "§5.4", "accept",
     "a launch reference: no payload, a target application id, fixed own id",
     _launch())
case("role-launch-with-payload", "§6.7", "reject",
     "a launch reference must carry no payload entries",
     _launch(payload=b"smuggled\n"))
case("role-launch-missing-application-id", "§5.4", "reject",
     "`launch.applicationId` is required for a launch reference",
     lambda p: [_launch()(p), p.manifest["launch"].pop("applicationId")])
case("role-launch-bad-application-id", "§5.4", "reject",
     "`launch.applicationId` has the same shape as `id`",
     _launch(manifest={"launch": {"applicationId": "not_an_id"}}))
case("role-launch-with-application-fields", "§5.3", "reject",
     "application-only fields MUST be absent for a launch reference",
     _launch(manifest={"applicationType": "native",
                       "architectures": ["x86_64"],
                       "entrypoint": {"executable": "bin/app"}}))

# ============================ optional shapes ===============================

case("optional-no-icons", "§2", "accept",
     "icons are optional; a package with none is perfectly valid",
     lambda p: p.members.pop("icons/128.png"))
case("optional-no-metadata-extras", "§2", "accept",
     "only hashes.json is required under metadata/",
     lambda p: p.members.pop("metadata/description.md"))
case("optional-permissions-empty", "§5.7", "accept",
     "`permissions` defaults to empty and is informational in 0.1",
     _mf(permissions=[]))
# These two were `unspecified`, and finding that out was the point.
#
# Appendix A claimed the `permissions` vocabulary was "closed and checked at
# stage 2" and that duplicates were rejected. NEITHER rule appeared in §5.7,
# which said only `permissions` (`[]`, informational in 0.1)`, and the document
# named no valid permission anywhere — so a reader written from the normative
# text could not write the check at all, and correctly accepted `["telepathy"]`
# while the reference runtime refused it. A rule that exists only in a freeze
# record is not a rule.
#
# §5.7.1 now states the closed vocabulary, lists its two members, and states the
# no-duplicates rule with its reason (the approved set is recorded with a digest,
# so two spellings of one request produce two digests for the same authority).
# These are therefore ordinary `reject` cases now, asserting the rule rather than
# merely checking that two implementations happen to agree.
case("optional-permission-unknown", "§5.7.1", "reject",
     "the 0.1 vocabulary is closed: only network and user-files-selected",
     _mf(permissions=["telepathy"]))
case("optional-permission-duplicate", "§5.7.1", "reject",
     "no permission id may be listed more than once",
     _mf(permissions=["network", "network"]))
case("optional-permission-both-legal", "§5.7.1", "accept",
     "both members of the vocabulary together are a legitimate request, and a "
     "corpus that only rejected would not notice a reader refusing them",
     _mf(permissions=["network", "user-files-selected"]))
case("optional-runtimeprofile-unknown", "§5.7", "accept",
     "a reader that cannot resolve `runtimeProfile` treats the package as "
     "declaring none; it MUST NOT reject and MUST NOT substitute a default",
     _mf(runtimeProfile="quantum-native"))
case("optional-launch-mode-console", "§5.6", "accept",
     "launch.mode console is one of the three defined modes",
     _mf(launch={"mode": "console"}))
case("optional-launch-mode-unknown", "§5.6", "reject",
     "an undefined launch mode must be rejected",
     _mf(launch={"mode": "hologram"}))


# ------------------------------------------------------------------ emission

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out_dir")
    ap.add_argument("--include-large", action="store_true",
                    help="also emit the multi-megabyte budget cases")
    args = ap.parse_args()

    out = args.out_dir
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)

    index, skipped, errors = [], 0, []
    for spec in CASES:
        if spec["large"] and not args.include_large:
            skipped += 1
            continue
        pkg = Pkg()
        try:
            if spec["mutate"] is not None:
                replaced = spec["mutate"](pkg)
                if isinstance(replaced, Pkg):
                    pkg = replaced
            data = pkg.build()
        except Exception as exc:                       # a broken CASE, not a finding
            errors.append("%s: %s: %s" % (spec["name"], type(exc).__name__, exc))
            continue
        fname = spec["name"] + ".lexe"
        with open(os.path.join(out, fname), "wb") as fh:
            fh.write(data)
        index.append({"name": spec["name"], "file": fname,
                      "rule": spec["rule"], "expect": spec["expect"],
                      "why": spec["why"], "bytes": len(data)})

    with open(os.path.join(out, "index.json"), "w") as fh:
        json.dump({"cases": index,
                   "counts": {
                       "total": len(index),
                       "accept": sum(1 for c in index if c["expect"] == "accept"),
                       "reject": sum(1 for c in index if c["expect"] == "reject"),
                       "unspecified": sum(1 for c in index
                                          if c["expect"] == "unspecified"),
                   }}, fh, indent=2)

    sys.stderr.write("corpus: %d cases emitted (%d accept, %d reject, "
                     "%d unspecified), %d large skipped\n" % (
                         len(index),
                         sum(1 for c in index if c["expect"] == "accept"),
                         sum(1 for c in index if c["expect"] == "reject"),
                         sum(1 for c in index if c["expect"] == "unspecified"),
                         skipped))
    if errors:
        sys.stderr.write("corpus: %d case(s) FAILED TO BUILD:\n" % len(errors))
        for e in errors:
            sys.stderr.write("    " + e + "\n")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())

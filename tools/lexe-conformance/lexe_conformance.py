#!/usr/bin/env python3
"""lexe-conformance -- an INDEPENDENT conformance validator for `.lexe` packages.

This program exists to DISAGREE with the C++ reference implementation. It was
written from docs/FORMAT-0.1.md (with docs/HARDENING.md for the resource
limits), in Python 3, using nothing but the standard library. It never shells
out to `lexe`, never links the engine, and re-derives every predicate from the
prose rather than porting the C++ one. Where the two disagree, one of them has
a bug, and that is the point.

Usage:
    python3 lexe_conformance.py PACKAGE.lexe
    python3 lexe_conformance.py --json PACKAGE.lexe

Exit codes:
    0  conformant (no error-severity violations)
    1  violations found
    2  the package could not be read at all
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import struct
import sys
import zipfile
from pathlib import Path

# --------------------------------------------------------------------------
# Resource limits. FORMAT-0.1.md does not state most of these numbers; they
# come from docs/HARDENING.md §B.10 / §F and its "Remaining limitations"
# section (see README: spec gap G1).
# --------------------------------------------------------------------------
MAX_PACKAGE_BYTES = 2 * 1024 * 1024 * 1024               # 2 GiB
MAX_ENTRY_COUNT = 65535
MAX_ENTRY_UNCOMPRESSED_BYTES = 1 * 1024 * 1024 * 1024    # 1 GiB
MAX_TOTAL_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024    # 2 GiB
MAX_EXPANSION_RATIO = 200
RATIO_GRACE_BYTES = 16 * 1024 * 1024                     # 16 MiB
MAX_PATH_BYTES = 1024
MAX_PATH_COMPONENT_BYTES = 255
MAX_PATH_DEPTH = 64
MAX_MANIFEST_BYTES = 1024 * 1024                         # 1 MiB
MAX_HASHES_BYTES = 16 * 1024 * 1024                      # 16 MiB
MAX_ID_BYTES = 255
MAX_VERSION_CHARS = 64
ED25519_SIGNATURE_BYTES = 64
ED25519_PUBLIC_KEY_BYTES = 32

# FORMAT-0.1 §2 entry layout.
REQUIRED_ENTRIES = (
    "lexe.json",
    "metadata/hashes.json",
    "signatures/manifest.sig",
    "signatures/payload.sig",
)
ALLOWED_TOP_LEVEL = frozenset(
    ("lexe.json", "signatures", "metadata", "icons", "payload", "scripts")
)

# FORMAT-0.1 §5 enumerations.
ROLES = ("application", "launch")
APPLICATION_TYPES = ("native", "portable", "windows")
ARCHITECTURES = ("x86_64", "aarch64")
LAUNCH_MODES = ("gui", "console", "service")
INSTALL_MODES = ("bundled",)
BUILD_SYSTEMS = ("make", "cmake", "command")

HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
ID_SEGMENT = re.compile(r"\A[a-zA-Z0-9-]+\Z")
CHAIN_ID = re.compile(r"\A[a-zA-Z0-9\-+_]+\Z")

# ELF e_machine -> FORMAT-0.1 §5 architecture id. Only these two have an id.
ELF_MACHINE_ARCH = {0x3E: "x86_64", 0xB7: "aarch64"}
ELF_MACHINE_NAMES = {
    0x03: "i386", 0x08: "mips", 0x15: "ppc64", 0x16: "s390",
    0x28: "arm", 0x3E: "x86-64", 0xB7: "aarch64", 0xF3: "riscv",
}
ELF_TYPE_NAMES = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}
ELF_RUNNABLE_TYPES = (2, 3)  # ET_EXEC, ET_DYN (FORMAT-0.1 §6.7)

# PE COFF machine -> §5 architecture id.
PE_MACHINE_ARCH = {0x8664: "x86_64", 0xAA64: "aarch64"}
PE_MACHINE_NAMES = {
    0x0000: "unknown", 0x014C: "i386", 0x01C4: "armnt", 0x0200: "ia64",
    0x8664: "x86-64", 0xAA64: "arm64",
}
PE_SUBSYSTEM_NAMES = {1: "native", 2: "gui", 3: "console"}
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_DLL = 0x2000


class Unreadable(Exception):
    """The file is not a package we can inspect at all -> exit 2."""


# Everything that can go wrong inflating one hostile entry. RuntimeError is in
# the list because that is what zipfile raises for an encrypted member, and a
# crash on hostile input would be a worse bug than the one being looked for.
READ_ERRORS = (
    KeyError, Unreadable, zipfile.BadZipFile, zipfile.LargeZipFile,
    OSError, RuntimeError, NotImplementedError, ValueError, EOFError,
)


# ==========================================================================
# Findings
# ==========================================================================
class Report:
    def __init__(self, package):
        self.package = package
        self.violations = []
        self.skipped = []

    def add(self, code, where, expected, observed, spec, severity="error"):
        self.violations.append(
            {
                "code": code,
                "severity": severity,
                "where": where,
                "expected": expected,
                "observed": observed,
                "spec": spec,
            }
        )

    def warn(self, code, where, expected, observed, spec):
        self.add(code, where, expected, observed, spec, severity="warning")

    def skip(self, check, reason, spec):
        self.skipped.append({"check": check, "reason": reason, "spec": spec})

    @property
    def conformant(self):
        return not any(v["severity"] == "error" for v in self.violations)

    def to_json(self):
        return {
            "package": self.package,
            "conformant": self.conformant,
            "violations": self.violations,
            "skipped": self.skipped,
        }


# ==========================================================================
# Container: an independent central-directory reader
#
# The ZIP central directory is parsed here by hand rather than taken from
# zipfile.namelist(), because several §2 rules are about bytes zipfile has
# already normalised away: it decodes entry names (hiding an embedded NUL and
# non-UTF-8 bytes), and it exposes neither the raw name nor the flag bits we
# need. zipfile is used ONLY to inflate entry data.
# ==========================================================================
EOCD_SIG = b"PK\x05\x06"
CD_SIG = b"PK\x01\x02"


class RawEntry:
    __slots__ = (
        "index", "name_bytes", "name", "name_decodable", "flags",
        "method", "comp_size", "uncomp_size", "external_attr", "is_directory",
    )


class Container:
    """Raw view of the archive: the whole file plus a hand-parsed central dir."""

    def __init__(self, path):
        self.path = path
        try:
            self.size = path.stat().st_size
        except OSError as exc:
            raise Unreadable("cannot stat %s: %s" % (path, exc)) from exc
        if not path.is_file():
            raise Unreadable("not a regular file: %s" % path)
        # Bound before slurping (HARDENING §F): a hostile multi-GiB file is
        # never read into memory. The caller reports it as a violation.
        self.oversized = self.size > MAX_PACKAGE_BYTES

        self.eocd_at_tail = False
        self.archive_comment_len = None
        self.cd_ends_at_eocd = None
        self.zip64 = False
        self.entries = []
        self.eocd_off = None
        self.cd_off = None
        self.cd_size = None

        if not self.oversized:
            try:
                self.blob = path.read_bytes()
            except OSError as exc:
                raise Unreadable("cannot read %s: %s" % (path, exc)) from exc
            self._parse_eocd()
            self._parse_central_directory()
        else:
            self.blob = b""

        try:
            self.zf = zipfile.ZipFile(str(path))
        except Exception as exc:  # noqa: BLE001 -- any failure means unreadable
            raise Unreadable("not a readable ZIP archive: %s" % exc) from exc
        self._infolist = self.zf.infolist()

    # -- §1: the archive must span the whole file ---------------------------
    def _parse_eocd(self):
        b = self.blob
        if len(b) < 22:
            raise Unreadable(
                "file is shorter than a ZIP end-of-central-directory record")
        tail = len(b) - 22
        if b[tail:tail + 4] == EOCD_SIG:
            self.eocd_at_tail = True
            eocd = tail
        else:
            # Search backwards for the EOCD so the report can still say *why*
            # the archive does not span the file (comment or trailing data).
            eocd = b.rfind(EOCD_SIG, 0, len(b) - 3)
            if eocd < 0:
                raise Unreadable("no ZIP end-of-central-directory record found")
        (self.archive_comment_len,) = struct.unpack_from("<H", b, eocd + 20)
        cd_size, cd_offset = struct.unpack_from("<II", b, eocd + 12)
        if cd_offset == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
            self.zip64 = True
            self.cd_ends_at_eocd = None
        else:
            self.cd_ends_at_eocd = (cd_offset + cd_size == eocd)
        self.eocd_off = eocd
        self.cd_size = cd_size
        self.cd_declared_off = cd_offset
        # The declared central-directory offset is relative to the start of the
        # ZIP archive, which is not the start of the FILE when something has
        # been prepended. Recover the real offset so the rest of the §2 checks
        # still run; cd_ends_at_eocd above has already recorded the violation.
        if b[cd_offset:cd_offset + 4] == CD_SIG:
            self.cd_off = cd_offset
        elif cd_size and b[eocd - cd_size:eocd - cd_size + 4] == CD_SIG:
            self.cd_off = eocd - cd_size
        else:
            self.cd_off = cd_offset

    def _parse_central_directory(self):
        if self.zip64:
            return
        b = self.blob
        off = self.cd_off
        end = min(len(b), self.cd_off + self.cd_size)
        index = 0
        while off + 46 <= end and b[off:off + 4] == CD_SIG:
            flags, method = struct.unpack_from("<HH", b, off + 8)
            comp_size, uncomp_size = struct.unpack_from("<II", b, off + 20)
            name_len, extra_len, comment_len = struct.unpack_from("<HHH", b, off + 28)
            (external_attr,) = struct.unpack_from("<I", b, off + 38)
            name_bytes = bytes(b[off + 46: off + 46 + name_len])
            e = RawEntry()
            e.index = index
            e.name_bytes = name_bytes
            e.flags = flags
            e.method = method
            e.comp_size = comp_size
            e.uncomp_size = uncomp_size
            e.external_attr = external_attr
            try:
                e.name = name_bytes.decode("utf-8")
                e.name_decodable = True
            except UnicodeDecodeError:
                e.name = name_bytes.decode("utf-8", "replace")
                e.name_decodable = False
            e.is_directory = name_bytes.endswith(b"/")
            self.entries.append(e)
            off += 46 + name_len + extra_len + comment_len
            index += 1
        if not self.entries and self.cd_size:
            raise Unreadable("central directory could not be parsed")

    # -- data access -------------------------------------------------------
    def read(self, entry):
        """Inflate one entry, bounded by the per-entry cap."""
        info = self._info_for(entry)
        if info is None:
            raise KeyError(entry.name)
        limit = MAX_ENTRY_UNCOMPRESSED_BYTES
        with self.zf.open(info) as fh:
            data = fh.read(limit + 1)
        if len(data) > limit:
            raise Unreadable(
                "entry %r inflates beyond the per-entry cap" % entry.name)
        return data

    def sha256(self, entry):
        """Stream-hash one entry without ever holding it all in memory."""
        info = self._info_for(entry)
        if info is None:
            raise KeyError(entry.name)
        h = hashlib.sha256()
        total = 0
        with self.zf.open(info) as fh:
            while True:
                chunk = fh.read(1 << 16)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ENTRY_UNCOMPRESSED_BYTES:
                    raise Unreadable(
                        "entry %r exceeds the per-entry cap" % entry.name)
                h.update(chunk)
        return h.hexdigest(), total

    def _info_for(self, entry):
        # infolist() walks the same central directory in the same order, so
        # positional identity is exact even when two entries share a name.
        if entry.index < len(self._infolist):
            return self._infolist[entry.index]
        for info in self._infolist:
            if info.filename == entry.name:
                return info
        return None


# ==========================================================================
# §2 path safety, derived from the prose rather than ported
# ==========================================================================
def files_by_name(container):
    """First central-directory record wins.

    With a duplicate path there is no single answer, so the reader picks ONE
    authoritative view and sticks to it everywhere (HARDENING §B.5). The
    duplicate itself is already reported as CONTAINER_DUPLICATE_PATH.
    """
    out = {}
    for e in container.entries:
        if not e.is_directory:
            out.setdefault(e.name, e)
    return out


def path_problems(name_bytes):
    """Return (code, expected, observed) for every §2 path rule broken.

    Written from FORMAT-0.1 §2's list of reader MUST-rejects plus the
    HARDENING §B.10/§F size caps. The analysis is textual on the RAW name
    bytes: nothing is normalised first, because normalisation is exactly how
    a traversal gets past a validator.
    """
    out = []
    shown = name_bytes.decode("utf-8", "backslashreplace")

    if not name_bytes:
        out.append(("CONTAINER_PATH_EMPTY_SEGMENT",
                    "a non-empty entry path", "an empty name"))
        return out
    if len(name_bytes) > MAX_PATH_BYTES:
        out.append(("CONTAINER_PATH_TOO_LONG",
                    "entry path at most %d bytes" % MAX_PATH_BYTES,
                    "%d bytes" % len(name_bytes)))
    if not _utf8_ok(name_bytes):
        out.append(("CONTAINER_PATH_NOT_UTF8",
                    "entry paths are UTF-8 (§1)",
                    "undecodable bytes in %r" % shown))
    if 0 in name_bytes:
        out.append(("CONTAINER_PATH_NUL",
                    "no NUL byte in an entry path",
                    "NUL byte at offset %d of %r" % (name_bytes.index(0), shown)))
    if b"\\" in name_bytes:
        out.append(("CONTAINER_PATH_BACKSLASH",
                    "forward slashes only as the path separator",
                    "backslash in %r" % shown))
    if name_bytes.startswith(b"/"):
        out.append(("CONTAINER_PATH_ABSOLUTE",
                    "a relative entry path",
                    "absolute path %r" % shown))

    stem = name_bytes[:-1] if name_bytes.endswith(b"/") else name_bytes
    if not stem:
        out.append(("CONTAINER_PATH_EMPTY_SEGMENT",
                    "a non-empty entry path", repr(shown)))
        return out
    segments = stem.split(b"/")
    if len(segments) > MAX_PATH_DEPTH:
        out.append(("CONTAINER_DEPTH_EXCEEDED",
                    "at most %d path components" % MAX_PATH_DEPTH,
                    "%d components in %r" % (len(segments), shown)))
    for seg in segments:
        if not seg:
            out.append(("CONTAINER_PATH_EMPTY_SEGMENT",
                        "no empty path segment (no '//')",
                        "empty segment in %r" % shown))
        elif seg == b"..":
            out.append(("CONTAINER_PATH_TRAVERSAL",
                        "no '..' path segment",
                        "'..' segment in %r" % shown))
        elif seg == b".":
            out.append(("CONTAINER_PATH_DOT_SEGMENT",
                        "no '.' path segment",
                        "'.' segment in %r" % shown))
        if len(seg) > MAX_PATH_COMPONENT_BYTES:
            out.append(("CONTAINER_COMPONENT_TOO_LONG",
                        "each path component at most %d bytes"
                        % MAX_PATH_COMPONENT_BYTES,
                        "component of %d bytes in %r" % (len(seg), shown)))
        if len(seg) >= 2 and seg[1:2] == b":" and _ascii_alpha(seg[0]):
            out.append(("CONTAINER_PATH_DRIVE_LETTER",
                        "no Windows drive designator ('X:')",
                        "drive designator in segment %r"
                        % seg.decode("utf-8", "backslashreplace")))

    first = segments[0].decode("utf-8", "backslashreplace")
    if first not in ALLOWED_TOP_LEVEL:
        out.append(("CONTAINER_TOPLEVEL_NOT_ALLOWED",
                    "first path segment in " + ", ".join(sorted(ALLOWED_TOP_LEVEL)),
                    "first segment %r" % first))
    elif first == "lexe.json" and (len(segments) > 1 or name_bytes.endswith(b"/")):
        out.append(("CONTAINER_LEXE_JSON_NOT_FILE",
                    "'lexe.json' is a top-level FILE",
                    "%r uses 'lexe.json' as a directory or path prefix" % shown))
    return out


def _utf8_ok(raw):
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _ascii_alpha(byte):
    return 65 <= byte <= 90 or 97 <= byte <= 122


def check_container(c, rep):
    if c.oversized:
        rep.add("CONTAINER_PACKAGE_TOO_LARGE", str(c.path),
                "package at most %d bytes" % MAX_PACKAGE_BYTES,
                "%d bytes" % c.size, "§1")
        return

    if not c.eocd_at_tail or c.cd_ends_at_eocd is False:
        if not c.eocd_at_tail:
            observed = ("the end-of-central-directory record is not the final 22 "
                        "bytes of the file (trailing data or an archive comment)")
        else:
            observed = ("the central directory ends at offset %d but the EOCD "
                        "begins at offset %d (prepended data or a gap)"
                        % (c.cd_off + c.cd_size, c.eocd_off))
        rep.add("CONTAINER_NOT_SPANNING_FILE", "archive framing",
                "the ZIP archive occupies exactly the whole file: the EOCD is "
                "the final 22 bytes and the central directory ends where the "
                "EOCD begins",
                observed, "§1")
    if c.archive_comment_len:
        rep.add("CONTAINER_ARCHIVE_COMMENT", "ZIP end-of-central-directory",
                "no archive comment (comment length 0)",
                "comment length %d" % c.archive_comment_len, "§1")
    if c.zip64:
        rep.skip("zip64",
                 "the archive uses ZIP64 central-directory sentinels; this "
                 "validator parses only the 32-bit EOCD, so the whole-file-span "
                 "check and the raw central-directory checks were not performed",
                 "§1")

    if len(c.entries) > MAX_ENTRY_COUNT:
        rep.add("CONTAINER_ENTRY_COUNT_EXCEEDED", "central directory",
                "at most %d entries" % MAX_ENTRY_COUNT,
                "%d entries" % len(c.entries), "§1")

    seen = {}
    seen_fold = {}
    total_declared = 0
    for e in c.entries:
        for code, expected, observed in path_problems(e.name_bytes):
            rep.add(code, e.name, expected, observed, "§2")

        if e.name_bytes in seen:
            rep.add("CONTAINER_DUPLICATE_PATH", e.name,
                    "each entry path appears exactly once",
                    "path appears at central-directory indexes %d and %d"
                    % (seen[e.name_bytes], e.index), "§2")
        else:
            seen[e.name_bytes] = e.index

        fold = bytes(ch + 32 if 65 <= ch <= 90 else ch for ch in e.name_bytes)
        if fold in seen_fold and seen_fold[fold] != e.name_bytes:
            rep.add("CONTAINER_CASE_COLLISION", e.name,
                    "no two entry paths that differ only in ASCII case (they "
                    "alias on a case-insensitive filesystem)",
                    "%r collides with %r"
                    % (e.name, seen_fold[fold].decode("utf-8", "backslashreplace")),
                    "§2")
        else:
            seen_fold.setdefault(fold, e.name_bytes)

        # General-purpose bit 0 = encrypted.
        if e.flags & 0x0001:
            rep.add("CONTAINER_ENCRYPTED_ENTRY", e.name,
                    "no encryption (§1)",
                    "general-purpose flag bit 0 (encrypted) is set", "§1")
        # Unix S_IFLNK in the external-attributes high word.
        if (e.external_attr >> 16) & 0xF000 == 0xA000:
            rep.add("CONTAINER_SYMLINK_ENTRY", e.name,
                    "no symbolic-link entries",
                    "external attributes carry Unix mode S_IFLNK", "§2")
        if e.uncomp_size > MAX_ENTRY_UNCOMPRESSED_BYTES:
            rep.add("CONTAINER_ENTRY_TOO_LARGE", e.name,
                    "each entry at most %d uncompressed bytes"
                    % MAX_ENTRY_UNCOMPRESSED_BYTES,
                    "declares %d uncompressed bytes" % e.uncomp_size, "§1")
        if e.is_directory:
            # Upgraded from a warning to a violation when FORMAT-0.1 §2.1 made
            # the rule normative. It had been a warning precisely because the
            # spec did not state it while HARDENING.md §B.11 did, and the
            # reference reader did neither -- it silently SKIPPED them. That was
            # settled the hard way: a directory record can carry data bytes, and
            # because a skipped entry is an entry no later rule applies to, one
            # named `signatures/evil/` bypassed the exact allowlist written to
            # stop exactly that. Both implementations now reject.
            rep.add("CONTAINER_DIRECTORY_ENTRY", e.name,
                    "no ZIP directory entries (paths ending in '/')",
                    "a directory entry is present", "§2.1")
        total_declared += e.uncomp_size

    if total_declared > MAX_TOTAL_UNCOMPRESSED_BYTES:
        rep.add("CONTAINER_TOTAL_UNCOMPRESSED_EXCEEDED", "whole archive",
                "at most %d total uncompressed bytes"
                % MAX_TOTAL_UNCOMPRESSED_BYTES,
                "%d total uncompressed bytes" % total_declared, "§1")
    if (total_declared > RATIO_GRACE_BYTES and c.size
            and total_declared > c.size * MAX_EXPANSION_RATIO):
        rep.add("CONTAINER_EXPANSION_RATIO", "whole archive",
                "expansion ratio at most %dx once past the %d-byte grace "
                "threshold" % (MAX_EXPANSION_RATIO, RATIO_GRACE_BYTES),
                "%d uncompressed bytes from a %d-byte package (%.1fx)"
                % (total_declared, c.size, total_declared / c.size), "§1")

    present = set(e.name_bytes for e in c.entries if not e.is_directory)
    for required in REQUIRED_ENTRIES:
        if required.encode() not in present:
            rep.add("CONTAINER_MISSING_REQUIRED_ENTRY", required,
                    "the archive contains %s as a file" % required,
                    "entry absent", "§2")


# ==========================================================================
# Strict JSON: duplicate keys at any depth, no trailing data
# ==========================================================================
def strict_json(text):
    """Parse `text`, collecting every duplicated object key at any depth.

    Raises ValueError on a syntax error or on trailing data after the value.
    """
    duplicates = []

    def hook(pairs):
        seen = set()
        for key, _ in pairs:
            if key in seen:
                duplicates.append(key)
            seen.add(key)
        return dict(pairs)

    decoder = json.JSONDecoder(object_pairs_hook=hook)
    value, end = decoder.raw_decode(text)
    if text[end:].strip():
        raise ValueError("trailing data after the JSON value at offset %d" % end)
    return value, duplicates


_JSON_CODES = {
    "lexe.json": {
        "too_large": "MANIFEST_TOO_LARGE", "bom": "MANIFEST_BOM",
        "not_utf8": "MANIFEST_NOT_UTF8", "parse": "MANIFEST_PARSE",
        "trailing": "MANIFEST_TRAILING_DATA", "dup": "MANIFEST_DUPLICATE_KEY",
    },
    "metadata/hashes.json": {
        "too_large": "HASH_JSON_TOO_LARGE", "bom": "HASH_JSON_BOM",
        "not_utf8": "HASH_JSON_NOT_UTF8", "parse": "HASH_JSON_PARSE",
        "trailing": "HASH_JSON_TRAILING_DATA", "dup": "HASH_DUPLICATE_KEY",
    },
}


def decode_json_document(raw, where, spec, max_bytes, rep):
    codes = _JSON_CODES[where]
    if len(raw) > max_bytes:
        rep.add(codes["too_large"], where, "at most %d bytes" % max_bytes,
                "%d bytes" % len(raw), spec)
        return None
    if raw.startswith(b"\xef\xbb\xbf"):
        rep.add(codes["bom"], where, "UTF-8 with no byte-order mark",
                "a UTF-8 BOM precedes the JSON", spec)
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        rep.add(codes["not_utf8"], where, "valid UTF-8",
                "invalid UTF-8: %s" % exc, spec)
        return None
    try:
        value, duplicates = strict_json(text)
    except ValueError as exc:
        msg = str(exc)
        code = codes["trailing"] if msg.startswith("trailing data") else codes["parse"]
        rep.add(code, where,
                "exactly one well-formed JSON value and nothing after it",
                msg, spec)
        return None
    for key in duplicates:
        rep.add(codes["dup"], "%s: key %r" % (where, key),
                "no object key repeated at any depth (last-wins would let a "
                "reader and a reviewer read different values)",
                "key %r appears more than once in the same object" % key, spec)
    return value


# ==========================================================================
# §3 hashes
# ==========================================================================
def coverage_excluded(path, is_directory):
    """Is `path` excluded from hashes.json coverage?

    §3 names three exclusions: lexe.json, metadata/hashes.json, signatures/*.
    ZIP *directory* entries are a fourth exclusion the spec does not state
    (README spec gap G2): they carry no bytes, and any writer that emitted
    them would otherwise make coverage unsatisfiable.
    """
    return (
        is_directory
        or path == "lexe.json"
        or path == "metadata/hashes.json"
        or path.startswith("signatures/")
    )


def check_hashes(c, rep, hashes_raw):
    if hashes_raw is None:
        return
    doc = decode_json_document(hashes_raw, "metadata/hashes.json", "§3",
                               MAX_HASHES_BYTES, rep)
    if doc is None:
        return
    if not isinstance(doc, dict):
        rep.add("HASH_JSON_NOT_OBJECT", "metadata/hashes.json",
                "a JSON object", type(doc).__name__, "§3")
        return
    algorithm = doc.get("algorithm")
    if algorithm != "sha256":
        rep.add("HASH_ALGORITHM", "metadata/hashes.json: algorithm",
                'the string "sha256"', json.dumps(algorithm), "§3")
    files = doc.get("files")
    if not isinstance(files, dict):
        rep.add("HASH_FILES_NOT_OBJECT", "metadata/hashes.json: files",
                "a JSON object mapping entry path -> lowercase hex SHA-256",
                json.dumps(files) if not isinstance(files, dict) else "an object",
                "§3")
        return

    by_path = {}
    should_cover = set()
    for e in c.entries:
        by_path.setdefault(e.name, e)
        if not coverage_excluded(e.name, e.is_directory):
            should_cover.add(e.name)

    covered = set()
    for key, digest in files.items():
        if not isinstance(digest, str):
            rep.add("HASH_DIGEST_NOT_STRING",
                    "metadata/hashes.json: files[%r]" % key,
                    "a string digest", type(digest).__name__, "§3")
            continue
        covered.add(key)
        if not HEX64.match(digest):
            rep.add("HASH_DIGEST_MALFORMED",
                    "metadata/hashes.json: files[%r]" % key,
                    "64 lowercase hexadecimal characters",
                    "%r (%d characters)" % (digest, len(digest)), "§3")

    # Set equality, direction 1: nothing covered that should not be.
    for key in sorted(covered - should_cover):
        if key in by_path:
            rep.add("HASH_COVERAGE_EXCLUDED", key,
                    "files{} covers only entries outside the §3 exclusions "
                    "(lexe.json, metadata/hashes.json, signatures/*, and ZIP "
                    "directory entries)",
                    "an excluded entry is covered", "§3")
        else:
            rep.add("HASH_COVERAGE_ORPHAN", key,
                    "every key of files{} names an entry present in the archive",
                    "no such entry in the archive", "§3")
    # Set equality, direction 2: everything coverable is covered.
    for key in sorted(should_cover - covered):
        rep.add("HASH_COVERAGE_MISSING", key,
                "every archive entry outside the §3 exclusions has a key in "
                "files{}",
                "entry is not covered by metadata/hashes.json", "§3")

    # Digests, recomputed from the archive bytes.
    for key in sorted(should_cover & covered):
        digest = files[key]
        try:
            actual, size = c.sha256(by_path[key])
        except READ_ERRORS as exc:
            rep.add("HASH_ENTRY_UNREADABLE", key,
                    "the covered entry can be decompressed and hashed",
                    str(exc), "§3")
            continue
        if actual != digest:
            rep.add("HASH_MISMATCH", key, "SHA-256 %s" % digest,
                    "SHA-256 %s over %d bytes" % (actual, size), "§3")


# ==========================================================================
# §5 manifest
# ==========================================================================
class ManifestFacts:
    def __init__(self):
        self.role = "application"
        self.application_type = None
        self.architectures = []
        self.entrypoint = None
        self.source_dir = None
        self.public_key_field = None
        self.launch_mode = "gui"


def _get(obj, key):
    """Member lookup treating JSON null as absent."""
    if not isinstance(obj, dict):
        return None
    value = obj.get(key)
    return None if value is None else value


def require_string(obj, key, where, rep, spec="§5", max_len=None):
    value = _get(obj, key)
    if value is None:
        rep.add("MANIFEST_FIELD_MISSING", where, "%s is present" % where,
                "field absent or null", spec)
        return None
    if not isinstance(value, str):
        rep.add("MANIFEST_FIELD_TYPE", where, "%s is a string" % where,
                "a JSON %s" % type(value).__name__, spec)
        return None
    if not value:
        rep.add("MANIFEST_FIELD_EMPTY", where,
                "%s is a non-empty string" % where, "an empty string", spec)
        return None
    if max_len is not None and len(value.encode()) > max_len:
        rep.add("MANIFEST_FIELD_TOO_LONG", where,
                "%s is at most %d bytes" % (where, max_len),
                "%d bytes" % len(value.encode()), spec)
    return value


def relative_payload_path_problems(path, field):
    """§5.3/§5.8: a manifest field naming something inside payload/."""
    out = []
    if "\x00" in path:
        out.append(("%s contains no NUL byte" % field, "a NUL byte is present"))
    if "\\" in path:
        out.append(("%s contains no backslash" % field, repr(path)))
    if path.startswith("/"):
        out.append(("%s is relative (no leading '/')" % field, repr(path)))
    if len(path) >= 2 and path[1] == ":" and path[0].isascii() and path[0].isalpha():
        out.append(("%s has no Windows drive designator" % field, repr(path)))
    for seg in path.split("/"):
        if seg == "":
            out.append(("%s has no empty path segment" % field, repr(path)))
        elif seg == "..":
            out.append(("%s has no '..' segment" % field, repr(path)))
        elif seg == ".":
            out.append(("%s has no '.' segment" % field, repr(path)))
    return out


def version_shape_problem(version):
    r"""1-64 chars, no whitespace/control/'/'/'\'/':' and not '.' or '..'.

    FORMAT-0.1 §5.2 says only "non-empty string"; this shape rule lives in
    src/lexe/base/identity.cpp (README spec gap G3).
    """
    if not 1 <= len(version) <= MAX_VERSION_CHARS:
        return "%d characters" % len(version)
    if version in (".", ".."):
        return "%r is not usable as a path component" % version
    for ch in version:
        if ord(ch) <= 0x20 or ord(ch) == 0x7F:
            return "whitespace or control character U+%04X" % ord(ch)
        if ch in "/\\:":
            return "path separator or drive designator %r" % ch
    return None


def _id_shape_ok(value):
    if not isinstance(value, str):
        return False
    segments = value.split(".")
    return len(segments) >= 2 and all(ID_SEGMENT.match(s) for s in segments)


def check_manifest(c, rep, manifest_raw):
    facts = ManifestFacts()
    if manifest_raw is None:
        return None
    doc = decode_json_document(manifest_raw, "lexe.json", "§5",
                               MAX_MANIFEST_BYTES, rep)
    if doc is None:
        return None
    if not isinstance(doc, dict):
        rep.add("MANIFEST_NOT_OBJECT", "lexe.json",
                "a JSON object at the top level", type(doc).__name__, "§5")
        return None

    # --- §5.2 fields required for every role ---
    lexe_version = require_string(doc, "lexeVersion", "lexeVersion", rep, "§5.2")
    if lexe_version is not None and lexe_version != "0.1":
        rep.add("MANIFEST_LEXEVERSION", "lexeVersion", 'the string "0.1"',
                json.dumps(lexe_version), "§5.2")

    app_id = require_string(doc, "id", "id", rep, "§5.2", max_len=MAX_ID_BYTES)
    if app_id is not None and not _id_shape_ok(app_id):
        rep.add("MANIFEST_ID_SHAPE", "id",
                "reverse-DNS: 2+ dot-separated segments of [a-zA-Z0-9-]+",
                json.dumps(app_id), "§5.2")

    require_string(doc, "name", "name", rep, "§5.2")

    version = require_string(doc, "version", "version", rep, "§5.2")
    if version is not None:
        problem = version_shape_problem(version)
        if problem:
            rep.add("MANIFEST_VERSION_SHAPE", "version",
                    "1-64 characters with no whitespace, control character, "
                    "'/', '\\' or ':', and not '.' or '..'", problem, "§5.2")

    publisher = _get(doc, "publisher")
    if publisher is None:
        rep.add("MANIFEST_FIELD_MISSING", "publisher", "publisher is present",
                "field absent", "§5.2")
    elif not isinstance(publisher, dict):
        rep.add("MANIFEST_FIELD_TYPE", "publisher",
                "publisher is a JSON object", type(publisher).__name__, "§5.2")
    else:
        require_string(publisher, "name", "publisher.name", rep, "§5.2")
        facts.public_key_field = require_string(
            publisher, "publicKey", "publisher.publicKey", rep, "§4")

    # --- §5.1 role ---
    role = doc.get("role", "application")
    if role is None:
        role = "application"
    if not isinstance(role, str) or role not in ROLES:
        rep.add("MANIFEST_ENUM_INVALID", "role",
                "one of " + ", ".join(json.dumps(r) for r in ROLES),
                json.dumps(role), "§5.1")
        return facts
    facts.role = role

    # --- §5.6 launch ---
    launch = _get(doc, "launch")
    if launch is not None and not isinstance(launch, dict):
        rep.add("MANIFEST_FIELD_TYPE", "launch", "launch is a JSON object",
                type(launch).__name__, "§5.6")
        launch = None
    if isinstance(launch, dict):
        mode = launch.get("mode", "gui")
        if mode is None:
            mode = "gui"
        if mode not in LAUNCH_MODES:
            rep.add("MANIFEST_ENUM_INVALID", "launch.mode",
                    "one of " + ", ".join(json.dumps(m) for m in LAUNCH_MODES),
                    json.dumps(mode), "§5.6")
        else:
            facts.launch_mode = mode
        single = launch.get("singleInstance")
        if single is not None and not isinstance(single, bool):
            rep.add("MANIFEST_FIELD_TYPE", "launch.singleInstance",
                    "a boolean", type(single).__name__, "§5.6")

    launch_app_id = _get(launch, "applicationId") if isinstance(launch, dict) else None

    if role == "launch":
        # §5.4 required, §5.3 forbidden.
        if launch_app_id is None:
            rep.add("MANIFEST_LAUNCH_APPID_REQUIRED", "launch.applicationId",
                    'role "launch" declares launch.applicationId',
                    "field absent", "§5.4")
        elif not _id_shape_ok(launch_app_id):
            rep.add("MANIFEST_ID_SHAPE", "launch.applicationId",
                    "reverse-DNS, same shape as id",
                    json.dumps(launch_app_id), "§5.4")
        for forbidden in ("applicationType", "architectures", "entrypoint",
                          "install", "build"):
            if _get(doc, forbidden) is not None:
                rep.add("MANIFEST_FIELD_FORBIDDEN", forbidden,
                        'role "launch" does not declare %s' % forbidden,
                        "field present", "§5.3")
        return facts

    # --- role "application" (§5.3) ---
    if launch_app_id is not None:
        rep.add("MANIFEST_LAUNCH_APPID_FORBIDDEN", "launch.applicationId",
                'launch.applicationId is absent for role "application"',
                json.dumps(launch_app_id), "§5.4")

    app_type = require_string(doc, "applicationType", "applicationType", rep, "§5.3")
    if app_type is not None:
        if app_type not in APPLICATION_TYPES:
            rep.add("MANIFEST_ENUM_INVALID", "applicationType",
                    "one of " + ", ".join(json.dumps(t) for t in APPLICATION_TYPES),
                    json.dumps(app_type), "§5.3")
        else:
            facts.application_type = app_type

    archs = _get(doc, "architectures")
    if archs is None:
        rep.add("MANIFEST_FIELD_MISSING", "architectures",
                'role "application" declares architectures', "field absent", "§5.3")
    elif not isinstance(archs, list) or not archs:
        rep.add("MANIFEST_FIELD_TYPE", "architectures",
                "a non-empty array of strings",
                "an empty array" if isinstance(archs, list) else json.dumps(archs),
                "§5.3")
    else:
        for item in archs:
            if not isinstance(item, str):
                rep.add("MANIFEST_FIELD_TYPE", "architectures[]",
                        "string elements", type(item).__name__, "§5.3")
            elif item not in ARCHITECTURES:
                rep.add("MANIFEST_ENUM_INVALID", "architectures[]",
                        "one of " + ", ".join(json.dumps(a) for a in ARCHITECTURES),
                        json.dumps(item), "§5.3")
            else:
                facts.architectures.append(item)

    entrypoint = _get(doc, "entrypoint")
    if entrypoint is None:
        rep.add("MANIFEST_FIELD_MISSING", "entrypoint",
                'role "application" declares entrypoint', "field absent", "§5.3")
    elif not isinstance(entrypoint, dict):
        rep.add("MANIFEST_FIELD_TYPE", "entrypoint", "a JSON object",
                type(entrypoint).__name__, "§5.3")
    else:
        exe = require_string(entrypoint, "executable", "entrypoint.executable",
                             rep, "§5.3")
        if exe is not None:
            problems = relative_payload_path_problems(exe, "entrypoint.executable")
            for expected, observed in problems:
                rep.add("MANIFEST_PATH_INVALID", "entrypoint.executable",
                        expected, observed, "§5.3")
            if not problems:
                facts.entrypoint = exe
        args = entrypoint.get("arguments")
        if args is not None and (not isinstance(args, list)
                                 or any(not isinstance(a, str) for a in args)):
            rep.add("MANIFEST_FIELD_TYPE", "entrypoint.arguments",
                    "an array of strings", json.dumps(args), "§5.7")

    install = _get(doc, "install")
    if install is None:
        rep.add("MANIFEST_FIELD_MISSING", "install",
                'role "application" declares install', "field absent", "§5.3")
    elif not isinstance(install, dict):
        rep.add("MANIFEST_FIELD_TYPE", "install", "a JSON object",
                type(install).__name__, "§5.3")
    else:
        mode = require_string(install, "mode", "install.mode", rep, "§5.3")
        if mode is not None and mode not in INSTALL_MODES:
            rep.add("MANIFEST_ENUM_INVALID", "install.mode",
                    'the string "bundled" (0.1 supports no other mode)',
                    json.dumps(mode), "§5.3")

    # --- §5.8 build: required iff portable ---
    build = _get(doc, "build")
    if facts.application_type == "portable":
        if build is None:
            rep.add("MANIFEST_BUILD_REQUIRED", "build",
                    'applicationType "portable" declares a build recipe',
                    "build absent", "§5.8")
        elif not isinstance(build, dict):
            rep.add("MANIFEST_FIELD_TYPE", "build", "a JSON object",
                    type(build).__name__, "§5.8")
        else:
            system = require_string(build, "system", "build.system", rep, "§5.8")
            if system is not None and system not in BUILD_SYSTEMS:
                rep.add("MANIFEST_ENUM_INVALID", "build.system",
                        "one of " + ", ".join(json.dumps(s) for s in BUILD_SYSTEMS),
                        json.dumps(system), "§5.8")
            source_dir = require_string(build, "sourceDir", "build.sourceDir",
                                        rep, "§5.8")
            if source_dir is not None:
                problems = relative_payload_path_problems(source_dir, "build.sourceDir")
                for expected, observed in problems:
                    rep.add("MANIFEST_PATH_INVALID", "build.sourceDir",
                            expected, observed, "§5.8")
                if not problems:
                    facts.source_dir = source_dir
            command = build.get("command")
            if system == "command":
                if (not isinstance(command, list) or not command
                        or any(not isinstance(a, str) or not a for a in command)):
                    rep.add("MANIFEST_BUILD_COMMAND_REQUIRED", "build.command",
                            'build.system "command" declares a non-empty argv '
                            "of non-empty strings", json.dumps(command), "§5.8")
            elif command is not None:
                rep.add("MANIFEST_BUILD_COMMAND_FORBIDDEN", "build.command",
                        'build.command only with build.system "command"',
                        "build.system %s with build.command %s"
                        % (json.dumps(system), json.dumps(command)), "§5.8")
            toolchain = build.get("toolchain")
            if (not isinstance(toolchain, list) or not toolchain
                    or any(not isinstance(t, str) or not t for t in toolchain)):
                rep.add("MANIFEST_FIELD_MISSING", "build.toolchain",
                        "a non-empty array of non-empty bare executable names",
                        json.dumps(toolchain), "§5.8")
            elif any("/" in t or "\\" in t for t in toolchain):
                rep.add("MANIFEST_FIELD_TYPE", "build.toolchain",
                        "bare executable names (no '/', never an absolute path)",
                        json.dumps(toolchain), "§5.8")
    elif build is not None and facts.application_type is not None:
        rep.add("MANIFEST_BUILD_FORBIDDEN", "build",
                'applicationType "%s" declares no build block (there is nothing '
                "to build)" % facts.application_type, "build present", "§5.8")

    # --- §5.5 execution policy ---
    execution = _get(doc, "execution")
    chains = ["native"]
    mission_critical = False
    if execution is not None and not isinstance(execution, dict):
        rep.add("MANIFEST_FIELD_TYPE", "execution", "a JSON object",
                type(execution).__name__, "§5.5")
    elif isinstance(execution, dict):
        mc = execution.get("missionCritical", False)
        if mc is None:
            mc = False
        if not isinstance(mc, bool):
            rep.add("MANIFEST_FIELD_TYPE", "execution.missionCritical",
                    "a boolean", type(mc).__name__, "§5.5")
        else:
            mission_critical = mc
        declared = execution.get("allowedChains")
        if declared is not None:
            if (not isinstance(declared, list) or not declared
                    or any(not isinstance(x, str) for x in declared)):
                rep.add("MANIFEST_FIELD_TYPE", "execution.allowedChains",
                        "a non-empty array of chain-id strings",
                        json.dumps(declared), "§5.5")
            else:
                chains = declared
                for chain in declared:
                    if not CHAIN_ID.match(chain):
                        rep.add("MANIFEST_CHAIN_ID_SHAPE",
                                "execution.allowedChains[]",
                                "a chain id matching [a-zA-Z0-9-+_]+",
                                json.dumps(chain), "§5.5")
    if mission_critical and any(ch != "native" for ch in chains):
        rep.add("MANIFEST_MISSION_CRITICAL_CONTRADICTION", "execution",
                'missionCritical true permits only the "native" chain',
                "allowedChains = %s" % json.dumps(chains), "§5.5")
    if facts.application_type == "windows":
        if mission_critical:
            rep.add("MANIFEST_MISSION_CRITICAL_CONTRADICTION",
                    "execution.missionCritical",
                    'applicationType "windows" is never missionCritical (a '
                    "Windows payload has no Linux-native, host-ISA-native "
                    "realization by construction)", "true", "§5.3")
        foreign = any(layer in ("wine", "proton")
                      for chain in chains for layer in chain.split("+"))
        if not foreign:
            rep.add("MANIFEST_WINDOWS_NO_FOREIGN_OS_CHAIN",
                    "execution.allowedChains",
                    'applicationType "windows" permits a foreign-OS chain (a '
                    "layer of wine or proton)",
                    "allowedChains = %s (the default is [\"native\"], and "
                    "silence is not consent)" % json.dumps(chains), "§5.3")

    # --- §5.3: the declared entrypoint must exist under payload/ ---
    names = set(e.name for e in c.entries if not e.is_directory)
    if facts.entrypoint is not None and facts.application_type in ("native", "windows"):
        target = "payload/" + facts.entrypoint
        if target not in names:
            rep.add("MANIFEST_ENTRYPOINT_NOT_IN_ARCHIVE", target,
                    'applicationType "%s" carries its entrypoint: the archive '
                    "contains %s" % (facts.application_type, target),
                    "no such entry in the archive", "§5.3")
    return facts


# ==========================================================================
# §2 / §6.7: payload/ presence is role-dependent
# ==========================================================================
def check_payload_presence(c, rep, facts):
    role = facts.role if facts else "application"
    payload = [e.name for e in c.entries
               if e.name.startswith("payload/") and len(e.name) > len("payload/")
               and not e.is_directory]
    if role == "launch":
        for name in payload:
            rep.add("PAYLOAD_LAUNCH_HAS_PAYLOAD", name,
                    'role "launch" carries no payload/ entries',
                    "a payload entry is present", "§6.7")
    elif not payload:
        rep.add("CONTAINER_PAYLOAD_MISSING", "payload/",
                'role "application" in bundled mode carries payload/ entries',
                "no payload/ entry in the archive", "§2")


# ==========================================================================
# §4 signatures
# ==========================================================================
def decode_publisher_key(field, rep):
    if field is None:
        return None
    prefix = "ed25519:"
    if not field.startswith(prefix):
        rep.add("SIGNATURE_KEY_PREFIX", "publisher.publicKey",
                'the prefix "ed25519:"', json.dumps(field[:32]), "§4")
        return None
    b64 = field[len(prefix):]
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        rep.add("SIGNATURE_KEY_BASE64", "publisher.publicKey",
                "standard RFC 4648 base64 with padding",
                "%r: %s" % (b64, exc), "§4")
        return None
    if len(raw) != ED25519_PUBLIC_KEY_BYTES:
        rep.add("SIGNATURE_KEY_LENGTH", "publisher.publicKey",
                "a decoded length of exactly %d bytes" % ED25519_PUBLIC_KEY_BYTES,
                "%d bytes" % len(raw), "§4")
        return None
    return raw


def load_ed25519_verifier():
    """Return (verify(pub, sig, msg) -> bool, backend name), or (None, None).

    The standard library cannot do Ed25519. Rather than pretend, this returns
    nothing at all unless a real implementation happens to be importable.
    """
    try:
        import cryptography
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        def verify(pub, sig, msg):
            try:
                Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
                return True
            except (InvalidSignature, ValueError):
                return False

        return verify, "cryptography %s" % cryptography.__version__
    except ImportError:
        pass
    try:
        import nacl
        import nacl.exceptions
        import nacl.signing

        def verify(pub, sig, msg):
            try:
                nacl.signing.VerifyKey(pub).verify(msg, sig)
                return True
            except (nacl.exceptions.BadSignatureError, ValueError):
                return False

        return verify, "PyNaCl %s" % nacl.__version__
    except ImportError:
        return None, None


def check_signatures(c, rep, facts, manifest_raw, hashes_raw):
    by_name = files_by_name(c)
    sigs = {}
    for name in ("signatures/manifest.sig", "signatures/payload.sig"):
        entry = by_name.get(name)
        if entry is None:
            sigs[name] = None
            continue
        try:
            data = c.read(entry)
        except READ_ERRORS as exc:
            rep.add("SIGNATURE_UNREADABLE", name,
                    "the signature entry can be decompressed", str(exc), "§4")
            sigs[name] = None
            continue
        sigs[name] = data
        if len(data) != ED25519_SIGNATURE_BYTES:
            rep.add("SIGNATURE_LENGTH", name,
                    "exactly %d raw bytes (a raw Ed25519 signature, not hex, "
                    "not base64)" % ED25519_SIGNATURE_BYTES,
                    "%d bytes" % len(data), "§4")

    key = decode_publisher_key(facts.public_key_field if facts else None, rep)
    verify, backend = load_ed25519_verifier()

    if verify is None:
        rep.skip("ed25519-signature-verification",
                 "Ed25519 (RFC 8032) cannot be implemented with the Python "
                 "standard library, and this validator will not fake a pass. "
                 "Install the `cryptography` or `pynacl` package to have the "
                 "signatures actually verified; until then stages 4 and 5 of "
                 "the §6 pipeline are NOT checked here. Signature LENGTHS and "
                 "the publisher key encoding were still checked.", "§4")
        return
    if key is None:
        rep.skip("ed25519-signature-verification",
                 "an Ed25519 backend is available (%s) but publisher.publicKey "
                 "did not decode to a 32-byte key, so there is nothing to "
                 "verify against" % backend, "§4")
        return

    checked = []
    for sig_name, covered, message in (
        ("signatures/manifest.sig", "lexe.json", manifest_raw),
        ("signatures/payload.sig", "metadata/hashes.json", hashes_raw),
    ):
        sig = sigs.get(sig_name)
        if sig is None or len(sig) != ED25519_SIGNATURE_BYTES or message is None:
            continue
        checked.append(sig_name)
        if not verify(key, sig, message):
            rep.add("SIGNATURE_INVALID", sig_name,
                    "a valid Ed25519 signature over the exact stored %s bytes "
                    "under publisher.publicKey (verified with %s)"
                    % (covered, backend),
                    "the signature does not verify over the %d stored bytes"
                    % len(message), "§4")
    if checked:
        rep.skip("ed25519-signature-verification-note",
                 "performed, not skipped: %s were verified with %s. Small-order "
                 "and non-canonical point handling is whatever that backend "
                 "does; this validator adds no checks of its own there."
                 % (", ".join(checked), backend), "§4")


# ==========================================================================
# §6.7 payload role: the bytes must BE what the manifest declares
# ==========================================================================
def parse_elf(data):
    """Minimal, bounds-checked ELF header read: class, endianness, type, machine."""
    if len(data) < 24 or data[:4] != b"\x7fELF":
        return None
    ei_class = data[4]
    ei_data = data[5]
    endian = "<" if ei_data != 2 else ">"
    e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
    return {
        "class": {1: 32, 2: 64}.get(ei_class),
        "endian": "little" if ei_data != 2 else "big",
        "type": e_type,
        "machine": e_machine,
    }


def parse_pe(data):
    """Minimal, bounds-checked PE read: machine, characteristics, subsystem."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew + 24 > len(data):
        return None
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    coff = e_lfanew + 4
    (machine,) = struct.unpack_from("<H", data, coff + 0)
    (optional_size,) = struct.unpack_from("<H", data, coff + 16)
    (characteristics,) = struct.unpack_from("<H", data, coff + 18)
    subsystem = None
    optional = coff + 20
    if optional_size and optional + 70 <= len(data):
        (magic,) = struct.unpack_from("<H", data, optional)
        if magic in (0x010B, 0x020B):
            (subsystem,) = struct.unpack_from("<H", data, optional + 68)
    return {
        "machine": machine,
        "characteristics": characteristics,
        "subsystem": subsystem,
        "executable_image": bool(characteristics & IMAGE_FILE_EXECUTABLE_IMAGE),
        "is_dll": bool(characteristics & IMAGE_FILE_DLL),
    }


def check_payload_role(c, rep, facts):
    if facts is None or facts.role != "application" or facts.application_type is None:
        return
    by_name = files_by_name(c)
    names = set(by_name)
    kind = facts.application_type

    if kind == "portable":
        if facts.source_dir is not None:
            prefix = "payload/%s/" % facts.source_dir
            if not any(n.startswith(prefix) for n in names):
                rep.add("PAYLOAD_PORTABLE_SOURCEDIR_MISSING", prefix,
                        'applicationType "portable" carries at least one entry '
                        "under %s (the source it is compiled from)" % prefix,
                        "no entry under that prefix", "§6.7")
        if facts.entrypoint is not None:
            produced = "payload/" + facts.entrypoint
            if produced in names:
                rep.add("PAYLOAD_PORTABLE_ENTRYPOINT_PRESENT", produced,
                        'applicationType "portable" does NOT ship the '
                        "entrypoint: the build produces it on the destination "
                        "machine",
                        "the entrypoint is already in the archive - a native "
                        "payload wearing a portable label", "§6.7")
        return

    if facts.entrypoint is None:
        return
    target = "payload/" + facts.entrypoint
    entry = by_name.get(target)
    if entry is None:
        return  # already reported as MANIFEST_ENTRYPOINT_NOT_IN_ARCHIVE
    try:
        data = c.read(entry)
    except READ_ERRORS as exc:
        rep.add("PAYLOAD_ENTRYPOINT_UNREADABLE", target,
                "the entrypoint entry can be decompressed", str(exc), "§6.7")
        return

    if kind == "native":
        elf = parse_elf(data)
        if elf is None:
            rep.add("PAYLOAD_NATIVE_NOT_ELF", target,
                    "the entrypoint bytes begin with the ELF magic "
                    "7f 45 4c 46 (\\x7fELF)",
                    "the first 4 bytes are %r" % data[:4], "§6.7")
            return
        if elf["type"] not in ELF_RUNNABLE_TYPES:
            rep.add("PAYLOAD_NATIVE_ELF_TYPE", target,
                    "ELF type ET_EXEC or ET_DYN (an executable, or a "
                    "position-independent executable)",
                    "e_type = %s" % ELF_TYPE_NAMES.get(elf["type"], elf["type"]),
                    "§6.7")
        arch = ELF_MACHINE_ARCH.get(elf["machine"])
        machine_name = ELF_MACHINE_NAMES.get(elf["machine"],
                                             "0x%X" % elf["machine"])
        if arch is None:
            rep.add("PAYLOAD_NATIVE_ARCH_UNNAMEABLE", target,
                    "an e_machine this format version can name "
                    "(x86-64 = 0x3E, AArch64 = 0xB7)",
                    "e_machine = 0x%X (%s)" % (elf["machine"], machine_name),
                    "§6.7")
        elif arch not in facts.architectures:
            rep.add("PAYLOAD_NATIVE_ARCH_MISMATCH", target,
                    "an ELF for one of the declared architectures %s"
                    % json.dumps(facts.architectures),
                    "e_machine = 0x%X (%s) -> %s"
                    % (elf["machine"], machine_name, arch), "§6.7")
        return

    if kind == "windows":
        pe = parse_pe(data)
        if pe is None:
            rep.add("PAYLOAD_WINDOWS_NOT_PE", target,
                    "an MZ header whose e_lfanew points, in range, at a "
                    "PE\\0\\0 signature",
                    "the first 2 bytes are %r and no in-range PE signature "
                    "follows e_lfanew" % data[:2], "§6.7")
            return
        if pe["is_dll"]:
            rep.add("PAYLOAD_WINDOWS_IS_DLL", target,
                    "IMAGE_FILE_DLL (0x2000) clear: a DLL is a library and "
                    "cannot be launched",
                    "Characteristics = 0x%04X (IMAGE_FILE_DLL set)"
                    % pe["characteristics"], "§6.7")
        if not pe["executable_image"]:
            rep.add("PAYLOAD_WINDOWS_NOT_EXECUTABLE_IMAGE", target,
                    "IMAGE_FILE_EXECUTABLE_IMAGE (0x0002) set",
                    "Characteristics = 0x%04X" % pe["characteristics"], "§6.7")
        arch = PE_MACHINE_ARCH.get(pe["machine"])
        machine_name = PE_MACHINE_NAMES.get(pe["machine"], "0x%X" % pe["machine"])
        if arch is None:
            rep.add("PAYLOAD_WINDOWS_ARCH_UNNAMEABLE", target,
                    "a COFF machine this format version can name "
                    "(x86-64 = 0x8664, AArch64 = 0xAA64)",
                    "Machine = 0x%04X (%s)" % (pe["machine"], machine_name),
                    "§6.7")
        elif arch not in facts.architectures:
            rep.add("PAYLOAD_WINDOWS_ARCH_MISMATCH", target,
                    "a PE for one of the declared architectures %s"
                    % json.dumps(facts.architectures),
                    "Machine = 0x%04X (%s) -> %s"
                    % (pe["machine"], machine_name, arch), "§6.7")
        sub = pe["subsystem"]
        if sub is not None and facts.launch_mode in ("gui", "console"):
            sub_name = PE_SUBSYSTEM_NAMES.get(sub, "0x%X" % sub)
            if sub_name in ("gui", "console") and sub_name != facts.launch_mode:
                rep.warn("PAYLOAD_WINDOWS_SUBSYSTEM_MISMATCH", target,
                         "a PE subsystem consistent with launch.mode %r. "
                         "Advisory only: §5.6 makes presentation declarative, "
                         "so this is NOT a MUST." % facts.launch_mode,
                         "IMAGE_OPTIONAL_HEADER.Subsystem = %d (%s)"
                         % (sub, sub_name), "§5.6")


# ==========================================================================
# Driver
# ==========================================================================
def validate(path):
    rep = Report(str(path))
    c = Container(path)
    check_container(c, rep)

    by_name = files_by_name(c)

    def read_optional(name):
        entry = by_name.get(name)
        if entry is None:
            return None
        try:
            return c.read(entry)
        except READ_ERRORS as exc:
            rep.add("CONTAINER_ENTRY_UNREADABLE", name,
                    "the entry can be decompressed", str(exc), "§1")
            return None

    manifest_raw = read_optional("lexe.json")
    hashes_raw = read_optional("metadata/hashes.json")

    facts = check_manifest(c, rep, manifest_raw)
    check_payload_presence(c, rep, facts)
    check_signatures(c, rep, facts, manifest_raw, hashes_raw)
    check_hashes(c, rep, hashes_raw)
    check_payload_role(c, rep, facts)
    return rep


def render_text(rep):
    lines = ["lexe-conformance: %s" % rep.package]
    errors = [v for v in rep.violations if v["severity"] == "error"]
    warnings = [v for v in rep.violations if v["severity"] != "error"]
    for v in rep.violations:
        lines.append("")
        lines.append("  [%s] %s  (%s)" % (v["severity"], v["code"], v["spec"]))
        lines.append("      where:    %s" % v["where"])
        lines.append("      expected: %s" % v["expected"])
        lines.append("      observed: %s" % v["observed"])
    for s in rep.skipped:
        lines.append("")
        lines.append("  [SKIPPED] %s  (%s)" % (s["check"], s["spec"]))
        lines.append("      reason:   %s" % s["reason"])
    lines.append("")
    verdict = "CONFORMANT" if rep.conformant else "NOT CONFORMANT"
    lines.append("%s: %d violation(s), %d warning(s), %d check(s) skipped"
                 % (verdict, len(errors), len(warnings), len(rep.skipped)))
    return "\n".join(lines)


def main(argv=None):
    # The spec section markers are non-ASCII; a legacy console encoding must
    # degrade to a replacement character, never to a traceback.
    try:
        sys.stdout.reconfigure(errors="backslashreplace")
        sys.stderr.reconfigure(errors="backslashreplace")
    except (AttributeError, OSError, ValueError):
        pass
    parser = argparse.ArgumentParser(
        prog="lexe_conformance.py",
        description="Independent conformance validator for .lexe packages "
                    "(docs/FORMAT-0.1.md).",
    )
    parser.add_argument("package", type=Path, help="the .lexe file to validate")
    parser.add_argument("--json", action="store_true",
                        help="emit the machine-readable report")
    args = parser.parse_args(argv)

    try:
        rep = validate(args.package)
    except Unreadable as exc:
        if args.json:
            json.dump(
                {
                    "package": str(args.package),
                    "conformant": False,
                    "violations": [
                        {
                            "code": "CONTAINER_UNREADABLE",
                            "severity": "fatal",
                            "where": str(args.package),
                            "expected": "a readable ZIP archive (§1)",
                            "observed": str(exc),
                            "spec": "§1",
                        }
                    ],
                    "skipped": [],
                },
                sys.stdout, indent=2, ensure_ascii=False,
            )
            sys.stdout.write("\n")
        else:
            print("lexe-conformance: cannot read %s: %s" % (args.package, exc),
                  file=sys.stderr)
        return 2

    if args.json:
        json.dump(rep.to_json(), sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        print(render_text(rep))
    return 0 if rep.conformant else 1


if __name__ == "__main__":
    sys.exit(main())

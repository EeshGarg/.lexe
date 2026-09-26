#!/usr/bin/env python3
"""Build one mutated .lexe from a valid one, re-hashed and re-signed.

Used by 02_gate_agreement.sh. Every mutation leaves the package AUTHENTIC — the
signatures are recomputed over the mutated documents — because the question the
lane asks is whether `verify` and `install` agree about a package, and a broken
signature would make them agree for an uninteresting reason.

    mutate.py <in.lexe> <out.lexe> <tag> <keyfile.json>

Exits non-zero (and prints why) when the mutation cannot be built here, so the
caller can SKIP rather than report a conformance result it did not obtain. The
commonest reason is no Ed25519 backend: signing is not optional for this to mean
anything.
"""
import base64
import json
import struct
import sys
import zipfile

EXCLUDED = ("lexe.json", "metadata/hashes.json")


def load_signer(keyfile):
    key = json.load(open(keyfile))
    seed = base64.b64decode(key["privateSeed"])
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError:
        sys.exit("no ed25519 backend (install `cryptography`)")
    return Ed25519PrivateKey.from_private_bytes(seed[:32]).sign


def members(path):
    """Every member as (name, bytes), in archive order."""
    with zipfile.ZipFile(path) as z:
        return [(i.filename, z.read(i.filename)) for i in z.infolist()]


def repack(out, entries, sign, executable=None):
    """Write entries, regenerating hashes.json and both signatures."""
    content = [(n, b) for n, b in entries if not n.startswith("signatures/")
               and n != "metadata/hashes.json"]
    manifest = dict(content)["lexe.json"]

    files = {n: __import__("hashlib").sha256(b).hexdigest()
             for n, b in sorted(content) if n not in EXCLUDED}
    doc = {"algorithm": "sha256", "files": files}
    if executable:
        doc["executable"] = executable
    hashes = json.dumps(doc, indent=2).encode()

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for n, b in sorted(content):
            z.writestr(n, b)
        z.writestr("metadata/hashes.json", hashes)
        z.writestr("signatures/manifest.sig", sign(manifest))
        z.writestr("signatures/payload.sig", sign(hashes))


def edit_manifest(entries, fn):
    out = []
    for n, b in entries:
        if n == "lexe.json":
            doc = json.loads(b)
            fn(doc)
            b = (json.dumps(doc, indent=2) + "\n").encode()
        out.append((n, b))
    return out


def main():
    src, dst, tag, keyfile = sys.argv[1:5]
    sign = load_signer(keyfile)
    entries = members(src)

    if tag == "unknown-permission":
        repack(dst, edit_manifest(
            entries, lambda d: d.update(permissions=["camera"])), sign)

    elif tag == "duplicate-permission":
        repack(dst, edit_manifest(
            entries, lambda d: d.update(permissions=["network", "network"])), sign)

    elif tag == "bomb":
        # Past the 16 MiB grace threshold and far past any sane ratio.
        repack(dst, entries + [("payload/big.dat", b"\0" * (32 * 1024 * 1024))],
               sign)

    elif tag == "bad-utf8-name":
        # Signed first, then the NAME is patched at the byte level: an entry
        # name is not covered by any digest, so this stays authentic.
        repack(dst, entries + [("payload/u8AA.txt", b"x")], sign)
        data = bytearray(open(dst, "rb").read())
        bad = b"payload/u8\xff\xfe.txt"
        needle = b"payload/u8AA.txt"
        assert len(bad) == len(needle), (len(bad), len(needle))
        while needle in data:
            at = data.index(needle)
            data[at:at + len(needle)] = bad
        open(dst, "wb").write(bytes(data))

    elif tag == "reserved-scope":
        def set_scope(d):
            d.setdefault("install", {})["scope"] = "machine-wide"
        repack(dst, edit_manifest(entries, set_scope), sign)

    elif tag == "exec-not-covered":
        repack(dst, entries, sign,
               executable=["payload/bin/does-not-exist"])

    elif tag == "exec-names-manifest":
        repack(dst, entries, sign, executable=["lexe.json"])

    elif tag == "long-version":
        repack(dst, edit_manifest(
            entries, lambda d: d.update(version="1." + "9" * 80)), sign)

    elif tag == "noncanonical-key":
        # A different spelling of the SAME key: base64 leaves the final group's
        # unused bits free. Found by trying the alphabet rather than hard-coded.
        alphabet = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789+/")
        original = json.loads(dict(entries)["lexe.json"])["publisher"]["publicKey"]
        body = original.split(":", 1)[1]
        want = base64.b64decode(body)
        variant = None
        last = len(body.rstrip("=")) - 1
        for ch in alphabet:
            if ch == body[last]:
                continue
            candidate = body[:last] + ch + body[last + 1:]
            try:
                if base64.b64decode(candidate) == want:
                    variant = "ed25519:" + candidate
                    break
            except Exception:
                pass
        if variant is None:
            sys.exit("no non-canonical spelling found for this key")

        def set_key(d):
            d["publisher"]["publicKey"] = variant
        repack(dst, edit_manifest(entries, set_key), sign)

    elif tag == "direntry":
        repack(dst, entries, sign)
        # Appended after signing: a directory record is covered by nothing.
        with zipfile.ZipFile(dst, "a", zipfile.ZIP_DEFLATED) as z:
            info = zipfile.ZipInfo("payload/evil/")
            info.external_attr = (0o40755 << 16) | 0x10
            z.writestr(info, b"SMUGGLED")

    elif tag == "dot-segment":
        repack(dst, entries + [("payload/aa/bb.txt", b"x")], sign)
        data = bytearray(open(dst, "rb").read())
        needle, bad = b"payload/aa/bb.txt", b"payload/./bb.txt"
        assert len(bad) == len(needle) - 1
        bad = bad + b"x"
        while needle in data:
            at = data.index(needle)
            data[at:at + len(needle)] = bad
        open(dst, "wb").write(bytes(data))

    else:
        sys.exit("unknown mutation tag: " + tag)


if __name__ == "__main__":
    main()

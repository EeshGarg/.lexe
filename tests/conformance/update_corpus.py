#!/usr/bin/env python3
"""update_corpus.py — the systematic corpus for `update.json` (FORMAT-0.1 §7).

    update_corpus.py <out-dir>

Emits, under <out-dir>:

    serve/            the fixed path the base package's manifest points at;
                      the lane copies one case's document here at a time
    base/app-1.0.0.lexe          the installed application
    pkgs/*.lexe                  packages the apply-mode cases point at
    cases/<name>/update.json     the document under test
    cases/<name>/update.json.sig its detached signature
    index.json                   (name, rule, expect, mode, why)

WRITTEN FROM §7, §7.0, §7.1, §5.0, §8 and §10.1 — not from `src/`.

**This corpus is NOT differential.** `tools/lexe-conformance` validates packages
and has no `update.json` mode, so there is no second implementation to compare
against. What it compares is the reference runtime against MY independent reading
of §7, which is the same axis as mission 5's "both wrong vs the spec" column and
none of the "two implementations agree" one. Every disagreement is therefore
either a runtime defect or a defect in my reading, and has to be argued either
way rather than settled by a vote. Cases the document does not determine are
recorded `unspecified` and assert nothing.

`expect` is one of:
    accept     the runtime proceeds: offers (check mode) or applies (apply mode)
    reject     the runtime refuses with an error
    no-update  the runtime reports no newer version — NOT an error, and not an
               acceptance either; check 7 makes an equal or lower offer a no-op
    unspecified §7 does not determine this; the lane records the outcome only

`mode` is "check" (`lexe update --check`: exercises checks 1,2,3,7 with no
download) or "apply" (`lexe update`: also 4,5,6).
"""
import base64
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from corpus import (Pkg, base_manifest, elf64, public_key_str, sha256_hex,
                    signer, SEED, FOREIGN_SEED)   # one generator, reused

APP_ID = "com.example.upd"
CHANNEL = "stable"
CASES = []


def case(name, rule, expect, why, doc=None, *, mode="check", raw=None,
         sig_seed=SEED, sig_over=None, no_sig=False, sig_bytes=None):
    """One update.json under test.

    doc      the document as a dict (signed after serialisation)
    raw      exact bytes instead, for shapes JSON cannot express
    sig_over exact bytes to sign instead of the document (a wrong-input signature)
    """
    CASES.append(dict(name=name, rule=rule, expect=expect, why=why, doc=doc,
                      mode=mode, raw=raw, sig_seed=sig_seed, sig_over=sig_over,
                      no_sig=no_sig, sig_bytes=sig_bytes))


def app_package(version="1.0.0", *, app_id=APP_ID, seed=SEED, serve_dir=None,
                tamper=False):
    """A valid application package, optionally with an `updates` block."""
    p = Pkg()
    p.seed = seed
    p.manifest = base_manifest()
    p.manifest["id"] = app_id
    p.manifest["version"] = version
    p.manifest["publisher"]["publicKey"] = public_key_str(seed)
    if serve_dir is not None:
        p.manifest["updates"] = {
            "enabled": True,
            "channel": CHANNEL,
            "manifest": "file://" + os.path.join(serve_dir, "update.json"),
            "allowSourceChange": True,
        }
    data = p.build()
    if tamper:
        # Flip a byte inside the stored payload so the §6 pipeline fails at the
        # hashes stage while the document that names it stays correctly signed.
        marker = b"corpus payload data"
        at = data.find(marker)
        assert at > 0, "payload marker not found"
        data = data[:at] + b"CORPUS-TAMPERED-XX!" + data[at + len(marker):]
    return data


def channel_doc(version, url, sha256, *, app_id=APP_ID, channel=CHANNEL,
                extra_channel=None, extra_top=None, drop=()):
    entry = {"version": version,
             "package": {"url": url, "sha256": sha256},
             "minimumRuntime": "0.1"}
    for k in drop:
        if "." in k:
            a, b = k.split(".", 1)
            entry.get(a, {}).pop(b, None)
        else:
            entry.pop(k, None)
    if extra_channel:
        entry.update(extra_channel)
    doc = {"lexeVersion": "0.1", "id": app_id, "channels": {channel: entry}}
    if extra_top:
        doc.update(extra_top)
    return doc


# ==================== the cases ==========================================
# Filled in by build(), which needs the emitted package URLs and digests.

def register(pkg_url, pkg_sha, tampered_url, tampered_sha, otherid_url,
             otherid_sha, foreign_url, foreign_sha):
    good = lambda v="2.0.0": channel_doc(v, pkg_url, pkg_sha)

    # ---------------- baseline + §8 ordering ----------------------------
    case("valid-newer", "§7", "accept",
         "a correctly signed document offering a strictly greater version",
         good())
    case("version-equal", "§7.7", "no-update",
         "check 7 requires strictly greater, so an equal offer is a no-op",
         good("1.0.0"))
    case("version-lower", "§7.7", "no-update",
         "an offer below the installed version must not be applied",
         good("0.9.0"))
    case("version-ordering-numeric", "§8", "accept",
         "components that are both all-digits compare NUMERICALLY, so 1.10.0 is "
         "greater than 1.9.0 even though it is lexicographically smaller",
         channel_doc("1.10.0", pkg_url, pkg_sha))
    case("version-ordering-leading-zeros", "§8", "no-update",
         "leading zeros are ignored, so 01.00.00 EQUALS 1.0.0 and is not greater",
         good("01.00.00"))
    case("version-ordering-prefix-longer", "§8", "accept",
         "a strict prefix is smaller, so 1.0.0.1 is greater than 1.0.0",
         channel_doc("1.0.0.1", pkg_url, pkg_sha))
    case("version-ordering-numeric-before-alpha", "§8", "accept",
         "when exactly one component is all-digits the numeric one sorts first, "
         "so 1.0.1 > 1.0.0 holds and 1.0.beta > 1.0.1",
         channel_doc("1.0.beta", pkg_url, pkg_sha))

    # ---------------- §5.0 strict JSON, applied to update.json ----------
    case("json-bom", "§5.0", "reject",
         "§5.0 binds every document this format defines, update.json included",
         raw=b"\xef\xbb\xbf" + json.dumps(good()).encode())
    case("json-duplicate-key-top", "§5.0", "reject",
         "a duplicated top-level member can be read two ways",
         raw=('{"lexeVersion":"0.1","id":"' + APP_ID + '","id":"other.app",'
              '"channels":{"stable":{"version":"2.0.0","package":{"url":"'
              + pkg_url + '","sha256":"' + pkg_sha + '"}}}}').encode())
    case("json-duplicate-key-nested", "§5.0", "reject",
         "the no-duplicates rule applies at ANY depth: a duplicated channel "
         "version is exactly the ambiguity a signature cannot resolve",
         raw=('{"lexeVersion":"0.1","id":"' + APP_ID + '","channels":'
              '{"stable":{"version":"2.0.0","version":"9.9.9","package":'
              '{"url":"' + pkg_url + '","sha256":"' + pkg_sha + '"}}}}').encode())
    case("json-trailing-data", "§5.0", "reject",
         "no trailing data after the top-level value",
         raw=json.dumps(good()).encode() + b"\n{}")
    case("json-not-object", "§5.0", "reject",
         "the top level must be a JSON object", raw=b"[1,2,3]")
    case("json-invalid-utf8", "§5.0", "reject",
         "the document must be valid UTF-8",
         raw=json.dumps(good()).encode().replace(b"stable", b"sta\xffle"))
    case("json-over-budget", "§10.1", "reject",
         "update.json must not exceed 1 MiB",
         channel_doc("2.0.0", pkg_url, pkg_sha,
                     extra_top={"pad": "z" * (1024 * 1024 + 64)}))
    case("json-unknown-member-top", "§5.0", "accept",
         "unknown members MUST be ignored for forward compatibility",
         channel_doc("2.0.0", pkg_url, pkg_sha,
                     extra_top={"futureTopLevel": {"a": 1}}))
    case("json-unknown-member-channel", "§5.0", "accept",
         "forward compatibility applies inside the channel entry too",
         channel_doc("2.0.0", pkg_url, pkg_sha,
                     extra_channel={"futureChannelThing": [1, 2]}))
    case("json-version-null", "§5.0", "reject",
         "`null` is absent, so a null version is a missing required field",
         channel_doc("2.0.0", pkg_url, pkg_sha,
                     extra_channel={"version": None}))

    # ---------------- check 1: signature ---------------------------------
    case("sig-foreign-key", "§7.1c", "reject",
         "the document must verify with the INSTALLED publisher key",
         good(), sig_seed=FOREIGN_SEED)
    case("sig-absent", "§7", "reject",
         "the detached signature is fetched from URL + \".sig\"; without it "
         "nothing is authenticated",
         good(), no_sig=True)
    case("sig-truncated", "§7", "reject",
         "a signature must be a raw 64-byte Ed25519 value",
         good(), sig_bytes=b"\x00" * 63)
    case("sig-over-wrong-bytes", "§7", "reject",
         "a valid signature over different bytes authenticates nothing here",
         good(), sig_over=b"some other document entirely")
    case("sig-checked-before-parse", "§7", "reject",
         "check 1 is first: an unparseable document with a BAD signature must "
         "be refused for the SIGNATURE, never reach the parser, and never "
         "allocate on the strength of its contents",
         raw=b'{"channels": ' + b"[" * 4000 + b"]" * 4000 + b"}",
         sig_bytes=b"\x11" * 64)
    case("sig-valid-over-garbage", "§7", "reject",
         "a correctly signed document that is not valid JSON is refused at the "
         "parse, which proves the order is signature-then-parse and not "
         "parse-then-signature",
         raw=b"this is not json at all")

    # ---------------- check 2: id ----------------------------------------
    case("id-mismatch", "§7.2", "reject",
         "the document's id must match the installed application",
         channel_doc("2.0.0", pkg_url, pkg_sha, app_id="com.example.other"))
    case("id-absent", "§7.2", "reject",
         "without an id the document cannot be matched to the application",
         channel_doc("2.0.0", pkg_url, pkg_sha, drop=("nothing",),
                     extra_top={"id": None}))

    # ---------------- check 3: channel -----------------------------------
    case("channels-absent", "§7.3", "reject",
         "a channels object is required",
         {"lexeVersion": "0.1", "id": APP_ID})
    case("channels-not-object", "§7.3", "reject",
         "`channels` must be an object",
         {"lexeVersion": "0.1", "id": APP_ID, "channels": []})
    case("channel-missing", "§7.3", "reject",
         "the app's configured channel must be present",
         channel_doc("2.0.0", pkg_url, pkg_sha, channel="beta"))
    case("channel-entry-not-object", "§7.3", "reject",
         "a channel entry must be an object",
         {"lexeVersion": "0.1", "id": APP_ID, "channels": {CHANNEL: "2.0.0"}})
    case("channel-version-missing", "§7.3", "reject",
         "a channel entry without a version offers nothing",
         channel_doc("2.0.0", pkg_url, pkg_sha, drop=("version",)))
    case("channel-package-missing", "§7.3", "reject",
         "a channel entry must name the package to fetch",
         channel_doc("2.0.0", pkg_url, pkg_sha, drop=("package",)))
    case("channel-package-url-missing", "§7.3", "reject",
         "the package entry must carry a url",
         channel_doc("2.0.0", pkg_url, pkg_sha, drop=("package.url",)))
    case("channel-package-sha-missing", "§7.3", "reject",
         "the package entry must carry a sha256, or check 4 has no input",
         channel_doc("2.0.0", pkg_url, pkg_sha, drop=("package.sha256",)))
    case("channel-extra-channel-ignored", "§5.0", "accept",
         "a second channel the app is not configured for is simply not chosen",
         {"lexeVersion": "0.1", "id": APP_ID,
          "channels": {CHANNEL: channel_doc("2.0.0", pkg_url,
                                            pkg_sha)["channels"][CHANNEL],
                       "beta": {"version": "9.9.9",
                                "package": {"url": "file:///nonexistent",
                                            "sha256": "0" * 64}}}})

    # ---------------- checks 4,5,6: the downloaded package ---------------
    case("package-sha-mismatch", "§7.4", "reject",
         "the downloaded package's SHA-256 must match what the signed document "
         "says; otherwise the document authenticated a different file",
         channel_doc("2.0.0", pkg_url, "0" * 64), mode="apply")
    case("package-fails-pipeline", "§7.5", "reject",
         "the downloaded package must pass the full §6 pipeline; a correctly "
         "advertised digest does not make tampered content installable",
         channel_doc("2.0.0", tampered_url, tampered_sha), mode="apply")
    case("package-id-differs", "§7.6", "reject",
         "the package's own id must match the installed application, not merely "
         "the document's id",
         channel_doc("2.0.0", otherid_url, otherid_sha), mode="apply")
    case("package-foreign-key", "§7.6", "reject",
         "the package's publisher key must match the installed one — 0.1 has no "
         "authenticated key rotation",
         channel_doc("2.0.0", foreign_url, foreign_sha), mode="apply")
    case("package-valid-apply", "§7", "accept",
         "the whole path end to end: signed document, matching digest, a package "
         "that passes §6 with the same id and key, strictly newer",
         good(), mode="apply")

    # ---------------- §7.0 field rules -----------------------------------
    #
    # All five of these were `unspecified` when this corpus was written: each
    # produced a definite runtime behaviour that §7 did not authorise, which is
    # how they were found. §7.0 now states every one of them, so they assert a
    # rule rather than merely record what happened.
    case("lexeversion-absent", "§7.0", "accept",
         "`lexeVersion` is OPTIONAL in update.json: absent claims no format "
         "version, and a reader that knows which format it speaks may proceed",
         {"id": APP_ID,
          "channels": {CHANNEL: channel_doc("2.0.0", pkg_url,
                                            pkg_sha)["channels"][CHANNEL]}})
    case("lexeversion-wrong", "§7.0", "reject",
         "a PRESENT `lexeVersion` MUST be \"0.1\" -- a wrong one is an explicit "
         "claim to be a document this reader does not understand. The asymmetry "
         "with `absent` is deliberate and §7.0 says so",
         channel_doc("2.0.0", pkg_url, pkg_sha, extra_top={"lexeVersion": "0.2"}))
    case("minimumruntime-unsatisfiable", "§7.0", "accept",
         # Resolved by REMOVAL, not by specification: `minimumRuntime` is not a
         # field of 0.1 and has been dropped from §7's example. It is therefore an
         # unknown member, and §5.0 requires readers to ignore those -- so a
         # channel carrying one is accepted, which is the third time this project
         # has had to decide what to do about a field nothing reads (after
         # `healthCheck` and `metadata/permissions.json`).
         "`minimumRuntime` is not a 0.1 field; as an unknown member it MUST be "
         "ignored (§5.0), not treated as a gate",
         channel_doc("2.0.0", pkg_url, pkg_sha,
                     extra_channel={"minimumRuntime": "99.0"}))
    case("package-sha-uppercase", "§7.0", "reject",
         "`package.sha256` MUST be lowercase, for the reason §3.6 already gives "
         "about hashes.json: a case-sensitive reader is conforming, so an "
         "uppercase digest would be read differently by different "
         "implementations. The runtime used to lowercase it and apply the update",
         channel_doc("2.0.0", pkg_url, pkg_sha.upper()), mode="apply")
    case("package-sha-not-hex", "§7.0", "reject",
         "`package.sha256` MUST be 64 hexadecimal characters",
         channel_doc("2.0.0", pkg_url, "not-a-digest"), mode="apply")


# ==================== emission ==========================================

def main():
    if len(sys.argv) != 2:
        sys.stderr.write(__doc__)
        return 2
    out = os.path.abspath(sys.argv[1])
    if os.path.isdir(out):
        shutil.rmtree(out)
    for sub in ("serve", "base", "pkgs", "cases"):
        os.makedirs(os.path.join(out, sub))

    serve = os.path.join(out, "serve")

    # The installed application, and the packages the apply-mode cases name.
    base = app_package("1.0.0", serve_dir=serve)
    with open(os.path.join(out, "base", "app-1.0.0.lexe"), "wb") as fh:
        fh.write(base)

    def emit_pkg(fname, data):
        path = os.path.join(out, "pkgs", fname)
        with open(path, "wb") as fh:
            fh.write(data)
        return "file://" + path, sha256_hex(data)

    good_url, good_sha = emit_pkg("app-2.0.0.lexe",
                                  app_package("2.0.0", serve_dir=serve))
    tam_url, tam_sha = emit_pkg("app-2.0.0-tampered.lexe",
                                app_package("2.0.0", serve_dir=serve,
                                            tamper=True))
    oth_url, oth_sha = emit_pkg("other-2.0.0.lexe",
                                app_package("2.0.0", app_id="com.example.other",
                                            serve_dir=serve))
    for_url, for_sha = emit_pkg("foreign-2.0.0.lexe",
                                app_package("2.0.0", seed=FOREIGN_SEED,
                                            serve_dir=serve))

    register(good_url, good_sha, tam_url, tam_sha, oth_url, oth_sha,
             for_url, for_sha)

    index = []
    for c in CASES:
        d = os.path.join(out, "cases", c["name"])
        os.makedirs(d)
        doc = c["raw"] if c["raw"] is not None else (
            json.dumps(c["doc"], indent=2).encode() + b"\n")
        with open(os.path.join(d, "update.json"), "wb") as fh:
            fh.write(doc)
        if not c["no_sig"]:
            if c["sig_bytes"] is not None:
                sig = c["sig_bytes"]
            else:
                sig = signer(c["sig_seed"]).sign(
                    c["sig_over"] if c["sig_over"] is not None else doc)
            with open(os.path.join(d, "update.json.sig"), "wb") as fh:
                fh.write(sig)
        index.append({k: c[k] for k in ("name", "rule", "expect", "mode", "why")})

    with open(os.path.join(out, "index.json"), "w") as fh:
        json.dump({"app_id": APP_ID, "serve": serve,
                   "base": os.path.join(out, "base", "app-1.0.0.lexe"),
                   "cases": index,
                   "counts": {
                       "total": len(index),
                       "accept": sum(1 for c in index if c["expect"] == "accept"),
                       "reject": sum(1 for c in index if c["expect"] == "reject"),
                       "no_update": sum(1 for c in index
                                        if c["expect"] == "no-update"),
                       "unspecified": sum(1 for c in index
                                          if c["expect"] == "unspecified"),
                   }}, fh, indent=2)

    sys.stderr.write(
        "update corpus: %d cases (%d accept, %d reject, %d no-update, "
        "%d unspecified)\n" % (
            len(index),
            sum(1 for c in index if c["expect"] == "accept"),
            sum(1 for c in index if c["expect"] == "reject"),
            sum(1 for c in index if c["expect"] == "no-update"),
            sum(1 for c in index if c["expect"] == "unspecified")))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env bash
# tests/conformance/01_differential.sh — two implementations over the same
# packages, and every disagreement is a finding.
#
# `lexe verify` and `tools/lexe-conformance/lexe_conformance.py` were written
# from the same document and share no code: the validator is stdlib Python, it
# parses the ZIP central directory by hand rather than through `zipfile` (which
# normalises away the very bytes several §2 rules are about), and it never
# invokes `lexe`. That independence is the whole point -- two implementations of
# one spec that agree are evidence about the SPEC, while two that share a parser
# only agree about the parser.
#
# So this lane does not assert that either tool is right. It asserts they reach
# the same verdict, and prints both when they do not. The one disagreement found
# so far was the validator being correct and the reference implementation wrong:
# `lexe verify` reported OK on a decompression bomb that `lexe install` refused,
# because the aggregate resource guards lived only in extract_payload(). That is
# fixed (the guard is in the PackageReader constructor now) and pinned by
# test_hostile_packages.cpp -- this lane is what would have caught it earlier.
#
# A disagreement is reported as FAIL, never silently resolved in favour of the
# C++. Investigating which side is right is the work; picking a winner by fiat
# is how a spec becomes "whatever the reference implementation happens to do".
set -uo pipefail
CONF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$CONF_DIR/../acceptance/lib.sh"

acc_begin "conformance 01 differential"
acc_require_binaries

VALIDATOR="$ACC_REPO/tools/lexe-conformance/lexe_conformance.py"
[[ -f "$VALIDATOR" ]] || { fail "the validator is missing: $VALIDATOR"; acc_summary; exit $?; }

PY=""
for candidate in python3 python; do
    command -v "$candidate" >/dev/null 2>&1 && { PY="$candidate"; break; }
done
if [[ -z "$PY" ]]; then
    skip "no python3, so the independent validator cannot run"
    acc_summary
    exit $?
fi

acc_scratch_home
note "validator: $PY $VALIDATOR"

# Does the validator have a real Ed25519 backend? Without one it reports stages
# 4-5 as SKIPPED rather than passing them, which is the honest behaviour -- but
# it means a signature-only defect would produce a legitimate disagreement, and
# calling that a failure would be blaming the validator for saying "I did not
# check". Recorded either way, so a run's output says which it was.
if "$PY" -c "import cryptography" >/dev/null 2>&1 || "$PY" -c "import nacl" >/dev/null 2>&1; then
    SIG_BACKEND=yes
    note "validator has an Ed25519 backend: signature defects are compared too"
else
    SIG_BACKEND=no
    note "validator has NO Ed25519 backend: it SKIPS stages 4-5, so signature-only"
    note "defects are compared for 'lexe rejects' alone, not for agreement"
fi

# ---------------------------------------------------------------- the compare

# differ <package> <label> [signature-only]
#
# Runs both and compares accept/reject. The verdict, not the message: the two
# tools describe a defect in their own words on purpose, and demanding identical
# prose would make this a test of phrasing.
differ() {
    local pkg="$1" label="$2" sig_only="${3:-no}"
    local lexe_rc conf_rc conf_out

    "$LEXE" verify "$pkg" >"$ACC_ROOT/work/lexe-verify.txt" 2>&1
    lexe_rc=$?
    conf_out="$("$PY" "$VALIDATOR" --json "$pkg" 2>&1)"
    conf_rc=$?

    # Exit 2 from the validator means "could not read it at all", which is a
    # rejection for this purpose -- both tools refusing a file is agreement,
    # whatever each calls it.
    local lexe_ok conf_ok
    [[ $lexe_rc -eq 0 ]] && lexe_ok=accept || lexe_ok=reject
    [[ $conf_rc -eq 0 ]] && conf_ok=accept || conf_ok=reject

    if [[ "$sig_only" == "yes" && "$SIG_BACKEND" == "no" ]]; then
        # The validator cannot see this class of defect here. Assert only that
        # the reference implementation rejects it, and say why the comparison
        # was not made rather than quietly counting a pass.
        if [[ "$lexe_ok" == "reject" ]]; then
            pass "$label (lexe rejects; validator could not check signatures)"
        else
            fail "$label" "lexe accepted a package with a signature defect"
        fi
        return
    fi

    if [[ "$lexe_ok" == "$conf_ok" ]]; then
        pass "$label — both $lexe_ok"
    else
        fail "$label — DISAGREEMENT" \
            "lexe verify:  $lexe_ok (exit $lexe_rc)" \
            "$(sed -n '1,6p' "$ACC_ROOT/work/lexe-verify.txt")" \
            "validator:    $conf_ok (exit $conf_rc)" \
            "$(printf '%s' "$conf_out" | sed -n '1,14p')"
    fi
}

# ------------------------------------------------------------ valid packages

# Built from COPIES: `lexe build` fills a manifest's "AUTO" publicKey in from
# --key and says so, which would pin this run's throwaway key into the tracked
# examples.
"$LEXE" keygen "$ACC_ROOT/work/key.json" >/dev/null 2>&1

built_any=no
for example in native/cli-hello service/heartbeat; do
    src="$ACC_REPO/examples/$example"
    [[ -d "$src" ]] || continue
    tag="$(basename "$example")"
    cp -r "$src" "$ACC_ROOT/work/$tag"
    # Several examples ship SOURCE and a Makefile rather than a built payload,
    # so `lexe build` would refuse them for having no payload/ at all. Build it
    # in the copy; a host with no compiler skips the example rather than
    # reporting a conformance result it did not obtain.
    if [[ -f "$ACC_ROOT/work/$tag/Makefile" && ! -d "$ACC_ROOT/work/$tag/payload" ]]; then
        make -s -C "$ACC_ROOT/work/$tag" >"$ACC_ROOT/work/$tag-make.log" 2>&1 || true
    fi
    if ! "$LEXE" build "$ACC_ROOT/work/$tag" -o "$ACC_ROOT/work/$tag.lexe" \
            --key "$ACC_ROOT/work/key.json" >"$ACC_ROOT/work/$tag-build.log" 2>&1; then
        # A payload this host cannot compile is not a conformance result.
        skip "$tag could not be built here"
        note "$(tail -2 "$ACC_ROOT/work/$tag-build.log")"
        continue
    fi
    built_any=yes
    differ "$ACC_ROOT/work/$tag.lexe" "valid: $tag"
done

if [[ "$built_any" == "no" ]]; then
    fail "no example package could be built, so nothing was compared"
    acc_summary
    exit $?
fi

GOOD="$ACC_ROOT/work/heartbeat.lexe"
[[ -f "$GOOD" ]] || GOOD="$ACC_ROOT/work/cli-hello.lexe"

# ---------------------------------------------------------- crafted defects
#
# Raw byte and archive surgery, because the interesting §2 rules are about bytes
# a well-behaved writer will not produce. Each one is a package both tools
# should refuse; the assertion is that they agree on that.

craft() {
    local tag="$1"
    local out="$ACC_ROOT/work/bad-$tag.lexe"
    if "$PY" - "$GOOD" "$out" "$tag" <<'CRAFT'
import sys, zipfile, shutil, os

src, dst, mode = sys.argv[1], sys.argv[2], sys.argv[3]
rest = sys.argv[4:]

if mode == "trailing":
    shutil.copy(src, dst)
    with open(dst, "ab") as f:
        f.write(b"\x5a" * 64)
elif mode == "prepend":
    with open(src, "rb") as a, open(dst, "wb") as b:
        b.write(b"\x00" * 64)
        b.write(a.read())
elif mode == "truncate":
    with open(src, "rb") as a, open(dst, "wb") as b:
        data = a.read()
        b.write(data[: len(data) // 2])
elif mode == "notzip":
    with open(dst, "wb") as b:
        b.write(b"this is not a zip archive at all, not even close")
elif mode == "empty":
    open(dst, "wb").close()
elif mode in ("traversal", "absolute", "backslash", "toplevel", "duplicate"):
    names = {
        "traversal": "payload/../../escape.txt",
        "absolute": "/etc/passwd",
        "backslash": "payload\\windows\\thing.txt",
        "toplevel": "unexpected/thing.txt",
        "duplicate": None,
    }
    zin = zipfile.ZipFile(src)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
        for n in zin.namelist():
            z.writestr(n, zin.read(n))
        if mode == "duplicate":
            z.writestr("lexe.json", zin.read("lexe.json"))
        else:
            z.writestr(names[mode], b"x")
elif mode == "tamper-hash":
    zin = zipfile.ZipFile(src)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
        for n in zin.namelist():
            data = zin.read(n)
            if n.startswith("payload/") and len(data) > 8:
                data = bytearray(data)
                data[-1] ^= 0xFF
                data = bytes(data)
            z.writestr(n, data)
elif mode == "bad-manifest":
    zin = zipfile.ZipFile(src)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
        for n in zin.namelist():
            z.writestr(n, b"{ not json" if n == "lexe.json" else zin.read(n))
elif mode == "short-sig":
    zin = zipfile.ZipFile(src)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
        for n in zin.namelist():
            z.writestr(n, zin.read(n)[:63] if n == "signatures/manifest.sig"
                       else zin.read(n))
elif mode == "missing-hashes":
    zin = zipfile.ZipFile(src)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
        for n in zin.namelist():
            if n == "metadata/hashes.json":
                continue
            z.writestr(n, zin.read(n))
elif mode == "bomb":
    zin = zipfile.ZipFile(src)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for n in zin.namelist():
            z.writestr(n, zin.read(n))
        z.writestr("payload/big.dat", b"\0" * (32 * 1024 * 1024))
else:
    sys.exit("unknown craft mode " + mode)
CRAFT
    then
        printf '%s' "$out"
    fi
}

for spec in \
    "trailing:trailing data after the archive" \
    "prepend:data prepended before the archive" \
    "truncate:a truncated archive" \
    "notzip:a file that is not a ZIP at all" \
    "empty:an empty file" \
    "traversal:a .. path traversal entry" \
    "absolute:an absolute path entry" \
    "backslash:a backslash separator entry" \
    "toplevel:a disallowed top-level directory" \
    "duplicate:a duplicate entry path" \
    "bad-manifest:an unparseable lexe.json" \
    "missing-hashes:a missing metadata/hashes.json" \
    "bomb:a decompression bomb"
do
    tag="${spec%%:*}"; label="${spec#*:}"
    pkg="$(craft "$tag")"
    if [[ -z "$pkg" || ! -f "$pkg" ]]; then
        fail "could not craft: $label"
        continue
    fi
    differ "$pkg" "broken: $label"
done

# These two are defects the validator can only see with a crypto backend.
for spec in \
    "tamper-hash:a tampered payload byte" \
    "short-sig:a 63-byte signature"
do
    tag="${spec%%:*}"; label="${spec#*:}"
    pkg="$(craft "$tag")"
    if [[ -z "$pkg" || ! -f "$pkg" ]]; then
        fail "could not craft: $label"
        continue
    fi
    # A tampered payload byte is caught by the HASHES, which the validator
    # recomputes without any crypto -- so only the signature-length case is
    # backend-dependent.
    if [[ "$tag" == "short-sig" ]]; then
        differ "$pkg" "broken: $label" yes
    else
        differ "$pkg" "broken: $label"
    fi
done

# ------------------------------------------------- the semantically-broken set
#
# examples/broken/ is STRUCTURALLY valid and semantically wrong on purpose: a
# .dll where a PE executable is required, source declared as native, a lying
# architecture. Both tools should reject them, but at different layers -- and
# that is worth comparing precisely because a schema over the manifest cannot
# see any of it.
for broken in "$ACC_REPO"/examples/broken/*/; do
    [[ -d "$broken" ]] || continue
    tag="$(basename "$broken")"
    cp -r "$broken" "$ACC_ROOT/work/broken-$tag"
    if ! "$LEXE" build "$ACC_ROOT/work/broken-$tag" \
            -o "$ACC_ROOT/work/broken-$tag.lexe" \
            --key "$ACC_ROOT/work/key.json" \
            >"$ACC_ROOT/work/broken-$tag.log" 2>&1; then
        # `lexe build` refusing to package it at all is itself a result, and the
        # right one -- the defect was caught before it could become a package.
        pass "broken example $tag: lexe build refuses to package it"
        continue
    fi
    differ "$ACC_ROOT/work/broken-$tag.lexe" "broken example: $tag"
done

acc_summary

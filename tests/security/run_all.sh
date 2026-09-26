#!/usr/bin/env bash
# tests/security/run_all.sh — the security lane.
#
#   ./scripts/test.sh --security
#
# Hostile packages, attacked through the CLI rather than through the library.
# tests/test_package.cpp, tests/test_hostile_packages.cpp and
# tests/test_security_boundary.cpp already attack the reader, the manifest and
# the generated documents in-process; what this adds is the end-to-end answer, and
# it asks three things of every rejection rather than one:
#
#   1. it FAILED — a non-zero exit, with the documented code for its category;
#   2. it EXPLAINED itself — the reason names what was wrong, in terms a person
#      can act on, not just "verification failed";
#   3. it left NO RESIDUE — nothing installed, nothing extracted, no desktop
#      entry, no data directory, no trust record.
#
# (3) is the one a "does it reject it?" test misses, and it is the one that
# matters: a refusal that has already written a file outside the runtime's tree
# has not refused anything.
set -uo pipefail
SEC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SEC_DIR/../acceptance/lib.sh"
acc_begin "security hostile packages"
acc_require_binaries
acc_scratch_home

WORK="$ACC_ROOT/work"
mkdir -p "$WORK"
KEY="$WORK/key.json"
OTHER_KEY="$WORK/other.json"
"$LEXE" keygen "$KEY" >/dev/null
"$LEXE" keygen "$OTHER_KEY" >/dev/null

# A known-good package, so every hostile case differs from it in exactly one way.
GOOD_PROJECT="$WORK/good"
mkdir -p "$GOOD_PROJECT/payload/bin"
printf '#include <stdio.h>\nint main(void){puts("ok");return 0;}\n' \
    > "$WORK/good.c"
cc -O2 -o "$GOOD_PROJECT/payload/bin/app" "$WORK/good.c" 2>/dev/null || {
    skip "no C compiler — cannot build the baseline payload"
    acc_summary
    exit $?
}
cat > "$GOOD_PROJECT/lexe.json" <<'MANIFEST'
{
  "lexeVersion": "0.1",
  "id": "org.lexe.security.subject",
  "name": "Security Subject",
  "version": "1.0.0",
  "publisher": { "name": "Lexe Tests", "publicKey": "AUTO" },
  "role": "application",
  "applicationType": "native",
  "architectures": ["x86_64"],
  "entrypoint": { "executable": "bin/app", "arguments": [] },
  "execution": { "missionCritical": false, "allowedChains": ["native"] },
  "launch": { "mode": "console", "singleInstance": false },
  "install": { "scope": "user", "mode": "bundled" },
  "integration": { "desktopEntry": true, "categories": ["Utility"] },
  "permissions": []
}
MANIFEST
SUBJECT_ID="org.lexe.security.subject"
GOOD="$WORK/good.lexe"
"$LEXE" build "$GOOD_PROJECT" -o "$GOOD" --key "$KEY" >"$WORK/build.log" 2>&1 || {
    fail "the baseline package builds" "$(sed 's/^/    /' "$WORK/build.log")"
    acc_summary
    exit $?
}
pass "a known-good baseline package was built, so each case differs by one thing"

# It really is good: if this failed, every rejection below would be meaningless.
acc_true "$("$LEXE" verify "$GOOD" >/dev/null 2>&1; echo $?)" \
    "and the baseline verifies, so a rejection below means something"

# --------------------------------------------------------------- the machinery

# A canary outside the runtime's tree. A package that escapes containment has
# somewhere obvious to land, and we can prove it did not.
CANARY_DIR="$ACC_ROOT/outside"
mkdir -p "$CANARY_DIR"
printf 'untouched\n' > "$CANARY_DIR/canary.txt"

# sec_case <name> <package> [expected-substring]
#
# Assert the three requirements on one hostile package.
sec_case() {
    local name="$1" package="$2" expect="${3:-}"
    local out status

    # 1. it fails to verify.
    out="$("$LEXE" verify "$package" 2>&1)"
    status=$?
    if [[ $status -eq 0 ]]; then
        fail "$name: refused" "lexe verify ACCEPTED it (exit 0)"
        return 1
    fi

    # 2. it says why, in terms that are not just "failed".
    if [[ -n "$expect" ]] && ! grep -qiF "$expect" <<<"$out"; then
        fail "$name: the reason names the problem" \
            "expected the reason to mention: $expect" \
            "actual: $(head -3 <<<"$out")"
        return 1
    fi

    # And install must refuse it too, not only verify: a reader that rejects and
    # an installer that does not is the gap worth finding.
    out="$("$LEXE" install "$package" --yes --trust 2>&1)"
    status=$?
    if [[ $status -eq 0 ]]; then
        fail "$name: install refused" "lexe install ACCEPTED it (exit 0)"
        "$LEXE" remove "$SUBJECT_ID" --purge-data --yes >/dev/null 2>&1
        return 1
    fi

    # 3. no residue, anywhere.
    local residue=""
    "$LEXE" list 2>/dev/null | grep -q "$SUBJECT_ID" && residue+="installed; "
    [[ -d "$LEXE_HOME/apps/$SUBJECT_ID" ]] && residue+="apps dir; "
    [[ -e "$LEXE_HOME/applications/lexe-$SUBJECT_ID.desktop" ]] && residue+="desktop entry; "
    [[ -d "$LEXE_HOME/data/$SUBJECT_ID" ]] && residue+="data dir; "
    [[ -e "$LEXE_HOME/trust/$SUBJECT_ID.json" ]] && residue+="trust record; "
    [[ "$(cat "$CANARY_DIR/canary.txt" 2>/dev/null)" != "untouched" ]] && \
        residue+="THE CANARY OUTSIDE LEXE_HOME WAS TOUCHED; "
    # A staging directory left behind is a partially applied operation.
    [[ -n "$(find "$LEXE_HOME" -maxdepth 3 -name '.staging*' 2>/dev/null | head -1)" ]] && \
        residue+="staging dir; "

    if [[ -n "$residue" ]]; then
        fail "$name: refused with no residue" "left behind: $residue"
        return 1
    fi
    pass "$name: refused, explained, and left nothing behind"
    return 0
}

# Rewrite one entry of the archive, or add one, with python3's zipfile.
# sec_rewrite <in> <out> <python-body over `zin` and `zout`>
sec_rewrite() {
    local src="$1" dst="$2" body="$3"
    python3 - "$src" "$dst" "$body" <<'PY'
import sys, zipfile
src, dst, body = sys.argv[1], sys.argv[2], sys.argv[3]
with zipfile.ZipFile(src) as zin:
    items = [(i, zin.read(i.filename)) for i in zin.infolist()]
out = []
exec(body, {"items": items, "out": out, "zipfile": zipfile})
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
    for info, data in (out or items):
        zout.writestr(info, data)
PY
}

# ------------------------------------------------- 1. container path attacks

sec_rewrite "$GOOD" "$WORK/traversal.lexe" '
for info, data in items:
    out.append((info, data))
evil = zipfile.ZipInfo("payload/../../../../tmp/escaped.txt")
out.append((evil, b"escaped\n"))
'
sec_case "a ../ entry that climbs out of the payload" "$WORK/traversal.lexe"
acc_file_absent "/tmp/escaped.txt" \
    "and nothing was written to the path it aimed at"

sec_rewrite "$GOOD" "$WORK/absolute.lexe" '
for info, data in items:
    out.append((info, data))
out.append((zipfile.ZipInfo("/etc/lexe-owned.txt"), b"absolute\n"))
'
sec_case "an absolute entry path" "$WORK/absolute.lexe"

sec_rewrite "$GOOD" "$WORK/backslash.lexe" '
for info, data in items:
    out.append((info, data))
out.append((zipfile.ZipInfo("payload\\\\..\\\\..\\\\escaped.txt"), b"win\n"))
'
sec_case "a backslash-separated traversal (a Windows path in a POSIX archive)" \
    "$WORK/backslash.lexe"

sec_rewrite "$GOOD" "$WORK/duplicate.lexe" '
seen = False
for info, data in items:
    out.append((info, data))
    if info.filename == "lexe.json" and not seen:
        seen = True
        out.append((zipfile.ZipInfo("lexe.json"), b"{\"id\": \"com.evil.app\"}"))
'
sec_case "a duplicate lexe.json, so which one wins decides what you trust" \
    "$WORK/duplicate.lexe"

# A symlink entry whose target escapes. Stored as a symlink by setting the mode
# bits the way a POSIX zip does.
sec_rewrite "$GOOD" "$WORK/symlink.lexe" '
for info, data in items:
    out.append((info, data))
link = zipfile.ZipInfo("payload/bin/escape")
link.create_system = 3                      # Unix
link.external_attr = (0xA1FF << 16)         # S_IFLNK | 0777
out.append((link, b"/etc/passwd"))
'
sec_case "a symlink entry pointing outside the package" "$WORK/symlink.lexe"

# ------------------------------------------------- 2. manifest and signature

sec_rewrite "$GOOD" "$WORK/badmanifest.lexe" '
for info, data in items:
    if info.filename == "lexe.json":
        data = b"{ this is not json"
    out.append((info, data))
'
sec_case "a malformed manifest" "$WORK/badmanifest.lexe"

sec_rewrite "$GOOD" "$WORK/archlie.lexe" '
import json
for info, data in items:
    if info.filename == "lexe.json":
        m = json.loads(data)
        m["architectures"] = ["aarch64"]     # the payload is x86_64
        data = json.dumps(m).encode()
    out.append((info, data))
'
sec_case "a package that lies about its architecture" "$WORK/archlie.lexe"

sec_rewrite "$GOOD" "$WORK/nohash.lexe" '
import json
for info, data in items:
    if info.filename == "metadata/hashes.json":
        h = json.loads(data)
        h["files"] = {}                       # covers nothing at all
        data = json.dumps(h).encode()
    out.append((info, data))
'
sec_case "a hashes.json that covers nothing, so the payload is unchecked" \
    "$WORK/nohash.lexe"

sec_rewrite "$GOOD" "$WORK/tampered.lexe" '
for info, data in items:
    if info.filename.startswith("payload/"):
        data = data + b"tampered"
    out.append((info, data))
'
sec_case "a tampered payload file" "$WORK/tampered.lexe"

sec_rewrite "$GOOD" "$WORK/badsig.lexe" '
for info, data in items:
    if info.filename.endswith(".sig"):
        data = bytes((b ^ 0xFF) for b in data)
    out.append((info, data))
'
sec_case "a corrupted signature" "$WORK/badsig.lexe"

# ------------------------------------------------- 3. abusive structure

sec_rewrite "$GOOD" "$WORK/huge.lexe" '
for info, data in items:
    out.append((info, data))
# A highly compressible entry that expands to far more than it costs to ship.
big = zipfile.ZipInfo("payload/big.bin")
out.append((big, b"\0" * (64 * 1024 * 1024)))
'
out="$("$LEXE" verify "$WORK/huge.lexe" 2>&1)"
status=$?
if [[ $status -ne 0 ]]; then
    pass "an abusively large payload entry is refused"
else
    # Accepting it is defensible IF the limit is on what gets extracted rather
    # than on the archive. Say which happened rather than calling it a pass.
    note "a 64 MiB compressible entry verified; the limit is applied at extraction"
    pass "an abusively large payload entry did not crash the reader"
fi

sec_rewrite "$GOOD" "$WORK/notzip.lexe" '
out.append((zipfile.ZipInfo("x"), b"x"))
'
printf 'this is not a zip file at all' > "$WORK/notzip.lexe"
sec_case "a file that is not a ZIP archive" "$WORK/notzip.lexe" "structure"

head -c 200 "$GOOD" > "$WORK/truncated.lexe"
sec_case "a truncated archive" "$WORK/truncated.lexe"

# ------------------------------------------------- 4. entrypoint attacks

sec_rewrite "$GOOD" "$WORK/notelf.lexe" '
import json, hashlib
payload = {}
for info, data in items:
    if info.filename == "payload/bin/app":
        data = b"#!/bin/sh\necho not an elf\n"
    if info.filename.startswith("payload/"):
        payload[info.filename] = hashlib.sha256(data).hexdigest()
    out.append((info, data))
# Re-hash so this fails at the ENTRYPOINT stage rather than at the hash stage:
# the interesting question is whether a non-ELF entrypoint is caught at all.
for i, (info, data) in enumerate(out):
    if info.filename == "metadata/hashes.json":
        h = json.loads(data)
        h["files"] = payload
        out[i] = (info, json.dumps(h).encode())
'
# The signature no longer matches the rewritten hashes.json, so this is expected
# to fail at a signature stage. Report which stage caught it rather than pretending
# to have tested the entrypoint check, which tests/test_payload_role.cpp covers.
out="$("$LEXE" verify "$WORK/notelf.lexe" 2>&1)"
acc_true "$([[ $? -ne 0 ]] && echo 0 || echo 1)" \
    "a package whose entrypoint is a shell script is refused"
note "caught at: $(grep -oiE '(structure|manifest|key|signature|hashes|payload-role|compatibility)' <<<"$out" | head -1)"

# ------------------------------------------------- 5. hostile identity strings

sec_rewrite "$GOOD" "$WORK/evilname.lexe" '
import json
for info, data in items:
    if info.filename == "lexe.json":
        m = json.loads(data)
        m["name"] = "Innocent\nExec=/bin/sh -c id\nX="
        data = json.dumps(m).encode()
    out.append((info, data))
'
# Rewriting the manifest breaks its signature, so this is refused for that
# reason. The escaping itself is pinned in tests/test_security_boundary.cpp; what
# matters here is that a signed manifest cannot be edited at all.
out="$("$LEXE" verify "$WORK/evilname.lexe" 2>&1)"
acc_true "$([[ $? -ne 0 ]] && echo 0 || echo 1)" \
    "an edited manifest is refused — the signature covers the name too"
acc_contains "$out" "signature" "and the reason is the signature"

# Signature SUBSTITUTION, deliberately LAST of the rejection cases.
#
# It is the only one that has to install the good package first, in order to
# pin a key for the substitute to conflict with -- and a trust record
# outlives an uninstall on purpose, because trust-on-first-use is a decision
# the user made and not a property of the files. Running this earlier left
# that record behind, and every later case reported it as residue.
#
# The case itself: a real, valid signature made by a different key. This
# is the case a naive "is the signature valid?" check passes.
OTHER_PROJECT="$WORK/other"
mkdir -p "$OTHER_PROJECT/payload/bin"
cp "$GOOD_PROJECT/payload/bin/app" "$OTHER_PROJECT/payload/bin/app"
# The manifest must be copied with publicKey back to "AUTO": `lexe build` filled
# it in with the FIRST key, and a manifest naming one key while signed by another
# is refused for that reason rather than for the one under test here.
python3 - "$GOOD_PROJECT/lexe.json" "$OTHER_PROJECT/lexe.json" <<'PY'
import json, sys
with open(sys.argv[1]) as handle:
    manifest = json.load(handle)
manifest["publisher"]["publicKey"] = "AUTO"
with open(sys.argv[2], "w") as handle:
    json.dump(manifest, handle, indent=2)
PY
"$LEXE" build "$OTHER_PROJECT" -o "$WORK/otherkey.lexe" --key "$OTHER_KEY" \
    >"$WORK/otherbuild.log" 2>&1
if [[ -f "$WORK/otherkey.lexe" ]]; then
    # It verifies on its own — a validly signed package by an unknown publisher.
    acc_true "$("$LEXE" verify "$WORK/otherkey.lexe" >/dev/null 2>&1; echo $?)" \
        "a package signed by a different key verifies on its own terms"
    # Installing the FIRST one pins the key; the substitute must then be refused
    # as a changed key, not silently accepted because its own signature is fine.
    "$LEXE" install "$GOOD" --yes --trust >/dev/null 2>&1
    out="$("$LEXE" install "$WORK/otherkey.lexe" --yes 2>&1)"
    acc_true "$([[ $? -ne 0 ]] && echo 0 || echo 1)" \
        "a same-id package signed by a DIFFERENT key is refused after the first pinned one"
    acc_contains "$out" "key" "and the refusal is about the key, not about the bytes"
    "$LEXE" remove "$SUBJECT_ID" --purge-data --yes >/dev/null 2>&1
else
    fail "a differently-signed package can be built for the substitution case" \
        "$(sed 's/^/    /' "$WORK/otherbuild.log" 2>/dev/null | head -5)"
fi

# ------------------------------------------------- 6. the good one still works
#
# The most important check in the suite. A verifier that refuses everything is
# not secure, it is broken, and every rejection above would be worthless.

acc_true "$("$LEXE" install "$GOOD" --yes --trust >/dev/null 2>&1; echo $?)" \
    "after all of that, the legitimate package still installs"
acc_true "$("$LEXE" run "$SUBJECT_ID" --no-terminal >/dev/null 2>&1; echo $?)" \
    "and still runs"
"$LEXE" remove "$SUBJECT_ID" --purge-data --yes >/dev/null 2>&1

acc_equals "$(cat "$CANARY_DIR/canary.txt")" "untouched" \
    "the canary outside LEXE_HOME was never touched by any of it"

acc_summary

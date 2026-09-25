#!/usr/bin/env bash
# 05 — portable code and host-ISA compilation (Definitive Architecture §5/§7,
# FORMAT-0.1 §5.8 and §6.9).
#
# The acceptance question is the architecture's promise, end to end: does ONE
# .lexe carrying source become a native program on the machine it lands on, and
# does the machine's owner stay in control of that happening?
#
#   1. a portable package verifies as source, with no prebuilt entrypoint
#   2. installing it WITHOUT approval is refused, and installs nothing
#   3. installing it WITH approval compiles it here and records what it did
#   4. there is no way to build it unconfined — not even when the sandbox is gone
#   5. the compiled entrypoint is a host-ISA ELF, and it runs natively
#   6. that compiled binary is tamper-protected exactly like an extracted one
#
# Headless by construction: lib.sh severs WAYLAND_DISPLAY and DISPLAY before
# anything runs, and this example is a console program that never opens a window.
set -uo pipefail
ACC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$ACC_DIR/lib.sh"
acc_begin "05 portable compile"
acc_require_binaries
acc_scratch_home

PORTABLE_EXAMPLE="$ACC_REPO/examples/portable-hello"
PORTABLE_ID="com.usha.portablehello"
PORTABLE_VERSION="1.0.0"
PORTABLE_ENTRY="bin/portable-hello"

# The host has to be able to compile at all. Say so rather than reporting a
# pass or a failure that is really about this machine.
missing=()
for tool in make cc; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [[ ${#missing[@]} -gt 0 ]]; then
    skip "this host is missing ${missing[*]} — the portable path cannot be exercised"
    acc_summary
    exit $?
fi

# --------------------------------------------------------------- package it

work="$ACC_ROOT/work"
project="$work/portable-hello"
key="$work/key.json"
package="$work/portable-hello.lexe"
mkdir -p "$project"
cp -r "$PORTABLE_EXAMPLE/lexe.json" "$PORTABLE_EXAMPLE/payload" "$project/"
"$LEXE" keygen "$key" >/dev/null
if ! "$LEXE" build "$project" -o "$package" --key "$key" >"$work/build.log" 2>&1; then
    fail "lexe build packaged the portable example" "$(sed 's/^/    /' "$work/build.log")"
    acc_summary
    exit $?
fi
pass "lexe build packaged a source-only project"

# 1. It verifies, and the payload-role stage says what it checked.
verify_out="$("$LEXE" verify "$package" 2>&1)"
acc_true "$?" "the portable package passes the full verification pipeline"
acc_contains "$verify_out" "portable" \
    "payload-role reports the package as portable source"
acc_contains "$verify_out" "compiled for this host at install" \
    "payload-role says the entrypoint is produced at install, not shipped"

# The entrypoint really is absent from the archive — that is the rule, and a
# third party (unzip) is a better witness for it than the runtime.
if command -v unzip >/dev/null 2>&1; then
    listing="$(unzip -Z1 "$package" 2>/dev/null)"
    if [[ "$listing" == *"payload/src/main.c"* ]]; then
        pass "the archive carries the source"
    else
        fail "the archive carries the source" "entries: $listing"
    fi
    if [[ "$listing" != *"payload/$PORTABLE_ENTRY"* ]]; then
        pass "the archive does NOT carry the entrypoint it declares"
    else
        fail "the archive does NOT carry the entrypoint it declares" \
            "found payload/$PORTABLE_ENTRY in the package"
    fi
else
    skip "unzip is not installed — cannot witness the archive contents independently"
fi

info_out="$("$LEXE" info "$package" 2>&1)"
acc_contains "$info_out" "Portable source, compiled on this machine" \
    "lexe info says what installing this package will DO"

# ------------------------------------------- 2. refused without approval

refused="$("$LEXE" install "$package" --yes --trust 2>&1)"
refused_code=$?
acc_equals "$refused_code" "5" \
    "installing without approval exits 5 (permission required)"
acc_contains "$refused" "compiles its source on this machine" \
    "the refusal says what it is refusing to do"
acc_contains "$refused" "--approve-compile" \
    "the refusal names the flag that authorizes it"
acc_contains "$refused" "grants the build no privileges" \
    "the refusal says what approval does NOT grant"
acc_file_absent "$LEXE_HOME/apps/$PORTABLE_ID/installation.json" \
    "nothing was installed by the refused attempt"

# A refusal is a failure with a diagnosis, like every other hard gate (§9).
record="$(find "$LEXE_HOME/state/errors/$PORTABLE_ID" -name '*.json' 2>/dev/null | sort | tail -1)"
if [[ -n "$record" ]]; then
    pass "the refusal produced a structured error record"
    acc_equals "$(acc_json "$record" 'd["stage"]')" "compile" \
        'the record is at stage "compile"'
else
    fail "the refusal produced a structured error record"
fi

# --------------------------------- 3/4. no sandbox means no build, ever

no_sandbox="$(LEXE_BWRAP="$ACC_ROOT/definitely-not-bwrap" \
    "$LEXE" install "$package" --yes --trust --approve-compile 2>&1)"
acc_true "$([[ $? -ne 0 ]] && echo 0 || echo 1)" \
    "an approved install still fails when there is no sandbox to build in"
acc_contains "$no_sandbox" "refusing to build unconfined" \
    "it refuses to build unconfined rather than falling back"
acc_file_absent "$LEXE_HOME/apps/$PORTABLE_ID/installation.json" \
    "the unconfined-build refusal installed nothing"

# ------------------------------------------- 5. approved install compiles

install_out="$("$LEXE" install "$package" --yes --trust --approve-compile 2>&1)"
install_code=$?
acc_equals "$install_code" "0" "the approved install succeeds"
acc_contains "$install_out" "carries source, not a program" \
    "the install says a compile is about to happen, before it happens"
acc_contains "$install_out" "network denied" \
    "the install states the conditions the build runs under"

version_dir="$LEXE_HOME/apps/$PORTABLE_ID/versions/$PORTABLE_VERSION"
entry="$version_dir/$PORTABLE_ENTRY"
acc_file_exists "$entry" "the build produced the declared entrypoint"

host_isa="$("$LEXE" version --json 2>/dev/null | acc_json - 'd.get("hostIsa", "")' 2>/dev/null || true)"
[[ -n "$host_isa" ]] || host_isa="$(uname -m)"

if command -v file >/dev/null 2>&1; then
    file_out="$(file -b "$entry")"
    acc_contains "$file_out" "ELF" \
        "an independent tool agrees the entrypoint is an ELF executable"
else
    skip "file(1) is not installed — cannot witness the ELF independently"
fi

# The source was never in the version directory as a program, and the compiled
# entrypoint was never in the package. Both halves, asserted.
acc_file_exists "$version_dir/src/main.c" \
    "the source is installed alongside what was built from it"

# What the runtime recorded about the build.
build_record="$LEXE_HOME/apps/$PORTABLE_ID/meta/$PORTABLE_VERSION/build.json"
acc_file_exists "$build_record" "the build is recorded per version"
if [[ -f "$build_record" ]]; then
    acc_equals "$(acc_json "$build_record" 'd["schema"]')" "lexe.build/1" \
        "the build record declares its schema"
    acc_equals "$(acc_json "$build_record" 'd["buildSystem"]')" "make" \
        "the record names the build system that ran"
    acc_equals "$(acc_json "$build_record" 'd["hostIsa"]')" "$host_isa" \
        "the record names the ISA the output was verified against"
    acc_equals "$(acc_json "$build_record" 'str(d["approval"]["granted"])')" "True" \
        "the record carries the approval that authorized the compile"
    acc_equals "$(acc_json "$build_record" 'd["approval"]["authority"]')" "user" \
        "the approval says whose decision it was, without inventing an admin"
    acc_contains "$(acc_json "$build_record" 'str(sorted(t["name"] for t in d["toolchain"]))')" \
        "make" "the record names the toolchain that was actually used"
    recorded_hash="$(acc_json "$build_record" 'd["products"]["payload/'"$PORTABLE_ENTRY"'"]')"
    actual_hash="$(sha256sum "$entry" | cut -d' ' -f1)"
    acc_equals "$recorded_hash" "$actual_hash" \
        "the recorded product hash is the hash of what was built"
fi

# It runs, and it runs natively.
run_out="$("$LEXE" run "$PORTABLE_ID" --no-terminal -- --selftest one 2>&1)"
run_code=$?
acc_equals "$run_code" "0" "the compiled application runs and exits 0"
acc_contains "$run_out" "selftest: PASS" \
    "the application confirms its private data root from inside the sandbox"
acc_contains "$run_out" "compiled for:             $host_isa" \
    "the program itself reports the ISA its compiler targeted"
acc_contains "$run_out" "LEXE_APP_ID:              $PORTABLE_ID" \
    ".LEXE launched it — nothing exec'd a raw ELF"
acc_contains "$run_out" "arg: one" "arguments reach the compiled program"

chain="$(acc_json "$LEXE_HOME/apps/$PORTABLE_ID/installation.json" \
    'd.get("lastExecution", {}).get("chain", "")')"
acc_equals "$chain" "native" \
    "the execution report records the native chain — a compiled portable package IS native"

# ------------------------------- 6. tamper protection and rebuild-on-repair

printf '\xff' | dd of="$entry" bs=1 seek=1024 conv=notrunc status=none 2>/dev/null
tampered="$("$LEXE" run "$PORTABLE_ID" --no-terminal 2>&1)"
acc_true "$([[ $? -ne 0 ]] && echo 0 || echo 1)" \
    "a tampered COMPILED entrypoint is refused, like a tampered extracted one"
acc_contains "$tampered" "integrity check" \
    "the refusal names the integrity check that failed"
acc_contains "$tampered" "--approve-compile" \
    "the refusal points at the repair that rebuilds it"

repair_refused="$("$LEXE" repair "$PORTABLE_ID" 2>&1)"
acc_equals "$?" "5" "repairing without approval exits 5 — repair never silently compiles"
acc_contains "$repair_refused" "compiling its source again" \
    "the repair refusal explains that repair means rebuilding here"

repaired="$("$LEXE" repair "$PORTABLE_ID" --approve-compile 2>&1)"
acc_true "$?" "repair with approval rebuilds the entrypoint"
acc_contains "$repaired" "$PORTABLE_ENTRY" "the repair names what it rebuilt"

acc_true "$("$LEXE" run "$PORTABLE_ID" --no-terminal >/dev/null 2>&1 && echo 0 || echo 1)" \
    "the application runs again after the rebuild"

# Removing the build record must not silently downgrade to "unchecked".
mv "$build_record" "$build_record.moved"
no_record="$("$LEXE" run "$PORTABLE_ID" --no-terminal 2>&1)"
acc_true "$([[ $? -ne 0 ]] && echo 0 || echo 1)" \
    "FAIL CLOSED: with no build record the compiled entrypoint is not run"
acc_contains "$no_record" "no build record" \
    "the refusal names the missing build record as the reason"
mv "$build_record.moved" "$build_record"

acc_summary

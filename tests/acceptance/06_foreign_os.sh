#!/usr/bin/env bash
# 06 — foreign-OS payloads (Definitive Architecture §8, FORMAT-0.1 §5.3/§6.7).
#
# The acceptance question: does a `.lexe` carrying a WINDOWS program actually
# start that program on Linux, under the sandbox, with the user able to see
# what layer is doing it and what their machine is missing?
#
#   1. a Windows payload verifies as a runnable PE, and the three ways it can
#      be wrong are all refused before install
#   2. a Windows package that permits no chain able to run it cannot be built
#   3. it installs, and `lexe compat` names the chain and the reasons
#   4. it RUNS — the PE really executes, sandboxed, with its arguments and its
#      private data root intact across the Wine boundary
#   5. Wine's own state lands in the application's private data root, and
#      nothing of the host session is visible
#
# Headless by construction: lib.sh severs WAYLAND_DISPLAY and DISPLAY, and this
# example is a console program. Steps 3-5 need Wine and MinGW on the host and
# say so when they are absent rather than passing vacuously.
set -uo pipefail
ACC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$ACC_DIR/lib.sh"
acc_begin "06 foreign os"
acc_require_binaries
acc_scratch_home

WIN_EXAMPLE="$ACC_REPO/examples/windows-hello"
WIN_ID="com.usha.windowshello"
WIN_VERSION="1.0.0"
WIN_ENTRY="bin/windows-hello.exe"

have_mingw=0
have_wine=0
command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 && have_mingw=1
command -v wine >/dev/null 2>&1 && have_wine=1

if [[ $have_mingw -eq 0 ]]; then
    skip "x86_64-w64-mingw32-gcc is not installed — cannot build a Windows payload"
    acc_summary
    exit $?
fi

work="$ACC_ROOT/work"
project="$work/windows-hello"
key="$work/key.json"
package="$work/windows-hello.lexe"
mkdir -p "$project"
cp -r "$WIN_EXAMPLE/lexe.json" "$WIN_EXAMPLE/src" "$WIN_EXAMPLE/Makefile" "$project/"
if ! make -s -C "$project" >"$work/make.log" 2>&1; then
    fail "the Windows payload cross-compiles" "$(sed 's/^/    /' "$work/make.log")"
    acc_summary
    exit $?
fi
pass "the Windows payload cross-compiles with MinGW"

"$LEXE" keygen "$key" >/dev/null
if ! "$LEXE" build "$project" -o "$package" --key "$key" >"$work/build.log" 2>&1; then
    fail "lexe build packaged the Windows example" "$(sed 's/^/    /' "$work/build.log")"
    acc_summary
    exit $?
fi
pass "lexe build packaged a Windows payload"

# --------------------------------------------- 1. it is what it claims to be

verify_out="$("$LEXE" verify "$package" 2>&1)"
acc_true "$?" "the Windows package passes the full verification pipeline"
acc_contains "$verify_out" "windows" \
    "payload-role reports the package as a Windows payload"
acc_contains "$verify_out" "runnable Windows executable" \
    "payload-role says it checked the entrypoint is runnable"

if command -v file >/dev/null 2>&1; then
    acc_contains "$(file -b "$project/payload/$WIN_ENTRY")" "PE32+" \
        "an independent tool agrees the payload is a Windows PE"
fi

info_out="$("$LEXE" info "$package" 2>&1)"
acc_contains "$info_out" "run through a compatibility layer" \
    "lexe info never calls it just a Windows application"

# The three ways a Windows package can be wrong, all refused before install.
bad_project="$work/bad"
mkdir -p "$bad_project/payload/bin"
cp "$project/lexe.json" "$bad_project/lexe.json"

# (a) a Linux binary wearing a .exe name
cp "$LEXE" "$bad_project/payload/$WIN_ENTRY"
"$LEXE" build "$bad_project" -o "$work/elf.lexe" --key "$key" >/dev/null 2>&1
elf_out="$("$LEXE" verify "$work/elf.lexe" 2>&1)"
acc_contains "$elf_out" "not a Windows PE image" \
    "a Linux binary named .exe is refused"

# (b) a DLL, which nothing can launch. Wine ships real ones; the path differs
# between distributions, so look rather than assume.
real_dll="$(find /usr/lib /usr/lib64 -name '*.dll' -path '*x86_64-windows*' \
    2>/dev/null | head -1)"
if [[ -n "$real_dll" ]]; then
    cp "$real_dll" "$bad_project/payload/$WIN_ENTRY"
    "$LEXE" build "$bad_project" -o "$work/dll.lexe" --key "$key" >/dev/null 2>&1
    dll_out="$("$LEXE" verify "$work/dll.lexe" 2>&1)"
    acc_contains "$dll_out" "DLL" "a real Windows DLL is refused as an entrypoint"
else
    skip "no Windows DLL on this host to test the DLL refusal against"
fi

# (c) a package that permits no chain able to run it
no_chain="$work/nochain"
mkdir -p "$no_chain"
cp -r "$project/payload" "$no_chain/"
python3 - "$project/lexe.json" "$no_chain/lexe.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
m["execution"]["allowedChains"] = ["native"]
json.dump(m, open(sys.argv[2], "w"), indent=2)
PY
nochain_out="$("$LEXE" build "$no_chain" -o "$work/nochain.lexe" --key "$key" 2>&1)"
acc_true "$([[ $? -ne 0 ]] && echo 0 || echo 1)" \
    "a Windows package permitting only native cannot even be built"
acc_contains "$nochain_out" "foreign-OS execution chain" \
    "the refusal says what is missing from the policy"

# ------------------------------------------------- 3. install and resolution

install_out="$("$LEXE" install "$package" --yes --trust 2>&1)"
acc_true "$?" "the Windows package installs"
acc_contains "$(acc_json "$(acc_installation_for "$WIN_ID")" \
    'd.get("runtime", {}).get("source", "")')" "foreign-os" \
    "the runtime contract records a foreign-OS payload, not an empty ELF analysis"

compat_out="$("$LEXE" compat "$WIN_ID" 2>&1)"
if [[ $have_wine -eq 1 ]]; then
    acc_contains "$compat_out" "Execution chain: wine" \
        "lexe compat resolves the application to Wine"
    acc_contains "$compat_out" "foreign-OS binary on Linux" \
        "it explains what that chain does"
else
    acc_contains "$compat_out" "none available" \
        "with no layer installed, no chain is claimed"
fi
# The property under test is that a chain the package PERMITS but the host
# cannot provide is reported with a reason rather than quietly omitted. It used
# to be asserted by looking for "Proton is not installed on this host", which
# made the check depend on this machine not having Proton — so it broke the day
# Proton was installed to test the Proton chain, while the behaviour was fine.
#
# Ask the question the test actually means instead: every chain the package
# permits must be accounted for, either as the selected one or with a stated
# reason.
for permitted in $(acc_json_str "$("$LEXE" compat "$WIN_ID" --json 2>/dev/null)" \
        '" ".join(d.get("allowedByPackage", []))'); do
    acc_contains "$compat_out" "$permitted" \
        "the permitted chain \"$permitted\" is accounted for, not hidden"
done

# And specifically: a permitted chain that is NOT the selected one must carry a
# reason, which is the half that would regress silently.
unavailable="$(acc_json_str "$("$LEXE" compat "$WIN_ID" --json 2>/dev/null)" \
    'next((c["id"] for c in d.get("rejected", [])), "")')"
if [[ -n "$unavailable" ]]; then
    reason="$(acc_json_str "$("$LEXE" compat "$WIN_ID" --json 2>/dev/null)" \
        'next((c["reason"] for c in d.get("rejected", [])), "")')"
    acc_true "$([[ -n "$reason" ]] && echo 0 || echo 1)" \
        "the unusable chain \"$unavailable\" states why: $reason"
else
    note "every chain this package permits is available on this host"
fi

# ------------------------------------------------------------- 4/5. it RUNS

if [[ $have_wine -eq 0 ]]; then
    skip "wine is not installed — the Windows program cannot actually be run here"
    run_out="$("$LEXE" run "$WIN_ID" --no-terminal 2>&1)"
    acc_true "$([[ $? -ne 0 ]] && echo 0 || echo 1)" \
        "without a layer the launch is refused, not attempted"
    acc_contains "$run_out" "no execution chain" \
        "the refusal names the missing capability"
    acc_summary
    exit $?
fi

run_out="$(timeout 300 "$LEXE" run "$WIN_ID" --no-terminal -- --selftest one "two words" 2>&1)"
run_code=$?
acc_equals "$run_code" "0" "the Windows program runs and exits 0"
acc_contains "$run_out" "this is a Windows PE running on Linux" \
    "the PE really executed"
acc_contains "$run_out" "selftest: PASS" \
    "it wrote into its private data root and read it back, from inside Windows"
acc_contains "$run_out" "LEXE_APP_ID:          $WIN_ID" \
    "the .LEXE environment crosses the compatibility boundary intact"
acc_contains "$run_out" "arg: one" "arguments reach the Windows program"
acc_contains "$run_out" "arg: two words" "an argument with a space stays one argument"

chain="$(acc_json "$(acc_installation_for "$WIN_ID")" \
    'd.get("lastExecution", {}).get("chain", "")')"
acc_equals "$chain" "wine" "the execution report records the chain that ran it"

# Wine's own state belongs to the application, not to the user's home.
data_dir="$LEXE_HOME/data/$WIN_ID"
acc_true "$([[ -d "$data_dir/.wine" ]] && echo 0 || echo 1)" \
    "Wine's prefix lands in the application's private data root"
acc_file_exists "$data_dir/windows-hello-launches.log" \
    "the launch is provable from the private data root alone"

# A second launch reuses the prefix rather than rebuilding or failing.
second="$(timeout 300 "$LEXE" run "$WIN_ID" --no-terminal 2>&1)"
acc_true "$?" "a second launch works against the existing prefix"
acc_contains "$second" "this is a Windows PE running on Linux" \
    "the second launch really ran too"
acc_equals "$(wc -l < "$data_dir/windows-hello-launches.log" | tr -d ' ')" "2" \
    "the payload recorded both of its starts in the same private data root"

# Nothing of the host session is reachable from inside.
leaks="$(find "$data_dir" -maxdepth 3 \( -name 'wayland-*' -o -name 'bus' \
    -o -name 'pulse' \) 2>/dev/null | head -3)"
acc_equals "$leaks" "" \
    "no session socket of the host was copied or bound into the app's data"

acc_summary

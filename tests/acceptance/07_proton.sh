#!/usr/bin/env bash
# 07 — the Proton chain (Definitive Architecture §8, FORMAT-0.1 §5.3).
#
# Suite 06 proves a Windows payload runs through WINE. This one asks the harder
# question, because "Steam and Proton exist on this machine" is not evidence that
# anything ran through them:
#
#   1. the runtime FINDS Proton where Proton actually lives
#   2. it invokes Proton the way Proton is invoked
#   3. a Windows PE really executes through the Proton chain
#   4. the execution report names `proton`, not `wine`
#   5. Proton's prefix is the application's state, not the user's
#   6. an undeclared chain is still refused, and a mission-critical package
#      cannot reach Proton at all
#
# Every one of those was broken when this suite was written, and all of it looked
# implemented:
#
#   * discovery was a $PATH lookup for a binary named `proton`. Proton is not a
#     distribution package and is never on $PATH, so on a machine with Proton
#     installed the probe answered "not installed on this host" and every Proton
#     chain resolved as unavailable. The failure read as policy, not as a bug.
#   * the chain invoked `proton <exe>`. Proton's entry point is a Python
#     dispatcher that requires a VERB; without one it runs nothing.
#   * nothing set STEAM_COMPAT_DATA_PATH or STEAM_COMPAT_CLIENT_INSTALL_PATH.
#     Proton exits 1 without either — "No compat data path?" for the first, a
#     Python KeyError for the second.
#
# Headless by construction: lib.sh severs the display, and the payload is a
# console program. BLOCKED, not skipped, when this host has no Proton: the
# capability is claimed, so a machine that cannot show it is a gap and not a
# non-applicable case.
set -uo pipefail
ACC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$ACC_DIR/lib.sh"
acc_begin "07 proton"
acc_require_binaries
acc_scratch_home

WIN_EXAMPLE="$ACC_REPO/examples/windows/console-hello"
[[ -d "$WIN_EXAMPLE" ]] || WIN_EXAMPLE="$ACC_REPO/examples/windows-hello"
WIN_ID="com.usha.windowshello"

if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    skip "x86_64-w64-mingw32-gcc is not installed — cannot build a Windows payload"
    acc_summary
    exit $?
fi

# --------------------------------------------- 1. discovery, before anything runs
#
# Asked through the CLI rather than by looking for Proton ourselves, so what is
# under test is the runtime's own discovery and not the test's.
runtime_json="$("$LEXE" runtime show proton --json 2>/dev/null)"
proton_found="$(acc_json_str "$runtime_json" 'str(d.get("available", False))')"
proton_path="$(acc_json_str "$runtime_json" 'd.get("executable", "")')"
searched="$(acc_json_str "$runtime_json" 'str(len(d.get("searched", [])))')"

acc_true "$([[ "$searched" != "0" ]] && echo 0 || echo 1)" \
    "discovery looks somewhere other than \$PATH ($searched candidate locations)"

if [[ "$proton_found" != "True" ]]; then
    blocked "no Proton installation on this host — the Proton chain cannot be demonstrated" \
        "The runtime searched $searched locations and found none." \
        "Install a Proton build under ~/.steam/root/compatibilitytools.d/," \
        "or point LEXE_PROTON at one. See docs/TESTING.md §4."
    acc_summary
    exit $?
fi
pass "the runtime found Proton where Proton actually lives"
note "$proton_path"

# It must not have been found on $PATH — that is the mechanism that did not work.
acc_equals "$(command -v proton || true)" "" \
    "and it is genuinely not on \$PATH, so a PATH-only probe would have missed it"

origin="$(acc_json_str "$runtime_json" 'd.get("origin", "")')"
acc_true "$([[ -n "$origin" ]] && echo 0 || echo 1)" \
    "the runtime says HOW it found it: $origin"

# --------------------------------------------- 2. build and install the payload

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
    fail "lexe build packaged a Windows payload" "$(sed 's/^/    /' "$work/build.log")"
    acc_summary
    exit $?
fi
pass "lexe build packaged a Windows payload"

if ! "$LEXE" install "$package" --yes --trust >"$work/install.log" 2>&1; then
    fail "the Windows package installs" "$(sed 's/^/    /' "$work/install.log")"
    acc_summary
    exit $?
fi
pass "the Windows package installs"

# --------------------------------------------- 3. the chain resolves to Proton
#
# The example permits both wine and proton and Wine sorts first, so Proton has to
# be ASKED for. That is the honest test anyway: a user pinning a permitted chain.
if ! "$LEXE" compat "$WIN_ID" --set proton >"$work/compat.log" 2>&1; then
    fail "a permitted chain can be pinned" "$(sed 's/^/    /' "$work/compat.log")"
    acc_summary
    exit $?
fi
pass "the proton chain can be pinned, because the package permits it"

compat_json="$("$LEXE" compat "$WIN_ID" --json 2>/dev/null)"
acc_equals "$(acc_json_str "$compat_json" 'd.get("chain", "")')" "proton" \
    "the resolver selects proton for this application"

# --------------------------------------------- 4. it actually runs

run_out="$(timeout 600 "$LEXE" run "$WIN_ID" --no-terminal -- --selftest one "two words" 2>&1)"
run_status=$?
acc_true "$run_status" "the Windows program runs through Proton and exits 0" \
    "$(printf '%s' "$run_out" | tail -20 | sed 's/^/    /')"

acc_contains "$run_out" "this is a Windows PE running on Linux" \
    "the PE really executed — its own stdout crossed the Proton boundary"
acc_contains "$run_out" "selftest: PASS" \
    "it wrote into its private data root and read it back, from inside Windows"
acc_contains "$run_out" "LEXE_APP_ID:          $WIN_ID" \
    "the .LEXE environment survives the Proton boundary"
acc_contains "$run_out" "arg: one" "arguments reach the Windows program"
acc_contains "$run_out" "arg: two words" "an argument with a space stays one argument"

# --------------------------------------------- 5. the record says proton

chain="$(acc_json "$(acc_installation_for "$WIN_ID")" \
    'd.get("lastExecution", {}).get("chain", "")')"
acc_equals "$chain" "proton" \
    "the execution report records proton — not wine, and not a guess"

# --------------------------------------------- 6. Proton's state is the app's
#
# STEAM_COMPAT_DATA_PATH points inside the sandbox at /run/lexe/data/.proton,
# which is this directory on the host. If it landed anywhere else, Proton's
# prefix would be the user's state and --purge-data would not remove it.
data_dir="$LEXE_HOME/data/$WIN_ID"
acc_true "$([[ -d "$data_dir/.proton/pfx" ]] && echo 0 || echo 1)" \
    "Proton's prefix lands in the application's private data root"
acc_file_exists "$data_dir/windows-hello-launches.log" \
    "the launch is provable from the private data root alone"

# Nothing of the user's real Steam installation may be reachable or copied in.
acc_equals "$(find "$data_dir" -maxdepth 4 -name 'steamapps' 2>/dev/null | head -1)" "" \
    "no part of the host Steam library was copied into the application's data"
acc_equals "$(find "$data_dir" -maxdepth 3 \( -name 'wayland-*' -o -name 'bus' \) \
    2>/dev/null | head -1)" "" \
    "no session socket of the host was bound into the app's data"

# A second launch reuses the prefix rather than rebuilding it or failing.
second="$(timeout 600 "$LEXE" run "$WIN_ID" --no-terminal 2>&1)"
acc_true "$?" "a second launch works against the existing Proton prefix"
acc_contains "$second" "this is a Windows PE running on Linux" \
    "the second launch really ran too"
acc_equals "$(wc -l < "$data_dir/windows-hello-launches.log" | tr -d ' ')" "2" \
    "the payload recorded both of its starts in the same private data root"

# --------------------------------------------- 7. policy still holds
#
# Finding and fixing Proton must not have widened what a package permits.
native_refusal="$("$LEXE" compat "$WIN_ID" --set native 2>&1)"
acc_true "$([[ $? -ne 0 ]] && echo 0 || echo 1)" \
    "a chain the package does not permit is still refused"
acc_contains "$native_refusal" "does not permit" \
    "and the refusal says so in those terms"

mc_project="$work/mission-critical"
mkdir -p "$mc_project"
cp -r "$project/lexe.json" "$project/src" "$project/Makefile" "$mc_project/"
python3 - "$mc_project/lexe.json" <<'PY'
import json, sys
path = sys.argv[1]
with open(path) as handle:
    manifest = json.load(handle)
manifest["id"] = "com.usha.windowsmission"
manifest["execution"] = {"missionCritical": True, "allowedChains": ["proton"]}
with open(path, "w") as handle:
    json.dump(manifest, handle, indent=2)
PY
make -s -C "$mc_project" >/dev/null 2>&1
mc_out="$("$LEXE" build "$mc_project" -o "$work/mc.lexe" --key "$key" 2>&1)"
acc_true "$([[ $? -ne 0 ]] && echo 0 || echo 1)" \
    "a mission-critical package may not declare Proton, and cannot even be built"
acc_contains "$mc_out" "missionCritical" \
    "the refusal names the contradiction rather than failing obscurely"

acc_summary

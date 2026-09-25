#!/usr/bin/env bash
# 04 — the native happy path has no compatibility process.
#
# Definitive Architecture acceptance criterion covered here:
#   * "For the native happy path, confirm the launched process is the native
#      application with no unnecessary compatibility process in the steady-state
#      execution path."
#
# Two independent proofs are required, because either alone is weak:
#   * the RECORDED chain (installation.json lastExecution.chain) is "native",
#     which is what .LEXE believes it did, and
#   * the LIVE process tree contains the installed ELF itself and no FEX /
#     Box64 / QEMU / Wine / Proton process, which is what actually happened.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

acc_begin "04 native steady state"
acc_require_binaries
acc_scratch_home
acc_build_package
acc_install_package

payload="$(acc_version_dir)/$ACC_ENTRYPOINT"
installation="$(acc_installation)"

# The chains a compatibility layer would show up as. "native" is the only chain
# this package's signed policy allows in the first place.
ACC_COMPAT_RE='fex|fexbash|FEXInterpreter|box64|box86|qemu-(x86_64|aarch64|user)|wine(server|64)?|proton|hangover|rosetta'

# ------------------------------------------------- what the package declares
manifest="$ACC_ROOT/work/manifest.json"
"$LEXE" inspect "$ACC_PACKAGE" --manifest >"$manifest"
acc_equals "$(acc_json "$manifest" 'str(d["execution"]["allowedChains"])')" "['native']" \
    'the signed policy allows only the "native" chain'
acc_equals "$(acc_json "$manifest" 'str(d["architectures"])')" "['$(uname -m)']" \
    "the package declares this host's ISA, so no ISA translation is needed"

# ------------------------------------------------ what .LEXE says it will do
if "$LEXE" help 2>&1 | grep -q '^  compat'; then
    "$LEXE" compat "$ACC_APP_ID" --json >"$ACC_ROOT/work/compat.json" 2>/dev/null
    acc_equals "$(acc_json "$ACC_ROOT/work/compat.json" 'd["chain"]')" "native" \
        "lexe compat resolves the application to the native chain"
    offered="$(acc_json "$ACC_ROOT/work/compat.json" "str(sorted({c['id'] for c in d.get('alternatives', [])} | {d['chain']}))")"
    acc_equals "$offered" "['native']" "no compatibility chain is even offered for this package"
else
    skip "lexe compat is not in this build"
fi

# ------------------------------------------------- the live process tree
# Hold the payload alive headlessly and look at what is actually running.
holder_log="$ACC_ROOT/work/hold.log"
"$LEXE" run "$ACC_APP_ID" -- --sleep 8 >"$holder_log" 2>&1 &
holder=$!

payload_pid=""
for _ in $(seq 1 60); do
    payload_pid="$(pgrep -f "^$payload " 2>/dev/null | head -1 || true)"
    [[ -n "$payload_pid" ]] || payload_pid="$(pgrep -x -f "$payload --sleep 8" 2>/dev/null | head -1 || true)"
    [[ -n "$payload_pid" ]] && break
    sleep 0.25
done

if [[ -z "$payload_pid" ]]; then
    fail "the installed native ELF is running as its own process" \
        "no process matching $payload was found" "$(cat "$holder_log" || true)"
else
    pass "the installed native ELF is running as its own process"
    exe="$(readlink -f "/proc/$payload_pid/exe" 2>/dev/null || true)"
    acc_equals "$exe" "$(readlink -f "$payload")" \
        "/proc/<pid>/exe IS the installed entrypoint — not an interpreter or loader"

    # Walk the whole tree under `lexe run` and classify every process in it.
    tree="$ACC_ROOT/work/tree.txt"
    : >"$tree"
    collect() {
        local pid="$1" kid
        ps -o pid=,comm=,args= -p "$pid" 2>/dev/null >>"$tree" || true
        for kid in $(pgrep -P "$pid" 2>/dev/null || true); do collect "$kid"; done
    }
    collect "$holder"
    note "process tree under \`lexe run\`:"
    sed 's/^/         /' "$tree" | cut -c1-150

    if grep -qiE "$ACC_COMPAT_RE" "$tree"; then
        fail "no compatibility process appears in the execution path" \
            "matched: $(grep -ioE "$ACC_COMPAT_RE" "$tree" | sort -u | tr '\n' ' ')"
    else
        pass "no compatibility process appears in the execution path"
    fi

    # The steady state is exactly: lexe -> bwrap (the sandbox) -> the payload.
    # bwrap is ISOLATION, not a compatibility layer, and it execs the payload
    # rather than emulating it.
    leaf_count="$(grep -c "$payload" "$tree" || true)"
    acc_true "$([[ "$leaf_count" -ge 1 ]] && echo 0 || echo 1)" \
        "the payload itself is in the tree (not merely an emulator running it)"
    non_sandbox="$(grep -vE "bwrap|$payload|lexe run|/lexe " "$tree" | grep -cE '[a-z]' || true)"
    acc_equals "$non_sandbox" "0" \
        "nothing but the runtime, the sandbox and the payload is in the path"

    # No compatibility provider is even installed on this host.
    if "$LEXE" doctor 2>/dev/null | grep -q "Compatibility:"; then
        compat_line="$("$LEXE" doctor 2>/dev/null | grep -m1 'Compatibility:')"
        note "$compat_line"
    fi
fi

set +e
wait "$holder"
hold_status=$?
set -e
acc_equals "$hold_status" "0" "the native launch completed successfully"

# --------------------------------------- what .LEXE recorded that it DID do
acc_equals "$(acc_json "$installation" 'd["lastExecution"]["chain"]')" "native" \
    "installation.json records lastExecution.chain = native"
acc_equals "$(acc_json "$installation" 'd["lastExecution"]["launchMode"]')" "gui" \
    "installation.json records the declared launch mode"
acc_equals "$(acc_json "$installation" 'd["lastRun"]["exitCode"]')" "0" \
    "installation.json records the successful exit code"

# A GUI launch must not have gone anywhere near a terminal emulator.
acc_equals "$(grep -c 'konsole\|xterm\|gnome-terminal' "$holder_log" || true)" "0" \
    "no terminal emulator was spawned for the GUI application"

# And no error record: a native happy path is not a diagnosable failure.
errdir="$(acc_error_dir)"
records=0
[[ -d "$errdir" ]] && records="$(find "$errdir" -name '*.json' | wc -l | tr -d ' ')"
acc_equals "$records" "0" "the native happy path produced no error record"

acc_summary

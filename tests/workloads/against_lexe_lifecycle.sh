#!/usr/bin/env bash
# tests/workloads/against_lexe_lifecycle.sh — Format 0.1 §9 checked BEHAVIOURALLY.
#
# against_lexe.sh answers "does each program still behave as it did?". This lane
# answers a different question with the same material: do the §9 runtime
# guarantees hold when the thing being guaranteed is a REAL program whose correct
# output is known independently?
#
# Why that distinction earns its own lane. §9.3 says a rollback must restore "the
# content that was originally verified and installed". A hash comparison can show
# the bytes came back. It cannot show that the program those bytes make is the
# program that was there before — for that you have to run it and recognise it,
# and recognising it requires a program whose output you already know. The
# workload corpus is exactly that, so this lane uses two specimens with
# DISTINGUISHABLE oracles and asks the runtime which one it is running.
#
# Same for §9.1/§9.8: "an application that reports as installed MUST be
# launchable, or MUST report honestly that it is damaged — it MUST NOT silently
# be missing files." The only way to test the "silently" is to damage an
# installed payload and see whether the runtime notices, then repair it and check
# the program's BEHAVIOUR is restored rather than merely its digest.
#
# Every specimen used here has a recorded direct-execution baseline, so a wrong
# answer is attributable to the runtime and not to the fixture.
#
# Usage:  tests/workloads/against_lexe_lifecycle.sh
# Env:    LEXE_BUILD_DIR, LEXE_WORKLOAD_ELF_INDEX (see against_lexe.sh)
set -uo pipefail
WL_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$WL_DIR/../acceptance/lib.sh"

acc_begin "workloads: Format 0.1 §9 checked with programs whose behaviour is known"

LEXE_BIN="${LEXE_BUILD_DIR:-$ACC_REPO/build-linux}/lexe"
CORPUS="$(dirname -- "${LEXE_WORKLOAD_ELF_INDEX:-/tmp/lexe-workloads/index.json}")"
BIN="$CORPUS/bin"

[[ -x "$LEXE_BIN" ]] || { blocked "runtime not built at $LEXE_BIN"; acc_summary; exit $?; }
for f in linux-outcome-exit-0 linux-io-both-streams linux-run-bounded-3s; do
    [[ -f "$BIN/$f" ]] || {
        blocked "ELF corpus not generated ($BIN/$f absent)" \
                "regenerate: python3 tests/workloads/generate.py"
        acc_summary; exit $?
    }
done

W="$(mktemp -d /tmp/lexe-wl-lifecycle.XXXXXX)"
export LEXE_HOME="$W/home"
mkdir -p "$LEXE_HOME"
"$LEXE_BIN" keygen "$W/key.json" >/dev/null 2>&1 || {
    fail "lexe keygen failed"; acc_summary; exit $?; }
PUB="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["publicKey"])' "$W/key.json")"

cleanup() {
    "$LEXE_BIN" remove "$APP" --purge-data --yes >/dev/null 2>&1
    rm -rf "$W"
}
APP="wl.lifecycle"
trap cleanup EXIT

# build_and_install <specimen> <version> [args...]
build_and_install() {
    local specimen="$1" version="$2"; shift 2
    local p="$W/pay-$specimen-$version"
    rm -rf "$p"; mkdir -p "$p/bin"
    cp "$BIN/$specimen" "$p/bin/prog"
    python3 - "$W/m.json" "$PUB" "$APP" "$version" "$@" <<'PYEOF'
import json, sys
out, pub, appid, version = sys.argv[1:5]
json.dump({"lexeVersion": "0.1", "id": appid, "name": "workload lifecycle",
           "version": version,
           "publisher": {"name": "workload-corpus", "publicKey": pub},
           "applicationType": "native", "architectures": ["x86_64"],
           "entrypoint": {"executable": "bin/prog", "arguments": sys.argv[5:]},
           "launch": {"mode": "console"},
           "install": {"scope": "user", "mode": "bundled"},
           "permissions": []}, open(out, "w"), indent=2)
PYEOF
    "$LEXE_BIN" pack "$p" --manifest "$W/m.json" --key "$W/key.json" \
        -o "$W/$specimen-$version.lexe" >"$W/pack.log" 2>&1 || {
        fail "pack failed for $specimen $version" "$(tail -3 "$W/pack.log")"; return 1; }
    "$LEXE_BIN" install "$W/$specimen-$version.lexe" --yes --trust \
        >"$W/install.log" 2>&1 || {
        fail "install failed for $specimen $version" "$(tail -3 "$W/install.log")"; return 1; }
}

# Which program is running? Answered from its own oracle, not from a digest.
# Both specimens exit 0 on purpose: the runtime withholds a non-zero-exit
# program's stdout from the caller (reported separately by against_lexe.sh), and
# a lane about rollback should not be measuring that.
whoami_running() {
    local out
    out="$("$LEXE_BIN" run "$APP" 2>/dev/null)"
    if   grep -q '^EXIT_CODE_INTENDED=0$' <<<"$out"; then echo "exit-0"
    elif grep -q '^OUT_TOTAL=8$'          <<<"$out"; then echo "both-streams"
    elif [[ -z "$out" ]];                            then echo "(no output)"
    else echo "(unrecognised)"; fi
}

# ------------------------------------------------------------------ §9.3/§9.1 #
note "§9.3 rollback restores the CONTENT that was verified — checked by running it"

if build_and_install linux-outcome-exit-0 1.0.0; then
    got="$(whoami_running)"
    acc_equals "exit-0" "$got" "v1.0.0 runs the program that was installed as v1.0.0"

    if build_and_install linux-io-both-streams 2.0.0; then
        got="$(whoami_running)"
        acc_equals "both-streams" "$got" "after update, v2.0.0 runs the NEW program"

        "$LEXE_BIN" rollback "$APP" >"$W/rb.log" 2>&1
        rb=$?
        acc_true "$([[ $rb -eq 0 ]] && echo 0 || echo 1)" \
                 "lexe rollback succeeds" "$(tail -3 "$W/rb.log")"
        got="$(whoami_running)"
        acc_equals "exit-0" "$got" \
            "after rollback the program that RUNS is the original one, recognised by its own oracle"
    fi
fi

# --------------------------------------------------------------------- §9.8 #
note "§9.1/§9.8 damaged installed content is reported, never silently executed"

VDIR="$LEXE_HOME/apps/$APP/versions/1.0.0"
if [[ -f "$VDIR/bin/prog" ]]; then
    cp "$VDIR/bin/prog" "$W/pristine"
    # One byte, deep inside .text — a modification, not a truncation, so the file
    # still looks like a valid ELF and only a digest can tell.
    python3 - "$VDIR/bin/prog" <<'PYEOF'
import sys
p = sys.argv[1]
d = bytearray(open(p, "rb").read())
i = len(d) // 2
d[i] ^= 0xFF
open(p, "wb").write(bytes(d))
PYEOF
    out="$("$LEXE_BIN" run "$APP" 2>"$W/dmg.err")"; rc=$?
    if [[ "$out" == *"EXIT_CODE_INTENDED=0"* ]]; then
        fail "a MODIFIED installed payload was executed and reported success" \
             "the runtime ran a binary whose bytes no longer match what it verified" \
             "exit=$rc"
    else
        pass "a modified installed payload is not silently executed (exit $rc)"
    fi

    # And does the runtime SAY it is damaged when asked?
    if "$LEXE_BIN" repair "$APP" >"$W/repair.log" 2>&1; then
        pass "lexe repair reports success on a damaged installation"
    else
        fail "lexe repair failed on a damaged installation" "$(tail -5 "$W/repair.log")"
    fi
    if cmp -s "$W/pristine" "$VDIR/bin/prog"; then
        pass "repair restored the payload byte for byte"
    else
        fail "repair did not restore the payload bytes"
    fi
    got="$(whoami_running)"
    acc_equals "exit-0" "$got" \
        "after repair the program BEHAVES as its direct-execution baseline says it should"
else
    blocked "installed version directory not found at $VDIR" \
            "the layout is a reference-implementation choice (REFERENCE-POLICY §2);" \
            "this check reads it directly and must be updated if it changes"
fi

# --------------------------------------------------------------------- §9.4 #
note "§9.4 a running application is not disturbed"

if build_and_install linux-run-bounded-3s 3.0.0 3000; then
    "$LEXE_BIN" run "$APP" >"$W/long.out" 2>&1 &
    LONGPID=$!
    # Wait for the launch to actually hold its lease rather than sleeping blind.
    for _ in $(seq 1 50); do
        [[ -n "$(ls "$LEXE_HOME/locks/" 2>/dev/null | grep "v\.3\.0\.0\.lease")" ]] && break
        sleep 0.1
    done
    # `remove` takes the whole application away, so §9.4 leaves it no option but
    # to refuse while a version is executing.
    "$LEXE_BIN" remove "$APP" --yes >"$W/busy.log" 2>&1
    rc=$?
    if [[ $rc -eq 6 ]]; then
        pass "lexe remove refuses (exit 6, busy) while the application is running"
    elif [[ $rc -eq 0 ]]; then
        fail "lexe remove SUCCEEDED while the application was running" \
             "§9.4: the files of an executing version must not be removed" \
             "$(tail -3 "$W/busy.log")"
    else
        fail "lexe remove exited $rc while running (expected 6, busy)" \
             "$(tail -3 "$W/busy.log")"
    fi

    # `gc` is the other half of §9.4 and the more interesting one: the section
    # permits an operation to "complete it without touching the running version's
    # content". So gc SUCCEEDING here is not a violation — reclaiming superseded
    # versions while one is running is exactly what it is for. What would be a
    # violation is the running version's files going away. Demanding exit 6 here
    # was this lane's own first mistake, corrected rather than left to look like a
    # runtime defect.
    RUNDIR="$LEXE_HOME/apps/$APP/versions/3.0.0"
    "$LEXE_BIN" gc "$APP" --keep 0 >"$W/gc.log" 2>&1
    rc=$?
    if [[ $rc -eq 0 || $rc -eq 6 ]]; then
        pass "lexe gc completes or refuses while the application runs (exit $rc)"
    else
        fail "lexe gc exited $rc while the application was running" "$(tail -3 "$W/gc.log")"
    fi
    if [[ -f "$RUNDIR/bin/prog" ]]; then
        pass "gc did NOT remove the content of the version that is executing"
    else
        fail "gc removed the files of the RUNNING version" \
             "§9.4: a runtime MUST NOT remove those files and rely on the OS's" \
             "open-file semantics to keep the process alive" \
             "$(tail -5 "$W/gc.log")"
    fi
    wait "$LONGPID"; longrc=$?
    acc_equals "0" "$longrc" "the running application completed undisturbed"
    grep -q '^SLEPT_AT_LEAST_REQUESTED=yes$' "$W/long.out" \
        && pass "and its own oracle confirms it did its full work" \
        || fail "the running application's oracle does not confirm a complete run" \
                "$(head -8 "$W/long.out")"
fi

acc_summary
exit $?

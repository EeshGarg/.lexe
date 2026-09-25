#!/usr/bin/env bash
# 03 — structured failure diagnostics.
#
# Definitive Architecture acceptance criterion covered here:
#   * "Break a dependency or force a launch failure; .LEXE Error shows a
#      structured diagnostic and allows retry/compatibility changes."
#
# §9 says every hard boolean gate produces a TYPED RECORD, never a bare string,
# and that a real failure is always distinguishable from a successful-but-
# invisible run. Two independent failures are forced here:
#
#   A. the application runs and exits non-zero      -> stage "runtime"
#   B. the installed entrypoint is tampered with    -> stage "verification",
#                                                      and the launch is REFUSED
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

acc_begin "03 failure diagnostics"
acc_require_binaries
acc_scratch_home
acc_build_package
acc_install_package

errdir="$(acc_error_dir)"
acc_true "$([[ ! -d "$errdir" ]] || [[ -z "$(ls -A "$errdir")" ]] && echo 0 || echo 1)" \
    "no error records exist before anything has failed"

# A successful run must NOT produce a record (§14.4: exit 0 is success even
# when no window appears).
"$LEXE" run "$ACC_APP_ID" -- --selftest >/dev/null 2>&1
records_after_success=0
[[ -d "$errdir" ]] && records_after_success="$(find "$errdir" -name '*.json' | wc -l | tr -d ' ')"
acc_equals "$records_after_success" "0" "a successful launch writes no error record"

# --------------------------------------------- A. the application exits != 0
# With no display the GUI payload cannot open its window and exits 2. That is a
# real runtime failure, not a .LEXE failure, and it must be recorded as one.
set +e
env -u WAYLAND_DISPLAY -u DISPLAY timeout 20 "$LEXE" run "$ACC_APP_ID" >"$ACC_ROOT/work/runfail.out" 2>&1
runtime_status=$?
set -e
acc_true "$([[ $runtime_status -ne 0 ]] && echo 0 || echo 1)" \
    "a failing launch propagates a non-zero exit status"

acc_true "$([[ -d "$errdir" ]] && echo 0 || echo 1)" \
    "the structured error store exists at <state>/errors/<id>"
record="$(find "$errdir" -name '*.json' | sort | tail -1)"
acc_true "$([[ -n "$record" ]] && echo 0 || echo 1)" "a structured error record was written"

if [[ -n "$record" ]]; then
    for field in schema timestamp applicationId stage summary detail executionChain launchMode host runtime outcome streams; do
        present="$(acc_json "$record" "'$field' in d")"
        acc_equals "$present" "True" "the record carries a \"$field\" field"
    done
    acc_equals "$(acc_json "$record" 'd["stage"]')" "runtime" 'stage is "runtime" for an application that exited non-zero'
    acc_equals "$(acc_json "$record" 'd["applicationId"]')" "$ACC_APP_ID" "the record names the application"
    acc_equals "$(acc_json "$record" 'd["executionChain"]')" "native" 'executionChain is "native"'
    acc_equals "$(acc_json "$record" 'd["launchMode"]')" "gui" 'launchMode records the DECLARED presentation'
    acc_contains "$(acc_json "$record" 'd["host"]["os"]')" "Linux" "host.os describes the host operating system"
    acc_equals "$(acc_json "$record" 'd["host"]["isa"]')" "$(uname -m)" "host.isa records the host architecture"
    acc_equals "$(acc_json "$record" 'd["outcome"]["exitCode"]')" "2" "outcome.exitCode is the payload's real exit code"
    acc_true "$(acc_json "$record" "'T' in d['timestamp'] and d['timestamp'].endswith('Z')" | grep -q True && echo 0 || echo 1)" \
        "timestamp is an RFC 3339 UTC instant"
    # The record always carries stream REFERENCES. They are only populated for
    # a console application that had nowhere to print (launcher.cpp
    # `capture_output`); a GUI application owns the caller's streams directly,
    # so for this launch both are legitimately empty rather than lost.
    streams_keys="$(acc_json "$record" "sorted(d['streams'])")"
    acc_equals "$streams_keys" "['stderr', 'stdout']" "the record references both captured streams"
    stderr_path="$(acc_json "$record" 'd["streams"]["stderr"]')"
    if [[ -z "$stderr_path" ]]; then
        pass "a GUI launch inherits the caller's streams instead of capturing them (§14.4)"
    else
        acc_file_exists "$stderr_path" "the captured stderr is stored next to the record"
    fi
    acc_true "$([[ -n "$(acc_json "$record" 'd["summary"]')" ]] && echo 0 || echo 1)" \
        "the record carries a one-line human summary"
fi

# `lexe errors` surfaces the record to a frontend, and points at the retry and
# compatibility actions the criterion names.
if "$LEXE" help 2>&1 | grep -q '^  errors'; then
    "$LEXE" errors "$ACC_APP_ID" --latest --json >"$ACC_ROOT/work/errors.json" 2>/dev/null || true
    acc_equals "$(acc_json "$ACC_ROOT/work/errors.json" 'd["applicationId"]' 2>/dev/null || echo missing)" \
        "$ACC_APP_ID" "lexe errors --latest --json is scoped to the application"
    acc_equals "$(acc_json "$ACC_ROOT/work/errors.json" 'd["records"][0]["stage"]' 2>/dev/null || echo missing)" \
        "runtime" "lexe errors --latest --json returns the structured record"
    acc_equals "$(acc_json "$ACC_ROOT/work/errors.json" 'len(d["records"])' 2>/dev/null || echo 0)" "1" \
        "--latest returns exactly the most recent record"
    errors_text="$("$LEXE" errors "$ACC_APP_ID" 2>/dev/null || true)"
    acc_contains "$errors_text" "Retry: lexe run $ACC_APP_ID" "the error view offers a retry action"
    acc_contains "$errors_text" "lexe compat $ACC_APP_ID" "the error view offers a compatibility change"
    acc_equals "$("$LEXE" errors "$ACC_APP_ID" --path 2>/dev/null || true)" "$errdir" \
        "lexe errors --path prints the error folder (\"Open Error Folder\")"
else
    skip "lexe errors is not in this build"
fi

# ------------------------------------- B. the installed entrypoint is tampered
payload="$(acc_version_dir)/$ACC_ENTRYPOINT"
cp "$payload" "$ACC_ROOT/work/payload.orig"
chmod u+w "$payload"
printf 'TAMPERED' >>"$payload"

before="$(acc_launch_count)"
set +e
timeout 20 "$LEXE" run "$ACC_APP_ID" -- --selftest >"$ACC_ROOT/work/tampered.out" 2>&1
tamper_status=$?
set -e
acc_true "$([[ $tamper_status -ne 0 ]] && echo 0 || echo 1)" \
    "the runtime REFUSES to launch a tampered entrypoint"
acc_equals "$(acc_launch_count)" "$before" \
    "the tampered payload was never executed (its launch log did not grow)"
acc_contains "$(cat "$ACC_ROOT/work/tampered.out")" "integrity" \
    "the refusal explains that the integrity check failed"

tamper_record="$(find "$errdir" -name '*.json' | sort | tail -1)"
acc_equals "$(acc_json "$tamper_record" 'd["stage"]')" "verification" \
    'the tamper failure is recorded at stage "verification"'
acc_contains "$(acc_json "$tamper_record" 'd["detail"]')" "modified after installation" \
    "the record says the executable was modified after installation"
acc_contains "$(acc_json "$tamper_record" 'd["detail"]')" "lexe repair" \
    "the record tells the user how to retry (lexe repair)"

# ... and `lexe repair` is the recovery path the record points at.
if "$LEXE" repair "$ACC_APP_ID" >"$ACC_ROOT/work/repair.out" 2>&1; then
    pass "lexe repair returns the application to a launchable state"
else
    # Repair needs the original package bytes; without them it must say so
    # rather than silently leaving a tampered binary in place.
    acc_contains "$(cat "$ACC_ROOT/work/repair.out")" "repair" \
        "lexe repair reports that it cannot fix the tampered file without the package"
    cp "$ACC_ROOT/work/payload.orig" "$payload"
fi
set +e
timeout 20 "$LEXE" run "$ACC_APP_ID" -- --selftest >/dev/null 2>&1
recovered=$?
set -e
acc_equals "$recovered" "0" "the application launches again once the payload is restored"

# The store is per-application and bounded.
acc_true "$([[ "$(find "$errdir" -name '*.json' | wc -l)" -ge 2 ]] && echo 0 || echo 1)" \
    "both failures are retained in the per-application error store"
acc_equals "$(basename "$errdir")" "$ACC_APP_ID" "the error store is scoped to the application id"

acc_summary

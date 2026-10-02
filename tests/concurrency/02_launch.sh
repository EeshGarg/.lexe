#!/usr/bin/env bash
# concurrency 02 — launches racing launches, and launches racing mutations.
#
# A launch takes a SHARED lease on its version, not an exclusive lock, and that
# asymmetry is the whole point: two launches must both succeed, while a mutation
# contending with a live launch must not pull files out from under it.
#
# So the assertions here are the opposite shape from 01. There, at most one winner
# was allowed. Here, two simultaneous launches that do not both run would be the
# defect — a shared lease that behaves exclusively is a lease that serialises every
# launch of every application.
set -uo pipefail
CONC_SRC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$CONC_SRC/../acceptance/lib.sh"
source "$CONC_SRC/../lifecycle/lib.sh"
source "$CONC_SRC/lib.sh"
acc_begin "concurrency 02 launch"
acc_require_binaries
conc_setup

v1="$(lc_build_version 1.0.0)" || { fail "build v1"; acc_summary; exit $?; }
v2="$(lc_build_version 2.0.0)" || { fail "build v2"; acc_summary; exit $?; }
"$LEXE" install "$v1" --yes --trust >/dev/null 2>&1 || {
    fail "install 1.0.0"; acc_summary; exit $?; }
pass "1.0.0 installed"

starts() { lc_starts_logged; }

# --------------------------------------------- two launchers at once
#
# Both must run. The lease is SHARED, so neither may refuse the other.

before="$(starts)"
conc_race_same "run-run" 2 -- "$LEXE" run "$LC_APP_ID" --no-terminal
conc_assert_no_timeouts "run-run" 2
acc_equals "$(conc_winners "run-run" 2)" "2" \
    "two simultaneous launches BOTH ran — the version lease is shared, not exclusive"
acc_equals "$(( $(starts) - before ))" "2" \
    "and the payload recorded two starts, so both really executed"

# --------------------------------------------- many launchers at once
#
# Four, to catch a lease that works for two and serialises beyond that.

before="$(starts)"
conc_race_same "run-x4" 4 -- "$LEXE" run "$LC_APP_ID" --no-terminal
conc_assert_no_timeouts "run-x4" 4
acc_equals "$(conc_winners "run-x4" 4)" "4" "four simultaneous launches all ran"
acc_equals "$(( $(starts) - before ))" "4" "and all four starts were recorded"
note "exit codes seen: $(conc_codes "run-x4" 4)"

# --------------------------------------------- launch + uninstall
#
# The uninstall must not delete files a running process is executing. Either it
# refuses as busy, or it waits — never "succeeds" by removing them underneath.

"$LEXE" run "$LC_APP_ID" --detach -- --sleep 40 >/dev/null 2>&1
live="$(conc_wait_alive 1.0.0 || true)"
if [[ -z "$live" ]]; then
    skip "could not keep the application alive long enough to race an uninstall"
else
    pass "a detached launch is holding a lease on 1.0.0 (pid $live)"
    out="$(timeout "$CONC_TIMEOUT" "$LEXE" uninstall "$LC_APP_ID" --yes 2>&1)"
    rc=$?
    acc_true "$([[ $rc -ne 0 ]] && echo 0 || echo 1)" \
        "uninstalling a running application is refused (exit $rc), not silently done"
    acc_true "$([[ $rc -ne 124 ]] && echo 0 || echo 1)" \
        "and it refused promptly rather than blocking until the timeout"
    acc_file_exists "$(lc_installed_entry 1.0.0)" \
        "the running version's files are still there"
    acc_true "$([[ -n "$(pgrep -f "versions/1.0.0/$LC_ENTRY" | head -1 || true)" ]] && echo 0 || echo 1)" \
        "and the running process was not killed by the attempt"
    pkill -f "versions/1.0.0/$LC_ENTRY" 2>/dev/null || true
    sleep 1
fi

# --------------------------------------------- launch + update
#
# An update while a launch is live is legitimate: it installs alongside. What it
# must not do is remove the version the live process is running from.

"$LEXE" run "$LC_APP_ID" --detach -- --sleep 40 >/dev/null 2>&1
live="$(conc_wait_alive 1.0.0 || true)"
if [[ -z "$live" ]]; then
    skip "could not keep the application alive long enough to race an update"
else
    out="$(timeout "$CONC_TIMEOUT" "$LEXE" install "$v2" --yes 2>&1)"
    rc=$?
    note "install 2.0.0 while 1.0.0 runs exited $rc"
    acc_true "$([[ $rc -ne 124 ]] && echo 0 || echo 1)" \
        "the update did not hang against a live lease"
    if [[ -n "$(pgrep -f "versions/1.0.0/$LC_ENTRY" | head -1 || true)" ]]; then
        acc_file_exists "$(lc_installed_entry 1.0.0)" \
            "the running version's files survived an update installed alongside them"
    else
        note "the running process exited before the check; not applicable"
    fi
    pkill -f "$LC_ENTRY" 2>/dev/null || true
    sleep 1
    lc_assert_coherent "after update during a live launch"
fi

# --------------------------------------------- two versions running at once
#
# Distinct leases on distinct versions must not exclude each other.

"$LEXE" install "$v1" --yes >/dev/null 2>&1
"$LEXE" install "$v2" --yes >/dev/null 2>&1
# 2.0.0 is current; start it detached, then roll back and start 1.0.0.
"$LEXE" run "$LC_APP_ID" --detach -- --sleep 40 >/dev/null 2>&1
if conc_wait_alive 2.0.0 >/dev/null; then
    rb=$(timeout "$CONC_TIMEOUT" "$LEXE" rollback "$LC_APP_ID" >/dev/null 2>&1; echo $?)
    note "rollback while 2.0.0 runs exited $rb"
    if [[ "$rb" == "0" ]]; then
        "$LEXE" run "$LC_APP_ID" --detach -- --sleep 30 >/dev/null 2>&1
        conc_wait_alive 1.0.0 >/dev/null || true
        both=0
        [[ -n "$(pgrep -f "versions/2.0.0/$LC_ENTRY" | head -1 || true)" ]] && both=$((both+1))
        [[ -n "$(pgrep -f "versions/1.0.0/$LC_ENTRY" | head -1 || true)" ]] && both=$((both+1))
        acc_true "$([[ $both -eq 2 ]] && echo 0 || echo 1)" \
            "two DIFFERENT versions ran simultaneously ($both of 2 alive) — per-version leases do not exclude each other"
    else
        note "rollback refused while the old version ran; the two-version case does not apply"
    fi
    pkill -f "$LC_ENTRY" 2>/dev/null || true
    sleep 1
else
    skip "could not keep 2.0.0 alive to test two simultaneous versions"
fi
lc_assert_coherent "after running two versions at once"

# --------------------------------------------- lock ORDER, not just lock presence
#
# docs/CONCURRENCY.md states an ordered acquisition discipline (GlobalRecovery <
# AppMutation < VersionLease < Registry) precisely to preclude deadlock. A
# violation shows up as a hang rather than an error, so the evidence that matters
# is that a mutation and a launch contending in BOTH directions always terminate.

for direction in mutation-first launch-first; do
    "$LEXE" install "$v1" --yes >/dev/null 2>&1
    if [[ "$direction" == mutation-first ]]; then
        conc_race_pair "order-$direction" \
            -- "$LEXE" repair "$LC_APP_ID" \
            -- "$LEXE" run "$LC_APP_ID" --no-terminal
    else
        conc_race_pair "order-$direction" \
            -- "$LEXE" run "$LC_APP_ID" --no-terminal \
            -- "$LEXE" repair "$LC_APP_ID"
    fi
    conc_assert_no_timeouts "order-$direction" 2
    note "$direction: a=$(conc_rc "order-$direction" a) b=$(conc_rc "order-$direction" b)"
done
pass "a mutation and a launch contending in both orders always terminate"
lc_assert_coherent "after contending in both lock orders"

"$LEXE" purge "$LC_APP_ID" --yes >/dev/null 2>&1
acc_summary

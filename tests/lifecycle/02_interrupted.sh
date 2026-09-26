#!/usr/bin/env bash
# lifecycle 02 — operations interrupted on purpose.
#
# The invariant under test:
#
#     A failed .LEXE operation leaves either the previous valid state or the new
#     valid state — never an ambiguous, partially applied one.
#
# Every case here ends in lc_assert_coherent, which checks that from the OUTSIDE:
# the runtime's view and the filesystem agree, and the application either
# launches at the version the runtime claims or is honestly absent. An entry that
# cannot run, a current version with no directory, or a directory with no record
# are all states this suite exists to rule out.
#
# Interruptions are delivered when the operation SAYS it has reached a phase,
# never after a fixed sleep. Racing a sleep against an install is how an
# interruption test becomes flaky and then vacuous: on a fast machine the
# operation finishes first, the signal lands on nothing, and the test reports
# success having proved nothing. lc_kill_at reports whether it interrupted
# anything, and a case that could not is recorded as such rather than claimed.
set -uo pipefail
LC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$LC_DIR/../acceptance/lib.sh"
source "$LC_DIR/lib.sh"
acc_begin "lifecycle 02 interrupted"
acc_require_binaries
lc_setup

v1="$(lc_build_version 1.0.0)" || { fail "build v1"; acc_summary; exit $?; }
v2="$(lc_build_version 2.0.0)" || { fail "build v2"; acc_summary; exit $?; }

# --------------------------------------------- 1. killed during a first install
#
# Nothing was installed before, so the only valid outcomes are "installed and
# working" or "absent". A half-extracted version directory that `lexe list`
# reports is the failure.

lc_kill_at "" KILL -- install "$v1" --yes --trust
lc_assert_coherent "killed during first install"

if lc_is_installed; then
    note "the install completed before the signal landed; coherence still checked"
else
    pass "a killed first install left nothing behind, not a partial one"
    acc_file_absent "$(lc_installed_entry 1.0.0)" \
        "no half-extracted payload was left in place"
fi

# The operation must be COMPLETABLE after an interruption, rather than leaving
# state that later operations trip over. Note what completion means: if the kill
# landed after promotion the version is already current, and re-running install
# is then refused on purpose ("already installed and current; use `lexe repair`").
# lc_complete_install takes whichever path applies and insists on the same end
# state either way.
acc_true "$(lc_complete_install 1.0.0 "$v1"; echo $?)" \
    "the install can be completed after being interrupted, and 1.0.0 runs"
lc_assert_coherent "after completing the install"

printf 'user settings\n' > "$LEXE_HOME/data/$LC_APP_ID/profile.conf"

# --------------------------------------------- 2. killed during an update
#
# Now there IS a previous valid state, so the invariant has teeth: the outcome
# must be 1.0.0 working or 2.0.0 working, never neither.

lc_kill_at "" KILL -- install "$v2" --yes
lc_assert_coherent "killed during update"
ran="$(lc_running_version)"
acc_true "$([[ "$ran" == "1.0.0" || "$ran" == "2.0.0" ]] && echo 0 || echo 1)" \
    "after a killed update the application runs, at the old or the new version ($ran)"
acc_file_exists "$LEXE_HOME/data/$LC_APP_ID/profile.conf" \
    "and the user's data survived the interruption"

acc_true "$(lc_complete_install 2.0.0 "$v2"; echo $?)" \
    "the update can be completed after being interrupted, and 2.0.0 runs"
lc_assert_coherent "after completing the update"

# --------------------------------------------- 3. an application running during an update
#
# A detached application holds a lease on its version. Updating underneath it
# must not remove the files it is executing from.

"$LEXE" run "$LC_APP_ID" --detach -- --sleep 20 >/dev/null 2>&1
sleep 2
running_pid="$(pgrep -f "versions/2.0.0/$LC_ENTRY" | head -1 || true)"
if [[ -z "$running_pid" ]]; then
    skip "could not keep the application running long enough to update underneath it"
else
    pass "the application is running (pid $running_pid) with a lease on 2.0.0"
    "$LEXE" install "$v1" --yes >/dev/null 2>&1
    install_status=$?
    note "install while running exited $install_status"
    # Either outcome is defensible — refuse while busy, or install and leave the
    # running version's files alone. Deleting the files of a running process is
    # not.
    still_running="$(pgrep -f "versions/2.0.0/$LC_ENTRY" | head -1 || true)"
    if [[ -n "$still_running" ]]; then
        acc_file_exists "$(lc_installed_entry 2.0.0)" \
            "the running version's files were NOT removed from under it"
    else
        note "the running process had already exited; that check does not apply"
    fi
    pkill -f "versions/2.0.0/$LC_ENTRY" 2>/dev/null || true
    sleep 1
    lc_assert_coherent "after updating while the application ran"
fi

# --------------------------------------------- 4. a corrupted installed payload

"$LEXE" install "$v2" --yes >/dev/null 2>&1
entry="$(lc_installed_entry 2.0.0)"
printf 'corrupt' >> "$entry"
out="$(timeout 120 "$LEXE" run "$LC_APP_ID" --no-terminal 2>&1)"
acc_true "$([[ $? -ne 0 ]] && echo 0 || echo 1)" \
    "a corrupted installed payload is refused, not executed"
acc_contains "$out" "integrity" "the refusal names integrity"
# Failing safe means a diagnostic exists and the state is still repairable — not
# that the application is now unrecoverable.
acc_true "$("$LEXE" errors "$LC_APP_ID" --latest >/dev/null 2>&1; echo $?)" \
    "a structured diagnostic record was written"
acc_true "$("$LEXE" repair "$LC_APP_ID" >/dev/null 2>&1; echo $?)" \
    "and repair recovers it"
lc_assert_coherent "after corruption and repair"

# --------------------------------------------- 5. deleted installed files

rm -rf "$(lc_version_dir 2.0.0)/bin"
out="$(timeout 120 "$LEXE" run "$LC_APP_ID" --no-terminal 2>&1)"
acc_true "$([[ $? -ne 0 ]] && echo 0 || echo 1)" \
    "a missing payload is refused with an error, not a crash"
acc_true "$("$LEXE" repair "$LC_APP_ID" >/dev/null 2>&1; echo $?)" \
    "repair restores a wholly deleted payload directory"
lc_assert_coherent "after deleting and repairing the payload"

# --------------------------------------------- 6. an unreadable installed file
#
# Not the same as missing: the file is present and its hash cannot be checked.

chmod 000 "$entry" 2>/dev/null || true
if [[ -r "$entry" ]]; then
    skip "cannot make a file unreadable here (running as root?)"
else
    out="$(timeout 120 "$LEXE" run "$LC_APP_ID" --no-terminal 2>&1)"
    acc_true "$([[ $? -ne 0 ]] && echo 0 || echo 1)" \
        "an unreadable entrypoint fails closed rather than running unchecked"
    chmod 755 "$entry" 2>/dev/null || true
    "$LEXE" repair "$LC_APP_ID" >/dev/null 2>&1
    lc_assert_coherent "after an unreadable file"
fi

# --------------------------------------------- 7. stale integration artifacts

rm -f "$LEXE_HOME/applications/lexe-$LC_APP_ID.desktop"
doctor_out="$("$LEXE" doctor 2>&1)"
doctor_status=$?
acc_true "$([[ $doctor_status -ne 0 ]] && echo 0 || echo 1)" \
    "doctor reports a problem when an integration artifact is missing"
acc_contains "$doctor_out" "$LC_APP_ID" "and it names the application affected"
acc_true "$("$LEXE" doctor --repair >/dev/null 2>&1; echo $?)" \
    "doctor --repair re-establishes it"
acc_file_exists "$LEXE_HOME/applications/lexe-$LC_APP_ID.desktop" \
    "the desktop entry is back"
acc_true "$("$LEXE" doctor >/dev/null 2>&1; echo $?)" "and doctor is healthy again"

# --------------------------------------------- 8. interrupted uninstall

lc_kill_at "" KILL -- remove "$LC_APP_ID" --yes
lc_assert_coherent "killed during uninstall"
"$LEXE" remove "$LC_APP_ID" --yes >/dev/null 2>&1
acc_true "$(lc_is_installed && echo 1 || echo 0)" \
    "the uninstall completes when retried"
lc_assert_coherent "after retrying the uninstall"

# --------------------------------------------- 9. a stale version lease
#
# A lease is an flock, so the kernel releases it when its holder dies. That is
# the design: a timestamp-based lease would need staleness heuristics and could
# strand a version forever. Check the consequence — a dead holder blocks nothing.

"$LEXE" install "$v1" --yes >/dev/null 2>&1
lease="$(find "$LEXE_HOME/apps/$LC_APP_ID" -name '*lease*' -type f 2>/dev/null |
    head -1)"
if [[ -n "$lease" ]]; then
    ( flock 9 && sleep 30 ) 9<"$lease" &
    holder=$!
    sleep 1
    kill -9 "$holder" 2>/dev/null
    wait "$holder" 2>/dev/null
    acc_true "$("$LEXE" remove "$LC_APP_ID" --yes >/dev/null 2>&1; echo $?)" \
        "a lease whose holder was killed does not strand the version"
else
    note "no lease file at rest; the kernel-released design leaves none behind"
    "$LEXE" remove "$LC_APP_ID" --yes >/dev/null 2>&1
fi
lc_assert_coherent "after a killed lease holder"

# --------------------------------------------- 10. a runtime this host lacks
#
# A package must fail honestly rather than fall back to a chain it did not
# declare.

"$LEXE" install "$v1" --yes >/dev/null 2>&1
compat_out="$("$LEXE" compat "$LC_APP_ID" --set fex 2>&1)"
compat_status=$?
acc_true "$([[ $compat_status -ne 0 ]] && echo 0 || echo 1)" \
    "a chain the package does not permit cannot be selected, absent or not"
acc_contains "$compat_out" "does not permit" "and the reason says so"
"$LEXE" remove "$LC_APP_ID" --purge-data --yes >/dev/null 2>&1

acc_summary

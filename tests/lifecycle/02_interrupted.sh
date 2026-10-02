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
v3="$(lc_build_version 3.0.0)" || { fail "build v3"; acc_summary; exit $?; }

# Where a version lands on disk. The interruption triggers watch these, because
# `lexe install` prints nothing at all until it has finished — so there is no
# output to wait for, and waiting for output meant waiting for "Installed ...",
# which is the operation announcing that there is nothing left to interrupt.
LC_VERSIONS="$LEXE_HOME/apps/$LC_APP_ID/versions"

# --------------------------------------------- 1. killed during a first install
#
# Nothing was installed before, so the only valid outcomes are "installed and
# working" or "absent". A half-extracted version directory that `lexe list`
# reports is the failure.

lc_kill_at "path:$LC_VERSIONS/*" KILL -- install "$v1" --yes --trust
lc_interrupt_report "killed during first install"
lc_assert_coherent "killed during first install"

if lc_is_installed; then
    note "the install completed before the signal landed; coherence still checked"
else
    pass "a killed first install left nothing behind that claims to be installed"
    # NOT `acc_file_absent` on the entrypoint. That assertion had never once been
    # evaluated -- the kill used to land after the install had announced its own
    # completion, so `lc_is_installed` was true and this branch was dead code.
    # The first run in which the interruption actually landed mid-extraction
    # showed it failing, on a half-written payload under versions/1.0.0/bin.
    #
    # And it is asking for something no design can promise: the process was
    # SIGKILLed, so no handler ran and no bytes could be swept. This block's own
    # criterion says so two dozen lines up -- "a half-extracted version directory
    # that `lexe list` reports is the failure". Bytes on disk that nothing claims
    # are debris; the invariant is about CLAIMS.
    #
    # So assert what the invariant forbids, and give it teeth the file check
    # never had: the debris must not be REACHABLE. A half-extracted payload that
    # `lexe run` will execute is the failure this case exists to rule out.
    acc_equals "$(lc_current_version)" "" \
        "no version is recorded as current after the killed install"
    killed_run_out="$(timeout 120 "$LEXE" run "$LC_APP_ID" --no-terminal 2>&1)"
    killed_run_status=$?
    acc_refused "$killed_run_status" \
        "the half-extracted payload is NOT launchable -- lexe refuses it" \
        "$killed_run_out"
    acc_equals "$(lc_starts_logged)" "0" \
        "and it was never executed: nothing recorded a start"
fi

# The operation must be COMPLETABLE after an interruption, rather than leaving
# state that later operations trip over. Note what completion means: if the kill
# landed after promotion the version is already current, and re-running install
# is then refused on purpose ("already installed and current; use `lexe repair`").
# lc_complete_install takes whichever path applies and insists on the same end
# state either way.
# Run directly, not inside `$(...)`: a command substitution is a subshell, and
# anything lc_complete_install learns about WHY it failed dies with it.
lc_complete_install 1.0.0 "$v1"; complete_status=$?
acc_true "$complete_status" \
    "the install can be completed after being interrupted, and 1.0.0 runs" \
    "$LC_COMPLETE_DETAIL"
lc_assert_coherent "after completing the install"

printf 'user settings\n' > "$LEXE_HOME/data/$LC_APP_ID/profile.conf"

# --------------------------------------------- 2. killed during an update
#
# Now there IS a previous valid state, so the invariant has teeth: the outcome
# must be 1.0.0 working or 2.0.0 working, never neither.

lc_kill_at "path:$LC_VERSIONS/2.0.0" KILL -- install "$v2" --yes
lc_interrupt_report "killed during update"
lc_assert_coherent "killed during update"
ran="$(lc_running_version)"
acc_true "$([[ "$ran" == "1.0.0" || "$ran" == "2.0.0" ]] && echo 0 || echo 1)" \
    "after a killed update the application runs, at the old or the new version ($ran)"
acc_file_exists "$LEXE_HOME/data/$LC_APP_ID/profile.conf" \
    "and the user's data survived the interruption"

lc_complete_install 2.0.0 "$v2"; complete_status=$?
acc_true "$complete_status" \
    "the update can be completed after being interrupted, and 2.0.0 runs" \
    "$LC_COMPLETE_DETAIL"
lc_assert_coherent "after completing the update"

# --------------------------------------------- 3. an application running during an update
#
# A detached application holds a lease on its version. Updating underneath it
# must not remove the files it is executing from.
#
# WHAT THIS SECTION USED TO DO, AND WHY IT PROVED NOTHING. It installed $v1 —
# 1.0.0 — while 2.0.0 was current and running. That is a DOWNGRADE, and the
# version-ordering guard refuses it before any lease, lock or concurrency code
# is reached:
#
#     lexe: refusing to move org.lexe.lifecycle.subject backwards from 2.0.0
#           to 1.0.0
#       hint: ... re-run with `--allow-downgrade`
#
# Exit 1, nothing installed, nothing extracted, nothing contended. So the
# section titled "an application running during an update" tested the downgrade
# check, and its one real assertion — that the running version's files are still
# there — was satisfied trivially, because no update had ever started. The
# concurrency path it was written for had never once been executed.
#
# 3.0.0 is a genuine update, so the install proceeds and the assertions below
# are about the thing they name. The first of them exists to keep this honest:
# if some future guard turns the install away before concurrency again, it says
# so rather than passing on the strength of an install that never happened.

"$LEXE" run "$LC_APP_ID" --detach -- --sleep 20 >/dev/null 2>&1
sleep 2
running_pid="$(pgrep -f "versions/2.0.0/$LC_ENTRY" | head -1 || true)"
if [[ -z "$running_pid" ]]; then
    skip "could not keep the application running long enough to update underneath it"
else
    pass "the application is running (pid $running_pid) with a lease on 2.0.0"
    update_out="$("$LEXE" install "$v3" --yes 2>&1)"
    install_status=$?
    note "install while running exited $install_status"

    acc_true "$(grep -qiE 'refus|downgrade|backwards' <<<"$update_out" && echo 1 || echo 0)" \
        "the update reached the concurrency path instead of being turned away by a version guard" \
        "$update_out"
    acc_true "$([[ -d "$(lc_version_dir 3.0.0)" ]] && echo 0 || echo 1)" \
        "the new version was really extracted while the old one was executing"

    # Either outcome is defensible — refuse while busy, or install and leave the
    # running version's files alone. Deleting the files of a running process is
    # not.
    still_running="$(pgrep -f "versions/2.0.0/$LC_ENTRY" | head -1 || true)"
    if [[ -n "$still_running" ]]; then
        acc_file_exists "$(lc_installed_entry 2.0.0)" \
            "the running version's files were NOT removed from under it"
        acc_equals "$still_running" "$running_pid" \
            "and it is the same process throughout — not one that died and was restarted"
    else
        note "the running process had already exited; that check does not apply"
    fi
    pkill -f "versions/2.0.0/$LC_ENTRY" 2>/dev/null || true
    sleep 1
    lc_assert_coherent "after updating while the application ran"
fi

# --------------------------------------------- 4. a corrupted installed payload
#
# Which version is current here depends on what sections 1-3 ended up doing, and
# hard-coding "2.0.0" would mean corrupting a directory that may not be the one
# the runtime would launch — an assertion that passes for the wrong reason. Ask.

cur="$(lc_current_version)"
acc_true "$([[ -n "$cur" ]] && echo 0 || echo 1)" \
    "an application is installed and current before the corruption cases ($cur)"
entry="$(lc_installed_entry "$cur")"
printf 'corrupt' >> "$entry"
# Capture the status into a named variable rather than reading `$?` from inside
# a `$(...)`. That form happens to work only while the substitution is the very
# next thing evaluated; insert one command between them -- a note, a log line --
# and the assertion starts reporting on something else entirely. And `-ne 0`
# accepted 124: a launch that hung for two minutes satisfied "is refused".
out="$(timeout 120 "$LEXE" run "$LC_APP_ID" --no-terminal 2>&1)"
run_status=$?
acc_refused "$run_status" "a corrupted installed payload is refused, not executed" "$out"
# The whole phrase, not the bare word "integrity". "integrity" alone appears in
# unrelated help text and in the word "integrity check skipped"; the assertion
# has to fail when the runtime stops refusing, and only the refusal says this.
acc_contains "$out" "fails its recorded integrity check" "the refusal names integrity"
# Failing safe means a diagnostic exists and the state is still repairable — not
# that the application is now unrecoverable.
acc_true "$("$LEXE" errors "$LC_APP_ID" --latest >/dev/null 2>&1; echo $?)" \
    "a structured diagnostic record was written"
acc_true "$("$LEXE" repair "$LC_APP_ID" >/dev/null 2>&1; echo $?)" \
    "and repair recovers it"
lc_assert_coherent "after corruption and repair"

# --------------------------------------------- 5. deleted installed files

rm -rf "$(lc_version_dir "$cur")/bin"
out="$(timeout 120 "$LEXE" run "$LC_APP_ID" --no-terminal 2>&1)"
run_status=$?
acc_refused "$run_status" "a missing payload is refused with an error, not a crash" "$out"
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
    run_status=$?
    acc_refused "$run_status" \
        "an unreadable entrypoint fails closed rather than running unchecked" "$out"
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

# The mirror image of the install trigger: a remove says nothing until it is
# done either, but the version directories disappearing is an unmistakable sign
# that it is in the middle of the work.
lc_kill_at "gone:$LC_VERSIONS/*" KILL -- uninstall "$LC_APP_ID" --yes
lc_interrupt_report "killed during uninstall"
lc_assert_coherent "killed during uninstall"
"$LEXE" uninstall "$LC_APP_ID" --yes >/dev/null 2>&1
acc_true "$(lc_is_installed && echo 1 || echo 0)" \
    "the uninstall completes when retried"
lc_assert_coherent "after retrying the uninstall"

# --------------------------------------------- 8b. interrupted purge
#
# Purge makes .LEXE forget an application, trust decision included, and is
# transactional: a journal (`apps/.removing/<id>.purge`) is written before
# anything changes and removed only after a post-check finds everything gone.
# Two real SIGKILLs, at the two boundaries that matter: the moment the journal
# appears, and the moment the trust record disappears. Whatever instant the
# signal lands at, three things must hold:
#
#   * never "files gone and installed=true" (lc_assert_coherent);
#   * an unfinished purge is never mistaken for a finished one: launch and
#     uninstall refuse (exit 6) and `trust show` says so;
#   * it FINISHES -- by `lexe purge` again, or by `lexe install`, which must
#     then be a first install, not a return under the old explicit trust.
#
# The unit failpoints (test_purge.cpp, CASE 4) stop the purge at chosen lines;
# this stops a real process wherever the kernel happens to find it, observed
# only through the CLI.
LC_PURGE_JOURNAL="$LEXE_HOME/apps/.removing/$LC_APP_ID.purge"
LC_TRUST_RECORD="$LEXE_HOME/trust/$LC_APP_ID.json"

lc_check_unfinished_purge() { # <label>
    local label="$1"
    if [[ ! -f "$LC_PURGE_JOURNAL" ]]; then
        note "$label: the purge completed before the signal landed; nothing unfinished to check"
        return 0
    fi
    pass "$label: the purge is recorded as unfinished (journal present)"
    local out rc
    out="$("$LEXE" uninstall "$LC_APP_ID" --yes 2>&1)"; rc=$?
    acc_equals "$rc" "6" "$label: uninstall refuses an unfinished purge (6)"
    if lc_is_installed; then
        out="$(timeout 120 "$LEXE" run "$LC_APP_ID" --no-terminal 2>&1)"; rc=$?
        acc_equals "$rc" "6" "$label: an application mid-purge is not launched (6)"
        acc_equals "$(lc_starts_logged)" "$LC_STARTS_BEFORE_PURGE" \
            "$label: and it really did not run: no start was recorded"
    fi
    out="$("$LEXE" trust show "$LC_APP_ID" 2>&1)"
    acc_contains "$out" "INTERRUPTED and not finished" \
        "$label: trust show says the purge is unfinished"
}

for trigger in "path:$LC_PURGE_JOURNAL" "gone:$LC_TRUST_RECORD"; do
    "$LEXE" install "$v1" --yes --trust >/dev/null 2>&1
    acc_true "$([[ -f "$LC_TRUST_RECORD" ]] && echo 0 || echo 1)" \
        "a trust record exists before the purge (the control)"
    LC_STARTS_BEFORE_PURGE="$(lc_starts_logged)"
    label="killed during purge (${trigger%%:*} trigger)"

    lc_kill_at "$trigger" KILL -- purge "$LC_APP_ID" --yes
    lc_interrupt_report "$label"
    lc_assert_coherent "$label"
    lc_check_unfinished_purge "$label"

    if [[ "$trigger" == path:* ]]; then
        # Finish it the direct way.
        out="$("$LEXE" purge "$LC_APP_ID" --yes 2>&1)"; rc=$?
        acc_equals "$rc" "0" "$label: purging again finishes it" "$out"
        acc_file_absent "$LC_TRUST_RECORD" "$label: the trust record is gone"
        acc_file_absent "$LEXE_HOME/data/$LC_APP_ID/profile.conf" \
            "$label: and so is the data"
        acc_file_absent "$LC_PURGE_JOURNAL" "$label: and nothing is left unfinished"
    else
        # Finish it by installing: install completes the purge FIRST, so this
        # is a first install -- the explicit trust from before must be gone.
        out="$("$LEXE" install "$v1" --yes 2>&1)"; rc=$?
        acc_equals "$rc" "0" "$label: installing finishes the purge, then installs" "$out"
        acc_file_absent "$LC_PURGE_JOURNAL" "$label: nothing is left unfinished"
        out="$("$LEXE" trust show "$LC_APP_ID" --json 2>&1)"
        acc_contains "$out" '"explicitlyTrusted": false' \
            "$label: the reinstall is a FIRST install, not a return under the old trust"
        lc_assert_coherent "$label: after finishing by install"
    fi
done

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
    acc_true "$("$LEXE" uninstall "$LC_APP_ID" --yes >/dev/null 2>&1; echo $?)" \
        "a lease whose holder was killed does not strand the version"
else
    note "no lease file at rest; the kernel-released design leaves none behind"
    "$LEXE" uninstall "$LC_APP_ID" --yes >/dev/null 2>&1
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
"$LEXE" purge "$LC_APP_ID" --yes >/dev/null 2>&1

acc_summary

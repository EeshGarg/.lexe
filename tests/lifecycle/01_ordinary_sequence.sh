#!/usr/bin/env bash
# lifecycle 01 — the ordinary sequence, with the state checked between steps.
#
#   install -> run -> update -> run -> rollback -> run -> repair -> run -> uninstall
#
# Every step asserts two different things, because they are two different claims:
#
#   * the operation reported success, and
#   * the installation is COHERENT afterwards — the version the runtime reports
#     is the version the program itself prints, and it launches.
#
# The second is why the subject payload reports its own version. A test that asks
# the registry which version is current and then believes the answer cannot
# notice a rollback that moved the record without moving the files.
set -uo pipefail
LC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$LC_DIR/../acceptance/lib.sh"
source "$LC_DIR/lib.sh"
acc_begin "lifecycle 01 ordinary sequence"
acc_require_binaries
lc_setup

v1="$(lc_build_version 1.0.0)" || { fail "build v1"; acc_summary; exit $?; }
v2="$(lc_build_version 2.0.0)" || { fail "build v2"; acc_summary; exit $?; }
pass "two signed versions of one application were built"

# ------------------------------------------------------------------- install

acc_true "$("$LEXE" install "$v1" --yes --trust >/dev/null 2>&1; echo $?)" \
    "install 1.0.0"
lc_assert_coherent "after install"
acc_equals "$(lc_current_version)" "1.0.0" "1.0.0 is the current version"

# State the application itself owns, seeded here so every later step can be
# checked for having preserved it. Data loss during an update is not a crash and
# would otherwise go unnoticed.
mkdir -p "$LEXE_HOME/data/$LC_APP_ID"
printf 'user settings\n' > "$LEXE_HOME/data/$LC_APP_ID/profile.conf"
mkdir -p "$LEXE_HOME/cache/apps/$LC_APP_ID"
printf 'cached\n' > "$LEXE_HOME/cache/apps/$LC_APP_ID/thumb.bin"

# ----------------------------------------------------------------------- run

acc_equals "$(lc_running_version)" "1.0.0" "run 1.0.0 — and 1.0.0 is what ran"
acc_file_exists "$LEXE_HOME/data/$LC_APP_ID/starts.log" \
    "the launch is provable from the private data root"

# -------------------------------------------------------------------- update

acc_true "$("$LEXE" install "$v2" --yes >/dev/null 2>&1; echo $?)" \
    "update to 2.0.0"
lc_assert_coherent "after update"
acc_equals "$(lc_current_version)" "2.0.0" "2.0.0 is now current"
acc_equals "$(lc_running_version)" "2.0.0" "and 2.0.0 is what runs"
acc_file_exists "$LEXE_HOME/data/$LC_APP_ID/profile.conf" \
    "the application's data survived the update"
acc_file_exists "$LEXE_HOME/cache/apps/$LC_APP_ID/thumb.bin" \
    "its cache survived the update"
acc_dir_exists "$(lc_version_dir 1.0.0)" \
    "the previous version is retained, so a rollback has somewhere to go"

# ------------------------------------------------------------------ rollback

acc_true "$("$LEXE" rollback "$LC_APP_ID" >/dev/null 2>&1; echo $?)" \
    "rollback 2.0.0 -> 1.0.0"
lc_assert_coherent "after rollback"
acc_equals "$(lc_current_version)" "1.0.0" "1.0.0 is current again"
acc_equals "$(lc_running_version)" "1.0.0" \
    "and the program that runs really is 1.0.0, not a record that only says so"
acc_file_exists "$LEXE_HOME/data/$LC_APP_ID/profile.conf" \
    "data survived the rollback"

# -------------------------------------------------------------------- repair
#
# Repair against an undamaged installation must be a no-op that still succeeds:
# a repair that only works on broken state is a repair nobody can safely run.

acc_true "$("$LEXE" repair "$LC_APP_ID" >/dev/null 2>&1; echo $?)" \
    "repair an undamaged installation succeeds"
lc_assert_coherent "after repair"

# Now damage it and repair for real.
entry="$(lc_installed_entry 1.0.0)"
acc_file_exists "$entry" "the installed entrypoint is where the record says"
printf 'tampered' >> "$entry"

run_out="$(timeout 120 "$LEXE" run "$LC_APP_ID" --no-terminal 2>&1)"
acc_true "$([[ $? -ne 0 ]] && echo 0 || echo 1)" \
    "a tampered entrypoint is refused rather than executed"
acc_contains "$run_out" "integrity" "and the refusal names integrity as the reason"

acc_true "$("$LEXE" repair "$LC_APP_ID" >/dev/null 2>&1; echo $?)" \
    "repair restores the tampered entrypoint"
lc_assert_coherent "after repairing real damage"
acc_equals "$(lc_running_version)" "1.0.0" "it runs again"

# A deleted file, not just a modified one.
rm -f "$entry"
acc_true "$("$LEXE" repair "$LC_APP_ID" >/dev/null 2>&1; echo $?)" \
    "repair restores a DELETED entrypoint"
acc_file_exists "$entry" "the file is back"
lc_assert_coherent "after repairing a deletion"

# ------------------------------------------------------------------ uninstall

starts_before="$(lc_starts_logged)"
acc_true "$("$LEXE" remove "$LC_APP_ID" --yes >/dev/null 2>&1; echo $?)" \
    "uninstall"
lc_assert_coherent "after uninstall"
acc_true "$(lc_is_installed && echo 1 || echo 0)" \
    "the application is gone from lexe list"
acc_dir_absent "$(lc_version_dir 1.0.0)" "its version directory is gone"

# The default uninstall keeps user data: losing it silently is the behaviour
# --purge-data exists to make explicit.
acc_file_exists "$LEXE_HOME/data/$LC_APP_ID/profile.conf" \
    "user data is RETAINED by default, so an uninstall is not a data loss event"
acc_true "$([[ "$starts_before" -gt 0 ]] && echo 0 || echo 1)" \
    "the application had really been run $starts_before time(s) before removal"

# And with --purge-data it is genuinely gone.
"$LEXE" install "$v1" --yes >/dev/null 2>&1
acc_true "$("$LEXE" remove "$LC_APP_ID" --purge-data --yes >/dev/null 2>&1; echo $?)" \
    "uninstall --purge-data"
acc_file_absent "$LEXE_HOME/data/$LC_APP_ID/profile.conf" \
    "and then the data really is gone"
lc_assert_coherent "after purging uninstall"

acc_summary

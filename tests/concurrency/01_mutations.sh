#!/usr/bin/env bash
# concurrency 01 — simultaneous MUTATING operations on one application.
#
# The previous wave attacked interrupted operations: one at a time, killed
# halfway. This attacks contended ones: two at once, both alive.
#
# What a correct outcome looks like is not "both succeeded". `AppMutation` is an
# exclusive lock, so serialisation is allowed to make one participant lose, and
# losing correctly — BusyError, exit 6, nothing written — is the right answer. The
# outcomes that are never acceptable:
#
#   * a HANG (exit 124 under the timeout): the operation neither completed nor
#     refused, which is the shape of a lock nobody releases;
#   * two winners where only one may win;
#   * a loser exiting with a code outside the allowed set, which means it did not
#     lose, it broke. The allowed set is 0 (did the work), 6 (BusyError, refused
#     without writing), and 1 ONLY when it says the work was already done — see
#     conc_assert_losers_lost_legitimately for why that third case exists;
#   * any partially applied state afterwards — checked by lc_assert_coherent,
#     which compares the runtime's view against the filesystem and demands the
#     application either launch at the version claimed or be honestly absent.
set -uo pipefail
CONC_SRC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$CONC_SRC/../acceptance/lib.sh"
source "$CONC_SRC/../lifecycle/lib.sh"
source "$CONC_SRC/lib.sh"
acc_begin "concurrency 01 mutations"
acc_require_binaries
conc_setup

v1="$(lc_build_version 1.0.0)" || { fail "build v1"; acc_summary; exit $?; }
v2="$(lc_build_version 2.0.0)" || { fail "build v2"; acc_summary; exit $?; }
pass "two signed versions were built"

# --------------------------------------------- install + install (same package)
#
# The classic double-click: two installs of the same package at the same instant.
# One must win. The other must either win idempotently or refuse as busy — and
# must not leave a half-extracted version behind either way.

conc_race_same "install-install" 2 -- "$LEXE" install "$v1" --yes --trust
conc_assert_no_timeouts "install-install" 2
conc_assert_losers_lost_legitimately "install-install" 2
note "exit codes seen: $(conc_codes "install-install" 2)"
acc_true "$([[ "$(conc_winners "install-install" 2)" -ge 1 ]] && echo 0 || echo 1)" \
    "install+install: at least one of them installed the application"
lc_assert_coherent "after install+install"
acc_equals "$(lc_current_version)" "1.0.0" "and 1.0.0 is the current version"

# --------------------------------------------- install + install (three ways)

"$LEXE" remove "$LC_APP_ID" --purge-data --yes >/dev/null 2>&1
conc_race_same "install-x3" 3 -- "$LEXE" install "$v1" --yes --trust
conc_assert_no_timeouts "install-x3" 3
conc_assert_losers_lost_legitimately "install-x3" 3
note "exit codes seen: $(conc_codes "install-x3" 3)"
lc_assert_coherent "after three simultaneous installs"

# --------------------------------------------- update + update (different versions)
#
# Two different mutations, not two copies of one. A lost update would show as a
# current version that neither participant installed, or as records describing a
# version whose files are not there.

conc_race_pair "update-update" \
    -- "$LEXE" install "$v2" --yes \
    -- "$LEXE" install "$v1" --yes
conc_assert_no_timeouts "update-update" 2
note "a exited $(conc_rc update-update a), b exited $(conc_rc update-update b)"
lc_assert_coherent "after update+update"
current="$(lc_current_version)"
acc_true "$([[ "$current" == "1.0.0" || "$current" == "2.0.0" ]] && echo 0 || echo 1)" \
    "after two competing updates the current version is one of them ($current)"
acc_equals "$(lc_running_version)" "$current" \
    "and the program that runs is the version the registry claims"

# --------------------------------------------- update + rollback
#
# The two operations most likely to disagree about what `current` should be.

"$LEXE" install "$v1" --yes >/dev/null 2>&1
"$LEXE" install "$v2" --yes >/dev/null 2>&1
conc_race_pair "update-rollback" \
    -- "$LEXE" install "$v1" --yes \
    -- "$LEXE" rollback "$LC_APP_ID"
conc_assert_no_timeouts "update-rollback" 2
note "install exited $(conc_rc update-rollback a), rollback exited $(conc_rc update-rollback b)"
lc_assert_coherent "after update+rollback"

# --------------------------------------------- repair + repair

"$LEXE" install "$v1" --yes >/dev/null 2>&1
entry="$(lc_installed_entry "$(lc_current_version)")"
printf 'damage' >> "$entry"
conc_race_same "repair-repair" 2 -- "$LEXE" repair "$LC_APP_ID"
conc_assert_no_timeouts "repair-repair" 2
conc_assert_losers_lost_legitimately "repair-repair" 2
note "exit codes seen: $(conc_codes "repair-repair" 2)"
lc_assert_coherent "after repair+repair"
acc_true "$("$LEXE" run "$LC_APP_ID" --no-terminal >/dev/null 2>&1; echo $?)" \
    "and the repaired application runs"

# --------------------------------------------- repair + uninstall

"$LEXE" install "$v1" --yes >/dev/null 2>&1
conc_race_pair "repair-uninstall" \
    -- "$LEXE" repair "$LC_APP_ID" \
    -- "$LEXE" remove "$LC_APP_ID" --yes
conc_assert_no_timeouts "repair-uninstall" 2
note "repair exited $(conc_rc repair-uninstall a), remove exited $(conc_rc repair-uninstall b)"
lc_assert_coherent "after repair+uninstall"
# Whichever won, the state must be decidable: either installed and runnable, or
# absent. A repair that "succeeded" against a removed application would be the
# interesting failure here.
if lc_is_installed; then
    acc_equals "$(lc_running_version)" "$(lc_current_version)" \
        "the surviving installation runs the version it claims"
else
    acc_dir_absent "$(lc_version_dir 1.0.0)" \
        "the removal completed, leaving no version directory behind"
fi

# --------------------------------------------- install + uninstall

"$LEXE" install "$v1" --yes >/dev/null 2>&1
conc_race_pair "install-uninstall" \
    -- "$LEXE" install "$v2" --yes \
    -- "$LEXE" remove "$LC_APP_ID" --yes
conc_assert_no_timeouts "install-uninstall" 2
note "install exited $(conc_rc install-uninstall a), remove exited $(conc_rc install-uninstall b)"
lc_assert_coherent "after install+uninstall"

# --------------------------------------------- the registry survived all of it
#
# Every mutation above touched installation.json. A record that no longer parses,
# or that describes a version with no directory, is registry corruption — and it
# would not necessarily have failed any single check above.

record="$(acc_installation_for "$LC_APP_ID")"
if [[ -f "$record" ]]; then
    parsed="$(acc_json "$record" 'd.get("id", "")' 2>/dev/null || echo PARSE_ERROR)"
    acc_equals "$parsed" "$LC_APP_ID" \
        "installation.json still parses and names the right application"
else
    pass "installation.json is absent, consistently with an uninstalled application"
fi

# No stray staging directories: each is a mutation that started and did not
# finish tidying up.
staging="$(find "$LEXE_HOME" -maxdepth 3 -name '.staging*' -o -maxdepth 3 -name '.repair-scratch' 2>/dev/null | head -3)"
acc_equals "$staging" "" \
    "no staging or scratch directory was left behind by any of the races"

# And a clean install still works after everything, which is the real test of
# whether the races left anything poisoned.
"$LEXE" remove "$LC_APP_ID" --purge-data --yes >/dev/null 2>&1
acc_true "$("$LEXE" install "$v1" --yes --trust >/dev/null 2>&1; echo $?)" \
    "a fresh install still succeeds after every race above"
acc_equals "$(lc_running_version)" "1.0.0" "and it runs"
"$LEXE" remove "$LC_APP_ID" --purge-data --yes >/dev/null 2>&1

acc_summary

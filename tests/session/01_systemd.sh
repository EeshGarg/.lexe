#!/usr/bin/env bash
# tests/session/01_systemd.sh — the session-manager boundary, against the real
# `systemd --user` of the invoking session (docs/SERVICES.md, §1).
#
# The claim under test is not "a unit file is produced". It is:
#
#     exactly one supervisor owns a running service, .LEXE and systemd agree on
#     which, and removing the application retracts the registration from both
#
# So every assertion that matters is checked against SYSTEMD's answer --
# `is-enabled`, `is-active`, `ExecMainStatus`, `MainPID` -- and not against
# `lexe service status`. A test that only asks .LEXE whether .LEXE succeeded
# cannot detect .LEXE being wrong, and the defect that motivated this lane
# (203/EXEC from an unquoted ExecStart) was invisible to every check except
# systemd's own.
set -uo pipefail
SESS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SESS_DIR/../acceptance/lib.sh"
source "$SESS_DIR/lib.sh"

acc_begin "session 01 systemd --user"
acc_require_binaries

if ! sess_have_systemd; then
    skip "no systemd --user session on this host"
    note "This feature does not apply here; \`lexe service\` reports it."
    note "The input-determined half is covered by tests/test_session.cpp."
    acc_summary
    exit $?
fi

acc_scratch_home
# Registered BEFORE anything is enabled, and after acc_scratch_home's own trap so
# both run: a unit left enabled against a scratch root that is about to be
# deleted would fail at the user's next login.
trap 'sess_cleanup; acc_teardown' EXIT

note "systemd: $(systemctl --version | head -1)"

if ! sess_install_service; then
    fail "the service example could not be built and installed"
    acc_summary
    exit $?
fi
pass "the heartbeat service example installs"

UNIT="$(sess_unit)"

# --------------------------------------------------------------- before enable

acc_contains "$("$LEXE" service --json 2>&1)" '"status": "available"' \
    "lexe service reports the host capability"

status_json="$("$LEXE" service status "$SESS_APP_ID" --json 2>&1)"
acc_contains "$status_json" '"sessionManageable": true' \
    "a launch.mode service is reported as session-manageable"
acc_contains "$status_json" '"supervisor": "none"' \
    "nothing supervises it before it is enabled"
acc_file_absent "$(sess_unit_file)" "no unit exists before enabling"
acc_equals "$(sess_is_enabled)" "not-found" \
    "systemd does not know the unit before enabling"

# A GUI or console application must be refused, because a unit that restarted a
# desktop application on exit would fight the user closing its window.
"$LEXE" service enable "org.lexe.examples.gui-hello" >/dev/null 2>&1
acc_true "$([[ $? -ne 0 ]] && echo 0 || echo 1)" \
    "enabling something that is not installed fails rather than half-succeeding"

# ---------------------------------------------------------------------- enable

enable_out="$("$LEXE" service enable "$SESS_APP_ID" 2>&1)"
enable_rc=$?
acc_true "$enable_rc" "lexe service enable succeeds" "$enable_out"
acc_file_exists "$(sess_unit_file)" "the unit file is written under LEXE_HOME"
acc_equals "$(sess_is_enabled)" "enabled" \
    "SYSTEMD agrees the unit is enabled"

# The unit must name the runtime absolutely and QUOTED. This is the regression:
# a systemd --user unit inherits no PATH, and systemd splits ExecStart on
# whitespace, so an unquoted path with a space fails 203/EXEC at every start.
unit_text="$(cat "$(sess_unit_file)")"
acc_contains "$unit_text" "--wait" \
    "ExecStart passes --wait, so systemd supervises the payload's whole life"
acc_contains "$unit_text" "Type=simple" "the unit is Type=simple"
acc_contains "$unit_text" "Restart=on-failure" \
    "a clean exit is not restarted"
exec_line="$(grep '^ExecStart=' "$(sess_unit_file)")"
acc_true "$([[ "$exec_line" == ExecStart=\"* ]] && echo 0 || echo 1)" \
    "the runtime path is quoted, so a path containing a space still execs" \
    "$exec_line"

# systemd resolved the unit to OUR file, which is what enable-by-absolute-path
# buys: production and this scratch root take one code path.
fragment="$(sess_show "" FragmentPath)"
acc_true "$([[ -n "$fragment" ]] && echo 0 || echo 1)" \
    "systemd resolved a fragment path for the unit" "$fragment"

acc_contains "$("$LEXE" service status "$SESS_APP_ID" --json 2>&1)" \
    '"enabled": true' "lexe service status agrees with systemd"
acc_contains "$(cat "$LEXE_HOME/integration.json" 2>/dev/null)" "session-unit" \
    "the unit is recorded as a durable integration artifact"

# ----------------------------------------------------------------- it must RUN

systemctl --user start "$UNIT" >/dev/null 2>&1
# Give it time to either come up or fail. A service that fails execs and is
# restarted looks "activating" for a while, so the status alone is not enough --
# ExecMainStatus is what distinguishes running from looping.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [[ "$(sess_is_active)" == "active" ]] && break
    sleep 1
done
acc_equals "$(sess_is_active)" "active" "SYSTEMD reports the service active"
acc_equals "$(sess_show "" ExecMainStatus)" "0" \
    "the main process did not fail to exec (203 means an unusable ExecStart)"
main_pid="$(sess_show "" MainPID)"
acc_true "$([[ -n "$main_pid" && "$main_pid" != "0" ]] && echo 0 || echo 1)" \
    "systemd holds a real MainPID for it" "MainPID=$main_pid"

# The MainPID must be the `lexe` process, not the payload: that is what --wait
# is for, and it is what lets `systemctl stop` tear the sandbox down through the
# mechanism systemd already uses.
main_comm="$(ps -o comm= -p "$main_pid" 2>/dev/null | tr -d ' ')"
acc_equals "$main_comm" "lexe" \
    "the unit's main process is the lexe runtime, so stop reaches the sandbox"

acc_contains "$("$LEXE" service status "$SESS_APP_ID" 2>&1)" \
    "the session manager" "lexe names the session manager as the supervisor"

# ------------------------------------------------- exactly one supervisor

# The lease is the only liveness signal the runtime has, and a running unit
# holds it. What must NOT happen is .LEXE reporting a second, competing
# supervisor for the process systemd is already running.
acc_contains "$("$LEXE" service status "$SESS_APP_ID" --json 2>&1)" \
    '"lexeSupervisedRunning": false' \
    "a systemd-run service is not also reported as lexe-supervised"

# ------------------------------------------------------------- stop tears down

systemctl --user stop "$UNIT" >/dev/null 2>&1
for _ in 1 2 3 4 5; do
    [[ "$(sess_is_active)" != "active" ]] && break
    sleep 1
done
acc_true "$([[ "$(sess_is_active)" != "active" ]] && echo 0 || echo 1)" \
    "systemctl stop stops it" "$(sess_is_active)"
strays="$(pgrep -f "$LEXE_HOME" 2>/dev/null | wc -l)"
acc_equals "$strays" "0" \
    "stopping the unit left no process running out of the scratch root"

# ------------------------------------------------------- doctor sees the unit

doctor_out="$("$LEXE" doctor --json 2>&1)"
acc_contains "$doctor_out" "session-unit" \
    "lexe doctor reports the unit among the registrations it watches"

# A missing unit file is a repairable artifact; whether it is ENABLED is not,
# because that is a decision the user made.
rm -f "$(sess_unit_file)"
"$LEXE" doctor --repair >/dev/null 2>&1
acc_file_exists "$(sess_unit_file)" \
    "doctor --repair regenerates a deleted unit file from installed state"
acc_equals "$(sess_is_enabled)" "enabled" \
    "and does not change whether it is enabled"

# ---------------------------------------------------------------- disable

"$LEXE" service disable "$SESS_APP_ID" >/dev/null 2>&1
acc_equals "$(sess_is_enabled)" "not-found" \
    "SYSTEMD no longer knows the unit after disable"
acc_file_absent "$(sess_unit_file)" "the unit file is gone"
acc_true "$("$LEXE" service disable "$SESS_APP_ID" >/dev/null 2>&1; echo $?)" \
    "disable is idempotent: disabling nothing succeeds"

# ------------------------------------------- uninstall must retract, not orphan

"$LEXE" service enable "$SESS_APP_ID" >/dev/null 2>&1
acc_equals "$(sess_is_enabled)" "enabled" "re-enabled for the removal test"

"$LEXE" uninstall "$SESS_APP_ID" --yes >"$ACC_ROOT/work/remove.log" 2>&1
acc_true "$?" "lexe uninstall succeeds with a service enabled" \
    "$(cat "$ACC_ROOT/work/remove.log")"
acc_equals "$(sess_is_enabled)" "not-found" \
    "removing the application retracted the unit from systemd too"
acc_file_absent "$(sess_unit_file)" "and removed the unit file"
sess_assert_profile_clean \
    "nothing of this lane is left in the real user session"

acc_summary

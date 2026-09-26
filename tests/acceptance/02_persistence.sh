#!/usr/bin/env bash
# 02 — the reboot / session-change boundary, WITHOUT requiring a real reboot.
#
# Definitive Architecture acceptance criteria covered here:
#   * "Reboot the machine. Double-click the same run.lexe again; the
#      application opens identically."
#   * "Restart or change the desktop session; launch remains under .LEXE
#      control."
#
# A reboot cannot be automated, but what a reboot (or a session change, or a
# desktop that rewrites its own associations) DESTROYS can be reproduced
# exactly. §15.1 says integration must be durable, explicit and repairable, so
# this script destroys each class of state in turn and asserts that
#
#   (a) `lexe doctor` REPORTS the breakage and NAMES the artifact, and
#   (b) `lexe doctor --repair` re-establishes it FROM INSTALLED STATE — the
#       original .lexe package is deleted first, so nothing may depend on it —
#   (c) run.lexe still launches the application afterwards.
#
# The genuinely manual parts (a real reboot, a real double-click) are in
# REBOOT.md.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

acc_begin "02 persistence across a reboot / session change"
acc_require_binaries
acc_scratch_home
acc_build_package
acc_install_package

ref="$(acc_launch_ref)"
entry="$(acc_desktop_entry)"
mimeapps="$(acc_mimeapps)"
integration="$(acc_integration)"

entry_before="$(sha256sum "$entry" | cut -d' ' -f1)"

# The reboot test is only meaningful if repair does NOT need the package.
rm -f "$ACC_PACKAGE"
acc_file_absent "$ACC_PACKAGE" "the original .lexe package is gone before any repair"

# `lexe doctor` exists in this build? (It is the command that makes the reboot
# test automatable; without it the assertions below cannot run.)
if ! "$LEXE" help 2>&1 | grep -q '^  doctor'; then
    skip "lexe doctor is not in this build — integration verify/repair not asserted"
    acc_summary
    exit $?
fi

acc_launch_via_reference() {
    # Launch through run.lexe exactly as a double-click would. The payload
    # appends to its own launch log BEFORE it touches GTK, so this assertion
    # works on a headless host too.
    local before after status
    before="$(acc_launch_count)"
    set +e
    PATH="$ACC_PATH_DIR:$PATH" timeout 3 "$LEXE" open "$ref" >"$ACC_ROOT/work/open.out" 2>&1
    status=$?
    set -e
    acc_kill_app
    sleep 0.3
    after="$(acc_launch_count)"
    if [[ "$after" -gt "$before" ]]; then
        pass "$1"
        case "$status" in
            124) note "the GUI stayed up until the 3s timeout (a window was open)" ;;
            2)   note "no display on this host: the payload started and exited 2 (headless)" ;;
            *)   note "payload exit status $status" ;;
        esac
    else
        fail "$1" "launch log did not grow ($before -> $after); exit status $status" \
             "$(head -5 "$ACC_ROOT/work/open.out")"
    fi
}

# --------------------------------------------------------------- baseline
acc_launch_via_reference "run.lexe launches the application before anything is broken"

# ------------------------------------------ 1. session caches are rebuilt
# A reboot/session restart regenerates the freedesktop caches. Losing them
# must not cost .LEXE control of the launch.
rm -f "$LEXE_HOME/applications/mimeinfo.cache" "$LEXE_HOME/mime/mime.cache"
rm -rf "$LEXE_HOME/cache"
acc_launch_via_reference "run.lexe still launches after the session caches are wiped"

# ---------------------------------------- 2. an icon is lost (§15.1 artifact)
# Icons are recorded in integration.json, so they are inside the durability
# contract: doctor must both REPORT and REPAIR a missing one. This runs
# BEFORE every other breakage, so the registration state under test is
# exactly what the install wrote.
icon="$LEXE_HOME/icons/hicolor/64x64/apps/lexe-$ACC_APP_ID.png"
acc_file_exists "$icon" "the 64px icon is present before this check"
rm -f "$icon"
set +e
"$LEXE" doctor >"$ACC_ROOT/work/doctor-noicon.txt" 2>/dev/null
set -e
acc_contains "$(cat "$ACC_ROOT/work/doctor-noicon.txt")" "$icon" "doctor NAMES the missing icon"
"$LEXE" doctor --repair >/dev/null 2>&1 || true
if [[ -f "$icon" ]]; then
    pass "doctor --repair restores the missing icon"
else
    fail "doctor --repair restores the missing icon" \
        "PRODUCT DEFECT (src/lexe/integration/integration.cpp DesktopIntegration::repair):" \
        "repair() passes <version-dir>/icons as the icon source, but the installer" \
        "never writes the package's icons/ into the version directory, so the" \
        "directory never exists. install_app() then records ZERO app-icon" \
        "artifacts and state.replace_scope() DROPS the icon registrations." \
        "Effect: the icon is not restored, the three surviving icons are" \
        "silently de-registered, and doctor now calls the system healthy."
fi
icons_registered="$(acc_json "$integration" "sum(1 for a in d['artifacts'] if a['kind'] == 'app-icon')")"
if [[ "$icons_registered" == "4" ]]; then
    pass "integration.json still owns all four icons after a repair"
else
    fail "integration.json still owns all four icons after a repair" \
        "app-icon artifacts recorded after repair: $icons_registered (expected 4)" \
        "Same defect as above: the icons remain on disk but .LEXE no longer" \
        "knows it owns them, so they are never verified again and are left" \
        "behind on uninstall."
fi

# ------------------------- 3. the desktop entry + default association are lost
# This is the alpha's actual post-reboot symptom: the menu entry disappears and
# something else owns application/vnd.usha.lexe.
rm -f "$entry"
python3 - "$mimeapps" <<'PY'
import sys
path = sys.argv[1]
text = open(path).read()
open(path, "w").write(
    text.replace("application/vnd.usha.lexe=lexe-handler.desktop\n", ""))
PY

doctor_out="$ACC_ROOT/work/doctor-broken.txt"
set +e
"$LEXE" doctor >"$doctor_out" 2>/dev/null
doctor_status=$?
set -e
acc_true "$([[ $doctor_status -ne 0 ]] && echo 0 || echo 1)" \
    "lexe doctor exits non-zero when integration is broken"
acc_contains "$(cat "$doctor_out")" "$entry" "doctor NAMES the missing .desktop entry"
acc_contains "$(cat "$doctor_out")" "no persistent default association" \
    "doctor NAMES the lost default .lexe association"
acc_contains "$(cat "$doctor_out")" "$mimeapps" "doctor points at the mimeapps.list that lost it"

repair_out="$ACC_ROOT/work/doctor-repair.txt"
set +e
"$LEXE" doctor --repair >"$repair_out" 2>/dev/null
repair_status=$?
set -e
acc_equals "$repair_status" "0" "lexe doctor --repair succeeds"
acc_file_exists "$entry" "the .desktop entry is restored"
acc_equals "$(sha256sum "$entry" | cut -d' ' -f1)" "$entry_before" \
    "the restored .desktop entry is byte-identical to the installed one"
acc_equals "$(grep -m1 '^Exec=' "$entry")" "Exec=lexe run $ACC_APP_ID" \
    "the restored entry still launches through lexe, not the raw ELF"
acc_contains "$(cat "$mimeapps")" "application/vnd.usha.lexe=lexe-handler.desktop" \
    "the persistent default association is restored"

set +e
"$LEXE" doctor >/dev/null 2>&1
doctor_status=$?
set -e
acc_equals "$doctor_status" "0" "lexe doctor reports a healthy system again"

acc_launch_via_reference "run.lexe still launches after the desktop integration was repaired"

# ----------------------------------- 4. the launch reference itself is lost
rm -f "$ref"
set +e
"$LEXE" doctor >"$ACC_ROOT/work/doctor-noref.txt" 2>/dev/null
set -e
acc_contains "$(cat "$ACC_ROOT/work/doctor-noref.txt")" "$ref" \
    "doctor NAMES the missing run.lexe launch reference"
"$LEXE" doctor --repair >/dev/null 2>&1 || true
acc_file_exists "$ref" "the run.lexe launch reference is regenerated"

ref_json="$ACC_ROOT/work/verify-ref2.json"
"$LEXE" verify "$ref" --json >"$ref_json"
acc_equals "$(acc_json "$ref_json" 'd["ok"]')" "True" "the regenerated launch reference verifies"
acc_contains "$(acc_json "$ref_json" "[s['detail'] for s in d['stages'] if s['name']=='payload-role'][0]")" \
    "role \"launch\"" "the regenerated reference still has role \"launch\""
ref_manifest="$ACC_ROOT/work/ref-manifest.json"
"$LEXE" inspect "$ref" --manifest >"$ref_manifest"
acc_equals "$(acc_json "$ref_manifest" 'd["launch"]["applicationId"]')" "$ACC_APP_ID" \
    "the regenerated reference still names the installed application"
# `lexe open` on a role "launch" artifact RUNS it; it installs nothing. Run it
# with no display so the payload exits promptly and stdout is flushed.
open_json="$(set +e; env -u WAYLAND_DISPLAY -u DISPLAY timeout 10 "$LEXE" open "$ref" --json --no-terminal 2>/dev/null; true)"
acc_kill_app
acc_contains "$open_json" "\"action\": \"run\"" \
    "opening a role \"launch\" artifact is a RUN, not an install"
acc_contains "$open_json" "\"applicationId\": \"$ACC_APP_ID\"" \
    "lexe open resolves the reference to the installed application"

# `lexe launch-ref` regenerates an equivalent artifact on demand.
if "$LEXE" help 2>&1 | grep -q '^  launch-ref'; then
    "$LEXE" launch-ref "$ACC_APP_ID" -o "$ACC_ROOT/work/run-explicit.lexe" >/dev/null 2>&1
    acc_file_exists "$ACC_ROOT/work/run-explicit.lexe" "lexe launch-ref writes a launch reference on demand"
    "$LEXE" verify "$ACC_ROOT/work/run-explicit.lexe" --json >"$ACC_ROOT/work/verify-ref3.json"
    acc_equals "$(acc_json "$ACC_ROOT/work/verify-ref3.json" 'd["ok"]')" "True" \
        "the on-demand launch reference verifies too"
else
    skip "lexe launch-ref is not in this build"
fi

# --------------------------------- 5. the whole state file is lost (worst case)
rm -f "$integration"
set +e
"$LEXE" doctor >"$ACC_ROOT/work/doctor-nostate.txt" 2>/dev/null
doctor_status=$?
set -e
acc_true "$([[ $doctor_status -ne 0 ]] && echo 0 || echo 1)" \
    "doctor reports a problem when integration.json itself is lost"
acc_contains "$(cat "$ACC_ROOT/work/doctor-nostate.txt")" "$ACC_APP_ID" \
    "doctor NAMES the application that has no integration recorded"
"$LEXE" doctor --repair >/dev/null 2>&1 || true
acc_file_exists "$integration" "integration.json is rebuilt from installed state"
acc_file_exists "$entry" "the .desktop entry survives a full state-file rebuild"
acc_file_exists "$ref" "the run.lexe launch reference survives a full state-file rebuild"
acc_launch_via_reference "run.lexe still launches after integration.json was rebuilt"

acc_summary

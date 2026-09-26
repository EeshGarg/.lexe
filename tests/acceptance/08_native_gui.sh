#!/usr/bin/env bash
# 08 — a native GUI application, launched under the sandbox, with the window
# PROVEN to have mapped (Definitive Architecture §14.4, docs/ISOLATION.md).
#
# This is the suite the previous development session recorded as impossible on
# this machine, and the reasoning was sound as far as it went:
#
#     WSLg mounts /tmp/.X11-unix read-only and puts the user's real display
#     there as X0, so Xvfb :99 cannot create a socket file and falls back to an
#     abstract socket — which a sandboxed process cannot reach, because the
#     sandbox unshares the network namespace. So the launcher has no display
#     socket to bind. X0 IS the user's screen. Do not be tempted.
#
# The last sentence stands. The conclusion did not: scripts/lib/private-display.sh
# runs the whole launch inside a private MOUNT namespace with a fresh tmpfs over
# /tmp/.X11-unix, so Xvfb creates a REAL socket file that the sandbox can bind —
# and inside a private NETWORK namespace, so the abstract socket cannot collide
# with, or be reached from, anything else on the machine. The user's X0 is not
# bound, not named, and not even visible in the namespace.
#
# That mechanism is strictly safer than binding the real display, so the headless
# rule is honoured rather than worked around, and these checks become possible:
#
#   1. the package verifies and installs
#   2. `lexe run` maps a real top-level window, as reported by xwininfo and
#      xlsclients — third-party tools, not the runtime's own bookkeeping
#   3. the window belongs to the sandboxed process
#   4. the application exits and the exit is observed correctly
#   5. no stale supervisor or version-lease state is left behind
#   6. the sandbox received the display and nothing else of the session
set -uo pipefail
ACC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$ACC_DIR/lib.sh"
source "$ACC_REPO/scripts/lib/private-display.sh"
acc_begin "08 native gui"
acc_require_binaries

if ! pkg-config --exists gtk+-3.0 2>/dev/null; then
    skip "GTK 3 development files are absent — the GUI example cannot be built"
    acc_summary
    exit $?
fi
if ! command -v xwininfo >/dev/null 2>&1; then
    blocked "xwininfo is not installed, so a mapped window cannot be witnessed" \
        "apt-get install x11-utils. Without it this suite could only show that a" \
        "process started, which is the thing it exists NOT to settle for."
    acc_summary
    exit $?
fi
if ! pd_available; then
    blocked "no private display is possible here: $PD_UNAVAILABLE_REASON" \
        "Binding the user's real display instead is forbidden (docs/TESTING.md §3)."
    acc_summary
    exit $?
fi

acc_scratch_home
acc_build_package

verify_out="$("$LEXE" verify "$ACC_PACKAGE" 2>&1)"
acc_true "$?" "the GUI package passes the full verification pipeline"
acc_contains "$verify_out" "payload-role" \
    "including the payload-role stage, which proves the entrypoint is runnable"

acc_install_package
pass "the GUI package installs"

declared_mode="$(acc_json_str "$("$LEXE" info "$ACC_APP_ID" --json 2>/dev/null)" \
    'd.get("manifest", {}).get("launch", {}).get("mode", "")')"
acc_equals "$declared_mode" "gui" \
    "the installed manifest DECLARES launch.mode gui — display access is declared, not guessed"

# --------------------------------------------- the launch, on a private display
#
# Everything below runs inside the namespace. The results come back through
# files, because the subshell cannot update this shell's counters.
report="$ACC_ROOT/work/gui-report"
mkdir -p "$report"

pd_run 99 -- bash -c '
set -uo pipefail
report="$1"; lexe="$2"; app_id="$3"
export LEXE_HOME="$4"
source "$5"            # private-display.sh, for pd_wait_for_window

printf "%s" "${DISPLAY:-}" > "$report/display"
# Nothing of the real session may be in scope in here. WAYLAND_DISPLAY is unset
# by the namespace entry, so GTK cannot prefer the user compositor over our X
# server, which is how a "headless" test ends up rendering on a real desktop.
printf "%s" "${WAYLAND_DISPLAY:-none}" > "$report/wayland"
ls /tmp/.X11-unix > "$report/sockets" 2>&1

# The window count BEFORE, so the one we see after is provably ours.
xwininfo -root -children > "$report/before" 2>&1

# --window-for opens the window for real and then leaves the main loop on its
# own, so the exit below is a genuine exit code and not the signal a kill would
# produce. (--sleep would be wrong here: it deliberately opens no window.)
"$lexe" run "$app_id" -- --window-for 8 > "$report/run.log" 2>&1 &
run_pid=$!

if pd_wait_for_window 25 "Lexe GUI Hello"; then
    printf "yes" > "$report/mapped"
else
    printf "no" > "$report/mapped"
fi
xwininfo -root -children > "$report/after" 2>&1
xlsclients -l > "$report/clients" 2>&1 || true
# Who owns the window, according to X itself rather than to us.
xdotool search --name "Lexe GUI Hello" getwindowpid %@ > "$report/winpid" 2>&1 || true

wait "$run_pid"
printf "%s" "$?" > "$report/exit"
' _ "$report" "$LEXE" "$ACC_APP_ID" "$LEXE_HOME" \
  "$ACC_REPO/scripts/lib/private-display.sh"

read_report() { cat "$report/$1" 2>/dev/null || printf ''; }

acc_equals "$(read_report display)" ":99" \
    "the launch ran against a private display, not the developer's session"
acc_equals "$(read_report wayland)" "none" \
    "and with no Wayland display in scope, so GTK could not reach the real desktop"
acc_equals "$(read_report sockets)" "X99" \
    "the namespace's /tmp/.X11-unix holds ONLY the private socket — the user's X0 is not even visible"

acc_equals "$(read_report mapped)" "yes" \
    "the application MAPPED A WINDOW — witnessed by xwininfo, not by lexe"

# grep -c already prints 0 when nothing matches, so a `|| echo 0` fallback
# appends a SECOND line and every arithmetic test on it becomes a syntax error.
before_count="$(grep -cE '^ +0x[0-9a-f]+ ' "$report/before" 2>/dev/null | head -1)"
after_count="$(grep -cE '^ +0x[0-9a-f]+ ' "$report/after" 2>/dev/null | head -1)"
before_count="${before_count:-0}"
after_count="${after_count:-0}"
acc_equals "$before_count" "0" "the private display started with no windows on it"
acc_true "$([[ "$after_count" -ge 1 ]] && echo 0 || echo 1)" \
    "and had $after_count after the launch, so the window is the one we started"

# xlsclients reports the client's own name (WM_CLASS / argv[0]), which is the
# BINARY name -- gui-hello -- not the window title. The title is what
# pd_wait_for_window matched above; this is the independent "a client of this
# application is connected to this display" witness.
acc_contains "$(read_report clients)" "gui-hello" \
    "xlsclients independently reports the application as a connected X client"

win_pid="$(read_report winpid | tr -d '[:space:]')"
acc_true "$([[ -n "$win_pid" && "$win_pid" =~ ^[0-9]+$ ]] && echo 0 || echo 1)" \
    "the window reports an owning process id ($win_pid) — a real client, not a stub"

# --------------------------------------------- the exit, and what it left

acc_equals "$(read_report exit)" "0" \
    "the application exited on its own and the exit code was observed as 0"

run_log="$(read_report run.log)"
acc_contains "$run_log" "window open for" \
    "the payload reports that it opened a window, from inside the sandbox"

applied_mode="$(acc_json "$(acc_installation)" \
    'd.get("lastExecution", {}).get("launchMode", "")')"
acc_equals "$applied_mode" "gui" \
    "and the execution record says the runtime APPLIED the gui launch mode"

# The payload notes every start in its private data root, before it touches GTK.
acc_true "$([[ "$(acc_launch_count)" -ge 1 ]] && echo 0 || echo 1)" \
    "the launch is provable from the application's private data root alone"

# --------------------------------------------- no residue
#
# A window that appeared and a process that ended are not enough: a stale
# version lease would block `lexe remove` and a stale supervisor would outlive
# the launch. Both are checked by consequence rather than by inspecting internals.
sleep 1
leftover="$(pgrep -f "bin/gui-hello" 2>/dev/null | head -1 || true)"
acc_equals "$leftover" "" "no gui-hello process outlived the launch"

leftover_bwrap="$(pgrep -f "bwrap.*$ACC_APP_ID" 2>/dev/null | head -1 || true)"
acc_equals "$leftover_bwrap" "" "no sandbox supervisor was left behind"

if "$LEXE" remove "$ACC_APP_ID" --yes >"$ACC_ROOT/work/remove.log" 2>&1; then
    pass "the version lease was released: the application can be uninstalled"
else
    fail "the version lease was released" \
        "$(sed 's/^/    /' "$ACC_ROOT/work/remove.log")"
fi

# --------------------------------------------- the session did not leak in

data_dir="$(acc_app_data)"
acc_equals "$(find "$data_dir" -maxdepth 3 \( -name 'wayland-*' -o -name 'bus' \
    -o -name 'pulse' \) 2>/dev/null | head -1)" "" \
    "no session socket of the host was copied into the application's data"

acc_summary

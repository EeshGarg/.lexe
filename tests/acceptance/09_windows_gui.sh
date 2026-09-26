#!/usr/bin/env bash
# 09 — a Windows GUI program, sandboxed, with the window PROVEN to have mapped,
# through Wine and again through Proton.
#
# The three suites before this one each settle a different question, and none of
# them settles this one:
#
#   * 06 proves a foreign-OS PROCESS runs through Wine — stdout crosses the
#     boundary, arguments arrive, the private data root is writable from inside
#     Windows. It is a console program, so no window is involved.
#   * 07 proves the same through Proton.
#   * 08 proves a NATIVE GUI window maps on a private display.
#
# A foreign-OS window is not implied by either half. The compatibility layer has
# to reach a display of its own accord, the sandbox has to have bound a display
# socket that a Windows process can use through the layer, and a window manager
# has to see a top-level window appear. Each of those can fail while the other two
# work.
#
# The window is witnessed with xwininfo and xlsclients — third-party tools, on a
# display created by scripts/lib/private-display.sh that the user cannot see and
# nothing else on the machine can reach. The user's own display is not bound, not
# named, and not visible in the namespace.
#
# One environmental detail worth recording, because it wasted time: inside the
# private display's user namespace the invoking user maps to root, and anything
# owned by the REAL root (such as /tmp itself) maps to `nobody`. Wine refuses to
# create a prefix in a directory it does not own — "'/tmp' is not owned by you" —
# so the prefix has to live somewhere the invoking user owns. Under .LEXE it
# always does: HOME inside the sandbox is the application's private data root,
# which the runtime created as that user.
set -uo pipefail
ACC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$ACC_DIR/lib.sh"
source "$ACC_REPO/scripts/lib/private-display.sh"
acc_begin "09 windows gui"
acc_require_binaries

WIN_EXAMPLE="$ACC_REPO/examples/windows/gui-hello"
WIN_ID="com.usha.windowsgui"

if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    skip "x86_64-w64-mingw32-gcc is not installed — cannot build a Windows GUI payload"
    acc_summary
    exit $?
fi
if ! command -v xwininfo >/dev/null 2>&1; then
    blocked "xwininfo is not installed, so a mapped window cannot be witnessed" \
        "apt-get install x11-utils."
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
work="$ACC_ROOT/work"
project="$work/windows-gui"
key="$work/key.json"
package="$work/windows-gui.lexe"
mkdir -p "$project"
cp -r "$WIN_EXAMPLE/lexe.json" "$WIN_EXAMPLE/src" "$WIN_EXAMPLE/Makefile" "$project/"

if ! make -s -C "$project" >"$work/make.log" 2>&1; then
    fail "the Windows GUI payload cross-compiles" \
        "$(sed 's/^/    /' "$work/make.log")"
    acc_summary
    exit $?
fi
pass "the Windows GUI payload cross-compiles with MinGW"

# It must be a GUI-subsystem image, not a console one: that is the difference
# from examples/windows/console-hello at the PE header level, and it is what makes this
# suite about windows rather than about processes.
subsystem="$(file -b "$project/payload/bin/windows-gui.exe" 2>/dev/null)"
acc_contains "$subsystem" "(GUI)" \
    "and an independent tool agrees it is a GUI-subsystem PE"

"$LEXE" keygen "$key" >/dev/null
if ! "$LEXE" build "$project" -o "$package" --key "$key" >"$work/build.log" 2>&1; then
    fail "lexe build packaged it" "$(sed 's/^/    /' "$work/build.log")"
    acc_summary
    exit $?
fi
pass "lexe build packaged a Windows GUI payload"

verify_out="$("$LEXE" verify "$package" 2>&1)"
acc_true "$?" "it passes the full verification pipeline"
acc_contains "$verify_out" "windows" "payload-role reports a Windows payload"

if ! "$LEXE" install "$package" --yes --trust >"$work/install.log" 2>&1; then
    fail "it installs" "$(sed 's/^/    /' "$work/install.log")"
    acc_summary
    exit $?
fi
pass "it installs"

declared_mode="$(acc_json_str "$("$LEXE" info "$WIN_ID" --json 2>/dev/null)" \
    'd.get("manifest", {}).get("launch", {}).get("mode", "")')"
acc_equals "$declared_mode" "gui" \
    "the manifest DECLARES a gui launch mode, so display access is declared"

# --------------------------------------------- the launch, once per chain

# run_chain <chain> — install-time state is shared; only the chain differs.
run_chain() {
    local chain="$1"
    local report="$work/report-$chain"
    mkdir -p "$report"

    if ! "$LEXE" compat "$WIN_ID" --set "$chain" >"$work/compat-$chain.log" 2>&1; then
        fail "the $chain chain can be selected" \
            "$(sed 's/^/    /' "$work/compat-$chain.log")"
        return 1
    fi
    local resolved
    resolved="$(acc_json_str "$("$LEXE" compat "$WIN_ID" --json 2>/dev/null)" \
        'd.get("chain", "")')"
    if [[ "$resolved" != "$chain" ]]; then
        fail "the resolver selects $chain" "it selected \"$resolved\""
        return 1
    fi
    pass "the resolver selects $chain for this application"

    pd_run 99 -- bash -c '
set -uo pipefail
report="$1"; lexe="$2"; app_id="$3"; export LEXE_HOME="$4"
source "$5"

printf "%s" "${DISPLAY:-}" > "$report/display"
ls /tmp/.X11-unix > "$report/sockets" 2>&1
xwininfo -root -children > "$report/before" 2>&1

# A generous budget: the first launch through a chain creates its prefix, which
# took ~20s on the machine this was written on.
"$lexe" run "$app_id" -- --window-for 8 > "$report/run.log" 2>&1 &
run_pid=$!

if pd_wait_for_window 180 "Lexe Windows GUI"; then
    printf "yes" > "$report/mapped"
else
    printf "no" > "$report/mapped"
fi
xwininfo -root -children > "$report/after" 2>&1
xlsclients -l > "$report/clients" 2>&1 || true

wait "$run_pid"
printf "%s" "$?" > "$report/exit"
' _ "$report" "$LEXE" "$WIN_ID" "$LEXE_HOME" \
      "$ACC_REPO/scripts/lib/private-display.sh"

    local read_report
    read_report() { cat "$report/$1" 2>/dev/null || printf ''; }

    acc_equals "$(read_report display)" ":99" \
        "$chain: it ran against a private display, not the developer's session"
    acc_equals "$(read_report sockets)" "X99" \
        "$chain: only the private socket is visible — the user's X0 is not in the namespace"

    acc_equals "$(read_report mapped)" "yes" \
        "$chain: A WINDOWS PROGRAM MAPPED A WINDOW ON LINUX — witnessed by xwininfo"

    local after
    after="$(grep -cE '^ +0x[0-9a-f]+ ' "$report/after" 2>/dev/null | head -1)"
    acc_true "$([[ "${after:-0}" -ge 1 ]] && echo 0 || echo 1)" \
        "$chain: the display has ${after:-0} top-level window(s) where it began with none"

    acc_contains "$(read_report after)" "Lexe Windows GUI" \
        "$chain: and the window carries the application's own title"
    # xlsclients lists clients that set WM_CLIENT_MACHINE, and Wine's windows do
    # not, so it reports nothing here even with a window plainly on screen. What
    # xwininfo prints is better evidence anyway: the WM_CLASS names the Windows
    # EXECUTABLE, and the geometry shows a real sized window rather than a
    # zero-size placeholder that technically exists.
    # The WM_CLASS says which foreign-OS client owns the window, and the two
    # chains answer differently: Wine reports the PE's own name
    # ("windows-gui.exe"), Proton reports itself ("steam_proton") because it sets
    # its own class. Both are evidence that a foreign-OS client owns this window
    # rather than something native; asserting one of them for both chains would
    # just be wrong about Proton.
    local expect_class="windows-gui.exe"
    [[ "$chain" == "proton" ]] && expect_class="steam_proton"
    acc_contains "$(read_report after)" "$expect_class" \
        "$chain: the window's WM_CLASS names its foreign-OS owner ($expect_class)"
    local geometry
    # xwininfo prints `WxH+X+Y`, and the window ID on the same line is `0x1600001`
    # -- which a bare [0-9]+x[0-9]+ happily matches inside. Require the offset that
    # follows a real geometry.
    geometry="$(grep -F "Lexe Windows GUI" "$report/after" 2>/dev/null |
        grep -oE '[0-9]+x[0-9]+\+[-0-9]+\+[-0-9]+' | head -1 |
        grep -oE '^[0-9]+x[0-9]+')"
    acc_true "$([[ -n "$geometry" && "$geometry" != "1x1" && \
                   "$geometry" != "0x0" ]] && echo 0 || echo 1)" \
        "$chain: and it is a real sized window ($geometry), not a placeholder"

    acc_equals "$(read_report exit)" "0" \
        "$chain: it closed its own window and exited 0 — a real exit, not a kill"
    acc_contains "$(read_report run.log)" "window open for" \
        "$chain: the payload's own stdout crossed the compatibility boundary"

    local recorded
    recorded="$(acc_json "$(acc_installation_for "$WIN_ID")" \
        'd.get("lastExecution", {}).get("chain", "")')"
    acc_equals "$recorded" "$chain" \
        "$chain: the execution report records the chain that actually ran it"
    return 0
}

run_chain wine

# --------------------------------------------- and again through Proton

proton_available="$(acc_json_str "$("$LEXE" runtime show proton --json 2>/dev/null)" \
    'str(d.get("available", False))')"
if [[ "$proton_available" == "True" ]]; then
    run_chain proton
else
    blocked "no Proton installation on this host — the Proton GUI path is unproven" \
        "Install a Proton build under ~/.steam/root/compatibilitytools.d/," \
        "or point LEXE_PROTON at one. See docs/TESTING.md §4."
fi

# --------------------------------------------- no residue, either way

data_dir="$LEXE_HOME/data/$WIN_ID"
acc_file_exists "$data_dir/windows-gui-launches.log" \
    "every launch is provable from the private data root alone"
acc_equals "$(find "$data_dir" -maxdepth 3 \( -name 'wayland-*' -o -name 'bus' \
    -o -name 'pulse' \) 2>/dev/null | head -1)" "" \
    "no session socket of the host was copied into the application's data"

leftover="$(pgrep -f "windows-gui.exe" 2>/dev/null | head -1 || true)"
acc_equals "$leftover" "" "no Windows process outlived the launches"

acc_true "$("$LEXE" remove "$WIN_ID" --purge-data --yes >/dev/null 2>&1; echo $?)" \
    "the version lease was released: it can be uninstalled"

acc_summary

#!/usr/bin/env bash
# tests/session/lib.sh — helpers for the session-manager lane.
#
# Sourced AFTER tests/acceptance/lib.sh, whose reporting and scratch LEXE_HOME
# these reuse. What this adds is a real service package and a guard.
#
# ------------------------------------------------------------------------
# This lane talks to the ACTUAL `systemd --user` of the invoking session
# ------------------------------------------------------------------------
#
# Nothing here is mocked, and that is the point: the whole feature is a contract
# with a program .LEXE does not control, so the only test that means anything is
# one where systemd is the other party. A stub would have agreed with every
# assumption that turned out to be wrong -- including the one that cost a
# 203/EXEC: that `ExecStart=` may contain an unquoted path.
#
# Two consequences, both deliberate:
#
#   1. It SKIPS, loudly, when there is no user session. Not BLOCKED: a host
#      without a session manager is a host where this feature does not apply,
#      not one where an expected capability could not be shown. `lexe service`
#      reports `not-installed`/`no-user-session` there, and the unit tests
#      (tests/test_session.cpp) still cover everything that is a function of its
#      inputs.
#
#   2. It touches the invoking user's real `~/.config/systemd/user`, because a
#      unit systemd cannot see is a unit that proves nothing. Every unit it
#      creates is the example's own `lexe-org.lexe.examples.heartbeat.service`,
#      and sess_cleanup removes
#      them whatever the outcome -- including on an interrupt, which is what the
#      trap is for. A leftover enabled unit pointing into a deleted scratch root
#      would fail at the user's next login, so cleanup is not tidiness here.

# The id of the service example this lane installs. Taken from the example's
# own manifest rather than invented, because the unit name systemd sees is
# derived from it -- a mismatch here would make every assertion in this file
# query a unit that was never created, which is exactly how the first run of
# this lane "failed" 23 checks against a correctly working implementation.
SESS_APP_ID="org.lexe.examples.heartbeat"

sess_unit() { printf 'lexe-%s.service' "${1:-$SESS_APP_ID}"; }

# Where .LEXE writes the unit under a scratch root. `LEXE_HOME` redirects
# config_home_, so this is NOT ~/.config/systemd/user -- systemd learns about it
# because `enable` passes the absolute path and systemd links it in.
sess_unit_file() {
    printf '%s/config-home/systemd/user/%s' "$LEXE_HOME" "$(sess_unit "${1:-}")"
}

# What systemd itself says, as opposed to what .LEXE believes. Every assertion
# in this lane that matters is checked against one of these rather than against
# `lexe service status`, because a test that only asks .LEXE whether .LEXE
# succeeded cannot detect .LEXE being wrong.
sess_is_enabled() { systemctl --user is-enabled "$(sess_unit "${1:-}")" 2>&1; }
sess_is_active()  { systemctl --user is-active  "$(sess_unit "${1:-}")" 2>&1; }
sess_show() { systemctl --user show -p "$2" --value "$(sess_unit "${1:-}")" 2>&1; }

# Is there a user session manager to talk to at all?
sess_have_systemd() {
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl --user is-system-running >/dev/null 2>&1 && return 0
    # A non-zero exit is not the question: `is-system-running` reports
    # "degraded" with status 1 whenever any unit in the session has ever failed,
    # which says nothing about whether the bus is reachable. What settles it is
    # whether it could connect.
    local err
    err="$(systemctl --user is-system-running 2>&1)"
    case "$err" in
        *"Failed to connect"*|*"No medium found"*|*"DBUS_SESSION_BUS_ADDRESS"*|*"XDG_RUNTIME_DIR"*)
            return 1 ;;
    esac
    return 0
}

# Build and install the heartbeat service example into the scratch root.
#
# From a COPY of the example: `lexe build` fills a manifest's "AUTO" publicKey
# in from --key and says so, which would otherwise pin this run's throwaway key
# into the tracked example and dirty the repository.
sess_install_service() {
    SESS_KEY="$ACC_ROOT/work/session-key.json"
    SESS_PROJECT="$ACC_ROOT/work/heartbeat"
    SESS_PACKAGE="$ACC_ROOT/work/heartbeat.lexe"
    local example="$ACC_REPO/examples/service/heartbeat"

    [[ -d "$example" ]] || { printf 'no service example at %s\n' "$example" >&2; return 2; }
    cp -r "$example" "$SESS_PROJECT"
    "$LEXE" keygen "$SESS_KEY" >/dev/null 2>&1 || return 2
    "$LEXE" build "$SESS_PROJECT" -o "$SESS_PACKAGE" --key "$SESS_KEY" \
        >"$ACC_ROOT/work/session-build.log" 2>&1 || {
        sed 's/^/    /' "$ACC_ROOT/work/session-build.log" >&2
        return 2
    }
    "$LEXE" install "$SESS_PACKAGE" --yes --trust \
        >"$ACC_ROOT/work/session-install.log" 2>&1 || {
        sed 's/^/    /' "$ACC_ROOT/work/session-install.log" >&2
        return 2
    }
    export SESS_KEY SESS_PROJECT SESS_PACKAGE
}

# Retract everything this lane could have left in the real user session.
#
# Runs on EXIT, including on an interrupt, and never fails the script: a cleanup
# that aborted partway would leave exactly the debris it exists to prevent.
sess_cleanup() {
    local unit
    for unit in "$HOME"/.config/systemd/user/lexe-org.lexe.examples.heartbeat.service; do
        [[ -e "$unit" || -L "$unit" ]] || continue
        systemctl --user stop "$(basename "$unit")" >/dev/null 2>&1
        systemctl --user disable "$(basename "$unit")" >/dev/null 2>&1
        rm -f "$unit"
    done
    for unit in "$HOME"/.config/systemd/user/*.wants/lexe-org.lexe.examples.heartbeat.service; do
        [[ -e "$unit" || -L "$unit" ]] || continue
        rm -f "$unit"
    done
    systemctl --user daemon-reload >/dev/null 2>&1
    return 0
}

# Assert that the real user session has nothing of ours left in it.
sess_assert_profile_clean() {
    local leftovers=()
    local unit
    for unit in "$HOME"/.config/systemd/user/lexe-org.lexe.examples.heartbeat.service \
                "$HOME"/.config/systemd/user/*.wants/lexe-org.lexe.examples.heartbeat.service; do
        [[ -e "$unit" || -L "$unit" ]] && leftovers+=("$unit")
    done
    if [[ ${#leftovers[@]} -eq 0 ]]; then
        pass "$1"
    else
        fail "$1" "left in the real user session:" "${leftovers[@]}"
    fi
}

#!/usr/bin/env bash
# private-display.sh — a display the test owns, that the user cannot see.
#
# Sourced by the GUI and lifecycle lanes. It exists because of a rule in
# docs/TESTING.md §3: no automated test may put a window on the developer's
# screen. A test that needs to prove a window MAPPED therefore has to bring its
# own X server, and that server's socket has to be reachable from inside the
# .LEXE sandbox.
#
# Why the obvious approach does not work, on the machine this was written on:
#
#   $ mount | grep x11
#   none on /tmp/.X11-unix type tmpfs (ro,relatime)
#
# WSLg mounts /tmp/.X11-unix READ-ONLY and puts the user's real display there as
# X0. `Xvfb :99` therefore cannot create /tmp/.X11-unix/X99 and silently falls
# back to an abstract socket — which a sandboxed process can never reach,
# because the sandbox unshares the network namespace and abstract sockets do not
# cross one. Ubuntu's Xorg 21.1 has no -unixdir to relocate the socket.
#
# So: run inside a private MOUNT namespace and mount a fresh writable tmpfs over
# /tmp/.X11-unix. Xvfb then creates a real filesystem socket there, and every
# child — including the bwrap sandbox the launcher starts — inherits the
# namespace and can bind that path like any other file.
#
# This is safer than binding the real display, not a workaround for not being
# able to. Inside the namespace the user's X0 is not merely unbound: it is not
# visible at all. Nothing can reach their desktop even by mistake.
#
# Two things the private /tmp/.X11-unix does not cover on its own, both found by
# running this rather than by reasoning about it:
#
#   * the X server also takes a LOCK at /tmp/.X<n>-lock, and /tmp itself is
#     shared with the host. A lock left behind by a crashed server blocks a
#     display number that is otherwise free, with "Server is already active for
#     display <n>". pd_pick_display below picks a number whose lock is absent or
#     provably stale — stale meaning the host has no socket beside it.
#
#   * Xvfb ALSO binds an abstract socket, @/tmp/.X11-unix/X<n>, and abstract
#     sockets live in the NETWORK namespace, not the mount namespace. A private
#     /tmp/.X11-unix does nothing about them, so a server still running
#     elsewhere on the machine holds the name and the new one dies with
#     "Cannot establish any listening sockets". Unsharing the network namespace
#     as well makes that structurally impossible, and has the same effect the
#     private mount does: the display cannot be reached from outside, by any
#     route, even by accident.
#
# Usage:
#
#     source scripts/lib/private-display.sh
#     pd_available || { echo "reason: $PD_UNAVAILABLE_REASON"; exit 0; }
#     pd_run 99 -- bash -c 'DISPLAY=:99 xwininfo -root -children'
#
# pd_run re-executes itself inside the namespace, so the command it is given
# runs with :N already serving. Everything the command starts sees the private
# /tmp/.X11-unix and nothing else.

PD_DISPLAY_NUM="${PD_DISPLAY_NUM:-99}"
PD_SCREEN="${PD_SCREEN:-1280x1024x24}"
PD_UNAVAILABLE_REASON=""

# --------------------------------------------------------------- availability

# Is the mechanism usable here? Sets PD_UNAVAILABLE_REASON when it is not, so a
# caller can report a specific SKIP instead of a bare failure.
pd_available() {
    PD_UNAVAILABLE_REASON=""
    if ! command -v Xvfb >/dev/null 2>&1; then
        PD_UNAVAILABLE_REASON="Xvfb is not installed (apt-get install xvfb)"
        return 1
    fi
    if ! command -v unshare >/dev/null 2>&1; then
        PD_UNAVAILABLE_REASON="unshare(1) is not available (util-linux)"
        return 1
    fi
    # Unprivileged user namespaces, and mounting inside one, must actually work.
    # Some kernels and container configurations forbid both; find out by trying
    # rather than by guessing from /proc.
    if ! unshare --mount --map-root-user /bin_missing_probe true 2>/dev/null &&
       ! unshare --mount --map-root-user true 2>/dev/null; then
        PD_UNAVAILABLE_REASON="unprivileged mount namespaces are not permitted \
on this kernel"
        return 1
    fi
    if ! unshare --mount --map-root-user \
            sh -c 'mount -t tmpfs tmpfs /tmp >/dev/null 2>&1' 2>/dev/null; then
        PD_UNAVAILABLE_REASON="cannot mount a tmpfs inside a user namespace"
        return 1
    fi
    if ! unshare --mount --net --map-root-user true 2>/dev/null; then
        PD_UNAVAILABLE_REASON="cannot unshare a network namespace, so the \
display's abstract socket would be reachable from outside"
        return 1
    fi
    return 0
}

# --------------------------------------------------------------- lock hygiene

# Echo a display number that is free, or nothing if none is.
#
# Run OUTSIDE the namespace, deliberately: the host /tmp/.X11-unix is the only
# place a live server's socket can be seen, and inside the namespace it has
# already been replaced. A lock with no socket beside it belonged to a server
# that is gone, so it is removed; a lock WITH a socket is a live display and is
# left strictly alone.
pd_pick_display() {
    local first="${1:-99}" n
    for (( n = first; n < first + 30; n++ )); do
        local socket="/tmp/.X11-unix/X$n" lock="/tmp/.X$n-lock"
        [[ -e "$socket" ]] && continue          # a live display; never touch it
        if [[ -e "$lock" ]]; then
            rm -f "$lock" 2>/dev/null || continue   # someone else's; try the next
        fi
        printf '%s' "$n"
        return 0
    done
    return 1
}

# --------------------------------------------------------------- the namespace

# Internal: already inside the namespace. Start Xvfb on $1, then exec the rest.
_pd_inner() {
    local display_num="$1"; shift
    mount -t tmpfs tmpfs /tmp/.X11-unix || {
        printf 'private-display: could not mount a private /tmp/.X11-unix\n' >&2
        return 1
    }
    chmod 1777 /tmp/.X11-unix
    # We are root in this user namespace, which owns the network namespace, so
    # loopback can be brought up here. Best effort: nothing in a GUI launch needs
    # it, but a toolkit that probes localhost gets a working answer instead of a
    # hang. Never fatal.
    ip link set lo up 2>/dev/null || true

    # An X server with no host to talk to and no TCP surface at all.
    Xvfb ":$display_num" -screen 0 "$PD_SCREEN" -nolisten tcp \
        >"${PD_LOG:-/dev/null}" 2>&1 &
    local xvfb_pid=$!

    # Wait for the socket rather than sleeping a guessed interval: the whole
    # point is that this socket is a real file, so its existence is observable.
    local socket="/tmp/.X11-unix/X$display_num"
    local waited=0
    while [[ ! -S "$socket" ]]; do
        if ! kill -0 "$xvfb_pid" 2>/dev/null; then
            printf 'private-display: Xvfb exited before serving :%s\n' \
                "$display_num" >&2
            return 1
        fi
        sleep 0.1
        waited=$((waited + 1))
        if [[ $waited -gt 100 ]]; then
            printf 'private-display: :%s did not come up within 10s\n' \
                "$display_num" >&2
            kill "$xvfb_pid" 2>/dev/null
            return 1
        fi
    done

    # The display is ours and it is the only one in this namespace.
    export DISPLAY=":$display_num"
    # A stray WAYLAND_DISPLAY would let GTK pick the user's real session over
    # the X server we just started — which is exactly the accident this whole
    # file exists to prevent.
    unset WAYLAND_DISPLAY
    export GDK_BACKEND=x11
    export XDG_SESSION_TYPE=x11
    # No shared X authority: nothing outside this namespace has the socket.
    export XAUTHORITY=/dev/null

    "$@"
    local status=$?
    # SIGTERM lets Xvfb remove its own /tmp/.X<n>-lock, which lives on the
    # SHARED /tmp and would otherwise block this number for the next run.
    kill "$xvfb_pid" 2>/dev/null
    wait "$xvfb_pid" 2>/dev/null
    rm -f "/tmp/.X$display_num-lock" 2>/dev/null
    return $status
}

# pd_run <display-num> -- <command...>
#
# Enters a private mount namespace, serves :<display-num> from a socket only
# that namespace can see, and runs <command...> with DISPLAY pointed at it.
pd_run() {
    local wanted="$1"; shift
    [[ "${1:-}" == "--" ]] && shift
    if [[ $# -eq 0 ]]; then
        printf 'usage: pd_run <display-num> -- <command...>\n' >&2
        return 2
    fi
    local display_num
    display_num="$(pd_pick_display "$wanted")" || {
        printf 'private-display: no free display number near :%s\n' "$wanted" >&2
        return 1
    }
    # Exported so a caller that needs to know which display it got can read it
    # (pd_run may not get the number it asked for).
    PD_DISPLAY_NUM="$display_num"
    export PD_DISPLAY_NUM
    # --map-root-user is what makes mount(2) permitted inside the namespace; it
    # is root in THIS namespace only and confers nothing on the host. The inner
    # side re-sources this file so _pd_inner exists in the new process.
    PD_SCREEN="$PD_SCREEN" PD_LOG="${PD_LOG:-/dev/null}" \
    unshare --mount --net --map-root-user -- \
        bash -c 'source "$0"; _pd_inner "$@"' \
        "${BASH_SOURCE[0]}" "$display_num" "$@"
}

# pd_window_count — how many top-level windows the private display has, as
# reported by a third-party tool rather than by anything .LEXE wrote.
pd_window_count() {
    xwininfo -root -children 2>/dev/null |
        grep -cE '^ +0x[0-9a-f]+ ' || true
}

# pd_wait_for_window <seconds> [name-substring]
#
# Succeeds as soon as the private display has a mapped top-level window (with a
# matching name, if given). This is the check that distinguishes "a process
# started" from "a window appeared", which is the distinction the GUI lanes
# exist to make.
pd_wait_for_window() {
    local deadline="$1" want="${2:-}"
    local waited=0
    while [[ $waited -lt $((deadline * 10)) ]]; do
        local listing
        listing="$(xwininfo -root -children 2>/dev/null || true)"
        if [[ -n "$listing" ]]; then
            if [[ -z "$want" ]]; then
                # Any child of the root that is not the root itself.
                if grep -qE '^ +0x[0-9a-f]+ ' <<<"$listing"; then return 0; fi
            elif grep -qiF "$want" <<<"$listing"; then
                return 0
            fi
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
    return 1
}

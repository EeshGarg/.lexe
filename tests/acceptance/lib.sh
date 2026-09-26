#!/usr/bin/env bash
# tests/acceptance/lib.sh — shared helpers for the .LEXE acceptance harness.
#
# Every script sources this, calls `acc_begin <title>`, does its work against a
# SCRATCH LEXE_HOME, and ends with `acc_summary`. Nothing here ever touches the
# real ~/.local/share/lexe: LEXE_HOME is redirected, and with LEXE_HOME set the
# paths module keeps applications/, icons/, mime/, state/, config/ and
# config-home/mimeapps.list all underneath it (src/lexe/base/paths.cpp).
#
# Sourcing this file does NOT create anything; call acc_scratch_home to do that.
#
# HEADLESS BY CONSTRUCTION. An automated test must never put a window on the
# developer's screen: a window that steals focus mid-run is disruptive, and a
# test whose result depends on a live desktop session is not reproducible on a
# build machine. The display environment is therefore severed for the WHOLE
# harness below, before any test runs.
#
# This is a hard guard, not a convention. The payload's own `--selftest` and
# `--sleep` flags already return before GTK is initialised, but a future change
# that tried to open a window would find no display to open it on and fail
# loudly instead of silently appearing on screen. Anything that genuinely needs
# to render must bring its own synthetic display (Xvfb / headless compositor) —
# see scripts/gui-smoke.sh.

# --------------------------------------------------------------- headless

# Recorded before severing, purely so a script can SAY it was running headless.
ACC_HOST_SESSION="${WAYLAND_DISPLAY:-${DISPLAY:-none}}"
unset WAYLAND_DISPLAY DISPLAY
# GDK would otherwise fall back to an auto-detected backend; pinning it to a
# backend with nothing to connect to makes the failure immediate and obvious.
export GDK_BACKEND=x11
export QT_QPA_PLATFORM=offscreen
# Belt and braces: with no display bound into the sandbox either, a GUI launch
# inside bwrap cannot reach the session even if the guard above were bypassed.
export XDG_SESSION_TYPE=tty

# --------------------------------------------------------------- locations

ACC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ACC_REPO="$(cd -- "$ACC_DIR/../.." && pwd)"
ACC_BUILD="${LEXE_BUILD_DIR:-$ACC_REPO/build}"
ACC_EXAMPLE="$ACC_REPO/examples/gui-hello"

# The application under test (examples/gui-hello/lexe.json).
ACC_APP_ID="com.usha.guihello"
ACC_APP_VERSION="1.0.0"
ACC_ENTRYPOINT="bin/gui-hello"

# --------------------------------------------------------------- reporting

ACC_PASS=0
ACC_FAIL=0
ACC_SKIP=0
ACC_TITLE=""
ACC_FAILURES=()

if [[ -t 1 ]]; then
    ACC_GREEN=$'\033[32m'; ACC_RED=$'\033[31m'; ACC_YELLOW=$'\033[33m'
    ACC_BOLD=$'\033[1m'; ACC_OFF=$'\033[0m'
else
    ACC_GREEN=""; ACC_RED=""; ACC_YELLOW=""; ACC_BOLD=""; ACC_OFF=""
fi

acc_begin() {
    ACC_TITLE="$1"
    printf '%s== %s ==%s\n' "$ACC_BOLD" "$ACC_TITLE" "$ACC_OFF"
}

pass() { ACC_PASS=$((ACC_PASS + 1)); printf '  %sPASS%s %s\n' "$ACC_GREEN" "$ACC_OFF" "$1"; }

fail() {
    ACC_FAIL=$((ACC_FAIL + 1))
    ACC_FAILURES+=("$1")
    printf '  %sFAIL%s %s\n' "$ACC_RED" "$ACC_OFF" "$1"
    if [[ $# -gt 1 ]]; then
        shift
        printf '       %s\n' "$@"
    fi
}

skip() { ACC_SKIP=$((ACC_SKIP + 1)); printf '  %sSKIP%s %s\n' "$ACC_YELLOW" "$ACC_OFF" "$1"; }

note() { printf '       %s\n' "$@"; }

acc_summary() {
    printf '\n  %s: %d passed, %d failed, %d skipped\n' \
        "$ACC_TITLE" "$ACC_PASS" "$ACC_FAIL" "$ACC_SKIP"
    if [[ $ACC_FAIL -gt 0 ]]; then
        printf '  %sfailing checks:%s\n' "$ACC_RED" "$ACC_OFF"
        printf '    - %s\n' "${ACC_FAILURES[@]}"
        return 1
    fi
    return 0
}

# ------------------------------------------------------------- assertions

# acc_assert <condition-result 0/1> <description>
acc_true() { if [[ "$1" == "0" ]]; then pass "$2"; else fail "$2" "${@:3}"; fi; }

acc_file_exists() {
    if [[ -f "$1" ]]; then pass "$2"; else fail "$2" "missing: $1"; fi
}

acc_file_absent() {
    if [[ ! -e "$1" ]]; then pass "$2"; else fail "$2" "unexpectedly present: $1"; fi
}

# acc_contains <haystack> <needle> <description>
acc_contains() {
    if [[ "$1" == *"$2"* ]]; then pass "$3"; else fail "$3" "expected to contain: $2" "actual: $1"; fi
}

# acc_equals <actual> <expected> <description>
acc_equals() {
    if [[ "$1" == "$2" ]]; then pass "$3"; else fail "$3" "expected: $2" "actual:   $1"; fi
}

# ----------------------------------------------------------------- binaries

acc_require_binaries() {
    if [[ ! -x "$ACC_BUILD/lexe" ]]; then
        printf '%sfatal%s: %s is not built. Run: cmake --build %s -j\n' \
            "$ACC_RED" "$ACC_OFF" "$ACC_BUILD/lexe" "$ACC_BUILD" >&2
        exit 2
    fi
    LEXE="$ACC_BUILD/lexe"
    export LEXE
}

# `lexe` on PATH matters: the generated .desktop Exec line is `lexe run <id>`,
# and the acceptance criteria are about that line resolving. Callers that want
# to exercise it use "$ACC_PATH_DIR" as a PATH prefix.
acc_shim_path() {
    mkdir -p "$ACC_ROOT/bin"
    ln -sf "$ACC_BUILD/lexe" "$ACC_ROOT/bin/lexe"
    ACC_PATH_DIR="$ACC_ROOT/bin"
    export ACC_PATH_DIR
}

# ------------------------------------------------------------- scratch home

# Creates ACC_ROOT (a private temp tree), exports LEXE_HOME under it, and
# registers a teardown on exit. Call once, near the top of a script.
acc_scratch_home() {
    ACC_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/lexe-acceptance-XXXXXX")"
    export ACC_ROOT
    export LEXE_HOME="$ACC_ROOT/home"
    mkdir -p "$LEXE_HOME" "$ACC_ROOT/work"
    # Belt and braces: even if something ignored LEXE_HOME, send the XDG roots
    # into the scratch tree too, so the user's profile can never be written.
    export XDG_DATA_HOME="$ACC_ROOT/xdg-data"
    export XDG_CONFIG_HOME="$ACC_ROOT/xdg-config"
    export XDG_STATE_HOME="$ACC_ROOT/xdg-state"
    export XDG_CACHE_HOME="$ACC_ROOT/xdg-cache"
    mkdir -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_STATE_HOME" "$XDG_CACHE_HOME"
    trap acc_teardown EXIT
    acc_shim_path
    printf '  scratch LEXE_HOME: %s\n' "$LEXE_HOME"
}

acc_teardown() {
    local status=$?
    acc_kill_app || true
    if [[ -n "${ACC_KEEP_SCRATCH:-}" ]]; then
        printf '  (kept scratch tree: %s)\n' "$ACC_ROOT"
    elif [[ -n "${ACC_ROOT:-}" && -d "$ACC_ROOT" ]]; then
        chmod -R u+rwX "$ACC_ROOT" 2>/dev/null || true
        rm -rf "$ACC_ROOT"
    fi
    return $status
}

# Kill anything still running out of this scratch tree (a GUI launch that was
# left open). Never matches another scratch run or the user's own apps.
acc_kill_app() {
    [[ -n "${ACC_ROOT:-}" ]] || return 0
    local pids
    pids="$(pgrep -f "$ACC_ROOT/home/apps/" 2>/dev/null || true)"
    if [[ -n "$pids" ]]; then
        # shellcheck disable=SC2086
        kill $pids 2>/dev/null || true
        sleep 0.4
        # shellcheck disable=SC2086
        kill -9 $pids 2>/dev/null || true
    fi
}

# --------------------------------------------------------------- packaging

# Copies examples/gui-hello into the scratch tree (so `lexe build`'s
# publisher.publicKey "AUTO" fill-in never dirties the repository), builds the
# payload if needed, and packages it. Sets ACC_PACKAGE and ACC_KEY.
acc_build_package() {
    ACC_KEY="$ACC_ROOT/work/key.json"
    ACC_PACKAGE="$ACC_ROOT/work/gui-hello.lexe"
    ACC_PROJECT="$ACC_ROOT/work/gui-hello"

    if [[ ! -x "$ACC_EXAMPLE/payload/bin/gui-hello" ]]; then
        printf '  building %s ...\n' "$ACC_EXAMPLE/payload/bin/gui-hello"
        if ! make -s -C "$ACC_EXAMPLE" >"$ACC_ROOT/work/make.log" 2>&1; then
            printf '%sfatal%s: could not build the gui-hello payload (GTK 3 dev headers required)\n' \
                "$ACC_RED" "$ACC_OFF" >&2
            sed 's/^/    /' "$ACC_ROOT/work/make.log" >&2
            exit 2
        fi
    fi

    mkdir -p "$ACC_PROJECT"
    cp -r "$ACC_EXAMPLE/lexe.json" "$ACC_EXAMPLE/icons" "$ACC_EXAMPLE/payload" "$ACC_PROJECT/"
    "$LEXE" keygen "$ACC_KEY" >/dev/null
    "$LEXE" build "$ACC_PROJECT" -o "$ACC_PACKAGE" --key "$ACC_KEY" >"$ACC_ROOT/work/build.log" 2>&1 || {
        printf '%sfatal%s: lexe build failed\n' "$ACC_RED" "$ACC_OFF" >&2
        sed 's/^/    /' "$ACC_ROOT/work/build.log" >&2
        exit 2
    }
    export ACC_KEY ACC_PACKAGE ACC_PROJECT
}

acc_install_package() {
    "$LEXE" install "$ACC_PACKAGE" --yes --trust >"$ACC_ROOT/work/install.log" 2>&1 || {
        printf '%sfatal%s: lexe install failed\n' "$ACC_RED" "$ACC_OFF" >&2
        sed 's/^/    /' "$ACC_ROOT/work/install.log" >&2
        exit 2
    }
}

# --------------------------------------------------------- derived locations

acc_desktop_entry() { printf '%s/applications/lexe-%s.desktop' "$LEXE_HOME" "$ACC_APP_ID"; }
acc_launch_ref()    { printf '%s/launch/%s.lexe' "$LEXE_HOME" "$ACC_APP_ID"; }
acc_integration()   { printf '%s/integration.json' "$LEXE_HOME"; }
acc_mimeapps()      { printf '%s/config-home/mimeapps.list' "$LEXE_HOME"; }
acc_installation_for() { printf '%s/apps/%s/installation.json' "$LEXE_HOME" "$1"; }
acc_installation()  { acc_installation_for "$ACC_APP_ID"; }
acc_error_dir()     { printf '%s/state/errors/%s' "$LEXE_HOME" "$ACC_APP_ID"; }
acc_app_data()      { printf '%s/data/%s' "$LEXE_HOME" "$ACC_APP_ID"; }
acc_version_dir()   { printf '%s/apps/%s/versions/%s' "$LEXE_HOME" "$ACC_APP_ID" "$ACC_APP_VERSION"; }

# ---------------------------------------------------------------- utilities

# acc_json <file-or-'-'> <python-expression over `d`>
acc_json() {
    local src="$1"; shift
    python3 -c '
import json, sys
src = sys.argv[1]
d = json.load(sys.stdin if src == "-" else open(src))
print(eval(sys.argv[2]))
' "$src" "$1"
}

acc_have_display() {
    [[ -n "${WAYLAND_DISPLAY:-}" || -n "${DISPLAY:-}" ]]
}

# How many times the payload has recorded a start of its own (the example app
# appends to this before it touches GTK, so it works with no display at all).
acc_launch_count() {
    local log="$(acc_app_data)/gui-hello-launches.log"
    if [[ -f "$log" ]]; then wc -l < "$log" | tr -d ' '; else echo 0; fi
}

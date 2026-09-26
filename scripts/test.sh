#!/usr/bin/env bash
# =============================================================================
# scripts/test.sh — the one way to validate .LEXE.
#
# No tribal knowledge. `--all` is intended to be the executable definition of a
# releasable build on the machine it runs on, and it reports four outcomes, not
# two:
#
#   PASS      demonstrated here
#   FAIL      expected here and did not happen — a defect
#   SKIP      deliberately not applicable on this host, reason named
#   BLOCKED   needs hardware or an environment this host does not have
#
# A BLOCKED lane is never counted as success and never silently disappears: it
# prints with its reason, and the summary lists every one. The exit status is
# non-zero if anything FAILED, zero otherwise — a build can be releasable with
# blocked lanes, but only if you can read which ones they were.
#
#   ./scripts/test.sh --list          what each lane covers, resolved for THIS host
#   ./scripts/test.sh --unit
#   ./scripts/test.sh --unit --security
#   ./scripts/test.sh --all
#
# Options:
#   --build-dir <dir>   default: build (or $LEXE_BUILD_DIR)
#   --no-build          use what is already built; do not configure or compile
#   --jobs <n>          default: nproc
#   -v, --verbose       stream each lane's output instead of only its result
#   -h, --help
#
# Every lane runs with the display severed (docs/TESTING.md §3). The lanes that
# must render bring their own private display via scripts/lib/private-display.sh
# and never touch the developer's session.
# =============================================================================
set -uo pipefail

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${LEXE_BUILD_DIR:-$REPO/build}"
JOBS="$(nproc 2>/dev/null || echo 4)"
VERBOSE=0
DO_BUILD=1
LANES=()

# --------------------------------------------------------------- presentation

if [[ -t 1 ]]; then
    C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m';  C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
    C_GREEN=""; C_RED=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_DIM=""; C_OFF=""
fi

# Results, in lane order.
RESULT_NAMES=(); RESULT_STATES=(); RESULT_NOTES=()

record() { RESULT_NAMES+=("$1"); RESULT_STATES+=("$2"); RESULT_NOTES+=("${3:-}"); }

say()  { printf '%s\n' "$*"; }
head2() { printf '\n%s== %s ==%s\n' "$C_BOLD" "$1" "$C_OFF"; }

# --------------------------------------------------------------- lane registry
#
# Each lane declares: a one-line description, a `<lane>_check` that decides
# whether it can run here (printing a reason when it cannot, and echoing
# "blocked" instead of "skip" when the obstacle is the environment rather than
# applicability), and a `<lane>_run`.

ALL_LANES=(unit acceptance integration gui lifecycle security windows proton sanitizers)

lane_desc() {
    case "$1" in
    unit)       echo "the doctest binary: every subsystem, both GUI view models, the architecture rules" ;;
    acceptance) echo "end-to-end scripts against a throwaway LEXE_HOME" ;;
    integration) echo "trust and lifecycle across process boundaries" ;;
    gui)        echo "the frontends start, render and exit clean on a private display" ;;
    lifecycle)  echo "install -> run -> update -> rollback -> repair -> uninstall, and the same interrupted" ;;
    security)   echo "hostile packages: traversal, escape, tampering, architecture lies, injection" ;;
    windows)    echo "a purpose-built Windows PE, actually run through Wine" ;;
    proton)     echo "the same Windows payload through the Proton chain" ;;
    sanitizers) echo "a separate ASan + UBSan build of the unit suite" ;;
    esac
}

have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------- availability

unit_check() { [[ -x "$BUILD_DIR/lexe_tests" ]] || { echo "skip: lexe_tests is not built"; return 1; }; }
acceptance_check() { [[ -x "$BUILD_DIR/lexe" ]] || { echo "skip: the lexe CLI is not built"; return 1; }; }
integration_check() { acceptance_check; }
security_check() { acceptance_check; }

gui_check() {
    [[ -x "$BUILD_DIR/lexe-ui" && -x "$BUILD_DIR/lexe-builder" ]] || {
        echo "skip: the GTK frontends are not built (install libgtk-3-dev, or -DLEXE_BUILD_GUI=ON)"
        return 1
    }
    have Xvfb || { echo "blocked: Xvfb is not installed (apt-get install xvfb)"; return 1; }
    have xwininfo || { echo "blocked: xwininfo is not installed (apt-get install x11-utils)"; return 1; }
}

lifecycle_check() {
    acceptance_check || return 1
    have bwrap || { echo "blocked: bubblewrap is not installed, so nothing can be sandboxed"; return 1; }
}

windows_check() {
    acceptance_check || return 1
    have wine || { echo "blocked: wine is not installed"; return 1; }
    have x86_64-w64-mingw32-gcc || {
        echo "blocked: no MinGW cross-compiler, so no purpose-built PE to run"
        return 1
    }
}

proton_check() {
    acceptance_check || return 1
    # Proton is located the way the engine locates it, so this lane cannot pass
    # by finding an installation the runtime would not use.
    local found
    found="$("$BUILD_DIR/lexe" runtime list --json 2>/dev/null |
             grep -c '"id"[[:space:]]*:[[:space:]]*"proton"' || true)"
    if [[ "${found:-0}" == "0" ]]; then
        echo "blocked: no Proton installation the runtime can find (see docs/TESTING.md §4)"
        return 1
    fi
}

sanitizers_check() {
    have cmake || { echo "blocked: cmake is not installed"; return 1; }
    have g++ || have clang++ || { echo "blocked: no sanitizer-capable compiler"; return 1; }
}

# --------------------------------------------------------------- lane bodies

unit_run() {
    env -u WAYLAND_DISPLAY -u DISPLAY "$BUILD_DIR/lexe_tests" \
        --reporters=console --no-intro=true
}

acceptance_run() {
    LEXE_BUILD_DIR="$BUILD_DIR" bash "$REPO/tests/acceptance/run_all.sh"
}

integration_run() {
    local status=0
    for script in "$REPO"/tests/integration/*.sh; do
        [[ -f "$script" ]] || continue
        printf '%s-- %s%s\n' "$C_DIM" "$(basename "$script")" "$C_OFF"
        LEXE_BUILD_DIR="$BUILD_DIR" bash "$script" || status=1
    done
    return $status
}

gui_run() { bash "$REPO/scripts/gui-smoke.sh" "$BUILD_DIR"; }

lifecycle_run() {
    LEXE_BUILD_DIR="$BUILD_DIR" bash "$REPO/tests/lifecycle/run_all.sh"
}

security_run() {
    LEXE_BUILD_DIR="$BUILD_DIR" bash "$REPO/tests/security/run_all.sh"
}

windows_run() {
    LEXE_BUILD_DIR="$BUILD_DIR" bash "$REPO/tests/acceptance/06_foreign_os.sh"
}

proton_run() {
    LEXE_BUILD_DIR="$BUILD_DIR" bash "$REPO/tests/acceptance/07_proton.sh"
}

sanitizers_run() {
    local san_dir="$BUILD_DIR-san"
    cmake -S "$REPO" -B "$san_dir" -G Ninja \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
        -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" >/dev/null || return 1
    cmake --build "$san_dir" -j "$JOBS" --target lexe_tests || return 1
    # The vendored ed25519 performs signed left-shifts that UBSan reports.
    # Suppress them BY NAME so a new finding is still visible, rather than
    # tolerating a permanently noisy run that nobody reads.
    local supp="$REPO/tests/ubsan.supp"
    UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0${supp:+:suppressions=$supp}" \
    ASAN_OPTIONS="detect_leaks=1:abort_on_error=0" \
    env -u WAYLAND_DISPLAY -u DISPLAY "$san_dir/lexe_tests" \
        --reporters=console --no-intro=true
}

# --------------------------------------------------------------- driver

usage() {
    cat <<USAGE
usage: scripts/test.sh [lane...] [options]

Lanes (any combination, or --all):
$(for l in "${ALL_LANES[@]}"; do printf '  --%-12s %s\n' "$l" "$(lane_desc "$l")"; done)

Options:
  --all               every lane
  --list              print the lanes with availability resolved for this host
  --build-dir <dir>   default: ${BUILD_DIR}
  --no-build          do not configure or compile first
  --jobs <n>          default: ${JOBS}
  -v, --verbose       stream each lane's output
  -h, --help

Outcomes: PASS / FAIL / SKIP (not applicable here) / BLOCKED (needs hardware or
an environment this host lacks). Exits non-zero only on FAIL; every SKIP and
BLOCKED is printed with its reason. See docs/TESTING.md.
USAGE
}

list_lanes() {
    printf '%slane          state     covers%s\n' "$C_BOLD" "$C_OFF"
    for lane in "${ALL_LANES[@]}"; do
        local out state colour
        out="$("${lane}_check" 2>&1)"
        if [[ $? -eq 0 ]]; then
            state="available"; colour="$C_GREEN"; out=""
        elif [[ "$out" == blocked:* ]]; then
            state="BLOCKED"; colour="$C_BLUE"; out="${out#blocked: }"
        else
            state="skip"; colour="$C_YELLOW"; out="${out#skip: }"
        fi
        printf '%s%-13s %-9s%s %s\n' "$colour" "$lane" "$state" "$C_OFF" \
            "$(lane_desc "$lane")"
        [[ -n "$out" ]] && printf '              %s%s%s\n' "$C_DIM" "$out" "$C_OFF"
    done
}

build_first() {
    head2 "build"
    if ! cmake -S "$REPO" -B "$BUILD_DIR" -G Ninja \
            -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null; then
        say "${C_RED}  configure failed${C_OFF}"
        return 1
    fi
    local log; log="$(mktemp)"
    if ! cmake --build "$BUILD_DIR" -j "$JOBS" >"$log" 2>&1; then
        say "${C_RED}  build failed${C_OFF}"; tail -30 "$log"; rm -f "$log"; return 1
    fi
    # First-party code must build warning-free; report it as part of the build,
    # because a warning that nobody reads is the same as no warning at all.
    local warnings
    warnings="$(grep -cE '\bwarning\b' "$log" || true)"
    if [[ "${warnings:-0}" -gt 0 ]]; then
        say "${C_RED}  ${warnings} compiler warning(s):${C_OFF}"
        grep -E '\bwarning\b' "$log" | head -20
        rm -f "$log"; return 1
    fi
    say "${C_GREEN}  built clean, zero warnings${C_OFF}"
    rm -f "$log"
}

run_lane() {
    local lane="$1" reason state
    head2 "$lane"
    say "${C_DIM}  $(lane_desc "$lane")${C_OFF}"

    reason="$("${lane}_check" 2>&1)"
    if [[ $? -ne 0 ]]; then
        if [[ "$reason" == blocked:* ]]; then
            state="BLOCKED"; reason="${reason#blocked: }"
            say "${C_BLUE}  BLOCKED${C_OFF} ${reason}"
        else
            state="SKIP"; reason="${reason#skip: }"
            say "${C_YELLOW}  SKIP${C_OFF} ${reason}"
        fi
        record "$lane" "$state" "$reason"
        return 0
    fi

    local log; log="$(mktemp)"
    local status=0
    if [[ $VERBOSE -eq 1 ]]; then
        "${lane}_run" 2>&1 | tee "$log" || status=$?
        status=${PIPESTATUS[0]}
    else
        "${lane}_run" >"$log" 2>&1 || status=$?
    fi

    if [[ $status -eq 0 ]]; then
        say "${C_GREEN}  PASS${C_OFF} $(lane_summary "$lane" "$log")"
        record "$lane" "PASS" "$(lane_summary "$lane" "$log")"
    else
        say "${C_RED}  FAIL${C_OFF} (exit $status)"
        [[ $VERBOSE -eq 0 ]] && tail -40 "$log"
        record "$lane" "FAIL" "exit $status"
    fi
    rm -f "$log"
    return 0
}

# A one-line "what did it actually prove" pulled from the lane's own output,
# so the summary carries evidence rather than only a colour.
lane_summary() {
    case "$1" in
    unit|sanitizers)
        grep -oE 'test cases: *[0-9]+ \| *[0-9]+ passed' "$2" | tail -1 |
            tr -s ' ' || true ;;
    acceptance)
        grep -oE 'all [0-9]+ automated acceptance scripts passed' "$2" | tail -1 || true ;;
    *)
        grep -oE '[0-9]+ passed, [0-9]+ failed(, [0-9]+ skipped)?' "$2" | tail -1 || true ;;
    esac
}

# --------------------------------------------------------------- arguments

[[ $# -eq 0 ]] && { usage; exit 2; }
WANT_LIST=0
while [[ $# -gt 0 ]]; do
    case "$1" in
    --all)        LANES=("${ALL_LANES[@]}") ;;
    --list)       WANT_LIST=1 ;;
    --build-dir)  BUILD_DIR="$2"; shift ;;
    --no-build)   DO_BUILD=0 ;;
    --jobs)       JOBS="$2"; shift ;;
    -v|--verbose) VERBOSE=1 ;;
    -h|--help)    usage; exit 0 ;;
    --*)
        lane="${1#--}"
        if [[ " ${ALL_LANES[*]} " == *" $lane "* ]]; then
            LANES+=("$lane")
        else
            printf 'test.sh: unknown lane or option: %s\n\n' "$1" >&2
            usage >&2
            exit 2
        fi
        ;;
    *)
        printf 'test.sh: unexpected argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

if [[ $WANT_LIST -eq 1 ]]; then
    # --list needs a build dir to judge availability, but must never build.
    list_lanes
    exit 0
fi
[[ ${#LANES[@]} -eq 0 ]] && { usage >&2; exit 2; }

printf '%s.LEXE test runner%s\n' "$C_BOLD" "$C_OFF"
printf '  repository: %s\n' "$REPO"
printf '  build dir:  %s\n' "$BUILD_DIR"
printf '  lanes:      %s\n' "${LANES[*]}"

if [[ $DO_BUILD -eq 1 ]]; then
    build_first || { printf '\n%sbuild failed — no lane was run%s\n' "$C_RED" "$C_OFF"; exit 1; }
fi

for lane in "${LANES[@]}"; do run_lane "$lane"; done

# --------------------------------------------------------------- summary

printf '\n%s== summary ==%s\n' "$C_BOLD" "$C_OFF"
failed=0; blocked=0; skipped=0; passed=0
for i in "${!RESULT_NAMES[@]}"; do
    name="${RESULT_NAMES[$i]}"; state="${RESULT_STATES[$i]}"; note="${RESULT_NOTES[$i]}"
    case "$state" in
    PASS)    printf '  %sPASS   %-12s%s %s\n' "$C_GREEN" "$name" "$C_OFF" "$note"; passed=$((passed+1)) ;;
    FAIL)    printf '  %sFAIL   %-12s%s %s\n' "$C_RED" "$name" "$C_OFF" "$note"; failed=$((failed+1)) ;;
    SKIP)    printf '  %sSKIP   %-12s%s %s\n' "$C_YELLOW" "$name" "$C_OFF" "$note"; skipped=$((skipped+1)) ;;
    BLOCKED) printf '  %sBLOCK  %-12s%s %s\n' "$C_BLUE" "$name" "$C_OFF" "$note"; blocked=$((blocked+1)) ;;
    esac
done

printf '\n  %d passed, %d failed, %d skipped, %d blocked\n' \
    "$passed" "$failed" "$skipped" "$blocked"

if [[ $blocked -gt 0 ]]; then
    printf '\n  %sBlocked lanes are not passes.%s The reasons above are recorded in\n' \
        "$C_BOLD" "$C_OFF"
    printf '  docs/TESTING.md §6 along with what would settle each one.\n'
fi

if [[ $failed -gt 0 ]]; then
    printf '\n  %s%d lane(s) failed%s\n' "$C_RED" "$failed" "$C_OFF"
    exit 1
fi
printf '\n  %sno failures%s\n' "$C_GREEN" "$C_OFF"
exit 0

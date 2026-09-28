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

ALL_LANES=(evidence unit acceptance integration gui lifecycle concurrency session conformance security windows proton workloads explore sanitizers)

# --------------------------------------------------------------- compute tiers
#
# A tier selects WHICH lanes run and tells each lane HOW HARD to work, through
# LEXE_TIER in its environment. The second half matters more than the first: a
# lane that ignores the tier cannot be scaled, and `--soak` would then be `--all`
# with a longer name and a summary that implies more than happened.
#
# The contract for a lane reading LEXE_TIER:
#   fast      seconds. Enough to catch an obvious break. Nothing that packages
#             or sandboxes.
#   standard  the working set a change is judged against. This is what --all is.
#   heavy     standard plus larger samples, higher-order combinations, and
#             concurrency under real CPU pressure.
#   soak      hours, deliberately. Repetition IS the point -- drift, leaks and
#             rare interleavings that a single pass cannot reach.
#   fuzz      extended sanitizer-backed campaigns against the parsers.
#
# A lane with nothing extra to offer at a tier must run its standard work and SAY
# SO, never silently do the same thing while the summary implies more. That is
# precisely the false-confidence pattern this project has had to dig out six
# separate times; see docs/ERRORS.md section 7.
LEXE_TIER="${LEXE_TIER:-standard}"

tier_lanes() {
    case "$1" in
    fast)     echo "evidence unit" ;;
    standard) echo "${ALL_LANES[*]}" ;;
    heavy)    echo "${ALL_LANES[*]}" ;;
    soak)     echo "${ALL_LANES[*]}" ;;
    fuzz)     echo "evidence unit sanitizers" ;;
    *)        echo "" ;;
    esac
}

tier_desc() {
    case "$1" in
    fast)     echo "seconds: the evidence guard and the unit suite only" ;;
    standard) echo "every lane once, the set a change is judged against" ;;
    heavy)    echo "every lane, larger samples and concurrency under CPU pressure" ;;
    soak)     echo "every lane, repeated for hours, resources measured either side" ;;
    fuzz)     echo "extended sanitizer-backed fuzz campaigns" ;;
    esac
}

lane_desc() {
    case "$1" in
    evidence)   echo "the evidence guard itself: does source_fingerprint() actually fire, and only where documented" ;;
    unit)       echo "the doctest binary: every subsystem, both GUI view models, the architecture rules" ;;
    acceptance) echo "end-to-end scripts against a throwaway LEXE_HOME" ;;
    integration) echo "trust and lifecycle across process boundaries" ;;
    gui)        echo "the frontends start, render and exit clean on a private display" ;;
    lifecycle)  echo "install -> run -> update -> rollback -> repair -> uninstall, and the same interrupted" ;;
    concurrency) echo "the same operations SIMULTANEOUSLY: contended locks, lease races, deadlock detection" ;;
    session) echo "the session-manager boundary, against the real systemd --user of this session" ;;
    conformance) echo "lexe verify vs the independent validator: a 182-case corpus derived from the SPEC, plus verify/install gate agreement" ;;
    security)   echo "hostile packages: traversal, escape, tampering, architecture lies, injection" ;;
    windows)    echo "a purpose-built Windows PE, actually run through Wine" ;;
    proton)     echo "the same Windows payload through the Proton chain" ;;
    workloads)  echo "programs .LEXE did not write: every specimen packaged, installed, run and compared against its direct-execution baseline, then FORMAT-0.1 §9 checked behaviourally" ;;
    explore)    echo "the combinations nobody hand-wrote: pairwise cross-product sampling, an independent lifecycle model over thousands of sequences, forced concurrent schedules" ;;
    sanitizers) echo "a separate ASan + UBSan build of the unit suite" ;;
    esac
}

have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------- availability

# Needs no build, no packages and no LEXE_HOME: it reads scripts/test.sh and
# hashes the tree. If this one cannot run, nothing can be cited as evidence
# anyway, so it has no skip condition worth naming beyond the hasher itself.
evidence_check() {
    have sha256sum || { echo "blocked: sha256sum is not available"; return 1; }
}

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

concurrency_check() {
    acceptance_check || return 1
    have bwrap || { echo "blocked: bubblewrap is not installed, so nothing can be sandboxed"; return 1; }
    have flock || { echo "blocked: flock(1) is not available, and the lease tests hold locks with it"; return 1; }
}

# Deliberately SKIP, not BLOCK. A host with no user session manager is a host
# where this feature does not apply -- `lexe service` reports that, and the
# input-determined half of the behaviour is covered by the unit lane. BLOCKED
# would claim an expected capability could not be shown, which is a different
# and stronger statement.
session_check() {
    acceptance_check || return 1
    have systemctl || { echo "skip: systemctl is not installed"; return 1; }
    systemctl --user is-system-running >/dev/null 2>&1 && return 0
    # Non-zero is not the question: "degraded" exits 1 whenever any unit in the
    # session has ever failed, and says nothing about whether the bus is
    # reachable. What settles it is whether it could connect at all.
    local err
    err="$(systemctl --user is-system-running 2>&1)"
    case "$err" in
        *"Failed to connect"*|*"No medium found"*|*"DBUS_SESSION_BUS_ADDRESS"*|*"XDG_RUNTIME_DIR"*)
            echo "skip: no systemd --user session here ($err)"; return 1 ;;
    esac
    return 0
}

# The corpora are generated artifacts and are deliberately NOT committed, so on
# a fresh clone this lane has nothing to run. That must read as BLOCKED, never
# as PASS: the lane's own summary exits 0 when every specimen was blocked, so if
# this check passed the run through, `--all` would report a green lane having
# executed none of the 184 specimens. Fake coverage is worse than a missing lane,
# because it is indistinguishable from real coverage in the summary.
workloads_check() {
    acceptance_check || return 1
    have python3 || { echo "skip: no python3, and the workload engine is Python"; return 1; }
    # BOTH corpora, not just the cheap one. Gating on the ELF index alone let
    # `--all` run with the Windows corpus absent and still record PASS.
    local pe_index="${LEXE_WORKLOAD_PE_INDEX:-/tmp/lexe-workloads-pe/index.json}"
    [[ -f "$pe_index" ]] || {
        echo "blocked: the PE workload corpus is not generated (python3 tests/workloads/generate_pe.py); an unexecuted specimen is not coverage"
        return 1
    }
    local elf_index="${LEXE_WORKLOAD_ELF_INDEX:-/tmp/lexe-workloads/index.json}"
    [[ -f "$elf_index" ]] || {
        echo "blocked: the ELF workload corpus is not generated (python3 tests/workloads/generate.py); an unexecuted specimen is not coverage"
        return 1
    }
}

explore_check() {
    workloads_check || return 1
}

conformance_check() {
    acceptance_check || return 1
    have python3 || have python || {
        echo "skip: no python3, so the independent validator cannot run"; return 1; }
    [[ -f "$REPO/tools/lexe-conformance/lexe_conformance.py" ]] || {
        echo "skip: the independent validator is not present"; return 1; }
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

# Counted and summarised, because an evidence audit found this lane emitting no
# line any summary could match: it appeared in every run as a green row with an
# empty note, which is indistinguishable from a lane that ran nothing.
#
# Discovering zero scripts is a FAILURE. The loop previously returned 0 in that
# case, so deleting the directory would have turned the lane green.
integration_run() {
    local status=0 found=0 passed=0 failed=0
    for script in "$REPO"/tests/integration/*.sh; do
        [[ -f "$script" ]] || continue
        found=$((found + 1))
        printf '%s-- %s%s\n' "$C_DIM" "$(basename "$script")" "$C_OFF"
        if LEXE_BUILD_DIR="$BUILD_DIR" bash "$script"; then
            passed=$((passed + 1))
        else
            failed=$((failed + 1)); status=1
        fi
    done
    if [[ $found -eq 0 ]]; then
        printf '  no integration cases were discovered: this lane proved nothing\n'
        printf '  0 passed, 1 failed, 0 skipped, 0 blocked\n'
        return 1
    fi
    printf '  %d integration cases discovered, %d attempted\n' "$found" "$found"
    printf '  %d passed, %d failed, 0 skipped, 0 blocked\n' "$passed" "$failed"
    return $status
}

gui_run() { bash "$REPO/scripts/gui-smoke.sh" "$BUILD_DIR"; }

lifecycle_run() {
    LEXE_BUILD_DIR="$BUILD_DIR" bash "$REPO/tests/lifecycle/run_all.sh"
}

concurrency_run() {
    LEXE_BUILD_DIR="$BUILD_DIR" bash "$REPO/tests/concurrency/run_all.sh"
}

session_run() {
    LEXE_BUILD_DIR="$BUILD_DIR" bash "$REPO/tests/session/run_all.sh"
}

# Needs no build and no LEXE_HOME -- it reads scripts/test.sh and hashes the
# tree, nothing more. That is why it is the first lane.
evidence_run() {
    bash "$REPO/tests/evidence/run_all.sh"
}

workloads_run() {
    # TWO scripts, and the second one is here because it was in no runner at all.
    # `against_lexe_lifecycle.sh` -- the FORMAT-0.1 §9 behavioural checks, the
    # launch-time dependency contract in both directions, and the assertion that
    # the pre-ship gate actually gates -- was reachable only by typing its path.
    # It was therefore not part of `--all`, and a green `--all` did not mean what
    # it appeared to mean. An unwired lane is a lane that does not run.
    local status=0
    LEXE_BUILD_DIR="$BUILD_DIR" bash "$REPO/tests/workloads/against_lexe.sh" || status=$?
    LEXE_BUILD_DIR="$BUILD_DIR" bash "$REPO/tests/workloads/against_lexe_lifecycle.sh"         || status=$?
    return $status
}

# The exploration lane. It reads LEXE_TIER itself (fast does the sampler only;
# heavy and soak widen the sequence counts, turn on 3-way sampling and add CPU
# pressure), so the tier contract above is honoured rather than ignored.
explore_run() {
    LEXE_BUILD_DIR="$BUILD_DIR" bash "$REPO/tests/workloads/against_lexe_matrix.sh"
}

conformance_run() {
    LEXE_BUILD_DIR="$BUILD_DIR" bash "$REPO/tests/conformance/run_all.sh"
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
    local stamp="$san_dir/.build-complete"

    # An INTERRUPTED build of this tree is discarded rather than continued.
    #
    # This lane once reported eight failures that looked exactly like logic bugs:
    # `approve_compile = true` read as not approved, `explicit_trust = true` read
    # as not trusted, `allow_permission_expansion = true` read as not approved.
    # Three unrelated booleans, all wrong, all in InstallOptions -- because a
    # field had been added to that struct and the tree held object files from
    # both layouts, so those booleans were being read from the wrong offsets.
    # The same 729 tests passed in the ordinary build and passed here again from
    # a clean tree.
    #
    # That is the worst shape a false failure can take: it is indistinguishable
    # from a real defect, and it sends you looking for a bug that is not there.
    # The stamp is removed before building and written after, so an interrupted
    # or killed build is detected on the next run and the tree is rebuilt from
    # scratch instead of being half-trusted.
    if [[ -d "$san_dir" && ! -f "$stamp" ]]; then
        echo "  (the previous sanitizer build did not complete — rebuilding clean)"
        rm -rf "$san_dir"
    fi
    rm -f "$stamp"

    cmake -S "$REPO" -B "$san_dir" -G Ninja \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
        -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" >/dev/null || return 1
    cmake --build "$san_dir" -j "$JOBS" --target lexe_tests || return 1
    : > "$stamp" # the build completed; this tree may be trusted incrementally
    # The vendored ed25519 performs signed left-shifts that UBSan reports.
    # Suppress them BY NAME so a new finding is still visible, rather than
    # tolerating a permanently noisy run that nobody reads.
    local supp="$REPO/tests/ubsan.supp"
    UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0${supp:+:suppressions=$supp}" \
    ASAN_OPTIONS="detect_leaks=1:abort_on_error=0" \
    env -u WAYLAND_DISPLAY -u DISPLAY "$san_dir/lexe_tests" \
        --reporters=console --no-intro=true
}

# ------------------------------------------------- evidence integrity
#
# A run is EVIDENCE about a particular state of the source tree. If the tree
# changes while the run is in flight, the result describes no state at all: some
# lanes tested the old code, some the new, and the object files may be a mixture
# of both.
#
# This is not hypothetical and it is not a style rule. It has happened three
# times in this project, and once it was maximally misleading: the sanitizer lane
# reported eight failures that looked exactly like logic bugs -- three unrelated
# booleans in one struct reading false while set true -- because a field had been
# added to that struct and the tree held object files from two layouts. The same
# tests passed in the ordinary build and passed again from a clean tree. Hours
# went into a defect that did not exist.
#
# So the runner records what it was testing and checks at the end that nothing
# moved. A run whose sources changed underneath it is reported as EVIDENCE
# INVALID and exits non-zero regardless of the lane results, because a green run
# that cannot be attributed to a commit is worse than a red one: it invites
# trust it has not earned.
#
# Cheap by construction: path, size and mtime of every source file, hashed. It
# catches an edit, which is the thing that matters, without reading the tree
# twice.
#
# `find -printf` rather than `find | xargs stat`, and the reason is a defect this
# project has now hit in three unrelated places: this repository lives under a
# path containing a space. `xargs` splits on whitespace, so every `stat` received
# two fragments of a path and failed, every failure went to /dev/null, and the
# fingerprint came back EMPTY — which made the guard silently approve everything.
# Found by testing that the guard FIRES rather than assuming it would: the first
# version did not fire when a source file was touched mid-run.
source_fingerprint() {
    {
        git -C "$REPO" rev-parse HEAD 2>/dev/null || echo "no-git"
        # Everything tracked or untracked EXCEPT two prefixes, each excluded for
        # a stated reason. The rule is "cover what can change a result", not
        # "cover everything" — but note that both exclusions have to be made
        # HERE as well as in the find below, because this line sees the whole
        # repository. The previous version pruned `tests/workloads/` in the find
        # and not here, which did almost nothing: a tracked specimen that was
        # edited still showed up in `git status`, so the prune only ever
        # suppressed a touch that changed no content. Found by testing that the
        # guard fires, which is the only way these things are ever found.
        #
        # 1. docs/ — documentation cannot change a lane result. Every docs/
        #    reference under scripts/, tests/ and tools/ is a comment or a
        #    human-readable message, and no lane parses a document at runtime.
        #    Checked, not assumed. The case that looks like a counterexample is
        #    not one: the conformance corpus is written FROM the spec by hand
        #    into corpus.py, which IS fingerprinted, so editing the spec cannot
        #    silently change what a lane checks.
        #
        # 2. tests/workloads/specs*/ — the specimen sources. These ARE inputs to
        #    the workload lane, so excluding them needs a better reason than
        #    convenience, and there is one: that lane fingerprints them by
        #    CONTENT, which is strictly stronger than what this function could
        #    do. It re-hashes the generator against the sha256 recorded in the
        #    corpus index and refuses to run on drift, and re-hashes every
        #    specimen binary against its recorded digest, blocking any whose
        #    bytes moved. They are also inputs to no other lane.
        #
        # Both exclusions also keep this bearable with three roles in one tree.
        # A guard that discards a twelve-lane run because somebody fixed a typo
        # in a Markdown file is a guard that creates pressure to bypass it.
        git -C "$REPO" status --porcelain 2>/dev/null \
            | grep -v -E '^(.. )"?(docs/|tests/workloads/specs)' || true
        # Only `tests/workloads/specs*/` is pruned now — the SPECIMEN sources,
        # the C and C++ programs manufactured for .LEXE to consume.
        #
        # This used to prune the whole of `tests/workloads/`, on the stated
        # grounds that no lane compiled or ran any of it, with the revisit
        # condition written down: "when a workload LANE exists, its inputs stop
        # being inert and belong back in here". That lane now exists
        # (`against_lexe.sh`), so the condition has come due and the harness
        # itself — the engine, the two lane scripts, the expectation files — is
        # fingerprinted like any other test code.
        #
        # The specimen sources stay pruned, and that is safe for a specific
        # reason rather than a convenient one: the harness fingerprints them
        # better than an mtime sweep can. It re-hashes the generator against the
        # sha256 recorded in the corpus `index.json` and refuses to run at all
        # on drift, and re-hashes every specimen binary against its recorded
        # digest, BLOCKING any specimen whose bytes moved. An mtime here would
        # only invalidate runs; that actually verifies the inputs.
        #
        # `examples/` and the build files are in the list because lanes DEPEND
        # on them and the patterns below used to miss both:
        # tests/conformance/01_differential.sh and 02_gate_agreement.sh build
        # packages out of `examples/`, and CMakeLists.txt decides what the
        # binary under test even is — yet neither is a *.cpp under src/, so the
        # only thing catching them was the repo-wide status line above, which is
        # now filtered. A guard that misses the build definition is not a guard.
        find "$REPO/src" "$REPO/tests" "$REPO/scripts" "$REPO/tools" \
             "$REPO/schema" "$REPO/examples" "$REPO/CMakeLists.txt" \
             -path "$REPO/tests/workloads/specs*" -prune -o -type f \
             \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' -o -name '*.sh' \
                -o -name '*.py' -o -name '*.json' -o -name '*.c' \
                -o -name 'CMakeLists.txt' -o -name '*.cmake' \) \
             -printf '%p %s %T@\n' 2>/dev/null \
            | LC_ALL=C sort
    } | sha256sum | cut -d' ' -f1
}

RUN_COMMIT="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
RUN_DIRTY="$(git -C "$REPO" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
RUN_FINGERPRINT_BEFORE=""

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
    # POSITIVE evidence that the expected products exist. An exit status of 0
    # covers "compiled everything" and "compiled nothing, already up to date"
    # equally, and `ninja: no work to do.` used to print as "built clean, zero
    # warnings" -- a warning count grepped from a log describing zero
    # compilations. That is the ninth instance of a check reporting on work it
    # never observed, so this one looks at the artifacts.
    local missing=() present=0 product
    for product in lexe lexe_tests; do
        if [[ -s "$BUILD_DIR/$product" && -x "$BUILD_DIR/$product" ]]; then
            present=$((present + 1))
        else
            missing+=( "$product" )
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        say "${C_RED}  the build reported success but produced no ${missing[*]}${C_OFF}"
        say "${C_RED}  (exit status 0 is not evidence that anything was built)${C_OFF}"
        rm -f "$log"; return 1
    fi
    # Say which it was, so a reader can tell a compile from a no-op.
    local did
    if grep -q 'no work to do' "$log"; then
        did="already up to date"
    else
        did="$(grep -cE '^\[[0-9]+/[0-9]+\]' "$log" || true) step(s) compiled"
    fi
    say "${C_GREEN}  ${present} product(s) present, zero warnings, ${did}${C_OFF}"
    rm -f "$log"
}

# The newest modification time anywhere in the fingerprint's file set.
#
# This answers a different question from source_fingerprint, and the difference
# is the point. A fingerprint says whether the tree LOOKS the same; this says
# whether anything was WRITTEN. A file edited and restored has identical content
# and a newer mtime, so A -> B -> A -- a stash/pop, a branch round-trip, an
# editor save-and-undo -- is invisible to the first and obvious to the second.
#
# Honest limit, stated because an unstated limit is how these things rot: a
# revert that deliberately restores the original timestamp (`cp -p`, `touch -r`)
# defeats this, and nothing short of watching the filesystem would catch it. It
# is aimed at accident and ordinary tooling, not at an adversary with the clock.
newest_mtime() {
    find "$REPO/src" "$REPO/tests" "$REPO/scripts" "$REPO/tools" \
         "$REPO/schema" "$REPO/examples" "$REPO/CMakeLists.txt" \
         -path "$REPO/tests/workloads/specs*" -prune -o -type f \
         \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' -o -name '*.sh' \
            -o -name '*.py' -o -name '*.json' -o -name '*.c' \
            -o -name 'CMakeLists.txt' -o -name '*.cmake' \) \
         -printf '%T@\n' 2>/dev/null | sort -rn | head -1
}

# Every fingerprint reading taken during this run, in order. A change-and-revert
# is invisible in the endpoints and obvious in the sequence.
FINGERPRINT_SAMPLES=()
FINGERPRINT_LANES=()

sample_fingerprint() { # lane-label
    FINGERPRINT_SAMPLES+=( "$(source_fingerprint)" )
    FINGERPRINT_LANES+=( "$1" )
}

run_lane() {
    local lane="$1" reason state
    head2 "$lane"
    say "${C_DIM}  $(lane_desc "$lane")${C_OFF}"
    sample_fingerprint "before:$lane"

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

    # A lane can exit 0 having blocked part of its work, and several do: the
    # shared lib.sh summary returns 0 whenever nothing FAILED, so BLOCKED is
    # invisible to the exit status. Read the lane's own count instead.
    #
    # This mattered. `--all` could report `PASS workloads  1 passed, 0 failed,
    # 0 skipped` over a run in which the entire 72-specimen Windows corpus was
    # never executed -- because the availability check gated on the Linux index
    # alone, the lane exited 0 with one corpus done, and the summary regex could
    # not even match the word "blocked". Three separate mechanisms each reported
    # honestly and the composition lied. And it is the EXPECTED state after a WSL
    # restart wipes /tmp, since the Linux corpus regenerates in seconds and the
    # Windows one needs MinGW and a Wine prefix.
    local in_lane_blocked
    in_lane_blocked="$(grep -oE '[0-9]+ blocked' "$log" | tail -1 | grep -oE '^[0-9]+' || true)"
    if [[ $status -eq 0 && -n "$in_lane_blocked" && "$in_lane_blocked" -gt 0 ]]; then
        say "${C_BLUE}  BLOCKED${C_OFF} $(lane_summary "$lane" "$log")"
        record "$lane" "BLOCKED" "$(lane_summary "$lane" "$log")"
    elif [[ $status -eq 0 ]]; then
        say "${C_GREEN}  PASS${C_OFF} $(lane_summary "$lane" "$log")"
        record "$lane" "PASS" "$(lane_summary "$lane" "$log")"
    else
        say "${C_RED}  FAIL${C_OFF} (exit $status)"
        [[ $VERBOSE -eq 0 ]] && tail -40 "$log"
        record "$lane" "FAIL" "exit $status"
    fi
    rm -f "$log"
    sample_fingerprint "after:$lane"
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
        grep -oE '[0-9]+ passed, [0-9]+ failed(, [0-9]+ skipped)?(, [0-9]+ blocked)?' "$2" | tail -1 || true ;;
    esac
}

# ------------------------------------------------------- soak + leak detection
#
# A soak is only worth its hours if something is WATCHING. Repetition on its own
# proves nothing crashed; what it is good for is the class of defect a single pass
# cannot see -- a descriptor, a mount, a lock, a process or a gigabyte that is not
# given back. So every cycle is bracketed by a snapshot and the deltas are
# reported PER CYCLE: a leak of one descriptor per install is invisible in a total
# and obvious in a slope.
#
# Every figure is read from outside .LEXE -- /proc, ps, the filesystem -- because
# a runtime reporting on its own resource use is the self-reporting pattern that
# has already produced six false-clean results here (docs/ERRORS.md §7).
soak_snapshot() {
    local lexe="$BUILD_DIR/lexe"
    local procs lexe_procs wine_procs dstate mounts netns tmp_entries tmp_mb fds load
    procs="$(ps -e --no-headers 2>/dev/null | wc -l)"
    # `pgrep -c` prints 0 AND exits 1 when it matches nothing, so `|| echo 0`
    # emits two zeros. Counting lines is unambiguous.
    lexe_procs="$(pgrep -f "$lexe" 2>/dev/null | wc -l)"
    wine_procs="$(pgrep -f 'wineserver|wine64' 2>/dev/null | wc -l)"
    # D-state is called out on its own: an uninterruptible process cannot be
    # killed, and is the one leak a later run inherits.
    dstate="$(ps -eo stat= 2>/dev/null | grep -c '^D' || true)"
    mounts="$(wc -l < /proc/mounts 2>/dev/null || echo 0)"
    netns="$(find /proc -maxdepth 3 -path '*/ns/net' -type l 2>/dev/null \
             | xargs -r readlink 2>/dev/null | sort -u | wc -l)"
    tmp_entries="$(find /tmp -maxdepth 1 2>/dev/null | wc -l)"
    tmp_mb="$(du -sm /tmp 2>/dev/null | cut -f1)"
    fds="$(find /proc -maxdepth 3 -path '*/fd/*' -type l 2>/dev/null | wc -l)"
    load="$(cut -d' ' -f1 /proc/loadavg 2>/dev/null)"
    printf 'processes=%s lexe_procs=%s wine_procs=%s dstate=%s mounts=%s netns=%s tmp_entries=%s tmp_mb=%s fds=%s loadavg=%s\n' \
        "${procs:-0}" "${lexe_procs:-0}" "${wine_procs:-0}" "${dstate:-0}" \
        "${mounts:-0}" "${netns:-0}" "${tmp_entries:-0}" "${tmp_mb:-0}" \
        "${fds:-0}" "${load:-0}"
}

snap_get() { printf '%s\n' "$1" | tr ' ' '\n' | grep "^$2=" | cut -d= -f2 | head -1; }

# Report what changed, and judge it. Not every delta is a leak: /tmp grows because
# a corpus was generated, and loadavg is not a resource at all. Judge only what
# nothing legitimate should retain across a COMPLETED cycle.
soak_compare() {
    local before="$1" after="$2" cycle="$3" bad=0
    local key b a
    for key in lexe_procs wine_procs dstate mounts netns fds; do
        b="$(snap_get "$before" "$key")"; a="$(snap_get "$after" "$key")"
        [[ -z "$b" || -z "$a" ]] && continue
        if (( a > b )); then
            printf '    %sleak?%s cycle %s: %s %s -> %s (+%s)\n' \
                "$C_YELLOW" "$C_OFF" "$cycle" "$key" "$b" "$a" "$((a - b))"
            bad=1
        fi
    done
    for key in processes tmp_entries tmp_mb; do
        b="$(snap_get "$before" "$key")"; a="$(snap_get "$after" "$key")"
        [[ -z "$b" || -z "$a" ]] && continue
        if [[ "$a" != "$b" ]]; then
            printf '    (informational) %s: %s -> %s\n' "$key" "$b" "$a"
        fi
    done
    return $bad
}

# Runs the lane set until LEXE_SOAK_SECONDS has elapsed (default one hour), at
# least once. A single completed cycle is reported as what it is rather than
# dressed up as a soak.
soak_run() {
    local budget="${LEXE_SOAK_SECONDS:-3600}"
    local started elapsed cycle=0 leaks=0
    started="$(date +%s)"
    local first_snap="" last_snap="" before after lane
    while :; do
        cycle=$((cycle + 1))
        before="$(soak_snapshot)"
        [[ -z "$first_snap" ]] && first_snap="$before"
        head2 "soak cycle $cycle"
        for lane in "${LANES[@]}"; do run_lane "$lane"; done
        after="$(soak_snapshot)"
        last_snap="$after"
        printf '  resources, cycle %s:\n' "$cycle"
        soak_compare "$before" "$after" "$cycle" || leaks=$((leaks + 1))
        elapsed=$(( $(date +%s) - started ))
        (( elapsed >= budget )) && break
        printf '  %ss of %ss budget used; starting another cycle\n' "$elapsed" "$budget"
    done
    printf '\n%s== soak summary ==%s\n' "$C_BOLD" "$C_OFF"
    printf '  %s cycle(s) over %ss\n' "$cycle" "$elapsed"
    if (( cycle == 1 )); then
        printf '  NOTE: one cycle only, so this measured no repetition. Raise\n'
        printf '  LEXE_SOAK_SECONDS to make it a soak.\n'
    fi
    printf '  cycles reporting a possible leak: %s\n' "$leaks"
    printf '  first snapshot: %s\n' "$first_snap"
    printf '  last  snapshot: %s\n' "$last_snap"
    (( leaks > 0 )) && return 1
    return 0
}


# --------------------------------------------------------------- arguments

[[ $# -eq 0 ]] && { usage; exit 2; }
WANT_LIST=0
while [[ $# -gt 0 ]]; do
    case "$1" in
    --all)        LANES=("${ALL_LANES[@]}") ;;
    --fast|--standard|--heavy|--soak|--fuzz)
        LEXE_TIER="${1#--}"
        # shellcheck disable=SC2207
        LANES=($(tier_lanes "$LEXE_TIER"))
        ;;
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
RUN_FINGERPRINT_BEFORE="$(source_fingerprint)"
RUN_NEWEST_MTIME_BEFORE="$(newest_mtime)"
printf '  commit:     %s%s\n' "$RUN_COMMIT" \
    "$([[ "$RUN_DIRTY" != "0" ]] && printf ' (+%s uncommitted file(s))' "$RUN_DIRTY")"
printf '  repository: %s\n' "$REPO"
printf '  build dir:  %s\n' "$BUILD_DIR"
printf '  lanes:      %s\n' "${LANES[*]}"
printf '  tier:       %s (%s)\n' "$LEXE_TIER" "$(tier_desc "$LEXE_TIER")"
export LEXE_TIER

if [[ $DO_BUILD -eq 1 ]]; then
    build_first || { printf '\n%sbuild failed — no lane was run%s\n' "$C_RED" "$C_OFF"; exit 1; }
fi

# A soak repeats the lane set and watches what accumulates; everything else
# runs it once. Dispatched here rather than inside soak_run, because putting it
# inside made soak_run call itself -- which would have recursed until bash gave
# up, and is the same defect an independent pass hit last wave with a patch that
# printed every correct line on the way down.
if [[ "$LEXE_TIER" == "soak" ]]; then
    soak_run || true   # a possible leak is reported, not turned into an exit here
else
    for lane in "${LANES[@]}"; do run_lane "$lane"; done
fi

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

RUN_FINGERPRINT_AFTER="$(source_fingerprint)"
if [[ -n "$RUN_FINGERPRINT_BEFORE" &&
      "$RUN_FINGERPRINT_BEFORE" != "$RUN_FINGERPRINT_AFTER" ]]; then
    # Something was WRITTEN during the run, whatever the tree looks like now.
    local newest_after; newest_after="$(newest_mtime)"
    if [[ -n "$RUN_NEWEST_MTIME_BEFORE" && -n "$newest_after" &&
          "$newest_after" != "$RUN_NEWEST_MTIME_BEFORE" ]]; then
        printf '\n  %sEVIDENCE INVALID: a source file was written during this run.%s\n' \
            "$C_RED" "$C_OFF"
        printf '  The newest modification time moved from %s to %s.\n' \
            "$RUN_NEWEST_MTIME_BEFORE" "$newest_after"
        printf '  It does not matter whether the content ended up identical:\n'
        printf '  some lanes ran before that write and some after, so this run\n'
        printf '  describes no single tree. Discard it and repeat.\n'
    fi

    # The endpoints matching is NOT proof that nothing moved. Report any lane
    # boundary whose reading differed from the first, so a change-and-revert
    # names the lanes it straddled instead of vanishing.
    local base_sample="${FINGERPRINT_SAMPLES[0]:-}"
    local drifted=() i
    for i in "${!FINGERPRINT_SAMPLES[@]}"; do
        [[ "${FINGERPRINT_SAMPLES[$i]}" != "$base_sample" ]] &&
            drifted+=( "${FINGERPRINT_LANES[$i]}" )
    done
    if [[ ${#drifted[@]} -gt 0 && "$RUN_FINGERPRINT_BEFORE" == "$(source_fingerprint)" ]]; then
        printf '\n  %sEVIDENCE INVALID: the tree changed and changed back.%s\n' \
            "$C_RED" "$C_OFF"
        printf '  The run started and ended in the same state, so the endpoints\n'
        printf '  agree, but these lane boundaries saw something different:\n'
        printf '    %s\n' "${drifted[*]}"
        printf '  Those lanes did not all test the same tree. Discard and repeat.\n'
    fi
    printf '\n  %sEVIDENCE INVALID: the source tree changed during this run.%s\n' \
        "$C_RED" "$C_OFF"
    printf '  Some lanes tested the code before the change and some after, and the\n'
    printf '  object files may be a mixture. Whatever the results above say, they\n'
    printf '  describe no single state of the tree — discard them and run again\n'
    printf '  against a still tree.\n'
    exit 1
fi

if [[ $failed -gt 0 ]]; then
    printf '\n  %s%d lane(s) failed%s\n' "$C_RED" "$failed" "$C_OFF"
    exit 1
fi
printf '\n  %sno failures%s\n' "$C_GREEN" "$C_OFF"
exit 0

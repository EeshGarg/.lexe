#!/usr/bin/env bash
# tests/concurrency/lib.sh — helpers for racing real operations against each other.
#
# Sourced after tests/acceptance/lib.sh and tests/lifecycle/lib.sh, whose
# reporting, scratch LEXE_HOME, headless guard, versioned-package builder and
# coherence check these reuse.
#
# Three things make a concurrency test worth having rather than merely present:
#
#   1. **Real processes.** The locks are `flock(2)`, so they are per-open-file and
#      per-process. Two threads in one process would share descriptors and prove
#      nothing about the thing that actually serialises operations.
#
#   2. **A real barrier.** Starting two commands with `&` on adjacent lines loses
#      the race: the first is usually finished before the second is scheduled.
#      `conc_race` makes every participant spin on a shared file and then proceed
#      in the same instant, so the contended window is genuinely entered.
#
#   3. **A hard timeout on everything.** A deadlock must FAIL the suite, not hang
#      it. Every participant runs under `timeout`, and the wait for them has its
#      own deadline, so "the suite took forever" can never be the symptom.
#
# What the assertions look for is not "both succeeded". Serialisation is allowed
# to make one of them lose, and losing correctly (BusyError, exit 6) is the right
# outcome for a conflicting mutation. What is NOT allowed is: a crash, a hang, two
# winners where only one may win, a mutation that reports success without having
# happened, or any partially applied state afterwards.

CONC_TIMEOUT="${CONC_TIMEOUT:-120}"

# conc_race <label> <n> -- <command...>
#
# Run N copies of the same command simultaneously. Results land in
# $CONC_DIR/<label>.<i>.{out,rc}.
conc_race_same() {
    local label="$1" n="$2"; shift 2
    [[ "${1:-}" == "--" ]] && shift
    local go="$CONC_DIR/$label.go"
    rm -f "$go" "$CONC_DIR/$label".*.out "$CONC_DIR/$label".*.rc

    local pids=()
    for ((i = 0; i < n; ++i)); do
        (
            # Spin until the starter releases everyone. A file test is cheap and
            # needs no IPC primitive that could itself serialise us.
            while [[ ! -e "$go" ]]; do :; done
            timeout "$CONC_TIMEOUT" "$@" >"$CONC_DIR/$label.$i.out" 2>&1
            printf '%s' "$?" > "$CONC_DIR/$label.$i.rc"
        ) &
        pids+=($!)
    done
    # Let them all reach the spin, then start them together.
    sleep 0.3
    : > "$go"
    conc_wait_all "$label" "${pids[@]}"
}

# conc_race_pair <label> -- <command A...> -- <command B...>
#
# Run two DIFFERENT commands simultaneously. Results land in
# $CONC_DIR/<label>.a.{out,rc} and .b.{out,rc}.
conc_race_pair() {
    local label="$1"; shift
    [[ "${1:-}" == "--" ]] && shift
    local a=() b=() target=a
    while [[ $# -gt 0 ]]; do
        if [[ "$1" == "--" ]]; then target=b; shift; continue; fi
        if [[ "$target" == a ]]; then a+=("$1"); else b+=("$1"); fi
        shift
    done
    local go="$CONC_DIR/$label.go"
    rm -f "$go" "$CONC_DIR/$label".*.out "$CONC_DIR/$label".*.rc

    local pids=()
    for side in a b; do
        (
            while [[ ! -e "$go" ]]; do :; done
            if [[ "$side" == a ]]; then
                timeout "$CONC_TIMEOUT" "${a[@]}" >"$CONC_DIR/$label.a.out" 2>&1
                printf '%s' "$?" > "$CONC_DIR/$label.a.rc"
            else
                timeout "$CONC_TIMEOUT" "${b[@]}" >"$CONC_DIR/$label.b.out" 2>&1
                printf '%s' "$?" > "$CONC_DIR/$label.b.rc"
            fi
        ) &
        pids+=($!)
    done
    sleep 0.3
    : > "$go"
    conc_wait_all "$label" "${pids[@]}"
}

# Wait for every participant, with a deadline of its own so a wedged child cannot
# hang the suite even if `timeout` were somehow evaded.
conc_wait_all() {
    local label="$1"; shift
    local deadline=$(( CONC_TIMEOUT + 30 ))
    local waited=0
    for pid in "$@"; do
        while kill -0 "$pid" 2>/dev/null; do
            if [[ $waited -ge $((deadline * 10)) ]]; then
                fail "$label: participants finished within $deadline s" \
                    "a participant is still running — treating this as a DEADLOCK"
                kill -9 "$pid" 2>/dev/null
                CONC_DEADLOCK=1
                return 1
            fi
            sleep 0.1
            waited=$((waited + 1))
        done
        wait "$pid" 2>/dev/null
    done
    CONC_DEADLOCK=0
    return 0
}

conc_rc()  { cat "$CONC_DIR/$1.$2.rc" 2>/dev/null || printf 'missing'; }
conc_out() { cat "$CONC_DIR/$1.$2.out" 2>/dev/null || printf ''; }

# How many of the N participants exited 0.
conc_winners() {
    local label="$1" n="$2" won=0
    for ((i = 0; i < n; ++i)); do
        [[ "$(conc_rc "$label" "$i")" == "0" ]] && won=$((won + 1))
    done
    printf '%s' "$won"
}

# Every distinct exit code the participants produced, sorted — so a report can
# say WHICH codes were seen rather than only how many won.
conc_codes() {
    local label="$1" n="$2"
    for ((i = 0; i < n; ++i)); do conc_rc "$label" "$i"; printf '\n'; done |
        sort -u | tr '\n' ' '
}

# A timeout kill shows up as 124, and it is never an acceptable outcome: it means
# the operation neither completed nor refused.
#
# Reads the result files that EXIST rather than assuming numeric indices.
# `conc_race_same` writes <label>.0.rc, <label>.1.rc ...; `conc_race_pair` writes
# <label>.a.rc and <label>.b.rc. This function indexed 0..n-1 for BOTH, so after
# every PAIR race it read two files that do not exist, `conc_rc` returned the
# string "missing", nothing ever equalled "124", and it fell straight through to
# `pass`. Five assertions -- update-update, update-rollback, repair-uninstall,
# install-uninstall and order-<direction>, which are precisely the
# deadlock-prone pairings -- could not fail. Demonstrated by planting a real 124
# in <label>.a.rc and watching the assertion pass.
#
# Discovering NO result files is now a failure too: an assertion that observed
# nothing has not been performed.
conc_assert_no_timeouts() {
    local label="$1" n="${2:-}" bad="" found=0 f idx
    for f in "$CONC_DIR/$label".*.rc; do
        [[ -f "$f" ]] || continue
        found=$((found + 1))
        idx="${f##*/}"; idx="${idx#"$label."}"; idx="${idx%.rc}"
        [[ "$(cat "$f" 2>/dev/null)" == "124" ]] && bad+="$idx "
    done
    if [[ $found -eq 0 ]]; then
        fail "$label: no participant timed out" \
            "no participant recorded an exit status at all, so this assertion" \
            "observed nothing -- which is not a pass"
        return 1
    fi
    if [[ -n "$n" && "$found" -ne "$n" ]]; then
        fail "$label: no participant timed out" \
            "expected $n participants, found $found result file(s)"
        return 1
    fi
    if [[ -n "$bad" ]]; then
        fail "$label: no participant timed out" \
            "participant(s) $bad hit the ${CONC_TIMEOUT}s timeout — neither" \
            "completed nor refused, which is the shape of a lock that is never released"
        return 1
    fi
    pass "$label: no participant timed out"
    return 0
}

# A participant that did not win must have lost for a REASON THAT IS ALLOWED, and
# must say which. There are exactly two acceptable outcomes for a contended
# mutation:
#
#   0  it did the work
#   6  it found the lock held and refused, OR it acquired the lock second and
#      found the desired state already holding — both BusyError since
#      docs/ERRORS.md §6 was resolved
#
# The second half of 6 is not a lock failure at all. `install` serialises on
# AppMutation, so the loser does not fail to acquire — it acquires second and
# then discovers the desired state already holds. Refusing rather than silently
# exiting 0 is deliberate: reinstalling the FILES is a different operation, and
# the message points at the one that does it.
#
# That case used to exit 1, the catch-all, which a script racing two installs
# could not tell apart from "something broke". docs/ERRORS.md §6 records the
# change to 6 as **resolved**, and this function was the only thing that could
# have held it — except that it did not. It kept an `1)` arm that accepted exit 1
# whenever the message matched "already installed|already current|already at",
# so reverting the fix left this lane GREEN. That was verified rather than
# argued: driving this function with fabricated participant records, the
# reverted shape passed and only a silent exit 1 failed. A resolved finding with
# no regression test behind it is an unresolved finding with better paperwork.
#
# So exit 1 is now a FAILURE. The grep survives only to NAME it — it decides how
# the failure is described, never whether one is reported, which is the sense in
# which §6's claim that the prose-matching is "no longer load-bearing" is now
# true. Any other exit code means the loser did not lose, it broke.
conc_assert_losers_lost_legitimately() {
    local label="$1" n="$2" bad="" busy=0
    for ((i = 0; i < n; ++i)); do
        local rc; rc="$(conc_rc "$label" "$i")"
        case "$rc" in
        0) continue ;;
        6) busy=$((busy + 1)) ;;
        1)
            if grep -qiE "already installed|already current|already at" \
                    "$CONC_DIR/$label.$i.out" 2>/dev/null; then
                bad+="[$i found the work already done and exited 1 rather than 6 — the pre-§6 behaviour] "
            else
                bad+="[$i exited 1 without saying why] "
            fi
            ;;
        *) bad+="[$i exited $rc] " ;;
        esac
    done
    if [[ -n "$bad" ]]; then
        fail "$label: every loser lost for an allowed reason" "$bad" \
            "$(conc_out "$label" 0 | tail -3)"
        return 1
    fi
    pass "$label: every participant won or refused with 6 ($busy did), and none \
fell back to the untyped 1"
    return 0
}

# conc_wait_alive <version> [seconds] -> prints the payload pid, or nothing
#
# Waits for a detached launch to actually be RUNNING, rather than sleeping a
# fixed two seconds and hoping.
#
# This replaced a `sleep 2`, and the reason is worth recording: that two seconds
# was enough on an idle machine and not enough on a busy one. Running this lane
# beside a sanitizer build turned three passing checks into failures and two into
# skips -- "could not keep the application alive long enough" -- with nothing
# wrong in the engine at all. A concurrency suite that cries wolf under load is
# worse than no suite, because the first thing anyone does with a flaky failure
# is stop reading it.
#
# Polling is also strictly more correct than a longer sleep: it returns as soon
# as the process is up, so the common case does not get slower to make the loaded
# case pass.
conc_wait_alive() {
    local version="$1" deadline="${2:-20}" waited=0 pid
    while (( waited < deadline )); do
        pid="$(pgrep -f "versions/$version/$LC_ENTRY" | head -1 || true)"
        if [[ -n "$pid" ]]; then
            printf '%s' "$pid"
            return 0
        fi
        sleep 1
        waited=$(( waited + 1 ))
    done
    return 1
}

conc_setup() {
    lc_setup
    CONC_DIR="$ACC_ROOT/work/conc"
    mkdir -p "$CONC_DIR"
}

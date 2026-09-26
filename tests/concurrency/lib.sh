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
conc_assert_no_timeouts() {
    local label="$1" n="$2" bad=""
    for ((i = 0; i < n; ++i)); do
        [[ "$(conc_rc "$label" "$i")" == "124" ]] && bad+="$i "
    done
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
# must say which. There are exactly three acceptable outcomes for a contended
# mutation, and the third one was a surprise worth recording:
#
#   0  it did the work
#   6  BusyError — it found the lock held and refused, without writing anything
#   1  it WAITED for the lock, got it, and found the work already done
#      ("... is already installed and current; use `lexe repair` ...")
#
# The third is not a lock failure at all. `install` serialises on AppMutation, so
# the loser does not fail to acquire — it acquires second and then discovers the
# desired state already holds. Refusing rather than silently exiting 0 is
# deliberate: reinstalling the FILES is a different operation, and the message
# points at the one that does it.
#
# It does mean exit 1 currently covers both "someone else already did this" and
# "something broke", which a script racing two installs cannot tell apart. That is
# an error-identity gap rather than a concurrency defect, and it is why the
# structured error taxonomy exists — see docs/ERRORS.md.
#
# Any OTHER exit code means the loser did not lose, it broke.
conc_assert_losers_lost_legitimately() {
    local label="$1" n="$2" bad="" already=0
    for ((i = 0; i < n; ++i)); do
        local rc; rc="$(conc_rc "$label" "$i")"
        case "$rc" in
        0) continue ;;
        6) continue ;;
        1)
            # Only acceptable when it says so. An exit 1 that does NOT identify
            # itself as "already done" is an ordinary failure hiding in the set.
            if grep -qiE "already installed|already current|already at" \
                    "$CONC_DIR/$label.$i.out" 2>/dev/null; then
                already=$((already + 1))
                continue
            fi
            bad+="[$i exited 1 without saying why] "
            ;;
        *) bad+="[$i exited $rc] " ;;
        esac
    done
    if [[ -n "$bad" ]]; then
        fail "$label: every loser lost for an allowed reason" "$bad" \
            "$(conc_out "$label" 0 | tail -3)"
        return 1
    fi
    pass "$label: every participant won, refused as busy (6), or found the work \
already done ($already did)"
    return 0
}

conc_setup() {
    lc_setup
    CONC_DIR="$ACC_ROOT/work/conc"
    mkdir -p "$CONC_DIR"
}

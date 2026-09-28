#!/usr/bin/env bash
# tests/workloads/against_lexe_matrix.sh — the exploration lane.
#
# `against_lexe.sh` asks whether each program still behaves as it did.
# `against_lexe_lifecycle.sh` asks whether the §9 guarantees hold for programs
# whose correct output is known. This lane asks a third question with the same
# material:
#
#     across the combinations nobody hand-wrote, and the operation sequences
#     nobody thought to try, does anything disagree?
#
# It drives tests/workloads/explore.py, which is four engines:
#
#   sample  a deterministic PAIRWISE plan over ten dimensions (specimen, payload,
#           chain, launch mode, sandbox policy, arguments, environment,
#           filesystem state, lifecycle state, concurrency condition). The plan's
#           own promise is verified — every required pair is re-derived from the
#           plan and a miss FAILS the lane, because a sampler that claims all-pairs
#           without checking is claiming, not covering.
#
#   model   an INDEPENDENT abstract model of the lifecycle, run over thousands of
#           generated legal and illegal sequences. The model shares no code with
#           the runtime's state handling; where FORMAT-0.1 and docs/ERRORS.md do
#           not decide an outcome it says so and falls back to a property that
#           needs no specification — that the same abstract state answer the same
#           operation the same way, whatever path reached it.
#
#   race    generated concurrent schedules. Where a critical section can be made
#           long and its entry observed from outside (a launch lease), the
#           interleaving is FORCED rather than hoped for.
#
#   reduce  delta-debugging of any failing sequence down to a minimal reproducer,
#           with the original trace retained beside it as provenance.
#
# Every randomised choice descends from a seed that is printed, and a printed seed
# replays the run exactly.
#
# Sizes. Ordinary is a few minutes. LEXE_HEAVY=1 raises the sequence count and
# turns on 3-way sampling and CPU pressure; LEXE_SOAK=1 goes further. The ordinary
# size is chosen so this lane can live in `--all` without dominating it.
#
# Usage:  tests/workloads/against_lexe_matrix.sh
# Env:    LEXE_BUILD_DIR, LEXE_WORKLOAD_ELF_INDEX, LEXE_HEAVY, LEXE_SOAK,
#         LEXE_EXPLORE_SEED, LEXE_EXPLORE_JOBS, LEXE_EXPLORE_OUT
set -uo pipefail
WL_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$WL_DIR/../acceptance/lib.sh"

acc_begin "workloads: cross-product sampling, model-based lifecycle, forced races"

LEXE_BIN="${LEXE_BUILD_DIR:-$ACC_REPO/build-linux}/lexe"
INDEX="${LEXE_WORKLOAD_ELF_INDEX:-/tmp/lexe-workloads/index.json}"
SEED="${LEXE_EXPLORE_SEED:-$(date +%Y%m%d)}"
JOBS="${LEXE_EXPLORE_JOBS:-8}"
OUT="${LEXE_EXPLORE_OUT:-$(mktemp -d /tmp/lexe-explore-report.XXXXXX)}"
SCRATCH="$(mktemp -d /tmp/lexe-explore-scratch.XXXXXX)"

cleanup() { rm -rf "$SCRATCH"; }
trap cleanup EXIT

# A lane that executed nothing must exit NON-ZERO, and this lane enforces that
# itself rather than relying on scripts/test.sh's `explore_check` having run
# first. Two reasons. That check only guards the test.sh path, and this script is
# invokable directly — which is how it will be audited. And `acc_summary` returns
# 0 whenever no check FAILED, so a run that blocked on everything reports success
# by construction; scripts/test.sh says exactly that about the workload lane at
# its own `workloads_check`. Blocking with nothing executed is therefore an
# explicit non-zero here, kept distinct from a FAIL so the reason stays readable.
blocked_exit() {
    blocked "$@"
    acc_summary
    printf '  no engine executed anything; exiting non-zero so this cannot read as a pass\n'
    exit 3
}

[[ -x "$LEXE_BIN" ]] || blocked_exit "runtime not built at $LEXE_BIN" \
    "build it: cmake --build build-linux -j"
[[ -f "$INDEX" ]] || blocked_exit "no ELF workload corpus at $INDEX" \
    "regenerate: python3 tests/workloads/generate.py --out /tmp/lexe-workloads"
command -v python3 >/dev/null 2>&1 || \
    blocked_exit "python3 is required to drive explore.py"

# Sizes, resolved from LEXE_TIER -- the runner's own contract (scripts/test.sh)
# rather than a private pair of switches -- and PRINTED, so a report that cites a
# number also says which budget produced it. A lane that ignores the tier cannot
# be scaled, and then `--soak` is `--all` with a longer name.
SIZE="${LEXE_TIER:-standard}"
case "$SIZE" in
fast)     SEQ=250;   ORDER=2; REPEATS=2;  PRESSURE="";        CASES=0 ;;
heavy)    SEQ=20000; ORDER=3; REPEATS=25; PRESSURE=--pressure; CASES=400 ;;
soak)     SEQ=60000; ORDER=3; REPEATS=60; PRESSURE=--pressure; CASES=1200 ;;
fuzz)     SEQ=20000; ORDER=2; REPEATS=4;  PRESSURE="";        CASES=0 ;;
*)        SIZE=standard
          SEQ=3000;  ORDER=2; REPEATS=8;  PRESSURE="";        CASES=0 ;;
esac
note "tier=$SIZE  seed=$SEED  jobs=$JOBS  sequences=$SEQ  ${ORDER}-way sampling"
if [[ "$SIZE" == "fuzz" ]]; then
    note "this lane has nothing fuzz-specific to offer: it runs its heavy sequence"
    note "count against the SAME engines. Said out loud rather than implied."
fi
note "reports: $OUT"
note "host load at start: $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo '?')"

# `explore.py` pins PATH for every child it spawns. That is not tidiness: with a
# WSL-interop PATH (36 /mnt/c entries here) .LEXE's compatibility-provider
# discovery stats every candidate in every entry, and `lexe doctor` costs 3.5s
# instead of 22ms. Timing this lane through such a PATH would measure the host.
EXPLORE=(python3 "$WL_DIR/explore.py" --lexe "$LEXE_BIN" --index "$INDEX"
         --scratch "$SCRATCH" --jobs "$JOBS")
[[ -n "${LEXE_WORKLOAD_PE_INDEX:-}" ]] && EXPLORE+=(--index-pe "$LEXE_WORKLOAD_PE_INDEX")
[[ -n "${LEXE_WORKLOAD_PORTABLE_INDEX:-}" ]] && \
    EXPLORE+=(--index-portable "$LEXE_WORKLOAD_PORTABLE_INDEX")

EXECUTED_TOTAL=0

# run_engine <label> <report-name> <args...>
#
# A lane that executed nothing must exit non-zero rather than 0, so the count of
# executed units is read back out of each engine's own report and accumulated. An
# engine that ran and did nothing is a failure, not a pass.
run_engine() {
    local label="$1" name="$2"; shift 2
    local report="$OUT/$name.json" log="$OUT/$name.log" rc
    "${EXPLORE[@]}" --out "$report" "$@" >"$log" 2>&1
    rc=$?
    local executed=0 headline=""
    if [[ -f "$report" ]]; then
        executed="$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(int((d.get("meta") or {}).get("executed") or 0))
except Exception:
    print(0)
' "$report")"
        headline="$(python3 -c '
import json, sys
try:
    print((json.load(open(sys.argv[1])).get("meta") or {}).get("headline") or "")
except Exception:
    print("")
' "$report")"
    fi
    EXECUTED_TOTAL=$((EXECUTED_TOTAL + executed))
    if [[ "$executed" -eq 0 ]]; then
        fail "$label executed nothing" \
             "an engine that ran and exercised nothing is a failure, not a pass" \
             "$(tail -12 "$log")"
        return
    fi
    if [[ $rc -eq 0 ]]; then
        pass "$label — $headline"
    else
        fail "$label — $headline" "$(grep -E '^  (FAIL|INCONSISTENT|GAP)' "$log" | head -20)" \
             "full log: $log"
    fi
    # Gaps and NOTEs are neither pass nor fail, and must not vanish into either.
    # The NOTEs are where the findings live — the exit codes a calling script
    # cannot tell apart, the lifecycle verb the CLI does not have. An engine that
    # discovers something and reports PASS without saying what it discovered has
    # thrown the result away.
    while IFS= read -r line; do
        [[ -n "$line" ]] && note "$line"
    done < <(grep -E '^  (GAP|NOTE|SKIP) ' "$log" | head -24)
    while IFS= read -r line; do
        [[ -n "$line" ]] && note "$line"
    done < <(grep -E '^        ' "$log" | grep -E 'exits|indistinguishable' | head -8)
}

mkdir -p "$OUT"

# ------------------------------------------------------------------ 0. cost #
# Measured first, and printed, because everything below is sized against it and
# because a number nobody measured is the fastest way to a wrong conclusion.
note "measuring per-operation cost before sizing anything"
"${EXPLORE[@]}" --out "$OUT/cost.json" cost --samples 5 >"$OUT/cost.log" 2>&1
if [[ -f "$OUT/cost.json" ]]; then
    while IFS= read -r line; do note "$line"; done < <(
        grep -E '^  (install|run|repair|doctor|remove|verify|rollback) ' "$OUT/cost.log" | head -8)
    pass "per-operation cost measured (see $OUT/cost.log)"
else
    blocked "could not measure operation cost" "$(tail -5 "$OUT/cost.log")"
fi

# ----------------------------------------------------- 1. pairwise sampling #
SAMPLE_ARGS=(sample --seed "$SEED" --order "$ORDER")
[[ "$CASES" -gt 0 ]] && SAMPLE_ARGS+=(--cases "$CASES")
run_engine "cross-product sampler (${ORDER}-way, seed $SEED)" sample "${SAMPLE_ARGS[@]}"

# ------------------------------------------------- 2. model-based lifecycle #
run_engine "abstract lifecycle model, $SEQ sequences (seed $SEED)" model \
    model --seed "$SEED" --sequences "$SEQ" --max-len 14 --illegal-bias 0.5 \
    --minimise 3

# ---------------------------------------------------- 3. concurrent schedules #
RACE_ARGS=(race --repeats "$REPEATS")
[[ -n "$PRESSURE" ]] && RACE_ARGS+=("$PRESSURE")
run_engine "concurrent schedules, $REPEATS repeats" race "${RACE_ARGS[@]}"

# ------------------------------------------------------------------ closing #
note "seed $SEED reproduces this run exactly:"
note "  LEXE_EXPLORE_SEED=$SEED tests/workloads/against_lexe_matrix.sh"
note "executed $EXECUTED_TOTAL units across the engines"

acc_summary
rc=$?
if [[ "$EXECUTED_TOTAL" -eq 0 ]]; then
    printf '  the lane executed nothing at all; a lane that exercised nothing\n'
    printf '  must never report success\n'
    exit 3
fi
exit $rc

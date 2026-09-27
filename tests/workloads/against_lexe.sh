#!/usr/bin/env bash
# tests/workloads/against_lexe.sh — the workload lane.
#
# This is the lane that takes the two workload corpora — 112 Linux ELF specimens
# and 72 Windows PE specimens, all of them legitimate programs that `.LEXE` did
# not write and does not know about — packages every one of them as a `.lexe`,
# installs it, runs it under the runtime, and compares what happened against the
# DIRECT-EXECUTION baseline the corpus recorded before `.LEXE` was involved.
#
# Why that baseline is the whole point: when a program misbehaves under `.LEXE`,
# the baseline is what makes the finding attributable. Without it, "the program
# printed nothing" is indistinguishable from "the fixture prints nothing".
#
# The oracle — what divergence is forgiven and what is demanded — is documented
# at the top of against_lexe.py, and every forgiven divergence is an entry in
# against_lexe_expected_<corpus>.json carrying a reason and a citation. The
# engine refuses to load an entry that has neither.
#
# BLOCKED is not FAIL and is never PASS. A corpus that has not been generated, a
# specimen whose binary no longer matches its recorded baseline, an absent
# toolchain or an absent translation layer all produce BLOCKED with the reason.
# An unexecuted specimen is not coverage in either direction.
#
# EVIDENCE NOTE. `source_fingerprint()` in scripts/test.sh currently PRUNES
# `tests/workloads/`, on the stated grounds that no lane runs the specimens. This
# lane does. Until that prune is narrowed, a scripts/test.sh run including this
# lane fingerprints less than it appears to. The engine compensates for the
# corpus half — it re-hashes the generator and every specimen binary against what
# index.json recorded, and refuses to run on drift — but it cannot honestly
# fingerprint itself. See the EVIDENCE PROVENANCE section of against_lexe.py.
#
# Usage:
#   tests/workloads/against_lexe.sh                 both corpora, as available
#   tests/workloads/against_lexe.sh elf             one corpus
#   tests/workloads/against_lexe.sh pe
#   LEXE_WORKLOAD_PE_CHAIN=proton tests/workloads/against_lexe.sh pe
#
# Environment:
#   LEXE_BUILD_DIR          where the runtime is (default <repo>/build-linux)
#   LEXE_WORKLOAD_ELF_INDEX default /tmp/lexe-workloads/index.json
#   LEXE_WORKLOAD_PE_INDEX  default /tmp/lexe-workloads-pe/index.json
#   LEXE_WORKLOAD_PE_CHAIN  wine (default) or proton; the baseline layer is
#                           chosen to match (wine -> `wine`, proton ->
#                           `proton-wine`, which is Proton's own Wine binary and
#                           the only Proton cell the corpus could baseline)
#   LEXE_WORKLOAD_JOBS      parallel workers (default 6)
set -uo pipefail
WL_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$WL_DIR/../acceptance/lib.sh"

acc_begin "workloads: 184 foreign programs through .LEXE"

# ---------------------------------------------------------------- finishing up #

# Every exit from this lane goes through here. There are five exit sites, and the
# first attempt at this fix patched only the last one -- so the runtime-missing
# path still returned 0 having executed nothing, which is the very defect the fix
# was for. Found by running the patched lane, not by reading it.
#
# BLOCKED stays distinct from FAIL: an unexecuted specimen is not a failure and
# never will be (docs/TESTING.md, and the house rule in acceptance/lib.sh). But
# "this lane produced no evidence" is a third outcome, and reporting it as success
# is how a green suite comes to mean nothing. This session produced five separate
# instances of that one shape -- a fingerprint that hashed nothing, an acceptance
# glob that stopped at 09, this lane going unregistered while its inputs were
# fingerprinted, these five exit sites, and a shared output path that overwrote
# another run's artifact. Every one of them reported success over something it had
# not done.
wl_finish() {
    acc_summary
    local rc=$?
    if [[ $ACC_PASS -eq 0 && $ACC_FAIL -eq 0 ]]; then
        printf '  %sno evidence:%s this lane executed no specimens, so it proves nothing\n' \
            "$ACC_BLUE" "$ACC_OFF"
        printf '       %d prerequisite(s) were unavailable; the reasons are above\n' \
            "$ACC_BLOCKED"
        exit 2
    fi
    exit $rc
}

ENGINE="$WL_DIR/against_lexe.py"
WL_RUN_ID="$$-$(date -u +%Y%m%dT%H%M%SZ)"
LEXE_BIN="${LEXE_BUILD_DIR:-$ACC_REPO/build-linux}/lexe"
JOBS="${LEXE_WORKLOAD_JOBS:-6}"
ELF_INDEX="${LEXE_WORKLOAD_ELF_INDEX:-/tmp/lexe-workloads/index.json}"
PE_INDEX="${LEXE_WORKLOAD_PE_INDEX:-/tmp/lexe-workloads-pe/index.json}"
PE_CHAIN="${LEXE_WORKLOAD_PE_CHAIN:-wine}"
case "$PE_CHAIN" in
    wine)   PE_LAYER=wine ;;
    proton) PE_LAYER=proton-wine ;;
    *)      fail "LEXE_WORKLOAD_PE_CHAIN must be wine or proton, not $PE_CHAIN"
            wl_finish ;;
esac

WANT=("$@")
[[ ${#WANT[@]} -eq 0 ]] && WANT=(elf pe)

PY=""
for candidate in python3 python; do
    command -v "$candidate" >/dev/null 2>&1 && { PY="$candidate"; break; }
done
[[ -n "$PY" ]] || { blocked "no python3: the comparison engine cannot run"; wl_finish; }
[[ -f "$ENGINE" ]] || { fail "engine missing: $ENGINE"; wl_finish; }
[[ -x "$LEXE_BIN" ]] || {
    blocked "the runtime is not built at $LEXE_BIN" \
            "build it with scripts/build.sh, then re-run this lane"
    wl_finish
}

# --------------------------------------------------------------------------- #

run_corpus() {   # $1 corpus  $2 index  $3 extra description  rest: engine args
    local corpus="$1" index="$2" desc="$3"; shift 3
    # Unique per invocation. A stable path is convenient right up to the
    # moment two runs overlap, at which point the second silently destroys
    # the first's evidence -- which happened twice in one session, once to
    # another role's in-flight regression run. It was noticed only because
    # results.json records the runtime hash and the corpus provenance, which
    # is the argument for recording them.
    local out="/tmp/lexe-vs-workloads-lane-$corpus.$WL_RUN_ID"
    local log="$out.log"

    if [[ ! -f "$index" ]]; then
        local gen="generate.py"
        [[ "$corpus" == "pe" ]] && gen="generate_pe.py"
        blocked "$corpus corpus not generated ($index absent)" \
                "regenerate: python3 tests/workloads/$gen" \
                "the specimens are a pure function of the generator and are never committed"
        return
    fi

    note "$corpus: $desc"
    "$PY" "$ENGINE" --corpus "$corpus" --index "$index" --lexe "$LEXE_BIN" \
          --out "$out" --jobs "$JOBS" "$@" >"$log" 2>&1
    local rc=$?
    local res="$out/results.json"
    if [[ ! -f "$res" ]]; then
        fail "$corpus: the engine did not produce results.json (exit $rc)" \
             "$(tail -n 12 "$log")"
        return
    fi

    # The engine's own numbers, read back rather than re-counted here.
    local line
    line="$("$PY" - "$res" <<'PYEOF'
import json, sys
s = json.load(open(sys.argv[1]))["summary"]
print(s["executed"], s["pass"], s["fail"], s["blocked"],
      len(s.get("fail_stream_delivery_only") or []),
      s["specimens_in_corpus"], s["wall_seconds"],
      "drift" if s["corpus_provenance"]["matches"] is False else "pinned",
      s.get("expectations_sha256") or "none")
PYEOF
)"
    read -r n_exec n_pass n_fail n_block n_sd n_corpus secs prov expect <<<"$line"

    note "$corpus: $n_exec of $n_corpus executed in ${secs}s, corpus $prov"
    # Surfaced beside the corpus provenance, because with no expectations
    # file the lane reports every INTENDED divergence as a failure -- twelve
    # of them, confident-looking, with the cause named only in a side log.
    if [[ "$expect" == "none" ]]; then
        note "$corpus: NO expectations file was loaded, so every intended divergence will be reported as a failure"
    else
        note "$corpus: expectations ${expect:0:12}"
    fi
    [[ "$prov" == "pinned" ]] || fail "$corpus: the corpus does not match the committed generator"

    if [[ "$n_block" -gt 0 ]]; then
        while IFS= read -r b; do blocked "$corpus: $b"; done < <(
            "$PY" - "$res" <<'PYEOF'
import json, sys
for r in json.load(open(sys.argv[1]))["results"]:
    if r["status"] == "BLOCKED":
        print(f"{r['id']}: {r.get('reason')}")
PYEOF
        )
    fi

    # Reported whatever the failures are, because "93 of 112 programs behave
    # exactly as they do outside .LEXE" is a result, and a summary that shows
    # only the failures makes the lane look like it proved nothing.
    if [[ "$n_pass" -gt 0 ]]; then
        pass "$corpus: $n_pass of $n_exec executed specimens match their direct-execution baseline, or diverge only in a classified way"
    fi
    # Where the evidence is, on every outcome and not only on failure. A passing
    # run is evidence too, and the record carries the runtime hash, the corpus
    # provenance and the expectations hash -- which is what let a clobbered
    # artifact be spotted at all.
    note "$corpus: full record in $res, engine log in $log"

    if [[ "$n_fail" -eq 0 ]]; then
        return
    fi

    while IFS= read -r f; do
        fail "$corpus: $f"
    done < <(
        "$PY" - "$res" <<'PYEOF'
import json, sys
for r in json.load(open(sys.argv[1]))["results"]:
    if r["status"] != "FAIL":
        continue
    if r.get("sole_divergence") == "stream-delivery":
        continue
    bits = [f"{d['kind']}:{d['key']}" for d in r.get("divergences", [])
            if not d["classified"]]
    if r.get("phase") == "install":
        bits = ["install refused: " + (r.get("detail") or "").strip().split("\n")[0]]
    print(f"{r['id']} — {', '.join(bits[:6])}")
PYEOF
    )
    if [[ "$n_sd" -gt 0 ]]; then
        fail "$corpus: $n_sd specimens ran correctly but the runtime did not deliver their output to the caller" \
             "$("$PY" - "$res" <<'PYEOF'
import json, sys
s = json.load(open(sys.argv[1]))["summary"]
ids = s.get("fail_stream_delivery_only") or []
print("   " + ", ".join(ids))
PYEOF
)"
    fi
}

for corpus in "${WANT[@]}"; do
    case "$corpus" in
        elf)
            run_corpus elf "$ELF_INDEX" \
                "native x86_64 ELF specimens, sandboxed native launch, no permissions granted"
            ;;
        pe)
            if ! command -v wine >/dev/null 2>&1; then
                blocked "pe: wine is not installed on this host" \
                        "every PE specimen needs a foreign-OS execution chain; without one" \
                        "none of them can run, and an unexecuted specimen is not coverage"
                continue
            fi
            run_corpus pe "$PE_INDEX" \
                "Windows PE specimens through the $PE_CHAIN chain, compared with the $PE_LAYER baseline" \
                --chain "$PE_CHAIN" --layer "$PE_LAYER"
            ;;
        *)
            fail "unknown corpus: $corpus (expected elf or pe)"
            ;;
    esac
done

wl_finish

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

ENGINE="$WL_DIR/against_lexe.py"
LEXE_BIN="${LEXE_BUILD_DIR:-$ACC_REPO/build-linux}/lexe"
JOBS="${LEXE_WORKLOAD_JOBS:-6}"
ELF_INDEX="${LEXE_WORKLOAD_ELF_INDEX:-/tmp/lexe-workloads/index.json}"
PE_INDEX="${LEXE_WORKLOAD_PE_INDEX:-/tmp/lexe-workloads-pe/index.json}"
PE_CHAIN="${LEXE_WORKLOAD_PE_CHAIN:-wine}"
case "$PE_CHAIN" in
    wine)   PE_LAYER=wine ;;
    proton) PE_LAYER=proton-wine ;;
    *)      fail "LEXE_WORKLOAD_PE_CHAIN must be wine or proton, not $PE_CHAIN"
            acc_summary; exit $? ;;
esac

WANT=("$@")
[[ ${#WANT[@]} -eq 0 ]] && WANT=(elf pe)

PY=""
for candidate in python3 python; do
    command -v "$candidate" >/dev/null 2>&1 && { PY="$candidate"; break; }
done
[[ -n "$PY" ]] || { blocked "no python3: the comparison engine cannot run"; acc_summary; exit $?; }
[[ -f "$ENGINE" ]] || { fail "engine missing: $ENGINE"; acc_summary; exit $?; }
[[ -x "$LEXE_BIN" ]] || {
    blocked "the runtime is not built at $LEXE_BIN" \
            "build it with scripts/build.sh, then re-run this lane"
    acc_summary; exit $?
}

# --------------------------------------------------------------------------- #

run_corpus() {   # $1 corpus  $2 index  $3 extra description  rest: engine args
    local corpus="$1" index="$2" desc="$3"; shift 3
    local out="/tmp/lexe-vs-workloads-lane-$corpus"
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
      "drift" if s["corpus_provenance"]["matches"] is False else "pinned")
PYEOF
)"
    read -r n_exec n_pass n_fail n_block n_sd n_corpus secs prov <<<"$line"

    note "$corpus: $n_exec of $n_corpus executed in ${secs}s, corpus $prov"
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
    note "$corpus: full record in $res, engine log in $log"
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

acc_summary
exit $?

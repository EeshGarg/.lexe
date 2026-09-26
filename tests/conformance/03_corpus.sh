#!/usr/bin/env bash
# tests/conformance/03_corpus.sh — the systematic differential corpus.
#
# `corpus.py` generates a package per rule of FORMAT-0.1 together with
# `index.json`, which records for each case its rule, its expected verdict, and
# why. This lane drives BOTH implementations over every case and checks two
# independent things:
#
#   1. each implementation's verdict matches the SPEC's expectation;
#   2. the two implementations agree with each other.
#
# Both matter, and neither subsumes the other. (1) alone would let a shared
# misreading pass; (2) alone cannot tell a correct pair from a pair that is
# identically wrong. A case marked `expect: unspecified` is one the frozen spec
# does not determine: there (2) is still checked and (1) is deliberately not,
# because asserting a verdict the document does not require would be inventing
# format policy in a test.
#
# A disagreement is a FAIL and is never resolved in favour of the C++ — see
# 01_differential.sh for why that direction matters.
#
# The corpus is GENERATED, never committed: it is a pure function of corpus.py,
# so there are no binary fixtures in the tree to drift out of date.
set -uo pipefail
CONF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$CONF_DIR/../acceptance/lib.sh"

acc_begin "conformance 03 systematic corpus"
acc_require_binaries

VALIDATOR="$ACC_REPO/tools/lexe-conformance/lexe_conformance.py"
GENERATOR="$CONF_DIR/corpus.py"
[[ -f "$VALIDATOR" ]] || { fail "validator missing: $VALIDATOR"; acc_summary; exit $?; }
[[ -f "$GENERATOR" ]] || { fail "generator missing: $GENERATOR"; acc_summary; exit $?; }

PY=""
for candidate in python3 python; do
    command -v "$candidate" >/dev/null 2>&1 && { PY="$candidate"; break; }
done
[[ -n "$PY" ]] || { skip "no python3"; acc_summary; exit $?; }

# The generator SIGNS every case, so it needs an Ed25519 backend. The validator
# uses the same module, which is why this lane has no "signature defect could
# not be compared" caveat: if the corpus exists at all, both sides can check
# signatures.
if ! "$PY" -c "import cryptography" >/dev/null 2>&1; then
    skip "no python cryptography module: the corpus cannot be signed, and an"
    note "unsigned corpus would test nothing. Install it to run this lane."
    acc_summary
    exit $?
fi

acc_scratch_home
CORPUS="$ACC_ROOT/work/corpus"
LARGE=()
[[ "${LEXE_CORPUS_LARGE:-0}" == "1" ]] && LARGE=(--include-large)

note "generating the corpus from docs/FORMAT-0.1.md rules"
if ! "$PY" "$GENERATOR" "$CORPUS" "${LARGE[@]}" 2>"$ACC_ROOT/work/gen.log"; then
    fail "the corpus generator failed" "$(sed -n '1,20p' "$ACC_ROOT/work/gen.log")"
    acc_summary
    exit $?
fi
note "$(sed -n '1p' "$ACC_ROOT/work/gen.log")"
[[ "${#LARGE[@]}" -gt 0 ]] || note "large budget cases skipped (LEXE_CORPUS_LARGE=1 to include)"

# Emit "name<TAB>file<TAB>rule<TAB>expect" per case.
mapfile -t ROWS < <("$PY" - "$CORPUS/index.json" <<'PYEOF'
import json, sys
doc = json.load(open(sys.argv[1]))
for c in doc["cases"]:
    print("\t".join([c["name"], c["file"], c["rule"], c["expect"]]))
PYEOF
)
[[ ${#ROWS[@]} -gt 0 ]] || { fail "the corpus index is empty"; acc_summary; exit $?; }

disagreements=0
spec_misses=0
unspecified_seen=0

for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r name file rule expect <<<"$row"
    pkg="$CORPUS/$file"

    "$LEXE" verify "$pkg" >"$ACC_ROOT/work/lexe.txt" 2>&1
    lexe_rc=$?
    conf_out="$("$PY" "$VALIDATOR" --json "$pkg" 2>&1)"
    conf_rc=$?

    # The validator's exit 2 means "could not read it at all", which is a
    # rejection for this purpose: both tools refusing a file is agreement,
    # whatever each calls it.
    [[ $lexe_rc -eq 0 ]] && lexe_v=accept || lexe_v=reject
    [[ $conf_rc -eq 0 ]] && conf_v=accept || conf_v=reject

    if [[ "$lexe_v" != "$conf_v" ]]; then
        disagreements=$((disagreements + 1))
        fail "$name [$rule] — DISAGREEMENT" \
            "expected per spec: $expect" \
            "lexe verify: $lexe_v (exit $lexe_rc)" \
            "$(sed -n '1,6p' "$ACC_ROOT/work/lexe.txt")" \
            "validator:   $conf_v (exit $conf_rc)" \
            "$(printf '%s' "$conf_out" | sed -n '1,12p')"
        continue
    fi

    if [[ "$expect" == "unspecified" ]]; then
        unspecified_seen=$((unspecified_seen + 1))
        pass "$name [$rule] — both $lexe_v (spec does not determine this)"
        continue
    fi

    if [[ "$lexe_v" == "$expect" ]]; then
        pass "$name [$rule] — both $lexe_v"
    else
        spec_misses=$((spec_misses + 1))
        fail "$name [$rule] — BOTH WRONG vs the spec" \
            "expected $expect, both said $lexe_v" \
            "$(sed -n '1,6p' "$ACC_ROOT/work/lexe.txt")"
    fi
done

note ""
note "corpus: ${#ROWS[@]} cases"
note "  disagreements between implementations: $disagreements"
note "  cases where both differ from the spec: $spec_misses"
note "  cases the spec does not determine:     $unspecified_seen"

acc_summary

#!/usr/bin/env bash
# tests/conformance/04_update_corpus.sh — the `update.json` corpus (FORMAT-0.1 §7).
#
# `update_corpus.py` emits one signed update document per rule of §7, plus the
# packages the apply-mode cases point at. This lane installs the base
# application once, then for each case drops that case's document at the fixed
# path the base package's signed manifest points at and runs either
# `lexe update --check` (checks 1,2,3,7 — no download) or `lexe update`
# (also 4,5,6), comparing the outcome against what §7 requires.
#
# UNLIKE 01/03 THIS LANE IS NOT DIFFERENTIAL. tools/lexe-conformance validates
# packages and has no update.json mode, so there is no independent reader to
# compare against; what is compared is the runtime against a reading of §7
# written from the document. A failure here is therefore either a runtime defect
# or a defect in that reading, and has to be argued rather than settled by two
# tools agreeing. Cases §7 does not determine are `unspecified` and assert
# nothing — their outcome is recorded so a later decision has the evidence.
#
# The corpus is GENERATED, never committed.
set -uo pipefail
CONF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$CONF_DIR/../acceptance/lib.sh"

acc_begin "conformance 04 update.json corpus"
acc_require_binaries

GEN="$CONF_DIR/update_corpus.py"
[[ -f "$GEN" ]] || { fail "generator missing: $GEN"; acc_summary; exit $?; }

PY=""
for candidate in python3 python; do
    command -v "$candidate" >/dev/null 2>&1 && { PY="$candidate"; break; }
done
[[ -n "$PY" ]] || { skip "no python3"; acc_summary; exit $?; }
if ! "$PY" -c "import cryptography" >/dev/null 2>&1; then
    skip "no python cryptography module: update documents cannot be signed"
    acc_summary
    exit $?
fi

acc_scratch_home
CORPUS="$ACC_ROOT/work/updcorpus"

note "generating the update corpus from §7 / §7.0 / §7.1 / §5.0 / §8 / §10.1"
if ! "$PY" "$GEN" "$CORPUS" 2>"$ACC_ROOT/work/updgen.log"; then
    fail "the update corpus generator failed" \
        "$(sed -n '1,20p' "$ACC_ROOT/work/updgen.log")"
    acc_summary
    exit $?
fi
note "$(sed -n '1p' "$ACC_ROOT/work/updgen.log")"

APP_ID="$("$PY" -c "import json,sys;print(json.load(open(sys.argv[1]))['app_id'])" \
    "$CORPUS/index.json")"
SERVE="$("$PY" -c "import json,sys;print(json.load(open(sys.argv[1]))['serve'])" \
    "$CORPUS/index.json")"
BASE="$("$PY" -c "import json,sys;print(json.load(open(sys.argv[1]))['base'])" \
    "$CORPUS/index.json")"

mapfile -t ROWS < <("$PY" - "$CORPUS/index.json" <<'PYEOF'
import json, sys
for c in json.load(open(sys.argv[1]))["cases"]:
    print("\t".join([c["name"], c["rule"], c["expect"], c["mode"]]))
PYEOF
)
[[ ${#ROWS[@]} -gt 0 ]] || { fail "the update corpus index is empty"; acc_summary; exit $?; }

# One fresh installation per case: an applied update would change the installed
# version and silently alter what every later case is compared against.
install_base() {
    rm -rf "$LEXE_HOME/apps" "$LEXE_HOME/state" 2>/dev/null
    "$LEXE" install "$BASE" --yes >"$ACC_ROOT/work/install.txt" 2>&1
}

unspecified=0
for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r name rule expect mode <<<"$row"

    install_base || { fail "$name [$rule] — the base package would not install" \
        "$(sed -n '1,6p' "$ACC_ROOT/work/install.txt")"; continue; }

    cp "$CORPUS/cases/$name/update.json" "$SERVE/update.json"
    rm -f "$SERVE/update.json.sig"
    [[ -f "$CORPUS/cases/$name/update.json.sig" ]] && \
        cp "$CORPUS/cases/$name/update.json.sig" "$SERVE/update.json.sig"

    if [[ "$mode" == "apply" ]]; then
        timeout 90 "$LEXE" update "$APP_ID" >"$ACC_ROOT/work/upd.txt" 2>&1
    else
        timeout 60 "$LEXE" update "$APP_ID" --check >"$ACC_ROOT/work/upd.txt" 2>&1
    fi
    rc=$?
    out="$(cat "$ACC_ROOT/work/upd.txt")"

    # Classify. rc != 0 is a refusal. rc == 0 is either an acceptance or a
    # "nothing newer" report, and those are different outcomes under §7 check 7,
    # so the wording has to be consulted to tell them apart.
    if [[ $rc -eq 124 ]]; then
        verdict=timeout
    elif [[ $rc -ne 0 ]]; then
        verdict=reject
    elif printf '%s' "$out" | grep -qiE 'no newer|offers no newer|already|up to date|which is OLDER than'; then
        # "which is OLDER than" is the report for a source advertising a version
        # below the installed one. It was added because §7.1 forbids describing
        # that state as "up to date": it is the one externally visible symptom of
        # the freeze attack §7.1 documents as undefended, and it used to be
        # indistinguishable from the healthy case. Still `no-update` -- nothing
        # was applied -- but now distinguishable in the output, which is the
        # point.
        verdict=no-update
    else
        verdict=accept
    fi

    if [[ "$expect" == "unspecified" ]]; then
        unspecified=$((unspecified + 1))
        pass "$name [$rule] — $verdict (§7 does not determine this)"
        note "    $(printf '%s' "$out" | sed -n '1p' | cut -c1-96)"
        continue
    fi

    if [[ "$verdict" == "$expect" ]]; then
        pass "$name [$rule] — $verdict"
    else
        fail "$name [$rule]" \
            "expected $expect, got $verdict (exit $rc)" \
            "$(printf '%s' "$out" | sed -n '1,6p')"
    fi
done

note ""
note "update corpus: ${#ROWS[@]} cases, $unspecified undetermined by §7"

acc_summary

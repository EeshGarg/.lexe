#!/usr/bin/env bash
# tests/evidence/run_all.sh — the evidence-integrity lane.
#
#   ./scripts/test.sh --evidence
#   bash tests/evidence/run_all.sh [01 ...]
#
# Tests the machinery this project uses to decide whether a test run may be
# CITED, rather than testing the product. It is a lane because the alternative
# is trusting that machinery, and it has been wrong before: a fingerprint that
# hashed nothing at all approved every run it saw.
#
# Deliberately cheap and dependency-free — no build, no packages, no LEXE_HOME —
# so it can run first and always.
set -uo pipefail
EV_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

scripts=()
if [[ $# -gt 0 ]]; then
    for want in "$@"; do
        for candidate in "$EV_DIR/${want}"*.sh; do
            [[ -f "$candidate" ]] && scripts+=("$candidate")
        done
    done
else
    for candidate in "$EV_DIR"/[0-9]*.sh; do
        [[ -f "$candidate" ]] && scripts+=("$candidate")
    done
fi

if [[ ${#scripts[@]} -eq 0 ]]; then
    printf 'no evidence scripts matched\n' >&2
    exit 2
fi

printf '.LEXE evidence-integrity lane\n\n'

names=(); results=(); failed=0
for script in "${scripts[@]}"; do
    name="$(basename "$script" .sh)"
    names+=("$name")
    if bash "$script"; then results+=("ok"); else results+=("FAILED"); failed=$((failed + 1)); fi
    printf '\n'
done

printf '== evidence summary ==\n'
total_pass=0
for i in "${!names[@]}"; do
    if [[ "${results[$i]}" == "ok" ]]; then
        printf '    ok    %s\n' "${names[$i]}"
        total_pass=$((total_pass + 1))
    else
        printf '    FAIL  %s\n' "${names[$i]}"
    fi
done
printf '\n  %d passed, %d failed\n' "$total_pass" "$failed"
exit $(( failed > 0 ? 1 : 0 ))

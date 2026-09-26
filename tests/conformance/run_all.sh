#!/usr/bin/env bash
# tests/conformance/run_all.sh — the differential conformance lane.
#
#   ./scripts/test.sh --conformance
#   bash tests/conformance/run_all.sh [01 ...]
#
# Runs `lexe verify` and the independent validator in tools/lexe-conformance
# over the same packages and compares their verdicts. A disagreement FAILS the
# lane rather than being resolved in favour of the C++ -- see 01_differential.sh
# for why that direction matters.
set -uo pipefail
CONF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$CONF_DIR/../acceptance/lib.sh"
acc_require_binaries

scripts=()
if [[ $# -gt 0 ]]; then
    for want in "$@"; do
        for candidate in "$CONF_DIR/${want}"*.sh; do
            [[ -f "$candidate" ]] && scripts+=("$candidate")
        done
    done
else
    for candidate in "$CONF_DIR"/[0-9]*.sh; do
        [[ -f "$candidate" ]] && scripts+=("$candidate")
    done
fi

if [[ ${#scripts[@]} -eq 0 ]]; then
    printf 'no conformance scripts matched\n' >&2
    exit 2
fi

printf '%s.LEXE conformance lane%s\n' "$ACC_BOLD" "$ACC_OFF"
printf '  runtime: %s\n\n' "$LEXE"

names=(); results=(); failed=0
for script in "${scripts[@]}"; do
    name="$(basename "$script" .sh)"
    names+=("$name")
    if bash "$script"; then results+=("ok"); else results+=("FAILED"); failed=$((failed + 1)); fi
    printf '\n'
done

printf '%s== conformance summary ==%s\n' "$ACC_BOLD" "$ACC_OFF"
total_pass=0
for i in "${!names[@]}"; do
    if [[ "${results[$i]}" == "ok" ]]; then
        printf '  %s  ok    %s%s\n' "$ACC_GREEN" "${names[$i]}" "$ACC_OFF"
        total_pass=$((total_pass + 1))
    else
        printf '  %s  FAIL  %s%s\n' "$ACC_RED" "${names[$i]}" "$ACC_OFF"
    fi
done
printf '\n  %d passed, %d failed\n' "$total_pass" "$failed"
exit $(( failed > 0 ? 1 : 0 ))

#!/usr/bin/env bash
# tests/concurrency/run_all.sh — the concurrency lane.
#
#   ./scripts/test.sh --concurrency
#   bash tests/concurrency/run_all.sh [01 02 ...]
#
# Simultaneous operations, as opposed to the lifecycle lane's interrupted ones.
# Every participant runs under a hard timeout so a deadlock FAILS the suite
# instead of hanging it — "the suite never finished" is the one symptom a
# concurrency test must never produce.
set -uo pipefail
CONC_DIR_SELF="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$CONC_DIR_SELF/../acceptance/lib.sh"
acc_require_binaries

scripts=()
if [[ $# -gt 0 ]]; then
    for want in "$@"; do
        for candidate in "$CONC_DIR_SELF/${want}"*.sh; do
            [[ -f "$candidate" ]] && scripts+=("$candidate")
        done
    done
else
    for candidate in "$CONC_DIR_SELF"/[0-9]*.sh; do
        [[ -f "$candidate" ]] && scripts+=("$candidate")
    done
fi
[[ ${#scripts[@]} -eq 0 ]] && { printf 'no concurrency scripts matched\n' >&2; exit 2; }

printf '%s.LEXE concurrency lane%s\n' "$ACC_BOLD" "$ACC_OFF"
printf '  runtime: %s\n\n' "$LEXE"

names=(); results=(); failed=0
for script in "${scripts[@]}"; do
    name="$(basename "$script" .sh)"; names+=("$name")
    if bash "$script"; then results+=("ok"); else results+=("FAILED"); failed=$((failed+1)); fi
    printf '\n'
done

printf '%s== concurrency summary ==%s\n' "$ACC_BOLD" "$ACC_OFF"
passed=0
for i in "${!names[@]}"; do
    if [[ "${results[$i]}" == "ok" ]]; then
        printf '  %s  ok    %s%s\n' "$ACC_GREEN" "${names[$i]}" "$ACC_OFF"; passed=$((passed+1))
    else
        printf '  %s  FAIL  %s%s\n' "$ACC_RED" "${names[$i]}" "$ACC_OFF"
    fi
done
printf '\n  %d passed, %d failed\n' "$passed" "$failed"
exit $(( failed > 0 ? 1 : 0 ))

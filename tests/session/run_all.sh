#!/usr/bin/env bash
# tests/session/run_all.sh — the session-manager lane.
#
#   ./scripts/test.sh --session
#   bash tests/session/run_all.sh [01 ...]
#
# Talks to the REAL `systemd --user` of the invoking session. See lib.sh for why
# nothing here is mocked and why it skips rather than blocks on a host with no
# session manager.
set -uo pipefail
SESS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SESS_DIR/../acceptance/lib.sh"
acc_require_binaries

scripts=()
if [[ $# -gt 0 ]]; then
    for want in "$@"; do
        for candidate in "$SESS_DIR/${want}"*.sh; do
            [[ -f "$candidate" ]] && scripts+=("$candidate")
        done
    done
else
    for candidate in "$SESS_DIR"/[0-9]*.sh; do
        [[ -f "$candidate" ]] && scripts+=("$candidate")
    done
fi

if [[ ${#scripts[@]} -eq 0 ]]; then
    printf 'no session scripts matched\n' >&2
    exit 2
fi

printf '%s.LEXE session lane%s\n' "$ACC_BOLD" "$ACC_OFF"
printf '  runtime: %s\n\n' "$LEXE"

names=(); results=(); failed=0
for script in "${scripts[@]}"; do
    name="$(basename "$script" .sh)"
    names+=("$name")
    if bash "$script"; then results+=("ok"); else results+=("FAILED"); failed=$((failed + 1)); fi
    printf '\n'
done

printf '%s== session summary ==%s\n' "$ACC_BOLD" "$ACC_OFF"
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

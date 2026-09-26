#!/usr/bin/env bash
# tests/lifecycle/run_all.sh — the lifecycle lane.
#
#   ./scripts/test.sh --lifecycle
#   bash tests/lifecycle/run_all.sh [01 03 ...]
#
# Two halves, in order:
#
#   1. the ORDINARY path, end to end and in sequence:
#        install -> run -> update -> run -> rollback -> run -> repair -> run
#        -> uninstall
#      Each step is checked for its own result AND for what it left behind, since
#      "it worked" and "it left the installation coherent" are different claims.
#
#   2. the same operations INTERRUPTED on purpose: killed mid-install, killed
#      mid-update, killed mid-compile, corrupted payload, corrupted build
#      attestation, deleted files, missing runtime, application running during
#      update, stale lease.
#
# The invariant under test throughout is the transactional one:
#
#     A failed .LEXE operation leaves either the previous valid state or the new
#     valid state — never an ambiguous, partially applied one.
#
# "Valid" is checked by consequence rather than by inspecting internals: after
# any interrupted operation, `lexe apps` must agree with what is on disk, the
# application must either launch or be absent, and `lexe repair` (or a re-run of
# the interrupted operation) must be able to finish the job.
set -uo pipefail
LC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$LC_DIR/../acceptance/lib.sh"
# The runner prints which binary it is about to drive, so it needs LEXE resolved.
# Each script calls this for itself too; it is idempotent.
acc_require_binaries

scripts=()
if [[ $# -gt 0 ]]; then
    for want in "$@"; do
        for candidate in "$LC_DIR/${want}"*.sh; do
            [[ -f "$candidate" ]] && scripts+=("$candidate")
        done
    done
else
    for candidate in "$LC_DIR"/[0-9]*.sh; do
        [[ -f "$candidate" ]] && scripts+=("$candidate")
    done
fi

if [[ ${#scripts[@]} -eq 0 ]]; then
    printf 'no lifecycle scripts matched\n' >&2
    exit 2
fi

printf '%s.LEXE lifecycle lane%s\n' "$ACC_BOLD" "$ACC_OFF"
printf '  runtime: %s\n\n' "$LEXE"

names=(); results=(); failed=0
for script in "${scripts[@]}"; do
    name="$(basename "$script" .sh)"
    names+=("$name")
    if bash "$script"; then results+=("ok"); else results+=("FAILED"); failed=$((failed + 1)); fi
    printf '\n'
done

printf '%s== lifecycle summary ==%s\n' "$ACC_BOLD" "$ACC_OFF"
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

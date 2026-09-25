#!/usr/bin/env bash
# run_all.sh — the automated part of the .LEXE acceptance criteria.
#
#   ./tests/acceptance/run_all.sh              run 01..04
#   ./tests/acceptance/run_all.sh 01 03        run only those
#
# Each script works against its own throwaway LEXE_HOME; the user's real
# ~/.local/share/lexe is never read or written. The parts that genuinely need a
# real reboot and a real double-click are in REBOOT.md and are NOT run here.
set -euo pipefail
ACC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$ACC_DIR/lib.sh"
acc_require_binaries

scripts=()
if [[ $# -gt 0 ]]; then
    for want in "$@"; do
        for candidate in "$ACC_DIR/${want}"*.sh; do
            [[ -f "$candidate" ]] && scripts+=("$candidate")
        done
    done
else
    for candidate in "$ACC_DIR"/0*.sh; do
        [[ -f "$candidate" ]] && scripts+=("$candidate")
    done
fi

if [[ ${#scripts[@]} -eq 0 ]]; then
    printf 'no acceptance scripts matched\n' >&2
    exit 2
fi

printf '%s.LEXE acceptance harness%s\n' "$ACC_BOLD" "$ACC_OFF"
printf '  runtime: %s (%s)\n' "$LEXE" "$("$LEXE" version 2>/dev/null | head -1)"
printf '  display: %s\n' \
    "${WAYLAND_DISPLAY:+wayland=$WAYLAND_DISPLAY }${DISPLAY:+x11=$DISPLAY}${WAYLAND_DISPLAY:-${DISPLAY:-none (GUI checks run headless)}}"
printf '\n'

names=()
results=()
failed=0
for script in "${scripts[@]}"; do
    name="$(basename "$script" .sh)"
    names+=("$name")
    if bash "$script"; then
        results+=("ok")
    else
        results+=("FAILED")
        failed=$((failed + 1))
    fi
    printf '\n'
done

printf '%s== acceptance summary ==%s\n' "$ACC_BOLD" "$ACC_OFF"
for i in "${!names[@]}"; do
    if [[ "${results[$i]}" == "ok" ]]; then
        printf '  %s  ok    %s%s\n' "$ACC_GREEN" "${names[$i]}" "$ACC_OFF"
    else
        printf '  %s  FAIL  %s%s\n' "$ACC_RED" "${names[$i]}" "$ACC_OFF"
    fi
done
printf '\n'
if [[ $failed -eq 0 ]]; then
    printf '  %sall %d automated acceptance scripts passed%s\n' \
        "$ACC_GREEN" "${#names[@]}" "$ACC_OFF"
else
    printf '  %s%d of %d acceptance scripts reported failures%s\n' \
        "$ACC_RED" "$failed" "${#names[@]}" "$ACC_OFF"
fi
printf '  Still MANUAL (a real reboot and a real double-click): %s/REBOOT.md\n' "$ACC_DIR"
exit $(( failed > 0 ? 1 : 0 ))

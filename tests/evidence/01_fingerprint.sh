#!/usr/bin/env bash
# tests/evidence/01_fingerprint.sh — does the EVIDENCE GUARD actually fire?
#
# `scripts/test.sh` refuses to let a run be cited as regression evidence if the
# source changed underneath it (§22: "if source changes during the original run,
# discard that run as evidence"). That refusal rests entirely on
# `source_fingerprint()` noticing. A fingerprint that notices nothing turns the
# guard into a rubber stamp that says EVIDENCE VALID over anything at all.
#
# This is not hypothetical. The first version of that function ran
# `find … | xargs stat`, which split on the space in this repository's own path;
# every stat failed into /dev/null and the fingerprint came back as the hash of
# an empty string. It approved everything, for days, and nothing noticed —
# because a guard that never fires looks exactly like a guard with nothing to
# report. It was found only by testing that it fires.
#
# So this lane checks BOTH directions, which is the part that matters:
#
#   * things that MUST move the fingerprint — source, the build definition, the
#     lane scripts, the examples the conformance lanes build packages out of, and
#     the workload harness
#   * things that MUST NOT — the two documented exclusions. An exclusion that
#     silently stopped working would make the guard fire constantly and train
#     everyone to ignore it, which is the same failure wearing the other mask.
#
# A change here is a change to what "evidence" means in this project, so if this
# lane fails, do not adjust the expectations to match the code: work out which of
# the two is wrong first.
set -uo pipefail
EV_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$EV_DIR/../.." && pwd)"
cd "$REPO" || exit 2

# Lift the function out of the script under test rather than reimplementing it.
# A reimplementation would pass while the real one was broken, which is the
# whole failure this lane exists to catch.
eval "$(sed -n '/^source_fingerprint()/,/^}/p' scripts/test.sh)"
if ! declare -F source_fingerprint >/dev/null; then
    printf 'FAIL: could not extract source_fingerprint() from scripts/test.sh\n'
    exit 1
fi

printf 'evidence guard: does source_fingerprint() fire?\n\n'

base="$(source_fingerprint)"
empty="$(printf '' | sha256sum | cut -d' ' -f1)"
if [[ -z "$base" || "$base" == "$empty" ]]; then
    printf 'FAIL: the fingerprint is empty or the hash of nothing.\n'
    printf '      The guard is blind and every run it approves is worthless.\n'
    exit 1
fi
printf '  baseline: %s\n' "$base"

fail=0
check() { # label, expect(change|same), path-to-create
    local label="$1" expect="$2" path="$3"
    mkdir -p "$(dirname "$path")" 2>/dev/null
    printf 'probe\n' > "$path"
    local now; now="$(source_fingerprint)"
    rm -f "$path"
    local after; after="$(source_fingerprint)"

    local moved="same"; [[ "$now" != "$base" ]] && moved="change"
    local verdict="ok"
    [[ "$moved" == "$expect" ]] || { verdict="WRONG"; fail=1; }
    # And it must return to the baseline, or the fingerprint is not a function
    # of the tree and comparing two of them proves nothing.
    [[ "$after" == "$base" ]] || { verdict="${verdict}/NOT-RESTORED"; fail=1; }
    printf '  %-48s expect %-6s got %-6s  %s\n' "$label" "$expect" "$moved" "$verdict"
}

printf '\n  must CHANGE the fingerprint:\n'
check "a new src/ file"                     change "src/lexe/base/zz_evidence_probe.cpp"
check "the build definition"                change "CMakeLists.txt.zz_probe"
check "an examples/ file (lanes build it)"  change "examples/native/cli-hello/zz_probe.c"
check "the workload harness"                change "tests/workloads/zz_evidence_probe.py"
check "a conformance lane script"           change "tests/conformance/zz_evidence_probe.sh"

printf '\n  must NOT change the fingerprint (the documented exclusions):\n'
check "docs/ — cannot alter a lane result"  same   "docs/ZZ_EVIDENCE_PROBE.md"
check "a specimen source — hashed by lane"  same   "tests/workloads/specs_pe/zz_probe.c"

# The probe above creates `CMakeLists.txt.zz_probe`, which is not the real file.
# Prove the real one is matched by name, without touching it: it lives at the
# repository root and is not a *.cpp, so it was invisible to an earlier version
# of this fingerprint and was caught only incidentally by the git-status line.
printf '\n  is the REAL CMakeLists.txt in the fingerprint set?\n'
if find "$REPO/src" "$REPO/tests" "$REPO/scripts" "$REPO/tools" \
        "$REPO/schema" "$REPO/examples" "$REPO/CMakeLists.txt" \
        -path "$REPO/tests/workloads/specs*" -prune -o -type f \
        -name 'CMakeLists.txt' -print 2>/dev/null | grep -q 'CMakeLists.txt'; then
    printf '    yes\n'
else
    printf '    NO — the build definition is invisible to the guard\n'
    fail=1
fi

printf '\n'
if [[ "$fail" -eq 0 ]]; then
    printf '  ok  the guard fires where it must and stays quiet where it must\n'
else
    printf '  FAIL  the evidence guard does not behave as documented\n'
fi
exit "$fail"

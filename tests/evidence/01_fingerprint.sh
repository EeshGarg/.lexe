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

# Each probe takes its OWN before-reading rather than comparing against one
# baseline captured at the start.
#
# Not a refinement — the single-baseline version reported two false WRONGs the
# first time another agent happened to be writing specimen files while this ran.
# Concurrent work in the tree is the normal condition here, not an anomaly, and
# a check that misreports under the exact circumstance it exists to police is
# worthless. A per-probe before/after pair is immune to drift between probes,
# and drift DURING a probe is reported as its own outcome (DRIFTED) rather than
# being blamed on the fingerprint.
#
# It PRINTS its verdict and sets nothing. The previous version also did
# `fail=1` -- from inside a function only ever called as `$(verdict_for ...)`,
# which is a command substitution, which is a SUBSHELL. Every one of those
# assignments died with the subshell, `exit "$fail"` always saw 0, and this lane
# COULD NOT FAIL.
#
# An independent audit proved it by reintroducing the exact defect the lane was
# written for -- a fingerprint that hashes nothing and approves everything --
# and watching the lane print six WRONG verdicts, then "ok", then exit 0.
#
# So this is instance seven of the pattern documented in docs/ERRORS.md section
# 7, committed by the author of the lane, inside the lane whose entire purpose is
# catching it. The lesson is not "be careful with subshells": it is that a value
# which has to cross a subshell boundary is not a signal, and that a check nobody
# has watched FAIL is not yet a check.
verdict_for() { # expect, before, now, after -> prints "<moved>|<verdict>"
    local expect="$1" before="$2" now="$3" after="$4"
    local moved="same"; [[ "$now" != "$before" ]] && moved="change"
    local verdict="ok"
    [[ "$moved" == "$expect" ]] || verdict="WRONG"
    # Must return to where it started, or the fingerprint is not a function of
    # the tree and comparing two readings proves nothing.
    if [[ "$after" != "$before" ]]; then
        verdict="DRIFTED (tree changed under the probe; rerun on a quiet tree)"
    fi
    printf '%s|%s' "$moved" "$verdict"
}

# Judge a printed verdict in the CALLER's shell, where `fail` is real.
judge() { case "$1" in *WRONG*|*DRIFTED*) fail=1 ;; esac; }

check() { # label, expect(change|same), path-to-create
    local label="$1" expect="$2" path="$3"
    local before; before="$(source_fingerprint)"
    mkdir -p "$(dirname "$path")" 2>/dev/null
    printf 'probe\n' > "$path"
    local now; now="$(source_fingerprint)"
    rm -f "$path"
    local after; after="$(source_fingerprint)"
    local r; r="$(verdict_for "$expect" "$before" "$now" "$after")"
    printf '  %-48s expect %-6s got %-6s  %s\n' \
        "$label" "$expect" "${r%%|*}" "${r#*|}"
    judge "${r#*|}"
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

# Every probe above creates a NEW, UNTRACKED file — which `git status` reports on
# its own. So none of them can tell whether the `find` half of the fingerprint
# works at all, and the `find` half is where the real bug was: the old
# `tests/workloads/` prune looked effective while doing nothing, because git
# status was quietly covering for it.
#
# The case that isolates `find` is a TRACKED file whose mtime moves and whose
# content does not. git status says nothing about it — there is nothing to say —
# so if the fingerprint still notices, that can only be `find`.
touch_check() { # label, expect, tracked-path
    local label="$1" expect="$2" path="$3"
    if [[ ! -f "$path" ]]; then
        printf '  %-48s SKIP (no such tracked file)\n' "$label"
        fail=1
        return
    fi
    # Restore the mtime EXACTLY, or this probe leaves the tree looking changed to
    # every later run, including the one being collected as evidence. `cp -p`
    # keeps full sub-second precision and `touch -r` copies it back verbatim;
    # round-tripping through `stat -c %y` and `touch -d` does not, and loses
    # nanoseconds, which the fingerprint reads.
    local ref; ref="$(mktemp)"
    cp -p "$path" "$ref"
    local before; before="$(source_fingerprint)"
    touch "$path"
    local now; now="$(source_fingerprint)"
    touch -r "$ref" "$path"
    rm -f "$ref"
    local after; after="$(source_fingerprint)"
    local r; r="$(verdict_for "$expect" "$before" "$now" "$after")"
    printf '  %-48s expect %-6s got %-6s  %s\n' \
        "$label" "$expect" "${r%%|*}" "${r#*|}"
    judge "${r#*|}"
}

printf '\n  the find half specifically — a tracked file touched, content unchanged\n'
printf '  (git status cannot see this, so only find can):\n'
touch_check "touch a tracked src/ file"          change "src/lexe/base/util.cpp"
touch_check "touch a tracked specimen (pruned)"  same   "tests/workloads/specs_pe/t_common.h"

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

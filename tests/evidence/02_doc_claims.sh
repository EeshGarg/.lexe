#!/usr/bin/env bash
# tests/evidence/02_doc_claims.sh — does the documentation still describe THIS tree?
#
# The release documents make claims that are checkable against the repository:
# they cite files as evidence, and they state counts. Both rot silently. A
# citation survives the file being renamed, and a count survives the suite
# growing, because nothing reads a document at runtime — which is precisely why
# a document is the easiest place in this project for a false claim to live.
#
# That is this project's recurring defect wearing prose instead of shell. The
# pattern has been found ten times in machinery: something reports success over
# work it did not do. docs/ALPHA.md is the support contract — the document that
# says what the release commits to — and it opens by promising that "nothing
# below is claimed that is not backed by an automated test, a CI job, or a
# reproducible script linked in the evidence checklist". A link in that
# checklist pointing at a file that no longer exists breaks that promise
# directly, and no lane would ever notice.
#
# It had rotted. At the time this check was written, three live documents cited
# source paths that did not exist (`src/gui/main.cpp` twice, after the GUI was
# split into lexe-builder and lexe-ui; `src/lexe/base/lock.hpp`, after the lock
# moved to state/), and ALPHA.md stated 692 test cases / 8924 assertions and
# "10 acceptance suites, 3 lifecycle scripts" for a tree holding 740 / 9382,
# eleven acceptance suites and five lifecycle scripts.
#
# ---------------------------------------------------------------------------
# THE DESIGN DECISION, which is the whole reason this check is worth anything
#
# A check that greps a document for a number has an obvious failure mode: the
# sentence gets reworded, the grep matches nothing, and "nothing matched" reads
# as "nothing wrong". That is docs/ERRORS.md §7 practice 3 — a check cannot
# detect what it holds constant — and it would make this script a rubber stamp
# in about one editing pass.
#
# So every claim below is located first and asserted second. If the claim is
# not found in the document AT ALL, that is a FAILURE, not a pass: it means the
# document was rewritten out from under the check and nobody re-aimed it. The
# check is never allowed to conclude anything from an absence.
#
# Two shell hazards this project has been bitten by, avoided deliberately:
#   * assignments inside $(...) are lost to the subshell. That defect killed
#     two separate checks here, one of which was the evidence lane itself. No
#     verdict below is computed inside a command substitution.
#   * `grep -c ... || echo 0` prints TWO zeros, because grep prints 0 and then
#     exits 1. Nothing here uses `grep -c`.
# ---------------------------------------------------------------------------
#
# Exit codes:  0 claims hold · 1 a claim is false or missing · 2 BLOCKED,
# a claim could not be observed (no test binary). 2 is deliberately not 0: an
# unobserved claim is not a verified claim, and this lane exists to say so.

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 2

fail=0
stale_binary=0
blocked=0

say()  { printf '  %s\n' "$*"; }
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; fail=$((fail + 1)); }
blok() { printf '  BLOCK %s\n' "$*"; blocked=$((blocked + 1)); }

printf 'evidence: does the documentation still describe THIS tree?\n\n'

# ---------------------------------------------------------------------------
# 1. Every path a live document cites as evidence must exist.
#
# Scope and its justification:
#
#   * `docs/*.md` and `README.md` describe the tree as it IS. CHANGELOG.md is
#     excluded on purpose — a changelog describes the tree as it WAS, and
#     `src/core/version.hpp` in a historical entry is correct prose about a
#     path that has since moved. Holding a changelog to the present tree would
#     force it to lie about the past.
#
#   * A citation is a backticked string rooted at a known top-level directory,
#     or a markdown link target. Bare basenames are NOT citations: documents
#     say `lexe.json` and `test_verify.cpp` as nouns, dozens of times, and
#     treating those as paths produced ~110 false positives against 3 real
#     ones. A check that noisy gets switched off, which is a worse outcome
#     than no check.
# ---------------------------------------------------------------------------
say '1. cited paths resolve'

cited_total=0
cited_dead=0

# Rooted, backticked citations. Read from a process substitution so the
# counters below live in THIS shell and survive the loop.
while IFS= read -r line; do
    doc="${line%%$'\t'*}"
    path="${line#*$'\t'}"
    cited_total=$((cited_total + 1))
    if [[ ! -e "$path" ]]; then
        bad "$doc cites $path — no such file"
        cited_dead=$((cited_dead + 1))
    fi
done < <(
    for d in docs/*.md README.md; do
        [[ -f "$d" ]] || continue
        grep -oE '`(src|tests|scripts|examples|packaging|docs|\.github)/[a-zA-Z0-9_./-]+`' "$d" 2>/dev/null |
            tr -d '`' | sort -u | sed "s|^|${d}\t|"
    done
)

# Markdown link targets, resolved relative to the linking document.
while IFS= read -r line; do
    doc="${line%%$'\t'*}"
    path="${line#*$'\t'}"
    cited_total=$((cited_total + 1))
    if [[ ! -e "$(dirname "$doc")/$path" ]]; then
        bad "$doc links to $path — no such file"
        cited_dead=$((cited_dead + 1))
    fi
done < <(
    for d in docs/*.md README.md; do
        [[ -f "$d" ]] || continue
        grep -oE '\]\([^)#]+\)' "$d" 2>/dev/null |
            sed -E 's/^\]\(//; s/\)$//' |
            grep -vE '^(https?|mailto):' | sort -u | sed "s|^|${d}\t|"
    done
)

# A sweep that examined nothing must not report success. If the corpus of
# citations is empty, the extraction broke — a regex typo, a moved docs/ — and
# every citation would then "resolve" vacuously.
if [[ "$cited_total" -eq 0 ]]; then
    bad 'no citations were extracted at all — the extraction is broken, not the docs clean'
elif [[ "$cited_dead" -eq 0 ]]; then
    ok "$cited_total cited paths, all resolve"
fi

# ---------------------------------------------------------------------------
# 2. The counts ALPHA.md states must match the tree it states them about.
# ---------------------------------------------------------------------------
say '2. stated suite counts match the tree'

ALPHA=docs/ALPHA.md

# Count the tree. Numbered scripts only: lib.sh and run_all.sh are machinery,
# not suites, and counting them would make the documented number depend on how
# the lane happens to be plumbed.
acc_actual=0;  for f in tests/acceptance/[0-9]*.sh;  do [[ -f "$f" ]] && acc_actual=$((acc_actual + 1)); done
life_actual=0; for f in tests/lifecycle/[0-9]*.sh;   do [[ -f "$f" ]] && life_actual=$((life_actual + 1)); done
int_actual=0;  for f in tests/integration/*.sh;      do [[ -f "$f" ]] && int_actual=$((int_actual + 1)); done

# claim_number <label> <regex with ONE capturing group> — the located-first
# discipline: a claim that cannot be found is a failure, never a pass.
claimed=""
claim_number() {
    local label="$1" re="$2" hit
    claimed=""
    hit="$(grep -oE "$re" "$ALPHA" 2>/dev/null | head -1)"
    if [[ -z "$hit" ]]; then
        bad "$ALPHA no longer states a $label — this check lost its subject and must not pass"
        return 1
    fi
    claimed="$(printf '%s' "$hit" | grep -oE '[0-9]+' | head -1)"
    return 0
}

if claim_number 'acceptance-suite count' '\*\*[0-9]+ acceptance suites\*\*'; then
    if [[ "$claimed" == "$acc_actual" ]]; then
        ok "acceptance suites: $claimed, and the tree holds $acc_actual"
    else
        bad "acceptance suites: $ALPHA claims $claimed, the tree holds $acc_actual"
    fi
fi

if claim_number 'lifecycle-script count' '[0-9]+ lifecycle'; then
    if [[ "$claimed" == "$life_actual" ]]; then
        ok "lifecycle scripts: $claimed, and the tree holds $life_actual"
    else
        bad "lifecycle scripts: $ALPHA claims $claimed, the tree holds $life_actual"
    fi
fi

if claim_number 'integration-script count' '[0-9]+ integration scripts'; then
    if [[ "$claimed" == "$int_actual" ]]; then
        ok "integration scripts: $claimed, and the tree holds $int_actual"
    else
        bad "integration scripts: $ALPHA claims $claimed, the tree holds $int_actual"
    fi
fi

# ---------------------------------------------------------------------------
# 3. The regression totals ALPHA.md publishes must be the totals the suite
#    actually reports.
#
# This is the claim a reader is most likely to take on trust and least able to
# check, which is exactly why it is worth observing rather than asserting.
# ---------------------------------------------------------------------------
say '3. published regression totals match the suite'

# Scope first, and the scoping is a judgement call worth stating.
#
# The published totals describe a RELEASED LINE -- a commit -- not whatever is
# in someone's editor. Asserting them against a dirty working tree would make
# the evidence lane red for every developer mid-change, and a check that is red
# by default gets switched off, which is strictly worse than no check.
#
# So on a dirty tree this is skipped with a note, and on a clean tree it is
# enforced. That is not a loophole: the moment the change is committed, the tree
# is clean and the claim is checked, which is exactly when it matters. What it
# deliberately does NOT do is treat "skipped" as "verified" -- the note says so
# in those words.
dirty="$(git status --porcelain 2>/dev/null | head -1)"
BIN="${LEXE_TEST_BIN:-${LEXE_BUILD_DIR:-./build}/lexe_tests}"

# Name the artifact, and say how old it is relative to the source.
#
# This check compares a NUMBER IN A DOCUMENT against a NUMBER FROM A BINARY,
# and it never said which binary. Run standalone against a stale tree it
# reported a mismatch that looked like a documentation defect and was an
# out-of-date build -- which happened, and cost real time. The whole point of
# this lane is evidence provenance, so a check inside it that cannot name its
# own evidence is the failure it exists to catch.
#
# The mtime comparison is a heuristic and is labelled as one: it cannot prove a
# binary was built from the current source, only notice when it demonstrably
# was not. A newer binary is not proof of a matching build -- it is merely the
# absence of this particular reason to distrust it.
provenance() {
    local newest_src
    newest_src="$(find src tests CMakeLists.txt -type f -newer "$BIN" 2>/dev/null | head -1)"
    printf '  evidence under test:\n'
    printf '    binary   %s\n' "$BIN"
    printf '    built    %s\n' "$(date -r "$BIN" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'unknown')"
    printf '    commit   %s%s\n' \
        "$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
        "$([[ -n "$(git status --porcelain 2>/dev/null)" ]] && echo ' (working tree DIRTY)' || echo ' (clean)')"
    if [[ -n "$newest_src" ]]; then
        printf '    %sSTALE%s: %s is newer than the binary -- rebuild before trusting a mismatch\n' \
            "" "" "$newest_src"
        return 1
    fi
    printf '    freshness: no tracked source is newer than the binary\n'
    return 0
}

if [[ -n "$dirty" ]]; then
    say 'skipped: the working tree has uncommitted changes.'
    say '        The published totals describe a commit, not a working tree, so'
    say '        there is nothing here to compare them against. NOT verified.'
elif [[ ! -x "$BIN" ]]; then
    blok "no test binary at $BIN — the published totals were NOT verified by this run"
    say '        (build first: cmake --build build -j6. Reported as BLOCKED, never as a pass:'
    say '         a total nobody observed is not a total anybody verified.)'
else
    # State the evidence before drawing a conclusion from it.
    provenance || stale_binary=1
    # doctest's tail: "assertions: 9382 | 9382 passed | 0 failed |"
    summary="$("$BIN" --no-colors 2>/dev/null | tail -20)"
    real_cases="$(printf '%s\n' "$summary" | grep -oE 'test cases: *[0-9]+' | grep -oE '[0-9]+' | head -1)"
    real_asserts="$(printf '%s\n' "$summary" | grep -oE 'assertions: *[0-9]+' | grep -oE '[0-9]+' | head -1)"

    if [[ -z "$real_cases" || -z "$real_asserts" ]]; then
        bad "could not read totals out of $BIN — the summary format changed and this check went blind"
    elif claim_number 'regression total' '\*\*[0-9]+ test cases / [0-9]+'; then
        doc_cases="$claimed"
        doc_asserts="$(grep -oE '\*\*[0-9]+ test cases / [0-9]+' "$ALPHA" | grep -oE '[0-9]+' | tail -1)"
        if [[ "$doc_cases" == "$real_cases" && "$doc_asserts" == "$real_asserts" ]]; then
            ok "regression totals: $doc_cases cases / $doc_asserts assertions, as the suite reports"
        else
            bad "regression totals: $ALPHA publishes $doc_cases/$doc_asserts, the suite reports $real_cases/$real_asserts"
            # Do not let a stale artifact be read as a documentation defect.
            if [[ "${stale_binary:-0}" == "1" ]]; then
                say '        ...but the binary above is OLDER than tracked source, so this'
                say '        mismatch may be the build, not the document. Rebuild and re-run'
                say '        before believing it.'
            fi
        fi
    fi
fi

printf '\n'
if [[ "$fail" -gt 0 ]]; then
    printf '  %d documentation claim(s) do not hold\n' "$fail"
    exit 1
fi
if [[ "$blocked" -gt 0 ]]; then
    printf '  claims hold, but %d could not be observed — not citable as evidence\n' "$blocked"
    exit 2
fi
printf '  every checked documentation claim holds against this tree\n'
exit 0

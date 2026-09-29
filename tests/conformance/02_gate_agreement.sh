#!/usr/bin/env bash
# tests/conformance/02_gate_agreement.sh — what `verify` promises, `install`
# must honour (FORMAT-0.1 §10.3).
#
# The invariant:
#
#     A package that passes verification MUST NOT be rejected at install time
#     for an INTRINSIC property of the package.
#
# `verify` is what a repository gate, a CI job or a cautious user runs to decide
# whether a package is acceptable. If it passes things the installer refuses, it
# is handing out an assurance the runtime does not honour — and a publisher who
# trusts it ships a package that fails for every user.
#
# Three separate defects of exactly this shape were found while freezing 0.1: an
# unknown permission id, a decompression bomb, and a non-UTF-8 entry name each
# verified cleanly and then failed at install. Each was fixed individually. This
# lane exists so the CLASS cannot come back, because fixing three instances of a
# pattern is not the same as closing the pattern.
#
# How the two kinds of refusal are told apart, without parsing prose: the exit
# code. `install` exits **3** exactly when verification failed, which is the
# intrinsic case. Every other non-zero exit is environmental or policy —
# already installed (1), not found (4), permission not approved (5), busy or
# retained data under another key (6), a local trust decision (7) — and those
# are legitimate outcomes for a perfectly valid package. §10.3 says so.
set -uo pipefail
CONF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$CONF_DIR/../acceptance/lib.sh"

acc_begin "conformance 02 verify/install agreement"
acc_require_binaries
acc_scratch_home

PY=""
for candidate in python3 python; do
    command -v "$candidate" >/dev/null 2>&1 && { PY="$candidate"; break; }
done
if [[ -z "$PY" ]]; then
    skip "no python3, so the mutation corpus cannot be built"
    acc_summary
    exit $?
fi

"$LEXE" keygen "$ACC_ROOT/work/key.json" >/dev/null 2>&1

# One good package to mutate. Built from a COPY: `lexe build` rewrites a
# manifest's "AUTO" publicKey in place and would dirty the tracked example.
cp -r "$ACC_REPO/examples/service/heartbeat" "$ACC_ROOT/work/project"
# Build the payload first. Only the SOURCES are tracked -- payload/bin is
# compiled output and correctly gitignored -- so on a fresh clone there is
# nothing to package until make has run. This lane used to assume the
# binary was lying around from some earlier run, which is true on a
# developer machine and false everywhere else; an evidence audit hit it by
# working from a `git archive` extraction, which is what a fresh clone is.
if ! make -s -C "$ACC_ROOT/work/project" >"$ACC_ROOT/work/make.log" 2>&1; then
    fail "the example payload could not be compiled"
    note "$(tail -3 "$ACC_ROOT/work/make.log")"
    acc_summary
    exit $?
fi
if ! "$LEXE" build "$ACC_ROOT/work/project" -o "$ACC_ROOT/work/good.lexe" \
        --key "$ACC_ROOT/work/key.json" >"$ACC_ROOT/work/build.log" 2>&1; then
    fail "the base package could not be built"
    note "$(tail -3 "$ACC_ROOT/work/build.log")"
    acc_summary
    exit $?
fi

MUTANTS_ATTEMPTED=0
MUTANTS_CHECKED=0

# check_gate <package> <label>
#
# Runs verify, then install into a FRESH root so no earlier install can turn an
# intrinsic refusal into "already installed".
check_gate() {
    local pkg="$1" label="$2"
    local vrc irc home
    "$LEXE" verify "$pkg" >"$ACC_ROOT/work/v.txt" 2>&1
    vrc=$?

    home="$ACC_ROOT/work/home-$RANDOM$RANDOM"
    mkdir -p "$home"
    LEXE_HOME="$home" "$LEXE" install "$pkg" --yes --trust --approve-compile \
        >"$ACC_ROOT/work/i.txt" 2>&1
    irc=$?
    rm -rf "$home"

    if [[ $vrc -ne 0 ]]; then
        # Verification refused it. Installation must refuse it too — an
        # installer that accepted what the verifier rejected would be the same
        # defect pointing the other way, and a worse one.
        if [[ $irc -ne 0 ]]; then
            pass "$label — both refuse (verify $vrc, install $irc)"
        else
            fail "$label — INSTALL ACCEPTED WHAT VERIFY REJECTED" \
                "verify exit $vrc:" "$(sed -n '2,5p' "$ACC_ROOT/work/v.txt")"
        fi
        return
    fi

    # Verification passed. Installation may still fail — but not with exit 3.
    if [[ $irc -eq 3 ]]; then
        fail "$label — GATE MISMATCH: verify passed, install rejected it as invalid" \
            "install exit 3 means verification failed at install time," \
            "so the package has an intrinsic defect verify did not report:" \
            "$(head -3 "$ACC_ROOT/work/i.txt")"
    elif [[ $irc -eq 0 ]]; then
        pass "$label — verify passed and it installed"
    else
        pass "$label — verify passed; install declined for a non-package reason (exit $irc)"
        note "$(head -1 "$ACC_ROOT/work/i.txt")"
    fi
}

# ------------------------------------------------------------------ the corpus
#
# Every mutation is applied to a validly signed package and, where it touches a
# covered member, re-hashed and re-signed — so the package stays authentic and
# the only question is whether the two commands agree about it. A mutation that
# broke the signature would be refused by both for an uninteresting reason.

check_gate "$ACC_ROOT/work/good.lexe" "the unmodified package"

mutate() {
    local tag="$1"
    local out="$ACC_ROOT/work/m-$tag.lexe"
    if "$PY" "$CONF_DIR/mutate.py" "$ACC_ROOT/work/good.lexe" "$out" "$tag" \
            "$ACC_ROOT/work/key.json" >"$ACC_ROOT/work/mutate.log" 2>&1; then
        printf '%s' "$out"
    else
        printf ''
    fi
}

for spec in \
    "unknown-permission:an unknown permission id" \
    "duplicate-permission:a repeated permission id" \
    "bomb:a highly compressible payload" \
    "bad-utf8-name:an entry name that is not valid UTF-8" \
    "reserved-scope:a reserved install.scope" \
    "exec-not-covered:an executable declaration naming an uncovered path" \
    "exec-names-manifest:an executable declaration naming lexe.json" \
    "long-version:an over-long version string" \
    "noncanonical-key:a non-canonical publisher key encoding" \
    "direntry:a directory entry" \
    "dot-segment:a '.' path segment"
do
    tag="${spec%%:*}"; label="${spec#*:}"
    MUTANTS_ATTEMPTED=$((MUTANTS_ATTEMPTED + 1))
    pkg="$(mutate "$tag")"
    if [[ -z "$pkg" || ! -f "$pkg" ]]; then
        skip "could not build the mutation: $label"
        note "$(tail -2 "$ACC_ROOT/work/mutate.log")"
        continue
    fi
    MUTANTS_CHECKED=$((MUTANTS_CHECKED + 1))
    check_gate "$pkg" "$label"
done

# A lane that checked NO mutants has not tested the gate, whatever its
# summary says. Every mutation becoming a `skip` leaves the one PASS from
# the unmodified package, and acc_summary returns 0 whenever nothing
# FAILED -- so the runner recorded "PASS conformance 4 passed, 0 failed"
# over zero mutants checked. An evidence audit produced exactly that by
# breaking mutate.py, and it is the same shape as a lane exiting 0 having
# executed nothing, which the workload lane already guards against.
printf "  %d mutation(s) attempted, %d actually built and checked\n" \
    "$MUTANTS_ATTEMPTED" "$MUTANTS_CHECKED"
if [[ "$MUTANTS_CHECKED" -eq 0 ]]; then
    fail "no mutation could be built, so the install gate was never exercised"
    note "the unmodified package passing proves only that the happy path works"
fi

acc_summary

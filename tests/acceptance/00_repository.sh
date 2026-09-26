#!/usr/bin/env bash
# 00 — the repository contains what the other suites depend on.
#
# Runs first, needs no build, and exists because of a defect that hid for as long
# as it did precisely because every machine that ran the suite had the missing
# files sitting untracked in its working tree:
#
#     examples/.gitignore said `*/payload/`. That was correct while every example
#     was a `native` package, where the payload is a compiled binary and
#     committing it would mean committing build output. Then the `portable`
#     application type arrived, for which the payload IS THE SOURCE. The rule
#     therefore excluded examples/portable/c-hello/payload/src/ from the
#     repository, and 05_portable_compile.sh — the suite that proves the whole
#     portable capability — could not have run on a fresh clone.
#
# A test suite that depends on files outside version control proves nothing about
# the project; it proves something about one developer's disk. These checks ask
# git what is actually committed, so "it works here" cannot stand in for "it is
# in the repository".
set -uo pipefail
ACC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$ACC_DIR/lib.sh"
acc_begin "00 repository"

if ! command -v git >/dev/null 2>&1; then
    skip "git is not installed — cannot ask what is committed"
    acc_summary
    exit $?
fi
if ! git -C "$ACC_REPO" rev-parse --git-dir >/dev/null 2>&1; then
    skip "not a git checkout — nothing to ask about"
    acc_summary
    exit $?
fi

# Everything git has, once.
tracked="$(git -C "$ACC_REPO" ls-files)"
is_tracked() { printf '%s\n' "$tracked" | grep -qxF "$1"; }

check_tracked() {
    local path="$1" why="$2"
    if is_tracked "$path"; then
        pass "$path is in the repository"
    else
        local exists="and it is not on disk either"
        [[ -e "$ACC_REPO/$path" ]] && exists="it EXISTS on disk but is untracked — \
a fresh clone would not have it"
        fail "$path is in the repository" "$why" "$exists"
    fi
}

# --------------------------------------------- every example is a real project

acc_true 0 "examples a test builds must be committed in full"
for project in "$ACC_REPO"/examples/*/ "$ACC_REPO"/examples/*/*/; do
    project="${project%/}"          # the glob leaves a trailing slash
    [[ -f "$project/lexe.json" ]] || continue
    relative="${project#$ACC_REPO/}"
    check_tracked "$relative/lexe.json" "an example without its manifest is not an example"

    # Whatever the manifest says this package is made of has to be present.
    kind="$(acc_json "$project/lexe.json" 'd.get("applicationType", "native")')"
    if [[ "$kind" == "portable" ]]; then
        # The payload IS the source. This is the case the old ignore rule broke.
        if [[ ! -d "$project/payload" ]] ||
           [[ -z "$(find "$project/payload" -type f -print -quit 2>/dev/null)" ]]; then
            fail "$relative carries its portable source" \
                "applicationType is \"portable\", so payload/ must hold the source" \
                "and payload/ is empty or absent"
        else
            while IFS= read -r source; do
                [[ -n "$source" ]] || continue
                check_tracked "${source#$ACC_REPO/}" \
                    "a portable payload IS source, never build output"
            done < <(find "$project/payload" -type f | sort)
        fi
    else
        # A compiled example keeps its SOURCE and its recipe in the repository;
        # the compiled result is build output and must NOT be committed.
        for needed in src Makefile; do
            [[ -e "$project/$needed" ]] || continue
            if [[ -d "$project/$needed" ]]; then
                while IFS= read -r source; do
                    [[ -n "$source" ]] || continue
                    check_tracked "${source#$ACC_REPO/}" "example source"
                done < <(find "$project/$needed" -type f | sort)
            else
                check_tracked "${relative}/$needed" "the recipe that builds it"
            fi
        done
    fi
done

# --------------------------------------------- and build output is NOT committed

committed_binaries="$(printf '%s\n' "$tracked" |
    grep -E '^examples/.*/payload/(bin|lib)/' || true)"
acc_equals "$committed_binaries" "" \
    "no compiled example payload is committed — that is build output"

# --------------------------------------------- the suites themselves

for suite in "$ACC_REPO"/tests/acceptance/*.sh "$ACC_REPO"/scripts/*.sh \
             "$ACC_REPO"/scripts/lib/*.sh; do
    [[ -f "$suite" ]] || continue
    check_tracked "${suite#$ACC_REPO/}" "a test that is not committed cannot be run by anyone else"
done

# --------------------------------------------- nothing that must never be in git

for pattern in '*.key' 'id_ed25519' '*.pem' '*_rsa'; do
    hits="$(printf '%s\n' "$tracked" | grep -E "${pattern//\*/.*}$" || true)"
    acc_equals "$hits" "" "no $pattern is committed"
done

# A signing key file the CLI writes is JSON with a secretKey field; make sure no
# such file ever became part of the tree.
key_like="$(git -C "$ACC_REPO" grep -l 'secretKey' -- '*.json' 2>/dev/null || true)"
acc_equals "$key_like" "" "no committed JSON file carries a secretKey"

# Wine/Proton prefixes and build trees are machine state, not source.
for junk in 'build/' 'build-linux/' 'pfx/' 'compatdata/'; do
    hits="$(printf '%s\n' "$tracked" | grep -F "$junk" | head -1 || true)"
    acc_equals "$hits" "" "no $junk is committed"
done

acc_summary

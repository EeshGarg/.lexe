#!/usr/bin/env bash
# Real-binary trust lifecycle acceptance for runtime-trust WS3/WS4/WS10. Drives
# the actual `lexe` CLI on a real Linux host through the full local-trust story:
# first-seen preview, binding persistence, same-key update (known), changed-key
# refusal, block/unblock at launch, corrupt-record fail-closed + restore, and
# permission consent staying separate from publisher trust.
#
# Usage:  tests/integration/ws3_ws4_trust_lifecycle.sh /path/to/lexe

set -uo pipefail
# The binary to drive: an explicit first argument, else LEXE_BUILD_DIR (what
# scripts/test.sh and the acceptance harness use), else ./build/lexe.
#
# LEXE_BUILD_DIR was the missing case: every other suite honours it, so a
# checkout that builds anywhere but ./build ran everything EXCEPT these two,
# which failed with "lexe not found at ./build/lexe" inside the runner.
LEXE="${1:-${LEXE_BUILD_DIR:-./build}/lexe}"
[[ -x "$LEXE" ]] || { echo "FATAL: lexe not found at $LEXE" >&2; exit 2; }
LEXE="$(readlink -f "$LEXE")"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lexe-trust.XXXXXX")"
export LEXE_HOME="$WORK/home"; mkdir -p "$LEXE_HOME"
ID="com.example.trust"; STEP=0; FAILED=0
trap 'rm -rf "$WORK"' EXIT

# Where each command's stdout and stderr land, and why they are not /tmp/tx.out.
#
# Every assertion in this file reads those two files. With fixed names in the
# shared /tmp they were a rendezvous point between unrelated runs: two lanes in
# parallel overwrite each other's output mid-assertion, and a run that dies
# before writing them leaves the PREVIOUS run's output in place, so `grep_out`
# happily finds the string it wanted in bytes produced by a different tree. That
# is not hypothetical here -- a stale /tmp file from an earlier WSL session once
# held a complete, plausible summary of a different tree and was nearly cited as
# evidence. /tmp is also wiped by a WSL restart, which has happened four times.
#
# Inside $WORK they are private to this process and removed with it.
TX_OUT="$WORK/tx.out"; TX_ERR="$WORK/tx.err"
: > "$TX_OUT"; : > "$TX_ERR"

step()  { STEP=$((STEP+1)); echo; echo "== step $STEP: $* =="; }
pass()  { echo "  PASS: $*"; }
fail()  { echo "  FAIL: $*" >&2; FAILED=$((FAILED+1)); }
expect_exit() { local want="$1"; shift; echo "  \$ lexe $* (expect $want)";
  "$LEXE" "$@" >"$TX_OUT" 2>"$TX_ERR"; local got=$?
  sed 's/^/    | /' "$TX_OUT"; sed 's/^/    ! /' "$TX_ERR"
  [[ "$got" == "$want" ]] && pass "exit $got" || fail "exit $got, wanted $want"; }
# An empty needle would make `grep -qi` match every line, so every grep_out in
# the file would pass unconditionally. Cheap to rule out, and the shape has
# already cost this project a whole lane (tests/lifecycle/lib.sh's lc_kill_at).
grep_out() {
  if [[ -z "$1" ]]; then fail "grep_out called with an empty needle — that matches everything"; return 1; fi
  grep -qi -- "$1" "$TX_OUT" "$TX_ERR" && pass "saw: $1" || fail "missing: $1"
}
assert_file()   { [[ -e "$1" ]] && pass "exists: $1" || fail "missing: $1"; }
assert_absent() { [[ ! -e "$1" ]] && pass "absent: $1" || fail "present: $1"; }

KEYS="$WORK/keys"; mkdir -p "$KEYS"
"$LEXE" keygen "$KEYS/A.json" >/dev/null
"$LEXE" keygen "$KEYS/B.json" >/dev/null
pubkey() { grep -o '"publicKey": *"[^"]*"' "$1" | sed 's/.*"\([^"]*\)".*/\1/'; }

make_pkg() { # <version> <keyfile> <out> [perm]
  local ver="$1" key="$2" out="$3" perm="${4:-}"
  local p="$WORK/proj-$ver-$RANDOM"; mkdir -p "$p/payload/bin"
  # A COMPILED payload, not a shell script.
  #
  # These suites used to write `payload/bin/app.sh` and declare it as the entrypoint
  # of an `applicationType: "native"` package. The `payload-role` verification stage
  # refuses that, correctly and by design:
  #
  #     applicationType "native" declares "bin/app.sh" as the entrypoint, but those
  #     bytes are not an ELF object (a native package must contain a COMPILED
  #     executable — source files belong in a portable-code package)
  #
  # So both suites had been failing at the first install since that stage landed,
  # and nobody knew, because nothing ran them: there was no single test entry point,
  # and they were not in the acceptance runner. `scripts/test.sh --integration` is
  # what surfaced it.
  #
  # The payload prints its own version, so "which version is installed" can be
  # answered by the running program rather than only by the registry.
  printf '#include <stdio.h>\nint main(void){puts("hi %s");return 0;}\n' \
      "$ver" > "$p/app.c"
  cc -O2 -o "$p/payload/bin/app" "$p/app.c" || {
      printf 'FATAL: no C compiler; cannot build a native payload\n' >&2
      exit 2
  }
  local perms="[]"; [[ -n "$perm" ]] && perms="[\"$perm\"]"
  cat > "$p/lexe.json" <<EOF
{ "lexeVersion":"0.1", "id":"$ID", "name":"Trust Demo", "version":"$ver",
  "publisher":{"name":"Same Publisher Name","publicKey":"$(pubkey "$key")"},
  "applicationType":"native", "architectures":["x86_64","aarch64"],
  "entrypoint":{"executable":"bin/app","arguments":[]},
  "install":{"scope":"user","mode":"bundled"}, "permissions":$perms }
EOF
  "$LEXE" build "$p" -o "$out" --key "$key" >/dev/null
}

echo "### WS3/WS4 real-binary trust lifecycle — LEXE_HOME=$LEXE_HOME"

step "build packages: A@1.0.0, A@2.0.0, A@3.0.0(+network), B@2.0.0"
make_pkg 1.0.0 "$KEYS/A.json" "$WORK/a1.lexe"
make_pkg 2.0.0 "$KEYS/A.json" "$WORK/a2.lexe"
make_pkg 3.0.0 "$KEYS/A.json" "$WORK/a3net.lexe" network
make_pkg 2.0.0 "$KEYS/B.json" "$WORK/b2.lexe"
assert_file "$WORK/a1.lexe"; assert_file "$WORK/b2.lexe"

# The interactive "yes", written down. A REGULAR FILE, not `printf 'y\n' |`.
#
# REFERENCE-POLICY.md §4: a confirmation prompt reads stdin only when it is a
# terminal or a regular file, and refuses anything else -- a pipe included --
# with exit 5, because an open pipe that nothing writes to held `lexe install`
# in getline for 180 seconds. This file piped its "y" for the whole time that
# rule has existed (2164dd9), so the install in step 2 was refused, and nothing
# here looked at its exit status: the preview text it greps is printed BEFORE
# the prompt, so step 2 stayed green while steps 3-9 failed eight times over on
# an application that had never been installed -- the last of them as a
# changed-key conflict that was really key B landing on an empty slot.
ANSWER_YES="$WORK/answer-yes"; printf 'y\n' > "$ANSWER_YES"
install_status() { # <expected status> <label> <package> -- stdin is the answer
  "$LEXE" install "$3" >"$TX_OUT" 2>"$TX_ERR"; local got=$?
  [[ "$got" == "$1" ]] && pass "$2 (exit $got)" \
    || { fail "$2: exit $got, wanted $1"; sed 's/^/    ! /' "$TX_ERR"; }
}

step "a pipe cannot answer the prompt: refused with exit 5, nothing installed"
# The old form of this step, kept as the negative it always secretly was. It
# observes the §4 rule from this lane, and it is what makes the positive below
# mean something: the same command and package, differing only in what stdin is.
#
# `< <(printf ...)`, not `printf ... |`: stdin is a pipe either way, but on the
# right of a `|` this function would run in a subshell and its FAILED count would
# die with it -- a negative that could never fail the script.
install_status 5 "a piped answer is refused, not waited on" "$WORK/a1.lexe" \
  < <(printf 'y\n')
grep_out "not a file holding an answer"
assert_absent "$LEXE_HOME/apps/$ID"

step "install preview shows first-seen, not-verified, fingerprint"
install_status 0 "an answer written in a file confirms the install" \
  "$WORK/a1.lexe" < "$ANSWER_YES"
grep_out "first seen"
grep_out "not independently verified"
grep_out "Signing key fingerprint"

step "the App-ID/key binding is recorded after install"
assert_file "$LEXE_HOME/trust/$ID.json"
expect_exit 0 trust show "$ID"; grep_out "known key"

step "trust show --json: known, identity NOT verified"
"$LEXE" trust show "$ID" --json >"$TX_OUT" 2>"$TX_ERR"
grep_out '"localKeyState": *"known"'
grep_out '"identityVerified": *false'

step "same-key update reports a KNOWN key and installs"
install_status 0 "the same-key update is confirmed and installs" \
  "$WORK/a2.lexe" < "$ANSWER_YES"
grep_out "known publisher key"
expect_exit 0 run "$ID"

step "a DIFFERENT key at a higher version is refused (changed key, exit 7)"
expect_exit 7 install "$WORK/b2.lexe" --yes
[[ "$("$LEXE" trust show "$ID" --json | grep -o '"blocked": *[a-z]*')" == *false* ]] \
  && pass "not blocked, just refused" || true
# key A's version stays active and its data ownership is unchanged.
grep -q '"version": *"2.0.0"' "$LEXE_HOME/apps/$ID/installation.json" \
  && pass "key A version 2.0.0 still active" || fail "active version changed"

step "block: launch and install are refused; unblock restores launch"
expect_exit 0 trust block "$ID"
expect_exit 7 run "$ID"
expect_exit 7 install "$WORK/a2.lexe" --yes
expect_exit 0 trust unblock "$ID"
expect_exit 0 run "$ID"

step "a corrupt trust record fails closed; forget --force restores"
echo "{ corrupt" > "$LEXE_HOME/trust/$ID.json"
expect_exit 7 run "$ID"
expect_exit 7 install "$WORK/a2.lexe" --yes
expect_exit 0 trust forget "$ID" --force      # documented administrative path
expect_exit 0 run "$ID"                        # first-seen again → allowed

step "permission consent stays SEPARATE from publisher trust"
# a2 (no perms) is installed + same key. a3 requests network (an expansion):
# refused for PERMISSION reasons (exit 5), not trust — the key is still known.
"$LEXE" install "$WORK/a1.lexe" --yes >/dev/null 2>&1   # reset to a no-perm base
expect_exit 5 install "$WORK/a3net.lexe" --yes          # permission expansion
expect_exit 0 install "$WORK/a3net.lexe" --yes --accept-permissions

step "cleanup: purge forgets the trust record too"
# Was purge THEN `trust forget`: `remove --purge-data` kept the record.
assert_file "$LEXE_HOME/trust/$ID.json"   # the control: it is there to remove
expect_exit 0 purge "$ID" --yes
assert_absent "$LEXE_HOME/apps/$ID"
assert_absent "$LEXE_HOME/trust/$ID.json"
"$LEXE" trust show "$ID" --json >"$TX_OUT" 2>"$TX_ERR"
grep_out '"localKeyState": *"first-seen"'

echo
if [[ "$FAILED" -eq 0 ]]; then echo "### TRUST LIFECYCLE OK — $STEP steps"; exit 0
else echo "### TRUST LIFECYCLE FAILED — $FAILED assertion(s)"; exit 1; fi

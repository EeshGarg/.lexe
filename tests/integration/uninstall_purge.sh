#!/usr/bin/env bash
# Real-binary evidence for the uninstall/purge contract
# (docs/REFERENCE-POLICY.md, "Uninstall and purge").
#
#   lexe uninstall <id>   remove the program; keep what makes a reinstall a
#                         RETURNING installation
#   lexe purge <id>       make .LEXE forget the application
#
# tests/test_purge.cpp proves the same contract against the installer API, with
# failpoints and mutants. This drives the actual `lexe` CLI and observes it the
# way a person would: what the install PREVIEW says about the publisher key --
# "first seen" versus "explicitly trusted by you" -- is the security path, as a
# user meets it. Files on disk are the second observer.
#
# Usage:  tests/integration/uninstall_purge.sh [/path/to/lexe]

set -uo pipefail
LEXE="${1:-${LEXE_BUILD_DIR:-./build}/lexe}"
[[ -x "$LEXE" ]] || { echo "FATAL: lexe not found at $LEXE" >&2; exit 2; }
LEXE="$(readlink -f "$LEXE")"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lexe-purge.XXXXXX")"
export LEXE_HOME="$WORK/home"; mkdir -p "$LEXE_HOME"
trap 'rm -rf "$WORK"' EXIT
A="com.example.purge"          # the application under test
B="com.example.purge.v.2"      # same key as A, and A's App ID is its prefix
STEP=0; FAILED=0
OUT="$WORK/out"; ERR="$WORK/err"; : >"$OUT"; : >"$ERR"

step()  { STEP=$((STEP+1)); echo; echo "== step $STEP: $* =="; }
pass()  { echo "  PASS: $*"; }
fail()  { echo "  FAIL: $*" >&2; FAILED=$((FAILED+1)); }
# Runs lexe with stdin from $STDIN_FILE (default: /dev/null) and checks the exit.
expect_exit() { local want="$1"; shift; echo "  \$ lexe $* (expect $want)"
  "$LEXE" "$@" <"${STDIN_FILE:-/dev/null}" >"$OUT" 2>"$ERR"; local got=$?
  sed 's/^/    | /' "$OUT"; sed 's/^/    ! /' "$ERR"
  [[ "$got" == "$want" ]] && pass "exit $got" || fail "exit $got, wanted $want"; }
saw()     { [[ -n "$1" ]] || { fail "empty needle"; return; }
            grep -qF -- "$1" "$OUT" "$ERR" && pass "saw: $1" || fail "missing: $1"; }
not_saw() { [[ -n "$1" ]] || { fail "empty needle"; return; }
            grep -qF -- "$1" "$OUT" "$ERR" && fail "unexpected: $1" || pass "absent from output: $1"; }
exists()  { [[ -e "$1" ]] && pass "exists: ${1#"$WORK"/}" || fail "missing: ${1#"$WORK"/}"; }
absent()  { [[ ! -e "$1" ]] && pass "absent: ${1#"$WORK"/}" || fail "present: ${1#"$WORK"/}"; }

KEYS="$WORK/keys"; mkdir -p "$KEYS"
"$LEXE" keygen "$KEYS/K.json" >/dev/null
"$LEXE" keygen "$KEYS/K2.json" >/dev/null
pubkey() { grep -o '"publicKey": *"[^"]*"' "$1" | sed 's/.*"\([^"]*\)".*/\1/'; }

make_pkg() { # <id> <keyfile> <out>
  local id="$1" key="$2" out="$3"
  local p="$WORK/proj-$id-$RANDOM"; mkdir -p "$p/payload/bin"
  # Compiled: a native package's entrypoint must BE an ELF (payload-role stage).
  printf '#include <stdio.h>\nint main(void){puts("hi from %s");return 0;}\n' \
      "$id" > "$p/app.c"
  cc -O2 -o "$p/payload/bin/app" "$p/app.c" || {
      printf 'FATAL: no C compiler; cannot build a native payload\n' >&2; exit 2; }
  cat > "$p/lexe.json" <<EOF
{ "lexeVersion":"0.1", "id":"$id", "name":"Purge Demo", "version":"1.0.0",
  "publisher":{"name":"Same Publisher","publicKey":"$(pubkey "$key")"},
  "applicationType":"native", "architectures":["x86_64","aarch64"],
  "entrypoint":{"executable":"bin/app","arguments":[]},
  "install":{"scope":"user","mode":"bundled"}, "permissions":[] }
EOF
  "$LEXE" build "$p" -o "$out" --key "$key" >/dev/null
}

# The interactive "yes", written down: a prompt reads a terminal or a regular
# file, never a pipe (REFERENCE-POLICY §4). This is what shows the PREVIEW.
YES="$WORK/answer-yes"; printf 'y\n' > "$YES"

echo "### uninstall / purge, real binary — LEXE_HOME=$LEXE_HOME"

step "build: A and B signed by K; A' signed by a different key K2"
make_pkg "$A" "$KEYS/K.json"  "$WORK/a.lexe"
make_pkg "$B" "$KEYS/K.json"  "$WORK/b.lexe"
make_pkg "$A" "$KEYS/K2.json" "$WORK/a-k2.lexe"
exists "$WORK/a.lexe"; exists "$WORK/b.lexe"; exists "$WORK/a-k2.lexe"

step "install A with an EXPLICIT trust decision, and give it state"
expect_exit 0 install "$WORK/a.lexe" --yes --trust
mkdir -p "$LEXE_HOME/data/$A"; printf 'precious\n' > "$LEXE_HOME/data/$A/save.dat"
expect_exit 0 compat "$A" --set native
exists "$LEXE_HOME/config/apps/$A.json"

# ------------------------------------------------------------------ CASE 1
step "CASE 1: uninstall removes the program and keeps the returning state"
expect_exit 0 uninstall "$A" --yes
saw "Kept for a later reinstall"
absent "$LEXE_HOME/apps/$A"
exists "$LEXE_HOME/data/$A/save.dat"
exists "$LEXE_HOME/trust/$A.json"
exists "$LEXE_HOME/config/apps/$A.json"
expect_exit 4 run "$A"

step "CASE 1: the reinstall is a RETURNING one -- the preview says so"
STDIN_FILE="$YES" expect_exit 0 install "$WORK/a.lexe"
saw "Publisher key: explicitly trusted by you on this machine"
not_saw "Publisher key: first seen on this machine"
exists "$LEXE_HOME/data/$A/save.dat"

# ------------------------------------------------------------------ CASE 3 (setup)
step "CASE 3 setup: B, signed by the same key K, explicitly trusted, running"
expect_exit 0 install "$WORK/b.lexe" --yes --trust
"$LEXE" trust show "$B" --json > "$WORK/b-trust-before.json"
cp "$LEXE_HOME/trust/$B.json" "$WORK/b-record-before.json"
expect_exit 0 run "$B"
saw "hi from $B"

# ------------------------------------------------------------------ CASE 2
step "CASE 2: purge forgets A -- program, data, trust decision, preferences"
expect_exit 0 purge "$A" --yes
saw "Purged $A"
absent "$LEXE_HOME/apps/$A"
absent "$LEXE_HOME/data/$A"
absent "$LEXE_HOME/trust/$A.json"
absent "$LEXE_HOME/config/apps/$A.json"
absent "$LEXE_HOME/apps/.removing/$A.purge"
expect_exit 0 trust show "$A" --json
saw '"localKeyState": "first-seen"'

step "CASE 2: the reinstall is a FIRST install -- the preview says so"
STDIN_FILE="$YES" expect_exit 0 install "$WORK/a.lexe"
saw "Publisher key: first seen on this machine"
not_saw "explicitly trusted by you"
absent "$LEXE_HOME/data/$A/save.dat"

# ------------------------------------------------------------------ CASE 3
step "CASE 3: purging A left B -- same key, A's id as prefix -- untouched"
"$LEXE" trust show "$B" --json > "$WORK/b-trust-after.json"
cmp -s "$WORK/b-trust-before.json" "$WORK/b-trust-after.json" \
  && pass "B's trust, as \`trust show\` reports it, is unchanged" \
  || fail "B's trust changed: $(diff "$WORK/b-trust-before.json" "$WORK/b-trust-after.json")"
cmp -s "$WORK/b-record-before.json" "$LEXE_HOME/trust/$B.json" \
  && pass "B's trust record is byte-for-byte unchanged" \
  || fail "B's trust record was rewritten"
expect_exit 0 run "$B"
saw "hi from $B"

step "CASE 3: A did not regain trust because K is trusted for B"
expect_exit 0 trust show "$A" --json
saw '"explicitlyTrusted": false'

step "after purge, a DIFFERENT publisher's key installs as a first install"
expect_exit 0 purge "$A" --yes
STDIN_FILE="$YES" expect_exit 0 install "$WORK/a-k2.lexe"
saw "Publisher key: first seen on this machine"

# ------------------------------------------------------------------ CASE 5
step "CASE 5: the user's own files, outside .LEXE storage, survive a purge"
USERFILES="$WORK/user-home"
mkdir -p "$USERFILES/Documents" "$USERFILES/projects/$A"
printf 'export\n' > "$USERFILES/Documents/$A-export.txt"
printf 'notes\n'  > "$USERFILES/projects/$A/notes.txt"
expect_exit 0 purge "$A" --yes
saw "were not touched"
exists "$USERFILES/Documents/$A-export.txt"
exists "$USERFILES/projects/$A/notes.txt"

# ------------------------------------------------------------------ answers
step "a purged App ID is unknown again: uninstall and purge both answer 4"
expect_exit 4 uninstall "$A" --yes
expect_exit 4 purge "$A" --yes

step "\`lexe remove\` is retired: exit 2, naming both replacements"
expect_exit 2 remove "$B" --purge-data --yes
saw "lexe uninstall <id>"
saw "lexe purge <id>"
exists "$LEXE_HOME/apps/$B"     # and it removed nothing

echo
if [[ "$FAILED" -eq 0 ]]; then echo "### UNINSTALL/PURGE OK — $STEP steps"; exit 0
else echo "### UNINSTALL/PURGE FAILED — $FAILED assertion(s)"; exit 1; fi

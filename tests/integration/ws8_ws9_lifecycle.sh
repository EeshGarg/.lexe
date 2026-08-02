#!/usr/bin/env bash
# Real-binary lifecycle acceptance for runtime-trust WS8 (application data +
# uninstall lifecycle) and WS9 (concurrency locking). Drives the actual `lexe`
# CLI end to end on a real Linux host — install, run (isolated), update, run,
# rollback, garbage-collect, the three uninstall modes, retained-data key
# continuity, and a live uninstall-while-running refusal — asserting the
# storage taxonomy and lock behavior at every step.
#
# Usage:  tests/integration/ws8_ws9_lifecycle.sh /path/to/lexe [/path/to/build]
# Exits non-zero on the first failed assertion.

set -uo pipefail

LEXE="${1:-./build/lexe}"
if [[ ! -x "$LEXE" ]]; then
  echo "FATAL: lexe binary not found/executable at: $LEXE" >&2
  exit 2
fi
LEXE="$(readlink -f "$LEXE")"

WORK="$(mktemp -d /tmp/lexe-lifecycle.XXXXXX)"
export LEXE_HOME="$WORK/home"
mkdir -p "$LEXE_HOME"
ID="com.example.lifecycle"
STEP=0
FAILED=0

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

step()   { STEP=$((STEP+1)); echo; echo "== step $STEP: $* =="; }
pass()   { echo "  PASS: $*"; }
fail()   { echo "  FAIL: $*" >&2; FAILED=$((FAILED+1)); }
run()    { echo "  \$ lexe $*"; "$LEXE" "$@"; }

# Assert the exit code of a lexe invocation.
expect_exit() { # <expected> <args...>
  local want="$1"; shift
  echo "  \$ lexe $* (expect exit $want)"
  "$LEXE" "$@" >/tmp/lx.out 2>/tmp/lx.err; local got=$?
  sed 's/^/    | /' /tmp/lx.out; sed 's/^/    ! /' /tmp/lx.err
  if [[ "$got" == "$want" ]]; then pass "exit $got"; else fail "exit $got, wanted $want"; fi
}
assert_file()    { if [[ -e "$1" ]]; then pass "exists: $1"; else fail "missing: $1"; fi; }
assert_absent()  { if [[ ! -e "$1" ]]; then pass "absent: $1"; else fail "present: $1"; fi; }
assert_current() { # <version>
  local rec="$LEXE_HOME/apps/$ID/installation.json" cur=""
  if [[ -f "$rec" ]]; then
    cur="$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$rec" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
  fi
  if [[ "$cur" == "$1" ]]; then pass "current == $1"; else fail "current == '$cur', wanted $1"; fi
}

# --- build a signed project of ID at a given version -------------------------
KEYDIR="$WORK/keys"; mkdir -p "$KEYDIR"
"$LEXE" keygen "$KEYDIR/k1.json" >/dev/null
"$LEXE" keygen "$KEYDIR/k2.json" >/dev/null
pubkey() { grep -o '"publicKey": *"[^"]*"' "$1" | sed 's/.*"publicKey": *"\([^"]*\)".*/\1/'; }

make_pkg() { # <version> <keyfile> <outfile> [id]
  local ver="$1" key="$2" out="$3" id="${4:-$ID}"
  local proj="$WORK/proj-$ver-$RANDOM"
  mkdir -p "$proj/payload/bin"
  cat > "$proj/payload/bin/app.sh" <<EOF
#!/bin/sh
echo "hello from $id $ver"
exit 0
EOF
  chmod +x "$proj/payload/bin/app.sh"
  cat > "$proj/lexe.json" <<EOF
{
  "lexeVersion": "0.1",
  "id": "$id",
  "name": "Lifecycle App",
  "version": "$ver",
  "publisher": { "name": "Test", "publicKey": "$(pubkey "$key")" },
  "applicationType": "native",
  "architectures": ["x86_64", "aarch64"],
  "entrypoint": { "executable": "bin/app.sh", "arguments": [] },
  "install": { "scope": "user", "mode": "bundled" }
}
EOF
  "$LEXE" build "$proj" -o "$out" --key "$key" >/dev/null
}

echo "### WS8/WS9 real-binary lifecycle — LEXE_HOME=$LEXE_HOME"
echo "### lexe: $LEXE"

step "build signed packages v1.0.0, v2.0.0, v3.0.0 (key k1)"
make_pkg 1.0.0 "$KEYDIR/k1.json" "$WORK/v1.lexe"
make_pkg 2.0.0 "$KEYDIR/k1.json" "$WORK/v2.lexe"
make_pkg 3.0.0 "$KEYDIR/k1.json" "$WORK/v3.lexe"
assert_file "$WORK/v1.lexe"; assert_file "$WORK/v2.lexe"; assert_file "$WORK/v3.lexe"

step "install v1.0.0"
expect_exit 0 install "$WORK/v1.lexe" --yes
assert_current 1.0.0
assert_file "$LEXE_HOME/apps/$ID/versions/1.0.0"
assert_file "$LEXE_HOME/data/$ID/.lexe-data-owner"   # data-owner marker written

step "seed persistent data + cache (simulating app-created state)"
echo "user profile" > "$LEXE_HOME/data/$ID/profile.db"
mkdir -p "$LEXE_HOME/cache/apps/$ID"
echo "thumb" > "$LEXE_HOME/cache/apps/$ID/thumb.png"
assert_file "$LEXE_HOME/data/$ID/profile.db"
assert_file "$LEXE_HOME/cache/apps/$ID/thumb.png"

step "run v1.0.0 (through the isolation backend)"
expect_exit 0 run "$ID"

step "update to v2.0.0 — data and cache must survive"
expect_exit 0 install "$WORK/v2.lexe" --yes
assert_current 2.0.0
assert_file "$LEXE_HOME/data/$ID/profile.db"          # data survives update
assert_file "$LEXE_HOME/cache/apps/$ID/thumb.png"     # cache survives update

step "run v2.0.0"
expect_exit 0 run "$ID"

step "install v3.0.0 — data still intact"
expect_exit 0 install "$WORK/v3.lexe" --yes
assert_current 3.0.0
assert_file "$LEXE_HOME/data/$ID/profile.db"

step "rollback 3.0.0 -> 2.0.0 — data survives"
expect_exit 0 rollback "$ID"
assert_current 2.0.0
assert_file "$LEXE_HOME/data/$ID/profile.db"

step "rollback 2.0.0 -> 1.0.0"
expect_exit 0 rollback "$ID"
assert_current 1.0.0

step "gc --keep 1 — reclaim superseded versions, keep active + window; data intact"
expect_exit 0 gc "$ID" --keep 1
assert_file "$LEXE_HOME/apps/$ID/versions/1.0.0"      # active retained
assert_file "$LEXE_HOME/data/$ID/profile.db"          # data untouched by gc
"$LEXE" repair "$ID" >/dev/null 2>&1 && pass "active install healthy after gc" \
  || fail "active install unhealthy after gc"

step "remove --remove-cache — cache cleared, data preserved, app uninstalled"
expect_exit 0 remove "$ID" --remove-cache --yes
assert_absent "$LEXE_HOME/apps/$ID"                   # app gone
assert_absent "$LEXE_HOME/cache/apps/$ID"             # cache gone
assert_file   "$LEXE_HOME/data/$ID/profile.db"        # data preserved

step "reinstall v1.0.0 with the SAME key — retained data is reused"
expect_exit 0 install "$WORK/v1.lexe" --yes
assert_file "$LEXE_HOME/data/$ID/profile.db"          # same-owner inherits data

step "remove (app-only) — data retained for later"
expect_exit 0 remove "$ID" --yes
assert_absent "$LEXE_HOME/apps/$ID"
assert_file   "$LEXE_HOME/data/$ID/profile.db"

step "install with a DIFFERENT key — refused as a changed key (exit 7)"
# The local TRUST record (bound to key k1) persists across the app-only
# uninstall, so a different key is now a changed-key rejection (WS4) — the
# strongest form of "must not silently take over".
make_pkg 1.0.0 "$KEYDIR/k2.json" "$WORK/v1-k2.lexe"
expect_exit 7 install "$WORK/v1-k2.lexe" --yes
assert_file "$LEXE_HOME/data/$ID/profile.db"          # unchanged by the refusal

step "remove --purge-data — data deleted, but local trust history preserved"
"$LEXE" install "$WORK/v1.lexe" --yes >/dev/null 2>&1  # reinstall (same key) to remove
expect_exit 0 remove "$ID" --purge-data --yes
assert_absent "$LEXE_HOME/data/$ID"                   # data gone
assert_absent "$LEXE_HOME/apps/$ID"
assert_file   "$LEXE_HOME/trust/$ID.json"             # trust history preserved

step "a DIFFERENT publisher is STILL refused after purge (trust persists)"
expect_exit 7 install "$WORK/v1-k2.lexe" --yes

step "forget local trust, THEN a different publisher may claim the id"
expect_exit 0 trust forget "$ID"
assert_absent "$LEXE_HOME/trust/$ID.json"
expect_exit 0 install "$WORK/v1-k2.lexe" --yes
assert_current 1.0.0

step "concurrency: uninstall while running is refused (busy), not a silent kill"
# Build a long-running app under a second id, launch it in the background so its
# launcher holds the version lease, then attempt to remove it.
SLEEP_ID="com.example.sleeper"
SPROJ="$WORK/sleeper"; mkdir -p "$SPROJ/payload/bin"
cat > "$SPROJ/payload/bin/app.sh" <<'EOF'
#!/bin/sh
sleep 30
EOF
chmod +x "$SPROJ/payload/bin/app.sh"
cat > "$SPROJ/lexe.json" <<EOF
{ "lexeVersion": "0.1", "id": "$SLEEP_ID", "name": "Sleeper", "version": "1.0.0",
  "publisher": { "name": "Test", "publicKey": "$(pubkey "$KEYDIR/k1.json")" },
  "applicationType": "native", "architectures": ["x86_64","aarch64"],
  "entrypoint": { "executable": "bin/app.sh", "arguments": [] },
  "install": { "scope": "user", "mode": "bundled" } }
EOF
"$LEXE" build "$SPROJ" -o "$WORK/sleeper.lexe" --key "$KEYDIR/k1.json" >/dev/null
"$LEXE" install "$WORK/sleeper.lexe" --yes >/dev/null
"$LEXE" run "$SLEEP_ID" >/dev/null 2>&1 &
RUN_PID=$!
sleep 2  # let the launcher acquire the version lease and start the child
expect_exit 6 remove "$SLEEP_ID" --yes           # busy: a launch holds the lease
kill "$RUN_PID" 2>/dev/null; wait "$RUN_PID" 2>/dev/null || true
sleep 1
expect_exit 0 remove "$SLEEP_ID" --purge-data --yes   # succeeds once the run ends

step "purge the k2 install from step 16, then assert no orphaned files remain"
expect_exit 0 remove "$ID" --purge-data --yes
assert_absent "$LEXE_HOME/apps/$ID"
assert_absent "$LEXE_HOME/data/$ID"
assert_absent "$LEXE_HOME/apps/$SLEEP_ID"
assert_absent "$LEXE_HOME/data/$SLEEP_ID"

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "### LIFECYCLE OK — all $STEP steps passed"
  exit 0
else
  echo "### LIFECYCLE FAILED — $FAILED assertion(s) failed across $STEP steps"
  exit 1
fi

#!/usr/bin/env bash
# 10 — what the caller actually receives on stdout and stderr.
#
# A launcher's most basic promise is that the program's output reaches whoever
# ran it. This runtime broke that promise three ways at once, and all three were
# invisible to every test that existed, because they only appear when the
# caller's stdout is NOT a terminal. Under a pty the child inherits the streams
# and everything works; in a pipe, a shell substitution, a CI job or a script —
# which is how a CLI is actually used — the runtime captures the output and
# relays it, and that relay was wrong:
#
#   1. It relayed with `fputs`, which takes a C string, so it stopped at the
#      program's first NUL byte. A program emitting 8 MiB of binary data
#      delivered 163 bytes. One emitting all 256 byte values delivered NONE,
#      because byte zero is NUL. Captured in full, discarded at the last step,
#      silently.
#
#   2. It never relayed stderr at all, in any branch. A program that reports on
#      stderr and exits 0 produced nothing whatsoever — and no error record
#      either, since those are only written for a failing exit. FORMAT-0.1 §5.6
#      forbids precisely this, in these words: the application must not be left
#      "silently appearing to do nothing".
#
#   3. It withheld output whenever the program exited non-zero, because the
#      relay was the `else` of the non-zero-exit branch. For `diff`, `grep`,
#      `test` and every compiler a non-zero exit is a normal outcome and the
#      output IS the result.
#
# So: run everything here with both streams redirected to FILES. A version of
# this test that used a terminal would pass against all three defects.
#
# And `launch.mode: "console"` is LOAD-BEARING, which this test learned the
# embarrassing way. The manifest default is `gui`, and the runtime only captures
# and relays for a CONSOLE launch -- every other mode hands the child our streams
# to inherit. Without that line this test ran gui-mode launches, the child wrote
# straight to the redirected files, and the relay was never involved at all.
#
# It therefore passed 10/10 with the sandboxed stderr relay deliberately disabled
# -- including the two checks named "stderr reaches the caller on a SUCCESSFUL
# exit" and "stderr is relayed even though the application exited non-zero". A
# regression written for a defect, which did not execute the code path of that
# defect, reporting success for a reason unrelated to what it claimed to check.
# It was only found when an independent audit broke the relay on purpose and
# noticed this lane did not care.
#
# Found by putting 184 independently written programs through the runtime and
# comparing against their recorded direct-execution baselines, which is why the
# specimen here is a purpose-built program with an exactly known output rather
# than one of the examples.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

acc_begin "10 stdout/stderr relay when the caller is not a terminal"
acc_require_binaries
acc_scratch_home

APP_ID="org.lexe.tests.relay"
ACC_APP_ID="$APP_ID"        # so acc_error_dir() resolves
ACC_APP_VERSION="1.0.0"
PROJECT="$ACC_ROOT/work/relay"
mkdir -p "$PROJECT/payload/bin" "$PROJECT/src"

# argv: <stdout byte count> <exit code> <1 to also write stderr>
cat > "$PROJECT/src/main.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char** argv) {
    long n = argc > 1 ? atol(argv[1]) : 0;
    int rc = argc > 2 ? atoi(argv[2]) : 0;
    int use_err = argc > 3 && argv[3][0] == '1';
    if (n > 0) {
        char* buf = malloc((size_t)n);
        if (buf == NULL) return 99;
        /* Byte 0 is NUL by construction: a C-string relay delivers nothing. */
        for (long i = 0; i < n; ++i) buf[i] = (char)(i % 256);
        fwrite(buf, 1, (size_t)n, stdout);
        fflush(stdout);
        free(buf);
    }
    if (use_err) { fputs("STDERR_REPORT=present\n", stderr); fflush(stderr); }
    /* argv[4]: linger this many seconds, so a DETACHED launch is still
       running when the caller checks whether its pipe was released. */
    if (argc > 4) sleep((unsigned)atoi(argv[4]));
    return rc;
}
EOF

if ! cc -O1 -o "$PROJECT/payload/bin/relay" "$PROJECT/src/main.c" \
        >"$ACC_ROOT/work/cc.log" 2>&1; then
    printf '%sfatal%s: could not compile the relay specimen\n' "$ACC_RED" "$ACC_OFF" >&2
    sed 's/^/    /' "$ACC_ROOT/work/cc.log" >&2
    exit 2
fi

KEY="$ACC_ROOT/work/key.json"
"$LEXE" keygen "$KEY" >/dev/null

# One package per argument set: the arguments are in the manifest, so this also
# keeps the launch free of anything the caller could have influenced.
build_and_install() { # $1=args-json
    cat > "$PROJECT/lexe.json" <<EOF
{
  "lexeVersion": "0.1",
  "id": "$APP_ID",
  "name": "Relay Probe",
  "version": "1.0.0",
  "publisher": { "name": "Lexe Tests", "publicKey": "AUTO" },
  "applicationType": "native",
  "architectures": ["x86_64"],
  "entrypoint": { "executable": "bin/relay", "arguments": $1 },
  "launch": { "mode": "console" },
  "install": { "scope": "user", "mode": "bundled" },
  "permissions": []
}
EOF
    rm -rf "$LEXE_HOME"
    mkdir -p "$LEXE_HOME"
    "$LEXE" build "$PROJECT" -o "$ACC_ROOT/work/relay.lexe" --key "$KEY" \
        >"$ACC_ROOT/work/build.log" 2>&1 || {
        printf '%sfatal%s: lexe build failed\n' "$ACC_RED" "$ACC_OFF" >&2
        sed 's/^/    /' "$ACC_ROOT/work/build.log" >&2
        exit 2
    }
    "$LEXE" install "$ACC_ROOT/work/relay.lexe" --yes --trust \
        >"$ACC_ROOT/work/install.log" 2>&1 || {
        printf '%sfatal%s: lexe install failed\n' "$ACC_RED" "$ACC_OFF" >&2
        sed 's/^/    /' "$ACC_ROOT/work/install.log" >&2
        exit 2
    }
}

OUT="$ACC_ROOT/work/out.bin"
ERR="$ACC_ROOT/work/err.txt"

# ---------------------------------------------------------------- 1. binary
# 8 MiB through the relay, first byte NUL. Both the LENGTH and the CONTENT are
# checked: a relay that delivered the right number of wrong bytes would be a
# different bug wearing this one's clothes.
BYTES=8388608
build_and_install "[\"$BYTES\",\"0\",\"0\"]"
set +e
"$LEXE" run "$APP_ID" >"$OUT" 2>"$ERR"
rc=$?
set -e
acc_equals "$rc" "0" "a successful binary-output launch exits 0"
acc_equals "$(stat -c %s "$OUT")" "$BYTES" \
    "all $BYTES bytes of binary stdout reach the caller (NUL at offset 0)"
acc_equals "$(head -c 1 "$OUT" | od -An -tu1 | tr -d ' ')" "0" \
    "the leading NUL byte is preserved, not treated as a terminator"
# Reproduce the program's own output and compare, so nothing about the content
# is taken on trust.
"$PROJECT/payload/bin/relay" "$BYTES" 0 0 > "$ACC_ROOT/work/direct.bin"
acc_equals "$(sha256sum < "$OUT" | cut -d' ' -f1)" \
           "$(sha256sum < "$ACC_ROOT/work/direct.bin" | cut -d' ' -f1)" \
    "the relayed bytes are identical to what the program wrote directly"

# ---------------------------------------------------------------- 2. stderr
# Nothing on stdout, a report on stderr, exit 0 — the "silently appears to do
# nothing" case §5.6 names.
build_and_install '["0","0","1"]'
set +e
"$LEXE" run "$APP_ID" >"$OUT" 2>"$ERR"
rc=$?
set -e
acc_equals "$rc" "0" "a stderr-only launch exits 0"
acc_true "$(grep -q 'STDERR_REPORT=present' "$ERR" && echo 0 || echo 1)" \
    "stderr reaches the caller on a SUCCESSFUL exit (FORMAT-0.1 §5.6)" \
    "stderr was empty; the application would appear to have done nothing"

# ------------------------------------------------------- 3. non-zero exit
# A non-zero exit is a normal outcome, and the output is still the result.
build_and_install '["1024","42","1"]'
set +e
"$LEXE" run "$APP_ID" >"$OUT" 2>"$ERR"
rc=$?
set -e
acc_equals "$rc" "42" "the application's own exit code reaches the caller"
acc_equals "$(stat -c %s "$OUT")" "1024" \
    "stdout is relayed even though the application exited non-zero"
acc_true "$(grep -q 'STDERR_REPORT=present' "$ERR" && echo 0 || echo 1)" \
    "stderr is relayed even though the application exited non-zero" \
    "output was diverted into the error record instead of reaching the caller"

# The error record is ADDITIONAL, not a substitute. If this stops being true the
# relay above has quietly become the only copy.
acc_true "$([[ -d "$(acc_error_dir)" ]] && echo 0 || echo 1)" \
    "a failing launch still records a diagnostic as well as relaying output" \
    "expected an error record under $(acc_error_dir)"

# ------------------------------------------------- 4. a DETACHED service
# must not hold the caller's stdout open.
#
# The classic "backgrounded service hangs the shell that started it": a command
# substitution, a pipeline or a CI step waits for EOF on the pipe, and a detached
# child that inherited the descriptor never gives it. The runtime redirects a
# detached launch's stdio to /dev/null for exactly this reason.
#
# Checked here because an independent mutation audit removed that redirect and
# NOTHING noticed -- not the 740 unit cases, not the eleven acceptance scripts,
# not the 196-specimen corpus. A guard with no test is a guard until somebody
# tidies it away.
#
# The observation is external and needs no cooperation from the runtime: run the
# launch inside a command substitution, which blocks by definition until every
# writer closes the pipe, and give it a deadline. The service lingers well past
# that deadline, so returning promptly means the descriptor was released and
# timing out means it was not.
cat > "$PROJECT/lexe.json" <<EOF
{
  "lexeVersion": "0.1",
  "id": "$APP_ID.svc",
  "name": "Relay Probe Service",
  "version": "1.0.0",
  "publisher": { "name": "Lexe Tests", "publicKey": "AUTO" },
  "applicationType": "native",
  "architectures": ["x86_64"],
  "entrypoint": { "executable": "bin/relay", "arguments": ["0","0","0","30"] },
  "launch": { "mode": "service" },
  "install": { "scope": "user", "mode": "bundled" },
  "permissions": []
}
EOF
rm -rf "$LEXE_HOME"; mkdir -p "$LEXE_HOME"
if "$LEXE" build "$PROJECT" -o "$ACC_ROOT/work/svc.lexe" --key "$KEY" \
        >"$ACC_ROOT/work/svcbuild.log" 2>&1 &&
   "$LEXE" install "$ACC_ROOT/work/svc.lexe" --yes --trust \
        >"$ACC_ROOT/work/svcinstall.log" 2>&1; then
    svc_start="$(date +%s)"
    # `set -e` is in force, and a timeout returns 124: without the `if` the
    # script would abort here and the lane would fail with no message at all --
    # detection, but mute, which is barely better than the blind spot this check
    # was written to close.
    # `cmd || var=$?`, not `if ! cmd; then var=$?`: inside the `then` branch of a
    # negated test, $? is the status of the NEGATION (always 0), so the first
    # version recorded success for a run that had just timed out. The elapsed
    # check caught the mutant anyway, which is the argument for having two
    # independent observations of one property rather than one.
    svc_rc=0
    timeout 20 bash -c "out=\$(\"$LEXE\" run \"$APP_ID.svc\" 2>/dev/null); exit 0"         || svc_rc=$?
    svc_elapsed=$(( $(date +%s) - svc_start ))
    acc_true "$([[ $svc_rc -ne 124 ]] && echo 0 || echo 1)" \
        "a detached service releases the caller's stdout (no hang)" \
        "the command substitution never saw EOF: the detached child kept the" \
        "caller's pipe open, which hangs any shell, pipeline or CI step that" \
        "starts a service and then waits for its output"
    acc_true "$([[ $svc_elapsed -lt 15 ]] && echo 0 || echo 1)" \
        "and it returns promptly rather than waiting the service out" \
        "took ${svc_elapsed}s while the service lingers 30s"
    pkill -f "$PROJECT/payload/bin/relay" 2>/dev/null || true
else
    skip "could not build/install the service variant"
fi

acc_summary

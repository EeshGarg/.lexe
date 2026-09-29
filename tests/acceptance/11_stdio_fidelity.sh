#!/usr/bin/env bash
# 11 — the SHAPE of the streams a launched application receives.
#
# Suite 10 asks whether the caller receives the bytes. This one asks whether the
# application receives the same KIND of descriptor it would have received had
# the user run the binary directly. Those are different questions, and the
# second was answered wrongly for every caller whose stdout was not a terminal.
#
# The launcher interposed a pipe so it could retain output for `lexe errors`.
# Measured against direct execution of the same binary:
#
#   caller's stdout    direct                       through .LEXE (before)
#   ---------------    --------------------------   ----------------------
#   regular file       regular, seekable            fifo, NOT seekable
#   closed (`>&-`)     closed, write gives EBADF    fifo, and the write said "ok"
#
# The second row is the defect that matters. Closing fd 1 is how a program is
# told "produce nothing". It produced output anyway, and a program that checks
# for EBADF to notice was told its write had landed when nothing could receive
# it. The first row is quieter and still real: anything that seeks its own
# stdout -- a pager, a progress renderer, a program writing a seekable log --
# behaves differently under .LEXE than outside it, which FORMAT-0.1 §0.2 says a
# package must not be able to detect.
#
# THE OBSERVER IS DIRECT EXECUTION, NOT THE RUNTIME'S OWN REPORT. Every case
# below runs the identical binary twice -- once bare, once through `lexe run` --
# under the same caller-side redirection, and requires the two answers to match.
# A test that only asserted "stdout is regular" would be asserting this test's
# opinion; requiring equality with the bare run means the specimen cannot be
# wrong about what a normal Linux process sees, because it IS one.
#
# `launch.mode: "console"` is load-bearing here for the same reason suite 10
# records: the manifest default is `gui`, and only a console launch ever went
# near the capture path. Without it this suite would exercise nothing and pass.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

acc_begin "11 the stdio shape an application receives matches direct execution"
acc_require_binaries
acc_scratch_home

APP_ID="org.lexe.tests.stdio"
ACC_APP_ID="$APP_ID"
ACC_APP_VERSION="1.0.0"
PROJECT="$ACC_ROOT/work/stdio"
mkdir -p "$PROJECT/payload/bin" "$PROJECT/src"

# Reports what each standard descriptor IS. Everything goes to stderr except
# one deliberate write to stdout, so the report survives even when stdout is
# the thing under test -- including when it is closed.
cat > "$PROJECT/src/main.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

static const char* kind_of(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) return errno == EBADF ? "closed" : "unstattable";
    if (S_ISFIFO(st.st_mode)) return "fifo";
    if (S_ISREG(st.st_mode))  return "regular";
    if (S_ISCHR(st.st_mode))  return "chr";
    return "other";
}

int main(void) {
    fprintf(stderr, "STDOUT_KIND=%s\n", kind_of(1));
    fprintf(stderr, "STDOUT_SEEKABLE=%s\n",
            lseek(1, 0, SEEK_CUR) == (off_t)-1 ? "no" : "yes");
    fprintf(stderr, "STDERR_KIND=%s\n", kind_of(2));
    errno = 0;
    ssize_t n = write(1, "X\n", 2);
    fprintf(stderr, "WRITE_STDOUT=%s\n",
            n < 0 ? (errno == EBADF ? "EBADF" : "other-error") : "ok");
    fflush(stderr);
    return 0;
}
EOF

cc -O1 -o "$PROJECT/payload/bin/stdio-probe" "$PROJECT/src/main.c" 2>/dev/null || {
    printf '  BLOCKED: no working C compiler; the specimen cannot be built, so\n'
    printf '           direct execution cannot be compared against anything.\n'
    acc_summary
    exit 0
}
PROBE="$PROJECT/payload/bin/stdio-probe"

cat > "$PROJECT/lexe.json" <<EOF
{ "lexeVersion": "0.1", "id": "$APP_ID", "name": "Stdio Probe",
  "version": "1.0.0",
  "publisher": { "name": "LEXE Tests", "publicKey": "AUTO" },
  "applicationType": "native", "architectures": ["x86_64"],
  "entrypoint": { "executable": "bin/stdio-probe", "arguments": [] },
  "launch": { "mode": "console" },
  "install": { "scope": "user", "mode": "bundled" },
  "permissions": [] }
EOF

KEY="$ACC_ROOT/work/stdio-key.json"
PKG="$ACC_ROOT/work/stdio.lexe"
"$LEXE" keygen "$KEY" >/dev/null
"$LEXE" build "$PROJECT" -o "$PKG" --key "$KEY" >/dev/null
"$LEXE" install "$PKG" --yes --trust >/dev/null

D_ERR="$ACC_ROOT/work/direct.err"
L_ERR="$ACC_ROOT/work/lexe.err"

# ---------------------------------------------------------------------------
# 1. The caller's stdout is a REGULAR FILE.
# ---------------------------------------------------------------------------
"$PROBE"                  > "$ACC_ROOT/work/direct.out" 2> "$D_ERR" || true
"$LEXE" run "$APP_ID"     > "$ACC_ROOT/work/lexe.out"   2> "$L_ERR" || true

direct_file="$(tr '\n' ' ' < "$D_ERR")"
lexe_file="$(tr '\n' ' ' < "$L_ERR")"

acc_equals "$lexe_file" "$direct_file" \
    "stdout redirected to a file: the application sees what it sees directly"

# Stated separately so a failure names the property rather than a whole blob.
# Without this, the equality above would still hold if BOTH runs reported
# 'fifo' -- which is what a regression to the old behaviour plus a broken
# baseline would look like.
acc_contains "$direct_file" "STDOUT_KIND=regular" \
    "the direct baseline really is a regular file (else the comparison is empty)"
acc_contains "$lexe_file" "STDOUT_KIND=regular" \
    "and .LEXE does not substitute a pipe for it"
acc_contains "$lexe_file" "STDOUT_SEEKABLE=yes" \
    "a file redirected by the caller is still seekable inside the application"

# ---------------------------------------------------------------------------
# 2. The caller CLOSED fd 1. This is the case with teeth.
# ---------------------------------------------------------------------------
( exec "$PROBE" >&- ) 2> "$D_ERR" || true
( exec "$LEXE" run "$APP_ID" >&- ) 2> "$L_ERR" || true

direct_closed="$(tr '\n' ' ' < "$D_ERR")"
lexe_closed="$(tr '\n' ' ' < "$L_ERR")"

acc_equals "$lexe_closed" "$direct_closed" \
    "stdout closed by the caller: the application sees what it sees directly"
acc_contains "$direct_closed" "WRITE_STDOUT=EBADF" \
    "the direct baseline really does get EBADF (else this case proves nothing)"
acc_contains "$lexe_closed" "STDOUT_KIND=closed" \
    "a closed descriptor is not replaced with a pipe"
acc_contains "$lexe_closed" "WRITE_STDOUT=EBADF" \
    "a write to it fails, rather than being told it landed"

# ---------------------------------------------------------------------------
# 3. The caller's stdout is a PIPE. This case is still captured, deliberately:
#    a pipe replacing a pipe is indistinguishable, so retention for
#    `lexe errors` costs nothing observable. Asserting it keeps the narrowing
#    honest -- without it, "never capture anything" would pass everything above.
# ---------------------------------------------------------------------------
#    Note the redirection order. An earlier version wrote `2>&1 >/dev/null`,
#    which sends stderr to the CURRENT stdout and only then points stdout at
#    /dev/null -- so the probe's stdout was a character device and both runs
#    reported `chr`. They agreed with each other, so an equality-only check
#    would have passed; the "is the baseline really a fifo" guard below is what
#    caught it. That guard exists for precisely this, and it earned its place
#    on the first run.
"$PROBE"              2> "$D_ERR" | cat > /dev/null
"$LEXE" run "$APP_ID" 2> "$L_ERR" | cat > /dev/null
direct_pipe="$(tr '\n' ' ' < "$D_ERR")"
lexe_pipe="$(tr '\n' ' ' < "$L_ERR")"

acc_contains "$direct_pipe" "STDOUT_KIND=fifo" \
    "the direct baseline through a pipe reports a fifo"
acc_contains "$lexe_pipe" "STDOUT_KIND=fifo" \
    "and so does .LEXE, which is why interposing there is permitted"

acc_summary

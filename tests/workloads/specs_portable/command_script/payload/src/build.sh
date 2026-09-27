#!/bin/sh
# The build, as a shell script rather than a Makefile. `build.command` in the
# manifest is ["sh", "build.sh"], an argv and not a shell string, so there is no
# second quoting language between the manifest and exec.
#
# Deliberately ordinary in every way that matters: it respects $CC if set, it
# creates its output directory, it reports what it did, and it exits non-zero if
# the compiler failed rather than pretending.
set -eu

CC=${CC:-cc}
CFLAGS=${CFLAGS:--O2 -Wall -Wextra}
BINDIR=../bin
TARGET="$BINDIR/portable-command-driver"

echo "build.sh: starting in $(pwd)"
echo "build.sh: CC=$CC"
mkdir -p "$BINDIR"

# shellcheck disable=SC2086
$CC $CFLAGS -DBUILT_BY_MARKER='"built-by-build-sh"' -o "$TARGET" main.c

echo "build.sh: produced $TARGET"
ls -l "$TARGET"

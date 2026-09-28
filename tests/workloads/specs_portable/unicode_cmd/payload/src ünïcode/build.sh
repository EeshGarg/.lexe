#!/bin/sh
# The build of a package whose paths contain spaces and non-ASCII characters.
#
# A Makefile is the wrong tool here and the corpus says so elsewhere: make splits
# its prerequisite lists on whitespace and has no quoting that survives it, so a
# target called `../bin/pörtable unicode` is two targets. A script can quote, so
# this build is a script, and every single path below is quoted.
#
# `set -eu` and nothing clever: the point of the specimen is the paths, and a
# build that was also doing something interesting would not isolate them.
set -eu

CC=${CC:-cc}
CFLAGS=${CFLAGS:--O2 -Wall -Wextra}
BINDIR="../bin"
TARGET="$BINDIR/pörtable unicode"

echo "build.sh: building in $(pwd)"
mkdir -p "$BINDIR"

# shellcheck disable=SC2086
$CC $CFLAGS -c -o "shared ütil.o" "shared ütil.c"
# shellcheck disable=SC2086
$CC $CFLAGS -o "$TARGET" "héllo wörld.c" "shared ütil.o"

echo "build.sh: produced $TARGET"
ls -l "$TARGET"

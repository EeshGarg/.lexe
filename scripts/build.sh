#!/bin/sh
# Lexe one-shot Linux build (ARCHITECTURE.md #Build).
# Usage: build.sh [build-dir-name]   (default: build)
# Configures + builds + runs ctest. Exits non-zero on any failure.
set -eu

BUILD_DIR="${1:-build}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

if command -v ninja >/dev/null 2>&1; then
    GEN="-G Ninja"
else
    GEN=""
fi

# shellcheck disable=SC2086
cmake -S "$REPO" -B "$REPO/$BUILD_DIR" $GEN -DCMAKE_BUILD_TYPE=Release
cmake --build "$REPO/$BUILD_DIR"
ctest --test-dir "$REPO/$BUILD_DIR" --output-on-failure

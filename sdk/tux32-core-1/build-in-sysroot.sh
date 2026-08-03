#!/bin/sh
# Build a project against the Tux32 Core 1 baseline by compiling INSIDE a
# container whose glibc is no newer than the ceiling (2.31). The build host's
# newer glibc never becomes the compatibility target: a compiler cannot import
# symbols the sysroot's glibc does not define.
#
# This is a MINIMAL reference, not a packaged SDK toolchain. It uses rootless
# podman and, by default, debian:11 (glibc 2.31) as the Core 1 sysroot — the
# same baseline the cross-distribution proof installs and launches on.
#
# Usage:
#   build-in-sysroot.sh <project-dir> [make-target]
#
# Environment:
#   TUX32_SYSROOT_IMAGE   image to build in       (default: debian:11)
#   CONTAINER             container CLI to use     (default: podman)
#
# After it builds, ALWAYS confirm the result:
#   lexe sdk verify <project-dir>
set -eu

PROJECT="${1:?usage: build-in-sysroot.sh <project-dir> [make-target]}"
TARGET="${2:-}"
IMAGE="${TUX32_SYSROOT_IMAGE:-docker.io/library/debian:11}"
CONTAINER="${CONTAINER:-podman}"

PROJECT_ABS=$(cd "$PROJECT" && pwd)

# PKG_CONFIG_LIBDIR is pinned to the sysroot's own directories (and
# PKG_CONFIG_PATH cleared) so a newer host library can never leak into the build
# and silently raise the symbol floor. A minimal C toolchain is installed inside
# the sysroot if absent.
"$CONTAINER" run --rm \
  -v "$PROJECT_ABS:/src" -w /src \
  -e PKG_CONFIG_LIBDIR=/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig \
  -e PKG_CONFIG_PATH= \
  "$IMAGE" sh -eu -c '
    if ! command -v cc >/dev/null 2>&1; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq --no-install-recommends build-essential >/dev/null
    fi
    echo "sysroot toolchain: $(cc --version | head -1)"
    echo "sysroot glibc:     $(getconf GNU_LIBC_VERSION)"
    make '"$TARGET"'
  '

echo
echo "Built in $IMAGE (Tux32 Core 1 sysroot)."
echo "Now verify:  lexe sdk verify \"$PROJECT_ABS\""

#!/bin/sh
# =============================================================================
# Build, test-install and package a prebuilt Linux release tarball.
#
# Usage:   scripts/package-release.sh [OUTDIR]        (default: dist)
# Output:  OUTDIR/lexe-<version>-linux-<arch>.tar.gz
#          OUTDIR/SHA256SUMS            (covers every file in OUTDIR)
#
# What it guarantees before it writes a digest:
#   1. the tree was built Release with libstdc++/libgcc linked statically, so
#      the shipped `lexe` needs only glibc from the host (checked with ldd);
#   2. the full unit suite passed on exactly that build (skip with
#      LEXE_SKIP_TESTS=1 only when a prior CI step already ran it);
#   3. the tarball was EXTRACTED to a scratch directory and the shipped
#      installer was run against it under a throw-away $HOME — what users get
#      is what was tested, not the build tree;
#   4. the archive is reproducible: fixed member order, owner 0, mtime taken
#      from the commit (SOURCE_DATE_EPOCH), gzip without a timestamp.
#
# It never tags, pushes or publishes anything.
# =============================================================================
set -eu

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$REPO/dist}"
BUILD="${LEXE_RELEASE_BUILD:-$REPO/build-release}"
ARCH="$(uname -m)"
[ "$(uname -s)" = Linux ] || { echo "error: Linux only" >&2; exit 1; }

die() { printf 'error: %s\n' "$1" >&2; exit 1; }
command -v cmake >/dev/null 2>&1 || die "cmake is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
command -v tar >/dev/null 2>&1 || die "tar is required"

if command -v ninja >/dev/null 2>&1; then GEN="-G Ninja"; else GEN=""; fi

# Reproducible timestamp: the commit, else an explicit override, else now.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH="$(git -C "$REPO" log -1 --format=%ct 2>/dev/null || date +%s)"
fi
export SOURCE_DATE_EPOCH

echo "== configure (Release, static libstdc++)"
# shellcheck disable=SC2086
cmake -S "$REPO" -B "$BUILD" $GEN -DCMAKE_BUILD_TYPE=Release \
      -DLEXE_STATIC_RUNTIME=ON >/dev/null
echo "== build"
cmake --build "$BUILD" >/dev/null

if [ "${LEXE_SKIP_TESTS:-0}" != 1 ]; then
    echo "== test"
    ctest --test-dir "$BUILD" --output-on-failure >/dev/null \
        || die "the test suite failed on the release build; nothing was packaged"
fi

VERSION="$("$BUILD/lexe" version --json | sed -n 's/.*"runtime"[^"]*"\([^"]*\)".*/\1/p' | head -n1)"
[ -n "$VERSION" ] || VERSION="$("$BUILD/lexe" version | sed -n '1s/[^0-9]*\([0-9][^ ]*\).*/\1/p')"
[ -n "$VERSION" ] || die "could not read the runtime version from the built binary"
NAME="lexe-$VERSION-linux-$ARCH"

echo "== stage $NAME"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/$NAME"
cmake --install "$BUILD" --prefix "$ROOT" >/dev/null
mkdir -p "$ROOT/packaging"
cp "$REPO"/packaging/install.sh "$REPO"/packaging/uninstall.sh \
   "$REPO"/packaging/lexe-builder.desktop "$REPO"/packaging/README.md \
   "$ROOT/packaging/"
cat >"$ROOT/install.sh" <<'WRAP'
#!/bin/sh
# Per-user install of the binaries in this archive. No root. See packaging/README.md.
here="$(cd "$(dirname "$0")" && pwd)"
exec "$here/packaging/install.sh" "$here/bin"
WRAP
chmod 755 "$ROOT/install.sh" "$ROOT"/packaging/*.sh

# Only glibc may be required of the host.
if ldd "$ROOT/bin/lexe" 2>/dev/null | grep -E 'libstdc\+\+|libgcc_s' >/dev/null; then
    die "bin/lexe still links libstdc++/libgcc dynamically"
fi

echo "== archive"
mkdir -p "$OUT"
TAR="$OUT/$NAME.tar.gz"
( cd "$STAGE" && find "$NAME" -print | LC_ALL=C sort |
  tar --no-recursion --owner=0 --group=0 --numeric-owner \
      --mtime="@$SOURCE_DATE_EPOCH" -cf - -T - ) | gzip -9n >"$TAR"

echo "== verify what shipped (extract, install under a scratch HOME, run)"
CHECK="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$CHECK"' EXIT
tar -xzf "$TAR" -C "$CHECK"
SCRATCH="$CHECK/home"; mkdir -p "$SCRATCH"
HOME="$SCRATCH" XDG_DATA_HOME="$SCRATCH/.local/share" LEXE_HOME="$SCRATCH/lexe" \
    "$CHECK/$NAME/install.sh" >/dev/null 2>&1 || die "the shipped installer failed"
"$SCRATCH/.local/bin/lexe" version >/dev/null || die "the installed lexe does not run"
echo "   shipped binary: $("$CHECK/$NAME/bin/lexe" version | head -n1)"

( cd "$OUT" && sha256sum -- *.tar.gz *.zip 2>/dev/null >SHA256SUMS || sha256sum -- *.tar.gz >SHA256SUMS )
echo "== done"
cat "$OUT/SHA256SUMS"

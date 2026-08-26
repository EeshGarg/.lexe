#!/bin/sh
# =============================================================================
# Fetch the source archives GitHub generates for a tag and write SHA256SUMS.
#
# The release is source-only (docs/ALPHA.md#release-artifacts): GitHub builds
# the .tar.gz and .zip itself from the tag, so the checksums can only be taken
# after the tag is pushed, and they must be taken from the SAME bytes the
# release actually serves — not from a local `git archive`, which can differ in
# mtimes, compression and prefix and would publish a digest nobody can
# reproduce.
#
# Usage:   scripts/release-checksums.sh [TAG] [OUTDIR]
#          (defaults: TAG=v0.1.0-alpha.1, OUTDIR=dist)
# Output:  OUTDIR/lexe-<version>.tar.gz, .zip, and SHA256SUMS beside them.
# Exit:    0 only if both archives downloaded and both digests were written.
# =============================================================================
set -eu

TAG="${1:-v0.1.0-alpha.1}"
OUT="${2:-dist}"
REPO="${LEXE_REPO:-EeshGarg/.lexe}"
VER=${TAG#v}                                  # v0.1.0-alpha.1 -> 0.1.0-alpha.1

die() { printf 'error: %s\n' "$1" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required (coreutils)"

mkdir -p "$OUT"

fetch() {
    url="$1"; dest="$2"
    printf '  fetching %s\n' "$(basename "$dest")"
    # --fail so an HTML 404 page is never silently checksummed as an archive.
    curl -fsSL --retry 3 --retry-delay 2 -o "$dest" "$url" \
        || die "could not download $url — is the tag '$TAG' pushed?"
    [ -s "$dest" ] || die "$dest is empty"
}

fetch "https://github.com/$REPO/archive/refs/tags/$TAG.tar.gz" "$OUT/lexe-$VER.tar.gz"
fetch "https://github.com/$REPO/archive/refs/tags/$TAG.zip"    "$OUT/lexe-$VER.zip"

# Verify they are what they claim to be before publishing a digest for them.
gzip -t "$OUT/lexe-$VER.tar.gz" 2>/dev/null || die "the .tar.gz is not valid gzip"
if command -v unzip >/dev/null 2>&1; then
    unzip -tqq "$OUT/lexe-$VER.zip" >/dev/null 2>&1 || die "the .zip is not a valid archive"
fi

# Digests are taken over the bare filenames, so `sha256sum -c SHA256SUMS` works
# for anyone who downloads the two files into one directory.
( cd "$OUT" && sha256sum "lexe-$VER.tar.gz" "lexe-$VER.zip" > SHA256SUMS )

printf '\n%s\n' "SHA256SUMS ($OUT/SHA256SUMS):"
sed 's/^/  /' "$OUT/SHA256SUMS"
printf '\nAttach all three files to the GitHub release for %s.\n' "$TAG"

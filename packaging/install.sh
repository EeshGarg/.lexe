#!/usr/bin/env bash
#
# install.sh — install the Lexe runtime for the current user and wire up the
# desktop so double-clicking a .lexe file opens the graphical installer.
#
# Usage: ./packaging/install.sh [build-dir]
#   build-dir  directory holding the built binaries (default: ./build)
#
# Installs, per-user (no root required):
#   * lexe, lexe-installer, lexe-builder  -> ~/.local/bin
#   * lexe-installer.desktop, lexe-builder.desktop
#                                         -> ~/.local/share/applications
#   * application-x-lexe.xml (MIME def)   -> ~/.local/share/mime/packages
# then refreshes the MIME/desktop databases and sets lexe-installer as the
# default handler for application/x-lexe. Safe to re-run (idempotent).

set -euo pipefail

# ----------------------------------------------------------------- locations
# Directory this script lives in, so it can find the shipped .desktop/.xml
# files regardless of the caller's working directory.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

build_dir="${1:-build}"

bin_dir="${XDG_BIN_HOME:-$HOME/.local/bin}"
data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
applications_dir="$data_home/applications"
mime_packages_dir="$data_home/mime/packages"
mime_dir="$data_home/mime"

binaries=(lexe lexe-installer lexe-builder)

# ------------------------------------------------------------------- checks
if [ ! -d "$build_dir" ]; then
    echo "error: build directory not found: $build_dir" >&2
    echo "       build the runtime first, e.g.:" >&2
    echo "         cmake -S . -B build -G Ninja -DLEXE_BUILD_GUI=ON" >&2
    echo "         cmake --build build" >&2
    echo "       then re-run: $0 [build-dir]" >&2
    exit 1
fi

missing=0
for bin in "${binaries[@]}"; do
    if [ ! -x "$build_dir/$bin" ]; then
        echo "error: missing built binary: $build_dir/$bin" >&2
        missing=1
    fi
done
if [ "$missing" -ne 0 ]; then
    echo "       build the runtime first, e.g.:" >&2
    echo "         cmake -S . -B build -G Ninja -DLEXE_BUILD_GUI=ON" >&2
    echo "         cmake --build build" >&2
    exit 1
fi

# The runtime links libsodium dynamically (the Ed25519 provider). Warn early if
# it is missing rather than failing cryptically at first launch.
if command -v ldconfig >/dev/null 2>&1; then
    if ! ldconfig -p 2>/dev/null | grep -q 'libsodium\.so'; then
        echo "warning: libsodium runtime library not found." >&2
        echo "         install it, e.g.:  sudo apt install libsodium23" >&2
    fi
fi

# ------------------------------------------------------------ install binaries
mkdir -p "$bin_dir"
for bin in "${binaries[@]}"; do
    cp -f "$build_dir/$bin" "$bin_dir/$bin"
    chmod +x "$bin_dir/$bin"
    echo "installed $bin_dir/$bin"
done

# --------------------------------------------------------- desktop + MIME wiring
mkdir -p "$applications_dir" "$mime_packages_dir"

cp -f "$script_dir/lexe-installer.desktop" \
    "$applications_dir/lexe-installer.desktop"
echo "installed $applications_dir/lexe-installer.desktop"

cp -f "$script_dir/lexe-builder.desktop" \
    "$applications_dir/lexe-builder.desktop"
echo "installed $applications_dir/lexe-builder.desktop"

cp -f "$script_dir/application-x-lexe.xml" \
    "$mime_packages_dir/application-x-lexe.xml"
echo "installed $mime_packages_dir/application-x-lexe.xml"

# Refresh the shared databases (best-effort: absent tools are not an error).
if command -v update-mime-database >/dev/null 2>&1; then
    update-mime-database "$mime_dir" || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$applications_dir" || true
fi

# Make double-clicking a .lexe open the graphical installer (best-effort).
if command -v xdg-mime >/dev/null 2>&1; then
    xdg-mime default lexe-installer.desktop application/x-lexe || true
    echo "set lexe-installer.desktop as the default handler for application/x-lexe"
else
    echo "note: xdg-mime not found; skipped setting the default .lexe handler" >&2
fi

# ------------------------------------------------------------------ next steps
cat <<'BANNER'

      __
     / /__  _  _____
    / / _ \| |/_/ _ \
   / /  __/>  </  __/
  /_/\___/_/|_|\___/

  Linux applications, made simple.

BANNER

echo "Installed:"
echo "  [ok] Runtime          (lexe)"
echo "  [ok] Builder          (lexe-builder)"
echo "  [ok] Installer        (lexe-installer)"
echo "  [ok] MIME type        (application/x-lexe)"
echo "  [ok] Desktop handler  (double-click a .lexe file)"
echo
echo "Welcome to .lexe."
echo
echo "  Build applications:    lexe-builder"
echo "  Install applications:  lexe install App.lexe"
echo "  Explore the CLI:       lexe help"

case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *)
        echo
        echo "note: $bin_dir is not on your PATH. Add it so the 'lexe' commands"
        echo "      resolve, e.g. add to your ~/.bashrc or ~/.profile:"
        echo "        export PATH=\"\$HOME/.local/bin:\$PATH\""
        ;;
esac

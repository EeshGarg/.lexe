#!/usr/bin/env bash
#
# install.sh — install the .LEXE runtime for the current user.
#
# Usage: ./packaging/install.sh [build-dir]
#   build-dir  directory holding the built binaries (default: ./build)
#
# Installs, per-user (no root required):
#   * lexe, lexe-ui, lexe-builder  -> ~/.local/bin
#   * lexe-builder.desktop         -> ~/.local/share/applications
# and then hands desktop registration to the runtime itself:
#   * lexe integrate
#
# That last step matters architecturally. The .LEXE handler, the MIME type and
# the default .lexe association are owned by ONE implementation — the runtime —
# so there is exactly one thing to verify and repair afterwards:
#
#   lexe doctor            what is registered, and what is missing or stale
#   lexe doctor --repair   put it back
#
# A shell script that hand-rolled the same registration would be a second,
# silently diverging copy of it. Safe to re-run (idempotent).

set -euo pipefail

# ----------------------------------------------------------------- locations
# Directory this script lives in, so it can find the shipped .desktop files
# regardless of the caller's working directory.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

build_dir="${1:-build}"

bin_dir="${XDG_BIN_HOME:-$HOME/.local/bin}"
# Desktop registration goes to the XDG user dirs a desktop actually scans, and
# is deliberately NOT derived from LEXE_HOME: an entry written anywhere else
# registers nothing. (`lexe integrate` confines itself to LEXE_HOME when that is
# set, since it is also what the tests and demos use to stay out of the real
# profile — it reports that instead of claiming a registration. See README.md.)
data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
applications_dir="$data_home/applications"

# lexe is required; the GUIs are built only when GTK 3 is available.
required_binaries=(lexe)
optional_binaries=(lexe-ui lexe-builder)

# --------------------------------------------------------------- presentation
step_total=4
step() { printf '\n[%d/%d] %s\n' "$1" "$step_total" "$2"; }
ok()   { printf '   ok  %s\n' "$1"; }
note() { printf '   --  %s\n' "$1"; }

cat <<'BANNER'
      __
     / /__  _  _____
    / / _ \| |/_/ _ \
   / /  __/>  </  __/
  /_/\___/_/|_|\___/   installing the .lexe runtime (per-user, no root)
BANNER

# ------------------------------------------------------------------- checks
step 1 "Checking the build"
if [ ! -d "$build_dir" ]; then
    echo "error: build directory not found: $build_dir" >&2
    echo "       build the runtime first, e.g.:" >&2
    echo "         cmake -S . -B build -G Ninja -DLEXE_BUILD_GUI=ON" >&2
    echo "         cmake --build build" >&2
    echo "       then re-run: $0 [build-dir]" >&2
    exit 1
fi

missing=0
for bin in "${required_binaries[@]}"; do
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
        echo "         Fedora:        sudo dnf install libsodium" >&2
        echo "         Debian/Ubuntu: sudo apt install libsodium23" >&2
        echo "         Arch:          sudo pacman -S libsodium" >&2
    fi
fi

# ------------------------------------------------------------ install binaries
step 2 "Installing binaries to $bin_dir"
mkdir -p "$bin_dir"
installed_gui=0
for bin in "${required_binaries[@]}"; do
    install -m 755 "$build_dir/$bin" "$bin_dir/$bin"
    ok "$bin"
done
for bin in "${optional_binaries[@]}"; do
    if [ -x "$build_dir/$bin" ]; then
        install -m 755 "$build_dir/$bin" "$bin_dir/$bin"
        ok "$bin"
        installed_gui=1
    else
        note "$bin not built (GTK 3 development files absent) — skipping"
    fi
done

# --------------------------------------------------------- desktop + MIME wiring
step 3 "Registering desktop integration"
mkdir -p "$applications_dir"

if [ -f "$script_dir/lexe-builder.desktop" ] && [ "$installed_gui" -eq 1 ]; then
    install -m 644 "$script_dir/lexe-builder.desktop" \
        "$applications_dir/lexe-builder.desktop"
    ok "lexe-builder.desktop"
fi

# The runtime owns the handler, the MIME type and the default association.
# Run the freshly installed copy so the registration matches the binary that
# will actually handle the files.
if "$bin_dir/lexe" integrate; then
    ok "handler, MIME type and default .lexe association"
else
    echo "warning: 'lexe integrate' did not complete; run 'lexe doctor' for" >&2
    echo "         details and 'lexe doctor --repair' to retry." >&2
fi

# The alpha shipped a separate lexe-installer binary and desktop entry. The
# consumer frontend is now lexe-ui and the handler entry is lexe-handler.desktop,
# so remove the superseded ones rather than leaving two things claiming .lexe.
for stale in "$applications_dir/lexe-installer.desktop" \
             "$bin_dir/lexe-installer" \
             "$data_home/mime/packages/application-x-lexe.xml"; do
    if [ -e "$stale" ]; then
        rm -f "$stale"
        note "removed superseded $stale"
    fi
done
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$applications_dir" || true
fi

# ------------------------------------------------------------------- verify
step 4 "Verifying the installation"
if "$bin_dir/lexe" doctor; then
    :
else
    echo
    echo "note: 'lexe doctor' reported problems above. Fix them with:" >&2
    echo "        lexe doctor --repair" >&2
fi

# ------------------------------------------------------------------ next steps
echo
echo "Done — the .lexe runtime is installed for $(id -un)."
echo
echo "  Runtime      lexe            the source of truth for every operation"
if [ "$installed_gui" -eq 1 ]; then
echo "  Applications lexe-ui         install, launch, compatibility, diagnostics"
echo "  Builder      lexe-builder    build and sign your own .lexe packages"
fi
echo
echo "Try it:"
echo "  Install an app:    lexe install App.lexe      (or just double-click it)"
echo "  Launch it:         lexe run <app-id>"
echo "  See what you have: lexe apps"
echo "  Check the system:  lexe doctor"
echo "  Explore the CLI:   lexe help"
echo
echo "Everything installs under your home directory. Nothing needs root, and"
echo "uninstalling the runtime never removes apps you installed, their data, or"
echo "your trust records — see packaging/uninstall.sh."

case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *)
        echo
        echo "note: $bin_dir is not on your PATH. Add it so the 'lexe' commands"
        echo "      resolve, e.g. add to your ~/.bashrc or ~/.profile:"
        echo "        export PATH=\"\$HOME/.local/bin:\$PATH\""
        ;;
esac

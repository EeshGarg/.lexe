#!/usr/bin/env bash
#
# uninstall.sh — reverse packaging/install.sh: remove the Lexe binaries,
# desktop entries and MIME definition installed for the current user, then
# refresh the databases. Safe to re-run (missing files are ignored).
#
# Usage: ./packaging/uninstall.sh

set -euo pipefail

bin_dir="${XDG_BIN_HOME:-$HOME/.local/bin}"
data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
applications_dir="$data_home/applications"
mime_packages_dir="$data_home/mime/packages"
mime_dir="$data_home/mime"

binaries=(lexe lexe-installer lexe-builder)

remove() {
    if [ -e "$1" ]; then
        rm -f "$1"
        echo "   removed $1"
    fi
}

echo "Removing the .lexe runtime for $(id -un) (per-user; nothing else is touched)…"

# Drop the default-handler association (best-effort) before removing files.
if command -v xdg-mime >/dev/null 2>&1; then
    current="$(xdg-mime query default application/x-lexe 2>/dev/null || true)"
    if [ "$current" = "lexe-installer.desktop" ]; then
        # No portable "unset"; point the type at nothing to clear our default.
        xdg-mime default "" application/x-lexe >/dev/null 2>&1 || true
    fi
fi

for bin in "${binaries[@]}"; do
    remove "$bin_dir/$bin"
done

remove "$applications_dir/lexe-installer.desktop"
remove "$applications_dir/lexe-builder.desktop"
remove "$mime_packages_dir/application-x-lexe.xml"

# Refresh the shared databases (best-effort: absent tools are not an error).
if command -v update-mime-database >/dev/null 2>&1; then
    update-mime-database "$mime_dir" || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$applications_dir" || true
fi

echo
echo "Lexe runtime uninstalled (binaries, desktop entries and MIME type removed)."
echo
echo "Left untouched — on purpose:"
echo "  * Installed applications and their data under"
echo "    \${LEXE_HOME:-\${XDG_DATA_HOME:-~/.local/share}/lexe}."
echo "  * Local publisher-trust records."
echo
echo "Nothing you installed or created is removed without your explicit intent."
echo "To remove an application and its data, use the runtime BEFORE uninstalling:"
echo "  lexe remove <app-id> --purge-data"
echo "Or delete the data directory above by hand."

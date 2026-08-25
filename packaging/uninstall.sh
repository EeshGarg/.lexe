#!/usr/bin/env bash
#
# uninstall.sh — reverse packaging/install.sh: remove the Lexe binaries,
# desktop entries and MIME definition installed for the current user, then
# refresh the databases. Safe to re-run (missing files are ignored).
#
# It removes exactly the files `lexe integrate` and install.sh create, in both
# places they can land:
#   * $XDG_DATA_HOME (default ~/.local/share) — where a real run registers;
#   * $LEXE_HOME, when that is set — where `lexe integrate` confines its writes
#     instead, because LEXE_HOME is also how the tests and demos keep out of
#     your profile. Leaving that copy behind while reporting the MIME type
#     removed is the same untruth in reverse.
#
# Usage: ./packaging/uninstall.sh

set -euo pipefail

bin_dir="${XDG_BIN_HOME:-$HOME/.local/bin}"
data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
applications_dir="$data_home/applications"
mime_packages_dir="$data_home/mime/packages"

binaries=(lexe lexe-installer lexe-builder)

# Counted so the closing summary can report what actually happened. Announcing
# "desktop entries and MIME type removed" on a machine where none were present
# is the same kind of claim this uninstall exists to avoid.
removed_count=0
missing_count=0

remove() {
    if [ -e "$1" ] || [ -L "$1" ]; then
        rm -f "$1"
        echo "   removed $1"
        removed_count=$((removed_count + 1))
    else
        missing_count=$((missing_count + 1))
    fi
}

# The refresh tools error out on directories that do not exist ("Directory
# '…/mime/packages' does not exist!"), which on a clean machine buried the
# actual result in noise. Only refresh what is there.
refresh_databases() {
    if [ -d "$1/mime/packages" ] && command -v update-mime-database >/dev/null 2>&1; then
        update-mime-database "$1/mime" || true
    fi
    if [ -d "$1/applications" ] && command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "$1/applications" || true
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
refresh_databases "$data_home"

# The confined copy, if LEXE_HOME is set. Only the runtime's own two files:
# `lexe-<id>.desktop` entries belong to installed applications and are removed
# by `lexe remove <id>`, never by uninstalling the runtime.
#
# No database refresh here, deliberately. Those caches exist for a desktop, and
# nothing scans a confined tree, so the runtime does not build them there —
# running update-mime-database on it would CREATE a dozen cache files (mime.cache,
# globs, magic, …) as a side effect of an uninstall, and print a "not in the
# search path" warning while doing it.
if [ -n "${LEXE_HOME:-}" ] && [ "$LEXE_HOME" != "$data_home" ]; then
    remove "$LEXE_HOME/applications/lexe-installer.desktop"
    remove "$LEXE_HOME/mime/packages/application-x-lexe.xml"
fi

echo
if [ "$removed_count" -eq 0 ]; then
    echo "Nothing to remove — the .lexe runtime was not installed for this user."
    echo "(Looked under $bin_dir, $applications_dir and $mime_packages_dir.)"
else
    echo "Lexe runtime uninstalled: $removed_count file(s) removed, each listed above."
    if [ "$missing_count" -gt 0 ]; then
        echo "($missing_count other file(s) this script knows about were already absent.)"
    fi
fi
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

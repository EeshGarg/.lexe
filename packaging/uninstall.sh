#!/usr/bin/env bash
#
# uninstall.sh — reverse packaging/install.sh: deregister the .LEXE handler and
# remove the runtime binaries and desktop entries installed for the current
# user. Safe to re-run (missing files are ignored).
#
# Usage: ./packaging/uninstall.sh
#
# Deregistration is delegated to `lexe integrate --remove`, which owns the
# handler entry, the MIME declaration and the default association — the same
# implementation that created them. It deliberately leaves per-application
# entries alone: removing the runtime must not silently deregister
# applications you still have installed.

set -euo pipefail

bin_dir="${XDG_BIN_HOME:-$HOME/.local/bin}"
data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
applications_dir="$data_home/applications"
mime_dir="$data_home/mime"

# lexe-installer is the alpha's name for the consumer frontend; it is removed
# too so an upgrade does not leave a stale binary behind.
binaries=(lexe lexe-ui lexe-builder lexe-installer)

remove() {
    if [ -e "$1" ]; then
        rm -f "$1"
        echo "   removed $1"
    fi
}

echo "Removing the .lexe runtime for $(id -un) (per-user; nothing else is touched)…"

# Deregister BEFORE removing the binary that knows how to do it.
if [ -x "$bin_dir/lexe" ]; then
    "$bin_dir/lexe" integrate --remove || true
elif command -v lexe >/dev/null 2>&1; then
    lexe integrate --remove || true
fi

for bin in "${binaries[@]}"; do
    remove "$bin_dir/$bin"
done

remove "$applications_dir/lexe-builder.desktop"
# Superseded alpha-era files, removed if an older install left them behind.
remove "$applications_dir/lexe-installer.desktop"
remove "$data_home/mime/packages/application-x-lexe.xml"

# Refresh the shared databases (best-effort: absent tools are not an error).
if command -v update-mime-database >/dev/null 2>&1; then
    update-mime-database "$mime_dir" || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$applications_dir" || true
fi

echo
echo "Lexe runtime uninstalled (binaries, desktop entries and the .lexe handler)."
echo
echo "Left untouched — on purpose:"
echo "  * Installed applications and their data under"
echo "    \${LEXE_HOME:-\${XDG_DATA_HOME:-~/.local/share}/lexe}."
echo "  * Per-application menu entries and run.lexe launch references."
echo "  * Local publisher-trust records."
echo "  * Diagnostics under \${XDG_STATE_HOME:-~/.local/state}/lexe."
echo "  * Compatibility preferences under \${XDG_CONFIG_HOME:-~/.config}/lexe."
echo
echo "Nothing you installed or created is removed without your explicit intent."
echo "To remove an application and its data, use the runtime BEFORE uninstalling:"
echo "  lexe remove <app-id> --purge-data"
echo "Or delete the data directory above by hand."

#!/bin/sh
# =============================================================================
# Headless GTK smoke test — the GUIs must render WARNING-CLEAN under a virtual
# X server, including markup-sensitive text.
#
# Regression guard for the "block screen" class of bug: a heading or a name
# containing Pango-markup metacharacters (& < > ") that is embedded in markup
# WITHOUT escaping makes Pango fail to parse it and render the label BLANK,
# emitting a Gtk-WARNING. This test feeds exactly those characters through the
# installer (app name, publisher name, and the "Authenticity & local trust:"
# heading) and fails if ANY Gtk/Gdk/Pango/GLib WARNING or CRITICAL, assertion
# failure, or crash appears. It also launches the builder, whose every section
# heading is built at startup.
#
# Usage:   scripts/gui-smoke.sh [BUILD_DIR]     (default: build)
# Env:     TIMEOUT (seconds a GUI is held open before it is closed; default 6)
# Requires: xvfb-run, and the GUIs built in BUILD_DIR (Linux only).
# Exit:    0 only if both GUIs render clean; non-zero otherwise.
# =============================================================================
set -eu

BUILD_DIR="${1:-build}"
TIMEOUT="${TIMEOUT:-6}"
REPO=$(cd "$(dirname "$0")/.." && pwd)
LEXE="$BUILD_DIR/lexe"
INSTALLER="$BUILD_DIR/lexe-installer"
BUILDER="$BUILD_DIR/lexe-builder"

ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
die() { printf '  \033[31mFAIL\033[0m %s\n' "$1" >&2; exit 1; }

command -v xvfb-run >/dev/null 2>&1 || die "xvfb-run is required (install the xvfb package)"
command -v xwininfo >/dev/null 2>&1 || die "xwininfo is required (install the x11-utils package)"
[ -x "$INSTALLER" ] || die "no lexe-installer in $BUILD_DIR (build the GTK GUI first)"
[ -x "$BUILDER" ]   || die "no lexe-builder in $BUILD_DIR"
[ -x "$LEXE" ]      || die "no lexe CLI in $BUILD_DIR"

# Force the X11 backend and hide any Wayland display BEFORE anything launches.
# On a host with a Wayland compositor — every WSLg session, and most current
# desktops — GTK prefers Wayland and connects to THAT, silently ignoring the
# virtual X server xvfb-run just created. The test then "passes" while the GUIs
# render on the developer's real desktop, proving nothing about headless
# behaviour and putting windows on their screen. Pinning the backend keeps this
# test genuinely headless wherever it runs.
unset WAYLAND_DISPLAY
export GDK_BACKEND=x11

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Lines that indicate a real GUI defect. The allowlist strips environment noise
# that a headless X server / missing a11y bus legitimately produces and that is
# NOT an application bug.
#
# On `gdk_seat_get_keyboard: assertion 'GDK_IS_SEAT (seat)' failed`: a virtual X
# server that has just started has no input devices yet, so GDK's default seat
# is briefly absent and any GTK program that touches it logs this. It was
# verified to be environmental rather than ours: a stock GTK window (one plain
# label, no lexe code at all) reproduces it 3/3 times against a freshly started
# Xvfb, while both lexe GUIs are clean 8/8 against a warm one. Allowlisting the
# assertion stops that race from failing CI without hiding any GTK warning the
# GUIs actually emit.
offending() {
    grep -aE \
      '(Gtk|Gdk|GLib|GLib-GObject|GdkPixbuf|Pango|Gnome)-(WARNING|CRITICAL|ERROR)|CRITICAL \*\*|assertion .*failed|due to error parsing markup|Segmentation fault|core dumped|Trace/breakpoint trap' \
      "$1" 2>/dev/null \
      | grep -avE 'dbind-WARNING|AT-SPI|at-spi|atk-bridge|Failed to connect to|session (manager|bus)|Theme parsing error|Gtk-Message|accessibility bus|Unable to init server|cannot open display: after|Could not load a pixbuf|pixbuf from .*(theme|icon|symbolic|Adwaita)|Error loading (theme )?icon|gdk_seat_get_keyboard: assertion' \
      || true
}

# Run a GUI under Xvfb, hold it open for TIMEOUT seconds, and assert it neither
# crashed nor emitted an offending line. A clean run is closed by the timeout
# (exit 124); a self-exit of 0 is fine; anything else (a crash signal, 128+N)
# is a failure.
smoke() {
    label="$1"; shift
    log="$WORK/$(echo "$label" | tr ' /' '__').log"
    code=0
    # Launch under Xvfb and, from INSIDE that display, wait for the GUI to map a
    # real toplevel window. Checking only for warnings is not enough: a GUI that
    # never shows a window, or one that connects to a different display
    # entirely, emits nothing at all and would "pass" silently.
    timeout "$TIMEOUT" xvfb-run -a sh -c '
        "$@" &
        app=$!
        i=0
        while [ "$i" -lt 20 ]; do
            if xwininfo -root -children 2>/dev/null                  | grep -qE "^ +0x[0-9a-f]+ \"[^\"]+\".*[0-9][0-9][0-9]+x[0-9][0-9][0-9]+"
            then
                echo "GUI-SMOKE: mapped a toplevel window"
                break
            fi
            i=$((i + 1))
            sleep 0.5
        done
        wait $app
    ' sh "$@" >"$log" 2>&1 || code=$?
    if [ "$code" != 124 ] && [ "$code" != 0 ]; then
        echo "---- $label output ----"; sed 's/^/    /' "$log" >&2
        die "$label exited $code (a crash, not a clean render)"
    fi
    if ! grep -q "GUI-SMOKE: mapped a toplevel window" "$log"; then
        echo "---- $label output ----"; sed 's/^/    /' "$log" >&2
        die "$label never mapped a window on the virtual display"
    fi
    bad=$(offending "$log")
    if [ -n "$bad" ]; then
        echo "---- $label offending lines ----"; printf '%s\n' "$bad" | sed 's/^/    /' >&2
        die "$label emitted GTK/Pango warnings"
    fi
    ok "$label mapped a window and rendered clean (exit $code)"
}

printf 'Headless GTK smoke test\n  build dir: %s\n  timeout:   %ss\n' \
    "$BUILD_DIR" "$TIMEOUT"

# --- Build a markup-HOSTILE package: name/publisher carry & < > " ------------
mkdir -p "$WORK/proj/payload/bin"
cp /bin/true "$WORK/proj/payload/bin/app"   # any dynamically linked ELF
cat > "$WORK/proj/lexe.json" <<'JSON'
{
  "lexeVersion": "0.1",
  "id": "org.lexe.markup.smoke",
  "name": "Ampersand & <Angle> \"Quote\" & Co.",
  "version": "1.0.0",
  "publisher": { "name": "Bell & <Howell> \"Labs\"", "publicKey": "AUTO" },
  "applicationType": "native",
  "architectures": ["x86_64"],
  "entrypoint": { "executable": "bin/app", "arguments": [] },
  "install": { "scope": "user", "mode": "bundled" },
  "permissions": []
}
JSON
"$LEXE" keygen "$WORK/key.json" >/dev/null
"$LEXE" build "$WORK/proj" -o "$WORK/hostile.lexe" --key "$WORK/key.json" >/dev/null
ok "built a package whose name + publisher contain & < > \""

# --- The installer renders the markup-hostile package -------------------------
export LEXE_HOME="$WORK/home"
smoke "installer (markup-hostile package)" "$INSTALLER" "$WORK/hostile.lexe"

# --- The builder builds every section heading at startup ----------------------
smoke "builder (startup)" "$BUILDER"

printf '\n\033[1mGUI smoke test passed.\033[0m\n'

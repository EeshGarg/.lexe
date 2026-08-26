#pragma once
// style — the one visual language both GTK frontends render in.
//
// The GUIs were structurally sound and visually stuck in the era of the widget
// defaults: a flat run of bold-label-then-text down a grey box, controls at
// whatever size the theme gave them, and severity carried only by a word. This
// gives them a deliberate design instead:
//
//   * CARDS with real radius and a hairline border group related facts, so a
//     package's identity, trust and permissions read as distinct things rather
//     than one wall of text (One UI's grouping, without its phone-sized metrics);
//   * a TYPE SCALE — a large semibold title, small uppercase-weight section
//     labels in a muted tone, comfortable body — so hierarchy comes from
//     typography rather than from bold runs (Fluent/Metro);
//   * a single ACCENT for the one primary action per screen, filled and
//     unmistakable, with every other button quiet (Metro);
//   * soft vertical GRADIENTS and a hairline highlight on the banner and action
//     bar, which is the one honest borrowing from Aero: a lit strip top and
//     bottom framing flat content between them.
//
// Constraints this file works under:
//   * GTK 3.24 CSS only. No box-sizing, letter-spacing, text-transform or
//     media queries — GTK warns on unknown properties, and the headless smoke
//     test fails the build on GTK warnings.
//   * Severity must survive the restyle. ok/caution/danger keep distinct hue,
//     border AND text colour, never hue alone, because the whole point of the
//     banner is that a first-seen key is not styled like a verified one.
//   * Both themes. A user on a dark GTK theme got white text on white cards if
//     the palette were hardcoded light, so the palette is chosen at runtime.

#include <gtk/gtk.h>

namespace lexe::gui::style {

/// The stylesheet for one theme. `dark` picks the palette; every rule below is
/// identical in both, so the two can never drift in layout, only in colour.
inline const char* stylesheet(bool dark) {
    if (dark) {
        return R"CSS(
@define-color lexe_canvas   #16181d;
@define-color lexe_surface  #1e2128;
@define-color lexe_border   rgba(255,255,255,0.10);
@define-color lexe_text     #e9ecf1;
@define-color lexe_muted    #9aa3b2;
@define-color lexe_accent   #2f7fe0;
@define-color lexe_accent_h #3d8ff0;

window { background-color: @lexe_canvas; color: @lexe_text; }

.lexe-title    { font-size: 19px; font-weight: 800; color: @lexe_text; }
.lexe-subtitle { font-size: 12px; color: @lexe_muted; }
.lexe-body     { color: @lexe_text; }
.lexe-muted    { color: @lexe_muted; font-size: 12px; }
.lexe-section-heading { font-size: 12px; font-weight: 700; color: @lexe_muted; }

.lexe-card {
  background-color: @lexe_surface;
  border: 1px solid @lexe_border;
  border-radius: 14px;
  padding: 14px 16px;
}

.lexe-banner { padding: 14px 18px; font-weight: 700; border-bottom: 1px solid @lexe_border; }
.lexe-banner.ok      { background-image: linear-gradient(to bottom, #1b3326, #162b20); color: #7ee0a1; }
.lexe-banner.caution { background-image: linear-gradient(to bottom, #3a2f18, #322813); color: #f0c471; }
.lexe-banner.danger  { background-image: linear-gradient(to bottom, #3a1f1d, #331a18); color: #ff9c93; }

.lexe-actionbar {
  background-image: linear-gradient(to bottom, #22252c, #1c1f25);
  border-top: 1px solid @lexe_border;
  padding: 12px 16px;
}

.lexe-stepbar {
  background-image: linear-gradient(to bottom, #22252c, #1c1f25);
  border-bottom: 1px solid @lexe_border;
  padding: 14px 18px;
}

button { border-radius: 10px; padding: 7px 16px; min-height: 20px; }
button.lexe-primary {
  background-image: linear-gradient(to bottom, @lexe_accent_h, @lexe_accent);
  color: #ffffff;
  font-weight: 700;
  border: 1px solid rgba(0,0,0,0.30);
}
button.lexe-primary:hover {
  background-image: linear-gradient(to bottom, #4a99f5, #2f7fe0);
}
button.lexe-primary:disabled {
  background-image: none;
  background-color: #2a2e36;
  color: #6b7383;
  border-color: @lexe_border;
}

entry { border-radius: 10px; padding: 7px 10px; min-height: 22px; }
entry:disabled { color: #6b7383; }
.lexe-mono { font-family: monospace; font-size: 12px; }
)CSS";
    }
    return R"CSS(
@define-color lexe_canvas   #f2f3f5;
@define-color lexe_surface  #ffffff;
@define-color lexe_border   rgba(16,24,40,0.12);
@define-color lexe_text     #14161a;
@define-color lexe_muted    #5b6472;
@define-color lexe_accent   #0b64d0;
@define-color lexe_accent_h #1273e6;

window { background-color: @lexe_canvas; color: @lexe_text; }

.lexe-title    { font-size: 19px; font-weight: 800; color: @lexe_text; }
.lexe-subtitle { font-size: 12px; color: @lexe_muted; }
.lexe-body     { color: @lexe_text; }
.lexe-muted    { color: @lexe_muted; font-size: 12px; }
.lexe-section-heading { font-size: 12px; font-weight: 700; color: @lexe_muted; }

.lexe-card {
  background-color: @lexe_surface;
  border: 1px solid @lexe_border;
  border-radius: 14px;
  padding: 14px 16px;
}

.lexe-banner { padding: 14px 18px; font-weight: 700; border-bottom: 1px solid @lexe_border; }
.lexe-banner.ok      { background-image: linear-gradient(to bottom, #eff8f2, #e3f2e9); color: #11632b; }
.lexe-banner.caution { background-image: linear-gradient(to bottom, #fff8ea, #fdf0d8); color: #7a4f00; }
.lexe-banner.danger  { background-image: linear-gradient(to bottom, #fdeeed, #fbe0de); color: #a01a13; }

.lexe-actionbar {
  background-image: linear-gradient(to bottom, #ffffff, #f6f7f9);
  border-top: 1px solid @lexe_border;
  padding: 12px 16px;
}

.lexe-stepbar {
  background-image: linear-gradient(to bottom, #ffffff, #f6f7f9);
  border-bottom: 1px solid @lexe_border;
  padding: 14px 18px;
}

button { border-radius: 10px; padding: 7px 16px; min-height: 20px; }
button.lexe-primary {
  background-image: linear-gradient(to bottom, @lexe_accent_h, @lexe_accent);
  color: #ffffff;
  font-weight: 700;
  border: 1px solid rgba(0,0,0,0.14);
}
button.lexe-primary:hover {
  background-image: linear-gradient(to bottom, #2b86f0, #0f6ad8);
}
button.lexe-primary:disabled {
  background-image: none;
  background-color: #e3e5e9;
  color: #9aa1ab;
  border-color: @lexe_border;
}

entry { border-radius: 10px; padding: 7px 10px; min-height: 22px; }
entry:disabled { color: #9aa1ab; }
.lexe-mono { font-family: monospace; font-size: 12px; }
)CSS";
}

/// Add `klass` to `widget`'s style context. A tiny wrapper only so call sites
/// read as one line instead of three.
inline void add_class(GtkWidget* widget, const char* klass) {
    gtk_style_context_add_class(gtk_widget_get_style_context(widget), klass);
}

inline void remove_class(GtkWidget* widget, const char* klass) {
    gtk_style_context_remove_class(gtk_widget_get_style_context(widget), klass);
}

/// Install the stylesheet for the default screen. Call once, after gtk_init().
///
/// Loaded at APPLICATION priority, which sits above the user's theme but below
/// anything they set themselves — so a deliberate user override still wins, and
/// a theme that happens to style `button` does not fight us.
inline void apply() {
    gboolean prefer_dark = FALSE;
    if (GtkSettings* settings = gtk_settings_get_default()) {
        g_object_get(settings, "gtk-application-prefer-dark-theme", &prefer_dark,
                     nullptr);
    }
    GtkCssProvider* provider = gtk_css_provider_new();
    // Parsing errors are reported rather than swallowed: an unsupported
    // property silently drops one rule and leaves a half-styled window, which
    // is exactly the kind of "looks broken, nobody knows why" the headless
    // smoke test exists to catch.
    g_signal_connect(provider, "parsing-error",
                     G_CALLBACK(+[](GtkCssProvider*, GtkCssSection*,
                                    GError* error, gpointer) {
                         g_warning("lexe stylesheet: %s",
                                   error != nullptr ? error->message
                                                    : "unknown parsing error");
                     }),
                     nullptr);
    gtk_css_provider_load_from_data(provider, stylesheet(prefer_dark == TRUE), -1,
                                    nullptr);
    if (GdkScreen* screen = gdk_screen_get_default()) {
        gtk_style_context_add_provider_for_screen(
            screen, GTK_STYLE_PROVIDER(provider),
            GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    }
    g_object_unref(provider);
}

} // namespace lexe::gui::style

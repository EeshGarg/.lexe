#pragma once
// style — the one visual language both GTK frontends render in.
//
// The first attempt at this leaned literally on Aero: vertical gradients on
// every strip, a bordered gradient button, hairline borders around cards. Those
// are the exact cues that date a window to the late 2000s, so they are gone. The
// borrowing from Aero that survives is DEPTH — surfaces that sit above the page
// — expressed the way it is expressed now, with a soft shadow rather than a
// bevel and a sheen.
//
// What the look is built from:
//   * FLAT surfaces. One canvas tone, one card tone, no gradient anywhere. Depth
//     comes from a two-layer shadow (a tight contact shadow plus a wider ambient
//     one), which is what reads as "raised" today.
//   * SPACE. Cards are padded 18/20 and separated by 12; the page is inset 22.
//     The old layout was tight enough that everything read as one block, and no
//     amount of colour fixes that.
//   * A real TYPE SCALE with a neutral slate palette: 26px/700 title, 13px
//     muted subtitle, 12px/600 muted section labels, 14px body. GTK's default
//     11px everywhere is itself a period detail.
//   * ONE solid accent. No gradient, no border, no bevel — a filled rounded
//     rectangle, which is the single strongest signal that a UI is current.
//   * Severity as an inset CALLOUT: flat tint plus a 4px bar down the leading
//     edge, instead of a full-bleed gradient band.
//
// Constraints this file works under:
//   * GTK 3.24 CSS only. No box-sizing, letter-spacing, text-transform or media
//     queries — GTK warns on unknown properties, and the headless smoke test
//     fails the build on GTK warnings.
//   * Severity must survive the restyle. ok/caution/danger keep a distinct
//     tint, edge-bar AND text colour, never hue alone, because the whole point
//     of the banner is that a first-seen key is not styled like a verified one.
//   * Both themes, chosen at runtime — a hardcoded light palette gives a user on
//     a dark GTK theme white text on white cards.

#include <gtk/gtk.h>

#include <string>

namespace lexe::gui::style {

/// The stylesheet for one theme. `dark` picks the palette; the metrics below are
/// identical in both, so the two can only differ in colour, never in layout.
inline const char* stylesheet(bool dark) {
    if (dark) {
        return R"CSS(
@define-color lexe_canvas  #0f1115;
@define-color lexe_surface #181b21;
@define-color lexe_text    #e7eaf0;
@define-color lexe_muted   #98a2b3;
@define-color lexe_accent  #3b82f6;


window { background-color: @lexe_canvas; color: @lexe_text; }

.lexe-title    { font-size: 26px; font-weight: 700; color: @lexe_text; }
.lexe-subtitle { font-size: 13px; color: @lexe_muted; }
.lexe-body     { font-size: 14px; color: @lexe_text; }
.lexe-muted    { font-size: 13px; color: @lexe_muted; }
.lexe-section-heading { font-size: 12px; font-weight: 600; color: @lexe_muted; }
/* A success heading. A CLASS, not a colour in markup: a colour baked into
   Pango when a build finished kept the old palette's green after a theme flip,
   leaving mint text on a white card at ~1.4:1 contrast. */
.lexe-success { font-size: 17px; font-weight: 700; color: #6ee7a8; }

.lexe-card {
  background-color: @lexe_surface;
  border-radius: 16px;
  padding: 18px 20px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.40), 0 4px 12px rgba(0,0,0,0.28);
}

.lexe-banner {
  padding: 16px 20px;
  font-size: 14px;
  font-weight: 600;
  background-color: @lexe_surface;
}
.lexe-banner.ok      { background-color: #12271b; color: #6ee7a8; border-left: 4px solid #22c55e; }
.lexe-banner.caution { background-color: #2a2113; color: #fbbf5c; border-left: 4px solid #f59e0b; }
.lexe-banner.danger  { background-color: #2b1517; color: #ff8f8a; border-left: 4px solid #ef4444; }

.lexe-actionbar { background-color: @lexe_surface; padding: 14px 20px; }
.lexe-stepbar   { background-color: @lexe_surface; padding: 20px 22px 18px 22px; }

button {
  border-radius: 999px;
  padding: 8px 20px;
  min-height: 22px;
  font-size: 13px;
  font-weight: 500;
  background-image: none;
  background-color: #252932;
  color: @lexe_text;
  border: none;
  box-shadow: none;
  transition: background-color 120ms ease-out;
}
button:hover { background-color: #2e333e; }
button.lexe-primary {
  background-color: @lexe_accent;
  color: #ffffff;
  font-weight: 600;
  padding: 8px 24px;
}
button.lexe-primary:hover    { background-color: #5b9bf8; }
button.lexe-primary:disabled { background-color: #262a33; color: #616b7d; }
button:disabled              { background-color: #1d2129; color: #616b7d; }

entry {
  border-radius: 10px;
  padding: 9px 12px;
  min-height: 26px;
  font-size: 14px;
  background-image: none;
  background-color: #1d2129;
  border: none;
  color: @lexe_text;
}
entry:disabled { color: #616b7d; }
.lexe-mono { font-family: monospace; font-size: 13px; }
)CSS";
    }
    return R"CSS(
@define-color lexe_canvas  #f5f6f8;
@define-color lexe_surface #ffffff;
@define-color lexe_text    #0f172a;
@define-color lexe_muted   #64748b;
@define-color lexe_accent  #2563eb;


window { background-color: @lexe_canvas; color: @lexe_text; }

.lexe-title    { font-size: 26px; font-weight: 700; color: @lexe_text; }
.lexe-subtitle { font-size: 13px; color: @lexe_muted; }
.lexe-body     { font-size: 14px; color: @lexe_text; }
.lexe-muted    { font-size: 13px; color: @lexe_muted; }
.lexe-section-heading { font-size: 12px; font-weight: 600; color: @lexe_muted; }
/* A success heading - see the dark palette for why this is a class. */
.lexe-success { font-size: 17px; font-weight: 700; color: #15803d; }

.lexe-card {
  background-color: @lexe_surface;
  border-radius: 16px;
  padding: 18px 20px;
  box-shadow: 0 1px 2px rgba(15,23,42,0.06), 0 4px 12px rgba(15,23,42,0.05);
}

.lexe-banner {
  padding: 16px 20px;
  font-size: 14px;
  font-weight: 600;
  background-color: @lexe_surface;
}
.lexe-banner.ok      { background-color: #ecfdf3; color: #15803d; border-left: 4px solid #22c55e; }
.lexe-banner.caution { background-color: #fff8eb; color: #b45309; border-left: 4px solid #f59e0b; }
.lexe-banner.danger  { background-color: #fef2f2; color: #b91c1c; border-left: 4px solid #ef4444; }

.lexe-actionbar { background-color: @lexe_surface; padding: 14px 20px; }
.lexe-stepbar   { background-color: @lexe_surface; padding: 20px 22px 18px 22px; }

button {
  border-radius: 999px;
  padding: 8px 20px;
  min-height: 22px;
  font-size: 13px;
  font-weight: 500;
  background-image: none;
  background-color: #eef0f4;
  color: @lexe_text;
  border: none;
  box-shadow: none;
  transition: background-color 120ms ease-out;
}
button:hover { background-color: #e4e7ec; }
button.lexe-primary {
  background-color: @lexe_accent;
  color: @lexe_surface;
  font-weight: 600;
}
button.lexe-primary:hover    { background-color: #1d4ed8; }
button.lexe-primary:disabled { background-color: #dfe3ea; color: #9aa4b2; }
button:disabled              { background-color: #f1f3f6; color: #9aa4b2; }

entry {
  border-radius: 10px;
  padding: 9px 12px;
  min-height: 26px;
  font-size: 14px;
  background-image: none;
  background-color: #f1f3f6;
  border: none;
  color: @lexe_text;
}
entry:disabled { color: #9aa4b2; }
.lexe-mono { font-family: monospace; font-size: 13px; }
)CSS";
}

/// Which palette to render in. `System` is the default and follows the desktop;
/// the other two are a deliberate user override, persisted in settings.json as
/// the `theme` preference so the GUI toggle and `lexe config set theme` are the
/// same setting rather than two competing ones.
enum class Theme { System, Light, Dark };

inline Theme theme_from_string(const std::string& value) {
    if (value == "light") return Theme::Light;
    if (value == "dark") return Theme::Dark;
    return Theme::System; // unknown values fall back to following the desktop
}

inline const char* theme_to_string(Theme t) {
    switch (t) {
    case Theme::Light: return "light";
    case Theme::Dark:  return "dark";
    case Theme::System: break;
    }
    return "system";
}

/// Whether `theme` should render dark right now.
///
/// For System this asks the desktop two ways, because neither alone is
/// reliable: GTK's prefer-dark flag is what a settings daemon sets, but many
/// desktops instead just select a theme whose NAME ends in "-dark" and leave the
/// flag off. Missing the second case is how an app ends up as the one bright
/// window on a dark desktop.
inline bool resolve_dark(Theme theme) {
    if (theme == Theme::Light) return false;
    if (theme == Theme::Dark) return true;
    GtkSettings* settings = gtk_settings_get_default();
    if (settings == nullptr) return false;
    gboolean prefer_dark = FALSE;
    gchar* theme_name = nullptr;
    g_object_get(settings, "gtk-application-prefer-dark-theme", &prefer_dark,
                 "gtk-theme-name", &theme_name, nullptr);
    bool dark = prefer_dark == TRUE;
    if (!dark && theme_name != nullptr) {
        const std::string name = theme_name;
        dark = name.size() >= 5 &&
               name.compare(name.size() - 5, 5, "-dark") == 0;
    }
    if (theme_name != nullptr) g_free(theme_name);
    // GTK_THEME=Adwaita:dark is the developer/CI override and sets NEITHER of
    // the above — gtk-theme-name reports the base name and the prefer-dark flag
    // stays off — so a session started that way would render light inside a
    // dark shell. Cheap to honour, and it is how a dark run gets tested.
    if (!dark) {
        if (const char* env = g_getenv("GTK_THEME"); env != nullptr) {
            const std::string value = env;
            dark = value.size() >= 5 &&
                   value.compare(value.size() - 5, 5, ":dark") == 0;
        }
    }
    return dark;
}

/// Add `klass` to `widget`'s style context. A tiny wrapper only so call sites
/// read as one line instead of three.
inline void add_class(GtkWidget* widget, const char* klass) {
    gtk_style_context_add_class(gtk_widget_get_style_context(widget), klass);
}

inline void remove_class(GtkWidget* widget, const char* klass) {
    gtk_style_context_remove_class(gtk_widget_get_style_context(widget), klass);
}

/// Install (or REPLACE) the stylesheet for the default screen.
///
/// Safe to call repeatedly: one provider is kept and reloaded in place, so
/// flipping the theme toggle restyles the live window instead of stacking a
/// second provider on top of the first — two providers at the same priority
/// would leave whichever loaded last winning per-property, which is how a theme
/// switch ends up half-applied.
///
/// Loaded at APPLICATION priority: above the user's theme, below anything they
/// set themselves, so a deliberate user override still wins.
inline void apply(Theme theme = Theme::System) {
    static GtkCssProvider* provider = nullptr;
    if (provider == nullptr) {
        provider = gtk_css_provider_new();
        // Parsing errors are reported rather than swallowed: an unsupported
        // property silently drops one rule and leaves a half-styled window,
        // which is exactly the kind of "looks broken, nobody knows why" the
        // headless smoke test exists to catch.
        g_signal_connect(provider, "parsing-error",
                         G_CALLBACK(+[](GtkCssProvider*, GtkCssSection*,
                                        GError* error, gpointer) {
                             g_warning("lexe stylesheet: %s",
                                       error != nullptr ? error->message
                                                        : "unknown parsing error");
                         }),
                         nullptr);
        if (GdkScreen* screen = gdk_screen_get_default()) {
            gtk_style_context_add_provider_for_screen(
                screen, GTK_STYLE_PROVIDER(provider),
                GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
        }
    }
    const bool dark = resolve_dark(theme);
    // Keep GTK's own widgetry (menus, tooltips, the file chooser) in step with
    // our palette. Styling only our own widgets would leave a light chooser
    // dialog opening out of a dark window.
    if (GtkSettings* settings = gtk_settings_get_default()) {
        g_object_set(settings, "gtk-application-prefer-dark-theme",
                     dark ? TRUE : FALSE, nullptr);
    }
    gtk_css_provider_load_from_data(provider, stylesheet(dark), -1, nullptr);
}

} // namespace lexe::gui::style

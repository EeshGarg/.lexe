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
// The second attempt then overcorrected the other way. Flat and modern is also
// what Adwaita is: 16px cards floating on soft shadows, pill buttons, a 26px
// title and generous padding read as a GTK sample, not as something installing
// software. What this aims at now is the anatomy of a SETUP DIALOG — header,
// content, command bar — in the visual language Windows uses for one, which is
// mostly a matter of restraint.
//
// What the look is built from:
//   * HAIRLINES, not shadows. A 1px border and a 4px radius, on a card tone
//     against a slightly darker canvas. Depth by border is what a system
//     dialog does; a drop shadow under every panel is what a web page does.
//   * DENSITY. Cards padded 12/14, the type scale 20px/600 title and 13px
//     body. An oversized heading is itself a period detail, in both
//     directions — GTK's default 11px everywhere was one, and 26px/700 was the
//     next one.
//   * A COMMAND BAR. The action row carries a hairline top border and sits on
//     the canvas tone. That separator is the whole trick: it is what makes the
//     buttons read as the window's commands rather than as more content.
//   * RECTANGULAR buttons with a minimum width, and exactly ONE filled accent
//     button per screen, in the Windows accent blue. Note the dark palette
//     inverts it the way Windows does — a light blue fill with dark text, not
//     a dark blue fill with white text.
//   * Severity as an inset CALLOUT in the WinUI InfoBar palette: flat tint,
//     matching text, and a 4px bar down the leading edge.
//
// A NAVIGATION PANE is part of this, not decoration: `lexe-ui`'s pages used
// four stock buttons stacked in a column, which was the strongest "toolkit
// demo" cue in the window and also read as four things to press rather than as
// where you are.
//
// Constraints this file works under:
//   * GTK 3.24 CSS only. No box-sizing, letter-spacing, text-transform or media
//     queries — GTK warns on unknown properties, and the headless smoke test
//     fails the build on GTK warnings.
//   * NOTHING here can restyle what Pango markup has already decided. A
//     `size=` or `foreground=` baked into a label WINS over this stylesheet,
//     so a title sized in markup ignored `.lexe-title` entirely and severity
//     colours baked in markup kept their light-theme values on a dark
//     background. Size, weight and colour belong in a class; markup is for
//     structure. `.lexe-success` exists because of this and was not the only
//     case — see the comment on it.
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
@define-color lexe_canvas  #202020;
@define-color lexe_surface #2b2b2b;
@define-color lexe_border  #3d3d3d;
@define-color lexe_text    #ffffff;
@define-color lexe_muted   #c5c5c5;
@define-color lexe_accent  #60cdff;


window { background-color: @lexe_canvas; color: @lexe_text; }

.lexe-title    { font-size: 20px; font-weight: 600; color: @lexe_text; }
.lexe-subtitle { font-size: 12px; color: @lexe_muted; }
.lexe-body     { font-size: 13px; color: @lexe_text; }
.lexe-muted    { font-size: 12px; color: @lexe_muted; }
.lexe-section-heading { font-size: 12px; font-weight: 600; color: @lexe_text; }
/* A success heading. A CLASS, not a colour in markup: a colour baked into
   Pango when a build finished kept the old palette's green after a theme flip,
   leaving mint text on a white card at ~1.4:1 contrast. */
.lexe-success { font-size: 15px; font-weight: 600; color: #6ccb5f; }

.lexe-card {
  background-color: @lexe_surface;
  border: 1px solid @lexe_border;
  border-radius: 4px;
  padding: 12px 14px;
}

.lexe-banner {
  padding: 10px 14px;
  font-size: 13px;
  font-weight: 600;
  border: 1px solid @lexe_border;
  border-radius: 4px;
  background-color: @lexe_surface;
  color: @lexe_text;
}
.lexe-banner.ok      { background-color: #393d1b; color: #6ccb5f; border-left: 4px solid #6ccb5f; }
.lexe-banner.caution { background-color: #433519; color: #fce100; border-left: 4px solid #fce100; }
.lexe-banner.danger  { background-color: #442726; color: #ff99a4; border-left: 4px solid #ff99a4; }

/* The command bar of a setup dialog: pinned, hairline-separated, buttons right.
   The separator is what makes the buttons read as the window's commands rather
   than as more content. */
.lexe-actionbar {
  background-color: @lexe_canvas;
  border-top: 1px solid @lexe_border;
  padding: 12px 16px;
}
.lexe-stepbar {
  background-color: @lexe_surface;
  border-bottom: 1px solid @lexe_border;
  padding: 14px 16px 12px 16px;
}

button {
  border-radius: 4px;
  padding: 5px 14px;
  min-height: 22px;
  min-width: 82px;
  font-size: 13px;
  font-weight: 400;
  background-image: none;
  background-color: #373737;
  color: @lexe_text;
  border: 1px solid @lexe_border;
  box-shadow: none;
  transition: background-color 90ms ease-out;
}
button:hover { background-color: #3d3d3d; }
button.lexe-primary {
  background-color: @lexe_accent;
  color: #000000;
  font-weight: 600;
  border: 1px solid @lexe_accent;
}
button.lexe-primary:hover    { background-color: #7cd7ff; border-color: #7cd7ff; }
button.lexe-primary:disabled { background-color: #404040; color: #7a7a7a; border-color: @lexe_border; }
button:disabled              { background-color: #2f2f2f; color: #7a7a7a; }

entry {
  border-radius: 4px;
  padding: 6px 10px;
  min-height: 24px;
  font-size: 13px;
  background-image: none;
  background-color: #2d2d2d;
  border: 1px solid @lexe_border;
  color: @lexe_text;
}
entry:focus { border-color: @lexe_accent; }
entry:disabled { color: #7a7a7a; }
/* The navigation pane: its own surface, flat full-width items, and a clear
   "you are here" marked by an accent bar rather than by a pressed-looking
   button. Buttons styled as buttons in a nav column are what makes a window
   look like a toolkit sample. */
.lexe-nav { background-color: @lexe_surface; border-right: 1px solid @lexe_border; }
.lexe-nav-item {
  background-color: transparent;
  border: none;
  border-left: 3px solid transparent;
  border-radius: 4px;
  min-width: 0;
  padding: 7px 10px;
  font-weight: 400;
  color: @lexe_text;
}
.lexe-nav-item:hover           { background-color: #353535; }
.lexe-nav-item.selected        { background-color: #3a3a3a; border-left: 3px solid @lexe_accent; font-weight: 600; }
.lexe-nav-item.selected:hover  { background-color: #404040; }

.lexe-mono { font-family: monospace; font-size: 12px; }
)CSS";
    }
    return R"CSS(
@define-color lexe_canvas  #f3f3f3;
@define-color lexe_surface #ffffff;
@define-color lexe_border  #e0e0e0;
@define-color lexe_text    #1b1b1b;
@define-color lexe_muted   #5d5d5d;
@define-color lexe_accent  #005fb8;


window { background-color: @lexe_canvas; color: @lexe_text; }

.lexe-title    { font-size: 20px; font-weight: 600; color: @lexe_text; }
.lexe-subtitle { font-size: 12px; color: @lexe_muted; }
.lexe-body     { font-size: 13px; color: @lexe_text; }
.lexe-muted    { font-size: 12px; color: @lexe_muted; }
.lexe-section-heading { font-size: 12px; font-weight: 600; color: @lexe_text; }
/* A success heading - see the dark palette for why this is a class. */
.lexe-success { font-size: 15px; font-weight: 600; color: #0f7b0f; }

.lexe-card {
  background-color: @lexe_surface;
  border: 1px solid @lexe_border;
  border-radius: 4px;
  padding: 12px 14px;
}

.lexe-banner {
  padding: 10px 14px;
  font-size: 13px;
  font-weight: 600;
  border: 1px solid @lexe_border;
  border-radius: 4px;
  background-color: @lexe_surface;
  color: @lexe_text;
}
.lexe-banner.ok      { background-color: #dff6dd; color: #0f7b0f; border-left: 4px solid #0f7b0f; }
.lexe-banner.caution { background-color: #fff4ce; color: #9d5d00; border-left: 4px solid #9d5d00; }
.lexe-banner.danger  { background-color: #fde7e9; color: #c42b1c; border-left: 4px solid #c42b1c; }

/* The command bar of a setup dialog - see the dark palette. */
.lexe-actionbar {
  background-color: @lexe_canvas;
  border-top: 1px solid @lexe_border;
  padding: 12px 16px;
}
.lexe-stepbar {
  background-color: @lexe_surface;
  border-bottom: 1px solid @lexe_border;
  padding: 14px 16px 12px 16px;
}

button {
  border-radius: 4px;
  padding: 5px 14px;
  min-height: 22px;
  min-width: 82px;
  font-size: 13px;
  font-weight: 400;
  background-image: none;
  background-color: #fdfdfd;
  color: @lexe_text;
  border: 1px solid #d1d1d1;
  box-shadow: none;
  transition: background-color 90ms ease-out;
}
button:hover { background-color: #f5f5f5; }
button.lexe-primary {
  background-color: @lexe_accent;
  color: #ffffff;
  font-weight: 600;
  border: 1px solid @lexe_accent;
}
button.lexe-primary:hover    { background-color: #1a6cc0; border-color: #1a6cc0; }
button.lexe-primary:disabled { background-color: #e5e5e5; color: #a0a0a0; border-color: #e0e0e0; }
button:disabled              { background-color: #f5f5f5; color: #a0a0a0; }

entry {
  border-radius: 4px;
  padding: 6px 10px;
  min-height: 24px;
  font-size: 13px;
  background-image: none;
  background-color: @lexe_surface;
  border: 1px solid #d1d1d1;
  color: @lexe_text;
}
entry:focus { border-color: @lexe_accent; }
entry:disabled { color: #a0a0a0; }
/* The navigation pane - see the dark palette. */
.lexe-nav { background-color: @lexe_surface; border-right: 1px solid @lexe_border; }
.lexe-nav-item {
  background-color: transparent;
  border: none;
  border-left: 3px solid transparent;
  border-radius: 4px;
  min-width: 0;
  padding: 7px 10px;
  font-weight: 400;
  color: @lexe_text;
}
.lexe-nav-item:hover           { background-color: #ededed; }
.lexe-nav-item.selected        { background-color: #e8e8e8; border-left: 3px solid @lexe_accent; font-weight: 600; }
.lexe-nav-item.selected:hover  { background-color: #e0e0e0; }

.lexe-mono { font-family: monospace; font-size: 12px; }
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

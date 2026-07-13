// lexe-installer — GTK 3 graphical installer (ARCHITECTURE.md #GUI).
//
// Flow per SPEC "User Interface": open with a `.lexe` argument -> run the
// FORMAT-0.1 §6 verification pipeline -> primary screen (app, publisher,
// version, source, "Native Linux — <arch>", permissions, install scope +
// size, update policy, verification status banner) -> [Advanced Options]
// expander (directories used, update channel) + [Install] -> progress ->
// success screen with [Launch] (launcher::run_app) and [Close]. A failed
// verification stage disables Install and names the stage and reason (SPEC
// "Security Model": users must understand what they are trusting).
//
// The file has two layers:
//  * `lexe::gui` — pure, GTK-free presentation logic (the "view model"),
//    unit-tested on every platform by tests/test_gui.cpp (which defines
//    LEXE_GUI_VIEWMODEL_ONLY before including this file);
//  * the GTK 3 application itself, compiled only when <gtk/gtk.h> is
//    available — i.e. only as the Linux-only `lexe-installer` CMake target
//    (built when pkg-config finds gtk+-3.0; never on Windows).
//
// The GUI links lexe_core directly and shells out to nothing. Installation
// runs OFF the UI thread (g_thread_new); the worker touches no GTK API and
// reports back via g_idle_add, which runs its callback on the main loop.

#if !defined(LEXE_GUI_VIEWMODEL_ONLY)
#if defined(__has_include)
#if !__has_include(<gtk/gtk.h>)
#define LEXE_GUI_VIEWMODEL_ONLY 1
#endif
#else
#define LEXE_GUI_VIEWMODEL_ONLY 1
#endif
#endif

#include "core/manifest.hpp"
#include "core/paths.hpp"
#include "core/verify.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

namespace lexe::gui {

// ---------------------------------------------------------------------------
// Pure presentation logic — everything the primary screen displays, as
// strings, mirroring the SPEC "User Interface" mock. No GTK types anywhere so
// this layer is unit-testable on hosts without GTK.
// ---------------------------------------------------------------------------

/// Human-readable size, decimal units, mirroring the SPEC mock
/// (125829120 bytes -> "126 MB").
inline std::string format_size(std::uint64_t bytes) {
    static const char* const kUnits[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1000.0 && unit + 1 < std::size(kUnits)) {
        value /= 1000.0;
        ++unit;
    }
    char buf[64];
    if (unit == 0) {
        std::snprintf(buf, sizeof(buf), "%llu B",
                      static_cast<unsigned long long>(bytes));
    } else if (value < 10.0) {
        std::snprintf(buf, sizeof(buf), "%.1f %s", value, kUnits[unit]);
    } else {
        std::snprintf(buf, sizeof(buf), "%.0f %s", value, kUnits[unit]);
    }
    return buf;
}

/// Map a manifest permission id (SPEC "Permission Disclosure") to user
/// language; unknown ids pass through verbatim so nothing is ever hidden.
inline std::string describe_permission(const std::string& permission) {
    if (permission == "network") return "Network access";
    if (permission == "user-files-selected") return "Access to files you select";
    if (permission == "user-files-all") return "Access to all of your files";
    if (permission == "microphone") return "Microphone access";
    if (permission == "camera") return "Camera access";
    if (permission == "notifications") return "Show notifications";
    if (permission == "removable-storage") return "Access to removable storage";
    if (permission == "background") return "Run in the background";
    if (permission == "autostart") return "Start automatically at login";
    if (permission == "system-service") return "Install a system service";
    if (permission == "device-access") return "Direct device access";
    return permission;
}

/// The "Permissions:" block: one description per line, or an explicit
/// "None requested" (permissions are informational in 0.1).
inline std::string format_permissions(const std::vector<std::string>& permissions) {
    if (permissions.empty()) return "None requested";
    std::string text;
    for (const auto& p : permissions) {
        if (!text.empty()) text += '\n';
        text += describe_permission(p);
    }
    return text;
}

/// Architecture part of the type line: the host architecture when the
/// package supports it, otherwise every architecture the package offers.
inline std::string architecture_text(const std::vector<std::string>& architectures,
                                     const std::string& host_arch) {
    if (std::find(architectures.begin(), architectures.end(), host_arch) !=
        architectures.end()) {
        return host_arch;
    }
    std::string joined;
    for (const auto& a : architectures) {
        if (!joined.empty()) joined += ", ";
        joined += a;
    }
    return joined.empty() ? std::string("unknown architecture") : joined;
}

/// SPEC mock "Application Type:" line, e.g. "Native Linux — x86_64".
inline std::string format_application_type(const std::string& application_type,
                                           const std::vector<std::string>& architectures,
                                           const std::string& host_arch) {
    const std::string type =
        application_type == "native" ? "Native Linux" : application_type;
    return type + " — " + architecture_text(architectures, host_arch);
}

/// SPEC mock "Installation:" scope line ("Current user only").
inline std::string format_install_scope(const std::string& scope) {
    if (scope == "user") return "Current user only";
    if (scope == "system") return "All users (system-wide)";
    return scope;
}

/// The full "Installation:" block: scope + size.
inline std::string format_install(const std::string& scope,
                                  std::uint64_t estimated_size) {
    std::string text = format_install_scope(scope);
    text += '\n';
    text += estimated_size > 0 ? format_size(estimated_size)
                               : std::string("Install size not specified");
    return text;
}

/// The "Source:" block. Lexe 0.1 supports bundled packages only, so the
/// source is always the package file itself.
inline std::string format_source(const std::string& install_mode,
                                 const std::string& package_filename) {
    if (install_mode == "bundled") {
        return "Bundled package — all application files are contained in " +
               package_filename;
    }
    return install_mode + " (unsupported in Lexe 0.1)";
}

/// The "Updates:" block (SPEC mock "Automatically check the developer
/// repository"), or an explicit disabled notice.
inline std::string format_updates(bool enabled, const std::string& manifest_url,
                                  const std::string& channel) {
    if (!enabled || manifest_url.empty()) {
        return "Updates are disabled for this package.";
    }
    return "Automatically check " + manifest_url + "\nChannel: " + channel;
}

/// The verification status banner. A failure names the FORMAT-0.1 §6 stage
/// and its reason, and states that installation is disabled.
inline std::string format_verification_status(const VerificationReport& report) {
    if (report.stages.empty()) {
        return "Verification could not be performed on this package.";
    }
    if (report.ok()) {
        return "Verified — structure, manifest, publisher signature and "
               "content hashes all check out.";
    }
    const VerificationStage* failure = report.first_failure();
    std::string text = "Verification FAILED at the \"" + failure->name + "\" stage";
    if (!failure->detail.empty()) text += ": " + failure->detail;
    text += ". Installation is disabled.";
    return text;
}

/// Update-channel choices for the Advanced Options combo. The standard
/// channels (SPEC "Updates") plus, first, any non-standard channel the
/// manifest configured.
inline std::vector<std::string> channel_options(const std::string& configured) {
    std::vector<std::string> options = {"stable", "beta", "nightly"};
    if (!configured.empty() &&
        std::find(options.begin(), options.end(), configured) == options.end()) {
        options.insert(options.begin(), configured);
    }
    return options;
}

/// Index of the configured channel inside channel_options(configured).
inline int channel_active_index(const std::vector<std::string>& options,
                                const std::string& configured) {
    const std::string wanted = configured.empty() ? "stable" : configured;
    const auto it = std::find(options.begin(), options.end(), wanted);
    return it == options.end() ? 0 : static_cast<int>(it - options.begin());
}

/// Advanced Options "directories used" summary (FORMAT-0.1 §9 layout).
inline std::string format_advanced_directories(const Paths& paths,
                                               const std::string& id) {
    std::string text;
    text += "Application files: " + (paths.apps_dir() / id).string() + '\n';
    text += "Application data: " + (paths.data_dir() / id).string() + '\n';
    text += "Desktop entries: " + paths.applications_dir().string() + '\n';
    text += "Icons: " + paths.icons_dir().string() + '\n';
    text += "Download cache: " + paths.cache_dir().string();
    return text;
}

/// Everything the installer window displays, precomputed as plain strings.
struct ViewModel {
    std::string app_name;
    std::string app_id;
    std::string publisher_line;   // "Published by …"
    std::string version_line;     // "Version …"
    std::string source_text;      // "Source:" block
    std::string type_text;        // "Application Type:" block
    std::string permissions_text; // "Permissions:" block
    std::string install_text;     // "Installation:" block (scope + size)
    std::string updates_text;     // "Updates:" block
    std::string status_text;      // verification banner
    bool verified = false;        // the §6 report passed
    bool can_install = false;     // verified AND the manifest is readable
    std::vector<std::string> channels;  // Advanced Options channel combo
    int active_channel = 0;             // preselected combo index
    std::string advanced_dirs_text;     // Advanced Options directory summary
};

/// Build the primary-screen view model from the verification report and the
/// (possibly unreadable) manifest. `manifest` is nullopt when the package is
/// too broken to read `lexe.json` — the screen still renders, with the
/// banner explaining the failure and Install disabled.
inline ViewModel build_view_model(const std::optional<Manifest>& manifest,
                                  const VerificationReport& report,
                                  const std::filesystem::path& package_path,
                                  const Paths& paths,
                                  const std::string& host_arch) {
    ViewModel vm;
    const std::string filename = package_path.filename().string();
    vm.verified = report.ok();
    vm.status_text = format_verification_status(report);

    if (manifest.has_value()) {
        const Manifest& m = *manifest;
        vm.app_id = m.id;
        vm.app_name = m.name;
        vm.publisher_line = "Published by " + m.publisher_name;
        if (!m.publisher_website.empty()) {
            vm.publisher_line += " (" + m.publisher_website + ")";
        }
        vm.version_line = "Version " + m.version;
        vm.source_text = format_source(m.install_mode, filename);
        vm.type_text = format_application_type(m.application_type,
                                               m.architectures, host_arch);
        vm.permissions_text = format_permissions(m.permissions);
        vm.install_text = format_install(m.install_scope, m.install_estimated_size);
        vm.updates_text = format_updates(m.updates_enabled, m.updates_manifest_url,
                                         m.updates_channel);
        vm.channels = channel_options(m.updates_channel);
        vm.active_channel = channel_active_index(vm.channels, m.updates_channel);
        vm.advanced_dirs_text = format_advanced_directories(paths, m.id);
    } else {
        vm.app_name = filename.empty() ? std::string("Unknown application")
                                       : filename;
        vm.publisher_line = "Publisher unknown";
        vm.version_line = "Version unknown";
        vm.source_text = filename.empty() ? std::string("Unknown") : filename;
        vm.type_text = "Unknown";
        vm.permissions_text = "Unknown — the manifest could not be read";
        vm.install_text = "Unknown";
        vm.updates_text = "Unknown";
        vm.channels = channel_options("stable");
        vm.active_channel = 0;
        vm.advanced_dirs_text =
            format_advanced_directories(paths, "<application-id>");
    }
    vm.can_install = vm.verified && manifest.has_value();
    return vm;
}

} // namespace lexe::gui

// ===========================================================================
// GTK 3 application. Compiled only when <gtk/gtk.h> is available — the
// Linux-only `lexe-installer` target. Never seen by non-GTK builds.
// ===========================================================================
#ifndef LEXE_GUI_VIEWMODEL_ONLY

#include "core/error.hpp"
#include "core/installer.hpp"
#include "core/launcher.hpp"
#include "core/package.hpp"

#include <gtk/gtk.h>

#include <exception>

namespace {

/// Whole-application state, owned by main(). Widget pointers are only ever
/// touched on the GTK main thread; the plain-data result fields are written
/// by exactly one worker thread and read on the main thread only after the
/// worker's final g_idle_add (which orders the accesses).
struct AppState {
    std::filesystem::path package_path;
    lexe::Paths paths;
    lexe::gui::ViewModel vm;

    // Widgets (main thread only).
    GtkWidget* window = nullptr;
    GtkWidget* stack = nullptr;
    GtkWidget* banner_label = nullptr;
    GtkWidget* install_button = nullptr;
    GtkWidget* details_close_button = nullptr;
    GtkWidget* channel_combo = nullptr;
    GtkWidget* spinner = nullptr;
    GtkWidget* progress_label = nullptr;
    GtkWidget* success_label = nullptr;
    GtkWidget* launch_button = nullptr;
    GtkWidget* launch_status_label = nullptr;

    // Install worker -> main loop.
    std::string selected_channel = "stable";
    std::string install_error;
    std::string installed_id;
    std::string installed_version;

    // Launch worker -> main loop.
    std::string launch_error;
    int launch_exit_code = 0;
};

/// Set the verification/status banner (bold, green on ok / red on failure).
void set_banner(AppState* st, bool ok, const std::string& text) {
    gchar* escaped = g_markup_escape_text(text.c_str(), -1);
    gchar* markup = g_strdup_printf(
        "<span weight=\"bold\" foreground=\"%s\">%s</span>",
        ok ? "#1a7f37" : "#b00020", escaped);
    gtk_label_set_markup(GTK_LABEL(st->banner_label), markup);
    g_free(markup);
    g_free(escaped);
}

/// Left-aligned, wrapped, selectable body label appended to `box`.
GtkWidget* add_body_label(GtkWidget* box, const std::string& text) {
    GtkWidget* label = gtk_label_new(text.c_str());
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_selectable(GTK_LABEL(label), TRUE);
    gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
    return label;
}

/// Bold heading + body block, mirroring the SPEC mock's sections. `heading`
/// is a fixed program literal (never user-controlled) so it is safe to embed
/// in markup unescaped.
void add_section(GtkWidget* box, const char* heading, const std::string& body) {
    GtkWidget* head = gtk_label_new(nullptr);
    gchar* markup = g_strdup_printf("<b>%s</b>", heading);
    gtk_label_set_markup(GTK_LABEL(head), markup);
    g_free(markup);
    gtk_label_set_xalign(GTK_LABEL(head), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), head, FALSE, FALSE, 0);
    add_body_label(box, body);
}

void on_window_destroy(GtkWidget*, gpointer) { gtk_main_quit(); }

void on_close_clicked(GtkButton*, gpointer) { gtk_main_quit(); }

// --------------------------------------------------------------- installing

/// Worker thread: runs the actual installation. NO GTK calls here — results
/// land in AppState and the main loop is notified via g_idle_add.
gboolean on_install_finished(gpointer user_data);

gpointer install_worker(gpointer user_data) {
    AppState* st = static_cast<AppState*>(user_data);
    try {
        lexe::InstallOptions opts;
        opts.channel = st->selected_channel;
        lexe::Installer installer(st->paths);
        const lexe::InstallResult result =
            installer.install(st->package_path, opts);
        st->installed_id = result.id;
        st->installed_version = result.version;
        st->install_error.clear();
    } catch (const std::exception& e) {
        st->install_error = e.what();
    } catch (...) {
        st->install_error = "unknown installation error";
    }
    g_idle_add(on_install_finished, st);
    return nullptr;
}

/// Main-loop continuation of install_worker.
gboolean on_install_finished(gpointer user_data) {
    AppState* st = static_cast<AppState*>(user_data);
    gtk_spinner_stop(GTK_SPINNER(st->spinner));
    if (!st->install_error.empty()) {
        // Back to the details screen with the failure in the banner; the
        // user may retry (verification state is unchanged).
        set_banner(st, false, "Installation failed: " + st->install_error);
        gtk_widget_set_sensitive(st->install_button, TRUE);
        gtk_widget_set_sensitive(st->details_close_button, TRUE);
        gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "details");
    } else {
        const std::string message =
            st->vm.app_name + " " + st->installed_version +
            " has been installed for the current user.";
        gtk_label_set_text(GTK_LABEL(st->success_label), message.c_str());
        gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "done");
    }
    return G_SOURCE_REMOVE;
}

void on_install_clicked(GtkButton*, gpointer user_data) {
    AppState* st = static_cast<AppState*>(user_data);
    // Read the channel choice on the main thread, before the worker starts.
    gchar* channel = gtk_combo_box_text_get_active_text(
        GTK_COMBO_BOX_TEXT(st->channel_combo));
    st->selected_channel =
        (channel != nullptr && *channel != '\0') ? channel : "stable";
    if (channel != nullptr) g_free(channel);

    gtk_widget_set_sensitive(st->install_button, FALSE);
    gtk_widget_set_sensitive(st->details_close_button, FALSE);
    gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "progress");
    gtk_spinner_start(GTK_SPINNER(st->spinner));

    GThread* thread = g_thread_new("lexe-install", install_worker, st);
    g_thread_unref(thread);
}

// ----------------------------------------------------------------- launching

gboolean on_launch_finished(gpointer user_data);

/// Worker thread: `lexe run <id>` semantics (launcher::run_app blocks until
/// the application exits, so it must stay off the UI thread). No GTK calls.
gpointer launch_worker(gpointer user_data) {
    AppState* st = static_cast<AppState*>(user_data);
    try {
        st->launch_exit_code = lexe::run_app(st->paths, st->installed_id, {});
        st->launch_error.clear();
    } catch (const std::exception& e) {
        st->launch_error = e.what();
    } catch (...) {
        st->launch_error = "unknown launch error";
    }
    g_idle_add(on_launch_finished, st);
    return nullptr;
}

gboolean on_launch_finished(gpointer user_data) {
    AppState* st = static_cast<AppState*>(user_data);
    gtk_widget_set_sensitive(st->launch_button, TRUE);
    if (!st->launch_error.empty()) {
        const std::string text = "Launch failed: " + st->launch_error;
        gtk_label_set_text(GTK_LABEL(st->launch_status_label), text.c_str());
    } else {
        const std::string text = "Application exited with code " +
                                 std::to_string(st->launch_exit_code) + ".";
        gtk_label_set_text(GTK_LABEL(st->launch_status_label), text.c_str());
    }
    return G_SOURCE_REMOVE;
}

void on_launch_clicked(GtkButton*, gpointer user_data) {
    AppState* st = static_cast<AppState*>(user_data);
    gtk_widget_set_sensitive(st->launch_button, FALSE);
    gtk_label_set_text(GTK_LABEL(st->launch_status_label), "Launching…");
    GThread* thread = g_thread_new("lexe-launch", launch_worker, st);
    g_thread_unref(thread);
}

// ------------------------------------------------------------------ screens

/// Primary screen — mirrors the SPEC "Opening a .lexe File" mock.
GtkWidget* build_details_page(AppState* st) {
    const lexe::gui::ViewModel& vm = st->vm;
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 16);

    // Verification status banner.
    st->banner_label = gtk_label_new(nullptr);
    gtk_label_set_xalign(GTK_LABEL(st->banner_label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(st->banner_label), TRUE);
    gtk_box_pack_start(GTK_BOX(box), st->banner_label, FALSE, FALSE, 0);
    set_banner(st, vm.verified, vm.status_text);

    // Application name (user-controlled: escape before markup).
    GtkWidget* name_label = gtk_label_new(nullptr);
    {
        gchar* escaped = g_markup_escape_text(vm.app_name.c_str(), -1);
        gchar* markup = g_strdup_printf(
            "<span size=\"x-large\" weight=\"bold\">%s</span>", escaped);
        gtk_label_set_markup(GTK_LABEL(name_label), markup);
        g_free(markup);
        g_free(escaped);
    }
    gtk_label_set_xalign(GTK_LABEL(name_label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(name_label), TRUE);
    gtk_box_pack_start(GTK_BOX(box), name_label, FALSE, FALSE, 0);

    add_body_label(box, vm.publisher_line);
    add_body_label(box, vm.version_line);
    add_section(box, "Source:", vm.source_text);
    add_section(box, "Application Type:", vm.type_text);
    add_section(box, "Permissions:", vm.permissions_text);
    add_section(box, "Installation:", vm.install_text);
    add_section(box, "Updates:", vm.updates_text);

    // [Advanced Options] — directories used + update channel.
    GtkWidget* expander = gtk_expander_new("Advanced Options");
    GtkWidget* advanced = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(advanced), 8);
    add_section(advanced, "Directories used:", vm.advanced_dirs_text);
    GtkWidget* channel_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(channel_row),
                       gtk_label_new("Update channel:"), FALSE, FALSE, 0);
    st->channel_combo = gtk_combo_box_text_new();
    for (const std::string& channel : vm.channels) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(st->channel_combo),
                                       channel.c_str());
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(st->channel_combo),
                             vm.active_channel);
    gtk_box_pack_start(GTK_BOX(channel_row), st->channel_combo, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(advanced), channel_row, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(expander), advanced);
    gtk_box_pack_start(GTK_BOX(box), expander, FALSE, FALSE, 0);

    // Button row: [Close] [Install].
    GtkWidget* buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(buttons, GTK_ALIGN_END);
    st->details_close_button = gtk_button_new_with_label("Close");
    g_signal_connect(st->details_close_button, "clicked",
                     G_CALLBACK(on_close_clicked), nullptr);
    st->install_button = gtk_button_new_with_label("Install");
    gtk_widget_set_sensitive(st->install_button,
                             vm.can_install ? TRUE : FALSE);
    g_signal_connect(st->install_button, "clicked",
                     G_CALLBACK(on_install_clicked), st);
    gtk_box_pack_start(GTK_BOX(buttons), st->details_close_button,
                       FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(buttons), st->install_button, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(box), buttons, FALSE, FALSE, 0);

    return box;
}

GtkWidget* build_progress_page(AppState* st) {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(box), 24);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);

    st->spinner = gtk_spinner_new();
    gtk_widget_set_size_request(st->spinner, 48, 48);
    gtk_widget_set_halign(st->spinner, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(box), st->spinner, FALSE, FALSE, 0);

    const std::string text = "Installing " + st->vm.app_name + "…";
    st->progress_label = gtk_label_new(text.c_str());
    gtk_widget_set_halign(st->progress_label, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(box), st->progress_label, FALSE, FALSE, 0);

    return box;
}

GtkWidget* build_done_page(AppState* st) {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(box), 24);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);

    st->success_label = gtk_label_new("Installed.");
    gtk_label_set_line_wrap(GTK_LABEL(st->success_label), TRUE);
    gtk_widget_set_halign(st->success_label, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(box), st->success_label, FALSE, FALSE, 0);

    st->launch_status_label = gtk_label_new("");
    gtk_label_set_line_wrap(GTK_LABEL(st->launch_status_label), TRUE);
    gtk_widget_set_halign(st->launch_status_label, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(box), st->launch_status_label, FALSE, FALSE, 0);

    GtkWidget* buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(buttons, GTK_ALIGN_CENTER);
    GtkWidget* close_button = gtk_button_new_with_label("Close");
    g_signal_connect(close_button, "clicked", G_CALLBACK(on_close_clicked),
                     nullptr);
    st->launch_button = gtk_button_new_with_label("Launch");
    g_signal_connect(st->launch_button, "clicked",
                     G_CALLBACK(on_launch_clicked), st);
    gtk_box_pack_start(GTK_BOX(buttons), close_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(buttons), st->launch_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), buttons, FALSE, FALSE, 0);

    return box;
}

void build_ui(AppState* st) {
    st->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    const std::string title = "Lexe Installer — " + st->vm.app_name;
    gtk_window_set_title(GTK_WINDOW(st->window), title.c_str());
    gtk_window_set_default_size(GTK_WINDOW(st->window), 520, 640);
    g_signal_connect(st->window, "destroy", G_CALLBACK(on_window_destroy),
                     nullptr);

    st->stack = gtk_stack_new();

    GtkWidget* scroller = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroller), build_details_page(st));

    gtk_stack_add_named(GTK_STACK(st->stack), scroller, "details");
    gtk_stack_add_named(GTK_STACK(st->stack), build_progress_page(st),
                        "progress");
    gtk_stack_add_named(GTK_STACK(st->stack), build_done_page(st), "done");
    gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "details");

    gtk_container_add(GTK_CONTAINER(st->window), st->stack);
}

/// Modal startup error (bad usage, unresolvable directories). Returns `code`
/// so main() can `return show_startup_error(…)`.
int show_startup_error(const std::string& message, int code) {
    GtkWidget* dialog = gtk_message_dialog_new(
        nullptr, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
        "%s", message.c_str());
    gtk_window_set_title(GTK_WINDOW(dialog), "Lexe Installer");
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    return code;
}

} // namespace

int main(int argc, char** argv) {
    gtk_init(&argc, &argv);

    if (argc < 2 || argv[1] == nullptr || *argv[1] == '\0') {
        return show_startup_error(
            "Usage: lexe-installer <application.lexe>\n\n"
            "Open a .lexe package to review and install it.",
            2);
    }

    // Deliberately not freed: worker threads may still reference the state
    // when the main loop quits, and the process is exiting anyway.
    AppState* st = new AppState();
    st->package_path = std::filesystem::path(argv[1]);

    try {
        st->paths = lexe::Paths::detect();
    } catch (const std::exception& e) {
        return show_startup_error(
            std::string("Cannot resolve the Lexe directories: ") + e.what(), 1);
    }

    // FORMAT-0.1 §6 pipeline, with the §6.7 architecture check — this is an
    // install flow. verify_package reports failures rather than throwing;
    // the catch below is defensive (e.g. an unreadable path).
    lexe::VerificationReport report;
    try {
        report = lexe::verify_package(st->package_path,
                                      /*check_architecture=*/true);
    } catch (const std::exception& e) {
        lexe::VerificationStage stage;
        stage.name = "structure";
        stage.ok = false;
        stage.detail = e.what();
        report.stages.push_back(stage);
    }

    // Read the manifest for display. Failures leave it empty — the screen
    // still renders and the report banner explains what went wrong.
    std::optional<lexe::Manifest> manifest;
    try {
        lexe::PackageReader reader(st->package_path);
        manifest = lexe::Manifest::parse(reader.read_entry("lexe.json"));
    } catch (const std::exception&) {
        manifest.reset();
    }

    st->vm = lexe::gui::build_view_model(manifest, report, st->package_path,
                                         st->paths, lexe::host_architecture());
    if (!st->vm.channels.empty()) {
        st->selected_channel =
            st->vm.channels[static_cast<std::size_t>(st->vm.active_channel)];
    }

    build_ui(st);
    gtk_widget_show_all(st->window);
    gtk_main();
    return 0;
}

#endif // !LEXE_GUI_VIEWMODEL_ONLY

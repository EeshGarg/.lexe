// lexe-ui — the consumer and power-user graphical frontend for .LEXE
// (Definitive Architecture, "Frontends"):
//
//     lexe-ui
//     |
//     +-- Home
//     +-- Install
//     +-- Apps
//     |   +-- App
//     |       +-- Launch
//     |       +-- Compatibility
//     |       +-- Runtime
//     |       +-- Permissions
//     |       +-- Diagnostics
//     |       +-- Error History
//     |       +-- Uninstall
//     +-- Settings
//
// Two architectural points this file exists to honour:
//
//   * ".LEXE Menu" and ".LEXE Error" are NOT separate applications. The menu is
//     the selected application's page inside this window; the error view is the
//     Error History section of that same page. `--app` and `--errors` therefore
//     do not launch anything new — they navigate this one window.
//
//   * The GUIs EXPOSE .LEXE; they do not reimplement it. Every operation here
//     goes through lexe_core (verify / Installer / run_application /
//     resolve_application_chain / AppConfig / ErrorStore / DesktopIntegration /
//     Settings). Nothing is shelled out to the CLI, and there is no second
//     packaging, verification or install engine anywhere in this file.
//
// Single instance is an architectural requirement, not a nicety: opening an app
// in .LEXE Menu while lexe-ui is already open must FOCUS the existing window and
// navigate to that app. That is implemented with GtkApplication +
// G_APPLICATION_HANDLES_COMMAND_LINE, so a second invocation is forwarded to the
// primary instance as a command line instead of starting a second process.
//
// The file has two layers, exactly like src/gui/main.cpp and src/gui/builder.cpp:
//  * `lexe::ui` — pure, GTK-free presentation logic (the "view model"),
//    unit-tested on every platform by tests/test_ui.cpp (which defines
//    LEXE_GUI_VIEWMODEL_ONLY before including this file);
//  * the GTK 3 application itself, compiled only when <gtk/gtk.h> is available
//    — the Linux-only `lexe-ui` CMake target.
//
// Long operations (verify, install, launch, health check, integration repair)
// run on a worker thread created with g_thread_new; the worker touches NO GTK
// API and reports back through g_idle_add, whose callback runs on the main loop.

#if !defined(LEXE_GUI_VIEWMODEL_ONLY)
#if defined(__has_include)
#if !__has_include(<gtk/gtk.h>)
#define LEXE_GUI_VIEWMODEL_ONLY 1
#endif
#else
#define LEXE_GUI_VIEWMODEL_ONLY 1
#endif
#endif

// The install flow — the FORMAT-0.1 §6 verification pipeline, the consent
// screen's strings and the two-dimensional authenticity banner — already exists
// in the installer. Include ITS pure view model rather than growing a second
// copy: `lexe::gui::build_view_model` and friends are reused verbatim below.
// The include always suppresses the installer's own GTK layer (it owns a
// main(); this file owns ours).
#if defined(LEXE_GUI_VIEWMODEL_ONLY)
#include "gui/main.cpp"
#else
#define LEXE_GUI_VIEWMODEL_ONLY 1
#include "gui/main.cpp"
#undef LEXE_GUI_VIEWMODEL_ONLY
#endif

#include "core/appconfig.hpp"
#include "core/diagnostics.hpp"
#include "core/execpolicy.hpp"
#include "core/installer.hpp"
#include "core/integration.hpp"
#include "core/isolation.hpp"
#include "core/launcher.hpp"
#include "core/manifest.hpp"
#include "core/paths.hpp"
#include "core/presentation.hpp"
#include "core/registry.hpp"
#include "core/settings.hpp"
#include "core/trust.hpp"
#include "core/verify.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace lexe::ui {

// ---------------------------------------------------------------------------
// Pure presentation logic. Everything the window displays is computed here as
// plain strings/values from typed core results, so the wording is unit-tested
// without GTK. Nothing in this namespace performs I/O.
//
// Wording rule (presentation.hpp): this layer NEVER writes "verified",
// "trusted" (unqualified), "safe" or "secure" on its own authority. Anything
// about authenticity, permissions or isolation is routed through
// lexe::presentation (directly, or through lexe::gui's installer view model,
// which does the same).
// ---------------------------------------------------------------------------

/// Join non-empty lines with newlines.
inline std::string join_lines(const std::vector<std::string>& lines) {
    std::string text;
    for (const std::string& line : lines) {
        if (line.empty()) continue;
        if (!text.empty()) text += '\n';
        text += line;
    }
    return text;
}

/// "  • item" per line, or `empty_text` when there is nothing to list.
inline std::string bullet_list(const std::vector<std::string>& items,
                               const std::string& empty_text) {
    if (items.empty()) return empty_text;
    std::string text;
    for (const std::string& item : items) {
        if (!text.empty()) text += '\n';
        text += "  • " + item;
    }
    return text;
}

/// "1 thing" / "3 things".
inline std::string count_of(std::size_t n, const std::string& singular,
                            const std::string& plural) {
    return std::to_string(n) + " " + (n == 1 ? singular : plural);
}

// ------------------------------------------------------------- command line

/// What this invocation asked the (single) window to do.
enum class StartMode {
    Home,         // lexe-ui
    OpenFile,     // lexe-ui --open <file.lexe>  — THE .lexe handler entry point
    AppPage,      // lexe-ui --app <id>          — ".LEXE Menu"
    ErrorHistory, // lexe-ui --errors <id>       — ".LEXE Error"
    Usage,        // --help, or a command line that was rejected
};

struct StartRequest {
    StartMode mode = StartMode::Home;
    std::string argument; // file path (OpenFile) or application id
    std::string message;  // usage / rejection text (Usage only)
    bool bad = false;     // true when the command line was rejected
};

inline std::string usage_text() {
    return "lexe-ui — the .LEXE application frontend\n"
           "\n"
           "Usage:\n"
           "  lexe-ui                      open at Home\n"
           "  lexe-ui --open <file.lexe>   open a .lexe artifact; the SIGNED\n"
           "                               manifest role decides whether that\n"
           "                               installs an application or launches\n"
           "                               an installed one\n"
           "  lexe-ui --app <id>           open an installed application's page\n"
           "  lexe-ui --errors <id>        open an application's error history\n"
           "  lexe-ui --help               show this text\n"
           "\n"
           "A second invocation focuses the window that is already open and\n"
           "navigates it; it never starts a second lexe-ui.\n";
}

/// Parse the arguments AFTER argv[0]. Pure, so the handler contract is tested
/// rather than trusted. A bare path is accepted and takes exactly the --open
/// route, because some desktops pass the file positionally.
inline StartRequest parse_command_line(const std::vector<std::string>& args) {
    StartRequest req;
    if (args.empty()) return req;

    auto reject = [&req](const std::string& why) {
        req.mode = StartMode::Usage;
        req.bad = true;
        req.message = why + "\n\n" + usage_text();
        return req;
    };

    if (args[0] == "--help" || args[0] == "-h") {
        req.mode = StartMode::Usage;
        req.message = usage_text();
        return req;
    }

    std::string flag = args[0];
    std::string value;
    bool have_value = false;
    std::size_t consumed = 1;

    if (flag.rfind("--", 0) != 0) {
        // Positional path: `lexe-ui /path/App.lexe`.
        value = args[0];
        flag = "--open";
        have_value = true;
    } else {
        const std::size_t eq = flag.find('=');
        if (eq != std::string::npos) {
            value = flag.substr(eq + 1);
            flag = flag.substr(0, eq);
            have_value = true;
        } else if (args.size() > 1) {
            value = args[1];
            have_value = true;
            consumed = 2;
        }
    }

    if (args.size() > consumed) {
        return reject("unexpected extra argument \"" + args[consumed] + "\"");
    }
    if (flag != "--open" && flag != "--app" && flag != "--errors") {
        return reject("unknown option \"" + flag + "\"");
    }
    if (!have_value || value.empty()) {
        return reject(flag + " needs a value");
    }

    if (flag == "--open") {
        req.mode = StartMode::OpenFile;
        req.argument = value;
        return req;
    }
    if (!app_id_is_valid(value)) {
        return reject("\"" + value + "\" is not a valid application id");
    }
    req.mode = flag == "--app" ? StartMode::AppPage : StartMode::ErrorHistory;
    req.argument = value;
    return req;
}

// --------------------------------------------------- --open role dispatch

/// What opening a `.lexe` artifact must do. Decided by the SIGNED manifest
/// role (Definitive Architecture §15.1) — never by the file's name, which is
/// not signed and can be changed by anyone who can rename a file.
enum class OpenAction {
    Install,   // role "application": review-and-install
    LaunchApp, // role "launch": navigate to the named app and launch it
    Refuse,    // the artifact did not verify, or its role cannot be acted on
};

struct OpenDispatch {
    OpenAction action = OpenAction::Refuse;
    std::string application_id; // LaunchApp: launch.applicationId
    std::string reason;         // always set; names the deciding fact
};

inline OpenDispatch decide_open_dispatch(const VerificationReport& report,
                                         const std::optional<Manifest>& manifest) {
    OpenDispatch dispatch;
    if (!report.ok()) {
        const VerificationStage* failure = report.first_failure();
        dispatch.reason =
            failure != nullptr
                ? "Verification failed at the \"" + failure->name +
                      "\" stage: " + failure->detail + "."
                : std::string("Verification did not run to completion for this "
                              "file.");
        dispatch.reason += " Nothing was installed and nothing was launched.";
        return dispatch;
    }
    if (!manifest.has_value()) {
        dispatch.reason = "The manifest of this file could not be read, so its "
                          "role is unknown. Nothing was installed and nothing "
                          "was launched.";
        return dispatch;
    }
    switch (manifest->role) {
    case PackageRole::Application:
        dispatch.action = OpenAction::Install;
        dispatch.reason = "The signed manifest declares role \"application\", "
                          "so this opens the install review for " +
                          manifest->name + ".";
        return dispatch;
    case PackageRole::Launch:
        dispatch.application_id = manifest->launch_application_id;
        if (dispatch.application_id.empty()) {
            dispatch.reason = "The signed manifest declares role \"launch\" but "
                              "names no application to launch.";
            return dispatch;
        }
        dispatch.action = OpenAction::LaunchApp;
        dispatch.reason = "The signed manifest declares role \"launch\", so this "
                          "is a launch reference for " + dispatch.application_id +
                          " — nothing is installed.";
        return dispatch;
    }
    dispatch.reason = "This artifact declares a role this runtime does not "
                      "understand.";
    return dispatch;
}

/// Explanation shown when a launch reference names an application that is not
/// installed on this machine.
inline std::string missing_launch_target_text(const std::string& id) {
    return "This is a launch reference for " + id +
           ", but that application is not installed on this machine. Install "
           "the application package first; a launch reference carries no "
           "payload of its own.";
}

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
//     goes through lexe_engine (verify / Installer / run_application /
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
// The file has two layers, exactly like src/gui/lexe-builder/builder.cpp:
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
// screen's strings and the two-dimensional authenticity banner — is shared
// presentation logic, not this window's private business. It lives in a header
// both frontends include: `lexe::gui::build_view_model` and friends below come
// from there, and no second copy of it exists anywhere.
#include "gui/package_view.hpp"

#include "lexe/state/appconfig.hpp"
#include "lexe/diagnostics/diagnostics.hpp"
#include "lexe/runtime/execpolicy.hpp"
#include "lexe/install/installer.hpp"
#include "lexe/integration/integration.hpp"
#include "lexe/sandbox/isolation.hpp"
#include "lexe/runtime/launcher.hpp"
#include "lexe/package/manifest.hpp"
#include "lexe/base/paths.hpp"
#include "lexe/diagnostics/presentation.hpp"
#include "lexe/state/registry.hpp"
#include "lexe/base/settings.hpp"
#include "lexe/verify/trust.hpp"
#include "lexe/verify/verify.hpp"

// The shared visual language of both frontends (gui/style.hpp), needed only by
// the GTK layer below.
#if !defined(LEXE_GUI_VIEWMODEL_ONLY)
#include "gui/style.hpp"
#endif

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

// ------------------------------------------------------------- Apps list

/// "Last launched …" line for an installed application. An exit code of 0 is
/// stated as success here too, for the same reason it is on the Launch page.
inline std::string format_last_run(const std::string& last_run_at,
                                   int last_exit_code) {
    if (last_run_at.empty()) return "Never launched through .LEXE";
    std::string text = "Last launched " + last_run_at;
    text += last_exit_code == 0
                ? " — exited 0 (success)"
                : " — exited " + std::to_string(last_exit_code);
    return text;
}

/// The LOCAL trust state of an installed application, from its local trust
/// record. Local only: this is a record of what this machine has seen, never a
/// statement about the publisher's real-world identity.
inline std::string format_local_trust(const std::optional<TrustRecord>& record) {
    if (!record.has_value()) {
        return "No local signing-key record — this machine has not recorded a "
               "publisher key for this application.";
    }
    if (record->blocked) {
        return "Locally blocked on this machine" +
               (record->blocked_at.empty() ? std::string()
                                           : " since " + record->blocked_at) +
               ".";
    }
    if (record->explicitly_trusted) {
        return "Signing key recorded and explicitly trusted on this machine — a "
               "local decision only, not a check of the publisher's identity.";
    }
    return "Signing key recorded on this machine" +
           (record->first_seen.empty() ? std::string()
                                       : ", first seen " + record->first_seen) +
           " — a local record only, not a check of the publisher's identity.";
}

/// One row of the Apps list.
struct AppRow {
    std::string id;
    std::string title;
    std::string subtitle;   // version + id
    std::string last_run;
    std::string trust_line;
};

inline AppRow build_app_row(const InstallationRecord& record,
                            const std::optional<Manifest>& manifest,
                            const std::optional<TrustRecord>& trust) {
    AppRow row;
    row.id = record.id;
    row.title = manifest.has_value() && !manifest->name.empty() ? manifest->name
                                                                : record.id;
    row.subtitle =
        "Version " + (record.version.empty() ? std::string("unknown")
                                             : record.version) +
        "  ·  " + record.id;
    if (!record.last_chain.empty()) {
        row.subtitle += "  ·  last chain: " + record.last_chain;
    }
    row.last_run = format_last_run(record.last_run_at, record.last_exit_code);
    row.trust_line = format_local_trust(trust);
    return row;
}

inline std::string format_installed_count(std::size_t installed) {
    if (installed == 0) {
        return "No applications are installed yet. Open a .lexe file to install "
               "one.";
    }
    return count_of(installed, "application is", "applications are") +
           " installed for this user.";
}

// -------------------------------------------------------------- Launch

/// The declared launch presentation, in the user's language. Presentation is
/// DECLARED by the package, never inferred from whether a terminal appeared
/// (Definitive Architecture §14.4).
inline std::string format_launch_mode(LaunchMode mode) {
    switch (mode) {
    case LaunchMode::Gui:
        return "Declared as a GUI application: it opens its own window. Exit "
               "code 0 means it finished successfully, even if you never saw a "
               "window.";
    case LaunchMode::Console:
        return "Declared as a console application: .LEXE provides a terminal "
               "for it, or captures its output, so a console program is never "
               "mistaken for a launch that did nothing.";
    case LaunchMode::Service:
        return "Declared as a service: it runs detached in the background. No "
               "terminal and no window are expected.";
    }
    return "Launch presentation not declared.";
}

inline std::string format_mission_critical(bool mission_critical) {
    if (!mission_critical) return "";
    return "This application is declared mission-critical: it may run only "
           "Linux-native, on the host's own instruction set, from a verified "
           "install. ISA translation, Wine/Proton and any \"run anyway\" "
           "fallback are refused for it. That is an execution restriction, not "
           "a certification of the application.";
}

/// The plain-language outcome of a launch. The architecture is explicit that
/// exit code 0 is SUCCESS even when nothing appeared on screen — the alpha's
/// "console Hello World looked like a failed launch" is exactly the bug this
/// wording exists to prevent, so it is stated rather than implied.
struct LaunchLines {
    std::string headline;
    std::string detail;
    std::string severity = "caution"; // "ok" | "caution" | "danger"
    bool has_error = false;           // an error record was written
};

inline LaunchLines format_execution_report(const ExecutionReport& report) {
    LaunchLines lines;
    lines.has_error = report.error.has_value();

    if (!report.started) {
        lines.severity = "danger";
        lines.headline = "The application was not started.";
    } else if (report.detached) {
        lines.severity = "ok";
        lines.headline = "Started. It is running independently of this window.";
    } else if (report.signal.has_value()) {
        lines.severity = "danger";
        lines.headline = "The application was killed by signal " +
                         std::to_string(*report.signal) + ".";
    } else if (report.exit_code == 0) {
        lines.severity = "ok";
        lines.headline = "Exit code 0 — the application ran and reported "
                         "success.";
    } else {
        lines.severity = "danger";
        lines.headline = "The application exited with code " +
                         std::to_string(report.exit_code) + ".";
    }

    std::vector<std::string> detail;
    if (report.started && !report.detached && !report.signal.has_value() &&
        report.exit_code == 0) {
        detail.push_back(
            "Exit code 0 is success even if no window ever appeared: a console "
            "or service application can do its whole job without showing "
            "anything on screen. This is NOT a failed launch.");
    }
    if (report.detached) {
        detail.push_back("A detached launch reports no exit code here; look in "
                         "Error History if it fails later.");
    }
    if (!report.chain.empty()) {
        std::string chain = "Execution chain: " + report.chain;
        if (!report.chain_reason.empty()) chain += " — " + report.chain_reason;
        detail.push_back(chain);
    }
    if (!report.version.empty()) {
        detail.push_back("Version launched: " + report.version);
    }
    if (!report.launch_mode.empty()) {
        detail.push_back("Declared launch presentation: " + report.launch_mode);
    }
    if (report.mission_critical) {
        detail.push_back("Mission-critical: native execution only.");
    }
    if (!report.isolation_summary.empty()) {
        detail.push_back("Isolation: " + report.isolation_summary);
    }
    if (lines.has_error) {
        detail.push_back("A structured error record was written for this "
                         "launch — open Error History for the full details.");
    }
    lines.detail = join_lines(detail);
    return lines;
}

/// A launch that was REFUSED (the core threw). run_application guarantees an
/// error record has already been written when it throws, so the view always
/// offers Error History for this case.
inline LaunchLines format_launch_failure(const std::string& message) {
    LaunchLines lines;
    lines.severity = "danger";
    lines.has_error = true;
    lines.headline = "The launch was refused: " + message;
    lines.detail = "The application was not executed. A structured error record "
                   "was written — open Error History for the stage that failed.";
    return lines;
}

// -------------------------------------------------------- Compatibility

/// One selectable execution chain. Populated ONLY from what the resolver
/// actually offers (§8: "only chains allowed by the package policy are shown").
struct ChainOption {
    std::string id;
    std::string detail;
    bool selected = false; // this is the chain the resolver chose
};

struct CompatibilityView {
    bool resolved = false;
    std::string selected_line;
    std::string reason_line;
    std::vector<ChainOption> options;
    std::vector<std::string> rejected_lines;
    bool locked = false;          // mission-critical: not user-changeable
    std::string locked_reason;
    bool automatic = true;        // the saved user mode
    std::string manual_chain;     // the saved manual preference ("" when none)
    int active_option = -1;       // index of manual_chain in options, else -1
    std::string stale_preference; // set when the saved preference is not offered
};

inline CompatibilityView build_compatibility_view(const ChainResolution& resolution,
                                                  const AppConfig& config) {
    CompatibilityView view;
    view.resolved = resolution.ok;
    view.automatic = config.compatibility_mode == CompatibilityMode::Automatic;
    if (!config.preferred_chain.empty()) {
        view.manual_chain = config.preferred_chain.front();
    }

    if (resolution.ok) {
        view.selected_line = "Selected execution chain: " + resolution.chain.id;
        if (!resolution.chain.explanation.empty()) {
            view.selected_line += " — " + resolution.chain.explanation;
        }
        view.options.push_back(
            ChainOption{resolution.chain.id, resolution.chain.explanation, true});
    } else {
        view.selected_line = "No execution chain is available for this "
                             "application on this machine.";
    }
    view.reason_line = resolution.reason;

    for (const ExecutionChain& alternative : resolution.alternatives) {
        bool already = false;
        for (const ChainOption& option : view.options) {
            if (option.id == alternative.id) already = true;
        }
        if (already) continue;
        view.options.push_back(
            ChainOption{alternative.id, alternative.explanation, false});
    }
    for (const RejectedChain& rejected : resolution.rejected) {
        view.rejected_lines.push_back(rejected.id + " — " + rejected.reason);
    }

    if (resolution.mission_critical) {
        view.locked = true;
        view.locked_reason =
            "This application is declared mission-critical, so it is locked to "
            "the native execution chain: no ISA translation, no Wine/Proton, no "
            "compatibility fallback and no \"run anyway\". The choice below "
            "cannot be changed for this application.";
    }

    if (!view.manual_chain.empty()) {
        for (std::size_t i = 0; i < view.options.size(); ++i) {
            if (view.options[i].id == view.manual_chain) {
                view.active_option = static_cast<int>(i);
                break;
            }
        }
        if (view.active_option < 0 && !view.automatic) {
            view.stale_preference =
                "Your saved preference \"" + view.manual_chain +
                "\" is not available for this application right now, so .LEXE "
                "fell back to what the package policy and this host allow. "
                "Only the chains listed here can be chosen.";
        }
    }
    return view;
}

// ------------------------------------------------------------- Runtime

/// The runtime-resolution state recorded at install/repair time. The expensive
/// dependency analysis happens ONCE, at install; this shows its result.
inline std::string format_runtime_block(const InstallationRecord& record) {
    std::vector<std::string> lines;
    lines.push_back("Dependency source: " +
                    (record.runtime_source.empty()
                         ? std::string("not recorded for this install")
                         : record.runtime_source));
    lines.push_back(
        "Resolved at: " +
        (record.runtime_resolved_at.empty()
             ? std::string("never — this install predates runtime resolution, "
                           "or has not been repaired since")
             : record.runtime_resolved_at));
    lines.push_back("Highest glibc requirement: " +
                    (record.runtime_glibc.empty()
                         ? std::string("none recorded")
                         : record.runtime_glibc));
    if (record.runtime_unresolved.empty()) {
        lines.push_back("Unresolved libraries: none — every library the payload "
                        "needs was resolved when it was installed.");
    } else {
        lines.push_back("Unresolved libraries (" +
                        std::to_string(record.runtime_unresolved.size()) + "):");
        lines.push_back(bullet_list(record.runtime_unresolved, ""));
        lines.push_back(
            "While these are unresolved the dependency contract is not "
            "satisfied: a launch records a runtime-resolution failure instead of "
            "executing into a broken loader.");
    }
    if (!record.last_chain.empty()) {
        lines.push_back("Last execution chain used: " + record.last_chain);
    }
    if (!record.last_launch_mode.empty()) {
        lines.push_back("Last declared launch presentation: " +
                        record.last_launch_mode);
    }
    return join_lines(lines);
}

inline std::string format_health(const HealthReport& health) {
    if (health.ok) {
        return "Health check passed: the manifest, the declared entrypoint and "
               "every recorded payload file are present and match the hashes "
               "recorded at install.";
    }
    return "Health check found " +
           count_of(health.issues.size(), "issue", "issues") + ":\n" +
           bullet_list(health.issues, "");
}

// -------------------------------------------- Desktop integration / Home

struct HealthTile {
    std::string headline;
    std::string detail;
    std::string severity = "caution"; // "ok" | "caution" | "danger"
    bool needs_repair = false;
};

/// The Home "System health" tile, from DesktopIntegration::verify(). The
/// architecture's reboot test is the point: a missing artifact is a named,
/// repairable state, not a mystery.
inline HealthTile build_health_tile(const IntegrationReport& report) {
    HealthTile tile;
    const std::size_t problems = report.problem_count();
    std::vector<std::string> detail;

    for (const ArtifactCheck& check : report.checks) {
        if (check.health == ArtifactHealth::Ok) continue;
        std::string line = std::string(to_string(check.artifact.kind)) + " " +
                           to_string(check.health) + ": " + check.artifact.path;
        if (!check.detail.empty()) line += " (" + check.detail + ")";
        detail.push_back(line);
    }
    for (const std::string& app : report.unregistered_apps) {
        detail.push_back(app + " is installed but has no desktop integration "
                               "recorded.");
    }
    for (const std::string& orphan : report.orphaned) {
        detail.push_back("Left behind by an application that is no longer "
                         "installed: " + orphan);
    }
    for (const std::string& note : report.notes) detail.push_back(note);

    if (report.ok && problems == 0) {
        tile.severity = "ok";
        tile.headline = "Desktop integration is in place.";
        detail.insert(detail.begin(),
                      count_of(report.checks.size(), "registration",
                               "registrations") +
                          " .LEXE owns are present and unchanged.");
    } else {
        tile.severity = "caution";
        tile.needs_repair = true;
        tile.headline = problems == 0
                            ? std::string("Desktop integration needs attention.")
                            : count_of(problems, "integration problem",
                                       "integration problems") + " found.";
        detail.push_back("Repair re-establishes everything .LEXE owns from the "
                         "installed manifests; no package file is needed.");
    }
    tile.detail = join_lines(detail);
    return tile;
}

inline std::string format_repair_result(const IntegrationReport& report) {
    std::vector<std::string> lines;
    lines.push_back(
        report.ok ? "Integration repaired: every registration .LEXE owns is now "
                    "in place."
                  : "Repair ran, but some registrations could not be "
                    "re-established.");
    if (!report.repaired.empty()) {
        lines.push_back("Re-established:");
        lines.push_back(bullet_list(report.repaired, ""));
    }
    if (!report.unrepaired.empty()) {
        lines.push_back("Could not repair:");
        lines.push_back(bullet_list(report.unrepaired, ""));
    }
    return join_lines(lines);
}

// -------------------------------------------------------- Error History

inline std::string format_error_row(const ErrorRecord& record) {
    std::string head = record.timestamp.empty() ? std::string("(no timestamp)")
                                                : record.timestamp;
    head += "  ·  " + std::string(to_string(record.stage));
    if (record.exit_code.has_value()) {
        head += "  ·  exit " + std::to_string(*record.exit_code);
    }
    if (record.signal.has_value()) {
        head += "  ·  signal " + std::to_string(*record.signal);
    }
    if (!record.execution_chain.empty()) {
        head += "  ·  " + record.execution_chain;
    }
    return head + "\n" +
           (record.summary.empty() ? std::string("(no summary recorded)")
                                   : record.summary);
}

inline std::string format_error_history_empty(const std::string& id) {
    return "No error records for " + id +
           ". A record is written whenever a launch is refused or an "
           "application fails, so an empty history means nothing has failed "
           "through .LEXE on this machine.";
}

// ------------------------------------------------------------ Uninstall

inline std::string uninstall_mode_label(Installer::UninstallMode mode) {
    switch (mode) {
    case Installer::UninstallMode::AppOnly:
        return "Remove the application (keep my data)";
    case Installer::UninstallMode::AppAndCache:
        return "Remove the application and its cache (keep my data)";
    case Installer::UninstallMode::PurgeData:
        return "Remove everything, including my data";
    }
    return "Remove the application";
}

inline std::string uninstall_mode_description(Installer::UninstallMode mode) {
    switch (mode) {
    case Installer::UninstallMode::AppOnly:
        return "Deletes the installed program files and everything .LEXE "
               "registered for it (menu entry, icons, file associations, launch "
               "reference). Your saved data and its cache are kept, so "
               "reinstalling later picks them up again.";
    case Installer::UninstallMode::AppAndCache:
        return "As above, and also deletes the application's cache directory. "
               "Your saved data is still kept. Use this to reclaim space "
               "without losing anything you created.";
    case Installer::UninstallMode::PurgeData:
        return "As above, and also deletes the application's persistent data "
               "directory — documents, profiles and settings the application "
               "saved. This cannot be undone, and reinstalling starts from "
               "scratch.";
    }
    return "";
}

inline std::string uninstall_confirmation(const std::string& name,
                                          const std::string& id,
                                          Installer::UninstallMode mode) {
    std::string text = "Remove " + name + " (" + id + ")?\n\n" +
                       uninstall_mode_description(mode);
    if (mode != Installer::UninstallMode::PurgeData) {
        text += "\n\nYour saved data is NOT deleted by this choice.";
    } else {
        text += "\n\nThis permanently deletes the saved data as well.";
    }
    return text;
}

// ---------------------------------------------------------- Permissions

/// The permission block, built from presentation::present_permissions() so the
/// enforcement wording is the single truthful one shared with the CLI.
inline std::string
format_permission_rows(const std::vector<presentation::PermissionView>& views) {
    if (views.empty()) {
        return "This application requests no permissions.";
    }
    std::vector<std::string> lines;
    for (const presentation::PermissionView& view : views) {
        lines.push_back(view.title + "  [" + view.enforcement + "]");
    }
    return join_lines(lines);
}

/// What the user actually approved at install time, recorded per version.
inline std::string
format_approved_permissions(const std::vector<std::string>& approved) {
    if (approved.empty()) {
        return "No permissions were approved for the installed version.";
    }
    std::vector<std::string> titles;
    for (const std::string& id : approved) {
        titles.push_back(presentation::describe_permission(id));
    }
    return "Approved for the installed version:\n" + bullet_list(titles, "");
}

// ---------------------------------------------------------- Diagnostics

/// The per-application storage taxonomy, as displayed. Every value comes from
/// the core path API (Registry / Paths / ErrorStore / launchref / AppConfig) —
/// the UI never builds a .LEXE path by string concatenation of its own.
struct AppLocations {
    std::string version_dir;
    std::string data_dir;
    std::string cache_dir;
    std::string error_dir;
    std::string launch_reference;
    std::string config_file;
};

inline std::string format_app_locations(const AppLocations& locations) {
    std::vector<std::string> lines;
    lines.push_back("Installed version files: " + locations.version_dir);
    lines.push_back("Persistent data: " + locations.data_dir);
    lines.push_back("Cache: " + locations.cache_dir);
    lines.push_back("Error records: " + locations.error_dir);
    lines.push_back("Launch reference: " + locations.launch_reference);
    lines.push_back("Your compatibility overrides: " + locations.config_file);
    return join_lines(lines);
}

/// The "Copy diagnostics" payload: one self-contained block a user can paste
/// into a bug report without hunting through the UI.
inline std::string format_diagnostics_text(const std::string& runtime_version,
                                           const std::string& host_os,
                                           const std::string& host_isa,
                                           const InstallationRecord& record,
                                           const AppLocations& locations,
                                           const std::string& chain_text,
                                           const std::string& health_text,
                                           const std::string& integration_text) {
    std::vector<std::string> lines;
    lines.push_back("lexe-ui diagnostics");
    lines.push_back("Runtime: " + runtime_version);
    lines.push_back("Host: " + host_os + " (" + host_isa + ")");
    lines.push_back("");
    lines.push_back("Application: " + record.id);
    lines.push_back("Version: " + record.version);
    lines.push_back("Installed at: " + record.installed_at);
    lines.push_back("Source: " + record.source);
    lines.push_back("Channel: " + record.channel);
    lines.push_back(format_last_run(record.last_run_at, record.last_exit_code));
    lines.push_back("");
    lines.push_back("Runtime resolution:");
    lines.push_back(format_runtime_block(record));
    lines.push_back("");
    lines.push_back("Execution:");
    lines.push_back(chain_text);
    lines.push_back("");
    lines.push_back("Health:");
    lines.push_back(health_text);
    lines.push_back("");
    lines.push_back("Desktop integration:");
    lines.push_back(integration_text);
    lines.push_back("");
    lines.push_back("Locations:");
    lines.push_back(format_app_locations(locations));
    // join_lines drops empties, so blank separators are emitted explicitly.
    std::string text;
    for (const std::string& line : lines) {
        text += line;
        text += '\n';
    }
    return text;
}

/// The compact "how would this run" text used by Diagnostics and by the copy
/// payload. Built from the same ChainResolution the Compatibility page shows.
inline std::string format_chain_summary(const ChainResolution& resolution) {
    std::vector<std::string> lines;
    if (resolution.ok) {
        lines.push_back("Chain: " + resolution.chain.id);
    } else {
        lines.push_back("Chain: none available");
    }
    lines.push_back("Reason: " + resolution.reason);
    lines.push_back(resolution.mission_critical
                        ? "Policy: mission-critical (native only)"
                        : "Policy: normal compatibility resolution");
    if (!resolution.rejected.empty()) {
        std::vector<std::string> rejected;
        for (const RejectedChain& item : resolution.rejected) {
            rejected.push_back(item.id + " — " + item.reason);
        }
        lines.push_back("Not used:");
        lines.push_back(bullet_list(rejected, ""));
    }
    return join_lines(lines);
}

// ------------------------------------------------------------- Settings

inline std::string setting_title(const std::string& key) {
    if (key == "theme") return "Theme";
    if (key == "updateCheck") return "Update checks";
    if (key == "developerMode") return "Developer mode";
    if (key == "diagnostics") return "Verbose diagnostics";
    return key;
}

inline std::string setting_help(const std::string& key) {
    if (key == "theme") {
        return "A display hint only. It changes nothing about how applications "
               "are verified or run.";
    }
    if (key == "updateCheck") {
        return "Whether .LEXE offers to check a publisher's update manifest. "
               "\"never\" does not disable signature or integrity checking — "
               "those always run.";
    }
    if (key == "developerMode") {
        return "Surfaces extra developer-facing detail in the frontends. It "
               "grants no additional authority.";
    }
    if (key == "diagnostics") {
        return "Verbose diagnostic logging. Error records are always written "
               "whether or not this is on.";
    }
    return "";
}

/// The allowed values of a settings key, for a combo box. Empty for the
/// boolean keys, which get a switch instead.
inline std::vector<std::string> setting_choices(const std::string& key) {
    if (key == "theme") return {"system", "light", "dark"};
    if (key == "updateCheck") return {"manual", "never"};
    return {};
}

inline bool setting_is_boolean(const std::string& key) {
    return key == "developerMode" || key == "diagnostics";
}

/// A note stating what settings can NOT do, shown on the Settings page.
inline std::string settings_scope_note() {
    return "These are workflow and display preferences. Signature and payload "
           "verification, launch-time integrity checks, permission consent and "
           "fail-closed isolation are always enforced and are deliberately not "
           "settings.";
}

/// Whether this machine currently has .LEXE registered as the handler for
/// `.lexe` files, from the recorded integration state.
inline std::string format_handler_state(const IntegrationReport& report) {
    bool handler_seen = false;
    bool handler_ok = false;
    bool mime_seen = false;
    bool mime_ok = false;
    for (const ArtifactCheck& check : report.checks) {
        if (check.artifact.kind == ArtifactKind::RuntimeHandler) {
            handler_seen = true;
            handler_ok = check.health == ArtifactHealth::Ok;
        } else if (check.artifact.kind == ArtifactKind::RuntimeMime) {
            mime_seen = true;
            mime_ok = check.health == ArtifactHealth::Ok;
        }
    }
    if (!handler_seen && !mime_seen) {
        return "No .LEXE handler registration is recorded on this machine. "
               "Until it is registered, opening a .lexe file from a file "
               "manager will not reach .LEXE.";
    }
    if (handler_ok && mime_ok) {
        return "The .lexe file type and its handler entry are both registered "
               "and unchanged. Opening a .lexe file from a file manager reaches "
               ".LEXE, and that survives logout and reboot.";
    }
    std::vector<std::string> problems;
    if (mime_seen && !mime_ok) {
        problems.push_back("the .lexe file-type declaration is missing or has "
                           "been changed");
    }
    if (handler_seen && !handler_ok) {
        problems.push_back("the handler entry that owns the .lexe type is "
                           "missing or has been changed");
    }
    if (!mime_seen) problems.push_back("no .lexe file-type declaration is recorded");
    if (!handler_seen) problems.push_back("no handler entry is recorded");
    std::string joined;
    for (const std::string& problem : problems) {
        if (!joined.empty()) joined += ", ";
        joined += problem;
    }
    return "Handler registration needs repair: " + joined +
           ". Re-register to put it back.";
}

} // namespace lexe::ui

// ===========================================================================
// GTK 3 application. Compiled only when <gtk/gtk.h> is available — the
// Linux-only `lexe-ui` target. Never seen by non-GTK builds.
// ===========================================================================
#ifndef LEXE_GUI_VIEWMODEL_ONLY

#include "lexe/base/error.hpp"
#include "lexe/runtime/launchref.hpp"
#include "lexe/package/package.hpp"
#include "lexe/sandbox/permissions.hpp"
#include "lexe/base/util.hpp"
#include "lexe/base/version.hpp"

#include <gtk/gtk.h>

#include <exception>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <system_error>
#include <utility>

namespace {

namespace fs = std::filesystem;
namespace style = lexe::gui::style;

struct Ui;
/// Defined beside build_window, which takes the "what does the desktop want?"
/// snapshot it depends on; declared here because the Settings handler above it
/// is what makes a theme change take effect.
void apply_theme(Ui* ui, const std::string& value);

/// The single-instance identity. A second `lexe-ui` invocation with this id is
/// forwarded to the running process as a command line instead of starting a
/// second window (Definitive Architecture: ".LEXE Menu" must focus the window
/// that is already open and navigate it).
constexpr const char* kApplicationId = "com.usha.lexe.Ui";

// ---------------------------------------------------------------------------
// Whole-application state, owned by main(). Widget pointers are touched ONLY
// on the GTK main thread. Worker threads never read or write this struct: a
// task owns its own result object and the main-loop continuation copies the
// result in, so there is no shared mutable state across threads.
//
// Every page is REBUILT from this state (clear the container, build it again),
// which is why no worker continuation ever holds a widget pointer: by the time
// it runs, the widgets it might have captured may already be gone.
// ---------------------------------------------------------------------------
struct Ui {
    GtkApplication* app = nullptr;
    GtkWidget* window = nullptr;
    GtkWidget* stack = nullptr;
    GtkWidget* status_label = nullptr;

    // Page content hosts (cleared and rebuilt by refresh()).
    GtkWidget* home_box = nullptr;
    GtkWidget* install_box = nullptr;
    GtkWidget* apps_box = nullptr;
    GtkWidget* app_box = nullptr;
    GtkWidget* settings_box = nullptr;

    // Controls belonging to the page currently on screen. Valid only between
    // one refresh() and the next; read on the main thread, from a callback
    // raised by the very page that created them.
    GtkWidget* compat_auto_radio = nullptr;
    GtkWidget* compat_manual_radio = nullptr;
    GtkWidget* compat_combo = nullptr;
    GtkWidget* channel_combo = nullptr;
    GtkWidget* error_details_view = nullptr;
    GtkWidget* wait_check = nullptr;
    GtkWidget* uninstall_radios[3] = {nullptr, nullptr, nullptr};

    lexe::Paths paths;
    bool paths_ok = false;
    lexe::Settings settings;
    std::string runtime_version;

    bool building = false; // suppress change handlers while a page is built

    // Navigation.
    std::string page = "home";
    std::string app_id;
    std::string section = "launch";
    bool errors_entry = false; // opened via --errors: Close closes the window
    std::string status;

    // Install flow (reuses the installer's view model).
    std::string install_stage = "choose"; // choose|working|details|progress|done|blocked
    fs::path package_path;
    lexe::gui::ViewModel vm;
    std::string install_note;
    std::string selected_channel = "stable";
    /// ADMIN COMPILE APPROVAL for a portable package (§5A). Its own flag and
    /// its own control, kept separate from every other consent for the same
    /// reason the CLI keeps `--approve-compile` separate from `--yes`.
    bool approve_compile = false;
    GtkWidget* approve_compile_check = nullptr;
    /// What the DESKTOP wants, snapshotted before the first style::apply
    /// overwrites the flag that answers it. See apply_theme().
    gboolean desktop_prefers_dark = FALSE;
    /// The navigation items, by page name, so the current one can be marked.
    /// A nav pane that does not show where you are is a list of links.
    std::map<std::string, GtkWidget*> nav_buttons;
    std::string installed_id;
    std::string installed_version;

    // Desktop integration (Home tile + Settings handler state).
    bool integration_loaded = false;
    bool integration_loading = false;
    lexe::IntegrationReport integration;
    std::string integration_message;

    // Probed isolation capability (Permissions).
    bool caps_loaded = false;
    bool caps_loading = false;
    lexe::IsolationCapabilities caps;

    // Health check of the selected app (Runtime + Diagnostics).
    std::string health_app;
    bool health_loaded = false;
    bool health_loading = false;
    lexe::HealthReport health;

    // Launch (Launch section).
    bool launch_running = false;
    bool launch_wait = true;
    bool launch_reported = false;
    lexe::ui::LaunchLines launch_lines;

    // Error History.
    std::vector<lexe::ErrorRecord> error_records;
    int selected_error = -1;

    // Uninstall.
    int uninstall_mode = 0;
};

// --------------------------------------------------------- forward decls
void refresh(Ui* ui);
void navigate(Ui* ui, const std::string& page);
void navigate_app(Ui* ui, const std::string& id, const std::string& section);
void set_status(Ui* ui, const std::string& message);
void start_launch(Ui* ui, const std::string& id);
void start_open_file(Ui* ui, const fs::path& file);
void ensure_integration(Ui* ui, bool force);
void ensure_health(Ui* ui, bool force);
void ensure_caps(Ui* ui);

// --------------------------------------------------------- widget helpers

/// Left-aligned, wrapped, selectable body label appended to `box`.
GtkWidget* add_body(GtkWidget* box, const std::string& text) {
    GtkWidget* label = gtk_label_new(text.c_str());
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_selectable(GTK_LABEL(label), TRUE);
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
    return label;
}

/// A page title. PLAIN TEXT with the size and weight in CSS: Pango markup wins
/// over the stylesheet, so a baked-in `size="x-large"` renders at its own size
/// whatever `.lexe-title` says — and leaves one more place where a
/// user-controlled string has to be escaped correctly.
GtkWidget* add_title(GtkWidget* box, const std::string& text) {
    GtkWidget* label = gtk_label_new(text.c_str());
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    style::add_class(label, "lexe-title");
    gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
    return label;
}

GtkWidget* add_heading(GtkWidget* box, const std::string& text) {
    GtkWidget* label = gtk_label_new(text.c_str());
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    style::add_class(label, "lexe-section-heading");
    gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
    return label;
}

/// A labelled block of detail, as a CARD.
///
/// These used to be a bare heading followed by a paragraph, repeated down the
/// page — which on a review screen with eight of them is one undifferentiated
/// wall of text, and the reader has to find the boundaries themselves. A
/// hairline card per block is what the installer already does and what makes
/// "Permissions" legible as a thing separate from "Isolation".
void add_section(GtkWidget* box, const std::string& heading,
                 const std::string& body) {
    GtkWidget* card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    style::add_class(card, "lexe-card");
    add_heading(card, heading);
    add_body(card, body);
    gtk_box_pack_start(GTK_BOX(box), card, FALSE, FALSE, 0);
}

/// A severity CALLOUT — tinted fill, an edge bar and matching text. The
/// severity is the one the core model reported; it is never this file's own
/// claim about trust or safety.
///
/// The colours are CSS classes, not Pango markup. They used to be markup
/// (`foreground="#1a7f37"`), which is the trap `style.hpp` documents for
/// exactly this reason: a colour baked into Pango survives a theme flip, so
/// those three light-theme colours stayed put on a dark background. Worse, the
/// most important line on the screen — whether a key has been seen before —
/// rendered as merely coloured text while the installer gave it a banner.
GtkWidget* add_severity(GtkWidget* box, const std::string& severity,
                        const std::string& text) {
    GtkWidget* strip = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    style::add_class(strip, "lexe-banner");
    style::add_class(strip, severity == "ok"        ? "ok"
                            : severity == "caution" ? "caution"
                                                    : "danger");
    GtkWidget* label = gtk_label_new(text.c_str());
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(strip), label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), strip, FALSE, FALSE, 0);
    return label;
}

/// A titled card; returns the box its contents go into.
GtkWidget* add_card(GtkWidget* box, const std::string& title) {
    GtkWidget* frame = gtk_frame_new(nullptr);
    GtkWidget* header = gtk_label_new(nullptr);
    gchar* escaped = g_markup_escape_text(title.c_str(), -1);
    gchar* markup = g_strdup_printf("<b> %s </b>", escaped);
    gtk_label_set_markup(GTK_LABEL(header), markup);
    g_free(markup);
    g_free(escaped);
    gtk_frame_set_label_widget(GTK_FRAME(frame), header);
    GtkWidget* inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(inner), 12);
    gtk_container_add(GTK_CONTAINER(frame), inner);
    gtk_box_pack_start(GTK_BOX(box), frame, FALSE, FALSE, 0);
    return inner;
}

GtkWidget* add_button_row(GtkWidget* box) {
    GtkWidget* row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(row, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(box), row, FALSE, FALSE, 4);
    return row;
}

/// Payload for a signal handler: the app state plus up to two strings and an
/// integer, freed with the closure.
struct Action {
    Ui* ui = nullptr;
    std::string a;
    std::string b;
    int n = 0;
};

void destroy_action(gpointer data, GClosure*) {
    delete static_cast<Action*>(data);
}

void connect_action(GtkWidget* widget, const char* signal, GCallback callback,
                    Ui* ui, const std::string& a = {}, const std::string& b = {},
                    int n = 0) {
    Action* action = new Action{ui, a, b, n};
    g_signal_connect_data(widget, signal, callback, action, destroy_action,
                          GConnectFlags(0));
}

GtkWidget* add_button(GtkWidget* row, const std::string& label,
                      GCallback callback, Ui* ui, const std::string& a = {},
                      const std::string& b = {}, int n = 0) {
    GtkWidget* button = gtk_button_new_with_label(label.c_str());
    connect_action(button, "clicked", callback, ui, a, b, n);
    gtk_box_pack_start(GTK_BOX(row), button, FALSE, FALSE, 0);
    return button;
}

void style_class(GtkWidget* widget, const char* name) {
    gtk_style_context_add_class(gtk_widget_get_style_context(widget), name);
}

void clear_container(GtkWidget* container) {
    GList* children = gtk_container_get_children(GTK_CONTAINER(container));
    for (GList* it = children; it != nullptr; it = it->next) {
        gtk_widget_destroy(GTK_WIDGET(it->data));
    }
    g_list_free(children);
}

/// A scrolled, monospace, read-only text view (error details, copyable text).
GtkWidget* add_text_view(GtkWidget* box, const std::string& text, int height) {
    GtkWidget* scroller = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(scroller, -1, height);
    GtkWidget* view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)),
                             text.c_str(), -1);
    gtk_container_add(GTK_CONTAINER(scroller), view);
    gtk_box_pack_start(GTK_BOX(box), scroller, TRUE, TRUE, 0);
    return view;
}

void copy_to_clipboard(Ui* ui, const std::string& text,
                       const std::string& what) {
    if (ui->window == nullptr) return;
    GtkClipboard* clipboard = gtk_clipboard_get_for_display(
        gtk_widget_get_display(ui->window), GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(clipboard, text.c_str(), -1);
    gtk_clipboard_store(clipboard);
    set_status(ui, what + " copied to the clipboard.");
}

void open_in_file_manager(Ui* ui, const fs::path& directory) {
    if (ui->window == nullptr) return;
    GError* error = nullptr;
    gchar* uri = g_filename_to_uri(directory.string().c_str(), nullptr, &error);
    if (uri != nullptr) {
        gtk_show_uri_on_window(GTK_WINDOW(ui->window), uri, GDK_CURRENT_TIME,
                               &error);
        g_free(uri);
    }
    if (error != nullptr) {
        set_status(ui, std::string("Could not open ") + directory.string() +
                           ": " + error->message);
        g_error_free(error);
    } else {
        set_status(ui, "Opened " + directory.string() + ".");
    }
}

bool confirm(Ui* ui, const std::string& question, const std::string& accept) {
    GtkWidget* dialog = gtk_message_dialog_new(
        GTK_WINDOW(ui->window), GTK_DIALOG_MODAL, GTK_MESSAGE_QUESTION,
        GTK_BUTTONS_NONE, "%s", question.c_str());
    gtk_dialog_add_button(GTK_DIALOG(dialog), "_Cancel", GTK_RESPONSE_CANCEL);
    GtkWidget* ok =
        gtk_dialog_add_button(GTK_DIALOG(dialog), accept.c_str(), GTK_RESPONSE_ACCEPT);
    style_class(ok, "destructive-action");
    const gint response = gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    return response == GTK_RESPONSE_ACCEPT;
}

// ------------------------------------------------------------ worker tasks

/// A unit of off-thread work. `work` runs on a worker thread and MUST NOT
/// touch GTK or the Ui struct; `done` runs on the main loop via g_idle_add.
struct Task {
    std::function<void()> work;
    std::function<void()> done;
    GApplication* hold = nullptr;
};

gboolean task_finished(gpointer data) {
    std::unique_ptr<Task> task(static_cast<Task*>(data));
    try {
        task->done();
    } catch (const std::exception&) {
        // A continuation must never let an exception cross back into GLib.
    }
    if (task->hold != nullptr) g_application_release(task->hold);
    return G_SOURCE_REMOVE;
}

gpointer task_worker(gpointer data) {
    Task* task = static_cast<Task*>(data);
    try {
        task->work();
    } catch (const std::exception&) {
        // Every work lambda records its own failure; this is the last resort.
    } catch (...) {
    }
    g_idle_add(task_finished, task);
    return nullptr;
}

void run_task(Ui* ui, std::function<void()> work, std::function<void()> done) {
    Task* task = new Task{std::move(work), std::move(done),
                          ui->app != nullptr ? G_APPLICATION(ui->app) : nullptr};
    // Hold the application so it cannot exit while work is in flight.
    if (task->hold != nullptr) g_application_hold(task->hold);
    GThread* thread = g_thread_new("lexe-ui-task", task_worker, task);
    g_thread_unref(thread);
}

// ------------------------------------------------------- core query helpers
// Small try/catch wrappers so a page can render even when one record is
// unreadable. They perform no logic of their own — every value comes from
// lexe_engine.

std::optional<lexe::InstallationRecord> try_record(const lexe::Paths& paths,
                                                   const std::string& id) {
    try {
        return lexe::Registry(paths).read_record(id);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<lexe::Manifest> try_manifest(const lexe::Paths& paths,
                                           const std::string& id) {
    try {
        return lexe::Registry(paths).read_manifest(id);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<lexe::TrustRecord> try_trust(const lexe::Paths& paths,
                                           const std::string& id) {
    try {
        return lexe::TrustStore(paths).read(id);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool is_installed(const lexe::Paths& paths, const std::string& id) {
    try {
        return lexe::Registry(paths).is_installed(id);
    } catch (const std::exception&) {
        return false;
    }
}

/// resolve_application_chain(), with the failure turned into a resolution the
/// page can still render.
lexe::ChainResolution try_resolve_chain(const lexe::Paths& paths,
                                        const std::string& id) {
    try {
        return lexe::resolve_application_chain(paths, id);
    } catch (const std::exception& e) {
        lexe::ChainResolution resolution;
        resolution.ok = false;
        resolution.reason = e.what();
        return resolution;
    }
}

lexe::AppConfig try_app_config(const lexe::Paths& paths, const std::string& id) {
    try {
        return lexe::AppConfig::load(paths, id);
    } catch (const std::exception&) {
        lexe::AppConfig config;
        config.id = id;
        return config;
    }
}

/// The per-application locations, straight from the core path API.
lexe::ui::AppLocations app_locations(const lexe::Paths& paths,
                                     const std::string& id,
                                     const std::string& version) {
    lexe::ui::AppLocations locations;
    const lexe::Registry registry(paths);
    try {
        locations.version_dir =
            version.empty() ? registry.app_dir(id).string()
                            : registry.version_dir(id, version).string();
    } catch (const std::exception& e) {
        locations.version_dir = e.what();
    }
    try {
        locations.data_dir = registry.app_data_dir(id).string();
        locations.cache_dir = registry.app_cache_dir(id).string();
    } catch (const std::exception& e) {
        locations.data_dir = e.what();
    }
    try {
        locations.error_dir = lexe::ErrorStore(paths).app_dir(id).string();
    } catch (const std::exception& e) {
        locations.error_dir = e.what();
    }
    try {
        locations.launch_reference =
            lexe::launch_reference_path(paths, id).string();
    } catch (const std::exception& e) {
        locations.launch_reference = e.what();
    }
    try {
        locations.config_file = lexe::AppConfig::file(paths, id).string();
    } catch (const std::exception& e) {
        locations.config_file = e.what();
    }
    return locations;
}

// ---------------------------------------------------------- async operations
// Everything below starts a worker thread through run_task(). The worker only
// calls lexe_engine and writes into a heap result object it owns; the main-loop
// continuation copies the result into Ui and rebuilds the page.

void ensure_integration(Ui* ui, bool force) {
    if (ui->integration_loading) return;
    if (ui->integration_loaded && !force) return;
    ui->integration_loading = true;
    const lexe::Paths paths = ui->paths;
    auto report = std::make_shared<lexe::IntegrationReport>();
    auto failure = std::make_shared<std::string>();
    run_task(
        ui,
        [paths, report, failure] {
            try {
                *report = lexe::DesktopIntegration(paths).verify();
            } catch (const std::exception& e) {
                *failure = e.what();
            }
        },
        [ui, report, failure] {
            ui->integration_loading = false;
            ui->integration_loaded = true;
            ui->integration = *report;
            if (!failure->empty()) {
                ui->integration_message =
                    "The integration check could not run: " + *failure;
            }
            refresh(ui);
        });
}

void start_integration_repair(Ui* ui) {
    if (ui->integration_loading) return;
    ui->integration_loading = true;
    set_status(ui, "Repairing desktop integration…");
    const lexe::Paths paths = ui->paths;
    auto repaired = std::make_shared<lexe::IntegrationReport>();
    auto verified = std::make_shared<lexe::IntegrationReport>();
    auto failure = std::make_shared<std::string>();
    run_task(
        ui,
        [paths, repaired, verified, failure] {
            try {
                lexe::DesktopIntegration integration(paths);
                *repaired = integration.repair();
                *verified = integration.verify();
            } catch (const std::exception& e) {
                *failure = e.what();
            }
        },
        [ui, repaired, verified, failure] {
            ui->integration_loading = false;
            if (failure->empty()) {
                ui->integration_loaded = true;
                ui->integration = *verified;
                ui->integration_message = lexe::ui::format_repair_result(*repaired);
                set_status(ui, verified->ok
                                   ? "Desktop integration repaired."
                                   : "Repair ran; some registrations remain "
                                     "unrepaired.");
            } else {
                ui->integration_message = "Repair failed: " + *failure;
                set_status(ui, ui->integration_message);
            }
            refresh(ui);
        });
}

void start_handler_registration(Ui* ui) {
    if (ui->integration_loading) return;
    ui->integration_loading = true;
    set_status(ui, "Re-registering the .LEXE handler…");
    const lexe::Paths paths = ui->paths;
    auto verified = std::make_shared<lexe::IntegrationReport>();
    auto failure = std::make_shared<std::string>();
    run_task(
        ui,
        [paths, verified, failure] {
            try {
                lexe::DesktopIntegration integration(paths);
                integration.install_runtime_handler();
                lexe::refresh_desktop_databases(paths);
                *verified = integration.verify();
            } catch (const std::exception& e) {
                *failure = e.what();
            }
        },
        [ui, verified, failure] {
            ui->integration_loading = false;
            if (failure->empty()) {
                ui->integration_loaded = true;
                ui->integration = *verified;
                ui->integration_message.clear();
                set_status(ui, "The .LEXE handler was registered for this user.");
            } else {
                set_status(ui, "Could not register the handler: " + *failure);
            }
            refresh(ui);
        });
}

void ensure_caps(Ui* ui) {
    if (ui->caps_loaded || ui->caps_loading) return;
    ui->caps_loading = true;
    const lexe::Paths paths = ui->paths;
    auto caps = std::make_shared<lexe::IsolationCapabilities>();
    run_task(
        ui,
        [paths, caps] {
            try {
                *caps = lexe::make_isolation_backend(paths)->capabilities();
            } catch (const std::exception& e) {
                caps->detail = e.what();
            }
        },
        [ui, caps] {
            ui->caps_loading = false;
            ui->caps_loaded = true;
            ui->caps = *caps;
            refresh(ui);
        });
}

void ensure_health(Ui* ui, bool force) {
    if (ui->app_id.empty() || ui->health_loading) return;
    if (ui->health_loaded && ui->health_app == ui->app_id && !force) return;
    ui->health_loading = true;
    ui->health_app = ui->app_id;
    const lexe::Paths paths = ui->paths;
    const std::string id = ui->app_id;
    auto health = std::make_shared<lexe::HealthReport>();
    auto failure = std::make_shared<std::string>();
    run_task(
        ui,
        [paths, id, health, failure] {
            try {
                *health = lexe::Installer(paths).check_health(id);
            } catch (const std::exception& e) {
                *failure = e.what();
            }
        },
        [ui, id, health, failure] {
            ui->health_loading = false;
            if (ui->app_id != id) {
                // The user moved on: discard this result and let the rebuilt
                // page request the health of whatever is selected now.
                refresh(ui);
                return;
            }
            ui->health_loaded = true;
            if (failure->empty()) {
                ui->health = *health;
            } else {
                ui->health = lexe::HealthReport{};
                ui->health.ok = false;
                ui->health.issues.push_back("the health check could not run: " +
                                            *failure);
            }
            refresh(ui);
        });
}

void start_launch(Ui* ui, const std::string& id) {
    if (ui->launch_running) return;
    ui->launch_running = true;
    ui->launch_reported = false;
    ui->launch_lines = lexe::ui::LaunchLines{};
    ui->launch_lines.severity = "caution";
    ui->launch_lines.headline = "Starting " + id + "…";
    ui->launch_lines.detail =
        "The application is being resolved and started. This window stays "
        "responsive while it runs.";
    set_status(ui, "Launching " + id + "…");
    refresh(ui);

    const lexe::Paths paths = ui->paths;
    const bool wait = ui->launch_wait;
    auto report = std::make_shared<lexe::ExecutionReport>();
    auto failure = std::make_shared<std::string>();
    run_task(
        ui,
        [paths, id, wait, report, failure] {
            try {
                lexe::RunRequest request;
                request.id = id;
                request.detach = !wait;
                request.allow_terminal_spawn = true;
                *report = lexe::run_application(paths, request);
            } catch (const std::exception& e) {
                *failure = e.what();
            }
        },
        [ui, report, failure] {
            ui->launch_running = false;
            ui->launch_reported = true;
            ui->launch_lines =
                failure->empty() ? lexe::ui::format_execution_report(*report)
                                 : lexe::ui::format_launch_failure(*failure);
            set_status(ui, ui->launch_lines.headline);
            refresh(ui);
        });
}

void start_uninstall(Ui* ui, const std::string& id,
                     lexe::Installer::UninstallMode mode) {
    const lexe::Paths paths = ui->paths;
    set_status(ui, "Removing " + id + "…");
    auto failure = std::make_shared<std::string>();
    run_task(
        ui,
        [paths, id, mode, failure] {
            try {
                lexe::Installer(paths).uninstall(id, mode);
            } catch (const std::exception& e) {
                *failure = e.what();
            }
        },
        [ui, id, failure] {
            if (failure->empty()) {
                set_status(ui, id + " was removed.");
                ui->integration_loaded = false;
                ui->health_loaded = false;
                ui->app_id.clear();
                navigate(ui, "apps");
            } else {
                set_status(ui, "Could not remove " + id + ": " + *failure);
                refresh(ui);
            }
        });
}

void start_install(Ui* ui) {
    ui->install_stage = "progress";
    refresh(ui);
    const lexe::Paths paths = ui->paths;
    const fs::path package = ui->package_path;
    const std::string channel = ui->selected_channel;
    const bool approve_compile = ui->approve_compile;
    auto result = std::make_shared<lexe::InstallResult>();
    auto failure = std::make_shared<std::string>();
    run_task(
        ui,
        [paths, package, channel, approve_compile, result, failure] {
            try {
                lexe::InstallOptions options;
                options.channel = channel;
                // §5A: a separate, explicit act. Pressing Install is not it.
                options.approve_compile = approve_compile;
                *result = lexe::Installer(paths).install(package, options);
            } catch (const std::exception& e) {
                *failure = e.what();
            }
        },
        [ui, result, failure] {
            if (failure->empty()) {
                ui->installed_id = result->id;
                ui->installed_version = result->version;
                ui->install_stage = "done";
                ui->install_note.clear();
                ui->integration_loaded = false; // install changed integration
                ui->health_loaded = false;
                set_status(ui, "Installed " + result->id + " " +
                                   result->version + ".");
            } else {
                // Back to the consent screen with the failure stated; the
                // verification state is unchanged, so the user may retry.
                ui->install_stage = "details";
                ui->install_note = "Installation failed: " + *failure;
                set_status(ui, ui->install_note);
            }
            refresh(ui);
        });
}

// ------------------------------------------------- opening a .lexe artifact

/// Everything reading a `.lexe` produces, gathered off the UI thread. Each
/// value comes from lexe_engine; this struct only carries them across the thread
/// boundary.
struct PackageView {
    lexe::VerificationReport report;
    std::optional<lexe::Manifest> manifest;
    std::optional<lexe::TrustEvaluation> eval;
    lexe::PermissionDelta delta;
    lexe::IsolationCapabilities caps;
    /// What this host can build, when the package is portable (§5A). Probed
    /// here with the other host facts so the pure view model only formats it.
    lexe::ToolchainReport toolchain;
};

PackageView gather_package_view(const lexe::Paths& paths, const fs::path& file) {
    PackageView view;
    // FORMAT-0.1 §6 pipeline. The architecture stage is requested; verify skips
    // it for a launch reference, which declares no architectures.
    try {
        view.report = lexe::verify_package(file, /*check_architecture=*/true);
    } catch (const std::exception& e) {
        lexe::VerificationStage stage;
        stage.name = "structure";
        stage.ok = false;
        stage.detail = e.what();
        view.report.stages.push_back(stage);
    }
    try {
        lexe::PackageReader reader(file);
        view.manifest = lexe::Manifest::parse(reader.read_entry("lexe.json"));
    } catch (const std::exception&) {
        view.manifest.reset();
    }
    if (view.manifest.has_value()) {
        try {
            const lexe::SignatureState signature =
                lexe::signature_state_from_report(view.report);
            const lexe::Registry registry(paths);
            std::optional<std::string> retained;
            const fs::path owner = registry.data_owner_marker(view.manifest->id);
            std::error_code ec;
            if (fs::is_regular_file(owner, ec)) {
                std::string prior = lexe::util::slurp_text(owner);
                while (!prior.empty() &&
                       (prior.back() == '\n' || prior.back() == '\r' ||
                        prior.back() == ' ')) {
                    prior.pop_back();
                }
                if (!prior.empty()) retained = prior;
            }
            view.eval = lexe::TrustStore(paths).evaluate(
                view.manifest->id, view.manifest->decoded_public_key(),
                signature, retained);
            if (registry.is_installed(view.manifest->id)) {
                const lexe::InstallationRecord record =
                    registry.read_record(view.manifest->id);
                view.delta = lexe::permission_delta(
                    lexe::normalized_from_ids(record.approved_permissions),
                    lexe::normalize_permissions(view.manifest->permissions));
            }
        } catch (const std::exception&) {
            // Leave the evaluation empty: the banner then states that
            // authenticity could not be established.
        }
    }
    try {
        view.caps = lexe::make_isolation_backend(paths)->capabilities();
    } catch (const std::exception&) {
    }
    if (view.manifest.has_value() &&
        view.manifest->application_kind == lexe::ApplicationType::Portable) {
        view.toolchain = lexe::probe_toolchain(view.manifest->build);
    }
    return view;
}

/// The handler decision. Dispatch is on the SIGNED manifest role, never on the
/// file name (Definitive Architecture §15.1).
void apply_package_view(Ui* ui, const PackageView& view) {
    if (ui->window == nullptr) return;
    const lexe::ui::OpenDispatch dispatch =
        lexe::ui::decide_open_dispatch(view.report, view.manifest);

    // The probe already ran for this package; reuse it for the Permissions page.
    ui->caps = view.caps;
    ui->caps_loaded = true;

    if (dispatch.action == lexe::ui::OpenAction::LaunchApp) {
        if (is_installed(ui->paths, dispatch.application_id)) {
            set_status(ui, dispatch.reason);
            navigate_app(ui, dispatch.application_id, "launch");
            start_launch(ui, dispatch.application_id);
            return;
        }
        ui->install_stage = "blocked";
        ui->install_note =
            lexe::ui::missing_launch_target_text(dispatch.application_id);
        set_status(ui, dispatch.reason);
        navigate(ui, "install");
        return;
    }

    ui->vm = lexe::gui::build_view_model(
        view.manifest, view.report, ui->package_path, ui->paths,
        lexe::host_architecture(), view.eval, view.caps, view.delta,
        /*payload_bytes=*/0, /*installed_version=*/"", view.toolchain);
    ui->approve_compile = false; // a fresh package, a fresh decision
    if (!ui->vm.channels.empty()) {
        ui->selected_channel =
            ui->vm.channels[static_cast<std::size_t>(ui->vm.active_channel)];
    }
    ui->install_stage = "details";
    ui->install_note = dispatch.action == lexe::ui::OpenAction::Refuse
                           ? dispatch.reason
                           : std::string();
    set_status(ui, dispatch.reason);
    navigate(ui, "install");
}

void start_open_file(Ui* ui, const fs::path& file) {
    ui->package_path = file;
    ui->install_stage = "working";
    ui->install_note.clear();
    navigate(ui, "install");
    const lexe::Paths paths = ui->paths;
    auto view = std::make_shared<PackageView>();
    run_task(
        ui, [paths, file, view] { *view = gather_package_view(paths, file); },
        [ui, view] { apply_package_view(ui, *view); });
}

void choose_package_file(Ui* ui) {
    GtkWidget* dialog = gtk_file_chooser_dialog_new(
        "Open a .lexe file", GTK_WINDOW(ui->window),
        GTK_FILE_CHOOSER_ACTION_OPEN, "_Cancel", GTK_RESPONSE_CANCEL, "_Open",
        GTK_RESPONSE_ACCEPT, nullptr);
    GtkFileFilter* lexe_filter = gtk_file_filter_new();
    gtk_file_filter_set_name(lexe_filter, ".LEXE artifacts (*.lexe)");
    gtk_file_filter_add_pattern(lexe_filter, "*.lexe");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), lexe_filter);
    GtkFileFilter* all_filter = gtk_file_filter_new();
    gtk_file_filter_set_name(all_filter, "All files");
    gtk_file_filter_add_pattern(all_filter, "*");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), all_filter);

    const gint response = gtk_dialog_run(GTK_DIALOG(dialog));
    gchar* filename = nullptr;
    if (response == GTK_RESPONSE_ACCEPT) {
        filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
    }
    gtk_widget_destroy(dialog);
    if (filename != nullptr) {
        const fs::path chosen(filename);
        g_free(filename);
        start_open_file(ui, chosen);
    }
}

// ------------------------------------------------------------- handlers
// Thin: they read widget state on the main thread, mutate Ui, and either start
// a task or refresh. No core logic lives in a handler.

Action* action_of(gpointer data) { return static_cast<Action*>(data); }

void on_window_destroy(GtkWidget*, gpointer data) {
    Ui* ui = action_of(data)->ui;
    // Continuations still in flight check this before touching any widget.
    ui->window = nullptr;
    ui->stack = nullptr;
    ui->status_label = nullptr;
    ui->home_box = ui->install_box = ui->apps_box = ui->app_box =
        ui->settings_box = nullptr;
}

void on_nav_clicked(GtkButton*, gpointer data) {
    Action* action = action_of(data);
    navigate(action->ui, action->a);
}

void on_open_app_clicked(GtkButton*, gpointer data) {
    Action* action = action_of(data);
    navigate_app(action->ui, action->a, action->b.empty() ? "launch" : action->b);
}

void on_choose_file_clicked(GtkButton*, gpointer data) {
    choose_package_file(action_of(data)->ui);
}

void on_install_clicked(GtkButton*, gpointer data) {
    start_install(action_of(data)->ui);
}

void on_channel_changed(GtkComboBox* combo, gpointer data) {
    Ui* ui = action_of(data)->ui;
    if (ui->building) return;
    gchar* text = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(combo));
    if (text != nullptr && *text != '\0') ui->selected_channel = text;
    if (text != nullptr) g_free(text);
}

void on_approve_compile_toggled(GtkToggleButton* toggle, gpointer data) {
    Ui* ui = action_of(data)->ui;
    if (ui->building) return;
    ui->approve_compile = gtk_toggle_button_get_active(toggle) != FALSE;
    // Rebuild so the Install button follows the decision immediately; a
    // disabled button whose reason is a tick box above it is a dead end.
    refresh(ui);
}

void on_install_reset_clicked(GtkButton*, gpointer data) {
    Ui* ui = action_of(data)->ui;
    ui->install_stage = "choose";
    ui->install_note.clear();
    refresh(ui);
}

void on_launch_clicked(GtkButton*, gpointer data) {
    Action* action = action_of(data);
    start_launch(action->ui, action->a);
}

void on_wait_toggled(GtkToggleButton* toggle, gpointer data) {
    Ui* ui = action_of(data)->ui;
    if (ui->building) return;
    ui->launch_wait = gtk_toggle_button_get_active(toggle) == TRUE;
}

void on_integration_recheck_clicked(GtkButton*, gpointer data) {
    Ui* ui = action_of(data)->ui;
    set_status(ui, "Checking desktop integration…");
    ensure_integration(ui, /*force=*/true);
}

void on_integration_repair_clicked(GtkButton*, gpointer data) {
    start_integration_repair(action_of(data)->ui);
}

void on_register_handler_clicked(GtkButton*, gpointer data) {
    start_handler_registration(action_of(data)->ui);
}

void on_health_recheck_clicked(GtkButton*, gpointer data) {
    Ui* ui = action_of(data)->ui;
    set_status(ui, "Running the health check…");
    ensure_health(ui, /*force=*/true);
}

void on_compat_apply_clicked(GtkButton*, gpointer data) {
    Action* action = action_of(data);
    Ui* ui = action->ui;
    if (ui->compat_auto_radio == nullptr) return;
    lexe::AppConfig config = try_app_config(ui->paths, action->a);
    config.id = action->a;
    const bool automatic =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ui->compat_auto_radio)) ==
        TRUE;
    if (automatic) {
        config.compatibility_mode = lexe::CompatibilityMode::Automatic;
        config.preferred_chain.clear();
    } else {
        gchar* chain = ui->compat_combo != nullptr
                           ? gtk_combo_box_text_get_active_text(
                                 GTK_COMBO_BOX_TEXT(ui->compat_combo))
                           : nullptr;
        if (chain == nullptr || *chain == '\0') {
            if (chain != nullptr) g_free(chain);
            set_status(ui, "Choose one of the listed execution chains first.");
            return;
        }
        config.compatibility_mode = lexe::CompatibilityMode::Manual;
        config.preferred_chain.assign(1, std::string(chain));
        g_free(chain);
    }
    try {
        config.save(ui->paths);
        set_status(ui, automatic
                           ? "Compatibility set to automatic. The installed "
                             "package is unchanged."
                           : "Compatibility preference saved. The installed "
                             "package is unchanged.");
    } catch (const std::exception& e) {
        set_status(ui, std::string("Could not save the preference: ") + e.what());
    }
    refresh(ui);
}

void on_compat_reset_clicked(GtkButton*, gpointer data) {
    Action* action = action_of(data);
    Ui* ui = action->ui;
    try {
        lexe::AppConfig::reset(ui->paths, action->a);
        set_status(ui, "Compatibility overrides cleared for " + action->a + ".");
    } catch (const std::exception& e) {
        set_status(ui, std::string("Could not clear the overrides: ") + e.what());
    }
    refresh(ui);
}

void on_copy_text_clicked(GtkButton*, gpointer data) {
    Action* action = action_of(data);
    copy_to_clipboard(action->ui, action->a, action->b);
}

void on_open_folder_clicked(GtkButton*, gpointer data) {
    Action* action = action_of(data);
    open_in_file_manager(action->ui, fs::path(action->a));
}

void on_error_row_selected(GtkListBox*, GtkListBoxRow* row, gpointer data) {
    Ui* ui = action_of(data)->ui;
    if (row == nullptr) return;
    const int index = gtk_list_box_row_get_index(row);
    if (index < 0 || static_cast<std::size_t>(index) >= ui->error_records.size()) {
        return;
    }
    ui->selected_error = index;
    if (ui->building) return;
    if (ui->error_details_view != nullptr) {
        const std::string details =
            ui->error_records[static_cast<std::size_t>(index)].to_details_text();
        gtk_text_buffer_set_text(
            gtk_text_view_get_buffer(GTK_TEXT_VIEW(ui->error_details_view)),
            details.c_str(), -1);
    }
}

void on_error_copy_path_clicked(GtkButton*, gpointer data) {
    Ui* ui = action_of(data)->ui;
    if (ui->selected_error < 0) {
        set_status(ui, "Select an error record first.");
        return;
    }
    const lexe::ErrorRecord& record =
        ui->error_records[static_cast<std::size_t>(ui->selected_error)];
    copy_to_clipboard(ui, record.record_path, "Error record path");
}

void on_error_copy_details_clicked(GtkButton*, gpointer data) {
    Ui* ui = action_of(data)->ui;
    if (ui->selected_error < 0) {
        set_status(ui, "Select an error record first.");
        return;
    }
    const lexe::ErrorRecord& record =
        ui->error_records[static_cast<std::size_t>(ui->selected_error)];
    copy_to_clipboard(ui, record.to_details_text(), "Error details");
}

void on_error_clear_clicked(GtkButton*, gpointer data) {
    Action* action = action_of(data);
    Ui* ui = action->ui;
    // Copied before the modal loop below: the page may be rebuilt underneath it.
    const std::string id = action->a;
    if (!confirm(ui,
                 "Delete every error record for " + id +
                     "?\n\nThe records and their captured output are removed "
                     "from this machine. Nothing else about the application "
                     "changes.",
                 "_Clear history")) {
        return;
    }
    try {
        const std::size_t removed = lexe::ErrorStore(ui->paths).clear(id);
        ui->selected_error = -1;
        set_status(ui, "Cleared " +
                           lexe::ui::count_of(removed, "error record",
                                              "error records") +
                           ".");
    } catch (const std::exception& e) {
        set_status(ui, std::string("Could not clear the history: ") + e.what());
    }
    refresh(ui);
}

void on_error_close_clicked(GtkButton*, gpointer data) {
    Action* action = action_of(data);
    Ui* ui = action->ui;
    // ".LEXE Error" is a view inside this window. Closing it returns to the
    // application page — unless this window was opened purely to show it
    // (`--errors`), in which case closing the view closes the window.
    if (ui->errors_entry) {
        gtk_widget_destroy(ui->window);
        return;
    }
    navigate_app(ui, action->a, "launch");
}

void on_error_retry_clicked(GtkButton*, gpointer data) {
    Action* action = action_of(data);
    Ui* ui = action->ui;
    ui->errors_entry = false;
    navigate_app(ui, action->a, "launch");
    start_launch(ui, action->a);
}

void on_uninstall_mode_toggled(GtkToggleButton* toggle, gpointer data) {
    Action* action = action_of(data);
    Ui* ui = action->ui;
    if (ui->building) return;
    if (gtk_toggle_button_get_active(toggle) == TRUE) {
        ui->uninstall_mode = action->n;
    }
    // Deliberately no refresh(): every option and its description is already
    // on screen, and rebuilding here would destroy the radio group while GTK
    // is still emitting "toggled" across it.
}

void on_uninstall_clicked(GtkButton*, gpointer data) {
    Action* action = action_of(data);
    Ui* ui = action->ui;
    // Copied before the modal loop below: the page may be rebuilt underneath it.
    const std::string id = action->a;
    const std::string name = action->b;
    using Mode = lexe::Installer::UninstallMode;
    const Mode modes[3] = {Mode::AppOnly, Mode::AppAndCache, Mode::PurgeData};
    const int index = ui->uninstall_mode < 0 || ui->uninstall_mode > 2
                          ? 0
                          : ui->uninstall_mode;
    const Mode mode = modes[index];
    if (!confirm(ui, lexe::ui::uninstall_confirmation(name, id, mode),
                 "_Remove")) {
        return;
    }
    start_uninstall(ui, id, mode);
}

void on_setting_combo_changed(GtkComboBox* combo, gpointer data) {
    Action* action = action_of(data);
    Ui* ui = action->ui;
    if (ui->building) return;
    gchar* value = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(combo));
    if (value == nullptr) return;
    try {
        lexe::Settings settings = ui->settings;
        settings.set(action->a, value);
        settings.save(ui->paths);
        ui->settings = settings;
        // Act on it, not just record it. The theme is the one key whose whole
        // effect is on this window.
        if (action->a == "theme") apply_theme(ui, value);
        set_status(ui, lexe::ui::setting_title(action->a) + " set to " + value +
                           ".");
    } catch (const std::exception& e) {
        set_status(ui, std::string("Could not save the setting: ") + e.what());
    }
    g_free(value);
}

void on_setting_toggled(GtkToggleButton* toggle, gpointer data) {
    Action* action = action_of(data);
    Ui* ui = action->ui;
    if (ui->building) return;
    const bool active = gtk_toggle_button_get_active(toggle) == TRUE;
    try {
        lexe::Settings settings = ui->settings;
        settings.set(action->a, active ? "true" : "false");
        settings.save(ui->paths);
        ui->settings = settings;
        set_status(ui, lexe::ui::setting_title(action->a) +
                           (active ? " enabled." : " disabled."));
    } catch (const std::exception& e) {
        set_status(ui, std::string("Could not save the setting: ") + e.what());
    }
}

// ----------------------------------------------------------------- Home

void build_home_page(Ui* ui) {
    GtkWidget* box = ui->home_box;
    add_title(box, ".LEXE");
    add_body(box, "Runtime " + ui->runtime_version + "  ·  package format " +
                      lexe::version::kPackageFormat + "\nApplications and data "
                      "live under " + ui->paths.home().string() + ".");

    // The prominent primary action.
    {
        GtkWidget* row = add_button_row(box);
        GtkWidget* install = add_button(row, "Install a .lexe file…",
                                        G_CALLBACK(on_choose_file_clicked), ui);
        style_class(install, "suggested-action");
        gtk_widget_set_size_request(install, 260, 44);
        add_button(row, "Browse installed applications",
                   G_CALLBACK(on_nav_clicked), ui, "apps");
    }

    // Installed applications.
    {
        std::size_t installed = 0;
        try {
            installed = lexe::Registry(ui->paths).list_installed().size();
        } catch (const std::exception&) {
        }
        GtkWidget* card = add_card(box, "Installed applications");
        add_body(card, lexe::ui::format_installed_count(installed));
    }

    // System health, from DesktopIntegration::verify().
    {
        GtkWidget* card = add_card(box, "System health");
        if (!ui->integration_loaded) {
            add_body(card, "Checking the desktop integration .LEXE owns…");
            ensure_integration(ui, /*force=*/false);
        } else {
            const lexe::ui::HealthTile tile =
                lexe::ui::build_health_tile(ui->integration);
            add_severity(card, tile.severity, tile.headline);
            if (!tile.detail.empty()) add_body(card, tile.detail);
            if (!ui->integration_message.empty()) {
                add_body(card, ui->integration_message);
            }
            GtkWidget* row = add_button_row(card);
            if (tile.needs_repair) {
                GtkWidget* repair =
                    add_button(row, "Repair",
                               G_CALLBACK(on_integration_repair_clicked), ui);
                style_class(repair, "suggested-action");
            }
            GtkWidget* recheck =
                add_button(row, "Re-check",
                           G_CALLBACK(on_integration_recheck_clicked), ui);
            gtk_widget_set_sensitive(recheck, ui->integration_loading ? FALSE
                                                                      : TRUE);
        }
    }

    // Recent errors.
    {
        GtkWidget* card = add_card(box, "Recent errors");
        std::vector<std::string> apps;
        try {
            apps = lexe::ErrorStore(ui->paths).applications_with_errors();
        } catch (const std::exception&) {
        }
        if (apps.empty()) {
            add_body(card, "No application has recorded an error on this "
                           "machine.");
        } else {
            const lexe::ErrorStore store(ui->paths);
            for (const std::string& id : apps) {
                std::string line = id;
                try {
                    const std::optional<lexe::ErrorRecord> latest =
                        store.latest(id);
                    if (latest.has_value()) {
                        line += "  —  " + lexe::ui::format_error_row(*latest);
                    }
                } catch (const std::exception&) {
                }
                add_body(card, line);
                GtkWidget* row = add_button_row(card);
                add_button(row, "Error history", G_CALLBACK(on_open_app_clicked),
                           ui, id, "errors");
                add_button(row, "Open application",
                           G_CALLBACK(on_open_app_clicked), ui, id, "launch");
            }
        }
    }
}

// -------------------------------------------------------------- Install
// The install flow is the installer's, reused: the same FORMAT-0.1 §6
// pipeline, the same lexe::gui::ViewModel, the same two-dimensional
// authenticity banner, the same Installer::install call. Only the widget
// packing lives here.

void add_spinner_page(GtkWidget* box, const std::string& message) {
    GtkWidget* spinner = gtk_spinner_new();
    gtk_widget_set_size_request(spinner, 32, 32);
    gtk_widget_set_halign(spinner, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(box), spinner, FALSE, FALSE, 8);
    gtk_spinner_start(GTK_SPINNER(spinner));
    add_body(box, message);
}

void build_install_details(Ui* ui, GtkWidget* box) {
    const lexe::gui::ViewModel& vm = ui->vm;

    add_severity(box, vm.trust_severity, vm.status_text);
    add_title(box, vm.app_name);
    add_body(box, vm.publisher_line);
    add_body(box, vm.version_line);

    {
        std::string trust = vm.signature_text;
        if (!vm.key_text.empty()) trust += "\n" + vm.key_text;
        if (!vm.fingerprint_text.empty()) {
            trust += "\nSigning key fingerprint: " + vm.fingerprint_text;
        }
        if (!vm.identity_caveat.empty()) trust += "\n" + vm.identity_caveat;
        add_section(box, "Authenticity & local trust:", trust);
    }
    add_section(box, "Source:", vm.source_text);
    add_section(box, "Application Type:", vm.type_text);
    if (vm.requires_compile_approval) {
        add_section(box, "Compiles on this machine:", vm.compile_text);
    }
    add_section(box, "Permissions:", vm.permissions_text);
    if (!vm.permission_delta_text.empty()) {
        add_section(box, "Permission changes:", vm.permission_delta_text);
    }
    add_section(box, "Installation:", vm.install_text);
    add_section(box, "Updates:", vm.updates_text);
    add_section(box, "Isolation on this platform:", vm.isolation_text);
    add_section(box, "After install:", vm.after_install_text);
    add_section(box, "Verify later:", vm.verify_later_text);

    GtkWidget* expander = gtk_expander_new("Advanced options");
    GtkWidget* advanced = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(advanced), 8);
    add_section(advanced, "Directories used:", vm.advanced_dirs_text);
    GtkWidget* channel_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(channel_row), gtk_label_new("Update channel:"),
                       FALSE, FALSE, 0);
    ui->channel_combo = gtk_combo_box_text_new();
    for (const std::string& channel : vm.channels) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ui->channel_combo),
                                       channel.c_str());
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(ui->channel_combo), vm.active_channel);
    connect_action(ui->channel_combo, "changed", G_CALLBACK(on_channel_changed),
                   ui);
    gtk_box_pack_start(GTK_BOX(channel_row), ui->channel_combo, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(advanced), channel_row, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(expander), advanced);
    gtk_box_pack_start(GTK_BOX(box), expander, FALSE, FALSE, 0);

    // The compile consent sits with the button it gates, and is only offered
    // when this host can actually build the package: a tick box that can only
    // lead to a failed install is worse than no tick box.
    ui->approve_compile_check = nullptr;
    if (vm.requires_compile_approval && vm.compile_possible) {
        ui->approve_compile_check =
            gtk_check_button_new_with_label(vm.compile_consent_label.c_str());
        gtk_toggle_button_set_active(
            GTK_TOGGLE_BUTTON(ui->approve_compile_check),
            ui->approve_compile ? TRUE : FALSE);
        gtk_label_set_line_wrap(
            GTK_LABEL(gtk_bin_get_child(GTK_BIN(ui->approve_compile_check))),
            TRUE);
        connect_action(ui->approve_compile_check, "toggled",
                       G_CALLBACK(on_approve_compile_toggled), ui);
        gtk_box_pack_start(GTK_BOX(box), ui->approve_compile_check, FALSE,
                           FALSE, 0);
    }

    GtkWidget* row = add_button_row(box);
    GtkWidget* install =
        add_button(row, "Install", G_CALLBACK(on_install_clicked), ui);
    const bool compile_approved =
        !vm.requires_compile_approval || ui->approve_compile;
    const bool ready = vm.can_install && compile_approved;
    gtk_widget_set_sensitive(install, ready ? TRUE : FALSE);
    if (ready) style_class(install, "suggested-action");
    if (vm.can_install && !compile_approved) {
        add_body(box, "Install is waiting on your approval to compile this "
                      "application's source on this machine.");
    }
    add_button(row, "Choose a different file…",
               G_CALLBACK(on_choose_file_clicked), ui);
    if (!vm.can_install) {
        add_body(box, "Install is disabled: the package must pass every "
                      "verification stage and the local key decision must "
                      "allow it.");
    }
}

void build_install_page(Ui* ui) {
    GtkWidget* box = ui->install_box;

    if (ui->install_stage == "choose") {
        add_title(box, "Install a .lexe file");
        add_body(box,
                 "Choose a .lexe artifact. What happens next is decided by the "
                 "SIGNED manifest inside it, not by the file's name: an "
                 "application package opens this review screen, while a launch "
                 "reference goes straight to that application's page.");
        GtkWidget* row = add_button_row(box);
        GtkWidget* choose = add_button(row, "Choose a .lexe file…",
                                       G_CALLBACK(on_choose_file_clicked), ui);
        style_class(choose, "suggested-action");
        gtk_widget_set_size_request(choose, 260, 44);
        return;
    }

    if (ui->install_stage == "working") {
        add_title(box, "Checking the file");
        add_spinner_page(box, "Running the verification pipeline on " +
                                  ui->package_path.filename().string() + "…");
        return;
    }

    if (ui->install_stage == "blocked") {
        add_title(box, ui->package_path.filename().string());
        add_severity(box, "danger", "This file was not acted on.");
        add_body(box, ui->install_note);
        GtkWidget* row = add_button_row(box);
        add_button(row, "Choose a different file…",
                   G_CALLBACK(on_choose_file_clicked), ui);
        add_button(row, "Back to Home", G_CALLBACK(on_nav_clicked), ui, "home");
        return;
    }

    if (ui->install_stage == "progress") {
        add_title(box, "Installing");
        add_spinner_page(box, "Installing " + ui->vm.app_name + "…");
        return;
    }

    if (ui->install_stage == "done") {
        add_title(box, "Installed");
        add_severity(box, "ok",
                     ui->vm.app_name + " " + ui->installed_version +
                         " has been installed for the current user.");
        add_body(box, "It now has a menu entry and a launch reference, and it "
                      "can be launched from its application page here.");
        GtkWidget* row = add_button_row(box);
        GtkWidget* open =
            add_button(row, "Open its application page",
                       G_CALLBACK(on_open_app_clicked), ui, ui->installed_id,
                       "launch");
        style_class(open, "suggested-action");
        add_button(row, "Launch now", G_CALLBACK(on_launch_clicked), ui,
                   ui->installed_id);
        add_button(row, "Install another file…",
                   G_CALLBACK(on_install_reset_clicked), ui);
        return;
    }

    // "details"
    if (!ui->install_note.empty()) {
        add_severity(box, "danger", ui->install_note);
    }
    build_install_details(ui, box);
}

// ----------------------------------------------------------------- Apps

void build_apps_page(Ui* ui) {
    GtkWidget* box = ui->apps_box;
    add_title(box, "Applications");

    std::vector<std::string> ids;
    std::string error;
    try {
        ids = lexe::Registry(ui->paths).list_installed();
    } catch (const std::exception& e) {
        error = e.what();
    }
    if (!error.empty()) {
        add_severity(box, "danger", "Could not read the application registry: " +
                                        error);
        return;
    }
    add_body(box, lexe::ui::format_installed_count(ids.size()));
    if (ids.empty()) {
        GtkWidget* row = add_button_row(box);
        GtkWidget* choose = add_button(row, "Install a .lexe file…",
                                       G_CALLBACK(on_choose_file_clicked), ui);
        style_class(choose, "suggested-action");
        return;
    }

    for (const std::string& id : ids) {
        const std::optional<lexe::InstallationRecord> record =
            try_record(ui->paths, id);
        if (!record.has_value()) {
            GtkWidget* card = add_card(box, id);
            add_body(card, "The installation record for this application could "
                           "not be read.");
            continue;
        }
        const lexe::ui::AppRow row = lexe::ui::build_app_row(
            *record, try_manifest(ui->paths, id), try_trust(ui->paths, id));

        GtkWidget* button = gtk_button_new();
        GtkWidget* content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
        gtk_container_set_border_width(GTK_CONTAINER(content), 8);
        add_heading(content, row.title);
        add_body(content, row.subtitle);
        add_body(content, row.last_run);
        add_body(content, row.trust_line);
        gtk_container_add(GTK_CONTAINER(button), content);
        connect_action(button, "clicked", G_CALLBACK(on_open_app_clicked), ui,
                       row.id, "launch");
        gtk_box_pack_start(GTK_BOX(box), button, FALSE, FALSE, 0);
    }
}

// ------------------------------------------------------------- App page
// ".LEXE Menu" is this page. Its sections are the architecture's sub-nodes:
// Launch / Compatibility / Runtime / Permissions / Diagnostics / Error History
// / Uninstall.

void ensure_section_data(Ui* ui) {
    if (ui->section == "runtime") {
        ensure_health(ui, /*force=*/false);
    } else if (ui->section == "permissions") {
        ensure_caps(ui);
    } else if (ui->section == "diagnostics") {
        ensure_health(ui, /*force=*/false);
        ensure_integration(ui, /*force=*/false);
    }
}

void on_section_changed(GObject* object, GParamSpec*, gpointer data) {
    Ui* ui = action_of(data)->ui;
    if (ui->building) return;
    const gchar* name = gtk_stack_get_visible_child_name(GTK_STACK(object));
    if (name == nullptr) return;
    ui->section = name;
    ensure_section_data(ui);
}

GtkWidget* add_section_page(GtkWidget* stack, const char* name,
                            const char* title) {
    GtkWidget* scroller = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 16);
    gtk_container_add(GTK_CONTAINER(scroller), box);
    gtk_stack_add_titled(GTK_STACK(stack), scroller, name, title);
    return box;
}

void build_launch_section(Ui* ui, GtkWidget* box,
                          const lexe::InstallationRecord& record,
                          const std::optional<lexe::Manifest>& manifest) {
    const std::string name =
        manifest.has_value() && !manifest->name.empty() ? manifest->name
                                                        : record.id;
    add_title(box, "Launch");
    if (manifest.has_value()) {
        add_body(box, lexe::ui::format_launch_mode(manifest->launch_mode));
        const std::string critical =
            lexe::ui::format_mission_critical(manifest->mission_critical);
        if (!critical.empty()) add_severity(box, "caution", critical);
    }

    const lexe::ChainResolution resolution =
        try_resolve_chain(ui->paths, record.id);
    add_body(box, resolution.ok
                      ? "It would run through the \"" + resolution.chain.id +
                            "\" chain — " + resolution.reason
                      : "It cannot run on this machine right now: " +
                            resolution.reason);

    GtkWidget* row = add_button_row(box);
    GtkWidget* launch = add_button(row, "Launch " + name,
                                   G_CALLBACK(on_launch_clicked), ui, record.id);
    style_class(launch, "suggested-action");
    gtk_widget_set_size_request(launch, 240, 48);
    gtk_widget_set_sensitive(
        launch, (ui->launch_running || !resolution.ok) ? FALSE : TRUE);

    ui->wait_check = gtk_check_button_new_with_label(
        "Wait for it to exit and report the result");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ui->wait_check),
                                 ui->launch_wait ? TRUE : FALSE);
    connect_action(ui->wait_check, "toggled", G_CALLBACK(on_wait_toggled), ui);
    gtk_box_pack_start(GTK_BOX(box), ui->wait_check, FALSE, FALSE, 0);
    add_body(box, "Unchecked, .LEXE starts the application detached and does "
                  "not wait for it, so no exit code is reported here.");

    if (ui->launch_running || ui->launch_reported) {
        GtkWidget* card = add_card(box, "Last launch");
        if (ui->launch_running) {
            add_spinner_page(card, ui->launch_lines.headline);
        } else {
            add_severity(card, ui->launch_lines.severity,
                         ui->launch_lines.headline);
        }
        if (!ui->launch_lines.detail.empty()) {
            add_body(card, ui->launch_lines.detail);
        }
        if (ui->launch_lines.has_error) {
            GtkWidget* error_row = add_button_row(card);
            GtkWidget* open =
                add_button(error_row, "Open Error History",
                           G_CALLBACK(on_open_app_clicked), ui, record.id,
                           "errors");
            style_class(open, "suggested-action");
        }
    }
}

void build_compatibility_section(Ui* ui, GtkWidget* box,
                                 const lexe::InstallationRecord& record) {
    add_title(box, "Compatibility");
    add_body(box,
             "The signed manifest states what the publisher permits. A choice "
             "here can only narrow or reorder that list — it can never grant an "
             "execution method the publisher forbade, and it never modifies or "
             "re-signs the installed package.");

    const lexe::ChainResolution resolution =
        try_resolve_chain(ui->paths, record.id);
    const lexe::AppConfig config = try_app_config(ui->paths, record.id);
    const lexe::ui::CompatibilityView view =
        lexe::ui::build_compatibility_view(resolution, config);

    add_severity(box, view.resolved ? "ok" : "danger", view.selected_line);
    if (!view.reason_line.empty()) add_body(box, "Why: " + view.reason_line);
    if (view.locked) add_severity(box, "caution", view.locked_reason);
    if (!view.stale_preference.empty()) {
        add_severity(box, "caution", view.stale_preference);
    }

    GtkWidget* card = add_card(box, "How this application should run");
    ui->compat_auto_radio = gtk_radio_button_new_with_label(
        nullptr, "Automatic — let .LEXE pick the best allowed chain");
    gtk_box_pack_start(GTK_BOX(card), ui->compat_auto_radio, FALSE, FALSE, 0);
    ui->compat_manual_radio = gtk_radio_button_new_with_label_from_widget(
        GTK_RADIO_BUTTON(ui->compat_auto_radio), "Always use this chain:");
    gtk_box_pack_start(GTK_BOX(card), ui->compat_manual_radio, FALSE, FALSE, 0);

    ui->compat_combo = gtk_combo_box_text_new();
    for (const lexe::ui::ChainOption& option : view.options) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ui->compat_combo),
                                       option.id.c_str());
    }
    if (!view.options.empty()) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(ui->compat_combo),
                                 view.active_option >= 0 ? view.active_option
                                                         : 0);
    }
    gtk_box_pack_start(GTK_BOX(card), ui->compat_combo, FALSE, FALSE, 0);
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(view.automatic ? ui->compat_auto_radio
                                         : ui->compat_manual_radio),
        TRUE);

    const gboolean editable =
        (!view.locked && !view.options.empty()) ? TRUE : FALSE;
    gtk_widget_set_sensitive(ui->compat_auto_radio, editable);
    gtk_widget_set_sensitive(ui->compat_manual_radio, editable);
    gtk_widget_set_sensitive(ui->compat_combo, editable);

    GtkWidget* row = add_button_row(card);
    GtkWidget* apply = add_button(row, "Apply",
                                  G_CALLBACK(on_compat_apply_clicked), ui,
                                  record.id);
    gtk_widget_set_sensitive(apply, editable);
    add_button(row, "Reset to automatic", G_CALLBACK(on_compat_reset_clicked),
               ui, record.id);

    GtkWidget* offered = add_card(box, "Chains offered for this application");
    if (view.options.empty()) {
        add_body(offered, "None. No execution chain that the package policy "
                          "allows is available on this host, so there is "
                          "nothing to choose between.");
    } else {
        for (const lexe::ui::ChainOption& option : view.options) {
            std::string line = option.id;
            if (option.selected) line += "  (currently selected)";
            if (!option.detail.empty()) line += " — " + option.detail;
            add_body(offered, line);
        }
    }
    add_body(offered, "Only chains this package's policy allows AND this host "
                      "can actually provide are listed. Nothing else can be "
                      "chosen here.");

    if (!view.rejected_lines.empty()) {
        GtkWidget* rejected = add_card(box, "Considered and not used");
        for (const std::string& line : view.rejected_lines) {
            add_body(rejected, line);
        }
    }
}

void build_runtime_section(Ui* ui, GtkWidget* box,
                           const lexe::InstallationRecord& record) {
    add_title(box, "Runtime");
    add_body(box, "The dependency analysis runs ONCE, when the application is "
                  "installed or repaired. A normal launch only confirms that "
                  "the recorded state still holds, and then runs natively.");
    add_section(box, "Recorded at install:",
                lexe::ui::format_runtime_block(record));

    GtkWidget* card = add_card(box, "Installed files");
    if (ui->health_loading || !ui->health_loaded ||
        ui->health_app != record.id) {
        add_spinner_page(card, "Re-checking the installed files against the "
                               "hashes recorded at install…");
        ensure_health(ui, /*force=*/false);
    } else {
        add_severity(card, ui->health.ok ? "ok" : "danger",
                     lexe::ui::format_health(ui->health));
        GtkWidget* row = add_button_row(card);
        add_button(row, "Re-check now", G_CALLBACK(on_health_recheck_clicked),
                   ui);
    }
}

void build_permissions_section(Ui* ui, GtkWidget* box,
                               const lexe::InstallationRecord& record,
                               const std::optional<lexe::Manifest>& manifest) {
    add_title(box, "Permissions");
    if (!ui->caps_loaded) {
        add_spinner_page(box, "Probing what this host's isolation backend can "
                              "actually enforce…");
        ensure_caps(ui);
        return;
    }

    const std::vector<std::string> requested =
        manifest.has_value() ? manifest->permissions : std::vector<std::string>();
    const std::vector<lexe::presentation::PermissionView> views =
        lexe::presentation::present_permissions(requested, ui->caps);
    add_section(box, "Requested by the signed manifest:",
                lexe::ui::format_permission_rows(views));
    add_body(box, "The state in brackets is what this host can actually "
                  "establish for that permission — not what the package asked "
                  "for.");
    add_section(box, "Approved for the installed version:",
                lexe::ui::format_approved_permissions(record.approved_permissions));

    const lexe::presentation::IsolationView isolation =
        lexe::presentation::present_isolation(ui->caps);
    GtkWidget* card = add_card(box, "Isolation on this platform");
    add_body(card, isolation.headline);
    if (!isolation.detail.empty()) add_body(card, isolation.detail);
    for (const std::pair<std::string, std::string>& control :
         isolation.controls) {
        add_body(card, control.first + ": " + control.second);
    }
    add_body(card, isolation.platform_caveat);
}

void build_diagnostics_section(Ui* ui, GtkWidget* box,
                               const lexe::InstallationRecord& record) {
    add_title(box, "Diagnostics");

    const lexe::ui::AppLocations locations =
        app_locations(ui->paths, record.id, record.version);
    const lexe::ChainResolution resolution =
        try_resolve_chain(ui->paths, record.id);
    const std::string chain_text = lexe::ui::format_chain_summary(resolution);

    std::string health_text = "not checked yet";
    if (ui->health_loaded && ui->health_app == record.id) {
        health_text = lexe::ui::format_health(ui->health);
        add_severity(box, ui->health.ok ? "ok" : "danger", health_text);
    } else {
        add_spinner_page(box, "Running the health check…");
        ensure_health(ui, /*force=*/false);
    }

    add_section(box, "How it would run:", chain_text);
    add_section(box, "Where its files are:",
                lexe::ui::format_app_locations(locations));

    std::string integration_text = "not checked yet";
    GtkWidget* card = add_card(box, "Desktop integration");
    if (!ui->integration_loaded) {
        add_spinner_page(card, "Checking the registrations .LEXE owns…");
        ensure_integration(ui, /*force=*/false);
    } else {
        const lexe::ui::HealthTile tile =
            lexe::ui::build_health_tile(ui->integration);
        integration_text = tile.headline + "\n" + tile.detail;
        add_severity(card, tile.severity, tile.headline);
        if (!tile.detail.empty()) add_body(card, tile.detail);
        if (!ui->integration_message.empty()) {
            add_body(card, ui->integration_message);
        }
    }
    GtkWidget* integration_row = add_button_row(card);
    GtkWidget* verify_repair =
        add_button(integration_row, "Verify & repair integration",
                   G_CALLBACK(on_integration_repair_clicked), ui);
    gtk_widget_set_sensitive(verify_repair,
                             ui->integration_loading ? FALSE : TRUE);

    const std::string diagnostics = lexe::ui::format_diagnostics_text(
        ui->runtime_version, lexe::host_os_description(),
        lexe::host_architecture(), record, locations, chain_text, health_text,
        integration_text);
    GtkWidget* row = add_button_row(box);
    GtkWidget* copy = add_button(row, "Copy diagnostics",
                                 G_CALLBACK(on_copy_text_clicked), ui,
                                 diagnostics, "Diagnostics");
    style_class(copy, "suggested-action");
    add_button(row, "Open error folder", G_CALLBACK(on_open_folder_clicked), ui,
               locations.error_dir);
}

void build_errors_section(Ui* ui, GtkWidget* box,
                          const lexe::InstallationRecord& record) {
    add_title(box, "Error History");
    add_body(box, "Every refused launch and every failed run writes a "
                  "structured record here, so a real failure is always "
                  "distinguishable from a successful run that simply showed "
                  "nothing on screen.");

    try {
        ui->error_records = lexe::ErrorStore(ui->paths).history(record.id, 50);
    } catch (const std::exception&) {
        ui->error_records.clear();
    }
    if (ui->selected_error >= static_cast<int>(ui->error_records.size())) {
        ui->selected_error = -1;
    }
    std::string error_dir;
    try {
        error_dir = lexe::ErrorStore(ui->paths).app_dir(record.id).string();
    } catch (const std::exception&) {
    }

    if (ui->error_records.empty()) {
        ui->error_details_view = nullptr;
        add_body(box, lexe::ui::format_error_history_empty(record.id));
        GtkWidget* row = add_button_row(box);
        if (!error_dir.empty()) {
            add_button(row, "Open Error Folder",
                       G_CALLBACK(on_open_folder_clicked), ui, error_dir);
        }
        add_button(row, "Close", G_CALLBACK(on_error_close_clicked), ui,
                   record.id);
        return;
    }

    if (ui->selected_error < 0) ui->selected_error = 0;

    GtkWidget* scroller = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(scroller, -1, 200);
    GtkWidget* list = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_SINGLE);
    for (const lexe::ErrorRecord& item : ui->error_records) {
        GtkWidget* row_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
        gtk_container_set_border_width(GTK_CONTAINER(row_box), 6);
        add_body(row_box, lexe::ui::format_error_row(item));
        gtk_list_box_insert(GTK_LIST_BOX(list), row_box, -1);
    }
    gtk_container_add(GTK_CONTAINER(scroller), list);
    gtk_box_pack_start(GTK_BOX(box), scroller, FALSE, FALSE, 0);

    const lexe::ErrorRecord& selected =
        ui->error_records[static_cast<std::size_t>(ui->selected_error)];
    add_heading(box, "Record details");
    ui->error_details_view = add_text_view(box, selected.to_details_text(), 260);

    connect_action(list, "row-selected", G_CALLBACK(on_error_row_selected), ui);
    GtkListBoxRow* row =
        gtk_list_box_get_row_at_index(GTK_LIST_BOX(list), ui->selected_error);
    if (row != nullptr) gtk_list_box_select_row(GTK_LIST_BOX(list), row);

    GtkWidget* actions = add_button_row(box);
    add_button(actions, "Copy Error Path",
               G_CALLBACK(on_error_copy_path_clicked), ui);
    if (!error_dir.empty()) {
        add_button(actions, "Open Error Folder",
                   G_CALLBACK(on_open_folder_clicked), ui, error_dir);
    }
    add_button(actions, "Copy Error Details",
               G_CALLBACK(on_error_copy_details_clicked), ui);
    GtkWidget* more = add_button_row(box);
    GtkWidget* retry = add_button(more, "Retry",
                                  G_CALLBACK(on_error_retry_clicked), ui,
                                  record.id);
    style_class(retry, "suggested-action");
    gtk_widget_set_sensitive(retry, ui->launch_running ? FALSE : TRUE);
    GtkWidget* clear = add_button(more, "Clear history",
                                  G_CALLBACK(on_error_clear_clicked), ui,
                                  record.id);
    style_class(clear, "destructive-action");
    add_button(more, "Close", G_CALLBACK(on_error_close_clicked), ui, record.id);
}

void build_uninstall_section(Ui* ui, GtkWidget* box,
                             const lexe::InstallationRecord& record,
                             const std::optional<lexe::Manifest>& manifest) {
    using Mode = lexe::Installer::UninstallMode;
    const Mode modes[3] = {Mode::AppOnly, Mode::AppAndCache, Mode::PurgeData};
    const std::string name =
        manifest.has_value() && !manifest->name.empty() ? manifest->name
                                                        : record.id;

    add_title(box, "Uninstall");
    add_body(box, "Removing an application never removes your data unless you "
                  "choose that explicitly. Each option states exactly what it "
                  "deletes.");

    GtkWidget* card = add_card(box, "What to remove");
    GtkWidget* first = nullptr;
    for (int i = 0; i < 3; ++i) {
        GtkWidget* radio =
            first == nullptr
                ? gtk_radio_button_new_with_label(
                      nullptr, lexe::ui::uninstall_mode_label(modes[i]).c_str())
                : gtk_radio_button_new_with_label_from_widget(
                      GTK_RADIO_BUTTON(first),
                      lexe::ui::uninstall_mode_label(modes[i]).c_str());
        if (first == nullptr) first = radio;
        ui->uninstall_radios[i] = radio;
        gtk_box_pack_start(GTK_BOX(card), radio, FALSE, FALSE, 0);
        GtkWidget* description =
            add_body(card, lexe::ui::uninstall_mode_description(modes[i]));
        gtk_widget_set_margin_start(description, 24);
        gtk_widget_set_margin_bottom(description, 6);
        connect_action(radio, "toggled", G_CALLBACK(on_uninstall_mode_toggled),
                       ui, "", "", i);
    }
    const int active = (ui->uninstall_mode < 0 || ui->uninstall_mode > 2)
                           ? 0
                           : ui->uninstall_mode;
    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(ui->uninstall_radios[active]), TRUE);

    bool retained = false;
    try {
        retained = lexe::Registry(ui->paths).has_retained_data(record.id);
    } catch (const std::exception&) {
    }
    add_body(box, retained
                      ? "This application currently has saved data on this "
                        "machine."
                      : "This application has no saved data on this machine "
                        "right now.");

    GtkWidget* row = add_button_row(box);
    GtkWidget* remove = add_button(row, "Remove…",
                                   G_CALLBACK(on_uninstall_clicked), ui,
                                   record.id, name);
    style_class(remove, "destructive-action");
    add_button(row, "Cancel", G_CALLBACK(on_nav_clicked), ui, "apps");
}

void build_app_page(Ui* ui) {
    GtkWidget* box = ui->app_box;
    if (ui->app_id.empty()) {
        GtkWidget* content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
        gtk_container_set_border_width(GTK_CONTAINER(content), 16);
        gtk_box_pack_start(GTK_BOX(box), content, FALSE, FALSE, 0);
        add_title(content, "No application selected");
        add_button(add_button_row(content), "Browse installed applications",
                   G_CALLBACK(on_nav_clicked), ui, "apps");
        return;
    }

    const std::optional<lexe::InstallationRecord> record =
        try_record(ui->paths, ui->app_id);
    if (!record.has_value()) {
        GtkWidget* content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
        gtk_container_set_border_width(GTK_CONTAINER(content), 16);
        gtk_box_pack_start(GTK_BOX(box), content, FALSE, FALSE, 0);
        add_title(content, ui->app_id);
        add_severity(content, "danger",
                     "This application is not installed on this machine, or its "
                     "installation record could not be read.");
        add_button(add_button_row(content), "Browse installed applications",
                   G_CALLBACK(on_nav_clicked), ui, "apps");
        return;
    }
    const std::optional<lexe::Manifest> manifest =
        try_manifest(ui->paths, ui->app_id);

    GtkWidget* header = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(header), 16);
    gtk_box_pack_start(GTK_BOX(box), header, FALSE, FALSE, 0);
    add_button(add_button_row(header), "← All applications",
               G_CALLBACK(on_nav_clicked), ui, "apps");
    add_title(header, manifest.has_value() && !manifest->name.empty()
                          ? manifest->name
                          : record->id);
    add_body(header, "Version " + record->version + "  ·  " + record->id);
    add_body(header, lexe::ui::format_last_run(record->last_run_at,
                                               record->last_exit_code));
    gtk_box_pack_start(GTK_BOX(box),
                       gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE,
                       FALSE, 0);

    GtkWidget* pane = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_box_pack_start(GTK_BOX(box), pane, TRUE, TRUE, 0);
    GtkWidget* sub = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(sub), GTK_STACK_TRANSITION_TYPE_NONE);
    GtkWidget* sidebar = gtk_stack_sidebar_new();
    gtk_stack_sidebar_set_stack(GTK_STACK_SIDEBAR(sidebar), GTK_STACK(sub));
    gtk_widget_set_size_request(sidebar, 170, -1);
    gtk_box_pack_start(GTK_BOX(pane), sidebar, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(pane),
                       gtk_separator_new(GTK_ORIENTATION_VERTICAL), FALSE,
                       FALSE, 0);
    gtk_box_pack_start(GTK_BOX(pane), sub, TRUE, TRUE, 0);

    build_launch_section(ui, add_section_page(sub, "launch", "Launch"), *record,
                         manifest);
    build_compatibility_section(
        ui, add_section_page(sub, "compatibility", "Compatibility"), *record);
    build_runtime_section(ui, add_section_page(sub, "runtime", "Runtime"),
                          *record);
    build_permissions_section(
        ui, add_section_page(sub, "permissions", "Permissions"), *record,
        manifest);
    build_diagnostics_section(
        ui, add_section_page(sub, "diagnostics", "Diagnostics"), *record);
    build_errors_section(ui, add_section_page(sub, "errors", "Error History"),
                         *record);
    build_uninstall_section(ui, add_section_page(sub, "uninstall", "Uninstall"),
                            *record, manifest);

    gtk_stack_set_visible_child_name(GTK_STACK(sub), ui->section.c_str());
    connect_action(sub, "notify::visible-child-name",
                   G_CALLBACK(on_section_changed), ui);
}

// ------------------------------------------------------------- Settings

void build_settings_page(Ui* ui) {
    GtkWidget* box = ui->settings_box;
    add_title(box, "Settings");
    add_body(box, lexe::ui::settings_scope_note());

    GtkWidget* card = add_card(box, "Preferences");
    for (const std::string& key : lexe::Settings::keys()) {
        std::string current;
        try {
            current = ui->settings.get(key);
        } catch (const std::exception&) {
            continue;
        }
        GtkWidget* row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
        GtkWidget* label = gtk_label_new(lexe::ui::setting_title(key).c_str());
        gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
        gtk_widget_set_size_request(label, 190, -1);
        gtk_box_pack_start(GTK_BOX(row), label, FALSE, FALSE, 0);

        if (lexe::ui::setting_is_boolean(key)) {
            GtkWidget* check = gtk_check_button_new_with_label("Enabled");
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check),
                                         current == "true" ? TRUE : FALSE);
            connect_action(check, "toggled", G_CALLBACK(on_setting_toggled), ui,
                           key);
            gtk_box_pack_start(GTK_BOX(row), check, FALSE, FALSE, 0);
        } else {
            GtkWidget* combo = gtk_combo_box_text_new();
            const std::vector<std::string> choices =
                lexe::ui::setting_choices(key);
            int active = 0;
            for (std::size_t i = 0; i < choices.size(); ++i) {
                gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo),
                                               choices[i].c_str());
                if (choices[i] == current) active = static_cast<int>(i);
            }
            gtk_combo_box_set_active(GTK_COMBO_BOX(combo), active);
            connect_action(combo, "changed",
                           G_CALLBACK(on_setting_combo_changed), ui, key);
            gtk_box_pack_start(GTK_BOX(row), combo, FALSE, FALSE, 0);
        }
        gtk_box_pack_start(GTK_BOX(card), row, FALSE, FALSE, 0);
        GtkWidget* help = add_body(card, lexe::ui::setting_help(key));
        gtk_widget_set_margin_start(help, 8);
        gtk_widget_set_margin_bottom(help, 8);
    }

    GtkWidget* handler = add_card(box, ".LEXE file handler");
    if (!ui->integration_loaded) {
        add_spinner_page(handler, "Checking how .lexe files are registered on "
                                  "this machine…");
        ensure_integration(ui, /*force=*/false);
    } else {
        add_body(handler, lexe::ui::format_handler_state(ui->integration));
        if (!ui->integration_message.empty()) {
            add_body(handler, ui->integration_message);
        }
    }
    GtkWidget* handler_row = add_button_row(handler);
    GtkWidget* reregister =
        add_button(handler_row, "Re-register .LEXE handler",
                   G_CALLBACK(on_register_handler_clicked), ui);
    style_class(reregister, "suggested-action");
    gtk_widget_set_sensitive(reregister, ui->integration_loading ? FALSE : TRUE);
    GtkWidget* recheck = add_button(handler_row, "Re-check",
                                    G_CALLBACK(on_integration_recheck_clicked),
                                    ui);
    gtk_widget_set_sensitive(recheck, ui->integration_loading ? FALSE : TRUE);

    GtkWidget* locations = add_card(box, "Where .LEXE keeps things");
    add_body(locations,
             "Applications and launch references: " + ui->paths.home().string() +
                 "\nPersistent data: " + ui->paths.data_dir().string() +
                 "\nCache: " + ui->paths.cache_dir().string() +
                 "\nRuntime state and error records: " +
                 ui->paths.state_dir().string() + "\nYour configuration: " +
                 ui->paths.config_dir().string() + "\nMenu entries: " +
                 ui->paths.applications_dir().string());
    GtkWidget* locations_row = add_button_row(locations);
    add_button(locations_row, "Open the .LEXE folder",
               G_CALLBACK(on_open_folder_clicked), ui,
               ui->paths.home().string());
}

// ------------------------------------------------------ navigation + shell

void set_status(Ui* ui, const std::string& message) {
    ui->status = message;
    if (ui->status_label != nullptr) {
        gtk_label_set_text(GTK_LABEL(ui->status_label), message.c_str());
        gtk_widget_set_tooltip_text(ui->status_label, message.c_str());
    }
}

void update_title(Ui* ui) {
    std::string title = "Lexe " + ui->runtime_version;
    if (ui->page == "app" && !ui->app_id.empty()) {
        title += " — " + ui->app_id;
    }
    gtk_window_set_title(GTK_WINDOW(ui->window), title.c_str());
}

void refresh(Ui* ui) {
    if (ui->window == nullptr) return;
    ui->building = true;
    // Mark where we are. The nav pane is rebuilt only once, so this is the
    // only place the selection can follow the page.
    for (const auto& [page, button] : ui->nav_buttons) {
        if (button == nullptr) continue;
        GtkStyleContext* context = gtk_widget_get_style_context(button);
        const bool here =
            page == ui->page || (ui->page == "app" && page == "apps");
        if (here) {
            gtk_style_context_add_class(context, "selected");
        } else {
            gtk_style_context_remove_class(context, "selected");
        }
    }
    // Controls from the page being replaced are about to be destroyed.
    ui->compat_auto_radio = nullptr;
    ui->compat_manual_radio = nullptr;
    ui->compat_combo = nullptr;
    ui->channel_combo = nullptr;
    ui->error_details_view = nullptr;
    ui->wait_check = nullptr;
    ui->uninstall_radios[0] = nullptr;
    ui->uninstall_radios[1] = nullptr;
    ui->uninstall_radios[2] = nullptr;

    if (ui->page != "home" && ui->page != "install" && ui->page != "apps" &&
        ui->page != "app" && ui->page != "settings") {
        ui->page = "home";
    }
    GtkWidget* host = nullptr;
    if (ui->page == "home") {
        host = ui->home_box;
        clear_container(host);
        build_home_page(ui);
    } else if (ui->page == "install") {
        host = ui->install_box;
        clear_container(host);
        build_install_page(ui);
    } else if (ui->page == "apps") {
        host = ui->apps_box;
        clear_container(host);
        build_apps_page(ui);
    } else if (ui->page == "app") {
        host = ui->app_box;
        clear_container(host);
        build_app_page(ui);
    } else {
        host = ui->settings_box;
        clear_container(host);
        build_settings_page(ui);
    }
    if (host != nullptr) gtk_widget_show_all(host);
    gtk_stack_set_visible_child_name(GTK_STACK(ui->stack), ui->page.c_str());
    update_title(ui);
    ui->building = false;
}

void navigate(Ui* ui, const std::string& page) {
    ui->page = page;
    if (page != "app") ui->errors_entry = false;
    refresh(ui);
}

void navigate_app(Ui* ui, const std::string& id, const std::string& section) {
    if (ui->app_id != id) {
        // A different application: nothing cached about the previous one is
        // valid any more. (An in-flight health check discards itself when it
        // sees the id changed.)
        ui->health_loaded = false;
        ui->selected_error = -1;
        ui->launch_reported = false;
        ui->launch_lines = lexe::ui::LaunchLines{};
        ui->uninstall_mode = 0;
    }
    ui->app_id = id;
    ui->section = section.empty() ? std::string("launch") : section;
    ui->page = "app";
    refresh(ui);
    ensure_section_data(ui);
}

/// Apply the Settings theme to the LIVE window (Settings → Theme).
///
/// This window used to ignore the setting entirely: the value was validated,
/// saved and read back, and nothing ever called `style::apply`, so choosing
/// Dark changed a file and nothing else. A setting that persists a preference
/// it does not act on is worse than no setting.
///
/// The System case needs care, and the reason is subtle enough that the
/// builder documents it too: `style::apply` WRITES the theme it resolved into
/// GTK's `gtk-application-prefer-dark-theme`, and resolving System reads that
/// same flag back to ask what the desktop wants. Once a window has been Dark
/// the flag says "dark" from then on, so Dark → System would stay dark on a
/// light desktop. The desktop's own answer is snapshotted before the first
/// apply and put back here.
void apply_theme(Ui* ui, const std::string& value) {
    if (value == "system") {
        if (GtkSettings* settings = gtk_settings_get_default()) {
            g_object_set(settings, "gtk-application-prefer-dark-theme",
                         ui->desktop_prefers_dark, nullptr);
        }
    }
    style::apply(style::theme_from_string(value));
}

void build_window(Ui* ui) {
    // Before the first style::apply, which overwrites the flag this reads.
    if (GtkSettings* settings = gtk_settings_get_default()) {
        g_object_get(settings, "gtk-application-prefer-dark-theme",
                     &ui->desktop_prefers_dark, nullptr);
    }
    apply_theme(ui, ui->settings.get("theme"));

    ui->window = gtk_application_window_new(ui->app);
    gtk_window_set_default_size(GTK_WINDOW(ui->window), 1020, 740);
    connect_action(ui->window, "destroy", G_CALLBACK(on_window_destroy), ui);

    GtkWidget* root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(ui->window), root);

    GtkWidget* body = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_box_pack_start(GTK_BOX(root), body, TRUE, TRUE, 0);

    // A navigation PANE, not a column of dialog buttons: flat, full-width,
    // left-aligned items on their own surface. Stock GTK buttons here are the
    // single strongest "this is a toolkit demo" cue in the whole window, and
    // they also read as four things to press rather than as where you are.
    GtkWidget* nav = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    style::add_class(nav, "lexe-nav");
    gtk_container_set_border_width(GTK_CONTAINER(nav), 8);
    gtk_widget_set_size_request(nav, 176, -1);
    gtk_box_pack_start(GTK_BOX(body), nav, FALSE, FALSE, 0);
    const struct {
        const char* page;
        const char* label;
    } items[] = {{"home", "Home"},
                 {"install", "Install"},
                 {"apps", "Apps"},
                 {"settings", "Settings"}};
    for (const auto& item : items) {
        GtkWidget* button = gtk_button_new_with_label(item.label);
        gtk_button_set_relief(GTK_BUTTON(button), GTK_RELIEF_NONE);
        style::add_class(button, "lexe-nav-item");
        // Label left, like every navigation pane and unlike every button.
        if (GtkWidget* child = gtk_bin_get_child(GTK_BIN(button))) {
            gtk_label_set_xalign(GTK_LABEL(child), 0.0f);
        }
        connect_action(button, "clicked", G_CALLBACK(on_nav_clicked), ui,
                       item.page);
        ui->nav_buttons[item.page] = button;
        gtk_box_pack_start(GTK_BOX(nav), button, FALSE, FALSE, 0);
    }
    GtkWidget* version = gtk_label_new(("Lexe " + ui->runtime_version).c_str());
    gtk_label_set_xalign(GTK_LABEL(version), 0.0f);
    gtk_box_pack_end(GTK_BOX(nav), version, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(body),
                       gtk_separator_new(GTK_ORIENTATION_VERTICAL), FALSE,
                       FALSE, 0);

    ui->stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(ui->stack),
                                  GTK_STACK_TRANSITION_TYPE_NONE);
    gtk_box_pack_start(GTK_BOX(body), ui->stack, TRUE, TRUE, 0);

    auto add_page = [ui](const char* name) {
        GtkWidget* scroller = gtk_scrolled_window_new(nullptr, nullptr);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                       GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
        GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
        gtk_container_set_border_width(GTK_CONTAINER(box), 20);
        gtk_container_add(GTK_CONTAINER(scroller), box);
        gtk_stack_add_named(GTK_STACK(ui->stack), scroller, name);
        return box;
    };
    ui->home_box = add_page("home");
    ui->install_box = add_page("install");
    ui->apps_box = add_page("apps");
    ui->settings_box = add_page("settings");
    // The application page is NOT wrapped in a scroller: each of its sections
    // scrolls on its own, beside the section sidebar.
    ui->app_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_stack_add_named(GTK_STACK(ui->stack), ui->app_box, "app");

    gtk_box_pack_start(GTK_BOX(root),
                       gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE,
                       FALSE, 0);
    ui->status_label = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(ui->status_label), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(ui->status_label), PANGO_ELLIPSIZE_END);
    gtk_label_set_selectable(GTK_LABEL(ui->status_label), TRUE);
    gtk_widget_set_margin_start(ui->status_label, 12);
    gtk_widget_set_margin_end(ui->status_label, 12);
    gtk_widget_set_margin_top(ui->status_label, 4);
    gtk_widget_set_margin_bottom(ui->status_label, 4);
    gtk_box_pack_start(GTK_BOX(root), ui->status_label, FALSE, FALSE, 0);

    gtk_widget_show_all(ui->window);
    set_status(ui, ui->status);
}

void show_fatal(const std::string& message) {
    GtkWidget* dialog =
        gtk_message_dialog_new(nullptr, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR,
                               GTK_BUTTONS_CLOSE, "%s", message.c_str());
    gtk_window_set_title(GTK_WINDOW(dialog), "Lexe");
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

bool ensure_paths(Ui* ui, std::string& error) {
    if (ui->paths_ok) return true;
    try {
        ui->paths = lexe::Paths::detect();
    } catch (const std::exception& e) {
        error = std::string("Cannot resolve the .LEXE directories: ") + e.what();
        return false;
    }
    try {
        ui->settings = lexe::Settings::load(ui->paths);
    } catch (const std::exception& e) {
        ui->settings = lexe::Settings{};
        ui->status = std::string("Settings could not be read, so the defaults "
                                 "are shown: ") +
                     e.what();
    }
    ui->paths_ok = true;
    return true;
}

void ensure_window(Ui* ui) {
    if (ui->window == nullptr) build_window(ui);
}

void apply_start_request(Ui* ui, const lexe::ui::StartRequest& request,
                         const std::string& cwd) {
    switch (request.mode) {
    case lexe::ui::StartMode::Home:
        navigate(ui, "home");
        return;
    case lexe::ui::StartMode::OpenFile: {
        fs::path file(request.argument);
        if (file.is_relative() && !cwd.empty()) file = fs::path(cwd) / file;
        start_open_file(ui, file);
        return;
    }
    case lexe::ui::StartMode::AppPage:
        ui->errors_entry = false;
        if (!is_installed(ui->paths, request.argument)) {
            set_status(ui, request.argument +
                               " is not installed on this machine.");
        }
        navigate_app(ui, request.argument, "launch");
        return;
    case lexe::ui::StartMode::ErrorHistory:
        // ".LEXE Error" is this section of this window, not an application of
        // its own. Opened this way, Close closes the window.
        ui->errors_entry = true;
        navigate_app(ui, request.argument, "errors");
        return;
    case lexe::ui::StartMode::Usage:
        return;
    }
}

/// The command line of EVERY invocation — the first one and every later one,
/// which GApplication forwards here instead of starting a second process.
gint on_command_line(GApplication*, GApplicationCommandLine* cmdline,
                     gpointer data) {
    Ui* ui = static_cast<Ui*>(data);

    gint argc = 0;
    gchar** argv = g_application_command_line_get_arguments(cmdline, &argc);
    std::vector<std::string> args;
    for (gint i = 1; i < argc; ++i) {
        if (argv[i] != nullptr) args.push_back(argv[i]);
    }
    const gchar* raw_cwd = g_application_command_line_get_cwd(cmdline);
    const std::string cwd = raw_cwd != nullptr ? raw_cwd : std::string();
    g_strfreev(argv);

    const lexe::ui::StartRequest request = lexe::ui::parse_command_line(args);
    if (request.mode == lexe::ui::StartMode::Usage) {
        if (request.bad) {
            g_application_command_line_printerr(cmdline, "%s",
                                                request.message.c_str());
            return 2;
        }
        g_application_command_line_print(cmdline, "%s", request.message.c_str());
        return 0;
    }

    std::string error;
    if (!ensure_paths(ui, error)) {
        g_application_command_line_printerr(cmdline, "%s\n", error.c_str());
        show_fatal(error);
        return 1;
    }

    ensure_window(ui);
    // Single instance: a second invocation FOCUSES this window and navigates
    // it. It never opens a second window and never starts a second process.
    gtk_window_present(GTK_WINDOW(ui->window));
    apply_start_request(ui, request, cwd);
    return 0;
}

void on_activate(GApplication*, gpointer data) {
    Ui* ui = static_cast<Ui*>(data);
    std::string error;
    if (!ensure_paths(ui, error)) {
        show_fatal(error);
        return;
    }
    ensure_window(ui);
    gtk_window_present(GTK_WINDOW(ui->window));
    if (ui->page.empty()) navigate(ui, "home");
}

} // namespace

int main(int argc, char** argv) {
    // Deliberately never freed: a worker continuation may still reference it
    // when the main loop stops, and the process is exiting anyway.
    Ui* ui = new Ui();
    ui->runtime_version = lexe::version::runtime_string();

    GtkApplication* app =
        gtk_application_new(kApplicationId, G_APPLICATION_HANDLES_COMMAND_LINE);
    // Stated explicitly: this id is what makes a second invocation focus the
    // window that is already open instead of starting another lexe-ui.
    g_application_set_application_id(G_APPLICATION(app), kApplicationId);
    ui->app = app;

    g_signal_connect(app, "command-line", G_CALLBACK(on_command_line), ui);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), ui);

    const int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}

#endif // !LEXE_GUI_VIEWMODEL_ONLY

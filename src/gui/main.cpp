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

#include "core/isolation.hpp"
#include "core/manifest.hpp"
#include "core/paths.hpp"
#include "core/presentation.hpp"
#include "core/transaction.hpp"
#include "core/trust.hpp"
#include "core/verify.hpp"
#include "core/versioncmp.hpp"

#if !defined(LEXE_GUI_VIEWMODEL_ONLY)
#include "gui/style.hpp"
#endif

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <iterator>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

namespace lexe::gui {

// ---------------------------------------------------------------------------
// Pure presentation logic — everything the primary screen displays, as
// strings, mirroring the SPEC "User Interface" mock. No GTK types anywhere so
// this layer is unit-testable on hosts without GTK.
// ---------------------------------------------------------------------------

// The plain package facts — size, permission wording, type line, scope, source,
// update policy — are NOT formatted here. They come from core/presentation, the
// one place both this GUI and the CLI render them, so the two can never again
// describe the same package differently. These thin aliases keep the call sites
// (and the view-model tests) readable.

using lexe::presentation::describe_permission;
using lexe::presentation::format_size;

/// The "Permissions:" block: one description per line with its TRUTHFUL
/// enforcement state on this platform, or an explicit "None requested".
inline std::string format_permissions(const std::vector<std::string>& permissions,
                                      const IsolationCapabilities& caps) {
    if (permissions.empty()) return "None requested";
    std::string text;
    for (const presentation::PermissionView& row :
         presentation::present_permissions(permissions, caps)) {
        if (!text.empty()) text += '\n';
        text += row.title + "  [" + row.enforcement + "]";
    }
    return text;
}

/// The permission CHANGE on an update, kept separate from any key-change or
/// trust decision (empty when there is nothing new).
inline std::string format_permission_delta(const PermissionDelta& delta) {
    const presentation::PermissionDeltaView view =
        presentation::present_permission_delta(delta);
    if (!view.expands) return "";
    std::string text = "New permissions this update requests (separate approval "
                       "required):";
    for (const std::string& title : view.added) {
        text += "\n  + " + title;
    }
    return text;
}

/// SPEC mock "Application Type:" line, e.g. "Native Linux — x86_64".
inline std::string format_application_type(const std::string& application_type,
                                           const std::vector<std::string>& architectures,
                                           const std::string& host_arch) {
    return presentation::application_type_line(application_type, architectures,
                                               host_arch);
}

/// The full "Installation:" block: scope + size. `payload_bytes` is the
/// package's actual payload size, used when the manifest declares no estimate —
/// the same fallback `lexe info` applies, so the CLI and the Installer never
/// disagree about how much space an install takes.
inline std::string format_install(const std::string& scope,
                                  std::uint64_t estimated_size,
                                  std::uint64_t payload_bytes = 0) {
    std::string text = presentation::install_scope_line(scope);
    text += '\n';
    const std::string size =
        presentation::install_size_line(estimated_size, payload_bytes);
    text += size.empty() ? std::string("Install size not specified") : size;
    return text;
}

/// The "Source:" block. Lexe 0.1 supports bundled packages only, so the
/// source is always the package file itself.
inline std::string format_source(const std::string& install_mode,
                                 const std::string& package_filename) {
    return presentation::source_line(install_mode, package_filename);
}

/// The "Updates:" block, or an explicit "no automatic updates" notice.
inline std::string format_updates(bool enabled, const std::string& manifest_url,
                                  const std::string& channel) {
    return presentation::updates_line(enabled, manifest_url, channel);
}

/// The two-dimensional authenticity + local-trust lines for the banner and the
/// trust section. Derived from a trust evaluation (nullopt when the package is
/// too broken to expose a key). `severity` is a styling hint — "ok" / "caution"
/// / "danger" — NEVER a claim of external verification; first-seen is "caution".
struct TrustLines {
    std::string headline;
    std::string signature;
    std::string key;
    std::string fingerprint;
    std::string expected_fingerprint; // set only when the key CHANGED
    std::string remedy;               // what the user can do about a refusal
    std::string caveat;
    std::string severity = "danger";
    bool allowed = false;
};
/// `manifest_readable` distinguishes the two ways an evaluation goes missing —
/// see the no-evaluation branch. It is NOT a trust input: an absent evaluation
/// refuses the install either way.
inline TrustLines format_trust(const std::optional<TrustEvaluation>& eval,
                               bool manifest_readable = false) {
    TrustLines t;
    if (!eval.has_value()) {
        // With no evaluation there is no signature state, no key and no
        // fingerprint — so this branch used to set the headline ONLY, and the
        // details page printed the "Authenticity & local trust:" heading over
        // four empty strings: a bold heading above a blank gap. That reads as a
        // broken renderer, and it leaves the one question the section exists to
        // answer ("was a key checked?") unanswered — the reader cannot tell
        // whether a key was found and rejected or never obtained at all. State
        // which, in the section itself.
        //
        // The two ways to get here are different facts and must not be
        // described with the same sentence: either the file could not be
        // decoded (no manifest, therefore no key), or the manifest read fine
        // and TrustStore::evaluate failed (a key exists; the local record it
        // must be compared against could not be read).
        t.severity = "danger";
        if (manifest_readable) {
            t.headline = "Local trust could not be evaluated — authenticity "
                         "cannot be established. Installation is disabled.";
            t.signature = "Signature: not presented — this application's local "
                          "trust record could not be read, so the outcome of "
                          "the signature check cannot be reported here.";
            t.key = "Signing key: not compared — until that record can be read, "
                    "a changed publisher key cannot be told apart from the key "
                    "this application is already bound to.";
        } else {
            t.headline = "This package could not be read — authenticity cannot "
                         "be established. Installation is disabled.";
            t.signature = "Signature: not checked — the file could not be "
                          "decoded, so there are no signed bytes to check.";
            t.key = "Signing key: none — the manifest that carries the "
                    "publisher's key could not be read from this file.";
        }
        // Deliberately no fingerprint, no expected fingerprint and no TOFU
        // caveat: each is a statement about a key that was never obtained. The
        // stage that actually failed is named once, by the page's "Why this
        // package was refused:" section; it is not repeated here.
        return t;
    }
    const presentation::AuthenticityView v =
        presentation::present_authenticity(*eval, "");
    t.headline = v.headline;
    t.signature = v.signature_text;
    t.key = v.key_text;
    t.fingerprint = v.fingerprint_grouped;
    t.expected_fingerprint = v.expected_fingerprint_grouped;
    t.remedy = v.remedy;
    t.caveat = v.identity_caveat;
    t.severity = presentation::to_string(v.severity);
    t.allowed = v.can_proceed;
    return t;
}

/// The "Isolation on this platform" block: headline + per-control truthful
/// states + the platform caveat.
inline std::string format_isolation(const IsolationCapabilities& caps) {
    const presentation::IsolationView v = presentation::present_isolation(caps);
    std::string text = v.headline;
    for (const std::pair<std::string, std::string>& c : v.controls) {
        text += "\n  " + c.first + ": " + c.second;
    }
    text += "\n" + v.platform_caveat;
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

// ---------------------------------------------------------------------------
// Theme preference. THREE states, not two.
//
// "Follow the desktop" is the default and is a genuinely different answer from
// "light": a two-state control (a "Dark mode" switch) can only say light or
// dark, so the first time a user touched it they would be silently converted
// from "follows my desktop" to "pinned light" forever — including when their
// desktop later flips to dark on a schedule. A GtkSwitch plus a "Follow
// system" check does express three values, but it also puts a fourth,
// meaningless combination on screen (Follow system ticked, the switch sitting
// in the "dark" position, the window rendering light), which the reader has to
// work out is not a contradiction. One list of three mutually exclusive
// options has no such state, shows all three choices at once, and needs no
// explanation.
//
// The values are exactly the three `Settings::set("theme", ...)` accepts, so
// the GUI control and `lexe config set theme` are the same preference in the
// same file rather than two stores that disagree the moment one is used.
// ---------------------------------------------------------------------------

/// The persisted values, in display order. Index 0 is the default.
inline const std::vector<std::string>& theme_option_values() {
    static const std::vector<std::string> values{"system", "light", "dark"};
    return values;
}

/// What the control shows for each value. "Follow system" rather than
/// "System": next to "Light" and "Dark", a bare "System" reads as a third
/// palette instead of as "whatever the desktop is doing".
inline const std::vector<std::string>& theme_option_labels() {
    static const std::vector<std::string> labels{"Follow system", "Light",
                                                 "Dark"};
    return labels;
}

/// Which option a persisted preference selects. An unknown value selects
/// "system" — the same fallback style::theme_from_string makes — so a
/// settings.json written by a newer runtime leaves the control showing what is
/// actually being rendered, rather than showing nothing selected at all.
inline int theme_option_index(const std::string& persisted) {
    const std::vector<std::string>& values = theme_option_values();
    const auto it = std::find(values.begin(), values.end(), persisted);
    return it == values.end() ? 0 : static_cast<int>(it - values.begin());
}

/// The value a control index selects. Out of range means "system": GTK reports
/// -1 for "no active item", and handing that on as an empty string would make
/// Settings::set throw on a purely cosmetic change.
inline std::string theme_option_value(int index) {
    const std::vector<std::string>& values = theme_option_values();
    if (index < 0 || static_cast<std::size_t>(index) >= values.size()) {
        return values.front();
    }
    return values[static_cast<std::size_t>(index)];
}

// ---------------------------------------------------------------------------
// Drag-and-drop admission.
//
// A dropped file is untrusted input that happens to have arrived by mouse.
// This decides only whether the drag delivered ONE local file worth opening; it
// decides nothing about whether that file is safe. Everything that decides
// that — the FORMAT-0.1 section 6 pipeline, the local trust evaluation, the
// permission-vocabulary check, the consent gate on Install — runs afterwards,
// unchanged, exactly as it does for a command-line argument.
//
// Every refusal carries a message. A drag that lands on the window and changes
// nothing on screen is indistinguishable from a drop target that does not
// work, and the user's next move is to drag the same file again.
// ---------------------------------------------------------------------------

struct DropCheck {
    bool accept = false;
    std::filesystem::path path; ///< set only when `accept`
    std::string message;        ///< always set when !accept, never empty
};

/// Whether a drag delivered exactly one openable `.lexe`.
///
/// `local_paths` is the drop's URI list already resolved to local filesystem
/// paths, with an EMPTY entry standing for a URI that is not a local file (an
/// http:// download, a trash:// entry, an unmounted GVfs location). Keeping the
/// URI decode in the GTK layer — it is g_filename_from_uri's job — leaves this
/// decision pure, so every refusal below is covered by tests/test_gui.cpp
/// rather than only by dragging things onto a window by hand.
inline DropCheck check_dropped_package(
    const std::vector<std::string>& local_paths) {
    DropCheck result;
    if (local_paths.empty()) {
        result.message =
            "That drop carried no file. Drag a .lexe package from a file "
            "manager, or pass one on the command line.";
        return result;
    }
    if (local_paths.size() > 1) {
        result.message =
            "Drop one package at a time — that drag carried " +
            std::to_string(local_paths.size()) +
            " items, and this window reviews and installs a single package.";
        return result;
    }
    if (local_paths.front().empty()) {
        result.message =
            "Only a local file can be opened here. That drop was a remote or "
            "virtual location; save the .lexe to disk first, then drop the "
            "file.";
        return result;
    }
    const std::filesystem::path candidate(local_paths.front());
    const std::string shown = candidate.filename().string();
    std::error_code ec;
    // Directory FIRST. A folder named "app.lexe" — which is what an unpacked
    // project directory tends to be called during development — would otherwise
    // pass the extension check below and be reported as an unreadable package,
    // naming a zip failure instead of the mistake the user actually made.
    if (std::filesystem::is_directory(candidate, ec)) {
        result.message = "\"" + shown +
                         "\" is a folder. Drop the .lexe package file itself, "
                         "not the directory it lives in — build a directory "
                         "into a package with `lexe build`.";
        return result;
    }
    if (!std::filesystem::is_regular_file(candidate, ec)) {
        result.message =
            "\"" + shown +
            "\" is not a readable file — it may have been moved, or it may be "
            "a device or socket rather than a package.";
        return result;
    }
    // Case-insensitive: a package that travelled through a FAT or ISO-9660
    // volume (a USB stick, a burned image) comes back named APP.LEXE, and
    // refusing a perfectly good package because the filesystem upcased its name
    // is a false rejection the user cannot act on. The extension is a hint about
    // intent only — section 6 verification is what decides whether the bytes are
    // really a package.
    std::string extension = candidate.extension().string();
    for (char& c : extension) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (extension != ".lexe") {
        result.message =
            "\"" + shown +
            "\" is not a .lexe package. This window installs Lexe packages, "
            "which are named <application>.lexe.";
        return result;
    }
    result.accept = true;
    result.path = candidate;
    return result;
}

/// The empty-state screen, shown when the installer is launched with no
/// argument.
///
/// That used to be a modal usage error and exit(2), which is the wrong answer
/// for a window that is a drop target: someone who launches the installer from
/// a desktop menu has no command line to add an argument to, and the one thing
/// they need is somewhere to put a package.
struct DropZoneText {
    std::string title;
    std::string hint;
    std::string command;   ///< rendered monospaced
    std::string assurance;
};

inline DropZoneText drop_zone_text() {
    DropZoneText text;
    text.title = "Drop a .lexe package here";
    text.hint = "… or pass one on the command line:";
    text.command = "lexe-installer <application.lexe>";
    text.assurance =
        "However it arrives, a package is checked the same way: signature and "
        "payload verification, then the signing key against the ones this "
        "machine already trusts. Nothing installs until that passes.";
    return text;
}

/// Everything the installer window displays, precomputed as plain strings.
struct ViewModel {
    std::string app_name;
    std::string app_id;
    std::string publisher_line;   // "Published by … (not independently verified)"
    std::string version_line;     // "Version …"
    std::string source_text;      // "Source:" block
    std::string type_text;        // "Application Type:" block
    std::string permissions_text; // "Permissions:" block (with enforcement)
    std::string permission_delta_text; // new-permissions-on-update ("" when none)
    bool permission_expansion = false;  // this update requests NEW permissions
    /// What this install REPLACES, when the application is already installed
    /// ("" for a fresh install). The window used to give no sign at all that it
    /// was about to replace something, including when it moved backwards.
    std::string replacement_text;
    std::string install_text;     // "Installation:" block (scope + size)
    std::string updates_text;     // "Updates:" block
    std::string isolation_text;   // "Isolation on this platform" block
    // Authenticity + local trust (two dimensions, never one "verified" bit):
    std::string status_text;      // banner headline (the trust headline)
    std::string signature_text;   // "Signature: valid (Ed25519)" etc.
    std::string key_text;         // the local key-state sentence
    std::string fingerprint_text; // grouped signing-key fingerprint
    std::string expected_fingerprint_text; // the bound key, when it differs
    std::string trust_remedy;     // what to do about a trust refusal
    std::string identity_caveat;  // TOFU caveat (always present when readable)
    std::string trust_severity;   // "ok" | "caution" | "danger" (banner color)
    bool verified = false;        // the §6 report passed (authenticity only)
    // WHY a package was refused, named the way `lexe verify` names it. Without
    // this the window showed the same screen for a missing file, a corrupt
    // payload and a bad signature, and never told the user which stage failed.
    std::string refusal_text;
    bool can_install = false;     // §6 passed AND trust allows AND manifest read
    std::vector<std::string> channels;  // Advanced Options channel combo
    int active_channel = 0;             // preselected combo index
    /// Whether this package actually declares somewhere to check for updates.
    /// The channel selector is meaningless without one.
    bool has_update_source = false;
    std::string advanced_dirs_text;     // Advanced Options directory summary
    // Plain-language answer to "where does this go, and can I undo it?"
    std::string after_install_text =
        "Installs under your home directory — no root, nothing system-wide. You "
        "can remove it any time; your data is kept unless you explicitly purge it.";
    // Plain-language answer to "can I verify this again later?"
    std::string verify_later_text =
        "Verified now, and re-checked on every launch — the runtime confirms file "
        "integrity before the app runs. Re-inspect any package with `lexe inspect`; "
        "re-verify installed files with `lexe repair <id>`.";
};

/// Build the primary-screen view model. `eval` is the local trust evaluation
/// (nullopt when the manifest is unreadable), `caps` the probed isolation
/// capability, `delta` the permission change on an update (empty for a fresh
/// install). Pure: all effectful inputs are passed in, so the GTK-free layer is
/// unit-testable on every platform.
inline ViewModel build_view_model(const std::optional<Manifest>& manifest,
                                  const VerificationReport& report,
                                  const std::filesystem::path& package_path,
                                  const Paths& paths,
                                  const std::string& host_arch,
                                  const std::optional<TrustEvaluation>& eval,
                                  const IsolationCapabilities& caps,
                                  const PermissionDelta& delta = {},
                                  std::uint64_t payload_bytes = 0,
                                  const std::string& installed_version = "") {
    ViewModel vm;
    const std::string filename = package_path.filename().string();
    vm.verified = report.ok();
    if (!report.ok()) {
        if (const VerificationStage* f = report.first_failure(); f != nullptr) {
            vm.refusal_text = "Verification failed at the \"" + f->name +
                              "\" stage.";
            if (!f->detail.empty()) vm.refusal_text += "\n" + f->detail;
        } else {
            vm.refusal_text = "This package did not pass verification.";
        }
        vm.refusal_text +=
            "\nRe-download it from the original source, or inspect it with "
            "`lexe verify`.";
    }

    const TrustLines trust = format_trust(eval, manifest.has_value());
    vm.status_text = trust.headline;
    vm.signature_text = trust.signature;
    vm.key_text = trust.key;
    vm.fingerprint_text = trust.fingerprint;
    vm.expected_fingerprint_text = trust.expected_fingerprint;
    vm.trust_remedy = trust.remedy;
    vm.identity_caveat = trust.caveat;
    vm.trust_severity = trust.severity;
    vm.isolation_text = format_isolation(caps);

    if (manifest.has_value()) {
        const Manifest& m = *manifest;
        vm.app_id = m.id;
        vm.app_name = m.name;
        vm.publisher_line = "Published by " + m.publisher_name +
                            " (publisher identity not independently verified)";
        if (!m.publisher_website.empty()) {
            vm.publisher_line += " — " + m.publisher_website;
        }
        vm.version_line = "Version " + m.version;
        vm.source_text = format_source(m.install_mode, filename);
        vm.type_text = format_application_type(m.application_type,
                                               m.architectures, host_arch);
        vm.permissions_text = format_permissions(m.permissions, caps);
        vm.permission_delta_text = format_permission_delta(delta);
        vm.permission_expansion = delta.expands();
        if (!installed_version.empty()) {
            // `lexe rollback` only ever moves to an OLDER retained version, so a
            // downgrade nobody noticed strands the newer build on disk with no
            // way to reach it. Say so before, not after.
            if (installed_version == m.version) {
                vm.replacement_text = "Version " + m.version +
                                      " is already installed. Installing again "
                                      "replaces it with this copy.";
            } else if (version_less(m.version, installed_version)) {
                vm.replacement_text =
                    "Downgrade: version " + installed_version +
                    " is installed, and this is the older " + m.version +
                    ".\nGoing back to " + installed_version +
                    " afterwards means installing that package again — "
                    "\"rollback\" moves to an older version, not a newer one.";
            } else {
                vm.replacement_text = "This replaces the installed version " +
                                      installed_version + " with " + m.version +
                                      ".";
            }
        }
        vm.install_text = format_install(m.install_scope,
                                         m.install_estimated_size,
                                         payload_bytes);
        vm.after_install_text =
            "Installs under your home directory — no root, nothing system-wide.\n"
            "Remove it any time with:  lexe remove " + m.id + "\n"
            "Your data is kept unless you also pass --purge-data.";
        vm.updates_text = format_updates(m.updates_enabled, m.updates_manifest_url,
                                         m.updates_channel);
        vm.channels = channel_options(m.updates_channel);
        vm.active_channel = channel_active_index(vm.channels, m.updates_channel);
        vm.has_update_source = m.updates_enabled && !m.updates_manifest_url.empty();
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
    // Install is permitted only when the signature verified AND local trust
    // allows it (a valid-but-first-seen key is allowed, but a changed/blocked/
    // corrupt key disables Install even though the signature is valid).
    vm.can_install = vm.verified && manifest.has_value() && trust.allowed;

    // A package may verify perfectly and still be impossible for this runtime
    // to install: the 0.1 permission vocabulary is frozen, and the installer
    // refuses an id outside it (`lexe install` exits 3 with "unknown permission
    // ... (not in the 0.1 vocabulary)"). The window used to show the ordinary
    // caution banner with Install ENABLED, so the only way to discover that was
    // to press it — and the failure that came back was reported off-screen.
    // Nothing downstream catches it either: `lexe build`, `lexe verify` and
    // `lexe info` all accept these ids.
    if (manifest.has_value()) {
        try {
            (void)normalize_permissions(manifest->permissions);
        } catch (const std::exception& e) {
            vm.can_install = false;
            vm.trust_severity = "danger";
            vm.status_text = "Refused — this runtime cannot grant a permission "
                             "this package requires";
            vm.refusal_text =
                std::string(e.what()) +
                "\nThe 0.1 permission vocabulary is frozen. A package may only "
                "request permissions this runtime knows how to enforce or "
                "record, so there is nothing to consent to here.";
        }
    }
    return vm;
}

/// The body of the details page's "Authenticity & local trust:" section, in one
/// pure place so the "heading over an empty body" defect is testable rather than
/// only visible on screen: build_view_model guarantees a signature line for every
/// input, and this composes the rest around it. Never returns an empty string.
inline std::string trust_section_body(const ViewModel& vm) {
    std::string body = vm.signature_text;
    const auto add = [&body](const std::string& line) {
        if (line.empty()) return;
        if (!body.empty()) body += '\n';
        body += line;
    };
    add(vm.key_text);
    if (!vm.fingerprint_text.empty()) {
        // When the key CHANGED, label the two so they can be compared. A lone
        // fingerprint on a screen that says "the signing key has changed" gives
        // the reader nothing to compare it against.
        add(vm.expected_fingerprint_text.empty()
                ? "Signing key fingerprint: " + vm.fingerprint_text
                : "Expected (already installed): " + vm.expected_fingerprint_text +
                      "\nPresented (this package):  " + vm.fingerprint_text);
    }
    add(vm.identity_caveat);
    return body;
}

// ---------------------------------------------------------------------------
// Progress reporting for an install in flight.
//
// Installer::install() takes no progress callback, so the GUI cannot be told
// where it has got to — but it can READ it: every phase transition of the
// staged install is written to apps/<id>/txn.json before the work of that phase
// starts (HARDENING.md §A, core/transaction.hpp). Polling that journal names the
// stage that is genuinely running. It is the real state on disk, not a timer
// pretending to be one, and there is deliberately no percentage or bar: the
// installer publishes phases, not byte counts, and a fraction here would be an
// invention.
// ---------------------------------------------------------------------------

/// The stages an install passes through, in order. Ordering is meaningful: the
/// on-screen stage only ever moves FORWARD (see install_stage_rank).
enum class InstallStage {
    Verifying,  // §6 pipeline, trust + permission gates: before any txn exists
    Extracting, // TxnPhase::Preparing
    Rechecking, // TxnPhase::Staged
    Placing,    // TxnPhase::Verified
    Activating, // TxnPhase::Promoted
    Finishing,  // TxnPhase::RecordUpdated
};

/// Monotonic position of a stage. The journal is DELETED on commit, so a naive
/// reading of the phase snaps back to "no transaction" just as the install
/// succeeds; ranking lets the screen refuse to walk backwards and claim it is
/// verifying again at the very end.
inline int install_stage_rank(InstallStage stage) {
    return static_cast<int>(stage);
}

/// Map a transaction journal phase to the stage to show. TxnPhase::None means
/// no transaction has begun yet, which during an install is the §6 verification
/// and the trust/permission gates that run before InstallTransaction::begin().
inline InstallStage install_stage_from_phase(TxnPhase phase) {
    switch (phase) {
        case TxnPhase::Preparing:     return InstallStage::Extracting;
        case TxnPhase::Staged:        return InstallStage::Rechecking;
        case TxnPhase::Verified:      return InstallStage::Placing;
        case TxnPhase::Promoted:      return InstallStage::Activating;
        case TxnPhase::RecordUpdated: return InstallStage::Finishing;
        case TxnPhase::None:          break;
    }
    return InstallStage::Verifying;
}

/// What the stage is doing, in the user's terms. Each sentence describes work
/// the installer actually performs in that phase — nothing is promised about
/// how long it takes.
inline std::string install_stage_text(InstallStage stage) {
    switch (stage) {
        case InstallStage::Extracting:
            return "Extracting the application into a staging area.";
        case InstallStage::Rechecking:
            return "Re-checking the extracted files against their signed hashes.";
        case InstallStage::Placing:
            return "Putting the new version into place.";
        case InstallStage::Activating:
            return "Making the new version the active one.";
        case InstallStage::Finishing:
            return "Finishing up.";
        case InstallStage::Verifying:
            break;
    }
    return "Checking the package: signatures first, then every file against its "
           "signed hashes.";
}

/// "0:07" / "3:42" / "1:05:30". Shown next to the stage so a long extraction is
/// visibly RUNNING: a spinner alone is indistinguishable from a hung process,
/// and this screen has no other moving part that reflects real elapsed work.
inline std::string format_elapsed(std::int64_t seconds) {
    if (seconds < 0) seconds = 0;
    const std::int64_t hours = seconds / 3600;
    const std::int64_t minutes = (seconds % 3600) / 60;
    const std::int64_t secs = seconds % 60;
    char buffer[32];
    if (hours > 0) {
        std::snprintf(buffer, sizeof(buffer), "%lld:%02lld:%02lld",
                      static_cast<long long>(hours),
                      static_cast<long long>(minutes),
                      static_cast<long long>(secs));
    } else {
        std::snprintf(buffer, sizeof(buffer), "%lld:%02lld",
                      static_cast<long long>(minutes),
                      static_cast<long long>(secs));
    }
    return std::string(buffer);
}

/// The standing explanation under the progress spinner. It answers the two
/// questions the old screen left open — "is it stuck?" and "how do I stop it?" —
/// without offering a stop that cannot be performed safely.
inline std::string install_progress_note() {
    return "Nothing is switched over until every file has been extracted and "
           "re-checked, so this can be left to finish — the previous state stays "
           "active until then.\n"
           "There is no Cancel: once files are being written there is no point "
           "this runtime can stop at without leaving the install half-applied, "
           "so the window stays put until the install finishes or fails.";
}

} // namespace lexe::gui

// ===========================================================================
// GTK 3 application. Compiled only when <gtk/gtk.h> is available — the
// Linux-only `lexe-installer` target. Never seen by non-GTK builds.
// ===========================================================================
#ifndef LEXE_GUI_VIEWMODEL_ONLY

#include "core/error.hpp"
#include "core/installer.hpp"
#include "core/isolation.hpp"
#include "core/launcher.hpp"
#include "core/package.hpp"
#include "core/permissions.hpp"
#include "core/registry.hpp"
#include "core/settings.hpp"
#include "core/trust.hpp"
#include "core/util.hpp"
#include "core/version.hpp"

#include <gtk/gtk.h>

#include <exception>
#include <system_error>

namespace {

/// The shared visual language (src/gui/style.hpp); this GTK layer lives in an
/// anonymous namespace outside lexe::gui, so alias it rather than repeating the
/// full qualification at every call site.
namespace style = lexe::gui::style;

/// Whole-application state, owned by main(). Widget pointers are only ever
/// touched on the GTK main thread; the plain-data result fields are written
/// by exactly one worker thread and read on the main thread only after the
/// worker's final g_idle_add (which orders the accesses).
struct AppState {
    std::filesystem::path package_path;
    lexe::Paths paths;
    lexe::gui::ViewModel vm;
    /// True once a package has been opened. Launched with no argument the
    /// window starts on the drop zone with no package at all, so nothing may
    /// assume `vm` describes something real.
    bool has_package = false;

    // Theme preference (main thread only). The WHOLE persisted bundle is kept,
    // not just the theme string: settings.json holds update_check,
    // developer_mode and diagnostics too, and saving a freshly defaulted
    // Settings to write one cosmetic field would silently reset the other three.
    lexe::Settings settings;
    style::Theme theme = style::Theme::System;
    /// The desktop's OWN dark preference, sampled once BEFORE the first
    /// style::apply() — see apply_theme() for why that snapshot has to exist.
    gboolean desktop_prefer_dark = FALSE;

    // Widgets (main thread only).
    GtkWidget* window = nullptr;
    GtkWidget* stack = nullptr;
    GtkWidget* banner_label = nullptr;
    GtkWidget* install_button = nullptr;
    GtkWidget* details_close_button = nullptr;
    GtkWidget* channel_combo = nullptr;
    GtkWidget* accept_permissions_check = nullptr;
    bool accept_permissions = false; // read on the main thread, before the worker
    GtkWidget* spinner = nullptr;
    GtkWidget* progress_label = nullptr;
    GtkWidget* progress_stage_label = nullptr;
    GtkWidget* progress_elapsed_label = nullptr;
    GtkWidget* progress_note_label = nullptr;
    GtkWidget* success_label = nullptr;
    GtkWidget* launch_button = nullptr;
    GtkWidget* launch_status_label = nullptr;
    GtkWidget* theme_combo = nullptr;
    /// The details screen's CONTAINER (banner + scroller + action bar). Held
    /// separately from the widgets inside it because opening a second package
    /// by dropping it rebuilds those from a new view model; everything above
    /// only ever refers to the current generation.
    GtkWidget* details_page = nullptr;
    GtkWidget* drop_banner_strip = nullptr;
    GtkWidget* drop_banner_label = nullptr;
    GtkWidget* drop_close_button = nullptr;
    /// Handed from the drag handler to the idle callback that actually opens
    /// the file, so the drag protocol completes before verification blocks the
    /// UI thread.
    std::filesystem::path pending_drop;

    // Install worker -> main loop.
    std::string selected_channel = "stable";
    std::string install_error;
    std::string installed_id;
    std::string installed_version;

    // Progress screen (main thread only). The stage is not pushed by the
    // worker — the worker touches no GTK API and Installer::install() reports
    // nothing back until it returns — it is polled off the transaction journal
    // the installer writes to disk. See lexe::gui's progress section.
    bool installing = false;       // an install worker is in flight
    guint progress_timer = 0;      // g_timeout_add id, 0 when not running
    gint64 progress_started_us = 0;
    int progress_stage_rank = 0;   // highest stage shown so far (never rewinds)
    /// The journal timestamp present BEFORE this install started, if any. A
    /// leftover journal from an earlier interrupted run is still on disk while
    /// install() recovers it, and reporting its phase as this install's progress
    /// would name a stage that is not running. Ignore that journal until the
    /// timestamp changes, i.e. until begin() writes a new one.
    std::string pre_txn_started_at;

    // Launch worker -> main loop.
    std::string launch_error;
    int launch_exit_code = 0;
    /// A launch worker is in flight. It reads `installed_id` on its own thread,
    /// so opening another package (which rewrites it) has to wait.
    bool launching = false;
};

/// Set the authenticity/trust banner. The colour reflects the trust SEVERITY,
/// never a plain "verified": green only for a known/trusted key ("ok"), amber
/// for a valid-but-first-seen key ("caution" — NOT styled as verified), red for
/// a refusal ("danger"). Any other value is treated as danger.
void set_banner_label(GtkWidget* banner_label, const std::string& severity,
                      const std::string& text) {
    if (banner_label == nullptr) return;
    // Severity is a STYLE CLASS on the banner strip, not a colour baked into
    // markup: the strip carries a tinted background, a border and a text colour
    // together, so the three states stay distinguishable to someone who cannot
    // separate the hues — which a bare coloured word does not manage.
    GtkWidget* strip = gtk_widget_get_parent(banner_label);
    for (const char* klass : {"ok", "caution", "danger"}) {
        if (strip != nullptr) style::remove_class(strip, klass);
    }
    const char* klass = severity == "ok"        ? "ok"
                        : severity == "caution" ? "caution"
                                                : "danger";
    if (strip != nullptr) style::add_class(strip, klass);
    gtk_label_set_text(GTK_LABEL(banner_label), text.c_str());
}

void set_banner(AppState* st, const std::string& severity,
                const std::string& text) {
    set_banner_label(st->banner_label, severity, text);
}

/// Put a message where the user is actually looking.
///
/// The window has four screens and only the details screen carries the trust
/// banner, so a drop refused while the drop zone (or the progress or success
/// screen) is up would have been written to a strip that is not on screen —
/// the same "the window came back looking completely unchanged" failure the
/// banner was pinned above the scroller to prevent. Each screen has one place
/// that is always visible on it; this picks that place.
void set_status_message(AppState* st, const std::string& severity,
                        const std::string& text) {
    const gchar* visible =
        st->stack != nullptr
            ? gtk_stack_get_visible_child_name(GTK_STACK(st->stack))
            : nullptr;
    const std::string page = visible != nullptr ? visible : "";
    // Deliberately NO "details" branch: the details screen's banner states the
    // package's authenticity, which is not ours to overwrite.
    if (page == "progress" && st->progress_note_label != nullptr) {
        gtk_label_set_text(GTK_LABEL(st->progress_note_label), text.c_str());
        return;
    }
    if (page == "done" && st->launch_status_label != nullptr) {
        gtk_label_set_text(GTK_LABEL(st->launch_status_label), text.c_str());
        return;
    }
    if (st->drop_banner_label != nullptr) {
        set_banner_label(st->drop_banner_label, severity, text);
        // The strip is gtk_widget_set_no_show_all()'d so an empty tinted bar
        // never sits above an empty window, which means the toplevel's
        // show_all never descended into it — show the label explicitly, not
        // just the strip, or the bar appears blank.
        gtk_widget_show(st->drop_banner_label);
        gtk_widget_show(st->drop_banner_strip);
    }
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

/// Bold heading + body block, mirroring the SPEC mock's sections. The heading
/// is ESCAPED before being embedded in Pango markup — a heading may legitimately
/// contain markup metacharacters (e.g. the "&" in "Authenticity & local trust"),
/// which would otherwise fail to parse and render the heading blank.
void add_section(GtkWidget* box, const char* heading, const std::string& body) {
    // A heading with nothing under it is not a section, it is a rendering bug
    // the user has to interpret — the "Authenticity & local trust:" heading over
    // an empty body (an unreadable package leaves no key, signature or
    // fingerprint to print) looked exactly like a label that had failed to
    // render, and said nothing about whether a key had been checked. The view
    // model now always supplies a body for that section; this is the structural
    // guarantee that no future section can reintroduce the defect. Dropping a
    // heading with no content hides nothing: there was nothing to show.
    if (body.empty()) return;
    // Each section is a CARD: related facts group visually instead of running
    // together into one column of bold-then-text. The heading is a small muted
    // label rather than bold body text, so hierarchy comes from the type scale.
    GtkWidget* card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    style::add_class(card, "lexe-card");
    GtkWidget* head = gtk_label_new(heading);
    style::add_class(head, "lexe-section-heading");
    gtk_label_set_xalign(GTK_LABEL(head), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(head), TRUE);
    gtk_box_pack_start(GTK_BOX(card), head, FALSE, FALSE, 0);
    add_body_label(card, body);
    gtk_box_pack_start(GTK_BOX(box), card, FALSE, FALSE, 0);
}

void on_window_destroy(GtkWidget*, gpointer) { gtk_main_quit(); }

void on_close_clicked(GtkButton*, gpointer) { gtk_main_quit(); }

/// The window manager's close button, while an install is in flight.
///
/// This WAS the unsafe cancel the progress screen is careful not to offer:
/// "destroy" quits the main loop, main() returns, and the process exits with
/// the install worker still extracting into apps/<id>/.txn-staging or midway
/// through desktop integration. Nothing is corrupted — that is what the
/// transaction journal is for — but it strands a pending transaction that only
/// a later `lexe` run will unwind, and it does so on an accidental click, with
/// no warning, in the one window where the user has just been told the install
/// cannot be interrupted safely. Refuse the close and say why; the details
/// [Close] button is already insensitive for the same reason, and both come
/// back the moment the install finishes or fails.
gboolean on_window_delete(GtkWidget*, GdkEvent*, gpointer user_data) {
    AppState* st = static_cast<AppState*>(user_data);
    if (!st->installing) return FALSE; // not installing: close normally
    if (st->progress_note_label != nullptr) {
        const std::string text =
            "Closing now would stop the installation while files are being "
            "written, so it was ignored.\n" +
            lexe::gui::install_progress_note();
        gtk_label_set_text(GTK_LABEL(st->progress_note_label), text.c_str());
    }
    return TRUE; // TRUE == handled: do not destroy the window
}

// --------------------------------------------------------------- installing

/// Worker thread: runs the actual installation. NO GTK calls here — results
/// land in AppState and the main loop is notified via g_idle_add.
gboolean on_install_finished(gpointer user_data);
/// Defined with the details page; the failure path below re-arms Install
/// through it so a retry still respects the consent box.
void update_install_sensitivity(AppState* st);

gpointer install_worker(gpointer user_data) {
    AppState* st = static_cast<AppState*>(user_data);
    try {
        lexe::InstallOptions opts;
        opts.channel = st->selected_channel;
        // A separate, explicit act — never implied by pressing Install, exactly
        // as the CLI never implies it from --yes.
        opts.allow_permission_expansion = st->accept_permissions;
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

/// Poll the install's real progress. Runs on the main loop once a second while
/// an install is in flight; see the AppState progress fields and the lexe::gui
/// progress section for why the stage is read from disk rather than pushed.
gboolean on_progress_tick(gpointer user_data) {
    AppState* st = static_cast<AppState*>(user_data);
    if (!st->installing) return G_SOURCE_REMOVE;

    const gint64 elapsed_us = g_get_monotonic_time() - st->progress_started_us;
    const std::string elapsed =
        "Running for " + lexe::gui::format_elapsed(elapsed_us / G_USEC_PER_SEC);
    gtk_label_set_text(GTK_LABEL(st->progress_elapsed_label), elapsed.c_str());

    // Reading the journal is plain, bounded file I/O on a small JSON file the
    // installer writes atomically (temp + rename), so a poll never observes a
    // half-written phase. A failure to read it must not disturb the install:
    // the screen simply keeps the last stage it knew.
    try {
        const lexe::TransactionJournal journal =
            lexe::read_journal(st->paths, st->vm.app_id);
        if (!journal.started_at.empty() &&
            journal.started_at != st->pre_txn_started_at) {
            const int rank = lexe::gui::install_stage_rank(
                lexe::gui::install_stage_from_phase(journal.phase));
            if (rank > st->progress_stage_rank) st->progress_stage_rank = rank;
        }
    } catch (const std::exception&) {
    }
    const std::string stage = lexe::gui::install_stage_text(
        static_cast<lexe::gui::InstallStage>(st->progress_stage_rank));
    gtk_label_set_text(GTK_LABEL(st->progress_stage_label), stage.c_str());
    return G_SOURCE_CONTINUE;
}

void stop_progress_tracking(AppState* st) {
    st->installing = false;
    if (st->progress_timer != 0) {
        g_source_remove(st->progress_timer);
        st->progress_timer = 0;
    }
    gtk_spinner_stop(GTK_SPINNER(st->spinner));
}

/// Main-loop continuation of install_worker.
gboolean on_install_finished(gpointer user_data) {
    AppState* st = static_cast<AppState*>(user_data);
    stop_progress_tracking(st);
    if (!st->install_error.empty()) {
        // Back to the details screen with the failure in the banner; the
        // user may retry (verification state is unchanged).
        set_banner(st, "danger", "Installation failed: " + st->install_error);
        update_install_sensitivity(st);
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
    st->accept_permissions =
        st->accept_permissions_check != nullptr &&
        gtk_toggle_button_get_active(
            GTK_TOGGLE_BUTTON(st->accept_permissions_check));
    if (channel != nullptr) g_free(channel);

    gtk_widget_set_sensitive(st->install_button, FALSE);
    gtk_widget_set_sensitive(st->details_close_button, FALSE);

    // Note any journal that is ALREADY on disk before the worker starts, so a
    // leftover transaction from an earlier interrupted run (which install()
    // recovers before it begins its own) is not reported as this install's
    // progress. Anything install() writes from here on carries a new timestamp.
    st->pre_txn_started_at.clear();
    try {
        st->pre_txn_started_at =
            lexe::read_journal(st->paths, st->vm.app_id).started_at;
    } catch (const std::exception&) {
    }
    st->installing = true;
    st->progress_started_us = g_get_monotonic_time();
    st->progress_stage_rank =
        lexe::gui::install_stage_rank(lexe::gui::InstallStage::Verifying);
    gtk_label_set_text(
        GTK_LABEL(st->progress_stage_label),
        lexe::gui::install_stage_text(lexe::gui::InstallStage::Verifying).c_str());
    gtk_label_set_text(GTK_LABEL(st->progress_elapsed_label), "Running for 0:00");
    gtk_label_set_text(GTK_LABEL(st->progress_note_label),
                       lexe::gui::install_progress_note().c_str());
    gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "progress");
    gtk_spinner_start(GTK_SPINNER(st->spinner));
    st->progress_timer = g_timeout_add(1000, on_progress_tick, st);

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
    st->launching = false;
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
    st->launching = true;
    gtk_widget_set_sensitive(st->launch_button, FALSE);
    gtk_label_set_text(GTK_LABEL(st->launch_status_label), "Launching…");
    GThread* thread = g_thread_new("lexe-launch", launch_worker, st);
    g_thread_unref(thread);
}

// ------------------------------------------------------------------ screens

/// Install is allowed only when the package verifies, trust permits it, AND —
/// when this update asks for permissions the user has not approved before — the
/// consent box is ticked. Pressing Install must never itself be the act that
/// grants new authority (runtime-trust WS5), which is the same rule the CLI
/// applies by refusing to infer --accept-permissions from --yes.
void update_install_sensitivity(AppState* st) {
    if (st->install_button == nullptr) return;
    const bool consented =
        !st->vm.permission_expansion ||
        (st->accept_permissions_check != nullptr &&
         gtk_toggle_button_get_active(
             GTK_TOGGLE_BUTTON(st->accept_permissions_check)));
    gtk_widget_set_sensitive(st->install_button,
                             (st->vm.can_install && consented) ? TRUE : FALSE);
}

void on_accept_permissions_toggled(GtkToggleButton*, gpointer user_data) {
    update_install_sensitivity(static_cast<AppState*>(user_data));
}

/// The authenticity + local-trust banner (severity-coloured, never a plain
/// green "verified" for a first-seen key), and the place every install failure
/// is reported. Built separately from the details page so build_ui can pin it
/// ABOVE the scroller: a message the user has to go looking for is a message
/// they do not get.
GtkWidget* build_banner(AppState* st) {
    // A STRIP, not a bare label: the severity styling is a tinted background
    // plus a border plus a text colour, and a label alone gives the tint
    // nowhere to sit. set_banner() swaps the class on this wrapper.
    GtkWidget* strip = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    style::add_class(strip, "lexe-banner");
    st->banner_label = gtk_label_new(nullptr);
    gtk_label_set_xalign(GTK_LABEL(st->banner_label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(st->banner_label), TRUE);
    gtk_box_pack_start(GTK_BOX(strip), st->banner_label, FALSE, FALSE, 0);
    set_banner(st, st->vm.trust_severity, st->vm.status_text);
    return strip;
}

/// Primary screen — mirrors the SPEC "Opening a .lexe File" mock.
GtkWidget* build_details_page(AppState* st) {
    const lexe::gui::ViewModel& vm = st->vm;
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(box), 22);

    // The banner is NOT packed here — see build_banner(), which pins it above
    // the scroller. It used to be the first child of the scrolled content, so
    // an install failure wrote its message to the top of a page roughly two
    // viewports long while the user was at the bottom, next to the pinned
    // Install button they had just pressed. The window came back looking
    // completely unchanged, and pressing Install again failed again, silently.

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
    style::add_class(name_label, "lexe-title");
    gtk_box_pack_start(GTK_BOX(box), name_label, FALSE, FALSE, 0);

    // Publisher and version are supporting detail, not headline: muted, so the
    // eye lands on the application name and then on whatever is wrong.
    style::add_class(add_body_label(box, vm.publisher_line), "lexe-muted");
    style::add_class(add_body_label(box, vm.version_line), "lexe-muted");

    // The reason first, directly under the banner: when a package is refused
    // the user's only question is "why, and what do I do now".
    if (!vm.refusal_text.empty()) {
        add_section(box, "Why this package was refused:", vm.refusal_text);
    }
    if (!vm.replacement_text.empty()) {
        add_section(box, "Already installed:", vm.replacement_text);
    }

    // Authenticity & local trust: two dimensions, the fingerprint, and the
    // always-present "not real-world identity" caveat. Composed by the pure
    // layer (lexe::gui::trust_section_body) so the "never a heading over an
    // empty body" rule is covered by tests/test_gui.cpp rather than only by
    // looking at the window.
    add_section(box, "Authenticity & local trust:",
                lexe::gui::trust_section_body(vm));
    if (!vm.trust_remedy.empty()) {
        add_section(box, "What you can do:", vm.trust_remedy);
    }

    add_section(box, "Source:", vm.source_text);
    add_section(box, "Application Type:", vm.type_text);
    add_section(box, "Permissions:", vm.permissions_text);
    if (!vm.permission_delta_text.empty()) {
        add_section(box, "Permission changes:", vm.permission_delta_text);
    }

    add_section(box, "Installation:", vm.install_text);
    add_section(box, "Updates:", vm.updates_text);
    add_section(box, "Isolation on this platform:", vm.isolation_text);
    add_section(box, "After install:", vm.after_install_text);
    add_section(box, "Verify later:", vm.verify_later_text);

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
    // A package with no update source has no channel to choose. Offering a
    // working selector next to a screen that says "No automatic updates" asked
    // the user to make a decision that could not have an effect.
    if (!vm.has_update_source) {
        gtk_widget_set_sensitive(st->channel_combo, FALSE);
        gtk_widget_set_tooltip_text(
            st->channel_combo,
            "This package declares no update source, so there is no channel to "
            "choose.");
    }
    gtk_box_pack_start(GTK_BOX(channel_row), st->channel_combo, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(advanced), channel_row, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(expander), advanced);
    gtk_box_pack_start(GTK_BOX(box), expander, FALSE, FALSE, 0);

    return box;
}

/// The action bar: [Close] [Install]. Built SEPARATELY from the details page so
/// build_ui can pin it below the scroller. It used to be packed at the bottom
/// of the scrolled content, which meant that at the default window size the
/// primary action of an installer was below the fold — the window opened with
/// no visible way to install, and the user had to scroll a long page to find
/// it.
GtkWidget* build_action_bar(AppState* st) {
    GtkWidget* bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    style::add_class(bar, "lexe-actionbar");

    // The consent control lives HERE, beside the button it gates, not with the
    // permission list up in the scrolled details. Install is disabled until it
    // is ticked, and a disabled button whose reason has scrolled out of sight
    // is just a dead end with extra steps.
    if (st->vm.permission_expansion) {
        st->accept_permissions_check = gtk_check_button_new_with_label(
            "Grant the new permissions this update requests");
        gtk_widget_set_halign(st->accept_permissions_check, GTK_ALIGN_START);
        gtk_label_set_line_wrap(
            GTK_LABEL(gtk_bin_get_child(
                GTK_BIN(st->accept_permissions_check))),
            TRUE);
        g_signal_connect(st->accept_permissions_check, "toggled",
                         G_CALLBACK(on_accept_permissions_toggled), st);
        gtk_box_pack_start(GTK_BOX(bar), st->accept_permissions_check, TRUE,
                           TRUE, 0);
    }

    GtkWidget* buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(buttons, GTK_ALIGN_END);
    gtk_widget_set_valign(buttons, GTK_ALIGN_CENTER);
    gtk_box_pack_end(GTK_BOX(bar), buttons, FALSE, FALSE, 0);
    st->details_close_button = gtk_button_new_with_label("Close");
    g_signal_connect(st->details_close_button, "clicked",
                     G_CALLBACK(on_close_clicked), nullptr);
    st->install_button = gtk_button_new_with_label("Install");
    style::add_class(st->install_button, "lexe-primary");
    // sensitivity is set below, once the consent box (if any) exists
    g_signal_connect(st->install_button, "clicked",
                     G_CALLBACK(on_install_clicked), st);
    gtk_box_pack_start(GTK_BOX(buttons), st->details_close_button,
                       FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(buttons), st->install_button, FALSE, FALSE, 0);
    update_install_sensitivity(st);
    return bar;
}

/// The progress screen. A spinner with one fixed line ("Installing X…") was
/// indistinguishable from a hung process: it never changed, whether the install
/// was five seconds from done or wedged. It now carries the stage that is
/// actually running (polled off the installer's own transaction journal — see
/// on_progress_tick) and a ticking elapsed time, so the screen visibly moves
/// while real work happens.
///
/// There is deliberately NO [Cancel] button. Installer::install() is a single
/// blocking call with no cancellation point: the §6 verification, the payload
/// extraction and the staged re-hash all run to completion inside it, and
/// nothing short of killing the process can stop them from outside. That is
/// precisely the mid-flight abort HARDENING.md §A is built to SURVIVE, not to
/// invite — it strands a txn.json journal and a .txn-staging tree for the next
/// run's recovery to unwind, and leaves the app's desktop integration in
/// whatever state the kill caught it in. A button whose only implementation is
/// "kill the process and hope recovery runs later" is not a cancel, so the
/// screen explains the situation instead of offering one. Adding a real one
/// needs a cancellation token threaded through core/installer, which is not
/// this file's to change.
GtkWidget* build_progress_page(AppState* st) {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(box), 24);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);

    st->spinner = gtk_spinner_new();
    gtk_widget_set_size_request(st->spinner, 48, 48);
    gtk_widget_set_halign(st->spinner, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(box), st->spinner, FALSE, FALSE, 0);

    const std::string text = "Installing " + st->vm.app_name + "…";
    st->progress_label = gtk_label_new(nullptr);
    {
        gchar* escaped = g_markup_escape_text(text.c_str(), -1);
        gchar* markup = g_strdup_printf("<b>%s</b>", escaped);
        gtk_label_set_markup(GTK_LABEL(st->progress_label), markup);
        g_free(markup);
        g_free(escaped);
    }
    gtk_label_set_line_wrap(GTK_LABEL(st->progress_label), TRUE);
    gtk_label_set_justify(GTK_LABEL(st->progress_label), GTK_JUSTIFY_CENTER);
    gtk_widget_set_halign(st->progress_label, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(box), st->progress_label, FALSE, FALSE, 0);

    // The stage the installer is genuinely in. Its initial text is the first
    // stage rather than a placeholder, so the screen is never blank for the
    // second between showing it and the first tick.
    st->progress_stage_label = gtk_label_new(
        lexe::gui::install_stage_text(lexe::gui::InstallStage::Verifying).c_str());
    gtk_label_set_line_wrap(GTK_LABEL(st->progress_stage_label), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(st->progress_stage_label), 46);
    gtk_label_set_justify(GTK_LABEL(st->progress_stage_label),
                          GTK_JUSTIFY_CENTER);
    gtk_widget_set_halign(st->progress_stage_label, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(box), st->progress_stage_label, FALSE, FALSE, 0);

    st->progress_elapsed_label = gtk_label_new("Running for 0:00");
    gtk_widget_set_halign(st->progress_elapsed_label, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(box), st->progress_elapsed_label, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(box),
                       gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE,
                       FALSE, 8);

    st->progress_note_label =
        gtk_label_new(lexe::gui::install_progress_note().c_str());
    gtk_label_set_line_wrap(GTK_LABEL(st->progress_note_label), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(st->progress_note_label), 46);
    gtk_label_set_xalign(GTK_LABEL(st->progress_note_label), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), st->progress_note_label, FALSE, FALSE, 0);

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

// ------------------------------------------------- theme, drop zone, loading

/// Render `theme` on the LIVE window.
///
/// The System case needs the extra step above style::apply(). apply() writes
/// GTK's `gtk-application-prefer-dark-theme` so GTK's own widgetry (menus,
/// tooltips, the file chooser) follows our palette — and style::resolve_dark()
/// reads that same property back to decide what the desktop wants. Left alone
/// the two latch: choosing Dark sets the flag, and choosing "Follow system"
/// afterwards reads back the flag WE set, so the window stays dark forever on a
/// light desktop with no way out short of restarting. Restoring the value
/// sampled before the first apply() makes "Follow system" mean the desktop
/// again. (The other half of resolve_dark — the "-dark" theme NAME check — is
/// never written by apply(), so it stays honest on its own.)
void apply_theme(AppState* st, style::Theme theme) {
    st->theme = theme;
    if (theme == style::Theme::System) {
        if (GtkSettings* settings = gtk_settings_get_default()) {
            g_object_set(settings, "gtk-application-prefer-dark-theme",
                         st->desktop_prefer_dark, nullptr);
        }
    }
    style::apply(theme);
}

void on_theme_changed(GtkComboBox* combo, gpointer user_data) {
    AppState* st = static_cast<AppState*>(user_data);
    const std::string value =
        lexe::gui::theme_option_value(gtk_combo_box_get_active(combo));

    // Restyle FIRST. This is a cosmetic change the user just asked for; making
    // it wait on a disk write means a read-only or full home directory leaves
    // the window looking like the control does nothing.
    apply_theme(st, style::theme_from_string(value));

    // Then persist, into the same settings.json `lexe config set theme` writes.
    // Re-read it first: a `lexe config set developer_mode true` run in a
    // terminal while this window is open would otherwise be reverted by writing
    // back the copy loaded at startup.
    lexe::Settings settings = st->settings;
    try {
        settings = lexe::Settings::load(st->paths);
    } catch (const std::exception&) {
        // Unparseable on disk. Fall back to the in-memory copy — this write is
        // the user's chance to replace a corrupt file with a valid one.
    }
    try {
        settings.set("theme", value);
        settings.save(st->paths);
        st->settings = settings;
    } catch (const std::exception& e) {
        set_status_message(
            st, "caution",
            "This window is now using the \"" + value +
                "\" theme, but the preference could not be saved for next "
                "time: " +
                e.what());
    }
}

/// The persistent chrome strip: what this window is, and the theme control.
///
/// The control lives here rather than in the Advanced Options expander or the
/// details action bar because both of those exist only on the details screen.
/// Launched with no argument the window opens on the drop zone, where there is
/// no expander and no action bar at all — a preference you can only reach after
/// finding a package to install is not reachable at the moment you first see
/// the window. One control, in one place, present on every screen, so there is
/// no second copy to keep in step.
GtkWidget* build_header_bar(AppState* st) {
    GtkWidget* bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    style::add_class(bar, "lexe-actionbar");

    GtkWidget* product = gtk_label_new("Lexe Installer");
    style::add_class(product, "lexe-muted");
    gtk_widget_set_halign(product, GTK_ALIGN_START);
    gtk_widget_set_valign(product, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(bar), product, FALSE, FALSE, 0);

    GtkWidget* right = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(right, GTK_ALIGN_END);
    gtk_widget_set_valign(right, GTK_ALIGN_CENTER);
    // A mnemonic label rather than a bare one: it gives the combo a keyboard
    // route (Alt+T) and, because GTK derives the accessible name from the
    // mnemonic relation, a screen reader announces the list as "Theme" instead
    // of reading out only whichever option happens to be selected.
    GtkWidget* label = gtk_label_new_with_mnemonic("_Theme");
    style::add_class(label, "lexe-muted");
    gtk_box_pack_start(GTK_BOX(right), label, FALSE, FALSE, 0);

    st->theme_combo = gtk_combo_box_text_new();
    for (const std::string& option : lexe::gui::theme_option_labels()) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(st->theme_combo),
                                       option.c_str());
    }
    // Select BEFORE connecting: gtk_combo_box_set_active emits "changed", and a
    // handler running here would write the freshly loaded preference straight
    // back to disk on every startup — turning a read into a write, and turning
    // an unreadable settings.json into an overwritten one.
    gtk_combo_box_set_active(GTK_COMBO_BOX(st->theme_combo),
                             lexe::gui::theme_option_index(st->settings.theme));
    g_signal_connect(st->theme_combo, "changed", G_CALLBACK(on_theme_changed),
                     st);
    gtk_label_set_mnemonic_widget(GTK_LABEL(label), st->theme_combo);
    gtk_widget_set_tooltip_text(
        st->theme_combo,
        "Which palette this window renders in. Saved as the `theme` preference, "
        "the same one `lexe config set theme` writes.");
    gtk_box_pack_start(GTK_BOX(right), st->theme_combo, FALSE, FALSE, 0);

    gtk_box_pack_end(GTK_BOX(bar), right, FALSE, FALSE, 0);
    return bar;
}

/// The empty state: what the window shows when it has no package yet.
GtkWidget* build_drop_page(AppState* st) {
    const lexe::gui::DropZoneText text = lexe::gui::drop_zone_text();
    GtkWidget* page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    // A refused drop has to say so somewhere the user is already looking, and
    // this screen has no trust banner of its own. Same strip, same severity
    // classes, hidden until there is something to say — an empty tinted bar
    // above an empty window is a message the reader has to work out is not a
    // message.

    GtkWidget* body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_set_border_width(GTK_CONTAINER(body), 22);
    gtk_widget_set_valign(body, GTK_ALIGN_CENTER);

    GtkWidget* card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    style::add_class(card, "lexe-card");

    GtkWidget* title = gtk_label_new(text.title.c_str());
    style::add_class(title, "lexe-title");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(title), TRUE);
    gtk_box_pack_start(GTK_BOX(card), title, FALSE, FALSE, 0);

    GtkWidget* hint = gtk_label_new(text.hint.c_str());
    style::add_class(hint, "lexe-muted");
    gtk_label_set_xalign(GTK_LABEL(hint), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(hint), TRUE);
    gtk_box_pack_start(GTK_BOX(card), hint, FALSE, FALSE, 0);

    GtkWidget* command = gtk_label_new(text.command.c_str());
    style::add_class(command, "lexe-mono");
    gtk_label_set_xalign(GTK_LABEL(command), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(command), TRUE);
    gtk_box_pack_start(GTK_BOX(card), command, FALSE, FALSE, 0);

    GtkWidget* assurance = gtk_label_new(text.assurance.c_str());
    style::add_class(assurance, "lexe-muted");
    gtk_label_set_xalign(GTK_LABEL(assurance), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(assurance), TRUE);
    gtk_box_pack_start(GTK_BOX(card), assurance, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(body), card, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(page), body, TRUE, TRUE, 0);

    // The drop zone gets the same pinned action bar as the details screen, so
    // there is a keyboard-reachable way out of a window that otherwise responds
    // only to a mouse drag.
    GtkWidget* bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    style::add_class(bar, "lexe-actionbar");
    st->drop_close_button = gtk_button_new_with_label("Close");
    g_signal_connect(st->drop_close_button, "clicked",
                     G_CALLBACK(on_close_clicked), nullptr);
    gtk_box_pack_end(GTK_BOX(bar), st->drop_close_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(page), bar, FALSE, FALSE, 0);

    return page;
}

void update_window_title(AppState* st) {
    std::string title = "Lexe Installer " + lexe::version::runtime_string();
    title += st->has_package ? " \u2014 " + st->vm.app_name
                             : std::string(" \u2014 no package open");
    gtk_window_set_title(GTK_WINDOW(st->window), title.c_str());
}

/// Fill — or REFILL — the details screen from the current view model.
///
/// Opening a second package replaces the whole screen rather than parts of it.
/// The action bar's consent checkbox exists only for an update that expands
/// permissions, the channel combo is populated from this manifest, and the
/// banner's severity class belongs to this package's trust state. Patching
/// those in place would eventually leave one of them describing the PREVIOUS
/// package — most dangerously a ticked "grant the new permissions this update
/// requests" box surviving into a package the user has approved nothing for.
void rebuild_details_page(AppState* st) {
    GList* children =
        gtk_container_get_children(GTK_CONTAINER(st->details_page));
    for (GList* item = children; item != nullptr; item = item->next) {
        gtk_widget_destroy(GTK_WIDGET(item->data));
    }
    g_list_free(children);
    // Every pointer below referred to a widget that has just been destroyed.
    st->banner_label = nullptr;
    st->install_button = nullptr;
    st->details_close_button = nullptr;
    st->channel_combo = nullptr;
    st->accept_permissions_check = nullptr;
    st->accept_permissions = false;

    GtkWidget* scroller = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroller), build_details_page(st));

    // Banner pinned above, action bar pinned below, details scrolling between:
    // the state of the package and the button that acts on it are both always
    // on screen, whatever the scroll position.
    gtk_box_pack_start(GTK_BOX(st->details_page), build_banner(st), FALSE,
                       FALSE, 0);
    gtk_box_pack_start(GTK_BOX(st->details_page), scroller, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(st->details_page), build_action_bar(st), FALSE,
                       FALSE, 0);
    gtk_widget_show_all(st->details_page);
}

/// Open `package`: the FORMAT-0.1 section 6 verification pipeline, the local
/// trust evaluation, the isolation probe and the permission delta, then a
/// rebuilt primary screen.
///
/// This is the ONLY route a package takes into the window. The command-line
/// argument and a drag-and-drop both call it, so a dropped file cannot reach
/// the Install button by a shorter path than an argument does — there is no
/// shorter path to take. In particular vm.can_install is recomputed from this
/// package's own report, so Install is disabled again the moment a bad package
/// replaces a good one.
///
/// Verification runs on the UI thread, exactly as it did at startup before the
/// window existed. That is a deliberate carry-over rather than an oversight:
/// the pipeline hashes the payload once and the drag handler paints a
/// "Verifying ..." message before handing over, but a very large package will
/// visibly hold the window while it runs.
void load_package(AppState* st, const std::filesystem::path& package) {
    st->package_path = package;
    // A reload must not inherit the previous package's results. Every field
    // below is read on a later screen (the success message, the launcher's
    // target, the retry banner), and carrying one across would report the old
    // package's outcome for the new one.
    st->install_error.clear();
    st->installed_id.clear();
    st->installed_version.clear();
    st->launch_error.clear();
    st->launch_exit_code = 0;
    st->accept_permissions = false;

    // FORMAT-0.1 section 6 pipeline, with the section 6.7 architecture check —
    // this is an install flow. verify_package reports failures rather than
    // throwing; the catch below is defensive (e.g. an unreadable path).
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
    // still renders and the report banner explains what went wrong. The
    // uncompressed payload size is read alongside it so the "Installation:"
    // block can show a real figure when the manifest declares no estimate,
    // matching what `lexe info` reports for the same package.
    std::optional<lexe::Manifest> manifest;
    std::uint64_t payload_bytes = 0;
    try {
        lexe::PackageReader reader(st->package_path);
        manifest = lexe::Manifest::parse(reader.read_entry("lexe.json"));
        for (const lexe::PackageEntry& entry : reader.entries()) {
            if (entry.path.rfind("payload/", 0) == 0) {
                payload_bytes += entry.uncompressed_size;
            }
        }
    } catch (const std::exception&) {
        manifest.reset();
        payload_bytes = 0;
    }

    // Local trust evaluation + isolation capability + permission delta for the
    // truthful two-dimensional view (WS10). All effectful; the pure view-model
    // builder just formats them.
    std::optional<lexe::TrustEvaluation> eval;
    lexe::PermissionDelta delta;
    std::string installed_version; // "" when this is a fresh install
    if (manifest.has_value()) {
        try {
            const lexe::SignatureState sig =
                lexe::signature_state_from_report(report);
            const lexe::Registry registry(st->paths);
            std::optional<std::string> retained;
            const std::filesystem::path owner =
                registry.data_owner_marker(manifest->id);
            std::error_code ec;
            if (std::filesystem::is_regular_file(owner, ec)) {
                std::string prior = lexe::util::slurp_text(owner);
                while (!prior.empty() &&
                       (prior.back() == '\n' || prior.back() == '\r' ||
                        prior.back() == ' ')) {
                    prior.pop_back();
                }
                if (!prior.empty()) retained = prior;
            }
            eval = lexe::TrustStore(st->paths).evaluate(
                manifest->id, manifest->decoded_public_key(), sig, retained);
            if (registry.is_installed(manifest->id)) {
                const lexe::InstallationRecord rec =
                    registry.read_record(manifest->id);
                delta = lexe::permission_delta(
                    lexe::normalized_from_ids(rec.approved_permissions),
                    lexe::normalize_permissions(manifest->permissions));
                installed_version = registry.current_version(manifest->id);
            }
        } catch (const std::exception&) {
            // Leave eval empty (banner shows a danger "cannot establish
            // authenticity"); the isolation probe below still runs.
        }
    }
    lexe::IsolationCapabilities caps;
    try {
        caps = lexe::make_isolation_backend(st->paths)->capabilities();
    } catch (const std::exception&) {
    }

    st->vm = lexe::gui::build_view_model(manifest, report, st->package_path,
                                         st->paths, lexe::host_architecture(),
                                         eval, caps, delta, payload_bytes,
                                         installed_version);
    st->has_package = true;
    if (!st->vm.channels.empty()) {
        st->selected_channel =
            st->vm.channels[static_cast<std::size_t>(st->vm.active_channel)];
    }

    // The success screen belongs to the package that produced it. Reset it, or
    // a second package opened from the success screen would be installed under
    // a receipt still naming the first one.
    if (st->success_label != nullptr) {
        gtk_label_set_text(GTK_LABEL(st->success_label), "Installed.");
    }
    if (st->launch_status_label != nullptr) {
        gtk_label_set_text(GTK_LABEL(st->launch_status_label), "");
    }
    if (st->launch_button != nullptr) {
        gtk_widget_set_sensitive(st->launch_button, TRUE);
    }
    if (st->drop_banner_strip != nullptr) {
        gtk_widget_hide(st->drop_banner_strip);
    }

    update_window_title(st);
    rebuild_details_page(st);
    gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "details");
    // Focus the safe action, for the same reason main() does at startup: this
    // screen asks for consent, so Close is what should be armed.
    if (st->details_close_button != nullptr) {
        gtk_widget_grab_focus(st->details_close_button);
    }
}

/// Opens the file the drag handler accepted, one main-loop turn later.
gboolean on_dropped_package(gpointer user_data) {
    AppState* st = static_cast<AppState*>(user_data);
    const std::filesystem::path package = st->pending_drop;
    st->pending_drop.clear();
    if (!package.empty()) load_package(st, package);
    return G_SOURCE_REMOVE;
}

/// A `.lexe` dropped onto the window — the same thing as passing it on the
/// command line, and nothing more than that. This function decides only WHICH
/// file (if any) was dropped; load_package runs the identical verification
/// pipeline over it, and Install stays disabled unless that pipeline passes.
void on_drag_data_received(GtkWidget*, GdkDragContext*, gint, gint,
                           GtkSelectionData* data, guint, guint,
                           gpointer user_data) {
    AppState* st = static_cast<AppState*>(user_data);
    // No gtk_drag_finish() anywhere below: the drop site is registered with
    // GTK_DEST_DEFAULT_ALL, so GTK finishes the drag itself once this handler
    // returns, and finishing it twice is a protocol error. The drag is only
    // ever GDK_ACTION_COPY, so nothing is deleted at the source either way.

    // An install in flight owns package_path, the transaction journal and the
    // progress poller. Swapping the package under it would rename the screen
    // mid-install and poll a journal belonging to a different application — the
    // same reason the window manager's [X] is vetoed on that screen.
    if (st->installing) {
        set_status_message(st, "caution",
                           "An installation is running, so the dropped package "
                           "was not opened.\n" +
                               lexe::gui::install_progress_note());
        return;
    }
    // Same argument for a launch: launch_worker reads installed_id on another
    // thread, and opening a package rewrites it.
    if (st->launching) {
        set_status_message(st, "caution",
                           "The application launched from this window is still "
                           "running. Close it before opening another package.");
        return;
    }

    std::vector<std::string> local_paths;
    if (gtk_selection_data_get_length(data) > 0) {
        if (gchar** uris = gtk_selection_data_get_uris(data)) {
            for (gchar** uri = uris; *uri != nullptr; ++uri) {
                // g_filename_from_uri fails for anything that is not a local
                // file:// URI — an http:// download, a trash:// entry, an
                // unmounted GVfs share. Recording an EMPTY path rather than
                // skipping the entry keeps "one item, but not a local file"
                // distinguishable from "nothing was dropped", which are
                // different messages to the user.
                gchar* path = g_filename_from_uri(*uri, nullptr, nullptr);
                local_paths.emplace_back(path != nullptr ? path : "");
                if (path != nullptr) g_free(path);
            }
            g_strfreev(uris);
        }
    }

    const lexe::gui::DropCheck check =
        lexe::gui::check_dropped_package(local_paths);
    if (!check.accept) {
        set_status_message(st, "danger", check.message);
        return;
    }

    // Say what is happening BEFORE the pipeline runs: verification hashes the
    // whole payload on this thread, and a window that freezes with no
    // explanation reads as a crash. The open is queued with g_idle_add, whose
    // default priority sits BELOW GDK's redraw priority, so this message is
    // painted before the hashing starts — and the drag protocol completes when
    // this handler returns instead of blocking the source application.
    set_status_message(st, "caution",
                       "Verifying " + check.path.filename().string() +
                           "\u2026");
    st->pending_drop = check.path;
    g_idle_add(on_dropped_package, st);
}

void build_ui(AppState* st) {
    st->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(st->window), 580, 760);
    g_signal_connect(st->window, "destroy", G_CALLBACK(on_window_destroy),
                     nullptr);
    // Vetoes the [X] while an install is running — see on_window_delete.
    g_signal_connect(st->window, "delete-event", G_CALLBACK(on_window_delete),
                     st);

    // The WHOLE window is the drop target. A small labelled rectangle would be
    // something the user has to aim at, and on the details screen — which is a
    // full page of package facts — there is no spare rectangle to give up.
    // GTK_DEST_DEFAULT_ALL has GTK negotiate the drag and call gtk_drag_finish()
    // itself once the handler returns; GDK_ACTION_COPY alone means the source
    // is never asked to delete anything.
    static GtkTargetEntry uri_targets[] = {
        {const_cast<gchar*>("text/uri-list"), 0, 0},
    };
    gtk_drag_dest_set(st->window, GTK_DEST_DEFAULT_ALL, uri_targets,
                      G_N_ELEMENTS(uri_targets), GDK_ACTION_COPY);
    g_signal_connect(st->window, "drag-data-received",
                     G_CALLBACK(on_drag_data_received), st);

    // The theme control sits OUTSIDE the stack so it is on every screen; see
    // build_header_bar.
    GtkWidget* root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_pack_start(GTK_BOX(root), build_header_bar(st), FALSE, FALSE, 0);

    st->stack = gtk_stack_new();
    // The details screen is an EMPTY container here; rebuild_details_page fills
    // it from a view model, once per package opened.
    st->details_page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_stack_add_named(GTK_STACK(st->stack), build_drop_page(st), "drop");
    gtk_stack_add_named(GTK_STACK(st->stack), st->details_page, "details");
    gtk_stack_add_named(GTK_STACK(st->stack), build_progress_page(st),
                        "progress");
    gtk_stack_add_named(GTK_STACK(st->stack), build_done_page(st), "done");
    // Start on the drop zone. main() switches to the details screen only if it
    // was given a package to open.
    gtk_stack_set_visible_child_name(GTK_STACK(st->stack), "drop");
    // Drop feedback gets its OWN strip, in the shell above the stack, so it is
    // present on every page. It used to be written into whatever label the
    // visible page happened to own — which on the details screen is the
    // AUTHENTICITY banner: refusing a dropped folder replaced "Signed —
    // publisher not verified" with a red refusal and never put it back, so the
    // window then misreported the trust state of the package still loaded in
    // it, with Install still armed. A transient message must never overwrite a
    // standing one about something else.
    st->drop_banner_strip = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    style::add_class(st->drop_banner_strip, "lexe-banner");
    st->drop_banner_label = gtk_label_new(nullptr);
    gtk_label_set_xalign(GTK_LABEL(st->drop_banner_label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(st->drop_banner_label), TRUE);
    gtk_box_pack_start(GTK_BOX(st->drop_banner_strip), st->drop_banner_label,
                       FALSE, FALSE, 0);
    gtk_widget_set_no_show_all(st->drop_banner_strip, TRUE);
    gtk_box_pack_start(GTK_BOX(root), st->drop_banner_strip, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(root), st->stack, TRUE, TRUE, 0);

    gtk_container_add(GTK_CONTAINER(st->window), root);
    update_window_title(st);
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

    // Deliberately not freed: worker threads may still reference the state
    // when the main loop quits, and the process is exiting anyway.
    AppState* st = new AppState();

    // Sample the desktop's own dark preference BEFORE the first style::apply(),
    // which overwrites that property. apply_theme() explains what depends on it.
    if (GtkSettings* settings = gtk_settings_get_default()) {
        g_object_get(settings, "gtk-application-prefer-dark-theme",
                     &st->desktop_prefer_dark, nullptr);
    }
    // Style anything shown before the preference is known — including the
    // startup error dialogs below, which can be the only window this process
    // ever puts on screen.
    style::apply();

    // Body text is selectable so a user can copy a fingerprint or an ID. GTK
    // pairs that with gtk-label-select-on-focus, which makes the first
    // focusable label select ALL of its text the moment the window opens — one
    // line comes up highlighted as if the user had dragged over it. Turn the
    // behaviour off; the labels stay selectable by hand.
    if (GtkSettings* settings = gtk_settings_get_default()) {
        g_object_set(settings, "gtk-label-select-on-focus", FALSE, nullptr);
    }

    // NO argument now opens the drop zone rather than exiting: this window is a
    // drop target, and someone who launched it from a desktop menu has no
    // command line to add an argument to. An argument that is PRESENT but empty
    // is still a usage error — it is a path nothing can open, and quietly
    // showing the drop zone instead would hide a broken caller (a .desktop Exec
    // line, a file-manager association passing an empty field) behind a screen
    // that looks like an ordinary empty launch.
    const bool has_argument =
        argc >= 2 && argv[1] != nullptr && *argv[1] != '\0';
    if (argc >= 2 && !has_argument) {
        return show_startup_error(
            "Usage: lexe-installer [application.lexe]\n\n"
            "Open a .lexe package to review and install it, or start with no "
            "argument and drop one onto the window.",
            2);
    }

    try {
        st->paths = lexe::Paths::detect();
    } catch (const std::exception& e) {
        return show_startup_error(
            std::string("Cannot resolve the Lexe directories: ") + e.what(), 1);
    }

    // The persisted theme, read from the settings.json `lexe config set theme`
    // writes — one preference, not two. A corrupt file is not fatal for a
    // cosmetic setting: fall back to the defaults and say so once there is a
    // window to say it in.
    std::string settings_error;
    try {
        st->settings = lexe::Settings::load(st->paths);
    } catch (const std::exception& e) {
        st->settings = lexe::Settings();
        settings_error = e.what();
    }
    apply_theme(st, style::theme_from_string(st->settings.theme));

    build_ui(st);
    if (has_argument) {
        // Identical to what a drop does — one pipeline, one entry point.
        load_package(st, std::filesystem::path(argv[1]));
    }
    gtk_widget_show_all(st->window);
    if (!settings_error.empty()) {
        set_status_message(st, "caution",
                           "Your settings file could not be read, so the "
                           "defaults are in use: " +
                               settings_error);
    }
    // Start focus on Close, not on a body label. Two reasons: a selectable
    // label that holds focus draws a blinking text caret, so the window opened
    // with a cursor sitting in read-only prose; and this dialog asks for
    // consent, so the safe action is the one that should be armed — matching
    // `lexe install`, whose prompt defaults to No ("[y/N]"). Install stays one
    // click or one Tab away.
    GtkWidget* initial_focus =
        st->has_package ? st->details_close_button : st->drop_close_button;
    if (initial_focus != nullptr) {
        gtk_widget_grab_focus(initial_focus);
    }
    gtk_main();
    return 0;
}

#endif // !LEXE_GUI_VIEWMODEL_ONLY

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
#include "core/trust.hpp"
#include "core/util.hpp"
#include "core/version.hpp"

#include <gtk/gtk.h>

#include <exception>
#include <system_error>

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
};

/// Set the authenticity/trust banner. The colour reflects the trust SEVERITY,
/// never a plain "verified": green only for a known/trusted key ("ok"), amber
/// for a valid-but-first-seen key ("caution" — NOT styled as verified), red for
/// a refusal ("danger"). Any other value is treated as danger.
void set_banner(AppState* st, const std::string& severity,
                const std::string& text) {
    const char* colour = severity == "ok"        ? "#1a7f37"   // green
                         : severity == "caution" ? "#9a6700"   // amber
                                                 : "#b00020";  // red
    gchar* escaped = g_markup_escape_text(text.c_str(), -1);
    gchar* markup = g_strdup_printf(
        "<span weight=\"bold\" foreground=\"%s\">%s</span>", colour, escaped);
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
    GtkWidget* head = gtk_label_new(nullptr);
    gchar* escaped = g_markup_escape_text(heading, -1);
    gchar* markup = g_strdup_printf("<b>%s</b>", escaped);
    gtk_label_set_markup(GTK_LABEL(head), markup);
    g_free(markup);
    g_free(escaped);
    gtk_label_set_xalign(GTK_LABEL(head), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), head, FALSE, FALSE, 0);
    add_body_label(box, body);
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
    st->banner_label = gtk_label_new(nullptr);
    gtk_label_set_xalign(GTK_LABEL(st->banner_label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(st->banner_label), TRUE);
    gtk_widget_set_margin_start(st->banner_label, 16);
    gtk_widget_set_margin_end(st->banner_label, 16);
    gtk_widget_set_margin_top(st->banner_label, 12);
    gtk_widget_set_margin_bottom(st->banner_label, 8);
    set_banner(st, st->vm.trust_severity, st->vm.status_text);
    return st->banner_label;
}

/// Primary screen — mirrors the SPEC "Opening a .lexe File" mock.
GtkWidget* build_details_page(AppState* st) {
    const lexe::gui::ViewModel& vm = st->vm;
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 16);

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
    gtk_box_pack_start(GTK_BOX(box), name_label, FALSE, FALSE, 0);

    add_body_label(box, vm.publisher_line);
    add_body_label(box, vm.version_line);

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
    gtk_container_set_border_width(GTK_CONTAINER(bar), 12);

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

void build_ui(AppState* st) {
    st->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    const std::string title = "Lexe Installer " +
                              lexe::version::runtime_string() + " — " +
                              st->vm.app_name;
    gtk_window_set_title(GTK_WINDOW(st->window), title.c_str());
    gtk_window_set_default_size(GTK_WINDOW(st->window), 520, 640);
    g_signal_connect(st->window, "destroy", G_CALLBACK(on_window_destroy),
                     nullptr);
    // Vetoes the [X] while an install is running — see on_window_delete.
    g_signal_connect(st->window, "delete-event", G_CALLBACK(on_window_delete),
                     st);

    st->stack = gtk_stack_new();

    GtkWidget* scroller = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroller), build_details_page(st));

    // The details scroll; the action bar stays pinned to the bottom, so
    // [Install] is visible the moment the window opens however long the
    // package's details run.
    GtkWidget* details = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    // Banner pinned above, action bar pinned below, details scrolling between:
    // the state of the package and the button that acts on it are both always
    // on screen, whatever the scroll position.
    gtk_box_pack_start(GTK_BOX(details), build_banner(st), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(details), gtk_separator_new(
                                             GTK_ORIENTATION_HORIZONTAL),
                       FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(details), scroller, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(details), gtk_separator_new(
                                             GTK_ORIENTATION_HORIZONTAL),
                       FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(details), build_action_bar(st), FALSE, FALSE, 0);

    gtk_stack_add_named(GTK_STACK(st->stack), details, "details");
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

    // Body text is selectable so a user can copy a fingerprint or an ID. GTK
    // pairs that with gtk-label-select-on-focus, which makes the first
    // focusable label select ALL of its text the moment the window opens — one
    // line comes up highlighted as if the user had dragged over it. Turn the
    // behaviour off; the labels stay selectable by hand.
    if (GtkSettings* settings = gtk_settings_get_default()) {
        g_object_set(settings, "gtk-label-select-on-focus", FALSE, nullptr);
    }

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
    if (!st->vm.channels.empty()) {
        st->selected_channel =
            st->vm.channels[static_cast<std::size_t>(st->vm.active_channel)];
    }

    build_ui(st);
    gtk_widget_show_all(st->window);
    // Start focus on Close, not on a body label. Two reasons: a selectable
    // label that holds focus draws a blinking text caret, so the window opened
    // with a cursor sitting in read-only prose; and this dialog asks for
    // consent, so the safe action is the one that should be armed — matching
    // `lexe install`, whose prompt defaults to No ("[y/N]"). Install stays one
    // click or one Tab away.
    if (st->details_close_button != nullptr) {
        gtk_widget_grab_focus(st->details_close_button);
    }
    gtk_main();
    return 0;
}

#endif // !LEXE_GUI_VIEWMODEL_ONLY

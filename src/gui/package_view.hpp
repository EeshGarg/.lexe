#pragma once
// gui/package_view.hpp — the install/consent view model, shared by the .LEXE
// graphical frontends.
//
// This is the presentation half of opening a package: the FORMAT-0.1 §6
// verification pipeline's result turned into the strings a human reads — what
// the application is, who signed it and what that does and does not prove,
// which permissions are being asked for and which are new, how it will be
// executed, where it will land, and why Install is or is not available.
//
// It lives in a header, on purpose. It began inside the alpha's separate
// `lexe-installer` program, and `lexe-ui` reused it by `#include`-ing that
// program's translation unit and defining a macro to suppress its `main()`.
// That worked, and it was a lie about the structure: it made a frontend depend
// on a sibling frontend's program. The window that owned this logic is gone;
// the logic is here, where both frontends can include it as a header and
// neither owns it.
//
// Everything here is PURE and GTK-free: no toolkit type appears, no file is
// written, and nothing is probed. Callers gather the host facts (verification
// report, manifest, trust evaluation, permission delta, isolation
// capabilities, toolchain probe) and pass them in; these functions only format
// them. That is what lets tests/test_package_view.cpp exercise the strings on
// every platform, including the ones that cannot build a GUI at all.
//
// Trust language is load-bearing and deliberately narrow. A valid signature
// proves the package is intact and that whoever produced it held the matching
// private key. It does not prove who they are. No string below says
// "verified", "trusted" or "safe" about a publisher, and
// lexe::present_authenticity() in the engine is the single source of that
// wording — see docs/TRUST-MODEL.md.


#include "lexe/runtime/hostbuild.hpp"
#include "lexe/sandbox/isolation.hpp"
#include "lexe/package/manifest.hpp"
#include "lexe/base/paths.hpp"
#include "lexe/diagnostics/presentation.hpp"
#include "lexe/install/transaction.hpp"
#include "lexe/verify/trust.hpp"
#include "lexe/verify/verify.hpp"
#include "lexe/base/versioncmp.hpp"

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
    // The binary the user can actually run. This named the alpha's
    // `lexe-installer` until that frontend was retired, which left the
    // window telling people to type a command that did not exist.
    text.command = "lexe-ui --open <application.lexe>";
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
    // ------------------------------------------------ host-ISA compilation
    // Installing an `applicationType: "portable"` package COMPILES its source
    // on this machine, which the owner of the installation authorizes
    // explicitly (Definitive Architecture §5A). A frontend that cannot express
    // that consent cannot install such a package at all, so these three carry
    // it: what the install would do, whether this host can do it, and whether
    // the user has said yes.
    bool requires_compile_approval = false; // the package is portable
    bool compile_possible = false;          // the declared toolchain is here
    std::string compile_text;               // the "Compiles on this machine" block
    /// The one-line label beside the consent control. Deliberately says what
    /// approval does NOT grant, because that is the part a cautious user has
    /// every reason to ask about.
    std::string compile_consent_label;
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
                                  const std::string& installed_version = "",
                                  const ToolchainReport& toolchain = {}) {
    ViewModel vm;
    const std::string filename = package_path.filename().string();
    vm.verified = report.ok();
    if (!report.ok()) {
        std::string remedy;
        if (const VerificationStage* f = report.first_failure(); f != nullptr) {
            vm.refusal_text = "Verification failed at the \"" + f->name +
                              "\" stage.";
            if (!f->detail.empty()) vm.refusal_text += "\n" + f->detail;
            remedy = f->hint;
        } else {
            vm.refusal_text = "This package did not pass verification.";
        }
        // Only fall back to "re-download" when the stage had nothing specific
        // to say. A dropped folder or a path that names no package is not a
        // damaged download, and telling someone to fetch it again sends them
        // to do the one thing that cannot help.
        vm.refusal_text +=
            "\n" + (remedy.empty()
                        ? std::string("Re-download it from the original source, "
                                      "or inspect it with `lexe verify`.")
                        : remedy);
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

    // Host-ISA compilation (§5A). This is the one install that runs a build on
    // the user's machine, so the window has to say so BEFORE the button is
    // pressed, name what it will run, and get an answer — the CLI's
    // `--approve-compile` with a face on it.
    if (manifest.has_value() &&
        manifest->application_kind == ApplicationType::Portable) {
        vm.requires_compile_approval = true;
        vm.compile_possible = toolchain.complete;
        vm.compile_text =
            "This package carries SOURCE, not a program. Installing it "
            "compiles \"" + manifest->build.source_dir + "\" for " + host_arch +
            " with `" + to_string(manifest->build.system) +
            "` on this machine.\nThe build runs unprivileged, in the same "
            "sandbox applications run in, with the network denied. Its result "
            "is checked to be a native executable for this machine before "
            "anything is installed.\n" + toolchain.summary;
        vm.compile_consent_label =
            "Compile this application's source on this machine";
        if (!toolchain.complete) {
            // Not a verification failure: the package is fine, this host
            // cannot build it. Say which, and do not offer a button that
            // could only fail.
            vm.can_install = false;
            vm.refusal_text = toolchain.summary;
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

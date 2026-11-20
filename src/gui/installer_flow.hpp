#pragma once
// The double-click experience, as a pure decision layer.
//
// Opening a `.lexe` used to land in the full management console: a navigation
// pane, a dozen text cards, an Install button below the fold, and a status line
// that read "The signed manifest declares role \"application\"". It also never
// told the review screen that the application was ALREADY installed, so opening
// the same package twice offered "Install" again, and an update that asked for
// a new permission or moved to an older version failed at the end with an error
// the user had never been asked about.
//
// This header decides, from the facts lexe_engine already produced, what the
// installer window should say and offer:
//
//   * the INTENT — install, update, reinstall, downgrade, or refuse — because
//     executing and installing are different acts and the window must never
//     blur them: an installed app's primary action is Open, not Install;
//   * the explicit CONSENTS an install needs (a downgrade, new permissions,
//     compiling source), each its own control, never folded into one button;
//   * a short, plain-language list of what the application can and cannot do
//     on this machine, derived from the permissions and the probed sandbox —
//     never a claim the runtime does not enforce.
//
// GTK-free and side-effect free, so it is unit-tested on every platform
// (tests/test_installer_flow.cpp). The window in lexe-ui only renders it.

#include "gui/package_view.hpp"

#include "lexe/diagnostics/presentation.hpp"
#include "lexe/package/manifest.hpp"
#include "lexe/sandbox/isolation.hpp"
#include "lexe/sandbox/permissions.hpp"

#include <optional>
#include <string>
#include <vector>

namespace lexe::gui {

enum class InstallIntent {
    Install,   // not installed here
    Update,    // an older version is installed
    Reinstall, // this exact version is installed — the primary action is OPEN
    Downgrade, // a NEWER version is installed
    Refused,   // verification or local trust says no
};

/// One line of "what this app can do here". `tone` drives the glyph colour:
/// "ok" (a protection), "caution" (an ability worth knowing about),
/// "danger" (a protection this machine cannot provide), "neutral".
struct CapabilityLine {
    std::string tone;
    std::string text;
};

struct InstallerPlan {
    InstallIntent intent = InstallIntent::Refused;
    std::string window_title;  // "Install Lexe GUI Hello"
    std::string headline;      // "Install Lexe GUI Hello?"
    std::string subline;       // "Usha · Version 1.0.0"
    std::string context_line;  // what this does to an existing install ("" when fresh)
    /// The trust headline in a few words, and one sentence saying what it means.
    std::string trust_badge;
    std::string trust_severity; // ok | caution | danger
    std::string trust_explainer;
    std::vector<CapabilityLine> capabilities;

    std::string primary_label;   // Install | Update | Open | Downgrade | ""
    bool primary_is_open = false; // the primary action LAUNCHES, it does not install
    bool primary_destructive = false;
    std::string secondary_label; // "Reinstall" for an installed version, else ""
    /// Why nothing can be installed, in user terms. Empty when allowed.
    std::string blocked_reason;

    /// Each consent is a separate checkbox the primary action waits on.
    bool needs_downgrade_consent = false;
    std::string downgrade_consent_label;
    bool needs_permission_consent = false;
    std::string permission_consent_label;
    bool needs_compile_consent = false;
    bool compile_possible = false;
    std::string compile_consent_label;

    std::string progress_label;  // "Installing Lexe GUI Hello…"
    std::string done_headline;   // "Lexe GUI Hello is installed"
    std::string done_detail;
};

namespace detail {

inline std::string host_of(const std::string& url) {
    const std::size_t scheme = url.find("://");
    if (scheme == std::string::npos) return {};
    const std::size_t start = scheme + 3;
    const std::size_t end = url.find_first_of("/:?#", start);
    return url.substr(start, end == std::string::npos ? std::string::npos
                                                      : end - start);
}

inline bool sandbox_available(const IsolationCapabilities& caps) {
    return caps.status == CapabilityStatus::Available;
}

} // namespace detail

/// What the application can and cannot do on THIS machine, in plain words.
///
/// Every line is a statement the runtime backs: the sandbox lines come from
/// the probe, not from the manifest's hopes, and an advisory permission says it
/// is advisory. Order: the sandbox first (the thing that protects you), then
/// abilities, then how it runs.
inline std::vector<CapabilityLine>
capability_lines(const Manifest& m, const IsolationCapabilities& caps,
                 const std::vector<std::string>& newly_added = {}) {
    const auto is_new = [&](const std::string& id) {
        for (const std::string& a : newly_added) {
            if (a == id) return true;
        }
        return false;
    };
    const std::string kNew = "  — new in this version";
    std::vector<CapabilityLine> out;
    const bool sandbox = detail::sandbox_available(caps);
    if (sandbox) {
        out.push_back({"ok", "Runs in a sandbox: it cannot see your personal "
                             "files or other applications"});
    } else {
        out.push_back({"danger",
                       "This machine cannot sandbox applications right now, "
                       "so Lexe will refuse to start it until it can"});
    }

    bool network = false;
    for (const std::string& id : m.permissions) {
        if (id == "network") {
            network = true;
            continue;
        }
        const PermissionSpec* spec = find_permission(id);
        const std::string title = spec != nullptr ? spec->title : id;
        std::string text = title;
        if (spec != nullptr && spec->baseline == PermissionBaseline::Advisory) {
            text += " (requested; not enforced by this version of Lexe)";
        }
        if (is_new(id)) text += kNew;
        out.push_back({"caution", text});
    }
    if (network) {
        out.push_back({"caution", std::string("Can connect to the internet") +
                                      (is_new("network") ? kNew : "")});
    } else if (sandbox && caps.network_namespaces) {
        out.push_back({"ok", "Cannot connect to the internet"});
    } else {
        out.push_back({"neutral", "Asks for no internet access"});
    }

    switch (m.application_kind) {
    case ApplicationType::Portable:
        out.push_back({"caution", "Ships as source code: this machine compiles "
                                  "it once, offline and sandboxed, before first "
                                  "use"});
        break;
    case ApplicationType::Windows:
        out.push_back({"neutral", "A Windows program, run through Wine or "
                                  "Proton"});
        break;
    case ApplicationType::Native:
        break;
    }
    switch (m.launch_mode) {
    case LaunchMode::Gui:
        out.push_back({"neutral", "Opens windows on your desktop"});
        break;
    case LaunchMode::Console:
        out.push_back({"neutral", "Runs in a terminal window"});
        break;
    case LaunchMode::Service:
        out.push_back({"caution", "Runs in the background after you start it"});
        break;
    }
    if (m.updates_enabled && !m.updates_manifest_url.empty()) {
        const std::string host = detail::host_of(m.updates_manifest_url);
        out.push_back({"neutral",
                       host.empty() ? std::string("Can check for updates")
                                    : "Checks " + host + " for updates"});
    }
    return out;
}

/// One-sentence meaning of the trust headline. The full lines (fingerprint,
/// key state, caveat) stay in the Details section.
inline std::string trust_explainer(const ViewModel& vm) {
    if (!vm.verified) {
        return "This file failed verification, so nothing in it can be "
               "trusted.";
    }
    if (vm.trust_severity == "danger") {
        return vm.trust_remedy.empty()
                   ? std::string("Your local trust settings do not allow this "
                                 "package.")
                   : vm.trust_remedy;
    }
    if (vm.trust_severity == "ok") {
        return "Signed by the same key you trusted before.";
    }
    return "The signature is valid. This is the first time this publisher's "
           "key has been seen here — Lexe will remember it and warn you if it "
           "ever changes.";
}

/// The verification failure in user terms. The stage name and the reader's
/// exact message stay in Details; this is the sentence a person acts on.
inline std::string refusal_summary(const VerificationReport& report) {
    const VerificationStage* f = report.first_failure();
    const std::string stage = f != nullptr ? f->name : std::string();
    if (stage == "structure") {
        return "This is not a valid .lexe file, or it is damaged. If you "
               "downloaded it, download it again.";
    }
    if (stage == "hashes") {
        return "Its contents do not match what the publisher signed: the file "
               "is damaged or was changed after it was signed. Download it "
               "again from where you got it.";
    }
    if (stage == "manifest-signature" || stage == "payload-signature" ||
        stage == "key") {
        return "Its signature does not check out, so there is no way to know "
               "who made it or whether it was altered.";
    }
    if (stage == "manifest") {
        return "Its description breaks the .lexe rules, so Lexe cannot safely "
               "say what it is or what it would do.";
    }
    if (stage == "compatibility") {
        return "It was not built for this computer.";
    }
    if (stage == "payload-role") {
        return "The program inside does not match what the package says it "
               "is.";
    }
    return "It did not pass verification.";
}

/// Decide what the installer window shows. `installed_version` is "" when the
/// application is not installed.
inline InstallerPlan plan_installer(const ViewModel& vm,
                                    const VerificationReport& report,
                                    const std::optional<Manifest>& manifest,
                                    const std::string& installed_version,
                                    const IsolationCapabilities& caps,
                                    const PermissionDelta& delta = {}) {
    InstallerPlan plan;
    const std::string& name = vm.app_name;
    plan.trust_badge = vm.verified ? vm.status_text
                                   : std::string("Failed verification");
    plan.trust_severity = vm.verified ? vm.trust_severity : std::string("danger");
    plan.trust_explainer = trust_explainer(vm);

    // Nothing from a manifest that failed verification is shown as fact: not
    // its name as a heading, not what it "can do". A forged package would
    // otherwise get to describe itself in the window's own voice.
    if (!vm.verified) {
        plan.intent = InstallIntent::Refused;
        plan.window_title = "Cannot open this file";
        plan.headline = "This file can't be trusted";
        plan.subline = manifest.has_value()
                           ? "It claims to be \"" + manifest->name + "\" from " +
                                 manifest->publisher_name + " — unverified"
                           : std::string();
        plan.blocked_reason = refusal_summary(report);
        return plan;
    }
    if (manifest.has_value()) {
        plan.subline = manifest->publisher_name + "  ·  Version " +
                       manifest->version;
        plan.capabilities = capability_lines(*manifest, caps, delta.added);
    } else {
        plan.subline = "Publisher unknown";
    }

    if (!vm.can_install || !manifest.has_value()) {
        // Verified, but local trust says no (a changed or blocked key) or the
        // manifest could not be read. The trust remedy is already user-facing.
        plan.intent = InstallIntent::Refused;
        plan.window_title = "Cannot install " + name;
        plan.headline = name + " cannot be installed";
        plan.capabilities.clear();
        plan.blocked_reason =
            !vm.trust_remedy.empty()
                ? vm.trust_remedy
                : std::string("Your local trust settings do not allow this "
                              "package.");
        return plan;
    }

    const Manifest& m = *manifest;
    if (installed_version.empty()) {
        plan.intent = InstallIntent::Install;
        plan.window_title = "Install " + name;
        plan.headline = "Install " + name + "?";
        plan.primary_label = "Install";
        plan.progress_label = "Installing " + name + "…";
        plan.done_headline = name + " is installed";
        plan.done_detail = "It is in your applications menu. You can open it "
                           "now, or later from there or from Lexe.";
    } else if (installed_version == m.version) {
        plan.intent = InstallIntent::Reinstall;
        plan.window_title = name;
        plan.headline = name + " is already installed";
        plan.context_line = "Version " + m.version +
                            " is installed and this file is the same version.";
        plan.primary_label = "Open";
        plan.primary_is_open = true;
        plan.secondary_label = "Reinstall";
        plan.progress_label = "Reinstalling " + name + "…";
        plan.done_headline = name + " was reinstalled";
        plan.done_detail = "Its files were replaced with this copy. Your data "
                           "and settings were kept.";
    } else if (version_less(m.version, installed_version)) {
        plan.intent = InstallIntent::Downgrade;
        plan.window_title = "Downgrade " + name;
        plan.headline = "Go back to an older " + name + "?";
        plan.context_line = "Version " + installed_version +
                            " is installed. This file is the older " +
                            m.version + ".";
        plan.primary_label = "Downgrade";
        plan.primary_destructive = true;
        plan.needs_downgrade_consent = true;
        plan.downgrade_consent_label =
            "Replace " + installed_version + " with the older " + m.version +
            ". Returning to " + installed_version +
            " later means installing that file again.";
        plan.progress_label = "Installing " + name + " " + m.version + "…";
        plan.done_headline = name + " is now version " + m.version;
        plan.done_detail = "Your data and settings were kept.";
    } else {
        plan.intent = InstallIntent::Update;
        plan.window_title = "Update " + name;
        plan.headline = "Update " + name + "?";
        plan.context_line = "From version " + installed_version + " to " +
                            m.version + ". Your data and settings are kept.";
        plan.primary_label = "Update";
        plan.progress_label = "Updating " + name + "…";
        plan.done_headline = name + " is updated to " + m.version;
        plan.done_detail = "Your data and settings were kept.";
    }

    // An update that asks for MORE than was approved is a fresh decision, and
    // it is made here, by name, not discovered as an install failure.
    if (plan.intent != InstallIntent::Install && vm.permission_expansion) {
        plan.needs_permission_consent = true;
        const presentation::PermissionDeltaView view =
            presentation::present_permission_delta(delta);
        std::string names;
        for (const std::string& title : view.added) {
            if (!names.empty()) names += ", ";
            names += title;
        }
        plan.permission_consent_label =
            (view.added.size() == 1 ? "Allow the new permission this version "
                                      "asks for: "
                                    : "Allow the new permissions this version "
                                      "asks for: ") +
            (names.empty() ? std::string("see Details") : names);
    }
    if (vm.requires_compile_approval) {
        plan.needs_compile_consent = true;
        plan.compile_possible = vm.compile_possible;
        plan.compile_consent_label = vm.compile_consent_label;
        if (!vm.compile_possible) {
            plan.blocked_reason =
                "This application ships as source code, and this machine is "
                "missing the tools it needs to build it.\n" + vm.compile_text;
        }
    }
    return plan;
}

/// Whether the primary action may be pressed, given the consents ticked.
/// Open (an installed version) needs none of the install consents.
inline bool primary_enabled(const InstallerPlan& plan, bool downgrade_ok,
                            bool permissions_ok, bool compile_ok) {
    if (plan.intent == InstallIntent::Refused || plan.primary_label.empty()) {
        return false;
    }
    if (plan.primary_is_open) return true;
    if (!plan.blocked_reason.empty()) return false;
    if (plan.needs_downgrade_consent && !downgrade_ok) return false;
    if (plan.needs_permission_consent && !permissions_ok) return false;
    if (plan.needs_compile_consent && !compile_ok) return false;
    return true;
}

/// Whether the SECONDARY action (Reinstall) may be pressed.
inline bool secondary_enabled(const InstallerPlan& plan, bool permissions_ok,
                              bool compile_ok) {
    if (plan.secondary_label.empty() || !plan.blocked_reason.empty()) return false;
    if (plan.needs_permission_consent && !permissions_ok) return false;
    if (plan.needs_compile_consent && !compile_ok) return false;
    return true;
}

/// The icon entry to show, best first: a large raster, then the vector, then
/// smaller rasters. `entries` are archive paths. "" when there is none.
inline std::string best_icon_entry(const std::vector<std::string>& entries) {
    static const char* const kPreference[] = {
        "icons/128.png", "icons/256.png", "icons/scalable.svg", "icons/64.png",
        "icons/48.png",  "icons/512.png", "icons/32.png"};
    for (const char* want : kPreference) {
        for (const std::string& e : entries) {
            if (e == want) return e;
        }
    }
    for (const std::string& e : entries) {
        if (e.rfind("icons/", 0) == 0) return e;
    }
    return {};
}

} // namespace lexe::gui

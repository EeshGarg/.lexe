#pragma once
// integration — DURABLE desktop integration (Definitive Architecture §14.1,
// §15.1 "Durable integration").
//
// The alpha's first end-to-end run worked and then did not survive a reboot.
// The engineering conclusion in §13 is not "blame a KDE component" but:
//
//     .LEXE desktop integration must be durable, explicit, and repairable
//     across login sessions and reboots.
//
// This module is that conclusion in code. Integration stops being an
// unrecorded side effect of `install` and becomes INSTALLED SYSTEM STATE with
// three properties:
//
//   explicit   — every registration .LEXE owns is enumerated in one state file
//                (`<home>/integration.json`) with its expected content hash
//   durable    — everything is written into persistent user locations, and the
//                per-app entries are regenerable from the installed manifest
//                alone, with no package file present
//   repairable — verify() reports exactly what is missing or has drifted, and
//                repair() re-establishes it, so "it broke after reboot" is a
//                diagnosable, fixable state instead of a mystery
//
// The reboot test of §15.1 is therefore a first-class, automatable check:
//
//     before reboot:  run.lexe -> lexe -> app
//     reboot
//     after reboot:   run.lexe -> lexe -> app
//     anything else = integration bug   <- verify() names which artifact broke

#include "core/manifest.hpp"
#include "core/paths.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace lexe {

/// What a registered artifact IS. The kind decides how repair regenerates it.
enum class ArtifactKind {
    RuntimeMime,     // the shared-mime-info XML declaring the .lexe type
    RuntimeHandler,  // the .desktop entry that OWNS application/vnd.usha.lexe
    AppDesktopEntry, // an installed application's menu entry (Exec=lexe run id)
    AppIcon,         // an installed application's hicolor icon
    AppMimeTypes,    // MIME XML for an application's file associations
    LaunchReference, // the generated run.lexe launch artifact (§15.1)
};
const char* to_string(ArtifactKind k);
bool artifact_kind_from_string(const std::string& text, ArtifactKind& out);

/// One registration .LEXE owns, as recorded in `<home>/integration.json`.
struct IntegrationArtifact {
    ArtifactKind kind = ArtifactKind::RuntimeMime;
    std::string path;      // absolute path of the file
    std::string sha256;    // expected content hash ("" = content not pinned)
    std::string owner_app; // App ID for app-scoped artifacts; "" for runtime
};

/// Health of one artifact at verify time.
enum class ArtifactHealth {
    Ok,       // present and matching the recorded hash
    Missing,  // the file is gone (the classic post-reboot symptom)
    Modified, // present but the content differs from what .LEXE wrote
};
const char* to_string(ArtifactHealth h);

struct ArtifactCheck {
    IntegrationArtifact artifact;
    ArtifactHealth health = ArtifactHealth::Ok;
    std::string detail;
};

/// The result of verify() / repair().
struct IntegrationReport {
    bool ok = false;
    std::vector<ArtifactCheck> checks;   // every artifact, healthy or not
    std::vector<std::string> repaired;   // paths repair() re-established
    std::vector<std::string> unrepaired; // paths repair() could not fix
    /// Applications that are installed but have NO integration recorded at all
    /// — the "installed before this runtime learned to record it" case, and
    /// the case where the state file itself was lost.
    std::vector<std::string> unregistered_apps;
    /// Registrations left behind by applications that are no longer installed.
    std::vector<std::string> orphaned;
    std::vector<std::string> notes;

    std::size_t problem_count() const;
};

/// The recorded integration state (`<home>/integration.json`).
struct IntegrationState {
    std::string schema = "lexe.integration/1";
    std::string runtime_version;
    std::string updated_at;
    std::vector<IntegrationArtifact> artifacts;

    static IntegrationState load(const Paths& paths);
    void save(const Paths& paths) const;
    std::string to_json() const;

    /// Replace every artifact owned by `app_id` (or, when `app_id` is empty,
    /// every runtime-scoped artifact) with `replacement`.
    void replace_scope(const std::string& app_id,
                       const std::vector<IntegrationArtifact>& replacement);
    std::vector<IntegrationArtifact> scope(const std::string& app_id) const;
};

/// The durable-integration façade used by install/uninstall and `lexe doctor`.
class DesktopIntegration {
public:
    explicit DesktopIntegration(const Paths& paths);

    /// Register the runtime itself as the persistent `.lexe` handler: the
    /// shared-mime-info type, the handler `.desktop` entry, and the default
    /// association. Idempotent; safe to run at every install and from
    /// `lexe doctor --repair`.
    IntegrationReport install_runtime_handler();

    /// Create every user-facing artifact for an installed application: its
    /// menu entry (Exec = `lexe run <id>`, never a payload path), its icons,
    /// any file-association MIME types, and its `run.lexe` launch reference.
    /// `icons_source_dir` may not exist (then no icons are installed).
    IntegrationReport install_app(const Manifest& manifest,
                                  const std::filesystem::path& icons_source_dir);

    /// Remove every artifact owned by `id` and forget it in the state file.
    void remove_app(const std::string& id);

    /// Check every recorded artifact plus the invariants that make the reboot
    /// test meaningful. Executes nothing and changes nothing.
    IntegrationReport verify() const;

    /// verify(), then re-establish everything that is missing or modified,
    /// re-register applications that have no integration recorded, and drop
    /// registrations owned by applications that are no longer installed.
    IntegrationReport repair();

    /// The MIME type the architecture names for `.lexe` artifacts (§7).
    static const char* canonical_mime_type();
    /// The earlier type, kept as an alias so already-registered desktops and
    /// existing files keep working.
    static const char* legacy_mime_type();

private:
    IntegrationReport check_state(const IntegrationState& state) const;
    Paths paths_;
};

/// Refresh the freedesktop MIME/desktop databases (best effort; the tools may
/// be absent, which is not an error).
void refresh_desktop_databases(const Paths& paths);

} // namespace lexe

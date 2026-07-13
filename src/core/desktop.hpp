#pragma once
// desktop — Linux desktop integration (FORMAT-0.1 §9, SPEC "Installed
// Application Representation"): `.desktop` entries whose Exec line is always
// `lexe run <id>` (never a version-specific path), hicolor icons, MIME XML,
// best-effort `update-desktop-database` / `update-mime-database`.
// On Windows every function is a recorded no-op returning `skipped` so the
// portable core tests run anywhere.

#include "core/manifest.hpp"
#include "core/paths.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace lexe::desktop {

enum class IntegrationStatus {
    applied, // files written (Linux)
    skipped, // platform without desktop integration (Windows dev host)
};

/// What integration did; `created_files` (absolute paths) is recorded into
/// installation.json so uninstall can remove them (FORMAT-0.1 §9).
struct IntegrationResult {
    IntegrationStatus status = IntegrationStatus::skipped;
    std::vector<std::string> created_files;
};

// --- pure content generation (unit-testable as strings on any platform) ---

/// The `.desktop` entry contents for an installed app. The Exec line is
/// always `lexe run <id>` — the stable Lexe launcher, never a
/// version-specific path (SPEC "Installed Application Representation").
/// Values are escaped per the Desktop Entry specification.
std::string desktop_entry_text(const Manifest& manifest);

/// shared-mime-info XML for the manifest's `integration.fileAssociations`:
/// one <mime-type> per distinct mimeType, one <glob> per extension.
/// XML-special characters in names/types/patterns are escaped.
std::string mime_xml_text(const Manifest& manifest);

/// The runtime's own `.desktop` entry: handler for `application/x-lexe`
/// (Exec=`lexe-installer %f`) so double-clicking a `.lexe` file opens the
/// installer.
std::string runtime_desktop_entry_text();

/// shared-mime-info XML declaring `application/x-lexe` (glob `*.lexe`).
std::string runtime_mime_xml_text();

// --- integration operations ---

/// Create the app's desktop entry (`lexe-<id>.desktop`, Exec=`lexe run <id>`),
/// copy icons from `icons_source_dir` (the package's extracted `icons/`;
/// missing/nonexistent dir means "no icons") into the hicolor theme, and
/// write MIME XML for manifest file associations. Best-effort database
/// refresh; failures of the refresh tools are not errors.
IntegrationResult integrate_app(const Paths& paths, const Manifest& manifest,
                                const std::filesystem::path& icons_source_dir);

/// Remove previously created integration files (absolute paths from
/// installation.json). Missing files are ignored; databases refreshed
/// best-effort.
void remove_integration(const Paths& paths,
                        const std::vector<std::string>& created_files);

/// Register the runtime itself as the handler for `application/x-lexe`
/// (`lexe integrate` — used by packaging so double-clicking .lexe files
/// opens the installer).
IntegrationResult integrate_runtime(const Paths& paths);

} // namespace lexe::desktop

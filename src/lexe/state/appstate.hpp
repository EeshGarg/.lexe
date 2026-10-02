#pragma once
// appstate — every .LEXE-managed location that belongs to exactly ONE App ID,
// and what `lexe uninstall` and `lexe purge` each do to it.
//
// This table is the single source of truth for the removal contract
// (docs/REFERENCE-POLICY.md "Uninstall and purge"). `Installer::uninstall`,
// `Installer::purge`, purge's fail-closed post-check, `lexe purge`'s report and
// the tests all read it, so "what survives an uninstall" cannot be one thing in
// the code, another in the documentation and a third in what a test asserts.
//
// What it deliberately does NOT contain: anything outside .LEXE-managed
// storage. An application may write documents, exports or projects anywhere the
// user lets it; purge never guesses that such files belong to it.

#include "lexe/base/error.hpp"
#include "lexe/base/paths.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace lexe {

/// What each removal operation does to one location.
enum class StateFate {
    /// Installation material and debris: removed by uninstall AND by purge.
    RemovedByUninstall,
    /// Deliberately persistent per-app state that makes a reinstall behave like
    /// a RETURNING installation. Kept by uninstall; removed by purge.
    SurvivesUninstall,
    /// Never removed by either: an inert anchor whose deletion would itself be a
    /// defect (the per-app mutation lock, see Installer::uninstall).
    Kept,
};
const char* to_string(StateFate fate);

/// One per-app location.
struct AppStateEntry {
    std::string what;            // a short human description, for reports/docs
    std::filesystem::path path;  // file or directory
    StateFate fate = StateFate::RemovedByUninstall;
    /// True when the location can change a later install, verification,
    /// authorization, configuration or execution of the App ID (the purge
    /// invariant is about exactly these).
    bool security_relevant = false;
};

/// The fixed table for `id` (validated).
///
/// Version lease files (`locks/<id>.v.<version>.lease`) are NOT in it, and that
/// is deliberate. Their names cannot be attributed to an App ID by parsing:
/// versions may contain dots and letters, so `com.a.v.1.v.2.0.0.lease` is
/// equally App `com.a` at version `1.v.2.0.0` and App `com.a.v.1` at `2.0.0`.
/// Deleting another application's HELD lease would silently remove its
/// running-launch protection (flock is per-inode). So removal deletes leases
/// only for versions it finds in the application's own directories, and a
/// lease is never part of the post-check: it is an empty flock anchor the
/// kernel releases when its holder dies, and it influences nothing.
std::vector<AppStateEntry> app_state_table(const Paths& paths,
                                           const std::string& id);

/// The purge journal: written before a purge changes anything and removed only
/// after its post-check passes. While it exists the purge is unfinished.
std::filesystem::path purge_journal(const Paths& paths, const std::string& id);
bool purge_pending(const Paths& paths, const std::string& id);

/// The refusal every operation other than `purge` and `install` gives while a
/// purge of `id` is unfinished (exit 6, an operation conflict). One sentence,
/// so the CLI, the GUI and the launcher cannot describe one state three ways.
BusyError purge_unfinished_error(const std::string& id);

/// The entries of `table` that still exist on disk.
std::vector<AppStateEntry> present_entries(const std::vector<AppStateEntry>& table);

} // namespace lexe

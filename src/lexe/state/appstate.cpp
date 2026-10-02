// appstate — the per-App-ID state table. See appstate.hpp.

#include "lexe/state/appstate.hpp"

#include "lexe/base/identity.hpp"
#include "lexe/state/appconfig.hpp"
#include "lexe/state/registry.hpp"

#include <system_error>

namespace fs = std::filesystem;

namespace lexe {

const char* to_string(StateFate fate) {
    switch (fate) {
    case StateFate::RemovedByUninstall: return "removed by uninstall and purge";
    case StateFate::SurvivesUninstall: return "kept by uninstall, removed by purge";
    case StateFate::Kept: return "kept by both";
    }
    return "?";
}

std::vector<AppStateEntry> app_state_table(const Paths& paths,
                                           const std::string& id) {
    const Registry registry(paths); // every accessor below validates `id`
    using F = StateFate;
    // Every path is asked of the module that OWNS it, never re-derived here, so
    // a location that moves cannot leave this table describing the old one.
    return {
        {"installation: program files, installation record, approved "
         "permissions, update source, transaction journal",
         registry.app_dir(id), F::RemovedByUninstall, true},
        {"remains of an interrupted uninstall",
         registry.app_dir(id).parent_path() / ".removing" / id,
         F::RemovedByUninstall, false},
        {"cache", registry.app_cache_dir(id), F::RemovedByUninstall, false},
        {"downloaded update packages", paths.cache_dir() / "updates" / id,
         F::RemovedByUninstall, false},
        {"launch-reference scratch", paths.cache_dir() / "launchref-work" / id,
         F::RemovedByUninstall, false},
        // ORDER MATTERS among these: purge deletes them in table order, and the
        // trust record comes first because it alone decides whether a later
        // install of this App ID is a first install.
        {"local trust record: the App-ID/key binding, any explicit trust and "
         "any local block",
         registry.trust_record_file(id), F::SurvivesUninstall, true},
        // FORMAT-0.1 §9.5.1: approval "persists across update, rollback and
        // reinstall by the same publisher key" and is discarded "when the
        // application's persistent data is purged". Its lifetime is the data's,
        // so it survives uninstall -- with the key that received it, which is
        // the only key it is ever honoured for.
        {"permission approvals, bound to the publisher key that received them",
         permission_approvals_file(paths, id), F::SurvivesUninstall, true},
        {"persistent application data, and the marker binding it to a "
         "publisher key",
         registry.app_data_dir(id), F::SurvivesUninstall, true},
        {"compatibility preferences", AppConfig::file(paths, id),
         F::SurvivesUninstall, true},
        // ErrorStore (diagnostics/) owns this directory, but diagnostics/ sits
        // ABOVE state/ in the engine's layering, so the path is derived from
        // the root base/ owns. test_purge.cpp asserts it equals
        // ErrorStore::app_dir(id), so the two cannot drift apart silently.
        {"error history", paths.errors_dir() / id, F::SurvivesUninstall,
         false},
        {"per-app mutation lock (an empty flock anchor)",
         registry.mutation_lock_file(id), F::Kept, false},
    };
}

fs::path permission_approvals_file(const Paths& paths, const std::string& id) {
    (void)Registry(paths).app_dir(id); // validates id: a single safe component
    return paths.home() / "approvals" / (id + ".json");
}

fs::path purge_journal(const Paths& paths, const std::string& id) {
    return Registry(paths).app_dir(id).parent_path() / ".removing" /
           (id + ".purge");
}

bool purge_pending(const Paths& paths, const std::string& id) {
    std::error_code ec;
    return fs::exists(fs::symlink_status(purge_journal(paths, id), ec));
}

BusyError purge_unfinished_error(const std::string& id) {
    return BusyError(
        "an interrupted purge of " + id + " has not finished",
        "Run `lexe purge " + id + "` to finish it. Until it does, " + id +
            " cannot be launched, uninstalled or have its trust changed; "
            "installing it finishes the purge first.");
}

std::vector<AppStateEntry> present_entries(
    const std::vector<AppStateEntry>& table) {
    std::vector<AppStateEntry> out;
    for (const AppStateEntry& e : table) {
        std::error_code ec;
        // symlink_status: a dangling symlink at one of these paths is still
        // something there, and "nothing there" is the claim being checked.
        if (fs::exists(fs::symlink_status(e.path, ec))) out.push_back(e);
    }
    return out;
}

} // namespace lexe

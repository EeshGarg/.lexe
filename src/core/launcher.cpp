// launcher — `lexe run <id>` (SPEC "Installed Application Representation",
// ARCHITECTURE.md #Modules). Resolves the current version via the registry,
// validates the manifest entrypoint, and enforces security invariant #6:
// nothing outside the app's current version directory is ever executed. The
// containment check runs on the *canonical* resolved path, so an entrypoint
// that lexically stays inside but escapes through a symlink is rejected too.
// The child is spawned with an argv array (no shell, invariant #3) and
// cwd = the version directory; its exit code is recorded as `lastRun` in
// installation.json and propagated to the caller.

#include "core/launcher.hpp"

#include "core/error.hpp"
#include "core/manifest.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"

#include <filesystem>
#include <system_error>

namespace fs = std::filesystem;

namespace lexe {

namespace {

/// True when canonical path `p` is strictly inside canonical directory
/// `root` (equal to `root` itself does not count — the entrypoint must be a
/// file within the directory).
bool strictly_inside(const fs::path& root, const fs::path& p) {
    const fs::path rel = p.lexically_relative(root);
    if (rel.empty() || rel == ".") return false;      // unrelated / same path
    return rel.begin()->string() != "..";             // must not walk up
}

} // namespace

int run_app(const Paths& paths, const std::string& id,
            const std::vector<std::string>& args) {
    const Registry registry(paths);

    // Throws NotFoundError when the app is not installed.
    InstallationRecord record = registry.read_record(id);

    // Active version (symlink or current.txt fallback, FORMAT-0.1 §9).
    // version_dir() re-validates the version string, so a tampered current
    // pointer can never traverse outside apps/<id>/versions/.
    const std::string version = registry.current_version(id);
    const fs::path version_dir = registry.version_dir(id, version);

    std::error_code ec;
    if (!fs::is_directory(version_dir, ec)) {
        throw Error("launcher: current version directory of " + id +
                    " is missing: " + version_dir.string());
    }

    // The manifest.json copy of the active version; Manifest::parse re-checks
    // every FORMAT-0.1 §5 constraint (relative entrypoint, no "..", no
    // backslash, no drive designator) even if the copy was tampered with.
    const Manifest manifest = registry.read_manifest(id);

    // Resolve the entrypoint and reject any resolution that escapes the
    // version directory (security invariant #6). weakly_canonical follows
    // symlinks in the existing part of the path, so a symlinked subdirectory
    // pointing elsewhere is caught here as well.
    const fs::path root = fs::weakly_canonical(version_dir, ec);
    if (ec) {
        throw Error("launcher: cannot resolve version directory: " +
                    version_dir.string());
    }
    const fs::path entry = fs::weakly_canonical(
        version_dir / fs::path(manifest.entrypoint_executable), ec);
    if (ec || !strictly_inside(root, entry)) {
        throw Error("launcher: entrypoint \"" +
                    manifest.entrypoint_executable +
                    "\" resolves outside the current version directory of " +
                    id);
    }
    if (!fs::is_regular_file(entry, ec)) {
        throw Error("launcher: entrypoint missing for " + id + ": " +
                    entry.string());
    }

#ifndef _WIN32
    // Ensure the entrypoint is executable (ZIP extraction does not always
    // preserve mode bits). Exec is added for owner, and for group/others
    // where the corresponding read bit is already present.
    const fs::perms perms = fs::status(entry, ec).permissions();
    if (ec) {
        throw Error("launcher: cannot stat entrypoint: " + entry.string());
    }
    if ((perms & fs::perms::owner_exec) == fs::perms::none) {
        fs::perms add = fs::perms::owner_exec;
        if ((perms & fs::perms::group_read) != fs::perms::none) {
            add |= fs::perms::group_exec;
        }
        if ((perms & fs::perms::others_read) != fs::perms::none) {
            add |= fs::perms::others_exec;
        }
        fs::permissions(entry, add, fs::perm_options::add, ec);
        if (ec) {
            throw Error("launcher: entrypoint of " + id +
                        " is not executable and the exec bit cannot be set: " +
                        entry.string());
        }
    }
#endif

    // argv = entrypoint, manifest arguments, then caller arguments — an argv
    // array end to end, never a shell (security invariant #3).
    std::vector<std::string> argv;
    argv.reserve(1 + manifest.entrypoint_arguments.size() + args.size());
    argv.push_back(entry.string());
    argv.insert(argv.end(), manifest.entrypoint_arguments.begin(),
                manifest.entrypoint_arguments.end());
    argv.insert(argv.end(), args.begin(), args.end());

    util::RunOptions opts;
    opts.cwd = root;
    opts.capture_stdout = false; // the child owns our stdout (normal launch)

    // Throws lexe::Error when the process cannot be started (unlaunchable).
    const util::ProcessResult result = util::run_process(argv, opts);

    // Record lastRun {at, exitCode} in installation.json (FORMAT-0.1 §9).
    record.last_run_at = util::now_utc_string();
    record.last_exit_code = result.exit_code;
    registry.write_record(record);

    return result.exit_code;
}

} // namespace lexe

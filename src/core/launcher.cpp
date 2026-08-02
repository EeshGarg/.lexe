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

#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/isolation.hpp"
#include "core/json_strict.hpp"
#include "core/limits.hpp"
#include "core/manifest.hpp"
#include "core/permissions.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <memory>
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

    // Runtime-trust WS6: revalidate the entrypoint's integrity against the
    // hash recorded at install time, so a binary tampered with AFTER
    // installation is never executed. Enforced whenever a recorded hash for the
    // entrypoint is present (every real install writes one); the launch is
    // refused on mismatch — it never falls through to direct execution.
    {
        fs::path hashes_file = registry.meta_dir(id, version) / "hashes.json";
        if (!fs::is_regular_file(hashes_file, ec)) {
            hashes_file = registry.app_dir(id) / "hashes.json";
        }
        if (fs::is_regular_file(hashes_file, ec)) {
            const nlohmann::json doc =
                json_strict::parse(util::slurp_text(hashes_file),
                                   "installed hashes.json", limits::kMaxHashesBytes);
            const auto files = doc.find("files");
            if (files != doc.end() && files->is_object()) {
                const std::string key =
                    "payload/" + manifest.entrypoint_executable;
                const auto it = files->find(key);
                if (it != files->end() && it->is_string() &&
                    crypto::sha256_file_hex(entry) != it->get<std::string>()) {
                    throw LaunchError(
                        "launcher: entrypoint of " + id +
                        " fails its recorded integrity check (modified after "
                        "install); refusing to launch. Run `lexe repair " + id +
                        "`.");
                }
            }
        }
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

    // App arguments (manifest arguments then caller arguments) — argv elements
    // end to end, never a shell (security invariant #3).
    std::vector<std::string> app_args;
    app_args.reserve(manifest.entrypoint_arguments.size() + args.size());
    app_args.insert(app_args.end(), manifest.entrypoint_arguments.begin(),
                    manifest.entrypoint_arguments.end());
    app_args.insert(app_args.end(), args.begin(), args.end());

    // Runtime isolation (WS7): construct the request from trusted installed
    // state and launch THROUGH the isolation backend. The approved permission
    // set decides network access; everything else is the baseline sandbox.
    const NormalizedPermissions approved =
        normalized_from_ids(record.approved_permissions);
    const bool network_allowed =
        std::find(approved.ids.begin(), approved.ids.end(),
                  std::string("network")) != approved.ids.end();

    const fs::path data_root = paths.data_dir() / id;
    const fs::path cache_root = paths.cache_dir() / "apps" / id;
    std::error_code mkec;
    fs::create_directories(data_root, mkec);
    fs::create_directories(cache_root, mkec);

    IsolationRequest req;
    req.app_id = id;
    req.app_root = root;
    req.entrypoint = entry;
    req.args = app_args;
    req.data_root = data_root;
    req.cache_root = cache_root;
    req.network_allowed = network_allowed;
    req.gui = false; // 0.1: headless/terminal isolation only (see isolation docs)

    const std::unique_ptr<IsolationBackend> backend =
        make_isolation_backend(paths);
    const IsolationCapabilities caps = backend->capabilities();

    int exit_code = 0;
    if (caps.status == CapabilityStatus::PolicyUnsupported) {
        // No isolation backend on this platform (e.g. the Windows dev host):
        // run directly. This is NOT a fail-closed failure — the platform has no
        // isolation to establish; the capability is reported truthfully.
        std::vector<std::string> argv;
        argv.push_back(entry.string());
        argv.insert(argv.end(), app_args.begin(), app_args.end());
        util::RunOptions opts;
        opts.cwd = root;
        opts.capture_stdout = false;
        exit_code = util::run_process(argv, opts).exit_code;
    } else if (caps.status == CapabilityStatus::Unavailable ||
               caps.status == CapabilityStatus::SetupFailed) {
        // Isolation is expected here but the backend does not work — FAIL
        // CLOSED. Never execute the application unconfined.
        throw IsolationError(
            "launcher: runtime isolation backend is unavailable (" +
            caps.detail + "); refusing to launch " + id + " unconfined");
    } else {
        // Available / PartiallyAvailable: build the plan (throws IsolationError
        // if a required control cannot be enforced) and launch through the
        // backend (throws on setup failure — never falls back to direct exec).
        const IsolationPlan plan = build_plan(req, caps);
        exit_code = backend->run(plan).exit_code;
    }

    // Record lastRun {at, exitCode} in installation.json (FORMAT-0.1 §9).
    record.last_run_at = util::now_utc_string();
    record.last_exit_code = exit_code;
    registry.write_record(record);

    return exit_code;
}

} // namespace lexe

// commands — the complete Lexe 0.1 command surface (ARCHITECTURE.md #CLI,
// SPEC #Command-Line Interface). Hand-rolled argument parsing (no deps),
// human output kept clean and aligned with no colour codes, errors to
// stderr (main.cpp prints exception text and maps to the exit codes
// 0 ok / 1 runtime error / 2 usage / 3 verification failure / 4 not found).

#include "commands.hpp"

#include "core/buildreport.hpp"
#include "core/compat.hpp"
#include "core/crypto.hpp"
#include "core/depengine.hpp"
#include "core/desktop.hpp"
#include "core/elf.hpp"
#include "core/error.hpp"
#include "core/installer.hpp"
#include "core/isolation.hpp"
#include "core/json_strict.hpp"
#include "core/launcher.hpp"
#include "core/limits.hpp"
#include "core/lock.hpp"
#include "core/manifest.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
#include "core/permissions.hpp"
#include "core/presentation.hpp"
#include "core/registry.hpp"
#include "core/runtime_profile.hpp"
#include "core/trust.hpp"
#include "core/tux32.hpp"
#include "core/version.hpp"
#include "core/updater.hpp"
#include "core/util.hpp"
#include "core/verify.hpp"
#include "core/versioncmp.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

namespace lexe::cli {

namespace {

using nlohmann::ordered_json;

// ------------------------------------------------------------ usage strings

constexpr const char* kInstallUsage =
    "usage: lexe install <file.lexe> [--yes] [--trust] [--accept-permissions] "
    "[--channel <c>]";
constexpr const char* kRunUsage = "usage: lexe run <id> [-- <args...>]";
constexpr const char* kUpdateUsage =
    "usage: lexe update <id> | --all [--check]";
constexpr const char* kRemoveUsage =
    "usage: lexe remove <id> [--remove-cache] [--purge-data] [--yes]";
constexpr const char* kRepairUsage = "usage: lexe repair <id>";
constexpr const char* kInfoUsage = "usage: lexe info <file.lexe | id> [--json]";
constexpr const char* kAnalyzeUsage =
    "usage: lexe analyze <binary | project-dir | payload-dir> [--json] "
    "[--profile <core-portable|forward-runtime|native-capture>]";
constexpr const char* kVerifyUsage = "usage: lexe verify <file.lexe> [--json]";
constexpr const char* kSourceUsage = "usage: lexe source set <id> <url>";
constexpr const char* kRollbackUsage = "usage: lexe rollback <id>";
constexpr const char* kGcUsage = "usage: lexe gc <id> [--keep <n>]";
constexpr const char* kTrustUsage =
    "usage: lexe trust show <id> [--json]\n"
    "       lexe trust block <id>\n"
    "       lexe trust unblock <id>\n"
    "       lexe trust forget <id> [--force]";
constexpr const char* kListUsage = "usage: lexe list [--json]";
constexpr const char* kKeygenUsage = "usage: lexe keygen <keyfile.json>";
constexpr const char* kPackUsage =
    "usage: lexe pack <source-dir> --manifest <lexe.json> --key "
    "<keyfile.json> -o <out.lexe> [--icons <dir>] [--metadata <dir>]";
constexpr const char* kIntegrateUsage = "usage: lexe integrate";
constexpr const char* kSignUpdateUsage =
    "usage: lexe sign-update <update.json> --key <keyfile.json>";
constexpr const char* kBuildUsage =
    "usage: lexe build <project-dir> [-o <out.lexe>] [--key <keyfile.json>]";
constexpr const char* kSdkUsage =
    "usage: lexe sdk verify <binary | project-dir | payload-dir> [--json] "
    "[--profile <tux32-core-1>]";

// -------------------------------------------------------- argument parsing

/// Result of the hand-rolled per-command argument scan.
struct Parsed {
    std::vector<std::string> positionals;
    std::set<std::string> flags;                 // value-less options present
    std::map<std::string, std::string> options;  // valued options
    std::vector<std::string> passthrough;        // everything after "--"
};

/// Scan `args` against the sets of recognised value-less flags and valued
/// options. When `collect_passthrough` is true, everything after a literal
/// "--" is collected verbatim (used by `lexe run`); otherwise "--" ends
/// option parsing and the rest are positionals. Unknown options and options
/// missing their value are UsageErrors carrying the command's usage line.
Parsed parse_arguments(const std::vector<std::string>& args,
                       const std::set<std::string>& known_flags,
                       const std::set<std::string>& known_options,
                       bool collect_passthrough, const std::string& usage) {
    Parsed out;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& arg = args[i];
        if (arg == "--") {
            if (collect_passthrough) {
                out.passthrough.assign(args.begin() +
                                           static_cast<std::ptrdiff_t>(i) + 1,
                                       args.end());
            } else {
                out.positionals.insert(out.positionals.end(),
                                       args.begin() +
                                           static_cast<std::ptrdiff_t>(i) + 1,
                                       args.end());
            }
            return out;
        }
        if (arg.size() > 1 && arg.front() == '-') {
            if (known_flags.count(arg) != 0) {
                out.flags.insert(arg);
                continue;
            }
            if (known_options.count(arg) != 0) {
                if (i + 1 >= args.size()) {
                    throw UsageError("missing value for " + arg + "\n" + usage);
                }
                out.options[arg] = args[++i];
                continue;
            }
            throw UsageError("unknown option \"" + arg + "\"\n" + usage);
        }
        out.positionals.push_back(arg);
    }
    return out;
}

/// Exactly `count` positional arguments, or a UsageError with the usage line.
void require_positionals(const Parsed& parsed, std::size_t count,
                         const std::string& usage) {
    if (parsed.positionals.size() != count) {
        throw UsageError(parsed.positionals.size() < count
                             ? "missing argument\n" + usage
                             : "unexpected argument \"" +
                                   parsed.positionals[count] + "\"\n" + usage);
    }
}

/// Required valued option, or a UsageError naming it.
const std::string& require_option(const Parsed& parsed, const std::string& name,
                                  const std::string& usage) {
    const auto it = parsed.options.find(name);
    if (it == parsed.options.end()) {
        throw UsageError("missing required option " + name + "\n" + usage);
    }
    return it->second;
}

// ------------------------------------------------------------- formatting

std::string join(const std::vector<std::string>& parts,
                 const std::string& separator) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) out += separator;
        out += parts[i];
    }
    return out;
}

/// Human size in decimal units, matching the SPEC primary screen
/// (125829120 bytes -> "126 MB").
std::string format_size(std::uint64_t bytes) {
    if (bytes < 1000) return std::to_string(bytes) + " B";
    static const char* const kUnits[] = {"KB", "MB", "GB", "TB"};
    double value = static_cast<double>(bytes) / 1000.0;
    std::size_t unit = 0;
    while (value >= 1000.0 && unit + 1 < 4) {
        value /= 1000.0;
        ++unit;
    }
    char buf[32];
    if (value < 10.0) {
        std::snprintf(buf, sizeof(buf), "%.1f %s", value, kUnits[unit]);
    } else {
        std::snprintf(buf, sizeof(buf), "%.0f %s", value, kUnits[unit]);
    }
    return buf;
}

/// Sum of the package's payload/ entry sizes (shown when the manifest gives
/// no install.estimatedSize).
std::uint64_t payload_size(const PackageReader& reader) {
    std::uint64_t total = 0;
    for (const PackageEntry& entry : reader.entries()) {
        if (entry.path.rfind("payload/", 0) == 0) {
            total += entry.uncompressed_size;
        }
    }
    return total;
}

/// The size shown for a package: manifest estimate when given, else the
/// uncompressed payload size.
std::uint64_t display_size(const Manifest& manifest,
                           const PackageReader& reader) {
    return manifest.install_estimated_size != 0
               ? manifest.install_estimated_size
               : payload_size(reader);
}

std::string install_scope_text(const Manifest& manifest) {
    if (manifest.install_scope == "user") return "Current user only";
    if (manifest.install_scope == "system") return "System-wide";
    return manifest.install_scope;
}

std::string update_policy_text(const Manifest& manifest) {
    if (manifest.updates_enabled && !manifest.updates_manifest_url.empty()) {
        return "Automatically check " + manifest.updates_manifest_url +
               " (channel: " + manifest.updates_channel + ")";
    }
    return "No automatic updates";
}

/// Ask on stdin. Only "y"/"yes" (any case) confirms; EOF declines.
bool confirm(const std::string& question) {
    std::cout << question << " [y/N] " << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) {
        std::cout << "\n";
        return false;
    }
    const std::size_t begin = line.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return false;
    const std::size_t end = line.find_last_not_of(" \t\r\n");
    std::string answer = line.substr(begin, end - begin + 1);
    std::transform(answer.begin(), answer.end(), answer.begin(),
                   [](unsigned char c) {
                       return static_cast<char>(
                           (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c);
                   });
    return answer == "y" || answer == "yes";
}

/// A short label for the local key state of a trust record (query view — no
/// package/signature is involved, so this is the record's own standing).
std::string local_key_state_label(const std::optional<TrustRecord>& rec) {
    if (!rec.has_value()) return "no-record";
    if (rec->blocked) return "blocked";
    if (rec->explicitly_trusted) return "explicitly-trusted";
    return "known";
}

/// The data-owner marker's key for `id`, if persistent data is retained.
std::optional<std::string> retained_data_owner(const Registry& registry,
                                               const std::string& id) {
    const fs::path owner = registry.data_owner_marker(id);
    std::error_code ec;
    if (!fs::is_regular_file(owner, ec)) return std::nullopt;
    std::string prior = util::slurp_text(owner);
    while (!prior.empty() && (prior.back() == '\n' || prior.back() == '\r' ||
                              prior.back() == ' ')) {
        prior.pop_back();
    }
    if (prior.empty()) return std::nullopt;
    return prior;
}

/// The install confirmation screen — a TRUTHFUL two-dimensional authenticity +
/// local-trust view (never a single "verified" line), truthful per-permission
/// enforcement, and the real isolation state for this platform. The signature
/// has already been validated by the caller, so it is presented as Valid.
void print_primary_screen(const Manifest& manifest, const fs::path& package,
                          std::uint64_t size_bytes, const Paths& paths) {
    const Registry registry(paths);
    const TrustEvaluation eval = TrustStore(paths).evaluate(
        manifest.id, manifest.decoded_public_key(), SignatureState::Valid,
        retained_data_owner(registry, manifest.id));
    const presentation::AuthenticityView auth =
        presentation::present_authenticity(eval, manifest.publisher_name);

    const std::unique_ptr<IsolationBackend> backend =
        make_isolation_backend(paths);
    const IsolationCapabilities caps = backend->capabilities();
    const presentation::IsolationView iso = presentation::present_isolation(caps);
    const NormalizedPermissions perms = normalize_permissions(manifest.permissions);

    std::cout << manifest.name << "\n"
              << "Published by " << manifest.publisher_name
              << " (publisher identity not independently verified)\n"
              << "Version " << manifest.version << "\n\n"
              << "Authenticity & local trust:\n"
              << "  " << auth.headline << "\n"
              << "  " << auth.signature_text << "\n"
              << "  " << auth.key_text << "\n"
              << "  Signing key fingerprint: " << auth.fingerprint_grouped << "\n"
              << "  " << auth.identity_caveat << "\n\n"
              << "Source:\n  " << package.string() << "\n\n"
              << "Application Type:\n  Native Linux - "
              << join(manifest.architectures, ", ") << "\n\n"
              << "Permissions:\n";
    if (perms.ids.empty()) {
        std::cout << "  (none requested)\n";
    } else {
        for (const presentation::PermissionView& row :
             presentation::present_permissions(perms.ids, caps)) {
            std::cout << "  - " << row.title << "  [" << row.enforcement << "]\n";
        }
    }
    if (registry.is_installed(manifest.id)) {
        try {
            const InstallationRecord rec = registry.read_record(manifest.id);
            const presentation::PermissionDeltaView dv =
                presentation::present_permission_delta(permission_delta(
                    normalized_from_ids(rec.approved_permissions), perms));
            if (dv.expands) {
                std::cout << "  New permissions this update requests (separate "
                             "approval required):\n";
                for (const std::string& a : dv.added) {
                    std::cout << "    + " << a << "\n";
                }
            }
        } catch (const Error&) {
        }
    }
    std::cout << "\nInstallation:\n  " << install_scope_text(manifest) << "\n  "
              << format_size(size_bytes) << "\n\n"
              << "Updates:\n  " << update_policy_text(manifest) << "\n\n"
              << "Isolation on this platform:\n  " << iso.headline << "\n";
    for (const std::pair<std::string, std::string>& c : iso.controls) {
        std::cout << "    " << c.first << ": " << c.second << "\n";
    }
    std::cout << "  " << iso.platform_caveat << "\n";
}

constexpr int kLabelWidth = 15;

void print_kv(const std::string& label, const std::string& value) {
    std::cout << "  " << std::left << std::setw(kLabelWidth) << label << " "
              << value << "\n";
}

/// Shared manifest block of `lexe info` (package and installed modes).
void print_manifest_info(const Manifest& manifest, std::uint64_t size_bytes) {
    print_kv("Name:", manifest.name);
    print_kv("Id:", manifest.id);
    print_kv("Version:", manifest.version);
    print_kv("Publisher:", manifest.publisher_name);
    if (!manifest.publisher_website.empty()) {
        print_kv("Website:", manifest.publisher_website);
    }
    print_kv("Type:", manifest.application_type + " (" +
                          join(manifest.architectures, ", ") + ")");
    print_kv("Entrypoint:", manifest.entrypoint_executable);
    print_kv("Install:",
             manifest.install_mode + ", " + manifest.install_scope + " scope");
    print_kv("Size:", format_size(size_bytes));
    print_kv("Permissions:", manifest.permissions.empty()
                                 ? "(none)"
                                 : join(manifest.permissions, ", "));
    print_kv("Updates:", update_policy_text(manifest));
}

/// manifest.to_json() re-parsed so it can be embedded in --json documents.
ordered_json manifest_json(const Manifest& manifest) {
    return ordered_json::parse(manifest.to_json());
}

// ------------------------------------------------------------- commands

int cmd_install(const std::vector<std::string>& args) {
    const Parsed parsed = parse_arguments(
        args, {"--yes", "--accept-permissions", "--trust"}, {"--channel"}, false,
        kInstallUsage);
    require_positionals(parsed, 1, kInstallUsage);
    const fs::path package(parsed.positionals[0]);
    const Paths paths = Paths::detect();

    // FORMAT-0.1 §6 pipeline including the architecture stage; a failing
    // package throws VerificationError (exit 3) before anything else happens.
    const Manifest manifest =
        verify_package_or_throw(package, /*check_architecture=*/true);

    if (parsed.flags.count("--yes") == 0) {
        std::uint64_t size = manifest.install_estimated_size;
        if (size == 0) {
            const PackageReader reader(package);
            size = payload_size(reader);
        }
        print_primary_screen(manifest, package, size, paths);
        std::cout << "\n";
        if (!confirm("Install " + manifest.name + " " + manifest.version +
                     "?")) {
            // Declining the prompt is a valid user choice, not an error.
            std::cerr << "installation cancelled\n";
            return 0;
        }
    }

    Installer installer(paths);
    InstallOptions opts;
    const auto channel = parsed.options.find("--channel");
    if (channel != parsed.options.end()) opts.channel = channel->second;
    // Approving new permissions on an update is a separate, explicit act
    // (runtime-trust WS5) — never implied by --yes.
    opts.allow_permission_expansion =
        parsed.flags.count("--accept-permissions") != 0;
    // Explicitly TRUSTING the signing key locally is a separate act from
    // consenting to this install (runtime-trust WS4) — also never implied by
    // --yes. A plain install still records the App-ID/key binding as accepted.
    opts.explicit_trust = parsed.flags.count("--trust") != 0;
    const InstallResult result = installer.install(package, opts);

    std::cout << "Installed " << manifest.name << " " << result.version << " ("
              << result.id << ")\n"
              << "Location: " << result.app_dir.string() << "\n";
    return 0;
}

int cmd_run(const std::vector<std::string>& args) {
    const Parsed parsed = parse_arguments(args, {}, {}, true, kRunUsage);
    require_positionals(parsed, 1, kRunUsage);
    // The child's exit code is propagated verbatim (SPEC "Installed
    // Application Representation").
    return run_app(Paths::detect(), parsed.positionals[0], parsed.passthrough);
}

int cmd_update(const std::vector<std::string>& args) {
    const Parsed parsed = parse_arguments(
        args, {"--all", "--check", "--accept-permissions"}, {}, false,
        kUpdateUsage);
    const bool all = parsed.flags.count("--all") != 0;
    const bool check_only = parsed.flags.count("--check") != 0;
    const bool accept_perms = parsed.flags.count("--accept-permissions") != 0;
    if (all) {
        require_positionals(parsed, 0, kUpdateUsage);
    } else {
        require_positionals(parsed, 1, kUpdateUsage);
    }

    const Paths paths = Paths::detect();
    Updater updater(paths);

    const auto update_one = [&](const std::string& id) {
        const UpdateCheck chk = updater.check(id);
        if (check_only) {
            if (chk.update_available) {
                std::cout << id << ": update available: "
                          << chk.installed_version << " -> "
                          << chk.available_version << "\n";
            } else {
                std::cout << id << ": up to date (installed "
                          << chk.installed_version << ", channel offers "
                          << chk.available_version << ")\n";
            }
            return;
        }
        if (!chk.update_available) {
            std::cout << id << ": up to date (" << chk.installed_version
                      << ")\n";
            return;
        }
        const InstallResult result = updater.apply(id, accept_perms);
        std::cout << id << ": updated " << chk.installed_version << " -> "
                  << result.version << "\n";
    };

    if (!all) {
        update_one(parsed.positionals[0]);
        return 0;
    }

    const Registry registry(paths);
    const std::vector<std::string> ids = registry.list_installed();
    if (ids.empty()) {
        std::cout << "no applications installed\n";
        return 0;
    }
    bool failed = false;
    for (const std::string& id : ids) {
        try {
            if (registry.read_record(id).update_url.empty()) {
                std::cout << id << ": no update source configured (skipped)\n";
                continue;
            }
            update_one(id);
        } catch (const std::exception& e) {
            std::cerr << "lexe: " << id << ": " << e.what() << "\n";
            failed = true;
        }
    }
    return failed ? 1 : 0;
}

int cmd_remove(const std::vector<std::string>& args) {
    const Parsed parsed = parse_arguments(
        args, {"--remove-cache", "--purge-data", "--yes"}, {}, false,
        kRemoveUsage);
    require_positionals(parsed, 1, kRemoveUsage);
    const std::string& id = parsed.positionals[0];
    const bool purge = parsed.flags.count("--purge-data") != 0;
    const bool remove_cache = parsed.flags.count("--remove-cache") != 0;

    // Purge is a superset of remove-cache. Data removal happens ONLY on the
    // explicit --purge-data flag; --yes confirms the prompt but never widens
    // the scope to include persistent data (runtime-trust WS8).
    using Mode = Installer::UninstallMode;
    const Mode mode = purge          ? Mode::PurgeData
                      : remove_cache ? Mode::AppAndCache
                                     : Mode::AppOnly;

    const Paths paths = Paths::detect();
    const Registry registry(paths);
    if (!registry.is_installed(id)) {
        throw NotFoundError("application not installed: " + id);
    }
    if (parsed.flags.count("--yes") == 0) {
        std::string question;
        switch (mode) {
        case Mode::PurgeData:
            question = "Remove " + id + " and permanently delete its data?";
            break;
        case Mode::AppAndCache:
            question = "Remove " + id + " and its cache (data preserved)?";
            break;
        case Mode::AppOnly:
            question = "Remove " + id + "?";
            break;
        }
        if (!confirm(question)) {
            // Declining the prompt is a valid user choice, not an error.
            std::cerr << "removal cancelled\n";
            return 0;
        }
    }
    Installer(paths).uninstall(id, mode);
    switch (mode) {
    case Mode::PurgeData:
        std::cout << "Removed " << id << " (application data purged)\n";
        break;
    case Mode::AppAndCache:
        std::cout << "Removed " << id << " (cache cleared; data preserved)\n";
        break;
    case Mode::AppOnly:
        std::cout << "Removed " << id << "\n";
        // Report retained data so the user knows a later reinstall inherits it,
        // and how to reclaim the space (WS8 reinstall/orphaned-data behavior).
        if (registry.has_retained_data(id)) {
            std::cout << "  Application data retained; reinstalling " << id
                      << " will reuse it. Use `lexe remove " << id
                      << " --purge-data` to delete it.\n";
        }
        break;
    }
    return 0;
}

int cmd_repair(const std::vector<std::string>& args) {
    const Parsed parsed = parse_arguments(args, {}, {}, false, kRepairUsage);
    require_positionals(parsed, 1, kRepairUsage);
    const std::string& id = parsed.positionals[0];

    Installer installer(Paths::detect());
    const RepairReport report = installer.repair(id);
    if (report.ok) {
        if (report.repaired_files.empty()) {
            std::cout << id << " is healthy; nothing to repair\n";
        } else {
            std::cout << "Repaired " << report.repaired_files.size()
                      << " file(s) of " << id << ":\n";
            for (const std::string& file : report.repaired_files) {
                std::cout << "  " << file << "\n";
            }
        }
        return 0;
    }
    throw VerificationError(
        id + " has " + std::to_string(report.corrupt_files.size()) +
        " corrupt or missing file(s) that could not be repaired: " +
        join(report.corrupt_files, ", ") +
        " (reinstall from the original package to repair)");
}

// A directory plus every subdirectory under it (bounded), used as dependency
// search paths so an app's own bundled libraries resolve first.
std::vector<fs::path> gather_dirs(const fs::path& root) {
    std::vector<fs::path> dirs{root};
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(root, ec);
         it != fs::recursive_directory_iterator() && dirs.size() < 4096;
         it.increment(ec)) {
        if (it->is_directory(ec)) dirs.push_back(it->path());
    }
    return dirs;
}

// The likely main executable in a payload directory: a dynamically linked ELF
// executable/PIE (has a program interpreter). Deterministic (first by path).
fs::path find_main_executable(const fs::path& dir) {
    std::error_code ec;
    std::vector<fs::path> found;
    for (auto it = fs::recursive_directory_iterator(dir, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (!it->is_regular_file(ec)) continue;
        const elf::ElfInfo info = elf::read(it->path());
        if (info.is_elf && info.has_interpreter) found.push_back(it->path());
    }
    std::sort(found.begin(), found.end());
    return found.empty() ? fs::path() : found.front();
}

// A CLI target resolved to the root binary and its dependency search paths.
// For a project folder, identity fields are filled from the manifest.
struct ResolvedTarget {
    fs::path root;
    std::vector<fs::path> search;
    std::string app_name, app_id, app_version;
    std::vector<std::string> permissions;
};

// Resolve a positional target — a binary, a project folder (lexe.json +
// payload/), or a payload directory — to its root executable and the search
// paths its bundled libraries resolve against. Shared by `analyze` and
// `sdk verify` so both walk the exact same discovery path. Throws
// NotFoundError; `noun` names the command in the "nothing found" message.
ResolvedTarget resolve_binary_target(const fs::path& target, const char* noun) {
    ResolvedTarget out;
    std::error_code ec;
    if (fs::is_regular_file(target, ec)) {
        out.root = target;
        if (target.has_parent_path()) {
            out.search = gather_dirs(target.parent_path());
        }
    } else if (fs::is_directory(target, ec)) {
        fs::path payload = target;
        const fs::path manifest_file = target / "lexe.json";
        if (fs::is_regular_file(manifest_file, ec) &&
            fs::is_directory(target / "payload", ec)) {
            payload = target / "payload";
            try {
                const Manifest m = Manifest::parse(util::slurp(manifest_file));
                out.app_name = m.name;
                out.app_id = m.id;
                out.app_version = m.version;
                out.permissions = m.permissions;
                out.root = payload / fs::path(m.entrypoint_executable);
            } catch (const Error&) {
                // Fall back to auto-detection below.
            }
        }
        out.search = gather_dirs(payload);
        if (out.root.empty() || !fs::is_regular_file(out.root, ec)) {
            out.root = find_main_executable(payload);
        }
        if (out.root.empty()) {
            throw NotFoundError("no ELF executable found under " +
                                payload.string() + " (point `lexe " + noun +
                                "` at a binary, a project folder, or a payload "
                                "directory)");
        }
    } else {
        throw NotFoundError("no such file or directory: " + target.string());
    }
    return out;
}

int cmd_analyze(const std::vector<std::string>& args) {
    const Parsed parsed =
        parse_arguments(args, {"--json"}, {"--profile"}, false, kAnalyzeUsage);
    require_positionals(parsed, 1, kAnalyzeUsage);
    const fs::path target(parsed.positionals[0]);

    RuntimeProfile profile = RuntimeProfile::CorePortable;
    const auto pf = parsed.options.find("--profile");
    if (pf != parsed.options.end()) {
        profile = runtime_profile_from_string(pf->second); // UsageError on bad id
    }

    const ResolvedTarget t = resolve_binary_target(target, "analyze");
    const fs::path& root = t.root;
    const std::string& app_name = t.app_name;
    const std::string& app_id = t.app_id;
    const std::string& app_version = t.app_version;
    const std::vector<std::string>& permissions = t.permissions;

    DependencyOptions opts;
    opts.payload_search_paths = t.search;
    DependencyReport deps = analyze_dependencies(root, opts);
    if (!deps.root_info.is_elf) {
        throw Error(root.string() +
                    " is not an ELF binary; `lexe analyze` inspects native "
                    "executables");
    }

    BuildReport report = assemble_report(std::move(deps), profile);
    report.app_name = app_name;
    report.app_id = app_id;
    report.app_version = app_version;
    report.permissions = permissions;

    if (parsed.flags.count("--json") != 0) {
        std::cout << build_report_json(report).dump(2) << "\n";
    } else {
        std::cout << render_build_report_text(report);
        if (!report.profile_assessment.warnings.empty()) {
            std::cout << "Profile notes (" << runtime_profile_info(profile).name
                      << "):\n";
            for (const std::string& w : report.profile_assessment.warnings) {
                std::cout << "  ! " << w << "\n";
            }
        }
    }
    return 0; // analysis is informational; the report content conveys issues
}

// ---------------------------------------------------------------- sdk verify

// Resolve a `--profile <id>` to a Tux32 profile. Core 1 is the only shipped
// profile; an unknown id is a UsageError (speculative profiles are refused).
const Tux32Profile& sdk_profile_for(const std::string& id) {
    if (id == "tux32-core-1" || id == "core-1") return tux32_core_1();
    throw UsageError("unknown Tux32 profile \"" + id +
                     "\" (supported: tux32-core-1)");
}

// The sdk-verify result as JSON — a machine-consumable superset of the human
// report. Automation switches on "verdict"; "conformant" is the boolean gate.
ordered_json sdk_verify_json(const fs::path& target,
                             const Tux32Profile& profile,
                             const Core1VerifyResult& r) {
    ordered_json j;
    j["tool"] = "lexe sdk verify";
    j["profile"] = {
        {"id", profile.id},
        {"specVersion", profile.spec_version},
        {"executableFormat", profile.executable_format},
        {"cpuBaseline", profile.cpu_baseline},
        {"glibcCeiling", profile.glibc_ceiling()},
    };
    j["target"] = target.string();
    j["executable"] = r.selected_executable;
    j["architecture"] = r.architecture;
    j["verdict"] = to_string(r.verdict);
    j["conformant"] = r.conformant();
    j["requiredGlibc"] = r.required_glibc; // "" when nothing declares a need
    ordered_json offenders = ordered_json::array();
    for (const Core1Offender& o : r.symbol_offenders) {
        offenders.push_back({{"object", o.object}, {"version", o.version}});
    }
    j["symbolOffenders"] = std::move(offenders);
    j["bundle"] = r.bundle_candidates;
    j["hostInterfaces"] = r.host_interfaces;
    j["forbidden"] = r.forbidden;
    j["unresolved"] = r.unresolved;
    j["notes"] = r.notes;
    j["detail"] = r.detail;
    return j;
}

void render_sdk_verify_text(std::ostream& os, const Tux32Profile& profile,
                            const Core1VerifyResult& r) {
    const auto list = [&](const char* label,
                          const std::vector<std::string>& items) {
        if (items.empty()) return;
        os << label << ":\n";
        for (const std::string& s : items) os << "    " << s << "\n";
    };

    os << "Tux32 " << profile.id << " verification (spec " << profile.spec_version
       << ")\n";
    os << "  executable:    " << r.selected_executable << "\n";
    os << "  architecture:  "
       << (r.architecture.empty() ? std::string("unknown") : r.architecture)
       << "\n";
    os << "  cpu baseline:  " << profile.cpu_baseline << "\n";
    os << "  glibc ceiling: " << r.glibc_ceiling << "\n";
    if (!r.required_glibc.empty()) {
        os << "  requires glibc: " << r.required_glibc << "\n";
    }
    os << "\n  VERDICT: " << to_string(r.verdict) << "\n";
    os << "  " << r.detail << "\n\n";

    if (!r.symbol_offenders.empty()) {
        os << "Objects above the glibc ceiling:\n";
        for (const Core1Offender& o : r.symbol_offenders) {
            os << "    " << o.object << "  needs " << o.version << "\n";
        }
    }
    list("Libraries to bundle", r.bundle_candidates);
    list("Host-provided interfaces (not bundled)", r.host_interfaces);
    list("Forbidden (host driver) interfaces", r.forbidden);
    list("Unresolved dependencies", r.unresolved);
    if (!r.notes.empty()) {
        os << "Notes:\n";
        for (const std::string& n : r.notes) os << "  ! " << n << "\n";
    }
}

int cmd_sdk_verify(const std::vector<std::string>& args) {
    const Parsed parsed =
        parse_arguments(args, {"--json"}, {"--profile"}, false, kSdkUsage);
    require_positionals(parsed, 1, kSdkUsage);
    const fs::path target(parsed.positionals[0]);

    std::string profile_id = "tux32-core-1";
    const auto pf = parsed.options.find("--profile");
    if (pf != parsed.options.end()) profile_id = pf->second;
    const Tux32Profile& profile = sdk_profile_for(profile_id);

    // ONE dependency-analysis path: resolve exactly as `analyze` does, run the
    // shared dependency engine, then verify the resulting report — no second
    // analyzer, and the build host never becomes the compatibility target.
    const ResolvedTarget t = resolve_binary_target(target, "sdk verify");
    DependencyOptions opts;
    opts.payload_search_paths = t.search;
    const DependencyReport deps = analyze_dependencies(t.root, opts);
    const Core1VerifyResult r = verify_against_profile(deps, profile);

    if (parsed.flags.count("--json") != 0) {
        std::cout << sdk_verify_json(target, profile, r).dump(2) << "\n";
    } else {
        render_sdk_verify_text(std::cout, profile, r);
    }

    // Typed exit: 0 = conformant (the ONLY case a build may claim the profile);
    // 3 = a non-conformant verdict (a verification failure, matching the tool's
    // exit-code model). The precise reason is the typed `verdict` in the output.
    return r.conformant() ? 0 : 3;
}

constexpr const char* kVersionUsage = "usage: lexe version [--json]";

// Report the platform's DISTINCT version axes: the runtime/CLI build version,
// the .lexe package-format version, and the Tux32 baseline. They evolve
// independently and are never conflated (Alpha requirement).
int cmd_version(const std::vector<std::string>& args) {
    const Parsed parsed =
        parse_arguments(args, {"--json"}, {}, false, kVersionUsage);
    require_positionals(parsed, 0, kVersionUsage);
    const Tux32Profile& t = tux32_core_1();

    if (parsed.flags.count("--json") != 0) {
        ordered_json j;
        j["runtime"] = version::runtime_string();
        j["runtimeVersion"] = version::kRuntime;
        j["stage"] = version::kStage;
        j["packageFormat"] = version::kPackageFormat;
        j["tux32Baseline"] = {{"id", t.id}, {"specVersion", t.spec_version}};
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "lexe " << version::runtime_string() << "\n";
        std::cout << "  runtime:        " << version::runtime_string() << "\n";
        std::cout << "  package format: " << version::kPackageFormat
                  << " (.lexe FORMAT-0.1)\n";
        std::cout << "  Tux32 baseline: " << t.id << " (spec " << t.spec_version
                  << ")\n";
    }
    return 0;
}

constexpr const char* kCompletionUsage = "usage: lexe completion [bash]";

// Shell-completion groundwork (DX6): emit a minimal, dependency-free bash
// completion for the top-level commands. `source <(lexe completion bash)`.
int cmd_completion(const std::vector<std::string>& args) {
    const Parsed parsed =
        parse_arguments(args, {}, {}, false, kCompletionUsage);
    const std::string shell =
        parsed.positionals.empty() ? "bash" : parsed.positionals[0];
    if (shell != "bash") {
        throw UsageError("unsupported shell \"" + shell +
                         "\" (supported: bash)\n" + kCompletionUsage);
    }
    std::cout <<
        "# lexe bash completion. Load it with:\n"
        "#   source <(lexe completion bash)\n"
        "_lexe() {\n"
        "  local cur cmds\n"
        "  cur=\"${COMP_WORDS[COMP_CWORD]}\"\n"
        "  cmds=\"install run list info inspect update rollback repair remove gc \\\n"
        "        build analyze sdk pack keygen sign-update verify trust source \\\n"
        "        apps config integrate completion version help\"\n"
        "  if [ \"$COMP_CWORD\" -eq 1 ]; then\n"
        "    COMPREPLY=( $(compgen -W \"$cmds\" -- \"$cur\") )\n"
        "  fi\n"
        "}\n"
        "complete -F _lexe lexe\n";
    return 0;
}

int cmd_sdk(const std::vector<std::string>& args) {
    if (args.empty()) throw UsageError(kSdkUsage);
    const std::string& sub = args[0];
    const std::vector<std::string> rest(args.begin() + 1, args.end());
    if (sub == "verify") return cmd_sdk_verify(rest);
    throw UsageError("unknown sdk subcommand \"" + sub + "\"\n" + kSdkUsage);
}

int cmd_info(const std::vector<std::string>& args) {
    const Parsed parsed =
        parse_arguments(args, {"--json"}, {}, false, kInfoUsage);
    require_positionals(parsed, 1, kInfoUsage);
    const std::string& target = parsed.positionals[0];
    const bool as_json = parsed.flags.count("--json") != 0;

    std::error_code ec;
    if (fs::is_regular_file(target, ec)) {
        // Package mode: structure/§5 problems surface as VerificationError.
        const PackageReader reader(target);
        const Manifest manifest =
            Manifest::parse(reader.read_entry("lexe.json"));
        const std::uint64_t size = display_size(manifest, reader);

        const Fingerprint fp = key_fingerprint(manifest.decoded_public_key());
        if (as_json) {
            ordered_json j;
            j["source"] = "package";
            j["package"] = {
                {"path", fs::path(target).string()},
                {"fileSize", static_cast<std::uint64_t>(fs::file_size(target))},
                {"payloadSize", payload_size(reader)},
            };
            j["signingKey"] = manifest.publisher_public_key;
            j["fingerprint"] = {
                {"full", fp.full}, {"grouped", fp.grouped}, {"short", fp.short_id}};
            j["identityVerified"] = false;
            j["manifest"] = manifest_json(manifest);
            std::cout << j.dump(2) << "\n";
        } else {
            std::cout << "Package: " << target << " ("
                      << format_size(
                             static_cast<std::uint64_t>(fs::file_size(target)))
                      << ")\n";
            print_manifest_info(manifest, size);
            print_kv("Signing key:", fp.grouped);
            std::cout << "  (a valid signature proves consistency with this key, "
                         "not the publisher's real-world identity)\n";
        }
        return 0;
    }

    // Installed mode.
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    if (!registry.is_installed(target)) {
        throw NotFoundError("no such package file or installed application: " +
                            target);
    }
    const Manifest manifest = registry.read_manifest(target);
    const InstallationRecord record = registry.read_record(target);
    const std::string current = registry.current_version(target);
    std::vector<std::string> versions = registry.installed_versions(target);
    std::sort(versions.begin(), versions.end(),
              [](const std::string& a, const std::string& b) {
                  return version_less(a, b);
              });

    // Local trust state (never presented as external identity verification).
    std::optional<TrustRecord> trust;
    std::string trust_state = "first-seen";
    try {
        trust = TrustStore(paths).read(target);
        trust_state = local_key_state_label(trust);
        if (trust_state == "no-record") trust_state = "first-seen";
    } catch (const CorruptTrustError&) {
        trust_state = "corrupt";
    }
    const Fingerprint fp = key_fingerprint(manifest.decoded_public_key());

    if (as_json) {
        ordered_json j;
        j["source"] = "installed";
        j["installed"] = {
            {"id", record.id},
            {"version", current},
            {"versions", versions},
            {"channel", record.channel},
            {"packageSource", record.source},
            {"updateUrl", record.update_url},
            {"installedAt", record.installed_at},
            {"lastRunAt", record.last_run_at},
            {"lastExitCode", record.last_exit_code},
        };
        j["signingKey"] = record.publisher_key;
        j["fingerprint"] = {
            {"full", fp.full}, {"grouped", fp.grouped}, {"short", fp.short_id}};
        j["localTrust"] = {
            {"state", trust_state},
            {"blocked", trust.has_value() && trust->blocked},
            {"explicitlyTrusted", trust.has_value() && trust->explicitly_trusted},
            {"identityVerified", false},
        };
        j["manifest"] = manifest_json(manifest);
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "Installed application: " << record.id << "\n";
        print_manifest_info(manifest, manifest.install_estimated_size);
        print_kv("Current:", current);
        print_kv("Versions:", join(versions, ", "));
        print_kv("Signing key:", fp.grouped);
        print_kv("Local trust:",
                 trust_state == "blocked"
                     ? "BLOCKED locally"
                     : trust_state == "explicitly-trusted"
                           ? "explicitly trusted locally (not external identity)"
                           : trust_state == "corrupt"
                                 ? "CORRUPT (fail closed)"
                                 : trust_state == "known"
                                       ? "known key, accepted for this App ID"
                                       : "first-seen (identity not verified)");
        print_kv("Channel:", record.channel);
        print_kv("Source:", record.source);
        print_kv("Update source:",
                 record.update_url.empty() ? "(none)" : record.update_url);
        print_kv("Installed at:", record.installed_at);
        print_kv("Last run:",
                 record.last_run_at.empty()
                     ? "(never)"
                     : record.last_run_at + " (exit " +
                           std::to_string(record.last_exit_code) + ")");
    }
    return 0;
}

int cmd_verify(const std::vector<std::string>& args) {
    const Parsed parsed =
        parse_arguments(args, {"--json"}, {}, false, kVerifyUsage);
    require_positionals(parsed, 1, kVerifyUsage);
    const std::string& file = parsed.positionals[0];

    const VerificationReport report =
        verify_package(file, /*check_architecture=*/false);
    const SignatureState sig = signature_state_from_report(report);

    // The signing key + fingerprint, when the package parsed far enough to
    // expose it. This is AUTHENTICITY only — it says nothing about the
    // publisher's real-world identity or local trust for any App ID.
    std::optional<Fingerprint> fp;
    std::string signing_key;
    std::error_code fec;
    if (fs::is_regular_file(file, fec)) {
        try {
            const Manifest m = Manifest::parse(PackageReader(file).read_entry("lexe.json"));
            signing_key = m.publisher_public_key;
            fp = key_fingerprint(m.decoded_public_key());
        } catch (const Error&) {
        }
    }

    if (parsed.flags.count("--json") != 0) {
        ordered_json j;
        j["file"] = file;
        j["ok"] = report.ok();
        j["signatureState"] = to_string(sig);
        if (fp.has_value()) {
            j["signingKey"] = signing_key;
            j["fingerprint"] = {{"full", fp->full},
                                {"grouped", fp->grouped},
                                {"short", fp->short_id}};
        }
        j["identityVerified"] = false;
        j["note"] = "Verification checks package integrity and signature "
                    "(authenticity), NOT the publisher's real-world identity.";
        ordered_json stages = ordered_json::array();
        for (const VerificationStage& stage : report.stages) {
            stages.push_back({{"name", stage.name},
                              {"ok", stage.ok},
                              {"detail", stage.detail}});
        }
        j["stages"] = std::move(stages);
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "Verifying " << file << "\n";
        for (const VerificationStage& stage : report.stages) {
            std::cout << "  " << (stage.ok ? "[ ok ]" : "[FAIL]") << " "
                      << std::left << std::setw(18) << stage.name << " "
                      << stage.detail << "\n";
        }
        if (report.ok()) {
            std::cout << "verification: OK (signature valid, Ed25519)\n";
            if (fp.has_value()) {
                std::cout << "signing key fingerprint: " << fp->grouped << "\n";
            }
            std::cout << "note: this proves package integrity + signature, NOT "
                         "the publisher's real-world identity.\n";
        } else {
            const VerificationStage* failure = report.first_failure();
            std::cout << "verification: FAILED ("
                      << (failure != nullptr ? failure->name : "unknown")
                      << ")\n";
        }
    }
    return report.ok() ? 0 : 3;
}

int cmd_source(const std::vector<std::string>& args) {
    if (args.empty() || args[0] != "set") {
        throw UsageError(std::string("unknown source subcommand\n") +
                         kSourceUsage);
    }
    const Parsed parsed = parse_arguments(
        std::vector<std::string>(args.begin() + 1, args.end()), {}, {}, false,
        kSourceUsage);
    require_positionals(parsed, 2, kSourceUsage);
    const std::string& id = parsed.positionals[0];
    const std::string& url = parsed.positionals[1];

    Updater(Paths::detect()).set_source(id, url);
    std::cout << "Update source for " << id << " set to " << url << "\n";
    return 0;
}

int cmd_rollback(const std::vector<std::string>& args) {
    const Parsed parsed = parse_arguments(args, {}, {}, false, kRollbackUsage);
    require_positionals(parsed, 1, kRollbackUsage);
    const std::string& id = parsed.positionals[0];

    const Paths paths = Paths::detect();
    Installer(paths).rollback(id);
    std::cout << "Rolled back " << id << " to "
              << Registry(paths).current_version(id) << "\n";
    return 0;
}

int cmd_gc(const std::vector<std::string>& args) {
    const Parsed parsed =
        parse_arguments(args, {}, {"--keep"}, false, kGcUsage);
    require_positionals(parsed, 1, kGcUsage);
    const std::string& id = parsed.positionals[0];

    std::size_t keep = 1; // keep active + one rollback-reachable version
    const auto keep_opt = parsed.options.find("--keep");
    if (keep_opt != parsed.options.end()) {
        try {
            keep = static_cast<std::size_t>(std::stoul(keep_opt->second));
        } catch (const std::exception&) {
            throw UsageError(std::string("lexe gc: --keep expects a "
                                         "non-negative integer\n") +
                             kGcUsage);
        }
    }

    const Paths paths = Paths::detect();
    const GcReport report =
        Installer(paths).garbage_collect(id, keep); // NotFoundError

    std::cout << "Cleaned up " << id << ": " << report.removed.size()
              << " version(s) removed, " << report.retained.size()
              << " retained";
    if (!report.skipped_in_use.empty()) {
        std::cout << ", " << report.skipped_in_use.size() << " in use";
    }
    if (!report.failed.empty()) {
        std::cout << ", " << report.failed.size() << " failed";
    }
    std::cout << "\n";
    for (const std::string& v : report.removed) {
        std::cout << "  removed " << v << "\n";
    }
    for (const std::string& v : report.skipped_in_use) {
        std::cout << "  kept (in use) " << v << "\n";
    }
    for (const std::string& v : report.failed) {
        std::cout << "  could not remove " << v << "\n";
    }
    // A removal failure is a soft error: the active install is intact, but the
    // reclaim did not fully succeed.
    return report.failed.empty() ? 0 : 1;
}

// Acquire the per-app mutation lock for a trust mutation (runtime-trust WS9):
// trust writes serialize with install/update/rollback/remove of the same id.
// The returned AppLock owns the OS lock independently of the temporary manager.
AppLock trust_mutation_lock(const Paths& paths, const std::string& id) {
    return make_lock_manager(paths)->lock_app_mutation(
        id, "trust", WaitPolicy::bounded(std::chrono::seconds(10)));
}

int cmd_trust_show(const std::string& id, bool as_json) {
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const bool installed = registry.is_installed(id);

    std::optional<TrustRecord> rec;
    std::string corrupt_reason;
    try {
        rec = TrustStore(paths).read(id);
    } catch (const CorruptTrustError& e) {
        corrupt_reason = e.what();
    }

    const char* kNote =
        "Local trust-on-first-use: a valid signature proves the package is "
        "consistent with this key, NOT the publisher's real-world identity.";

    if (as_json) {
        ordered_json j;
        j["appId"] = id;
        j["installed"] = installed;
        if (!corrupt_reason.empty()) {
            j["localKeyState"] = "corrupt";
            j["detail"] = corrupt_reason;
        } else if (!rec.has_value()) {
            j["localKeyState"] = "first-seen"; // nothing recorded yet
        } else {
            j["localKeyState"] = local_key_state_label(rec);
            j["blocked"] = rec->blocked;
            j["explicitlyTrusted"] = rec->explicitly_trusted;
            if (!rec->public_key.empty()) {
                const Fingerprint fp = key_fingerprint(rec->public_key);
                j["signingKey"] = rec->public_key;
                j["fingerprint"] = {{"full", fp.full},
                                    {"grouped", fp.grouped},
                                    {"short", fp.short_id}};
            }
            j["firstSeen"] = rec->first_seen;
            j["lastSeen"] = rec->last_seen;
            if (rec->blocked) j["blockedAt"] = rec->blocked_at;
            if (rec->explicitly_trusted) j["trustProvenance"] = rec->trust_provenance;
        }
        j["identityVerified"] = false; // never externally verified
        j["note"] = kNote;
        std::cout << j.dump(2) << "\n";
        return 0;
    }

    std::cout << "Application: " << id << "\n";
    std::cout << "Installed:   " << (installed ? "yes" : "no") << "\n";
    if (!corrupt_reason.empty()) {
        std::cout << "Local trust: CORRUPT — refusing to use it (fail closed)\n"
                  << "  " << corrupt_reason << "\n";
        return 0;
    }
    if (!rec.has_value()) {
        std::cout << "Local trust: no record — a package would be FIRST-SEEN "
                     "(publisher identity not independently verified)\n";
        return 0;
    }
    if (rec->blocked) {
        std::cout << "Local trust: BLOCKED locally"
                  << (rec->blocked_at.empty() ? "" : " since " + rec->blocked_at)
                  << " — install, update and launch are refused\n";
    } else if (rec->explicitly_trusted) {
        std::cout << "Local trust: explicitly trusted locally (a local decision, "
                     "not external identity verification)\n";
    } else {
        std::cout << "Local trust: known key, accepted for this App ID\n";
    }
    if (!rec->public_key.empty()) {
        const Fingerprint fp = key_fingerprint(rec->public_key);
        std::cout << "Signing key fingerprint:\n  " << fp.grouped << "\n";
    }
    if (!rec->first_seen.empty()) std::cout << "First seen:  " << rec->first_seen << "\n";
    if (!rec->last_seen.empty()) std::cout << "Last seen:   " << rec->last_seen << "\n";
    std::cout << kNote << "\n";
    return 0;
}

int cmd_trust(const std::vector<std::string>& args) {
    if (args.empty()) {
        throw UsageError(std::string("missing trust subcommand\n") + kTrustUsage);
    }
    const std::string sub = args[0];
    const std::vector<std::string> rest(args.begin() + 1, args.end());
    const Paths paths = Paths::detect();

    if (sub == "show") {
        const Parsed p = parse_arguments(rest, {"--json"}, {}, false, kTrustUsage);
        require_positionals(p, 1, kTrustUsage);
        return cmd_trust_show(p.positionals[0], p.flags.count("--json") != 0);
    }
    if (sub == "block") {
        const Parsed p = parse_arguments(rest, {}, {}, false, kTrustUsage);
        require_positionals(p, 1, kTrustUsage);
        const std::string& id = p.positionals[0];
        const AppLock lock = trust_mutation_lock(paths, id);
        TrustStore(paths).block(id);
        std::cout << "Blocked " << id
                  << " locally — install, update and launch are now refused "
                     "(this is a LOCAL block, not a global revocation)\n";
        return 0;
    }
    if (sub == "unblock") {
        const Parsed p = parse_arguments(rest, {}, {}, false, kTrustUsage);
        require_positionals(p, 1, kTrustUsage);
        const std::string& id = p.positionals[0];
        const AppLock lock = trust_mutation_lock(paths, id);
        TrustStore(paths).unblock(id); // NotFoundError when nothing to unblock
        std::cout << "Unblocked " << id << " locally\n";
        return 0;
    }
    if (sub == "forget") {
        const Parsed p =
            parse_arguments(rest, {"--force"}, {}, false, kTrustUsage);
        require_positionals(p, 1, kTrustUsage);
        const std::string& id = p.positionals[0];
        const bool force = p.flags.count("--force") != 0;
        const AppLock lock = trust_mutation_lock(paths, id);
        const Registry registry(paths);
        const bool installed = registry.is_installed(id);
        const bool retained = registry.has_retained_data(id);
        if ((installed || retained) && !force) {
            throw UsageError(
                "refusing to forget local trust for " + id + " while it is " +
                (installed ? "still installed" : "holding retained data") +
                ". Remove it first (`lexe remove " + id +
                (retained ? " --purge-data" : "") +
                "`), or pass --force to forget trust anyway.");
        }
        TrustStore(paths).forget(id);
        std::cout << "Forgot local trust history for " << id << "\n";
        return 0;
    }
    throw UsageError("unknown trust subcommand: " + sub + "\n" + kTrustUsage);
}

int cmd_list(const std::vector<std::string>& args) {
    const Parsed parsed =
        parse_arguments(args, {"--json"}, {}, false, kListUsage);
    require_positionals(parsed, 0, kListUsage);

    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const std::vector<std::string> ids = registry.list_installed();

    if (parsed.flags.count("--json") != 0) {
        ordered_json j = ordered_json::array();
        for (const std::string& id : ids) {
            const InstallationRecord record = registry.read_record(id);
            std::string name;
            try {
                name = registry.read_manifest(id).name;
            } catch (const Error&) {
                // manifest.json copy unreadable: list the app anyway.
            }
            j.push_back({{"id", id},
                         {"name", name},
                         {"version", record.version},
                         {"channel", record.channel},
                         {"updateUrl", record.update_url},
                         {"installedAt", record.installed_at}});
        }
        std::cout << j.dump(2) << "\n";
        return 0;
    }

    if (ids.empty()) {
        std::cout << "no applications installed\n";
        return 0;
    }
    std::size_t id_width = 2;      // "ID"
    std::size_t version_width = 7; // "VERSION"
    struct Row {
        std::string id, version, name;
    };
    std::vector<Row> rows;
    for (const std::string& id : ids) {
        const InstallationRecord record = registry.read_record(id);
        std::string name;
        try {
            name = registry.read_manifest(id).name;
        } catch (const Error&) {
        }
        id_width = std::max(id_width, id.size());
        version_width = std::max(version_width, record.version.size());
        rows.push_back({id, record.version, name});
    }
    std::cout << std::left << std::setw(static_cast<int>(id_width)) << "ID"
              << "  " << std::setw(static_cast<int>(version_width))
              << "VERSION"
              << "  "
              << "NAME"
              << "\n";
    for (const Row& row : rows) {
        std::cout << std::left << std::setw(static_cast<int>(id_width))
                  << row.id << "  "
                  << std::setw(static_cast<int>(version_width)) << row.version
                  << "  " << row.name << "\n";
    }
    return 0;
}

int cmd_keygen(const std::vector<std::string>& args) {
    const Parsed parsed = parse_arguments(args, {}, {}, false, kKeygenUsage);
    require_positionals(parsed, 1, kKeygenUsage);
    const fs::path keyfile(parsed.positionals[0]);

    std::error_code ec;
    if (fs::exists(keyfile, ec)) {
        throw Error("refusing to overwrite existing key file: " +
                    keyfile.string());
    }
    const crypto::KeyPair key = crypto::generate_keypair();
    crypto::write_keyfile(keyfile, key);
    // The private seed is never printed (security invariant #5).
    std::cout << "Generated Ed25519 keypair.\n"
              << "Key file:   " << keyfile.string() << "\n"
              << "Public key: " << crypto::encode_public_key(key.public_key)
              << "\n";
    return 0;
}

int cmd_pack(const std::vector<std::string>& args) {
    const Parsed parsed = parse_arguments(
        args, {}, {"--manifest", "--key", "-o", "--icons", "--metadata"},
        false, kPackUsage);
    require_positionals(parsed, 1, kPackUsage);

    PackageWriter::Inputs inputs;
    inputs.payload_dir = fs::path(parsed.positionals[0]);
    inputs.manifest_file =
        fs::path(require_option(parsed, "--manifest", kPackUsage));
    const fs::path keyfile(require_option(parsed, "--key", kPackUsage));
    const fs::path out(require_option(parsed, "-o", kPackUsage));
    const auto icons = parsed.options.find("--icons");
    if (icons != parsed.options.end()) inputs.icons_dir = fs::path(icons->second);
    const auto metadata = parsed.options.find("--metadata");
    if (metadata != parsed.options.end()) {
        inputs.metadata_dir = fs::path(metadata->second);
    }

    const crypto::KeyPair key = crypto::read_keyfile(keyfile);
    // Full FORMAT-0.1 §5 validation is the CLI's job (the package module only
    // requires well-formed JSON), and a manifest whose publisher key is not
    // the signing key would produce a package that can never verify.
    const Manifest manifest = Manifest::parse(util::slurp(inputs.manifest_file));
    if (manifest.decoded_public_key() != key.public_key) {
        throw Error("manifest publisher.publicKey (" +
                    manifest.publisher_public_key +
                    ") does not match the signing key (" +
                    crypto::encode_public_key(key.public_key) +
                    "); the package would fail verification");
    }

    PackageWriter::write(inputs, key, out);
    std::cout << "Packed " << out.string() << " ("
              << format_size(static_cast<std::uint64_t>(fs::file_size(out)))
              << ")\n";
    return 0;
}

int cmd_build(const std::vector<std::string>& args) {
    const Parsed parsed =
        parse_arguments(args, {}, {"-o", "--key"}, false, kBuildUsage);
    require_positionals(parsed, 1, kBuildUsage);
    const fs::path project(parsed.positionals[0]);

    if (!fs::is_directory(project)) {
        throw NotFoundError("no such project directory: " + project.string());
    }
    // A Lexe project folder is: lexe.json + payload/ (+ optional icons/,
    // metadata/). "Drop your app files into payload/, describe them in
    // lexe.json, then `lexe build`."
    const fs::path manifest_file = project / "lexe.json";
    const fs::path payload_dir = project / "payload";
    if (!fs::is_regular_file(manifest_file)) {
        throw Error("project is missing lexe.json: " + manifest_file.string() +
                    "\n  a Lexe project folder holds lexe.json plus a payload/ "
                    "directory");
    }
    if (!fs::is_directory(payload_dir)) {
        throw Error("project is missing a payload/ directory: " +
                    payload_dir.string() +
                    "\n  put the application's files under payload/");
    }

    // Resolve the signing key: --key, else <project>/key.json, else generate
    // one there. The signing key is the application's durable identity — every
    // future update must be signed with it (FORMAT-0.1 §7.1).
    fs::path keyfile;
    bool generated_key = false;
    const auto key_opt = parsed.options.find("--key");
    if (key_opt != parsed.options.end()) {
        keyfile = fs::path(key_opt->second);
        if (!fs::is_regular_file(keyfile)) {
            throw NotFoundError("no such key file: " + keyfile.string());
        }
    } else {
        keyfile = project / "key.json";
        if (!fs::exists(keyfile)) {
            crypto::write_keyfile(keyfile, crypto::generate_keypair());
            generated_key = true;
        }
    }
    const crypto::KeyPair key = crypto::read_keyfile(keyfile);
    const std::string pubkey = crypto::encode_public_key(key.public_key);

    // Fill in publisher.publicKey when it is blank or the literal "AUTO": the
    // manifest key must equal the signing key, and hand-copying a freshly
    // generated key is exactly the friction a builder should remove.
    // Strict parse (HARDENING.md §E): even on the authoring side, a manifest
    // with duplicate keys must be rejected rather than silently rewritten.
    ordered_json doc = json_strict::parse_ordered(
        util::slurp_text(manifest_file), "manifest", limits::kMaxManifestBytes);
    bool injected_key = false;
    if (doc.is_object()) {
        std::string existing;
        if (doc.contains("publisher") && doc["publisher"].is_object() &&
            doc["publisher"].contains("publicKey") &&
            doc["publisher"]["publicKey"].is_string()) {
            existing = doc["publisher"]["publicKey"].get<std::string>();
        }
        if (existing.empty() || existing == "AUTO") {
            doc["publisher"]["publicKey"] = pubkey;
            util::spit(manifest_file, std::string_view(doc.dump(2) + "\n"));
            injected_key = true;
        }
    }

    // Validate the manifest (friendly early error) and confirm the publisher
    // key matches the signing key — otherwise the package can never verify.
    const Manifest manifest = Manifest::parse(util::slurp(manifest_file));
    if (manifest.decoded_public_key() != key.public_key) {
        throw Error(
            "manifest publisher.publicKey (" + manifest.publisher_public_key +
            ") does not match the signing key (" + pubkey +
            "); set publicKey to \"AUTO\" (or remove it) to have `lexe build` "
            "fill it in from --key");
    }

    fs::path out;
    const auto out_opt = parsed.options.find("-o");
    if (out_opt != parsed.options.end()) {
        out = fs::path(out_opt->second);
    } else {
        std::string base = project.filename().string();
        if (base.empty() || base == ".") base = manifest.id;
        out = fs::path(base + ".lexe");
    }

    PackageWriter::Inputs inputs;
    inputs.payload_dir = payload_dir;
    inputs.manifest_file = manifest_file;
    const fs::path icons = project / "icons";
    if (fs::is_directory(icons)) inputs.icons_dir = icons;
    const fs::path metadata = project / "metadata";
    if (fs::is_directory(metadata)) inputs.metadata_dir = metadata;

    PackageWriter::write(inputs, key, out);

    // Verify what we just built (no architecture gate — a cross-arch build is
    // legitimate) and report.
    const VerificationReport report =
        verify_package(out, /*check_architecture=*/false);

    std::cout << "Built " << out.string() << " ("
              << format_size(static_cast<std::uint64_t>(fs::file_size(out)))
              << ")\n"
              << "  application:   " << manifest.name << " "
              << manifest.version << " (" << manifest.id << ")\n"
              << "  publisher key: " << pubkey << "\n"
              << "  verification:  " << (report.ok() ? "OK" : "FAILED") << "\n";
    if (injected_key) {
        std::cout << "  filled in publisher.publicKey in "
                  << manifest_file.string() << "\n";
    }
    if (generated_key) {
        std::cout << "  generated a signing key at " << keyfile.string()
                  << " — keep it safe and out of version control; it is the "
                     "identity of every future update\n";
    }
    return report.ok() ? 0 : 3;
}

int cmd_sign_update(const std::vector<std::string>& args) {
    const Parsed parsed =
        parse_arguments(args, {}, {"--key"}, false, kSignUpdateUsage);
    require_positionals(parsed, 1, kSignUpdateUsage);
    const fs::path update_file(parsed.positionals[0]);
    const fs::path keyfile(require_option(parsed, "--key", kSignUpdateUsage));

    // Sign the EXACT bytes of update.json, matching what the updater verifies
    // (FORMAT-0.1 §7 check 1: detached raw 64-byte Ed25519 over the stored
    // update.json bytes). The document is signed as bytes, never re-serialized.
    const std::vector<std::uint8_t> bytes = util::slurp(update_file);
    const crypto::KeyPair key = crypto::read_keyfile(keyfile);
    const crypto::Signature signature = crypto::sign(bytes, key);

    const fs::path sig_file = update_file.string() + ".sig";
    util::spit(sig_file,
               std::vector<std::uint8_t>(signature.begin(), signature.end()));
    std::cout << "Signed " << update_file.string() << "\n"
              << "Signature: " << sig_file.string() << " (64 bytes, Ed25519)\n"
              << "Public key: " << crypto::encode_public_key(key.public_key)
              << "\n";
    return 0;
}

int cmd_integrate(const std::vector<std::string>& args) {
    const Parsed parsed = parse_arguments(args, {}, {}, false, kIntegrateUsage);
    require_positionals(parsed, 0, kIntegrateUsage);

    const desktop::IntegrationResult result =
        desktop::integrate_runtime(Paths::detect());
    if (result.status == desktop::IntegrationStatus::applied) {
        std::cout
            << "Registered the Lexe runtime as the .lexe handler; created:\n";
        for (const std::string& file : result.created_files) {
            std::cout << "  " << file << "\n";
        }
    } else {
        std::cout << "desktop integration skipped: not available on this "
                     "platform\n";
    }
    return 0;
}

} // namespace

/// The .lexe wordmark, shown atop `lexe help`. Kept tasteful and small.
const char* banner_text() {
    return "      __\n"
           "     / /__  _  _____\n"
           "    / / _ \\| |/_/ _ \\\n"
           "   / /  __/>  </  __/\n"
           "  /_/\\___/_/|_|\\___/   Linux applications, made simple.\n";
}

std::string usage_text() {
    return std::string(banner_text()) +
           "\n"
           "usage: lexe <command> [arguments]        (run a command with no "
           "arguments to see its usage)\n"
           "\n"
           "Applications\n"
           "  install <file.lexe> [--yes] [--trust]    verify and install a "
           "package\n"
           "  run <id> [-- <args...>]                  launch an installed "
           "application (sandboxed)\n"
           "  list [--json]                            list installed "
           "applications\n"
           "  info <file.lexe | id> [--json]           show package or "
           "application details\n"
           "  update <id> | --all [--check]            apply (or check for) "
           "updates\n"
           "  rollback <id>                            return to the previous "
           "version\n"
           "  repair <id>                              verify and repair "
           "installed files\n"
           "  remove <id> [--purge-data] [--yes]       uninstall an "
           "application\n"
           "  gc <id> [--keep <n>]                     reclaim old versions "
           "(keeps active + n)\n"
           "\n"
           "Developer\n"
           "  build <project-dir> [-o <out.lexe>] [--key <keyfile.json>]\n"
           "                                           build a signed .lexe from "
           "a project folder\n"
           "  analyze <binary | dir> [--json] [--profile <p>]\n"
           "                                           inspect dependencies and "
           "runtime compatibility\n"
           "  sdk verify <binary | dir> [--json]       check Tux32 Core 1 "
           "portability (typed verdict/exit)\n"
           "  pack <source-dir> --manifest <m> --key <k> -o <out.lexe>\n"
           "                                           build a signed package "
           "(low-level)\n"
           "  keygen <keyfile.json>                    generate a signing "
           "keypair\n"
           "  sign-update <update.json> --key <keyfile.json>\n"
           "                                           sign an update manifest "
           "(writes <update.json>.sig)\n"
           "\n"
           "Trust & verification\n"
           "  verify <file.lexe> [--json]              run the verification "
           "pipeline\n"
           "  trust show|block|unblock|forget <id>     inspect or set local "
           "publisher trust\n"
           "  source set <id> <url>                    set the update source\n"
           "\n"
           "System\n"
           "  integrate                                register .lexe handling "
           "for the runtime\n"
           "  completion [bash]                        print a shell-completion "
           "script\n"
           "  version [--json]                         show runtime, format and "
           "Tux32 versions\n"
           "  help                                     show this help\n"
           "\n"
           "Examples\n"
           "  lexe install ./app.lexe        install a package (shows what it is "
           "and asks first)\n"
           "  lexe run com.example.app       launch it under the sandbox\n"
           "  lexe build ./my-project        package a project folder into a "
           "signed .lexe\n"
           "  lexe sdk verify ./my-app       check Tux32 Core 1 portability\n"
           "\n"
           "Learn more: docs/TUTORIAL.md and docs/README.md\n";
}

int dispatch(const std::vector<std::string>& args) {
    if (args.empty()) {
        throw UsageError(usage_text());
    }
    const std::string& command = args[0];
    const std::vector<std::string> rest(args.begin() + 1, args.end());

    if (command == "help" || command == "--help" || command == "-h") {
        std::cout << usage_text();
        return 0;
    }
    if (command == "version" || command == "--version" || command == "-V") {
        return cmd_version(rest);
    }
    if (command == "install") return cmd_install(rest);
    if (command == "run") return cmd_run(rest);
    if (command == "update") return cmd_update(rest);
    if (command == "remove") return cmd_remove(rest);
    if (command == "repair") return cmd_repair(rest);
    if (command == "info") return cmd_info(rest);
    if (command == "analyze") return cmd_analyze(rest);
    if (command == "sdk") return cmd_sdk(rest);
    if (command == "verify") return cmd_verify(rest);
    if (command == "source") return cmd_source(rest);
    if (command == "rollback") return cmd_rollback(rest);
    if (command == "gc") return cmd_gc(rest);
    if (command == "trust") return cmd_trust(rest);
    if (command == "list") return cmd_list(rest);
    if (command == "keygen") return cmd_keygen(rest);
    if (command == "pack") return cmd_pack(rest);
    if (command == "build") return cmd_build(rest);
    if (command == "sign-update") return cmd_sign_update(rest);
    if (command == "integrate") return cmd_integrate(rest);
    if (command == "completion") return cmd_completion(rest);

    throw UsageError("unknown command \"" + command + "\"\n" + usage_text());
}

} // namespace lexe::cli

// commands — the complete Lexe 0.1 command surface (ARCHITECTURE.md #CLI,
// SPEC #Command-Line Interface). Hand-rolled argument parsing (no deps),
// human output kept clean and aligned with no colour codes, errors to
// stderr (main.cpp prints exception text and maps to the exit codes
// 0 ok / 1 runtime error / 2 usage / 3 verification failure / 4 not found).

#include "commands.hpp"

#include "core/crypto.hpp"
#include "core/desktop.hpp"
#include "core/error.hpp"
#include "core/installer.hpp"
#include "core/launcher.hpp"
#include "core/manifest.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/updater.hpp"
#include "core/util.hpp"
#include "core/verify.hpp"
#include "core/versioncmp.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
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
    "usage: lexe install <file.lexe> [--yes] [--channel <c>]";
constexpr const char* kRunUsage = "usage: lexe run <id> [-- <args...>]";
constexpr const char* kUpdateUsage =
    "usage: lexe update <id> | --all [--check]";
constexpr const char* kRemoveUsage =
    "usage: lexe remove <id> [--purge-data] [--yes]";
constexpr const char* kRepairUsage = "usage: lexe repair <id>";
constexpr const char* kInfoUsage = "usage: lexe info <file.lexe | id> [--json]";
constexpr const char* kVerifyUsage = "usage: lexe verify <file.lexe> [--json]";
constexpr const char* kSourceUsage = "usage: lexe source set <id> <url>";
constexpr const char* kRollbackUsage = "usage: lexe rollback <id>";
constexpr const char* kListUsage = "usage: lexe list [--json]";
constexpr const char* kKeygenUsage = "usage: lexe keygen <keyfile.json>";
constexpr const char* kPackUsage =
    "usage: lexe pack <source-dir> --manifest <lexe.json> --key "
    "<keyfile.json> -o <out.lexe> [--icons <dir>] [--metadata <dir>]";
constexpr const char* kIntegrateUsage = "usage: lexe integrate";
constexpr const char* kSignUpdateUsage =
    "usage: lexe sign-update <update.json> --key <keyfile.json>";

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

/// The SPEC #User Interface primary screen: name, publisher, version,
/// type/arch, source, permissions, size, update policy, verification result.
void print_primary_screen(const Manifest& manifest, const fs::path& package,
                          std::uint64_t size_bytes) {
    std::cout << manifest.name << "\n"
              << "Published by " << manifest.publisher_name << "\n"
              << "Version " << manifest.version << "\n"
              << "\n"
              << "Source:\n"
              << "  " << package.string() << "\n"
              << "\n"
              << "Application Type:\n"
              << "  Native Linux - " << join(manifest.architectures, ", ")
              << "\n"
              << "\n"
              << "Permissions:\n";
    if (manifest.permissions.empty()) {
        std::cout << "  (none requested)\n";
    } else {
        for (const std::string& permission : manifest.permissions) {
            std::cout << "  " << permission << "\n";
        }
    }
    std::cout << "\n"
              << "Installation:\n"
              << "  " << install_scope_text(manifest) << "\n"
              << "  " << format_size(size_bytes) << "\n"
              << "\n"
              << "Updates:\n"
              << "  " << update_policy_text(manifest) << "\n"
              << "\n"
              << "Verification:\n"
              << "  passed: signatures and hashes verified\n";
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
    const Parsed parsed =
        parse_arguments(args, {"--yes"}, {"--channel"}, false, kInstallUsage);
    require_positionals(parsed, 1, kInstallUsage);
    const fs::path package(parsed.positionals[0]);

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
        print_primary_screen(manifest, package, size);
        std::cout << "\n";
        if (!confirm("Install " + manifest.name + " " + manifest.version +
                     "?")) {
            // Declining the prompt is a valid user choice, not an error.
            std::cerr << "installation cancelled\n";
            return 0;
        }
    }

    const Paths paths = Paths::detect();
    Installer installer(paths);
    InstallOptions opts;
    const auto channel = parsed.options.find("--channel");
    if (channel != parsed.options.end()) opts.channel = channel->second;
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
    const Parsed parsed =
        parse_arguments(args, {"--all", "--check"}, {}, false, kUpdateUsage);
    const bool all = parsed.flags.count("--all") != 0;
    const bool check_only = parsed.flags.count("--check") != 0;
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
        const InstallResult result = updater.apply(id);
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
    const Parsed parsed = parse_arguments(args, {"--purge-data", "--yes"}, {},
                                          false, kRemoveUsage);
    require_positionals(parsed, 1, kRemoveUsage);
    const std::string& id = parsed.positionals[0];
    const bool purge = parsed.flags.count("--purge-data") != 0;

    const Paths paths = Paths::detect();
    const Registry registry(paths);
    if (!registry.is_installed(id)) {
        throw NotFoundError("application not installed: " + id);
    }
    if (parsed.flags.count("--yes") == 0) {
        const std::string question =
            purge ? "Remove " + id + " and delete its application data?"
                  : "Remove " + id + "?";
        if (!confirm(question)) {
            // Declining the prompt is a valid user choice, not an error.
            std::cerr << "removal cancelled\n";
            return 0;
        }
    }
    Installer(paths).uninstall(id, purge);
    std::cout << "Removed " << id
              << (purge ? " (application data purged)" : "") << "\n";
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

        if (as_json) {
            ordered_json j;
            j["source"] = "package";
            j["package"] = {
                {"path", fs::path(target).string()},
                {"fileSize", static_cast<std::uint64_t>(fs::file_size(target))},
                {"payloadSize", payload_size(reader)},
            };
            j["manifest"] = manifest_json(manifest);
            std::cout << j.dump(2) << "\n";
        } else {
            std::cout << "Package: " << target << " ("
                      << format_size(
                             static_cast<std::uint64_t>(fs::file_size(target)))
                      << ")\n";
            print_manifest_info(manifest, size);
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
        j["manifest"] = manifest_json(manifest);
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "Installed application: " << record.id << "\n";
        print_manifest_info(manifest, manifest.install_estimated_size);
        print_kv("Current:", current);
        print_kv("Versions:", join(versions, ", "));
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

    if (parsed.flags.count("--json") != 0) {
        ordered_json j;
        j["file"] = file;
        j["ok"] = report.ok();
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
            std::cout << "verification: OK\n";
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

std::string usage_text() {
    return "usage: lexe <command> [arguments]\n"
           "\n"
           "commands:\n"
           "  install <file.lexe> [--yes] [--channel <c>]  verify and install "
           "a package\n"
           "  run <id> [-- <args...>]                      launch an installed "
           "application\n"
           "  update <id> | --all [--check]                apply (or check "
           "for) updates\n"
           "  remove <id> [--purge-data] [--yes]           uninstall an "
           "application\n"
           "  repair <id>                                  verify and repair "
           "installed files\n"
           "  info <file.lexe | id> [--json]               show package or "
           "application details\n"
           "  verify <file.lexe> [--json]                  run the "
           "verification pipeline\n"
           "  source set <id> <url>                        set the update "
           "source\n"
           "  rollback <id>                                return to the "
           "previous version\n"
           "  list [--json]                                list installed "
           "applications\n"
           "  keygen <keyfile.json>                        generate a signing "
           "keypair\n"
           "  pack <source-dir> --manifest <lexe.json> --key <keyfile.json> "
           "-o <out.lexe>\n"
           "       [--icons <dir>] [--metadata <dir>]      build a signed "
           "package\n"
           "  sign-update <update.json> --key <keyfile.json>\n"
           "                                               sign an update "
           "manifest (writes <update.json>.sig)\n"
           "  integrate                                    register .lexe "
           "handling for the runtime\n"
           "  help                                         show this help\n";
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
    if (command == "install") return cmd_install(rest);
    if (command == "run") return cmd_run(rest);
    if (command == "update") return cmd_update(rest);
    if (command == "remove") return cmd_remove(rest);
    if (command == "repair") return cmd_repair(rest);
    if (command == "info") return cmd_info(rest);
    if (command == "verify") return cmd_verify(rest);
    if (command == "source") return cmd_source(rest);
    if (command == "rollback") return cmd_rollback(rest);
    if (command == "list") return cmd_list(rest);
    if (command == "keygen") return cmd_keygen(rest);
    if (command == "pack") return cmd_pack(rest);
    if (command == "sign-update") return cmd_sign_update(rest);
    if (command == "integrate") return cmd_integrate(rest);

    throw UsageError("unknown command \"" + command + "\"\n" + usage_text());
}

} // namespace lexe::cli

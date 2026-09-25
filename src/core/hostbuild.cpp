// hostbuild — see hostbuild.hpp for the four properties this module holds
// together, and why they all live in one place.

#include "core/hostbuild.hpp"

#include "core/crypto.hpp"
#include "core/elf.hpp"
#include "core/error.hpp"
#include "core/isolation.hpp"
#include "core/json_strict.hpp"
#include "core/limits.hpp"
#include "core/util.hpp"
#include "core/verify.hpp"
#include "core/version.hpp"

#include <nlohmann/json.hpp>

#include <memory>
#include <system_error>

#ifndef _WIN32
#include <pwd.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using nlohmann::json;
using ordered_json = nlohmann::ordered_json;

namespace lexe {

// ------------------------------------------------------------------ toolchain

ToolchainReport probe_toolchain(const BuildRecipe& recipe) {
    ToolchainReport report;
    for (const std::string& tool : recipe.toolchain) {
        ToolchainEntry entry;
        entry.name = tool;
        entry.path = util::find_on_path(tool);
        entry.present = !entry.path.empty();
        if (!entry.present) report.missing.push_back(tool);
        report.entries.push_back(std::move(entry));
    }
    report.complete = report.missing.empty();
    if (report.complete) {
        std::string found;
        for (const ToolchainEntry& e : report.entries) {
            if (!found.empty()) found += ", ";
            found += e.name + " (" + e.path + ")";
        }
        report.summary = report.entries.empty()
                             ? "this package declares no build tools"
                             : "build tools found: " + found;
    } else {
        std::string missing;
        for (const std::string& m : report.missing) {
            if (!missing.empty()) missing += ", ";
            missing += m;
        }
        report.summary =
            "this host is missing the build tools this package needs: " +
            missing +
            ". Install them and run the install again — .LEXE does not "
            "substitute a different toolchain for the one the package "
            "declares.";
    }
    return report;
}

// ----------------------------------------------------------------- commands

std::vector<std::vector<std::string>> build_commands(const Manifest& manifest) {
    const BuildRecipe& r = manifest.build;
    switch (r.system) {
    case BuildSystem::Make:
        return {{"make", "-C", r.source_dir}};
    case BuildSystem::CMake:
        // Configured OUT of tree, into a build directory the runtime names, so
        // a package does not get to decide where its build artifacts land.
        return {{"cmake", "-S", r.source_dir, "-B", "lexe-build",
                 "-DCMAKE_BUILD_TYPE=Release"},
                {"cmake", "--build", "lexe-build"}};
    case BuildSystem::Command:
        return {r.command};
    }
    return {};
}

// ------------------------------------------------------------------- record

namespace {

std::string current_user_name() {
#ifdef _WIN32
    return util::get_env("USERNAME").value_or(std::string());
#else
    const struct passwd* pw = ::getpwuid(::getuid());
    if (pw != nullptr && pw->pw_name != nullptr) return std::string(pw->pw_name);
    return util::get_env("USER").value_or(std::string());
#endif
}

std::string render_argv(const std::vector<std::string>& argv) {
    std::string text;
    for (const std::string& a : argv) {
        if (!text.empty()) text += ' ';
        text += a;
    }
    return text;
}

} // namespace

CompileApproval CompileApproval::grant() {
    CompileApproval approval;
    approval.granted = true;
    approval.authority = "user";
    approval.approved_by = current_user_name();
    approval.approved_at = util::now_utc_string();
    return approval;
}

std::string BuildRecord::to_json() const {
    ordered_json j;
    j["schema"] = schema;
    j["applicationId"] = application_id;
    j["applicationVersion"] = application_version;
    j["buildSystem"] = build_system;
    j["sourceDir"] = source_dir;
    j["hostIsa"] = host_isa;
    j["builtAt"] = built_at;
    j["runtimeVersion"] = runtime_version;

    ordered_json approval_json;
    approval_json["granted"] = approval.granted;
    approval_json["authority"] = approval.authority;
    approval_json["approvedBy"] = approval.approved_by;
    approval_json["approvedAt"] = approval.approved_at;
    j["approval"] = std::move(approval_json);

    ordered_json tools = ordered_json::array();
    for (const ToolchainEntry& e : toolchain) {
        ordered_json entry;
        entry["name"] = e.name;
        entry["path"] = e.path;
        tools.push_back(std::move(entry));
    }
    j["toolchain"] = std::move(tools);

    ordered_json products_json(ordered_json::value_t::object);
    for (const auto& [key, digest] : products) products_json[key] = digest;
    j["products"] = std::move(products_json);

    return j.dump(2) + "\n";
}

BuildRecord BuildRecord::from_json(std::string_view text) {
    const json doc =
        json_strict::parse(text, "build.json", limits::kMaxRecordBytes);
    if (!doc.is_object()) throw Error("build.json: expected a JSON object");

    const auto str = [](const json& parent, const char* key) -> std::string {
        const auto it = parent.find(key);
        return (it != parent.end() && it->is_string()) ? it->get<std::string>()
                                                       : std::string();
    };

    BuildRecord record;
    record.schema = str(doc, "schema");
    if (record.schema != "lexe.build/1") {
        throw Error("build.json: unknown schema \"" + record.schema + "\"");
    }
    record.application_id = str(doc, "applicationId");
    record.application_version = str(doc, "applicationVersion");
    record.build_system = str(doc, "buildSystem");
    record.source_dir = str(doc, "sourceDir");
    record.host_isa = str(doc, "hostIsa");
    record.built_at = str(doc, "builtAt");
    record.runtime_version = str(doc, "runtimeVersion");

    const auto approval = doc.find("approval");
    if (approval != doc.end() && approval->is_object()) {
        const auto granted = approval->find("granted");
        record.approval.granted = granted != approval->end() &&
                                  granted->is_boolean() &&
                                  granted->get<bool>();
        record.approval.authority = str(*approval, "authority");
        record.approval.approved_by = str(*approval, "approvedBy");
        record.approval.approved_at = str(*approval, "approvedAt");
    }
    const auto tools = doc.find("toolchain");
    if (tools != doc.end() && tools->is_array()) {
        for (const json& element : *tools) {
            if (!element.is_object()) continue;
            ToolchainEntry entry;
            entry.name = str(element, "name");
            entry.path = str(element, "path");
            entry.present = !entry.path.empty();
            record.toolchain.push_back(std::move(entry));
        }
    }
    const auto products = doc.find("products");
    if (products != doc.end() && products->is_object()) {
        for (const auto& item : products->items()) {
            if (item.value().is_string()) {
                record.products[item.key()] = item.value().get<std::string>();
            }
        }
    }
    return record;
}

std::optional<BuildRecord> BuildRecord::load(const fs::path& meta_dir) {
    const fs::path file = meta_dir / kBuildRecordFile;
    std::error_code ec;
    if (!fs::is_regular_file(file, ec)) return std::nullopt;
    return from_json(util::slurp_text(file));
}

void BuildRecord::save(const fs::path& meta_dir) const {
    util::write_atomic(meta_dir / kBuildRecordFile, to_json());
}

// ------------------------------------------------------------------ compile

const char* to_string(CompileOutcome o) {
    switch (o) {
    case CompileOutcome::Built: return "built";
    case CompileOutcome::NotApproved: return "not-approved";
    case CompileOutcome::ToolchainMissing: return "toolchain-missing";
    case CompileOutcome::NoSandbox: return "no-sandbox";
    case CompileOutcome::BuildFailed: return "build-failed";
    case CompileOutcome::OutputNotAccepted: return "output-not-accepted";
    }
    return "not-approved";
}

CompileResult compile_for_host(const Paths& paths, const CompileRequest& req) {
    const Manifest& manifest = req.manifest;
    if (manifest.application_kind != ApplicationType::Portable) {
        throw Error("hostbuild: " + manifest.id +
                    " is not a portable package; there is nothing to compile");
    }

    CompileResult result;
    result.record.application_id = manifest.id;
    result.record.application_version = manifest.version;
    result.record.build_system = to_string(manifest.build.system);
    result.record.source_dir = manifest.build.source_dir;
    result.record.host_isa = host_architecture();
    result.record.runtime_version = version::runtime_string();
    result.record.approval = req.approval;

    const auto fail = [&result](CompileOutcome outcome, std::string failure,
                                std::string hint) -> CompileResult {
        result.ok = false;
        result.outcome = outcome;
        result.failure = std::move(failure);
        result.hint = std::move(hint);
        return result;
    };

    // (1) APPROVAL gates the OPERATION, and it is checked first — a machine
    // that would refuse anyway never probes a toolchain on a package's say-so.
    if (!req.approval.granted) {
        return fail(CompileOutcome::NotApproved,
                    "installing " + manifest.id +
                        " compiles its source on this machine, and that was "
                        "not approved",
                    "Re-run with `--approve-compile` to authorize the "
                    "compilation. Approval authorizes THIS operation for this "
                    "package and version; it grants the build no privileges. "
                    "The build still runs unprivileged, isolated, and with the "
                    "network denied.");
    }

    // (2) The host must actually have what the package declared, before
    // anything runs: an unavailable capability is reported, never assumed.
    const ToolchainReport toolchain = probe_toolchain(manifest.build);
    result.record.toolchain = toolchain.entries;
    if (!toolchain.complete) {
        return fail(CompileOutcome::ToolchainMissing,
                    "cannot build " + manifest.id + " on this host — " +
                        toolchain.summary,
                    "Install the missing tools, or obtain a native package "
                    "already built for this machine.");
    }

    // The recipe is expected to produce the declared entrypoint; the directory
    // it lives in has to exist before the first command runs.
    const fs::path output =
        req.build_tree / fs::path(manifest.entrypoint_executable);
    std::error_code ec;
    if (output.has_parent_path()) {
        fs::create_directories(output.parent_path(), ec);
    }
    fs::create_directories(req.scratch_dir / "home", ec);
    fs::create_directories(req.scratch_dir / "cache", ec);

    // (3) Unprivileged and isolated. The backend is the one the launcher uses,
    // and it fails CLOSED the same way: there is no "build it outside the
    // sandbox" path here, just as there is no "run it unconfined" path there.
    const std::unique_ptr<IsolationBackend> backend =
        make_isolation_backend(paths);
    const IsolationCapabilities caps = backend->capabilities();
    if (caps.status != CapabilityStatus::Available) {
        return fail(
            CompileOutcome::NoSandbox,
            "compiling " + manifest.id +
                " needs an isolated build environment and this host has none (" +
                to_string(caps.status) +
                (caps.detail.empty() ? std::string() : ": " + caps.detail) +
                "); refusing to build unconfined",
            "A portable package is compiled inside the same sandbox .LEXE "
            "launches applications in. Without it, installing would mean "
            "running the build unconfined on your machine.");
    }

    for (const std::vector<std::string>& argv : build_commands(manifest)) {
        if (argv.empty()) continue;
        IsolationRequest isolation;
        isolation.app_id = manifest.id;
        isolation.app_root = req.build_tree;
        isolation.entrypoint = argv.front();
        isolation.args.assign(argv.begin() + 1, argv.end());
        isolation.data_root = req.scratch_dir / "home";
        isolation.cache_root = req.scratch_dir / "cache";
        isolation.private_runtime_dir = sandbox_runtime_dir_for_current_user();
        isolation.build = true;

        result.commands_run.push_back(render_argv(argv));
        IsolationResult run;
        try {
            const IsolationPlan plan = build_plan(isolation, caps);
            run = backend->run(plan);
        } catch (const IsolationError& e) {
            return fail(CompileOutcome::NoSandbox, e.what(), e.hint());
        }
        result.stdout_text += run.stdout_text;
        result.stderr_text += run.stderr_text;
        if (run.exit_code != 0) {
            return fail(
                CompileOutcome::BuildFailed,
                "building " + manifest.id + " failed: the build command `" +
                    render_argv(argv) + "` exited with code " +
                    std::to_string(run.exit_code),
                "The build output is kept with the failure record — `lexe "
                "errors " + manifest.id + " --latest` names the files.");
        }
    }

    // (4) VERIFY THE OUTPUT. A build that exits 0 has proved nothing. This is
    // the question the payload-role stage asks a native package, asked of bytes
    // that did not exist when the package was signed.
    if (!fs::is_regular_file(output, ec)) {
        return fail(CompileOutcome::OutputNotAccepted,
                    "the build of " + manifest.id +
                        " completed but produced no \"" +
                        manifest.entrypoint_executable + "\"",
                    "A portable package build recipe must produce exactly the "
                    "file its manifest declares as the entrypoint.");
    }
    const elf::ElfInfo info = elf::read(output);
    if (!info.is_elf) {
        return fail(CompileOutcome::OutputNotAccepted,
                    "the build of " + manifest.id + " produced \"" +
                        manifest.entrypoint_executable +
                        "\", but those bytes are not an ELF object — a "
                        "portable package must compile to a native executable "
                        "for this host",
                    "");
    }
    if (info.type != elf::Type::Executable &&
        info.type != elf::Type::SharedObject) {
        return fail(CompileOutcome::OutputNotAccepted,
                    "the build of " + manifest.id + " produced an ELF " +
                        elf::to_string(info.type) +
                        " object, which is not runnable (expected an "
                        "executable or a position-independent executable)",
                    "");
    }
    const std::string produced_isa = info.arch();
    const std::string host_isa = host_architecture();
    if (produced_isa != host_isa) {
        return fail(CompileOutcome::OutputNotAccepted,
                    "the build of " + manifest.id + " produced a " +
                        (produced_isa.empty() ? elf::to_string(info.machine)
                                              : produced_isa) +
                        " binary on a " + host_isa +
                        " host — host-ISA compilation must produce a binary "
                        "for the machine it is installed on",
                    "That is the build recipe cross-compiling, not .LEXE "
                    "choosing an architecture.");
    }

#ifndef _WIN32
    fs::permissions(output,
                    fs::perms::owner_all | fs::perms::group_read |
                        fs::perms::group_exec | fs::perms::others_read |
                        fs::perms::others_exec,
                    ec);
#endif

    // The output is NOT covered by the signed hashes.json — it did not exist
    // when the package was signed — so it is recorded here. Without this the
    // launcher integrity check would find no expected hash for a compiled
    // entrypoint and skip it, leaving exactly the compiled binaries
    // unprotected against tampering after installation.
    result.record.products["payload/" + manifest.entrypoint_executable] =
        crypto::sha256_file_hex(output);
    result.record.built_at = util::now_utc_string();
    result.ok = true;
    result.outcome = CompileOutcome::Built;
    return result;
}

} // namespace lexe

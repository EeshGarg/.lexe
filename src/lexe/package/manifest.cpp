// manifest — parse/validate/serialize the `lexe.json` application manifest
// (FORMAT-0.1 §5). Unknown JSON fields are ignored (forward compatibility);
// missing/invalid REQUIRED fields throw VerificationError describing the
// first violated constraint. Publisher-key *decoding* is deliberately NOT
// part of §5 validation — it is verification pipeline stage 3 (FORMAT-0.1
// §6) and lives in decoded_public_key() / crypto::decode_public_key().

#include "lexe/package/manifest.hpp"

#include "lexe/base/error.hpp"
#include "lexe/base/json_strict.hpp"
#include "lexe/base/limits.hpp"
#include "lexe/base/version.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace lexe {

namespace {

using nlohmann::json;
using nlohmann::ordered_json;

[[noreturn]] void fail(const std::string& message) {
    throw VerificationError("manifest: " + message);
}

/// Member lookup treating JSON null the same as an absent key.
const json* find_member(const json& object, const char* key) {
    const auto it = object.find(key);
    if (it == object.end() || it->is_null()) return nullptr;
    return &*it;
}

std::string require_nonempty_string(const json& object, const char* key,
                                    const char* path) {
    const json* value = find_member(object, key);
    if (value == nullptr) {
        fail(std::string("missing required field \"") + path + "\"");
    }
    if (!value->is_string()) {
        fail(std::string("\"") + path + "\" must be a string");
    }
    std::string text = value->get<std::string>();
    if (text.empty()) {
        fail(std::string("\"") + path + "\" must be a non-empty string");
    }
    return text;
}

/// Optional string field: absent/null -> fallback; present -> must be a string.
std::string optional_string(const json& object, const char* key,
                            const char* path, std::string fallback) {
    const json* value = find_member(object, key);
    if (value == nullptr) return fallback;
    if (!value->is_string()) {
        fail(std::string("\"") + path + "\" must be a string");
    }
    return value->get<std::string>();
}

/// Optional boolean field: absent/null -> fallback; present -> must be a bool.
bool optional_bool(const json& object, const char* key, const char* path,
                   bool fallback) {
    const json* value = find_member(object, key);
    if (value == nullptr) return fallback;
    if (!value->is_boolean()) {
        fail(std::string("\"") + path + "\" must be a boolean");
    }
    return value->get<bool>();
}

/// Optional array-of-strings field: absent/null -> {}; present -> every
/// element must be a string.
std::vector<std::string> optional_string_array(const json& object,
                                               const char* key,
                                               const char* path) {
    std::vector<std::string> result;
    const json* value = find_member(object, key);
    if (value == nullptr) return result;
    if (!value->is_array()) {
        fail(std::string("\"") + path + "\" must be an array of strings");
    }
    result.reserve(value->size());
    for (const json& element : *value) {
        if (!element.is_string()) {
            fail(std::string("\"") + path +
                 "\" must contain only string elements");
        }
        result.push_back(element.get<std::string>());
    }
    return result;
}

const json& require_object(const json& object, const char* key,
                           const char* path) {
    const json* value = find_member(object, key);
    if (value == nullptr) {
        fail(std::string("missing required field \"") + path + "\"");
    }
    if (!value->is_object()) {
        fail(std::string("\"") + path + "\" must be a JSON object");
    }
    return *value;
}

/// Optional object field: absent/null -> nullptr; present -> must be an object.
const json* optional_object(const json& object, const char* key,
                            const char* path) {
    const json* value = find_member(object, key);
    if (value == nullptr) return nullptr;
    if (!value->is_object()) {
        fail(std::string("\"") + path + "\" must be a JSON object");
    }
    return value;
}

bool is_ascii_alnum(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

bool is_ascii_alpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/// FORMAT-0.1 §5: reverse-DNS — 2+ dot-separated segments of [a-zA-Z0-9-]+,
/// at most 255 characters.
void validate_id(const std::string& id) {
    if (id.size() > limits::kMaxIdBytes) {
        fail("\"id\" must be at most " + std::to_string(limits::kMaxIdBytes) +
             " characters");
    }
    std::size_t segment_count = 0;
    std::size_t segment_length = 0;
    for (const char c : id) {
        if (c == '.') {
            if (segment_length == 0) {
                fail("\"id\" must not contain empty dot-separated segments");
            }
            ++segment_count;
            segment_length = 0;
        } else if (is_ascii_alnum(c) || c == '-') {
            ++segment_length;
        } else {
            fail("\"id\" must be reverse-DNS: dot-separated segments of "
                 "[a-zA-Z0-9-]+");
        }
    }
    if (segment_length == 0) {
        fail("\"id\" must not contain empty dot-separated segments");
    }
    ++segment_count;
    if (segment_count < 2) {
        fail("\"id\" must have at least two dot-separated segments "
             "(reverse-DNS)");
    }
}

/// FORMAT-0.1 §5: a manifest field naming something inside `payload/` is a
/// relative path — no leading '/', no ".." segment, no backslash (and,
/// mirroring the §2 entry rules, no NUL byte and no Windows drive
/// designator). `entrypoint.executable` and `build.sourceDir` are both such
/// fields and are held to the same rules by the same code.
void validate_relative_payload_path(const std::string& path,
                                    const std::string& field) {
    const std::string kField = "\"" + field + "\"";
    if (path.find('\0') != std::string::npos) {
        fail(std::string(kField) + " must not contain NUL bytes");
    }
    if (path.find('\\') != std::string::npos) {
        fail(std::string(kField) + " must not contain backslashes");
    }
    if (path.front() == '/') {
        fail(std::string(kField) +
             " must be a relative path (no leading '/')");
    }
    if (path.size() >= 2 && is_ascii_alpha(path[0]) && path[1] == ':') {
        fail(std::string(kField) +
             " must not contain a Windows drive designator");
    }
    std::size_t start = 0;
    while (true) {
        const std::size_t slash = path.find('/', start);
        const std::string_view segment =
            std::string_view(path).substr(start, slash == std::string::npos
                                                     ? std::string::npos
                                                     : slash - start);
        if (segment.empty()) {
            fail(std::string(kField) +
                 " must not contain empty path segments");
        }
        if (segment == "..") {
            fail(std::string(kField) + " must not contain \"..\" segments");
        }
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
}

void parse_install(const json& root, Manifest& m) {
    const json& install = require_object(root, "install", "install");

    const std::string mode =
        require_nonempty_string(install, "mode", "install.mode");
    if (mode == "network" || mode == "launcher") {
        fail("install.mode \"" + mode + "\" is unsupported in 0.1 "
             "(only \"bundled\" is supported)");
    }
    if (mode != "bundled") {
        fail("invalid install.mode \"" + mode +
             "\" (must be \"bundled\" in 0.1)");
    }
    m.install_mode = mode;

    m.install_scope = optional_string(install, "scope", "install.scope",
                                      "user");
    if (m.install_scope.empty()) {
        fail("\"install.scope\" must be a non-empty string");
    }

    if (const json* size = find_member(install, "estimatedSize")) {
        if (size->is_number_unsigned()) {
            m.install_estimated_size = size->get<std::uint64_t>();
        } else if (size->is_number_integer()) {
            const std::int64_t value = size->get<std::int64_t>();
            if (value < 0) {
                fail("\"install.estimatedSize\" must be a non-negative "
                     "integer");
            }
            m.install_estimated_size = static_cast<std::uint64_t>(value);
        } else {
            fail("\"install.estimatedSize\" must be a non-negative integer");
        }
    }
}

void parse_updates(const json& root, Manifest& m) {
    const json* updates = optional_object(root, "updates", "updates");
    if (updates == nullptr) return; // disabled when absent (§5/§7)
    m.updates_enabled =
        optional_bool(*updates, "enabled", "updates.enabled", false);
    m.updates_channel =
        optional_string(*updates, "channel", "updates.channel", "stable");
    m.updates_manifest_url =
        optional_string(*updates, "manifest", "updates.manifest", "");
    m.updates_allow_source_change = optional_bool(
        *updates, "allowSourceChange", "updates.allowSourceChange", true);
}

/// Definitive Architecture §6/§8 — the execution-policy block. Absent means
/// "the boring native path only", which is the safe default.
void parse_execution(const json& root, Manifest& m) {
    const json* execution = optional_object(root, "execution", "execution");
    if (execution == nullptr) {
        m.allowed_chains = {"native"};
        return;
    }
    m.mission_critical = optional_bool(*execution, "missionCritical",
                                       "execution.missionCritical", false);
    m.allowed_chains = optional_string_array(*execution, "allowedChains",
                                             "execution.allowedChains");
    if (m.allowed_chains.empty()) {
        m.allowed_chains = {"native"};
    }
    for (const std::string& chain : m.allowed_chains) {
        if (chain.empty()) {
            fail("\"execution.allowedChains\" must not contain empty strings");
        }
        if (chain.size() > limits::kMaxNameBytes) {
            fail("\"execution.allowedChains\" entry is too long");
        }
        for (const char c : chain) {
            if (!is_ascii_alnum(c) && c != '-' && c != '+' && c != '_') {
                fail("invalid execution chain id \"" + chain +
                     "\" (use [a-zA-Z0-9-+_])");
            }
        }
    }
    // §6 FORBID: a mission-critical package may not carry a compatibility
    // policy at all. Rejecting the contradiction in the manifest is better
    // than silently ignoring it at launch time.
    if (m.mission_critical) {
        for (const std::string& chain : m.allowed_chains) {
            if (chain != "native") {
                fail("execution.missionCritical forbids compatibility chains, "
                     "but execution.allowedChains contains \"" + chain + "\"");
            }
        }
    }
}

/// FORMAT-0.1 §5.8 — how a portable package is built on the destination
/// machine. Present exactly when `applicationType` is `"portable"`: a native
/// package declaring a build recipe is a contradiction (there is nothing to
/// build), and a portable package without one cannot be installed anywhere.
///
/// Everything here is validated BEFORE any approval is asked for and long
/// before anything is executed, so an unbuildable package is refused by the
/// parser rather than halfway through a compile.
void parse_build(const json& root, Manifest& m) {
    const json* build = optional_object(root, "build", "build");

    if (m.application_kind != ApplicationType::Portable) {
        if (build != nullptr) {
            fail("applicationType \"" + m.application_type +
                 "\" must not declare \"build\" — there is nothing to build; "
                 "a package whose payload is source declares "
                 "applicationType \"portable\"");
        }
        return;
    }
    if (build == nullptr) {
        fail("applicationType \"portable\" requires a \"build\" block "
             "describing how to compile the payload for this host");
    }

    const std::string system =
        require_nonempty_string(*build, "system", "build.system");
    if (!build_system_from_string(system, m.build.system)) {
        fail("unknown build.system \"" + system +
             "\" (this runtime understands \"make\", \"cmake\" and "
             "\"command\")");
    }

    m.build.source_dir =
        require_nonempty_string(*build, "sourceDir", "build.sourceDir");
    validate_relative_payload_path(m.build.source_dir, "build.sourceDir");

    m.build.command =
        optional_string_array(*build, "command", "build.command");
    if (m.build.system == BuildSystem::Command) {
        if (m.build.command.empty()) {
            fail("build.system \"command\" requires a non-empty "
                 "\"build.command\" argv");
        }
    } else if (!m.build.command.empty()) {
        fail("build.command may only be given with build.system "
             "\"command\"; \"" + system +
             "\" names a build driver this runtime invokes itself");
    }
    for (const std::string& argument : m.build.command) {
        if (argument.empty()) {
            fail("\"build.command\" must not contain empty arguments");
        }
        if (argument.find('\0') != std::string::npos) {
            fail("\"build.command\" must not contain NUL bytes");
        }
        if (argument.size() > limits::kMaxNameBytes) {
            fail("\"build.command\" argument is too long");
        }
    }

    // The tools the build needs, named so the host can be checked for them
    // before the user is asked to approve anything. Bare executable names
    // only: the build resolves them on the sandbox PATH, and an absolute host
    // path in a signed manifest would be a claim about a machine the
    // publisher has never seen.
    m.build.toolchain =
        optional_string_array(*build, "toolchain", "build.toolchain");
    for (const std::string& tool : m.build.toolchain) {
        if (tool.empty()) {
            fail("\"build.toolchain\" must not contain empty strings");
        }
        if (tool.size() > limits::kMaxNameBytes) {
            fail("\"build.toolchain\" entry is too long");
        }
        if (tool.find('/') != std::string::npos ||
            tool.find('\\') != std::string::npos) {
            fail("\"build.toolchain\" entry \"" + tool +
                 "\" must be a bare executable name, not a path");
        }
    }
    if (m.build.toolchain.empty()) {
        fail("applicationType \"portable\" requires a non-empty "
             "\"build.toolchain\": the host is checked for these executables "
             "before the build is approved, and a package that names none "
             "cannot report why it will not build here");
    }
}

/// Definitive Architecture §14.4 — declared launch presentation, and (for a
/// launch reference) the App ID being launched.
void parse_launch(const json& root, Manifest& m) {
    const json* launch = optional_object(root, "launch", "launch");
    if (launch != nullptr) {
        const std::string mode =
            optional_string(*launch, "mode", "launch.mode", "gui");
        if (!launch_mode_from_string(mode, m.launch_mode)) {
            fail("invalid launch.mode \"" + mode +
                 "\" (choose gui, console or service)");
        }
        m.launch_single_instance = optional_bool(
            *launch, "singleInstance", "launch.singleInstance", false);
        m.launch_application_id =
            optional_string(*launch, "applicationId", "launch.applicationId",
                            "");
    }

    if (m.role == PackageRole::Launch) {
        if (m.launch_application_id.empty()) {
            fail("a launch reference (role \"launch\") must declare "
                 "\"launch.applicationId\"");
        }
        validate_id(m.launch_application_id);
    } else if (!m.launch_application_id.empty()) {
        fail("\"launch.applicationId\" is only valid for role \"launch\"");
    }
}

/// The optional runtime-profile declaration. Stored as written: an id this
/// runtime does not recognise is NOT an error (a newer builder may name a
/// profile that did not exist yet), and readers treat anything they cannot
/// resolve as "not declared" rather than guessing.
void parse_runtime_profile(const json& root, Manifest& m) {
    m.runtime_profile = optional_string(root, "runtimeProfile", "runtimeProfile", "");
}

void parse_integration(const json& root, Manifest& m) {
    const json* integration =
        optional_object(root, "integration", "integration");
    if (integration == nullptr) return;
    m.integration_desktop_entry = optional_bool(
        *integration, "desktopEntry", "integration.desktopEntry", true);
    m.categories = optional_string_array(*integration, "categories",
                                         "integration.categories");
    const json* associations = find_member(*integration, "fileAssociations");
    if (associations == nullptr) return;
    if (!associations->is_array()) {
        fail("\"integration.fileAssociations\" must be an array");
    }
    for (const json& element : *associations) {
        if (!element.is_object()) {
            fail("\"integration.fileAssociations\" elements must be JSON "
                 "objects");
        }
        FileAssociation assoc;
        assoc.extension = require_nonempty_string(
            element, "extension", "integration.fileAssociations[].extension");
        assoc.mime_type = require_nonempty_string(
            element, "mimeType", "integration.fileAssociations[].mimeType");
        m.file_associations.push_back(std::move(assoc));
    }
}

} // namespace

Manifest Manifest::parse(const std::vector<std::uint8_t>& bytes) {
    if (bytes.empty()) return parse(std::string_view{});
    return parse(std::string_view(reinterpret_cast<const char*>(bytes.data()),
                                  bytes.size()));
}

Manifest Manifest::parse(std::string_view json_text) {
    // FORMAT-0.1 §5: UTF-8 JSON, no BOM.
    if (json_text.size() >= 3 &&
        static_cast<unsigned char>(json_text[0]) == 0xEF &&
        static_cast<unsigned char>(json_text[1]) == 0xBB &&
        static_cast<unsigned char>(json_text[2]) == 0xBF) {
        fail("UTF-8 BOM is not allowed");
    }

    // Strict parse (HARDENING.md §E/§F): rejects duplicate keys, invalid UTF-8,
    // and an over-budget document before the DOM is built. A duplicate
    // "publicKey"/"entrypoint" could otherwise make the verifier and a reviewer
    // read different values.
    json root = json_strict::parse(json_text, "manifest",
                                    limits::kMaxManifestBytes);
    if (!root.is_object()) {
        fail("top-level value must be a JSON object");
    }

    Manifest m;

    // --- required fields, in §5 table order ---
    m.lexe_version =
        require_nonempty_string(root, "lexeVersion", "lexeVersion");
    if (m.lexe_version != version::kPackageFormat) {
        fail("unsupported lexeVersion \"" + m.lexe_version +
             "\" (this runtime implements \"" +
             std::string(version::kPackageFormat) + "\")");
    }

    m.id = require_nonempty_string(root, "id", "id");
    validate_id(m.id);

    m.name = require_nonempty_string(root, "name", "name");
    if (m.name.size() > limits::kMaxNameBytes) {
        fail("\"name\" exceeds the " + std::to_string(limits::kMaxNameBytes) +
             "-byte limit");
    }
    m.version = require_nonempty_string(root, "version", "version");
    if (m.version.size() > limits::kMaxVersionBytes) {
        fail("\"version\" exceeds the " +
             std::to_string(limits::kMaxVersionBytes) + "-byte limit");
    }

    const json& publisher = require_object(root, "publisher", "publisher");
    m.publisher_name =
        require_nonempty_string(publisher, "name", "publisher.name");
    if (m.publisher_name.size() > limits::kMaxNameBytes) {
        fail("\"publisher.name\" exceeds the " +
             std::to_string(limits::kMaxNameBytes) + "-byte limit");
    }
    // Presence + string-ness only; decoding is pipeline stage 3 (§6). A giant
    // key field is rejected here before it ever reaches the base64 decoder.
    m.publisher_public_key =
        require_nonempty_string(publisher, "publicKey", "publisher.publicKey");
    if (m.publisher_public_key.size() > limits::kMaxKeyFieldBytes) {
        fail("\"publisher.publicKey\" exceeds the " +
             std::to_string(limits::kMaxKeyFieldBytes) + "-byte limit");
    }
    m.publisher_website =
        optional_string(publisher, "website", "publisher.website", "");

    // Definitive Architecture §15.1 — the role decides WHICH remaining fields
    // are required. It is part of the signed manifest, so renaming the file
    // cannot turn a launch reference into an installable package.
    {
        const std::string role =
            optional_string(root, "role", "role", "application");
        if (role == "application") {
            m.role = PackageRole::Application;
        } else if (role == "launch") {
            m.role = PackageRole::Launch;
        } else {
            fail("unknown role \"" + role +
                 "\" (this runtime understands \"application\" and "
                 "\"launch\")");
        }
    }

    if (m.role == PackageRole::Application) {
        m.application_type =
            require_nonempty_string(root, "applicationType", "applicationType");
        if (!application_type_from_string(m.application_type,
                                          m.application_kind)) {
            fail("applicationType \"" + m.application_type +
                 "\" is unsupported in 0.1 (\"native\" is a compiled Linux "
                 "payload, \"portable\" is source compiled for this host at "
                 "install, \"windows\" is a Windows executable run through a "
                 "compatibility layer)");
        }

        const json* architectures = find_member(root, "architectures");
        if (architectures == nullptr) {
            fail("missing required field \"architectures\"");
        }
        if (!architectures->is_array() || architectures->empty()) {
            fail("\"architectures\" must be a non-empty array");
        }
        for (const json& element : *architectures) {
            if (!element.is_string()) {
                fail("\"architectures\" must contain only string elements");
            }
            const std::string arch = element.get<std::string>();
            if (arch != "x86_64" && arch != "aarch64") {
                fail("unrecognised architecture \"" + arch +
                     "\" (0.1 recognises x86_64, aarch64)");
            }
            m.architectures.push_back(arch);
        }

        const json& entrypoint =
            require_object(root, "entrypoint", "entrypoint");
        m.entrypoint_executable = require_nonempty_string(
            entrypoint, "executable", "entrypoint.executable");
        validate_relative_payload_path(m.entrypoint_executable,
                                       "entrypoint.executable");
        m.entrypoint_arguments =
            optional_string_array(entrypoint, "arguments",
                                  "entrypoint.arguments");

        parse_install(root, m);
        parse_build(root, m);
    } else {
        // A launch reference carries NO payload and NO entrypoint: it names an
        // installed application. Rejecting these fields keeps the two roles
        // structurally distinct instead of merely differently labelled.
        for (const char* forbidden :
             {"applicationType", "architectures", "entrypoint", "install",
              "build"}) {
            if (find_member(root, forbidden) != nullptr) {
                fail(std::string("a launch reference (role \"launch\") must "
                                 "not declare \"") +
                     forbidden + "\"");
            }
        }
        m.install_mode = "bundled"; // structural default; nothing is installed
    }

    // --- optional blocks with defaults (§5) ---
    m.permissions = optional_string_array(root, "permissions", "permissions");
    parse_updates(root, m);
    parse_integration(root, m);
    parse_execution(root, m);
    parse_launch(root, m);
    parse_runtime_profile(root, m);

    // A payload and a policy that cannot run it is a contradiction, and the
    // place to say so is here — not at launch, where the user would meet it as
    // "no execution chain is available" long after installing something that
    // was never going to run (FORMAT-0.1 §5.5).
    if (m.role == PackageRole::Application &&
        m.application_kind == ApplicationType::Windows) {
        if (m.mission_critical) {
            fail("applicationType \"windows\" cannot be missionCritical: "
                 "mission-critical execution requires a Linux-native, "
                 "host-ISA-native realization, and a Windows payload has none "
                 "by construction");
        }
        bool foreign_os_permitted = false;
        for (const std::string& chain : m.effective_allowed_chains()) {
            if (chain_runs_foreign_os(chain)) foreign_os_permitted = true;
        }
        if (!foreign_os_permitted) {
            fail("applicationType \"windows\" needs a foreign-OS execution "
                 "chain, but execution.allowedChains permits none (add "
                 "\"wine\" or \"proton\", or a layered form such as "
                 "\"proton+fex\"). Nothing can run a Windows payload natively.");
        }
    }

    return m;
}

std::string Manifest::to_json() const {
    ordered_json j;
    j["lexeVersion"] = lexe_version;
    j["id"] = id;
    j["name"] = name;
    j["version"] = version;
    j["role"] = to_string(role);

    ordered_json publisher;
    publisher["name"] = publisher_name;
    if (!publisher_website.empty()) publisher["website"] = publisher_website;
    publisher["publicKey"] = publisher_public_key;
    j["publisher"] = std::move(publisher);

    if (role == PackageRole::Application) {
        j["applicationType"] = application_type;
        j["architectures"] = architectures;

        ordered_json entrypoint;
        entrypoint["executable"] = entrypoint_executable;
        entrypoint["arguments"] = entrypoint_arguments;
        j["entrypoint"] = std::move(entrypoint);

        ordered_json install;
        install["scope"] = install_scope;
        install["mode"] = install_mode;
        if (install_estimated_size != 0) {
            install["estimatedSize"] = install_estimated_size;
        }
        j["install"] = std::move(install);

        if (application_kind == ApplicationType::Portable) {
            ordered_json build_block;
            build_block["system"] = to_string(build.system);
            build_block["sourceDir"] = build.source_dir;
            if (!build.command.empty()) {
                build_block["command"] = build.command;
            }
            build_block["toolchain"] = build.toolchain;
            j["build"] = std::move(build_block);
        }
    }

    ordered_json launch;
    launch["mode"] = to_string(launch_mode);
    launch["singleInstance"] = launch_single_instance;
    if (role == PackageRole::Launch) {
        launch["applicationId"] = launch_application_id;
    }
    j["launch"] = std::move(launch);

    ordered_json execution;
    execution["missionCritical"] = mission_critical;
    execution["allowedChains"] =
        allowed_chains.empty() ? std::vector<std::string>{"native"}
                               : allowed_chains;
    j["execution"] = std::move(execution);

    j["permissions"] = permissions;

    ordered_json updates;
    updates["enabled"] = updates_enabled;
    updates["channel"] = updates_channel;
    if (!updates_manifest_url.empty()) {
        updates["manifest"] = updates_manifest_url;
    }
    updates["allowSourceChange"] = updates_allow_source_change;
    j["updates"] = std::move(updates);

    ordered_json integration;
    integration["desktopEntry"] = integration_desktop_entry;
    integration["categories"] = categories;
    ordered_json associations = ordered_json::array();
    for (const FileAssociation& assoc : file_associations) {
        ordered_json element;
        element["extension"] = assoc.extension;
        element["mimeType"] = assoc.mime_type;
        associations.push_back(std::move(element));
    }
    integration["fileAssociations"] = std::move(associations);
    j["integration"] = std::move(integration);
    // Emitted only when declared, so a manifest that never mentioned a profile
    // round-trips byte-identically.
    if (!runtime_profile.empty()) j["runtimeProfile"] = runtime_profile;

    return j.dump(2);
}

crypto::PublicKey Manifest::decoded_public_key() const {
    return crypto::decode_public_key(publisher_public_key);
}

const char* to_string(PackageRole r) {
    switch (r) {
    case PackageRole::Application: return "application";
    case PackageRole::Launch: return "launch";
    }
    return "application";
}

const char* to_string(LaunchMode m) {
    switch (m) {
    case LaunchMode::Gui: return "gui";
    case LaunchMode::Console: return "console";
    case LaunchMode::Service: return "service";
    }
    return "gui";
}

bool launch_mode_from_string(const std::string& text, LaunchMode& out) {
    if (text == "gui") { out = LaunchMode::Gui; return true; }
    if (text == "console") { out = LaunchMode::Console; return true; }
    if (text == "service") { out = LaunchMode::Service; return true; }
    return false;
}

const char* to_string(ApplicationType t) {
    switch (t) {
    case ApplicationType::Native: return "native";
    case ApplicationType::Portable: return "portable";
    case ApplicationType::Windows: return "windows";
    }
    return "native";
}

bool application_type_from_string(const std::string& text,
                                  ApplicationType& out) {
    if (text == "native") { out = ApplicationType::Native; return true; }
    if (text == "portable") { out = ApplicationType::Portable; return true; }
    if (text == "windows") { out = ApplicationType::Windows; return true; }
    return false;
}

const char* to_string(ChainLayerKind k) {
    switch (k) {
    case ChainLayerKind::IsaTranslation: return "isa-translation";
    case ChainLayerKind::ForeignOs: return "foreign-os";
    case ChainLayerKind::Unknown: break;
    }
    return "unknown";
}

ChainLayerKind chain_layer_kind(const std::string& layer_id) {
    if (layer_id == "fex" || layer_id == "box64" || layer_id == "qemu-user") {
        return ChainLayerKind::IsaTranslation;
    }
    if (layer_id == "wine" || layer_id == "proton") {
        return ChainLayerKind::ForeignOs;
    }
    return ChainLayerKind::Unknown;
}

bool chain_runs_foreign_os(const std::string& chain_id) {
    std::size_t start = 0;
    while (start <= chain_id.size()) {
        const std::size_t plus = chain_id.find('+', start);
        const std::string layer = chain_id.substr(
            start, plus == std::string::npos ? std::string::npos : plus - start);
        if (chain_layer_kind(layer) == ChainLayerKind::ForeignOs) return true;
        if (plus == std::string::npos) break;
        start = plus + 1;
    }
    return false;
}

const char* to_string(BuildSystem s) {
    switch (s) {
    case BuildSystem::Make: return "make";
    case BuildSystem::CMake: return "cmake";
    case BuildSystem::Command: return "command";
    }
    return "make";
}

bool build_system_from_string(const std::string& text, BuildSystem& out) {
    if (text == "make") { out = BuildSystem::Make; return true; }
    if (text == "cmake") { out = BuildSystem::CMake; return true; }
    if (text == "command") { out = BuildSystem::Command; return true; }
    return false;
}

std::vector<std::string> Manifest::effective_allowed_chains() const {
    // §6 FORBID — mission-critical execution permits the native chain only,
    // whatever the list says. The parser already rejects the contradiction;
    // this is the belt-and-braces enforcement point used at launch.
    if (mission_critical) return {"native"};
    if (allowed_chains.empty()) return {"native"};
    return allowed_chains;
}

bool Manifest::chain_allowed(const std::string& chain) const {
    const std::vector<std::string> chains = effective_allowed_chains();
    return std::find(chains.begin(), chains.end(), chain) != chains.end();
}

} // namespace lexe

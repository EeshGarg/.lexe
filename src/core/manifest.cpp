// manifest — parse/validate/serialize the `lexe.json` application manifest
// (FORMAT-0.1 §5). Unknown JSON fields are ignored (forward compatibility);
// missing/invalid REQUIRED fields throw VerificationError describing the
// first violated constraint. Publisher-key *decoding* is deliberately NOT
// part of §5 validation — it is verification pipeline stage 3 (FORMAT-0.1
// §6) and lives in decoded_public_key() / crypto::decode_public_key().

#include "core/manifest.hpp"

#include "core/error.hpp"

#include <nlohmann/json.hpp>

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
    if (id.size() > 255) {
        fail("\"id\" must be at most 255 characters");
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

/// FORMAT-0.1 §5: entrypoint.executable is a relative path inside payload/ —
/// no leading '/', no ".." segment, no backslash (and, mirroring the §2 entry
/// rules, no NUL byte and no Windows drive designator).
void validate_entrypoint_path(const std::string& path) {
    static const char* const kField = "\"entrypoint.executable\"";
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

    json root;
    try {
        root = json::parse(json_text); // validates UTF-8, throws on error
    } catch (const json::exception& e) {
        fail(std::string("invalid JSON: ") + e.what());
    }
    if (!root.is_object()) {
        fail("top-level value must be a JSON object");
    }

    Manifest m;

    // --- required fields, in §5 table order ---
    m.lexe_version =
        require_nonempty_string(root, "lexeVersion", "lexeVersion");
    if (m.lexe_version != "0.1") {
        fail("unsupported lexeVersion \"" + m.lexe_version +
             "\" (this runtime implements \"0.1\")");
    }

    m.id = require_nonempty_string(root, "id", "id");
    validate_id(m.id);

    m.name = require_nonempty_string(root, "name", "name");
    m.version = require_nonempty_string(root, "version", "version");

    const json& publisher = require_object(root, "publisher", "publisher");
    m.publisher_name =
        require_nonempty_string(publisher, "name", "publisher.name");
    // Presence + string-ness only; decoding is pipeline stage 3 (§6).
    m.publisher_public_key =
        require_nonempty_string(publisher, "publicKey", "publisher.publicKey");
    m.publisher_website =
        optional_string(publisher, "website", "publisher.website", "");

    m.application_type =
        require_nonempty_string(root, "applicationType", "applicationType");
    if (m.application_type != "native") {
        fail("applicationType \"" + m.application_type +
             "\" is unsupported in 0.1 (only \"native\" is supported)");
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

    const json& entrypoint = require_object(root, "entrypoint", "entrypoint");
    m.entrypoint_executable = require_nonempty_string(
        entrypoint, "executable", "entrypoint.executable");
    validate_entrypoint_path(m.entrypoint_executable);
    m.entrypoint_arguments = optional_string_array(entrypoint, "arguments",
                                                   "entrypoint.arguments");

    parse_install(root, m);

    // --- optional blocks with defaults (§5) ---
    m.permissions = optional_string_array(root, "permissions", "permissions");
    parse_updates(root, m);
    parse_integration(root, m);

    return m;
}

std::string Manifest::to_json() const {
    ordered_json j;
    j["lexeVersion"] = lexe_version;
    j["id"] = id;
    j["name"] = name;
    j["version"] = version;

    ordered_json publisher;
    publisher["name"] = publisher_name;
    if (!publisher_website.empty()) publisher["website"] = publisher_website;
    publisher["publicKey"] = publisher_public_key;
    j["publisher"] = std::move(publisher);

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

    return j.dump(2);
}

crypto::PublicKey Manifest::decoded_public_key() const {
    return crypto::decode_public_key(publisher_public_key);
}

} // namespace lexe

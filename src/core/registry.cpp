// registry — installed-application records under `<LEXE_HOME>/apps/<id>/`
// (FORMAT-0.1 §9): installation.json read/write, the manifest.json copy,
// version listing, and the `current` symlink with the `current.txt` text
// fallback where symlinks are unavailable (typical on Windows).
//
// The pinned publisher key recorded in installation.json is the trust anchor
// for updates (FORMAT-0.1 §7.1). Application ids and version strings are
// validated before they are joined into filesystem paths so a hostile id or
// version can never escape `<LEXE_HOME>/apps/` (security invariant #1).

#include "core/registry.hpp"

#include "core/error.hpp"
#include "core/util.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

namespace lexe {

namespace {

using nlohmann::json;
using nlohmann::ordered_json;

[[noreturn]] void fail_record(const std::string& message) {
    throw Error("installation.json: " + message);
}

/// One dot-separated id segment: non-empty, [a-zA-Z0-9-]+ (FORMAT-0.1 §5).
bool id_segment_ok(std::string_view segment) {
    if (segment.empty()) return false;
    for (const char c : segment) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '-';
        if (!ok) return false;
    }
    return true;
}

/// Enforce the FORMAT-0.1 §5 reverse-DNS id shape (2+ dot-separated segments
/// of [a-zA-Z0-9-]+, ≤255 chars). Because the shape excludes separators,
/// drive designators and `.`/`..` segments, a validated id is always safe to
/// join under apps/. Throws lexe::Error otherwise.
void validate_id(const std::string& id) {
    bool ok = !id.empty() && id.size() <= 255;
    std::size_t segments = 0;
    std::size_t start = 0;
    while (ok) {
        const std::size_t dot = id.find('.', start);
        const std::size_t end = (dot == std::string::npos) ? id.size() : dot;
        ok = id_segment_ok(std::string_view(id).substr(start, end - start));
        ++segments;
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    if (!ok || segments < 2) {
        throw Error("registry: invalid application id: \"" + id + "\"");
    }
}

/// Version strings are free-form (FORMAT-0.1 §5) but become a single path
/// component under versions/, so reject anything that could traverse or
/// re-root the path. Throws lexe::Error.
void validate_version(const std::string& version) {
    const bool ok = !version.empty() && version != "." && version != ".." &&
                    version.find_first_of("/\\:\0", 0, 4) == std::string::npos;
    if (!ok) {
        throw Error("registry: invalid version string: \"" + version + "\"");
    }
}

/// Strict member lookup helpers; JSON null is treated as an absent key.
const json* find_member(const json& object, const char* key) {
    const auto it = object.find(key);
    if (it == object.end() || it->is_null()) return nullptr;
    return &*it;
}

std::string optional_string(const json& object, const char* key,
                            std::string fallback) {
    const json* value = find_member(object, key);
    if (value == nullptr) return fallback;
    if (!value->is_string()) {
        fail_record(std::string("\"") + key + "\" must be a string");
    }
    return value->get<std::string>();
}

std::string trim_whitespace(std::string text) {
    const char* ws = " \t\r\n";
    const std::size_t first = text.find_first_not_of(ws);
    if (first == std::string::npos) return {};
    const std::size_t last = text.find_last_not_of(ws);
    return text.substr(first, last - first + 1);
}

} // namespace

// ------------------------------------------------------- InstallationRecord

InstallationRecord InstallationRecord::from_json(std::string_view json_text) {
    json j;
    try {
        j = json::parse(json_text);
    } catch (const json::exception& e) {
        fail_record(std::string("not valid JSON: ") + e.what());
    }
    if (!j.is_object()) {
        fail_record("top level must be a JSON object");
    }

    InstallationRecord r;
    r.id = optional_string(j, "id", "");
    if (r.id.empty()) {
        fail_record("missing required field \"id\"");
    }
    r.version = optional_string(j, "version", "");
    r.source = optional_string(j, "source", "");
    r.publisher_key = optional_string(j, "publisherKey", "");
    r.channel = optional_string(j, "channel", "stable");
    r.update_url = optional_string(j, "updateUrl", "");
    r.installed_at = optional_string(j, "installedAtUtc", "");

    if (const json* last_run = find_member(j, "lastRun")) {
        if (!last_run->is_object()) {
            fail_record("\"lastRun\" must be an object or null");
        }
        r.last_run_at = optional_string(*last_run, "at", "");
        if (const json* code = find_member(*last_run, "exitCode")) {
            if (!code->is_number_integer()) {
                fail_record("\"lastRun.exitCode\" must be an integer");
            }
            r.last_exit_code = code->get<int>();
        }
    }

    if (const json* created = find_member(j, "createdFiles")) {
        if (!created->is_array()) {
            fail_record("\"createdFiles\" must be an array");
        }
        for (const auto& element : *created) {
            if (!element.is_string()) {
                fail_record("\"createdFiles\" entries must be strings");
            }
            r.created_files.push_back(element.get<std::string>());
        }
    }
    return r;
}

std::string InstallationRecord::to_json() const {
    ordered_json j;
    j["id"] = id;
    j["version"] = version;
    j["source"] = source;
    j["publisherKey"] = publisher_key;
    j["channel"] = channel;
    j["updateUrl"] = update_url;
    j["installedAtUtc"] = installed_at;
    if (last_run_at.empty()) {
        j["lastRun"] = nullptr; // never run (§9 lastRun)
    } else {
        j["lastRun"] = ordered_json{{"at", last_run_at},
                                    {"exitCode", last_exit_code}};
    }
    j["createdFiles"] = created_files;
    return j.dump(2) + "\n";
}

// ------------------------------------------------------------------ Registry

Registry::Registry(const Paths& paths) : paths_(paths) {}

fs::path Registry::app_dir(const std::string& id) const {
    validate_id(id);
    return paths_.apps_dir() / id;
}

fs::path Registry::version_dir(const std::string& id,
                               const std::string& version) const {
    validate_version(version);
    return app_dir(id) / "versions" / version;
}

std::vector<std::string> Registry::list_installed() const {
    std::vector<std::string> ids;
    std::error_code ec;
    if (!fs::is_directory(paths_.apps_dir(), ec)) return ids;
    for (const auto& entry : fs::directory_iterator(paths_.apps_dir(), ec)) {
        std::error_code entry_ec;
        if (!entry.is_directory(entry_ec)) continue;
        if (fs::is_regular_file(entry.path() / "installation.json", entry_ec)) {
            ids.push_back(entry.path().filename().string());
        }
    }
    std::sort(ids.begin(), ids.end());
    return ids;
}

bool Registry::is_installed(const std::string& id) const {
    std::error_code ec;
    return fs::is_regular_file(app_dir(id) / "installation.json", ec);
}

InstallationRecord Registry::read_record(const std::string& id) const {
    const fs::path file = app_dir(id) / "installation.json";
    std::error_code ec;
    if (!fs::is_regular_file(file, ec)) {
        throw NotFoundError("application not installed: " + id);
    }
    return InstallationRecord::from_json(util::slurp_text(file));
}

void Registry::write_record(const InstallationRecord& record) const {
    // app_dir validates record.id, so a malformed record can never write
    // outside apps/. spit creates the parent directories.
    const fs::path file = app_dir(record.id) / "installation.json";
    util::spit(file, std::string_view(record.to_json()));
}

std::string Registry::current_version(const std::string& id) const {
    const fs::path dir = app_dir(id);
    std::error_code ec;

    // Primary mechanism: the `current` symlink (FORMAT-0.1 §9).
    const fs::path link = dir / "current";
    if (fs::is_symlink(link, ec)) {
        const fs::path target = fs::read_symlink(link, ec);
        if (!ec) {
            const std::string version = target.filename().string();
            if (!version.empty()) return version;
        }
    }

    // Fallback: `current.txt` containing the version string.
    const fs::path txt = dir / "current.txt";
    if (fs::is_regular_file(txt, ec)) {
        const std::string version = trim_whitespace(util::slurp_text(txt));
        if (!version.empty()) return version;
    }

    if (!fs::is_directory(dir, ec)) {
        throw NotFoundError("application not installed: " + id);
    }
    throw NotFoundError("no current version set for " + id);
}

void Registry::set_current_version(const std::string& id,
                                   const std::string& version) const {
    const fs::path dir = app_dir(id);
    validate_version(version);
    std::error_code ec;
    if (!fs::is_directory(dir / "versions" / version, ec)) {
        throw NotFoundError("version " + version + " of " + id +
                            " is not installed");
    }

    const fs::path link = dir / "current";
    const fs::path txt = dir / "current.txt";
    // Remove both previous pointers first so the two mechanisms can never
    // disagree afterwards. remove_all deletes a symlink without following it.
    util::remove_recursive(link);
    util::remove_recursive(txt);

    if (use_symlinks_) {
        // Relative target so the link survives a moved LEXE_HOME.
        std::error_code link_ec;
        fs::create_directory_symlink(fs::path("versions") / version, link,
                                     link_ec);
        if (!link_ec) return;
        // Symlink creation unavailable (typical on Windows without developer
        // mode) — fall through to the text fallback.
    }
    util::spit(txt, std::string_view(version + "\n"));
}

std::vector<std::string> Registry::installed_versions(const std::string& id) const {
    std::vector<std::string> versions;
    const fs::path root = app_dir(id) / "versions";
    std::error_code ec;
    if (!fs::is_directory(root, ec)) return versions;
    for (const auto& entry : fs::directory_iterator(root, ec)) {
        std::error_code entry_ec;
        if (entry.is_directory(entry_ec)) {
            versions.push_back(entry.path().filename().string());
        }
    }
    return versions;
}

Manifest Registry::read_manifest(const std::string& id) const {
    const fs::path file = app_dir(id) / "manifest.json";
    std::error_code ec;
    if (!fs::is_regular_file(file, ec)) {
        throw NotFoundError("no manifest recorded for " + id);
    }
    return Manifest::parse(util::slurp(file));
}

void Registry::write_manifest_bytes(
    const std::string& id, const std::vector<std::uint8_t>& lexe_json_bytes) const {
    util::spit(app_dir(id) / "manifest.json", lexe_json_bytes);
}

} // namespace lexe

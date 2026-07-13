// updater — signed update manifests (FORMAT-0.1 §7).
//
// The installed application's record (installation.json) is the trust
// anchor: its pinned publisher key verifies update.json (§7 check 1) and
// must match the downloaded package's key (§7 check 6) — key rotation is
// out of scope for 0.1 (security invariant #4). Downgrades are refused
// (§7 check 7). The previous version directory is retained for
// `lexe rollback`.
//
// update.json bytes are parsed only AFTER their detached signature has
// verified (signature-before-parse discipline, security invariant #2).
//
// The §9 bookkeeping of installing the new version (extract payload to
// versions/<v>/, flip `current`, refresh manifest.json + installation.json)
// is done through the registry module's primitives; the update flow never
// deletes a previously installed version.

#include "core/updater.hpp"

#include "core/crypto.hpp"
#include "core/error.hpp"
#include "core/http.hpp"
#include "core/manifest.hpp"
#include "core/package.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"
#include "core/verify.hpp"
#include "core/versioncmp.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace lexe {

namespace {

using nlohmann::json;

[[noreturn]] void fail(const std::string& message) {
    throw VerificationError(message);
}

/// Strict member lookup; JSON null counts as absent.
const json* find_member(const json& object, const char* key) {
    const auto it = object.find(key);
    if (it == object.end() || it->is_null()) return nullptr;
    return &*it;
}

/// Required non-empty string member of update.json, with a located error.
std::string require_string(const json& object, const char* key,
                           const std::string& where) {
    const json* value = find_member(object, key);
    if (value == nullptr || !value->is_string() ||
        value->get<std::string>().empty()) {
        fail("update.json: " + where + " \"" + key +
             "\" must be a non-empty string");
    }
    return value->get<std::string>();
}

std::string ascii_lowercase(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c);
    });
    return s;
}

/// 64 lowercase hex characters (a SHA-256 digest, FORMAT-0.1 §3).
bool is_sha256_hex(const std::string& s) {
    if (s.size() != 64) return false;
    for (const char c : s) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) return false;
    }
    return true;
}

/// §7 check 7: the offered version must be strictly greater (FORMAT-0.1 §8).
/// Equal is a plain no-op Error ("already up to date"); older is a refused
/// downgrade — a VerificationError (security invariant #4).
void require_strictly_newer(const std::string& offered,
                            const std::string& installed,
                            const std::string& id) {
    const int cmp = compare_versions(offered, installed);
    if (cmp == 0) {
        throw Error("already up to date: " + id + " " + installed);
    }
    if (cmp < 0) {
        fail("downgrade refused (check 7): offered version \"" + offered +
             "\" is older than installed \"" + installed + "\"");
    }
}

} // namespace

Updater::Updater(const Paths& paths) : paths_(paths) {}

UpdateCheck Updater::check(const std::string& id) {
    const Registry registry(paths_);
    const InstallationRecord record = registry.read_record(id);
    if (record.update_url.empty()) {
        throw NotFoundError("no update source configured for " + id);
    }

    // Fetch update.json and its detached signature at the same URL + ".sig"
    // (FORMAT-0.1 §7). file:// and plain paths are served by the http module.
    const std::vector<std::uint8_t> update_bytes =
        http::fetch_bytes(record.update_url);
    const std::vector<std::uint8_t> sig_bytes =
        http::fetch_bytes(record.update_url + ".sig");

    // ---- §7 check 1: signature with the INSTALLED publisher key ----------
    const crypto::PublicKey pinned =
        crypto::decode_public_key(record.publisher_key);
    crypto::Signature signature{};
    if (sig_bytes.size() != signature.size()) {
        fail("update.json signature (check 1): expected a raw 64-byte "
             "Ed25519 signature, got " + std::to_string(sig_bytes.size()) +
             " bytes");
    }
    std::copy(sig_bytes.begin(), sig_bytes.end(), signature.begin());
    if (!crypto::verify_signature(update_bytes, signature, pinned)) {
        fail("update.json signature (check 1) does not verify with the "
             "installed publisher key; key rotation is not supported in "
             "0.1 — reinstall manually to accept a new key");
    }

    // Parse only after the signature verified (invariant #2).
    json manifest;
    try {
        manifest = json::parse(update_bytes.begin(), update_bytes.end());
    } catch (const json::exception& e) {
        fail(std::string("update.json: not valid JSON: ") + e.what());
    }
    if (!manifest.is_object()) {
        fail("update.json: top level must be a JSON object");
    }
    if (const json* v = find_member(manifest, "lexeVersion")) {
        if (!v->is_string() || v->get<std::string>() != "0.1") {
            fail("update.json: unsupported lexeVersion (expected \"0.1\")");
        }
    }

    // ---- §7 check 2: id matches the installed application ----------------
    const std::string manifest_id = require_string(manifest, "id", "top-level");
    if (manifest_id != id) {
        fail("update.json id (check 2): \"" + manifest_id +
             "\" does not match installed application \"" + id + "\"");
    }

    // ---- §7 check 3: entry for the app's configured channel --------------
    const std::string channel =
        record.channel.empty() ? std::string("stable") : record.channel;
    const json* channels = find_member(manifest, "channels");
    if (channels == nullptr || !channels->is_object()) {
        fail("update.json: missing \"channels\" object (check 3)");
    }
    const json* entry = find_member(*channels, channel.c_str());
    if (entry == nullptr) {
        fail("update.json has no entry for channel \"" + channel +
             "\" (check 3)");
    }
    if (!entry->is_object()) {
        fail("update.json: channel \"" + channel +
             "\" entry must be an object (check 3)");
    }
    const std::string where = "channel \"" + channel + "\"";
    const std::string available = require_string(*entry, "version", where);
    const json* package = find_member(*entry, "package");
    if (package == nullptr || !package->is_object()) {
        fail("update.json: " + where + " is missing the \"package\" object");
    }
    const std::string url =
        require_string(*package, "url", where + " package");
    const std::string sha256 = ascii_lowercase(
        require_string(*package, "sha256", where + " package"));
    if (!is_sha256_hex(sha256)) {
        fail("update.json: " + where +
             " package \"sha256\" must be 64 hexadecimal characters");
    }

    UpdateCheck out;
    out.id = id;
    out.installed_version =
        record.version.empty() ? registry.current_version(id) : record.version;
    out.available_version = available;
    out.package_url = url;
    out.package_sha256 = sha256;
    out.update_available =
        compare_versions(available, out.installed_version) > 0;
    return out;
}

InstallResult Updater::apply(const std::string& id) {
    const Registry registry(paths_);

    // §7 checks 1–3 (and no side effects yet).
    const UpdateCheck chk = check(id);
    const InstallationRecord record = registry.read_record(id);

    // §7 check 7, advertised version (fast path): refuse before downloading
    // anything when the channel does not offer a strictly newer version. The
    // check is re-enforced below on the downloaded package's own manifest
    // version — the one that would actually be installed.
    require_strictly_newer(chk.available_version, chk.installed_version, id);

    // ---- §7 check 4: download to the cache, verify its SHA-256 -----------
    // `id` was validated by the registry lookups above, so it is safe to
    // join into a path; the filename is fixed so a hostile version string
    // from update.json never becomes a path component here.
    const fs::path package_path =
        paths_.cache_dir() / "updates" / id / "package.lexe";
    http::fetch_to_file(chk.package_url, package_path);
    const std::string actual_sha256 = crypto::sha256_file_hex(package_path);
    if (actual_sha256 != chk.package_sha256) {
        fail("downloaded package SHA-256 (check 4): update.json says " +
             chk.package_sha256 + " but the download is " + actual_sha256);
    }

    // ---- §7 check 5: the full §6 pipeline (with the architecture stage) --
    Manifest new_manifest;
    try {
        new_manifest =
            verify_package_or_throw(package_path, /*check_architecture=*/true);
    } catch (const VerificationError& e) {
        fail(std::string("update package (check 5): ") + e.what());
    }

    // ---- §7 check 6: package id + publisher key match the installed ones -
    if (new_manifest.id != id) {
        fail("update package id (check 6): \"" + new_manifest.id +
             "\" does not match installed application \"" + id + "\"");
    }
    const crypto::PublicKey pinned =
        crypto::decode_public_key(record.publisher_key);
    if (new_manifest.decoded_public_key() != pinned) {
        fail("update package publisher key (check 6) does not match the "
             "installed publisher key; key rotation is not supported in "
             "0.1 — reinstall manually to accept a new key");
    }

    // ---- §7 check 7: strictly newer than what is installed ---------------
    require_strictly_newer(new_manifest.version, chk.installed_version, id);

    // ---- install the new version beside the previous one (§9) ------------
    // Previous version directories are retained for `lexe rollback` (§7).
    const std::string new_version = new_manifest.version;
    const fs::path version_dir = registry.version_dir(id, new_version);
    // A stale directory can exist when this version was installed before and
    // rolled back; re-extract it fresh from the verified package.
    util::remove_recursive(version_dir);
    const PackageReader reader(package_path);
    reader.extract_payload(version_dir);

    registry.set_current_version(id, new_version); // flip current
    registry.write_manifest_bytes(id, reader.read_entry("lexe.json"));

    InstallationRecord updated = record;
    updated.version = new_version;
    updated.source = chk.package_url; // where this version came from
    updated.installed_at = util::now_utc_string();
    // channel, update_url (user-approved source), publisher_key (pinned),
    // created_files and lastRun are carried over unchanged.
    registry.write_record(updated);

    InstallResult result;
    result.id = id;
    result.version = new_version;
    result.app_dir = registry.app_dir(id);
    return result;
}

void Updater::set_source(const std::string& id, const std::string& url) {
    if (url.empty()) {
        throw UsageError("update source URL must not be empty");
    }
    const Registry registry(paths_);
    // read_record throws NotFoundError when the app is not installed.
    InstallationRecord record = registry.read_record(id);
    // SPEC "Update Ownership": changing the update source requires explicit
    // user approval — `lexe source set` IS that explicit action, and the
    // chosen source becomes the default update source.
    record.update_url = url;
    registry.write_record(record);
}

} // namespace lexe

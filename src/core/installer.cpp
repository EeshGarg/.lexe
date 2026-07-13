// installer — userspace install / uninstall / rollback / repair (SPEC
// "Standard User Flow", FORMAT-0.1 §6 verification, §9 installed layout).
//
// Trust rules implemented here:
//  * nothing is extracted or recorded before the full §6 pipeline passes
//    (signature-before-parse discipline, security invariant #2);
//  * the publisher key pinned in installation.json is the update trust
//    anchor (§7.1) — a package for an already-installed id signed with a
//    different key is a hard error, never a silent takeover;
//  * payload lands in versions/<v>/ via a staging directory so a failed
//    extraction cannot leave a half-written version behind;
//  * the exact lexe.json and hashes.json bytes of every installed version
//    are kept under apps/<id>/meta/<v>/ — the hash source for repair and
//    the restore source for rollback — with the active version's copies at
//    apps/<id>/manifest.json and apps/<id>/hashes.json (FORMAT-0.1 §9).

#include "core/installer.hpp"

#include "core/crypto.hpp"
#include "core/desktop.hpp"
#include "core/error.hpp"
#include "core/package.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"
#include "core/verify.hpp"
#include "core/versioncmp.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace lexe {

namespace {

constexpr std::string_view kPayloadPrefix = "payload/";

/// apps/<id>/meta/<version>/ — the per-version store of the exact lexe.json
/// and hashes.json bytes of an installed version.
fs::path meta_dir(const fs::path& app_dir, const std::string& version) {
    return app_dir / "meta" / version;
}

/// Turn a hashes.json key ("payload/<rel>") into a relative path that is
/// safe to join under the version directory. Returns nullopt for keys
/// outside payload/ (icons/, metadata/ — those are not installed files).
/// The stored hashes.json copy is plain state on disk, not a signed package
/// entry, so its keys are NOT trusted for path building: anything that could
/// escape the version dir throws (security invariant #1).
std::optional<fs::path> payload_relative(const std::string& key) {
    if (key.compare(0, kPayloadPrefix.size(), kPayloadPrefix) != 0) {
        return std::nullopt;
    }
    const std::string rel = key.substr(kPayloadPrefix.size());
    bool ok = !rel.empty() && rel.find('\\') == std::string::npos &&
              rel.find(':') == std::string::npos &&
              rel.find('\0') == std::string::npos;
    std::size_t start = 0;
    while (ok) {
        const std::size_t slash = rel.find('/', start);
        const std::size_t end = (slash == std::string::npos) ? rel.size() : slash;
        const std::string_view segment =
            std::string_view(rel).substr(start, end - start);
        ok = !segment.empty() && segment != "." && segment != "..";
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    if (!ok) {
        throw Error("recorded hashes contain an unsafe payload path: \"" + key +
                    "\"");
    }
    return fs::path(rel);
}

/// One payload file of the stored hashes.json copy.
struct PayloadHash {
    std::string key;    // full hashes.json key ("payload/…")
    fs::path relative;  // safe path under versions/<v>/
    std::string digest; // expected lowercase-hex SHA-256 (FORMAT-0.1 §3)
};

/// Payload entries of a stored hashes.json copy. Throws Error on malformed
/// contents. Keys come back sorted (nlohmann object iteration order).
std::vector<PayloadHash> load_payload_hashes(const fs::path& hashes_file) {
    const nlohmann::json doc = nlohmann::json::parse(
        util::slurp_text(hashes_file), nullptr, /*allow_exceptions=*/false);
    if (doc.is_discarded() || !doc.is_object()) {
        throw Error("recorded hashes are malformed: " + hashes_file.string());
    }
    const auto files = doc.find("files");
    if (files == doc.end() || !files->is_object()) {
        throw Error("recorded hashes are malformed (no \"files\" object): " +
                    hashes_file.string());
    }
    std::vector<PayloadHash> entries;
    for (const auto& item : files->items()) {
        const std::optional<fs::path> relative = payload_relative(item.key());
        if (!relative.has_value()) continue; // icons/, metadata/: not installed
        if (!item.value().is_string()) {
            throw Error("recorded hashes are malformed: digest for \"" +
                        item.key() + "\" is not a string");
        }
        entries.push_back(
            {item.key(), *relative, item.value().get<std::string>()});
    }
    return entries;
}

/// Re-hash installed payload files against the recorded digests; returns the
/// entries that are missing or mismatch.
std::vector<PayloadHash>
corrupt_payload_files(const fs::path& version_dir,
                      const std::vector<PayloadHash>& expected) {
    std::vector<PayloadHash> bad;
    for (const PayloadHash& entry : expected) {
        const fs::path file = version_dir / entry.relative;
        std::error_code ec;
        if (!fs::is_regular_file(file, ec) ||
            crypto::sha256_file_hex(file) != entry.digest) {
            bad.push_back(entry);
        }
    }
    return bad;
}

std::vector<std::string> keys_of(const std::vector<PayloadHash>& entries) {
    std::vector<std::string> keys;
    keys.reserve(entries.size());
    for (const PayloadHash& entry : entries) keys.push_back(entry.key);
    return keys;
}

/// Extract the package's flat `icons/<name>` entries into `dest` so
/// desktop::integrate_app can copy them into the hicolor theme. Entry paths
/// already passed the §2 rules in PackageReader.
void extract_icons(const PackageReader& reader, const fs::path& dest) {
    for (const PackageEntry& entry : reader.entries()) {
        const std::string& path = entry.path;
        if (path.rfind("icons/", 0) != 0) continue;
        const std::string name = path.substr(6);
        if (name.empty() || name.find('/') != std::string::npos) continue;
        util::spit(dest / name, reader.read_entry(path));
    }
}

#ifndef _WIN32
/// ZIP extraction can drop Unix mode bits — FORMAT-0.1 §1 writers (and
/// PackageWriter in particular) store entries with zeroed external
/// attributes, so the extracted entrypoint may land without its exec bit.
/// The launcher self-heals at launch time, but install time is the correct
/// place (e.g. app dirs made read-only afterwards). Owner exec is always
/// added; group/others exec mirror the corresponding read bits.
void ensure_entrypoint_executable(const fs::path& version_dir,
                                  const std::string& entrypoint) {
    std::error_code ec;
    const fs::path exe = version_dir / fs::path(entrypoint);
    if (!fs::is_regular_file(exe, ec)) return;
    const fs::perms current = fs::status(exe, ec).permissions();
    if (ec) return;
    fs::perms add = fs::perms::owner_exec;
    if ((current & fs::perms::group_read) != fs::perms::none) {
        add |= fs::perms::group_exec;
    }
    if ((current & fs::perms::others_read) != fs::perms::none) {
        add |= fs::perms::others_exec;
    }
    fs::permissions(exe, add, fs::perm_options::add, ec); // best effort
}
#endif

void merge_created_files(std::vector<std::string>& into,
                         const std::vector<std::string>& add) {
    for (const std::string& file : add) {
        if (std::find(into.begin(), into.end(), file) == into.end()) {
            into.push_back(file);
        }
    }
}

} // namespace

Installer::Installer(const Paths& paths) : paths_(paths) {}

InstallResult Installer::install(const fs::path& lexe_file,
                                 const InstallOptions& opts) {
    // FORMAT-0.1 §6 stages 1–7 — nothing is trusted or written before this
    // passes. opts.force_arch skips only stage 7 (§6.7).
    const Manifest manifest =
        verify_package_or_throw(lexe_file, /*check_architecture=*/!opts.force_arch);

    const Registry registry(paths_);
    const fs::path app_dir = registry.app_dir(manifest.id); // validates id
    const fs::path version_dir =
        registry.version_dir(manifest.id, manifest.version); // validates version

    InstallationRecord record;
    if (registry.is_installed(manifest.id)) {
        record = registry.read_record(manifest.id);
        // The pinned publisher key is the update trust anchor (FORMAT-0.1
        // §7.1): a different key MUST NOT silently take over an installed id.
        if (record.publisher_key != manifest.publisher_public_key) {
            throw VerificationError(
                "publisher key mismatch for " + manifest.id +
                ": the installed application is pinned to key " +
                record.publisher_key + " but this package is signed with " +
                manifest.publisher_public_key +
                "; refusing to install. Key rotation is not supported in "
                "0.1 — uninstall the application first to accept the new "
                "key (SPEC \"Update Ownership\").");
        }
        std::string current;
        try {
            current = registry.current_version(manifest.id);
        } catch (const NotFoundError&) {
            // No usable current pointer — allow the install to self-heal.
        }
        if (current == manifest.version) {
            throw Error(manifest.id + " " + manifest.version +
                        " is already installed and current; use `lexe repair " +
                        manifest.id + "` to reinstall its files");
        }
    }

    const PackageReader reader(lexe_file);
    const std::vector<std::uint8_t> manifest_bytes =
        reader.read_entry("lexe.json");
    const std::vector<std::uint8_t> hashes_bytes =
        reader.read_entry("metadata/hashes.json");

    // Extract payload/ into a staging dir first, then move into place, so a
    // failed extraction never leaves a half-written versions/<v>/ behind.
    // (Staging lives outside versions/, so rollback never sees it.)
    const fs::path staging = app_dir / (".staging-" + manifest.version);
    util::remove_recursive(staging);
    try {
        reader.extract_payload(staging); // zip-slip safe (package module)
        util::remove_recursive(version_dir);
        fs::create_directories(version_dir.parent_path());
        fs::rename(staging, version_dir);
    } catch (...) {
        util::remove_recursive(staging);
        throw;
    }
#ifndef _WIN32
    ensure_entrypoint_executable(version_dir, manifest.entrypoint_executable);
#endif

    // Per-version copies of the exact lexe.json / hashes.json bytes: the
    // hash source for repair and the restore source for rollback.
    const fs::path meta = meta_dir(app_dir, manifest.version);
    util::spit(meta / "lexe.json", manifest_bytes);
    util::spit(meta / "hashes.json", hashes_bytes);

    // Active-version copies (FORMAT-0.1 §9).
    registry.write_manifest_bytes(manifest.id, manifest_bytes);
    util::spit(app_dir / "hashes.json", hashes_bytes);

    // Desktop integration (recorded no-op on Windows). Previously recorded
    // files are kept: an update re-integrates over them.
    std::vector<std::string> created_files = record.created_files;
    if (opts.desktop_integration) {
        const fs::path icons_staging = app_dir / ".staging-icons";
        util::remove_recursive(icons_staging);
        try {
            extract_icons(reader, icons_staging);
            const desktop::IntegrationResult integration =
                desktop::integrate_app(paths_, manifest, icons_staging);
            merge_created_files(created_files, integration.created_files);
        } catch (...) {
            util::remove_recursive(icons_staging);
            throw;
        }
        util::remove_recursive(icons_staging);
    }

    registry.set_current_version(manifest.id, manifest.version);

    record.id = manifest.id;
    record.version = manifest.version;
    record.source = opts.source.value_or(lexe_file.string());
    record.publisher_key = manifest.publisher_public_key; // trust anchor (§7.1)
    record.channel = opts.channel;
    if (record.update_url.empty() && manifest.updates_enabled) {
        // First install: the manifest's update source becomes the default.
        // A source the user already configured is never silently replaced
        // (SPEC "Update Ownership").
        record.update_url = manifest.updates_manifest_url;
    }
    record.installed_at = util::now_utc_string();
    record.created_files = std::move(created_files);
    registry.write_record(record);

    return InstallResult{manifest.id, manifest.version, app_dir};
}

void Installer::uninstall(const std::string& id, bool purge_data) {
    const Registry registry(paths_);
    const InstallationRecord record = registry.read_record(id); // NotFoundError

    // Desktop-side removal first (refreshes the databases on Linux) …
    desktop::remove_integration(paths_, record.created_files);
    // … then a portable sweep so every recorded file is gone even where the
    // desktop module is a recorded no-op (FORMAT-0.1 §9: uninstall removes
    // everything recorded in installation.json, then the app directory).
    for (const std::string& file : record.created_files) {
        util::remove_recursive(fs::path(file));
    }
    util::remove_recursive(registry.app_dir(id));

    if (purge_data) {
        // Application data is removed ONLY with --purge-data (FORMAT-0.1 §9).
        util::remove_recursive(paths_.data_dir() / id);
    }
}

void Installer::rollback(const std::string& id) {
    const Registry registry(paths_);
    InstallationRecord record = registry.read_record(id); // NotFoundError
    const std::string current = registry.current_version(id);

    // The newest retained version strictly older than current, under the
    // semver-lite total order (FORMAT-0.1 §8).
    std::optional<std::string> target;
    for (const std::string& version : registry.installed_versions(id)) {
        if (!version_less(version, current)) continue;
        if (!target.has_value() || version_less(*target, version)) {
            target = version;
        }
    }
    if (!target.has_value()) {
        throw NotFoundError("no previous version of " + id +
                            " to roll back to (current is " + current + ")");
    }

    registry.set_current_version(id, *target);

    // Restore the active-version copies from the per-version meta store so
    // manifest.json/hashes.json keep describing the active version (§9).
    const fs::path app_dir = registry.app_dir(id);
    const fs::path meta = meta_dir(app_dir, *target);
    std::error_code ec;
    if (fs::is_regular_file(meta / "lexe.json", ec)) {
        registry.write_manifest_bytes(id, util::slurp(meta / "lexe.json"));
    }
    if (fs::is_regular_file(meta / "hashes.json", ec)) {
        util::spit(app_dir / "hashes.json", util::slurp(meta / "hashes.json"));
    }

    record.version = *target;
    registry.write_record(record);
}

RepairReport Installer::repair(const std::string& id,
                               const std::optional<fs::path>& package) {
    const Registry registry(paths_);
    const InstallationRecord record = registry.read_record(id); // NotFoundError
    const std::string current = registry.current_version(id);
    const fs::path app_dir = registry.app_dir(id);
    const fs::path version_dir = registry.version_dir(id, current);

    // Hash source: the hashes.json copy stored at install time (per-version
    // meta store, falling back to the active-version copy).
    std::error_code ec;
    fs::path hashes_file = meta_dir(app_dir, current) / "hashes.json";
    if (!fs::is_regular_file(hashes_file, ec)) {
        hashes_file = app_dir / "hashes.json";
    }
    if (!fs::is_regular_file(hashes_file, ec)) {
        throw Error("no recorded hashes for " + id + " " + current +
                    "; cannot verify the installation");
    }
    const std::vector<PayloadHash> expected = load_payload_hashes(hashes_file);

    RepairReport report;
    const std::vector<PayloadHash> corrupt =
        corrupt_payload_files(version_dir, expected);
    if (corrupt.empty()) {
        report.ok = true;
        return report;
    }

    // A package to re-extract from: the explicit argument, else the original
    // package when record.source still points at a local file (e.g. the
    // cached download an update installed from).
    std::optional<fs::path> pkg = package;
    const bool explicit_package = package.has_value();
    if (!pkg.has_value() && !record.source.empty()) {
        const fs::path source(record.source);
        if (fs::is_regular_file(source, ec)) pkg = source;
    }

    if (pkg.has_value()) {
        try {
            // Nothing is copied out of the package before it passes §6 in
            // full, and it must be exactly the installed release: same id,
            // same version, signed with the pinned publisher key.
            const Manifest m = verify_package_or_throw(*pkg, false);
            if (m.id != id || m.version != current ||
                m.publisher_public_key != record.publisher_key) {
                throw Error("package " + pkg->string() + " is not " + id + " " +
                            current +
                            " signed with the pinned publisher key; cannot "
                            "repair from it");
            }
            const PackageReader reader(*pkg);
            const fs::path staging = app_dir / ".staging-repair";
            util::remove_recursive(staging);
            try {
                // Full zip-slip-safe extraction (restores POSIX exec bits),
                // then copy only the damaged files into place.
                reader.extract_payload(staging);
                for (const PayloadHash& entry : corrupt) {
                    const fs::path from = staging / entry.relative;
                    std::error_code file_ec;
                    if (!fs::is_regular_file(from, file_ec)) {
                        continue; // absent from the package: stays corrupt
                    }
                    const fs::path to = version_dir / entry.relative;
                    fs::create_directories(to.parent_path());
                    fs::copy_file(from, to, fs::copy_options::overwrite_existing);
                    report.repaired_files.push_back(entry.key);
                }
            } catch (...) {
                util::remove_recursive(staging);
                throw;
            }
            util::remove_recursive(staging);
#ifndef _WIN32
            // A repaired entrypoint must come back executable, same as at
            // install time.
            ensure_entrypoint_executable(version_dir, m.entrypoint_executable);
#endif
        } catch (const Error&) {
            if (explicit_package) throw;
            // The cached source turned out unusable — report health only.
            report.repaired_files.clear();
        }
    }

    report.corrupt_files =
        keys_of(corrupt_payload_files(version_dir, expected));
    report.ok = report.corrupt_files.empty();
    return report;
}

} // namespace lexe

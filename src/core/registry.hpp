#pragma once
// registry — installed-application records under `<LEXE_HOME>/apps/<id>/`
// (FORMAT-0.1 §9): installation.json read/write, the manifest.json copy,
// version listing, and the `current` symlink (with the `current.txt` text
// fallback where symlinks are unavailable).

#include "core/manifest.hpp"
#include "core/paths.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace lexe {

/// Contents of `apps/<id>/installation.json` (FORMAT-0.1 §9). The pinned
/// publisher key recorded here is the trust anchor for updates (§7.1).
struct InstallationRecord {
    std::string id;
    std::string version;        // active (current) version string
    std::string source;         // package path/URL the install came from
    std::string publisher_key;  // pinned "ed25519:…" string (§4/§7.1)
    std::string channel = "stable";   // update channel (§7.3)
    std::string update_url;     // configured update manifest source ("" = none)
    std::string installed_at;   // RFC 3339 UTC
    std::string last_run_at;    // RFC 3339 UTC; "" until first `lexe run`
    int last_exit_code = 0;     // exit code of the last `lexe run`
    /// Absolute paths of files created OUTSIDE the app dir (desktop entries,
    /// icons, MIME XML) — exactly what uninstall must remove (§9).
    std::vector<std::string> created_files;
    /// The normalized permission ids the user approved for this version, and a
    /// digest over them (runtime-trust WS2/WS5). The digest is the consent
    /// anchor an update's permission-delta gate compares against.
    std::vector<std::string> approved_permissions;
    std::string permissions_digest;

    /// Parse installation.json text. Throws Error on malformed contents.
    static InstallationRecord from_json(std::string_view json_text);
    std::string to_json() const;
};

/// Accessor for everything under `<LEXE_HOME>/apps/` (FORMAT-0.1 §9).
class Registry {
public:
    explicit Registry(const Paths& paths);

    /// `<LEXE_HOME>/apps/<id>` (not created implicitly).
    std::filesystem::path app_dir(const std::string& id) const;
    /// `<LEXE_HOME>/apps/<id>/versions/<version>`.
    std::filesystem::path version_dir(const std::string& id,
                                      const std::string& version) const;
    /// `<LEXE_HOME>/apps/<id>/meta/<version>` — the per-version store of the
    /// exact lexe.json/hashes.json bytes (hash source for repair, restore
    /// source for rollback). Validates id and version like version_dir.
    std::filesystem::path meta_dir(const std::string& id,
                                   const std::string& version) const;

    // --- application storage taxonomy (WS8): one canonical API for every
    // per-app path. All validate the id (and version) before joining. ---

    /// Per-app PERSISTENT data root (`<home>/data/<id>`). Belongs to the App
    /// ID, not a version; survives ordinary update, rollback and app-only
    /// uninstall; removed only on an explicit purge.
    std::filesystem::path app_data_dir(const std::string& id) const;
    /// Per-app CACHE root (`<cache>/apps/<id>`). Removable independently of
    /// persistent data.
    std::filesystem::path app_cache_dir(const std::string& id) const;
    /// Root under which per-launch private temp directories are created
    /// (`<cache>/runtime-tmp`).
    std::filesystem::path runtime_temp_root() const;
    /// Directory holding operation lock files (`<home>/locks`).
    std::filesystem::path locks_dir() const;
    /// The per-app exclusive-mutation lock file (`<home>/locks/<id>.lock`).
    std::filesystem::path mutation_lock_file(const std::string& id) const;
    /// The single global recovery-coordination lock file
    /// (`<home>/locks/global.recovery.lock`).
    std::filesystem::path global_recovery_lock_file() const;
    /// A per-(id,version) launch-lease lock file.
    std::filesystem::path version_lease_file(const std::string& id,
                                             const std::string& version) const;
    /// The data-owner marker inside app_data_dir(id): records the publisher key
    /// that owns the retained data (WS8 key-continuity for retained data).
    std::filesystem::path data_owner_marker(const std::string& id) const;
    /// Directory holding local publisher-trust records (`<home>/trust`). Outside
    /// every package-controlled path and never bound into the sandbox (WS3).
    std::filesystem::path trust_dir() const;
    /// The local trust record for `id` (`<home>/trust/<id>.json`).
    std::filesystem::path trust_record_file(const std::string& id) const;
    /// True when persistent data is retained for `id` (its data dir exists and
    /// is non-empty), regardless of whether the app is currently installed.
    bool has_retained_data(const std::string& id) const;

    /// Ids of all installed applications (directories with installation.json).
    std::vector<std::string> list_installed() const;
    bool is_installed(const std::string& id) const;

    /// Read/write installation.json. read_record throws NotFoundError when
    /// the app is not installed.
    InstallationRecord read_record(const std::string& id) const;
    void write_record(const InstallationRecord& record) const;

    /// Resolve the active version: the `current` symlink target, falling back
    /// to the `current.txt` text file (FORMAT-0.1 §9). Throws NotFoundError.
    std::string current_version(const std::string& id) const;
    /// Point `current` at versions/<version> (symlink, or current.txt where
    /// symlinks are unavailable). The version directory must exist.
    void set_current_version(const std::string& id, const std::string& version) const;
    /// When disabled, set_current_version skips the symlink attempt and always
    /// writes the `current.txt` text fallback (FORMAT-0.1 §9). Defaults to
    /// enabled; tests use this to exercise the fallback deterministically
    /// (symlink availability on Windows depends on host privileges).
    void set_use_symlinks(bool use) { use_symlinks_ = use; }
    bool use_symlinks() const { return use_symlinks_; }

    /// All version strings present under versions/ (unordered).
    std::vector<std::string> installed_versions(const std::string& id) const;

    /// The manifest.json copy of the active version (FORMAT-0.1 §9).
    /// read_manifest throws NotFoundError when absent.
    Manifest read_manifest(const std::string& id) const;
    /// Store the exact lexe.json bytes of the active version as manifest.json.
    void write_manifest_bytes(const std::string& id,
                              const std::vector<std::uint8_t>& lexe_json_bytes) const;

private:
    Paths paths_;
    bool use_symlinks_ = true;
};

} // namespace lexe

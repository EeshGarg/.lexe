#pragma once
// updater — signed update manifests (FORMAT-0.1 §7). Fetches `update.json`
// and its detached `.sig` from the configured source (https:// in
// production; file:// and plain paths in tests), enforces §7 checks 1–7,
// downloads to cache, and hands the package to the installer. The previous
// version directory is retained for `lexe rollback`.

#include "core/installer.hpp"
#include "core/paths.hpp"

#include <string>

namespace lexe {

/// Result of a dry-run check (`lexe update --check`).
struct UpdateCheck {
    std::string id;
    std::string installed_version;
    std::string available_version; // channel entry's version (§7.3)
    bool update_available = false; // strictly greater per FORMAT-0.1 §8 (§7.7)
    std::string package_url;       // channel package.url
    std::string package_sha256;    // channel package.sha256 (lowercase hex)
};

class Updater {
public:
    explicit Updater(const Paths& paths);

    /// Fetch update.json + .sig from the app's configured source and run
    /// FORMAT-0.1 §7 checks 1 (signature with the INSTALLED publisher key —
    /// key rotation is out of scope, a mismatch aborts), 2 (id match) and
    /// 3 (channel entry exists). No download. Throws NotFoundError when the
    /// app is not installed or has no update source, VerificationError on
    /// §7 violations.
    UpdateCheck check(const std::string& id);

    /// Full §7 flow 1–7: check(), download the package to the cache, verify
    /// its SHA-256 (§7.4) and the full §6 pipeline (§7.5), require matching
    /// id + publisher key (§7.6) and a strictly greater version (§7.7), then
    /// install. Throws Error("already up to date")-style when nothing newer.
    InstallResult apply(const std::string& id);

    /// `lexe source set <id> <url>`: record a new update source in
    /// installation.json (SPEC "Update Ownership": explicit user action).
    void set_source(const std::string& id, const std::string& url);

private:
    Paths paths_;
};

} // namespace lexe

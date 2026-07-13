#pragma once
// installer — userspace install/uninstall/rollback/repair (SPEC "Standard
// User Flow", FORMAT-0.1 §9 installed layout, §6 verification before any
// byte of payload is trusted).

#include "core/manifest.hpp"
#include "core/paths.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace lexe {

/// Options for Installer::install.
struct InstallOptions {
    /// Update channel recorded in installation.json (FORMAT-0.1 §7.3).
    std::string channel = "stable";
    /// Source recorded in installation.json; defaults to the package path.
    /// The updater sets this to the download URL.
    std::optional<std::string> source;
    /// Create desktop entry/icons/MIME (desktop.hpp). Disabled by tests and
    /// by `--no-integration` style flows.
    bool desktop_integration = true;
    /// Skip only the §6.7 architecture-compatibility stage (tests and
    /// explicit "install anyway" flows). Every other verification stage
    /// (FORMAT-0.1 §6.1–§6.6) always runs.
    bool force_arch = false;
};

/// What an install/update produced.
struct InstallResult {
    std::string id;
    std::string version;
    std::filesystem::path app_dir; // <LEXE_HOME>/apps/<id>
};

/// Result of Installer::repair.
struct RepairReport {
    bool ok = false;                          // true when app is now healthy
    std::vector<std::string> repaired_files;  // payload files re-extracted
    /// hashes.json keys ("payload/…") that are still missing or hash-
    /// mismatched — populated by a report-only run (no usable package) and
    /// by anything a repair attempt could not fix.
    std::vector<std::string> corrupt_files;
};

class Installer {
public:
    explicit Installer(const Paths& paths);

    /// Full §6 pipeline (with architecture check), then extract payload/ to
    /// versions/<version>/, write manifest.json + installation.json, flip
    /// `current`, run desktop integration. When the app is already installed,
    /// the publisher key must match (§7.6) and the previous version directory
    /// is retained for rollback (§7). Throws VerificationError / Error.
    InstallResult install(const std::filesystem::path& lexe_file,
                          const InstallOptions& opts = {});

    /// Remove everything recorded in installation.json, then the app dir
    /// (FORMAT-0.1 §9). `<LEXE_HOME>/data/<id>` is removed only when
    /// purge_data is true. Throws NotFoundError when not installed.
    void uninstall(const std::string& id, bool purge_data = false);

    /// Flip `current` back to the most recent retained previous version and
    /// update the records (SPEC "Rollback"). Throws NotFoundError when there
    /// is no previous version.
    void rollback(const std::string& id);

    /// Re-verify installed payload files against the recorded hashes; when
    /// `package` is given, re-extract mismatching/missing files from it after
    /// verifying it (§6). Without a package, reports health only.
    RepairReport repair(const std::string& id,
                        const std::optional<std::filesystem::path>& package = std::nullopt);

private:
    Paths paths_;
};

} // namespace lexe

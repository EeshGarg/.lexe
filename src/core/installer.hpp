#pragma once
// installer — userspace install/uninstall/rollback/repair (SPEC "Standard
// User Flow", FORMAT-0.1 §9 installed layout, §6 verification before any
// byte of payload is trusted).

#include "core/lock.hpp"
#include "core/manifest.hpp"
#include "core/paths.hpp"

#include <filesystem>
#include <memory>
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
    /// Explicit consent to grant NEW permissions on an update (runtime-trust
    /// WS5). Without it, an update whose normalized permission set expands
    /// beyond the installed approved set is refused with PermissionError. A
    /// bare "--yes" never sets this — approving new authority is a separate,
    /// deliberate act.
    bool allow_permission_expansion = false;
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

/// Result of Installer::check_health (HARDENING.md §D). A structured result, not
/// a free-form string: `ok` is true only when `issues` is empty.
struct HealthReport {
    bool ok = false;
    std::vector<std::string> issues; // human-readable health problems
};

class Installer {
public:
    explicit Installer(const Paths& paths);
    /// Test/embedding seam: inject a lock manager (e.g. an in-process fake) so
    /// concurrency behavior can be exercised deterministically (runtime-trust
    /// WS9). Production code uses the single-argument constructor.
    Installer(const Paths& paths,
              std::shared_ptr<OperationLockManager> locks);

    /// How long an operation waits for a conflicting same-App mutation before
    /// giving up with BusyError. Default: a bounded wait (a brief overlap waits;
    /// a long-held lock eventually yields busy). Tests set WaitPolicy::none()
    /// for deterministic contention checks.
    void set_mutation_wait(const WaitPolicy& wait) { mutation_wait_ = wait; }

    /// Full §6 pipeline (with architecture check), then extract payload/ to
    /// versions/<version>/, write manifest.json + installation.json, flip
    /// `current`, run desktop integration. When the app is already installed,
    /// the publisher key must match (§7.6) and the previous version directory
    /// is retained for rollback (§7). Throws VerificationError / Error.
    InstallResult install(const std::filesystem::path& lexe_file,
                          const InstallOptions& opts = {});

    /// The three explicit uninstall modes (runtime-trust WS8).
    enum class UninstallMode {
        AppOnly,     // remove binaries + integration; PRESERVE data and cache
        AppAndCache, // remove binaries + integration + cache; PRESERVE data
        PurgeData,   // remove binaries + integration + cache + persistent data
    };

    /// Remove the application per `mode`. Application-only removal preserves
    /// persistent data (and cache); PurgeData removes every application-owned
    /// root. Throws NotFoundError when not installed. Full data removal must be
    /// an explicit choice (PurgeData) — never a side effect of a bare confirm.
    void uninstall(const std::string& id,
                   UninstallMode mode = UninstallMode::AppOnly);

    /// Flip `current` back to the most recent retained previous version and
    /// update the records (SPEC "Rollback"). Throws NotFoundError when there
    /// is no previous version.
    void rollback(const std::string& id);

    /// Re-verify installed payload files against the recorded hashes; when
    /// `package` is given, re-extract mismatching/missing files from it after
    /// verifying it (§6). Without a package, reports health only.
    RepairReport repair(const std::string& id,
                        const std::optional<std::filesystem::path>& package = std::nullopt);

    /// Post-install health check of the active version (HARDENING.md §D):
    /// re-parses the manifest and confirms identity, that the declared
    /// entrypoint exists inside the committed version root and (on POSIX) is
    /// executable, and that every recorded payload file is present and matches
    /// its hash. Executes nothing. Throws NotFoundError when not installed.
    HealthReport check_health(const std::string& id) const;

    /// Finish or roll back an interrupted install transaction for `id`
    /// (HARDENING.md §A/§C): a pre-promotion transaction is rolled back
    /// (previous version untouched), a promoted one is completed forward (new
    /// version made active). Idempotent: a no-op when there is no journal.
    /// Takes the per-app mutation lock so recovery serializes with any
    /// concurrent mutation of the same App ID (runtime-trust WS9).
    void recover(const std::string& id);
    /// Run recover() for every application with a pending transaction journal,
    /// under the global recovery lock. Safe to call at process startup.
    void recover_all();

private:
    /// recover()'s body, assuming the per-app mutation lock is already held —
    /// used by install() (which holds the lock) and by recover()/recover_all().
    void recover_locked(const std::string& id);

    Paths paths_;
    std::shared_ptr<OperationLockManager> locks_;
    WaitPolicy mutation_wait_ = WaitPolicy::bounded(std::chrono::seconds(10));
};

} // namespace lexe

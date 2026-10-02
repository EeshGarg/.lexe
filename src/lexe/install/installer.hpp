#pragma once
// installer — userspace install/uninstall/rollback/repair (SPEC "Standard
// User Flow", FORMAT-0.1 §9 installed layout, §6 verification before any
// byte of payload is trusted).

#include "lexe/state/lock.hpp"
#include "lexe/package/manifest.hpp"
#include "lexe/base/paths.hpp"

#include <cstddef>
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
    /// Explicit consent to move an application BACKWARDS to an older version
    /// (FORMAT-0.1 §7.1).
    ///
    /// `lexe update` already refuses to go backwards (§7 check 7). A direct
    /// install did not: the package is authentic, so nothing in verification
    /// objects, and `lexe install app-1.0.0.lexe` over 3.0.0 silently returned
    /// the user to 1.0.0 with a success exit and no mention of it.
    ///
    /// That matters because "open this .lexe" is the PRIMARY user gesture. An
    /// old signed package is exactly what an attacker who cannot forge a
    /// signature still has, and a downgrade to a known-vulnerable version is a
    /// real outcome to reach by a double-click.
    ///
    /// Downgrading stays possible -- it is legitimate when a new version is
    /// broken, and refusing outright would make the runtime worse than the
    /// problem. It just has to be asked for. A bare `--yes` does NOT set this,
    /// for the same reason it does not grant new permissions: confirming an
    /// action is not the same as choosing a different one.
    bool allow_downgrade = false;
    /// Explicit consent to grant NEW permissions on an update (runtime-trust
    /// WS5). Without it, an update whose normalized permission set expands
    /// beyond the installed approved set is refused with PermissionError. A
    /// bare "--yes" never sets this — approving new authority is a separate,
    /// deliberate act.
    bool allow_permission_expansion = false;
    /// The user deliberately chose to TRUST this signing key locally (runtime-
    /// trust WS4), not merely to consent to this install. Recorded in the trust
    /// record as an explicit trust decision. A plain install leaves this false
    /// (the App-ID/key binding is still recorded, but only as "accepted").
    /// Separate from permission consent, and never set by a bare "--yes".
    bool explicit_trust = false;
    /// ADMIN COMPILE APPROVAL (Definitive Architecture §5/§7). Installing a
    /// `applicationType: "portable"` package COMPILES its source on this
    /// machine, and that is an operation the owner of the installation
    /// authorizes explicitly — never something a package obtains by declaring
    /// itself portable. Without it a portable install is refused with
    /// PermissionError before any toolchain is probed or any build runs.
    ///
    /// It authorizes the OPERATION. It grants no privilege: the build runs
    /// unprivileged, in the launcher's sandbox, with the network denied. A
    /// bare "--yes" never sets it.
    bool approve_compile = false;
};

/// Options for Installer::repair.
struct RepairOptions {
    /// Same approval as InstallOptions::approve_compile. A portable
    /// application's entrypoint cannot be re-extracted from its package —
    /// the package never contained it — so repairing one means compiling
    /// again, which needs the same explicit authorization the install did.
    bool approve_compile = false;
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
    /// WHY a repair could not proceed, when something specific went wrong.
    ///
    /// Repair used to swallow this. The catch-all around the restore attempt
    /// discarded the exception whenever the package came from the recorded
    /// source rather than the command line, so two quite different situations
    /// arrived at the user as the same sentence — "N corrupt or missing file(s)
    /// that could not be repaired":
    ///
    ///   the recorded digests had been tampered with, so the comparison failed
    ///   against LOCAL records while the package itself verified perfectly
    ///
    ///   `source.txt` had been redirected at a package signed by a key that is
    ///   not the pinned publisher key — which is exactly the fingerprint of
    ///   somebody having edited it, and is the kind of event this runtime
    ///   reports well everywhere else
    ///
    /// Worse, the generic verification hint was attached to the first case,
    /// telling the user to re-download a package that was never the problem.
    /// Empty when the repair simply had nothing usable to work from.
    std::string blocked_reason;
    /// The actionable step for `blocked_reason`, when its throw site had one.
    std::string blocked_hint;
};

/// Result of Installer::check_health (HARDENING.md §D). A structured result, not
/// a free-form string: `ok` is true only when `issues` is empty.
struct HealthReport {
    bool ok = false;
    std::vector<std::string> issues; // human-readable health problems
};

/// Result of Installer::garbage_collect (runtime-trust WS8). Deterministic and
/// typed — never a free-form string. Every installed version appears in exactly
/// one bucket.
struct GcReport {
    std::vector<std::string> removed;        // version dirs reclaimed
    std::vector<std::string> retained;       // active / newer / rollback / txn
    std::vector<std::string> skipped_in_use; // a launch lease is held: kept
    std::vector<std::string> failed;         // removal failed; active untouched
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

    /// Paths `uninstall` declined to delete because they lie outside the
    /// directories this runtime writes into. Cleared at the start of each
    /// uninstall; read it afterwards.
    ///
    /// `installation.json` records absolute paths and is local unsigned state,
    /// so a recorded path is not a licence to remove a file — see
    /// `may_delete` in integration.hpp, which this mirrors deliberately. A
    /// refusal is neither obeyed nor swallowed: a record naming a path outside
    /// the tree is itself a finding, and the caller decides how loudly to say
    /// so.
    const std::vector<std::string>& refused_paths() const {
        return refused_paths_;
    }

    /// The policy currently in force. Exists so a test can assert the DEFAULT,
    /// which otherwise nothing observes: every contention test in the suite
    /// calls set_mutation_wait(WaitPolicy::none()) to stay deterministic, so
    /// changing the default below to none() or forever() would break no test
    /// while changing what a contended `lexe install` does -- from "waits out a
    /// brief overlap" to "refuses instantly", or to "hangs". docs/ERRORS.md §7:
    /// a check cannot detect what it holds constant, and every check here holds
    /// this constant.
    const WaitPolicy& mutation_wait() const { return mutation_wait_; }

    /// Full §6 pipeline (with architecture check), then extract payload/ to
    /// versions/<version>/, write manifest.json + installation.json, flip
    /// `current`, run desktop integration. When the app is already installed,
    /// the publisher key must match (§7.6) and the previous version directory
    /// is retained for rollback (§7). Throws VerificationError / Error.
    InstallResult install(const std::filesystem::path& lexe_file,
                          const InstallOptions& opts = {});

    /// `lexe uninstall`: remove the installed program -- everything the
    /// installation needs to execute, its desktop integration, and its
    /// installation debris (cache, downloaded updates). Keeps exactly the
    /// locations appstate.hpp marks SurvivesUninstall: persistent data, the
    /// local trust record, compatibility preferences and error history, so a
    /// reinstall behaves as a RETURNING installation.
    ///
    /// Throws NotFoundError when not installed; BusyError when a version is
    /// running, or when an interrupted purge of `id` has not finished --
    /// uninstall never deletes data, so it will not finish a purge either.
    void uninstall(const std::string& id);

    /// What `purge` found and removed.
    struct PurgeReport {
        bool was_installed = false;
        /// A purge journal was already present: this call FINISHED an
        /// interrupted purge rather than starting one.
        bool finished_interrupted = false;
        /// Descriptions (appstate.hpp) of the locations that existed and are
        /// now gone, plus "desktop integration" when any was recorded.
        std::vector<std::string> removed;
    };

    /// `lexe purge`: make .LEXE forget the application. Removes every location
    /// in appstate.hpp's table except the inert per-app mutation lock --
    /// installation, data, trust record (binding, explicit trust AND any local
    /// block), preferences, error history, cache -- whether or not it is
    /// currently installed.
    ///
    /// Transactional and fail-closed. A journal is written before anything is
    /// changed and removed only after a post-check finds every location gone;
    /// until then the purge is unfinished, `install` finishes it first, and
    /// launch, uninstall and the trust commands refuse. Throws (and leaves the
    /// journal) rather than report success over anything that remains.
    ///
    /// Throws NotFoundError when .LEXE holds no state for `id` and no purge is
    /// pending; BusyError when a version is running.
    PurgeReport purge(const std::string& id);

    /// Flip `current` back to the most recent retained previous version and
    /// update the records (SPEC "Rollback"). Throws NotFoundError when there
    /// is no previous version.
    void rollback(const std::string& id);

    /// Reclaim superseded immutable versions of `id` (runtime-trust WS8),
    /// keeping ALWAYS: the active version, every version at or newer than it,
    /// the newest `keep_previous` versions older than active (rollback-
    /// reachable), any version referenced by a pending transaction journal, and
    /// any version a running launch holds a lease on. A version is removed only
    /// after its exclusive gc-lock is taken (so a running launch is never
    /// disturbed — it is reported in skipped_in_use instead). A removal failure
    /// is recorded in `failed` and never invalidates the active install. Takes
    /// the per-app mutation lock. Throws NotFoundError when not installed.
    GcReport garbage_collect(const std::string& id,
                             std::size_t keep_previous = 1);

    /// Re-verify installed payload files against the recorded hashes; when
    /// `package` is given, re-extract mismatching/missing files from it after
    /// verifying it (§6). Without a package, reports health only.
    ///
    /// A portable application's recorded set also covers what its build
    /// PRODUCED (`build.json`). Those files are not in the package and cannot
    /// be copied back out of it, so repairing one compiles again — with
    /// `opts.approve_compile`, or not at all.
    RepairReport repair(const std::string& id,
                        const std::optional<std::filesystem::path>& package = std::nullopt,
                        const RepairOptions& opts = {});

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
    /// Returns the version it completed FORWARD, or nullopt when it found
    /// nothing to do or rolled a transaction back.
    ///
    /// The caller needs to know because `install` runs recovery first, and
    /// what it then reports depends on who did the work. An install that
    /// healed an interrupted one and an install that found the state already
    /// correct end in the same place by different routes, and only one of them
    /// changed anything.
    std::optional<std::string> recover_locked(const std::string& id);

    /// Where `uninstall` moves `apps/<id>` before deleting it:
    /// `apps/.removing/<id>`. The rename is what makes removal atomic.
    std::filesystem::path removal_tomb(const std::string& id) const;
    /// Deletes a tombstone a killed uninstall left behind. Best-effort;
    /// assumes the per-app mutation lock is held.
    void sweep_removed_locked(const std::string& id);

    /// Exclusive gc-holds on every version of `id` found in its own
    /// directories, or BusyError naming the one that is running. Taken BEFORE a
    /// removal writes anything, so a refusal leaves nothing behind.
    std::vector<LaunchLease> hold_versions_or_refuse(const std::string& id);

    /// The removal shared by uninstall and purge (lock held, versions held):
    /// integration, recorded files, the atomic detach of `apps/<id>`, version
    /// leases, and every RemovedByUninstall location. Works whether or not the
    /// app is still installed, so it can finish what an interrupted run left.
    void remove_installation_locked(const std::string& id);

    /// purge()'s body with the per-app mutation lock already held. Also how
    /// install finishes an interrupted purge before it does anything else.
    PurgeReport purge_locked(const std::string& id);

    Paths paths_;
    std::shared_ptr<OperationLockManager> locks_;
    WaitPolicy mutation_wait_ = WaitPolicy::bounded(std::chrono::seconds(10));
    std::vector<std::string> refused_paths_;
};

} // namespace lexe

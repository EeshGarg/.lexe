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
#include "core/fault.hpp"
#include "core/json_strict.hpp"
#include "core/limits.hpp"
#include "core/package.hpp"
#include "core/permissions.hpp"
#include "core/registry.hpp"
#include "core/transaction.hpp"
#include "core/util.hpp"
#include "core/verify.hpp"
#include "core/versioncmp.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
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
    // Strict parse (HARDENING.md §E): the installed hashes.json is the source of
    // truth for repair; reject duplicate keys rather than silently collapse.
    const nlohmann::json doc = json_strict::parse(
        util::slurp_text(hashes_file), "installed hashes.json",
        limits::kMaxHashesBytes);
    if (!doc.is_object()) {
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

/// Staged validation (HARDENING.md §A step 5): the freshly extracted tree at
/// `version_dir` must match the signed hashes.json that was staged beside it,
/// BEFORE it is promoted into place. Throws VerificationError on any mismatch.
void validate_staged_tree(const fs::path& version_dir,
                          const fs::path& staged_hashes) {
    const std::vector<PayloadHash> expected = load_payload_hashes(staged_hashes);
    const std::vector<PayloadHash> corrupt =
        corrupt_payload_files(version_dir, expected);
    if (!corrupt.empty()) {
        throw VerificationError(
            "staged installation failed validation (" +
            std::to_string(corrupt.size()) +
            " payload file(s) missing or mismatched): " +
            keys_of(corrupt).front() + (corrupt.size() > 1 ? ", …" : ""));
    }
}

/// Health checks for a version directory (HARDENING.md §D): the manifest-
/// declared entrypoint must exist inside the version root and be a regular file,
/// and on POSIX it must be executable. Returns the list of problems found (empty
/// = healthy). Package §6 verification does NOT check that the declared
/// entrypoint is actually present in the payload — this does. It executes
/// nothing: package-controlled content is never run to verify the package.
std::vector<std::string> entrypoint_health_issues(const fs::path& version_dir,
                                                  const Manifest& manifest) {
    std::vector<std::string> issues;
    const fs::path exe = version_dir / fs::path(manifest.entrypoint_executable);
    std::error_code ec;
    if (!fs::is_regular_file(exe, ec)) {
        issues.push_back("declared entrypoint \"" +
                         manifest.entrypoint_executable +
                         "\" is missing from the payload");
        return issues; // nothing more to check
    }
#ifndef _WIN32
    const fs::perms perms = fs::status(exe, ec).permissions();
    if (!ec && (perms & fs::perms::owner_exec) == fs::perms::none) {
        issues.push_back("entrypoint \"" + manifest.entrypoint_executable +
                         "\" is not executable");
    }
#endif
    return issues;
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

Installer::Installer(const Paths& paths)
    : paths_(paths), locks_(make_lock_manager(paths)) {}

Installer::Installer(const Paths& paths,
                     std::shared_ptr<OperationLockManager> locks)
    : paths_(paths), locks_(std::move(locks)) {}

InstallResult Installer::install(const fs::path& lexe_file,
                                 const InstallOptions& opts) {
    // FORMAT-0.1 §6 stages 1–7 — nothing is trusted or written before this
    // passes. opts.force_arch skips only stage 7 (§6.7). Verification is
    // read-only on the package, so it runs before we take any lock.
    const Manifest manifest =
        verify_package_or_throw(lexe_file, /*check_architecture=*/!opts.force_arch);

    // Runtime-trust WS9: serialize every mutation of this App ID. A concurrent
    // install/update/rollback/remove/recovery of the SAME id waits (bounded)
    // or fails with BusyError; DIFFERENT ids take different locks and proceed
    // concurrently. Held (RAII) for the rest of this call.
    const AppLock app_lock =
        locks_->lock_app_mutation(manifest.id, "install", mutation_wait_);

    // Finish or roll back any transaction a previous run left interrupted for
    // THIS app before starting a new one (HARDENING.md §A/§C). Done UNDER the
    // mutation lock, so recovery never races another operation.
    recover_locked(manifest.id);

    const Registry registry(paths_);
    const fs::path app_dir = registry.app_dir(manifest.id); // validates id
    (void)registry.version_dir(manifest.id, manifest.version); // validates version

    InstallationRecord record;
    std::string previous_version; // active version before this install ("" = fresh)
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
        try {
            previous_version = registry.current_version(manifest.id);
        } catch (const NotFoundError&) {
            // No usable current pointer — allow the install to self-heal.
        }
        if (previous_version == manifest.version) {
            throw Error(manifest.id + " " + manifest.version +
                        " is already installed and current; use `lexe repair " +
                        manifest.id + "` to reinstall its files");
        }
    }

    // Runtime-trust WS2: parse + normalize + validate the requested permissions
    // (reject unknown / duplicate / conflicting) BEFORE anything is installed,
    // and record the approved set + digest as the consent anchor.
    const NormalizedPermissions requested_perms =
        normalize_permissions(manifest.permissions);

    // Runtime-trust WS8: retained-data key continuity. If persistent data is
    // retained for this id under a DIFFERENT publisher key (e.g. after an
    // app-only uninstall), a new publisher must NOT inherit it — refuse until
    // the user explicitly purges. The same publisher reinstalling inherits it.
    {
        const fs::path owner = registry.data_owner_marker(manifest.id);
        std::error_code ec;
        if (fs::is_regular_file(owner, ec)) {
            std::string prior = util::slurp_text(owner);
            while (!prior.empty() &&
                   (prior.back() == '\n' || prior.back() == '\r' ||
                    prior.back() == ' ')) {
                prior.pop_back();
            }
            if (!prior.empty() && prior != manifest.publisher_public_key) {
                throw RetainedDataConflict(
                    "persistent data for " + manifest.id +
                    " belongs to a different publisher key; purge it first "
                    "(`lexe remove " + manifest.id +
                    " --purge-data`) to install under the new key");
            }
        }
    }

    // Runtime-trust WS5: on an UPGRADE, an update that expands the approved
    // permission set requires explicit consent — a bare confirmation never
    // grants new authority. Removals and reordering are not an expansion.
    if (registry.is_installed(manifest.id) && !previous_version.empty()) {
        const NormalizedPermissions approved =
            normalized_from_ids(record.approved_permissions);
        const PermissionDelta delta =
            permission_delta(approved, requested_perms);
        if (delta.expands() && !opts.allow_permission_expansion) {
            std::string added;
            for (const std::string& id : delta.added) {
                if (!added.empty()) added += ", ";
                added += id;
            }
            throw PermissionError(
                "update to " + manifest.id + " " + manifest.version +
                " requests new permissions not previously approved: " + added +
                ". Re-run with explicit permission approval to grant them.");
        }
    }

    const PackageReader reader(lexe_file);
    const std::vector<std::uint8_t> manifest_bytes =
        reader.read_entry("lexe.json");
    const std::vector<std::uint8_t> hashes_bytes =
        reader.read_entry("metadata/hashes.json");

    // The installation record we intend to commit (created_files are added
    // after desktop integration). It is stored in the transaction journal so a
    // crash-recovered promotion can write a faithful record (HARDENING.md §A).
    InstallationRecord new_record = record; // carries prior update_url/createdFiles
    new_record.id = manifest.id;
    new_record.version = manifest.version;
    new_record.source = opts.source.value_or(lexe_file.string());
    new_record.publisher_key = manifest.publisher_public_key; // trust anchor §7.1
    new_record.channel = opts.channel;
    if (new_record.update_url.empty() && manifest.updates_enabled) {
        // First install: the manifest's update source becomes the default. A
        // source the user already configured is never silently replaced
        // (SPEC "Update Ownership").
        new_record.update_url = manifest.updates_manifest_url;
    }
    new_record.installed_at = util::now_utc_string();
    new_record.approved_permissions = requested_perms.ids;
    new_record.permissions_digest = requested_perms.digest;

    // Transactional staged install (HARDENING.md §A). Nothing becomes active
    // until the staged tree is validated and atomically promoted; a failure
    // before promotion leaves the previous version untouched.
    InstallTransaction txn(paths_, manifest.id, manifest.version);
    try {
        fault::maybe("before-staging");
        txn.begin(previous_version, new_record.to_json());

        // (3) Extract payload and (4) write meta INTO staging — never the live
        // version directory.
        fault::maybe("during-extraction"); // staging exists, extraction not done
        reader.extract_payload(txn.staging_version_dir());
        fault::maybe("after-extraction");
#ifndef _WIN32
        ensure_entrypoint_executable(txn.staging_version_dir(),
                                     manifest.entrypoint_executable);
#endif
        util::spit(txn.staging_meta_dir() / "lexe.json", manifest_bytes);
        util::spit(txn.staging_meta_dir() / "hashes.json", hashes_bytes);
        txn.mark_staged();
        fault::maybe("after-staged");

        // (5) Staged validation: the extracted tree must match its own signed
        // hashes, and pass the health check (declared entrypoint present +
        // executable), BEFORE anything is promoted. Because this gate runs
        // before the `current` flip, an upgrade to a package that fails its
        // health check NEVER replaces the working version — the previous
        // known-good version simply stays active (HARDENING.md §D auto-rollback,
        // achieved by never activating an unhealthy version).
        validate_staged_tree(txn.staging_version_dir(),
                             txn.staging_meta_dir() / "hashes.json");
        {
            const std::vector<std::string> issues =
                entrypoint_health_issues(txn.staging_version_dir(), manifest);
            if (!issues.empty()) {
                throw VerificationError("post-install health check failed: " +
                                        issues.front());
            }
        }
        txn.mark_verified();

        // (6) Atomic promotion of versions/<v> + meta/<v>.
        fault::maybe("before-promote");
        txn.promote();
        fault::maybe("after-promote"); // version in place, not yet active

        // (7) Activation — idempotently redone by recovery if interrupted:
        // active copies, desktop integration, record, then the atomic `current`
        // flip last.
        registry.write_manifest_bytes(manifest.id, manifest_bytes);
        util::spit(app_dir / "hashes.json", hashes_bytes);

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
        new_record.created_files = std::move(created_files);
        registry.write_record(new_record);

        registry.set_current_version(manifest.id, manifest.version); // atomic
        txn.mark_record_updated();
        fault::maybe("after-record"); // activated, cleanup not yet done

        // (8) Done: drop staging and clear the journal.
        txn.commit();
    } catch (const fault::Injected&) {
        // Simulate a crash: leave the journal mid-transaction so recovery runs
        // on the NEXT invocation (recover_all), not here. Do not clean up.
        throw;
    } catch (...) {
        // A genuine error: drive the app back to a consistent state per the
        // journal, then propagate. Pre-promotion → rolled back (previous
        // untouched); post-promotion → completed forward (new version active).
        try {
            recover(manifest.id);
        } catch (...) {
        }
        throw;
    }

    // Runtime-trust WS8: record the data owner. Persistent data belongs to the
    // App ID, and this marker pins the publisher key that owns it so a later
    // reinstall under a DIFFERENT key cannot inherit retained data. Written
    // only after a fully committed install; a pre-existing marker (same key)
    // is left as-is. Never touched: the installer does not read or execute the
    // app's own data — this is a sibling metadata file it owns.
    {
        std::error_code ec;
        fs::create_directories(registry.app_data_dir(manifest.id), ec);
        util::spit(registry.data_owner_marker(manifest.id),
                   std::string_view(manifest.publisher_public_key));
    }

    return InstallResult{manifest.id, manifest.version, app_dir};
}

void Installer::recover(const std::string& id) {
    // Recovery mutates the app, so it takes the per-app mutation lock — this is
    // what makes recovery serialize with a same-App install/update/rollback
    // (runtime-trust WS9).
    const AppLock app_lock =
        locks_->lock_app_mutation(id, "recover", mutation_wait_);
    recover_locked(id);
}

void Installer::recover_locked(const std::string& id) {
    const Registry registry(paths_);
    TransactionJournal journal;
    try {
        journal = read_journal(paths_, id);
    } catch (const Error&) {
        // An unreadable/corrupt journal: leave the app as-is rather than guess.
        return;
    }
    if (journal.phase == TxnPhase::None) return;

    InstallTransaction txn(paths_, id, journal.target_version);

    // Pre-promotion → roll back. The previous version and `current` were never
    // touched, so removing staging (and any orphan target dirs) restores the
    // app to "previous active" or "safely absent".
    if (journal.phase == TxnPhase::Preparing ||
        journal.phase == TxnPhase::Staged ||
        journal.phase == TxnPhase::Verified) {
        txn.abort();
        return;
    }

    // Promoted / RecordUpdated → complete forward. The version + meta are in
    // place and were validated before promotion; make them active idempotently.
    const fs::path app_dir = registry.app_dir(id);
    const fs::path meta = registry.meta_dir(id, journal.target_version);
    std::error_code ec;
    if (!fs::is_regular_file(meta / "lexe.json", ec) ||
        !fs::is_regular_file(meta / "hashes.json", ec)) {
        // Promotion metadata is gone — cannot complete; fall back to rollback.
        txn.abort();
        return;
    }
    const std::vector<std::uint8_t> manifest_bytes =
        util::slurp(meta / "lexe.json");
    const std::vector<std::uint8_t> hashes_bytes =
        util::slurp(meta / "hashes.json");
    const Manifest manifest = Manifest::parse(manifest_bytes);

    registry.write_manifest_bytes(id, manifest_bytes);
    util::spit(app_dir / "hashes.json", hashes_bytes);
#ifndef _WIN32
    ensure_entrypoint_executable(registry.version_dir(id, journal.target_version),
                                 manifest.entrypoint_executable);
#endif

    // Rebuild the record from the journal's pending record (falling back to a
    // minimal record from the manifest), then refresh the desktop entry + MIME
    // best-effort (no icons on the recovery path — the package may be gone).
    InstallationRecord rec;
    try {
        rec = InstallationRecord::from_json(journal.pending_record);
    } catch (const Error&) {
        rec.id = id;
        rec.publisher_key = manifest.publisher_public_key;
        rec.installed_at = util::now_utc_string();
    }
    rec.id = id;
    rec.version = journal.target_version;
    std::vector<std::string> created = rec.created_files;
    try {
        const desktop::IntegrationResult integration = desktop::integrate_app(
            paths_, manifest, app_dir / ".txn-staging" / "no-icons");
        merge_created_files(created, integration.created_files);
    } catch (...) {
        // Desktop integration is best-effort; a recovered install still works
        // from the CLI and a later `lexe repair` restores full integration.
    }
    rec.created_files = std::move(created);
    registry.write_record(rec);

    registry.set_current_version(id, journal.target_version); // atomic activation
    txn.commit();
}

void Installer::recover_all() {
    // Serialize recovery passes with one another (runtime-trust WS9). Per-app
    // recovery still takes each app's own mutation lock underneath this, so a
    // busy app is skipped rather than blocked (unrelated apps are not
    // serialized by this global lock — they only wait to be enumerated).
    const GlobalRecoveryLock recovery_lock =
        locks_->lock_global_recovery(mutation_wait_);

    std::error_code ec;
    const fs::path apps = paths_.apps_dir();
    if (!fs::is_directory(apps, ec)) return;
    // A crashed FRESH install has a txn.json but no installation.json, so we
    // cannot use list_installed(); scan every app dir for a journal.
    std::vector<std::string> ids;
    for (const auto& entry : fs::directory_iterator(apps, ec)) {
        std::error_code e2;
        if (!entry.is_directory(e2)) continue;
        if (fs::is_regular_file(entry.path() / "txn.json", e2)) {
            ids.push_back(entry.path().filename().string());
        }
    }
    for (const std::string& id : ids) {
        try {
            recover(id);
        } catch (...) {
            // One app's recovery failure must not block the others.
        }
    }
}

HealthReport Installer::check_health(const std::string& id) const {
    const Registry registry(paths_);
    const std::string current = registry.current_version(id); // NotFoundError
    const fs::path app_dir = registry.app_dir(id);
    const fs::path version_dir = registry.version_dir(id, current);
    const Manifest manifest = registry.read_manifest(id); // NotFoundError

    HealthReport report;
    // Identity: the active manifest must describe THIS application.
    if (manifest.id != id) {
        report.issues.push_back("manifest id \"" + manifest.id +
                                "\" does not match installed id \"" + id + "\"");
    }
    // Entrypoint present + executable.
    for (std::string& issue : entrypoint_health_issues(version_dir, manifest)) {
        report.issues.push_back(std::move(issue));
    }
    // Integrity: every recorded payload file present and matching its hash.
    std::error_code ec;
    fs::path hashes_file = meta_dir(app_dir, current) / "hashes.json";
    if (!fs::is_regular_file(hashes_file, ec)) {
        hashes_file = app_dir / "hashes.json";
    }
    if (fs::is_regular_file(hashes_file, ec)) {
        const std::vector<PayloadHash> expected =
            load_payload_hashes(hashes_file);
        for (const PayloadHash& bad :
             corrupt_payload_files(version_dir, expected)) {
            report.issues.push_back("payload file missing or corrupt: " +
                                    bad.key);
        }
    } else {
        report.issues.push_back("no recorded hashes to verify against");
    }
    report.ok = report.issues.empty();
    return report;
}

void Installer::uninstall(const std::string& id, UninstallMode mode) {
    const AppLock app_lock =
        locks_->lock_app_mutation(id, "remove", mutation_wait_);
    const Registry registry(paths_);
    const InstallationRecord record = registry.read_record(id); // NotFoundError

    // Runtime-trust WS9: never delete the binaries of an app that is currently
    // running. A launch holds a SHARED lease on its version; probe every
    // installed version with a non-blocking EXCLUSIVE gc-lock. If any is leased,
    // a live process is using it — refuse with BusyError (the documented
    // policy) rather than silently pull files out from under it. Holding the
    // exclusive locks across the removal also prevents a launch from STARTING
    // mid-uninstall (its shared lease would block on our exclusive hold).
    std::vector<LaunchLease> version_locks;
    for (const std::string& v : registry.installed_versions(id)) {
        std::optional<LaunchLease> vlock = locks_->try_lock_version_for_gc(id, v);
        if (!vlock.has_value()) {
            throw BusyError("cannot remove " + id +
                            ": it is currently running (version " + v +
                            " is in use); close it and try again");
        }
        version_locks.push_back(std::move(*vlock));
    }

    // Application binaries + integration are removed in EVERY mode.
    // Desktop-side removal first (refreshes the databases on Linux) …
    desktop::remove_integration(paths_, record.created_files);
    // … then a portable sweep so every recorded file is gone even where the
    // desktop module is a recorded no-op (FORMAT-0.1 §9: uninstall removes
    // everything recorded in installation.json, then the app directory).
    for (const std::string& file : record.created_files) {
        util::remove_recursive(fs::path(file));
    }
    util::remove_recursive(registry.app_dir(id));

    // Cache is removed by AppAndCache and PurgeData; independently of data.
    if (mode == UninstallMode::AppAndCache || mode == UninstallMode::PurgeData) {
        util::remove_recursive(registry.app_cache_dir(id));
    }
    // Persistent data is removed ONLY by an explicit PurgeData. Application-only
    // removal leaves it (and its owner marker) intact for a later reinstall.
    if (mode == UninstallMode::PurgeData) {
        util::remove_recursive(registry.app_data_dir(id));
    }
}

void Installer::rollback(const std::string& id) {
    const AppLock app_lock =
        locks_->lock_app_mutation(id, "rollback", mutation_wait_);
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

GcReport Installer::garbage_collect(const std::string& id,
                                    std::size_t keep_previous) {
    const AppLock app_lock =
        locks_->lock_app_mutation(id, "cleanup", mutation_wait_);
    const Registry registry(paths_);

    // NotFoundError when the app is not installed (no active version).
    const std::string active = registry.current_version(id);

    // Deterministic order over all installed versions (semver-lite, §8).
    std::vector<std::string> versions = registry.installed_versions(id);
    std::sort(versions.begin(), versions.end(),
              [](const std::string& a, const std::string& b) {
                  return version_less(a, b);
              });

    // Build the retain set. ALWAYS keep the active version and everything at or
    // newer than it (a rollback target may be newer; forward re-install stays
    // possible). Keep the newest `keep_previous` versions OLDER than active
    // (the rollback-reachable window).
    std::set<std::string> retain;
    retain.insert(active);
    std::vector<std::string> older; // ascending
    for (const std::string& v : versions) {
        if (version_less(v, active)) {
            older.push_back(v);
        } else {
            retain.insert(v); // active or newer — never GC'd
        }
    }
    for (std::size_t i = 0; i < older.size(); ++i) {
        if (older.size() - i <= keep_previous) retain.insert(older[i]);
    }
    // A version referenced by an interrupted transaction must survive so
    // recovery can still complete or roll it back.
    try {
        const TransactionJournal journal = read_journal(paths_, id);
        if (journal.phase != TxnPhase::None && !journal.target_version.empty()) {
            retain.insert(journal.target_version);
        }
    } catch (const Error&) {
        // Unreadable journal: keep the retain set as-is (active + window are
        // already protected); never remove a version we are unsure about.
    }

    GcReport report;
    for (const std::string& v : versions) {
        if (retain.count(v) != 0) {
            report.retained.push_back(v);
            continue;
        }
        // Remove only a version no launch is using. try-exclusive is
        // non-blocking: a held shared lease means a live process → skip it, and
        // keep the exclusive lock across the removal so a launch cannot start
        // on this version mid-delete.
        std::optional<LaunchLease> vlock =
            locks_->try_lock_version_for_gc(id, v);
        if (!vlock.has_value()) {
            report.skipped_in_use.push_back(v);
            continue;
        }
        bool ok = true;
        try {
            util::remove_recursive(registry.version_dir(id, v));
            util::remove_recursive(registry.meta_dir(id, v));
        } catch (...) {
            ok = false; // a failure here never touches the active version
        }
        std::error_code ec;
        if (ok && !fs::exists(registry.version_dir(id, v), ec)) {
            report.removed.push_back(v);
        } else {
            report.failed.push_back(v);
        }
    }
    return report;
}

RepairReport Installer::repair(const std::string& id,
                               const std::optional<fs::path>& package) {
    const AppLock app_lock =
        locks_->lock_app_mutation(id, "repair", mutation_wait_);
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

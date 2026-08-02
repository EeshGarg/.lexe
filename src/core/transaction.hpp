// transaction — crash-safe install/upgrade of one version of one application
// (HARDENING.md §A). Every mutation of apps/<id>/ during an install goes
// through here, and the transaction STATE is written to an explicit journal
// (apps/<id>/txn.json) rather than inferred from scattered filesystem
// artifacts. On interruption, recovery reads the journal and drives the app to
// exactly one of: previous version active, new version active, or safely
// absent (see installer::recover / recover_all, and HARDENING §C).
//
// Ordering (the promotion is atomic where the platform supports rename):
//   Preparing  staging created; payload extracted + meta written INTO staging
//   Staged     staging fully populated
//   Verified   staged tree re-hashed against its own hashes.json
//   Promoted   staging/version + staging/meta renamed into versions/<v> +
//              meta/<v>; the previous version and `current` are still untouched
//   (installer then flips `current` — the atomic activation — and writes the
//    installation record)
//   RecordUpdated  activation done; only staging cleanup + journal clear remain
//
// A failure at or before Verified rolls back (staging and any orphan
// versions/<v>/meta/<v> for THIS target are removed — all installer-owned
// descendants of apps/<id>/, never a path derived from package content). A
// failure at Promoted or later completes forward. The previous version's
// directory is never touched by a promotion, so an interrupted upgrade always
// leaves the previous install intact until the atomic flip.

#pragma once

#include "core/paths.hpp"
#include "core/registry.hpp"

#include <filesystem>
#include <string>
#include <string_view>

namespace lexe {

enum class TxnPhase {
    None,          // no active transaction
    Preparing,     // staging created; extraction/meta write in progress
    Staged,        // staging fully populated (payload + meta)
    Verified,      // staged tree validated against its hashes.json
    Promoted,      // versions/<v> + meta/<v> in place; current not yet flipped
    RecordUpdated, // current flipped + record written; only cleanup remains
};

std::string to_string(TxnPhase phase);
TxnPhase txn_phase_from_string(std::string_view name);

/// The on-disk transaction state (apps/<id>/txn.json). `pending_record` is the
/// installation.json content the installer intends to write on completion; it
/// is carried opaquely so recovery can finish a Promoted transaction without
/// re-deriving trust data. Written atomically (temp file + rename).
struct TransactionJournal {
    std::string id;
    std::string target_version;
    std::string previous_version; // current version before this txn ("" = fresh)
    TxnPhase phase = TxnPhase::None;
    std::string started_at;       // RFC 3339 UTC
    std::string pending_record;   // installation.json text to write on commit

    std::string to_json() const;
    static TransactionJournal from_json(std::string_view text);
};

/// Drives one install/upgrade transaction. Not copyable.
class InstallTransaction {
public:
    InstallTransaction(Paths paths, std::string id, std::string target_version);
    InstallTransaction(const InstallTransaction&) = delete;
    InstallTransaction& operator=(const InstallTransaction&) = delete;

    /// Begin the transaction: clear any prior staging, record the version being
    /// replaced (for rollback bookkeeping) and the intended installation record,
    /// and write the Preparing journal. The caller then extracts the payload
    /// into staging_version_dir() and writes lexe.json/hashes.json into
    /// staging_meta_dir().
    void begin(const std::string& previous_version,
               const std::string& pending_record);

    std::filesystem::path staging_version_dir() const;
    std::filesystem::path staging_meta_dir() const;

    void mark_staged();
    void mark_verified();

    /// Atomically move the staged version and meta into their final locations
    /// (removing any stale installer-owned versions/<v> and meta/<v> first) and
    /// write the Promoted journal. After this, the version's files are present
    /// but not yet active.
    void promote();

    /// The installer calls this after flipping `current` and writing the record.
    void mark_record_updated();

    /// Transaction done: remove staging and delete the journal.
    void commit();

    /// Roll back a not-yet-promoted transaction: remove staging plus any orphan
    /// versions/<v>/meta/<v> for THIS target, then delete the journal. The
    /// previous version and `current` pointer are untouched. Never throws
    /// (usable from a catch handler).
    void abort() noexcept;

    const std::string& id() const { return id_; }
    const std::string& target_version() const { return target_version_; }
    std::filesystem::path journal_path() const;

private:
    void write_journal(TxnPhase phase);

    Paths paths_;
    Registry registry_;
    std::string id_;
    std::string target_version_;
    std::string previous_version_;
    std::string pending_record_;
};

/// Read the journal for `id`, or a journal with phase None when none exists.
TransactionJournal read_journal(const Paths& paths, const std::string& id);

/// The staging root for `id` (apps/<id>/.txn-staging), exposed for recovery
/// cleanup and tests.
std::filesystem::path staging_root(const Paths& paths, const std::string& id);

} // namespace lexe

// transaction — see transaction.hpp. The journal is written atomically
// (temp + rename) so it is never observed half-written; every deletion target
// is an installer-owned descendant of apps/<id>/ (id and version validated by
// the registry) — never a path derived from package content.

#include "core/transaction.hpp"

#include "core/error.hpp"
#include "core/fault.hpp"
#include "core/json_strict.hpp"
#include "core/limits.hpp"
#include "core/util.hpp"

#include <nlohmann/json.hpp>

#include <system_error>
#include <utility>

namespace fs = std::filesystem;

namespace lexe {

std::string to_string(TxnPhase phase) {
    switch (phase) {
        case TxnPhase::None: return "None";
        case TxnPhase::Preparing: return "Preparing";
        case TxnPhase::Staged: return "Staged";
        case TxnPhase::Verified: return "Verified";
        case TxnPhase::Promoted: return "Promoted";
        case TxnPhase::RecordUpdated: return "RecordUpdated";
    }
    return "None";
}

TxnPhase txn_phase_from_string(std::string_view name) {
    if (name == "Preparing") return TxnPhase::Preparing;
    if (name == "Staged") return TxnPhase::Staged;
    if (name == "Verified") return TxnPhase::Verified;
    if (name == "Promoted") return TxnPhase::Promoted;
    if (name == "RecordUpdated") return TxnPhase::RecordUpdated;
    return TxnPhase::None;
}

// ------------------------------------------------------------------ Journal

std::string TransactionJournal::to_json() const {
    nlohmann::ordered_json j;
    j["id"] = id;
    j["targetVersion"] = target_version;
    j["previousVersion"] = previous_version;
    j["phase"] = to_string(phase);
    j["startedAtUtc"] = started_at;
    j["pendingRecord"] = pending_record;
    return j.dump(2) + "\n";
}

TransactionJournal TransactionJournal::from_json(std::string_view text) {
    const nlohmann::json j =
        json_strict::parse(text, "transaction journal", limits::kMaxJournalBytes);
    if (!j.is_object()) {
        throw Error("transaction journal: top level must be a JSON object");
    }
    TransactionJournal out;
    auto str = [&](const char* key) -> std::string {
        const auto it = j.find(key);
        if (it == j.end() || !it->is_string()) {
            throw Error(std::string("transaction journal: missing/invalid \"") +
                        key + "\"");
        }
        return it->get<std::string>();
    };
    out.id = str("id");
    out.target_version = str("targetVersion");
    out.previous_version = str("previousVersion");
    out.phase = txn_phase_from_string(str("phase"));
    out.started_at = str("startedAtUtc");
    out.pending_record = str("pendingRecord");
    return out;
}

namespace {

/// Write `text` to `file` atomically (the canonical helper is util::write_atomic;
/// this thin wrapper keeps the call sites below readable).
void atomic_write(const fs::path& file, const std::string& text) {
    util::write_atomic(file, text);
}

} // namespace

// --------------------------------------------------------------- free helpers

fs::path staging_root(const Paths& paths, const std::string& id) {
    const Registry registry(paths);
    return registry.app_dir(id) / ".txn-staging";
}

TransactionJournal read_journal(const Paths& paths, const std::string& id) {
    const Registry registry(paths);
    const fs::path jp = registry.app_dir(id) / "txn.json";
    std::error_code ec;
    if (!fs::is_regular_file(jp, ec)) {
        TransactionJournal none;
        none.id = id;
        none.phase = TxnPhase::None;
        return none;
    }
    return TransactionJournal::from_json(util::slurp_text(jp));
}

// ----------------------------------------------------------- InstallTransaction

InstallTransaction::InstallTransaction(Paths paths, std::string id,
                                       std::string target_version)
    : paths_(std::move(paths)), registry_(paths_), id_(std::move(id)),
      target_version_(std::move(target_version)) {
    // Validate id/version up front (throws on a hostile id/version) so every
    // path this object forms is installer-owned and path-safe.
    (void)registry_.version_dir(id_, target_version_);
}

fs::path InstallTransaction::journal_path() const {
    return registry_.app_dir(id_) / "txn.json";
}

fs::path InstallTransaction::staging_version_dir() const {
    return staging_root(paths_, id_) / "version";
}

fs::path InstallTransaction::staging_meta_dir() const {
    return staging_root(paths_, id_) / "meta";
}

void InstallTransaction::write_journal(TxnPhase phase) {
    TransactionJournal j;
    j.id = id_;
    j.target_version = target_version_;
    j.previous_version = previous_version_;
    j.phase = phase;
    j.started_at = util::now_utc_string();
    j.pending_record = pending_record_;
    fs::create_directories(registry_.app_dir(id_));
    atomic_write(journal_path(), j.to_json());
}

void InstallTransaction::begin(const std::string& previous_version,
                               const std::string& pending_record) {
    previous_version_ = previous_version;
    pending_record_ = pending_record;
    // A fresh staging tree; discard any remnant from an earlier attempt.
    util::remove_recursive(staging_root(paths_, id_));
    fs::create_directories(staging_version_dir());
    fs::create_directories(staging_meta_dir());
    write_journal(TxnPhase::Preparing);
}

void InstallTransaction::mark_staged() { write_journal(TxnPhase::Staged); }
void InstallTransaction::mark_verified() { write_journal(TxnPhase::Verified); }

void InstallTransaction::promote() {
    const fs::path version_target = registry_.version_dir(id_, target_version_);
    const fs::path meta_target = registry_.meta_dir(id_, target_version_);

    // Remove any stale installer-owned target dirs from a prior partial attempt.
    util::remove_recursive(version_target);
    util::remove_recursive(meta_target);
    fs::create_directories(version_target.parent_path());
    fs::create_directories(meta_target.parent_path());

    std::error_code ec;
    // meta first (pure metadata), then the payload version dir.
    fs::rename(staging_meta_dir(), meta_target, ec);
    if (ec) {
        throw Error("transaction: cannot promote meta into place: " +
                    meta_target.string());
    }
    // Crash BETWEEN the two renames: meta/<v> is in place, versions/<v> is not,
    // and the journal still says Verified — recovery must roll this back
    // cleanly (HARDENING.md §C "during replacement").
    fault::maybe("during-promote");
    fs::rename(staging_version_dir(), version_target, ec);
    if (ec) {
        throw Error("transaction: cannot promote version into place: " +
                    version_target.string());
    }
    write_journal(TxnPhase::Promoted);
}

void InstallTransaction::mark_record_updated() {
    write_journal(TxnPhase::RecordUpdated);
}

void InstallTransaction::commit() {
    util::remove_recursive(staging_root(paths_, id_));
    std::error_code ec;
    fs::remove(journal_path(), ec);
}

void InstallTransaction::abort() noexcept {
    try {
        util::remove_recursive(staging_root(paths_, id_));
        // A partial promote may have created orphan target dirs; they are
        // installer-owned (id+version validated) and not active, so remove them.
        util::remove_recursive(registry_.version_dir(id_, target_version_));
        util::remove_recursive(registry_.meta_dir(id_, target_version_));
        std::error_code ec;
        fs::remove(journal_path(), ec);
    } catch (...) {
        // abort must never throw; best-effort cleanup only.
    }
}

} // namespace lexe

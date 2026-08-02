// transaction / staged-install tests (HARDENING.md §A). Proves the journal is
// explicit and round-trips, that a clean install commits (no journal/staging
// left behind), that recovery is a no-op when clean, and that recovery both
// rolls back a pre-promotion transaction and completes a promoted one. The
// exhaustive per-failpoint crash matrix is in test_crash_recovery.cpp (§C).

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/installer.hpp"
#include "core/manifest.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/transaction.hpp"
#include "core/util.hpp"

#include <filesystem>
#include <string>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

/// Build a signed package for `id`@`version` into `work`.
fs::path build_pkg(const fs::path& work, const crypto::KeyPair& key,
                   const std::string& id, const std::string& version) {
    test::TestAppSpec spec;
    spec.id = id;
    spec.version = version;
    spec.public_key = test::encode_public_key_str(key.public_key);
    const test::TestAppTree tree =
        test::make_test_app_tree(work / ("tree-" + version), spec);
    PackageWriter::Inputs in;
    in.payload_dir = tree.payload_dir;
    in.manifest_file = tree.manifest_file;
    const fs::path out = work / (id + "-" + version + ".lexe");
    PackageWriter::write(in, key, out);
    return out;
}

} // namespace

TEST_SUITE("transaction") {

TEST_CASE("the journal round-trips through JSON with every phase") {
    test::TempLexeHome home;
    for (TxnPhase phase :
         {TxnPhase::Preparing, TxnPhase::Staged, TxnPhase::Verified,
          TxnPhase::Promoted, TxnPhase::RecordUpdated}) {
        TransactionJournal j;
        j.id = "com.example.app";
        j.target_version = "2.0.0";
        j.previous_version = "1.0.0";
        j.phase = phase;
        j.started_at = "2026-01-01T00:00:00Z";
        j.pending_record = R"({"id":"com.example.app","version":"2.0.0"})";
        const TransactionJournal back =
            TransactionJournal::from_json(j.to_json());
        CHECK(back.id == j.id);
        CHECK(back.target_version == j.target_version);
        CHECK(back.previous_version == j.previous_version);
        CHECK(back.phase == phase);
        CHECK(back.pending_record == j.pending_record);
        CHECK(to_string(back.phase) == to_string(phase));
    }
}

TEST_CASE("a successful install commits: no journal, no staging left behind") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const fs::path pkg = build_pkg(work, key, "com.example.app", "1.0.0");

    Installer(paths).install(pkg, InstallOptions{});

    const Registry registry(paths);
    CHECK(registry.current_version("com.example.app") == "1.0.0");
    // The transaction state is explicit and cleared on commit.
    CHECK_FALSE(fs::exists(registry.app_dir("com.example.app") / "txn.json"));
    CHECK_FALSE(fs::exists(staging_root(paths, "com.example.app")));
    // read_journal reports None when there is no journal.
    CHECK(read_journal(paths, "com.example.app").phase == TxnPhase::None);
}

TEST_CASE("recover_all is a no-op when nothing is pending (idempotent)") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    Installer(paths).install(build_pkg(work, key, "com.example.app", "1.0.0"),
                             InstallOptions{});

    Installer inst(paths);
    inst.recover_all();
    inst.recover_all(); // twice — must not damage a healthy install
    CHECK(Registry(paths).current_version("com.example.app") == "1.0.0");
    CHECK(Registry(paths).is_installed("com.example.app"));
}

TEST_CASE("recover ROLLS BACK a pre-promotion transaction") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    Installer(paths).install(build_pkg(work, key, "com.example.app", "1.0.0"),
                             InstallOptions{});

    // Simulate a crash mid-staging of a 2.0.0 install: a Verified journal and a
    // populated staging dir, but no promotion.
    InstallTransaction txn(paths, "com.example.app", "2.0.0");
    txn.begin("1.0.0", R"({"id":"com.example.app","version":"2.0.0"})");
    lexe::util::spit(txn.staging_version_dir() / "bin" / "app",
                     std::string_view("staged\n"));
    txn.mark_staged();
    txn.mark_verified();
    REQUIRE(read_journal(paths, "com.example.app").phase == TxnPhase::Verified);

    Installer(paths).recover("com.example.app");

    const Registry registry(paths);
    CHECK(registry.current_version("com.example.app") == "1.0.0"); // untouched
    CHECK_FALSE(fs::exists(staging_root(paths, "com.example.app")));
    CHECK(read_journal(paths, "com.example.app").phase == TxnPhase::None);
    CHECK_FALSE(fs::exists(registry.version_dir("com.example.app", "2.0.0")));
}

TEST_CASE("recover COMPLETES a promoted transaction (crash after promote)") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    Installer(paths).install(build_pkg(work, key, "com.example.app", "1.0.0"),
                             InstallOptions{});

    // Drive a real transaction to Promoted for 2.0.0, then STOP (as if the
    // process died right after promotion, before the current flip / record).
    const fs::path pkg2 = build_pkg(work, key, "com.example.app", "2.0.0");
    const PackageReader reader(pkg2);
    const Manifest m2 = Manifest::parse(reader.read_entry("lexe.json"));
    InstallationRecord pending;
    pending.id = "com.example.app";
    pending.version = "2.0.0";
    pending.publisher_key = m2.publisher_public_key;
    pending.installed_at = "2026-01-01T00:00:00Z";

    InstallTransaction txn(paths, "com.example.app", "2.0.0");
    txn.begin("1.0.0", pending.to_json());
    reader.extract_payload(txn.staging_version_dir());
    lexe::util::spit(txn.staging_meta_dir() / "lexe.json",
                     reader.read_entry("lexe.json"));
    lexe::util::spit(txn.staging_meta_dir() / "hashes.json",
                     reader.read_entry("metadata/hashes.json"));
    txn.mark_staged();
    txn.mark_verified();
    txn.promote();
    REQUIRE(read_journal(paths, "com.example.app").phase == TxnPhase::Promoted);

    const Registry registry(paths);
    // Still 1.0.0 active at this point — promotion did not activate anything.
    CHECK(registry.current_version("com.example.app") == "1.0.0");

    Installer(paths).recover("com.example.app");

    // Completed forward: 2.0.0 now active, record consistent, journal cleared,
    // 1.0.0 retained for rollback.
    CHECK(registry.current_version("com.example.app") == "2.0.0");
    CHECK(registry.read_record("com.example.app").version == "2.0.0");
    CHECK(read_journal(paths, "com.example.app").phase == TxnPhase::None);
    CHECK(fs::exists(registry.version_dir("com.example.app", "1.0.0")));
    CHECK_FALSE(fs::exists(staging_root(paths, "com.example.app")));
}

} // TEST_SUITE("transaction")

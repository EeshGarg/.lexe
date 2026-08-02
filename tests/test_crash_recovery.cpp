// crash-recovery matrix (HARDENING.md §C). At every deterministic failpoint in
// the install transaction we simulate a crash (LEXE_TEST_FAULT), then run the
// recovery routine as if the installer restarted, and prove the app is left in
// exactly ONE of: previous version active, new version active, or safely
// absent — never a partially extracted active application. Recovery is also
// proven idempotent (running it twice does not damage a valid install).

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/installer.hpp"
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

struct ScopedFault {
    explicit ScopedFault(const std::string& site) {
        util::set_env("LEXE_TEST_FAULT", site);
    }
    ~ScopedFault() { util::unset_env("LEXE_TEST_FAULT"); }
};

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

// Every install failpoint, and whether recovery COMPLETES it forward (the fault
// fired at/after promotion) or ROLLS it back (before promotion).
struct Failpoint {
    const char* site;
    bool completes_forward;
};
constexpr Failpoint kFailpoints[] = {
    {"before-staging", false},    {"during-extraction", false},
    {"after-extraction", false},  {"after-staged", false},
    {"before-promote", false},    {"during-promote", false},
    {"after-promote", true},      {"after-record", true},
};

const char* kId = "com.example.app";

/// After recovery there must be no journal and no staging left behind, and the
/// active application (if any) must be COMPLETE (repair reports healthy) — never
/// partially extracted.
void assert_consistent(const Paths& paths) {
    const Registry registry(paths);
    CHECK(read_journal(paths, kId).phase == TxnPhase::None);
    CHECK_FALSE(fs::exists(staging_root(paths, kId)));
    if (registry.is_installed(kId)) {
        const std::string current = registry.current_version(kId);
        CHECK(fs::is_directory(registry.version_dir(kId, current)));
        CHECK(Installer(paths).repair(kId).ok); // active version is complete
    }
}

} // namespace

TEST_SUITE("crash_recovery") {

TEST_CASE("fresh-install crash at every failpoint recovers to a valid state") {
    for (const Failpoint& fp : kFailpoints) {
        CAPTURE(fp.site);
        test::TempLexeHome home;
        const Paths paths = Paths::detect();
        const crypto::KeyPair key = test::make_keypair();
        const fs::path work = home.path() / "work";
        fs::create_directories(work);
        const fs::path pkg = build_pkg(work, key, kId, "1.0.0");

        {
            ScopedFault fault(fp.site);
            CHECK_THROWS(Installer(paths).install(pkg, InstallOptions{}));
        }

        // Restart: recovery drives the app to a valid state.
        Installer(paths).recover_all();
        assert_consistent(paths);

        const Registry registry(paths);
        if (fp.completes_forward) {
            // Promotion happened, so recovery completes the fresh install.
            CHECK(registry.is_installed(kId));
            CHECK(registry.current_version(kId) == "1.0.0");
        } else {
            // Rolled back: the app is safely absent.
            CHECK_FALSE(registry.is_installed(kId));
            CHECK_FALSE(fs::exists(registry.version_dir(kId, "1.0.0")));
        }

        // Idempotent: a second recovery does not change anything.
        Installer(paths).recover_all();
        assert_consistent(paths);
    }
}

TEST_CASE("upgrade crash at every failpoint preserves or advances the version") {
    for (const Failpoint& fp : kFailpoints) {
        CAPTURE(fp.site);
        test::TempLexeHome home;
        const Paths paths = Paths::detect();
        const crypto::KeyPair key = test::make_keypair();
        const fs::path work = home.path() / "work";
        fs::create_directories(work);

        // A healthy 1.0.0 baseline.
        Installer(paths).install(build_pkg(work, key, kId, "1.0.0"),
                                 InstallOptions{});
        const fs::path pkg2 = build_pkg(work, key, kId, "2.0.0");

        {
            ScopedFault fault(fp.site);
            CHECK_THROWS(Installer(paths).install(pkg2, InstallOptions{}));
        }

        // The previous version is ALWAYS intact until the atomic switch.
        const Registry registry(paths);
        CHECK(fs::is_directory(registry.version_dir(kId, "1.0.0")));

        Installer(paths).recover_all();
        assert_consistent(paths);

        CHECK(registry.is_installed(kId)); // never lost
        if (fp.completes_forward) {
            CHECK(registry.current_version(kId) == "2.0.0"); // advanced
            CHECK(registry.read_record(kId).version == "2.0.0");
            CHECK(fs::is_directory(registry.version_dir(kId, "1.0.0"))); // retained
        } else {
            CHECK(registry.current_version(kId) == "1.0.0"); // preserved
            CHECK_FALSE(fs::exists(registry.version_dir(kId, "2.0.0")));
        }

        Installer(paths).recover_all(); // idempotent
        assert_consistent(paths);
        CHECK(registry.current_version(kId) ==
              (fp.completes_forward ? "2.0.0" : "1.0.0"));
    }
}

TEST_CASE("recovery of a crash DURING rollback is still idempotent") {
    // A fault before promotion leaves staging; if recovery itself were
    // interrupted, re-running it must still converge. We approximate an
    // interrupted rollback by leaving a stale staging dir + Verified journal
    // and running recovery twice.
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    Installer(paths).install(build_pkg(work, key, kId, "1.0.0"), InstallOptions{});

    InstallTransaction txn(paths, kId, "2.0.0");
    txn.begin("1.0.0", R"({"id":"com.example.app","version":"2.0.0"})");
    util::spit(txn.staging_version_dir() / "x", std::string_view("y"));
    txn.mark_verified();

    Installer(paths).recover(kId);
    Installer(paths).recover(kId); // again — must not damage the 1.0.0 install
    assert_consistent(paths);
    CHECK(Registry(paths).current_version(kId) == "1.0.0");
}

} // TEST_SUITE("crash_recovery")

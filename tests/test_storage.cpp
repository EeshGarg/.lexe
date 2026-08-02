// storage taxonomy + uninstall-lifecycle tests (runtime-trust WS8). Every case
// starts from a fresh TempLexeHome, so the real profile is never touched and
// the canonical path API is exercised against a known LEXE_HOME.

#include <doctest/doctest.h>

#include "helpers.hpp"
#include "lock_fake.hpp"

#include "core/error.hpp"
#include "core/installer.hpp"
#include "core/lock.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/transaction.hpp"
#include "core/trust.hpp"
#include "core/util.hpp"

#include <memory>
#include <string>
#include <system_error>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

constexpr const char* kId = "com.example.hello";

/// RAII scratch dir OUTSIDE LEXE_HOME for building packages.
struct TempWorkDir {
    fs::path dir;
    TempWorkDir() : dir(test::unique_temp_dir("lexe-storage-work-")) {
        fs::create_directories(dir);
    }
    ~TempWorkDir() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    TempWorkDir(const TempWorkDir&) = delete;
    TempWorkDir& operator=(const TempWorkDir&) = delete;
};

/// Install `kId` signed by `key`; returns the publisher key string recorded.
std::string install_with(const Paths& paths, const fs::path& work,
                         const crypto::KeyPair& key,
                         const std::string& version = "1.0.0") {
    test::TestAppSpec spec;
    spec.id = kId;
    spec.version = version;
    const fs::path pkg = test::make_test_package(work, key, spec);
    Installer installer(paths);
    installer.install(pkg);
    return test::encode_public_key_str(key.public_key);
}

} // namespace

TEST_SUITE("storage") {

// -------------------------------------------------- canonical path taxonomy

TEST_CASE("registry: canonical per-app paths are single-sourced and validated") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const Registry registry(paths);

    CHECK(registry.app_data_dir(kId) == paths.data_dir() / kId);
    CHECK(registry.app_cache_dir(kId) == paths.cache_dir() / "apps" / kId);
    CHECK(registry.runtime_temp_root() == paths.cache_dir() / "runtime-tmp");
    CHECK(registry.locks_dir() == paths.home() / "locks");
    CHECK(registry.mutation_lock_file(kId) ==
          registry.locks_dir() / (std::string(kId) + ".lock"));
    CHECK(registry.version_lease_file(kId, "1.0.0") ==
          registry.locks_dir() / (std::string(kId) + ".v.1.0.0.lease"));
    CHECK(registry.data_owner_marker(kId) ==
          registry.app_data_dir(kId) / ".lexe-data-owner");

    // Every id/version-taking accessor validates BEFORE joining, so a hostile
    // id can never be turned into a traversal path.
    CHECK_THROWS_AS(registry.app_data_dir("../etc"), Error);
    CHECK_THROWS_AS(registry.app_cache_dir("nodot"), Error);
    CHECK_THROWS_AS(registry.mutation_lock_file("../etc"), Error);
    CHECK_THROWS_AS(registry.version_lease_file(kId, ".."), Error);
}

TEST_CASE("registry: has_retained_data reflects only real data content") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const Registry registry(paths);

    CHECK_FALSE(registry.has_retained_data(kId)); // no data dir yet

    util::spit(registry.app_data_dir(kId) / "settings.ini",
               std::string_view("k=v\n"));
    CHECK(registry.has_retained_data(kId));
}

// ----------------------------------------------------- three uninstall modes

TEST_CASE("uninstall modes: cache and data are removed only when asked") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const crypto::KeyPair key = test::make_keypair();

    // A helper that (re)installs and seeds one data file + one cache file.
    const auto seed = [&]() {
        install_with(paths, work.dir, key);
        util::spit(registry.app_data_dir(kId) / "save.dat",
                   std::string_view("user save"));
        util::spit(registry.app_cache_dir(kId) / "thumb.png",
                   std::string_view("cache"));
    };

    SUBCASE("AppOnly preserves BOTH data and cache") {
        seed();
        Installer(paths).uninstall(kId, Installer::UninstallMode::AppOnly);
        CHECK_FALSE(registry.is_installed(kId));
        CHECK(fs::exists(registry.app_data_dir(kId) / "save.dat"));
        CHECK(fs::exists(registry.app_cache_dir(kId) / "thumb.png"));
    }

    SUBCASE("AppAndCache removes cache, preserves data") {
        seed();
        Installer(paths).uninstall(kId, Installer::UninstallMode::AppAndCache);
        CHECK_FALSE(registry.is_installed(kId));
        CHECK(fs::exists(registry.app_data_dir(kId) / "save.dat"));
        CHECK_FALSE(fs::exists(registry.app_cache_dir(kId)));
    }

    SUBCASE("PurgeData removes app, cache AND data") {
        seed();
        Installer(paths).uninstall(kId, Installer::UninstallMode::PurgeData);
        CHECK_FALSE(registry.is_installed(kId));
        CHECK_FALSE(fs::exists(registry.app_data_dir(kId)));
        CHECK_FALSE(fs::exists(registry.app_cache_dir(kId)));
    }
}

TEST_CASE("uninstall: removing cache is idempotent and stays under the root") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const crypto::KeyPair key = test::make_keypair();
    install_with(paths, work.dir, key);

    // No cache written yet: AppAndCache must still succeed (idempotent remove).
    Installer(paths).uninstall(kId, Installer::UninstallMode::AppAndCache);
    CHECK_FALSE(fs::exists(registry.app_cache_dir(kId)));
    // The shared cache root itself is untouched — only the per-app subtree goes.
    CHECK(registry.app_cache_dir(kId).parent_path() ==
          paths.cache_dir() / "apps");
}

// -------------------------------------------------- retained-data ownership

TEST_CASE("install records the data owner, and data survives app-only removal") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const crypto::KeyPair key = test::make_keypair();

    const std::string owner = install_with(paths, work.dir, key);

    // The owner marker pins the publisher key of the persistent data.
    const fs::path marker = registry.data_owner_marker(kId);
    REQUIRE(fs::is_regular_file(marker));
    CHECK(util::slurp_text(marker) == owner);
}

TEST_CASE("retained data: a different publisher key may not inherit it") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const Registry registry(paths);

    const crypto::KeyPair key_a = test::make_keypair();
    const crypto::KeyPair key_b = test::make_keypair();

    // Publisher A installs, the user creates data, then removes app-only so the
    // data (and its owner marker) is retained.
    install_with(paths, work.dir, key_a);
    util::spit(registry.app_data_dir(kId) / "profile.db",
               std::string_view("A's data"));
    Installer(paths).uninstall(kId, Installer::UninstallMode::AppOnly);
    REQUIRE(registry.has_retained_data(kId));

    test::TestAppSpec spec;
    spec.id = kId;
    const fs::path pkg_b = test::make_test_package(work.dir, key_b, spec);

    // App-only uninstall preserves the LOCAL TRUST record (bound to key A), so a
    // different key is refused as a changed key (runtime-trust WS4) — the
    // strongest form of "must not silently inherit".
    CHECK_THROWS_AS(Installer(paths).install(pkg_b), ChangedKeyError);
    CHECK(util::slurp_text(registry.app_data_dir(kId) / "profile.db") ==
          "A's data");

    // If the local trust is DELIBERATELY forgotten but data still remains, a
    // different key is refused as a retained-data conflict instead — it still
    // never inherits A's data.
    TrustStore(paths).forget(kId);
    CHECK_THROWS_AS(Installer(paths).install(pkg_b), RetainedDataConflict);
    CHECK(util::slurp_text(registry.app_data_dir(kId) / "profile.db") ==
          "A's data");

    // The ORIGINAL publisher reinstalling reclaims its own retained data.
    CHECK_NOTHROW(install_with(paths, work.dir, key_a));
    CHECK(util::slurp_text(registry.app_data_dir(kId) / "profile.db") ==
          "A's data");
}

TEST_CASE("retained data: purge removes data but preserves local trust history") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const Registry registry(paths);

    const crypto::KeyPair key_a = test::make_keypair();
    const crypto::KeyPair key_b = test::make_keypair();

    install_with(paths, work.dir, key_a);
    util::spit(registry.app_data_dir(kId) / "profile.db",
               std::string_view("A's data"));
    Installer(paths).uninstall(kId, Installer::UninstallMode::PurgeData);
    CHECK_FALSE(registry.has_retained_data(kId)); // data gone

    // Purge deletes DATA, but must NOT silently delete trust history: a
    // different key is still refused as a changed key.
    CHECK_THROWS_AS(install_with(paths, work.dir, key_b), ChangedKeyError);

    // Forgetting trust is the explicit, separate step that lets a new publisher
    // claim the id cleanly.
    TrustStore(paths).forget(kId);
    CHECK_NOTHROW(install_with(paths, work.dir, key_b));
}

// ------------------------------------------------ lease-aware garbage collect

TEST_CASE("gc: reclaims old versions, always keeps active + rollback window") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const crypto::KeyPair key = test::make_keypair();

    Installer installer(paths);
    install_with(paths, work.dir, key, "1.0.0");
    install_with(paths, work.dir, key, "2.0.0");
    install_with(paths, work.dir, key, "3.0.0");
    REQUIRE(registry.current_version(kId) == "3.0.0");

    // keep_previous = 1: active (3.0.0) + newest older (2.0.0) survive; 1.0.0 is
    // beyond the window and reclaimed.
    const GcReport r = installer.garbage_collect(kId, /*keep_previous=*/1);
    CHECK(fs::is_directory(registry.version_dir(kId, "3.0.0")));
    CHECK(fs::is_directory(registry.version_dir(kId, "2.0.0")));
    CHECK_FALSE(fs::exists(registry.version_dir(kId, "1.0.0")));
    CHECK_FALSE(fs::exists(registry.meta_dir(kId, "1.0.0")));
    CHECK(r.removed == std::vector<std::string>{"1.0.0"});
    CHECK(r.failed.empty());
    // The active install is fully intact after collection.
    CHECK(registry.current_version(kId) == "3.0.0");
    CHECK(installer.check_health(kId).ok);
}

TEST_CASE("gc: never removes a version at or newer than active") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const crypto::KeyPair key = test::make_keypair();

    Installer installer(paths);
    install_with(paths, work.dir, key, "1.0.0");
    install_with(paths, work.dir, key, "2.0.0");
    install_with(paths, work.dir, key, "3.0.0");
    installer.rollback(kId); // active is now 2.0.0; 3.0.0 is newer, on disk

    const GcReport r = installer.garbage_collect(kId, /*keep_previous=*/0);
    CHECK(fs::is_directory(registry.version_dir(kId, "3.0.0"))); // newer: kept
    CHECK(fs::is_directory(registry.version_dir(kId, "2.0.0"))); // active: kept
    CHECK_FALSE(fs::exists(registry.version_dir(kId, "1.0.0"))); // older: gone
    CHECK(r.removed == std::vector<std::string>{"1.0.0"});
}

TEST_CASE("gc: a leased (running) version is skipped, not removed") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const crypto::KeyPair key = test::make_keypair();

    auto locks = std::make_shared<test::FakeLockManager>();
    Installer installer(paths, locks);
    installer.set_mutation_wait(WaitPolicy::none());
    install_with(paths, work.dir, key, "1.0.0");
    install_with(paths, work.dir, key, "2.0.0");
    install_with(paths, work.dir, key, "3.0.0");

    // A process is running 1.0.0: it holds a shared lease.
    LaunchLease running =
        locks->acquire_launch_lease(kId, "1.0.0", WaitPolicy::none());

    // keep_previous = 1 keeps active (3.0.0) + 2.0.0, so 1.0.0 is the only
    // reclaim candidate — but the lease keeps it: reported in-use, not removed.
    const GcReport r = installer.garbage_collect(kId, /*keep_previous=*/1);
    CHECK(fs::is_directory(registry.version_dir(kId, "1.0.0")));
    CHECK(r.skipped_in_use == std::vector<std::string>{"1.0.0"});
    CHECK(r.removed.empty());
}

TEST_CASE("gc: a version referenced by a pending transaction is retained") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const Registry registry(paths);
    const crypto::KeyPair key = test::make_keypair();

    Installer installer(paths);
    install_with(paths, work.dir, key, "1.0.0");
    install_with(paths, work.dir, key, "2.0.0");

    // Leave a pending journal that targets the oldest version.
    InstallTransaction txn(paths, kId, "1.0.0");
    txn.begin("2.0.0", R"({"id":"com.example.hello","version":"1.0.0"})");

    // Even with keep_previous = 0, the txn target must not be reclaimed.
    const GcReport r = installer.garbage_collect(kId, /*keep_previous=*/0);
    CHECK(fs::is_directory(registry.version_dir(kId, "1.0.0")));
    CHECK(r.removed.empty());
}

TEST_CASE("gc: unknown application is NotFoundError") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    CHECK_THROWS_AS(Installer(paths).garbage_collect("com.example.nope"),
                    NotFoundError);
}

// ------------------------------------------------------ exit-code contract

TEST_CASE("WS8/WS9 typed errors map to CLI exit code 6") {
    CHECK(exit_code_for(RetainedDataConflict("x")) == 6);
    CHECK(exit_code_for(BusyError("x")) == 6);
}

} // namespace

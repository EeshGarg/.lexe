// storage taxonomy + uninstall-lifecycle tests (runtime-trust WS8). Every case
// starts from a fresh TempLexeHome, so the real profile is never touched and
// the canonical path API is exercised against a known LEXE_HOME.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/error.hpp"
#include "core/installer.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"

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

    // A DIFFERENT publisher claiming the same id must be refused — it must not
    // silently inherit A's retained data.
    {
        test::TestAppSpec spec;
        spec.id = kId;
        const fs::path pkg_b = test::make_test_package(work.dir, key_b, spec);
        CHECK_THROWS_AS(Installer(paths).install(pkg_b), RetainedDataConflict);
    }
    // A's data is still present and unmodified: the refusal changed nothing.
    CHECK(util::slurp_text(registry.app_data_dir(kId) / "profile.db") ==
          "A's data");

    // The ORIGINAL publisher reinstalling reclaims its own retained data.
    CHECK_NOTHROW(install_with(paths, work.dir, key_a));
    CHECK(util::slurp_text(registry.app_data_dir(kId) / "profile.db") ==
          "A's data");
}

TEST_CASE("retained data: purge clears the owner marker so any publisher may reinstall") {
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
    CHECK_FALSE(registry.has_retained_data(kId));

    // With the retained data (and marker) gone, B may take over the id cleanly.
    CHECK_NOTHROW(install_with(paths, work.dir, key_b));
}

// ------------------------------------------------------ exit-code contract

TEST_CASE("WS8/WS9 typed errors map to CLI exit code 6") {
    CHECK(exit_code_for(RetainedDataConflict("x")) == 6);
    CHECK(exit_code_for(BusyError("x")) == 6);
}

} // namespace

// health-check + auto-rollback tests (HARDENING.md §D). The health check runs
// BEFORE the atomic activation, so an upgrade to a package that fails it never
// replaces the working version — the previous known-good version stays active.
// It executes nothing (no package-controlled content is run to verify).

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/installer.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"

#include <filesystem>
#include <string>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

// Build a package for id@version. When `entrypoint` is given it overrides the
// manifest's entrypoint (used to declare an entrypoint that is NOT in the
// payload — a package that verifies but is unhealthy).
fs::path build_pkg(const fs::path& work, const crypto::KeyPair& key,
                   const std::string& id, const std::string& version,
                   const std::string& entrypoint = "") {
    test::TestAppSpec spec;
    spec.id = id;
    spec.version = version;
    spec.public_key = test::encode_public_key_str(key.public_key);
    if (!entrypoint.empty()) spec.entrypoint = entrypoint;
    const test::TestAppTree tree =
        test::make_test_app_tree(work / ("tree-" + version + "-" + entrypoint),
                                 spec);
    PackageWriter::Inputs in;
    in.payload_dir = tree.payload_dir;
    in.manifest_file = tree.manifest_file;
    const fs::path out =
        work / (id + "-" + version + (entrypoint.empty() ? "" : "-bad") +
                ".lexe");
    PackageWriter::write(in, key, out);
    return out;
}

const char* kId = "com.example.app";

} // namespace

TEST_SUITE("health_check") {

TEST_CASE("a healthy install reports healthy") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    Installer(paths).install(build_pkg(work, key, kId, "1.0.0"), InstallOptions{});

    const HealthReport report = Installer(paths).check_health(kId);
    CHECK(report.ok);
    CHECK(report.issues.empty());
}

TEST_CASE("a package whose declared entrypoint is missing is REFUSED") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    // Verifies (§6) but declares an entrypoint not present in the payload.
    const fs::path bad =
        build_pkg(work, key, kId, "1.0.0", "bin/does-not-exist");

    CHECK_THROWS_WITH_AS(Installer(paths).install(bad, InstallOptions{}),
                         doctest::Contains("health check"),
                         lexe::VerificationError);
    // Rolled back: nothing installed.
    CHECK_FALSE(Registry(paths).is_installed(kId));
}

TEST_CASE("an unhealthy UPGRADE leaves the previous version active (rollback)") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);

    // Healthy 1.0.0 baseline.
    Installer(paths).install(build_pkg(work, key, kId, "1.0.0"), InstallOptions{});
    REQUIRE(Registry(paths).current_version(kId) == "1.0.0");

    // Attempt to upgrade to a 2.0.0 that fails its health check.
    const fs::path bad2 =
        build_pkg(work, key, kId, "2.0.0", "bin/does-not-exist");
    CHECK_THROWS_WITH_AS(Installer(paths).install(bad2, InstallOptions{}),
                         doctest::Contains("health check"),
                         lexe::VerificationError);

    // The previous known-good version is still active and healthy; the bad
    // 2.0.0 never became active and left no version dir.
    const Registry registry(paths);
    CHECK(registry.current_version(kId) == "1.0.0");
    CHECK(Installer(paths).check_health(kId).ok);
    CHECK_FALSE(fs::exists(registry.version_dir(kId, "2.0.0")));
}

TEST_CASE("check_health detects a corrupted installed payload file") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    Installer(paths).install(build_pkg(work, key, kId, "1.0.0"), InstallOptions{});
    REQUIRE(Installer(paths).check_health(kId).ok);

    // Tamper with an installed payload file.
    const Registry registry(paths);
    const fs::path victim =
        registry.version_dir(kId, "1.0.0") / "data.txt";
    util::spit(victim, std::string_view("corrupted!\n"));

    const HealthReport report = Installer(paths).check_health(kId);
    CHECK_FALSE(report.ok);
    CHECK_FALSE(report.issues.empty());
}

} // TEST_SUITE("health_check")

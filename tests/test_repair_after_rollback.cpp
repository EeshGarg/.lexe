// Regression: repair could not repair a rolled-back application.
//
// `installation.json` has a single `source` field, and it necessarily means
// "where the most recent install came from". Repair needs a different fact:
// where the CURRENT version came from.
//
// After install 1.0.0 -> install 2.0.0 -> rollback to 1.0.0, those are different
// packages. Repair found `record.source` (the 2.0.0 package), checked — correctly
// — whether its version matched the version being repaired, found that it did
// not, and refused it. With no other candidate it reported
//
//     N corrupt or missing file(s) that could not be repaired
//     (reinstall from the original package to repair)
//
// on an application whose own package was sitting on disk the whole time. The
// version check was right; the candidate was wrong.
//
// Found by tests/lifecycle/01_ordinary_sequence.sh, which is the reason that
// suite runs the operations in sequence rather than each from a clean install:
// every individual operation worked, and the defect lived only in the state one
// of them left for another.
//
// The fix records the source in the per-version meta store, beside that version's
// hashes.json, and repair prefers it. These pin both halves: that a rolled-back
// application repairs, and that the version check it used to fall foul of stays.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/base/paths.hpp"
#include "lexe/base/util.hpp"
#include "lexe/install/installer.hpp"
#include "lexe/state/registry.hpp"

#include <filesystem>
#include <map>
#include <string>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

/// Append to a file so its recorded hash no longer matches.
void tamper_file(const fs::path& file) {
    std::string bytes = util::slurp_text(file);
    bytes += "tampered";
    util::spit(file, bytes);
}

} // namespace

TEST_SUITE("repair-after-rollback") {

TEST_CASE("a rolled-back application can be repaired from its own package") {
    test::TempLexeHome home;
    const fs::path work = test::unique_temp_dir("lexe-rollback-repair-");
    const crypto::KeyPair key = crypto::generate_keypair();
    const Paths paths = Paths::detect();

    test::TestAppSpec spec;
    spec.id = "com.example.rollback";
    spec.architectures = {host_architecture()};
    spec.version = "1.0.0";
    const fs::path v1 = test::make_test_package(work, key, spec);
    spec.version = "2.0.0";
    const fs::path v2 = test::make_test_package(work, key, spec);

    Installer installer(paths);
    InstallOptions opts;
    opts.explicit_trust = true;
    opts.desktop_integration = false;
    installer.install(v1, opts);
    installer.install(v2, opts);

    const Registry registry(paths);
    REQUIRE(registry.current_version(spec.id) == "2.0.0");

    installer.rollback(spec.id);
    REQUIRE(registry.current_version(spec.id) == "1.0.0");

    // This is the condition that made the bug: installation.json still names the
    // 2.0.0 package, because that is where the most recent INSTALL came from.
    const InstallationRecord record = registry.read_record(spec.id);
    CHECK(record.source == v2.string());

    // Damage the CURRENT (rolled-back) version.
    const fs::path entry =
        registry.version_dir(spec.id, "1.0.0") / spec.entrypoint;
    REQUIRE(fs::is_regular_file(entry));
    tamper_file(entry);

    const RepairReport report = installer.repair(spec.id, std::nullopt, {});
    INFO("repair must find the 1.0.0 package from the per-version meta store, "
         "rather than being left with only the 2.0.0 one it correctly refuses");
    CHECK(report.ok);
    CHECK(report.corrupt_files.empty());
    CHECK(report.repaired_files.size() == 1);

    // Idempotent afterwards: a second repair finds nothing to do, which also
    // shows the restored bytes really do match 1.0.0's recorded hashes. A repair
    // that "succeeded" by copying 2.0.0's binary would fail this.
    const RepairReport again = installer.repair(spec.id, std::nullopt, {});
    CHECK(again.ok);
    CHECK(again.repaired_files.empty());

    fs::remove_all(work);
}

TEST_CASE("the per-version source is recorded for every installed version") {
    test::TempLexeHome home;
    const fs::path work = test::unique_temp_dir("lexe-rollback-sources-");
    const crypto::KeyPair key = crypto::generate_keypair();
    const Paths paths = Paths::detect();

    test::TestAppSpec spec;
    spec.id = "com.example.sources";
    spec.architectures = {host_architecture()};
    spec.version = "1.0.0";
    const fs::path v1 = test::make_test_package(work, key, spec);
    spec.version = "2.0.0";
    const fs::path v2 = test::make_test_package(work, key, spec);

    Installer installer(paths);
    InstallOptions opts;
    opts.explicit_trust = true;
    opts.desktop_integration = false;
    installer.install(v1, opts);
    installer.install(v2, opts);

    const Registry registry(paths);
    const std::map<std::string, fs::path> expected = {{"1.0.0", v1},
                                                      {"2.0.0", v2}};
    for (const auto& [version, package] : expected) {
        const fs::path recorded =
            registry.meta_dir(spec.id, version) / "source.txt";
        CAPTURE(version);
        INFO("each version's meta store must know where THAT version came from");
        REQUIRE(fs::is_regular_file(recorded));
        CHECK(util::slurp_text(recorded) == package.string());
    }

    fs::remove_all(work);
}

TEST_CASE("repair still refuses a package for the wrong version") {
    // The version check is what made the original bug visible, and it has to
    // stay: repairing 1.0.0 from a 2.0.0 package would put 2.0.0's files under
    // 1.0.0's directory, where their hashes would never match again.
    test::TempLexeHome home;
    const fs::path work = test::unique_temp_dir("lexe-rollback-wrong-");
    const crypto::KeyPair key = crypto::generate_keypair();
    const Paths paths = Paths::detect();

    test::TestAppSpec spec;
    spec.id = "com.example.wrongversion";
    spec.architectures = {host_architecture()};
    spec.version = "1.0.0";
    const fs::path v1 = test::make_test_package(work, key, spec);
    spec.version = "2.0.0";
    const fs::path v2 = test::make_test_package(work, key, spec);

    Installer installer(paths);
    InstallOptions opts;
    opts.explicit_trust = true;
    opts.desktop_integration = false;
    installer.install(v1, opts);

    const Registry registry(paths);
    tamper_file(registry.version_dir(spec.id, "1.0.0") / spec.entrypoint);

    CHECK_THROWS_AS(installer.repair(spec.id, v2, {}), std::exception);

    fs::remove_all(work);
}

} // TEST_SUITE

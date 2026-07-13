// installer module tests (ARCHITECTURE.md #Tests: "installer —
// install/uninstall/rollback/repair on a fake app"). Every test case
// constructs lexe::test::TempLexeHome first, so LEXE_HOME always points into
// a fresh temp directory and the real user profile is never touched.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/error.hpp"
#include "core/installer.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"
#include "core/verify.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

constexpr const char* kId = "com.example.hello";

/// RAII scratch directory for packages/trees, OUTSIDE LEXE_HOME.
struct TempWorkDir {
    fs::path dir;
    TempWorkDir() : dir(test::unique_temp_dir("lexe-installer-work-")) {
        fs::create_directories(dir);
    }
    ~TempWorkDir() {
        std::error_code ec;
        fs::remove_all(dir, ec); // best effort
    }
    TempWorkDir(const TempWorkDir&) = delete;
    TempWorkDir& operator=(const TempWorkDir&) = delete;
};

/// Signed test package for `kId` at `version`.
fs::path make_versioned_package(const fs::path& work,
                                const crypto::KeyPair& key,
                                const std::string& version,
                                const std::string& update_url = "") {
    test::TestAppSpec spec;
    spec.id = kId;
    spec.version = version;
    spec.update_url = update_url;
    return test::make_test_package(work, key, spec);
}

/// Signed test package whose manifest lists ONLY `arch`.
fs::path make_single_arch_package(const fs::path& work,
                                  const crypto::KeyPair& key,
                                  const std::string& arch) {
    test::TestAppSpec spec;
    spec.public_key = test::encode_public_key_str(key.public_key);
    const test::TestAppTree tree =
        test::make_test_app_tree(work / ("arch-tree-" + arch), spec);
    nlohmann::json manifest =
        nlohmann::json::parse(util::slurp_text(tree.manifest_file));
    manifest["architectures"] = nlohmann::json::array({arch});
    util::spit(tree.manifest_file, std::string_view(manifest.dump(2) + "\n"));
    PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;
    const fs::path out = work / ("arch-only-" + arch + ".lexe");
    PackageWriter::write(inputs, key, out);
    return out;
}

bool contains(const std::vector<std::string>& haystack,
              const std::string& needle) {
    return std::find(haystack.begin(), haystack.end(), needle) !=
           haystack.end();
}

} // namespace

TEST_SUITE("installer") {

// ---------------------------------------------------------------- install

TEST_CASE("install: full lifecycle — verify, extract, records, current") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(
        work.dir, key, "1.0.0", "https://example.com/releases/update.json");

    Installer installer(paths);
    const InstallResult result = installer.install(pkg);

    CHECK(result.id == kId);
    CHECK(result.version == "1.0.0");
    CHECK(result.app_dir == paths.apps_dir() / kId);

    // Payload extracted to versions/<version>/ with the payload/ prefix
    // stripped (FORMAT-0.1 §9).
    const fs::path vdir = result.app_dir / "versions" / "1.0.0";
    REQUIRE(fs::is_directory(vdir));
    CHECK(fs::is_regular_file(vdir / "bin" / "hello.sh"));
    CHECK(fs::is_regular_file(vdir / "bin" / "hello.cmd"));
    CHECK(util::slurp_text(vdir / "data.txt") ==
          std::string("test payload data for ") + kId + "\n");

    // manifest.json copy of the active version + the hashes.json copy the
    // repair contract requires the installer to store in the app dir.
    const Registry registry(paths);
    CHECK(fs::is_regular_file(result.app_dir / "manifest.json"));
    CHECK(fs::is_regular_file(result.app_dir / "hashes.json"));
    const Manifest recorded_manifest = registry.read_manifest(kId);
    CHECK(recorded_manifest.id == kId);
    CHECK(recorded_manifest.version == "1.0.0");

    // current points at the new version (symlink or current.txt fallback).
    CHECK(registry.current_version(kId) == "1.0.0");

    // installation.json: the publisher key recorded here is the update
    // trust anchor (FORMAT-0.1 §7.1).
    REQUIRE(registry.is_installed(kId));
    const InstallationRecord record = registry.read_record(kId);
    CHECK(record.id == kId);
    CHECK(record.version == "1.0.0");
    CHECK(record.source == pkg.string());
    CHECK(record.publisher_key == test::encode_public_key_str(key.public_key));
    CHECK(record.channel == "stable");
    CHECK(record.update_url == "https://example.com/releases/update.json");
    CHECK(!record.installed_at.empty());

    // Desktop integration is recorded (paths reported even on Windows,
    // where the desktop module is a recorded no-op).
    const std::string desktop_file =
        (paths.applications_dir() / ("lexe-" + std::string(kId) + ".desktop"))
            .string();
    CHECK(contains(record.created_files, desktop_file));

    CHECK(contains(registry.list_installed(), kId));
}

TEST_CASE("install: options are honoured — channel, source, no integration") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");

    InstallOptions opts;
    opts.channel = "beta";
    opts.source = "https://example.com/releases/hello-1.0.0.lexe";
    opts.desktop_integration = false;

    Installer installer(paths);
    installer.install(pkg, opts);

    const InstallationRecord record = Registry(paths).read_record(kId);
    CHECK(record.channel == "beta");
    CHECK(record.source == "https://example.com/releases/hello-1.0.0.lexe");
    CHECK(record.created_files.empty());
}

TEST_CASE("install: a package failing verification installs nothing") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");

    // Flip a payload byte: the §6 hashes stage must fail and nothing may be
    // written (signature-before-parse discipline, security invariant #2).
    test::tamper_entry(pkg, "payload/data.txt",
                       [](std::vector<std::uint8_t>& bytes) {
                           REQUIRE(!bytes.empty());
                           bytes[0] ^= 0xff;
                       });

    Installer installer(paths);
    CHECK_THROWS_AS(installer.install(pkg), VerificationError);
    CHECK(!Registry(paths).is_installed(kId));
    CHECK(!fs::exists(paths.apps_dir() / kId));
}

TEST_CASE("install: architecture gate (§6.7) and the force_arch override") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();

    // A manifest listing ONLY the architecture this host is not.
    const std::string other =
        host_architecture() == "aarch64" ? "x86_64" : "aarch64";
    const fs::path pkg = make_single_arch_package(work.dir, key, other);

    Installer installer(paths);
    CHECK_THROWS_AS(installer.install(pkg), VerificationError);
    CHECK(!Registry(paths).is_installed(kId));

    InstallOptions opts;
    opts.force_arch = true; // skips ONLY stage 7
    const InstallResult result = installer.install(pkg, opts);
    CHECK(result.id == kId);
    CHECK(Registry(paths).is_installed(kId));
}

TEST_CASE("install: refuses installing the same version over itself") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");

    Installer installer(paths);
    installer.install(pkg);

    bool threw = false;
    try {
        installer.install(pkg);
    } catch (const VerificationError&) {
        FAIL("double install must not be reported as a verification failure");
    } catch (const Error& e) {
        threw = true;
        CHECK(std::string(e.what()).find("already installed") !=
              std::string::npos);
        CHECK(std::string(e.what()).find("repair") != std::string::npos);
    }
    CHECK(threw);

    // The installation is untouched.
    CHECK(Registry(paths).current_version(kId) == "1.0.0");
}

TEST_CASE("install: same id with a different publisher key is a hard error") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key_a = test::make_keypair();
    const crypto::KeyPair key_b = test::make_keypair();

    Installer installer(paths);
    installer.install(make_versioned_package(work.dir, key_a, "1.0.0"));

    // Same id, newer version, valid signatures — but a DIFFERENT key. The
    // pinned key is the update trust anchor (FORMAT-0.1 §7.1): hard error.
    const fs::path impostor = make_versioned_package(work.dir, key_b, "1.1.0");
    bool threw = false;
    try {
        installer.install(impostor);
    } catch (const VerificationError& e) {
        threw = true;
        CHECK(std::string(e.what()).find("key mismatch") != std::string::npos);
    }
    CHECK(threw);

    // Still the original install, pinned to key A.
    const Registry registry(paths);
    CHECK(registry.current_version(kId) == "1.0.0");
    CHECK(registry.read_record(kId).publisher_key ==
          test::encode_public_key_str(key_a.public_key));
    CHECK(!fs::exists(registry.version_dir(kId, "1.1.0")));
}

TEST_CASE("install: updating to a newer version retains the previous one") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();

    Installer installer(paths);
    installer.install(make_versioned_package(work.dir, key, "1.0.0"));
    installer.install(make_versioned_package(work.dir, key, "1.1.0"));

    const Registry registry(paths);
    CHECK(registry.current_version(kId) == "1.1.0");
    // Previous version dir retained for rollback (FORMAT-0.1 §7).
    CHECK(fs::is_directory(registry.version_dir(kId, "1.0.0")));
    CHECK(fs::is_directory(registry.version_dir(kId, "1.1.0")));
    CHECK(registry.read_record(kId).version == "1.1.0");
    CHECK(registry.read_manifest(kId).version == "1.1.0");
}

// -------------------------------------------------------------- uninstall

TEST_CASE("uninstall: removes exactly the recorded files and the app dir") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");

    Installer installer(paths);
    installer.install(pkg);

    const Registry registry(paths);
    const InstallationRecord record = registry.read_record(kId);
    REQUIRE(!record.created_files.empty());

    // Materialise every recorded file (on Windows the desktop module records
    // them without writing; on Linux they already exist), plus an unrelated
    // neighbour that MUST survive, plus per-app data.
    for (const std::string& file : record.created_files) {
        if (!fs::exists(fs::path(file))) {
            util::spit(fs::path(file), std::string_view("integration file"));
        }
    }
    const fs::path neighbour = paths.applications_dir() / "unrelated.desktop";
    util::spit(neighbour, std::string_view("not lexe's file"));
    const fs::path data_file = paths.data_dir() / kId / "settings.ini";
    util::spit(data_file, std::string_view("user data"));

    SUBCASE("without purge_data: data survives") {
        installer.uninstall(kId, /*purge_data=*/false);

        CHECK(!fs::exists(paths.apps_dir() / kId));
        CHECK(!registry.is_installed(kId));
        for (const std::string& file : record.created_files) {
            CHECK(!fs::exists(fs::path(file)));
        }
        CHECK(fs::exists(neighbour));            // exactly the recorded files
        CHECK(fs::exists(data_file));            // data only with purge (§9)
    }

    SUBCASE("with purge_data: data dir removed too") {
        installer.uninstall(kId, /*purge_data=*/true);

        CHECK(!fs::exists(paths.apps_dir() / kId));
        for (const std::string& file : record.created_files) {
            CHECK(!fs::exists(fs::path(file)));
        }
        CHECK(fs::exists(neighbour));
        CHECK(!fs::exists(paths.data_dir() / kId));
    }
}

TEST_CASE("uninstall: unknown application is NotFoundError") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    Installer installer(paths);
    CHECK_THROWS_AS(installer.uninstall("com.example.nope", false),
                    NotFoundError);
}

// --------------------------------------------------------------- rollback

TEST_CASE("rollback: newest retained older version, semver-lite order") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();

    Installer installer(paths);
    installer.install(make_versioned_package(work.dir, key, "1.2.0"));
    installer.install(make_versioned_package(work.dir, key, "1.9.0"));
    const fs::path newest = make_versioned_package(work.dir, key, "1.10.0");
    installer.install(newest);

    const Registry registry(paths);
    REQUIRE(registry.current_version(kId) == "1.10.0");

    // 1.9.0 is the NEWEST older version (numeric component compare: 9 < 10,
    // FORMAT-0.1 §8 — a byte-string compare would wrongly pick "1.9.0" as
    // greater than "1.10.0").
    installer.rollback(kId);
    CHECK(registry.current_version(kId) == "1.9.0");
    CHECK(registry.read_record(kId).version == "1.9.0");
    CHECK(registry.read_manifest(kId).version == "1.9.0"); // §9 active copy

    installer.rollback(kId);
    CHECK(registry.current_version(kId) == "1.2.0");

    // Nothing older than 1.2.0 is retained.
    CHECK_THROWS_AS(installer.rollback(kId), NotFoundError);
    CHECK(registry.current_version(kId) == "1.2.0");

    // Rollback deletes no version directory.
    CHECK(fs::is_directory(registry.version_dir(kId, "1.2.0")));
    CHECK(fs::is_directory(registry.version_dir(kId, "1.9.0")));
    CHECK(fs::is_directory(registry.version_dir(kId, "1.10.0")));

    // Re-installing a retained version that is NOT current is allowed and
    // flips current forward again ("same version over itself" keys off the
    // current version, not mere presence on disk).
    installer.install(newest);
    CHECK(registry.current_version(kId) == "1.10.0");
}

TEST_CASE("rollback: single version or unknown app is NotFoundError") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();

    Installer installer(paths);
    CHECK_THROWS_AS(installer.rollback("com.example.nope"), NotFoundError);

    installer.install(make_versioned_package(work.dir, key, "1.0.0"));
    CHECK_THROWS_AS(installer.rollback(kId), NotFoundError);
    CHECK(Registry(paths).current_version(kId) == "1.0.0");
}

// ----------------------------------------------------------------- repair

TEST_CASE("repair: healthy installation reports ok with nothing to do") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();

    Installer installer(paths);
    installer.install(make_versioned_package(work.dir, key, "1.0.0"));

    const RepairReport report = installer.repair(kId);
    CHECK(report.ok);
    CHECK(report.repaired_files.empty());
    CHECK(report.corrupt_files.empty());
}

TEST_CASE("repair: detects and fixes deliberately corrupted files") {
    test::TempLexeHome home;
    TempWorkDir work;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path pkg = make_versioned_package(work.dir, key, "1.0.0");

    Installer installer(paths);
    installer.install(pkg);
    const fs::path vdir = paths.apps_dir() / kId / "versions" / "1.0.0";

    // Deliberate damage: modify one file, delete another, rewrite a third.
    util::spit(vdir / "data.txt", std::string_view("corrupted!!!"));
    fs::remove(vdir / "bin" / "hello.cmd");
    util::spit(vdir / "bin" / "hello.sh",
               std::string_view("#!/bin/sh\nevil\n"));

    SUBCASE("no package available: reports, changes nothing") {
        fs::remove(pkg); // the recorded source is gone → report-only
        const RepairReport report = installer.repair(kId);
        CHECK(!report.ok);
        CHECK(report.repaired_files.empty());
        REQUIRE(report.corrupt_files.size() == 3);
        CHECK(contains(report.corrupt_files, "payload/data.txt"));
        CHECK(contains(report.corrupt_files, "payload/bin/hello.cmd"));
        CHECK(contains(report.corrupt_files, "payload/bin/hello.sh"));
        CHECK(util::slurp_text(vdir / "data.txt") == "corrupted!!!");
        CHECK(!fs::exists(vdir / "bin" / "hello.cmd"));
    }

    SUBCASE("explicit package: re-extracts exactly the damaged files") {
        const RepairReport report = installer.repair(kId, pkg);
        CHECK(report.ok);
        CHECK(report.corrupt_files.empty());
        REQUIRE(report.repaired_files.size() == 3);
        CHECK(contains(report.repaired_files, "payload/data.txt"));
        CHECK(contains(report.repaired_files, "payload/bin/hello.cmd"));
        CHECK(contains(report.repaired_files, "payload/bin/hello.sh"));

        CHECK(util::slurp_text(vdir / "data.txt") ==
              std::string("test payload data for ") + kId + "\n");
        CHECK(fs::is_regular_file(vdir / "bin" / "hello.cmd"));
        CHECK(util::slurp_text(vdir / "bin" / "hello.sh") ==
              std::string("#!/bin/sh\necho hello from ") + kId + "\nexit 0\n");
#ifndef _WIN32
        // Re-extraction restores the executable bit (POSIX).
        const fs::perms perms =
            fs::status(vdir / "bin" / "hello.sh").permissions();
        CHECK((perms & fs::perms::owner_exec) != fs::perms::none);
#endif
        // Now healthy.
        CHECK(installer.repair(kId).ok);
    }

    SUBCASE("package auto-found from the recorded source") {
        // record.source is the original package path, which still exists.
        const RepairReport report = installer.repair(kId);
        CHECK(report.ok);
        CHECK(report.corrupt_files.empty());
        CHECK(report.repaired_files.size() == 3);
    }

    SUBCASE("explicit package failing verification is an error") {
        const fs::path tampered = work.dir / "tampered.lexe";
        fs::copy_file(pkg, tampered);
        test::tamper_entry(tampered, "payload/data.txt",
                           [](std::vector<std::uint8_t>& bytes) {
                               REQUIRE(!bytes.empty());
                               bytes[0] ^= 0xff;
                           });
        CHECK_THROWS_AS(installer.repair(kId, tampered), VerificationError);
        // Still corrupted — the bad package repaired nothing.
        CHECK(util::slurp_text(vdir / "data.txt") == "corrupted!!!");
    }

    SUBCASE("explicit package for a different version is an error") {
        const fs::path wrong = make_versioned_package(work.dir, key, "2.0.0");
        CHECK_THROWS_AS(installer.repair(kId, wrong), Error);
        CHECK(util::slurp_text(vdir / "data.txt") == "corrupted!!!");
    }
}

TEST_CASE("repair: unknown application is NotFoundError") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    Installer installer(paths);
    CHECK_THROWS_AS(installer.repair("com.example.nope"), NotFoundError);
}

} // TEST_SUITE("installer")

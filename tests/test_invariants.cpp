// End-to-end security-invariant matrix (HARDENING.md §H). Drives the real
// installer/verify engine — the same engine the CLI and GUI call — and asserts
// the enforced invariants. Several invariants are proven exhaustively in
// dedicated suites and are cross-referenced here rather than re-proven:
//   * no path escapes staging/install roots  -> test_package (zip-slip corpus)
//   * no partial install becomes active       -> test_crash_recovery
//   * failed upgrade preserves previous        -> test_health_check, test_crash_recovery
//   * recovery is idempotent                   -> test_crash_recovery
//   * duplicate JSON keys rejected             -> test_json_strict
//   * package expansion bounded                -> test_limits
//   * strict signature verification            -> test_ed25519_strict, test_verify
// This file adds the remaining engine-level checks.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/installer.hpp"
#include "core/launcher.hpp"
#include "core/package.hpp"
#include "core/paths.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"
#include "core/verify.hpp"

#include <filesystem>
#include <string>

namespace fs = std::filesystem;
using namespace lexe;

namespace {
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
const char* kId = "com.example.app";
} // namespace

TEST_SUITE("invariants") {

// Invariant: signature verification is strict and performed BEFORE any package
// activation — a package that fails verification writes nothing.
TEST_CASE("a package that fails verification is never installed (writes nothing)") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const fs::path pkg = build_pkg(work, key, kId, "1.0.0");
    // Break the payload signature.
    test::tamper_entry(pkg, "signatures/payload.sig",
                       [](std::vector<std::uint8_t>& b) {
                           std::fill(b.begin(), b.end(), std::uint8_t{0});
                       });

    CHECK_THROWS_AS(Installer(paths).install(pkg, InstallOptions{}),
                    lexe::VerificationError);
    // Nothing was written for the app: no app dir, no journal, no staging.
    const Registry registry(paths);
    CHECK_FALSE(registry.is_installed(kId));
    CHECK_FALSE(fs::exists(registry.app_dir(kId)));
}

// Invariant: the installation record cannot claim a version that was never
// committed — after any successful install/upgrade, record.version equals the
// resolved active version.
TEST_CASE("the installation record always matches the active version") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const Registry registry(paths);

    Installer(paths).install(build_pkg(work, key, kId, "1.0.0"), InstallOptions{});
    CHECK(registry.read_record(kId).version == registry.current_version(kId));
    CHECK(registry.current_version(kId) == "1.0.0");

    Installer(paths).install(build_pkg(work, key, kId, "2.0.0"), InstallOptions{});
    CHECK(registry.read_record(kId).version == registry.current_version(kId));
    CHECK(registry.current_version(kId) == "2.0.0");

    Installer(paths).rollback(kId);
    CHECK(registry.read_record(kId).version == registry.current_version(kId));
}

// Invariant: the manifest public key is always tied to the signing key — a
// package built by the engine verifies its own publisher signature.
TEST_CASE("a package built by the engine verifies (publicKey == signing key)") {
    test::TempLexeHome home;
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const fs::path pkg = build_pkg(work, key, kId, "1.0.0");
    const VerificationReport report = verify_package(pkg, false);
    CHECK(report.ok());
    // The key stage in particular passed.
    bool key_stage_ok = false;
    for (const VerificationStage& s : report.stages) {
        if (std::string(s.name) == "key") key_stage_ok = s.ok;
    }
    CHECK(key_stage_ok);
}

// Invariant: installer-owned cleanup only removes paths under the app root.
// Uninstall removes exactly the app dir (and recorded external files) and
// nothing else in LEXE_HOME.
TEST_CASE("uninstall removes only the app's own directory") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    const Registry registry(paths);

    // A second, unrelated app must survive the first app's uninstall.
    Installer(paths).install(build_pkg(work, key, "com.example.one", "1.0.0"),
                             InstallOptions{});
    Installer(paths).install(build_pkg(work, key, "com.example.two", "1.0.0"),
                             InstallOptions{});

    Installer(paths).uninstall("com.example.one");
    CHECK_FALSE(registry.is_installed("com.example.one"));
    CHECK_FALSE(fs::exists(registry.app_dir("com.example.one")));
    CHECK(registry.is_installed("com.example.two")); // untouched
    CHECK(registry.current_version("com.example.two") == "1.0.0");
}

// Invariant: installed integrity is revalidated at launch — a binary tampered
// with after installation is not executed (runtime-trust WS6).
TEST_CASE("the launcher refuses an entrypoint tampered after install") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    const crypto::KeyPair key = test::make_keypair();
    const fs::path work = home.path() / "work";
    fs::create_directories(work);
    Installer(paths).install(build_pkg(work, key, kId, "1.0.0"), InstallOptions{});

    const Registry registry(paths);
    const Manifest m = registry.read_manifest(kId);
    const fs::path entry =
        registry.version_dir(kId, "1.0.0") / fs::path(m.entrypoint_executable);
    // Overwrite the installed entrypoint with different bytes.
    util::spit(entry, std::string_view("#!/bin/sh\necho pwned\n"));

    CHECK_THROWS_WITH_AS(run_app(paths, kId, {}),
                         doctest::Contains("integrity"), lexe::LaunchError);
}

} // TEST_SUITE("invariants")

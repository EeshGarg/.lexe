// payload-role tests — "does the artifact actually BE what its manifest
// declares?" (Definitive Architecture §14.2 / §15.1, verify.cpp stage
// "payload-role").
//
// This file exists because of a real defect: the 0.1.0-alpha.1 package
// declared `applicationType: "native"` while its entrypoint was
// `helloworld.cpp` — C++ SOURCE TEXT that was never compiled. Every stage of
// the §6 pipeline was green (the archive was well-formed, the manifest parsed,
// both signatures verified, every hash matched), because nothing in the
// pipeline ever asked whether the declared entrypoint was a runnable binary.
// It installed, and then failed at launch. The payload-role stage closes that
// gap: for a native application the declared entrypoint must be a real ELF
// executable (or PIE) whose machine is one of the declared architectures.
//
// The stage runs AFTER "hashes" on purpose: bytes are judged only once they
// are known to be intact and authentic — see the ordering test at the bottom.
// Every test case constructs lexe::test::TempLexeHome first.

#include <doctest/doctest.h>

#include "elf_builder.hpp"
#include "helpers.hpp"

#include "lexe/package/crypto.hpp"
#include "lexe/base/error.hpp"
#include "lexe/package/package.hpp"
#include "lexe/base/util.hpp"
#include "lexe/verify/verify.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using lexe::VerificationReport;
using lexe::test::TempLexeHome;

namespace {

constexpr const char* kPayloadRole = "payload-role";

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

/// Detail text of the failing stage (empty when the report passed).
std::string failure_detail(const VerificationReport& report) {
    const lexe::VerificationStage* failure = report.first_failure();
    return failure == nullptr ? std::string() : failure->detail;
}

/// Position of `name` in the report, or npos when the stage did not run.
std::size_t stage_index(const VerificationReport& report,
                        const std::string& name) {
    for (std::size_t i = 0; i < report.stages.size(); ++i) {
        if (report.stages[i].name == name) return i;
    }
    return std::string::npos;
}

/// Detail text of one named stage ("" when the stage did not run).
std::string stage_detail(const VerificationReport& report,
                         const std::string& name) {
    const std::size_t i = stage_index(report, name);
    return i == std::string::npos ? std::string() : report.stages[i].detail;
}

/// Assert the report failed exactly at payload-role: the stage is last, and
/// everything the pipeline ran before it is green — the package IS authentic
/// and intact, it simply is not what it claims to be.
void expect_payload_role_failure(const VerificationReport& report) {
    REQUIRE_FALSE(report.ok());
    REQUIRE(report.first_failure() != nullptr);
    CHECK(report.first_failure()->name == kPayloadRole);
    REQUIRE_FALSE(report.stages.empty());
    CHECK(report.stages.back().name == kPayloadRole);
    for (std::size_t i = 0; i + 1 < report.stages.size(); ++i) {
        CAPTURE(report.stages[i].name);
        CHECK(report.stages[i].ok);
    }
    CHECK_FALSE(failure_detail(report).empty());
}

/// Build a fully signed package that declares `entrypoint` and `architectures`
/// and whose payload entrypoint file is whatever `write_entrypoint` writes.
/// Everything else (both signatures, hashes.json) is correct, so the package
/// reaches the payload-role stage with every earlier stage green.
fs::path pack_with_entrypoint(
    const fs::path& work, const lexe::crypto::KeyPair& key,
    const std::string& entrypoint,
    const std::vector<std::string>& architectures,
    const std::function<void(const fs::path&)>& write_entrypoint,
    const std::string& tag) {
    lexe::test::TestAppSpec spec;
    spec.id = "com.example.payloadrole";
    spec.public_key = lexe::test::encode_public_key_str(key.public_key);
    spec.entrypoint = entrypoint;
    spec.architectures = architectures;
    const lexe::test::TestAppTree tree =
        lexe::test::make_test_app_tree(work / ("tree-" + tag), spec);
    write_entrypoint(tree.payload_dir / fs::path(entrypoint));

    lexe::PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;
    const fs::path out = work / (tag + ".lexe");
    lexe::PackageWriter::write(inputs, key, out);
    return out;
}

} // namespace

TEST_SUITE("payload_role") {

// ===================================================================
// The alpha bug itself
// ===================================================================

TEST_CASE("ALPHA BUG: a native package whose entrypoint is helloworld.cpp "
          "SOURCE TEXT is rejected at the payload-role stage") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();

    // Exactly what 0.1.0-alpha.1 shipped: applicationType "native", entrypoint
    // "helloworld.cpp", and the file is C++ source that was never compiled.
    static const char* kHelloWorldCpp =
        "#include <iostream>\n"
        "\n"
        "int main() {\n"
        "    std::cout << \"Hello, world!\" << std::endl;\n"
        "    return 0;\n"
        "}\n";

    const fs::path pkg = pack_with_entrypoint(
        home.path(), key, "helloworld.cpp", {"x86_64", "aarch64"},
        [](const fs::path& p) {
            lexe::util::spit(p, std::string_view(kHelloWorldCpp));
        },
        "alpha-source-entrypoint");

    const VerificationReport report = lexe::verify_package(pkg);
    expect_payload_role_failure(report);

    // The signatures and hashes are all good — that is the whole point: the
    // package is authentic, and still must not install.
    CHECK(report.stages[stage_index(report, "manifest-signature")].ok);
    CHECK(report.stages[stage_index(report, "payload-signature")].ok);
    CHECK(report.stages[stage_index(report, "hashes")].ok);

    // The failure has to say WHY, in the terms a publisher can act on.
    const std::string detail = failure_detail(report);
    CAPTURE(detail);
    CHECK(contains(detail, "helloworld.cpp"));
    CHECK(contains(detail, "native"));
    CHECK(contains(detail, "not an ELF"));
    CHECK(contains(detail, "source"));   // "source files belong in ..."
    CHECK(contains(detail, "COMPILED")); // ... a native package needs a binary

    // And the install/update path refuses it just as hard.
    CHECK_THROWS_AS(
        (void)lexe::verify_package_or_throw(pkg, /*check_architecture=*/true),
        lexe::VerificationError);
}

TEST_CASE("a plain-text entrypoint with no extension is rejected too") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    // A shell script is the other shape this defect takes: it "runs" on the
    // publisher's machine, so it is easy to ship by mistake.
    const fs::path pkg = pack_with_entrypoint(
        home.path(), key, "bin/app", {"x86_64", "aarch64"},
        [](const fs::path& p) {
            lexe::util::spit(p, std::string_view("#!/bin/sh\necho hi\n"));
        },
        "script-entrypoint");

    const VerificationReport report = lexe::verify_package(pkg);
    expect_payload_role_failure(report);
    CHECK(contains(failure_detail(report), "bin/app"));
    CHECK(contains(failure_detail(report), "not an ELF"));
}

// ===================================================================
// Real ELF objects that are still the wrong thing
// ===================================================================

TEST_CASE("an ELF built for a DIFFERENT architecture than the manifest "
          "declares is rejected at the payload-role stage") {
    TempLexeHome home;
    const std::string host = lexe::host_architecture();
    REQUIRE((host == "x86_64" || host == "aarch64"));
    const std::string other = host == "x86_64" ? "aarch64" : "x86_64";

    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    // The manifest declares only `host`; the entrypoint is a genuine ELF
    // executable for `other` (EM_AARCH64 vs EM_X86_64).
    const fs::path pkg = pack_with_entrypoint(
        home.path(), key, "bin/app", {host},
        [&other](const fs::path& p) {
            lexe::test::write_elf_executable_for_arch(p, other);
        },
        "wrong-arch-entrypoint");

    const VerificationReport report = lexe::verify_package(pkg);
    expect_payload_role_failure(report);
    const std::string detail = failure_detail(report);
    CAPTURE(detail);
    CHECK(contains(detail, "bin/app"));
    CHECK(contains(detail, other)); // what the binary actually is
    CHECK(contains(detail, host));  // what the manifest declared
}

TEST_CASE("an ELF RELOCATABLE object (ET_REL, a .o file) is rejected at the "
          "payload-role stage") {
    TempLexeHome home;
    const std::string host = lexe::host_architecture();
    REQUIRE((host == "x86_64" || host == "aarch64"));

    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    // A compiled-but-not-linked object file: right machine, real ELF magic,
    // and still not something the OS can execute.
    const fs::path pkg = pack_with_entrypoint(
        home.path(), key, "bin/app", {host},
        [&host](const fs::path& p) {
            lexe::test::ElfSpec spec;
            spec.e_type = 1; // ET_REL
            spec.e_machine = lexe::test::elf_machine_for_arch(host);
            lexe::test::write_elf(p, spec);
        },
        "relocatable-entrypoint");

    const VerificationReport report = lexe::verify_package(pkg);
    expect_payload_role_failure(report);
    const std::string detail = failure_detail(report);
    CAPTURE(detail);
    CHECK(contains(detail, "bin/app"));
    CHECK(contains(detail, "relocatable"));
    CHECK(contains(detail, "not runnable"));
}

TEST_CASE("an entrypoint that is not in the payload at all is rejected at the "
          "payload-role stage") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    lexe::test::TestAppSpec spec;
    spec.public_key = lexe::test::encode_public_key_str(key.public_key);
    spec.entrypoint = "bin/does-not-exist";
    const lexe::test::TestAppTree tree =
        lexe::test::make_test_app_tree(home.path() / "tree-absent", spec);
    lexe::PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;
    const fs::path pkg = home.path() / "absent-entrypoint.lexe";
    lexe::PackageWriter::write(inputs, key, pkg);

    const VerificationReport report = lexe::verify_package(pkg);
    expect_payload_role_failure(report);
    CHECK(contains(failure_detail(report), "bin/does-not-exist"));
    CHECK(contains(failure_detail(report), "not present"));
}

// ===================================================================
// The good path, and where the stage sits in the pipeline
// ===================================================================

TEST_CASE("a native package with a REAL compiled ELF entrypoint passes the "
          "payload-role stage") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    // make_test_app_tree emits a compiled native executable as the entrypoint
    // (helpers.hpp write_native_executable) — the shape the alpha should have
    // shipped.
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    const VerificationReport report = lexe::verify_package(pkg);
    CHECK(report.ok());
    const std::size_t index = stage_index(report, kPayloadRole);
    REQUIRE(index != std::string::npos);
    CHECK(report.stages[index].ok);
    CHECK(contains(stage_detail(report, kPayloadRole), "runnable ELF"));

    // The entrypoint really is an ELF executable/PIE for a declared arch.
    const lexe::PackageReader reader(pkg);
    const std::vector<std::uint8_t> bytes =
        reader.read_entry("payload/" + lexe::test::TestAppSpec{}.entrypoint);
    const lexe::elf::ElfInfo info =
        lexe::elf::read_bytes(bytes.data(), bytes.size());
    CHECK(info.is_elf);
    CHECK((info.type == lexe::elf::Type::Executable ||
           info.type == lexe::elf::Type::SharedObject));
    CHECK(info.arch() == lexe::host_architecture());
}

TEST_CASE("payload-role runs AFTER hashes: a tampered entrypoint is an "
          "integrity failure, not a role failure") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);
    const std::string entry =
        "payload/" + lexe::test::TestAppSpec{}.entrypoint;

    // Destroy the ELF magic of the entrypoint. That makes it BOTH a hash
    // mismatch and a role violation — the pipeline must report the integrity
    // failure, because unverified bytes are never worth interpreting.
    lexe::test::tamper_entry(pkg, entry,
                             [](std::vector<std::uint8_t>& bytes) {
                                 REQUIRE(bytes.size() > 4);
                                 for (int i = 0; i < 4; ++i) bytes[i] = 0;
                             });

    const VerificationReport report = lexe::verify_package(pkg);
    REQUIRE_FALSE(report.ok());
    REQUIRE(report.first_failure() != nullptr);
    CHECK(report.first_failure()->name == "hashes");
    CHECK(contains(failure_detail(report), entry));
    // payload-role never ran — stages after the first failure are absent.
    CHECK(stage_index(report, kPayloadRole) == std::string::npos);
}

TEST_CASE("payload-role sits between hashes and compatibility") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_test_package(home.path(), key);

    const VerificationReport report =
        lexe::verify_package(pkg, /*check_architecture=*/true);
    REQUIRE(report.ok());
    const std::size_t hashes = stage_index(report, "hashes");
    const std::size_t role = stage_index(report, kPayloadRole);
    const std::size_t compat = stage_index(report, "compatibility");
    REQUIRE(hashes != std::string::npos);
    REQUIRE(role != std::string::npos);
    REQUIRE(compat != std::string::npos);
    CHECK(role == hashes + 1);
    CHECK(compat == role + 1);
}

// ---------------------------------------------------------------------------
// The inverse of the alpha bug: applicationType "portable" (FORMAT-0.1 §6.7).
//
// The alpha shipped SOURCE labelled as a native payload. A portable package
// shipping a prebuilt binary is the same lie told the other way round: the
// package claims the destination machine compiles it, while the entrypoint
// that ends up installed is a binary this host never built. Stage 7 refuses
// both, and for the same reason — the bytes must BE what the manifest says.
// ---------------------------------------------------------------------------

TEST_CASE("a portable package carrying source passes payload-role") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_portable_package(home.path(), key);

    const VerificationReport report = lexe::verify_package(pkg);
    REQUIRE(report.ok());
    const std::string detail = stage_detail(report, kPayloadRole);
    CHECK(contains(detail, "portable"));
    // The stage says what it checked, including that the entrypoint is absent
    // on purpose rather than missing by accident.
    CHECK(contains(detail, "src"));
    CHECK(contains(detail, "bin/app"));
}

TEST_CASE("a portable package that ships its entrypoint is refused") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    lexe::test::PortableAppSpec spec;
    spec.id = "com.example.prebuilt";
    spec.ship_prebuilt_entrypoint = true;
    const fs::path pkg =
        lexe::test::make_portable_package(home.path(), key, spec);

    const VerificationReport report = lexe::verify_package(pkg);
    expect_payload_role_failure(report);
    const std::string detail = failure_detail(report);
    CHECK(contains(detail, "bin/app"));
    CHECK(contains(detail, "portable"));
    // And it says WHY, in the terms a publisher can act on.
    CHECK(contains(detail, "native payload wearing a portable label"));
}

TEST_CASE("a portable package with no source is refused") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    lexe::test::PortableAppSpec spec;
    spec.id = "com.example.nosource";
    spec.omit_source = true;
    const fs::path pkg =
        lexe::test::make_portable_package(home.path(), key, spec);

    const VerificationReport report = lexe::verify_package(pkg);
    expect_payload_role_failure(report);
    CHECK(contains(failure_detail(report), "src"));
    CHECK(contains(failure_detail(report),
                   "must carry the source it is compiled from"));
}

TEST_CASE("a portable package's source is not judged as an ELF") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    // The exact shape of the original defect — C source in the payload — is
    // correct here, and must not trip the native ELF check.
    const fs::path pkg = lexe::test::make_portable_package(home.path(), key);
    const VerificationReport report = lexe::verify_package(pkg);
    REQUIRE(report.ok());
    CHECK_FALSE(contains(stage_detail(report, kPayloadRole), "ELF"));
}

// ---------------------------------------------------------------------------
// applicationType "windows" — the same question, one operating system over
// (FORMAT-0.1 §6.7).
//
// Without this, a foreign-OS package would reintroduce the alpha's defining
// bug exactly: a manifest describing bytes nothing had checked it against. The
// failure would surface as an unexplained Wine error long after the package
// was installed, which is the shape of defect this stage exists to end.
// ---------------------------------------------------------------------------

TEST_CASE("a windows package carrying a PE executable passes payload-role") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    const fs::path pkg = lexe::test::make_windows_package(home.path(), key);

    const VerificationReport report = lexe::verify_package(pkg);
    REQUIRE(report.ok());
    const std::string detail = stage_detail(report, kPayloadRole);
    CHECK(contains(detail, "windows"));
    CHECK(contains(detail, "bin/app.exe"));
}

TEST_CASE("a windows package whose entrypoint is a Linux binary is refused") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    lexe::test::WindowsAppSpec spec;
    spec.id = "com.example.notwindows";
    // A real, valid ELF executable — every signature and hash will be correct.
    // It is simply not what the manifest says it is.
    spec.raw_entrypoint = lexe::test::build_elf(lexe::test::ElfSpec{});
    const fs::path pkg =
        lexe::test::make_windows_package(home.path(), key, spec);

    const VerificationReport report = lexe::verify_package(pkg);
    expect_payload_role_failure(report);
    const std::string detail = failure_detail(report);
    CHECK(contains(detail, "not a Windows PE image"));
    // And it says where those bytes DO belong.
    CHECK(contains(detail, "\"native\" package"));
}

TEST_CASE("a windows package whose entrypoint is a DLL is refused") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    lexe::test::WindowsAppSpec spec;
    spec.id = "com.example.dll";
    spec.payload.dll = true;
    const fs::path pkg =
        lexe::test::make_windows_package(home.path(), key, spec);

    const VerificationReport report = lexe::verify_package(pkg);
    expect_payload_role_failure(report);
    CHECK(contains(failure_detail(report), "DLL"));
    CHECK(contains(failure_detail(report), "cannot be launched"));
}

TEST_CASE("a windows package for an undeclared architecture is refused") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    lexe::test::WindowsAppSpec spec;
    spec.id = "com.example.wrongarch";
    spec.architectures = {"aarch64"};
    spec.payload.machine = 0x8664; // an amd64 image
    const fs::path pkg =
        lexe::test::make_windows_package(home.path(), key, spec);

    const VerificationReport report = lexe::verify_package(pkg);
    expect_payload_role_failure(report);
    CHECK(contains(failure_detail(report), "x86_64"));
    CHECK(contains(failure_detail(report), "aarch64"));
}

TEST_CASE("a 32-bit windows payload is refused, by name") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    lexe::test::WindowsAppSpec spec;
    spec.id = "com.example.win32";
    spec.payload.machine = 0x014C; // i386
    spec.payload.pe32_plus = false;
    const fs::path pkg =
        lexe::test::make_windows_package(home.path(), key, spec);

    const VerificationReport report = lexe::verify_package(pkg);
    expect_payload_role_failure(report);
    // FORMAT-0.1 §5 has no architecture id for i386, so the package cannot
    // declare one. Saying that is better than reporting a mismatch against a
    // list the publisher could never have satisfied.
    CHECK(contains(failure_detail(report), "i386"));
    CHECK(contains(failure_detail(report), "cannot name"));
}

TEST_CASE("a windows package with a missing entrypoint is refused") {
    TempLexeHome home;
    const lexe::crypto::KeyPair key = lexe::test::make_keypair();
    lexe::test::WindowsAppSpec spec;
    spec.id = "com.example.noentry";
    // Write the PE somewhere else, so the payload is non-empty but the
    // declared entrypoint is simply not there.
    spec.entrypoint = "bin/app.exe";
    const fs::path tree_root = home.path() / "handmade";
    lexe::test::TestAppTree tree =
        lexe::test::make_windows_app_tree(tree_root, spec);
    fs::remove(tree.payload_dir / "bin" / "app.exe");

    // Re-sign the tree as it now stands.
    lexe::PackageWriter::Inputs inputs;
    inputs.payload_dir = tree.payload_dir;
    inputs.manifest_file = tree.manifest_file;
    const fs::path pkg = home.path() / "noentry.lexe";
    {
        // The manifest embeds the fixture's placeholder key; rewrite it with
        // the real one so every earlier stage still passes.
        std::string text = lexe::util::slurp_text(tree.manifest_file);
        const std::string placeholder = spec.public_key;
        const std::string real = lexe::test::encode_public_key_str(key.public_key);
        const std::size_t at = text.find(placeholder);
        REQUIRE(at != std::string::npos);
        text.replace(at, placeholder.size(), real);
        lexe::util::spit(tree.manifest_file, std::string_view(text));
    }
    lexe::PackageWriter::write(inputs, key, pkg);

    const VerificationReport report = lexe::verify_package(pkg);
    expect_payload_role_failure(report);
    CHECK(contains(failure_detail(report), "not present in the package"));
}

} // TEST_SUITE("payload_role")

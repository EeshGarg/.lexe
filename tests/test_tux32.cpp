// Tux32 Core 1 baseline tests (portability milestone): the compiled profile is
// pinned, strict JSON parsing is enforced, and the checked-in machine-readable
// profile.json mirror is proven to match the compiled definition (no drift).

#include <doctest/doctest.h>

#include "core/error.hpp"
#include "core/tux32.hpp"
#include "core/util.hpp"

#include <filesystem>
#include <string>

using namespace lexe;

namespace {
std::string profile_json_path() {
#ifdef LEXE_SOURCE_DIR
    return std::string(LEXE_SOURCE_DIR) + "/sdk/tux32-core-1/profile.json";
#else
    return "sdk/tux32-core-1/profile.json";
#endif
}
} // namespace

TEST_SUITE("tux32") {

TEST_CASE("Core 1 is concretely defined and versioned") {
    const Tux32Profile& p = tux32_core_1();
    CHECK(p.id == "tux32-core-1");
    CHECK(p.spec_version == "1");
    CHECK(p.executable_format == "elf-dynamic");
    // Core 1 is x86-64 ONLY — it must not claim aarch64/riscv64.
    CHECK(p.architectures == std::vector<std::string>{"x86_64"});
    CHECK(p.supports_arch("x86_64"));
    CHECK_FALSE(p.supports_arch("aarch64"));
    CHECK_FALSE(p.supports_arch("riscv64"));
    CHECK(p.cpu_baseline == "x86-64-v1");
    CHECK(p.glibc_ceiling() == "2.31");
}

TEST_CASE("the glibc ceiling comparison is inclusive at the ceiling") {
    const Tux32Profile& p = tux32_core_1(); // 2.31
    CHECK(p.within_glibc_ceiling(2, 17));   // below
    CHECK(p.within_glibc_ceiling(2, 31));   // exactly at the ceiling
    CHECK_FALSE(p.within_glibc_ceiling(2, 32)); // above
    CHECK_FALSE(p.within_glibc_ceiling(2, 34)); // the __libc_start_main bump
    CHECK(p.within_glibc_ceiling(1, 99));   // a smaller major is always within
    CHECK_FALSE(p.within_glibc_ceiling(3, 0));
}

TEST_CASE("parse_glibc_version handles good and bad inputs") {
    int major = 0, minor = 0;
    CHECK(parse_glibc_version("2.38", major, minor));
    CHECK(major == 2);
    CHECK(minor == 38);
    CHECK_FALSE(parse_glibc_version("2", major, minor));
    CHECK_FALSE(parse_glibc_version("", major, minor));
    CHECK_FALSE(parse_glibc_version("x.y", major, minor));
}

TEST_CASE("strict profile parsing rejects malformed input") {
    // Duplicate keys are rejected (json_strict).
    CHECK_THROWS_AS(parse_profile_json(R"({"id":"a","id":"b"})"),
                    VerificationError);
    // Missing required fields.
    CHECK_THROWS_AS(parse_profile_json(R"({"id":"tux32-core-1"})"),
                    VerificationError);
    // Bad glibc ceiling.
    CHECK_THROWS_AS(
        parse_profile_json(
            R"({"id":"x","specVersion":"1","executableFormat":"elf-dynamic","architectures":["x86_64"],"cpuBaseline":"x86-64-v1","glibcCeiling":"nope"})"),
        VerificationError);
    // Empty architectures.
    CHECK_THROWS_AS(
        parse_profile_json(
            R"({"id":"x","specVersion":"1","executableFormat":"elf-dynamic","architectures":[],"cpuBaseline":"x86-64-v1","glibcCeiling":"2.31"})"),
        VerificationError);
}

TEST_CASE("the machine-readable profile.json matches the compiled profile") {
    const std::string path = profile_json_path();
    REQUIRE(std::filesystem::is_regular_file(path));
    const Tux32Profile file = parse_profile_json(util::slurp_text(path));
    const Tux32Profile& compiled = tux32_core_1();

    // The ENFORCED contract must match exactly — the two can never drift.
    CHECK(file.id == compiled.id);
    CHECK(file.spec_version == compiled.spec_version);
    CHECK(file.executable_format == compiled.executable_format);
    CHECK(file.architectures == compiled.architectures);
    CHECK(file.cpu_baseline == compiled.cpu_baseline);
    CHECK(file.glibc_major == compiled.glibc_major);
    CHECK(file.glibc_minor == compiled.glibc_minor);
    // The descriptive policy must be fully populated in the mirror.
    CHECK_FALSE(file.forbidden.empty());
    CHECK_FALSE(file.isolation.empty());
    CHECK_FALSE(file.claim_language.empty());
    CHECK_FALSE(file.conformance.empty());
}

} // TEST_SUITE("tux32")

// Tux32 Core 1 verification-engine tests (portability milestone). Crafted ELFs
// drive each typed verdict through the REAL dependency engine — no second
// analysis path. Cross-platform (byte-level ELF fixtures; no system libs).

#include <doctest/doctest.h>

#include "elf_builder.hpp"
#include "helpers.hpp"

#include "core/depengine.hpp"
#include "core/tux32.hpp"
#include "core/util.hpp"

#include <algorithm>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

struct Payload {
    fs::path dir;
    Payload() : dir(test::unique_temp_dir("lexe-core1-")) {
        fs::create_directories(dir);
    }
    ~Payload() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

// Analyze `root` with the payload dir as a bundle search path, then verify.
Core1VerifyResult verify(const fs::path& root, const fs::path& payload) {
    DependencyOptions opts;
    opts.payload_search_paths = {payload};
    const DependencyReport deps = analyze_dependencies(root, opts);
    return verify_against_profile(deps, tux32_core_1());
}

bool has(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

test::ElfSpec dyn_app() {
    test::ElfSpec s;
    s.interp = "/lib64/ld-linux-x86-64.so.2"; // dynamically linked
    s.e_machine = 62;                          // x86_64
    return s;
}

} // namespace

TEST_SUITE("tux32-verify") {

TEST_CASE("a below-ceiling dynamic x86_64 app is conformant") {
    Payload p;
    test::ElfSpec lib;
    lib.soname = "libfoo.so.1";
    lib.version_needs = {"GLIBC_2.17"};
    test::write_elf(p.dir / "libfoo.so.1", lib);

    test::ElfSpec app = dyn_app();
    app.needed = {"libc.so.6", "libfoo.so.1"};
    app.version_needs = {"GLIBC_2.17"};
    const fs::path root = p.dir / "app";
    test::write_elf(root, app);

    const Core1VerifyResult r = verify(root, p.dir);
    CHECK(r.verdict == Core1Verdict::Conformant);
    CHECK(r.conformant());
    CHECK(r.architecture == "x86_64");
    CHECK(r.glibc_ceiling == "2.31");
    CHECK(r.required_glibc == "2.17");
    CHECK(has(r.host_interfaces, "libc.so.6"));
    CHECK(has(r.bundle_candidates, "libfoo.so.1"));
    CHECK(r.symbol_offenders.empty());
    CHECK(r.profile_id == "tux32-core-1");
}

TEST_CASE("exactly at the ceiling is conformant; one above is not") {
    Payload p;
    test::ElfSpec at = dyn_app();
    at.needed = {"libc.so.6"};
    at.version_needs = {"GLIBC_2.31"}; // exactly the ceiling
    test::write_elf(p.dir / "at", at);
    CHECK(verify(p.dir / "at", p.dir).verdict == Core1Verdict::Conformant);

    test::ElfSpec above = dyn_app();
    above.needed = {"libc.so.6"};
    above.version_needs = {"GLIBC_2.2", "GLIBC_2.34"}; // the real-world case
    const fs::path root = p.dir / "above";
    test::write_elf(root, above);

    const Core1VerifyResult r = verify(root, p.dir);
    CHECK(r.verdict == Core1Verdict::SymbolCeilingExceeded);
    CHECK_FALSE(r.conformant());
    CHECK(r.required_glibc == "2.34");
    REQUIRE(r.symbol_offenders.size() == 1);
    // The offender names the actual file, not the literal token "<executable>"
    // that used to be printed verbatim to users by `lexe analyze`, `lexe sdk
    // verify`, `lexe inspect` and the Builder.
    CHECK(r.symbol_offenders[0].object == "above");
    CHECK(r.symbol_offenders[0].version == "GLIBC_2.34");
    CHECK(r.detail.find("2.31") != std::string::npos); // names the ceiling
}

TEST_CASE("a TRANSITIVE bundled library sets the offending floor") {
    Payload p;
    // The app is fine, but a library it bundles needs a newer glibc.
    test::ElfSpec lib;
    lib.soname = "libbar.so.1";
    lib.version_needs = {"GLIBC_2.34"};
    test::write_elf(p.dir / "libbar.so.1", lib);

    test::ElfSpec app = dyn_app();
    app.needed = {"libc.so.6", "libbar.so.1"};
    app.version_needs = {"GLIBC_2.17"}; // the executable itself is fine
    const fs::path root = p.dir / "app";
    test::write_elf(root, app);

    const Core1VerifyResult r = verify(root, p.dir);
    CHECK(r.verdict == Core1Verdict::SymbolCeilingExceeded);
    CHECK(r.required_glibc == "2.34");
    REQUIRE(r.symbol_offenders.size() == 1);
    CHECK(r.symbol_offenders[0].object == "libbar.so.1"); // the transitive lib
}

TEST_CASE("an unresolved dependency is non-conformant") {
    Payload p;
    test::ElfSpec app = dyn_app();
    app.needed = {"libc.so.6", "libmissing.so.9"};
    app.version_needs = {"GLIBC_2.17"};
    const fs::path root = p.dir / "app";
    test::write_elf(root, app);

    const Core1VerifyResult r = verify(root, p.dir);
    CHECK(r.verdict == Core1Verdict::UnresolvedDependency);
    CHECK(has(r.unresolved, "libmissing.so.9"));
    CHECK_FALSE(r.notes.empty()); // closure-incomplete note
}

TEST_CASE("a forbidden host driver interface is non-conformant") {
    Payload p;
    test::ElfSpec app = dyn_app();
    app.needed = {"libc.so.6", "libGL.so.1"};
    app.version_needs = {"GLIBC_2.17"};
    const fs::path root = p.dir / "app";
    test::write_elf(root, app);

    const Core1VerifyResult r = verify(root, p.dir);
    CHECK(r.verdict == Core1Verdict::ForbiddenDependency);
    CHECK(has(r.forbidden, "libGL.so.1"));
}

TEST_CASE("a non-x86_64 architecture is unsupported by Core 1") {
    Payload p;
    test::ElfSpec app = dyn_app();
    app.e_machine = 183; // aarch64
    app.needed = {"libc.so.6"};
    app.version_needs = {"GLIBC_2.17"};
    const fs::path root = p.dir / "app";
    test::write_elf(root, app);

    const Core1VerifyResult r = verify(root, p.dir);
    CHECK(r.verdict == Core1Verdict::UnsupportedArchitecture);
    CHECK(r.architecture == "aarch64");
}

TEST_CASE("a statically linked object is an unsupported executable") {
    Payload p;
    test::ElfSpec app; // no interp → not dynamically linked
    app.e_machine = 62;
    app.version_needs = {"GLIBC_2.17"};
    const fs::path root = p.dir / "static";
    test::write_elf(root, app);

    const Core1VerifyResult r = verify(root, p.dir);
    CHECK(r.verdict == Core1Verdict::UnsupportedExecutable);
}

TEST_CASE("a non-ELF target is invalid input") {
    Payload p;
    const fs::path root = p.dir / "readme.txt";
    util::spit(root, std::string_view("not an elf"));
    const Core1VerifyResult r = verify(root, p.dir);
    CHECK(r.verdict == Core1Verdict::InvalidInput);
}

TEST_CASE("verification is deterministic") {
    Payload p;
    test::ElfSpec app = dyn_app();
    app.needed = {"libc.so.6"};
    app.version_needs = {"GLIBC_2.35"};
    const fs::path root = p.dir / "app";
    test::write_elf(root, app);
    const Core1VerifyResult a = verify(root, p.dir);
    const Core1VerifyResult b = verify(root, p.dir);
    CHECK(a.verdict == b.verdict);
    CHECK(a.required_glibc == b.required_glibc);
    CHECK(a.detail == b.detail);
}

} // TEST_SUITE("tux32-verify")

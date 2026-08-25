// Dependency-engine tests (Phase 2 / DX3). A crafted payload of ELF stubs
// exercises classification, recursion, hashing, dedup, cycles and version needs
// without touching any real system library.

#include <doctest/doctest.h>

#include "elf_builder.hpp"
#include "helpers.hpp"

#include "core/depengine.hpp"
#include "core/elf.hpp"

#include <algorithm>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;
using namespace lexe;

namespace {

const Dependency* find(const DependencyReport& r, const std::string& soname) {
    for (const Dependency& d : r.dependencies) {
        if (d.soname == soname) return &d;
    }
    return nullptr;
}

} // namespace

TEST_SUITE("depengine") {

TEST_CASE("classifies host / bundle / forbidden / unresolved dependencies") {
    const fs::path work = test::unique_temp_dir("lexe-dep-");
    fs::create_directories(work);

    // A bundled library present in the payload, which itself needs a nested lib.
    test::ElfSpec nested;
    nested.soname = "libnested.so.1";
    test::write_elf(work / "libnested.so.1", nested);

    test::ElfSpec custom;
    custom.soname = "libcustom.so.1";
    custom.needed = {"libnested.so.1", "libc.so.6"};
    test::write_elf(work / "libcustom.so.1", custom);

    // The application's main binary.
    test::ElfSpec app;
    app.interp = "/lib64/ld-linux-x86-64.so.2";
    app.needed = {"libc.so.6", "libcustom.so.1", "libGL.so.1", "libmissing.so.9"};
    const fs::path root = work / "app";
    test::write_elf(root, app);

    DependencyOptions opts;
    opts.payload_search_paths = {work};
    const DependencyReport r = analyze_dependencies(root, opts);

    CHECK(r.root_info.is_elf);
    CHECK(r.root_info.machine == elf::Machine::X86_64);

    REQUIRE(find(r, "libc.so.6") != nullptr);
    CHECK(find(r, "libc.so.6")->kind == DependencyKind::HostInterface);

    const Dependency* custom_dep = find(r, "libcustom.so.1");
    REQUIRE(custom_dep != nullptr);
    CHECK(custom_dep->kind == DependencyKind::Bundle);
    CHECK(custom_dep->resolved_path == work / "libcustom.so.1");
    CHECK(custom_dep->sha256.size() == 64); // bundled files are hashed

    CHECK(find(r, "libGL.so.1")->kind == DependencyKind::Forbidden);
    CHECK(find(r, "libmissing.so.9")->kind == DependencyKind::Unresolved);

    // Recursion discovered the nested library, attributed to its dependant.
    const Dependency* nested_dep = find(r, "libnested.so.1");
    REQUIRE(nested_dep != nullptr);
    CHECK(nested_dep->kind == DependencyKind::Bundle);
    CHECK(std::find(nested_dep->needed_by.begin(), nested_dep->needed_by.end(),
                    "libcustom.so.1") != nested_dep->needed_by.end());

    CHECK(r.count(DependencyKind::Forbidden) == 1);
    CHECK(r.has_unresolved());
    CHECK(r.has_forbidden());

    fs::remove_all(work);
}

TEST_CASE("a dependency cycle is handled without infinite recursion") {
    const fs::path work = test::unique_temp_dir("lexe-dep-cycle-");
    fs::create_directories(work);

    test::ElfSpec a;
    a.soname = "liba.so.1";
    a.needed = {"libb.so.1"};
    test::write_elf(work / "liba.so.1", a);
    test::ElfSpec b;
    b.soname = "libb.so.1";
    b.needed = {"liba.so.1"}; // cycle back to A
    test::write_elf(work / "libb.so.1", b);

    test::ElfSpec app;
    app.needed = {"liba.so.1"};
    const fs::path root = work / "app";
    test::write_elf(root, app);

    DependencyOptions opts;
    opts.payload_search_paths = {work};
    const DependencyReport r = analyze_dependencies(root, opts); // must terminate

    CHECK(find(r, "liba.so.1") != nullptr);
    CHECK(find(r, "libb.so.1") != nullptr);
    CHECK_FALSE(r.cycles.empty()); // the cycle was noticed
    fs::remove_all(work);
}

TEST_CASE("version needs aggregate to the highest glibc requirement") {
    const fs::path work = test::unique_temp_dir("lexe-dep-ver-");
    fs::create_directories(work);

    test::ElfSpec lib;
    lib.soname = "libx.so.1";
    lib.version_needs = {"GLIBC_2.38", "GLIBC_2.17"};
    test::write_elf(work / "libx.so.1", lib);

    test::ElfSpec app;
    app.needed = {"libx.so.1"};
    app.version_needs = {"GLIBC_2.34", "GLIBCXX_3.4.30"};
    const fs::path root = work / "app";
    test::write_elf(root, app);

    DependencyOptions opts;
    opts.payload_search_paths = {work};
    const DependencyReport r = analyze_dependencies(root, opts);

    CHECK(r.max_glibc_version() == "2.38");
    const std::vector<std::string> all = r.all_version_needs();
    CHECK(std::find(all.begin(), all.end(), "GLIBCXX_3.4.30") != all.end());
    fs::remove_all(work);
}

TEST_CASE("a non-ELF root yields an empty, non-crashing report") {
    const fs::path work = test::unique_temp_dir("lexe-dep-nonelf-");
    fs::create_directories(work);
    util::spit(work / "notelf", std::string_view("#!/bin/sh\necho hi\n"));

    const DependencyReport r = analyze_dependencies(work / "notelf");
    CHECK_FALSE(r.root_info.is_elf);
    CHECK(r.dependencies.empty());
    fs::remove_all(work);
}

TEST_CASE("default_search_dirs include the multiarch triplet") {
    const auto dirs = default_search_dirs(elf::Machine::X86_64);
    bool saw_triplet = false;
    for (const fs::path& d : dirs) {
        if (d.string().find("x86_64-linux-gnu") != std::string::npos) {
            saw_triplet = true;
        }
    }
    CHECK(saw_triplet);
}

TEST_CASE("the glibc requirement is the PACKAGE's, not the build host's") {
    // A host-interface library (libm.so.6) carries its own, much newer internal
    // GLIBC_x.y needs. The target host ships its own matching copy, so those
    // needs say nothing about this application — counting them would make the
    // same package report a different requirement on every distribution it was
    // analyzed on. Only the executable and BUNDLED libraries count.
    const fs::path work = test::unique_temp_dir("lexe-dep-hostglibc-");
    fs::create_directories(work);

    test::ElfSpec host;                       // classified host-interface by soname
    host.soname = "libm.so.6";
    host.version_needs = {"GLIBC_2.38"};      // the build host's own internals
    test::write_elf(work / "libm.so.6", host);

    test::ElfSpec bundled;                    // an ordinary library we ship
    bundled.soname = "libextra.so.1";
    bundled.version_needs = {"GLIBC_2.28"};
    test::write_elf(work / "libextra.so.1", bundled);

    test::ElfSpec app;
    app.needed = {"libm.so.6", "libextra.so.1"};
    app.version_needs = {"GLIBC_2.34"};
    const fs::path root = work / "app";
    test::write_elf(root, app);

    DependencyOptions opts;
    opts.payload_search_paths = {work};
    const DependencyReport r = analyze_dependencies(root, opts);

    REQUIRE(find(r, "libm.so.6") != nullptr);
    CHECK(find(r, "libm.so.6")->kind == DependencyKind::HostInterface);
    CHECK(find(r, "libextra.so.1")->kind == DependencyKind::Bundle);

    // The executable's 2.34 wins over the bundled 2.28; the host's 2.38 is
    // excluded entirely.
    CHECK(r.max_glibc_version() == "2.34");

    // The raw graph accessor still reports everything it saw, host libs
    // included — it is the diagnostic view, not the requirement.
    const std::vector<std::string> all = r.all_version_needs();
    CHECK(std::find(all.begin(), all.end(), "GLIBC_2.38") != all.end());

    fs::remove_all(work);
}

} // TEST_SUITE("depengine")

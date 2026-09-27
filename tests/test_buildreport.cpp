// Build-report tests (Phase 2 / DX5): assembly + frontend-neutral rendering.

#include <doctest/doctest.h>

#include "lexe/runtime/buildreport.hpp"
#include "lexe/analysis/depengine.hpp"
#include "lexe/runtime/runtime_profile.hpp"

#include <string>

using namespace lexe;

namespace {

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

Dependency dep(const std::string& soname, DependencyKind kind,
               const std::string& sha = "",
               DependencyOrigin origin = DependencyOrigin::Payload) {
    Dependency d;
    d.soname = soname;
    d.kind = kind;
    d.sha256 = sha;
    d.origin = origin;
    return d;
}

} // namespace

TEST_SUITE("buildreport") {

TEST_CASE("assemble + render summarizes identity, deps, profile and compatibility") {
    DependencyReport deps;
    deps.root_info.is_elf = true;
    deps.root_info.machine = elf::Machine::X86_64;
    deps.root_info.version_needs = {"GLIBC_2.17"};
    deps.dependencies = {dep("libc.so.6", DependencyKind::HostInterface),
                         dep("libfoo.so.1", DependencyKind::Bundle,
                             std::string(64, 'a'))};

    BuildReport r = assemble_report(std::move(deps), RuntimeProfile::CorePortable);
    r.app_name = "Demo";
    r.app_version = "1.0.0";
    r.app_id = "com.example.demo";
    r.permissions = {"network"};
    r.signing_fingerprint = "ABCD 1234";

    CHECK(r.architectures == std::vector<std::string>{"x86_64"});

    const std::string text = render_build_report_text(r);
    CHECK(has(text, "Demo 1.0.0 (com.example.demo)"));
    CHECK(has(text, "x86_64"));
    CHECK(has(text, "Core Portable"));
    // "Libraries to bundle", not "Bundled libraries". DependencyKind::Bundle is
    // a recommendation that the library be carried, and this heading used to
    // assert that it already was -- over a list that could include libraries
    // found on the build host, printed with digests.
    CHECK(has(text, "Libraries to bundle"));
    CHECK_FALSE(has(text, "Bundled libraries"));
    CHECK(has(text, "libfoo.so.1"));
    // Every resolved entry states WHERE it was found, so a digest can never be
    // read as a claim about package content.
    CHECK(has(text, "[in the package]"));
    CHECK(has(text, "Host interfaces"));
    CHECK(has(text, "network"));
    CHECK(has(text, "ABCD 1234"));
    CHECK(has(text, "Compatibility:"));
    CHECK(has(text, "UshaOS Core"));

    const nlohmann::ordered_json j = build_report_json(r);
    CHECK(j.at("application").at("id") == "com.example.demo");
    CHECK(j.at("runtimeProfile") == "core-portable");
    CHECK(j.at("dependencySummary").at("bundle") == 1);
    CHECK(j.at("compatibility").at("targets").size() ==
          known_runtime_targets().size());
}

TEST_CASE("a bare-binary report omits the identity block") {
    DependencyReport deps;
    deps.root_info.is_elf = true;
    deps.root_info.machine = elf::Machine::AArch64;
    const BuildReport r =
        assemble_report(std::move(deps), RuntimeProfile::NativeCapture);
    const std::string text = render_build_report_text(r);
    CHECK_FALSE(has(text, "Application:"));
    CHECK(has(text, "Native Capture"));
    // Native Capture is honestly labelled reduced portability.
    CHECK_FALSE(r.profile_assessment.claims_portability);
}

// A dynamically linked x86_64 root with the given glibc need.
DependencyReport dyn_root(const std::string& glibc_need) {
    DependencyReport deps;
    deps.root_info.is_elf = true;
    deps.root_info.has_interpreter = true;
    deps.root_info.is_dynamic = true;
    deps.root_info.machine = elf::Machine::X86_64;
    deps.root_info.version_needs = {glibc_need};
    deps.dependencies = {dep("libc.so.6", DependencyKind::HostInterface)};
    return deps;
}

TEST_CASE("Core Portable reports attach a Tux32 Core 1 verdict; others do not") {
    SUBCASE("conformant Core Portable") {
        const BuildReport r =
            assemble_report(dyn_root("GLIBC_2.17"), RuntimeProfile::CorePortable);
        REQUIRE(r.core1.has_value());
        CHECK(r.core1->verdict == Core1Verdict::Conformant);
        const std::string text = render_build_report_text(r);
        CHECK(has(text, "Tux32 tux32-core-1: conformant"));
        const nlohmann::ordered_json j = build_report_json(r);
        CHECK(j.at("tux32").at("verdict") == "conformant");
        CHECK(j.at("tux32").at("conformant") == true);
    }
    SUBCASE("non-conformant Core Portable names the offender") {
        const BuildReport r =
            assemble_report(dyn_root("GLIBC_2.34"), RuntimeProfile::CorePortable);
        REQUIRE(r.core1.has_value());
        CHECK(r.core1->verdict == Core1Verdict::SymbolCeilingExceeded);
        const std::string text = render_build_report_text(r);
        CHECK(has(text, "symbol-ceiling-exceeded"));
        CHECK(has(text, "GLIBC_2.34"));
        const nlohmann::ordered_json j = build_report_json(r);
        CHECK(j.at("tux32").at("requiredGlibc") == "2.34");
        CHECK(j.at("tux32").at("symbolOffenders").size() == 1);
    }
    SUBCASE("Forward Runtime carries no Tux32 verdict") {
        const BuildReport r = assemble_report(dyn_root("GLIBC_2.34"),
                                              RuntimeProfile::ForwardRuntime);
        CHECK_FALSE(r.core1.has_value());
        CHECK_FALSE(has(render_build_report_text(r), "Tux32"));
        const nlohmann::ordered_json j = build_report_json(r);
        CHECK(j.find("tux32") == j.end());
    }
    SUBCASE("Native Capture carries no Tux32 verdict") {
        const BuildReport r = assemble_report(dyn_root("GLIBC_2.34"),
                                              RuntimeProfile::NativeCapture);
        CHECK_FALSE(r.core1.has_value());
    }
}

TEST_CASE("a resolved library's origin is stated, never left to inference") {
    // The regression this locks down: an independent pass packaged a program
    // whose ONLY payload file was its own executable, carrying an absolute
    // DT_RPATH into a build-tree directory. `analyze` reported three libraries
    // as "bundle" with digests -- reading as "carried by the package and
    // verified" -- and the launch then failed with exit 127 and nothing on
    // either stream, because that directory does not exist inside the sandbox.
    DependencyReport deps;
    deps.root_info.is_elf = true;
    deps.root_info.machine = elf::Machine::X86_64;
    deps.dependencies = {
        dep("libin.so.1", DependencyKind::Bundle, std::string(64, 'a'),
            DependencyOrigin::Payload),
        dep("libhost.so.2", DependencyKind::Bundle, std::string(64, 'b'),
            DependencyOrigin::System),
        dep("libgone.so.3", DependencyKind::Bundle, std::string(64, 'c'),
            DependencyOrigin::Elsewhere)};
    deps.dependencies[2].resolved_path = "/tmp/some-build-tree/lib/libgone.so.3";

    const std::string text = render_build_report_text(
        assemble_report(std::move(deps), RuntimeProfile::CorePortable));

    CHECK(has(text, "[in the package]"));
    CHECK(has(text, "[found on this host, NOT in the package]"));
    // The one that breaks a launch names the path and says what it means.
    CHECK(has(text, "/tmp/some-build-tree/lib/libgone.so.3"));
    CHECK(has(text, "a sandboxed launch will not have"));
}

TEST_CASE("a disregarded out-of-package rpath is actually shown to the publisher") {
    // This exists because the field it covers was introduced WITH a stated
    // purpose -- "a real smell worth showing a publisher" -- assigned in the
    // engine, and then read by nothing at all. Not the text report, not --json,
    // not the builder, not a test. It was dead on arrival and nothing would have
    // noticed if the assignment had broken, which is the same failure as a
    // passing test that never runs: it reports like a feature and is not one.
    //
    // The shape it describes: the binary's DT_RPATH points at a build-tree
    // directory that still exists on the analysing host and shadows the system
    // copy, so the library IS satisfiable from /usr and the package installs and
    // runs -- while the binary quietly carries a search path that means nothing
    // anywhere else. Only the publisher can remove it, and only if told.
    DependencyReport deps;
    deps.root_info.is_elf = true;
    deps.root_info.machine = elf::Machine::X86_64;
    deps.dependencies = {dep("libz.so.1", DependencyKind::Bundle,
                             std::string(64, 'd'), DependencyOrigin::System)};
    deps.dependencies[0].resolved_path = "/usr/lib/x86_64-linux-gnu/libz.so.1";
    deps.dependencies[0].out_of_package_search_path =
        "/home/someone/build/stale/lib/libz.so.1";

    const BuildReport r =
        assemble_report(std::move(deps), RuntimeProfile::CorePortable);

    const std::string text = render_build_report_text(r);
    CHECK(has(text, "/home/someone/build/stale/lib/libz.so.1"));
    CHECK(has(text, "outside the package"));
    // And it must reach the machine-readable surface too, or a publisher's gate
    // cannot act on it.
    const nlohmann::ordered_json j = build_report_json(r);
    CHECK(j.at("dependencies").at(0).at("outOfPackageSearchPath") ==
          "/home/someone/build/stale/lib/libz.so.1");
    // The ordinary case stays quiet rather than printing an empty note.
    CHECK_FALSE(has(render_build_report_text(assemble_report(
                        DependencyReport{}, RuntimeProfile::CorePortable)),
                    "outside the package"));
}

} // TEST_SUITE("buildreport")

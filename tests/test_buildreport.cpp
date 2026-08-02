// Build-report tests (Phase 2 / DX5): assembly + frontend-neutral rendering.

#include <doctest/doctest.h>

#include "core/buildreport.hpp"
#include "core/depengine.hpp"
#include "core/runtime_profile.hpp"

#include <string>

using namespace lexe;

namespace {

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

Dependency dep(const std::string& soname, DependencyKind kind,
               const std::string& sha = "") {
    Dependency d;
    d.soname = soname;
    d.kind = kind;
    d.sha256 = sha;
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
    CHECK(has(text, "Bundled libraries"));
    CHECK(has(text, "libfoo.so.1"));
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

} // TEST_SUITE("buildreport")

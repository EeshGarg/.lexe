// Runtime-profile tests (Phase 2 / DX2). The typed model + honest,
// dependency-aware assessment.

#include <doctest/doctest.h>

#include "core/depengine.hpp"
#include "core/error.hpp"
#include "core/runtime_profile.hpp"

#include <algorithm>
#include <string>

using namespace lexe;

namespace {

bool has_warning(const ProfileAssessment& a, const std::string& needle) {
    return std::any_of(a.warnings.begin(), a.warnings.end(),
                       [&](const std::string& w) {
                           return w.find(needle) != std::string::npos;
                       });
}

DependencyReport report_with(std::vector<Dependency> deps,
                             const std::string& glibc = "") {
    DependencyReport r;
    r.root_info.is_elf = true;
    r.dependencies = std::move(deps);
    if (!glibc.empty()) r.root_info.version_needs = {"GLIBC_" + glibc};
    return r;
}

Dependency dep(const std::string& soname, DependencyKind kind) {
    Dependency d;
    d.soname = soname;
    d.kind = kind;
    return d;
}

} // namespace

TEST_SUITE("runtime-profile") {

TEST_CASE("the model round-trips and Core Portable is the default") {
    CHECK(runtime_profile_from_string("core-portable") ==
          RuntimeProfile::CorePortable);
    CHECK(runtime_profile_from_string("native-capture") ==
          RuntimeProfile::NativeCapture);
    CHECK(std::string(to_string(RuntimeProfile::ForwardRuntime)) ==
          "forward-runtime");
    CHECK_THROWS_AS(runtime_profile_from_string("nonsense"), UsageError);

    CHECK(runtime_profiles().front().profile == RuntimeProfile::CorePortable);
    CHECK(runtime_profile_info(RuntimeProfile::CorePortable).is_default);
    CHECK(runtime_profile_info(RuntimeProfile::NativeCapture).reduced_portability);
    CHECK_FALSE(runtime_profile_info(RuntimeProfile::CorePortable)
                    .reduced_portability);
}

TEST_CASE("Core Portable claims portability only without unresolved deps") {
    const DependencyReport clean =
        report_with({dep("libc.so.6", DependencyKind::HostInterface),
                     dep("libfoo.so.1", DependencyKind::Bundle)});
    const ProfileAssessment a =
        assess_profile(RuntimeProfile::CorePortable, clean);
    CHECK(a.claims_portability);
    CHECK(a.will_bundle == 1);
    CHECK(a.host_provided == 1);

    const DependencyReport missing =
        report_with({dep("libmissing.so.9", DependencyKind::Unresolved)});
    const ProfileAssessment b =
        assess_profile(RuntimeProfile::CorePortable, missing);
    CHECK_FALSE(b.claims_portability);
    CHECK(has_warning(b, "could not be resolved"));
}

TEST_CASE("Native Capture is always flagged as reduced portability") {
    const DependencyReport clean =
        report_with({dep("libfoo.so.1", DependencyKind::Bundle)});
    const ProfileAssessment a =
        assess_profile(RuntimeProfile::NativeCapture, clean);
    CHECK_FALSE(a.claims_portability); // never claims broad portability
    CHECK(has_warning(a, "REDUCED portability"));
}

TEST_CASE("Forward Runtime warns when the app raises the runtime floor") {
    // A newer glibc requirement than the broadly-available floor.
    const DependencyReport newer =
        report_with({dep("libfoo.so.1", DependencyKind::Bundle)}, "2.38");
    const ProfileAssessment a =
        assess_profile(RuntimeProfile::ForwardRuntime, newer);
    CHECK(has_warning(a, "raises the minimum runtime"));
    CHECK(has_warning(a, "2.38"));

    // A requirement within the floor does not warn.
    const DependencyReport old =
        report_with({dep("libfoo.so.1", DependencyKind::Bundle)}, "2.17");
    const ProfileAssessment b =
        assess_profile(RuntimeProfile::ForwardRuntime, old);
    CHECK_FALSE(has_warning(b, "raises the minimum runtime"));
}

TEST_CASE("a forbidden host driver interface limits portability under any profile") {
    const DependencyReport gpu =
        report_with({dep("libGL.so.1", DependencyKind::Forbidden)});
    const ProfileAssessment a =
        assess_profile(RuntimeProfile::CorePortable, gpu);
    CHECK(has_warning(a, "driver passthrough"));
}

} // TEST_SUITE("runtime-profile")

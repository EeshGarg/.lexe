// Compatibility-analysis tests (Phase 2 / DX4).

#include <doctest/doctest.h>

#include "core/compat.hpp"
#include "core/depengine.hpp"

#include <algorithm>
#include <string>

using namespace lexe;

namespace {

Dependency dep(const std::string& soname, DependencyKind kind) {
    Dependency d;
    d.soname = soname;
    d.kind = kind;
    return d;
}

DependencyReport make_report(std::vector<Dependency> deps,
                             const std::string& glibc = "") {
    DependencyReport r;
    r.root_info.is_elf = true;
    r.dependencies = std::move(deps);
    if (!glibc.empty()) r.root_info.version_needs = {"GLIBC_" + glibc};
    return r;
}

bool has_warning(const CompatibilityReport& r, const std::string& title) {
    return std::any_of(r.warnings.begin(), r.warnings.end(),
                       [&](const CompatWarning& w) { return w.title == title; });
}

const TargetCompat* target(const CompatibilityReport& r, const std::string& id) {
    for (const TargetCompat& t : r.targets) {
        if (t.target.id == id) return &t;
    }
    return nullptr;
}

} // namespace

TEST_SUITE("compat") {

TEST_CASE("a clean, modestly-versioned app is compatible everywhere") {
    const CompatibilityReport r = analyze_compatibility(make_report(
        {dep("libc.so.6", DependencyKind::HostInterface),
         dep("libfoo.so.1", DependencyKind::Bundle)},
        "2.17"));
    CHECK(r.all_compatible());
    CHECK_FALSE(r.any_incompatible());
    CHECK(r.warnings.empty());
    // Every known runtime is represented.
    CHECK(r.targets.size() == known_runtime_targets().size());
    CHECK(target(r, "ubuntu-runtime")->level == CompatLevel::Compatible);
}

TEST_CASE("a newer glibc makes older runtimes incompatible and explains why") {
    const CompatibilityReport r = analyze_compatibility(make_report(
        {dep("libc.so.6", DependencyKind::HostInterface)}, "2.38"));
    // Ubuntu (2.35 baseline) can't run a 2.38 requirement; UshaOS Core (2.38) can.
    CHECK(target(r, "ubuntu-runtime")->level == CompatLevel::Incompatible);
    CHECK(target(r, "ushaos-core")->level == CompatLevel::Compatible);
    CHECK(has_warning(r, "Uses newer glibc symbols"));
    // The explanation is more than a bare title.
    for (const CompatWarning& w : r.warnings) {
        if (w.title == "Uses newer glibc symbols") {
            CHECK(w.explanation.find("2.38") != std::string::npos);
        }
    }
}

TEST_CASE("unresolved dependencies make every target incompatible") {
    const CompatibilityReport r = analyze_compatibility(
        make_report({dep("libmystery.so.9", DependencyKind::Unresolved)}));
    CHECK(r.any_incompatible());
    for (const TargetCompat& t : r.targets) {
        CHECK(t.level == CompatLevel::Incompatible);
    }
    CHECK(has_warning(r, "Unknown dependency"));
}

TEST_CASE("a forbidden GPU interface is a warning, explained") {
    const CompatibilityReport r = analyze_compatibility(
        make_report({dep("libGL.so.1", DependencyKind::Forbidden)}, "2.17"));
    CHECK(target(r, "ubuntu-runtime")->level == CompatLevel::Warning);
    CHECK(has_warning(r, "Requires GPU driver passthrough"));
}

TEST_CASE("bundling a host-typical library is called out as unusual") {
    const CompatibilityReport r = analyze_compatibility(make_report(
        {dep("libstdc++.so.6", DependencyKind::Bundle)}, "2.17"));
    CHECK(has_warning(r, "Bundles unusual libraries"));
}

} // TEST_SUITE("compat")

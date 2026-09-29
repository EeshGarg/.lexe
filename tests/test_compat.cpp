// Compatibility-analysis tests (Phase 2 / DX4).

#include <doctest/doctest.h>

#include "lexe/runtime/compat.hpp"
#include "lexe/analysis/depengine.hpp"

#include <algorithm>
#include <string>
#include <vector>

using namespace lexe;

namespace {

// `origin` is stated at every call site that cares. It is NOT inferable from
// `kind`: DependencyKind::Bundle is a recommendation that the library be
// carried, DependencyOrigin::Payload is the finding that it already is.
Dependency dep(const std::string& soname, DependencyKind kind,
               DependencyOrigin origin = DependencyOrigin::Payload) {
    Dependency d;
    d.soname = soname;
    d.kind = kind;
    d.origin = origin;
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

std::string warning_text(const CompatibilityReport& r, const std::string& title) {
    for (const CompatWarning& w : r.warnings) {
        if (w.title == title) return w.explanation;
    }
    return {};
}

std::vector<std::string> warning_titles(const CompatibilityReport& r) {
    std::vector<std::string> t;
    for (const CompatWarning& w : r.warnings) t.push_back(w.title);
    return t;
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
    const CompatibilityReport r = analyze_compatibility(
        make_report({dep("libstdc++.so.6", DependencyKind::Bundle,
                         DependencyOrigin::Payload)},
                    "2.17"));
    CHECK(has_warning(r, "Bundles unusual libraries"));
}

TEST_CASE("a package that carries a host-typical library and one that is merely "
          "advised to are not told the same thing") {
    // Measured, not supposed. A four-line program linked against -lz, packaged
    // with `payload/bin/zmin` as its ONLY file, produced these two lines from
    // one `lexe analyze` run, adjacent, in that order:
    //
    //     - libz.so.1  sha256:86200da3…  [found on this host, NOT in the package]
    //   ! Bundles unusual libraries: Bundling libraries usually provided by the
    //     host (libz.so.1) improves portability but pins their versions; ...
    //
    // The first line is right and the second is false: nothing was bundled. The
    // warning was keyed on DependencyKind::Bundle -- a RECOMMENDATION that the
    // library be carried (DEPENDENCY_ENGINE.md) -- rather than on
    // DependencyOrigin::Payload, the finding that it actually is. A control run
    // with `payload/lib/libz.so.1` genuinely present flipped the first line to
    // "[in the package]" and left the warning BYTE-IDENTICAL, so no reader of
    // the warning could tell the two packages apart.
    //
    // Both cases are asserted in one test deliberately: a test that only pinned
    // the not-carried case would pass just as well for code that never warns
    // about anything at all.
    const CompatibilityReport advised = analyze_compatibility(make_report(
        {dep("libz.so.1", DependencyKind::Bundle, DependencyOrigin::System)},
        "2.17"));
    const CompatibilityReport carried = analyze_compatibility(make_report(
        {dep("libz.so.1", DependencyKind::Bundle, DependencyOrigin::Payload)},
        "2.17"));

    // The whole defect in one line: these two situations must not read alike.
    CHECK(warning_titles(advised) != warning_titles(carried));

    // The present-tense claim belongs only to the package that really carries it.
    CHECK(has_warning(carried, "Bundles unusual libraries"));
    CHECK_FALSE(has_warning(advised, "Bundles unusual libraries"));

    // The advice is still worth giving -- in words that are true of a package
    // which does not carry the library yet.
    CHECK(has_warning(advised, "Advised to bundle host-provided libraries"));
    CHECK_FALSE(has_warning(carried, "Advised to bundle host-provided libraries"));

    // Both name the library, and the advisory one says outright that it is not
    // there, so the sentence cannot be misread as a finding about the package.
    CHECK(warning_text(carried, "Bundles unusual libraries")
              .find("libz.so.1") != std::string::npos);
    const std::string advice =
        warning_text(advised, "Advised to bundle host-provided libraries");
    CHECK(advice.find("libz.so.1") != std::string::npos);
    CHECK(advice.find("not in the package") != std::string::npos);
}

TEST_CASE("a library resolved only outside the package is not called bundled") {
    // DependencyOrigin::Elsewhere means the soname was satisfied through an
    // rpath pointing outside both the package and the system directories. That
    // is even further from "the package carries it" than System is, and a
    // sandboxed launch will not have the path at all.
    const CompatibilityReport r = analyze_compatibility(make_report(
        {dep("libz.so.1", DependencyKind::Bundle, DependencyOrigin::Elsewhere)},
        "2.17"));
    CHECK_FALSE(has_warning(r, "Bundles unusual libraries"));
    CHECK(has_warning(r, "Advised to bundle host-provided libraries"));
}

} // TEST_SUITE("compat")

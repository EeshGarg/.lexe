// compat — see compat.hpp. Explained, dependency-driven compatibility analysis.

#include "core/compat.hpp"

#include "core/runtime_profile.hpp"

#include <algorithm>
#include <array>
#include <set>
#include <string_view>
#include <utility>

namespace lexe {

const char* to_string(CompatLevel l) {
    switch (l) {
    case CompatLevel::Compatible:   return "compatible";
    case CompatLevel::Warning:      return "warning";
    case CompatLevel::Incompatible: return "incompatible";
    }
    return "warning";
}

const std::vector<RuntimeTarget>& known_runtime_targets() {
    // Coarse, documented glibc baselines (approximate current stable releases).
    static const std::vector<RuntimeTarget> kTargets = {
        {"ushaos-core", "UshaOS Core", 2, 38},
        {"fedora-runtime", "Fedora Runtime", 2, 38},
        {"debian-runtime", "Debian Runtime", 2, 36},
        {"ubuntu-runtime", "Ubuntu Runtime", 2, 35},
    };
    return kTargets;
}

bool CompatibilityReport::any_incompatible() const {
    return std::any_of(targets.begin(), targets.end(), [](const TargetCompat& t) {
        return t.level == CompatLevel::Incompatible;
    });
}
bool CompatibilityReport::all_compatible() const {
    return std::all_of(targets.begin(), targets.end(), [](const TargetCompat& t) {
        return t.level == CompatLevel::Compatible;
    });
}

namespace {

// Parse "2.38" into (major, minor); returns false when absent/unparseable.
bool parse_glibc(const std::string& v, int& major, int& minor) {
    const std::size_t dot = v.find('.');
    if (dot == std::string::npos) return false;
    try {
        major = std::stoi(v.substr(0, dot));
        minor = std::stoi(v.substr(dot + 1));
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// Libraries usually provided by the host: bundling them is legitimate for
// portability but pins their version, so it is worth explaining.
bool commonly_host_provided(const std::string& soname) {
    static const std::array<std::string_view, 8> kPrefixes = {
        "libstdc++.so", "libssl.so",  "libcrypto.so", "libz.so",
        "libX11.so",    "libcurl.so", "libsqlite3.so","libglib-2.0.so",
    };
    for (const std::string_view& p : kPrefixes) {
        if (soname.rfind(std::string(p), 0) == 0) return true;
    }
    return false;
}

} // namespace

CompatibilityReport analyze_compatibility(const DependencyReport& deps) {
    CompatibilityReport rep;
    rep.glibc_requirement = deps.max_glibc_version();

    const std::size_t unresolved = deps.count(DependencyKind::Unresolved);
    const std::size_t forbidden = deps.count(DependencyKind::Forbidden);
    int req_major = 0, req_minor = 0;
    const bool have_glibc =
        parse_glibc(rep.glibc_requirement, req_major, req_minor);

    // Per-target verdicts.
    for (const RuntimeTarget& t : known_runtime_targets()) {
        TargetCompat tc;
        tc.target = t;
        if (unresolved > 0) {
            tc.level = CompatLevel::Incompatible;
            tc.detail = "cannot be guaranteed: " + std::to_string(unresolved) +
                        " dependency(ies) are unresolved.";
        } else if (have_glibc && (req_major > t.glibc_major ||
                                  (req_major == t.glibc_major &&
                                   req_minor > t.glibc_minor))) {
            tc.level = CompatLevel::Incompatible;
            tc.detail = "needs glibc " + rep.glibc_requirement +
                        ", newer than this runtime's " +
                        std::to_string(t.glibc_major) + "." +
                        std::to_string(t.glibc_minor) + " baseline.";
        } else if (forbidden > 0) {
            tc.level = CompatLevel::Warning;
            tc.detail = "runs where the host provides the required driver/GPU "
                        "interface(s); otherwise it will not start.";
        } else {
            tc.level = CompatLevel::Compatible;
            tc.detail = "all requirements are within this runtime's baseline.";
        }
        rep.targets.push_back(std::move(tc));
    }

    // Cross-cutting, explained warnings.
    if (have_glibc && (req_major > kBroadGlibcMajor ||
                       (req_major == kBroadGlibcMajor &&
                        req_minor > kBroadGlibcMinor))) {
        rep.warnings.push_back(
            {"Uses newer glibc symbols",
             "The application requires glibc " + rep.glibc_requirement +
                 ", newer than the broadly-available " +
                 std::to_string(kBroadGlibcMajor) + "." +
                 std::to_string(kBroadGlibcMinor) +
                 " floor. It will not run on older runtimes. Build against an "
                 "older toolchain to widen compatibility, or target a "
                 "Forward Runtime profile deliberately."});
    }
    if (forbidden > 0) {
        std::string list;
        for (const Dependency* d : deps.of_kind(DependencyKind::Forbidden)) {
            if (!list.empty()) list += ", ";
            list += d->soname;
        }
        rep.warnings.push_back(
            {"Requires GPU driver passthrough",
             "Needs host driver/GPU interface(s) (" + list +
                 "). These must come from the target host and cannot be "
                 "bundled; the package will not start where they are absent."});
    }
    if (unresolved > 0) {
        std::string list;
        for (const Dependency* d : deps.of_kind(DependencyKind::Unresolved)) {
            if (!list.empty()) list += ", ";
            list += d->soname;
        }
        rep.warnings.push_back(
            {"Unknown dependency",
             "Could not resolve " + list +
                 ". Add the library to the payload, or confirm every target "
                 "host provides it; until then compatibility cannot be assured."});
    }
    // Unusual bundles: host-typical libraries carried in the payload.
    std::set<std::string> unusual;
    for (const Dependency* d : deps.of_kind(DependencyKind::Bundle)) {
        if (commonly_host_provided(d->soname)) unusual.insert(d->soname);
    }
    if (!unusual.empty()) {
        std::string list;
        for (const std::string& s : unusual) {
            if (!list.empty()) list += ", ";
            list += s;
        }
        rep.warnings.push_back(
            {"Bundles unusual libraries",
             "Bundling libraries usually provided by the host (" + list +
                 ") improves portability but pins their versions; keep them "
                 "updated for security fixes."});
    }
    return rep;
}

} // namespace lexe

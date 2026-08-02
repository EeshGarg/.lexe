// runtime_profile — see runtime_profile.hpp. The typed model + honest,
// dependency-aware assessment. Pure, no I/O.

#include "core/runtime_profile.hpp"

#include "core/error.hpp"

namespace lexe {

const char* to_string(RuntimeProfile p) {
    switch (p) {
    case RuntimeProfile::CorePortable:   return "core-portable";
    case RuntimeProfile::ForwardRuntime: return "forward-runtime";
    case RuntimeProfile::NativeCapture:  return "native-capture";
    }
    return "core-portable";
}

RuntimeProfile runtime_profile_from_string(std::string_view id) {
    if (id == "core-portable") return RuntimeProfile::CorePortable;
    if (id == "forward-runtime") return RuntimeProfile::ForwardRuntime;
    if (id == "native-capture") return RuntimeProfile::NativeCapture;
    throw UsageError("unknown runtime profile: \"" + std::string(id) +
                     "\" (expected core-portable, forward-runtime or "
                     "native-capture)");
}

const std::vector<RuntimeProfileInfo>& runtime_profiles() {
    static const std::vector<RuntimeProfileInfo> kProfiles = {
        {RuntimeProfile::CorePortable, "core-portable", "Core Portable",
         "Maximum",
         "Bundle everything except the host interface; runs on any conforming "
         "runtime.",
         "The default. The application ships every non-system library it needs "
         "and relies only on the core host interface (glibc, the loader, the "
         "kernel). It aims to run unchanged on every conforming .lexe runtime.",
         /*reduced=*/false, /*is_default=*/true},
        {RuntimeProfile::ForwardRuntime, "forward-runtime", "Forward Runtime",
         "Forward-compatible",
         "Like Core Portable, but targets a forward-compatible runtime and warns "
         "when the app raises the minimum runtime.",
         "Bundles like Core Portable, but is explicit that it may require a "
         "newer runtime baseline. When the application uses newer system symbols "
         "(e.g. a newer glibc), that raised requirement is called out rather "
         "than hidden.",
         /*reduced=*/false, /*is_default=*/false},
        {RuntimeProfile::NativeCapture, "native-capture", "Native Capture",
         "Reduced",
         "Capture host libraries for this build's host — reduced portability.",
         "Captures libraries from the build host so the package is "
         "self-contained for hosts that match this build. This trades "
         "portability for fidelity and is clearly labelled as REDUCED "
         "portability — it is not a universal package.",
         /*reduced=*/true, /*is_default=*/false},
    };
    return kProfiles;
}

const RuntimeProfileInfo& runtime_profile_info(RuntimeProfile p) {
    for (const RuntimeProfileInfo& info : runtime_profiles()) {
        if (info.profile == p) return info;
    }
    return runtime_profiles().front();
}

ProfileAssessment assess_profile(RuntimeProfile profile,
                                 const DependencyReport& report) {
    ProfileAssessment a;
    a.profile = profile;
    a.will_bundle = report.count(DependencyKind::Bundle);
    a.host_provided = report.count(DependencyKind::HostInterface);

    const std::size_t unresolved = report.count(DependencyKind::Unresolved);
    const std::size_t forbidden = report.count(DependencyKind::Forbidden);
    const std::string glibc = report.max_glibc_version();

    // Requirements that limit portability under ANY profile.
    if (unresolved > 0) {
        a.warnings.push_back(
            std::to_string(unresolved) +
            " dependency(ies) could not be resolved; the target host must "
            "provide them or they must be added to the payload.");
    }
    if (forbidden > 0) {
        a.warnings.push_back(
            std::to_string(forbidden) +
            " host driver/GPU interface(s) are required; the package needs host "
            "driver passthrough and will not run where that is unavailable.");
    }

    switch (profile) {
    case RuntimeProfile::CorePortable:
        a.claims_portability = (unresolved == 0);
        a.notes.push_back("Bundles " + std::to_string(a.will_bundle) +
                          " library(ies); relies on the host interface for " +
                          std::to_string(a.host_provided) + ".");
        if (!glibc.empty()) {
            a.notes.push_back("Requires a host glibc of at least " + glibc + ".");
        }
        break;
    case RuntimeProfile::ForwardRuntime: {
        a.claims_portability = (unresolved == 0);
        bool raised = false;
        if (!glibc.empty()) {
            const std::size_t dot = glibc.find('.');
            if (dot != std::string::npos) {
                try {
                    const int major = std::stoi(glibc.substr(0, dot));
                    const int minor = std::stoi(glibc.substr(dot + 1));
                    if (major > kBroadGlibcMajor ||
                        (major == kBroadGlibcMajor && minor > kBroadGlibcMinor)) {
                        raised = true;
                    }
                } catch (const std::exception&) {
                }
            }
        }
        if (raised) {
            a.warnings.push_back(
                "This build raises the minimum runtime: it needs glibc " + glibc +
                ", newer than the broadly-available " +
                std::to_string(kBroadGlibcMajor) + "." +
                std::to_string(kBroadGlibcMinor) +
                " floor. Older runtimes will not run it.");
        } else {
            a.notes.push_back(
                "No requirement newer than the broadly-available runtime floor.");
        }
        break;
    }
    case RuntimeProfile::NativeCapture:
        // Reduced portability is inherent — never claim broad portability.
        a.claims_portability = false;
        a.warnings.push_back(
            "Native Capture has REDUCED portability: it captures host libraries "
            "and is intended for hosts matching this build, not universal use.");
        break;
    }
    return a;
}

} // namespace lexe

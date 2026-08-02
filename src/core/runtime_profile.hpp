#pragma once
// runtime_profile — the runtime-profile model (Phase 2 / DX2, Tux32 groundwork).
// A runtime profile is the portability contract a package targets. This phase
// builds the INFRASTRUCTURE (the typed model + honest assessment) rather than
// the full Tux32 specification — see docs/RUNTIME_PROFILES.md and docs/TUX32.md.
//
//   Core Portable   — bundle everything except the host interface; runs on any
//                     conforming runtime. The builder default. Maximum portability.
//   Forward Runtime — like Core Portable, but targets a forward-compatible
//                     runtime baseline and WARNS when the app raises the minimum
//                     runtime requirement (e.g. a newer glibc).
//   Native Capture  — capture host libraries for this build's host. Clearly
//                     REDUCED portability; never presented as universal.
//
// No profile silently claims portability: assess_profile() surfaces the honest
// warnings for a given dependency graph.

#include "core/depengine.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace lexe {

enum class RuntimeProfile {
    CorePortable,
    ForwardRuntime,
    NativeCapture,
};

const char* to_string(RuntimeProfile p);         // stable id, e.g. "core-portable"
RuntimeProfile runtime_profile_from_string(std::string_view id); // throws on bad id

/// Static description of a profile (for UI + docs; frontend-neutral).
struct RuntimeProfileInfo {
    RuntimeProfile profile = RuntimeProfile::CorePortable;
    std::string id;                 // "core-portable"
    std::string name;               // "Core Portable"
    std::string portability;        // "Maximum" / "Forward-compatible" / "Reduced"
    std::string summary;            // one line
    std::string description;        // a short paragraph
    bool reduced_portability = false; // true only for Native Capture
    bool is_default = false;          // Core Portable
};

const RuntimeProfileInfo& runtime_profile_info(RuntimeProfile p);
/// All profiles in presentation order (Core Portable first).
const std::vector<RuntimeProfileInfo>& runtime_profiles();

/// A conservative, broadly-available glibc floor. A requirement above this
/// raises the minimum runtime and is called out by Forward Runtime.
inline constexpr int kBroadGlibcMajor = 2;
inline constexpr int kBroadGlibcMinor = 31; // ~Debian 11 / Ubuntu 20.04 era

/// An honest, profile-specific assessment of a dependency graph.
struct ProfileAssessment {
    RuntimeProfile profile = RuntimeProfile::CorePortable;
    /// Whether this profile can honestly claim broad portability for THIS app.
    bool claims_portability = false;
    /// The bundle/host split the profile implies (counts, for the UI).
    std::size_t will_bundle = 0;      // deps this profile bundles
    std::size_t host_provided = 0;    // deps left to the host interface
    std::vector<std::string> warnings; // reasons portability is limited
    std::vector<std::string> notes;    // neutral, informational
};

/// Assess `report` under `profile`. Never overstates portability: unresolved and
/// forbidden dependencies always limit it, Native Capture is always flagged as
/// reduced, and Forward Runtime warns on a raised runtime floor.
ProfileAssessment assess_profile(RuntimeProfile profile,
                                 const DependencyReport& report);

} // namespace lexe

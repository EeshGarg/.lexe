#pragma once
// tux32 — the concrete, versioned Tux32 runtime baseline (portability milestone).
// A Tux32 profile is the stable ABI contract a Core Portable package targets: a
// package may claim conformance ONLY when its executable and bundled dependency
// closure satisfy the profile's published rules. The build host must never
// silently become the compatibility target.
//
// The profile is COMPILED into the runtime (authoritative, deterministic, not
// editable by package content, never fetched from the network). A checked-in
// machine-readable mirror lives at sdk/tux32-core-1/profile.json and is pinned
// to this compiled definition by a test, so the two can never drift.
//
// Core 1 is deliberately narrow: dynamically linked ELF, x86-64 only, glibc
// symbol-version ceiling 2.31 (see docs/TUX32.md for the justification).

#include "core/depengine.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace lexe {

/// A machine-consumable runtime baseline. The enforced fields (executable
/// format, architectures, CPU baseline, glibc ceiling) drive verification; the
/// descriptive fields document the rest of the contract.
struct Tux32Profile {
    // identity
    std::string id;               // "tux32-core-1"
    std::string spec_version;     // "1"

    // enforced ABI contract
    std::string executable_format;           // "elf-dynamic"
    std::vector<std::string> architectures;  // Core 1: {"x86_64"}
    std::string cpu_baseline;                // "x86-64-v1"
    int glibc_major = 2;                     // symbol-version ceiling …
    int glibc_minor = 31;                    // … (major.minor)

    // descriptive contract (documented, not independently machine-enforced
    // beyond what the dependency engine's classification already encodes)
    std::string dynamic_linking;  // the loader / libc model
    std::string kernel_baseline;  // minimum kernel assumptions
    std::string host_provided;    // classes provided by every conforming host
    std::string must_bundle;      // classes the package must carry
    std::string forbidden;        // classes that must NOT be bundled
    std::string filesystem;       // filesystem contract
    std::string environment;      // environment contract
    std::string isolation;        // isolation requirements
    std::string graphics;         // graphics/desktop limitations
    std::string network;          // network permission semantics
    std::string data_paths;       // data / cache / temp semantics
    std::string claim_language;   // the exact portability-claim wording
    std::string conformance;      // what a conforming runtime must satisfy

    /// "2.31".
    std::string glibc_ceiling() const;
    /// True when `arch` (a §5 architecture id) is in this profile.
    bool supports_arch(const std::string& arch) const;
    /// True when (major, minor) is at or below this profile's glibc ceiling.
    bool within_glibc_ceiling(int major, int minor) const;
};

/// The authoritative, compiled Tux32 Core 1 profile.
const Tux32Profile& tux32_core_1();

/// Parse a profile.json strictly (duplicate-key rejection, bounded, canonical
/// fields). Throws VerificationError on any malformed/invalid input. Used by the
/// SDK tooling and by the test that pins profile.json to tux32_core_1().
Tux32Profile parse_profile_json(std::string_view text);

/// Parse "2.31" into (major, minor); returns false when absent/unparseable.
bool parse_glibc_version(const std::string& v, int& major, int& minor);

// ------------------------------------------------------- SDK verification

/// The typed verdict of verifying an application against a Tux32 profile.
/// Automation must switch on this, never on message text.
enum class Core1Verdict {
    Conformant,               // satisfies every Core 1 rule
    ConformantWithNotes,      // conformant, but with advisory notes
    SymbolCeilingExceeded,    // requires a glibc symbol newer than the ceiling
    UnresolvedDependency,     // a DT_NEEDED soname could not be found
    ForbiddenDependency,      // needs a host driver/GPU interface (not bundlable)
    UnsupportedArchitecture,  // the executable's arch is not in the profile
    UnsupportedExecutable,    // not a dynamically linked ELF (Core 1 requires it)
    InvalidInput,             // the target is not an analyzable ELF binary
    IncompleteClosure,        // the dependency closure could not be completed
};
const char* to_string(Core1Verdict v);

/// The exact object + version that pushed a requirement above the ceiling.
struct Core1Offender {
    std::string object;   // the executable's filename, or a bundled soname
    std::string version;  // e.g. "GLIBC_2.34"
};

/// A complete, typed Core 1 verification result.
struct Core1VerifyResult {
    std::string profile_id;
    std::string profile_version;
    Core1Verdict verdict = Core1Verdict::InvalidInput;

    std::string selected_executable;  // the analyzed binary
    std::string architecture;         // the executable's arch ("x86_64" / …)
    std::string cpu_baseline;         // the profile's CPU baseline
    std::string glibc_ceiling;        // the profile's ceiling ("2.31")
    std::string required_glibc;       // the package's highest glibc need ("" none)

    std::vector<Core1Offender> symbol_offenders; // objects above the ceiling
    std::vector<std::string> bundle_candidates;  // sonames to bundle
    std::vector<std::string> host_interfaces;    // approved host sonames
    std::vector<std::string> forbidden;          // forbidden sonames
    std::vector<std::string> unresolved;         // unresolved sonames
    std::vector<std::string> notes;              // advisory notes / guidance
    std::string detail;                          // one-line human summary

    bool conformant() const {
        return verdict == Core1Verdict::Conformant ||
               verdict == Core1Verdict::ConformantWithNotes;
    }
};

/// Verify a dependency report against a Tux32 profile. Reuses the dependency
/// engine's already-computed graph — it does NOT re-analyze. Considers the
/// PACKAGE's requirement (the executable + bundled libraries) against the glibc
/// ceiling; host-interface libraries are supplied by the host and not counted.
Core1VerifyResult verify_against_profile(const DependencyReport& deps,
                                         const Tux32Profile& profile);

} // namespace lexe

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

} // namespace lexe

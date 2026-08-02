#pragma once
// compat — compatibility analysis (Phase 2 / DX4). Turns a dependency graph
// into a human-readable compatibility report: which known target runtimes the
// package should run on, and WHY any of them are a warning or incompatible. The
// report explains issues (newer glibc symbols, host driver passthrough, unusual
// bundles, unknown dependencies) rather than merely listing them.

#include "core/depengine.hpp"

#include <string>
#include <vector>

namespace lexe {

/// A known target runtime with the glibc floor it guarantees. These are coarse,
/// documented baselines — not a live probe of any specific host.
struct RuntimeTarget {
    std::string id;    // "ubuntu-runtime"
    std::string name;  // "Ubuntu Runtime"
    int glibc_major = 2;
    int glibc_minor = 31;
};

const std::vector<RuntimeTarget>& known_runtime_targets();

enum class CompatLevel { Compatible, Warning, Incompatible };
const char* to_string(CompatLevel l);

/// Compatibility with one target runtime, with an explanation.
struct TargetCompat {
    RuntimeTarget target;
    CompatLevel level = CompatLevel::Compatible;
    std::string detail;
};

/// A cross-cutting warning that explains an issue and how to think about it.
struct CompatWarning {
    std::string title;       // short label, e.g. "Uses newer glibc symbols"
    std::string explanation; // why it matters + guidance
};

struct CompatibilityReport {
    std::vector<TargetCompat> targets;   // one per known runtime
    std::vector<CompatWarning> warnings; // explained issues (may be empty)
    std::string glibc_requirement;       // e.g. "2.38", or "" when none

    /// True when no target is Incompatible.
    bool any_incompatible() const;
    bool all_compatible() const;
};

/// Analyze compatibility from a dependency report. Pure.
CompatibilityReport analyze_compatibility(const DependencyReport& deps);

} // namespace lexe

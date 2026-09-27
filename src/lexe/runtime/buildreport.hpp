#pragma once
// buildreport — the build/analysis summary (Phase 2 / DX5). One frontend-neutral
// structure that gathers everything a developer wants after analyzing or
// building an application: identity, architectures, the dependency breakdown,
// the target runtime profile, permissions, signing, output package, and the
// compatibility summary. The CLI `lexe analyze` and the builder's final report
// screen both render this same structure.

#include "lexe/runtime/compat.hpp"
#include "lexe/analysis/depengine.hpp"
#include "lexe/runtime/runtime_profile.hpp"
#include "lexe/analysis/tux32.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace lexe {

struct BuildReport {
    // --- identity (optional; empty for a bare-binary analysis) ---
    std::string app_name;
    std::string app_id;
    std::string app_version;
    std::vector<std::string> architectures;
    std::vector<std::string> permissions;

    // --- signing (optional) ---
    std::string signing_fingerprint; // grouped fingerprint, "" if none

    // --- analysis ---
    RuntimeProfile profile = RuntimeProfile::CorePortable;
    DependencyReport dependencies;
    ProfileAssessment profile_assessment;
    CompatibilityReport compatibility;
    // Tux32 Core 1 verification — populated ONLY when the target profile is Core
    // Portable (the profile that makes a cross-distribution portability claim).
    // Its typed verdict is the authoritative gate for that claim.
    std::optional<Core1VerifyResult> core1;

    /// Sonames the DYNAMIC LOADER could not reach — the answer to "will this
    /// start", as against `dependencies`, which answers "what does this need and
    /// where would it come from".
    ///
    /// Separate because the two questions have different answers for the same
    /// bytes, and reporting only the first one made this the pre-ship check that
    /// says "fine" about a package that cannot start. The advisory analysis
    /// searches the payload directly; the loader cannot, reaching it only
    /// through an `$ORIGIN`-relative rpath. So a package with its libraries in
    /// `payload/lib/` and nothing pointing there resolves cleanly here and dies
    /// at exec with 127 and nothing on either stream.
    ///
    /// Filled by whoever ran the contract analysis (DependencyOptions::
    /// runtime_contract). Empty means either "nothing unreachable" or "not
    /// asked" — `runtime_contract_checked` distinguishes them, because "we did
    /// not look" must never render as "all clear".
    std::vector<std::string> runtime_unreachable;
    bool runtime_contract_checked = false;

    // --- output (optional; set after a real build) ---
    std::filesystem::path output_package;
    std::uint64_t output_size = 0;
    std::string output_sha256;
};

/// Build the analysis part of a report: run the profile assessment + the
/// compatibility analysis over `deps` for `profile`, and derive architectures
/// from the root's machine. Identity/signing/output are filled by the caller.
BuildReport assemble_report(DependencyReport deps, RuntimeProfile profile);

/// A frontend-neutral, human-readable rendering (used by CLI + GUI).
std::string render_build_report_text(const BuildReport& r);

/// A structured rendering for `--json` output.
nlohmann::ordered_json build_report_json(const BuildReport& r);

} // namespace lexe

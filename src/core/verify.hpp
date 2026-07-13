#pragma once
// verify — the normative verification pipeline of FORMAT-0.1 §6, in order:
//   1 "structure"           archive opens; §2 entry rules; required entries
//   2 "manifest"            lexe.json parses; §5 constraints hold
//   3 "key"                 publisher.publicKey decodes per §4
//   4 "manifest-signature"  manifest.sig over the exact lexe.json bytes
//   5 "payload-signature"   payload.sig over the exact hashes.json bytes
//   6 "hashes"              §3 set equality + per-entry SHA-256
//   7 "compatibility"       (install/update only) host arch ∈ architectures
// The report distinguishes every failed stage; the CLI exits 3 on failure.

#include "core/manifest.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace lexe {

/// Outcome of one pipeline stage. Stage names are listed above.
struct VerificationStage {
    std::string name;
    bool ok = false;
    std::string detail; // human-readable success/failure explanation
};

/// Ordered stage results. Stages after the first failure are not run and are
/// absent from `stages`.
struct VerificationReport {
    std::vector<VerificationStage> stages;

    bool ok() const {
        for (const auto& s : stages) {
            if (!s.ok) return false;
        }
        return !stages.empty();
    }

    /// First failed stage, or nullptr when all present stages passed.
    const VerificationStage* first_failure() const {
        for (const auto& s : stages) {
            if (!s.ok) return &s;
        }
        return nullptr;
    }
};

/// The runtime's host architecture string as used in manifests
/// ("x86_64" or "aarch64"; FORMAT-0.1 §5).
std::string host_architecture();

/// Run the §6 pipeline on a `.lexe` file. Stage 7 runs only when
/// `check_architecture` is true (install/update). Never throws for a failing
/// package — failures are reported in the returned report.
VerificationReport verify_package(const std::filesystem::path& lexe_file,
                                  bool check_architecture = false);

/// Convenience for install/update paths: run the pipeline and either return
/// the parsed manifest or throw VerificationError naming the failed stage.
Manifest verify_package_or_throw(const std::filesystem::path& lexe_file,
                                 bool check_architecture = false);

} // namespace lexe

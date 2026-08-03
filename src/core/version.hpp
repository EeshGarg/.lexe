#pragma once
// version — the single source of truth for the runtime's version identity and
// the DISTINCT version axes the platform exposes (Alpha stabilization). Do not
// scatter version literals through the code; reference these.
//
//   * runtime         — the `lexe` runtime + CLI build version, from CMake
//                       project(VERSION), qualified by the release stage. This
//                       is what `lexe --version` reports.
//   * package format  — the `.lexe` container/manifest format (FORMAT-0.1 §5,
//                       the manifest "lexeVersion"). Independent of the runtime
//                       version: the runtime may advance while the format holds.
//
// Both are deliberately separate from the Tux32 baseline id
// (tux32_core_1().id == "tux32-core-1", spec version "1"), which versions the
// portability contract — not the runtime and not the package format. Keeping the
// three axes distinct is an Alpha requirement.

#include <string>

namespace lexe::version {

#ifndef LEXE_VERSION
#define LEXE_VERSION "0.0.0-dev" // fallback when the build did not set it
#endif

/// The runtime/CLI version from CMake project(VERSION), e.g. "0.1.0".
inline constexpr const char* kRuntime = LEXE_VERSION;

/// The release stage: "alpha" for the Alpha candidate, "" once stabilized.
inline constexpr const char* kStage = "alpha";

/// The `.lexe` package/manifest format version (FORMAT-0.1 §5 "lexeVersion").
/// NOT the runtime version — the runtime evolves independently of the format.
inline constexpr const char* kPackageFormat = "0.1";

/// The full runtime version string: "0.1.0-alpha" (or just the version when the
/// stage is empty).
inline std::string runtime_string() {
    std::string v = kRuntime;
    if (kStage[0] != '\0') {
        v += "-";
        v += kStage;
    }
    return v;
}

} // namespace lexe::version

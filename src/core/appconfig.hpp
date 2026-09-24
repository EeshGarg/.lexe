#pragma once
// appconfig — per-application USER overrides (Definitive Architecture §10).
//
// The signed manifest says what the PUBLISHER permits; this file says what THIS
// machine or user prefers. The two are deliberately different objects in
// different places:
//
//   ~/.config/lexe/apps/<application-id>.json     <- this module (user, mutable)
//   ~/.local/share/lexe/apps/<id>/manifest.json   <- the signed manifest (immutable)
//
// Changing a compatibility preference therefore never modifies, re-signs or
// invalidates the installed package — which is the whole point of §10. An
// override can only ever NARROW or REORDER what the manifest already permits:
// resolve_chain() intersects the preference with the manifest policy, so a
// user preference can never grant an execution method the publisher forbade
// (and can never re-enable one for a mission-critical application).

#include "core/paths.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace lexe {

/// How the execution chain is chosen for one application (§8/§10).
enum class CompatibilityMode {
    Automatic, // .LEXE picks the best allowed chain (the default)
    Manual,    // use preferred_chain, in order, restricted to what is allowed
};
const char* to_string(CompatibilityMode m);
bool compatibility_mode_from_string(const std::string& text,
                                    CompatibilityMode& out);

/// The contents of `<config>/apps/<application-id>.json`. Every field is
/// optional with a safe default, so a missing file is exactly "no overrides".
struct AppConfig {
    std::string id;
    CompatibilityMode compatibility_mode = CompatibilityMode::Automatic;
    /// Preferred chain ids in order, e.g. {"proton", "box64"}. Only meaningful
    /// in Manual mode; always filtered against the manifest policy.
    std::vector<std::string> preferred_chain;

    /// The file this config lives in. Not created here.
    static std::filesystem::path file(const Paths& paths, const std::string& id);

    /// Load overrides for `id`. A missing file yields defaults. Throws Error
    /// only when the file exists but cannot be parsed (recover by resetting).
    static AppConfig load(const Paths& paths, const std::string& id);

    /// Persist atomically (temp file + rename). Creates the directory.
    void save(const Paths& paths) const;

    /// Remove the override file for `id` (no-op when absent).
    static void reset(const Paths& paths, const std::string& id);

    std::string to_json() const;
};

} // namespace lexe

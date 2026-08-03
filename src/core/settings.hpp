#pragma once
// settings — persisted, per-user runtime preferences (DX5). Stored strictly as
// `<home>/settings.json`. These are COSMETIC / workflow preferences only: no
// setting can weaken a security guarantee. Signature and payload verification,
// launch-time integrity checks, permission consent and fail-closed isolation are
// always enforced and are deliberately NOT settings.

#include "core/paths.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <string>
#include <vector>

namespace lexe {

/// A validated bundle of user preferences with safe defaults.
struct Settings {
    std::string theme = "system";        // GUI theme hint: system | light | dark
    std::string update_check = "manual"; // update cadence intent: manual | never
    bool developer_mode = false;         // surface extra developer-facing detail
    bool diagnostics = false;            // verbose diagnostic logging

    /// The settings file path (`<home>/settings.json`). Not created here.
    static std::filesystem::path file(const Paths& paths);

    /// Load settings for `paths`. A missing file yields defaults; unknown fields
    /// are ignored (forward-compatible). Throws Error only when the file exists
    /// but is corrupt/unparseable (recover with a reset).
    static Settings load(const Paths& paths);

    /// Persist atomically (temp file + rename).
    void save(const Paths& paths) const;

    /// The settable keys, in display order.
    static std::vector<std::string> keys();

    /// Read one key as a string. Throws Error on an unknown key.
    std::string get(const std::string& key) const;

    /// Set one key from a string value. Validates the key and value; throws
    /// Error (usage-style) on an unknown key or an invalid value.
    void set(const std::string& key, const std::string& value);

    /// Ordered JSON view (stable key order) for `--json` and persistence.
    nlohmann::ordered_json to_json() const;
};

} // namespace lexe

// appconfig — see appconfig.hpp (Definitive Architecture §10). Strict load,
// atomic save; a missing file is "no overrides", never an error.

#include "core/appconfig.hpp"

#include "core/error.hpp"
#include "core/json_strict.hpp"
#include "core/limits.hpp"
#include "core/registry.hpp"
#include "core/util.hpp"

#include <nlohmann/json.hpp>

#include <system_error>

namespace fs = std::filesystem;

namespace lexe {

const char* to_string(CompatibilityMode m) {
    switch (m) {
    case CompatibilityMode::Automatic: return "automatic";
    case CompatibilityMode::Manual: return "manual";
    }
    return "automatic";
}

bool compatibility_mode_from_string(const std::string& text,
                                    CompatibilityMode& out) {
    if (text == "automatic" || text == "auto") {
        out = CompatibilityMode::Automatic;
        return true;
    }
    if (text == "manual") {
        out = CompatibilityMode::Manual;
        return true;
    }
    return false;
}

fs::path AppConfig::file(const Paths& paths, const std::string& id) {
    // The id is a single path component only after validation (§5 shape).
    validate_app_id(id, "app config");
    return paths.apps_config_dir() / (id + ".json");
}

AppConfig AppConfig::load(const Paths& paths, const std::string& id) {
    AppConfig config;
    config.id = id;

    const fs::path path = file(paths, id);
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) return config; // no overrides

    const nlohmann::json doc = json_strict::parse(
        util::slurp_text(path), "application configuration",
        limits::kMaxManifestBytes);
    if (!doc.is_object()) {
        throw Error("application configuration is corrupt (not a JSON "
                    "object): " +
                    path.string() + " — run `lexe config app " + id +
                    " reset`");
    }

    const auto compatibility = doc.find("compatibility");
    if (compatibility != doc.end() && compatibility->is_object()) {
        if (const auto mode = compatibility->find("mode");
            mode != compatibility->end() && mode->is_string()) {
            const std::string text = mode->get<std::string>();
            if (!compatibility_mode_from_string(text,
                                                config.compatibility_mode)) {
                throw Error("invalid compatibility.mode \"" + text + "\" in " +
                            path.string() +
                            " (choose: automatic, manual)");
            }
        }
        if (const auto chain = compatibility->find("preferredChain");
            chain != compatibility->end() && chain->is_array()) {
            for (const nlohmann::json& element : *chain) {
                if (!element.is_string()) {
                    throw Error("compatibility.preferredChain must contain "
                                "only strings in " +
                                path.string());
                }
                config.preferred_chain.push_back(element.get<std::string>());
            }
        }
    }
    return config;
}

std::string AppConfig::to_json() const {
    nlohmann::ordered_json compatibility;
    compatibility["mode"] = to_string(compatibility_mode);
    compatibility["preferredChain"] = preferred_chain;

    nlohmann::ordered_json doc;
    doc["compatibility"] = std::move(compatibility);
    return doc.dump(2) + "\n";
}

void AppConfig::save(const Paths& paths) const {
    const fs::path path = file(paths, id);
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    util::write_atomic(path, to_json());
}

void AppConfig::reset(const Paths& paths, const std::string& id) {
    std::error_code ec;
    fs::remove(file(paths, id), ec); // absent is fine
}

} // namespace lexe

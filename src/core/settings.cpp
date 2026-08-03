// settings — see settings.hpp. Strict load, atomic save, validated set.

#include "core/settings.hpp"

#include "core/error.hpp"
#include "core/json_strict.hpp"
#include "core/limits.hpp"
#include "core/util.hpp"

#include <algorithm>
#include <cctype>
#include <system_error>

namespace lexe {

namespace fs = std::filesystem;

namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Parse a permissive boolean ("true/false", "1/0", "yes/no", "on/off").
bool parse_bool(const std::string& v, bool& out) {
    const std::string s = lower(v);
    if (s == "true" || s == "1" || s == "yes" || s == "on") { out = true; return true; }
    if (s == "false" || s == "0" || s == "no" || s == "off") { out = false; return true; }
    return false;
}

bool one_of(const std::string& v, std::initializer_list<const char*> allowed) {
    for (const char* a : allowed) if (v == a) return true;
    return false;
}

std::string key_list() {
    std::string out;
    for (const std::string& k : Settings::keys()) {
        if (!out.empty()) out += ", ";
        out += k;
    }
    return out;
}

} // namespace

fs::path Settings::file(const Paths& paths) {
    return paths.home() / "settings.json";
}

std::vector<std::string> Settings::keys() {
    return {"theme", "updateCheck", "developerMode", "diagnostics"};
}

Settings Settings::load(const Paths& paths) {
    const fs::path path = file(paths);
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) return Settings{}; // defaults

    Settings s;
    const nlohmann::json j = json_strict::parse(
        util::slurp_text(path), "settings", limits::kMaxManifestBytes);
    if (!j.is_object()) {
        throw Error("settings file is corrupt (not a JSON object): " +
                    path.string() + " — run `lexe config reset`");
    }
    const auto str = [&](const char* k, std::string& out) {
        if (auto it = j.find(k); it != j.end() && it->is_string()) {
            out = it->get<std::string>();
        }
    };
    const auto boolean = [&](const char* k, bool& out) {
        if (auto it = j.find(k); it != j.end() && it->is_boolean()) {
            out = it->get<bool>();
        }
    };
    str("theme", s.theme);
    str("updateCheck", s.update_check);
    boolean("developerMode", s.developer_mode);
    boolean("diagnostics", s.diagnostics);
    return s;
}

void Settings::save(const Paths& paths) const {
    util::write_atomic(file(paths), to_json().dump(2) + "\n");
}

nlohmann::ordered_json Settings::to_json() const {
    return nlohmann::ordered_json{{"theme", theme},
                                  {"updateCheck", update_check},
                                  {"developerMode", developer_mode},
                                  {"diagnostics", diagnostics}};
}

std::string Settings::get(const std::string& key) const {
    if (key == "theme") return theme;
    if (key == "updateCheck") return update_check;
    if (key == "developerMode") return developer_mode ? "true" : "false";
    if (key == "diagnostics") return diagnostics ? "true" : "false";
    throw Error("unknown setting \"" + key + "\" (settings: " +
                key_list() + ")");
}

void Settings::set(const std::string& key, const std::string& value) {
    if (key == "theme") {
        if (!one_of(value, {"system", "light", "dark"})) {
            throw Error("invalid theme \"" + value +
                        "\" (choose: system, light, dark)");
        }
        theme = value;
    } else if (key == "updateCheck") {
        if (!one_of(value, {"manual", "never"})) {
            throw Error("invalid updateCheck \"" + value +
                        "\" (choose: manual, never)");
        }
        update_check = value;
    } else if (key == "developerMode") {
        if (!parse_bool(value, developer_mode)) {
            throw Error("developerMode must be true or false");
        }
    } else if (key == "diagnostics") {
        if (!parse_bool(value, diagnostics)) {
            throw Error("diagnostics must be true or false");
        }
    } else {
        throw Error("unknown setting \"" + key + "\" (settings: " +
                    key_list() + ")");
    }
}

} // namespace lexe

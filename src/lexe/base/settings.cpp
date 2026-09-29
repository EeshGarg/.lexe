// settings — see settings.hpp. Strict load, atomic save, validated set.

#include "lexe/base/settings.hpp"

#include "lexe/base/error.hpp"
#include "lexe/base/json_strict.hpp"
#include "lexe/base/limits.hpp"
#include "lexe/base/util.hpp"

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
    // json_strict is the one strict JSON entry point and it throws
    // VerificationError, which is right for what it was built for: manifests,
    // trust records, update documents. It is wrong HERE, and the borrowed type
    // came with a borrowed exit code and a borrowed hint.
    //
    // A settings.json with a stray brace exited 3 -- "verification failure: the
    // file was not accepted", which docs/ERRORS.md §1 gives the property "there
    // is no --force that turns it into an acceptance" -- and then printed the
    // VerificationError type fallback: "The package did not verify and was not
    // trusted. Re-download it from the original source and try again." There is
    // no package. Nothing was downloaded. settings.json is written by this
    // runtime, holds nothing security-relevant (no setting can disable
    // verification, consent or isolation), and the remedy is one command.
    //
    // Found while asserting that `config set <bad value>` is 2 and a broken
    // settings file is not: the second half of that distinction measured 3.
    //
    // 1, "the operation failed for a reason with no more specific code", is the
    // honest answer: the file is this runtime's own state and it is damaged.
    // The strict parse itself is unchanged -- duplicate-key rejection and the
    // byte budget still apply -- only the type it is reported as.
    nlohmann::json j;
    try {
        j = json_strict::parse(util::slurp_text(path), "settings",
                               limits::kMaxManifestBytes);
    } catch (const VerificationError& e) {
        throw Error(std::string("settings file is corrupt: ") + e.what(),
                    "Restore the defaults with `lexe config reset`. Nothing "
                    "else depends on this file: settings hold display and "
                    "workflow preferences only.");
    }
    if (!j.is_object()) {
        throw Error("settings file is corrupt (not a JSON object): " +
                        path.string(),
                    "Restore the defaults with `lexe config reset`.");
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

// UsageError, not Error, for every rejection below -- exit 2 rather than 1.
//
// docs/ERRORS.md §1 defines 2 as "the command line was wrong" and 1 as "the
// operation failed for a reason with no more specific code". An unknown key and
// an out-of-vocabulary value are the command line being wrong, and there IS a
// more specific code. `lexe config set theme chartreuse` and `lexe config set
// nope.nope 1` both exited 1, the untyped catch-all that also covers a corrupt
// settings file and a failed write -- while `lexe completion fish`, the exact
// same shape ("that word is not in this closed set"), exited 2.
//
// §3 is the confirming test: UsageError is deliberately given no hint "because
// its message already is the remedy". Every message here already names the
// permitted values, which is precisely why it needs no hint and precisely why
// it is a UsageError.
//
// What stays Error, and therefore exit 1: a settings file that will not parse,
// and a write that fails. Those are not the caller's command line.
std::string Settings::get(const std::string& key) const {
    if (key == "theme") return theme;
    if (key == "updateCheck") return update_check;
    if (key == "developerMode") return developer_mode ? "true" : "false";
    if (key == "diagnostics") return diagnostics ? "true" : "false";
    throw UsageError("unknown setting \"" + key + "\" (settings: " +
                     key_list() + ")");
}

void Settings::set(const std::string& key, const std::string& value) {
    if (key == "theme") {
        if (!one_of(value, {"system", "light", "dark"})) {
            throw UsageError("invalid theme \"" + value +
                             "\" (choose: system, light, dark)");
        }
        theme = value;
    } else if (key == "updateCheck") {
        if (!one_of(value, {"manual", "never"})) {
            throw UsageError("invalid updateCheck \"" + value +
                             "\" (choose: manual, never)");
        }
        update_check = value;
    } else if (key == "developerMode") {
        if (!parse_bool(value, developer_mode)) {
            throw UsageError("developerMode must be true or false");
        }
    } else if (key == "diagnostics") {
        if (!parse_bool(value, diagnostics)) {
            throw UsageError("diagnostics must be true or false");
        }
    } else {
        throw UsageError("unknown setting \"" + key + "\" (settings: " +
                         key_list() + ")");
    }
}

} // namespace lexe

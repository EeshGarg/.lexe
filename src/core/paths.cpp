// paths — implementation. See paths.hpp and FORMAT-0.1 §9.

#include "core/paths.hpp"
#include "core/error.hpp"
#include "core/util.hpp"

namespace fs = std::filesystem;

namespace lexe {

Paths Paths::detect() {
    Paths p;

    const auto lexe_home = util::get_env("LEXE_HOME");
    if (lexe_home.has_value() && !lexe_home->empty()) {
        // Override: everything (including desktop-integration dirs) is kept
        // under LEXE_HOME so tests never touch the real user profile.
        p.home_ = fs::path(*lexe_home);
        p.cache_ = p.home_ / "cache";
        p.applications_ = p.home_ / "applications";
        p.icons_ = p.home_ / "icons" / "hicolor";
        p.mime_ = p.home_ / "mime";
        return p;
    }

#ifdef _WIN32
    const auto local = util::get_env("LOCALAPPDATA");
    if (!local.has_value() || local->empty()) {
        throw Error("cannot resolve LEXE_HOME: neither LEXE_HOME nor "
                    "LOCALAPPDATA is set");
    }
    p.home_ = fs::path(*local) / "lexe";
    p.cache_ = p.home_ / "cache";
    p.applications_ = p.home_ / "applications";
    p.icons_ = p.home_ / "icons" / "hicolor";
    p.mime_ = p.home_ / "mime";
#else
    const auto home_env = util::get_env("HOME");
    const auto xdg_data = util::get_env("XDG_DATA_HOME");
    const auto xdg_cache = util::get_env("XDG_CACHE_HOME");

    fs::path data_home;
    if (xdg_data.has_value() && !xdg_data->empty()) {
        data_home = fs::path(*xdg_data);
    } else if (home_env.has_value() && !home_env->empty()) {
        data_home = fs::path(*home_env) / ".local" / "share";
    } else {
        throw Error("cannot resolve LEXE_HOME: none of LEXE_HOME, "
                    "XDG_DATA_HOME, HOME is set");
    }

    fs::path cache_home;
    if (xdg_cache.has_value() && !xdg_cache->empty()) {
        cache_home = fs::path(*xdg_cache);
    } else if (home_env.has_value() && !home_env->empty()) {
        cache_home = fs::path(*home_env) / ".cache";
    } else {
        cache_home = data_home / ".cache"; // degenerate fallback
    }

    p.home_ = data_home / "lexe";
    p.cache_ = cache_home / "lexe";
    p.applications_ = data_home / "applications";
    p.icons_ = data_home / "icons" / "hicolor";
    p.mime_ = data_home / "mime";
#endif
    return p;
}

} // namespace lexe

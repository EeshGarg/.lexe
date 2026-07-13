// paths module tests (FORMAT-0.1 §9, ARCHITECTURE.md #Modules).

#include <doctest/doctest.h>

#include "core/paths.hpp"
#include "core/util.hpp"
#include "helpers.hpp"

#include <optional>
#include <string>

using namespace lexe;
namespace fs = std::filesystem;

namespace {

/// RAII save/restore for one environment variable.
class EnvGuard {
public:
    explicit EnvGuard(std::string name)
        : name_(std::move(name)), previous_(util::get_env(name_)) {}
    ~EnvGuard() {
        if (previous_.has_value()) {
            util::set_env(name_, *previous_);
        } else {
            util::unset_env(name_);
        }
    }
    EnvGuard(const EnvGuard&) = delete;
    EnvGuard& operator=(const EnvGuard&) = delete;

private:
    std::string name_;
    std::optional<std::string> previous_;
};

} // namespace

TEST_SUITE("paths") {

TEST_CASE("LEXE_HOME override wins and nests every directory") {
    lexe::test::TempLexeHome home;
    const Paths p = Paths::detect();
    CHECK(p.home() == home.path());
    CHECK(p.apps_dir() == home.path() / "apps");
    CHECK(p.data_dir() == home.path() / "data");
    CHECK(p.cache_dir() == home.path() / "cache");
    CHECK(p.applications_dir() == home.path() / "applications");
    CHECK(p.icons_dir() == home.path() / "icons" / "hicolor");
    CHECK(p.mime_dir() == home.path() / "mime");
}

TEST_CASE("empty LEXE_HOME is treated as unset") {
    lexe::test::TempLexeHome home; // restores LEXE_HOME afterwards
    util::set_env("LEXE_HOME", "");
    const Paths p = Paths::detect();
    CHECK(p.home() != fs::path(""));
    CHECK(p.home().filename() == "lexe");
}

TEST_CASE("platform default when LEXE_HOME is unset") {
    lexe::test::TempLexeHome home; // restores LEXE_HOME afterwards
    util::unset_env("LEXE_HOME");
#ifdef _WIN32
    // Windows dev host: %LOCALAPPDATA%\lexe (FORMAT-0.1 §9).
    const auto local = util::get_env("LOCALAPPDATA");
    REQUIRE(local.has_value());
    const Paths p = Paths::detect();
    CHECK(p.home() == fs::path(*local) / "lexe");
    CHECK(p.apps_dir() == p.home() / "apps");
#else
    // Linux: XDG dirs (FORMAT-0.1 §9). Point XDG_* into the temp dir so the
    // real profile is never touched.
    EnvGuard g_data("XDG_DATA_HOME");
    EnvGuard g_cache("XDG_CACHE_HOME");
    const fs::path xdg_data = home.path() / "xdg-data";
    const fs::path xdg_cache = home.path() / "xdg-cache";
    util::set_env("XDG_DATA_HOME", xdg_data.string());
    util::set_env("XDG_CACHE_HOME", xdg_cache.string());

    const Paths p = Paths::detect();
    CHECK(p.home() == xdg_data / "lexe");
    CHECK(p.apps_dir() == xdg_data / "lexe" / "apps");
    CHECK(p.data_dir() == xdg_data / "lexe" / "data");
    CHECK(p.cache_dir() == xdg_cache / "lexe");
    CHECK(p.applications_dir() == xdg_data / "applications");
    CHECK(p.icons_dir() == xdg_data / "icons" / "hicolor");
    CHECK(p.mime_dir() == xdg_data / "mime");
#endif
}

#ifndef _WIN32
TEST_CASE("XDG fallback to ~/.local/share and ~/.cache") {
    lexe::test::TempLexeHome home;
    util::unset_env("LEXE_HOME");
    EnvGuard g_home("HOME");
    EnvGuard g_data("XDG_DATA_HOME");
    EnvGuard g_cache("XDG_CACHE_HOME");
    util::set_env("HOME", home.path().string());
    util::unset_env("XDG_DATA_HOME");
    util::unset_env("XDG_CACHE_HOME");

    const Paths p = Paths::detect();
    CHECK(p.home() == home.path() / ".local" / "share" / "lexe");
    CHECK(p.cache_dir() == home.path() / ".cache" / "lexe");
    CHECK(p.applications_dir() ==
          home.path() / ".local" / "share" / "applications");
}
#endif

} // TEST_SUITE("paths")

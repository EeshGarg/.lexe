// Settings tests (DX5): the persisted preferences module and the `lexe config`
// CLI. Defaults, validation, round-trip persistence, and forward-compatible
// loading — none of which can touch a security guarantee.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "core/error.hpp"
#include "core/paths.hpp"
#include "core/settings.hpp"
#include "core/util.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace lexe;
using json = nlohmann::json;

namespace {

fs::path cli_binary() {
    for (const char* var : {"LEXE_TEST_BINARY", "LEXE_CLI"}) {
        if (const auto env = util::get_env(var); env && !env->empty()) {
            return fs::path(*env);
        }
    }
#ifdef LEXE_TEST_BINARY_PATH
    return fs::path(LEXE_TEST_BINARY_PATH);
#else
    return fs::path("lexe");
#endif
}
util::ProcessResult run(const std::vector<std::string>& args) {
    std::vector<std::string> argv{cli_binary().string()};
    argv.insert(argv.end(), args.begin(), args.end());
    return util::run_process(argv);
}

} // namespace

TEST_SUITE("settings") {

TEST_CASE("defaults are safe and stable") {
    const Settings s;
    CHECK(s.theme == "system");
    CHECK(s.update_check == "manual");
    CHECK_FALSE(s.developer_mode);
    CHECK_FALSE(s.diagnostics);
}

TEST_CASE("a missing file yields defaults; set validates and round-trips") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    CHECK(Settings::load(paths).theme == "system"); // no file yet

    Settings s = Settings::load(paths);
    s.set("theme", "dark");
    s.set("developerMode", "yes");    // permissive boolean
    s.set("updateCheck", "never");
    s.save(paths);

    const Settings reloaded = Settings::load(paths);
    CHECK(reloaded.theme == "dark");
    CHECK(reloaded.developer_mode);
    CHECK(reloaded.update_check == "never");
    CHECK(fs::is_regular_file(Settings::file(paths)));
}

TEST_CASE("invalid keys and values are rejected") {
    Settings s;
    CHECK_THROWS_AS(s.set("nonsense", "x"), Error);
    CHECK_THROWS_AS(s.set("theme", "chartreuse"), Error);
    CHECK_THROWS_AS(s.set("updateCheck", "hourly"), Error);
    CHECK_THROWS_AS(s.set("developerMode", "maybe"), Error);
    CHECK_THROWS_AS(s.get("nope"), Error);
}

TEST_CASE("unknown JSON fields are ignored (forward compatible)") {
    test::TempLexeHome home;
    const Paths paths = Paths::detect();
    util::write_atomic(Settings::file(paths),
                       R"({"theme":"light","futureKnob":42})");
    const Settings s = Settings::load(paths);
    CHECK(s.theme == "light");
    CHECK(s.update_check == "manual"); // default for the absent field
}

TEST_CASE("`lexe config` set/get/list/reset through the CLI") {
    test::TempLexeHome home;
    CHECK(run({"config", "set", "theme", "dark"}).exit_code == 0);
    CHECK(run({"config", "get", "theme"}).stdout_text.find("dark") !=
          std::string::npos);

    const util::ProcessResult list = run({"config", "list", "--json"});
    CHECK(list.exit_code == 0);
    CHECK(json::parse(list.stdout_text).at("theme") == "dark");

    CHECK(run({"config", "set", "theme", "bogus"}).exit_code != 0); // rejected
    CHECK(run({"config", "reset"}).exit_code == 0);
    CHECK(json::parse(run({"config", "list", "--json"}).stdout_text).at("theme") ==
          "system");
}

} // TEST_SUITE("settings")

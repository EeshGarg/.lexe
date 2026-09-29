// Settings tests (DX5): the persisted preferences module and the `lexe config`
// CLI. Defaults, validation, round-trip persistence, and forward-compatible
// loading — none of which can touch a security guarantee.

#include <doctest/doctest.h>

#include "helpers.hpp"

#include "lexe/base/error.hpp"
#include "lexe/base/paths.hpp"
#include "lexe/base/settings.hpp"
#include "lexe/base/util.hpp"

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

/// As run(), but CAPTURING stderr. run() leaves it inherited, so
/// `result.stderr_text` is empty and any assertion on it is vacuously true.
util::ProcessResult run_err(const std::vector<std::string>& args) {
    std::vector<std::string> argv{cli_binary().string()};
    argv.insert(argv.end(), args.begin(), args.end());
    util::RunOptions opts;
    opts.capture_stderr = true;
    return util::run_process(argv, opts);
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
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

TEST_CASE("invalid keys and values are rejected as USAGE errors") {
    Settings s;
    // UsageError, not merely Error. These used to be plain Error, which
    // exit_code_for maps to 1 -- the untyped catch-all that also covers a
    // corrupt settings file and a failed write -- so `lexe config set theme
    // chartreuse` and `lexe config set nope.nope 1` both answered 1, while
    // `lexe completion fish`, the identical shape, answered 2.
    //
    // `Error` would still be satisfied by the old behaviour, since UsageError
    // derives from it. Naming the derived type is the whole assertion.
    CHECK_THROWS_AS(s.set("nonsense", "x"), UsageError);
    CHECK_THROWS_AS(s.set("theme", "chartreuse"), UsageError);
    CHECK_THROWS_AS(s.set("updateCheck", "hourly"), UsageError);
    CHECK_THROWS_AS(s.set("developerMode", "maybe"), UsageError);
    CHECK_THROWS_AS(s.get("nope"), UsageError);
    // Still Errors, so nothing else about the hierarchy moved.
    CHECK_THROWS_AS(s.set("nonsense", "x"), Error);

    // Every rejection above names the permitted values, which is docs/ERRORS.md
    // §3's stated reason a UsageError carries no hint: its message already is
    // the remedy. Asserted rather than claimed.
    try {
        s.set("theme", "chartreuse");
        FAIL("an invalid theme must be rejected");
    } catch (const UsageError& e) {
        CHECK(std::string(e.what()).find("system, light, dark") !=
              std::string::npos);
        CHECK(e.hint().empty());
    }
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

    // Exit 2, "the command line was wrong" (docs/ERRORS.md §1) -- not 1, and
    // not merely "nonzero". `!= 0` was satisfied by the exit 1 this used to
    // return, and by every other code too, so it could not have caught the
    // defect it was standing next to.
    CHECK(run({"config", "set", "theme", "bogus"}).exit_code == 2);
    CHECK(run({"config", "set", "nope.nope", "1"}).exit_code == 2);
    CHECK(run({"config", "get", "nope.nope"}).exit_code == 2);
    // The comparator that made these wrong: the same shape, already 2.
    CHECK(run({"completion", "fish"}).exit_code == 2);
    // And the distinction 2 exists to draw, in this same case: a settings file
    // that will not parse is NOT the command line being wrong, and still
    // answers 1. If both were 2 the code would have stopped meaning anything.
    //
    // It measured 3, not 1, and the reason is worth recording: Settings::load
    // parses through json_strict, the strict entry point built for manifests
    // and trust records, which throws VerificationError. So a stray brace in
    // settings.json was reported as "verification failure -- the file was not
    // accepted" and carried that type's hint, "The package did not verify and
    // was not trusted. Re-download it from the original source and try again."
    // There is no package and nothing was downloaded.
    util::spit(Settings::file(Paths::detect()),
               std::string_view("{not json at all"));
    const util::ProcessResult corrupt = run_err({"config", "list"});
    CHECK(corrupt.exit_code == 1);
    CHECK(corrupt.exit_code != 3);
    CHECK(corrupt.exit_code != 2); // and not the usage code either
    CHECK_FALSE(contains(corrupt.stderr_text, "Re-download"));
    CHECK(contains(corrupt.stderr_text, "lexe config reset"));
    CHECK(run({"config", "reset"}).exit_code == 0); // reset repairs it
    CHECK(json::parse(run({"config", "list", "--json"}).stdout_text).at("theme") ==
          "system");
}

} // TEST_SUITE("settings")

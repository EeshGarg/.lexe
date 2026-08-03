// Version tests (Alpha stabilization): the platform's DISTINCT version axes —
// the runtime/CLI build version, the .lexe package-format version, and the Tux32
// baseline — are centralized and never conflated, and `lexe version` reports
// them through the real CLI.

#include <doctest/doctest.h>

#include "core/tux32.hpp"
#include "core/util.hpp"
#include "core/version.hpp"

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

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

} // namespace

TEST_SUITE("version") {

TEST_CASE("the three version axes are distinct and centralized") {
    // Package format is the .lexe container/manifest version (FORMAT-0.1) — a
    // separate axis from the runtime build version.
    CHECK(std::string(version::kPackageFormat) == "0.1");

    // The runtime string embeds the build version and the release stage.
    CHECK(contains(version::runtime_string(), version::kRuntime));
    CHECK(contains(version::runtime_string(), "alpha")); // Alpha stage

    // The Tux32 baseline is its own axis (contract version, not runtime/format).
    CHECK(std::string(tux32_core_1().id) == "tux32-core-1");
    CHECK(tux32_core_1().spec_version == "1");

    // The three must not be conflated.
    CHECK(std::string(version::kPackageFormat) != tux32_core_1().spec_version);
    CHECK(std::string(version::kRuntime) != std::string(version::kPackageFormat));
}

TEST_CASE("`lexe version --json` reports every axis through the CLI") {
    const util::ProcessResult r = run({"version", "--json"});
    CHECK(r.exit_code == 0);
    const json j = json::parse(r.stdout_text);
    CHECK(j.at("packageFormat") == "0.1");
    CHECK(j.at("stage") == "alpha");
    CHECK(j.at("tux32Baseline").at("id") == "tux32-core-1");
    CHECK(j.at("tux32Baseline").at("specVersion") == "1");
    // runtime = runtimeVersion + stage
    CHECK(contains(j.at("runtime").get<std::string>(),
                   j.at("runtimeVersion").get<std::string>()));
}

TEST_CASE("`lexe --version` and `lexe version` are equivalent entry points") {
    const util::ProcessResult a = run({"--version"});
    const util::ProcessResult b = run({"version"});
    CHECK(a.exit_code == 0);
    CHECK(b.exit_code == 0);
    CHECK(a.stdout_text == b.stdout_text);
    CHECK(contains(a.stdout_text, "package format: 0.1"));
    CHECK(contains(a.stdout_text, "tux32-core-1"));
}

} // TEST_SUITE("version")
